"""
hermes-hostd VM-side client
Connects to the hostd daemon running on the Incus host and sends command requests.

Supports two transports:
  - VsockClient: AF_VSOCK to CID 2 (host), default port 9999
  - HttpClient:  HTTP POST to a URL, default http://127.0.0.1:9998/execute

Only stdlib is used: socket (vsock), urllib.request (http).

Wire format note: these dataclasses are deliberately kept field-for-field
identical to the server-side models in ../models.py (CommandRequest:
id/description/command/timeout/persistent_intent, CommandResult: id/approved/exit_code/
stdout/stderr/error/log_id/output_truncated plus preserved additive metadata). The two sides are duplicated (no shared import,
so the client works even if only this one file is copied to the VM),
but the field NAMES and JSON keys must stay in lockstep with models.py
or requests/results will silently deserialize with wrong/blank values.
"""

from __future__ import annotations

import json
import socket
import urllib.request
import urllib.error
import urllib.parse
import uuid
import os
import re
import stat
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from typing import List, Optional


# 1 MiB admits two 16 KiB daemon tails even at worst-case JSON escaping
# (replacement/control characters), plus IDs, ordinary errors and metadata.
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024


def _response_limit(value):
    if type(value) is not int or value <= 0:
        raise ValueError('max_response_bytes must be a positive integer')
    return value


def _read_response(read, limit):
    data = bytearray()
    while True:
        chunk = read(min(4096, limit + 1 - len(data)))
        if not chunk:
            break
        if len(data) + len(chunk) > limit:
            raise _ClientError('hostd response exceeds byte limit')
        data.extend(chunk)
    try:
        return data.decode('utf-8')
    except UnicodeError:
        raise _ClientError('hostd response is not valid UTF-8') from None


class _ClientError(RuntimeError):
    """Only locally authored, bounded diagnostics may cross the tool boundary."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate response field')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('non-JSON constant')


def _validate_token(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or not re.fullmatch(r'[A-Za-z0-9._~+/-]+={0,2}', value, re.ASCII):
        raise ValueError('invalid requester token (expected 1..256 ASCII bearer characters)')
    return value


def read_token_file(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
                raise ValueError('unsafe file')
            raw = stream.read(258)
        if raw.endswith(b'\n'):
            raw = raw[:-1]
        return _validate_token(raw.decode('ascii'))
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ValueError('cannot read requester token from private owned regular file') from None


def _credential(token, insecure_no_auth):
    if type(insecure_no_auth) is not bool:
        raise ValueError('insecure_no_auth must be an explicit boolean')
    if insecure_no_auth:
        if token is not None:
            raise ValueError('requester token and insecure_no_auth are mutually exclusive')
        logging.getLogger(__name__).warning('INSECURE: requester authentication explicitly disabled')
        return None
    if token is None:
        raise ValueError('requester token required; configure a private token source or explicitly set insecure_no_auth: true')
    return _validate_token(token)


# ---------------------------------------------------------------------------
# Data models (duplicated from server side — no shared import, but the
# field names and JSON keys must match models.py exactly — see module
# docstring above).
# ---------------------------------------------------------------------------

@dataclass
class CommandRequest:
    """A request to run a command on the host."""
    description: str = ""
    command: List[str] = field(default_factory=list)
    timeout: int = 30
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    persistent_intent: bool = False

    def __post_init__(self) -> None:
        if type(self.persistent_intent) is not bool:
            raise TypeError("persistent_intent must be a bool")

    def to_dict(self) -> dict:
        self.__post_init__()
        return {
            "id": self.id,
            "description": self.description,
            "command": self.command,
            "timeout": self.timeout,
            "persistent_intent": self.persistent_intent,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "CommandRequest":
        return cls(
            command=d["command"],
            description=d.get("description", ""),
            timeout=d.get("timeout", 30),
            id=d.get("id", str(uuid.uuid4())),
            persistent_intent=d.get("persistent_intent", False),
        )


@dataclass
class CommandResult:
    """The result returned by the host daemon after (attempted) execution.

    Note: ``approved`` reflects whether the approval channel + allowlist
    let the command run at all — NOT whether it exited 0. A command that
    ran and failed (e.g. exit_code=2) still has approved=True. Check
    ``exit_code == 0`` for actual success.
    """
    id: str = ""
    approved: bool = False
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None
    log_id: Optional[str] = None
    output_truncated: bool = False
    metadata: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        for name in ('id', 'stdout', 'stderr'):
            if type(getattr(self, name)) is not str:
                raise TypeError('invalid result string field')
        for name in ('error', 'log_id'):
            value = getattr(self, name)
            if value is not None and type(value) is not str:
                raise TypeError('invalid result nullable string field')
        if type(self.approved) is not bool or type(self.output_truncated) is not bool:
            raise TypeError('invalid result boolean field')
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise TypeError('invalid result exit code')
        if 'persistent_intent' in self.metadata and type(self.metadata['persistent_intent']) is not bool:
            raise TypeError('invalid result persistent intent')

    @property
    def succeeded(self) -> bool:
        """True only when the command was approved AND exited with code 0."""
        return self.approved and self.exit_code == 0

    def to_dict(self) -> dict:
        self.__post_init__()
        return {
            **self.metadata,
            "id": self.id,
            "approved": self.approved,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "log_id": self.log_id,
            "output_truncated": self.output_truncated,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "CommandResult":
        if type(d) is not dict or 'id' not in d or 'approved' not in d:
            raise ValueError('result must be an object with id and approved')
        names = ('id', 'approved', 'exit_code', 'stdout', 'stderr', 'error', 'log_id', 'output_truncated')
        return cls(
            id=d['id'], approved=d['approved'], exit_code=d.get('exit_code'),
            stdout=d.get('stdout', ''), stderr=d.get('stderr', ''), error=d.get('error'),
            log_id=d.get('log_id'), output_truncated=d.get('output_truncated', False),
            metadata={k: v for k, v in d.items() if k not in names},
        )

    @classmethod
    def from_json(cls, raw: str) -> "CommandResult":
        return cls.from_dict(json.loads(raw, object_pairs_hook=_unique_object,
                                        parse_constant=_reject_constant))


# ---------------------------------------------------------------------------
# Transport abstraction
# ---------------------------------------------------------------------------

class Transport(ABC):
    """Abstract base class for hostd transports."""

    @abstractmethod
    def send(self, payload: str) -> str:
        """Send a JSON payload string and return the JSON response string."""
        ...


# ---------------------------------------------------------------------------
# VsockClient transport
# ---------------------------------------------------------------------------

class VsockClient(Transport):
    """
    Connects to the host daemon over AF_VSOCK.

    The host VM always has CID 2. The port must match what the server
    is listening on (default 9999).

    Protocol: send the JSON request followed by a newline; read the
    response until the connection is closed.
    """

    HOST_CID = 2  # host CID is always 2 in VSOCK

    def __init__(self, port: int = 9999, timeout: Optional[float] = 30.0,
                 auth_token: Optional[str] = None, insecure_no_auth: bool = False,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES):
        self.max_response_bytes = _response_limit(max_response_bytes)
        self.auth_token = _credential(auth_token, insecure_no_auth)
        self.port = port
        self.timeout = timeout

    def send(self, payload: str) -> str:
        body = json.loads(payload)
        if not isinstance(body, dict) or 'auth' in body:
            raise ValueError('operation must be an object without transport auth metadata')
        if self.auth_token is not None:
            body['auth'] = {'token': self.auth_token}
        payload = json.dumps(body)
        try:
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        except AttributeError:
            raise _ClientError(
                "AF_VSOCK is not available on this system. "
                "Ensure you are running inside an VSOCK-enabled VM and the kernel module is loaded."
            )

        # None disables the socket timeout entirely (blocks indefinitely) —
        # used for requests with timeout=0 (long installs/downloads).
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.HOST_CID, self.port))
            # Send the request terminated by newline
            message = (payload + "\n").encode("utf-8")
            sock.sendall(message)
            return _read_response(sock.recv, self.max_response_bytes)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# HttpClient transport
# ---------------------------------------------------------------------------

class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never replay a privileged request at a server-selected destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpClient(Transport):
    """
    Sends the command request as a JSON HTTP POST to a URL.

    Default URL: http://127.0.0.1:9998/execute
    Loopback is the machine/network namespace running Hermes, not the physical
    host when Hermes runs in a VM/container. A local daemon at this endpoint
    needs no URL override. Otherwise configure the daemon endpoint explicitly,
    or establish an external SSH local forward and set the URL to its local
    listening port. This client does not establish tunnels automatically.
    """

    # Loopback targets the Hermes namespace; see the endpoint/tunnel setup above.
    DEFAULT_URL = "http://127.0.0.1:9998/execute"

    def __init__(self, url: str = DEFAULT_URL, timeout: Optional[float] = 30.0, auth_token: Optional[str] = None,
                 insecure_no_auth: bool = False, max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES):
        self.max_response_bytes = _response_limit(max_response_bytes)
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.query or parsed.fragment):
            raise ValueError('invalid hostd endpoint; use http(s) without credentials, query or fragment')
        self.url = url
        self.timeout = timeout
        self.auth_token = _credential(auth_token, insecure_no_auth)

    def send(self, payload: str) -> str:
        data = payload.encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        req = urllib.request.Request(
            self.url,
            data=data,
            headers=headers,
            method="POST",
        )
        # Keep urllib's default proxy/TLS handlers, but not redirect replay.
        opener = urllib.request.build_opener(_RejectRedirects())
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                response = _read_response(resp.read, self.max_response_bytes)
                if getattr(resp, 'length', None) not in (None, 0):
                    raise _ClientError('hostd HTTP response truncated')
                return response
        except urllib.error.HTTPError as exc:
            with exc:
                if 300 <= exc.code < 400:
                    # Do not expose Location or an untrusted response body.
                    raise _ClientError(
                        f"hostd HTTP redirect rejected ({exc.code}); configure the actual endpoint"
                    ) from None
                raise _ClientError(
                    f"hostd HTTP error {exc.code}"
                ) from None
        except urllib.error.URLError as exc:
            raise _ClientError(
                "hostd HTTP connection failed"
            ) from None


# ---------------------------------------------------------------------------
# HostdClient — high-level client
# ---------------------------------------------------------------------------

class HostdClient:
    """
    High-level client for the hermes-hostd daemon.

    Usage::

        transport = VsockClient(port=9999)
        client = HostdClient(transport)
        result = client.send_request(CommandRequest(command=["ls", "-la"], description="list files"))
        print(result.stdout)
    """

    def __init__(self, transport: Transport):
        self.transport = transport

    def send_request(self, request: CommandRequest) -> CommandResult:
        """Send a CommandRequest to the host daemon and return a CommandResult."""
        payload = request.to_json()
        try:
            raw_response = self.transport.send(payload)
        except Exception as exc:
            # Return a structured error rather than letting the caller deal with raw exceptions
            return CommandResult(
                id=request.id,
                approved=False,
                error=str(exc) if isinstance(exc, _ClientError) else 'Transport error: host daemon response unavailable',
            )

        if not raw_response:
            return CommandResult(
                id=request.id,
                approved=False,
                error="Empty response from host daemon",
            )

        try:
            result = CommandResult.from_json(raw_response)
            if result.id != request.id:
                raise ValueError('response id mismatch')
            return result
        except (ValueError, TypeError, KeyError, RecursionError):
            # Untrusted response/parser diagnostics can echo transport credentials.
            # Keep the error useful without returning body or exception contents.
            return CommandResult(
                id=request.id,
                approved=False,
                error="Failed to parse host daemon response",
            )


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def client_from_config(
    transport: str = "vsock",
    vsock_port: int = 9999,
    http_url: str = HttpClient.DEFAULT_URL,
    timeout: Optional[float] = 30.0,
    http_auth_token: Optional[str] = None,
    auth_token: Optional[str] = None,
    insecure_no_auth: bool = False,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> HostdClient:
    """
    Build a HostdClient from simple config values.

    Args:
        transport: "vsock" or "http"
        vsock_port: port for VsockClient
        http_url: full URL for HttpClient
        timeout: socket/HTTP timeout in seconds. Pass None (or 0) to disable
            the timeout entirely — use for long-running commands like large
            package installs/downloads where the command's own timeout is
            also set to 0 (no timeout).
        http_auth_token: legacy alias for auth_token; do not pass both.
        auth_token: required requester token for either transport.
        max_response_bytes: positive finite body-byte ceiling, including framing whitespace.
        insecure_no_auth: explicit unsafe no-token mode; emits a warning.
    """
    if timeout is not None and timeout <= 0:
        timeout = None
    if auth_token is not None and http_auth_token is not None:
        raise ValueError('choose one requester token argument')
    token = auth_token if auth_token is not None else http_auth_token
    if transport == "vsock":
        return HostdClient(VsockClient(port=vsock_port, timeout=timeout, auth_token=token,
                                      insecure_no_auth=insecure_no_auth, max_response_bytes=max_response_bytes))
    elif transport == "http":
        return HostdClient(HttpClient(url=http_url, timeout=timeout, auth_token=token,
                                     insecure_no_auth=insecure_no_auth, max_response_bytes=max_response_bytes))
    else:
        raise ValueError(f"Unknown transport {transport!r}. Use 'vsock' or 'http'.")
