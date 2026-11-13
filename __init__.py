"""
hostd-client Hermes plugin
Registers tools for running commands on the Incus host via the hermes-hostd
daemon, which provides out-of-band approval through ntfy before execution.

Credentials: HOSTD_AUTH_TOKEN from Hermes get_secret at call time only.
Legacy auth_token_file / HOSTD_AUTH_TOKEN_FILE selectors are rejected.
Nonsecret configuration is read from (in priority order):
  1. Flat compatibility config: active Hermes home / hostd-client.yaml
       (context-local profile first; standalone: $HERMES_HOME, then ~/.hermes)
       transport: vsock
       vsock_port: 9999
       http_url: http://127.0.0.1:9998/execute
  2. Public ctx.get_config settings declared in plugin.yaml (captured at registration)
  3. Built-in defaults (transport remains vsock; no automatic transport fallback)

HTTP loopback is the machine/network namespace running Hermes, not the physical
host when Hermes runs in a VM/container. A local daemon at the default endpoint
needs no URL override. Otherwise explicitly configure the daemon endpoint, or
establish an external SSH local forward and configure the URL to match its local
listening port. The plugin does not establish tunnels automatically.

The client library is bundled in this plugin's client/ package. If that
package is incomplete, tools return a clear error rather than an import traceback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Import only the bundled package; never resolve an external daemon checkout.
# Fail gracefully when the plugin copy is incomplete.
# ---------------------------------------------------------------------------

_CLIENT_AVAILABLE = False
_client_mod: Any = None
_CLIENT_IMPORT_ERROR: str = ""

try:
    from .client import client as _client_mod
    _CLIENT_AVAILABLE = True
except ImportError as exc:
    _CLIENT_IMPORT_ERROR = (
        f"Could not import the bundled hermes-hostd client: {exc}. "
        "Copy the complete plugin directory, including client/, and load it as a package."
    )


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

# Profile-owned nonsecret settings captured through the public plugin context.
# The active-profile compatibility file takes precedence over these settings.
_PLUGIN_SETTINGS: Dict[str, Any] = {}

def _load_yaml_config() -> Dict[str, Any]:
    """Load hostd-client.yaml from the active Hermes profile home."""
    try:
        from hermes_constants import get_hermes_home
    except ModuleNotFoundError as exc:
        if exc.name != "hermes_constants":
            raise
        # Standalone use without Hermes retains the environment/home contract.
        hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    else:
        # Resolve at call time: shared gateways route profiles via contextvars.
        # Resolver failures must not silently select the process/default profile.
        hermes_home = get_hermes_home()
    config_path = hermes_home / "hostd-client.yaml"
    if not config_path.exists():
        return {}
    try:
        # Use only stdlib — PyYAML may not be available.
        # Support the simple flat key: value format we need.
        result: Dict[str, Any] = {}
        with config_path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, _, val = line.partition(":")
                    result[key.strip()] = val.strip()
        return result
    except Exception:
        return {}


def _build_client(socket_timeout: float | None = 30.0):
    """Build a client using managed secrets and profile-owned nonsecret config.

    socket_timeout: transport-level timeout in seconds. Pass None or <= 0
    to disable it (matches a CommandRequest.timeout of 0 for long
    installs/downloads where the process itself may run far past 30s).
    """
    yaml_cfg = {**_PLUGIN_SETTINGS, **_load_yaml_config()}
    if 'HOSTD_AUTH_TOKEN_FILE' in os.environ or 'auth_token_file' in yaml_cfg:
        raise ValueError(
            'Credential file selectors were removed; remove auth_token_file and '
            'HOSTD_AUTH_TOKEN_FILE, then configure HOSTD_AUTH_TOKEN in Hermes managed secrets'
        )

    transport = yaml_cfg.get("transport", "vsock").lower()

    vsock_port_raw = yaml_cfg.get("vsock_port", "9999")
    try:
        vsock_port = int(vsock_port_raw)
    except (TypeError, ValueError):
        vsock_port = 9999

    # The HTTP fallback is Hermes-local loopback, not a VM/container's host.
    # Configure the daemon URL or an externally established SSH forward's local
    # port unless a local daemon already matches the default. No automatic tunnel.
    http_url = yaml_cfg.get("http_url", _client_mod.HttpClient.DEFAULT_URL)

    # Resolve at call time through Hermes, never through plugin-owned stores or
    # raw process-env reads. Do not expose import/resolver exception contents.
    try:
        from agent.secret_scope import get_secret
        token = get_secret('HOSTD_AUTH_TOKEN')
    except Exception:
        raise ValueError(
            'Hermes could not resolve HOSTD_AUTH_TOKEN for this profile; '
            'check the managed secret and active profile scope'
        ) from None
    insecure = yaml_cfg.get('insecure_no_auth', False)
    if isinstance(insecure, str):
        if insecure not in ('true', 'false'):
            raise ValueError('insecure_no_auth must be true or false')
        insecure = insecure == 'true'
    if not insecure:
        # Fail before creating any transport; validation diagnostics never echo values.
        _client_mod._credential(token, False)
    response_limit = yaml_cfg.get('max_response_bytes', _client_mod.DEFAULT_MAX_RESPONSE_BYTES)
    if isinstance(response_limit, str):
        if not response_limit.isascii() or not response_limit.isdecimal():
            raise ValueError('max_response_bytes must be a positive integer')
        response_limit = int(response_limit)
    return _client_mod.client_from_config(
        max_response_bytes=response_limit,
        transport=transport,
        vsock_port=vsock_port,
        http_url=http_url,
        timeout=socket_timeout,
        auth_token=token,
        insecure_no_auth=insecure,
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def _require_host_approval(tool_name: str, args=None, **kwargs):
    """Escalate host commands to Hermes policy before contacting the daemon."""
    if tool_name != "run_on_host":
        return None
    # JSON preserves argv boundaries and escapes control characters. Include all
    # submitted metadata without interpreting it as shell syntax or policy.
    return {
        "action": "approve",
        "message": "Host command request (argv and description):\n" + json.dumps(
            args if isinstance(args, dict) else {}, ensure_ascii=True),
        "rule_key": "run_on_host",
    }


def _handle_run_on_host(args: Dict[str, Any]) -> str:
    if not _CLIENT_AVAILABLE:
        return json.dumps({
            "success": False,
            "error": _CLIENT_IMPORT_ERROR,
        })

    description: str = args.get("description", "")
    command = args.get("command", [])
    timeout_raw = args.get("timeout", 120)
    persistent_intent = args.get("persistent_intent", False)
    if type(persistent_intent) is not bool:
        return json.dumps({"success": False, "error": "persistent_intent must be a bool"})

    if not command:
        return json.dumps({"success": False, "error": "'command' must be a non-empty list."})
    if not isinstance(command, list):
        return json.dumps({"success": False, "error": "'command' must be an array of strings."})
    try:
        timeout = int(timeout_raw)
        if timeout < 0:
            timeout = 0
    except (TypeError, ValueError):
        timeout = 120

    try:
        # timeout=0 means "no timeout" — disable both the request-level
        # subprocess timeout and the transport-level socket timeout.
        client = _build_client(socket_timeout=(None if timeout == 0 else float(timeout) + 30))
        request = _client_mod.CommandRequest(
            command=command,
            description=description,
            timeout=timeout,
            persistent_intent=persistent_intent,
        )
        result = client.send_request(request)
        return result.to_json()
    except Exception as exc:
        return json.dumps({"success": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

_SCHEMA_RUN_ON_HOST = {
    "type": "function",
    "function": {
        "name": "run_on_host",
        "description": (
            "Send a command to the hermes-hostd daemon running on the Incus host. "
            "The daemon will send an out-of-band approval request via ntfy before "
            "executing the command. Use this for host-level operations that require "
            "elevated privileges or access to host resources (e.g. managing Incus "
            "instances, modifying firewall rules, installing host packages). "
            "The command is an argv array; the description should explain in plain "
            "language what the command does and why it is needed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": (
                        "Human-readable explanation of what this command does and "
                        "why it is being requested. Shown to the approver in the "
                        "ntfy notification."
                    ),
                },
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "The command to run on the host, as an argv list. "
                        "Example: [\"incus\", \"list\"] or [\"systemctl\", \"restart\", \"nginx\"]"
                    ),
                },
                "persistent_intent": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Declare that the caller intentionally wants a long-running process "
                        "to remain running (default false). Approval metadata only: does not "
                        "change timeout, cancellation, cleanup or authority; does not detach, "
                        "start a service manager job or provide background lifecycle management. "
                        "timeout remains independent, including explicit 0 for unlimited; "
                        "the call still waits for execution. Requires a daemon supporting this marker."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": (
                        "Max seconds to wait for the command to finish (default 120). "
                        "Pass 0 to disable the timeout entirely for long-running commands "
                        "(large package installs, downloads, etc.) — the call will then "
                        "block until the command finishes or the connection drops."
                    ),
                },
            },
            "required": ["description", "command"],
        },
    },
}

# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def register(ctx):
    """Called by Hermes when the plugin is loaded."""
    ctx.register_hook("pre_tool_call", _require_host_approval)
    _PLUGIN_SETTINGS.clear()
    get_config = getattr(ctx, "get_config", None)
    if callable(get_config):
        # Read the removed selector only to reject stale configs; never open it.
        for key in ("transport", "vsock_port", "http_url", "auth_token_file", "insecure_no_auth", "max_response_bytes"):
            value = get_config(key, None)
            if value is not None:
                _PLUGIN_SETTINGS[key] = value
    # Hermes adds the provider wrapper; register only the inner function schema.
    ctx.register_tool(
        name="run_on_host",
        toolset="hostd",
        schema=_SCHEMA_RUN_ON_HOST["function"],
        handler=lambda args, **kwargs: _handle_run_on_host(args),
    )
