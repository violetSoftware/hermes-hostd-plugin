"""Strict untrusted result boundary; synthetic credentials/data only."""
import importlib.util
import json
from pathlib import Path
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import socket
import tempfile
import threading
from unittest.mock import patch
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('response_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
assert spec is not None and spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
client = plugin._client_mod


@contextlib.contextmanager
def endpoint(kind, response, wire_client=client, length_delta=0):
    """Real disposable HTTP or stream socket; only AF_VSOCK is adapted."""
    errors = []
    def reply(body):
        return response(body) if callable(response) else response
    if kind == 'http':
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                data = reply(body)
                self.send_response(200)
                self.send_header('Content-Length', str(len(data) + length_delta))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield {'transport': 'http', 'http_url': f'http://127.0.0.1:{server.server_port}/execute'}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
    else:
        left, right = socket.socketpair()
        def serve():
            try:
                with right, right.makefile('rb') as stream:
                    body = json.loads(stream.readline())
                    right.sendall(reply(body))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                errors.append(type(exc).__name__)
        thread = threading.Thread(target=serve)
        thread.start()
        class StreamSocket:
            def settimeout(self, value): left.settimeout(value)
            def connect(self, address): pass
            def sendall(self, value): left.sendall(value)
            def recv(self, size): return left.recv(size)
            def close(self): left.close()
        real_socket = socket.socket
        try:
            with patch.object(wire_client.socket, 'socket', side_effect=lambda *a, **k:
                    StreamSocket() if a and a[0] == socket.AF_VSOCK else real_socket(*a, **k)):
                yield {'transport': 'vsock'}
        finally:
            left.close()
            thread.join(2)
            right.close()
            assert not thread.is_alive()
            assert not errors, errors


class TransportBoundsTests(unittest.TestCase):
    def test_fragmented_decode_and_worst_case_log_tails(self):
        raw = json.dumps(dict(id='fixture', approved=True, stdout='\ufffd' * 16384,
                             stderr='\x00' * 16384, log_id='opaque', output_truncated=True)).encode()
        class Fragments(client.Transport):
            def send(self, payload):
                parts = iter(bytes([byte]) for byte in raw)
                return client._read_response(lambda size: next(parts, b''), client.DEFAULT_MAX_RESPONSE_BYTES)
        result = client.HostdClient(Fragments()).send_request(client.CommandRequest(id='fixture'))
        self.assertIs(result.approved, True)
        self.assertEqual(len(result.stdout), 16384)
        self.assertTrue(result.output_truncated)
        import tracemalloc
        tracemalloc.start()
        try:
            with self.assertRaises(RuntimeError):
                client._read_response(lambda size: b'x' * size, 65536)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 262144)
        print(f'bounded reader synthetic endless stream: peak={peak} bytes, limit=65536')

    def test_http_short_declared_body_is_not_authoritative(self):
        raw = b'{"id":"fixture","approved":true}'
        with endpoint('http', raw, length_delta=10) as config:
            result = client.client_from_config(**config, auth_token='synthetic').send_request(
                client.CommandRequest(id='fixture'))
        self.assertIs(result.approved, False)
        self.assertIsNotNone(result.error)

    def test_exact_byte_boundary_and_oversize_both_transports(self):
        raw = json.dumps({'id': 'fixture', 'approved': True, 'stdout': 'é'}, ensure_ascii=False).encode()
        for kind in ('http', 'vsock'):
            for extra in (b'', b' ', b' ' * 100000):
                with self.subTest(kind=kind, extra=len(extra)), endpoint(kind, raw + extra) as config:
                    built = client.client_from_config(**config, auth_token='synthetic', max_response_bytes=len(raw))
                    result = built.send_request(client.CommandRequest(id='fixture'))
                    self.assertIs(result.approved, not extra)
                    if extra:
                        self.assertIn('limit', result.error)

    def test_reads_request_at_most_remaining_plus_one(self):
        class Reader:
            def __init__(self): self.sizes = []; self.closed = False
            def read(self, size=-1):
                self.sizes.append(size)
                if size < 0: raise AssertionError('unbounded read')
                return b'x' * size
            recv = read
            def __enter__(self): return self
            def __exit__(self, *args): self.closed = True
            def settimeout(self, value): pass
            def connect(self, value): pass
            def sendall(self, value): pass
            def close(self): self.closed = True
        for kind in ('http', 'vsock'):
            reader = Reader()
            if kind == 'http':
                opener = type('Opener', (), {'open': lambda *a, **k: reader})()
                fixture = patch.object(client.urllib.request, 'build_opener', return_value=opener)
            else:
                fixture = patch.object(client.socket, 'socket', return_value=reader)
            built = client.client_from_config(transport=kind, auth_token='synthetic', max_response_bytes=5000)
            with fixture:
                result = built.send_request(client.CommandRequest(id='fixture'))
            self.assertIs(result.approved, False)
            self.assertEqual(sum(reader.sizes), 5001)
            self.assertLessEqual(max(reader.sizes), 4096)
            self.assertTrue(reader.closed)

    def test_real_plugin_invalid_replies_and_log_tail(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as home:
            with patch.dict(os.environ, {'HERMES_HOME': home, 'HOSTD_AUTH_TOKEN': 'synthetic'}, clear=True):
                for kind in ('http', 'vsock'):
                    for raw in (b'\xffsynthetic', b'{', b'[]', b'{"approved":true}',
                                b'{"id":"wrong","approved":true}', b'x' * 1048577):
                        with endpoint(kind, raw) as config, patch.dict(plugin._PLUGIN_SETTINGS, config, clear=True):
                            result = json.loads(plugin._handle_run_on_host({'command': ['echo']}))
                            self.assertIs(result['approved'], False)
                            self.assertTrue(result['error'])
                            self.assertNotIn('synthetic', result['error'])
                    def good(body):
                        return json.dumps(dict(id=body['id'], approved=True, exit_code=0,
                            stdout='tail' * 4096, stderr='tail' * 4096, log_id='opaque',
                            output_truncated=True, persistent_intent=True, future=[1])).encode() + b'\n'
                    with endpoint(kind, good) as config, patch.dict(plugin._PLUGIN_SETTINGS, config, clear=True):
                        result = json.loads(plugin._handle_run_on_host({'command': ['echo'], 'persistent_intent': True}))
                        self.assertIs(result['approved'], True)
                        self.assertEqual(result['log_id'], 'opaque')
                        self.assertIs(result['output_truncated'], True)
                        self.assertIs(result['persistent_intent'], True)
                        self.assertEqual(result['future'], [1])

    def test_plugin_response_limit_setting(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as home, patch.dict(
                os.environ, {'HERMES_HOME': home, 'HOSTD_AUTH_TOKEN': 'synthetic'}, clear=True):
            for kind in ('http', 'vsock'):
                with patch.dict(plugin._PLUGIN_SETTINGS, {'transport': kind, 'max_response_bytes': 1234}, clear=True):
                    self.assertEqual(plugin._build_client().transport.max_response_bytes, 1234)
                config = Path(home) / 'hostd-client.yaml'
                config.write_text('max_response_bytes: 4321\n')
                self.assertEqual(plugin._build_client().transport.max_response_bytes, 4321)
                config.unlink()

    def test_limit_configuration_rejects_nonfinite_or_nonstrict_values(self):
        for kind in ('http', 'vsock'):
            for value in (0, -1, True, None, 1.5, '100'):
                with self.assertRaises((ValueError, TypeError)):
                    client.client_from_config(transport=kind, auth_token='synthetic', max_response_bytes=value)


class WireTests(unittest.TestCase):
    def test_invalid_or_uncorrelated_wire_is_structured_and_sanitized(self):
        class Reply(client.Transport):
            def send(self, payload):
                if isinstance(self.raw, Exception):
                    raise self.raw
                return self.raw
        transport = Reply()
        for raw in ('{"id":"other","approved":true,"exit_code":0}',
                    '{"approved":true}', '{"id":"fixture","approved":"false"}',
                    '[]', 'null', 'true', '1', '"text"', '{', '',
                    '{"id":"fixture","approved":true,"approved":false}',
                    '{"id":"fixture","approved":true,"future":NaN}',
                    RuntimeError('synthetic-secret'), UnicodeError('synthetic-secret')):
            with self.subTest(kind=type(raw).__name__):
                transport.raw = raw
                result = client.HostdClient(transport).send_request(client.CommandRequest(id='fixture'))
                self.assertIs(result.approved, False)
                self.assertEqual(result.id, 'fixture')
                self.assertIsNotNone(result.error)
                self.assertLess(len(result.error), 200)
                self.assertNotIn('synthetic-secret', result.to_json())
                self.assertEqual(result.stdout, '')


class ResultTests(unittest.TestCase):
    def test_strict_result_fields(self):
        base = {'id': 'fixture', 'approved': False}
        invalid = {'approved': ['false', 'true', 0, 1, None, [], {}],
                   'id': [None, 1, True, [], {}],
                   'exit_code': [True, False, 0.0, '0', [], {}],
                   'stdout': [None, 1, [], {}], 'stderr': [None, False, []],
                   'error': [1, False, [], {}], 'log_id': [1, False, []],
                   'output_truncated': [0, None, 'false', []],
                   'persistent_intent': [0, None, 'false', []]}
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, kind=type(value).__name__):
                    with self.assertRaises((ValueError, TypeError)):
                        client.CommandResult.from_dict(dict(base, **{field: value}))
        for value in (None, [], 1, True, 'text', {}, {'id': 'fixture'}, {'approved': True}):
            with self.assertRaises((ValueError, TypeError)):
                client.CommandResult.from_dict(value)

    def test_metadata_and_ordinary_outcomes_roundtrip(self):
        for approved, code, error in ((False, None, 'denied'), (True, 0, None),
                (True, None, 'timeout'), (True, 0, 'capture error'), (True, 2, None)):
            wire = dict(id='fixture', approved=approved, exit_code=code, stdout='tail', stderr='',
                        error=error, log_id='opaque', output_truncated=True, persistent_intent=True,
                        future={'version': [1, 'compatible']})
            self.assertEqual(client.CommandResult.from_dict(wire).to_dict(), wire)


if __name__ == '__main__':
    unittest.main()
