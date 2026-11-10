"""Synthetic credentials through bundled transports and real plugin settings."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('auth_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
assert spec is not None and spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
client = plugin._client_mod
TOKEN = 'synthetic-requester-credential'


class ClientAuthTests(unittest.TestCase):
    def test_vsock_transport_metadata_not_operation(self):
        received = []
        left, right = socket.socketpair()
        def server():
            with right:
                received.append(json.loads(right.makefile('rb').readline()))
                right.sendall(b'{"id":"fixture","approved":false}\n')
        thread = threading.Thread(target=server)
        thread.start()
        # Only replace AF_VSOCK creation/connect: exercise real stream send/receive.
        class FixtureSocket:
            def settimeout(self, value): left.settimeout(value)
            def connect(self, address): pass
            def sendall(self, value): left.sendall(value)
            def recv(self, size): return left.recv(size)
            def close(self): left.close()
        try:
            transport = client.VsockClient(auth_token=TOKEN)
            with patch.object(client.socket, 'socket', return_value=FixtureSocket()):
                result = client.HostdClient(transport).send_request(client.CommandRequest(id='fixture', command=['echo']))
            self.assertNotIn(TOKEN, result.to_json())
            self.assertEqual(received[0].pop('auth'), {'token': TOKEN})
            self.assertNotIn(TOKEN, json.dumps(received))
        finally:
            left.close()
            right.close()
            thread.join(2)

    def test_plugin_env_token_is_forwarded_to_both_transports(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as home:
            with patch.dict(os.environ, {'HERMES_HOME': home, 'HOSTD_AUTH_TOKEN': TOKEN}, clear=True):
                for transport in ('http', 'vsock'):
                    with patch.dict(os.environ, {'HOSTD_TRANSPORT': transport}):
                        built = plugin._build_client()
                        self.assertEqual(built.transport.auth_token, TOKEN)
                        self.assertNotIn(TOKEN, repr(built.transport))

    def test_secret_file_precedence_failure_and_explicit_insecure(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as home:
            path = Path(home) / 'requester.token'
            path.write_text(TOKEN + '\n')
            path.chmod(0o600)
            with patch.dict(os.environ, {'HERMES_HOME': home}, clear=True), patch.dict(
                    plugin._PLUGIN_SETTINGS, {'auth_token_file': str(path)}, clear=True):
                self.assertEqual(plugin._build_client().transport.auth_token, TOKEN)
                config = Path(home) / 'hostd-client.yaml'
                config.write_text('auth_token_file: /nonexistent-synthetic-token\n')
                with self.assertRaisesRegex(ValueError, 'private owned regular file'):
                    plugin._build_client()
                with patch.dict(os.environ, {'HOSTD_AUTH_TOKEN_FILE': str(path)}):
                    self.assertEqual(plugin._build_client().transport.auth_token, TOKEN)
                    with patch.dict(os.environ, {'HOSTD_AUTH_TOKEN': 'synthetic-env-priority'}):
                        self.assertEqual(plugin._build_client().transport.auth_token, 'synthetic-env-priority')
                    with patch.dict(os.environ, {'HOSTD_AUTH_TOKEN': ''}):
                        with self.assertRaises(ValueError):
                            plugin._build_client()
                plugin._PLUGIN_SETTINGS.clear()
                config.write_text('insecure_no_auth: true\n')
                with self.assertLogs(level='WARNING'):
                    self.assertIsNone(plugin._build_client().transport.auth_token)
                for invalid in ('TRUE', '1', 'yes', 'null', ''):
                    config.write_text('insecure_no_auth: ' + invalid + '\n')
                    with self.assertRaises(ValueError):
                        plugin._build_client()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                client.read_token_file(path)
            path.chmod(0o600)
            link = Path(home) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                client.read_token_file(link)

    def test_unsafe_url_and_secret_echo_errors_are_not_exposed(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        for suffix in ('?token=synthetic', '#secret'):
            with self.assertRaisesRegex(ValueError, 'endpoint'):
                client.HttpClient('http://127.0.0.1/execute' + suffix, auth_token=TOKEN)
        with self.assertRaisesRegex(ValueError, 'endpoint'):
            client.HttpClient('http://user:password@127.0.0.1/execute', auth_token=TOKEN)
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(self.headers['Authorization'].encode())
            def log_message(self, format, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            result = client.HostdClient(client.HttpClient(
                f'http://127.0.0.1:{server.server_port}/execute', auth_token=TOKEN)).send_request(
                    client.CommandRequest(command=['echo']))
            self.assertNotIn(TOKEN, result.to_json())
            self.assertIn('401', result.error)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_omitted_client_config_fails_and_explicit_insecure_works(self):
        with patch.dict(os.environ, {}, clear=True):
            for transport in ('http', 'vsock'):
                with self.assertRaisesRegex(ValueError, 'requester token'):
                    client.client_from_config(transport=transport)
                self.assertIsNotNone(client.client_from_config(transport=transport, insecure_no_auth=True))


if __name__ == '__main__':
    unittest.main()
