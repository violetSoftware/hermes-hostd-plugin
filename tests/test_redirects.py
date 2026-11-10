"""Disposable loopback redirect fixtures; no command is ever executed."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import unittest

SPEC = importlib.util.spec_from_file_location('redirect_client', Path(__file__).resolve().parents[1] / 'client/client.py')
import sys
assert SPEC is not None and SPEC.loader is not None
client = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = client
SPEC.loader.exec_module(client)


class RedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seen = []
        cls.status = 200
        cls.location = None
        class Handler(BaseHTTPRequestHandler):
            def handle_request(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                cls.seen.append((self.server.server_address[1], self.path, self.command,
                                 self.headers.get('Authorization'), body))
                if self.path == '/execute':
                    self.send_response(cls.status)
                    if cls.location is not None:
                        self.send_header('Location', cls.location)
                    payload = (b'untrusted-response-secret' if cls.status != 200 else
                               json.dumps({'id': 'fixture', 'approved': True, 'exit_code': 0}).encode())
                else:
                    self.send_response(200)
                    payload = json.dumps({'id': 'fixture', 'approved': True, 'exit_code': 0}).encode()
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            do_GET = handle_request
            do_POST = handle_request
            def log_message(self, *args):
                pass
        cls.servers = [ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
        cls.threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in cls.servers]
        for thread in cls.threads:
            thread.start()
        cls.url = f'http://127.0.0.1:{cls.servers[0].server_port}/execute'

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(2)

    def setUp(self):
        self.seen.clear()

    def test_redirects_fail_without_forwarding(self):
        request = client.CommandRequest(id='fixture', command=['inert-secret'], description='synthetic')
        for status in (301, 302, 303, 307, 308):
            for location in ('/destination?location-secret',
                             f'http://127.0.0.1:{self.servers[0].server_port}/destination?location-secret',
                             f'http://127.0.0.1:{self.servers[1].server_port}/destination?location-secret'):
                with self.subTest(status=status, location=location):
                    self.seen.clear()
                    type(self).status, type(self).location = status, location
                    result = client.HostdClient(client.HttpClient(self.url, timeout=1, auth_token='synthetic-token')).send_request(request)
                    self.assertEqual(len(self.seen), 1, 'redirect destination received a request')
                    self.assertEqual(self.seen[0][3], 'Bearer synthetic-token')
                    self.assertEqual(self.seen[0][4], request.to_json().encode())
                    self.assertFalse(result.approved)
                    self.assertFalse(result.succeeded)
                    self.assertIn(f'redirect rejected ({status})', result.error)
                    self.assertIn('configure the actual endpoint', result.error)
                    for secret in ('synthetic-token', 'inert-secret', 'location-secret', 'untrusted-response-secret'):
                        self.assertNotIn(secret, result.error)

    def test_other_3xx_and_missing_location_fail_safely(self):
        for status in (300, 301, 302, 303, 304, 305, 306, 307, 308, 399):
            with self.subTest(status=status):
                type(self).status, type(self).location = status, None
                with self.assertRaisesRegex(RuntimeError, f'redirect rejected \\({status}\\).*configure the actual endpoint') as caught:
                    client.HttpClient(self.url, timeout=1, insecure_no_auth=True).send('{}')
                self.assertNotIn('untrusted-response-secret', str(caught.exception))

    def test_direct_success_preserves_request(self):
        type(self).status, type(self).location = 200, None
        request = client.CommandRequest(id='fixture', command=['inert'])
        result = client.HostdClient(client.HttpClient(self.url, timeout=1, auth_token='synthetic-token')).send_request(request)
        self.assertTrue(result.succeeded)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(self.seen[0][4], request.to_json().encode())


if __name__ == '__main__':
    unittest.main()
