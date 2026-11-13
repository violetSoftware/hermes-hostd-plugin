"""Subprocess acceptance probe; no daemon code or production config is read."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.abc
import json
import threading
import uuid
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


PLUGIN = Path(sys.argv.pop(1))
RUNTIME = Path(sys.argv.pop(1))
sys.path.insert(0, str(RUNTIME))
from agent.secret_scope import set_secret_scope, reset_secret_scope
SCOPE = set_secret_scope({'HOSTD_AUTH_TOKEN': 'synthetic-isolation'})
# Supplied by the parent harness; never fall back to a real checkout path.
FORBIDDEN_ROOTS = tuple(json.loads(os.environ["HOSTD_TEST_FORBIDDEN_ROOTS"]))
assert FORBIDDEN_ROOTS and all(isinstance(root, str) and os.path.isabs(root)
                               for root in FORBIDDEN_ROOTS)
ATTEMPTS = []


def check_path(path):
    if not isinstance(path, (str, bytes, os.PathLike)):
        return
    value = os.fsdecode(path)
    forbidden = any(value == root or value.startswith(root + "/")
                    for root in FORBIDDEN_ROOTS)
    # The fixture profile is empty. Never inspect any other runtime config.
    if value.endswith("hostd-client.yaml"):
        forbidden |= os.path.dirname(value) != os.environ["HERMES_HOME"]
    if forbidden:
        ATTEMPTS.append(value)
        raise AssertionError(f"Forbidden checkout/config access: {value}")


class CheckoutImportBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        for entry in list(sys.path) + list(path or []):
            check_path(entry)
        if fullname.split(".")[0] in {"hermes_hostd_client", "_hostd_client",
                                       "_hostd_mount_helper", "client"}:
            ATTEMPTS.append(fullname)
            raise AssertionError(f"Forbidden legacy/global import: {fullname}")
        return None


def audit(event, args):
    if event == "open":
        check_path(args[0])
    elif event == "import" and len(args) > 1:
        check_path(args[1])
    elif event == "socket.connect":
        if args[1][0] != "127.0.0.1":
            raise AssertionError(f"Non-loopback connection forbidden: {args[1]}")


def guarded(original):
    def wrapped(path, *args, **kwargs):
        check_path(path)
        return original(path, *args, **kwargs)
    return wrapped


sys.addaudithook(audit)
sys.meta_path.insert(0, CheckoutImportBlocker())


class IsolatedPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.initial_path = list(sys.path)
        guards = ExitStack()
        cls.addClassCleanup(guards.close)
        guards.enter_context(patch.object(Path, "resolve", guarded(Path.resolve)))
        guards.enter_context(patch.object(os, "stat", guarded(os.stat)))
        guards.enter_context(patch.object(os, "lstat", guarded(os.lstat)))
        original_spec = importlib.util.spec_from_file_location

        def safe_spec(name, location, *args, **kwargs):
            check_path(location)
            return original_spec(name, location, *args, **kwargs)

        guards.enter_context(patch.object(importlib.util, "spec_from_file_location", safe_spec))
        # Hermes-style package loading: register the package before execution.
        spec = safe_spec("relocated_hostd", PLUGIN / "__init__.py",
                         submodule_search_locations=[str(PLUGIN)])
        assert spec is not None and spec.loader is not None
        cls.plugin = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.plugin
        spec.loader.exec_module(cls.plugin)

    def test_fixture_checkout_guards_reject_access(self):
        self.assertEqual(ATTEMPTS, [], "Only deliberate guard probes may be rejected")
        roots = json.loads(os.environ["HOSTD_TEST_FORBIDDEN_ROOTS"])
        self.assertTrue(roots, "The isolation probe requires forbidden fixtures")
        for root in roots:
            for path in (Path(root), Path(root) / "fixture.txt"):
                operations = {
                    "resolve": path.resolve,
                    "stat": path.stat,
                    "lstat": path.lstat,
                    "open": path.read_bytes,
                    "import_spec": lambda: importlib.util.spec_from_file_location(
                        "forbidden_fixture", path),
                }
                for name, operation in operations.items():
                    with self.subTest(root=root, path=path, operation=name):
                        try:
                            with self.assertRaisesRegex(
                                    AssertionError, "Forbidden checkout/config access"):
                                operation()
                            self.assertEqual(ATTEMPTS, [str(path)])
                        finally:
                            ATTEMPTS.clear()
            with self.subTest(root=root, operation="import_discovery"):
                try:
                    with patch.object(sys, "path", [root]):
                        with self.assertRaisesRegex(
                                AssertionError, "Forbidden checkout/config access"):
                            CheckoutImportBlocker().find_spec("fixture_dependency")
                    self.assertEqual(ATTEMPTS, [root])
                finally:
                    ATTEMPTS.clear()

    def test_permitted_fixture_access_works(self):
        path = PLUGIN.parent / "permitted-checkout" / "fixture.txt"
        self.assertEqual(path.resolve(), path)
        self.assertGreater(path.stat().st_size, 0)
        self.assertGreater(path.lstat().st_size, 0)
        self.assertEqual(path.read_text(encoding="utf-8"), "permitted fixture")
        self.assertEqual(ATTEMPTS, [])

    def test_bundled_client_is_loaded_without_legacy_access(self):
        self.assertEqual(ATTEMPTS, [], "Legacy lookup must never be attempted")
        self.assertTrue(self.plugin._CLIENT_AVAILABLE, self.plugin._CLIENT_IMPORT_ERROR)
        self.assertEqual(sys.path, self.initial_path)
        self.assertEqual(Path(self.plugin._client_mod.__file__).parent, PLUGIN / "client")
        self.assertFalse((PLUGIN / "client/mount_helper.py").exists())
        self.assertFalse(hasattr(self.plugin, '_mount_mod'))
        package = sys.modules[self.plugin.__name__ + '.client']
        for name in ('mount_helper', 'mount_folder', 'unmount_folder'):
            self.assertFalse(hasattr(package, name))
            self.assertFalse(hasattr(self.plugin._client_mod, name))
        with self.assertRaises(ModuleNotFoundError):
            __import__(self.plugin.__name__ + '.client.mount_helper')
    def test_incomplete_copy_reports_bundled_dependency_error(self):
        # A distinct package whose search path contains no client package.
        spec = importlib.util.spec_from_file_location(
            "incomplete_hostd", PLUGIN / "__init__.py",
            submodule_search_locations=[str(PLUGIN / "missing")])
        assert spec is not None and spec.loader is not None
        plugin = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = plugin
        spec.loader.exec_module(plugin)
        self.assertFalse(plugin._CLIENT_AVAILABLE)
        for handler in (plugin._handle_run_on_host,):
            result = json.loads(handler({}))
            self.assertFalse(result["success"])
            self.assertIn("bundled hermes-hostd client", result["error"])
            self.assertIn("complete plugin directory", result["error"])
        self.assertEqual(ATTEMPTS, [])

    def test_registration_keeps_only_run_on_host(self):
        class Context:
            def __init__(self):
                self.tools = []

            def register_tool(self, *, name, toolset, schema, handler):
                self.tools.append((name, toolset, schema, handler))

            def register_hook(self, name, callback):
                assert name == "pre_tool_call" and callable(callback)

        ctx = Context()
        self.plugin.register(ctx)
        self.assertEqual([tool[0] for tool in ctx.tools],
                         ["run_on_host"])
        self.assertEqual(len(ctx.tools), 1)
        for name, toolset, schema, handler in ctx.tools:
            self.assertEqual(toolset, "hostd")
            self.assertEqual(schema["name"], name)
            self.assertNotIn("function", schema)
            self.assertTrue(callable(handler))

    def test_http_default_is_loopback_without_changing_vsock_default(self):
        client_mod = self.plugin._client_mod
        expected_url = "http://127.0.0.1:9998/execute"
        self.assertEqual(client_mod.HttpClient.DEFAULT_URL, expected_url)
        self.assertEqual(client_mod.HttpClient(auth_token='synthetic-isolation').url, expected_url)
        self.assertEqual(client_mod.client_from_config(transport="http", auth_token="synthetic-isolation").transport.url,
                         expected_url)
        self.assertEqual(self.plugin._PLUGIN_SETTINGS, {})
        with patch.dict(self.plugin._PLUGIN_SETTINGS, {"transport": "http"}, clear=True):
            self.assertEqual(self.plugin._build_client().transport.url, expected_url)
        for client in (client_mod.client_from_config(auth_token='synthetic-isolation'), self.plugin._build_client()):
            self.assertIsInstance(client.transport, client_mod.VsockClient)
            self.assertEqual(client.transport.port, 9999)
            self.assertEqual(client.transport.HOST_CID, 2)

    def test_stale_transport_environment_is_ignored_for_all_config_sources(self):
        client_mod = self.plugin._client_mod
        config = Path(os.environ['HERMES_HOME']) / 'hostd-client.yaml'
        self.addCleanup(lambda: config.unlink(missing_ok=True))
        stale_values = (
            {'HOSTD_TRANSPORT': 'http', 'HOSTD_VSOCK_PORT': '1234',
             'HOSTD_HTTP_URL': 'http://127.0.0.1:1234/stale'},
            {'HOSTD_TRANSPORT': 'vsock', 'HOSTD_VSOCK_PORT': '2345',
             'HOSTD_HTTP_URL': 'http://127.0.0.1:2345/stale'},
            {'HOSTD_TRANSPORT': 'invalid', 'HOSTD_VSOCK_PORT': 'invalid',
             'HOSTD_HTTP_URL': 'invalid'},
        )
        cases = (
            ({}, {}, 'vsock', 9999),
            ({'transport': 'http'}, {}, 'http', client_mod.HttpClient.DEFAULT_URL),
            ({'transport': 'vsock', 'vsock_port': 4567}, {}, 'vsock', 4567),
            ({'transport': 'http', 'http_url': 'http://127.0.0.1:4567/execute'},
             {}, 'http', 'http://127.0.0.1:4567/execute'),
            ({'transport': 'http', 'vsock_port': 4567},
             {'transport': 'vsock', 'vsock_port': 7654}, 'vsock', 7654),
            ({'transport': 'vsock', 'http_url': 'http://127.0.0.1:4567/execute'},
             {'transport': 'http', 'http_url': 'http://127.0.0.1:7654/execute'},
             'http', 'http://127.0.0.1:7654/execute'),
        )
        for settings, flat, kind, expected in cases:
            config.unlink(missing_ok=True)
            if flat:
                config.write_text(''.join(f'{key}: {value}\n' for key, value in flat.items()))
            for stale in stale_values:
                with self.subTest(settings=settings, flat=flat, stale=stale), patch.dict(
                        self.plugin._PLUGIN_SETTINGS, settings, clear=True), patch.dict(os.environ, stale):
                    transport = self.plugin._build_client().transport
                    if kind == 'http':
                        self.assertIsInstance(transport, client_mod.HttpClient)
                        self.assertEqual(transport.url, expected)
                    else:
                        self.assertIsInstance(transport, client_mod.VsockClient)
                        self.assertEqual(transport.port, expected)

    def test_manifest_defaults_match_runtime(self):
        # Read only the manifest's simple scalar defaults; no YAML dependency.
        defaults = {}
        field = None
        in_schema = False
        for line in (PLUGIN / "plugin.yaml").read_text(encoding="utf-8").splitlines():
            if line == "config_schema:":
                in_schema = True
            elif in_schema and line.startswith("  ") and not line.startswith("   "):
                field = line.strip().removesuffix(":")
            elif in_schema and line.startswith("    default:"):
                defaults[field] = line.partition(":")[2].strip()
        client_mod = self.plugin._client_mod
        self.assertEqual(defaults, {
            "transport": "vsock", "vsock_port": "9999",
            "http_url": "http://127.0.0.1:9998/execute",
            "insecure_no_auth": "false", "max_response_bytes": "1048576",
        })
        manifest_client = client_mod.client_from_config(
            transport=defaults["transport"], vsock_port=int(defaults["vsock_port"]),
            http_url=defaults["http_url"], auth_token="synthetic-isolation")
        self.assertIsInstance(manifest_client.transport, client_mod.VsockClient)
        self.assertEqual(manifest_client.transport.port,
                         client_mod.client_from_config(auth_token='synthetic-isolation').transport.port)
        self.assertEqual(defaults["http_url"], client_mod.HttpClient.DEFAULT_URL)
        with patch.dict(self.plugin._PLUGIN_SETTINGS, defaults, clear=True):
            self.assertIsInstance(self.plugin._build_client().transport,
                                  client_mod.VsockClient)
            with patch.dict(self.plugin._PLUGIN_SETTINGS, {"transport": "http"}):
                self.assertEqual(self.plugin._build_client().transport.url,
                                 client_mod.HttpClient.DEFAULT_URL)

    def test_declared_settings_are_used_below_active_profile_file(self):
        class Context:
            def get_config(self, key, default=None):
                return {"transport": "http", "vsock_port": 4567,
                        "http_url": "http://127.0.0.1:4567/execute"}.get(key, default)

            def register_tool(self, **kwargs):
                pass

            def register_hook(self, name, callback):
                assert name == "pre_tool_call" and callable(callback)

        self.plugin.register(Context())
        self.addCleanup(lambda: getattr(self.plugin, "_PLUGIN_SETTINGS", {}).clear())
        client = self.plugin._build_client()
        self.assertIsInstance(client.transport, self.plugin._client_mod.HttpClient)
        self.assertEqual(client.transport.url, "http://127.0.0.1:4567/execute")
        explicit_url = "http://127.0.0.1:19998/execute"
        self.assertEqual(self.plugin._client_mod.HttpClient(url=explicit_url, auth_token="synthetic-isolation").url,
                         explicit_url)
        self.assertEqual(self.plugin._client_mod.client_from_config(
            transport="http", http_url=explicit_url, auth_token="synthetic-isolation").transport.url, explicit_url)
        home = Path(os.environ["HERMES_HOME"])
        home.mkdir(exist_ok=True)
        config = home / "hostd-client.yaml"
        config.write_text("transport: vsock\nvsock_port: 7654\n", encoding="utf-8")
        self.addCleanup(config.unlink)
        client = self.plugin._build_client()
        self.assertIsInstance(client.transport, self.plugin._client_mod.VsockClient)
        self.assertEqual(client.transport.port, 7654)
        config.write_text(f"transport: http\nhttp_url: {explicit_url}\n", encoding="utf-8")
        self.assertEqual(self.plugin._build_client().transport.url, explicit_url)

    def test_run_handler_round_trips_over_real_loopback_http(self):
        captured = []
        responses = []

        class FixtureHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                captured.append((self.path, self.headers["Content-Type"], request))
                response = {"id": request["id"], "approved": False,
                            "exit_code": None, "stdout": "inert fixture stdout",
                            "stderr": "inert fixture stderr", "error": "fixture only",
                            "log_id": "fixture-log", "output_truncated": True}
                responses.append(response)
                body = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), FixtureHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.dict(self.plugin._PLUGIN_SETTINGS, {
                    "transport": "http",
                    "http_url": f"http://127.0.0.1:{server.server_port}/execute",
                }, clear=True):
                    result = json.loads(self.plugin._handle_run_on_host({
                        "description": "inert loopback acceptance fixture",
                        "command": ["fixture-only", "argument with spaces"], "timeout": 7,
                    }))
            finally:
                server.shutdown()
                thread.join(timeout=5)
        self.assertEqual(len(captured), 1)
        path, content_type, request = captured[0]
        self.assertEqual(path, "/execute")
        self.assertEqual(content_type, "application/json")
        self.assertEqual(set(request), {"id", "description", "command", "timeout", "persistent_intent"})
        self.assertIs(request['persistent_intent'], False)
        self.assertEqual(str(uuid.UUID(request["id"])), request["id"])
        self.assertEqual(request["command"], ["fixture-only", "argument with spaces"])
        self.assertEqual(request["description"], "inert loopback acceptance fixture")
        self.assertEqual(request["timeout"], 7)
        self.assertEqual(result, responses[0])
        self.assertEqual(ATTEMPTS, [])

    def test_ordinary_incus_argv_preserves_explicit_identity_without_execution(self):
        client_mod = self.plugin._client_mod
        payloads = []
        commands = [
            ["incus", "config", "device", "add", "fixture-vm", "explicit-data-device",
             "disk", "source=/host/data folder", "path=/mnt/data folder"],
            ["incus", "config", "device", "remove", "fixture-vm", "explicit-data-device"],
        ]
        class RecordingTransport(client_mod.Transport):
            def send(self, payload):
                request = json.loads(payload)
                payloads.append(request)
                return json.dumps({"id": request["id"], "approved": False,
                                   "error": "inert command fixture"})

        client = client_mod.HostdClient(RecordingTransport())
        for command in commands:
            description = "Synthetic explicit device operation; do not execute"
            with patch.object(self.plugin, '_build_client', return_value=client):
                result = json.loads(self.plugin._handle_run_on_host({
                    'command': command, 'description': description, 'timeout': 30}))
            self.assertEqual(payloads[-1]['command'], command)
            self.assertEqual(payloads[-1]['description'], description)
            self.assertEqual(payloads[-1]['timeout'], 30)
            self.assertIs(payloads[-1]['persistent_intent'], False)
            self.assertEqual(result['id'], payloads[-1]['id'])
            self.assertIs(result['approved'], False)
            self.assertEqual(result['error'], 'inert command fixture')


if __name__ == "__main__":
    unittest.main(verbosity=2)
