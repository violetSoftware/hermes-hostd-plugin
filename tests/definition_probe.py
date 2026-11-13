"""Exercise the installed public PluginContext -> real registry boundary offline."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

PLUGIN = Path(sys.argv.pop(1)).resolve()
RUNTIME = Path(sys.argv.pop(1)).resolve()
HOME = Path(os.environ["HOME"]).resolve()
assert Path(os.environ["HERMES_HOME"]).is_relative_to(HOME)


def audit(event, args):
    if event in {'socket.connect', 'socket.bind'}:
        address = args[1]
        if not isinstance(address, tuple) or address[0] != '127.0.0.1':
            raise AssertionError('Only disposable loopback allowed')
    if event in {"subprocess.Popen", "os.system"}:
        raise AssertionError(f"External execution/network forbidden: {event}")
    if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(args[0])).absolute()
        mode, flags = args[1:3]
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        if writing:
            assert path.is_relative_to(HOME), f"Write outside fixture: {path}"
        else:
            allowed = (HOME, PLUGIN, RUNTIME, Path(sys.base_prefix), Path(sys.prefix))
            assert any(path.is_relative_to(root) for root in allowed), (
                f"Read outside fixture/runtime/source: {path}")


sys.addaudithook(audit)
sys.path.insert(0, str(RUNTIME))
# Unrelated bundled providers probe platform subprocesses during config imports.
# Keep their discovery outside this tool-definition boundary test.
import providers
providers._BUNDLED_PLUGINS_DIR = HOME / "no-bundled-providers"
from hermes_constants import get_hermes_home
from hermes_cli.plugins import PluginContext, PluginManager, parse_manifest_file
from tools.registry import registry

assert Path(get_hermes_home()).resolve() == Path(os.environ["HERMES_HOME"])
manifest = parse_manifest_file(PLUGIN / "plugin.yaml", PLUGIN, "user", "")
assert manifest is not None
manager = PluginManager(scope_key=os.environ["HERMES_HOME"])
spec = importlib.util.spec_from_file_location(
    "definition_hostd", PLUGIN / "__init__.py", submodule_search_locations=[str(PLUGIN)])
assert spec is not None and spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
plugin.register(PluginContext(manifest, manager))
NAMES = {"run_on_host", "mount_host_folder", "unmount_host_folder"}
DEFINITIONS = registry.get_definitions(NAMES)
FUNCTIONS = {item["function"]["name"]: item["function"] for item in DEFINITIONS}


class DefinitionTests(unittest.TestCase):
    def test_registered_hook_uses_native_gate_before_daemon_dispatch(self):
        import json
        from unittest.mock import patch
        from hermes_cli.plugins import resolve_pre_tool_block
        assert manifest is not None
        self.assertIn('pre_tool_call', manifest.provides_hooks)
        callbacks = manager._hooks['pre_tool_call']
        self.assertTrue(callbacks)
        args = {'command': ['echo', 'two words'], 'description': 'synthetic host action'}
        def invoke(name, **kwargs):
            self.assertEqual(name, 'pre_tool_call')
            return [callback(**kwargs) for callback in callbacks]
        entry = registry.get_entry('run_on_host')
        assert entry is not None
        def dispatch():
            blocked = resolve_pre_tool_block('run_on_host', args)
            return blocked if blocked else entry.handler(args)
        with patch('hermes_cli.lifecycle.invoke_hook', side_effect=invoke):
            for decision in ({'approved': False, 'message': 'denied'},
                             {'approved': False, 'message': 'timed out'},
                             RuntimeError('synthetic gate failure')):
                with self.subTest(decision=decision):
                    with patch('tools.approval.request_tool_approval') as gate, \
                         patch.object(plugin, '_build_client') as build:
                        if isinstance(decision, Exception):
                            gate.side_effect = decision
                        else:
                            gate.return_value = decision
                        self.assertTrue(dispatch())
                        gate.assert_called_once()
                        self.assertEqual(gate.call_args.kwargs['rule_key'], 'run_on_host')
                        self.assertIn(json.dumps(args['command']), gate.call_args.args[1])
                        build.assert_not_called()
            # Native approval permits dispatch, but never overrides daemon denial.
            with patch('tools.approval.request_tool_approval', return_value={'approved': True}), \
                 patch.object(plugin, '_build_client') as build:
                build.return_value.send_request.return_value.to_json.return_value = '{"approved": false}'
                self.assertIs(json.loads(dispatch())['approved'], False)
                build.return_value.send_request.assert_called_once()

    def test_managed_secret_is_resolved_lazily_for_each_routed_call(self):
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        from unittest.mock import patch
        profile = HOME / 'managed-profile'
        profile.mkdir(exist_ok=True)
        context = PluginContext(manifest, manager)
        with patch('hermes_cli.plugins.load_config_readonly', return_value={}):
            plugin.register(context)
        override = set_hermes_home_override(profile)
        try:
            with patch.dict(os.environ, {'HOSTD_AUTH_TOKEN': 'synthetic-process-only'}):
                for token in ('synthetic-profile-one', 'synthetic-profile-two'):
                    scope = set_secret_scope({'HOSTD_AUTH_TOKEN': token}, profile_home=str(profile))
                    try:
                        for transport in ('http', 'vsock'):
                            with patch.dict(os.environ, {'HOSTD_TRANSPORT': transport}):
                                self.assertTrue(plugin._build_client().transport.auth_token == token)
                    finally:
                        reset_secret_scope(scope)
        finally:
            reset_hermes_home_override(override)
            plugin._PLUGIN_SETTINGS.clear()

    def test_legacy_context_selector_is_rejected_even_with_managed_secret(self):
        import json
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        from unittest.mock import patch
        assert manifest is not None
        settings = {'plugins': {'entries': {'hostd-client': {'settings': {
            'auth_token_file': '/synthetic-secret-path-never-open'}}}}}
        scope = set_secret_scope({'HOSTD_AUTH_TOKEN': 'synthetic-context-token'})
        try:
            with patch('hermes_cli.plugins.load_config_readonly', return_value=settings):
                plugin.register(PluginContext(manifest, manager))
            result = registry.get_entry('run_on_host').handler({'command': ['echo']})
            self.assertIs(json.loads(result)['success'], False)
            self.assertIn('removed', result)
            self.assertNotIn('/synthetic-secret-path', result)
        finally:
            reset_secret_scope(scope)
            plugin._PLUGIN_SETTINGS.clear()

    def test_manifest_declares_managed_credential_only(self):
        assert manifest is not None
        self.assertEqual(manifest.requires_env, ['HOSTD_AUTH_TOKEN'])
        text = (PLUGIN / 'plugin.yaml').read_text()
        optional = text.split('optional_env:', 1)[1].split('python_dependencies:', 1)[0]
        self.assertNotIn('HOSTD_AUTH_TOKEN', optional)
        self.assertNotIn('auth_token_file', manifest.config_schema)
        self.assertEqual(manifest.version, '0.1.0rc2')

    def test_only_run_on_host_with_exactly_one_provider_wrapper(self):
        self.assertEqual(set(FUNCTIONS), {'run_on_host'})
        self.assertEqual(len(DEFINITIONS), 1)
        for definition in DEFINITIONS:
            with self.subTest(tool=definition["function"]["name"]):
                self.assertEqual(set(definition), {"type", "function"})
                self.assertEqual(definition["type"], "function")
                function = definition["function"]
                self.assertNotIn("function", function)
                self.assertNotIn("type", function)
                self.assertTrue(function["description"].strip())
                entry = registry.get_entry(function["name"])
                self.assertIsNotNone(entry)
                assert entry is not None
                self.assertEqual(entry.toolset, "hostd")

    def assert_parameters(self, name, types, required):
        function = FUNCTIONS[name]
        self.assertTrue(function.get("description", "").strip(), name)
        parameters = function.get("parameters", {})
        self.assertEqual(parameters.get("type"), "object", name)
        properties = parameters["properties"]
        self.assertEqual({key: value["type"] for key, value in properties.items()}, types)
        self.assertEqual(set(parameters["required"]), set(required))
        for value in properties.values():
            self.assertTrue(value["description"].strip())
        return properties

    def test_run_on_host_exposes_argv_description_and_integer_timeout(self):
        properties = self.assert_parameters("run_on_host", {
            "command": "array", "description": "string", "timeout": "integer",
            "persistent_intent": "boolean",
        }, {"command", "description"})
        self.assertEqual(properties["command"]["items"], {"type": "string"})
        self.assertIn("Pass 0", properties["timeout"]["description"])
        self.assertIs(properties['persistent_intent']['default'], False)
        self.assertIn('metadata only', properties['persistent_intent']['description'])

    def test_registered_handler_preserves_marker_and_timeout_in_real_client_wire(self):
        import json
        from unittest.mock import patch
        entry = registry.get_entry('run_on_host')
        captured = []
        class CaptureTransport(plugin._client_mod.Transport):
            def send(self, payload):
                wire = json.loads(payload)
                captured.append(wire)
                return json.dumps({'id': wire['id'], 'approved': False})
        def client(socket_timeout):
            captured.append(socket_timeout)
            return plugin._client_mod.HostdClient(CaptureTransport())
        for marker in ('omitted', False, True):
            for timeout in (0, 7):
                args = {'description': 'synthetic', 'command': ['echo'], 'timeout': timeout}
                if marker != 'omitted':
                    args['persistent_intent'] = marker
                with patch.object(plugin, '_build_client', side_effect=client):
                    result = json.loads(entry.handler(args))
                self.assertIs(result['approved'], False)
                self.assertIs(captured[-1]['persistent_intent'], marker is True)
                self.assertEqual(captured[-1]['timeout'], timeout)
                self.assertEqual(captured[-2], None if timeout == 0 else 37.0)
        for marker in (None, 0, 1, 'true', [], {}):
            with patch.object(plugin, '_build_client') as build:
                result = json.loads(entry.handler({'description': 'synthetic', 'command': ['echo'],
                                                   'persistent_intent': marker}))
                self.assertIs(result['success'], False)
                self.assertIn('persistent_intent', result['error'])
                build.assert_not_called()

    def test_registered_auth_settings_and_real_http_and_vsock_wire(self):
        import json
        import socket
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch
        token = 'synthetic-context-requester'
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        scope = set_secret_scope({'HOSTD_AUTH_TOKEN': token})
        self.addCleanup(reset_secret_scope, scope)
        context = PluginContext(manifest, manager)
        settings = {'plugins': {'entries': {'hostd-client': {'settings': {
            'transport': 'http'}}}}}
        with patch('hermes_cli.plugins.load_config_readonly', return_value=settings):
            plugin.register(context)
        self.assertNotIn('auth_token_file', manifest.config_schema)
        self.assertNotIn(token, repr(plugin._PLUGIN_SETTINGS))
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                seen.append((self.headers.get('Authorization'), body))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'id': body['id'], 'approved': False}).encode())
            def log_message(self, format, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        entry = registry.get_entry('run_on_host')
        assert entry is not None
        try:
            with patch.dict(os.environ, {'HOSTD_HTTP_URL': f'http://127.0.0.1:{server.server_port}/execute'}):
                result = entry.handler({'command': ['echo'], 'description': 'synthetic'})
            self.assertNotIn(token, result)
            self.assertEqual(seen[0][0], 'Bearer ' + token)
            self.assertNotIn(token, json.dumps(seen[0][1]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(2)
        frames = []
        def receive():
            conn, _ = listener.accept()
            with conn:
                frame = json.loads(conn.makefile('rb').readline())
                frames.append(frame)
                conn.sendall(json.dumps({'id': frame['id'], 'approved': False}).encode() + b'\n')
        thread = threading.Thread(target=receive)
        thread.start()
        real_socket = socket.socket
        class LoopbackSocket:
            def __init__(self): self.sock = real_socket()
            def settimeout(self, value): self.sock.settimeout(value)
            def connect(self, address): self.sock.connect(listener.getsockname())
            def sendall(self, value): self.sock.sendall(value)
            def recv(self, size): return self.sock.recv(size)
            def close(self): self.sock.close()
        try:
            with patch.dict(os.environ, {'HOSTD_TRANSPORT': 'vsock'}), patch.object(
                    plugin._client_mod.socket, 'socket', side_effect=lambda *a, **k:
                        LoopbackSocket() if a and a[0] == socket.AF_VSOCK else real_socket(*a, **k)):
                result = entry.handler({'command': ['echo'], 'description': 'synthetic'})
            self.assertNotIn(token, result)
            self.assertEqual(frames[0].pop('auth'), {'token': token})
            self.assertNotIn(token, json.dumps(frames))
        finally:
            listener.close()
            thread.join(2)
        for definition in registry.get_definitions(NAMES):
            self.assertNotIn('auth_token', json.dumps(definition))
        plugin._PLUGIN_SETTINGS.clear()

    def test_registered_malformed_success_response_diagnostics_are_secret_safe(self):
        import contextlib
        import io
        import json
        import logging
        import socket
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch
        token = 'synthetic-malformed-response-credential'
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        scope = set_secret_scope({'HOSTD_AUTH_TOKEN': token})
        self.addCleanup(reset_secret_scope, scope)
        context = PluginContext(manifest, manager)
        settings = {'plugins': {'entries': {'hostd-client': {'settings': {
            'transport': 'http'}}}}}
        with patch('hermes_cli.plugins.load_config_readonly', return_value=settings):
            plugin.register(context)
        entry = registry.get_entry('run_on_host')
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                seen.append(self.headers.get('Authorization') == 'Bearer ' + token)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.headers['Authorization'].encode())
            def log_message(self, format, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        logging.getLogger().addHandler(handler)
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with patch.dict(os.environ, {'HOSTD_TRANSPORT': 'http',
                        'HOSTD_HTTP_URL': f'http://127.0.0.1:{server.server_port}/execute'}):
                    http_result = entry.handler({'command': ['echo'], 'description': 'synthetic'})
                left, right = socket.socketpair()
                def receive():
                    with right, right.makefile('rb') as stream:
                        frame = json.loads(stream.readline())
                        seen.append(frame['auth']['token'] == token)
                        right.sendall(frame['auth']['token'].encode() + b'\n')
                peer = threading.Thread(target=receive)
                peer.start()
                real_socket = socket.socket
                class StreamSocket:
                    def settimeout(self, value): left.settimeout(value)
                    def connect(self, address): pass
                    def sendall(self, value): left.sendall(value)
                    def recv(self, size): return left.recv(size)
                    def close(self): left.close()
                try:
                    with patch.dict(os.environ, {'HOSTD_TRANSPORT': 'vsock'}), patch.object(
                            plugin._client_mod.socket, 'socket', side_effect=lambda *a, **k:
                                StreamSocket() if a and a[0] == socket.AF_VSOCK else real_socket(*a, **k)):
                        vsock_result = entry.handler({'command': ['echo'], 'description': 'synthetic'})
                finally:
                    left.close()
                    peer.join(2)
                    right.close()
                for result in (http_result, vsock_result):
                    # Boolean assertions keep even a failing test from printing credentials.
                    self.assertFalse(token in result)
                    parsed = json.loads(result)
                    self.assertIs(parsed['approved'], False)
                    self.assertEqual(parsed['error'], 'Failed to parse host daemon response')
            self.assertEqual(seen, [True, True])
            self.assertFalse(token in output.getvalue())
        finally:
            logging.getLogger().removeHandler(handler)
            server.shutdown()
            server.server_close()
            thread.join(2)
            plugin._PLUGIN_SETTINGS.clear()

    def test_scoped_missing_empty_invalid_and_unscoped_fail_closed(self):
        import contextlib
        import io
        import json
        import logging
        from agent.secret_scope import (set_secret_scope, reset_secret_scope,
            set_multiplex_context, reset_multiplex_context)
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        from unittest.mock import patch
        profile = HOME / 'missing-managed-profile'
        profile.mkdir(exist_ok=True)
        context = PluginContext(manifest, manager)
        with patch('hermes_cli.plugins.load_config_readonly', return_value={}):
            plugin.register(context)
        entry = registry.get_entry('run_on_host')
        assert entry is not None
        override = set_hermes_home_override(profile)
        multiplex = set_multiplex_context(True)
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        logging.getLogger().addHandler(handler)
        try:
            with patch.dict(os.environ, {'HOSTD_AUTH_TOKEN': 'synthetic-process-only'}), patch.object(
                    plugin._client_mod, 'client_from_config', wraps=plugin._client_mod.client_from_config) as factory:
                for mapping in ({}, {'HOSTD_AUTH_TOKEN': ''}, {'HOSTD_AUTH_TOKEN': 'synthetic secret\n'},
                                {'HOSTD_AUTH_TOKEN': 42}, {'HOSTD_AUTH_TOKEN': 'x' * 257}, None):
                    scope = set_secret_scope(mapping, profile_home=str(profile))
                    try:
                        for transport in ('http', 'vsock'):
                            with patch.dict(os.environ, {'HOSTD_TRANSPORT': transport}), contextlib.redirect_stdout(
                                    output), contextlib.redirect_stderr(output):
                                result = entry.handler({'command': ['echo']})
                            parsed = json.loads(result)
                            self.assertIs(parsed['success'], False)
                            self.assertFalse('synthetic' in result)
                            self.assertLess(len(parsed['error']), 240)
                    finally:
                        reset_secret_scope(scope)
                self.assertFalse('synthetic' in output.getvalue())
                # No client may be created when resolution or validation fails.
                factory.assert_not_called()
        finally:
            logging.getLogger().removeHandler(handler)
            reset_multiplex_context(multiplex)
            reset_hermes_home_override(override)
            plugin._PLUGIN_SETTINGS.clear()

    def test_secret_resolver_import_and_exception_errors_are_sanitized(self):
        import builtins
        import json
        from unittest.mock import patch
        real_import = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name == 'agent.secret_scope':
                raise ImportError('synthetic-sensitive-import-error')
            return real_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=unavailable):
            result = plugin._handle_run_on_host({'command': ['echo']})
        self.assertIs(json.loads(result)['success'], False)
        self.assertNotIn('synthetic', result)
        with patch('agent.secret_scope.get_secret', side_effect=RuntimeError('synthetic-sensitive-resolver-error')):
            result = plugin._handle_run_on_host({'command': ['echo']})
        self.assertIs(json.loads(result)['success'], False)
        self.assertNotIn('synthetic', result)

    def test_registered_strict_correlated_bounded_results(self):
        import json
        from unittest.mock import patch
        helper_spec = importlib.util.spec_from_file_location('response_fixtures', PLUGIN / 'tests/test_responses.py')
        assert helper_spec and helper_spec.loader
        helpers = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helpers)
        context = PluginContext(manifest, manager)
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        scope = set_secret_scope({'HOSTD_AUTH_TOKEN': 'synthetic-strict-token'})
        self.addCleanup(reset_secret_scope, scope)
        def register(config):
            settings = {'plugins': {'entries': {'hostd-client': {'settings': {
                **config, 'max_response_bytes': 512}}}}}
            with patch('hermes_cli.plugins.load_config_readonly', return_value=settings):
                plugin.register(context)
        def wire(body, **changes):
            return json.dumps({'id': body['id'], 'approved': True, 'exit_code': 0, **changes}).encode()
        replies = [b'\xff', b'{', b'[]', b'null', b'{"approved":true}',
                   b'{"id":"wrong","approved":true}', b'x' * 513]
        for field, values in {'approved': ['false', 'true', 1, None, []],
                              'exit_code': [True, 1.5, '0'], 'stdout': [None],
                              'stderr': [[]], 'error': [False], 'log_id': [1],
                              'output_truncated': [0], 'persistent_intent': ['true']}.items():
            for value in values:
                replies.append(lambda body, field=field, value=value: wire(body, **{field: value}))
        for kind in ('http', 'vsock'):
            for response in replies:
                with helpers.endpoint(kind, response, plugin._client_mod) as config:
                    register(config)
                    entry = registry.get_entry('run_on_host')
                    result = json.loads(entry.handler({'command': ['echo'], 'description': 'synthetic'}))
                    self.assertIs(result['approved'], False)
                    self.assertTrue(result['error'])
                    self.assertLess(len(result['error']), 200)
            with helpers.endpoint(kind, lambda body: wire(body, log_id='opaque', output_truncated=True,
                    future={'v': 1}, persistent_intent=True), plugin._client_mod) as config:
                register(config)
                result = json.loads(registry.get_entry('run_on_host').handler({
                    'command': ['echo'], 'description': 'synthetic', 'persistent_intent': True}))
                self.assertIs(result['approved'], True)
                self.assertEqual(result['log_id'], 'opaque')
                self.assertEqual(result['future'], {'v': 1})
                self.assertIs(result['persistent_intent'], True)
                self.assertEqual(plugin._build_client().transport.max_response_bytes, 512)
        plugin._PLUGIN_SETTINGS.clear()

    def test_context_home_overrides_process_home_at_handler_time(self):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override

        process_home = Path(os.environ['HERMES_HOME'])
        profile = HOME / 'routed-profile'
        profile.mkdir()
        process_config = process_home / 'hostd-client.yaml'
        profile_config = profile / 'hostd-client.yaml'
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        process_token = 'synthetic-process-only'
        profile_token = 'synthetic-profile-only'
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                seen.append(self.headers.get('Authorization'))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'id': body['id'], 'approved': False}).encode())
            def log_message(self, format, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/execute'
        for config in (process_config, profile_config):
            config.write_text(f'transport: http\nhttp_url: {url}\n')
        assert manifest is not None
        context = PluginContext(manifest, manager)
        # Register in the process profile first: resolution must not be cached here.
        with patch('hermes_cli.plugins.load_config_readonly', return_value={}):
            plugin.register(context)
        entry = registry.get_entry('run_on_host')
        assert entry is not None
        override = set_hermes_home_override(profile)
        scope = set_secret_scope({'HOSTD_AUTH_TOKEN': profile_token}, profile_home=str(profile))
        process_env = patch.dict(os.environ, {'HOSTD_AUTH_TOKEN': process_token})
        process_env.start()
        try:
            self.assertEqual(os.environ['HERMES_HOME'], str(process_home))
            self.assertEqual(get_hermes_home(), profile)
            result = entry.handler({'command': ['echo'], 'description': 'synthetic'})
            self.assertIs(json.loads(result)['approved'], False)
            self.assertEqual(seen, ['Bearer synthetic-profile-only'])
            self.assertNotIn('synthetic-profile-only', result)
            self.assertNotIn('synthetic-process-only', result)
            # Missing selected config must not discover process-profile settings.
            profile_config.unlink()
            self.assertEqual(plugin._load_yaml_config(), {})
            missing_scope = set_secret_scope({}, profile_home=str(profile))
            try:
                result = json.loads(entry.handler({'command': ['echo'], 'description': 'synthetic'}))
                self.assertIs(result['success'], False)
                self.assertIn('requester token', result['error'])
                self.assertEqual(len(seen), 1)
            finally:
                reset_secret_scope(missing_scope)
            # Even a valid managed token cannot silently mask a legacy selector.
            profile_config.write_text(f'auth_token_file: {profile / "missing.token"}\n')
            with self.assertRaisesRegex(ValueError, 'removed.*HOSTD_AUTH_TOKEN'):
                plugin._build_client()
        finally:
            process_env.stop()
            reset_secret_scope(scope)
            reset_hermes_home_override(override)
            process_config.unlink(missing_ok=True)
            profile_config.unlink(missing_ok=True)
            plugin._PLUGIN_SETTINGS.clear()
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.assertEqual(get_hermes_home(), process_home)

    def test_removed_tools_have_no_registry_entry_or_manifest_promise(self):
        assert manifest is not None
        self.assertEqual(manifest.provides_tools, ['run_on_host'])
        for name in ('mount_host_folder', 'unmount_host_folder'):
            self.assertIsNone(registry.get_entry(name))
            self.assertFalse(hasattr(plugin, '_handle_' + name))
            self.assertFalse(hasattr(plugin, '_SCHEMA_' + name.upper()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
