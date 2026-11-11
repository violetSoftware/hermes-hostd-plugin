"""Standalone fallback and fail-closed Hermes home-resolution contracts."""
import builtins
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'home_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
assert spec and spec.loader
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class HomeResolutionTests(unittest.TestCase):
    def test_standalone_environment_and_default_home_fallback(self):
        real_import = builtins.__import__
        def without_hermes(name, *args, **kwargs):
            if name == 'hermes_constants':
                raise ModuleNotFoundError("No module named 'hermes_constants'", name=name)
            return real_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env_home = home / 'explicit'
            default_home = home / '.hermes'
            for path, value in ((env_home, '4321'), (default_home, '5432')):
                path.mkdir()
                (path / 'hostd-client.yaml').write_text(f'vsock_port: {value}\n')
            with patch('builtins.__import__', side_effect=without_hermes), patch.dict(
                    os.environ, {'HOME': str(home), 'HERMES_HOME': str(env_home)}, clear=True):
                self.assertEqual(plugin._load_yaml_config(), {'vsock_port': '4321'})
                del os.environ['HERMES_HOME']
                self.assertEqual(plugin._load_yaml_config(), {'vsock_port': '5432'})

    def test_hermes_resolver_failure_never_falls_back_to_process_config(self):
        runtime = ModuleType('hermes_constants')
        def fail():
            raise RuntimeError('synthetic resolver failure')
        setattr(runtime, 'get_hermes_home', fail)
        with patch.dict(sys.modules, {'hermes_constants': runtime}):
            with self.assertRaisesRegex(RuntimeError, 'synthetic resolver failure'):
                plugin._load_yaml_config()

    def test_incomplete_hermes_api_never_uses_standalone_fallback(self):
        with patch.dict(sys.modules, {'hermes_constants': ModuleType('hermes_constants')}):
            with self.assertRaises(ImportError):
                plugin._load_yaml_config()

    def test_hermes_dependency_import_failure_never_uses_standalone_fallback(self):
        real_import = builtins.__import__
        def broken_hermes(name, *args, **kwargs):
            if name == 'hermes_constants':
                raise ModuleNotFoundError('synthetic dependency missing', name='synthetic_dependency')
            return real_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=broken_hermes):
            with self.assertRaises(ModuleNotFoundError) as caught:
                plugin._load_yaml_config()
        self.assertEqual(caught.exception.name, 'synthetic_dependency')


if __name__ == '__main__':
    unittest.main()
