"""Hermes approval hook regressions; no daemon or production configuration."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "approval_hostd", SOURCE / "__init__.py", submodule_search_locations=[str(SOURCE)])
assert spec is not None and spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.ctx = Mock()
        self.ctx.get_config.return_value = None
        plugin.register(self.ctx)

    def hook(self):
        self.ctx.register_hook.assert_called_once()
        name, callback = self.ctx.register_hook.call_args.args
        self.assertEqual(name, "pre_tool_call")
        return callback

    def test_every_host_call_requests_native_approval_with_exact_arguments(self):
        args = {"command": ["printf", "%s", "two words", "line\nnext", "$(id)"],
                "description": "Explain the exact host action", "timeout": 0,
                "persistent_intent": True}
        original = json.dumps(args)
        result = self.hook()(tool_name="run_on_host", args=args, session_id="fixture")
        self.assertEqual(result["action"], "approve")
        self.assertEqual(result["rule_key"], "run_on_host")
        self.assertIn(json.dumps(args["command"], ensure_ascii=True), result["message"])
        self.assertIn(args["description"], result["message"])
        self.assertIn('"timeout": 0', result["message"])
        self.assertIn('"persistent_intent": true', result["message"])
        self.assertEqual(json.dumps(args), original)

    def test_other_tools_are_not_escalated(self):
        self.assertIsNone(self.hook()(tool_name="terminal", args={}))

    def test_missing_and_malformed_host_arguments_still_request_approval(self):
        for args in ({}, None, {"command": "echo"}, {"command": [None]}):
            with self.subTest(args=args):
                self.assertEqual(self.hook()(tool_name="run_on_host", args=args)["action"], "approve")

    def test_manifest_declares_approval_hook(self):
        text = (SOURCE / "plugin.yaml").read_text()
        self.assertIn("provides_hooks:\n  - pre_tool_call", text)


if __name__ == "__main__":
    unittest.main()
