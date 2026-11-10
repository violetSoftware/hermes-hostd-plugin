"""Run the plugin from a source-only copy in an isolated interpreter."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRATCH = Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
SOURCE = Path(__file__).resolve().parents[1]


class PortabilityTests(unittest.TestCase):
    def test_isolated_copy_loads_without_daemon_checkout(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="hostd-portable-", dir=SCRATCH) as tmp:
            root = Path(tmp)
            plugin = root / "relocated-plugin"
            plugin.mkdir()
            shutil.copyfile(SOURCE / "__init__.py", plugin / "__init__.py")
            shutil.copyfile(SOURCE / "plugin.yaml", plugin / "plugin.yaml")
            shutil.copytree(SOURCE / "client", plugin / "client",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("HOSTD_")}
            forbidden_roots = [root / name for name in (
                "synthetic-daemon-checkout", "synthetic-mounted-checkout",
                "synthetic-legacy-checkout",
            )]
            for forbidden_root in forbidden_roots:
                forbidden_root.mkdir()
                (forbidden_root / "fixture.txt").write_text("forbidden fixture", encoding="utf-8")
            permitted = root / "permitted-checkout"
            permitted.mkdir()
            (permitted / "fixture.txt").write_text("permitted fixture", encoding="utf-8")
            env["HOSTD_TEST_FORBIDDEN_ROOTS"] = json.dumps([str(path) for path in forbidden_roots])
            env["HERMES_HOME"] = str(root / "empty-profile")
            env["NO_PROXY"] = "127.0.0.1"
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(SOURCE / "tests" / "isolated_probe.py"),
                 str(plugin)], cwd=root, env=env, capture_output=True, text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout + result.stderr, end="")


if __name__ == "__main__":
    unittest.main()
