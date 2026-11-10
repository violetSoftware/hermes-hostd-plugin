"""Installed Hermes definition regression, isolated from all profile state."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
# Override when testing another installed runtime; never import the live launcher.
RUNTIME = Path(os.environ.get("HOSTD_TEST_HERMES_SOURCE", "/usr/local/lib/hermes-agent"))


class DefinitionBoundaryTests(unittest.TestCase):
    def test_public_context_emits_usable_definitions(self):
        self.assertTrue((RUNTIME / "tools" / "registry.py").is_file(),
                        "Set HOSTD_TEST_HERMES_SOURCE to an installed Hermes source tree")
        scratch = Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="hostd-definitions-", dir=scratch) as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            profile = home / "hermes"
            profile.mkdir()
            env = {"HOME": str(home), "HERMES_HOME": str(profile),
                   "TMPDIR": str(home), "PATH": os.defpath,
                   "PYTHONDONTWRITEBYTECODE": "1", "HERMES_SKIP_CHMOD": "1",
                   "LANG": "C.UTF-8"}
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(SOURCE / "tests" / "definition_probe.py"),
                 str(SOURCE), str(RUNTIME)], cwd=root, env=env,
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout + result.stderr, end="")


if __name__ == "__main__":
    unittest.main()
