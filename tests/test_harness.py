"""Regression tests for temporary-directory selection in the test harness."""
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

HARNESS = Path(__file__).with_name("test_portability.py")


class ScratchSelectionTests(unittest.TestCase):
    def test_harness_honors_tmpdir(self):
        with patch.dict(os.environ, {"TMPDIR": str(Path.cwd() / "custom-scratch")}):
            namespace = runpy.run_path(str(HARNESS))
        self.assertEqual(namespace["SCRATCH"], Path.cwd() / "custom-scratch")

    def test_harness_uses_tempfile_fallback_without_tmpdir(self):
        fallback = str(Path.cwd() / "platform-temp")
        with patch.dict(os.environ), patch.object(tempfile, "gettempdir", return_value=fallback):
            os.environ.pop("TMPDIR", None)
            namespace = runpy.run_path(str(HARNESS))
        self.assertEqual(namespace["SCRATCH"], Path(fallback))
