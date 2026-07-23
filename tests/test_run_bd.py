from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.beads as lib  # noqa: E402


class RunBdTests(unittest.TestCase):
    def test_run_bd_passes_configured_timeout(self) -> None:
        completed = subprocess.CompletedProcess(["bd", "ready"], 0, stdout="[]\n", stderr="")
        with patch("shutil.which", return_value="/usr/bin/bd"):
            with patch.dict(os.environ, {"CWO_BEADS_TIMEOUT_SECONDS": "17"}):
                with patch("subprocess.run", return_value=completed) as mocked_run:
                    self.assertEqual(lib.run_bd(["ready"]), "[]\n")
        self.assertEqual(mocked_run.call_args.kwargs["timeout"], 17)

    def test_run_bd_timeout_fails_cleanly(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/bd"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["bd", "ready"], 3)):
                with self.assertRaises(SystemExit) as exc:
                    lib.run_bd(["ready"], timeout=3)
        self.assertIn("bd command timed out after 3s: bd ready", str(exc.exception))

    def test_add_dependency_preserves_explicit_nonblocking_type(self) -> None:
        with patch.object(lib, "run_bd", return_value="") as mocked_run:
            lib.add_dependency("publication", "implementation", dependency_type="validates")

        mocked_run.assert_called_once_with(
            [
                "dep",
                "add",
                "publication",
                "implementation",
                "--type",
                "validates",
            ]
        )

    def test_add_dependency_rejects_unknown_type_before_bd_call(self) -> None:
        with patch.object(lib, "run_bd", return_value="") as mocked_run:
            with self.assertRaises(ValueError):
                lib.add_dependency("a", "b", dependency_type="integration-order")

        mocked_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
