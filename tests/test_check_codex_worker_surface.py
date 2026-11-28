"""The retired probe's public refusal and pinned fake-only lifecycle tests."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import HELD_QUALIFICATION_PRODUCERS, run_archived_cases

import check_codex_worker_surface as probe
from cwo_core.codex_tool_surface import CodexToolSurfaceError


class WorkerSurfaceRefusalTests(unittest.TestCase):
    def test_library_keeps_exact_tool_profile_validation(self):
        for tools in (None, ["exec_command"], ["exec_command", {}]):
            with self.subTest(tools=tools), \
                 self.assertRaisesRegex(CodexToolSurfaceError, "codex-tool-surface-permitted-tools-"):
                probe.capture_tool_request(codex_home=Path("/fixture/missing-home"), requested_model="fixture",
                                           timeout_seconds=1, permitted_tools=tools)

    def test_shipped_cli_refuses_before_reading_or_writing_probe_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([
                sys.executable, "-I", str(ROOT / "scripts/check_codex_worker_surface.py"),
                "--codex-home", str(root / "missing-home"), "--profile", "read-only",
                "--catalog-projection", str(root / "catalog.json"), "--capture", str(root / "capture.json"),
                "--output", str(root / "proof.json"), "--host-evidence", str(root / "host.json"),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertTrue(result.stderr.endswith("NativeLiveUnavailable: native-n1-live-unavailable\n"), result.stderr)
            self.assertEqual(list(root.iterdir()), [])

    def test_pinned_probe_lifecycle_and_transport_imports(self):
        run_archived_cases(self, HELD_QUALIFICATION_PRODUCERS,
            "tests.test_check_codex_worker_surface", "tests.test_worker_surface_transport_imports",
            "tests.test_release_effect_routes.ReleaseEffectRoutesTests.test_remaining_boundary_pairs_at_actual_effects",
            all_paths=True)
