from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_native_pool_activation_preview as preview_runner  # noqa: E402

BD_PATH = shutil.which("bd")


def snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    """Every path under ``root`` with its size, modification time and, for a regular file, its content digest."""
    import hashlib

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else ""

    return {str(path.relative_to(root)): (path.lstat().st_size, path.lstat().st_mtime_ns, digest(path))
            for path in root.rglob("*")}


class LiveActivationIsDisabledTests(unittest.TestCase):
    """Live activation closes accepted children in a Beads database it finds only by path."""

    def test_f5_held_route_preview_switches_are_off(self) -> None:
        self.assertIs(preview_runner.live_availability.N1_LIVE_AVAILABLE, False)
        self.assertIs(preview_runner.live_availability.POOL_LIVE_AVAILABLE, False)

    def test_the_closing_step_refuses_any_caller(self) -> None:
        adapter = MagicMock()
        with self.assertRaises(preview_runner.LiveActivationUnavailable) as raised:
            preview_runner._close_accepted_activation_beads({}, {}, {}, adapter, pool_receipt_sha256="0" * 64)
        self.assertEqual(str(raised.exception), preview_runner.LIVE_ACTIVATION_UNAVAILABLE)
        self.assertEqual(adapter.mock_calls, [])

    def test_every_live_input_is_refused_before_it_is_read(self) -> None:
        """No bd, no prepared plan: the guard comes before any input is loaded, whatever the input."""
        import tempfile

        effects = ("load_activation_plan", "ensure_private_directory", "read_private_json", "acquire_activation_claim",
                   "BeadsClaimAdapter", "reserve_pool_cohort", "NativeActivationLedgerStore", "AppServer",
                   "run_admitted_native_pool", "run_bd_structured", "capture_owner_identity", "read_activation_key")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "forged.json").write_text('{"plan_sha256": "0" * 64}', encoding="utf-8")
            (root / "stale.json").write_text('{"prepared_at": "2000-01-01T00:00:00Z"}', encoding="utf-8")
            cases = {"missing": (root / "absent.json", root / "absent-approval.json", root / "absent-control"),
                     "forged": (root / "forged.json", root / "forged.json", root),
                     "stale": (root / "stale.json", root / "stale.json", root)}
            for label, (plan, approval, control) in cases.items():
                spies = {name: MagicMock(side_effect=AssertionError(f"{name} used")) for name in effects
                         if hasattr(preview_runner, name)}
                with self.subTest(case=label), contextlib.ExitStack() as stack:
                    for name, spy in spies.items():
                        stack.enter_context(patch.object(preview_runner, name, spy))
                    with self.assertRaises(preview_runner.LiveActivationUnavailable) as raised:
                        preview_runner.run_live_activation(plan, approval, control_root=control, actor_id="operator-1",
                                                           identity_source="trusted-control-session")
                    self.assertEqual(str(raised.exception), preview_runner.LIVE_ACTIVATION_UNAVAILABLE)
                    stderr = io.StringIO()
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    code = preview_runner.main(["run", "--control-root", str(control), "--prepared", str(plan), "--approval",
                                                str(approval), "--operator-id", "operator-1", "--identity-source", "session",
                                                "--enable-tech-preview"])
                    self.assertEqual((code, json.loads(stderr.getvalue())["failure_class"]), (1, "LiveActivationUnavailable"))
                    self.assertEqual({name: spy.call_count for name, spy in spies.items()}, {name: 0 for name in spies})

    def fixture(self) -> tuple[Path, list[str]]:
        from tests.test_native_activation_preview import NativeActivationPreviewTests

        helper = NativeActivationPreviewTests("test_keygen_prepare_approve_and_dry_run_are_non_live")
        temporary, control, plan_path, approval_path, _plan, _approval = helper.fixture()
        self.addCleanup(temporary.cleanup)
        return control, ["run", "--control-root", str(control), "--prepared", str(plan_path), "--approval",
                         str(approval_path), "--operator-id", "operator-1", "--identity-source", "trusted-control-session"]

    @unittest.skipUnless(BD_PATH, "bd CLI not available")
    def test_a_live_run_refuses_before_any_claim_rpc_or_beads_write(self) -> None:
        control, argv = self.fixture()
        before = snapshot(control)
        stdout, stderr = io.StringIO(), io.StringIO()
        effects = ("acquire_activation_claim", "BeadsClaimAdapter", "reserve_pool_cohort", "NativeActivationLedgerStore",
                   "AppServer", "run_admitted_native_pool", "run_bd_structured", "capture_owner_identity")
        spies = {name: MagicMock(side_effect=AssertionError(f"{name} used")) for name in effects
                 if hasattr(preview_runner, name)}
        self.assertIn("AppServer", spies)
        with contextlib.ExitStack() as stack:
            for name, spy in spies.items():
                stack.enter_context(patch.object(preview_runner, name, spy))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = preview_runner.main([*argv, "--enable-tech-preview"])
        self.assertEqual(code, 1)
        rejection = json.loads(stderr.getvalue())
        self.assertEqual((rejection["failure_class"], rejection["failure_message"]),
                         ("LiveActivationUnavailable", preview_runner.LIVE_ACTIVATION_UNAVAILABLE))
        self.assertEqual({name: spy.call_count for name, spy in spies.items()}, {name: 0 for name in spies})
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(snapshot(control), before, "nothing under the control root, its Beads database included, changed")

    @unittest.skipUnless(BD_PATH, "bd CLI not available")
    def test_a_dry_run_still_works(self) -> None:
        _control, argv = self.fixture()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = preview_runner.main([*argv, "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "dry-run-accepted")


if __name__ == "__main__":
    unittest.main()
