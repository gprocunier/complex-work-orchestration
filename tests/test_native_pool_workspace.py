from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import seal_artifact  # noqa: E402
from cwo_core.native_pool_workspace import (  # noqa: E402
    PoolWorkspaceError,
    PoolWorkspaceMonitor,
    capture_workspace_snapshot,
    use_sealed_workspace_baselines,
)
from cwo_core import workspace as workspace_module  # noqa: E402
from tests.test_native_pool_contracts import pool_contract  # noqa: E402


def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


class WorkspaceFixture:
    def __init__(self, root: Path) -> None:
        self.integration = root / "integration"
        self.integration.mkdir()
        git("init", "-q", cwd=self.integration)
        (self.integration / "scripts").mkdir()
        (self.integration / "scripts" / "child_0.py").write_text("ZERO = 0\n", encoding="utf-8")
        (self.integration / "scripts" / "child_1.py").write_text("ONE = 1\n", encoding="utf-8")
        (self.integration / "README.md").write_text("baseline\n", encoding="utf-8")
        (self.integration / "link").symlink_to("scripts")
        git("add", ".", cwd=self.integration)
        git(
            "-c",
            "user.name=CWO Test",
            "-c",
            "user.email=cwo@example.invalid",
            "commit",
            "-qm",
            "baseline",
            cwd=self.integration,
        )
        self.first = root / "child-0"
        self.second = root / "child-1"
        git("worktree", "add", "-q", "-b", "pool-child-0", str(self.first), "HEAD", cwd=self.integration)
        git("worktree", "add", "-q", "-b", "pool-child-1", str(self.second), "HEAD", cwd=self.integration)

    def contract(self, *, read_only: bool = False) -> tuple[dict, dict[str, Path]]:
        contract, _ = pool_contract(cap=2, read_only=read_only)
        integration = capture_workspace_snapshot(self.integration)
        first = capture_workspace_snapshot(
            self.first, allowed_paths=contract["children"][0]["declared_write_paths"]
        )
        second = (
            first
            if read_only
            else capture_workspace_snapshot(
                self.second,
                allowed_paths=contract["children"][1]["declared_write_paths"],
            )
        )
        contract["topology"]["integration_root_identity"] = integration["identity"]
        contract["children"][0]["worktree_identity"] = first["identity"]
        contract["children"][1]["worktree_identity"] = second["identity"]
        return seal_artifact(contract, "contract_sha256"), {
            "child-0": self.first,
            "child-1": self.first if read_only else self.second,
        }


class NativePoolWorkspaceTests(unittest.TestCase):
    def test_sealed_dirty_baseline_is_explicit_scoped_and_drift_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            target = fixture.first / "scripts" / "child_0.py"
            target.write_text("ZERO = 7\n", encoding="utf-8")
            baseline = workspace_module.capture_workspace_baseline(
                fixture.first,
                allowed_paths=["scripts/child_0.py"],
                include_untracked=True,
            )

            with self.assertRaisesRegex(PoolWorkspaceError, "baseline-not-clean"):
                capture_workspace_snapshot(
                    fixture.first,
                    allowed_paths=["scripts/child_0.py"],
                )

            entries = {
                fixture.first: {
                    "baseline": baseline,
                    "allowed_paths": ["scripts/child_0.py"],
                }
            }
            with use_sealed_workspace_baselines(entries):
                accepted = capture_workspace_snapshot(
                    fixture.first,
                    allowed_paths=["scripts/child_0.py"],
                )
                self.assertEqual(accepted["baseline"], baseline)
                target.write_text("ZERO = 8\n", encoding="utf-8")
                with self.assertRaisesRegex(PoolWorkspaceError, "baseline-drift"):
                    capture_workspace_snapshot(
                        fixture.first,
                        allowed_paths=["scripts/child_0.py"],
                    )

            with self.assertRaisesRegex(PoolWorkspaceError, "baseline-not-clean"):
                capture_workspace_snapshot(
                    fixture.first,
                    allowed_paths=["scripts/child_0.py"],
                )

    def test_snapshot_avoids_discarded_all_tracked_file_fingerprint_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            with mock.patch.object(
                workspace_module,
                "_content_fingerprints",
                wraps=workspace_module._content_fingerprints,
            ) as fingerprints:
                snapshot = capture_workspace_snapshot(
                    fixture.integration,
                    allowed_paths=["scripts/child_0.py"],
                )

            self.assertTrue(snapshot["baseline"]["baseline_complete"])
            self.assertEqual(fingerprints.call_count, 1)
            self.assertEqual(
                fingerprints.call_args.kwargs["allowed_paths"],
                ["scripts/child_0.py"],
            )

    def test_baseline_uses_one_candidate_enumeration_for_capture_and_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            with mock.patch.object(
                workspace_module,
                "_fingerprint_candidates",
                wraps=workspace_module._fingerprint_candidates,
            ) as candidates:
                baseline = workspace_module.capture_workspace_baseline(
                    fixture.integration,
                    allowed_paths=["scripts/child_0.py"],
                    include_untracked=True,
                )

            self.assertTrue(baseline["baseline_complete"])
            self.assertEqual(candidates.call_count, 1)

    def test_symlink_target_changes_are_content_mutations_without_following_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git("init", "-q", cwd=root)
            (root / "first.txt").write_text("first\n", encoding="utf-8")
            (root / "second.txt").write_text("second\n", encoding="utf-8")
            (root / "current").symlink_to("first.txt")
            before = workspace_module.capture_workspace_baseline(
                root,
                allowed_paths=["."],
                include_untracked=True,
            )

            self.assertEqual(
                before["content_fingerprints"]["current"]["kind"],
                "symlink",
            )
            (root / "current").unlink()
            (root / "current").symlink_to("second.txt")
            after = workspace_module.capture_workspace_baseline(
                root,
                allowed_paths=["."],
                include_untracked=True,
            )
            report = workspace_module.compare_workspace_baseline(
                before,
                after,
                allowed_paths=["."],
            )

            self.assertEqual(
                [item["path"] for item in report["mutations"]],
                ["current"],
            )
            self.assertTrue(report["mutation_detected"])

    def test_whole_workspace_baseline_excludes_operational_state_and_caches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git("init", "-q", cwd=root)
            (root / "product.txt").write_text("product\n", encoding="utf-8")
            git("add", "product.txt", cwd=root)
            for directory in (
                ".beads",
                ".orchestration-audit",
                "__pycache__",
                ".ruff_cache",
            ):
                target = root / directory
                target.mkdir()
                (target / "large.bin").write_bytes(b"x" * 128)

            baseline = workspace_module.capture_workspace_baseline(
                root,
                allowed_paths=["."],
                include_untracked=True,
                max_bytes=32,
            )

            self.assertTrue(baseline["baseline_complete"])
            self.assertEqual(
                sorted(baseline["content_fingerprints"]),
                ["product.txt"],
            )

    def test_clean_tracked_first_write_is_out_of_scope_not_untracked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            before = workspace_module.capture_workspace_baseline(
                fixture.first,
                allowed_paths=["scripts/child_0.py"],
                include_untracked=True,
            )

            (fixture.first / "README.md").write_text("outside\n", encoding="utf-8")
            after = workspace_module.capture_workspace_baseline(
                fixture.first,
                allowed_paths=["scripts/child_0.py"],
                include_untracked=True,
            )
            report = workspace_module.compare_workspace_baseline(
                before,
                after,
                allowed_paths=["scripts/child_0.py"],
            )

            self.assertEqual(report["mutation_categories"]["out-of-scope"], ["README.md"])
            self.assertEqual(report["mutation_categories"]["untracked"], [])
            self.assertTrue(report["unexpected_mutation_detected"])

    def test_new_untracked_first_write_remains_untracked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            before = workspace_module.capture_workspace_baseline(
                fixture.first,
                allowed_paths=["scripts/child_0.py"],
                include_untracked=True,
            )

            (fixture.first / "outside.txt").write_text("outside\n", encoding="utf-8")
            after = workspace_module.capture_workspace_baseline(
                fixture.first,
                allowed_paths=["scripts/child_0.py"],
                include_untracked=True,
            )
            report = workspace_module.compare_workspace_baseline(
                before,
                after,
                allowed_paths=["scripts/child_0.py"],
            )

            self.assertEqual(report["mutation_categories"]["out-of-scope"], [])
            self.assertEqual(report["mutation_categories"]["untracked"], ["outside.txt"])
            self.assertTrue(report["unexpected_mutation_detected"])

    def test_mutable_isolated_writes_are_attributable_but_out_of_scope_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract()
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )
            self.assertTrue(all(monitor.compare(contract=contract, phase="initial").values()))

            (fixture.first / "scripts" / "child_0.py").write_text("ZERO = 2\n", encoding="utf-8")
            allowed = monitor.compare(contract=contract, phase="allowed-child-write")
            self.assertTrue(allowed["integration_root_clean"])
            self.assertTrue(allowed["child_worktrees_clean"])

            (fixture.first / "README.md").write_text("outside scope\n", encoding="utf-8")
            rejected = monitor.compare(contract=contract, phase="out-of-scope-child-write")
            self.assertFalse(rejected["child_worktrees_clean"])

    def test_integration_root_mutation_is_pool_wide_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract()
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )
            (fixture.integration / "README.md").write_text("mutated\n", encoding="utf-8")
            evidence = monitor.compare(contract=contract, phase="integration-mutation")
            self.assertFalse(evidence["integration_root_clean"])
            self.assertTrue(evidence["child_worktrees_clean"])

    def test_terminal_reconciliation_cannot_erase_a_restored_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract()
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )
            target = fixture.integration / "README.md"
            target.write_text("escaped\n", encoding="utf-8")
            suspicious = monitor.compare(contract=contract, phase="suspected")
            self.assertFalse(suspicious["integration_root_clean"])
            target.write_text("baseline\n", encoding="utf-8")

            reconciliation = monitor.reconcile_terminal(
                contract=contract,
                no_inflight_tool_calls=True,
                no_inflight_callbacks=True,
                no_background_processes=True,
                no_writable_sessions=True,
            )

            self.assertTrue(reconciliation["terminal_clean"])
            self.assertTrue(reconciliation["historical_escape_observed"])
            self.assertEqual(reconciliation["control_disposition"], "escaped")
            history = monitor.observations()
            self.assertEqual([item["sequence"] for item in history], [1, 2])
            self.assertEqual(
                history[1]["previous_observation_sha256"],
                history[0]["observation_sha256"],
            )
            history[0]["phase"] = "tampered-copy"
            self.assertEqual(monitor.observations()[0]["phase"], "suspected")

    def test_terminal_reconciliation_is_fail_dirty_without_quiescence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract()
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )
            result = monitor.reconcile_terminal(
                contract=contract,
                no_inflight_tool_calls=False,
                no_inflight_callbacks=True,
                no_background_processes=True,
                no_writable_sessions=True,
            )
            self.assertEqual(result["control_disposition"], "unobservable")
            self.assertFalse(result["quiescent"])

    def test_shared_read_only_mutation_is_rejected_for_entire_shared_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract(read_only=True)
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )
            (fixture.first / "README.md").write_text("forbidden\n", encoding="utf-8")
            evidence = monitor.compare(contract=contract, phase="read-only-mutation")
            self.assertFalse(evidence["shared_read_only_clean"])
            self.assertFalse(evidence["child_worktrees_clean"])

    def test_child_baseline_is_complete_and_returned_as_an_isolated_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract(read_only=True)
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )

            baseline = monitor.child_baseline("child-0")
            self.assertTrue(baseline["baseline_complete"])
            baseline["tracked_status"].append(" M forged.txt")
            self.assertNotIn(
                " M forged.txt",
                monitor.child_baseline("child-0")["tracked_status"],
            )
            with self.assertRaisesRegex(
                PoolWorkspaceError,
                "child-workspace-baseline-missing",
            ):
                monitor.child_baseline("missing")

    def test_incompatible_contract_profiles_cannot_reuse_physical_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, _ = fixture.contract()
            read_only_contract, _ = pool_contract(cap=2, read_only=True)
            changed = copy.deepcopy(contract)
            changed["children"][0].update(
                {
                    "isolation_class": "read-only-shared",
                    "completion_evidence_policy": read_only_contract["children"][0][
                        "completion_evidence_policy"
                    ],
                    "tool_policy": read_only_contract["children"][0]["tool_policy"],
                    "declared_write_paths": [],
                    "integration_target_paths": [],
                    "worktree_identity": capture_workspace_snapshot(
                        fixture.first,
                        allowed_paths=[],
                    )["identity"],
                }
            )
            changed = seal_artifact(changed, "contract_sha256")

            with self.assertRaisesRegex(
                PoolWorkspaceError,
                "incompatible-physical-worktree-reuse:child-1",
            ):
                PoolWorkspaceMonitor(
                    changed,
                    integration_root=fixture.integration,
                    child_worktrees={
                        "child-0": fixture.first,
                        "child-1": fixture.first,
                    },
                )

    def test_post_admission_contract_tampering_is_rejected_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract(read_only=True)
            monitor = PoolWorkspaceMonitor(
                contract,
                integration_root=fixture.integration,
                child_worktrees=worktrees,
            )
            changed = copy.deepcopy(contract)
            changed["children"][0]["completion_evidence_policy"][
                "expected_mutation_mode"
            ] = "mutable-isolated"

            with self.assertRaisesRegex(
                PoolWorkspaceError,
                "workspace-contract-content-mismatch",
            ):
                monitor.compare(contract=changed, phase="tampered")

    def test_symlinked_integration_target_component_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            contract, worktrees = fixture.contract()
            changed = copy.deepcopy(contract)
            changed["children"][0]["declared_write_paths"] = ["link/child_0.py"]
            changed["children"][0]["integration_target_paths"] = ["link/child_0.py"]
            changed = seal_artifact(changed, "contract_sha256")
            with self.assertRaisesRegex(PoolWorkspaceError, "symlink-component"):
                PoolWorkspaceMonitor(
                    changed,
                    integration_root=fixture.integration,
                    child_worktrees=worktrees,
                )


if __name__ == "__main__":
    unittest.main()
