from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import seal_artifact  # noqa: E402
from cwo_core.native_pool_workspace import (  # noqa: E402
    PoolWorkspaceError,
    PoolWorkspaceMonitor,
    capture_workspace_snapshot,
)
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
