from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import (  # noqa: E402
    POOL_STATE_SCHEMA,
    POOL_STATE_TYPE,
    VERSION,
    canonical_sha256,
    seal_artifact,
    validate_lease,
    validate_pool_state,
    zero_usage,
)
from cwo_core.native_pool_leases import (  # noqa: E402
    PoolLeaseCollision,
    PoolLeaseError,
    PoolLeaseRegistry,
    capture_owner_identity,
    owner_identity_is_live,
)
from tests.test_native_pool_contracts import identity, pool_contract, sha  # noqa: E402


NOW = dt.datetime(2026, 7, 16, 12, 0, tzinfo=dt.timezone.utc)


def terminal_state(contract: dict, leases: list[dict], *, status: str = "completed") -> dict:
    child_status = "control-failed" if status == "control-failed" else "closed"
    reasons = ["control-state-corrupt"] if status == "control-failed" else []
    first_protected_fault = (
        {
            "code": "control-state-corrupt",
            "operation": None,
            "observed_callback_latency_ms": None,
            "certified_callback_max_ms": None,
            "latched_state_sequence": 8,
        }
        if status == "control-failed"
        else None
    )
    children = [
        {
            "ordinal": index,
            "child_id": child["child_id"],
            "status": child_status,
            "last_deadline_ns": 1_000_000_000 + index,
            "next_deadline_ns": None,
            "child_state_sha256": sha(f"state:{child['child_id']}"),
            "child_receipt_sha256": sha(f"receipt:{child['child_id']}"),
            "last_cumulative_usage": zero_usage(),
            "lease_id": child["lease_id"],
        }
        for index, child in enumerate(contract["children"])
    ]
    return seal_artifact(
        {
            "state_type": POOL_STATE_TYPE,
            "version": VERSION,
            "schema": POOL_STATE_SCHEMA,
            "pool_id": contract["pool_id"],
            "pool_epoch": contract["pool_epoch"],
            "contract_sha256": contract["contract_sha256"],
            "state_sequence": 9,
            "status": status,
            "owner": contract["owner"],
            "coordinator_epoch": 0,
            "scheduler_cursor": 0,
            "active_children": [],
            "terminal_children": [child["child_id"] for child in contract["children"]],
            "children": children,
            "aggregate_usage": zero_usage(),
            "pool_started_monotonic_ns": 1,
            "pool_wall_seconds": 0,
            "worker_seconds": 0,
            "poll_overhead_seconds": 0,
            "lease_bindings": [lease["lease_sha256"] for lease in leases],
            "reasons": reasons,
            "first_protected_fault": first_protected_fault,
            "control_loss_scope": "pool" if status == "control-failed" else None,
        },
        "state_sha256",
    )


def alternate_contract(contract: dict, *, nested_target: bool = False, same_worktree: bool = False) -> dict:
    changed = copy.deepcopy(contract)
    changed["pool_id"] = "pool-2"
    changed["pool_epoch"] = "epoch-2"
    child = changed["children"][0]
    child.update(
        {
            "child_id": "other-child",
            "packet_id": "other-packet",
            "attempt_nonce": "other-nonce",
            "session_id": "other-session",
            "agent_id": "other-agent",
            "control_turn_id": "other-turn",
            "state_file": "/tmp/other-child.json",
            "lease_id": "other-lease",
        }
    )
    if not same_worktree:
        child["worktree_identity"] = identity("other-worktree")
    target = "scripts/child_0.py/nested" if nested_target else "tests/other.py"
    child["declared_write_paths"] = [target]
    child["integration_target_paths"] = [target]
    return seal_artifact(changed, "contract_sha256")


class NativePoolLeaseTests(unittest.TestCase):
    def test_process_owner_identity_is_strong_and_live(self) -> None:
        owner = capture_owner_identity()
        self.assertTrue(owner_identity_is_live(owner))
        changed = {**owner, "start_ticks": owner["start_ticks"] + 1}
        self.assertFalse(owner_identity_is_live(changed))

    def test_acquire_hold_release_is_private_and_hash_valid(self) -> None:
        contract, _ = pool_contract(cap=1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "leases.json"
            registry = PoolLeaseRegistry(path, owner_alive=lambda _: True, now=lambda: NOW)
            acquired = registry.acquire(contract, "child-0")
            self.assertEqual(validate_lease(acquired, contract=contract), [])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            held = registry.hold("lease-0")
            self.assertEqual(held["lifecycle_state"], "held")
            state = terminal_state(contract, [held])
            self.assertEqual(validate_pool_state(state, contract=contract), [])
            released = registry.release("lease-0", terminal_state=state)
            self.assertEqual(released["lifecycle_state"], "released")
            self.assertEqual(released["terminal_evidence_sha256"], state["state_sha256"])

    def test_overlapping_target_and_worktree_collisions_fail_closed(self) -> None:
        contract, _ = pool_contract(cap=1)
        with tempfile.TemporaryDirectory() as temporary:
            registry = PoolLeaseRegistry(
                Path(temporary) / "leases.json", owner_alive=lambda _: True, now=lambda: NOW
            )
            registry.acquire(contract, "child-0")
            with self.assertRaisesRegex(PoolLeaseCollision, "integration-target"):
                nested = alternate_contract(contract, nested_target=True)
                registry.acquire(nested, "other-child")
            with self.assertRaisesRegex(PoolLeaseCollision, "worktree"):
                same_worktree = alternate_contract(contract, same_worktree=True)
                same_worktree["children"][0]["worktree_identity"]["baseline_sha256"] = sha(
                    "different-baseline"
                )
                same_worktree = seal_artifact(same_worktree, "contract_sha256")
                registry.acquire(same_worktree, "other-child")

    def test_read_only_siblings_share_worktree_and_hold_empty_targets(self) -> None:
        contract, _ = pool_contract(read_only=True)
        with tempfile.TemporaryDirectory() as temporary:
            registry = PoolLeaseRegistry(
                Path(temporary) / "leases.json", owner_alive=lambda _: True, now=lambda: NOW
            )
            first = registry.acquire(contract, "child-0")
            second = registry.acquire(contract, "child-1")
            self.assertEqual(first["target_paths"], [])
            self.assertEqual(second["target_paths"], [])
            self.assertEqual(validate_lease(first, contract=contract), [])
            self.assertEqual(validate_lease(second, contract=contract), [])

    def test_dead_owner_requires_terminal_evidence_for_cleanup(self) -> None:
        contract, _ = pool_contract(cap=1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "leases.json"
            alive = True

            def owner_alive(_: dict) -> bool:
                return alive

            registry = PoolLeaseRegistry(path, owner_alive=owner_alive, now=lambda: NOW)
            lease = registry.acquire(contract, "child-0")
            alive = False
            changed = registry.cleanup_stale({})
            self.assertEqual(changed[0]["lifecycle_state"], "orphaned-active")

            state = terminal_state(contract, [lease])
            changed = registry.cleanup_stale({contract["pool_id"]: state})
            self.assertEqual(changed[0]["lifecycle_state"], "released")
            self.assertEqual(changed[0]["release_reason"], "stale-owner-terminal-pool")

    def test_control_failed_terminal_evidence_stays_release_pending(self) -> None:
        contract, _ = pool_contract(cap=1)
        with tempfile.TemporaryDirectory() as temporary:
            registry = PoolLeaseRegistry(
                Path(temporary) / "leases.json", owner_alive=lambda _: False, now=lambda: NOW
            )
            lease = registry.acquire(contract, "child-0")
            state = terminal_state(contract, [lease], status="control-failed")
            changed = registry.cleanup_stale({contract["pool_id"]: state})
            self.assertEqual(changed[0]["lifecycle_state"], "release-pending")
            self.assertEqual(changed[0]["release_reason"], "manual-containment-required")

    def test_symlink_and_corrupt_registry_are_rejected(self) -> None:
        contract, _ = pool_contract(cap=1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "leases.json"
            link.symlink_to(target)
            registry = PoolLeaseRegistry(link, owner_alive=lambda _: True, now=lambda: NOW)
            with self.assertRaisesRegex(PoolLeaseError, "symlink"):
                registry.acquire(contract, "child-0")

            link.unlink()
            link.write_text(json.dumps({"bad": True}), encoding="utf-8")
            with self.assertRaisesRegex(PoolLeaseError, "fields-invalid"):
                registry.snapshot()


if __name__ == "__main__":
    unittest.main()
