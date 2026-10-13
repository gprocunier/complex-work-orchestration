from __future__ import annotations

import copy
from dataclasses import replace
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import canonical_sha256  # noqa: E402
from cwo_core.native_pool_leases import PoolLeaseRegistry  # noqa: E402
from cwo_core.native_pool_preflight import run_pool_preflight  # noqa: E402
from cwo_core.native_pool_transaction import (  # noqa: E402
    AdmittedPoolLaunch,
    NativePoolItemError,
    NativePoolProtectedError,
    NativePoolTransactionError,
    PLAN_SCHEMA,
    PLAN_TYPE,
    RECOVERY_PLAN_SCHEMA,
    RECOVERY_TYPE,
    CAMPAIGN_RECOVERY_PLAN_SCHEMA,
    CAMPAIGN_RECOVERY_ID,
    CAMPAIGN_RECOVERY_PHASE,
    CAMPAIGN_RECOVERY_BEAD,
    TRANSACTION_CALL_GRAPH_SHA256,
    TransactionJournal,
    TransactionRuntime,
    build_readiness_record,
    execute_native_pool_transaction,
    execution_authoritative_bead_projection,
    execution_authoritative_bead_sha256,
    readiness_horizon_errors,
    seal_transaction_plan,
    validate_readiness_record,
    validate_transaction_plan,
)
from tests.test_native_pool_admission import _live  # noqa: E402
from tests.test_native_pool_admission_contracts import (  # noqa: E402
    _admitted_artifacts,
    _execution_inputs,
)
from tests.test_native_pool import FakeClock  # noqa: E402


NOW = dt.datetime(2026, 9, 7, 16, 0, tzinfo=dt.timezone.utc)
MODEL = "gpt-5.6-luna"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


class MutableUtcClock:
    def __init__(self, value: dt.datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> dt.datetime:
        return self.value

    def advance_ms(self, value: int) -> None:
        self.value += dt.timedelta(milliseconds=value)


def bead(bead_id: str, path: str) -> dict:
    return {
        "id": bead_id,
        "title": f"Task {bead_id}",
        "status": "open",
        "assignee": None,
        "parent": "epic-1",
        "priority": 1,
        "issue_type": "task",
        "acceptance_criteria": f"Validate {path}",
        "labels": ["wave-0", "implementation"],
        "dependencies": [
            {
                "id": "gate-1",
                "status": "closed",
                "dependency_type": "blocks",
                "comments": [{"ignored": True}],
            }
        ],
        "metadata": {
            "cwo_ready_set_admission": {
                "declared_read_paths": [],
                "declared_write_paths": [path],
                "integration_target_paths": [path],
                "isolation_class": "mutable-isolated",
                "topology": "single-host-process-v1",
                "share_boundary": "no-outside-sharing",
                "work_plan": {"bead_id": bead_id, "path": path},
            }
        },
        "comments": [{"body": "provenance only"}],
        "updated_at": "2026-09-07T15:00:00Z",
    }


def adapter_file(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "runtime_adapter.py"
    path.write_text("# hash-bound test adapter\n", encoding="utf-8")
    return path


def transaction_plan(
    root: Path,
    beads: list[dict],
    *,
    prelude: int = 0,
    cumulative_before: int = 239,
    ceiling: int | None = None,
    reserved: int | None = None,
) -> dict:
    adapter = adapter_file(root)
    children = []
    for index, issue in enumerate(beads):
        path = issue["metadata"]["cwo_ready_set_admission"]["declared_write_paths"][0]
        children.append(
            {
                "child_id": f"child-{index}",
                "bead_id": issue["id"],
                "segment_id": f"segment-{index}",
                "work_unit_id": f"work-unit-{index}",
                "requested_model": MODEL,
                "bead_projection_sha256": execution_authoritative_bead_sha256(issue),
                "worktree_identity_sha256": hashlib.sha256(
                    f"worktree-{index}".encode()
                ).hexdigest(),
                "work_plan_sha256": hashlib.sha256(
                    f"plan-{index}".encode()
                ).hexdigest(),
                "packet_blueprint_sha256": hashlib.sha256(
                    f"packet-{index}".encode()
                ).hexdigest(),
                "write_paths": [path],
            }
        )
    needed = prelude + len(children)
    reserved_sessions = needed if reserved is None else reserved
    limit = cumulative_before + reserved_sessions if ceiling is None else ceiling
    return seal_transaction_plan(
        {
            "plan_type": PLAN_TYPE,
            "version": 1,
            "schema": PLAN_SCHEMA,
            "transaction_id": f"transaction-{len(children)}-{prelude}",
            "phase_id": f"test-n{len(children)}",
            "candidate_manifest_sha256": "a" * 64,
            "controller_overlay_sha256": "b" * 64,
            "authority_sha256": "c" * 64,
            "call_graph_sha256": TRANSACTION_CALL_GRAPH_SHA256,
            "runtime_adapter_path": str(adapter),
            "runtime_adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
            "created_at": "2026-09-07T16:00:00Z",
            "selected_model": MODEL,
            "prelude_session_count": prelude,
            "required_session_count": needed,
            "budget": {
                "cumulative_before": cumulative_before,
                "cumulative_ceiling": limit,
                "reserved_sessions": reserved_sessions,
                "infrastructure_failures_before": 0,
                "maximum_infrastructure_failures": 3,
            },
            "startup_bounds_ms": {
                "pre_allocation_ms": 10,
                "per_allocation_ms": 20,
                "runtime_binding_ms": 10,
                "admission_ms": 10,
                "dispatch_and_first_observation_ms": 20,
                "safety_margin_ms": 30,
            },
            "children": children,
            "plan_sha256": "",
        }
    )


def recovery_plan(root: Path, issue: dict) -> dict:
    """Strict v2 fixture for one campaign-bound 3+1 opportunity."""

    plan = transaction_plan(root, [issue], prelude=1)
    plan["version"] = 2
    plan["schema"] = RECOVERY_PLAN_SCHEMA
    plan["budget"]["infrastructure_failures_before"] = 3
    plan["budget"]["maximum_infrastructure_failures"] = 4
    recovery = {
        "recovery_type": RECOVERY_TYPE,
        "version": 1,
        "campaign_id": "campaign-only-p1a",
        "phase_id": plan["phase_id"],
        "bead_id": issue["id"],
        "selected_model": MODEL,
        "authority_sha256": plan["authority_sha256"],
        "prior_failure_evidence_sha256": "f" * 64,
        "opportunity_ledger_path": str(root / "recovery-opportunity.json"),
        "additional_opportunities": 1,
    }
    recovery["grant_sha256"] = canonical_sha256(recovery)
    plan["infrastructure_recovery"] = recovery
    return seal_transaction_plan(plan)


def campaign_recovery_plan(root: Path) -> tuple[dict, dict]:
    """Strict P1a-only v3 fixture carrying the truthful four prior failures."""

    issue = bead(CAMPAIGN_RECOVERY_BEAD, "policy/native-worker-execution.yaml")
    plan = recovery_plan(root, issue)
    plan["version"] = 3
    plan["schema"] = CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan["phase_id"] = CAMPAIGN_RECOVERY_PHASE
    plan["budget"]["infrastructure_failures_before"] = 4
    plan["budget"]["maximum_infrastructure_failures"] = 5
    recovery = plan["infrastructure_recovery"]
    recovery["version"] = 2
    recovery["campaign_id"] = CAMPAIGN_RECOVERY_ID
    recovery["phase_id"] = CAMPAIGN_RECOVERY_PHASE
    recovery["bead_id"] = CAMPAIGN_RECOVERY_BEAD
    recovery["grant_sha256"] = canonical_sha256(
        {key: value for key, value in recovery.items() if key != "grant_sha256"}
    )
    return seal_transaction_plan(plan), issue


def dependencies(plan: dict, *, issued: dt.datetime = NOW, ttl_ms: int = 10_000) -> list[dict]:
    result = []
    for child in plan["children"]:
        for kind in ("precommit-receipt", "operative-release", "canary-release"):
            result.append(
                {
                    "child_id": child["child_id"],
                    "kind": kind,
                    "evidence_sha256": hashlib.sha256(
                        f"{child['child_id']}:{kind}:{issued.isoformat()}".encode()
                    ).hexdigest(),
                    "issued_at": issued.isoformat().replace("+00:00", "Z"),
                    "expires_at": (issued + dt.timedelta(milliseconds=ttl_ms))
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            )
    return result


def packet_bindings(plan: dict) -> list[dict]:
    return [
        {
            "child_id": child["child_id"],
            "packet_sha256": hashlib.sha256(
                f"runtime-packet:{child['child_id']}".encode()
            ).hexdigest(),
            "precommit_receipt_sha256": hashlib.sha256(
                f"precommit:{child['child_id']}".encode()
            ).hexdigest(),
            "work_plan_sha256": child["work_plan_sha256"],
        }
        for child in plan["children"]
    ]


class RuntimeHarness:
    def __init__(
        self,
        plan: dict,
        bead_records: list[dict],
        *,
        clock: MutableUtcClock,
        launch: AdmittedPoolLaunch | None = None,
        dependency_ttl_ms: int = 10_000,
    ) -> None:
        self.plan = plan
        self.beads = {item["id"]: item for item in bead_records}
        self.clock = clock
        self.launch = launch
        self.dependency_ttl_ms = dependency_ttl_ms
        self.starts: list[dict] = []
        self.reentrant_states: list[str | None] = []
        self.containments: list[dict] = []
        self.pool_turns: list[str] = []
        self.refreshes = 0
        self.validation = {
            "accepted": True,
            "healthy_evidence_retained": True,
            "atomic_promotion_authorized": True,
        }

    def read_bead(self, bead_id: str) -> dict:
        return copy.deepcopy(self.beads[bead_id])

    def prepare(self, plan: dict) -> dict:
        return {
            "phase_id": plan["phase_id"],
            "candidate_manifest_sha256": plan["candidate_manifest_sha256"],
            "controller_overlay_sha256": plan["controller_overlay_sha256"],
            "authority_sha256": plan["authority_sha256"],
            "runtime_adapter_sha256": plan["runtime_adapter_sha256"],
        }

    def trusted_session_count(self) -> int:
        return self.plan["budget"]["cumulative_before"] + len(self.starts)

    def _allocation(self, call_context: dict, child: dict | None) -> dict:
        intent = call_context["transaction_allocation"]
        session_id = f"session-{len(self.starts)}"
        if child is not None and self.launch is not None:
            session_id = next(
                str(item["session_id"])
                for item in self.launch.contract["children"]
                if item["child_id"] == child["child_id"]
            )
        allocation = {
            "allocation_id": intent["allocation_id"],
            "allocation_class": intent["allocation_class"],
            "child_id": child["child_id"] if child else None,
            "session_id": session_id,
            "requested_model": MODEL,
            "actual_model": MODEL,
            "attestation_source": "trusted-session-jsonl",
            "interrupt_supported": True,
            "close_supported": True,
            "wait_supported": True,
            "workspace_identity_sha256": (
                child["worktree_identity_sha256"] if child else None
            ),
        }
        self.starts.append(allocation)
        return allocation

    def start_prelude(self, _ordinal: int, call_context: dict) -> dict:
        return self._allocation(call_context, None)

    def release_artifacts(self, _plan: dict, _context: dict, _parent: dict | None) -> dict:
        return {
            "packet_bindings": packet_bindings(self.plan),
            "release_dependencies": dependencies(
                self.plan,
                issued=self.clock(),
                ttl_ms=self.dependency_ttl_ms,
            ),
        }

    def refresh(self, _plan: dict, _context: dict, _parent: dict | None) -> dict:
        self.refreshes += 1
        return {
            "packet_bindings": packet_bindings(self.plan),
            "release_dependencies": dependencies(
                self.plan, issued=self.clock(), ttl_ms=10_000
            ),
        }

    def start_worker(self, child: dict, call_context: dict) -> dict:
        journal_path = call_context.get("journal_path")
        if journal_path:
            events = TransactionJournal(
                journal_path, self.plan["transaction_id"]
            ).read()
            self.reentrant_states.append(events[-1]["state"])
        return self._allocation(call_context, child)

    def bind(self, _plan: dict, allocations: list[dict], _context: dict) -> AdmittedPoolLaunch:
        if self.launch is not None:
            return self.launch
        contract = {
            "contract_sha256": "d" * 64,
            "children": [
                {"child_id": item["child_id"], "session_id": item["session_id"]}
                for item in allocations
            ],
        }
        task_inputs = {
            item["child_id"]: f"task:{item['child_id']}" for item in allocations
        }
        child_callbacks = {
            item["child_id"]: {
                "send_input": (
                    lambda _task, child_id=item["child_id"]: self.pool_turns.append(
                        child_id
                    )
                )
            }
            for item in allocations
        }
        return AdmittedPoolLaunch(
            reservation_receipt={"reservation_sha256": "e" * 64},
            admission_capability=object(),
            contract=contract,
            preflight_request={},
            preflight_result={},
            child_contracts={},
            task_inputs=task_inputs,
            child_callbacks=child_callbacks,
            keyword_arguments={},
        )

    def contain(self, started: list[dict], reason: str, _context: dict) -> dict:
        result = {
            "all_contained": True,
            "session_ids": [item.get("session_id") for item in started],
            "reason": reason,
        }
        self.containments.append(result)
        return result

    def validate(self, _launched: dict, _context: dict) -> dict:
        return copy.deepcopy(self.validation)

    def runtime(self, *, journal_path: Path | None = None) -> TransactionRuntime:
        def prepare(plan: dict) -> dict:
            result = dict(self.prepare(plan))
            if journal_path is not None:
                result["journal_path"] = str(journal_path)
            return result

        return TransactionRuntime(
            trusted_session_count=self.trusted_session_count,
            read_bead=self.read_bead,
            prepare=prepare,
            start_prelude_session=self.start_prelude,
            release_artifacts=self.release_artifacts,
            refresh_release_artifacts=self.refresh,
            start_worker_session=self.start_worker,
            bind_admitted_launch=self.bind,
            contain=self.contain,
            validate=self.validate,
        )


class NativePoolTransactionTests(unittest.TestCase):
    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_plan_and_readiness_match_strict_schemas(self) -> None:
        import jsonschema

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            readiness = build_readiness_record(
                plan,
                {issue["id"]: issue},
                packet_bindings(plan),
                dependencies(plan),
                now=NOW,
            )
            plan_schema = json.loads(
                (ROOT / "schemas" / "native-pool-transaction-plan.schema.json").read_text()
            )
            readiness_schema = json.loads(
                (ROOT / "schemas" / "native-pool-transaction-readiness.schema.json").read_text()
            )
            jsonschema.validate(plan, plan_schema)
            jsonschema.validate(readiness, readiness_schema)

    def test_plan_accepts_n1_n2_n3_and_rejects_budget_below_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for size in (1, 2, 3):
                with self.subTest(size=size):
                    issues = [bead(f"bead-{index}", f"file-{index}") for index in range(size)]
                    plan = transaction_plan(root / f"n{size}", issues, prelude=1)
                    self.assertEqual(validate_transaction_plan(plan), [])
                    self.assertEqual(plan["required_session_count"], size + 1)
            issues = [bead("bead-budget", "budget.txt")]
            with self.assertRaisesRegex(
                NativePoolTransactionError,
                "session-reservation-insufficient",
            ):
                transaction_plan(root / "below", issues, prelude=1, reserved=1)
            above = transaction_plan(
                root / "above", issues, prelude=1, reserved=3
            )
            self.assertEqual(validate_transaction_plan(above), [])

    def test_plan_accepts_explicit_read_only_child_and_rejects_ambiguous_empty_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-read-only", "unused.txt")
            plan = transaction_plan(root, [issue])

            read_only = copy.deepcopy(plan)
            read_only["children"][0]["write_paths"] = []
            read_only["children"][0]["read_only"] = True
            read_only["plan_sha256"] = canonical_sha256(
                {key: value for key, value in read_only.items() if key != "plan_sha256"}
            )
            self.assertEqual(validate_transaction_plan(read_only), [])

            ambiguous = copy.deepcopy(read_only)
            del ambiguous["children"][0]["read_only"]
            ambiguous["plan_sha256"] = canonical_sha256(
                {key: value for key, value in ambiguous.items() if key != "plan_sha256"}
            )
            self.assertIn(
                "transaction-plan-child-read-only-invalid",
                validate_transaction_plan(ambiguous),
            )

            contradictory = copy.deepcopy(plan)
            contradictory["children"][0]["read_only"] = True
            contradictory["plan_sha256"] = canonical_sha256(
                {key: value for key, value in contradictory.items() if key != "plan_sha256"}
            )
            self.assertIn(
                "transaction-plan-child-read-only-invalid",
                validate_transaction_plan(contradictory),
            )

    def test_plan_rejects_overlapping_write_ownership_and_open_fuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issues = [bead("bead-a", "same.txt"), bead("bead-b", "other.txt")]
            plan = transaction_plan(root, issues)
            changed = copy.deepcopy(plan)
            changed["children"][1]["write_paths"] = ["same.txt"]
            changed["plan_sha256"] = canonical_sha256(
                {key: value for key, value in changed.items() if key != "plan_sha256"}
            )
            self.assertIn(
                "transaction-plan-child-write-paths-overlap",
                validate_transaction_plan(changed),
            )
            changed = copy.deepcopy(plan)
            changed["budget"]["infrastructure_failures_before"] = 3
            changed["plan_sha256"] = canonical_sha256(
                {key: value for key, value in changed.items() if key != "plan_sha256"}
            )
            self.assertIn(
                "transaction-plan-infrastructure-fuse-open",
                validate_transaction_plan(changed),
            )

    def test_bead_projection_ignores_comments_but_binds_execution_fields(self) -> None:
        issue = bead("bead-a", "a.txt")
        original = execution_authoritative_bead_projection(issue)
        provenance_only = copy.deepcopy(issue)
        provenance_only["comments"].append({"body": "new history"})
        provenance_only["updated_at"] = "2026-09-07T16:01:00Z"
        self.assertEqual(
            execution_authoritative_bead_projection(provenance_only), original
        )
        for mutation in ("status", "assignee", "acceptance_criteria"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(issue)
                changed[mutation] = "changed"
                self.assertNotEqual(
                    execution_authoritative_bead_sha256(changed),
                    execution_authoritative_bead_sha256(issue),
                )
        string_metadata = copy.deepcopy(issue)
        string_metadata["metadata"]["cwo_ready_set_admission"] = json.dumps(
            issue["metadata"]["cwo_ready_set_admission"], sort_keys=True
        )
        self.assertEqual(
            execution_authoritative_bead_projection(string_metadata), original
        )

    def test_horizon_is_inclusive_live_but_requires_remaining_margin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            expiry = NOW + dt.timedelta(seconds=1)
            deps = dependencies(plan, issued=NOW, ttl_ms=1000)
            record = build_readiness_record(
                plan,
                {issue["id"]: issue},
                packet_bindings(plan),
                deps,
                now=expiry,
            )
            errors = readiness_horizon_errors(
                record,
                plan,
                now=expiry,
                remaining_allocations=0,
            )
            self.assertTrue(
                any("horizon-insufficient" in error for error in errors), errors
            )
            exact_needed = sum(
                plan["startup_bounds_ms"][field]
                for field in (
                    "runtime_binding_ms",
                    "admission_ms",
                    "dispatch_and_first_observation_ms",
                    "safety_margin_ms",
                )
            )
            exact_now = NOW + dt.timedelta(milliseconds=1000 - exact_needed)
            self.assertEqual(
                readiness_horizon_errors(
                    build_readiness_record(
                        plan,
                        {issue["id"]: issue},
                        packet_bindings(plan),
                        deps,
                        now=exact_now,
                    ),
                    plan,
                    now=exact_now,
                    remaining_allocations=0,
                ),
                [],
            )

    def test_readiness_duration_uses_persisted_millisecond_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            current = NOW.replace(microsecond=123456)
            deps = dependencies(
                plan,
                issued=current - dt.timedelta(seconds=1),
                ttl_ms=10_000,
            )
            record = build_readiness_record(
                plan,
                {issue["id"]: issue},
                packet_bindings(plan),
                deps,
                now=current,
            )
            self.assertEqual(validate_readiness_record(record, plan=plan), [])
            created = dt.datetime.fromisoformat(
                record["created_at"].replace("Z", "+00:00")
            )
            earliest = dt.datetime.fromisoformat(
                record["earliest_expires_at"].replace("Z", "+00:00")
            )
            self.assertEqual(
                record["available_lifetime_ms"],
                int((earliest - created).total_seconds() * 1000),
            )

    def test_stale_packet_with_fresh_canary_starts_zero_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            clock = MutableUtcClock()
            harness = RuntimeHarness(plan, [issue], clock=clock)
            stale = dependencies(plan, issued=NOW - dt.timedelta(seconds=2), ttl_ms=1000)
            fresh = dependencies(plan, issued=NOW, ttl_ms=10_000)
            mixed = [
                stale[1] if item["kind"] == "operative-release" else item
                for item in fresh
            ]
            mixed_bundle = {
                "packet_bindings": packet_bindings(plan),
                "release_dependencies": mixed,
            }
            harness.release_artifacts = lambda *_args: mixed_bundle  # type: ignore[method-assign]
            harness.refresh = lambda *_args: mixed_bundle  # type: ignore[method-assign]
            with self.assertRaisesRegex(
                NativePoolTransactionError, "release-dependency-not-live"
            ):
                execute_native_pool_transaction(
                    plan,
                    harness.runtime(),
                    journal_path=root / "journal.jsonl",
                    now_utc=clock,
                    run_pool=lambda *_args, **_kwargs: {},
                )
            self.assertEqual(harness.starts, [])

    def test_horizon_refreshes_between_allocations_without_hidden_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issues = [bead(f"bead-{index}", f"file-{index}") for index in range(3)]
            plan = transaction_plan(root, issues)
            clock = MutableUtcClock()
            harness = RuntimeHarness(
                plan,
                issues,
                clock=clock,
                dependency_ttl_ms=200,
            )
            ordinary_start = harness.start_worker

            def delayed_start(child: dict, context: dict) -> dict:
                allocation = ordinary_start(child, context)
                clock.advance_ms(100)
                return allocation

            harness.start_worker = delayed_start  # type: ignore[method-assign]
            result = execute_native_pool_transaction(
                plan,
                harness.runtime(),
                journal_path=root / "journal.jsonl",
                now_utc=clock,
                run_pool=lambda *_args, **_kwargs: {
                    "pool_receipt": {"accepting": True}
                },
            )
            self.assertTrue(result["accepted"])
            self.assertEqual(harness.refreshes, 1)
            self.assertEqual(
                harness.trusted_session_count(),
                plan["budget"]["cumulative_before"] + 3,
            )

    def test_final_horizon_overrun_contains_before_admitted_pool_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            clock = MutableUtcClock()
            harness = RuntimeHarness(
                plan,
                [issue],
                clock=clock,
                dependency_ttl_ms=200,
            )
            ordinary_bind = harness.bind

            def slow_bind(plan_value, allocations, context):
                launch = ordinary_bind(plan_value, allocations, context)
                clock.advance_ms(180)
                return launch

            harness.bind = slow_bind  # type: ignore[method-assign]
            pool_called = False

            def forbidden_pool(*_args, **_kwargs):
                nonlocal pool_called
                pool_called = True
                return {}

            with self.assertRaisesRegex(
                NativePoolTransactionError,
                "final-release-horizon-invalid",
            ):
                execute_native_pool_transaction(
                    plan,
                    harness.runtime(),
                    journal_path=root / "journal.jsonl",
                    now_utc=clock,
                    run_pool=forbidden_pool,
                )
            self.assertFalse(pool_called)
            self.assertEqual(
                TransactionJournal(root / "journal.jsonl", plan["transaction_id"]).current_state,
                "CONTAINED",
            )

    def test_reentrant_observer_sees_intent_before_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            journal = root / "journal.jsonl"
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def run_pool(*args, **_kwargs):
                del _kwargs
                task_inputs = args[6]
                child_callbacks = args[7]
                for child_id, callbacks in child_callbacks.items():
                    callbacks["send_input"](task_inputs[child_id])
                return {"pool_receipt": {"accepting": True}}

            result = execute_native_pool_transaction(
                plan,
                harness.runtime(journal_path=journal),
                journal_path=journal,
                now_utc=harness.clock,
                run_pool=run_pool,
            )
            self.assertTrue(result["accepted"])
            self.assertEqual(harness.reentrant_states, ["ALLOCATING"])
            self.assertEqual(harness.pool_turns, ["child-0"])
            events = TransactionJournal(journal, plan["transaction_id"]).read()
            intent_index = next(
                index
                for index, event in enumerate(events)
                if event["event_type"] == "allocation-intent"
            )
            bound_index = next(
                index
                for index, event in enumerate(events)
                if event["event_type"] == "allocation-bound"
            )
            self.assertLess(intent_index, bound_index)

    def test_lost_acknowledgement_is_contained_and_trips_infrastructure_fuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def lost(_child, context):
                harness._allocation(context, plan["children"][0])
                raise ConnectionError("ack lost")

            harness.start_worker = lost  # type: ignore[method-assign]
            journal_path = root / "journal.jsonl"
            with self.assertRaisesRegex(Exception, "allocation-acknowledgement-lost"):
                execute_native_pool_transaction(
                    plan,
                    harness.runtime(),
                    journal_path=journal_path,
                    now_utc=harness.clock,
                    run_pool=lambda *_args, **_kwargs: {},
                )
            journal = TransactionJournal(journal_path, plan["transaction_id"])
            self.assertEqual(journal.infrastructure_failure_count, 1)
            self.assertEqual(journal.current_state, "CONTAINED")
            self.assertTrue(harness.containments[0]["all_contained"])

    def test_failed_validation_retains_healthy_evidence_without_atomic_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issues = [bead("bead-a", "a.txt"), bead("bead-b", "b.txt")]
            plan = transaction_plan(root, issues)
            harness = RuntimeHarness(plan, issues, clock=MutableUtcClock())
            harness.validation = {
                "accepted": False,
                "healthy_evidence_retained": True,
                "atomic_promotion_authorized": False,
                "reason": "one-item-needs-correction",
            }
            result = execute_native_pool_transaction(
                plan,
                harness.runtime(),
                journal_path=root / "journal.jsonl",
                now_utc=harness.clock,
                run_pool=lambda *_args, **_kwargs: {
                    "pool_receipt": {"accepting": False}
                },
            )
            self.assertEqual(result["state"], "CONTAINED")
            self.assertTrue(result["validation"]["healthy_evidence_retained"])
            self.assertFalse(result["validation"]["atomic_promotion_authorized"])

    def test_typed_item_failure_is_contained_without_spending_infrastructure_fuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def item_failure(_launched: dict, _context: dict) -> dict:
                raise NativePoolItemError(
                    "focused-validation-failed",
                    evidence={"command": "python -m unittest tests.test_example"},
                )

            harness.validate = item_failure  # type: ignore[method-assign]
            journal_path = root / "journal.jsonl"
            result = execute_native_pool_transaction(
                plan,
                harness.runtime(),
                journal_path=journal_path,
                now_utc=harness.clock,
                run_pool=lambda *_args, **_kwargs: {
                    "pool_receipt": {"accepting": False}
                },
            )
            journal = TransactionJournal(journal_path, plan["transaction_id"])
            events = journal.read()
            self.assertEqual(result["state"], "CONTAINED")
            self.assertEqual(result["failure_class"], "item")
            self.assertEqual(result["validation"]["failure_class"], "item")
            self.assertEqual(journal.infrastructure_failure_count, 0)
            self.assertEqual(
                sum(event["event_type"] == "item-failure" for event in events), 1
            )
            self.assertTrue(harness.containments[0]["all_contained"])

    def test_protected_failure_is_contained_and_never_classified_as_item(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = transaction_plan(root, [issue])
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def protected(_launched: dict, _context: dict) -> dict:
                raise NativePoolProtectedError(
                    "unexpected-workspace-mutation",
                    evidence={"path": "outside.txt"},
                )

            harness.validate = protected  # type: ignore[method-assign]
            journal_path = root / "journal.jsonl"
            with self.assertRaisesRegex(
                NativePoolProtectedError, "unexpected-workspace-mutation"
            ):
                execute_native_pool_transaction(
                    plan,
                    harness.runtime(),
                    journal_path=journal_path,
                    now_utc=harness.clock,
                    run_pool=lambda *_args, **_kwargs: {
                        "pool_receipt": {"accepting": False}
                    },
                )
            journal = TransactionJournal(journal_path, plan["transaction_id"])
            events = journal.read()
            self.assertEqual(journal.current_state, "CONTAINED")
            self.assertEqual(journal.infrastructure_failure_count, 0)
            self.assertEqual(
                sum(event["event_type"] == "protected-stop" for event in events), 1
            )
            self.assertEqual(
                sum(event["event_type"] == "item-failure" for event in events), 0
            )
            self.assertTrue(harness.containments[0]["all_contained"])

    def test_real_admitted_pool_path_reaches_worker_turn_for_n1_n2_n3(self) -> None:
        for size in (1, 2, 3):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture, reservation, contract, request = _admitted_artifacts(
                    root,
                    size=size,
                    requested_model=MODEL,
                )
                preflight = run_pool_preflight(
                    request, policy_document=fixture.policy_document
                )
                self.assertTrue(preflight["accepted"], preflight["findings"])
                (
                    child_contracts,
                    tasks,
                    child_callbacks,
                    adapters,
                    pool_callbacks,
                    _pool_clock,
                ) = _execution_inputs(fixture, contract)
                for child_adapter in adapters.values():
                    child_adapter.decisions = ["continue", "complete"]
                launch = AdmittedPoolLaunch(
                    reservation,
                    fixture.admission_capability,
                    contract,
                    request,
                    preflight,
                    child_contracts,
                    tasks,
                    child_callbacks,
                    {
                        "claim_adapter": fixture.claim_adapter,
                        "live_revalidate": _live,
                        "pool_callbacks": pool_callbacks,
                        "lease_registry": PoolLeaseRegistry(
                            root / "transaction-leases.json",
                            owner_alive=lambda _owner: True,
                            now=FakeClock.now_utc,
                        ),
                        "capability_receipt": (
                            None if size == 1 else fixture.pool_capability_receipt
                        ),
                        "policy_document": fixture.policy_document,
                    },
                )
                issues = [
                    bead(child["bead_id"], f"path-{index}.txt")
                    for index, child in enumerate(contract["children"])
                ]
                plan = transaction_plan(root / "transaction", issues)
                for planned, admitted in zip(plan["children"], contract["children"]):
                    planned["child_id"] = admitted["child_id"]
                    planned["bead_id"] = admitted["bead_id"]
                    planned["work_unit_id"] = admitted["work_unit_id"]
                plan["plan_sha256"] = canonical_sha256(
                    {key: value for key, value in plan.items() if key != "plan_sha256"}
                )
                issue_by_id = {item["id"]: item for item in issues}
                for child in plan["children"]:
                    child["bead_projection_sha256"] = execution_authoritative_bead_sha256(
                        issue_by_id[child["bead_id"]]
                    )
                plan["plan_sha256"] = canonical_sha256(
                    {key: value for key, value in plan.items() if key != "plan_sha256"}
                )
                harness = RuntimeHarness(
                    plan,
                    issues,
                    clock=MutableUtcClock(),
                    launch=launch,
                )
                result = execute_native_pool_transaction(
                    plan,
                    harness.runtime(),
                    journal_path=root / "transaction-journal.jsonl",
                    now_utc=harness.clock,
                )
                self.assertTrue(result["accepted"], result)
                self.assertTrue(result["launch_result"]["pool_receipt"]["accepting"])
                for child_adapter in adapters.values():
                    self.assertIn("send_input", child_adapter.calls)


class NativePoolCampaignRecoveryTests(unittest.TestCase):
    @staticmethod
    def reseal(plan: dict) -> dict:
        plan["infrastructure_recovery"]["grant_sha256"] = canonical_sha256(
            {key: value for key, value in plan["infrastructure_recovery"].items() if key != "grant_sha256"}
        )
        plan["plan_sha256"] = canonical_sha256(
            {key: value for key, value in plan.items() if key != "plan_sha256"}
        )
        return plan

    @staticmethod
    def authorized_runtime(harness: RuntimeHarness, *, expected_grant: dict | None = None) -> TransactionRuntime:
        pinned = copy.deepcopy(expected_grant or harness.plan["infrastructure_recovery"])
        return replace(
            harness.runtime(),
            authorize_recovery=lambda plan: plan.get("infrastructure_recovery") == pinned,
            persist_first_allocation_intent=lambda _context: None,
        )

    def test_v3_is_p1a_only_and_does_not_change_v1_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _issue = campaign_recovery_plan(root)
            self.assertEqual(validate_transaction_plan(plan), [])
            if HAS_JSONSCHEMA:
                import jsonschema

                schema = json.loads((ROOT / CAMPAIGN_RECOVERY_PLAN_SCHEMA).read_text(encoding="utf-8"))
                jsonschema.validate(plan, schema)
            for name, change in (
                ("unrelated-campaign", lambda p: p["infrastructure_recovery"].__setitem__("campaign_id", "other")),
                ("wrong-phase", lambda p: p["infrastructure_recovery"].__setitem__("phase_id", "other")),
                ("wrong-bead", lambda p: p["infrastructure_recovery"].__setitem__("bead_id", "other")),
                ("false-prior", lambda p: p["budget"].__setitem__("infrastructure_failures_before", 3)),
                ("global-max", lambda p: p["budget"].__setitem__("maximum_infrastructure_failures", 6)),
                ("wrong-grant-version", lambda p: p["infrastructure_recovery"].__setitem__("version", 1)),
                ("second-opportunity", lambda p: p["infrastructure_recovery"].__setitem__("additional_opportunities", 2)),
                ("wrong-model", lambda p: p["infrastructure_recovery"].__setitem__("selected_model", "wrong-model")),
                ("wrong-authority", lambda p: p["infrastructure_recovery"].__setitem__("authority_sha256", "0" * 64)),
            ):
                with self.subTest(name=name):
                    altered = copy.deepcopy(plan)
                    change(altered)
                    self.reseal(altered)
                    self.assertTrue(validate_transaction_plan(altered))
            v1 = transaction_plan(root / "v1", [bead("ordinary", "x.txt")], prelude=1)
            v2 = recovery_plan(root / "v2", bead("ordinary", "x.txt"))
            self.assertEqual(validate_transaction_plan(v1), [])
            self.assertEqual(validate_transaction_plan(v2), [])

    def test_v3_pinned_authority_claim_order_new_id_and_second_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, issue = campaign_recovery_plan(root)
            clock = MutableUtcClock()
            harness = RuntimeHarness(plan, [issue], clock=clock)
            opportunity = Path(plan["infrastructure_recovery"]["opportunity_ledger_path"])
            with self.assertRaisesRegex(NativePoolProtectedError, "authority-missing"):
                execute_native_pool_transaction(
                    plan, harness.runtime(), journal_path=root / "no-authority.jsonl",
                    now_utc=clock, run_pool=lambda *_a, **_k: {},
                )
            self.assertFalse(opportunity.exists())
            pinned = copy.deepcopy(plan["infrastructure_recovery"])
            changed = copy.deepcopy(plan)
            changed["infrastructure_recovery"]["prior_failure_evidence_sha256"] = "0" * 64
            self.reseal(changed)
            changed_harness = RuntimeHarness(changed, [issue], clock=clock)
            with self.assertRaisesRegex(NativePoolProtectedError, "authority-rejected"):
                execute_native_pool_transaction(
                    changed, self.authorized_runtime(changed_harness, expected_grant=pinned),
                    journal_path=root / "changed-history.jsonl", now_utc=clock,
                    run_pool=lambda *_a, **_k: {},
                )
            self.assertFalse(opportunity.exists())

            intent_seen: list[bool] = []
            original_start = harness.start_prelude

            def observe(_ordinal: int, context: dict) -> dict:
                events = TransactionJournal(root / "first.jsonl", plan["transaction_id"]).read()
                intent_seen.append(any(event["event_type"] == "allocation-intent" for event in events))
                self.assertTrue(opportunity.exists())
                event = json.loads(opportunity.read_text(encoding="utf-8"))
                self.assertEqual(event["prior_infrastructure_failures"], 4)
                self.assertEqual(event["additional_opportunities"], 1)
                return original_start(_ordinal, context)

            harness.start_prelude = observe  # type: ignore[method-assign]
            result = execute_native_pool_transaction(
                plan, self.authorized_runtime(harness), journal_path=root / "first.jsonl",
                now_utc=clock, run_pool=lambda *_a, **_k: {"pool_receipt": {"accepting": True}},
            )
            self.assertTrue(result["accepted"])
            self.assertEqual(intent_seen, [True])
            second = copy.deepcopy(plan)
            second["transaction_id"] = "same-campaign-new-id"
            second["budget"]["cumulative_before"] += 2
            second["budget"]["cumulative_ceiling"] += 2
            self.reseal(second)
            second_harness = RuntimeHarness(second, [issue], clock=clock)
            with self.assertRaisesRegex(NativePoolProtectedError, "opportunity-already-consumed"):
                execute_native_pool_transaction(
                    second, self.authorized_runtime(second_harness),
                    journal_path=root / "second.jsonl", now_utc=clock,
                    run_pool=lambda *_a, **_k: {},
                )
            self.assertEqual(second_harness.starts, [])

    def test_v3_coherent_identity_substitution_still_cannot_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, issue = campaign_recovery_plan(root)
            pinned = copy.deepcopy(original["infrastructure_recovery"])
            for name in ("wrong-phase", "wrong-bead", "wrong-model", "wrong-authority"):
                with self.subTest(name=name):
                    altered = copy.deepcopy(original)
                    active_issue = issue
                    if name == "wrong-phase":
                        altered["phase_id"] = "other-phase"
                        altered["infrastructure_recovery"]["phase_id"] = "other-phase"
                    elif name == "wrong-bead":
                        active_issue = bead("other-bead", "policy/native-worker-execution.yaml")
                        altered["children"][0]["bead_id"] = active_issue["id"]
                        altered["children"][0]["bead_projection_sha256"] = execution_authoritative_bead_sha256(active_issue)
                        altered["infrastructure_recovery"]["bead_id"] = active_issue["id"]
                    elif name == "wrong-model":
                        altered["selected_model"] = "another-model"
                        altered["children"][0]["requested_model"] = "another-model"
                        altered["infrastructure_recovery"]["selected_model"] = "another-model"
                    else:
                        altered["authority_sha256"] = "0" * 64
                        altered["infrastructure_recovery"]["authority_sha256"] = "0" * 64
                    self.reseal(altered)
                    harness = RuntimeHarness(altered, [active_issue], clock=MutableUtcClock())
                    errors = validate_transaction_plan(altered)
                    if errors:
                        self.assertIn("transaction-plan-recovery-campaign-invalid", errors)
                    else:
                        with self.assertRaisesRegex(NativePoolProtectedError, "authority-rejected"):
                            execute_native_pool_transaction(
                                altered, self.authorized_runtime(harness, expected_grant=pinned),
                                journal_path=root / (name + ".jsonl"), now_utc=harness.clock,
                                run_pool=lambda *_a, **_k: {},
                            )
                    self.assertEqual(harness.starts, [])
            self.assertFalse((root / "recovery-opportunity.json").exists())

    def test_v3_lost_ack_contains_and_consumes_one_opportunity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, issue = campaign_recovery_plan(root)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def lost(_ordinal: int, context: dict) -> dict:
                harness._allocation(context, None)
                raise ConnectionError("synthetic acknowledgement lost")

            harness.start_prelude = lost  # type: ignore[method-assign]
            journal_path = root / "failed.jsonl"
            with self.assertRaisesRegex(Exception, "allocation-acknowledgement-lost"):
                execute_native_pool_transaction(
                    plan, self.authorized_runtime(harness), journal_path=journal_path,
                    now_utc=harness.clock, run_pool=lambda *_a, **_k: {},
                )
            events = TransactionJournal(journal_path, plan["transaction_id"]).read()
            self.assertEqual(sum(event["event_type"] == "infrastructure-failure" for event in events), 1)
            self.assertEqual(events[-1]["state"], "CONTAINED")
            self.assertTrue(harness.containments[0]["all_contained"])
            self.assertEqual(len(harness.starts), 1)
            self.assertTrue((root / "recovery-opportunity.json").exists())

            second = copy.deepcopy(plan)
            second["transaction_id"] = "cannot-retry-after-lost-ack"
            second["budget"]["cumulative_before"] += 1
            second["budget"]["cumulative_ceiling"] += 1
            self.reseal(second)
            second_harness = RuntimeHarness(second, [issue], clock=MutableUtcClock())
            with self.assertRaisesRegex(NativePoolProtectedError, "opportunity-already-consumed"):
                execute_native_pool_transaction(
                    second, self.authorized_runtime(second_harness),
                    journal_path=root / "second.jsonl", now_utc=second_harness.clock,
                    run_pool=lambda *_a, **_k: {},
                )
            self.assertEqual(second_harness.starts, [])

    def test_v3_lost_ack_with_containment_loss_never_accepts_or_retries(self) -> None:
        for containment_mode in ("false", "throws"):
            with self.subTest(containment_mode=containment_mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, issue = campaign_recovery_plan(root)
                harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

                def lost(_ordinal: int, context: dict) -> dict:
                    harness._allocation(context, None)
                    raise ConnectionError("synthetic acknowledgement lost")

                def contain(_started: list[dict], _reason: str, _context: dict) -> dict:
                    if containment_mode == "throws":
                        raise RuntimeError("synthetic containment control lost")
                    return {"all_contained": False, "reason": "synthetic containment incomplete"}

                harness.start_prelude = lost  # type: ignore[method-assign]
                harness.contain = contain  # type: ignore[method-assign]
                journal_path = root / "failed.jsonl"
                with self.assertRaisesRegex(Exception, "allocation-acknowledgement-lost"):
                    execute_native_pool_transaction(
                        plan, self.authorized_runtime(harness), journal_path=journal_path,
                        now_utc=harness.clock, run_pool=lambda *_a, **_k: {},
                    )
                events = TransactionJournal(journal_path, plan["transaction_id"]).read()
                failure = next(event for event in events if event["event_type"] == "infrastructure-failure")
                self.assertIs(failure["details"]["all_contained"], False)
                self.assertEqual(events[-1]["state"], "CONTAINED")
                self.assertIs(events[-1]["details"]["all_contained"], False)
                self.assertTrue((root / "recovery-opportunity.json").exists())
                second = copy.deepcopy(plan)
                second["transaction_id"] = "cannot-retry-after-containment-loss"
                second["budget"]["cumulative_before"] += 1
                second["budget"]["cumulative_ceiling"] += 1
                self.reseal(second)
                second_harness = RuntimeHarness(second, [issue], clock=MutableUtcClock())
                with self.assertRaisesRegex(NativePoolProtectedError, "opportunity-already-consumed"):
                    execute_native_pool_transaction(
                        second, self.authorized_runtime(second_harness),
                        journal_path=root / "second.jsonl", now_utc=second_harness.clock,
                        run_pool=lambda *_a, **_k: {},
                    )
                self.assertEqual(second_harness.starts, [])

    def test_v1_stays_max_three_and_v2_is_strict_single_campaign_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            v1 = transaction_plan(root / "v1", [issue], prelude=1)
            changed = copy.deepcopy(v1)
            changed["budget"].update({"infrastructure_failures_before": 3, "maximum_infrastructure_failures": 4})
            changed["plan_sha256"] = canonical_sha256({k: v for k, v in changed.items() if k != "plan_sha256"})
            self.assertIn("transaction-plan-maximum-infrastructure-failures-must-equal-3", validate_transaction_plan(changed))
            boolean_v1 = copy.deepcopy(v1)
            boolean_v1["version"] = True
            boolean_v1["plan_sha256"] = canonical_sha256({k: v for k, v in boolean_v1.items() if k != "plan_sha256"})
            self.assertIn("transaction-plan-version-must-be-integer", validate_transaction_plan(boolean_v1))
            plan = recovery_plan(root / "v2", issue)
            self.assertEqual(validate_transaction_plan(plan), [])
            if HAS_JSONSCHEMA:
                import jsonschema

                schema = json.loads((ROOT / RECOVERY_PLAN_SCHEMA).read_text(encoding="utf-8"))
                jsonschema.validate(plan, schema)
            for name, change in (
                ("false-prior", lambda p: p["budget"].__setitem__("infrastructure_failures_before", 0)),
                ("global-max", lambda p: p["budget"].__setitem__("maximum_infrastructure_failures", 5)),
                ("wrong-model", lambda p: p["infrastructure_recovery"].__setitem__("selected_model", "gpt-5.6-terra")),
                ("changed-authority", lambda p: p["infrastructure_recovery"].__setitem__("authority_sha256", "0" * 64)),
                ("extra-opportunity", lambda p: p["infrastructure_recovery"].__setitem__("additional_opportunities", 2)),
                ("boolean-version", lambda p: p["infrastructure_recovery"].__setitem__("version", True)),
                ("boolean-opportunity", lambda p: p["infrastructure_recovery"].__setitem__("additional_opportunities", True)),
            ):
                with self.subTest(name=name):
                    altered = copy.deepcopy(plan)
                    change(altered)
                    self.reseal(altered)
                    self.assertTrue(validate_transaction_plan(altered))
            malformed_child = copy.deepcopy(plan)
            malformed_child["children"] = [None]
            malformed_child["plan_sha256"] = canonical_sha256(
                {key: value for key, value in malformed_child.items() if key != "plan_sha256"}
            )
            self.assertIn(
                "transaction-plan-recovery-child-must-be-object",
                validate_transaction_plan(malformed_child),
            )

    def test_v2_requires_runtime_authority_and_one_ledger_across_new_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            clock = MutableUtcClock()
            harness = RuntimeHarness(plan, [issue], clock=clock)
            opportunity = Path(plan["infrastructure_recovery"]["opportunity_ledger_path"])
            with self.assertRaisesRegex(NativePoolProtectedError, "authority-missing"):
                execute_native_pool_transaction(
                    plan, harness.runtime(), journal_path=root / "missing-authority.jsonl",
                    now_utc=clock, run_pool=lambda *_a, **_k: {},
                )
            self.assertFalse(opportunity.exists())
            result = execute_native_pool_transaction(
                plan, self.authorized_runtime(harness),
                journal_path=root / "first.jsonl", now_utc=clock,
                run_pool=lambda *_a, **_k: {"pool_receipt": {"accepting": True}},
            )
            self.assertTrue(result["accepted"])
            self.assertEqual(len(harness.starts), 2)
            event = json.loads(opportunity.read_text(encoding="utf-8"))
            self.assertEqual(event["prior_infrastructure_failures"], 3)
            self.assertEqual(event["additional_opportunities"], 1)
            self.assertEqual(event["transaction_id"], plan["transaction_id"])
            events = TransactionJournal(root / "first.jsonl", plan["transaction_id"]).read()
            consumed = next(i for i, item in enumerate(events) if item["event_type"] == "recovery-opportunity-consumed")
            first_intent = next(i for i, item in enumerate(events) if item["event_type"] == "allocation-intent")
            self.assertLess(first_intent, consumed)
            second = copy.deepcopy(plan)
            second["transaction_id"] = "new-id-cannot-evade-same-campaign"
            second["budget"]["cumulative_before"] += 2
            second["budget"]["cumulative_ceiling"] += 2
            self.reseal(second)
            second_harness = RuntimeHarness(second, [issue], clock=clock)
            with self.assertRaisesRegex(NativePoolProtectedError, "opportunity-already-consumed"):
                execute_native_pool_transaction(
                    second, self.authorized_runtime(second_harness),
                    journal_path=root / "second.jsonl", now_utc=clock,
                    run_pool=lambda *_a, **_k: {},
                )
            self.assertEqual(second_harness.starts, [])

    def test_v2_pinned_grant_rejects_resealed_ledger_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            original = recovery_plan(root, issue)
            for field, value in (
                ("opportunity_ledger_path", str(root / "other-ledger.json")),
                ("prior_failure_evidence_sha256", "0" * 64),
            ):
                with self.subTest(field=field):
                    altered = copy.deepcopy(original)
                    altered["infrastructure_recovery"][field] = value
                    self.reseal(altered)
                    self.assertEqual(validate_transaction_plan(altered), [])
                    harness = RuntimeHarness(altered, [issue], clock=MutableUtcClock())
                    with self.assertRaisesRegex(NativePoolProtectedError, "authority-rejected"):
                        execute_native_pool_transaction(
                            altered,
                            self.authorized_runtime(
                                harness, expected_grant=original["infrastructure_recovery"]
                            ),
                            journal_path=root / (field + ".jsonl"),
                            now_utc=harness.clock,
                            run_pool=lambda *_a, **_k: {},
                        )
                    self.assertEqual(harness.starts, [])

    def test_v2_first_callback_observes_durable_claim_and_nested_id_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
            original_start = harness.start_prelude

            def inspect_start(ordinal: int, context: dict) -> dict:
                ledger = root / "recovery-opportunity.json"
                event = json.loads(ledger.read_text(encoding="utf-8"))
                self.assertEqual(event["plan_sha256"], plan["plan_sha256"])
                nested = copy.deepcopy(plan)
                nested["transaction_id"] = "nested-new-id"
                self.reseal(nested)
                nested_harness = RuntimeHarness(nested, [issue], clock=MutableUtcClock())
                with self.assertRaisesRegex(NativePoolProtectedError, "opportunity-already-consumed"):
                    execute_native_pool_transaction(
                        nested,
                        self.authorized_runtime(nested_harness),
                        journal_path=root / "nested.jsonl",
                        now_utc=nested_harness.clock,
                        run_pool=lambda *_a, **_k: {},
                    )
                self.assertEqual(nested_harness.starts, [])
                return original_start(ordinal, context)

            harness.start_prelude = inspect_start  # type: ignore[method-assign]
            result = execute_native_pool_transaction(
                plan, self.authorized_runtime(harness), journal_path=root / "primary.jsonl",
                now_utc=harness.clock,
                run_pool=lambda *_a, **_k: {"pool_receipt": {"accepting": True}},
            )
            self.assertTrue(result["accepted"])

    def test_v2_failed_allocation_intent_journal_does_not_consume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
            original_append = TransactionJournal.append

            def fail_intent(self: TransactionJournal, *args: object, **kwargs: object) -> object:
                if kwargs.get("event_type") == "allocation-intent":
                    raise OSError("synthetic journal write failure")
                return original_append(self, *args, **kwargs)

            with mock.patch.object(TransactionJournal, "append", fail_intent):
                with self.assertRaisesRegex(OSError, "synthetic journal write failure"):
                    execute_native_pool_transaction(
                        plan, self.authorized_runtime(harness),
                        journal_path=root / "failed-intent.jsonl", now_utc=harness.clock,
                        run_pool=lambda *_a, **_k: {},
                    )
            self.assertEqual(harness.starts, [])
            self.assertFalse((root / "recovery-opportunity.json").exists())

    def test_v2_failed_controller_intent_fsync_does_not_consume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def failed_intent(_context: dict) -> None:
                raise OSError("synthetic allocation-ledger fsync failure")

            runtime = replace(
                self.authorized_runtime(harness),
                persist_first_allocation_intent=failed_intent,
            )
            with self.assertRaisesRegex(OSError, "allocation-ledger fsync failure"):
                execute_native_pool_transaction(
                    plan, runtime, journal_path=root / "failed-controller-intent.jsonl",
                    now_utc=harness.clock, run_pool=lambda *_a, **_k: {},
                )
            self.assertEqual(harness.starts, [])
            self.assertFalse((root / "recovery-opportunity.json").exists())

    def test_v2_private_parent_and_concurrent_claim_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            altered = copy.deepcopy(plan)
            altered["infrastructure_recovery"]["opportunity_ledger_path"] = str(link / "escape.json")
            self.reseal(altered)
            harness = RuntimeHarness(altered, [issue], clock=MutableUtcClock())
            with self.assertRaisesRegex(NativePoolProtectedError, "ledger-boundary-invalid"):
                execute_native_pool_transaction(
                    altered, self.authorized_runtime(harness),
                    journal_path=root / "symlink.jsonl", now_utc=harness.clock,
                    run_pool=lambda *_a, **_k: {},
                )
            self.assertFalse((root / "escape.json").exists())

            from cwo_core.native_pool_transaction import _consume_recovery_opportunity

            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def contend() -> None:
                barrier.wait()
                try:
                    _consume_recovery_opportunity(plan)
                    outcomes.append("won")
                except NativePoolProtectedError as exc:
                    outcomes.append(str(exc))

            threads = [threading.Thread(target=contend) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(outcomes.count("won"), 1)
            self.assertEqual(sum("opportunity-already-consumed" in value for value in outcomes), 1)

    def test_v2_replaced_parent_is_detected_before_native_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            plan["infrastructure_recovery"]["opportunity_ledger_path"] = str(private / "claim.json")
            self.reseal(plan)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
            from cwo_core import native_pool_transaction as transaction

            original_open_parent = transaction._open_recovery_parent

            def replace_after_pin(target: Path) -> int:
                descriptor = original_open_parent(target)
                private.rename(root / "moved")
                private.mkdir(mode=0o700)
                return descriptor

            with mock.patch.object(transaction, "_open_recovery_parent", replace_after_pin):
                with self.assertRaisesRegex(NativePoolProtectedError, "ledger-parent-replaced"):
                    execute_native_pool_transaction(
                        plan, self.authorized_runtime(harness),
                        journal_path=root / "replaced.jsonl", now_utc=harness.clock,
                        run_pool=lambda *_a, **_k: {},
                    )
            self.assertEqual(harness.starts, [])
            self.assertFalse((private / "claim.json").exists())
            self.assertTrue((root / "moved" / "claim.json").exists())

    def test_v2_preparation_failure_is_zero_model_and_does_not_consume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
            harness.prepare = lambda _plan: {"wrong": "context"}  # type: ignore[method-assign]
            with self.assertRaisesRegex(NativePoolTransactionError, "static-binding-mismatch"):
                execute_native_pool_transaction(
                    plan, self.authorized_runtime(harness),
                    journal_path=root / "prep-failed.jsonl", now_utc=harness.clock,
                    run_pool=lambda *_a, **_k: {},
                )
            self.assertFalse((root / "recovery-opportunity.json").exists())
            self.assertEqual(harness.starts, [])

    def test_v2_session_consuming_failure_spends_the_sole_opportunity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("bead-a", "a.txt")
            plan = recovery_plan(root, issue)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())

            def lost(_ordinal: int, context: dict) -> dict:
                harness._allocation(context, None)
                raise ConnectionError("synthetic acknowledgement lost")

            harness.start_prelude = lost  # type: ignore[method-assign]
            journal_path = root / "failed.jsonl"
            with self.assertRaisesRegex(Exception, "allocation-acknowledgement-lost"):
                execute_native_pool_transaction(
                    plan, self.authorized_runtime(harness), journal_path=journal_path,
                    now_utc=harness.clock, run_pool=lambda *_a, **_k: {},
                )
            self.assertEqual(TransactionJournal(journal_path, plan["transaction_id"]).infrastructure_failure_count, 1)
            self.assertTrue((root / "recovery-opportunity.json").exists())
            self.assertEqual(len(harness.starts), 1)
            self.assertTrue(harness.containments[0]["all_contained"])



def final_campaign_recovery_plan(root: Path) -> tuple[dict, dict]:
    """Prospective P1a v4 fixture: five spent, at most one further."""
    from cwo_core.native_pool_transaction import FINAL_CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan, issue = campaign_recovery_plan(root)
    plan["version"] = 4
    plan["schema"] = FINAL_CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan["budget"]["infrastructure_failures_before"] = 5
    plan["budget"]["maximum_infrastructure_failures"] = 6
    recovery = plan["infrastructure_recovery"]
    recovery["version"] = 3
    recovery["grant_sha256"] = canonical_sha256({key: value for key, value in recovery.items() if key != "grant_sha256"})
    return seal_transaction_plan(plan), issue


def seventh_campaign_recovery_plan(root: Path) -> tuple[dict, dict]:
    """Prospective v5 fixture: six spent, exactly one seventh opportunity."""
    from cwo_core.native_pool_transaction import SEVENTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan, issue = final_campaign_recovery_plan(root)
    plan["version"] = 5
    plan["schema"] = SEVENTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan["budget"]["infrastructure_failures_before"] = 6
    plan["budget"]["maximum_infrastructure_failures"] = 7
    plan["children"][0]["bead_id"] = "complex-work-orchestration-bpm4.14"
    plan["infrastructure_recovery"]["bead_id"] = "complex-work-orchestration-bpm4.14"
    recovery = plan["infrastructure_recovery"]
    recovery["version"] = 4
    recovery["grant_sha256"] = canonical_sha256({key: value for key, value in recovery.items() if key != "grant_sha256"})
    return seal_transaction_plan(plan), issue


def eighth_campaign_recovery_plan(root: Path) -> tuple[dict, dict]:
    """New v6 fixture: seven spent, exactly one fresh eighth opportunity."""
    from cwo_core.native_pool_transaction import EIGHTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan, _old_issue = seventh_campaign_recovery_plan(root)
    issue = bead("complex-work-orchestration-bpm4.15", "policy/native-worker-execution.yaml")
    plan["version"] = 6
    plan["schema"] = EIGHTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
    plan["budget"]["infrastructure_failures_before"] = 7
    plan["budget"]["maximum_infrastructure_failures"] = 8
    plan["children"][0]["bead_id"] = issue["id"]
    plan["children"][0]["bead_projection_sha256"] = execution_authoritative_bead_sha256(issue)
    recovery = plan["infrastructure_recovery"]
    recovery["bead_id"] = issue["id"]
    recovery["version"] = 5
    recovery["grant_sha256"] = canonical_sha256({key: value for key, value in recovery.items() if key != "grant_sha256"})
    return seal_transaction_plan(plan), issue


class EighthCampaignRecoveryTests(unittest.TestCase):
    def test_v6_exact_campaign_contract_and_historical_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _issue = eighth_campaign_recovery_plan(root)
            self.assertEqual(validate_transaction_plan(plan), [])
            if HAS_JSONSCHEMA:
                import jsonschema
                from cwo_core.native_pool_transaction import EIGHTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
                jsonschema.validate(plan, json.loads((ROOT / EIGHTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA).read_text()))
            for builder in (seventh_campaign_recovery_plan, final_campaign_recovery_plan, campaign_recovery_plan):
                old, _ = builder(root / builder.__name__)
                self.assertEqual(validate_transaction_plan(old), [])
            for name, change in (
                ("false-prior", lambda p: p["budget"].__setitem__("infrastructure_failures_before", 6)),
                ("extra-fuse", lambda p: p["budget"].__setitem__("maximum_infrastructure_failures", 9)),
                ("old-bead", lambda p: p["infrastructure_recovery"].__setitem__("bead_id", "complex-work-orchestration-bpm4.14")),
                ("old-grant-version", lambda p: p["infrastructure_recovery"].__setitem__("version", 4)),
                ("wrong-schema", lambda p: p.__setitem__("schema", "schemas/native-pool-transaction-plan-v5.schema.json")),
            ):
                with self.subTest(name=name):
                    altered = copy.deepcopy(plan)
                    change(altered)
                    recovery = altered["infrastructure_recovery"]
                    recovery["grant_sha256"] = canonical_sha256({key: value for key, value in recovery.items() if key != "grant_sha256"})
                    altered["plan_sha256"] = canonical_sha256({key: value for key, value in altered.items() if key != "plan_sha256"})
                    self.assertTrue(validate_transaction_plan(altered))

    def test_post_prelude_admission_static_projection_survives_real_transaction_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, issue = eighth_campaign_recovery_plan(root)
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
            original_release = harness.release_artifacts
            def persist_then_release(candidate, context, parent):
                admission = harness.beads[issue["id"]]["metadata"]["cwo_ready_set_admission"]
                admission["precommit_receipt"] = {"receipt_sha256": "f" * 64}
                admission["worker_commitment"] = {"receipt_sha256": "e" * 64}
                # Capability/authority/budget are frozen BEFORE prelude; only
                # genuine receipt-derived commitment slots are dynamic.
                self.assertEqual(execution_authoritative_bead_sha256(harness.read_bead(issue["id"])), plan["children"][0]["bead_projection_sha256"])
                return original_release(candidate, context, parent)
            harness.release_artifacts = persist_then_release  # type: ignore[method-assign]
            result = execute_native_pool_transaction(
                plan, NativePoolCampaignRecoveryTests.authorized_runtime(harness),
                journal_path=root / "transaction.jsonl", now_utc=harness.clock,
                run_pool=lambda *_a, **_k: {"pool_receipt": {"accepting": True}},
            )
            self.assertTrue(result["accepted"])
            self.assertEqual(len(harness.starts), 2)

    def test_post_prelude_scope_mutation_still_stops_before_worker(self) -> None:
        for field, value in (("topology", "changed"), ("isolation_class", "read-only"), ("share_boundary", "outside")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, issue = eighth_campaign_recovery_plan(root)
                harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
                original_release = harness.release_artifacts
                def changed_then_release(candidate, context, parent):
                    harness.beads[issue["id"]]["metadata"]["cwo_ready_set_admission"][field] = value
                    return original_release(candidate, context, parent)
                harness.release_artifacts = changed_then_release  # type: ignore[method-assign]
                with self.assertRaisesRegex(NativePoolTransactionError, "readiness-bead-projection-drift"):
                    execute_native_pool_transaction(
                        plan, NativePoolCampaignRecoveryTests.authorized_runtime(harness),
                        journal_path=root / "transaction.jsonl", now_utc=harness.clock,
                        run_pool=lambda *_a, **_k: {},
                    )
                self.assertEqual(len(harness.starts), 1)
                self.assertTrue(harness.containments[0]["all_contained"])


class SeventhCampaignRecoveryTests(unittest.TestCase):
    def test_v5_truthful_six_plus_one_without_v4_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _issue = seventh_campaign_recovery_plan(root)
            self.assertEqual(validate_transaction_plan(plan), [])
            if HAS_JSONSCHEMA:
                import jsonschema
                from cwo_core.native_pool_transaction import SEVENTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA
                jsonschema.validate(plan, json.loads((ROOT / SEVENTH_CAMPAIGN_RECOVERY_PLAN_SCHEMA).read_text()))
            old, _ = final_campaign_recovery_plan(root / "old")
            self.assertEqual(validate_transaction_plan(old), [])
            for name, mutate in (
                ("false-prior", lambda p: p["budget"].__setitem__("infrastructure_failures_before", 5)),
                ("extra-fuse", lambda p: p["budget"].__setitem__("maximum_infrastructure_failures", 8)),
                ("old-bead", lambda p: p["infrastructure_recovery"].__setitem__("bead_id", "complex-work-orchestration-bpm4")),
                ("old-grant-version", lambda p: p["infrastructure_recovery"].__setitem__("version", 3)),
                ("wrong-schema", lambda p: p.__setitem__("schema", "schemas/native-pool-transaction-plan-v4.schema.json")),
            ):
                with self.subTest(name=name):
                    changed = copy.deepcopy(plan)
                    mutate(changed)
                    recovery = changed["infrastructure_recovery"]
                    recovery["grant_sha256"] = canonical_sha256({key: value for key, value in recovery.items() if key != "grant_sha256"})
                    changed["plan_sha256"] = canonical_sha256({key: value for key, value in changed.items() if key != "plan_sha256"})
                    self.assertTrue(validate_transaction_plan(changed))


class FinalCampaignRecoveryTests(unittest.TestCase):
    def test_v4_truthful_fifth_and_no_global_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _issue = final_campaign_recovery_plan(root)
            self.assertEqual(validate_transaction_plan(plan), [])
            if HAS_JSONSCHEMA:
                import jsonschema
                from cwo_core.native_pool_transaction import FINAL_CAMPAIGN_RECOVERY_PLAN_SCHEMA
                jsonschema.validate(plan, json.loads((ROOT / FINAL_CAMPAIGN_RECOVERY_PLAN_SCHEMA).read_text()))
            for path, expected in (("v2", recovery_plan(root / "v2", bead("ordinary", "a.txt"))), ("v3", campaign_recovery_plan(root / "v3")[0])):
                with self.subTest(path=path):
                    self.assertEqual(validate_transaction_plan(expected), [])
            for name, field, value in (
                ("false-prior", "infrastructure_failures_before", 4),
                ("second-further", "maximum_infrastructure_failures", 7),
            ):
                with self.subTest(name=name):
                    altered = copy.deepcopy(plan)
                    altered["budget"][field] = value
                    altered["plan_sha256"] = canonical_sha256({k: v for k, v in altered.items() if k != "plan_sha256"})
                    self.assertTrue(validate_transaction_plan(altered))
            changed = copy.deepcopy(plan)
            changed["infrastructure_recovery"]["version"] = 2
            changed["infrastructure_recovery"]["grant_sha256"] = canonical_sha256({k: v for k, v in changed["infrastructure_recovery"].items() if k != "grant_sha256"})
            changed["plan_sha256"] = canonical_sha256({k: v for k, v in changed.items() if k != "plan_sha256"})
            self.assertTrue(validate_transaction_plan(changed))

    def test_v4_pinned_claim_precedes_observer_and_new_id_cannot_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, issue = final_campaign_recovery_plan(root)
            clock = MutableUtcClock()
            harness = RuntimeHarness(plan, [issue], clock=clock)
            opportunity = Path(plan["infrastructure_recovery"]["opportunity_ledger_path"])
            with self.assertRaisesRegex(NativePoolProtectedError, "authority-missing"):
                execute_native_pool_transaction(plan, harness.runtime(), journal_path=root / "missing.jsonl", now_utc=clock, run_pool=lambda *_a, **_k: {})
            self.assertFalse(opportunity.exists())
            original = harness.start_prelude
            def observe(ordinal: int, context: dict) -> dict:
                event = json.loads(opportunity.read_text())
                self.assertEqual(event["prior_infrastructure_failures"], 5)
                self.assertEqual(event["additional_opportunities"], 1)
                journal = TransactionJournal(root / "first.jsonl", plan["transaction_id"]).read()
                self.assertTrue(any(x["event_type"] == "allocation-intent" for x in journal))
                return original(ordinal, context)
            harness.start_prelude = observe  # type: ignore[method-assign]
            runtime = replace(harness.runtime(), authorize_recovery=lambda value: value.get("infrastructure_recovery") == plan["infrastructure_recovery"], persist_first_allocation_intent=lambda _context: None)
            result = execute_native_pool_transaction(plan, runtime, journal_path=root / "first.jsonl", now_utc=clock, run_pool=lambda *_a, **_k: {"pool_receipt": {"accepting": True}})
            self.assertTrue(result["accepted"])
            later = copy.deepcopy(plan)
            later["transaction_id"] = "same-campaign-new-id"
            later["budget"]["cumulative_before"] += 2
            later["budget"]["cumulative_ceiling"] += 2
            later["plan_sha256"] = canonical_sha256({k: v for k, v in later.items() if k != "plan_sha256"})
            later_harness = RuntimeHarness(later, [issue], clock=clock)
            later_runtime = replace(later_harness.runtime(), authorize_recovery=lambda value: value.get("infrastructure_recovery") == plan["infrastructure_recovery"], persist_first_allocation_intent=lambda _context: None)
            with self.assertRaisesRegex(NativePoolProtectedError, "opportunity-already-consumed"):
                execute_native_pool_transaction(later, later_runtime, journal_path=root / "second.jsonl", now_utc=clock, run_pool=lambda *_a, **_k: {})
            self.assertEqual(later_harness.starts, [])

class TransactionFinalObservationTests(unittest.TestCase):
    def run_case(self, mutate=None, *, clock_drift=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            issue = bead("final-observation", "fixture.txt")
            plan = transaction_plan(root, [issue])
            harness = RuntimeHarness(plan, [issue], clock=MutableUtcClock())
            original = harness.validate
            returned = [False]
            def validate(launched, context):
                value = original(launched, context)
                returned[0] = True
                if mutate is not None and not clock_drift:
                    mutate(harness.beads[issue["id"]])
                return value
            harness.validate = validate
            def clock():
                if returned[0] and clock_drift:
                    mutate(harness.beads[issue["id"]])
                return harness.clock()
            def execute():
                return execute_native_pool_transaction(
                    plan, harness.runtime(), journal_path=root / "transaction.jsonl",
                    now_utc=clock, run_pool=lambda *_a, **_k: {"pool_receipt": {"accepting": True}},
                )
            if mutate is not None:
                with self.assertRaisesRegex(NativePoolTransactionError, "transaction-final-bead-projection-drift"):
                    execute()
                events = TransactionJournal(root / "transaction.jsonl", plan["transaction_id"]).read()
                self.assertEqual(events[-1]["state"], "CONTAINED")
                self.assertFalse(any(e["state"] == "ACCEPTED" for e in events))
                return None, harness
            result = execute()
            return result, harness

    def test_unchanged_callback_remains_accepted(self):
        result, _ = self.run_case()
        self.assertTrue(result["accepted"])

    def test_validation_scope_change_is_nonaccepted_and_contained(self):
        def drift(issue):
            issue["metadata"]["cwo_ready_set_admission"]["declared_write_paths"] = ["unauthorized.txt"]
        result, harness = self.run_case(drift)
        self.assertIsNone(result)
        self.assertTrue(harness.containments[-1]["all_contained"])

    def test_terminal_clock_observer_cannot_change_scope_after_validation(self):
        def drift(issue):
            issue["acceptance_criteria"] = "changed by reentrant clock"
        result, _ = self.run_case(drift, clock_drift=True)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()


class MaintenanceExecutionProjectionTests(unittest.TestCase):
    def test_readiness_evidence_only_persistence_preserves_projection(self):
        from cwo_core.native_pool_transaction import execution_authoritative_bead_sha256
        issue={"id":"fixture-only","labels":[],"dependencies":[],"metadata":{"cwo_ready_set_admission":{"work_plan":{"scope":"frozen"},"hard_budget":{"tool_calls":12},"architecture_authority":"owner"}}}
        original=execution_authoritative_bead_sha256(issue)
        issue["metadata"]["cwo_ready_set_admission"].update(worker_commitment={"synthetic":"nonoperative"},precommit_receipt={"synthetic":"nonoperative"})
        self.assertEqual(original,execution_authoritative_bead_sha256(issue))
    def test_causal_admission_authority_drift_is_observed(self):
        from copy import deepcopy
        from cwo_core.native_pool_transaction import execution_authoritative_bead_sha256
        base={"id":"fixture-only","labels":[],"dependencies":[],"metadata":{"cwo_ready_set_admission":{}}}
        original=execution_authoritative_bead_sha256(base)
        for field in ("architecture_authority","execution_authority","required_tools","tool_policy","tool_surface_id","hard_budget","aggregate_hard_budget","capability_receipt","capability_assessed_at","lease_scope"):
            changed=deepcopy(base);changed["metadata"]["cwo_ready_set_admission"][field]="causal drift"
            self.assertNotEqual(original,execution_authoritative_bead_sha256(changed),field)
