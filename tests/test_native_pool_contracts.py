from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import (  # noqa: E402
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_SLACK_WARNING_FRACTION,
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    LEASE_SCHEMA,
    LEASE_TYPE,
    POOL_ALLOWED_ACTIONS,
    POOL_CONTRACT_SCHEMA,
    POOL_CONTRACT_TYPE,
    POOL_CONTROL_REQUEST_SCHEMA,
    POOL_CONTROL_REQUEST_TYPE,
    POOL_DECISION_SCHEMA,
    POOL_DECISION_TYPE,
    POOL_RECEIPT_SCHEMA,
    POOL_RECEIPT_TYPE,
    POOL_STATE_SCHEMA,
    POOL_STATE_TYPE,
    VERSION,
    artifact_sha256,
    canonical_sha256,
    callback_certification_policy_sha256,
    default_completion_evidence_policy,
    seal_artifact,
    validate_capability_receipt,
    validate_completion_evidence_policy,
    validate_lease,
    validate_pool_artifact,
    validate_pool_contract,
    validate_pool_control_request,
    validate_pool_decision,
    validate_pool_receipt,
    validate_pool_state,
    write_private_artifact,
    zero_usage,
)
from cwo_core.native_pool_capacity_compat import (  # noqa: E402
    LEGACY_CERTIFICATION_VERSION,
    LEGACY_RESPONSE_TIME_EQUATION,
    LEGACY_SCHEDULER_MODEL,
)
from cwo_core.native_tool_isolation import default_tool_policy  # noqa: E402
from cwo_core.native_authority import build_reason_records  # noqa: E402
from cwo_core.native_stop_scope import (  # noqa: E402
    build_stop_metadata,
    policy_scope_authority,
)


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def sha(label: str) -> str:
    return canonical_sha256({"label": label})


def baseline_stop_metadata() -> dict:
    return build_stop_metadata(
        "child",
        authority=policy_scope_authority(
            "native-pool-contract-test-baseline-v1",
            authorized_scope="child",
        ),
    )


def owner() -> dict:
    return {"pid": 1234, "start_ticks": 5678, "boot_id_sha256": sha("boot")}


def identity(label: str) -> dict:
    return {
        "canonical_path_sha256": sha(f"path:{label}"),
        "git_common_dir_sha256": sha(f"git:{label}"),
        "device": 10,
        "inode": 100 + len(label),
        "baseline_sha256": sha(f"baseline:{label}"),
    }


def child(index: int, *, isolation: str = "mutable-isolated") -> dict:
    read_only = isolation == "read-only-shared"
    target = [] if read_only else [f"scripts/child_{index}.py"]
    return {
        "ordinal": index,
        "child_id": f"child-{index}",
        "packet_id": f"packet-{index}",
        "attempt_nonce": f"nonce-{index}",
        "session_id": f"session-{index}",
        "agent_id": f"agent-{index}",
        "control_turn_id": f"child-turn-{index}",
        "packet_sha256": sha(f"packet:{index}"),
        "control_contract_sha256": sha(f"control:{index}"),
        "state_file": f"/tmp/cwo-child-{index}.json",
        "worktree_identity": identity("shared" if read_only else f"worktree:{index}"),
        "isolation_class": isolation,
        "completion_evidence_policy": default_completion_evidence_policy(isolation),
        "tool_policy": default_tool_policy(mutable=not read_only),
        "declared_write_paths": target,
        "integration_target_paths": target,
        "lease_id": f"lease-{index}",
    }


def capability_payload(*, requested_cap: int = 2) -> dict:
    stats = {"p50_ms": 20, "p90_ms": 40, "p99_ms": 80, "max_ms": 100}
    callbacks = {
        name: dict(stats)
        for name in ("arm", "send_input", "mark_dispatched", "check", "interrupt", "close", "finalize")
    }
    certification_policy = {
        "version": CAPABILITY_CERTIFICATION_VERSION,
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": CAPABILITY_SCHEDULER_MODEL,
        "response_time_equation": CAPABILITY_RESPONSE_TIME_EQUATION,
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_callback_max_ms": dict(CERTIFIED_CALLBACK_MAX_MS),
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
        "slack_warning_fraction": CAPABILITY_SLACK_WARNING_FRACTION,
    }
    return {
        "receipt_type": CAPABILITY_RECEIPT_TYPE,
        "version": VERSION,
        "schema": CAPABILITY_RECEIPT_SCHEMA,
        "adapter_id": "native-multi-agent-v1",
        "adapter_version": "1",
        "execution_surface": "connected-codex",
        "host_identity": owner(),
        "control_turn_id": "pool-turn",
        "measured_at": "2026-07-16T00:00:00Z",
        "expires_at": "2026-07-16T00:30:00Z",
        "sample_count": 20,
        "requested_cap": requested_cap,
        "clock": "monotonic_ns",
        "callbacks": callbacks,
        "scheduler_overhead": {"p50_ms": 10, "p90_ms": 20, "p99_ms": 30, "max_ms": 50},
        "certification": {
            **certification_policy,
            "policy_sha256": callback_certification_policy_sha256(certification_policy),
            "adapter_implementation_sha256": sha("adapter-implementation"),
        },
        "capabilities": {"interrupt": True, "close": True, "wait": True, "trusted_telemetry": True},
        "attestation_source": "trusted-control-plane-session-metadata",
        "validation_outcome": "accepted",
    }


def pool_contract(*, cap: int = 2, read_only: bool = False) -> tuple[dict, dict | None]:
    capability = (
        seal_artifact(
            capability_payload(requested_cap=cap),
            "receipt_sha256",
        )
        if cap > 1
        else None
    )
    isolation = "read-only-shared" if read_only else "mutable-isolated"
    children = [child(index, isolation=isolation) for index in range(cap)]
    payload = {
        "contract_type": POOL_CONTRACT_TYPE,
        "version": VERSION,
        "schema": POOL_CONTRACT_SCHEMA,
        "pool_id": "pool-1",
        "pool_epoch": "epoch-1",
        "control_turn_id": "pool-turn",
        "created_at": "2026-07-16T00:00:00Z",
        "owner": owner(),
        "children": children,
        "max_active_workers": cap,
        "scheduler": {
            "kind": "earliest-deadline-rotating-v1",
            "poll_interval_ms": 1000,
            "poll_lag_tolerance_ms": 1500,
            "certified_max_check_ms": 200 if cap > 1 else None,
            "certified_max_scheduler_overhead_ms": 100 if cap > 1 else None,
        },
        "aggregate_hard_budget": {
            "tool_calls": 56,
            "runtime_seconds": 1440,
            "compactions": 0,
            "full_suite_runs": 0,
            "mutations": 4,
        },
        "topology": {
            "integration_root_identity": identity("integration"),
            "shared_read_only_worktree": read_only,
        },
        "allowed_actions": list(POOL_ALLOWED_ACTIONS),
        "capability_receipt_sha256": capability["receipt_sha256"] if capability else None,
    }
    return seal_artifact(payload, "contract_sha256"), capability


def released_lease(contract: dict, index: int) -> dict:
    child_value = contract["children"][index]
    return seal_artifact(
        {
            "lease_type": LEASE_TYPE,
            "version": VERSION,
            "schema": LEASE_SCHEMA,
            "lease_id": child_value["lease_id"],
            "pool_id": contract["pool_id"],
            "child_id": child_value["child_id"],
            "pool_epoch": contract["pool_epoch"],
            "integration_root_identity": contract["topology"]["integration_root_identity"],
            "worktree_identity": child_value["worktree_identity"],
            "target_paths": child_value["integration_target_paths"],
            "owner": contract["owner"],
            "lifecycle_state": "released",
            "acquired_at": "2026-07-16T00:00:01Z",
            "updated_at": "2026-07-16T00:05:00Z",
            "terminal_evidence_sha256": sha(f"terminal:{index}"),
            "release_reason": "pool-closed",
        },
        "lease_sha256",
    )


def closed_state(contract: dict, leases: list[dict]) -> dict:
    children = []
    for index, child_value in enumerate(contract["children"]):
        children.append(
            {
                "ordinal": index,
                "child_id": child_value["child_id"],
                "status": "closed",
                "last_deadline_ns": 1_000_000_000 + index,
                "next_deadline_ns": None,
                "child_state_sha256": sha(f"child-state:{index}"),
                "child_receipt_sha256": sha(f"child-receipt:{index}"),
                "last_cumulative_usage": zero_usage(),
                "lease_id": child_value["lease_id"],
            }
        )
    return seal_artifact(
        {
            "state_type": POOL_STATE_TYPE,
            "version": VERSION,
            "schema": POOL_STATE_SCHEMA,
            "pool_id": contract["pool_id"],
            "pool_epoch": contract["pool_epoch"],
            "contract_sha256": contract["contract_sha256"],
            "state_sequence": 7,
            "status": "closed",
            "owner": contract["owner"],
            "coordinator_epoch": 0,
            "scheduler_cursor": 0,
            "active_children": [],
            "terminal_children": [child_value["child_id"] for child_value in contract["children"]],
            "children": children,
            "aggregate_usage": zero_usage(),
            "pool_started_monotonic_ns": 1_000_000,
            "pool_wall_seconds": 0,
            "worker_seconds": 0,
            "poll_overhead_seconds": 0,
            "lease_bindings": [lease["lease_sha256"] for lease in leases],
            "reasons": [],
            "reason_records": [],
            "first_protected_fault": None,
            "control_loss_scope": None,
            **baseline_stop_metadata(),
        },
        "state_sha256",
    )


def complete_decision(contract: dict, state: dict) -> dict:
    return seal_artifact(
        {
            "decision_type": POOL_DECISION_TYPE,
            "version": VERSION,
            "schema": POOL_DECISION_SCHEMA,
            "pool_id": contract["pool_id"],
            "pool_epoch": contract["pool_epoch"],
            "contract_sha256": contract["contract_sha256"],
            "state_sha256": state["state_sha256"],
            "decision_sequence": state["state_sequence"],
            "decision": "complete",
            "selected_child_id": None,
            "deadlines": [
                {"child_id": child_value["child_id"], "next_deadline_ns": None}
                for child_value in contract["children"]
            ],
            "observed_callback_latency_ms": 100,
            "aggregate_usage": state["aggregate_usage"],
            "reasons": [],
            "reason_records": [],
            "required_control_actions": ["finalize"],
            **baseline_stop_metadata(),
        },
        "decision_sha256",
    )


def accepting_receipt(contract: dict, state: dict, leases: list[dict]) -> dict:
    child_ids = [child_value["child_id"] for child_value in contract["children"]]
    mutation = {
        "integration_root_clean": True,
        "shared_read_only_clean": True,
        "child_worktrees_clean": True,
    }
    return seal_artifact(
        {
            "receipt_type": POOL_RECEIPT_TYPE,
            "version": VERSION,
            "schema": POOL_RECEIPT_SCHEMA,
            "pool_id": contract["pool_id"],
            "pool_epoch": contract["pool_epoch"],
            "contract_sha256": contract["contract_sha256"],
            "terminal_state_sha256": state["state_sha256"],
            "capability_receipt_sha256": contract["capability_receipt_sha256"],
            "admission_order": child_ids,
            "poll_order": child_ids,
            "terminal_order": child_ids,
            "timing": {
                "max_callback_latency_ms": 100,
                "max_poll_gap_ms": 1000,
                "poll_interval_ms": 1000,
                "poll_lag_tolerance_ms": 1500,
            },
            "child_terminal_receipts": [
                {"child_id": child_value["child_id"], "receipt_sha256": state["children"][index]["child_receipt_sha256"]}
                for index, child_value in enumerate(contract["children"])
            ],
            "final_aggregate_usage": state["aggregate_usage"],
            "pool_wall_seconds": state["pool_wall_seconds"],
            "worker_seconds": state["worker_seconds"],
            "lease_evidence": [
                {"lease_id": lease["lease_id"], "lease_sha256": lease["lease_sha256"], "lifecycle_state": "released"}
                for lease in leases
            ],
            "mutation_evidence": {**mutation, "evidence_sha256": canonical_sha256(mutation)},
            "reasons": [],
            "reason_records": [],
            "first_protected_fault": None,
            "child_dispositions": [
                {"child_id": child_id, "session_disposition": "accepted", "artifact_disposition": "accepted"}
                for child_id in child_ids
            ],
            "pool_disposition": "accepted",
            "accepting": True,
            **baseline_stop_metadata(),
        },
        "receipt_sha256",
    )


def control_request(contract: dict, state: dict, *, request_id: str = "interrupt-1") -> dict:
    return seal_artifact(
        {
            "request_type": POOL_CONTROL_REQUEST_TYPE,
            "version": VERSION,
            "schema": POOL_CONTROL_REQUEST_SCHEMA,
            "request_id": request_id,
            "pool_id": contract["pool_id"],
            "pool_epoch": contract["pool_epoch"],
            "contract_sha256": contract["contract_sha256"],
            "observed_state_sequence": state["state_sequence"],
            "observed_state_sha256": state["state_sha256"],
            "action": "interrupt",
            "reason": "operator requested bounded stop",
            "created_at": "2026-07-16T00:10:00Z",
        },
        "request_sha256",
    )


class NativePoolContractTest(unittest.TestCase):
    def artifacts(self):
        contract, capability = pool_contract()
        self.assertIsNotNone(capability)
        leases = [released_lease(contract, index) for index in range(2)]
        state = closed_state(contract, leases)
        decision = complete_decision(contract, state)
        receipt = accepting_receipt(contract, state, leases)
        return contract, capability, leases, state, decision, receipt

    def test_valid_artifact_family_and_cross_field_bindings(self) -> None:
        contract, capability, leases, state, decision, receipt = self.artifacts()
        now = dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)
        self.assertEqual(validate_pool_contract(contract), [])
        self.assertEqual(validate_capability_receipt(capability, expected_contract=contract, now=now), [])
        for lease in leases:
            self.assertEqual(validate_lease(lease, contract=contract), [])
        self.assertEqual(validate_pool_state(state, contract=contract), [])
        self.assertEqual(validate_pool_decision(decision, contract=contract, state=state), [])
        self.assertEqual(validate_pool_receipt(receipt, contract=contract, terminal_state=state), [])
        self.assertEqual(validate_pool_artifact(contract), [])

    def test_receipt_accepts_legacy_and_exclusive_timing_shapes(self) -> None:
        contract, _, _, state, _, legacy = self.artifacts()
        self.assertEqual(
            validate_pool_receipt(
                legacy,
                contract=contract,
                terminal_state=state,
            ),
            [],
        )

        exclusive = copy.deepcopy(legacy)
        exclusive["timing"].update(
            {
                "accounting_version": "exclusive-v1",
                "callback_ns": 0,
                "noncallback_invoke_ns": 0,
                "coordinator_ns": 0,
                "wait_ns": 0,
            }
        )
        exclusive = seal_artifact(exclusive, "receipt_sha256")
        self.assertEqual(
            validate_pool_receipt(
                exclusive,
                contract=contract,
                terminal_state=state,
            ),
            [],
        )

        missing_bucket = copy.deepcopy(exclusive)
        missing_bucket["timing"].pop("callback_ns")
        missing_bucket = seal_artifact(missing_bucket, "receipt_sha256")
        self.assertTrue(
            any(
                error.startswith("timing-missing-fields:callback_ns")
                for error in validate_pool_receipt(
                    missing_bucket,
                    contract=contract,
                    terminal_state=state,
                )
            )
        )

        overlapping = copy.deepcopy(exclusive)
        overlapping["timing"]["noncallback_invoke_ns"] = 2
        overlapping = seal_artifact(overlapping, "receipt_sha256")
        errors = validate_pool_receipt(
            overlapping,
            contract=contract,
            terminal_state=state,
        )
        self.assertIn("timing-buckets-do-not-reconcile-with-pool-wall", errors)
        self.assertIn("receipt-poll-overhead-seconds-mismatch", errors)

        if HAS_JSONSCHEMA:
            import jsonschema

            schema = json.loads(
                (ROOT / POOL_RECEIPT_SCHEMA).read_text(encoding="utf-8")
            )
            jsonschema.validate(legacy, schema)
            jsonschema.validate(exclusive, schema)

    def test_missing_unknown_tamper_and_replay_fail(self) -> None:
        contract, _, _, _, _, _ = self.artifacts()
        missing = copy.deepcopy(contract)
        missing.pop("owner")
        self.assertTrue(any("missing-fields" in error for error in validate_pool_contract(missing)))
        unknown = copy.deepcopy(contract)
        unknown["unexpected"] = True
        self.assertTrue(any("unknown-fields" in error for error in validate_pool_contract(unknown)))
        tampered = copy.deepcopy(contract)
        tampered["pool_id"] = "changed"
        self.assertIn("contract-sha256-mismatch", validate_pool_contract(tampered))
        self.assertIn(
            "replay-detected",
            validate_pool_contract(contract, seen_hashes={contract["contract_sha256"]}),
        )
        changed = copy.deepcopy(contract)
        changed["aggregate_hard_budget"]["tool_calls"] += 1
        self.assertNotEqual(artifact_sha256(changed, "contract_sha256"), contract["contract_sha256"])

    def test_control_request_is_strict_state_bound_and_replay_protected(self) -> None:
        contract, _, leases, state, _, _ = self.artifacts()
        request = control_request(contract, state)
        self.assertEqual(validate_pool_control_request(request, contract=contract, state=state), [])
        self.assertEqual(validate_pool_artifact(request, contract=contract, state=state), [])

        future = copy.deepcopy(request)
        future["observed_state_sequence"] = state["state_sequence"] + 1
        future = seal_artifact(future, "request_sha256")
        self.assertIn(
            "control-request-state-sequence-from-future",
            validate_pool_control_request(future, contract=contract, state=state),
        )

        mismatch = copy.deepcopy(request)
        mismatch["observed_state_sha256"] = sha("other-state")
        mismatch = seal_artifact(mismatch, "request_sha256")
        self.assertIn(
            "control-request-state-sha256-mismatch",
            validate_pool_control_request(mismatch, contract=contract, state=state),
        )

        unsafe = copy.deepcopy(request)
        unsafe["request_id"] = "unsafe\nidentifier"
        unsafe = seal_artifact(unsafe, "request_sha256")
        self.assertIn("invalid-request-id-format", validate_pool_control_request(unsafe))
        self.assertIn(
            "replay-detected",
            validate_pool_control_request(request, seen_hashes={request["request_sha256"]}),
        )

    def test_duplicate_identity_nonce_and_overlapping_targets_fail(self) -> None:
        contract, _ = pool_contract()
        duplicate = copy.deepcopy(contract)
        duplicate["children"][1]["packet_id"] = duplicate["children"][0]["packet_id"]
        duplicate["children"][1]["attempt_nonce"] = duplicate["children"][0]["attempt_nonce"]
        duplicate["children"][1]["worktree_identity"] = duplicate["children"][0]["worktree_identity"]
        duplicate["children"][1]["integration_target_paths"] = ["scripts/child_0.py/nested"]
        duplicate = seal_artifact(duplicate, "contract_sha256")
        errors = validate_pool_contract(duplicate)
        self.assertIn("duplicate-child-packet-id", errors)
        self.assertIn("duplicate-child-attempt-nonce", errors)
        self.assertIn("duplicate-mutable-worktree-identity", errors)
        self.assertTrue(any(error.startswith("cross-child-target-overlap") for error in errors))

    def test_cap_one_requires_no_capability_and_preserves_strict_contract(self) -> None:
        contract, capability = pool_contract(cap=1)
        self.assertIsNone(capability)
        self.assertEqual(validate_pool_contract(contract), [])
        changed = copy.deepcopy(contract)
        changed["capability_receipt_sha256"] = sha("unexpected")
        changed = seal_artifact(changed, "contract_sha256")
        self.assertIn(
            "single-worker-capability-receipt-must-be-null",
            validate_pool_contract(changed),
        )

    def test_cap_must_equal_fixed_cohort_and_schema_matches(self) -> None:
        contract, _ = pool_contract()
        changed = copy.deepcopy(contract)
        changed["children"].pop()
        changed = seal_artifact(changed, "contract_sha256")
        self.assertIn("max-active-workers-must-equal-fixed-cohort", validate_pool_contract(changed))
        if HAS_JSONSCHEMA:
            import jsonschema

            schema = json.loads((ROOT / POOL_CONTRACT_SCHEMA).read_text(encoding="utf-8"))
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(changed, schema)

    def test_capacity_three_contract_and_capability_match_policy_bound_schema(self) -> None:
        contract, capability = pool_contract(cap=3)
        self.assertIsNotNone(capability)
        self.assertEqual(validate_pool_contract(contract), [])
        self.assertEqual(
            validate_capability_receipt(
                capability,
                expected_contract=contract,
                now=dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc),
            ),
            [],
        )
        if HAS_JSONSCHEMA:
            import jsonschema

            contract_schema = json.loads(
                (ROOT / POOL_CONTRACT_SCHEMA).read_text(encoding="utf-8")
            )
            capability_schema = json.loads(
                (ROOT / CAPABILITY_RECEIPT_SCHEMA).read_text(encoding="utf-8")
            )
            jsonschema.validate(contract, contract_schema)
            jsonschema.validate(capability, capability_schema)

        over_limit, _ = pool_contract(cap=4)
        self.assertIn("invalid-max-active-workers", validate_pool_contract(over_limit))
        if HAS_JSONSCHEMA:
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(over_limit, contract_schema)

    def test_v1_poll_contract_is_exact_and_cap_one_has_no_certification(self) -> None:
        contract, _ = pool_contract(cap=1)
        changed = copy.deepcopy(contract)
        changed["scheduler"]["poll_interval_ms"] = 999
        changed["scheduler"]["poll_lag_tolerance_ms"] = 1501
        changed["scheduler"]["certified_max_check_ms"] = 100
        changed = seal_artifact(changed, "contract_sha256")
        errors = validate_pool_contract(changed)
        self.assertIn("invalid-scheduler-poll-interval-ms", errors)
        self.assertIn("invalid-scheduler-poll-lag-tolerance-ms", errors)
        self.assertIn("single-worker-scheduler-certification-must-be-null", errors)

    def test_read_only_contract_rejects_any_declared_mutation(self) -> None:
        contract, _ = pool_contract(read_only=True)
        self.assertEqual(validate_pool_contract(contract), [])
        changed = copy.deepcopy(contract)
        changed["children"][0]["declared_write_paths"] = ["README.md"]
        changed = seal_artifact(changed, "contract_sha256")
        self.assertTrue(any("paths-must-be-empty" in error for error in validate_pool_contract(changed)))

        widened = copy.deepcopy(contract)
        widened["children"][0]["tool_policy"]["permitted_tools"] = [
            "apply_patch",
            "exec_command",
            "write_stdin",
        ]
        widened = seal_artifact(widened, "contract_sha256")
        self.assertIn(
            "read-only-child[0]-tool-policy-permits-apply-patch",
            validate_pool_contract(widened),
        )

    def test_completion_evidence_policy_is_strict_and_narrowly_allows_tool_free_work(self) -> None:
        default = default_completion_evidence_policy("read-only-shared")
        self.assertEqual(
            validate_completion_evidence_policy(
                default,
                isolation_class="read-only-shared",
            ),
            [],
        )
        tool_free = {
            "minimum_tool_calls": 0,
            "required_evidence": {
                "predicates": [
                    "read-only-workspace-clean",
                    "trusted-terminal-boundary",
                ],
                "sha256": [],
            },
            "allow_zero_tool_completion": True,
            "expected_mutation_mode": "read-only",
        }
        self.assertEqual(
            validate_completion_evidence_policy(
                tool_free,
                isolation_class="read-only-shared",
            ),
            [],
        )
        contract, _ = pool_contract(cap=1, read_only=True)
        contract["children"][0]["completion_evidence_policy"] = tool_free
        contract = seal_artifact(contract, "contract_sha256")
        self.assertEqual(validate_pool_contract(contract), [])

        unsafe = copy.deepcopy(tool_free)
        unsafe["allow_zero_tool_completion"] = False
        self.assertIn(
            "completion-evidence-policy-observable-work-requirement-missing",
            validate_completion_evidence_policy(unsafe),
        )
        mismatch = copy.deepcopy(default)
        mismatch["expected_mutation_mode"] = "mutable-isolated"
        mismatch["required_evidence"]["predicates"] = [
            "expected-workspace-mutation",
            "trusted-terminal-boundary",
            "trusted-tool-call",
        ]
        errors = validate_completion_evidence_policy(
            mismatch,
            isolation_class="read-only-shared",
        )
        self.assertIn("completion-evidence-policy-isolation-mutation-mode-mismatch", errors)

        malformed = copy.deepcopy(default)
        malformed["required_evidence"]["predicates"] = [{}]
        self.assertIn(
            "completion-evidence-policy-required-evidence-predicates-unknown:{}",
            validate_completion_evidence_policy(malformed),
        )

    def test_completion_evidence_minimum_must_fit_aggregate_budget(self) -> None:
        contract, _ = pool_contract()
        for child_contract in contract["children"]:
            child_contract["completion_evidence_policy"]["minimum_tool_calls"] = 40
        contract = seal_artifact(contract, "contract_sha256")
        self.assertIn(
            "completion-evidence-minimum-tool-calls-exceed-aggregate-budget",
            validate_pool_contract(contract),
        )

    def test_topology_flag_and_declared_write_coverage_are_cross_checked(self) -> None:
        contract, _ = pool_contract()
        shared_mutable = copy.deepcopy(contract)
        shared_mutable["topology"]["shared_read_only_worktree"] = True
        shared_mutable = seal_artifact(shared_mutable, "contract_sha256")
        self.assertIn(
            "shared-read-only-worktree-has-mutable-child",
            validate_pool_contract(shared_mutable),
        )

        uncovered = copy.deepcopy(contract)
        uncovered["children"][0]["declared_write_paths"] = ["README.md"]
        uncovered = seal_artifact(uncovered, "contract_sha256")
        self.assertTrue(
            any(
                error.startswith("child[0]-declared-write-outside-integration-target")
                for error in validate_pool_contract(uncovered)
            )
        )

    def test_worker_worktree_may_not_alias_integration_root(self) -> None:
        contract, _ = pool_contract(cap=1)
        changed = copy.deepcopy(contract)
        changed["children"][0]["worktree_identity"] = changed["topology"]["integration_root_identity"]
        changed["children"][0]["worktree_identity"]["baseline_sha256"] = sha(
            "different-baseline-same-physical-root"
        )
        changed = seal_artifact(changed, "contract_sha256")
        self.assertIn("child[0]-worktree-aliases-integration-root", validate_pool_contract(changed))

    def test_stale_capability_overrun_and_cross_bound_receipt_fail(self) -> None:
        contract, capability, _, _, _, _ = self.artifacts()
        stale_now = dt.datetime(2026, 7, 16, 1, 0, tzinfo=dt.timezone.utc)
        self.assertIn(
            "capability-receipt-stale",
            validate_capability_receipt(capability, expected_contract=contract, now=stale_now),
        )
        overrun = copy.deepcopy(capability)
        overrun["callbacks"]["check"] = {"p50_ms": 410, "p90_ms": 410, "p99_ms": 410, "max_ms": 410}
        overrun = seal_artifact(overrun, "receipt_sha256")
        self.assertIn(
            "callback-observed-above-certified:check",
            validate_capability_receipt(overrun, now=dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)),
        )
        mismatch = copy.deepcopy(capability)
        mismatch["control_turn_id"] = "other"
        mismatch = seal_artifact(mismatch, "receipt_sha256")
        self.assertIn(
            "capability-control-turn-mismatch",
            validate_capability_receipt(mismatch, expected_contract=contract, now=dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)),
        )

    def test_certification_is_strict_policy_authority_not_observed_sample(self) -> None:
        _contract, capability, _, _, _, _ = self.artifacts()
        now = dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)

        observed_overrun = copy.deepcopy(capability)
        observed_overrun["callbacks"]["send_input"] = {
            "p50_ms": 251,
            "p90_ms": 251,
            "p99_ms": 251,
            "max_ms": 251,
        }
        observed_overrun = seal_artifact(observed_overrun, "receipt_sha256")
        self.assertIn(
            "callback-observed-above-certified:send_input",
            validate_capability_receipt(observed_overrun, now=now),
        )

        downgraded = copy.deepcopy(capability)
        downgraded["certification"]["certified_callback_max_ms"]["check"] = 199
        downgraded = seal_artifact(downgraded, "receipt_sha256")
        self.assertIn(
            "certification-callback-ceiling-mismatch:check",
            validate_capability_receipt(downgraded, now=now),
        )

        unknown = copy.deepcopy(capability)
        unknown["certification"]["unknown"] = True
        unknown = seal_artifact(unknown, "receipt_sha256")
        self.assertTrue(
            any("certification-unknown-fields:unknown" in error for error in validate_capability_receipt(unknown, now=now))
        )

        nonfinite = copy.deepcopy(capability)
        nonfinite["callbacks"]["check"]["max_ms"] = float("inf")
        nonfinite = seal_artifact(nonfinite, "receipt_sha256")
        self.assertIn("invalid-callback-check-values", validate_capability_receipt(nonfinite, now=now))

    def test_legacy_capacity_two_receipt_is_readable_but_not_operative(self) -> None:
        legacy = capability_payload()
        certification = legacy["certification"]
        certification["version"] = LEGACY_CERTIFICATION_VERSION
        certification["scheduler_model"] = LEGACY_SCHEDULER_MODEL
        certification["response_time_equation"] = LEGACY_RESPONSE_TIME_EQUATION
        certification.pop("slack_warning_fraction")
        certification_policy = {
            field: value
            for field, value in certification.items()
            if field not in {"policy_sha256", "adapter_implementation_sha256"}
        }
        certification["policy_sha256"] = callback_certification_policy_sha256(
            certification_policy
        )
        legacy = seal_artifact(legacy, "receipt_sha256")
        now = dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)
        self.assertEqual(validate_capability_receipt(legacy, now=now), [])

        contract, _ = pool_contract()
        operative_contract = copy.deepcopy(contract)
        operative_contract["capability_receipt_sha256"] = legacy["receipt_sha256"]
        operative_contract = seal_artifact(
            operative_contract,
            "contract_sha256",
        )
        errors = validate_capability_receipt(
            legacy,
            expected_contract=operative_contract,
            now=now,
        )
        self.assertIn("certification-version-mismatch", errors)
        self.assertIn("certification-scheduler-model-mismatch", errors)
        self.assertIn("certification-response-time-equation-mismatch", errors)

    def test_state_decision_lease_and_receipt_cross_binding_fail_closed(self) -> None:
        contract, _, leases, state, decision, receipt = self.artifacts()
        state_reset = copy.deepcopy(state)
        state_reset["children"][0]["last_cumulative_usage"]["tool_calls"] = 1
        state_reset = seal_artifact(state_reset, "state_sha256")
        self.assertIn("aggregate-usage-mismatch", validate_pool_state(state_reset, contract=contract))

        decision_mismatch = copy.deepcopy(decision)
        decision_mismatch["decision_sequence"] += 1
        decision_mismatch = seal_artifact(decision_mismatch, "decision_sha256")
        self.assertIn(
            "decision-sequence-mismatch",
            validate_pool_decision(decision_mismatch, contract=contract, state=state),
        )

        lease_mismatch = copy.deepcopy(leases[0])
        lease_mismatch["pool_epoch"] = "other"
        lease_mismatch = seal_artifact(lease_mismatch, "lease_sha256")
        self.assertIn("lease-pool-epoch-mismatch", validate_lease(lease_mismatch, contract=contract))

        receipt_mismatch = copy.deepcopy(receipt)
        receipt_mismatch["terminal_state_sha256"] = sha("stale-state")
        receipt_mismatch = seal_artifact(receipt_mismatch, "receipt_sha256")
        self.assertIn(
            "receipt-terminal-state-sha256-mismatch",
            validate_pool_receipt(receipt_mismatch, contract=contract, terminal_state=state),
        )

    def test_accepting_receipt_requires_clean_released_accepted_evidence(self) -> None:
        contract, _, leases, state, _, receipt = self.artifacts()
        changed = copy.deepcopy(receipt)
        changed["mutation_evidence"]["integration_root_clean"] = False
        changed["lease_evidence"][0]["lifecycle_state"] = "release-pending"
        changed["child_dispositions"][0]["artifact_disposition"] = "rejected"
        changed = seal_artifact(changed, "receipt_sha256")
        errors = validate_pool_receipt(changed, contract=contract, terminal_state=state)
        self.assertIn("mutation-evidence-sha256-mismatch", errors)
        self.assertIn("accepting-requires-clean-mutation-evidence", errors)
        self.assertIn("accepting-requires-released-leases", errors)
        self.assertIn("accepting-requires-accepted-children", errors)

    def test_nonaccepting_partial_admission_and_lease_evidence_are_strict_subsets(self) -> None:
        contract, _, leases, state, _, receipt = self.artifacts()
        fault = {
            "code": "lease-acquisition-failed",
            "operation": None,
            "observed_callback_latency_ms": None,
            "certified_callback_max_ms": None,
            "latched_state_sequence": state["state_sequence"],
        }
        state = copy.deepcopy(state)
        state["reasons"] = [fault["code"]]
        state["reason_records"] = build_reason_records(
            state["reasons"],
            state["scope_authority"],
            detected_by="native-pool-contract-test",
        )
        state["first_protected_fault"] = fault
        state = seal_artifact(state, "state_sha256")
        changed = copy.deepcopy(receipt)
        changed["terminal_state_sha256"] = state["state_sha256"]
        changed["admission_order"] = []
        changed["poll_order"] = []
        changed["lease_evidence"] = []
        changed["reasons"] = ["lease-acquisition-failed"]
        changed["reason_records"] = build_reason_records(
            changed["reasons"],
            changed["scope_authority"],
            detected_by="native-pool-contract-test",
        )
        changed["first_protected_fault"] = fault
        changed["pool_disposition"] = "quarantined"
        changed["accepting"] = False
        changed = seal_artifact(changed, "receipt_sha256")
        self.assertEqual(validate_pool_receipt(changed, contract=contract, terminal_state=state), [])
        if HAS_JSONSCHEMA:
            import jsonschema

            schema = json.loads((ROOT / POOL_RECEIPT_SCHEMA).read_text(encoding="utf-8"))
            jsonschema.validate(changed, schema)

        for active_state in ("acquired", "held"):
            active = copy.deepcopy(changed)
            active["lease_evidence"] = [copy.deepcopy(receipt["lease_evidence"][0])]
            active["lease_evidence"][0]["lifecycle_state"] = active_state
            active = seal_artifact(active, "receipt_sha256")
            self.assertEqual(
                validate_pool_receipt(active, contract=contract, terminal_state=state),
                [],
            )
            if HAS_JSONSCHEMA:
                jsonschema.validate(active, schema)

        unknown = copy.deepcopy(changed)
        unknown["admission_order"] = ["unknown-child"]
        unknown = seal_artifact(unknown, "receipt_sha256")
        self.assertIn(
            "admission-order-child-unknown",
            validate_pool_receipt(unknown, contract=contract, terminal_state=state),
        )

    def test_state_status_sets_and_release_pending_evidence_are_cross_checked(self) -> None:
        contract, _, leases, state, _, _ = self.artifacts()
        changed_state = copy.deepcopy(state)
        changed_state["active_children"] = ["child-0"]
        changed_state = seal_artifact(changed_state, "state_sha256")
        self.assertIn(
            "active-child-status-mismatch",
            validate_pool_state(changed_state, contract=contract),
        )

        changed_lease = copy.deepcopy(leases[0])
        changed_lease["lifecycle_state"] = "release-pending"
        changed_lease["terminal_evidence_sha256"] = None
        changed_lease["release_reason"] = None
        changed_lease = seal_artifact(changed_lease, "lease_sha256")
        errors = validate_lease(changed_lease, contract=contract)
        self.assertIn("release-pending-lease-terminal-evidence-required", errors)
        self.assertIn("release-pending-lease-reason-required", errors)

    def test_private_artifact_write_is_atomic_mode_0600(self) -> None:
        contract, _ = pool_contract(cap=1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pool.json"
            write_private_artifact(path, contract)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), contract)
            self.assertFalse(any(item.name.endswith(".tmp") for item in path.parent.iterdir()))

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_artifacts_validate_against_strict_schemas(self) -> None:
        import jsonschema

        contract, capability, leases, state, decision, receipt = self.artifacts()
        artifacts = [
            (contract, POOL_CONTRACT_SCHEMA),
            (capability, CAPABILITY_RECEIPT_SCHEMA),
            (leases[0], LEASE_SCHEMA),
            (state, POOL_STATE_SCHEMA),
            (decision, POOL_DECISION_SCHEMA),
            (receipt, POOL_RECEIPT_SCHEMA),
            (control_request(contract, state), POOL_CONTROL_REQUEST_SCHEMA),
        ]
        for artifact, schema_name in artifacts:
            with self.subTest(schema=schema_name):
                schema = json.loads((ROOT / schema_name).read_text(encoding="utf-8"))
                self.assertFalse(schema["additionalProperties"])
                jsonschema.validate(artifact, schema)


if __name__ == "__main__":
    unittest.main()
