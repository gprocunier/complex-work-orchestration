from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
import warnings


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_admission import (  # noqa: E402
    AdmissionCandidate,
    DISPATCH_AUTHORITY,
    DISPATCH_SCHEMA,
    DISPATCH_TYPE,
    PoolAdmissionReservation,
    _reservation_receipt,
    _validate_candidate,
    build_admission_child_binding,
    canonical_admission_sha256,
    reserve_pool_cohort,
)
from cwo_core.native_pool_admitted import run_admitted_native_pool  # noqa: E402
from cwo_core.native_pool import NativePoolCoordinator, NativePoolError  # noqa: E402
from cwo_core.native_pool_config import (  # noqa: E402
    ADMITTED_RENDER_REQUEST_SCHEMA,
    RENDER_REQUEST_SCHEMA,
    build_pool_contract,
    validate_pool_render_request,
)
from cwo_core.native_pool_contracts import (  # noqa: E402
    ADMITTED_POOL_CONTRACT_SCHEMA,
    ADMITTED_POOL_RECEIPT_SCHEMA,
    canonical_sha256,
    seal_artifact,
    validate_pool_artifact,
    validate_pool_contract,
    validate_pool_receipt,
    write_private_artifact,
    zero_usage,
)
from cwo_core.native_pool_leases import (  # noqa: E402
    PoolLeaseRegistry,
    capture_owner_identity,
)
from cwo_core.native_pool_preflight import (  # noqa: E402
    ADMITTED_PREFLIGHT_REQUEST_SCHEMA,
    ADMITTED_PREFLIGHT_RESULT_SCHEMA,
    effective_child_packet_sha256,
    default_callback_certification,
    run_pool_preflight,
    validate_pool_preflight_result,
)
from cwo_core.native_pool_proportionality import (  # noqa: E402
    pool_proportionality_check,
)
from cwo_core.native_pool_workspace import capture_workspace_snapshot  # noqa: E402
from cwo_core.native_tool_isolation import (  # noqa: E402
    build_tool_surface_snapshot,
    prompt_preflight,
)
from tests.test_native_pool_admission import (  # noqa: E402
    MemoryBdRunner,
    _adapter,
    _live,
)
from tests.test_native_pool_config import RenderFixture  # noqa: E402
from tests.test_native_pool_contracts import capability_payload  # noqa: E402
from tests.test_native_pool import FakeAdapter, FakeClock  # noqa: E402
from tests.test_native_pool_proportionality import _fixture  # noqa: E402
from tests.test_beads_ready_set import released_three_policy  # noqa: E402


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def _admitted_artifacts(
    root: Path,
    *,
    size: int = 2,
    completion_policy: str = "all-or-nothing",
    offline_candidate_harness: bool = False,
) -> tuple[RenderFixture, dict, dict, dict]:
    fixture = RenderFixture(root, size)
    preflight_records = root / "preflight-records"
    preflight_records.mkdir(mode=0o700)
    policy_fixture = released_three_policy() if size == 3 else None
    readiness, estimates, items, policy = _fixture(
        [600] * size,
        policy=policy_fixture,
    )
    assessment = pool_proportionality_check(
        readiness,
        estimates,
        requested_workers=size,
        policy_document=policy,
    )
    issue_ids = assessment["selected_cohort"]["issue_ids"]
    effective_children: list[dict] = []
    admission_bindings: dict[str, dict] = {}

    for index, bead_id in enumerate(issue_ids):
        render_child = fixture.request["children"][index]
        prompt = f"Inspect admitted target {bead_id}."
        tool_policy = render_child["tool_policy"]
        tool_surface = build_tool_surface_snapshot(
            tool_policy,
            source="offline-admission-test",
            server_allowlist_supported=True,
            allowlist_parameter="tools",
            effective_allowlist=tool_policy["permitted_tools"],
        )
        estimate_budget = estimates[bead_id]["aggregate_allowance"]
        hard_budget = {
            "tool_calls": estimate_budget["tool_calls_hard"],
            "runtime_seconds": estimate_budget["runtime_seconds_hard"],
            "compactions": estimate_budget["max_compactions"],
            "full_suite_runs": 0,
            "mutations": 1,
        }
        effective_child = {
            "child_id": render_child["child_id"],
            "packet_id": str(uuid.uuid4()),
            "packet_sha256": "0" * 64,
            "attempt_nonce": str(uuid.uuid4()),
            "session_id": str(uuid.uuid4()),
            "agent_id": None,
            "lease_id": str(uuid.uuid4()),
            "worktree": render_child["worktree"],
            "isolation_class": render_child["isolation_class"],
            "completion_evidence_policy": render_child["completion_evidence_policy"],
            "tool_policy": tool_policy,
            "prompt": prompt,
            "prompt_preflight": prompt_preflight(prompt, tool_policy),
            "tool_surface": tool_surface,
            "hard_budget": hard_budget,
            "declared_write_paths": render_child["declared_write_paths"],
            "integration_target_paths": render_child["integration_target_paths"],
        }
        effective_child["agent_id"] = effective_child["session_id"]
        effective_child["packet_sha256"] = effective_child_packet_sha256(
            effective_child
        )
        render_child.update(
            {
                "packet_id": effective_child["packet_id"],
                "attempt_nonce": effective_child["attempt_nonce"],
                "session_id": effective_child["session_id"],
                "agent_id": effective_child["agent_id"],
                "packet_sha256": effective_child["packet_sha256"],
                "lease_id": effective_child["lease_id"],
            }
        )
        state_path = Path(render_child["state_file"])
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["packet_id"] = render_child["packet_id"]
        state["packet_sha256"] = render_child["packet_sha256"]
        state["session_id"] = render_child["session_id"]
        state["agent_id"] = render_child["agent_id"]
        write_private_artifact(state_path, state)
        control_path = Path(render_child["control_contract_file"])
        control = json.loads(control_path.read_text(encoding="utf-8"))
        control["agent_id"] = render_child["agent_id"]
        control = seal_artifact(control, "contract_sha256")
        write_private_artifact(control_path, control)
        snapshot = capture_workspace_snapshot(
            render_child["worktree"],
            allowed_paths=render_child["declared_write_paths"],
        )
        binding = build_admission_child_binding(
            readiness,
            estimates[bead_id],
            bead_id=bead_id,
            child_id=render_child["child_id"],
            packet_id=render_child["packet_id"],
            packet_sha256=render_child["packet_sha256"],
            worktree_identity_sha256=canonical_sha256(snapshot["identity"]),
        )
        admission_bindings[bead_id] = binding
        effective_children.append(effective_child)

    runner = MemoryBdRunner(items)
    claim_adapter = _adapter(runner)
    candidate = AdmissionCandidate(
        readiness,
        estimates,
        assessment,
        admission_bindings,
    )
    if offline_candidate_harness:
        # This private test harness deliberately builds synthetic admission
        # evidence without minting a FixedCohortAdmissionCapability. It cannot
        # cross the supported productive launcher boundary.
        validated = _validate_candidate(candidate, policy_document=policy)
        attempt_adapter = claim_adapter.for_admission_attempt(
            "offline-candidate-harness"
        )
        claim_receipts = [
            dict(attempt_adapter.claim(issue_id).receipt)
            for issue_id in validated.issue_ids
        ]
        reservation_receipt = _reservation_receipt(
            validated,
            admission_nonce="offline-candidate-harness",
            claim_actor=attempt_adapter.actor,
            claims=claim_receipts,
            retained_owned=list(validated.issue_ids),
            recompute_count=0,
            status="admitted",
            created_at="2026-07-21T20:00:02.000Z",
        )
        reserved = PoolAdmissionReservation(
            receipt=reservation_receipt,
            capability=None,
            claim_adapter=attempt_adapter,
        )
    else:
        reserved = reserve_pool_cohort(
            candidate,
            claim_adapter=claim_adapter,
            admission_nonce="admission-contract-test",
            live_revalidate=_live,
            now="2026-07-21T20:00:02Z",
            policy_document=policy,
        )
    claims = {item["bead_id"]: item for item in reserved.receipt["claims"]}
    aggregate_budget = {
        field: sum(child["hard_budget"][field] for child in effective_children)
        for field in (
            "tool_calls",
            "runtime_seconds",
            "compactions",
            "full_suite_runs",
            "mutations",
        )
    }
    fixture.request.update(
        {
            "version": 2,
            "schema": ADMITTED_RENDER_REQUEST_SCHEMA,
            "aggregate_hard_budget": aggregate_budget,
            "completion_policy": completion_policy,
            "admission_reservation": reserved.receipt,
        }
    )
    for index, bead_id in enumerate(issue_ids):
        binding = admission_bindings[bead_id]
        admission_fields = {
            field: binding[field]
            for field in (
                "bead_id",
                "work_unit_id",
                "candidate_sha256",
                "work_estimate_sha256",
                "worker_commitment_sha256",
                "lease_scope_sha256",
                "worktree_identity_sha256",
                "requested_model",
                "admitted_child_sha256",
            )
        }
        admission_fields["claim_sha256"] = claims[bead_id]["claim_sha256"]
        admission_fields["hard_budget"] = effective_children[index]["hard_budget"]
        fixture.request["children"][index].update(admission_fields)
        effective_children[index].update(admission_fields)

    owner = capture_owner_identity()
    capability_body = capability_payload(requested_cap=size)
    capability_body["host_identity"] = owner
    capability = seal_artifact(capability_body, "receipt_sha256")
    contract = build_pool_contract(
        fixture.request,
        capability_receipt=capability,
        enable_concurrency=True,
        owner_pid=owner["pid"],
        now=dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc),
        policy_document=policy,
    )
    preflight_request = {
        "preflight_type": "cwo-native-supervision-pool-preflight-request",
        "version": 2,
        "schema": ADMITTED_PREFLIGHT_REQUEST_SCHEMA,
        "stage": "pre-dispatch",
        "launch_id": str(uuid.uuid4()),
        "campaign_nonce": str(uuid.uuid4()),
        "pool_id": str(uuid.uuid4()),
        "pool_epoch": str(uuid.uuid4()),
        "integration_root": str(fixture.integration),
        "artifact_directories": [str(preflight_records)],
        "requested_workers": size,
        "released_capacity": size,
        "aggregate_hard_budget": aggregate_budget,
        "children": effective_children,
        "fallback": {"main_thread": "main-thread", "recovery": "operator"},
        "productive_dogfood_delivery_prerequisite": False,
        "callback_certification": default_callback_certification(),
        "poll_interval_ms": 1000,
        "pool_contract": contract,
        "overrides": [],
        "admission_reservation": reserved.receipt,
    }
    contract["pool_id"] = preflight_request["pool_id"]
    contract["pool_epoch"] = preflight_request["pool_epoch"]
    contract = seal_artifact(contract, "contract_sha256")
    preflight_request["pool_contract"] = contract
    fixture.admission_capability = reserved.capability
    fixture.claim_adapter = reserved.claim_adapter
    fixture.claim_runner = runner
    fixture.pool_capability_receipt = capability
    fixture.policy_document = policy
    return fixture, reserved.receipt, contract, preflight_request


def _execution_inputs(
    fixture: RenderFixture, contract: dict
) -> tuple[dict, dict, dict, dict, dict, FakeClock]:
    clock = FakeClock()
    tasks = {
        child["child_id"]: f"task-{index}"
        for index, child in enumerate(contract["children"])
    }
    child_contracts = {
        child["child_id"]: json.loads(
            Path(fixture.request["children"][index]["control_contract_file"])
            .read_text(encoding="utf-8")
        )
        for index, child in enumerate(contract["children"])
    }
    adapters = {
        child["child_id"]: FakeAdapter(clock, ["complete"])
        for child in contract["children"]
    }

    def read_child_evidence(*, child_id: str, state_file: str) -> dict:
        return {
            "state_sha256": canonical_sha256(
                {
                    "child_id": child_id,
                    "state_file": state_file,
                    "calls": adapters[child_id].calls,
                }
            ),
            "usage": zero_usage(),
            "protected_fault": False,
            "control_loss": False,
            "failure_class": None,
            "recovery_evidence_sha256": None,
            "reasons": [],
            "session_disposition": "accepted",
            "artifact_disposition": "accepted",
        }

    def compare_workspaces(*, contract: dict, phase: str) -> dict:
        del contract, phase
        evidence = {
            "integration_root_clean": True,
            "shared_read_only_clean": True,
            "child_worktrees_clean": True,
        }
        return {**evidence, "evidence_sha256": canonical_sha256(evidence)}

    pool_callbacks = {
        "monotonic_ns": clock.monotonic_ns,
        "sleep": clock.sleep,
        "now_utc": clock.now_utc,
        "read_child_evidence": read_child_evidence,
        "compare_workspaces": compare_workspaces,
    }
    return (
        child_contracts,
        tasks,
        {child_id: adapter.callbacks() for child_id, adapter in adapters.items()},
        adapters,
        pool_callbacks,
        clock,
    )


class NativePoolAdmissionContractTests(unittest.TestCase):
    def _launch(
        self,
        root: Path,
        fixture: RenderFixture,
        reservation: dict,
        contract: dict,
        request: dict,
        result: dict,
        *,
        registry: PoolLeaseRegistry | None = None,
    ) -> tuple[dict, PoolLeaseRegistry, dict]:
        (
            child_contracts,
            tasks,
            child_callbacks,
            adapters,
            pool_callbacks,
            _clock,
        ) = _execution_inputs(fixture, contract)
        effective_registry = registry or PoolLeaseRegistry(
            root / "admitted-leases.json",
            owner_alive=lambda _owner: True,
            now=FakeClock.now_utc,
        )
        launched = run_admitted_native_pool(
            reservation,
            fixture.admission_capability,
            contract,
            request,
            result,
            child_contracts,
            tasks,
            child_callbacks,
            claim_adapter=fixture.claim_adapter,
            live_revalidate=_live,
            pool_callbacks=pool_callbacks,
            lease_registry=effective_registry,
            capability_receipt=fixture.pool_capability_receipt,
        )
        return launched, effective_registry, adapters

    def test_admitted_n2_consumes_once_and_emits_exact_v2_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, reservation, contract, request = _admitted_artifacts(root)
            result = run_pool_preflight(request)
            launched, registry, adapters = self._launch(
                root, fixture, reservation, contract, request, result
            )
            dispatch = launched["dispatch_receipt"]
            receipt = launched["pool_receipt"]
            self.assertEqual(receipt["version"], 2)
            self.assertEqual(receipt["schema"], ADMITTED_POOL_RECEIPT_SCHEMA)
            if HAS_JSONSCHEMA:
                from jsonschema import Draft202012Validator

                receipt_schema = json.loads(
                    (ROOT / ADMITTED_POOL_RECEIPT_SCHEMA).read_text(
                        encoding="utf-8"
                    )
                )
                Draft202012Validator.check_schema(receipt_schema)
                Draft202012Validator(receipt_schema).validate(receipt)
            self.assertEqual(
                (receipt["reservation_sha256"], receipt["dispatch_sha256"]),
                (reservation["reservation_sha256"], dispatch["dispatch_sha256"]),
            )
            self.assertEqual(
                validate_pool_receipt(
                    receipt,
                    contract=contract,
                    admission_reservation=reservation,
                    dispatch_receipt=dispatch,
                ),
                ["accepting-requires-closed-state"],
            )
            self.assertEqual(
                [item["bead_id"] for item in receipt["child_terminal_receipts"]],
                [child["bead_id"] for child in contract["children"]],
            )
            self.assertTrue(
                all(
                    item["control_receipt"]["contract_sha256"]
                    == child["control_contract_sha256"]
                    for item, child in zip(
                        receipt["child_terminal_receipts"],
                        contract["children"],
                        strict=True,
                    )
                )
            )
            self.assertTrue(
                all(
                    item["implementation_bead_close_authorized"] is True
                    and item["parent_close_authorized"] is False
                    and item["publication_close_authorized"] is False
                    for item in receipt["child_dispositions"]
                )
            )
            self.assertEqual(
                [item["lifecycle_state"] for item in registry.snapshot()],
                ["released", "released"],
            )
            calls_before = {
                child_id: list(adapter.calls) for child_id, adapter in adapters.items()
            }
            with self.assertRaisesRegex(
                Exception, "admitted-launch-capability-not-available:retired"
            ):
                self._launch(
                    root, fixture, reservation, contract, request, result,
                    registry=registry,
                )
            self.assertEqual(
                calls_before,
                {child_id: list(adapter.calls) for child_id, adapter in adapters.items()},
            )

            retargeted = copy.deepcopy(receipt)
            retargeted["child_terminal_receipts"][0]["bead_id"] = contract[
                "children"
            ][1]["bead_id"]
            retargeted = seal_artifact(retargeted, "receipt_sha256")
            self.assertTrue(
                any(
                    "child-receipt[0]-bead-id-mismatch" in error
                    for error in validate_pool_receipt(
                        retargeted,
                        contract=contract,
                        admission_reservation=reservation,
                        dispatch_receipt=dispatch,
                    )
                )
            )
            parent_retargeted = copy.deepcopy(receipt)
            parent_retargeted["child_dispositions"][0][
                "parent_close_authorized"
            ] = True
            parent_retargeted = seal_artifact(
                parent_retargeted, "receipt_sha256"
            )
            self.assertTrue(
                any(
                    "parent-close-authorized-must-be-false" in error
                    for error in validate_pool_receipt(
                        parent_retargeted,
                        contract=contract,
                        admission_reservation=reservation,
                        dispatch_receipt=dispatch,
                    )
                )
            )

            hash_swapped = copy.deepcopy(receipt)
            child_receipts = hash_swapped["child_terminal_receipts"]
            child_receipts[0]["receipt_sha256"], child_receipts[1][
                "receipt_sha256"
            ] = (
                child_receipts[1]["receipt_sha256"],
                child_receipts[0]["receipt_sha256"],
            )
            hash_swapped = seal_artifact(hash_swapped, "receipt_sha256")
            self.assertTrue(
                any(
                    "control-receipt-sha256-mismatch" in error
                    for error in validate_pool_receipt(
                        hash_swapped,
                        contract=contract,
                        admission_reservation=reservation,
                        dispatch_receipt=dispatch,
                    )
                )
            )

            full_swapped = copy.deepcopy(receipt)
            child_receipts = full_swapped["child_terminal_receipts"]
            for field in ("control_receipt", "receipt_sha256"):
                child_receipts[0][field], child_receipts[1][field] = (
                    child_receipts[1][field],
                    child_receipts[0][field],
                )
            full_swapped = seal_artifact(full_swapped, "receipt_sha256")
            self.assertTrue(
                any(
                    "control-contract-sha256-mismatch" in error
                    for error in validate_pool_receipt(
                        full_swapped,
                        contract=contract,
                        admission_reservation=reservation,
                        dispatch_receipt=dispatch,
                    )
                )
            )

    def test_admitted_predispatch_rejections_have_zero_callbacks_and_contain_leases(self) -> None:
        for case in ("v1", "missing", "mix-match", "live-drift"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture, reservation, contract, request = _admitted_artifacts(root)
                result = run_pool_preflight(request)
                (
                    child_contracts,
                    tasks,
                    child_callbacks,
                    adapters,
                    pool_callbacks,
                    _clock,
                ) = _execution_inputs(fixture, contract)
                if case == "v1":
                    contract["version"] = 1
                elif case == "missing":
                    result = copy.deepcopy(result)
                    result.pop("admission_reservation_sha256")
                elif case == "mix-match":
                    result = copy.deepcopy(result)
                    result["request_sha256"] = "f" * 64
                    result["result_sha256"] = canonical_sha256(
                        {
                            key: value
                            for key, value in result.items()
                            if key != "result_sha256"
                        }
                    )
                else:
                    bead_id = reservation["issue_ids"][0]
                    fixture.claim_runner.issues[bead_id]["title"] += " drift"
                registry = PoolLeaseRegistry(
                    root / "rejected-leases.json",
                    owner_alive=lambda _owner: True,
                    now=FakeClock.now_utc,
                )
                with self.assertRaises(Exception):
                    run_admitted_native_pool(
                        reservation,
                        fixture.admission_capability,
                        contract,
                        request,
                        result,
                        child_contracts,
                        tasks,
                        child_callbacks,
                        claim_adapter=fixture.claim_adapter,
                        live_revalidate=_live,
                        pool_callbacks=pool_callbacks,
                        lease_registry=registry,
                        capability_receipt=fixture.pool_capability_receipt,
                    )
                self.assertTrue(
                    all(not adapter.calls for adapter in adapters.values())
                )
                self.assertEqual(registry.snapshot(), [])
                if case == "live-drift":
                    self.assertEqual(fixture.admission_capability.state, "available")

    def test_later_child_lease_collision_has_zero_callbacks_and_no_partial_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, reservation, contract, request = _admitted_artifacts(root)
            result = run_pool_preflight(request)
            registry = PoolLeaseRegistry(
                root / "collision-leases.json",
                owner_alive=lambda _owner: True,
                now=FakeClock.now_utc,
            )
            existing = registry.acquire(contract, contract["children"][1]["child_id"])
            (
                child_contracts,
                tasks,
                child_callbacks,
                adapters,
                pool_callbacks,
                _clock,
            ) = _execution_inputs(fixture, contract)
            with self.assertRaises(Exception):
                run_admitted_native_pool(
                    reservation,
                    fixture.admission_capability,
                    contract,
                    request,
                    result,
                    child_contracts,
                    tasks,
                    child_callbacks,
                    claim_adapter=fixture.claim_adapter,
                    live_revalidate=_live,
                    pool_callbacks=pool_callbacks,
                    lease_registry=registry,
                    capability_receipt=fixture.pool_capability_receipt,
                )
            self.assertTrue(all(not adapter.calls for adapter in adapters.values()))
            self.assertEqual(registry.snapshot(), [existing])

    def test_v2_direct_coordinator_path_is_not_productive_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, _reservation, contract, _request = _admitted_artifacts(root)
            (
                child_contracts,
                tasks,
                child_callbacks,
                adapters,
                pool_callbacks,
                _clock,
            ) = _execution_inputs(fixture, contract)
            registry = PoolLeaseRegistry(
                root / "direct-leases.json",
                owner_alive=lambda _owner: True,
                now=FakeClock.now_utc,
            )
            with self.assertRaisesRegex(
                NativePoolError, "admitted-pool-launcher-required"
            ):
                NativePoolCoordinator(
                    contract,
                    child_contracts,
                    tasks,
                    child_callbacks,
                    pool_callbacks=pool_callbacks,
                    lease_registry=registry,
                    capability_receipt=fixture.pool_capability_receipt,
                )
            self.assertTrue(all(not adapter.calls for adapter in adapters.values()))
            self.assertEqual(registry.snapshot(), [])

    def test_v2_synthetic_terminal_evidence_cannot_close_any_bead(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, reservation, contract, request = _admitted_artifacts(root)
            result = run_pool_preflight(request)
            (
                child_contracts,
                tasks,
                child_callbacks,
                adapters,
                pool_callbacks,
                _clock,
            ) = _execution_inputs(fixture, contract)

            def dirty_workspace(*, contract: dict, phase: str) -> dict:
                del contract, phase
                evidence = {
                    "integration_root_clean": False,
                    "shared_read_only_clean": True,
                    "child_worktrees_clean": True,
                }
                return {
                    **evidence,
                    "evidence_sha256": canonical_sha256(evidence),
                }

            pool_callbacks["compare_workspaces"] = dirty_workspace
            launched = run_admitted_native_pool(
                reservation,
                fixture.admission_capability,
                contract,
                request,
                result,
                child_contracts,
                tasks,
                child_callbacks,
                claim_adapter=fixture.claim_adapter,
                live_revalidate=_live,
                pool_callbacks=pool_callbacks,
                lease_registry=PoolLeaseRegistry(
                    root / "synthetic-leases.json",
                    owner_alive=lambda _owner: True,
                    now=FakeClock.now_utc,
                ),
                capability_receipt=fixture.pool_capability_receipt,
            )
            receipt = launched["pool_receipt"]
            self.assertFalse(receipt["accepting"])
            self.assertTrue(all(not adapter.calls for adapter in adapters.values()))
            self.assertTrue(
                all(
                    item["control_receipt"] is None
                    for item in receipt["child_terminal_receipts"]
                )
            )
            self.assertTrue(
                all(
                    item["implementation_bead_close_authorized"] is False
                    and item["parent_close_authorized"] is False
                    and item["publication_close_authorized"] is False
                    for item in receipt["child_dispositions"]
                )
            )

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_reservation_schema_matches_python_and_registered_validator(self) -> None:
        from jsonschema import Draft202012Validator

        with tempfile.TemporaryDirectory() as temporary:
            _, reservation, _, _ = _admitted_artifacts(Path(temporary))
            schema = json.loads(
                (
                    ROOT / "schemas/native-pool-admission-reservation.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(reservation)
            self.assertEqual(validate_pool_artifact(reservation), [])
            child_schema = schema["$defs"]["child_binding"]
            self.assertIn("hard_budget", child_schema["required"])
            self.assertIn("requested_model", child_schema["required"])
            dispatch = {
                "dispatch_type": DISPATCH_TYPE,
                "version": 2,
                "schema": DISPATCH_SCHEMA,
                "dispatch_id": "1" * 64,
                "consumed_at": "2026-07-21T20:00:03Z",
                "reservation_sha256": reservation["reservation_sha256"],
                "fixed_cohort_sha256": reservation["fixed_cohort_sha256"],
                "pool_contract_sha256": "2" * 64,
                "preflight_request_sha256": "3" * 64,
                "preflight_result_sha256": "4" * 64,
                "lease_set_sha256": "5" * 64,
                "child_bindings_sha256": reservation["child_bindings_sha256"],
                "live_revalidation_sha256": "6" * 64,
                "authority": DISPATCH_AUTHORITY,
                "dispatch_authorized": True,
            }
            dispatch["dispatch_sha256"] = canonical_admission_sha256(dispatch)
            dispatch_schema = json.loads((ROOT / DISPATCH_SCHEMA).read_text())
            Draft202012Validator.check_schema(dispatch_schema)
            Draft202012Validator(dispatch_schema).validate(dispatch)
            self.assertEqual(
                validate_pool_artifact(
                    dispatch,
                    admission_reservation=reservation,
                ),
                [],
            )

    def test_v2_render_contract_is_exact_reservation_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, reservation, contract, _ = _admitted_artifacts(Path(temporary))
            self.assertEqual(validate_pool_render_request(fixture.request), [])
            self.assertEqual(
                validate_pool_contract(
                    contract,
                    admission_reservation=reservation,
                ),
                [],
            )
            self.assertEqual(contract["version"], 2)
            self.assertEqual(contract["schema"], ADMITTED_POOL_CONTRACT_SCHEMA)
            self.assertNotIn("dispatch_sha256", contract)
            self.assertEqual(
                set(contract["children"][0]["hard_budget"]),
                {
                    "tool_calls",
                    "runtime_seconds",
                    "compactions",
                    "full_suite_runs",
                    "mutations",
                },
            )
            tampered = copy.deepcopy(contract)
            tampered["children"][0]["claim_sha256"] = "f" * 64
            tampered = seal_artifact(tampered, "contract_sha256")
            self.assertTrue(
                any(
                    "admission-child[0]-claim-mismatch" in error
                    for error in validate_pool_contract(
                        tampered,
                        admission_reservation=reservation,
                    )
                )
            )

            historical_root = Path(temporary) / "historical"
            historical_root.mkdir()
            historical = RenderFixture(historical_root, 1)
            self.assertEqual(historical.request["schema"], RENDER_REQUEST_SCHEMA)
            self.assertEqual(validate_pool_render_request(historical.request), [])

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_v2_preflight_accepts_exact_chain_and_rejects_child_drift(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import Draft202012Validator, RefResolver

        with tempfile.TemporaryDirectory() as temporary:
            _, reservation, contract, request = _admitted_artifacts(Path(temporary))
            result = run_pool_preflight(request)
            self.assertTrue(result["accepted"], result["findings"])
            self.assertEqual(
                validate_pool_preflight_result(
                    result,
                    expected_stage="pre-dispatch",
                    expected_contract_sha256=contract["contract_sha256"],
                    expected_admission_reservation_sha256=reservation[
                        "reservation_sha256"
                    ],
                ),
                [],
            )
            base_uri = (ROOT / "schemas").as_uri() + "/"
            for relative, instance in (
                (ADMITTED_RENDER_REQUEST_SCHEMA, None),
                (ADMITTED_POOL_CONTRACT_SCHEMA, contract),
                (ADMITTED_PREFLIGHT_REQUEST_SCHEMA, request),
                (ADMITTED_PREFLIGHT_RESULT_SCHEMA, result),
            ):
                schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(schema)
                if instance is not None:
                    Draft202012Validator(
                        schema,
                        resolver=RefResolver(base_uri=base_uri, referrer=schema),
                    ).validate(instance)

            drifted = copy.deepcopy(request)
            drifted["children"][0]["claim_sha256"] = "f" * 64
            drifted["children"][0]["packet_sha256"] = effective_child_packet_sha256(
                drifted["children"][0]
            )
            rejected = run_pool_preflight(drifted)
            self.assertFalse(rejected["accepted"])
            self.assertIn(
                "admission.exact-child-binding",
                {finding["rule_id"] for finding in rejected["findings"]},
            )


if __name__ == "__main__":
    unittest.main()
