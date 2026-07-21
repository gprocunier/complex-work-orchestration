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
    build_admission_child_binding,
    canonical_admission_sha256,
    reserve_pool_cohort,
)
from cwo_core.native_pool_config import (  # noqa: E402
    ADMITTED_RENDER_REQUEST_SCHEMA,
    RENDER_REQUEST_SCHEMA,
    build_pool_contract,
    validate_pool_render_request,
)
from cwo_core.native_pool_contracts import (  # noqa: E402
    ADMITTED_POOL_CONTRACT_SCHEMA,
    canonical_sha256,
    seal_artifact,
    validate_pool_artifact,
    validate_pool_contract,
    write_private_artifact,
)
from cwo_core.native_pool_leases import capture_owner_identity  # noqa: E402
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
from tests.test_native_pool_proportionality import _fixture  # noqa: E402


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def _admitted_artifacts(root: Path) -> tuple[RenderFixture, dict, dict, dict]:
    fixture = RenderFixture(root, 2)
    preflight_records = root / "preflight-records"
    preflight_records.mkdir(mode=0o700)
    readiness, estimates, items, policy = _fixture([600, 600])
    assessment = pool_proportionality_check(
        readiness,
        estimates,
        requested_workers=2,
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
    reserved = reserve_pool_cohort(
        AdmissionCandidate(readiness, estimates, assessment, admission_bindings),
        claim_adapter=_adapter(runner),
        admission_nonce="admission-contract-test",
        live_revalidate=_live,
        now="2026-07-21T20:00:02Z",
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
    capability_body = capability_payload()
    capability_body["host_identity"] = owner
    capability = seal_artifact(capability_body, "receipt_sha256")
    contract = build_pool_contract(
        fixture.request,
        capability_receipt=capability,
        enable_concurrency=True,
        owner_pid=owner["pid"],
        now=dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc),
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
        "requested_workers": 2,
        "released_capacity": 2,
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
    return fixture, reserved.receipt, contract, preflight_request


class NativePoolAdmissionContractTests(unittest.TestCase):
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
