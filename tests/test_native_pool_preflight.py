from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
import warnings


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import (  # noqa: E402
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_ALLOWED_ACTIONS,
    POOL_CONTRACT_SCHEMA,
    POOL_CONTRACT_TYPE,
    POOL_POLL_INTERVAL_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    default_completion_evidence_policy,
    seal_artifact,
    validate_pool_contract,
)
from cwo_core.native_pool_preflight import (  # noqa: E402
    PREFLIGHT_REQUEST_SCHEMA,
    PREFLIGHT_REQUEST_TYPE,
    NativePoolPreflightError,
    default_callback_certification,
    effective_child_packet_sha256,
    evaluate_scheduling_admission,
    pool_preflight_override_action_sha256,
    require_pool_preflight,
    run_pool_preflight,
    validate_pool_preflight_result,
    verify_pool_preflight_override,
)
from cwo_core.native_tool_isolation import (  # noqa: E402
    build_tool_surface_snapshot,
    default_tool_policy,
    prompt_preflight,
    seal_tool_enforcement_override,
)


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def new_uuid() -> str:
    return str(uuid.uuid4())


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def identity(label: str, ordinal: int) -> dict[str, object]:
    return {
        "canonical_path_sha256": sha(f"{label}-path"),
        "git_common_dir_sha256": sha(f"{label}-git"),
        "device": ordinal + 1,
        "inode": ordinal + 101,
        "baseline_sha256": sha(f"{label}-baseline"),
    }


def temporary_tool_override(campaign_nonce: str) -> dict[str, object]:
    return seal_tool_enforcement_override(
        {
            "override_type": "cwo-native-tool-enforcement-override",
            "version": 1,
            "schema": "schemas/native-tool-enforcement-override.schema.json",
            "authorization_id": new_uuid(),
            "authorization_canonical_sha256": sha("authorization"),
            "outer_authority_id": new_uuid(),
            "outer_authority_file_sha256": sha("outer-file"),
            "outer_authority_canonical_sha256": sha("outer-canonical"),
            "campaign_nonce": campaign_nonce,
            "candidate_commit": "a" * 40,
            "candidate_tree": "b" * 40,
            "max_workers": 2,
            "max_mutating_workers": 1,
            "single_use": True,
            "risk_acknowledgement": (
                "unlisted-built-ins-may-act-before-detection"
            ),
        }
    )


class PreflightFixture:
    def __init__(self, root: Path) -> None:
        root.chmod(0o700)
        self.integration = root / "integration"
        self.integration.mkdir(mode=0o700)
        self.records = root / "records"
        self.records.mkdir(mode=0o700)
        self.worktrees = [root / "worker-0", root / "worker-1"]
        for worktree in self.worktrees:
            worktree.mkdir(mode=0o700)
        self.pool_id = new_uuid()
        self.pool_epoch = new_uuid()
        self.launch_id = new_uuid()
        self.campaign_nonce = new_uuid()
        self.aggregate_budget = {
            "tool_calls": 20,
            "runtime_seconds": 300,
            "compactions": 0,
            "full_suite_runs": 0,
            "mutations": 2,
        }
        self.effective_children: list[dict[str, object]] = []
        contract_children: list[dict[str, object]] = []
        for index, worktree in enumerate(self.worktrees):
            tool_policy = default_tool_policy(
                mutable=True, workload_class="safety-canary"
            )
            prompt = f"Inspect the assigned target for child {index}."
            prompt_receipt = prompt_preflight(prompt, tool_policy)
            tool_surface = build_tool_surface_snapshot(
                tool_policy,
                source="offline-test-surface",
                server_allowlist_supported=False,
                allowlist_parameter=None,
                effective_allowlist=None,
            )
            completion = default_completion_evidence_policy("mutable-isolated")
            child_id = f"child-{index}"
            packet_id = new_uuid()
            attempt_nonce = new_uuid()
            session_id = new_uuid()
            lease_id = new_uuid()
            target = f"targets/child_{index}.txt"
            effective_child: dict[str, object] = {
                "child_id": child_id,
                "packet_id": packet_id,
                "attempt_nonce": attempt_nonce,
                "session_id": session_id,
                "agent_id": session_id,
                "lease_id": lease_id,
                "worktree": str(worktree),
                "isolation_class": "mutable-isolated",
                "completion_evidence_policy": completion,
                "tool_policy": tool_policy,
                "prompt": prompt,
                "prompt_preflight": prompt_receipt,
                "tool_surface": tool_surface,
                "hard_budget": {
                    "tool_calls": 10,
                    "runtime_seconds": 150,
                    "compactions": 0,
                    "full_suite_runs": 0,
                    "mutations": 1,
                },
                "declared_write_paths": [target],
                "integration_target_paths": [target],
            }
            effective_child["packet_sha256"] = effective_child_packet_sha256(
                effective_child
            )
            self.effective_children.append(effective_child)
            contract_children.append(
                {
                    "ordinal": index,
                    "child_id": child_id,
                    "packet_id": packet_id,
                    "attempt_nonce": attempt_nonce,
                    "session_id": session_id,
                    "agent_id": session_id,
                    "control_turn_id": f"control-{index}",
                    "packet_sha256": effective_child["packet_sha256"],
                    "control_contract_sha256": sha(f"control-{index}"),
                    "state_file": str(self.records / f"child-{index}-state.json"),
                    "worktree_identity": identity(f"worker-{index}", index),
                    "isolation_class": "mutable-isolated",
                    "completion_evidence_policy": completion,
                    "tool_policy": tool_policy,
                    "declared_write_paths": [target],
                    "integration_target_paths": [target],
                    "lease_id": lease_id,
                }
            )
        self.contract = seal_artifact(
            {
                "contract_type": POOL_CONTRACT_TYPE,
                "version": 1,
                "schema": POOL_CONTRACT_SCHEMA,
                "pool_id": self.pool_id,
                "pool_epoch": self.pool_epoch,
                "control_turn_id": "control-root",
                "created_at": "2026-07-20T12:00:00Z",
                "owner": {
                    "pid": 1,
                    "start_ticks": 1,
                    "boot_id_sha256": sha("boot"),
                },
                "children": contract_children,
                "max_active_workers": 2,
                "scheduler": {
                    "kind": "earliest-deadline-rotating-v1",
                    "poll_interval_ms": POOL_POLL_INTERVAL_MS,
                    "poll_lag_tolerance_ms": POOL_POLL_LAG_TOLERANCE_MS,
                    "certified_max_check_ms": CERTIFIED_CALLBACK_MAX_MS["check"],
                    "certified_max_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
                },
                "aggregate_hard_budget": self.aggregate_budget,
                "topology": {
                    "integration_root_identity": identity("integration", 20),
                    "shared_read_only_worktree": False,
                },
                "allowed_actions": list(POOL_ALLOWED_ACTIONS),
                "capability_receipt_sha256": sha("capability"),
            },
            "contract_sha256",
        )
        assert validate_pool_contract(self.contract) == []
        self.request: dict[str, object] = {
            "preflight_type": PREFLIGHT_REQUEST_TYPE,
            "version": 1,
            "schema": PREFLIGHT_REQUEST_SCHEMA,
            "stage": "pre-dispatch",
            "launch_id": self.launch_id,
            "campaign_nonce": self.campaign_nonce,
            "pool_id": self.pool_id,
            "pool_epoch": self.pool_epoch,
            "integration_root": str(self.integration),
            "artifact_directories": [str(self.records)],
            "requested_workers": 2,
            "released_capacity": 2,
            "aggregate_hard_budget": self.aggregate_budget,
            "children": self.effective_children,
            "fallback": {
                "main_thread": "main-thread",
                "recovery": "operator-recovery",
            },
            "productive_dogfood_delivery_prerequisite": False,
            "callback_certification": default_callback_certification(),
            "poll_interval_ms": POOL_POLL_INTERVAL_MS,
            "pool_contract": self.contract,
            "overrides": [],
        }

    def preallocation_request(self) -> dict[str, object]:
        request = copy.deepcopy(self.request)
        request["stage"] = "pre-allocation"
        request["pool_contract"] = None
        for child in request["children"]:  # type: ignore[index,union-attr]
            child["session_id"] = None
            child["agent_id"] = None
        return request

    def reseal_contract(self, request: dict[str, object]) -> None:
        contract = request["pool_contract"]
        assert isinstance(contract, dict)
        contract.pop("contract_sha256", None)
        contract["contract_sha256"] = seal_artifact(contract, "contract_sha256")[
            "contract_sha256"
        ]


def finding_rules(result: dict[str, object]) -> set[str]:
    return {
        str(item["rule_id"]) for item in result["findings"]  # type: ignore[union-attr]
    }


def signed_directive(key: bytes, request: dict[str, object]) -> dict[str, object]:
    body: dict[str, object] = {
        "version": 1,
        "directive_id": "pool-preflight-override-1",
        "action_sha256": pool_preflight_override_action_sha256(request),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": "complete-task",
        "parent_receipt_sha256": None,
        "issued_at": "2026-07-20T12:00:00Z",
        "nonce": "pool-preflight-directive-1",
    }
    body["signature"] = hmac.new(
        key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return body


class NativePoolPreflightTests(unittest.TestCase):
    def test_exact_contract_and_preallocation_inputs_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            preallocation = run_pool_preflight(fixture.preallocation_request())
            exact = run_pool_preflight(fixture.request)
            self.assertTrue(preallocation["accepted"])
            self.assertTrue(exact["accepted"])
            self.assertEqual(
                exact["contract_sha256"], fixture.contract["contract_sha256"]
            )
            self.assertEqual(
                validate_pool_preflight_result(
                    preallocation, expected_stage="pre-allocation"
                ),
                [],
            )
            self.assertEqual(
                validate_pool_preflight_result(
                    exact,
                    expected_stage="pre-dispatch",
                    expected_contract_sha256=fixture.contract["contract_sha256"],
                ),
                [],
            )

    def test_existing_directory_and_repeated_invocation_are_safe_and_idempotent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            first = run_pool_preflight(fixture.request)
            second = run_pool_preflight(fixture.request)
            self.assertEqual(first, second)
            self.assertTrue(first["accepted"])
            self.assertIn("directory.existing-safe", finding_rules(first))
            rendered = json.dumps(first, sort_keys=True)
            self.assertNotIn(str(fixture.records), rendered)
            self.assertNotIn(str(fixture.effective_children[0]["prompt"]), rendered)

    def test_invalid_uuid_or_nonce_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            request["launch_id"] = "not-a-uuid"
            request["children"][0]["attempt_nonce"] = "also-not-a-uuid"  # type: ignore[index]
            result = run_pool_preflight(request)
            self.assertFalse(result["accepted"])
            self.assertIn("identity.canonical-uuid", finding_rules(result))
            with self.assertRaisesRegex(
                NativePoolPreflightError, "identity.canonical-uuid"
            ):
                require_pool_preflight(request)

    def test_budget_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            request["children"][0]["hard_budget"]["tool_calls"] = 9  # type: ignore[index]
            result = run_pool_preflight(request)
            self.assertIn("budget.aggregate-equality", finding_rules(result))
            self.assertFalse(result["accepted"])

    def test_prompt_trigger_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            child = request["children"][0]  # type: ignore[index]
            child["prompt"] = "Invoke $complex-work-orchestration now."
            child["prompt_preflight"] = prompt_preflight(
                child["prompt"], child["tool_policy"]
            )
            result = run_pool_preflight(request)
            self.assertIn("prompt.trigger-conflict", finding_rules(result))
            self.assertFalse(result["accepted"])

    def test_tool_surface_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            surface = request["children"][0]["tool_surface"]  # type: ignore[index]
            surface["source"] = "tampered-surface"
            result = run_pool_preflight(request)
            self.assertIn("tools.effective-surface", finding_rules(result))
            self.assertFalse(result["accepted"])

    def test_shared_temporary_override_requires_live_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            override = temporary_tool_override(fixture.campaign_nonce)
            request["aggregate_hard_budget"]["mutations"] = 0  # type: ignore[index]
            for child in request["children"]:  # type: ignore[union-attr]
                child["isolation_class"] = "read-only-shared"
                child["completion_evidence_policy"] = (
                    default_completion_evidence_policy("read-only-shared")
                )
                child["tool_policy"] = default_tool_policy(
                    mutable=False,
                    enforcement_override=override,
                )
                child["prompt_preflight"] = prompt_preflight(
                    child["prompt"], child["tool_policy"]
                )
                child["tool_surface"] = build_tool_surface_snapshot(
                    child["tool_policy"],
                    source="offline-test-surface",
                    server_allowlist_supported=False,
                    allowlist_parameter=None,
                    effective_allowlist=None,
                )
                child["hard_budget"]["mutations"] = 0
                child["declared_write_paths"] = []
                child["integration_target_paths"] = []
                child["packet_sha256"] = effective_child_packet_sha256(child)
            result = run_pool_preflight(request)
            self.assertFalse(result["accepted"])
            self.assertIn(
                "tools.policy-enforcement-activation",
                finding_rules(result),
            )
            self.assertNotIn(
                "tools.policy-enforcement-override", finding_rules(result)
            )
            self.assertNotIn(
                "tools.policy-enforcement-override-capacity",
                finding_rules(result),
            )

    def test_temporary_override_rejects_two_mutating_children(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            override = temporary_tool_override(fixture.campaign_nonce)
            for child in request["children"]:  # type: ignore[union-attr]
                child["tool_policy"] = default_tool_policy(
                    mutable=True,
                    enforcement_override=override,
                )
                child["prompt_preflight"] = prompt_preflight(
                    child["prompt"], child["tool_policy"]
                )
                child["tool_surface"] = build_tool_surface_snapshot(
                    child["tool_policy"],
                    source="offline-test-surface",
                    server_allowlist_supported=False,
                    allowlist_parameter=None,
                    effective_allowlist=None,
                )
                child["packet_sha256"] = effective_child_packet_sha256(child)
            result = run_pool_preflight(request)
            self.assertFalse(result["accepted"])
            self.assertIn(
                "tools.policy-enforcement-override-capacity",
                finding_rules(result),
            )

    def test_overlapping_mutable_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            request["children"][1]["integration_target_paths"] = [  # type: ignore[index]
                "targets/child_0.txt/nested"
            ]
            result = run_pool_preflight(request)
            self.assertIn("topology.mutable-overlap", finding_rules(result))
            self.assertFalse(result["accepted"])

    def test_missing_fallback_and_productive_dogfood_dependency_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            request["fallback"]["recovery"] = ""  # type: ignore[index]
            request["productive_dogfood_delivery_prerequisite"] = True
            result = run_pool_preflight(request)
            rules = finding_rules(result)
            self.assertIn("fallback.declared", rules)
            self.assertIn("delivery.productive-dogfood-prerequisite", rules)
            self.assertFalse(result["accepted"])

    def test_n3_scheduling_is_accepted_and_n4_is_rejected(self) -> None:
        n2 = evaluate_scheduling_admission(
            2,
            CERTIFIED_CALLBACK_MAX_MS,
            CERTIFIED_SCHEDULER_OVERHEAD_MS,
            POOL_POLL_INTERVAL_MS,
        )
        n3 = evaluate_scheduling_admission(
            3,
            CERTIFIED_CALLBACK_MAX_MS,
            CERTIFIED_SCHEDULER_OVERHEAD_MS,
            POOL_POLL_INTERVAL_MS,
        )
        n4 = evaluate_scheduling_admission(
            4,
            CERTIFIED_CALLBACK_MAX_MS,
            CERTIFIED_SCHEDULER_OVERHEAD_MS,
            POOL_POLL_INTERVAL_MS,
        )
        self.assertEqual((n2["total_demand_ms"], n2["slack_ms"]), (750, 250))
        self.assertEqual(n3["total_demand_ms"], 950)
        self.assertEqual(n3["slack_ms"], 50)
        self.assertTrue(n3["accepted"])
        self.assertEqual(n4["total_demand_ms"], 1150)
        self.assertEqual(n4["slack_ms"], -150)
        self.assertFalse(n4["accepted"])

    def test_unauthorized_override_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.request
            request["overrides"] = [
                {
                    "rule_id": "directory.existing-safe",
                    "reason": "Acknowledge the existing private directory.",
                }
            ]
            result = run_pool_preflight(request)
            self.assertIn("override.authorization-required", finding_rules(result))
            self.assertFalse(result["accepted"])

    def test_action_bound_operator_override_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.request
            request["overrides"] = [
                {
                    "rule_id": "directory.existing-safe",
                    "reason": "Acknowledge the existing private directory.",
                }
            ]
            key = b"test-only-pool-preflight-key"
            authorization = verify_pool_preflight_override(
                request,
                signed_directive(key, request),
                verification_key=key,
                expected_actor_id="operator-1",
                expected_identity_source="trusted-control-session",
            )
            result = run_pool_preflight(request, override_authorization=authorization)
            self.assertTrue(result["accepted"])
            matching = [
                item
                for item in result["findings"]
                if item["rule_id"] == "directory.existing-safe"
            ]
            self.assertTrue(matching)
            self.assertTrue(all(item["overridden"] for item in matching))
            self.assertEqual(
                result["override_authority"]["source_type"], "operator-directive"
            )

    def test_nonwaivable_identity_override_remains_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = fixture.preallocation_request()
            request["launch_id"] = "invalid"
            request["overrides"] = [
                {
                    "rule_id": "identity.canonical-uuid",
                    "reason": "Attempt to waive an identity failure.",
                }
            ]
            key = b"test-only-pool-preflight-key"
            authorization = verify_pool_preflight_override(
                request,
                signed_directive(key, request),
                verification_key=key,
                expected_actor_id="operator-1",
                expected_identity_source="trusted-control-session",
            )
            result = run_pool_preflight(request, override_authorization=authorization)
            self.assertFalse(result["accepted"])
            self.assertIn("override.non-waivable-rule", finding_rules(result))

    def test_cli_emits_machine_readable_result_and_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(fixture.request), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "validate_native_pool_preflight.py"),
                    str(request_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["accepted"])
            self.assertEqual(result["decision"], "accept")
            rejected_request = fixture.preallocation_request()
            rejected_request["launch_id"] = "invalid"
            request_path.write_text(json.dumps(rejected_request), encoding="utf-8")
            rejected = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "validate_native_pool_preflight.py"),
                    str(request_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rejected.returncode, 1, rejected.stderr)
            rejected_result = json.loads(rejected.stdout)
            self.assertFalse(rejected_result["accepted"])
            self.assertEqual(rejected_result["decision"], "reject")

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_preflight_schemas_are_valid_draft_2020_12(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import Draft202012Validator, RefResolver

        for relative in (
            "schemas/native-supervision-pool-preflight-request.schema.json",
            "schemas/native-supervision-pool-preflight-result.schema.json",
        ):
            with self.subTest(path=relative):
                Draft202012Validator.check_schema(
                    json.loads((ROOT / relative).read_text(encoding="utf-8"))
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            instances = (
                (
                    "schemas/native-supervision-pool-preflight-request.schema.json",
                    fixture.request,
                ),
                (
                    "schemas/native-supervision-pool-preflight-result.schema.json",
                    run_pool_preflight(fixture.request),
                ),
            )
            base_uri = (ROOT / "schemas").as_uri() + "/"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                for relative, instance in instances:
                    schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
                    Draft202012Validator(
                        schema,
                        resolver=RefResolver(base_uri=base_uri, referrer=schema),
                    ).validate(instance)


if __name__ == "__main__":
    unittest.main()
