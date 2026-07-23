import copy
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_native_worker import (
    _render_prompt,
    build_native_worker_packet,
    validate_native_worker_packet,
)
from cwo_core.work_sizing import (
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
    normalize_worker_commitment_response,
)
from cwo_core.native_worker_contracts import (  # noqa: E402
    ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS,
    ALLOWED_PACKET_FIELDS,
)
from tests.native_precommit_fixtures import (  # noqa: E402
    issue_accepting_precommit_receipt,
    issue_deterministic_precommit_receipt,
)

PATHS = ["tests/test_native_worker_planning.py"]

CHECKS = [
    "python -m unittest tests.test_native_worker_planning -v",
    "python -m compileall tests/test_native_worker_planning.py scripts/prepare_native_worker.py",
    "git diff --check",
]

BUDGET = {
    "tool_calls_soft": 12,
    "tool_calls_hard": 16,
    "runtime_seconds_soft": 120,
    "runtime_seconds_hard": 249,
    "max_compactions": 0,
    "max_full_suite_runs": 0,
}

_FIXTURE_ROOT: Path | None = None


def receipt_for(
    work_plan: dict,
    *,
    packet_id: str | None = None,
    deterministic_estimates: dict[str, int] | None = None,
) -> tuple[str, dict]:
    if _FIXTURE_ROOT is None:
        raise AssertionError("precommit fixture root is not initialized")
    selected_packet_id = packet_id or f"planning-packet-{uuid.uuid4().hex}"
    estimates = deterministic_estimates or {
        key: int(work_plan["estimates"][key])
        for key in (
            "tool_calls_p50",
            "tool_calls_p90",
            "runtime_seconds_p50",
            "runtime_seconds_p90",
        )
    }
    issuer = (
        issue_deterministic_precommit_receipt
        if deterministic_estimates is not None
        else issue_accepting_precommit_receipt
    )
    configured_temp = os.environ.get("CWO_TEMP_ROOT")
    artifact_root = (
        Path(configured_temp) / "cwo-precommit-fixtures"
        if configured_temp
        else _FIXTURE_ROOT
    )
    receipt = issuer(
        work_plan=work_plan,
        packet_id=selected_packet_id,
        artifact_root=artifact_root,
        workdir=ROOT,
        estimates=estimates,
    )
    return selected_packet_id, receipt


def draft() -> dict:
    return build_native_worker_packet(
        bead_id="bead-plan",
        lane="implementation",
        workdir=str(ROOT),
        allowed_paths=PATHS,
        acceptance_checks=CHECKS,
        budget_overrides=BUDGET,
        requested_model="gpt-5.3-codex-spark",
    )


def plan() -> dict:
    raw = {
        "estimate_type": "cwo-native-work-estimate",
        "version": 1,
        "work_unit_id": "wu-native-worker-planning",
        "bead_id": "bead-plan",
        "requested_model": "gpt-5.3-codex-spark",
        "primary_outcome": "build dispatch-ready native worker planning packet with aligned estimate metadata",
        "expected_artifacts": ["ticket", "packet", "estimate"],
        "expert_profiles": ["architect", "engineer", "planner"],
        "frozen_decisions": [],
        "unresolved_decisions": [],
        "subsystems": ["native_worker", "validation"],
        "write_paths": PATHS,
        "context_manifest": [],
        "acceptance_checks": CHECKS,
        "estimates": {
            "tool_calls_p50": 3,
            "tool_calls_p90": 4,
            "runtime_seconds_p50": 4,
            "runtime_seconds_p90": 9,
            "context_tokens_p90": 1000,
        },
        "scores": {
            "reasoning_uncertainty": 0,
            "subsystem_coupling": 1,
            "contract_risk": 1,
            "diagnostic_uncertainty": 0,
            "context_breadth": 1,
            "validation_breadth": 1,
        },
        "estimate_contract_version": 2,
        "semantic_estimate": {
            "estimated_diff_p50": 20, "estimated_diff_p90": 60, "behavioral_changes": 1,
            "state_machine_changes": 0, "schema_changes": 0, "self_hosting_risk": 1,
            "live_control_risk": 1, "contract_surfaces": 1, "cli_surfaces": 0,
            "policy_surfaces": 0, "telemetry_surfaces": 0, "expected_regressions": 3,
            "test_construction_complexity": 1, "command_complexity": 1, "nested_quote_layers": 1,
            "expected_context_reads": 1, "expected_mutations": 1, "read_to_mutation_ratio": 1,
        },
        "pm_estimate": {"tool_calls_p50": 3, "tool_calls_p90": 4, "runtime_seconds_p50": 4, "runtime_seconds_p90": 9},
        "domain_expert_estimate": {"tool_calls_p50": 3, "tool_calls_p90": 4, "runtime_seconds_p50": 4, "runtime_seconds_p90": 9},
    }
    return evaluate_work_estimate(raw)


def commitment(plan: dict, decision: str = "accept") -> dict:
    return {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": plan["work_unit_id"],
        "bead_id": plan["bead_id"],
        "requested_model": plan["requested_model"],
        "session_id": "session-native-worker-planning",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": plan["requested_model"],
        "work_estimate_sha256": canonical_work_estimate_sha256(plan),
        "decision": decision,
        "confidence": 0.91,
        "estimates": {
            "tool_calls_p50": 3,
            "tool_calls_p90": 4,
            "runtime_seconds_p50": 4,
            "runtime_seconds_p90": 9,
        },
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "focused packet planning and estimate completion",
    }


def planned(budget: dict = None) -> dict:
    budget = BUDGET if budget is None else budget
    p = plan()
    packet_id, receipt = receipt_for(p)
    return build_native_worker_packet(
        bead_id="bead-plan",
        lane="implementation",
        workdir=str(ROOT),
        allowed_paths=PATHS,
        acceptance_checks=CHECKS,
        work_plan=p,
        precommit_receipt=receipt,
        packet_id=packet_id,
        budget_overrides=budget,
        requested_model="gpt-5.3-codex-spark",
    )


def checked_plan() -> dict:
    value = plan()
    commands = [
        ["python3", "-m", "unittest", "tests.test_native_worker_planning", "-v"],
        ["git", "diff", "--check"],
    ]
    specs = []
    for index, argv in enumerate(commands):
        specs.append(
            {
                "spec_type": "cwo-checked-command-spec",
                "version": 1,
                "command_id": f"checked-{index}",
                "mode": "argv",
                "argv": argv,
                "cwd": str(ROOT),
                "env": {},
                "inherit_environment": True,
                "stdin": None,
                "source": None,
                "preflights": [],
                "mutation_intent": "none",
                "allowed_paths": [],
                "timeout_seconds": 60,
            }
        )
    value["task_profile"] = {
        "task_class": "bounded-implementation",
        "declared_outcome_count": 1,
        "command_count": len(commands),
        "check_count": len(commands),
        "focused_test_count": 1,
        "full_suite_count": 0,
        "read_context_count": 0,
        "source_mutation_count": len(PATHS),
        "commands": [{"argv": argv} for argv in commands],
        "source_mutation_paths": PATHS,
        "execution_contract": {"mode": "checked-sequence-v1", "checked_command_specs": specs},
    }
    return evaluate_work_estimate(value)


def checked_packet() -> dict:
    value = checked_plan()
    packet_id, receipt = receipt_for(value, packet_id="checked-packet")
    return build_native_worker_packet(
        bead_id="bead-plan",
        lane="implementation",
        workdir=str(ROOT),
        allowed_paths=PATHS,
        acceptance_checks=CHECKS,
        work_plan=value,
        precommit_receipt=receipt,
        budget_overrides=BUDGET,
        requested_model="gpt-5.3-codex-spark",
        packet_id=packet_id,
    )


def _contains(errors, text):
    lowered = text.lower()
    return any(lowered in err.lower() for err in errors)


class TestNativeWorkerPlanning(unittest.TestCase):
    def setUp(self):
        global _FIXTURE_ROOT
        self.precommit_temp = tempfile.TemporaryDirectory(prefix="cwo-planning-precommit-")
        self.addCleanup(self.precommit_temp.cleanup)
        _FIXTURE_ROOT = Path(self.precommit_temp.name)
        self.addCleanup(lambda: globals().__setitem__("_FIXTURE_ROOT", None))
        environment = mock.patch.dict(
            os.environ,
            {
                "CWO_PRECOMMIT_REGISTRY_ROOT": str(_FIXTURE_ROOT / "registry"),
                "CWO_TEMP_ROOT": str(_FIXTURE_ROOT),
            },
        )
        environment.start()
        self.addCleanup(environment.stop)

    def test_checked_sequence_packet_builds_strict_bound_receipt(self):
        with tempfile.TemporaryDirectory(), mock.patch.dict(
            os.environ, {"CWO_TEMP_ROOT": str(_FIXTURE_ROOT)}
        ):
            packet = checked_packet()
            receipt = packet["checked_command_sequence"]
            self.assertEqual(set(receipt), ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS)
            self.assertEqual(receipt["spec"]["packet_id"], packet["packet_id"])
            self.assertEqual(receipt["spec"]["commands"], packet["work_plan"]["task_profile"]["execution_contract"]["checked_command_specs"])
            self.assertEqual(Path(receipt["spec_path"]).parent, Path(receipt["state_path"]).parent)
            self.assertEqual(Path(receipt["spec_path"]).parent, Path(receipt["output_path"]).parent)
            self.assertEqual(json.loads(Path(receipt["spec_path"]).read_text(encoding="utf-8")), receipt["spec"])
            self.assertEqual(validate_native_worker_packet(packet), [])
            self.assertTrue(
                _contains(
                    validate_native_worker_packet(packet, dispatchable=True),
                    "operative-dispatch-forbidden",
                )
            )

            schema = json.loads((ROOT / "schemas" / "native-worker-packet.schema.json").read_text(encoding="utf-8"))
            self.assertEqual(set(schema["properties"]), ALLOWED_PACKET_FIELDS)
            self.assertEqual(
                set(schema["properties"]["checked_command_sequence"]["properties"]),
                ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS,
            )

    def test_checked_sequence_render_is_outer_only_and_direct_stays_direct(self):
        with tempfile.TemporaryDirectory(), mock.patch.dict(
            os.environ, {"CWO_TEMP_ROOT": str(_FIXTURE_ROOT)}
        ):
            packet = checked_packet()
            rendered = _render_prompt(packet)
            runner = " ".join(packet["checked_command_sequence"]["runner_argv"])
            self.assertIn("Run exactly one outer sequence runner command", rendered)
            self.assertIn(runner, rendered)
            self.assertNotIn("1. python3 -m unittest tests.test_native_worker_planning -v", rendered)
            self.assertEqual(rendered.count(runner), 2)

        direct = _render_prompt(planned())
        self.assertNotIn("Checked sequence execution contract", direct)
        self.assertNotIn("checked_command_sequence", planned())

    def test_checked_sequence_validation_rejects_missing_and_direct_receipts(self):
        with tempfile.TemporaryDirectory(), mock.patch.dict(
            os.environ, {"CWO_TEMP_ROOT": str(_FIXTURE_ROOT)}
        ):
            packet = checked_packet()
            missing = copy.deepcopy(packet)
            missing.pop("checked_command_sequence")
            self.assertTrue(_contains(validate_native_worker_packet(missing), "requires checked_command_sequence"))

            direct = planned()
            direct["checked_command_sequence"] = copy.deepcopy(packet["checked_command_sequence"])
            self.assertTrue(_contains(validate_native_worker_packet(direct), "is forbidden"))

    def test_checked_sequence_validation_rejects_tampering(self):
        with tempfile.TemporaryDirectory(), mock.patch.dict(
            os.environ, {"CWO_TEMP_ROOT": str(_FIXTURE_ROOT)}
        ):
            packet = checked_packet()
            cases = []
            embedded = copy.deepcopy(packet)
            embedded["checked_command_sequence"]["spec"]["packet_id"] = "other"
            cases.append((embedded, "packet_id"))
            digest = copy.deepcopy(packet)
            digest["checked_command_sequence"]["spec_sha256"] = "0" * 64
            cases.append((digest, "spec_sha256"))
            runner = copy.deepcopy(packet)
            runner["checked_command_sequence"]["runner_argv"][0] = "python"
            cases.append((runner, "runner_argv"))
            sibling = copy.deepcopy(packet)
            sibling["checked_command_sequence"]["state_path"] = str(
                Path(packet["checked_command_sequence"]["state_path"]).parent.parent
                / "other-sequence"
                / "state.json"
            )
            cases.append((sibling, "siblings"))
            work_plan = copy.deepcopy(packet)
            work_plan["work_plan"]["primary_outcome"] = "tampered"
            cases.append((work_plan, "work_plan_sha256"))
            for candidate, expected in cases:
                with self.subTest(expected=expected):
                    self.assertTrue(_contains(validate_native_worker_packet(candidate), expected))

            spec_path = Path(packet["checked_command_sequence"]["spec_path"])
            original = spec_path.read_text(encoding="utf-8")
            spec_path.write_text("{}\n", encoding="utf-8")
            try:
                self.assertTrue(_contains(validate_native_worker_packet(packet), "persisted spec"))
            finally:
                spec_path.write_text(original, encoding="utf-8")

    def test_draft_validation_modes(self):
        non_dispatch_errors = validate_native_worker_packet(draft(), dispatchable=False)
        self.assertEqual(non_dispatch_errors, [])

        dispatchable_errors = validate_native_worker_packet(draft(), dispatchable=True)
        self.assertNotEqual(dispatchable_errors, [])
        self.assertTrue(
            _contains(dispatchable_errors, "dispatchable packet requires work_plan and worker_commitment")
        )

    def test_build_with_exactly_one_planning_arg_fails(self):
        with self.assertRaises(SystemExit):
            build_native_worker_packet(
                bead_id="bead-plan",
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=PATHS,
                acceptance_checks=CHECKS,
                budget_overrides=BUDGET,
                requested_model="gpt-5.3-codex-spark",
                work_plan=plan(),
            )

        with self.assertRaises(SystemExit):
            build_native_worker_packet(
                bead_id="bead-plan",
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=PATHS,
                acceptance_checks=CHECKS,
                budget_overrides=BUDGET,
                requested_model="gpt-5.3-codex-spark",
                worker_commitment=commitment(plan()),
            )

    def test_planned_candidate_is_structurally_valid_and_dispatch_forbidden(self):
        packet = planned()
        self.assertEqual(validate_native_worker_packet(packet), [])
        errors = validate_native_worker_packet(packet, dispatchable=True)
        self.assertTrue(_contains(errors, "operative-dispatch-forbidden"))
        self.assertEqual(packet["work_plan"]["estimate_contract_version"], 2)
        self.assertEqual(packet["work_plan"]["authority_route"], "spark")
        self.assertEqual(packet["work_plan"]["operative_route"], "spark")
        self.assertEqual(packet["command_contract"]["wrapper"], "scripts/run_checked_command.py")

    def test_deterministic_plan_builds_policy_fit_commitment_from_trusted_attestation(self):
        deterministic = plan()
        deterministic["semantic_estimate"]["estimated_diff_p90"] = 40
        deterministic["task_profile"] = {
            "task_class": "narrow-mechanical",
            "declared_outcome_count": 1,
            "command_count": 0,
            "check_count": 3,
            "focused_test_count": 2,
            "full_suite_count": 0,
            "read_context_count": 0,
            "source_mutation_count": 1,
            "commands": [],
            "source_mutation_paths": PATHS,
        }
        deterministic = evaluate_work_estimate(deterministic)
        packet_id, receipt = receipt_for(
            deterministic,
            deterministic_estimates={
                "tool_calls_p50": 4,
                "tool_calls_p90": 6,
                "runtime_seconds_p50": 90,
                "runtime_seconds_p90": 180,
            },
        )
        packet = build_native_worker_packet(
            bead_id="bead-plan",
            lane="implementation",
            workdir=str(ROOT),
            allowed_paths=PATHS,
            acceptance_checks=CHECKS,
            work_plan=deterministic,
            precommit_receipt=receipt,
            packet_id=packet_id,
            budget_overrides={
                "tool_calls_soft": 6,
                "tool_calls_hard": 10,
                "runtime_seconds_soft": 180,
                "runtime_seconds_hard": 300,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
            requested_model="gpt-5.3-codex-spark",
        )
        self.assertEqual(packet["worker_commitment"]["session_id"], receipt["session_id"])
        self.assertEqual(packet["worker_commitment"]["estimates"]["tool_calls_p90"], 6)
        self.assertEqual(validate_native_worker_packet(packet), [])
        self.assertTrue(_contains(validate_native_worker_packet(packet, dispatchable=True), "operative-dispatch-forbidden"))

    def test_semantic_plan_cannot_skip_worker_commitment(self):
        with self.assertRaisesRegex(SystemExit, "trusted precommit receipt"):
            build_native_worker_packet(
                bead_id="bead-plan",
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=PATHS,
                acceptance_checks=CHECKS,
                work_plan=plan(),
                trusted_session_id="trusted-spark-session",
                attested_model="gpt-5.3-codex-spark",
                budget_overrides=BUDGET,
                requested_model="gpt-5.3-codex-spark",
            )

    def test_read_only_plan_separates_context_scope_from_write_scope(self):
        read_only = plan()
        read_only["write_paths"] = []
        read_only["context_manifest"] = [
            {"path": PATHS[0], "selector": "file", "purpose": "validation", "bytes": 1, "sha256": "0" * 64}
        ]
        read_only["semantic_estimate"].update(
            {
                "estimated_diff_p50": 0,
                "estimated_diff_p90": 0,
                "expected_context_reads": 1,
                "expected_mutations": 0,
                "read_to_mutation_ratio": 1,
            }
        )
        read_only["task_profile"] = {
            "task_class": "read-only-validation",
            "declared_outcome_count": 1,
            "command_count": 3,
            "check_count": 3,
            "focused_test_count": 1,
            "full_suite_count": 0,
            "read_context_count": 1,
            "source_mutation_count": 0,
            "commands": [
                {"argv": ["python3", "-m", "unittest", "tests.test_native_worker_planning", "-v"]},
                {"argv": ["python3", "-m", "compileall", "scripts/prepare_native_worker.py"]},
                {"argv": ["git", "diff", "--check"]},
            ],
            "source_mutation_paths": [],
        }
        read_only = evaluate_work_estimate(read_only)
        packet_id, receipt = receipt_for(
            read_only,
            deterministic_estimates={
                "tool_calls_p50": 2,
                "tool_calls_p90": 4,
                "runtime_seconds_p50": 150,
                "runtime_seconds_p90": 300,
            },
        )
        packet = build_native_worker_packet(
            bead_id="bead-plan",
            lane="validation",
            workdir=str(ROOT),
            allowed_paths=PATHS,
            acceptance_checks=CHECKS,
            work_plan=read_only,
            precommit_receipt=receipt,
            packet_id=packet_id,
            budget_overrides={
                "tool_calls_soft": 4,
                "tool_calls_hard": 10,
                "runtime_seconds_soft": 300,
                "runtime_seconds_hard": 600,
                "max_compactions": 0,
                "max_full_suite_runs": 0,
            },
        )
        self.assertEqual(packet["work_plan"]["write_paths"], [])
        self.assertEqual(packet["scope"]["allowed_paths"], PATHS)
        self.assertNotIn("edit-scoped-files", packet["scope"]["allowed_actions"])
        self.assertIn("source-mutation", packet["scope"]["prohibited_actions"])
        self.assertEqual(validate_native_worker_packet(packet), [])
        widened = copy.deepcopy(packet)
        widened["tool_policy"]["permitted_tools"] = [
            "apply_patch",
            "exec_command",
            "write_stdin",
        ]
        self.assertTrue(
            _contains(
                validate_native_worker_packet(widened),
                "read-only work_plan tool_policy must not permit apply_patch",
            )
        )
        self.assertTrue(_contains(validate_native_worker_packet(packet, dispatchable=True), "operative-dispatch-forbidden"))

        rendered = _render_prompt(packet)
        self.assertIn("Deterministic execution contract:", rendered)
        self.assertIn("The first tool call must execute command 1", rendered)
        self.assertIn("Do not acknowledge first, inspect helpers or source, run --help", rendered)
        self.assertIn("No exploratory tool calls are permitted", rendered)
        self.assertIn("1. python3 -m unittest tests.test_native_worker_planning -v", rendered)
        self.assertNotIn("- Wrapper: scripts/run_checked_command.py", rendered)
        self.assertNotIn("build wrapper specifications.\n- Wrapper:", rendered)
        self.assertIn('"files_touched": []', rendered)
        self.assertIn('"mutation_state": "clean"', rendered)

    def test_candidate_rejects_nonaccepting_commitment(self):
        packet = planned()
        packet["worker_commitment"]["decision"] = "pm-realignment"
        errors = validate_native_worker_packet(packet)
        self.assertTrue(_contains(errors, "decision accept"))

    def test_tampered_commitment_hash_and_binding_errors(self):
        packet = planned()

        tampered = copy.deepcopy(packet)
        tampered["worker_commitment"]["work_estimate_sha256"] = "0" * 64
        self.assertTrue(
            any(
                "work_estimate_sha256" in err.lower() or "hash" in err.lower()
                for err in validate_native_worker_packet(tampered, dispatchable=True)
            )
        )

        binding = copy.deepcopy(packet)
        binding["bead_id"] = "different-bead"
        binding["worker_commitment"]["bead_id"] = "different-bead"
        binding["requested_model"] = "different-model"
        binding["worker_commitment"]["attested_model"] = "different-model"
        binding["scope"]["allowed_paths"] = ["other/path"]
        binding["acceptance_checks"] = [
            "python -m unittest tests.test_native_worker_planning -q"
        ]
        binding_errors = validate_native_worker_packet(binding, dispatchable=True)
        self.assertTrue(binding_errors)
        for token in ("bead", "model", "path", "acceptance"):
            self.assertTrue(any(token in err.lower() for err in binding_errors))

    def test_plan_allowance_violation_tool_calls_hard(self):
        budget = dict(BUDGET)
        budget["tool_calls_hard"] = 17
        errors = validate_native_worker_packet(
            planned(budget=budget), dispatchable=True
        )
        self.assertTrue(_contains(errors, "aggregate allowance"))

    def test_planned_route_is_spark_only(self):
        route_packet = copy.deepcopy(planned())
        route_work_plan = copy.deepcopy(route_packet["work_plan"])
        route_work_plan["scores"]["reasoning_uncertainty"] = 3
        for key in ("score_total", "route", "hard_gate_reasons", "aggregate_allowance"):
            route_work_plan.pop(key, None)
        route_packet["work_plan"] = evaluate_work_estimate(route_work_plan)
        route_packet["worker_commitment"]["work_estimate_sha256"] = canonical_work_estimate_sha256(
            route_packet["work_plan"]
        )
        route_errors = validate_native_worker_packet(route_packet, dispatchable=True)
        self.assertTrue(_contains(route_errors, "work_plan.route"))

    def test_commitment_normalizer_derives_v2_exclusively_from_receipt(self):
        p = plan()
        _, receipt = receipt_for(p)
        result = normalize_worker_commitment_response(
            {"decision": "contradictory-untrusted-self-report"},
            p,
            precommit_receipt=receipt,
        )
        self.assertEqual(result["outcome"], "normalized")
        self.assertEqual(result["decision"], "accept")
        self.assertEqual(result["normalized_commitment"]["version"], 2)
        self.assertEqual(result["normalized_commitment"]["session_id"], receipt["session_id"])
        self.assertFalse(result["model_retry_allowed"])

    def test_commitment_normalizer_requires_receipt_without_model_retry(self):
        p = plan()
        result = normalize_worker_commitment_response(
            "proceed tool_calls_p50=3",
            p,
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertIsNone(result["normalized_commitment"])
        self.assertTrue(_contains(result["errors"], "trusted precommit receipt"))
        self.assertFalse(result["model_retry_allowed"])

    def test_commitment_normalizer_rejects_parallel_identity_authority(self):
        p = plan()
        _, receipt = receipt_for(p)
        result = normalize_worker_commitment_response(
            {},
            p,
            precommit_receipt=receipt,
            session_id="parallel-session",
            attested_model="gpt-5.3-codex-spark",
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertTrue(_contains(result["errors"], "derived exclusively"))
