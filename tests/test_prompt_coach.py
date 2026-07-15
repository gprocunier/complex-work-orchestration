from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402
from cwo_core.errors import CWOPolicyError  # noqa: E402

RETIRED_FIELD = "beads_" + "briefing_depth"
RETIRED_FLAG = "--beads-" + "briefing-depth"


class SchemaValidationError(AssertionError):
    pass


def _schema_type_matches(instance: object, expected: str) -> bool:
    return {
        "array": isinstance(instance, list),
        "boolean": isinstance(instance, bool),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        "null": instance is None,
        "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
        "object": isinstance(instance, dict),
        "string": isinstance(instance, str),
    }.get(expected, False)


def _resolve_schema_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaValidationError(f"unsupported schema reference: {reference}")
    value: Any = root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            raise SchemaValidationError(f"unresolved schema reference: {reference}")
        value = value[part]
    if not isinstance(value, dict):
        raise SchemaValidationError(f"schema reference is not an object: {reference}")
    return value


def validate_schema_instance(
    instance: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    root = schema if root is None else root

    if "$ref" in schema:
        validate_schema_instance(
            instance,
            _resolve_schema_ref(root, str(schema["$ref"])),
            root=root,
            path=path,
        )
    if "not" in schema:
        try:
            validate_schema_instance(instance, schema["not"], root=root, path=path)
        except SchemaValidationError:
            pass
        else:
            raise SchemaValidationError(f"{path} matches a forbidden schema")
    if "allOf" in schema:
        for child in schema["allOf"]:
            validate_schema_instance(instance, child, root=root, path=path)
    if "anyOf" in schema:
        if not any(_schema_accepts(instance, child, root, path) for child in schema["anyOf"]):
            raise SchemaValidationError(f"{path} does not match any allowed schema")
    if "oneOf" in schema:
        matches = sum(_schema_accepts(instance, child, root, path) for child in schema["oneOf"])
        if matches != 1:
            raise SchemaValidationError(f"{path} matches {matches} oneOf branches")
    if "if" in schema:
        branch = "then" if _schema_accepts(instance, schema["if"], root, path) else "else"
        if branch in schema:
            validate_schema_instance(instance, schema[branch], root=root, path=path)

    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path} does not equal {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path} is not in the schema enum")
    if "type" in schema:
        expected_types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_schema_type_matches(instance, str(expected)) for expected in expected_types):
            raise SchemaValidationError(f"{path} has the wrong type")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in instance]
        if missing:
            raise SchemaValidationError(f"{path} is missing required keys: {missing}")
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in instance:
                validate_schema_instance(instance[key], child, root=root, path=f"{path}.{key}")
        if schema.get("additionalProperties") is False:
            extras = sorted(set(instance) - set(properties))
            if extras:
                raise SchemaValidationError(f"{path} has unexpected keys: {extras}")

    if isinstance(instance, list):
        if len(instance) < int(schema.get("minItems", 0)):
            raise SchemaValidationError(f"{path} has too few items")
        if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
            raise SchemaValidationError(f"{path} has too many items")
        if "items" in schema:
            for index, item in enumerate(instance):
                validate_schema_instance(item, schema["items"], root=root, path=f"{path}[{index}]")
        if "contains" in schema and not any(
            _schema_accepts(item, schema["contains"], root, f"{path}[{index}]")
            for index, item in enumerate(instance)
        ):
            raise SchemaValidationError(f"{path} does not contain a matching item")

    if isinstance(instance, str):
        if len(instance) < int(schema.get("minLength", 0)):
            raise SchemaValidationError(f"{path} is too short")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            raise SchemaValidationError(f"{path} is too long")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise SchemaValidationError(f"{path} is below the minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise SchemaValidationError(f"{path} is above the maximum")


def _schema_accepts(instance: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> bool:
    try:
        validate_schema_instance(instance, schema, root=root, path=path)
    except SchemaValidationError:
        return False
    return True


class PromptCoachTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch(
            "cwo_core.routing.native_operative_containment",
            return_value={"status": "available", "dispatch_authorized": True},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unknown_execution_environment_raises_typed_policy_error(self) -> None:
        with self.assertRaisesRegex(CWOPolicyError, "unknown execution environment: missing-env"):
            coach_orchestration_prompt("Review the architecture plan.", execution_environment="missing-env")

    def test_coach_cli_translates_typed_error_without_traceback(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "coach_prompt.py"),
                "--brief",
                "--execution-environment",
                "missing-env",
                "Review the architecture plan.",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown execution environment: missing-env", result.stderr)
        self.assertNotIn("Traceback", result.stderr + result.stdout)

    def test_narrow_work_recommends_in_thread(self) -> None:
        result = coach_orchestration_prompt("Fix typo in README.md")
        self.assertEqual(result["recommended_orchestration_level"], "in-thread")
        self.assertEqual(result["model_synthesis"]["recommended_mode"], "none")
        self.assertEqual(result["operator_calibration"]["mode"], "none")
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn(result["beads_context_depth"], {"summary", "focused"})
        self.assertNotIn(RETIRED_FIELD, result)
        self.assertEqual(result["beads_context_depth_provenance"]["source"], "autosized")
        self.assertIn("mandatory Beads tracking", result["paste_ready_prompt"])
        self.assertIn("beads-durable-state", result["enabled_levers"])
        self.assertIn("beads-minimum-tracking", result["enabled_levers"])
        self.assertIn("full-harness", result["disabled_levers"])
        self.assertIn("model-synthesis-unselected", result["disabled_levers"])
        self.assertNotIn("beads-work-graph", result["disabled_levers"])

    def test_safety_deferred_clean_negative_requires_operator_calibration(self) -> None:
        result = coach_orchestration_prompt(
            "Close this lane as clean-negative after safety-deferred live execution was not run."
        )

        self.assertEqual(result["operator_calibration"]["mode"], "required")
        self.assertIn("clean-negative", result["operator_calibration"]["trigger_reasons"])
        self.assertIn("not run", result["operator_calibration"]["trigger_reasons"])
        self.assertIn("operator-calibrated-execution=required", result["enabled_levers"])
        self.assertIn("contract-jd-operator-calibrated-execution", result["enabled_levers"])
        self.assertIn("contract-jd-operator-calibrated-execution", result["paste_ready_prompt"])
        self.assertIn("Are we closing this because the hypothesis is disproven", result["paste_ready_prompt"])
        self.assertFalse(result["operator_calibration"]["prompt_user_in_plan_mode"])

    def test_autonomous_commit_push_recommends_operator_calibration(self) -> None:
        result = coach_orchestration_prompt(
            "Proceed autonomously through the sprint loop, then commit and push the completed artifacts."
        )

        self.assertEqual(result["operator_calibration"]["mode"], "recommended")
        self.assertIn("proceed autonomously", result["operator_calibration"]["trigger_reasons"])
        self.assertIn("commit and push", result["operator_calibration"]["trigger_reasons"])
        self.assertIn("operator-calibrated-execution=recommended", result["enabled_levers"])
        self.assertIn("Consider contract-jd-operator-calibrated-execution", result["paste_ready_prompt"])

    def test_model_disagreement_exhausted_lane_requires_operator_calibration(self) -> None:
        result = coach_orchestration_prompt(
            "Review conflicting feedback from two models before we mark the lane exhausted and pivot away."
        )

        self.assertEqual(result["operator_calibration"]["mode"], "required")
        self.assertIn("pivot away", result["operator_calibration"]["trigger_reasons"])
        self.assertIn("operator-calibrated-execution=required", result["enabled_levers"])

    def test_ordinary_docs_task_does_not_add_operator_calibration_lever(self) -> None:
        result = coach_orchestration_prompt("Fix typo in README.md")

        self.assertEqual(result["operator_calibration"]["mode"], "none")
        self.assertNotIn("operator-calibrated-execution=required", result["enabled_levers"])
        self.assertNotIn("operator-calibrated-execution=recommended", result["enabled_levers"])
        self.assertNotIn("contract-jd-operator-calibrated-execution", result["paste_ready_prompt"])

    def test_coach_cli_brief_mode_omits_launch_prompt(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "coach_prompt.py"),
                "--brief",
                "Fix typo in README.md",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Recommended orchestration: in-thread", result.stdout)
        self.assertIn("Route:", result.stdout)
        self.assertIn("Executor:", result.stdout)
        self.assertIn("Execution gate:", result.stdout)
        self.assertIn("Coach options:", result.stdout)
        self.assertIn("Native operative dispatch remains contained until fsh.3", result.stdout)
        self.assertNotIn("Should CWO parallelize this work with subagent lanes?", result.stdout)
        self.assertNotIn("Recommended launch prompt:", result.stdout)

    def test_multi_session_work_recommends_lightweight_beads(self) -> None:
        result = coach_orchestration_prompt("Plan a multi-session cleanup of installer docs, tests, and handoff notes.")
        self.assertEqual(result["recommended_orchestration_level"], "lightweight-beads")
        self.assertTrue(any(item["id"] == "beads_graph_size" for item in result["missing_questions"]))
        self.assertIn("beads-durable-state", result["enabled_levers"])

    def test_high_risk_architecture_recommends_full_harness(self) -> None:
        result = coach_orchestration_prompt(
            "Refactor the orchestration control plane across routing, schema validation, docs, and CI.",
            requested_roles=["architecture"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertIn("architect-review", result["enabled_levers"])
        self.assertEqual(result["model_synthesis"]["recommended_mode"], "recommended")
        self.assertFalse(result["model_synthesis"]["active"])
        self.assertTrue(result["model_synthesis"]["requires_user_acceptance"])
        self.assertTrue(result["model_synthesis"]["prompt_user_in_plan_mode"])
        self.assertEqual(result["route"]["model_synthesis"]["recommended_mode"], "recommended")
        self.assertIn("model-synthesis=recommended", result["enabled_levers"])
        self.assertIn("model-synthesis-opt-in-choice", result["enabled_levers"])
        self.assertIn("model-synthesis-until-opt-in", result["disabled_levers"])
        self.assertTrue(any(item["id"] == "model_synthesis_opt_in" for item in result["missing_questions"]))
        synthesis_questions = [
            item for item in result["interactive_questions"] if item["id"] == "model_synthesis_opt_in"
        ]
        self.assertEqual(len(synthesis_questions), 1)
        self.assertEqual(synthesis_questions[0]["options"][0]["value"], "model-synthesis")

    def test_explicit_scaffold_recommends_full_harness(self) -> None:
        result = coach_orchestration_prompt("Use $complex-work-orchestration to scaffold this project.")
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertEqual(result["scaffold_sizing"]["recommended_size"], "full")
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn("architect-review", result["enabled_levers"])
        self.assertIn("validation-lane", result["enabled_levers"])
        self.assertIn("scaffold-size=full", result["enabled_levers"])
        self.assertIn("full architect/PM/subagent/validation harness", result["paste_ready_prompt"])
        harness_questions = [
            item for item in result["interactive_questions"] if item["id"] == "orchestration_level"
        ]
        self.assertEqual(len(harness_questions), 1)
        self.assertEqual(harness_questions[0]["options"][0]["value"], "full-harness")

    def test_tight_chain_scaffold_is_a_prompt_coach_graph_size_choice(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration to scaffold a tight-chain review of CWO docs, routing, validation, and public pages."
        )

        self.assertEqual(result["scaffold_sizing"]["recommended_size"], "tight")
        self.assertIn("scaffold-size=tight", result["enabled_levers"])
        self.assertIn("optional-expert-fanout", result["disabled_levers"])
        self.assertIn("--scaffold-size tight", result["paste_ready_prompt"])
        graph_questions = [
            item for item in result["interactive_questions"] if item["id"] == "scaffold_size"
        ]
        self.assertEqual(len(graph_questions), 1)
        self.assertEqual(graph_questions[0]["options"][0]["value"], "tight-chain")

    def test_scaffold_size_flag_marks_coach_choice_accepted(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration to scaffold this project.",
            scaffold_size="tight",
        )

        self.assertEqual(result["scaffold_sizing"]["recommended_size"], "tight")
        self.assertIn("scaffold-size=tight", result["enabled_levers"])
        self.assertIn("helper was launched with scaffold-size=tight", " ".join(result["scaffold_sizing"]["rationale"]))

    def test_context_depth_override_is_auditable_and_prompted(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration coach for a deep second pass on docs and prior Beads comments.",
            beads_context_depth="heavy",
        )

        self.assertEqual(result["beads_context_depth"], "heavy")
        self.assertNotIn(RETIRED_FIELD, result)
        self.assertEqual(result["beads_context_depth_provenance"]["source"], "explicit")
        self.assertEqual(result["beads_context_depth_provenance"]["computed_depth"], "heavy")
        self.assertEqual(result["beads_context_depth_provenance"]["effective_depth"], "heavy")
        self.assertIn("beads-context-depth=heavy", result["enabled_levers"])
        self.assertIn("build_beads_brief.py --depth heavy --for subagent", result["paste_ready_prompt"])
        self.assertIn("do not export raw Beads comments", result["paste_ready_prompt"])
        self.assertTrue(any(item["id"] == "beads_context_depth" for item in result["interactive_questions"]))

    def test_context_depth_question_is_always_present_with_autosized_default(self) -> None:
        result = coach_orchestration_prompt("Fix typo in README.md")

        missing = [item for item in result["missing_questions"] if item["id"] == "beads_context_depth"]
        questions = [item for item in result["interactive_questions"] if item["id"] == "beads_context_depth"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(len(questions), 1)
        self.assertEqual(questions[0]["options"][0]["value"], result["beads_context_depth"])
        self.assertIn("(Recommended)", questions[0]["options"][0]["label"])
        self.assertIn(f"Use {result['beads_context_depth']} context", missing[0]["default"])

    def test_context_depth_alias_flag_is_removed(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "coach_prompt.py"),
                RETIRED_FLAG,
                "heavy",
                "Use $complex-work-orchestration coach for docs.",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"unrecognized arguments: {RETIRED_FLAG}", result.stderr)

    def test_data_sensitivity_declaration_is_preserved_in_route(self) -> None:
        result = coach_orchestration_prompt(
            "Publish public docs for the install flow.",
            data_sensitivity="restricted",
        )

        self.assertEqual(result["route"]["data_sensitivity"], "restricted")
        self.assertEqual(result["route"]["data_sensitivity_source"], "operator-declared")
        self.assertEqual(result["route"]["data_sensitivity_heuristic"], "public")
        self.assertIn("can miss paraphrases", result["route"]["data_sensitivity_disclaimer"])

    def test_coach_cli_accepts_data_sensitivity_declaration(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "coach_prompt.py"),
                "--json",
                "--data-sensitivity",
                "restricted",
                "Publish public docs for the install flow.",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["route"]["data_sensitivity"], "restricted")
        self.assertEqual(payload["route"]["data_sensitivity_source"], "operator-declared")

    def test_contractor_lane_terms_ask_for_sharing_boundary(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration to scaffold this project with Beads epic, "
            "PM coordination, workerbee validation, and contractor lanes."
        )
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertFalse(result["route"]["external_contract_allowed"])
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["missing_questions"]))
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["interactive_questions"]))
        self.assertIn("external-contracting-until-explicit-opt-in", result["disabled_levers"])

    def test_external_terms_without_opt_in_ask_for_boundary(self) -> None:
        result = coach_orchestration_prompt("Claude security review for auth token handling and contractor packet boundaries.")
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertFalse(result["route"]["external_contract_allowed"])
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["missing_questions"]))
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["interactive_questions"]))
        self.assertIn("external-contracting-until-explicit-opt-in", result["disabled_levers"])

    def test_gemini_agy_critique_without_opt_in_asks_for_boundary(self) -> None:
        result = coach_orchestration_prompt(
            "Use Gemini via agy for a second opinion critique of the Codex architect design.",
            requested_roles=["architecture"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertFalse(result["route"]["external_contract_allowed"])
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["missing_questions"]))
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["interactive_questions"]))
        self.assertIn("external-contracting-until-explicit-opt-in", result["disabled_levers"])

    def test_external_opt_in_recommends_external_contract(self) -> None:
        result = coach_orchestration_prompt(
            "Claude security review for contractor packet redaction.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "external-contract")
        self.assertIn("contractor-only-bead", result["enabled_levers"])
        self.assertIn("contractor-only bead", result["paste_ready_prompt"])

    def test_gemini_agy_critique_opt_in_recommends_external_contract(self) -> None:
        result = coach_orchestration_prompt(
            "Use Gemini via agy for a second opinion critique of the Codex architect design.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "external-contract")
        self.assertEqual(result["route"]["recommended_executor"], "gemini_architecture_critic")
        self.assertIn("contractor-only-bead", result["enabled_levers"])
        self.assertIn("contract-jd-architecture-reasoning", result["paste_ready_prompt"])

    def test_claude_and_gemini_architecture_critics_are_coached_as_parallel_contracts(self) -> None:
        result = coach_orchestration_prompt(
            "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
            "of the Codex architect design for a cross-cutting public contract architecture migration.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "external-contract")
        self.assertEqual(result["route"]["recommended_executor"], "claude_architecture_critic")
        self.assertIn("parallel-architecture-critic-contracts", result["enabled_levers"])
        self.assertIn("architecture-critic=claude_architecture_critic", result["enabled_levers"])
        self.assertIn("architecture-critic=gemini_architecture_critic", result["enabled_levers"])
        self.assertIn("claude-effort=xhigh", result["enabled_levers"])
        self.assertIn("one contractor-only/no-codex-exec Bead per selected architecture critic", result["paste_ready_prompt"])
        self.assertIn("claude --model claude-opus-4-6 --effort xhigh -p", result["paste_ready_prompt"])
        self.assertIn("agy --model gemini-3.1-pro-preview -p", result["paste_ready_prompt"])
        self.assertIn("Add ChatGPT Pro master review only after explicit opt-in", result["paste_ready_prompt"])

    def test_claude_and_gemini_2nd_opinions_wording_is_coached_as_parallel_contracts(self) -> None:
        result = coach_orchestration_prompt(
            "Have Claude Opus and Gemini provide 2nd opinions of the Codex architect design.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        self.assertIn("parallel-architecture-critic-contracts", result["enabled_levers"])
        self.assertIn("architecture-critic=claude_architecture_critic", result["enabled_levers"])
        self.assertIn("architecture-critic=gemini_architecture_critic", result["enabled_levers"])

    def test_chatgpt_pro_master_plan_without_opt_in_asks_for_boundary(self) -> None:
        result = coach_orchestration_prompt(
            "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer for the final execution plan and total work packet."
        )
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertFalse(result["route"]["external_contract_allowed"])
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["missing_questions"]))
        self.assertTrue(any(item["id"] == "outside_sharing_boundary" for item in result["interactive_questions"]))
        self.assertIn("external-contracting-until-explicit-opt-in", result["disabled_levers"])

    def test_chatgpt_pro_master_plan_opt_in_recommends_external_contract(self) -> None:
        result = coach_orchestration_prompt(
            "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer for the final execution plan and total work packet.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(result["recommended_orchestration_level"], "external-contract")
        self.assertEqual(result["route"]["recommended_executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertIn("contractor-only-bead", result["enabled_levers"])
        self.assertIn("chatgpt-pro-master-review-blocking-gate", result["enabled_levers"])
        self.assertIn("operator-waiver-required-for-chatgpt-pro-skip", result["enabled_levers"])
        self.assertTrue(result["route"]["blocking_review_active"])
        self.assertIn("contract-jd-master-plan-review", result["paste_ready_prompt"])
        self.assertIn("blocking gate before implementation", result["paste_ready_prompt"])
        self.assertIn("explicitly waive/downgrade it in Beads", result["paste_ready_prompt"])
        self.assertTrue(any("ChatGPT Pro 5.5 master review is blocking" in item for item in result["warnings"]))

    def test_chatgpt_pro_weigh_in_master_review_wording_is_coached(self) -> None:
        result = coach_orchestration_prompt(
            "Tap in ChatGPT Pro 5.5 to weigh in as a master review of the final architect plan.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(result["recommended_orchestration_level"], "external-contract")
        self.assertEqual(result["route"]["recommended_executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertIn("contract-jd-master-plan-review", result["paste_ready_prompt"])

    def test_explicit_model_synthesis_request_is_enabled(self) -> None:
        result = coach_orchestration_prompt(
            "Use model synthesis to combine Claude Opus, Gemini, and ChatGPT Pro findings "
            "into consensus, disagreements, and recommended plan revisions.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture", "master-plan-review"],
        )
        self.assertEqual(result["model_synthesis"]["recommended_mode"], "requested")
        self.assertTrue(result["model_synthesis"]["active"])
        self.assertFalse(result["model_synthesis"]["requires_user_acceptance"])
        self.assertFalse(result["model_synthesis"]["prompt_user_in_plan_mode"])
        self.assertEqual(result["route"]["model_synthesis"]["recommended_mode"], "requested")
        self.assertIn("model-synthesis=requested", result["enabled_levers"])
        self.assertIn("model-synthesis-lane", result["enabled_levers"])
        self.assertIn("CWO-native model synthesis", result["paste_ready_prompt"])
        self.assertIn("architect adjudication", " ".join(result["model_synthesis"]["rationale"]).lower())
        executors = [item["executor"] for item in result["model_synthesis"]["recommended_panel"]]
        self.assertIn("claude_architecture_critic", executors)
        self.assertIn("gemini_architecture_critic", executors)
        self.assertIn("chatgpt_pro_browser_master_reviewer", executors)
        self.assertFalse(any(item["id"] == "model_synthesis_opt_in" for item in result["missing_questions"]))

    def test_model_synthesis_flag_marks_coach_opt_in_accepted(self) -> None:
        result = coach_orchestration_prompt(
            "Refactor architecture policy and routing tests.",
            requested_roles=["architecture"],
            model_synthesis=True,
        )

        self.assertEqual(result["model_synthesis"]["recommended_mode"], "accepted")
        self.assertEqual(result["model_synthesis"]["activation_state"], "accepted")
        self.assertTrue(result["model_synthesis"]["active"])
        self.assertFalse(result["model_synthesis"]["requires_user_acceptance"])
        self.assertFalse(any(item["id"] == "model_synthesis_opt_in" for item in result["missing_questions"]))
        self.assertIn("model-synthesis=accepted", result["enabled_levers"])
        self.assertIn("model-synthesis-lane", result["enabled_levers"])

    def test_glm_primary_environment_is_visible_in_coach_output(self) -> None:
        result = coach_orchestration_prompt(
            "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.6 Sol counter-review.",
            requested_roles=["architecture"],
            execution_environment="connected-codex-glm-primary",
            model_synthesis=True,
        )

        self.assertEqual(result["route"]["execution_environment"], "connected-codex-glm-primary")
        self.assertIn("execution-environment=connected-codex-glm-primary", result["enabled_levers"])
        self.assertIn(
            "primary-architect=rhoai_glm_primary_architect",
            result["enabled_levers"],
        )
        self.assertIn("project-manager=codex_project_manager", result["enabled_levers"])
        self.assertIn("Primary architect: rhoai_glm_primary_architect", result["paste_ready_prompt"])
        self.assertEqual(
            result["model_synthesis"]["synthesis_owner"],
            "rhoai_glm_primary_architect",
        )

    def test_generic_weigh_in_does_not_coach_chatgpt_master_review(self) -> None:
        result = coach_orchestration_prompt(
            "Have someone weigh in on this plan.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertNotEqual(result["route"]["recommended_executor"], "chatgpt_pro_browser_master_reviewer")

    def test_local_worker_profile_recommends_local_worker(self) -> None:
        result = coach_orchestration_prompt(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "local-worker")
        self.assertEqual(result["route"]["recommended_executor"], "openshift_ai_vllm_worker")
        self.assertIn("local-profile=openshift-ai-vllm", result["enabled_levers"])

    def test_local_worker_terms_without_opt_in_do_not_dispatch(self) -> None:
        result = coach_orchestration_prompt(
            "Use local worker vLLM to review README examples.",
            requested_roles=["documentation"],
        )
        self.assertEqual(result["recommended_orchestration_level"], "in-thread")
        self.assertEqual(result["route"]["recommended_executor"], "internal_worker")
        self.assertFalse(result["route"]["local_worker_allowed"])
        self.assertTrue(any(item["id"] == "local_worker_opt_in" for item in result["missing_questions"]))
        self.assertTrue(any(item["id"] == "local_worker_opt_in" for item in result["interactive_questions"]))
        self.assertIn("local-worker-dispatch", result["disabled_levers"])

    def test_publish_work_requires_publish_grade_levers(self) -> None:
        result = coach_orchestration_prompt("Publish the skill to GitHub after release validation.")
        self.assertEqual(result["recommended_orchestration_level"], "publish-release")
        self.assertIn("publish-sanitization", result["enabled_levers"])
        self.assertIn("validation-lane", result["enabled_levers"])
        self.assertTrue(any(item["id"] == "repo_or_paths" for item in result["missing_questions"]))
        validation_questions = [
            item for item in result["interactive_questions"] if item["id"] == "validation_bar"
        ]
        self.assertEqual(len(validation_questions), 1)
        self.assertEqual(validation_questions[0]["options"][0]["value"], "publish-grade")

    def test_parallelizable_work_asks_for_workerbees(self) -> None:
        result = coach_orchestration_prompt(
            "Do a deep second pass on docs, GitHub Pages flow, routing policy, and tests."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertEqual(result["workerbee_parallelism"]["recommended_model"], "gpt-5.3-codex-spark")
        self.assertTrue(result["workerbee_parallelism"]["prompt_user_in_plan_mode"])
        self.assertIn("workerbee-parallelism=review-only", result["enabled_levers"])
        self.assertIn("workerbee-dispatch-route=native-spark", result["enabled_levers"])
        self.assertIn("codex-5.3-spark-workerbees-native-first", result["enabled_levers"])
        self.assertIn("Codex 5.3 Spark natively", result["paste_ready_prompt"])
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["header"], "Subagents")
        self.assertEqual(worker_questions[0]["options"][0]["value"], "review-subagents")
        self.assertIn("heavy-review-subagents", [option["value"] for option in worker_questions[0]["options"]])

    def test_workerbee_planned_delegation_is_recorded_on_prompt_result(self) -> None:
        result = coach_orchestration_prompt(
            "Heavily parallelize docs, terminology, web design, validation, and publish review lanes."
        )
        planned = result["workerbee_planned_delegation"]
        self.assertIsInstance(planned, dict)
        self.assertEqual(planned["mode"], "heavy-review")
        self.assertEqual(planned["model"], result["workerbee_parallelism"]["recommended_model"])
        self.assertEqual(planned["lanes"], result["workerbee_parallelism"]["suggested_lanes"])
        self.assertEqual(result["route"]["workerbee_planned_delegation"], planned)

    def test_explicit_workerbee_request_still_prompts_for_parallelism(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration to scaffold this project with PM coordination and workerbee validation."
        )
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertTrue(result["workerbee_parallelism"]["prompt_user_in_plan_mode"])
        self.assertIn("workerbee-parallelism=review-only", result["enabled_levers"])
        self.assertIn("workerbee-dispatch-route=native-spark", result["enabled_levers"])
        self.assertIn("codex-5.3-spark-workerbees-native-first", result["enabled_levers"])
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["options"][0]["value"], "review-subagents")

    def test_heavy_parallelization_recommends_heavy_review_subagents(self) -> None:
        result = coach_orchestration_prompt(
            "Heavily parallelize docs, terminology, web design, validation, and publish review lanes."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "heavy-review")
        self.assertIn("workerbee-parallelism=heavy-review", result["enabled_levers"])
        self.assertIn("heavy review parallelism", result["paste_ready_prompt"])
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["options"][0]["value"], "heavy-review-subagents")
        self.assertIn("review-subagents", [option["value"] for option in worker_questions[0]["options"]])
        self.assertIn("no-subagents", [option["value"] for option in worker_questions[0]["options"]])

    def test_implementation_subagent_request_recommends_split_implementation(self) -> None:
        result = coach_orchestration_prompt(
            "Spawn implementation-workerbees for disjoint files and keep main-thread integration."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "implementation-capable")
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["options"][0]["value"], "implementation-subagents")
        self.assertIn("heavy-review-subagents", [option["value"] for option in worker_questions[0]["options"]])
        self.assertIn("no-subagents", [option["value"] for option in worker_questions[0]["options"]])

    def test_spark_absence_rejection_and_mismatch_phrases_hard_stop(self) -> None:
        cases = [
            (
                "native unavailable",
                "Plan docs work, but native Spark is unavailable for workerbee dispatch.",
                "spark-native-capability-unavailable",
                "spark_native_unavailable",
                False,
            ),
            (
                "native tooling unavailable",
                "Plan docs work. Native Spark tooling is unavailable.",
                "spark-native-tool-absence",
                "spark_native_tool_absent",
                False,
            ),
            (
                "spawn tool missing",
                "Plan docs work. The native Spark spawn tool is missing.",
                "spark-native-tool-absence",
                "spark_native_tool_absent",
                False,
            ),
            (
                "registry omission",
                "Plan docs work. Spark is absent from the native worker registry.",
                "spark-native-tool-absence",
                "spark_native_tool_absent",
                False,
            ),
            (
                "model rejected",
                "Plan docs work. The native Spark model was rejected for this task.",
                "spark-native-model-rejection",
                "spark_native_model_rejected",
                False,
            ),
            (
                "override rejected",
                "Plan docs work. The gpt-5.3-codex-spark model override was rejected.",
                "spark-native-model-rejection",
                "spark_native_model_rejected",
                False,
            ),
            (
                "dispatch rejected",
                "Plan docs work. Native dispatch was rejected for Codex 5.3 Spark.",
                "spark-native-model-rejection",
                "spark_native_model_rejected",
                False,
            ),
            (
                "worker registry rejected spark",
                "Plan docs work. The native worker registry rejected Spark.",
                "spark-native-model-rejection",
                "spark_native_model_rejected",
                False,
            ),
            (
                "spark rejected by worker registry",
                "Plan docs work. Spark was rejected by the native worker registry.",
                "spark-native-model-rejection",
                "spark_native_model_rejected",
                False,
            ),
            (
                "registry tool mismatch",
                "There is a Spark registry/tool mismatch for this task.",
                "spark-registry-tool-mismatch",
                "registry_tool_mismatch",
                True,
            ),
            (
                "structured registry mismatch",
                "Native Spark evidence reports registry_tool_mismatch=true.",
                "spark-registry-tool-mismatch",
                "registry_tool_mismatch",
                True,
            ),
            (
                "registry and tool mismatch",
                "Native Spark has a registry and tool mismatch.",
                "spark-registry-tool-mismatch",
                "registry_tool_mismatch",
                True,
            ),
            (
                "reordered mismatch",
                "A mismatch exists between the Spark registry and native tool.",
                "spark-registry-tool-mismatch",
                "registry_tool_mismatch",
                True,
            ),
            (
                "registry does not match tool",
                "The Spark registry does not match the native tool.",
                "spark-registry-tool-mismatch",
                "registry_tool_mismatch",
                True,
            ),
            (
                "explicitly rejected model",
                "Native Spark model was explicitly rejected.",
                "spark-native-model-rejection",
                "spark_native_model_rejected",
                False,
            ),
            (
                "mismatch between registry and tool for spark",
                "There is a mismatch between the registry and tool for Spark.",
                "spark-registry-tool-mismatch",
                "registry_tool_mismatch",
                True,
            ),
        ]
        dispatch_fields = {
            "status",
            "requested_model",
            "requested_route",
            "failed_native_capability_check",
            "failed_native_capability_check_justification",
        }

        for name, prompt, failed_check, hard_stop_reason, expected_mismatch in cases:
            with self.subTest(name):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                planned = result["workerbee_planned_delegation"]
                spark_dispatch = workerbee["spark_dispatch"]

                self.assertEqual(workerbee["recommended_mode"], "blocked")
                self.assertIsNone(workerbee["recommended_model"])
                self.assertEqual(workerbee["suggested_lanes"], [])
                self.assertTrue(workerbee["hard_stop"])
                self.assertEqual(workerbee["hard_stop_reason"], hard_stop_reason)
                self.assertIs(workerbee["registry_tool_mismatch"], expected_mismatch)
                self.assertFalse(workerbee["spark_operational_worker"])
                self.assertEqual(set(spark_dispatch), dispatch_fields)
                self.assertEqual(spark_dispatch["status"], "hard-stop")
                self.assertEqual(spark_dispatch["requested_route"], "blocked")
                self.assertEqual(spark_dispatch["requested_model"], "gpt-5.3-codex-spark")
                self.assertEqual(spark_dispatch["failed_native_capability_check"], failed_check)
                self.assertEqual(planned["mode"], "blocked")
                self.assertIsNone(planned["model"])
                self.assertEqual(planned["lanes"], [])
                self.assertTrue(planned["hard_stop"])
                self.assertEqual(planned["hard_stop_reason"], hard_stop_reason)
                self.assertIs(planned["registry_tool_mismatch"], expected_mismatch)
                self.assertEqual(planned["spark_dispatch"], spark_dispatch)
                self.assertIn("workerbee-dispatch-route=hard-stop", result["enabled_levers"])
                self.assertIn("workerbee-dispatch-stopped", result["enabled_levers"])
                self.assertEqual(
                    "workerbee-blocked=registry_tool_mismatch" in result["enabled_levers"],
                    expected_mismatch,
                )
                self.assertEqual(
                    "workerbee-registry-tool-mismatch" in result["enabled_levers"],
                    expected_mismatch,
                )
                self.assertIn("subagent-parallelism-blocked", result["disabled_levers"])
                self.assertNotIn("codex-5.3-spark-workerbees-native-first", result["enabled_levers"])
                self.assertFalse(
                    any(
                        item["id"] == "workerbee_parallelism"
                        for item in result["missing_questions"]
                    )
                )
                self.assertFalse(
                    any(
                        item["id"] == "workerbee_parallelism"
                        for item in result["interactive_questions"]
                    )
                )
                emitted = json.dumps(result).lower()
                self.assertNotIn("bridge", emitted)
                self.assertNotIn("fallback", emitted)

    def test_unqualified_direct_spark_execution_subjects_hard_stop(self) -> None:
        cases = [
            ("Spark tooling is unavailable.", "spark_native_tool_absent"),
            ("Spark tool is unavailable.", "spark_native_tool_absent"),
            ("Spark capability is unavailable.", "spark_native_unavailable"),
            ("Spark dispatch is unavailable.", "spark_native_unavailable"),
            ("Spark route is unavailable.", "spark_native_unavailable"),
            ("Spark worker is unavailable.", "spark_native_unavailable"),
            ("Spark workerbee is unavailable.", "spark_native_unavailable"),
            ("Spark model is unavailable.", "spark_native_unavailable"),
            (
                "Use Spark workerbees for docs. Codex 5.3 Spark is unavailable.",
                "spark_native_unavailable",
            ),
            ("Codex 5.3 Spark isn't available.", "spark_native_unavailable"),
        ]

        for prompt, expected_reason in cases:
            with self.subTest(prompt):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                planned = result["workerbee_planned_delegation"]

                self.assertEqual(workerbee["recommended_mode"], "blocked")
                self.assertIsNone(workerbee["recommended_model"])
                self.assertEqual(workerbee["suggested_lanes"], [])
                self.assertTrue(workerbee["hard_stop"])
                self.assertEqual(workerbee["hard_stop_reason"], expected_reason)
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertEqual(workerbee["spark_dispatch"]["status"], "hard-stop")
                self.assertEqual(planned["mode"], "blocked")
                self.assertIsNone(planned["model"])
                self.assertEqual(planned["lanes"], [])
                self.assertTrue(planned["hard_stop"])
                self.assertEqual(planned["hard_stop_reason"], expected_reason)
                self.assertFalse(planned["registry_tool_mismatch"])
                self.assertEqual(planned["spark_dispatch"]["status"], "hard-stop")

    def test_provider_scoped_spark_failures_keep_native_route_eligible(self) -> None:
        prompts = [
            "Plan docs work. Codex 5.3 Spark may not be available in ChatGPT Pro.",
            "Plan docs work. Spark is unavailable to ChatGPT Pro.",
            "Plan docs work. Spark tooling is unavailable in ChatGPT Pro.",
            "Plan docs work. ChatGPT Pro rejected the Spark model override.",
            "Plan docs work. Spark may not be available on the Pro plan.",
            "Plan docs work. Spark tooling is unavailable in the browser.",
            "Plan docs work. Spark tooling is unavailable through the OpenAI provider.",
        ]

        for prompt in prompts:
            with self.subTest(prompt):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                spark_dispatch = workerbee["spark_dispatch"]

                self.assertEqual(workerbee["recommended_mode"], "review-only")
                self.assertEqual(workerbee["recommended_model"], "gpt-5.3-codex-spark")
                self.assertFalse(workerbee["hard_stop"])
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertTrue(workerbee["suggested_lanes"])
                self.assertEqual(spark_dispatch["status"], "native-first")
                self.assertEqual(spark_dispatch["requested_route"], "review-only")
                self.assertIn("workerbee-dispatch-route=native-spark", result["enabled_levers"])
                self.assertIn("codex-5.3-spark-workerbees-native-first", result["enabled_levers"])
                emitted = json.dumps(result).lower()
                self.assertNotIn("bridge", emitted)
                self.assertNotIn("fallback", emitted)

    def test_provider_scoped_direct_spark_failures_are_non_blocking(self) -> None:
        prompts = [
            "Spark tooling is unavailable in ChatGPT Pro.",
            "Spark may not be available on the Pro plan.",
            "ChatGPT Pro rejected the Spark model override.",
            "Spark tooling is unavailable in the browser.",
            "Spark tooling is unavailable through the OpenAI provider.",
        ]

        for prompt in prompts:
            with self.subTest(prompt):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                planned = result["workerbee_planned_delegation"]

                self.assertEqual(workerbee["recommended_mode"], "review-only")
                self.assertEqual(workerbee["recommended_model"], "gpt-5.3-codex-spark")
                self.assertFalse(workerbee["hard_stop"])
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertTrue(workerbee["suggested_lanes"])
                self.assertEqual(workerbee["spark_dispatch"]["status"], "native-first")
                self.assertEqual(planned["mode"], "review-only")
                self.assertEqual(planned["model"], "gpt-5.3-codex-spark")
                self.assertFalse(planned["hard_stop"])
                self.assertFalse(planned["registry_tool_mismatch"])
                self.assertTrue(planned["lanes"])
                self.assertEqual(planned["spark_dispatch"]["status"], "native-first")

    def test_explicit_native_scoping_overrides_provider_scope(self) -> None:
        prompts = [
            "ChatGPT Pro is available, but native Spark tooling is unavailable.",
            "ChatGPT Pro is available, but native Spark dispatch was rejected.",
            "Spark tooling is unavailable in the browser, but local Spark tooling is unavailable.",
            "Spark tooling is unavailable through the OpenAI provider, but the local Spark tool surface is unavailable.",
            "Spark tooling is unavailable in the browser, but the Spark tool surface is unavailable.",
        ]
        expected_hard_stop_reasons = {
            prompts[0]: "spark_native_tool_absent",
            prompts[1]: "spark_native_model_rejected",
            prompts[2]: "spark_native_tool_absent",
            prompts[3]: "spark_native_tool_absent",
            prompts[4]: "spark_native_tool_absent",
        }
        for prompt in prompts:
            with self.subTest(prompt):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                planned = result["workerbee_planned_delegation"]
                spark_dispatch = workerbee["spark_dispatch"]
                self.assertEqual(workerbee["recommended_mode"], "blocked")
                self.assertIsNone(workerbee["recommended_model"])
                self.assertTrue(workerbee["hard_stop"])
                self.assertEqual(workerbee["hard_stop_reason"], expected_hard_stop_reasons[prompt])
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertFalse(workerbee["spark_operational_worker"])
                self.assertEqual(spark_dispatch["status"], "hard-stop")
                self.assertEqual(planned["mode"], "blocked")
                self.assertIsNone(planned["model"])
                self.assertTrue(planned["hard_stop"])
                self.assertEqual(planned["hard_stop_reason"], expected_hard_stop_reasons[prompt])
                self.assertEqual(planned["spark_dispatch"]["status"], "hard-stop")

    def test_same_clause_unrelated_rejection_and_mismatch_do_not_bind_to_spark(self) -> None:
        prompts = [
            "Use Spark workerbee to review why the Figma model was rejected",
            "Use Spark workerbees despite a Figma registry/tool mismatch",
        ]

        for prompt in prompts:
            with self.subTest(prompt):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                planned = result["workerbee_planned_delegation"]

                self.assertNotEqual(workerbee["recommended_mode"], "blocked")
                self.assertFalse(workerbee["hard_stop"])
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertNotEqual(workerbee["spark_dispatch"]["status"], "hard-stop")
                self.assertNotEqual(planned["mode"], "blocked")
                self.assertFalse(planned["hard_stop"])
                self.assertFalse(planned["registry_tool_mismatch"])
                self.assertNotEqual(planned["spark_dispatch"]["status"], "hard-stop")

    def test_failure_predicates_bind_to_their_spark_subjects(self) -> None:
        non_blocking = [
            "Spark tooling is unavailable in the browser, but native Spark tooling is available.",
            "Use Spark tooling to diagnose why Figma tooling is unavailable.",
            "Use Spark tooling to diagnose why the Figma model was explicitly rejected.",
            "Use Spark tooling despite a mismatch between the registry and tool for Figma.",
        ]
        blocking = [
            "Spark tooling is available in the browser, but native Spark tooling is unavailable.",
            "Use Spark tooling to diagnose why Spark tooling is unavailable.",
            "Native Spark model was explicitly rejected.",
            "There is a mismatch between the registry and tool for Spark.",
        ]

        for prompt in non_blocking:
            with self.subTest(prompt=prompt, expected="native-first"):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                self.assertEqual(workerbee["recommended_mode"], "review-only")
                self.assertFalse(workerbee["hard_stop"])
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertEqual(workerbee["spark_dispatch"]["status"], "native-first")

        for prompt in blocking:
            with self.subTest(prompt=prompt, expected="hard-stop"):
                result = coach_orchestration_prompt(prompt)
                workerbee = result["workerbee_parallelism"]
                self.assertEqual(workerbee["recommended_mode"], "blocked")
                self.assertTrue(workerbee["hard_stop"])
                self.assertEqual(workerbee["spark_dispatch"]["status"], "hard-stop")

    def test_bare_spark_availability_failure_requires_direct_unscoped_predicate(self) -> None:
        blocked = coach_orchestration_prompt("Spark isn't available.")["workerbee_parallelism"]
        self.assertEqual(blocked["recommended_mode"], "blocked")
        self.assertTrue(blocked["hard_stop"])
        self.assertFalse(blocked["registry_tool_mismatch"])
        self.assertEqual(blocked["spark_dispatch"]["status"], "hard-stop")

        non_blocking = [
            "Spark isn't available in the browser.",
            "Spark isn't available through the OpenAI provider.",
            "Spark is available.",
            "Use Spark to diagnose why Figma isn't available.",
        ]
        for prompt in non_blocking:
            with self.subTest(prompt):
                workerbee = coach_orchestration_prompt(prompt)["workerbee_parallelism"]
                self.assertNotEqual(workerbee["recommended_mode"], "blocked")
                self.assertFalse(workerbee["hard_stop"])
                self.assertFalse(workerbee["registry_tool_mismatch"])
                self.assertNotEqual(workerbee["spark_dispatch"]["status"], "hard-stop")

    def test_unrelated_tool_failure_does_not_block_spark(self) -> None:
        result = coach_orchestration_prompt(
            "Use Spark workerbees. The Figma tool is missing."
        )
        workerbee = result["workerbee_parallelism"]

        self.assertNotEqual(workerbee["recommended_mode"], "blocked")
        self.assertFalse(workerbee["hard_stop"])
        self.assertFalse(workerbee["registry_tool_mismatch"])
        self.assertNotEqual(workerbee["spark_dispatch"]["status"], "hard-stop")

    def test_unrelated_provider_tool_failure_does_not_block_native_route(self) -> None:
        result = coach_orchestration_prompt(
            "Use Spark workerbees. ChatGPT Pro tooling is unavailable, but this task is unrelated to non-native tooling."
        )
        workerbee = result["workerbee_parallelism"]

        self.assertNotEqual(workerbee["recommended_mode"], "blocked")
        self.assertFalse(workerbee["hard_stop"])
        self.assertFalse(workerbee["registry_tool_mismatch"])
        self.assertNotEqual(workerbee["spark_dispatch"]["status"], "hard-stop")

    def test_registry_tool_mismatch_hard_stops_execution(self) -> None:
        result = coach_orchestration_prompt(
            "There is a Spark registry/tool mismatch for this task; execution must stop until this is fixed."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "blocked")
        self.assertIsNone(result["workerbee_parallelism"]["recommended_model"])
        self.assertTrue(result["workerbee_parallelism"]["registry_tool_mismatch"])
        self.assertTrue(result["workerbee_parallelism"]["hard_stop"])
        self.assertEqual(result["workerbee_parallelism"]["hard_stop_reason"], "registry_tool_mismatch")
        self.assertEqual(
            result["workerbee_parallelism"]["spark_dispatch"]["failed_native_capability_check"],
            "spark-registry-tool-mismatch",
        )
        self.assertEqual(result["workerbee_parallelism"]["spark_dispatch"].get("status"), "hard-stop")
        self.assertIn("workerbee-dispatch-stopped", result["enabled_levers"])
        self.assertIn("workerbee-blocked=registry_tool_mismatch", result["enabled_levers"])
        self.assertFalse(
            any(
                item["id"] == "workerbee_parallelism"
                for item in result["interactive_questions"]
            )
        )
        self.assertIn("subagent-parallelism-blocked", result["disabled_levers"])
        self.assertTrue(
            any(
                "spark registry/tool mismatch is a hard stop" in str(warning).lower()
                for warning in result["warnings"]
            )
        )

    def test_spark_operational_pairing_uses_canonical_lanes(self) -> None:
        result = coach_orchestration_prompt(
            "Use Codex 5.6 Sol as architect and Codex 5.3 Spark as implementation worker for docs, validation, and report."
        )
        self.assertEqual(
            set(result["workerbee_parallelism"]["suggested_lanes"]),
            {"implementation", "docs", "validation", "wrap-up-report", "dashboard-report"},
        )
        self.assertNotIn("test-construction", result["workerbee_parallelism"]["suggested_lanes"])
        self.assertNotIn("validation-troubleshooting", result["workerbee_parallelism"]["suggested_lanes"])
        self.assertNotIn("docs-reporting-dashboard", result["workerbee_parallelism"]["suggested_lanes"])

    def test_conditional_workerbee_language_still_prompts_for_parallelism(self) -> None:
        result = coach_orchestration_prompt(
            "Plan docs and validation work. Use review-only workerbee lanes if selected by the coach."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertTrue(result["workerbee_parallelism"]["prompt_user_in_plan_mode"])
        self.assertTrue(any(item["id"] == "workerbee_parallelism" for item in result["interactive_questions"]))

    def test_spark_operational_pairing_selects_implementation_capable_mode(self) -> None:
        result = coach_orchestration_prompt(
            "Native Spark is available. Use Codex 5.6 Sol as architect and Codex 5.3 Spark as implementation worker for docs, validation, and reporting."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "implementation-capable")
        self.assertEqual(result["workerbee_parallelism"]["recommended_model"], "gpt-5.3-codex-spark")
        self.assertTrue(result["workerbee_parallelism"]["spark_operational_worker"])
        self.assertFalse(result["workerbee_parallelism"]["registry_tool_mismatch"])
        spark_dispatch = result["workerbee_parallelism"]["spark_dispatch"]
        self.assertEqual(spark_dispatch.get("status"), "native-first")
        self.assertEqual(spark_dispatch.get("requested_route"), "implementation-capable")
        self.assertEqual(spark_dispatch.get("requested_model"), "gpt-5.3-codex-spark")
        self.assertEqual(
            set(spark_dispatch),
            {
                "status",
                "requested_model",
                "requested_route",
                "failed_native_capability_check",
                "failed_native_capability_check_justification",
            },
        )
        self.assertEqual(spark_dispatch.get("failed_native_capability_check"), "")
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["options"][0]["value"], "implementation-subagents")
        self.assertIn(
            "Native Spark dispatch is the preferred route.",
            result["paste_ready_prompt"],
        )
        emitted = json.dumps(result).lower()
        self.assertNotIn("bridge", emitted)
        self.assertNotIn("fallback", emitted)

    def test_prompt_coach_schema_defines_spark_hard_stop_contract(self) -> None:
        schema = json.loads((ROOT / "schemas" / "prompt-coach-result.schema.json").read_text())
        blocked_result = coach_orchestration_prompt(
            "Plan docs work. Native Spark tooling is unavailable."
        )
        workerbee_schema = schema["properties"]["workerbee_parallelism"]
        planned_schema = schema["properties"]["workerbee_planned_delegation"]
        dispatch_schema = schema["$defs"]["sparkDispatch"]
        hard_stop_fields = {
            "spark_operational_worker",
            "hard_stop",
            "hard_stop_reason",
            "registry_tool_mismatch",
            "spark_dispatch",
        }

        self.assertIn("blocked", workerbee_schema["properties"]["recommended_mode"]["enum"])
        self.assertIn("blocked", planned_schema["properties"]["mode"]["enum"])
        self.assertTrue(hard_stop_fields.issubset(workerbee_schema["required"]))
        self.assertTrue(hard_stop_fields.issubset(planned_schema["required"]))
        self.assertEqual(
            set(dispatch_schema["required"]),
            {
                "status",
                "requested_model",
                "requested_route",
                "failed_native_capability_check",
                "failed_native_capability_check_justification",
            },
        )
        self.assertFalse(dispatch_schema["additionalProperties"])
        self.assertIn("hard-stop", dispatch_schema["properties"]["status"]["enum"])
        self.assertFalse(blocked_result["workerbee_parallelism"]["registry_tool_mismatch"])
        self.assertFalse(blocked_result["workerbee_planned_delegation"]["registry_tool_mismatch"])
        validate_schema_instance(blocked_result, schema)

        for conditional_schema in (workerbee_schema, planned_schema):
            for conditional in conditional_schema["allOf"]:
                properties = conditional.get("then", {}).get("properties", {})
                if "registry_tool_mismatch" in properties:
                    self.assertEqual(properties["registry_tool_mismatch"], {"type": "boolean"})

        mismatch_result = coach_orchestration_prompt(
            "There is a Spark registry/tool mismatch for this task."
        )
        self.assertTrue(mismatch_result["workerbee_parallelism"]["registry_tool_mismatch"])
        self.assertTrue(mismatch_result["workerbee_planned_delegation"]["registry_tool_mismatch"])
        for result in (blocked_result, mismatch_result):
            validate_schema_instance(result, schema)
            self.assertFalse(
                any(
                    question["id"] == "workerbee_parallelism"
                    for question in result["interactive_questions"]
                )
            )

        stable_result = coach_orchestration_prompt("Fix typo in README.md")
        for schema_target, object_name in (
            (workerbee_schema, "workerbee_parallelism"),
            (planned_schema, "workerbee_planned_delegation"),
        ):
            object_result = json.loads(json.dumps(stable_result[object_name]))
            registry_inconsistent = json.loads(json.dumps(object_result))
            registry_inconsistent["registry_tool_mismatch"] = True
            registry_inconsistent["hard_stop"] = False
            with self.assertRaises(SchemaValidationError):
                validate_schema_instance(registry_inconsistent, schema_target)

            dispatch_status_inconsistent = json.loads(json.dumps(object_result))
            dispatch_status_inconsistent["spark_dispatch"]["status"] = "hard-stop"
            dispatch_status_inconsistent["hard_stop"] = False
            with self.assertRaises(SchemaValidationError):
                validate_schema_instance(dispatch_status_inconsistent, schema_target)

    def test_workerbee_parallel_mode_precedence_matrix(self) -> None:
        cases = [
            {
                "name": "hard-stop plus spark pairing",
                "prompt": "There is a Spark registry/tool mismatch for this task. Use Codex 5.6 Sol as architect and Codex 5.3 Spark as implementation worker for docs and reporting.",
                "expected_mode": "blocked",
                "expected_model": None,
                "expected_lanes": [],
                "expected_spark_worker": False,
                "expected_hard_stop": True,
                "expected_registry_tool_mismatch": True,
            },
            {
                "name": "review-only plus spark wording",
                "prompt": "Use review-only workerbees to inspect docs and run a second pass on GitHub Pages tests. Use Codex 5.6 Sol as architect and Codex 5.3 Spark as implementation worker.",
                "expected_mode": "review-only",
                "expected_model": "gpt-5.3-codex-spark",
                "expected_lanes": ["docs-flow-review", "terminology-review", "web-design-review", "test-gap-review"],
                "expected_spark_worker": False,
                "expected_hard_stop": False,
                "expected_registry_tool_mismatch": False,
            },
            {
                "name": "heavy review preserves heavy-review precedence over impl hints",
                "prompt": "Heavily parallelize docs, tests, and implementation workerbees for fixups in multiple files.",
                "expected_mode": "heavy-review",
                "expected_model": "gpt-5.3-codex-spark",
                "expected_lanes": ["docs-flow-review", "terminology-review", "web-design-review", "test-gap-review"],
                "expected_spark_worker": False,
                "expected_hard_stop": False,
                "expected_registry_tool_mismatch": False,
            },
            {
                "name": "implementation plus review wording keeps implementation-capable",
                "prompt": "Spawn implementation workerbees for disjoint files and run a second pass on routing and policy docs.",
                "expected_mode": "implementation-capable",
                "expected_model": "gpt-5.3-codex-spark",
                "expected_lanes": ["docs-flow-review", "terminology-review", "web-design-review", "policy-routing-review"],
                "expected_spark_worker": False,
                "expected_hard_stop": False,
                "expected_registry_tool_mismatch": False,
            },
        ]

        for case in cases:
            with self.subTest(case["name"]):
                result = coach_orchestration_prompt(case["prompt"])
                workerbee = result["workerbee_parallelism"]
                self.assertEqual(workerbee["recommended_mode"], case["expected_mode"], case["name"])
                self.assertEqual(workerbee["recommended_model"], case["expected_model"], case["name"])
                self.assertEqual(workerbee["spark_operational_worker"], case["expected_spark_worker"], case["name"])
                self.assertEqual(workerbee["hard_stop"], case["expected_hard_stop"], case["name"])
                self.assertEqual(
                    workerbee["registry_tool_mismatch"],
                    case["expected_registry_tool_mismatch"],
                    case["name"],
                )
                self.assertEqual(workerbee["suggested_lanes"], case["expected_lanes"], case["name"])

    def test_review_only_term_keeps_review_only_workerbee_mode(self) -> None:
        result = coach_orchestration_prompt(
            "Use review-only workerbees to inspect docs and run a second pass on GitHub Pages tests."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertEqual(result["workerbee_parallelism"]["recommended_model"], "gpt-5.3-codex-spark")
        self.assertFalse(result["workerbee_parallelism"]["spark_operational_worker"])
        worker_questions = [item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"]
        self.assertEqual(worker_questions[0]["options"][0]["value"], "review-subagents")

    def test_public_docs_editor_task_requires_editor_gate_in_coach(self) -> None:
        result = coach_orchestration_prompt(
            "Fix public-docs editor oversharing on the homepage and improve the Beads install section."
        )
        self.assertTrue(result["route"]["editor_gate_required"])
        self.assertIn("editor", result["route"]["editor_gate_experts"])

    def test_narrow_work_still_prompts_for_subagent_parallelism(self) -> None:
        result = coach_orchestration_prompt("Fix typo in README.md")
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "none")
        self.assertIsNone(result["workerbee_parallelism"]["recommended_model"])
        self.assertEqual(result["workerbee_parallelism"]["suggested_lanes"], [])
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["options"][0]["value"], "no-subagents")
        self.assertIn("review-subagents", [option["value"] for option in worker_questions[0]["options"]])

    def test_cli_json_output_contains_prompt_and_route(self) -> None:
        output = subprocess.check_output(
            [
                sys.executable,
                str(ROOT / "scripts" / "coach_prompt.py"),
                "--json",
                "Fix typo in README.md",
            ],
            text=True,
            cwd=ROOT,
        )
        result = json.loads(output)
        self.assertEqual(result["coach_result_type"], "complex-work-orchestration-prompt-coach")
        self.assertEqual(result["version"], 8)
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn("paste_ready_prompt", result)
        self.assertIn("interactive_questions", result)
        self.assertIn("requires_user_selection_before_plan", result)
        self.assertIn("selection_before_plan_reason", result)
        self.assertIn("selection_before_plan_question_ids", result)
        self.assertIn("workerbee_parallelism", result)
        self.assertIn("workerbee_planned_delegation", result)
        self.assertIn("model_synthesis", result)
        self.assertIn("operator_calibration", result)
        self.assertIn("route", result)
        self.assertIn("beads_context_depth", result)
        self.assertIn("beads_context_depth_provenance", result)

    def test_cwo_entrypoint_runs_coach_brief(self) -> None:
        output = subprocess.check_output(
            [
                sys.executable,
                str(ROOT / "scripts" / "cwo.py"),
                "coach",
                "--brief",
                "Fix typo in README.md",
            ],
            text=True,
            cwd=ROOT,
        )
        self.assertIn("Recommended orchestration:", output)
        self.assertIn("Route:", output)
        self.assertIn("Execution gate:", output)
        self.assertIn("Coach options:", output)
        self.assertNotIn("Recommended launch prompt:", output)

    def test_explicit_coach_request_requires_selection_before_plan(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration coach to determine the best path forward for docs and validation."
        )

        self.assertTrue(result["requires_user_selection_before_plan"])
        self.assertIn("explicitly asked for the CWO coach", result["selection_before_plan_reason"])
        self.assertIn("workerbee_parallelism", result["selection_before_plan_question_ids"])
        self.assertIn("beads_context_depth", result["selection_before_plan_question_ids"])

    def test_execution_request_clears_selection_before_plan_gate(self) -> None:
        result = coach_orchestration_prompt(
            "Implement the CWO coach UX guardrail plan after using the CWO coach."
        )

        self.assertFalse(result["requires_user_selection_before_plan"])
        self.assertIn("already requested execution", result["selection_before_plan_reason"])

    def test_cli_model_synthesis_flag_outputs_accepted_state(self) -> None:
        output = subprocess.check_output(
            [
                sys.executable,
                str(ROOT / "scripts" / "coach_prompt.py"),
                "--json",
                "--model-synthesis",
                "--requested-role",
                "architecture",
                "Refactor architecture policy and routing tests.",
            ],
            text=True,
            cwd=ROOT,
        )
        result = json.loads(output)
        self.assertEqual(result["model_synthesis"]["recommended_mode"], "accepted")
        self.assertTrue(result["model_synthesis"]["active"])
        self.assertIn("model-synthesis=accepted", result["enabled_levers"])

    def test_in_thread_interactive_option_keeps_beads(self) -> None:
        result = coach_orchestration_prompt("Fix")
        questions = result["interactive_questions"]
        self.assertTrue(any(question["id"] == "orchestration_level" for question in questions))
        options = [option for question in questions for option in question["options"]]
        in_thread = next(option for option in options if option["value"] == "in-thread")
        self.assertIn("Beads", in_thread["label"])
        self.assertIn("Beads task", in_thread["description"])

    def test_interactive_questions_are_plan_mode_sized(self) -> None:
        result = coach_orchestration_prompt(
            "Claude security review for production release readiness.",
            requested_roles=["security"],
        )
        questions = result["interactive_questions"]
        self.assertTrue(questions)
        for question in questions:
            self.assertLessEqual(len(question["header"]), 12)
            self.assertGreaterEqual(len(question["options"]), 2)
            self.assertLessEqual(len(question["options"]), 4)
            self.assertIn("(Recommended)", question["options"][0]["label"])
            values = [option["value"] for option in question["options"]]
            self.assertEqual(len(values), len(set(values)))

    def test_outside_sharing_boundary_has_patch_branch_option(self) -> None:
        result = coach_orchestration_prompt(
            "Claude security review for production release readiness.",
            requested_roles=["security"],
        )
        sharing_question = next(
            q for q in result["interactive_questions"] if q["id"] == "outside_sharing_boundary"
        )
        option_values = [opt["value"] for opt in sharing_question["options"]]
        self.assertEqual(len(option_values), 4)
        self.assertIn("patch-branch", option_values)
        self.assertEqual(
            set(option_values),
            {"no-outside-sharing", "redacted-packet", "repo-readonly", "patch-branch"},
        )

    def test_publish_validation_dedupes_interactive_options(self) -> None:
        result = coach_orchestration_prompt("Publish the skill to GitHub after release validation.")
        validation_questions = [
            item for item in result["interactive_questions"] if item["id"] == "validation_bar"
        ]
        self.assertEqual(len(validation_questions), 1)
        values = [option["value"] for option in validation_questions[0]["options"]]
        self.assertEqual(values.count("publish-grade"), 1)


if __name__ == "__main__":
    unittest.main()
