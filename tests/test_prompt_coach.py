from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402


class PromptCoachTests(unittest.TestCase):
    def test_narrow_work_recommends_in_thread(self) -> None:
        result = coach_orchestration_prompt("Fix typo in README.md")
        self.assertEqual(result["recommended_orchestration_level"], "in-thread")
        self.assertEqual(result["model_synthesis"]["recommended_mode"], "none")
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn("mandatory Beads tracking", result["paste_ready_prompt"])
        self.assertIn("beads-durable-state", result["enabled_levers"])
        self.assertIn("beads-minimum-tracking", result["enabled_levers"])
        self.assertIn("full-harness", result["disabled_levers"])
        self.assertIn("model-synthesis-unselected", result["disabled_levers"])
        self.assertNotIn("beads-work-graph", result["disabled_levers"])

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
        self.assertTrue(result["model_synthesis"]["prompt_user_in_plan_mode"])
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
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn("architect-review", result["enabled_levers"])
        self.assertIn("validation-lane", result["enabled_levers"])
        self.assertIn("full architect/PM/subagent/validation harness", result["paste_ready_prompt"])
        harness_questions = [
            item for item in result["interactive_questions"] if item["id"] == "orchestration_level"
        ]
        self.assertEqual(len(harness_questions), 1)
        self.assertEqual(harness_questions[0]["options"][0]["value"], "full-harness")

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
        self.assertEqual(result["route"]["recommended_executor"], "gemini_3_1_pro_preview_agy")
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
        self.assertEqual(result["route"]["recommended_executor"], "claude_opus_4_6_architecture_critic")
        self.assertIn("parallel-architecture-critic-contracts", result["enabled_levers"])
        self.assertIn("architecture-critic=claude_opus_4_6_architecture_critic", result["enabled_levers"])
        self.assertIn("architecture-critic=gemini_3_1_pro_preview_agy", result["enabled_levers"])
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
        self.assertIn("architecture-critic=claude_opus_4_6_architecture_critic", result["enabled_levers"])
        self.assertIn("architecture-critic=gemini_3_1_pro_preview_agy", result["enabled_levers"])

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
        self.assertEqual(result["route"]["recommended_executor"], "chatgpt_pro_5_5_extended_reasoning_browser")
        self.assertIn("contractor-only-bead", result["enabled_levers"])
        self.assertIn("contract-jd-master-plan-review", result["paste_ready_prompt"])

    def test_chatgpt_pro_weigh_in_master_review_wording_is_coached(self) -> None:
        result = coach_orchestration_prompt(
            "Tap in ChatGPT Pro 5.5 to weigh in as a master review of the final architect plan.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(result["recommended_orchestration_level"], "external-contract")
        self.assertEqual(result["route"]["recommended_executor"], "chatgpt_pro_5_5_extended_reasoning_browser")
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
        self.assertFalse(result["model_synthesis"]["prompt_user_in_plan_mode"])
        self.assertIn("model-synthesis=requested", result["enabled_levers"])
        self.assertIn("model-synthesis-lane", result["enabled_levers"])
        self.assertIn("CWO-native model synthesis", result["paste_ready_prompt"])
        self.assertIn("architect adjudication", " ".join(result["model_synthesis"]["rationale"]).lower())
        executors = [item["executor"] for item in result["model_synthesis"]["recommended_panel"]]
        self.assertIn("claude_opus_4_6_architecture_critic", executors)
        self.assertIn("gemini_3_1_pro_preview_agy", executors)
        self.assertIn("chatgpt_pro_5_5_extended_reasoning_browser", executors)
        self.assertFalse(any(item["id"] == "model_synthesis_opt_in" for item in result["missing_questions"]))

    def test_generic_weigh_in_does_not_coach_chatgpt_master_review(self) -> None:
        result = coach_orchestration_prompt(
            "Have someone weigh in on this plan.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertNotEqual(result["route"]["recommended_executor"], "chatgpt_pro_5_5_extended_reasoning_browser")

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
        self.assertIn("codex-5.3-spark-workerbees-when-available", result["enabled_levers"])
        self.assertIn("Codex 5.3 Spark when available", result["paste_ready_prompt"])
        worker_questions = [
            item for item in result["interactive_questions"] if item["id"] == "workerbee_parallelism"
        ]
        self.assertEqual(len(worker_questions), 1)
        self.assertEqual(worker_questions[0]["header"], "Subagents")
        self.assertEqual(worker_questions[0]["options"][0]["value"], "review-subagents")
        self.assertIn("heavy-review-subagents", [option["value"] for option in worker_questions[0]["options"]])

    def test_explicit_workerbee_request_still_prompts_for_parallelism(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration to scaffold this project with PM coordination and workerbee validation."
        )
        self.assertEqual(result["recommended_orchestration_level"], "full-harness")
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertTrue(result["workerbee_parallelism"]["prompt_user_in_plan_mode"])
        self.assertIn("workerbee-parallelism=review-only", result["enabled_levers"])
        self.assertIn("codex-5.3-spark-workerbees-when-available", result["enabled_levers"])
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

    def test_unavailable_spark_mention_still_prompts_for_workerbee_parallelism(self) -> None:
        result = coach_orchestration_prompt(
            "Plan a docs and GitHub Pages correction. Codex 5.3 Spark may not be available in ChatGPT Pro."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertEqual(
            result["workerbee_parallelism"]["recommended_model"],
            "smallest-available-capable-review-workerbee",
        )
        self.assertTrue(result["workerbee_parallelism"]["prompt_user_in_plan_mode"])
        self.assertIn("workerbee-model-fallback-required", result["enabled_levers"])
        self.assertIn("smallest available capable review subagent", result["paste_ready_prompt"])
        self.assertTrue(any(item["id"] == "workerbee_parallelism" for item in result["interactive_questions"]))

    def test_conditional_workerbee_language_still_prompts_for_parallelism(self) -> None:
        result = coach_orchestration_prompt(
            "Plan docs and validation work. Use review-only workerbee lanes if selected by the coach."
        )
        self.assertEqual(result["workerbee_parallelism"]["recommended_mode"], "review-only")
        self.assertTrue(result["workerbee_parallelism"]["prompt_user_in_plan_mode"])
        self.assertTrue(any(item["id"] == "workerbee_parallelism" for item in result["interactive_questions"]))

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
        self.assertEqual(result["version"], 4)
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn("paste_ready_prompt", result)
        self.assertIn("interactive_questions", result)
        self.assertIn("workerbee_parallelism", result)
        self.assertIn("model_synthesis", result)
        self.assertIn("route", result)

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
        self.assertIn("patch-branch", option_values)

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
