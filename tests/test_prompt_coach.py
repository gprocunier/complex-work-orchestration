from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402

RETIRED_FIELD = "beads_" + "briefing_depth"
RETIRED_FLAG = "--beads-" + "briefing-depth"


class PromptCoachTests(unittest.TestCase):
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
            "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.5 x-high synthesis.",
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
        self.assertEqual(result["version"], 7)
        self.assertTrue(result["beads_tracking_required"])
        self.assertIn("paste_ready_prompt", result)
        self.assertIn("interactive_questions", result)
        self.assertIn("workerbee_parallelism", result)
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
        self.assertNotIn("Recommended launch prompt:", output)

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
