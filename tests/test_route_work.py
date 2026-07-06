from __future__ import annotations

import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from route_work import print_human  # noqa: E402

RETIRED_FIELD = "beads_" + "briefing_depth"
RETIRED_FLAG = "--beads-" + "briefing-depth"


class RouteWorkTests(unittest.TestCase):
    def test_route_outputs_beads_context_depth_and_provenance(self) -> None:
        result = classify_work("Use subagents for a deep docs second pass with prior Beads comments.")

        self.assertEqual(result["beads_context_depth"], "heavy")
        self.assertNotIn(RETIRED_FIELD, result)
        self.assertEqual(result["beads_context_depth_source"], "autosized")
        self.assertEqual(result["beads_context_depth_provenance"]["computed_depth"], "heavy")
        self.assertEqual(result["beads_context_depth_provenance"]["effective_depth"], "heavy")

    def test_route_context_depth_override_records_requested_and_computed_depth(self) -> None:
        result = classify_work(
            "Use subagents for a deep docs second pass with prior Beads comments.",
            beads_context_depth="summary",
        )

        self.assertEqual(result["beads_context_depth"], "summary")
        self.assertNotIn(RETIRED_FIELD, result)
        self.assertEqual(result["beads_context_depth_source"], "explicit")
        self.assertEqual(result["beads_context_depth_provenance"]["requested_depth"], "summary")
        self.assertEqual(result["beads_context_depth_provenance"]["computed_depth"], "heavy")

    def test_route_context_depth_alias_flag_is_removed(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "route_work.py"),
                RETIRED_FLAG,
                "heavy",
                "Review Beads comments for docs.",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"unrecognized arguments: {RETIRED_FLAG}", result.stderr)

    def test_data_sensitivity_operator_declaration_overrides_heuristic(self) -> None:
        result = classify_work(
            "Publish public docs for the install flow.",
            data_sensitivity="restricted",
        )

        self.assertEqual(result["data_sensitivity"], "restricted")
        self.assertEqual(result["data_sensitivity_source"], "operator-declared")
        self.assertEqual(result["data_sensitivity_heuristic"], "public")
        self.assertEqual(result["data_sensitivity_provenance"]["declared_sensitivity"], "restricted")
        self.assertEqual(result["data_sensitivity_provenance"]["heuristic_sensitivity"], "public")
        self.assertEqual(result["data_sensitivity_provenance"]["effective_sensitivity"], "restricted")
        self.assertTrue(result["data_sensitivity_provenance"]["advisory_heuristic"])
        self.assertIn("can miss paraphrases", result["data_sensitivity_disclaimer"])

    def test_data_sensitivity_override_covers_heuristic_false_negative(self) -> None:
        result = classify_work(
            "Review tenant dossier retention for the workflow.",
            data_sensitivity="restricted",
        )

        self.assertEqual(result["data_sensitivity"], "restricted")
        self.assertEqual(result["data_sensitivity_heuristic"], "internal")
        self.assertEqual(result["data_sensitivity_source"], "operator-declared")

    def test_sensitivity_heuristic_catches_common_paraphrases(self) -> None:
        restricted = classify_work("Review customer records export and employee data cleanup.")
        redacted = classify_work("Review authentication flow and private repository boundaries.")

        self.assertEqual(restricted["data_sensitivity"], "restricted")
        self.assertEqual(restricted["data_sensitivity_source"], "heuristic")
        self.assertEqual(redacted["data_sensitivity"], "redacted")
        self.assertEqual(redacted["data_sensitivity_source"], "heuristic")

    def test_route_cli_accepts_data_sensitivity_declaration(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "route_work.py"),
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
        self.assertEqual(payload["data_sensitivity"], "restricted")
        self.assertEqual(payload["data_sensitivity_source"], "operator-declared")
        self.assertEqual(payload["data_sensitivity_heuristic"], "public")

    def test_security_and_web_design_triggers(self) -> None:
        result = classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertIn("security", names[:3])
        self.assertIn("web_design", names[:3])

    def test_work_rerouting_terms_require_sabotage_review_without_provider_conflict(self) -> None:
        result = classify_work(
            "Evaluate a contractor return for work_rerouting_or_subversion, objective dilution, and critical path deferral.",
            share_boundary="redacted-packet",
        )
        names = [expert["name"] for expert in result["ranked_experts"]]

        self.assertIn("sabotage_review", names[:3])
        self.assertTrue(result["sabotage_review_required"])
        self.assertTrue(result["peer_review_required"])
        self.assertFalse(result["provider_conflict_detected"])

    def test_ranked_experts_have_per_expert_executor_metadata(self) -> None:
        result = classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        )
        self.assertEqual(result["recommended_executor"], result["ranked_experts"][0]["recommended_executor"])
        for expert in result["ranked_experts"][:2]:
            self.assertIn("recommended_executor", expert)
            self.assertIn("selected_executor", expert)
            self.assertIn("executor_policy_violations", expert)

    def test_human_output_shows_per_expert_executor_and_controls(self) -> None:
        result = classify_work(
            "Security review redacted packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        output = StringIO()
        with redirect_stdout(output):
            print_human(result, 2)
        rendered = output.getvalue()
        self.assertIn("External contract allowed:", rendered)
        self.assertIn("Local worker allowed:", rendered)
        self.assertIn("Has external expert contracts:", rendered)
        self.assertIn("External experts:", rendered)
        self.assertIn("Acceptance required experts:", rendered)
        self.assertIn("Model synthesis:", rendered)
        self.assertIn("executor=", rendered)
        self.assertIn("violations=", rendered)

    def test_model_synthesis_flag_marks_route_opt_in_accepted(self) -> None:
        result = classify_work(
            "Refactor architecture policy and routing tests.",
            requested_roles=["architecture"],
            model_synthesis=True,
        )

        self.assertEqual(result["model_synthesis"]["recommended_mode"], "accepted")
        self.assertEqual(result["model_synthesis"]["activation_state"], "accepted")
        self.assertTrue(result["model_synthesis"]["active"])
        self.assertFalse(result["model_synthesis"]["requires_user_acceptance"])

    def test_glm_primary_environment_routes_architecture_to_glm_with_codex_counter_review(self) -> None:
        result = classify_work(
            "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.5 x-high synthesis.",
            requested_roles=["architecture"],
            execution_environment="connected-codex-glm-primary",
            model_synthesis=True,
        )

        self.assertEqual(result["execution_environment"], "connected-codex-glm-primary")
        self.assertEqual(result["architecture_authority"], "glm-5.2-primary-architect")
        self.assertEqual(result["project_manager_executor"], "codex_project_manager")
        self.assertEqual(result["recommended_executor"], "rhoai_glm_primary_architect")
        self.assertEqual(result["selected_executor"]["model_profile"], "rhoai-architect-glm-5-2-bf16-thinking")
        self.assertEqual(result["local_worker_opt_in_source"], "execution-environment")
        self.assertIn("codex_architecture_critic", result["requested_architecture_critic_executors"])
        self.assertEqual(
            result["model_synthesis"]["synthesis_owner"],
            "rhoai_glm_primary_architect",
        )
        panel = {item["executor"]: item for item in result["model_synthesis"]["recommended_panel"]}
        self.assertEqual(panel["codex_architecture_critic"]["role"], "architecture-counter-review")
        self.assertEqual(panel["rhoai_glm_primary_architect"]["role"], "primary-architect")

    def test_default_environment_keeps_codex_as_architect(self) -> None:
        result = classify_work(
            "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.5 x-high synthesis.",
            requested_roles=["architecture"],
            model_synthesis=True,
        )

        self.assertEqual(result["execution_environment"], "connected-codex")
        self.assertEqual(result["architecture_authority"], "codex-frontier-architect")
        self.assertNotEqual(result["recommended_executor"], "rhoai_glm_primary_architect")

    def test_cli_model_synthesis_flag_outputs_accepted_state(self) -> None:
        output = subprocess.check_output(
            [
                sys.executable,
                str(ROOT / "scripts" / "route_work.py"),
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

    def test_public_docs_pages_require_editor_gate(self) -> None:
        result = classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            file_paths=["docs/index.html", "README.md"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertTrue(result["editor_gate_required"])
        self.assertIn("documentation", names)
        self.assertIn("web_design", names)
        self.assertIn("editor", names)
        editor = next(expert for expert in result["ranked_experts"] if expert["name"] == "editor")
        self.assertTrue(editor["validation_gate_required"])
        self.assertEqual(editor["job_description_label"], "contract-jd-editorial-reasoning")

    def test_typo_class_readme_change_stays_low_risk_without_editor_gate(self) -> None:
        result = classify_work(
            "Fix a typo in the README.",
            file_paths=["README.md"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]

        self.assertEqual(result["risk_level"], "low")
        self.assertFalse(result["editor_gate_required"])
        self.assertNotIn("editor", names)

    def test_mixed_security_wording_change_is_not_demoted_to_low_risk(self) -> None:
        result = classify_work("fix wording in error messages and harden auth token validation")
        names = [expert["name"] for expert in result["ranked_experts"]]

        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(result["task_class"], "security-review")
        self.assertIn("security", names)

    def test_mixed_security_wording_change_with_code_path_is_not_demoted(self) -> None:
        result = classify_work(
            "fix wording in error messages and harden auth token validation",
            file_paths=["scripts/auth.py"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]

        self.assertEqual(result["risk_level"], "high")
        self.assertIn("security", names)

    def test_docs_only_wording_change_stays_low_risk_when_docs_scoped(self) -> None:
        result = classify_work(
            "Fix wording in docs/usage.md.",
            file_paths=["docs/usage.md"],
        )

        self.assertEqual(result["risk_level"], "low")
        self.assertIn(result["task_class"], {"docs-review", "general-review"})

    def test_publish_readme_change_still_requires_editor_gate(self) -> None:
        result = classify_work(
            "Publish README install docs for external operators.",
            file_paths=["README.md"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]

        self.assertTrue(result["editor_gate_required"])
        self.assertIn("editor", names)

    def test_substantive_readme_change_requires_editor_gate_by_path(self) -> None:
        result = classify_work(
            "Rewrite the README architecture overview and operator flow.",
            file_paths=["README.md"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]

        self.assertTrue(result["editor_gate_required"])
        self.assertIn("documentation", names)
        self.assertIn("editor", names)

    def test_patch_branch_gemini_contract_requires_disclosure_escalation(self) -> None:
        text = (
            "Contract Gemini 3.1 Pro for a public GitHub Pages web design refresh. "
            "Keep the internal editor gate with Codex."
        )
        blocked = classify_work(
            text,
            external_ok=True,
            share_boundary="patch-branch",
            requested_roles=["web-design"],
            file_paths=["docs/index.html", "docs/styles.css"],
        )
        self.assertNotEqual(blocked["route"], "external-contract")
        web_design = next(expert for expert in blocked["ranked_experts"] if expert["name"] == "web_design")
        gemini_candidate = next(
            item for item in web_design["executor_candidates"] if item["key"] == "gemini_manual_reviewer"
        )
        self.assertIn(
            "share boundary patch-branch requires disclosure escalation approval",
            gemini_candidate["policy_violations"],
        )

        allowed = classify_work(
            text,
            external_ok=True,
            allow_disclosure_escalation=True,
            share_boundary="patch-branch",
            requested_roles=["web-design"],
            file_paths=["docs/index.html", "docs/styles.css"],
        )
        self.assertEqual(allowed["route"], "external-contract")
        self.assertEqual(allowed["recommended_executor"], "gemini_manual_reviewer")
        self.assertIn("contract-jd-domain-web-design", allowed["guard_labels"])
        editor = next(expert for expert in allowed["ranked_experts"] if expert["name"] == "editor")
        self.assertFalse(editor["selected_executor"]["external"])
        self.assertEqual(editor["recommended_executor"], "frontier_architect")

    def test_gemini_agy_architect_critique_requires_external_opt_in(self) -> None:
        text = "Use Gemini via agy for a second opinion critique of the Codex architect design."
        blocked = classify_work(
            text,
            requested_roles=["architecture"],
            share_boundary="redacted-packet",
        )
        self.assertNotEqual(blocked["route"], "external-contract")
        candidate = next(
            item for item in blocked["ranked_executors"] if item["key"] == "gemini_architecture_critic"
        )
        self.assertIn("external dispatch requires user opt-in", candidate["policy_violations"])

        allowed = classify_work(
            text,
            requested_roles=["architecture"],
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(allowed["route"], "external-contract")
        self.assertEqual(allowed["recommended_executor"], "gemini_architecture_critic")
        self.assertEqual(allowed["guard_labels"], [
            "contractor-only",
            "no-codex-exec",
            "contract-jd-architecture-reasoning",
        ])
        self.assertEqual(allowed["external_experts"], ["architecture"])
        self.assertTrue(allowed["peer_review_required"])
        self.assertTrue(allowed["architect_adjudication_required"])

    def test_claude_opus_architect_critique_requires_external_opt_in(self) -> None:
        text = "Use Claude Opus 4.6 for a second opinion critique of the Codex architect design."
        blocked = classify_work(
            text,
            requested_roles=["architecture"],
            share_boundary="redacted-packet",
        )
        self.assertNotEqual(blocked["route"], "external-contract")
        candidate = next(
            item for item in blocked["ranked_executors"] if item["key"] == "claude_architecture_critic"
        )
        self.assertIn("external dispatch requires user opt-in", candidate["policy_violations"])

        allowed = classify_work(
            text,
            requested_roles=["architecture"],
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(allowed["route"], "external-contract")
        self.assertEqual(allowed["recommended_executor"], "claude_architecture_critic")
        self.assertEqual(allowed["requested_architecture_critic_executors"], ["claude_architecture_critic"])
        self.assertEqual(len(allowed["architecture_critic_contracts"]), 1)
        self.assertEqual(allowed["architecture_critic_contracts"][0]["manual_command"], "claude --model claude-opus-4-6 --effort high -p")
        self.assertEqual(allowed["architecture_critic_contracts"][0]["claude_effort"], "high")
        self.assertEqual(allowed["guard_labels"], [
            "contractor-only",
            "no-codex-exec",
            "contract-jd-architecture-reasoning",
        ])
        self.assertEqual(allowed["external_experts"], ["architecture"])
        self.assertTrue(allowed["peer_review_required"])
        self.assertTrue(allowed["architect_adjudication_required"])

    def test_dual_architecture_critics_are_preserved_as_independent_contracts(self) -> None:
        result = classify_work(
            "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
            "of the Codex architect design for a cross-cutting public contract architecture migration.",
            requested_roles=["architecture"],
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(result["recommended_executor"], "claude_architecture_critic")
        self.assertEqual(
            result["requested_architecture_critic_executors"],
            ["claude_architecture_critic", "gemini_architecture_critic"],
        )
        self.assertEqual(
            [contract["executor"] for contract in result["architecture_critic_contracts"]],
            ["claude_architecture_critic", "gemini_architecture_critic"],
        )
        self.assertEqual(result["architecture_review_complexity"], "high")
        self.assertEqual(result["claude_architecture_effort"], "xhigh")

    def test_dual_architecture_critics_accept_2nd_opinions_wording(self) -> None:
        result = classify_work(
            "Have Claude Opus and Gemini provide 2nd opinions of the architect design.",
            requested_roles=["architecture"],
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(
            result["requested_architecture_critic_executors"],
            ["claude_architecture_critic", "gemini_architecture_critic"],
        )

    def test_dual_architecture_critics_accept_hyphenated_plural_wording(self) -> None:
        result = classify_work(
            "Have Claude Opus and Gemini provide second-opinion critics for the architect design.",
            requested_roles=["architecture"],
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(
            result["requested_architecture_critic_executors"],
            ["claude_architecture_critic", "gemini_architecture_critic"],
        )

    def test_routing_public_imports_remain_available(self) -> None:
        from cwo_core.routing import classify_work as imported_classify_work
        from cwo_core.routing import explicit_gemini_architect_critique_requested

        self.assertIs(imported_classify_work, classify_work)
        self.assertTrue(explicit_gemini_architect_critique_requested("Gemini second-opinion critic for architecture"))

    def test_generic_second_opinion_does_not_authorize_external_critic(self) -> None:
        result = classify_work(
            "Get a second opinion on the architect design.",
            requested_roles=["architecture"],
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertNotIn("claude_architecture_critic", result["requested_architecture_critic_executors"])
        self.assertNotIn("gemini_architecture_critic", result["requested_architecture_critic_executors"])

    def test_chatgpt_pro_master_plan_review_requires_external_opt_in(self) -> None:
        text = "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer for the final execution plan and total work packet."
        blocked = classify_work(text, share_boundary="redacted-packet")
        self.assertNotEqual(blocked["route"], "external-contract")
        self.assertTrue(blocked["blocking_review_required"])
        self.assertFalse(blocked["blocking_review_active"])
        self.assertTrue(blocked["blocking_review_waiver_required"])
        self.assertEqual(blocked["blocking_review_gate"], "chatgpt-pro-5.5-master-plan-review")
        candidate = next(
            item for item in blocked["ranked_executors"] if item["key"] == "chatgpt_pro_browser_master_reviewer"
        )
        self.assertIn("external dispatch requires user opt-in", candidate["policy_violations"])

        allowed = classify_work(text, external_ok=True, share_boundary="redacted-packet")
        self.assertEqual(allowed["route"], "external-contract")
        self.assertEqual(allowed["task_class"], "master-plan-review")
        self.assertEqual(allowed["recommended_executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertTrue(allowed["blocking_review_required"])
        self.assertTrue(allowed["blocking_review_active"])
        self.assertTrue(allowed["blocking_review_waiver_required"])
        self.assertEqual(allowed["blocking_review_executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertEqual(allowed["blocking_review_job_description_label"], "contract-jd-master-plan-review")
        self.assertIn("share-link return ingested", " ".join(allowed["blocking_review_required_evidence"]))
        self.assertEqual(allowed["guard_labels"], [
            "contractor-only",
            "no-codex-exec",
            "contract-jd-master-plan-review",
        ])
        self.assertEqual(allowed["external_experts"], ["master_plan_review"])
        self.assertTrue(allowed["peer_review_required"])
        self.assertTrue(allowed["architect_adjudication_required"])

    def test_chatgpt_pro_master_review_weigh_in_wording_routes_to_master_review(self) -> None:
        result = classify_work(
            "Tap in ChatGPT Pro 5.5 to weigh in as a master review of the final architect plan.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(result["task_class"], "master-plan-review")
        self.assertEqual(result["recommended_executor"], "chatgpt_pro_browser_master_reviewer")

    def test_generic_weigh_in_does_not_route_to_chatgpt_master_review(self) -> None:
        result = classify_work(
            "Have someone weigh in on this plan.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertNotEqual(result["recommended_executor"], "chatgpt_pro_browser_master_reviewer")

    def test_chatgpt_pro_master_plan_review_keeps_deep_research_separate(self) -> None:
        master_review = classify_work(
            "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer; Deep Research is a later opt-in.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(master_review["recommended_executor"], "chatgpt_pro_browser_master_reviewer")

        deep_research = classify_work(
            "Use OpenAI Deep Research for external standards research before planning.",
            external_ok=True,
            share_boundary="redacted-packet",
        )
        self.assertEqual(deep_research["recommended_executor"], "openai_deep_research_manual")

    def test_chatgpt_pro_master_plan_patch_branch_requires_disclosure_escalation(self) -> None:
        text = "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer for the final execution plan."
        blocked = classify_work(text, external_ok=True, share_boundary="patch-branch")
        candidate = next(
            item for item in blocked["ranked_executors"] if item["key"] == "chatgpt_pro_browser_master_reviewer"
        )
        self.assertIn(
            "share boundary patch-branch requires disclosure escalation approval",
            candidate["policy_violations"],
        )

        escalated = classify_work(
            text,
            external_ok=True,
            allow_disclosure_escalation=True,
            share_boundary="patch-branch",
        )
        escalated_candidate = next(
            item for item in escalated["ranked_executors"] if item["key"] == "chatgpt_pro_browser_master_reviewer"
        )
        self.assertIn(
            "sensitivity internal exceeds executor max_data_sensitivity redacted",
            escalated_candidate["policy_violations"],
        )
        self.assertNotEqual(escalated["recommended_executor"], "gemini_architecture_critic")
        self.assertNotEqual(escalated["route"], "external-contract")

    def test_public_docs_page_path_alone_requires_editor_gate(self) -> None:
        result = classify_work(
            "Update landing page copy.",
            file_paths=["docs/index.html"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertTrue(result["editor_gate_required"])
        self.assertIn("documentation", names)
        self.assertIn("web_design", names)
        self.assertIn("editor", names)

    def test_prefer_local_does_not_skip_public_docs_editor_gate(self) -> None:
        result = classify_work(
            "Review public docs and README install guidance with local model evidence.",
            file_paths=["README.md"],
            local_ok=True,
            prefer_local=True,
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertTrue(result["editor_gate_required"])
        self.assertIn("documentation", names)
        self.assertIn("editor", names)
        self.assertIn("editor", result["editor_gate_experts"])
        editor = next(expert for expert in result["ranked_experts"] if expert["name"] == "editor")
        self.assertNotIn(
            editor["selected_executor"]["dispatch_mode"],
            {"local_openai_compatible", "local_secure_review"},
        )

    def test_non_public_doc_path_does_not_require_editor_gate(self) -> None:
        result = classify_work(
            "Update helper script copy.",
            file_paths=["scripts/coach_prompt.py"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertFalse(result["editor_gate_required"])
        self.assertNotIn("editor", names)

    def test_internal_docs_do_not_auto_require_editor_gate(self) -> None:
        result = classify_work(
            "Documentation review for internal Beads workgraph behavior.",
            requested_roles=["documentation"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertFalse(result["editor_gate_required"])
        self.assertNotIn("editor", names)

    def test_red_hat_product_experts_route_by_requested_role(self) -> None:
        cases = [
            (
                "openshift_platform",
                "Review OpenShift cluster Operator Lifecycle Manager and MachineConfig upgrade risk.",
                "contract-jd-redhat-openshift-platform",
            ),
            (
                "openshift_app_dev",
                "Review OpenShift application developer Source-to-Image BuildConfig Tekton pipeline rollout.",
                "contract-jd-redhat-openshift-app-dev",
            ),
            (
                "openshift_ai",
                "Review OpenShift AI RHOAI KServe vLLM model serving GPU behavior.",
                "contract-jd-redhat-openshift-ai",
            ),
            (
                "rhoso",
                "Review RHOSO OpenStack control plane dataplane Neutron and Cinder impact.",
                "contract-jd-redhat-rhoso",
            ),
            (
                "rhacm",
                "Review RHACM MultiClusterHub ManagedCluster placement governance policy behavior.",
                "contract-jd-redhat-rhacm",
            ),
            (
                "rhacs",
                "Review RHACS StackRox admission control runtime security vulnerability management.",
                "contract-jd-redhat-rhacs",
            ),
            (
                "rhel",
                "Review RHEL systemd SELinux DNF IdM Satellite lifecycle behavior.",
                "contract-jd-redhat-rhel",
            ),
            (
                "project_manager_sprint_steward",
                "Plan the next sprint with Beads epic and issue dependencies.",
                "contract-jd-project-manager-sprint-steward",
            ),
        ]
        for expert_name, text, job_label in cases:
            with self.subTest(expert_name=expert_name):
                result = classify_work(text, requested_roles=[expert_name])
                primary = result["ranked_experts"][0]
                self.assertEqual(primary["name"], expert_name)
                self.assertEqual(primary["job_description_label"], job_label)

    def test_project_manager_sprint_steward_routes_by_planning_terms(self) -> None:
        result = classify_work(
            "Use CWO and Beads for next sprint planning: define the sprint goal, "
            "map stories into Beads issues, set Definition of Ready and Definition of Done, "
            "and avoid backlog sprawl."
        )

        primary = result["ranked_experts"][0]
        self.assertEqual(primary["name"], "project_manager_sprint_steward")
        self.assertEqual(primary["job_description_label"], "contract-jd-project-manager-sprint-steward")
        self.assertIn("Definition of Ready", primary["output_contract"])
        self.assertIn("stories and sprints are treated as planning language", primary["acceptance_checks"])

    def test_project_manager_sprint_steward_routes_continuation_terms(self) -> None:
        result = classify_work(
            "Resume epic cwo-123 and tell me what next issue is ready or blocked for sprint continuation."
        )

        primary = result["ranked_experts"][0]
        self.assertEqual(primary["name"], "project_manager_sprint_steward")
        self.assertEqual(primary["task_class"], "project-management")

    def test_red_hat_product_experts_route_by_trigger_terms(self) -> None:
        cases = [
            ("openshift_platform", "OCP ClusterVersion CVO ingress route MachineConfig day-2 operations."),
            ("openshift_app_dev", "OpenShift application DeploymentConfig BuildConfig S2I Helm Kustomize."),
            ("openshift_ai", "RHOAI Data Science Pipelines KServe InferenceService vLLM GPU model serving."),
            ("rhoso", "Red Hat OpenStack Services on OpenShift EDPM OpenStackControlPlane Nova Neutron."),
            ("rhacm", "Advanced Cluster Management MultiClusterHub ManagedCluster Placement cluster set."),
            ("rhacs", "Advanced Cluster Security StackRox Central Sensor admission control compliance."),
            ("rhel", "Red Hat Enterprise Linux systemd SELinux subscription-manager IdM Satellite."),
        ]
        for expert_name, text in cases:
            with self.subTest(expert_name=expert_name):
                result = classify_work(text)
                names = [expert["name"] for expert in result["ranked_experts"][:2]]
                self.assertIn(expert_name, names)

    def test_short_trigger_terms_do_not_match_inside_unrelated_words(self) -> None:
        result = classify_work(
            "Distinguished Engineer documentation, security, architecture, and coding quality review.",
            requested_roles=["documentation", "security", "architecture", "coding-quality"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertNotIn("web_design", names)

    def test_short_trigger_terms_still_match_as_tokens(self) -> None:
        cases = [
            ("web_design", "Review UI accessibility and responsive layout."),
            ("architecture", "Review API compatibility and system boundaries."),
            ("coding_quality", "Review coding quality, code quality, and unit test coverage."),
            ("openshift_platform", "Review OCP OLM CVO upgrade behavior."),
            ("openshift_app_dev", "Review S2I and odo developer workflow."),
            ("rhacm", "Review RHACM managed cluster placement."),
            ("rhacs", "Review RHACS ACS admission control policy."),
            ("rhel", "Review RHEL IdM DNF RPM and Satellite behavior."),
        ]
        for expert_name, text in cases:
            with self.subTest(expert_name=expert_name):
                result = classify_work(text)
                names = [expert["name"] for expert in result["ranked_experts"][:3]]
                self.assertIn(expert_name, names)

    def test_generic_red_hat_adjacent_words_do_not_overroute_product_experts(self) -> None:
        result = classify_work("Review ACME deployment docs, central routing, and sensor data formatting.")
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertNotIn("rhacm", names)
        self.assertNotIn("rhacs", names)
        self.assertNotIn("openshift_app_dev", names)

    def test_advanced_cluster_services_routes_to_rhacs_compatibility_alias(self) -> None:
        result = classify_work("Review Advanced Cluster Services policy enforcement and admission behavior.")
        primary = result["ranked_experts"][0]
        self.assertEqual(primary["name"], "rhacs")
        self.assertEqual(primary["job_description_label"], "contract-jd-redhat-rhacs")

    def test_rhel_idm_and_satellite_subspecialties_use_single_rhel_expert(self) -> None:
        for text in [
            "Review Red Hat Identity Management IdM FreeIPA Kerberos SSSD DNS behavior.",
            "Review Red Hat Satellite Capsule content view activation key lifecycle environment behavior.",
        ]:
            with self.subTest(text=text):
                result = classify_work(text)
                primary = result["ranked_experts"][0]
                self.assertEqual(primary["name"], "rhel")
                self.assertEqual(primary["job_description_label"], "contract-jd-redhat-rhel")


if __name__ == "__main__":
    unittest.main()
