from __future__ import annotations

import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Callable, Literal, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from route_work import print_human  # noqa: E402

RETIRED_FIELD = "beads_" + "briefing_depth"
RETIRED_FLAG = "--beads-" + "briefing-depth"


class RouteCheck(NamedTuple):
    value: Callable[[dict], object]
    expected: object
    operation: Literal["equal", "not-equal", "contains", "not-contains", "in", "not-in", "true", "false"] = "equal"


class RouteCase(NamedTuple):
    task: str
    options: dict
    oracles: tuple[tuple[str, tuple[RouteCheck, ...] | Callable[[dict], None]], ...]


class RouteWorkTests(unittest.TestCase):
    def test_route_cli_translates_typed_error_without_traceback(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "route_work.py"),
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

    def test_routing_projection_rows(self) -> None:
        rows = (
            RouteCase(
                "Use subagents for a deep docs second pass with prior Beads comments.",
                {},
                (
                    ('test_route_outputs_beads_context_depth_and_provenance', (
                        RouteCheck(lambda result: result['beads_context_depth'], 'heavy'),
                        RouteCheck(lambda result: result, RETIRED_FIELD, 'not-contains'),
                        RouteCheck(lambda result: result['beads_context_depth_source'], 'autosized'),
                        RouteCheck(lambda result: result['beads_context_depth_provenance']['computed_depth'], 'heavy'),
                        RouteCheck(lambda result: result['beads_context_depth_provenance']['effective_depth'], 'heavy'),
                    )),
                ),
            ),
            RouteCase(
                "Use subagents for a deep docs second pass with prior Beads comments.",
                {'beads_context_depth': 'summary'},
                (
                    ('test_route_context_depth_override_records_requested_and_computed_depth', (
                        RouteCheck(lambda result: result['beads_context_depth'], 'summary'),
                        RouteCheck(lambda result: result, RETIRED_FIELD, 'not-contains'),
                        RouteCheck(lambda result: result['beads_context_depth_source'], 'explicit'),
                        RouteCheck(lambda result: result['beads_context_depth_provenance']['requested_depth'], 'summary'),
                        RouteCheck(lambda result: result['beads_context_depth_provenance']['computed_depth'], 'heavy'),
                    )),
                ),
            ),
            RouteCase(
                "Publish public docs for the install flow.",
                {'data_sensitivity': 'restricted'},
                (
                    ('test_data_sensitivity_operator_declaration_overrides_heuristic', (
                        RouteCheck(lambda result: result['data_sensitivity'], 'restricted'),
                        RouteCheck(lambda result: result['data_sensitivity_source'], 'operator-declared'),
                        RouteCheck(lambda result: result['data_sensitivity_heuristic'], 'public'),
                        RouteCheck(lambda result: result['data_sensitivity_provenance']['declared_sensitivity'], 'restricted'),
                        RouteCheck(lambda result: result['data_sensitivity_provenance']['heuristic_sensitivity'], 'public'),
                        RouteCheck(lambda result: result['data_sensitivity_provenance']['effective_sensitivity'], 'restricted'),
                        RouteCheck(lambda result: result['data_sensitivity_provenance']['advisory_heuristic'], None, 'true'),
                        RouteCheck(lambda result: result['data_sensitivity_disclaimer'], 'can miss paraphrases', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Review tenant dossier retention for the workflow.",
                {'data_sensitivity': 'restricted'},
                (
                    ('test_data_sensitivity_override_covers_heuristic_false_negative', (
                        RouteCheck(lambda result: result['data_sensitivity'], 'restricted'),
                        RouteCheck(lambda result: result['data_sensitivity_heuristic'], 'internal'),
                        RouteCheck(lambda result: result['data_sensitivity_source'], 'operator-declared'),
                    )),
                ),
            ),
            RouteCase(
                "Review customer records export and employee data cleanup.",
                {'data_sensitivity': 'public'},
                (
                    ('test_data_sensitivity_declaration_is_floor_not_ceiling', (
                        RouteCheck(lambda result: result['data_sensitivity'], 'restricted'),
                        RouteCheck(lambda result: result['data_sensitivity_heuristic'], 'restricted'),
                        RouteCheck(lambda result: result['data_sensitivity_source'], 'operator-declared'),
                        RouteCheck(lambda result: result['data_sensitivity_provenance']['declared_sensitivity'], 'public'),
                        RouteCheck(lambda result: result['data_sensitivity_provenance']['reason'], 'raised the effective sensitivity', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Security and web design review for contractor packet behavior.",
                {'external_ok': True,
                 'requested_roles': ['security', 'web-design'],
                 'share_boundary': 'redacted-packet'},
                (
                    ('test_security_and_web_design_triggers', (
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']][:3], 'security', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']][:3], 'web_design', 'contains'),
                    )),
                    ('test_ranked_experts_have_per_expert_executor_metadata', self._assert_ranked_experts_have_per_expert_executor_metadata),
                ),
            ),
            RouteCase(
                "Evaluate a contractor return for work_rerouting_or_subversion, objective dilution, and critical path deferral.",
                {'share_boundary': 'redacted-packet'},
                (
                    ('test_work_rerouting_terms_require_sabotage_review_without_provider_conflict', (
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']][:3], 'sabotage_review', 'contains'),
                        RouteCheck(lambda result: result['sabotage_review_required'], None, 'true'),
                        RouteCheck(lambda result: result['peer_review_required'], None, 'true'),
                        RouteCheck(lambda result: result['provider_conflict_detected'], None, 'false'),
                    )),
                ),
            ),
            RouteCase(
                "Refactor architecture policy and routing tests.",
                {'model_synthesis': True, 'requested_roles': ['architecture']},
                (
                    ('test_model_synthesis_flag_marks_route_opt_in_accepted', (
                        RouteCheck(lambda result: result['model_synthesis']['recommended_mode'], 'accepted'),
                        RouteCheck(lambda result: result['model_synthesis']['activation_state'], 'accepted'),
                        RouteCheck(lambda result: result['model_synthesis']['active'], None, 'true'),
                        RouteCheck(lambda result: result['model_synthesis']['requires_user_acceptance'], None, 'false'),
                    )),
                ),
            ),
            RouteCase(
                "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.6 Sol counter-review.",
                {'execution_environment': 'connected-codex-glm-primary',
                 'model_synthesis': True,
                 'requested_roles': ['architecture']},
                (
                    ('test_glm_primary_environment_routes_architecture_to_glm_with_codex_counter_review', (
                        RouteCheck(lambda result: result['execution_environment'], 'connected-codex-glm-primary'),
                        RouteCheck(lambda result: result['architecture_authority'], 'glm-5.2-primary-architect'),
                        RouteCheck(lambda result: result['project_manager_executor'], 'codex_project_manager'),
                        RouteCheck(lambda result: result['recommended_executor'], 'rhoai_glm_primary_architect'),
                        RouteCheck(lambda result: result['selected_executor']['model_profile'], 'rhoai-architect-glm-5-2-bf16-thinking'),
                        RouteCheck(lambda result: result['local_worker_opt_in_source'], 'execution-environment'),
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], 'codex_architecture_critic', 'contains'),
                        RouteCheck(lambda result: result['model_synthesis']['synthesis_owner'], 'rhoai_glm_primary_architect'),
                        RouteCheck(lambda result: {item['executor']: item for item in result['model_synthesis']['recommended_panel']}['codex_architecture_critic']['role'], 'architecture-counter-review'),
                        RouteCheck(lambda result: {item['executor']: item for item in result['model_synthesis']['recommended_panel']}['codex_architecture_critic']['effort'], 'codex-5.6-sol'),
                        RouteCheck(lambda result: {item['executor']: item for item in result['model_synthesis']['recommended_panel']}['rhoai_glm_primary_architect']['role'], 'primary-architect'),
                    )),
                ),
            ),
            RouteCase(
                "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.6 Sol counter-review.",
                {'model_synthesis': True, 'requested_roles': ['architecture']},
                (
                    ('test_default_environment_keeps_codex_as_architect', (
                        RouteCheck(lambda result: result['execution_environment'], 'connected-codex'),
                        RouteCheck(lambda result: result['architecture_authority'], 'codex-frontier-architect'),
                        RouteCheck(lambda result: result['primary_architect_executor'], 'frontier_architect'),
                        RouteCheck(lambda result: result['selected_executor']['model_label'], 'codex-5.6-sol'),
                        RouteCheck(lambda result: result['execution_environment_profile']['role_bindings']['architect']['model'], 'gpt-6.1-sol'),
                        RouteCheck(lambda result: result['recommended_executor'], 'rhoai_glm_primary_architect', 'not-equal'),
                    )),
                ),
            ),
            RouteCase(
                "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
                {'file_paths': ['docs/index.html', 'README.md']},
                (
                    ('test_public_docs_pages_require_editor_gate', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'true'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'documentation', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'web_design', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'contains'),
                        RouteCheck(lambda result: next((expert for expert in result['ranked_experts'] if expert['name'] == 'editor'))['validation_gate_required'], None, 'true'),
                        RouteCheck(lambda result: next((expert for expert in result['ranked_experts'] if expert['name'] == 'editor'))['job_description_label'], 'contract-jd-editorial-reasoning'),
                    )),
                ),
            ),
            RouteCase(
                "Fix a typo in the README.",
                {'file_paths': ['README.md']},
                (
                    ('test_typo_class_readme_change_stays_low_risk_without_editor_gate', (
                        RouteCheck(lambda result: result['risk_level'], 'low'),
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'false'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'not-contains'),
                    )),
                ),
            ),
            RouteCase(
                "fix wording in error messages and harden auth token validation",
                {},
                (
                    ('test_mixed_security_wording_change_is_not_demoted_to_low_risk', (
                        RouteCheck(lambda result: result['risk_level'], 'high'),
                        RouteCheck(lambda result: result['task_class'], 'security-review'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'security', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "fix wording in error messages and harden auth token validation",
                {'file_paths': ['scripts/auth.py']},
                (
                    ('test_mixed_security_wording_change_with_code_path_is_not_demoted', (
                        RouteCheck(lambda result: result['risk_level'], 'high'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'security', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Fix wording in docs/usage.md.",
                {'file_paths': ['docs/usage.md']},
                (
                    ('test_docs_only_wording_change_stays_low_risk_when_docs_scoped', (
                        RouteCheck(lambda result: result['risk_level'], 'low'),
                        RouteCheck(lambda result: result['task_class'], {'docs-review', 'general-review'}, 'in'),
                    )),
                ),
            ),
            RouteCase(
                "Publish README install docs for external operators.",
                {'file_paths': ['README.md']},
                (
                    ('test_publish_readme_change_still_requires_editor_gate', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'true'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Rewrite the README architecture overview and operator flow.",
                {'file_paths': ['README.md']},
                (
                    ('test_substantive_readme_change_requires_editor_gate_by_path', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'true'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'documentation', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
                "of the Codex architect design for a cross-cutting public contract architecture migration.",
                {'external_ok': True, 'requested_roles': ['architecture'], 'share_boundary': 'redacted-packet'},
                (
                    ('test_dual_architecture_critics_are_preserved_as_independent_contracts', (
                        RouteCheck(lambda result: result['recommended_executor'], 'claude_architecture_critic'),
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], ['claude_architecture_critic', 'gemini_architecture_critic']),
                        RouteCheck(lambda result: [contract['executor'] for contract in result['architecture_critic_contracts']], ['claude_architecture_critic', 'gemini_architecture_critic']),
                        RouteCheck(lambda result: result['architecture_review_complexity'], 'high'),
                        RouteCheck(lambda result: result['claude_architecture_effort'], 'xhigh'),
                    )),
                ),
            ),
            RouteCase(
                "Use exact GLM-5.3 as a second-opinion architecture critic.",
                {'local_ok': True,
                 'local_profile': 'openshift-ai-glm-5-3-direct',
                 'requested_roles': ['architecture']},
                (
                    ('test_glm53_does_not_silently_fall_back_to_glm52_executor', (
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], ['rhoai_glm_compact_architecture_critic']),
                        RouteCheck(lambda result: result['recommended_executor'], 'rhoai_glm_compact_architecture_critic'),
                        RouteCheck(lambda result: result['selected_executor']['model_profile'], 'rhoai-architect-glm-5-3-bf16-compact-critic'),
                    )),
                ),
            ),
            RouteCase(
                "Use Claude Opus and GLM as architecture critics. "
                "The critic panel is closed to those two providers. "
                "Do not add Gemini or ChatGPT Pro.",
                {'external_ok': True,
                 'local_ok': True,
                 'model_synthesis': True,
                 'requested_roles': ['architecture'],
                 'share_boundary': 'redacted-packet'},
                (
                    ('test_prohibited_provider_is_not_treated_as_architecture_critic_opt_in', (
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], ['claude_architecture_critic', 'rhoai_glm_hardened_architecture_critic']),
                        RouteCheck(lambda result: result['blocking_review_required'], None, 'false'),
                        RouteCheck(lambda result: any(('conflicting architecture critic intent' in item for item in result['hard_stops'])), None, 'false'),
                    )),
                ),
            ),
            RouteCase(
                "Reconcile and publish the public README and docs pages. "
                "Use Claude Opus and GLM as architecture critics with model synthesis. "
                "The critic panel is closed to those two providers. "
                "Do not add Gemini or ChatGPT Pro.",
                {'external_ok': True,
                 'file_paths': ['README.md', 'docs/workflows.html'],
                 'local_ok': True,
                 'local_profile': 'openshift-ai-glm-256k',
                 'model_synthesis': True,
                 'prefer_local': True,
                 'requested_roles': ['architecture'],
                 'share_boundary': 'redacted-packet'},
                (
                    ('test_public_docs_gate_does_not_change_architecture_critic_task_class', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'true'),
                        RouteCheck(lambda result: [contract['executor'] for contract in result['architecture_critic_contracts']], ['claude_architecture_critic', 'rhoai_glm_hardened_architecture_critic']),
                        RouteCheck(lambda result: all((not contract['selected_executor']['policy_violations'] for contract in result['architecture_critic_contracts'])), None, 'true'),
                    )),
                ),
            ),
            RouteCase(
                "Use Gemini as an architecture critic. Do not add Gemini.",
                {'external_ok': True, 'requested_roles': ['architecture'], 'share_boundary': 'redacted-packet'},
                (
                    ('test_conflicting_architecture_critic_intent_fails_closed', (
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], 'gemini_architecture_critic', 'not-contains'),
                        RouteCheck(lambda result: any((contract.get('executor') == 'gemini_architecture_critic' for contract in result['architecture_critic_contracts'])), None, 'false'),
                        RouteCheck(lambda result: result['hard_stops'], 'conflicting architecture critic intent: gemini_architecture_critic is both requested and prohibited', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Use Claude Opus as only external architecture critic. "
                "No Gemini/Agy. No GLM. "
                "Do not use model synthesis; direct adjudication.",
                {'external_ok': True, 'requested_roles': ['architecture'], 'share_boundary': 'redacted-packet'},
                (
                    ('test_single_claude_critic_with_direct_adjudication_disables_synthesis', (
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], ['claude_architecture_critic']),
                        RouteCheck(lambda result: [contract['executor'] for contract in result['architecture_critic_contracts']], ['claude_architecture_critic']),
                        RouteCheck(lambda result: result['model_synthesis']['recommended_mode'], 'disabled'),
                        RouteCheck(lambda result: result['model_synthesis']['active'], None, 'false'),
                        RouteCheck(lambda result: result['hard_stops'], []),
                    )),
                ),
            ),
            RouteCase(
                "Use model synthesis. Do not use model synthesis.",
                {'requested_roles': ['architecture']},
                (
                    ('test_conflicting_model_synthesis_language_fails_closed', (
                        RouteCheck(lambda result: result['model_synthesis']['recommended_mode'], 'disabled'),
                        RouteCheck(lambda result: result['hard_stops'], 'conflicting model synthesis intent: synthesis is both requested and prohibited', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Do not use model synthesis; use direct architect adjudication.",
                {'model_synthesis': True, 'requested_roles': ['architecture']},
                (
                    ('test_model_synthesis_flag_conflicting_with_prohibition_fails_closed', (
                        RouteCheck(lambda result: result['model_synthesis']['recommended_mode'], 'disabled'),
                        RouteCheck(lambda result: result['model_synthesis']['active'], None, 'false'),
                        RouteCheck(lambda result: result['hard_stops'], 'conflicting model synthesis intent: synthesis is both requested and prohibited', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Get a second opinion on the architect design.",
                {'external_ok': True, 'requested_roles': ['architecture'], 'share_boundary': 'redacted-packet'},
                (
                    ('test_generic_second_opinion_does_not_authorize_external_critic', (
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], 'claude_architecture_critic', 'not-contains'),
                        RouteCheck(lambda result: result['requested_architecture_critic_executors'], 'gemini_architecture_critic', 'not-contains'),
                    )),
                ),
            ),
            RouteCase(
                "Tap in ChatGPT Pro 5.5 to weigh in as a master review of the final architect plan.",
                {'external_ok': True, 'share_boundary': 'redacted-packet'},
                (
                    ('test_chatgpt_pro_master_review_weigh_in_wording_routes_to_master_review', (
                        RouteCheck(lambda result: result['task_class'], 'master-plan-review'),
                        RouteCheck(lambda result: result['recommended_executor'], 'chatgpt_pro_browser_master_reviewer'),
                    )),
                ),
            ),
            RouteCase(
                "Have someone weigh in on this plan.",
                {'external_ok': True, 'share_boundary': 'redacted-packet'},
                (
                    ('test_generic_weigh_in_does_not_route_to_chatgpt_master_review', (
                        RouteCheck(lambda result: result['recommended_executor'], 'chatgpt_pro_browser_master_reviewer', 'not-equal'),
                    )),
                ),
            ),
            RouteCase(
                "Update landing page copy.",
                {'file_paths': ['docs/index.html']},
                (
                    ('test_public_docs_page_path_alone_requires_editor_gate', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'true'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'documentation', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'web_design', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Review public docs and README install guidance with local model evidence.",
                {'file_paths': ['README.md'], 'local_ok': True, 'prefer_local': True},
                (
                    ('test_prefer_local_does_not_skip_public_docs_editor_gate', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'true'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'documentation', 'contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'contains'),
                        RouteCheck(lambda result: result['editor_gate_experts'], 'editor', 'contains'),
                        RouteCheck(lambda result: next((expert for expert in result['ranked_experts'] if expert['name'] == 'editor'))['selected_executor']['dispatch_mode'], {'local_openai_compatible', 'local_secure_review'}, 'not-in'),
                    )),
                ),
            ),
            RouteCase(
                "Update helper script copy.",
                {'file_paths': ['scripts/coach_prompt.py']},
                (
                    ('test_non_public_doc_path_does_not_require_editor_gate', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'false'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'not-contains'),
                    )),
                ),
            ),
            RouteCase(
                "Documentation review for internal Beads workgraph behavior.",
                {'requested_roles': ['documentation']},
                (
                    ('test_internal_docs_do_not_auto_require_editor_gate', (
                        RouteCheck(lambda result: result['editor_gate_required'], None, 'false'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'editor', 'not-contains'),
                    )),
                ),
            ),
            RouteCase(
                "Use CWO and Beads for next sprint planning: define the sprint goal, "
                "map stories into Beads issues, set Definition of Ready and Definition of Done, "
                "and avoid backlog sprawl.",
                {},
                (
                    ('test_project_manager_sprint_steward_routes_by_planning_terms', (
                        RouteCheck(lambda result: result['ranked_experts'][0]['name'], 'project_manager_sprint_steward'),
                        RouteCheck(lambda result: result['ranked_experts'][0]['job_description_label'], 'contract-jd-project-manager-sprint-steward'),
                        RouteCheck(lambda result: result['ranked_experts'][0]['output_contract'], 'Definition of Ready', 'contains'),
                        RouteCheck(lambda result: result['ranked_experts'][0]['acceptance_checks'], 'stories and sprints are treated as planning language', 'contains'),
                    )),
                ),
            ),
            RouteCase(
                "Resume epic cwo-123 and tell me what next issue is ready or blocked for sprint continuation.",
                {},
                (
                    ('test_project_manager_sprint_steward_routes_continuation_terms', (
                        RouteCheck(lambda result: result['ranked_experts'][0]['name'], 'project_manager_sprint_steward'),
                        RouteCheck(lambda result: result['ranked_experts'][0]['task_class'], 'project-management'),
                    )),
                ),
            ),
            RouteCase(
                "Distinguished Engineer documentation, security, architecture, and coding quality review.",
                {'requested_roles': ['documentation', 'security', 'architecture', 'coding-quality']},
                (
                    ('test_short_trigger_terms_do_not_match_inside_unrelated_words', (
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'web_design', 'not-contains'),
                    )),
                ),
            ),
            RouteCase(
                "Review ACME deployment docs, central routing, and sensor data formatting.",
                {},
                (
                    ('test_generic_red_hat_adjacent_words_do_not_overroute_product_experts', (
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'rhacm', 'not-contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'rhacs', 'not-contains'),
                        RouteCheck(lambda result: [expert['name'] for expert in result['ranked_experts']], 'openshift_app_dev', 'not-contains'),
                    )),
                ),
            ),
            RouteCase(
                "Review Advanced Cluster Services policy enforcement and admission behavior.",
                {},
                (
                    ('test_advanced_cluster_services_routes_to_rhacs_compatibility_alias', (
                        RouteCheck(lambda result: result['ranked_experts'][0]['name'], 'rhacs'),
                        RouteCheck(lambda result: result['ranked_experts'][0]['job_description_label'], 'contract-jd-redhat-rhacs'),
                    )),
                ),
            ),
        )
        assertions = {
            "equal": self.assertEqual, "not-equal": self.assertNotEqual,
            "contains": lambda value, expected: self.assertIn(expected, value),
            "not-contains": lambda value, expected: self.assertNotIn(expected, value),
            "in": self.assertIn, "not-in": self.assertNotIn,
            "true": lambda value, _: self.assertTrue(value),
            "false": lambda value, _: self.assertFalse(value),
        }
        for row in rows:
            with self.subTest(request=tuple(original for original, _ in row.oracles)):
                result = classify_work(row.task, **row.options)
                for original, oracle in row.oracles:
                    with self.subTest(original=original):
                        if callable(oracle):
                            oracle(result)
                        else:
                            for check in oracle:
                                assertions[check.operation](check.value(result), check.expected)

    def _assert_ranked_experts_have_per_expert_executor_metadata(self, result: dict) -> None:
        self.assertEqual(result["recommended_executor"], result["ranked_experts"][0]["recommended_executor"])
        for expert in result["ranked_experts"][:2]:
            self.assertIn("recommended_executor", expert)
            self.assertIn("selected_executor", expert)
            self.assertIn("executor_policy_violations", expert)


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


    def test_dual_architecture_critic_wording_variants(self) -> None:
        variants = (
            ('test_dual_architecture_critics_accept_2nd_opinions_wording',
             'Have Claude Opus and Gemini provide 2nd opinions of the architect design.'),
            ('test_dual_architecture_critics_accept_hyphenated_plural_wording',
             'Have Claude Opus and Gemini provide second-opinion critics for the architect design.'),
        )
        for original, prompt in variants:
            with self.subTest(original=original):
                result = classify_work(
                    prompt,
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
