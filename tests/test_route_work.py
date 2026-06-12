from __future__ import annotations

import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402
from route_work import print_human  # noqa: E402


class RouteWorkTests(unittest.TestCase):
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
        self.assertIn("executor=", rendered)
        self.assertIn("violations=", rendered)

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
            item for item in web_design["executor_candidates"] if item["key"] == "gemini_3_1_pro_manual"
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
        self.assertEqual(allowed["recommended_executor"], "gemini_3_1_pro_manual")
        self.assertIn("contract-jd-domain-web-design", allowed["guard_labels"])
        editor = next(expert for expert in allowed["ranked_experts"] if expert["name"] == "editor")
        self.assertFalse(editor["selected_executor"]["external"])
        self.assertEqual(editor["recommended_executor"], "frontier_architect")

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
