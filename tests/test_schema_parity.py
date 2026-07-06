from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.packets import (  # noqa: E402
    CONTRACTOR_PACKET_REQUIRED_FIELDS,
    LOCAL_DISPATCH_REQUIRED_FIELDS,
)
from cwo_core.coach import PROMPT_COACH_RESULT_REQUIRED_FIELDS  # noqa: E402
from cwo_core.harness import HARNESS_DISPATCH_REQUIRED_FIELDS, MODEL_PROFILE_REQUIRED_FIELDS  # noqa: E402


def load_schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


class SchemaParityTests(unittest.TestCase):
    def test_schema_files_are_not_title_only_duplicates(self) -> None:
        seen: dict[str, str] = {}
        for path in sorted((ROOT / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema.pop("title", None)
            normalized = json.dumps(schema, sort_keys=True, separators=(",", ":"))
            self.assertNotIn(
                normalized,
                seen,
                f"{path.name} duplicates {seen.get(normalized)} except for title",
            )
            seen[normalized] = path.name

    def test_contractor_packet_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("contractor-packet.schema.json")
        self.assertTrue(set(CONTRACTOR_PACKET_REQUIRED_FIELDS).issubset(set(schema["required"])))

    def test_acceptance_schema_has_review_and_malpractice_fields(self) -> None:
        properties = load_schema("acceptance-decision.schema.json")["properties"]
        for field in [
            "malpractice_score",
            "malpractice_signals",
            "evidence_quality_score",
            "evidence_quality_signals",
            "evidence_quality_signal_categories",
            "research_evidence_score",
            "research_evidence_signals",
            "research_evidence_signal_categories",
            "research_evidence_items",
            "research_contradictions",
            "research_reflection",
            "signal_categories",
            "peer_review_required",
            "peer_review_status",
            "implementation_blocked",
            "hold_reasons",
            "hold_classification",
            "boundary_taint_status",
            "boundary_taint_findings",
            "provider_key",
            "provider_trust_tier",
            "provider_external",
            "model_profile",
            "provenance_class",
            "human_adjudication_required",
            "recommended_disposition",
            "recommended_synthesis_use",
            "workspace_mutation",
        ]:
            self.assertIn(field, properties)

    def test_contractor_return_bundle_schema_supports_workspace_mutation(self) -> None:
        properties = load_schema("contractor-return-bundle.schema.json")["properties"]
        self.assertIn("workspace_mutation", properties)
        self.assertIn("boundary_taint_status", properties)
        self.assertIn("boundary_taint_findings", properties)
        self.assertIn("provider_key", properties)
        self.assertIn("provider_trust_tier", properties)
        self.assertIn("provider_external", properties)
        self.assertIn("dispatch_mode", properties)
        self.assertIn("local_profile", properties)
        self.assertIn("model_profile", properties)
        self.assertIn("provenance_class", properties)
        self.assertIn("evidence_quality_score", properties)
        self.assertIn("evidence_quality_signals", properties)
        self.assertIn("evidence_quality_signal_categories", properties)
        self.assertIn("research_evidence_score", properties)
        self.assertIn("research_evidence_signals", properties)
        self.assertIn("research_evidence_signal_categories", properties)
        self.assertIn("research_evidence_items", properties)
        self.assertIn("research_contradictions", properties)
        self.assertIn("research_reflection", properties)

    def test_contractor_return_schema_supports_research_evidence(self) -> None:
        properties = load_schema("contractor-return.schema.json")["properties"]
        self.assertIn("research_evidence_items", properties)
        self.assertIn("research_contradictions", properties)
        self.assertIn("research_reflection", properties)

    def test_local_dispatch_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("local-dispatch-envelope.schema.json")
        self.assertTrue(set(LOCAL_DISPATCH_REQUIRED_FIELDS).issubset(set(schema["required"])))
        for field in [
            "model_profile",
            "allow_private_dns",
            "tls_verify",
            "tls_ca_bundle_env",
            "request_options",
            "thinking_parser",
            "response_sanitization",
        ]:
            self.assertIn(field, schema["properties"])

    def test_prompt_coach_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("prompt-coach-result.schema.json")
        self.assertTrue(set(PROMPT_COACH_RESULT_REQUIRED_FIELDS).issubset(set(schema["required"])))
        self.assertIn("model_synthesis", schema["properties"])
        self.assertIn("scaffold_sizing", schema["properties"])
        self.assertIn("beads_context_depth", schema["properties"])
        self.assertIn("beads_briefing_depth", schema["properties"])
        self.assertIn("beads_context_depth_provenance", schema["properties"])
        self.assertIn("recommended_mode", schema["properties"]["model_synthesis"]["properties"])

    def test_route_schema_has_model_synthesis_contract(self) -> None:
        schema = load_schema("route-result.schema.json")
        model_synthesis = schema["properties"]["model_synthesis"]
        self.assertIn("model_synthesis", schema["required"])
        self.assertIn("beads_context_depth", schema["required"])
        self.assertIn("beads_briefing_depth", schema["required"])
        self.assertIn("beads_context_depth_provenance", schema["required"])
        self.assertIn("beads_context_depth", schema["properties"])
        for field in [
            "activation_state",
            "active",
            "requires_user_acceptance",
            "input_disposition_policy",
            "partial_synthesis_policy",
            "provider_conflict_flags",
        ]:
            self.assertIn(field, model_synthesis["required"])
            self.assertIn(field, model_synthesis["properties"])

    def test_route_schema_has_blocking_review_contract(self) -> None:
        schema = load_schema("route-result.schema.json")
        properties = schema["properties"]
        for field in [
            "blocking_review_required",
            "blocking_review_active",
            "blocking_review_gate",
            "blocking_review_executor",
            "blocking_review_job_description_label",
            "blocking_review_waiver_required",
            "blocking_review_failure_behavior",
            "blocking_review_required_evidence",
        ]:
            self.assertIn(field, properties)

    def test_opt_in_schema_supports_allowed_providers(self) -> None:
        properties = load_schema("opt-in-record.schema.json")["properties"]
        self.assertIn("allowed_providers", properties)

    def test_harness_dispatch_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("harness-dispatch-envelope.schema.json")
        self.assertTrue(set(HARNESS_DISPATCH_REQUIRED_FIELDS).issubset(set(schema["required"])))
        self.assertIn("model_profile", schema["properties"])
        self.assertIn("model_profile_details", schema["properties"])

    def test_model_profile_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("model-profile.schema.json")
        profile_schema = schema["properties"]["profiles"]["additionalProperties"]
        self.assertTrue(set(MODEL_PROFILE_REQUIRED_FIELDS).issubset(set(profile_schema["required"])))
        properties = profile_schema["properties"]
        self.assertIn("deployment_tier", properties)
        self.assertIn("precision", properties)
        self.assertIn("thinking_enabled", properties)
        self.assertIn("reasoning_mode", properties)
        self.assertIn("request_options", properties)
        self.assertIn("required_vllm_flags", properties)
        self.assertIn("hardware_profile", properties)
        self.assertIn("recommended_enterprise_scale", properties)
        self.assertIn("benchmark_gate", properties)
        self.assertIn("promotion_status", properties)
        row_properties = schema["properties"]["role_substitution_matrix"]["items"]["properties"]
        self.assertIn("enterprise_profiles", row_properties)

    def test_execution_environment_schema_has_profiles(self) -> None:
        schema = load_schema("execution-environment.schema.json")
        self.assertIn("profiles", schema["properties"])

    def test_run_readiness_schema_has_handoff_gates(self) -> None:
        schema = load_schema("run-readiness-plan.schema.json")
        properties = schema["properties"]
        for field in [
            "workstreams",
            "rubric",
            "criterion_evidence_matrix",
            "provider_provenance",
            "quarantine_rules",
            "boundary_negative_tests",
            "next_version_rail",
            "patrol_stopping_rule",
            "handoff_evidence_requirements",
            "adjudication_record",
        ]:
            self.assertIn(field, schema["required"])
            self.assertIn(field, properties)
        projection_schema = properties["artifact_authority"]["properties"]["projections"]["items"]
        self.assertIn("type", projection_schema["required"])
        self.assertEqual(
            set(projection_schema["properties"]["type"]["enum"]),
            {"run-sheet", "wrap-up-status", "next-version"},
        )
        self.assertEqual(projection_schema["properties"]["canonical_source"]["const"], "beads")
        self.assertIn("criterion_ids", properties["rubric"]["required"])
        patrol_evidence = properties["patrol_stopping_rule"]["properties"]["required_acceptance_evidence"]
        self.assertEqual(
            set(patrol_evidence["items"]["enum"]),
            {"ownership", "locking", "history", "failure_containment", "provider_neutral_execution"},
        )


if __name__ == "__main__":
    unittest.main()
