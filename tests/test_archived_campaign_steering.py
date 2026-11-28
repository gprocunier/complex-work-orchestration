"""Replay the historical steering receipt witnesses against reviewed source."""

from __future__ import annotations

import importlib.metadata
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import REVIEWED_CAMPAIGN_SOURCE, run_archived_cases  # noqa: E402


STEERING_CASES = "tests.test_native_canary_contracts.NativeCanaryContractTests."


class ArchivedCampaignSteeringTests(unittest.TestCase):
    def test_archived_steering_receipts_and_adjudication(self) -> None:
        methods = (
            "test_runtime_uuid_identities_reject_textual_aliases",
            "test_bound_steering_consumption_family",
            "test_neutral_steering_is_strict_write_with_compatible_v1_read",
            "test_neutral_steering_strict_writer_rejects_invalid_envelope",
            "test_operator_facts_require_exact_opaque_verified_authority",
            "test_neutral_steering_rejects_conflated_or_asserted_authority_fields",
            "test_neutral_steering_payload_tamper_cannot_hide_behind_outer_seal",
            "test_steering_text_and_confidence_cannot_promote_scope",
            "test_steering_stop_pre_mutation_malformed_resolution_cases",
            "test_steering_stop_pre_mutation_unknown_adjudication_fields_reject",
            "test_steering_stop_pre_mutation_reconciles_missing_required_findings",
            "test_steering_stop_pre_mutation_rejects_duplicate_receipt_finding_codes",
            "test_steering_model_activity_boundary_and_hash_tamper",
        )
        run_archived_cases(self, REVIEWED_CAMPAIGN_SOURCE, *(STEERING_CASES + method for method in methods))

    def test_archived_steering_writer_output_matches_its_schema(self) -> None:
        schema = importlib.util.find_spec("jsonschema")
        if schema is None:
            self.skipTest("jsonschema not installed")
        distribution = importlib.metadata.distribution("jsonschema")
        dependency_path = Path(distribution.locate_file("")).resolve(strict=True)
        entry = dependency_path / "jsonschema" / "__init__.py"
        self.assertEqual(Path(schema.origin or "").resolve(strict=True), entry.resolve(strict=True))
        run_archived_cases(
            self, REVIEWED_CAMPAIGN_SOURCE,
            STEERING_CASES + "test_neutral_steering_v2_schema_accepts_strict_writer_output",
            dependency_path=dependency_path,
        )
