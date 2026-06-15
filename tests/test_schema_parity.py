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


def load_schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


class SchemaParityTests(unittest.TestCase):
    def test_contractor_packet_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("contractor-packet.schema.json")
        self.assertTrue(set(CONTRACTOR_PACKET_REQUIRED_FIELDS).issubset(set(schema["required"])))

    def test_acceptance_schema_has_review_and_malpractice_fields(self) -> None:
        properties = load_schema("acceptance-decision.schema.json")["properties"]
        for field in [
            "malpractice_score",
            "malpractice_signals",
            "signal_categories",
            "peer_review_required",
            "peer_review_status",
            "human_adjudication_required",
            "recommended_disposition",
            "workspace_mutation",
        ]:
            self.assertIn(field, properties)

    def test_contractor_return_bundle_schema_supports_workspace_mutation(self) -> None:
        properties = load_schema("contractor-return-bundle.schema.json")["properties"]
        self.assertIn("workspace_mutation", properties)

    def test_local_dispatch_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("local-dispatch-envelope.schema.json")
        self.assertTrue(set(LOCAL_DISPATCH_REQUIRED_FIELDS).issubset(set(schema["required"])))

    def test_prompt_coach_schema_matches_runtime_required_fields(self) -> None:
        schema = load_schema("prompt-coach-result.schema.json")
        self.assertTrue(set(PROMPT_COACH_RESULT_REQUIRED_FIELDS).issubset(set(schema["required"])))
        self.assertIn("model_synthesis", schema["properties"])
        self.assertIn("recommended_mode", schema["properties"]["model_synthesis"]["properties"])

    def test_opt_in_schema_supports_allowed_providers(self) -> None:
        properties = load_schema("opt-in-record.schema.json")["properties"]
        self.assertIn("allowed_providers", properties)


if __name__ == "__main__":
    unittest.main()
