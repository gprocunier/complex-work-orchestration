from __future__ import annotations

import json
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.peer_review import pending_evaluation_sha256  # noqa: E402
from cwo_core.returns import make_acceptance_decision, normalize_contractor_return  # noqa: E402
from cwo_core.return_evidence import MAX_RETURN_JSON_CHARS, MAX_RETURN_JSON_DEPTH, MAX_RETURN_JSON_DOCUMENTS  # noqa: E402
from evaluate_return import print_human  # noqa: E402


class ReturnEvidenceJsonTest(unittest.TestCase):
    def evaluate(self, section: str, content: str) -> tuple[dict, dict]:
        text = (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")
        if section == "Evidence":
            text = text.replace("Evidence:\n", f"Evidence:\n{content}\n")
        else:
            text += f"\n{section}:\n{content}\n"
        return make_acceptance_decision(text), normalize_contractor_return(text)

    def test_invalid_json_numbers_produce_structured_rejections(self) -> None:
        for token in ("1e309", "-1e309", "NaN", "Infinity", "9" * 5_000):
            with self.subTest(token=token[:12]):
                result, bundle = self.evaluate(
                    "Research evidence", f'[{{"claim": "An observation", "source_reliability_score": {token}}}]',
                )
                self.assertEqual(result["verdict"], "reject")
                self.assertFalse(result["accepted_for_use"])
                self.assertEqual(result["research_evidence_items"], [])
                self.assertEqual(result["research_evidence_rejections"], bundle["research_evidence_rejections"])
                self.assertEqual(result["research_evidence_rejections"][0]["section"], "Research evidence")
                json.dumps(result, allow_nan=False)
                json.dumps(bundle, allow_nan=False)

    def test_wrong_type_scores_reject_evidence_instead_of_coercing(self) -> None:
        for value in ("95", True, 95.0, 95.5, None, [], {}, -1, 101):
            with self.subTest(value=value):
                item = {"claim": "An observation", "source_reliability_score": 0, "relevance_score": value}
                result, bundle = self.evaluate("Research evidence", json.dumps([item]))
                self.assertEqual(result["verdict"], "reject")
                self.assertFalse(result["accepted_for_use"])
                self.assertEqual(result["research_evidence_items"], [])
                self.assertEqual(result["research_evidence_rejections"], bundle["research_evidence_rejections"])
                self.assertEqual(result["research_evidence_rejections"][0]["field"], "relevance_score")

    def test_invalid_scores_report_original_item_index(self) -> None:
        item = {"reliability_score": "invalid fixture score"}
        for content, index in ((item, 1), ({"research_evidence_items": ["", item]}, 2)):
            with self.subTest(index=index):
                result, bundle = self.evaluate("Research evidence", json.dumps(content))
                expected = {"section": "Research evidence", "document_index": 1, "item_index": index,
                            "code": "invalid-score", "field": "reliability_score"}
                self.assertEqual(result["verdict"], "reject")
                self.assertEqual(result["research_evidence_rejections"], [expected])
                self.assertEqual(bundle["research_evidence_rejections"], [expected])
                with redirect_stdout(StringIO()) as output:
                    print_human(result)
                self.assertIn(f"Research evidence, document 1, item {index}, field reliability_score (invalid-score)",
                              output.getvalue())
                self.assertNotIn("invalid fixture score", output.getvalue())

    def test_return_sections_share_json_bounds(self) -> None:
        oversized = json.dumps({"note": "x" * MAX_RETURN_JSON_CHARS})
        cases = (
            ("Research contradictions", "[" * (MAX_RETURN_JSON_DEPTH + 1) + "]" * (MAX_RETURN_JSON_DEPTH + 1), "nesting-too-deep"),
            ("Research reflection", f"```json\n{oversized}\n```", "section-too-large"),
            ("Evidence", "```json\n{}\n```\n" * (MAX_RETURN_JSON_DOCUMENTS + 1), "too-many-documents"),
            ("Research reflection", '```json\n{"coverage": 1e309}\n```', "invalid-json"),
        )
        for section, content, code in cases:
            with self.subTest(section=section, code=code):
                result, bundle = self.evaluate(section, content)
                rejection, = result["research_evidence_rejections"]
                self.assertEqual((rejection["section"], rejection["code"]), (section, code))
                self.assertEqual(bundle["research_evidence_rejections"], [rejection])
                self.assertEqual(result["recommended_synthesis_use"], "reject")

    def test_repeated_sections_validate_superseded_json_and_score_latest(self) -> None:
        for section, repeated in (("Research evidence", "Research sources"), ("Evidence", "Evidence")):
            for prior in ('{"research_evidence_items": [1e309]}', '{"research_evidence_items": ["Earlier claim"]}'):
                with self.subTest(section=section, prior=prior):
                    result, bundle = self.evaluate(
                        section, f'```json\n{prior}\n```\n{repeated}:\n```json\n{{"research_evidence_items": ["Latest claim"]}}\n```',
                    )
                    self.assertNotIn(prior, bundle["sections"][section])
                    for output in (result, bundle):
                        self.assertEqual(output["research_evidence_items"], [{"claim": "Latest claim"}])
                        expected = ([{"section": section, "occurrence_index": 1, "document_index": 1, "code": "invalid-json"}]
                                    if "1e309" in prior else [])
                        self.assertEqual(output.get("research_evidence_rejections", []), expected)
                    if "1e309" in prior:
                        self.assertEqual(result["verdict"], "reject")

    def test_research_wrappers_require_their_container_type(self) -> None:
        for field in ("research_evidence_items", "evidence_items", "research_contradictions", "contradictions",
                      "research_reflection", "reflection"):
            with self.subTest(field=field):
                result, _ = self.evaluate("Research evidence", json.dumps({field: None}))
                rejection, = result["research_evidence_rejections"]
                self.assertEqual((rejection["code"], rejection["field"]), ("invalid-wrapper-type", field))
                self.assertEqual(result["verdict"], "reject")

    def test_research_lists_reject_nonclaim_entries(self) -> None:
        for value in (1, 1.5, True, None, []):
            with self.subTest(value=value):
                result, _ = self.evaluate("Research contradictions", json.dumps({"contradictions": ["Claim", value]}))
                rejection, = result["research_evidence_rejections"]
                self.assertEqual((rejection["code"], rejection["field"], rejection["item_index"]),
                                 ("invalid-list-item", "contradictions", 2))
                self.assertEqual(result["research_contradictions"], [])

    def test_numeric_markdown_citation_in_legacy_evidence_remains_prose(self) -> None:
        result, bundle = self.evaluate("Evidence", "[1] Packet policy identifies the review evidence requirements.")
        for output in (result, bundle):
            self.assertNotIn("research_evidence_rejections", output)
            self.assertFalse(output["research_evidence_present"])

    def test_unpaired_json_surrogates_do_not_reach_peer_evaluation_hash(self) -> None:
        for document in (r'{"\ud800": "Observation"}', r'{"note": "\udfff"}'):
            with self.subTest(document=document):
                result, _ = self.evaluate("Research reflection", document)
                rejection, = result["research_evidence_rejections"]
                self.assertEqual(rejection["code"], "invalid-json")
                self.assertEqual(len(pending_evaluation_sha256(result)), 64)
        result, _ = self.evaluate("Research reflection", r'{"note": "\ud83d\ude00"}')
        self.assertEqual(result["research_reflection"], {"note": "\U0001f600"})
        self.assertNotIn("research_evidence_rejections", result)

    def test_valid_fenced_legacy_evidence_keeps_integer_scores(self) -> None:
        item = {"claim": '[{"detail": "quoted bracket"}]' + "[" * MAX_RETURN_JSON_DEPTH,
                "reliability_score": 0, "relevance_score": 100}
        result, bundle = self.evaluate("Evidence", "```json\n" + json.dumps({"research_evidence_items": [item]}) + "\n```")
        for output in (result, bundle):
            self.assertEqual(output["research_evidence_items"], [item])
            self.assertNotIn("research_evidence_rejections", output)
