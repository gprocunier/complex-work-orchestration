"""Current adjudication policy fields remain loadable under whole-document checks."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core import policy, policy_schema  # noqa: E402


class SynthesisAdjudicationSchemaTests(unittest.TestCase):
    def document(self):
        return json.loads((ROOT / "policy/synthesis-policy.yaml").read_text())

    def test_actual_accepted_policy_loads_unchanged(self):
        policy.clear_policy_cache()
        self.assertEqual(policy.load_policy("synthesis-policy"), self.document())

    def test_authority_without_documented_fields_and_unknown_fields_refuse(self):
        actual = self.document()
        for key in actual["adjudication_authority"]:
            with self.subTest(missing=key):
                value = copy.deepcopy(actual)
                del value["adjudication_authority"][key]
                self.assertTrue(policy_schema.policy_document_errors("synthesis-policy.yaml", value))
        value = copy.deepcopy(actual)
        value["adjudication_authority"]["accept_any_source"] = True
        self.assertTrue(policy_schema.policy_document_errors("synthesis-policy.yaml", value))

    def test_wrong_shapes_unknown_decisions_and_empty_prefix_refuse(self):
        for key, value in [("rule_id", True), ("decisions", ["execute"]),
                           ("clearable_hold_reasons", "all"),
                           ("clearable_hold_reason_prefixes", [""])]:
            with self.subTest(key=key, value=value):
                document = self.document()
                document["adjudication_authority"][key] = value
                self.assertTrue(policy_schema.policy_document_errors("synthesis-policy.yaml", document))

    def test_no_authority_or_no_clearable_reasons_is_still_conservative(self):
        document = self.document()
        document.pop("adjudication_authority")
        self.assertEqual(policy_schema.policy_document_errors("synthesis-policy.yaml", document), [])
        document = self.document()
        document["adjudication_authority"].update(clearable_hold_reasons=[], clearable_hold_reason_prefixes=[])
        self.assertEqual(policy_schema.policy_document_errors("synthesis-policy.yaml", document), [])


if __name__ == "__main__":
    unittest.main()
