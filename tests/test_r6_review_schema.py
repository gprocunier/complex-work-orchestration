"""Structured review records and persisted separation match public schemas."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from cwo_core.audit import record_audit_event  # noqa: E402
from cwo_core.returns import make_acceptance_decision  # noqa: E402
from tests.f3_peer_review_fixtures import review_binding  # noqa: E402


class R6ReviewSchemaTests(unittest.TestCase):
    def test_r6_structured_record_and_actual_audit_separation_obey_public_schemas(self):
        """Catches stale v1/string schemas and missing bounded separation fields."""
        text = (ROOT / 'examples/sample-contractor-return.md').read_text()
        binding = review_binding(self, text, peer_review_required=True)
        passed = make_acceptance_decision(text, peer_review_required=True,
                                         peer_review_status='passed', **binding)
        audit = self._host_review_store.state_root.parent / 'schema-audit.jsonl'
        actual = record_audit_event({**passed, 'event_type': 'return_evaluated', 'bead_id': 'EXAMPLE_SCHEMA_REVIEW'}, audit)
        schemas = {name: json.loads((ROOT / 'schemas' / name).read_text()) for name in
                   ('peer-review-record.schema.json', 'audit-event.schema.json')}
        registry = Registry().with_resources((name, Resource.from_contents(schema))
                                             for name, schema in schemas.items())
        record_validator = Draft202012Validator(schemas['peer-review-record.schema.json'], registry=registry)
        audit_validator = Draft202012Validator(schemas['audit-event.schema.json'], registry=registry)
        record_validator.validate(passed['peer_review_record'])
        audit_validator.validate(actual)
        for field, invalid in (('reviewer_identity', 'EXAMPLE_LEGACY_REVIEWER'), ('version', 1)):
            changed = {**passed['peer_review_record'], field: invalid}
            self.assertTrue(list(record_validator.iter_errors(changed)), field)
        for field in passed['peer_review_reviewer']:
            changed = copy.deepcopy(passed['peer_review_record'])
            changed['reviewer_identity'][field] = 'x' * 129
            self.assertTrue(list(record_validator.iter_errors(changed)), field)
        changed = copy.deepcopy(actual)
        changed['peer_review_separation']['level'] = 'unrecorded'
        self.assertTrue(list(audit_validator.iter_errors(changed)))
