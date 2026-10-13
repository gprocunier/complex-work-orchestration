"""Public v3 propagation using synthetic qualification, never live authority."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.test_operative_routing import (
    ROOT, BUDGET, CONTEXT, NOW, capability_evidence, cache_profile, work_plan,
)
from cwo_core import operative_routing as routing
from cwo_core.routing import classify_work
from cwo_core.policy import load_policy
from tests.historical_policy_fixtures import historical_v2_policy


def synthetic_authority(model=routing.LUNA_MODEL):
    inputs = {
        'work_estimate': work_plan(requested_model=model, narrow=True),
        'cache_profile': cache_profile(total=8000, stable=4000),
        'capability_evidence': capability_evidence(),
        'context': copy.deepcopy(CONTEXT),
        'aggregate_budget': dict(BUDGET, allocation_before=7,
                                 allocation_ceiling=20, terminal_reserve=3),
    }
    identity = {k: 'b' * 64 for k in (
        'tool_profile_sha256', 'control_image_sha256', 'host_provenance_sha256')}
    qualifications = {
        m: dict(model=m, receipt_sha256='a'*64, canary_sha256='c'*64,
                origin_issued_at='2026-09-03T19:00:00Z',
                origin_expires_at='2026-09-03T19:45:00Z', **identity,
                command_sha256='d'*64, execution_sha256='e'*64, runner_sha256='f'*64)
        for m in routing.TASK_SELECTED_PORTFOLIO
    }
    return dict(version=1, fit_inputs=inputs,
        provenance={k:'a'*64 for k in (
            'source_sha256','context_sha256','scope_sha256','candidate_sha256')},
        attempt=dict(attempt_id='synthetic-attempt', bead_id=CONTEXT['bead_id'],
            work_lineage_id=CONTEXT['work_lineage_id'], ownership_sha256='b'*64,
            fresh_segment=True), attempt_state='ready', bound_model=model,
        identity=identity, qualifications=qualifications, escalation=None)


class PublicCurrentAuthorityTests(unittest.TestCase):
    def schema_check(self, route):
        # Optional dependency is a test convenience; production also runs the
        # closed stdlib validator, which is mandatory below.
        self.assertEqual(routing.validate_task_selected_route_shape(route), [])
        try:
            import jsonschema
        except ImportError:
            return
        schema = json.loads((ROOT/'schemas/operative-routing-state.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(route)

    def test_public_authorized_luna_positive_through_actual_evaluator(self):
        native = copy.deepcopy(load_policy('native-worker-execution'))
        native['task_selected_routing']['status'] = 'active'
        native['task_selected_routing']['activation'].update(active=True, dispatch_authority=True)
        original = routing.load_policy
        with patch.object(routing, 'load_policy', side_effect=lambda name:
                copy.deepcopy(native) if name == 'native-worker-execution' else original(name)):
            authority = synthetic_authority()
            route = classify_work('Bounded CWO implementation',
                current_authority=authority, operative_evaluated_at=NOW)['operative_route']
            self.assertEqual(route['version'], 3)
            self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
            self.assertEqual(route['selected_model'], routing.LUNA_MODEL)
            self.schema_check(route)
            self.assertEqual(routing.validate_operative_route_for_model(
                route, routing.LUNA_MODEL, current_authority=authority, now=NOW), [])

    def test_omitted_is_not_forwarded_as_private_sentinel(self):
        route = classify_work('Inspect existing historical route',
            operative_evaluated_at=NOW)['operative_route']
        self.assertEqual(route['version'], 3)
        self.assertFalse(route['dispatch_authorized'])
        self.assertEqual(route['stop_reason'], 'current-authority-missing')
        self.schema_check(route)

    def test_explicit_invalid_values_are_preserved_and_denied_without_fabrication(self):
        for value in (None, False, {}, [], 0, 'authority'):
            with self.subTest(value=value):
                route = classify_work('Bounded implementation', current_authority=value,
                    operative_evaluated_at=NOW)['operative_route']
                self.assertEqual(route['version'], 3)
                self.assertFalse(route['dispatch_authorized'])
                self.assertIsNone(route['selected_model'])
                self.assertIsNone(route['aggregate_budget'])
                self.schema_check(route)

    @historical_v2_policy()
    def test_inactive_policy_denies_otherwise_valid_current_claim(self):
        route = classify_work('Bounded implementation', current_authority=synthetic_authority(),
            operative_evaluated_at=NOW)['operative_route']
        self.assertFalse(route['dispatch_authorized'])
        self.assertEqual(route['stop_reason'], 'task-selected-policy-inactive')
        self.schema_check(route)

    def test_malformed_nested_fields_are_controlled(self):
        for field in ('qualifications', 'identity', 'provenance', 'attempt', 'fit_inputs'):
            for value in (None, False, 0, [], 'bad'):
                authority = synthetic_authority()
                authority[field] = value
                route = classify_work('Bounded implementation', current_authority=authority,
                    operative_evaluated_at=NOW)['operative_route']
                self.assertFalse(route['dispatch_authorized'], (field, value))
                self.assertEqual(route['stop_reason'], 'current-authority-invalid')


if __name__ == '__main__':
    unittest.main()
