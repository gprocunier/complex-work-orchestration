"""Public role-based routing evaluated with offline capability evidence."""
import copy
import json
import unittest
from unittest.mock import patch

from tests.test_operative_routing import (
    ROOT, BUDGET, CONTEXT, NOW, capability_evidence, cache_profile, work_plan,
)
from cwo_core import operative_routing as routing
from cwo_core import policy
from cwo_core.model_identities import operative_models
from cwo_core.routing import classify_work
from cwo_core.policy import load_policy
from tests.historical_policy_fixtures import historical_v2_policy


def synthetic_authority(model=None):
    models = operative_models()
    if model is None:
        model = models[0]
    inputs = {
        'work_estimate': work_plan(requested_model=model, narrow=True),
        'cache_profile': cache_profile(total=8000, stable=4000),
        'capability_evidence': capability_evidence(operative_models=models),
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
        for m in models
    }
    return dict(version=1, fit_inputs=inputs,
        provenance={k:'a'*64 for k in (
            'source_sha256','context_sha256','scope_sha256','candidate_sha256')},
        attempt=dict(attempt_id='synthetic-attempt', bead_id=CONTEXT['bead_id'],
            work_lineage_id=CONTEXT['work_lineage_id'], ownership_sha256='b'*64,
            fresh_segment=True), attempt_state='ready', bound_model=model,
        identity=identity, qualifications=qualifications, escalation=None)


class PublicCurrentAuthorityTests(unittest.TestCase):
    def test_route_schema_accepts_a_version_four_stop_record(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is required to check the published route schema")
        route = classify_work('Bounded implementation', current_authority=None,
                              operative_evaluated_at=NOW)['operative_route']
        schema = json.loads((ROOT / 'schemas/operative-routing-state.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(route)

    def test_historical_v3_route_remains_exact_evidence(self):
        route = json.loads((ROOT / 'tests/fixtures/historical-operative-route-v3.json').read_text())
        model = route['selected_model']
        self.schema_check(route)
        self.assertEqual(routing.task_selected_policy_sha256(version=3), route['policy_sha256'])
        self.assertEqual(routing.validate_operative_route_for_model(
            route, model, historical_parse=True), [])
        self.assertEqual(routing.validate_operative_route_for_model(route, model),
                         ['historical v3 route is parseable but cannot authorize new dispatch'])
        self.assertEqual(routing.validate_operative_route_for_model(
            route, f'{model}-alias', historical_parse=True),
            ['task selected route selected_model does not match requested model'])

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
        luna, terra = operative_models()
        native = copy.deepcopy(load_policy('native-worker-execution'))
        native['task_selected_routing']['status'] = 'active'
        native['task_selected_routing']['activation'].update(active=True, dispatch_authority=True)
        original = routing.load_policy
        with patch.object(routing, 'load_policy', side_effect=lambda name:
                copy.deepcopy(native) if name == 'native-worker-execution' else original(name)):
            authority = synthetic_authority()
            route = classify_work('Bounded CWO implementation',
                current_authority=authority, operative_evaluated_at=NOW)['operative_route']
            self.assertEqual(route['version'], 4)
            self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
            self.assertEqual(route['selected_model'], luna)
            self.schema_check(route)
            self.assertEqual(routing.validate_operative_route_for_model(
                route, luna, current_authority=authority, now=NOW), [])

            authority = synthetic_authority(terra)
            authority['fit_inputs']['work_estimate'] = work_plan(requested_model=terra)
            fit = routing.build_task_selected_fit(**authority['fit_inputs'], evaluated_at=NOW)
            self.assertFalse(fit['classifications']['luna_fit'])
            authority['escalation'] = {
                'kind': 'fit', 'reason': 'Synthetic work outside the Luna-fit shape.',
                'evidence_sha256': 'c' * 64, 'fit_sha256': fit['fit_sha256'],
                'attempt_id': authority['attempt']['attempt_id'],
            }
            route = classify_work('Bounded CWO implementation', current_authority=authority,
                                  operative_evaluated_at=NOW)['operative_route']
            self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
            self.assertEqual(route['selected_model'], terra)
            self.schema_check(route)
            self.assertEqual(routing.validate_operative_route_for_model(
                route, terra, current_authority=authority, now=NOW), [])
            unrecorded = copy.deepcopy(authority)
            unrecorded['escalation'] = None
            refused = classify_work('Bounded CWO implementation', current_authority=unrecorded,
                                    operative_evaluated_at=NOW)['operative_route']
            self.assertFalse(refused['dispatch_authorized'])
            self.assertEqual(refused['stop_reason'], 'terra-selection-requires-recorded-escalation')

    def test_current_route_does_not_require_a_model_qualification(self):
        authority = synthetic_authority()
        authority.pop('qualifications')
        route = classify_work('Bounded implementation', current_authority=authority,
                              operative_evaluated_at=NOW)['operative_route']
        self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
        self.assertEqual(route['version'], 4)
        self.assertIsNone(route['qualification'])
        self.assertEqual(route['identity'], authority['identity'])
        self.assertEqual(routing.validate_operative_route_for_model(
            route, authority['bound_model'], current_authority=authority, now=NOW), [])
        errors = routing.validate_operative_route_for_model(
            route, authority['bound_model'], current_authority=authority,
            now='2026-09-03T20:15:01Z')
        self.assertEqual(errors, ['task selected route exact-model capability evidence is stale or missing'])

    def test_model_version_can_change_in_policy_alone(self):
        config = load_policy('model-roles')
        original = config['roles']['luna']['current']
        replacement = 'gpt-9.99-luna' if original == 'gpt-9.9-luna' else 'gpt-9.9-luna'
        config['roles']['luna']['current'] = replacement
        with patch.object(policy, 'load_policy', side_effect=lambda name:
                          copy.deepcopy(config) if name == 'model-roles' else load_policy(name)):
            authority = synthetic_authority()
            authority.pop('qualifications')
            route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
            self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
            self.assertEqual(route['selected_model'], replacement)
            self.schema_check(route)
            self.assertEqual(routing.validate_operative_route_for_model(
                route, replacement, current_authority=authority, now=NOW), [])
            self.assertEqual(routing.validate_operative_route_for_model(
                route, original, current_authority=authority, now=NOW),
                ['task selected route selected_model does not match requested model'])

            authority['bound_model'] = original
            denied = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
            self.assertFalse(denied['dispatch_authorized'])
            self.assertIsNone(denied['selected_model'])

    def test_capability_evidence_must_name_one_exact_model(self):
        for mutation in ('whitespace', 'duplicate'):
            with self.subTest(mutation=mutation):
                authority = synthetic_authority()
                models = authority['fit_inputs']['capability_evidence']['operative_models']
                luna = next(record for record in models if record['model'] == authority['bound_model'])
                if mutation == 'whitespace':
                    luna['model'] = ' ' + luna['model']
                else:
                    models.append(copy.deepcopy(luna))
                route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
                self.assertFalse(route['dispatch_authorized'])
                self.assertEqual(route['stop_reason'], 'current-authority-bound-model-ineligible')

    def test_generic_internal_worker_key_cannot_authorize_operative_dispatch(self):
        authority = synthetic_authority()
        route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
        model = authority['bound_model']
        self.assertEqual(route['selected_executor'], 'internal_worker_luna')
        self.assertEqual(routing.validate_operative_route_for_model(
            route, model, current_authority=authority, now=NOW), [])

        route['selected_executor'] = 'internal_worker'
        route.pop('route_sha256')
        route['route_sha256'] = routing._canonical_sha256(route)
        self.assertIn('task selected route shape: authorized route executor does not match model',
                      routing.validate_operative_route_for_model(
                          route, model, current_authority=authority, now=NOW))

    def test_omitted_is_not_forwarded_as_private_sentinel(self):
        route = classify_work('Inspect existing historical route',
            operative_evaluated_at=NOW)['operative_route']
        self.assertEqual(route['version'], 4)
        self.assertFalse(route['dispatch_authorized'])
        self.assertEqual(route['stop_reason'], 'current-authority-missing')
        self.schema_check(route)

    def test_explicit_invalid_values_are_preserved_and_denied_without_fabrication(self):
        for value in (None, False, {}, [], 0, 'authority'):
            with self.subTest(value=value):
                route = classify_work('Bounded implementation', current_authority=value,
                    operative_evaluated_at=NOW)['operative_route']
                self.assertEqual(route['version'], 4)
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
