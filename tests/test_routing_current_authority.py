"""Public role-based routing evaluated with offline capability evidence."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_operative_routing import (
    ROOT, BUDGET, CONTEXT, NOW, capability_evidence, cache_profile, work_plan,
)
from cwo_core import operative_routing as routing
from cwo_core import policy
from cwo_core.model_identities import operative_models, resolve_model
from cwo_core.routing import classify_work
from cwo_core.policy import load_policy
from cwo_core.work_sizing import evaluate_work_estimate
from prepare_native_worker import build_native_worker_packet, validate_native_worker_packet
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
    def assert_cli_and_packet_match(self, text, authority, route):
        model = route['selected_model']
        with tempfile.TemporaryDirectory() as workdir:
            path = Path(workdir) / 'current-authority.json'
            path.write_text(json.dumps(authority), encoding='utf-8')
            result = subprocess.run(
                [sys.executable, 'scripts/route_work.py', '--json', '--current-authority', str(path),
                 '--operative-evaluated-at', NOW, text], cwd=ROOT, capture_output=True, text=True, check=True,
            )
            self.assertEqual(json.loads(result.stdout)['operative_route'], route)
            with patch.object(routing, '_now_iso', return_value=NOW):
                packet = build_native_worker_packet(
                    bead_id=CONTEXT['bead_id'], lane='review', workdir=workdir, allowed_paths=['.'],
                    acceptance_checks=['Review the scoped assignment.'], requested_model=model,
                    operative_routing=route, current_authority=authority,
                )
                self.assertEqual(packet['requested_model'], model)
                self.assertEqual(validate_native_worker_packet(packet), [])
                dispatch_errors = validate_native_worker_packet(packet, dispatchable=True, current_authority=authority)
                self.assertIn('packet release state is operative-dispatch-forbidden', dispatch_errors)
                self.assertFalse(any(error.startswith('operative_routing:') for error in dispatch_errors), dispatch_errors)

    def test_coding_difficulty_escalates_to_sol(self):
        sol = resolve_model('sol')
        authority = synthetic_authority(sol)
        authority.pop('qualifications')
        inputs = authority['fit_inputs']
        inputs['work_estimate'] = work_plan(requested_model=sol)
        fit = routing.build_task_selected_fit(**inputs, evaluated_at=NOW)
        self.assertFalse(fit['classifications']['luna_fit'])
        authority['escalation'] = {
            'kind': 'fit', 'reason': 'The implementation exceeds the Luna sizing limits.',
            'evidence_sha256': 'c' * 64, 'fit_sha256': fit['fit_sha256'],
            'attempt_id': authority['attempt']['attempt_id'],
        }
        route = classify_work('Bounded CWO implementation', current_authority=authority,
                              operative_evaluated_at=NOW)['operative_route']
        self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
        self.assertEqual(route['selected_model'], sol)
        self.assertEqual(route['selected_executor'], 'internal_worker_sol')
        self.schema_check(route)
        self.assertEqual(routing.validate_operative_route_for_model(
            route, sol, current_authority=authority, now=NOW), [])
        self.assert_cli_and_packet_match('Bounded CWO implementation', authority, route)

        for invalid_escalation in (None, dict(authority['escalation'], fit_sha256='d' * 64)):
            with self.subTest(escalation=invalid_escalation):
                denied = routing.resolve_operative_route(
                    current_authority=dict(authority, escalation=invalid_escalation), evaluated_at=NOW)
                self.assertFalse(denied['dispatch_authorized'])
                self.assertTrue(denied['protected_stop'])

    def test_general_escalation_cannot_select_terra(self):
        terra = resolve_model('terra')
        authority = synthetic_authority(terra)
        inputs = authority['fit_inputs']
        inputs['work_estimate'] = work_plan(requested_model=terra)
        fit = routing.build_task_selected_fit(**inputs, evaluated_at=NOW)
        authority['escalation'] = {
            'kind': 'fit', 'reason': 'The implementation exceeds the Luna sizing limits.',
            'evidence_sha256': 'c' * 64, 'fit_sha256': fit['fit_sha256'],
            'attempt_id': authority['attempt']['attempt_id'],
        }
        result = classify_work('Computer use and visual work', current_authority=authority,
                               operative_evaluated_at=NOW)['operative_route']
        self.assertFalse(result['dispatch_authorized'])
        self.assertTrue(result['protected_stop'])
        self.assertIsNone(result['selected_model'])

    def test_explicit_interface_visual_or_computer_use_selects_terra(self):
        luna = resolve_model('luna')
        terra = resolve_model('terra')
        for work_kind in ('interface', 'visual', 'computer-use'):
            with self.subTest(work_kind=work_kind):
                authority = synthetic_authority(terra)
                inputs = authority['fit_inputs']
                inputs['work_estimate'] = evaluate_work_estimate(dict(inputs['work_estimate'], work_kind=work_kind))
                route = classify_work('Bounded task', current_authority=authority,
                                      operative_evaluated_at=NOW)['operative_route']
                self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
                self.assertEqual(route['selected_model'], terra)
                self.assertEqual(route['selected_executor'], 'internal_worker_terra')
                self.schema_check(route)
                self.assertEqual(routing.validate_operative_route_for_model(
                    route, terra, current_authority=authority, now=NOW), [])
                self.assert_cli_and_packet_match('Bounded task', authority, route)

                wrong_model = routing.resolve_operative_route(
                    current_authority=dict(authority, bound_model=luna), evaluated_at=NOW)
                self.assertFalse(wrong_model['dispatch_authorized'])
                inputs['work_estimate']['work_kind'] = 'interface' if work_kind != 'interface' else 'visual'
                self.assertTrue(routing.validate_operative_route_for_model(
                    route, terra, current_authority=authority, now=NOW))

    def test_malformed_work_kind_fails_closed(self):
        for work_kind in (None, True, ['interface'], 'Interface', 'interface ', 'coding'):
            with self.subTest(work_kind=work_kind):
                authority = synthetic_authority()
                estimate = authority['fit_inputs']['work_estimate']
                estimate['work_kind'] = work_kind
                with self.assertRaisesRegex(ValueError, 'work_kind'):
                    evaluate_work_estimate(estimate)
                route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
                self.assertFalse(route['dispatch_authorized'])
                self.assertTrue(route['protected_stop'])

        authority = synthetic_authority()
        authority['fit_inputs']['work_estimate'].update(estimate_contract_version=1, work_kind='visual')
        route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
        self.assertTrue(route['protected_stop'])

    def test_route_schema_accepts_a_version_four_stop_record(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is required to check the published route schema")
        route = classify_work('Bounded implementation', current_authority=None,
                              operative_evaluated_at=NOW)['operative_route']
        schema = json.loads((ROOT / 'schemas/operative-routing-state.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(route)

    def test_prior_v4_selector_remains_readable_but_cannot_authorize_dispatch(self):
        terra = resolve_model('terra')
        authority = synthetic_authority(terra)
        estimate = authority['fit_inputs']['work_estimate']
        authority['fit_inputs']['work_estimate'] = evaluate_work_estimate(dict(estimate, work_kind='visual'))
        route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
        route.pop('route_sha256')
        route.update(selector_version=1, role='escalation-only-operative-worker')
        route['route_sha256'] = routing._canonical_sha256(route)
        self.schema_check(route)
        self.assertEqual(routing.validate_operative_route_for_model(route, terra, historical_parse=True), [])
        self.assertEqual(routing.validate_operative_route_for_model(route, terra),
                         ['prior routing selector is parseable but requires fresh evidence for current dispatch'])

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

    def test_current_native_worker_effort_is_sealed_to_original_scope(self):
        authority = synthetic_authority()
        source = authority['fit_inputs']['work_estimate']
        authority['fit_inputs']['work_estimate'] = evaluate_work_estimate(
            dict(source, primary_outcome="Update the container isolation policy for worker processes."))
        route = routing.resolve_operative_route(current_authority=authority, evaluated_at=NOW)
        self.assertTrue(route['dispatch_authorized'], route['stop_reason'])
        self.assertEqual(route['reasoning_effort'], 'xhigh')
        self.assertIn('security-or-containment', route['selection_reason'])
        self.schema_check(route)
        model = route['selected_model']
        self.assertEqual(routing.validate_operative_route_for_model(
            route, model, current_authority=authority, now=NOW), [])
        route['reasoning_effort'] = 'high'
        route['route_sha256'] = routing._canonical_sha256({key: value for key, value in route.items()
                                                          if key != 'route_sha256'})
        self.assertIn('task selected route does not match current authority evaluation',
                      routing.validate_operative_route_for_model(route, model, current_authority=authority, now=NOW))

    def test_public_authorized_luna_positive_through_actual_evaluator(self):
        luna = resolve_model('luna')
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
