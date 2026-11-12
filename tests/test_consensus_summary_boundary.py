"""Public-helper summary mutations, built from genuine evaluator output."""
import copy
import unittest

from tests.test_return_adjudication import table_scenario, table_mutation, adjudication, run, FIELD_TABLE, SUMMARY_FIELD_TABLE, ABSENT
from unittest import mock
from cwo_core.synthesis import evaluate_zero_trust_consensus


class SummaryBoundaryTests(unittest.TestCase):
    def scenario(self, external=False, peers_external=False, mode='dissent', shape='accepted'):
        s = table_scenario(shape, None, 'none', external, mode, peers_external)
        result = run(s['inputs'], s['records'], s['adjudications'], **s['arguments'])
        return s['inputs'], result['input_summaries']

    def check_restrictive(self, inputs, summaries):
        result = evaluate_zero_trust_consensus(inputs, summaries, required=True)
        self.assertIn(result['recommended_action'], ('block', 'quarantine', 'escalate'))
        self.assertNotEqual(result['consensus_status'], 'informational')

    def test_malformed_dissent_use_with_cleared_diagnostics(self):
        for external, peers_external in ((False, False), (True, True), (True, False), (False, True)):
            inputs, summaries = self.scenario(external, peers_external)
            self.check_restrictive(inputs, summaries)
            for value in (None, [], {}, '', 'unexpected', True, 7):
                with self.subTest(external=external, peers_external=peers_external, value=value):
                    mutated = copy.deepcopy(summaries)
                    mutated[2]['synthesis_use'] = value
                    mutated[2]['unresolved_data'] = []
                    self.check_restrictive(inputs, mutated)


    def test_collection_correspondence(self):
        inputs, summaries = self.scenario()
        variants = [None, {}, [], summaries[:1], summaries + [summaries[0]],
                    [summaries[0], summaries[1], summaries[1]], list(reversed(summaries)),
                    [summaries[0], summaries[1], None]]
        for value in variants:
            with self.subTest(value=value): self.check_restrictive(inputs, value)
        same_name = copy.deepcopy(inputs)
        same_name[2]['lane'] = same_name[0]['lane']
        swapped = [summaries[2], summaries[1], summaries[0]]
        for summary in swapped: summary['lane'] = same_name[0]['lane']
        self.check_restrictive(same_name, swapped)


    def test_summary_field_table_mutations(self):
        inputs, summaries = self.scenario()
        for row in SUMMARY_FIELD_TABLE:
            for value in row['malformed']:
                with self.subTest(where=row['where'], field=row['field'], value=value):
                    mutated = copy.deepcopy(summaries)
                    target = mutated[2]['dispatch_binding'] if row['where'] == 'summary-binding' else mutated[2]
                    if isinstance(value, str) and value == ABSENT:
                        target.pop(row['field'], None)
                    else:
                        target[row['field']] = copy.deepcopy(value)
                    self.check_restrictive(inputs, mutated)

    def test_original_input_errors_survive_cleared_summary_diagnostics(self):
        deciding = {'disposition', 'boundary_taint_status', 'boundary_status', 'share_boundary_status',
                    'provider_camp', 'provider_family', 'trust_domain', 'local_response_contract_status',
                    'local_completion_status', 'local_usable_final_content', 'local_normalized_return_matches',
                    'local_v2_frame_valid', 'local_v2_identity_consistent', 'local_response_model_status',
                    'local_model_preflight_status', 'local_http_status'}
        for external, peers_external in ((False, False), (True, True), (True, False), (False, True)):
            for shape in ('accepted', 'local-v2'):
                scenario = table_scenario(shape, None, 'none', external, 'dissent', peers_external)
                for row in FIELD_TABLE:
                    if row['where'] != 'input' or row['field'] not in deciding:
                        continue
                    if row['field'].startswith('local_') and shape != 'local-v2':
                        continue
                    for value in row['malformed']:
                        changed = table_mutation(scenario, row, value)
                        if changed is None:
                            continue
                        with self.subTest(shape=shape, field=row['field'], value=value, external=external):
                            result = run(changed['inputs'], changed['records'], changed['adjudications'], **changed['arguments'])
                            summaries = result['input_summaries']
                            # Clear caller diagnostics, not the supplied original input.
                            summaries[2]['unresolved_data'] = []
                            self.check_restrictive(changed['inputs'], summaries)

    def test_broker_underlying_must_be_direct_for_independence(self):
        from cwo_core import synthesis_inputs
        original_load = synthesis_inputs.load_policy
        for broker_flag in (True, 'unreadable', False):
            inputs, summaries = self.scenario()
            providers = copy.deepcopy(original_load('provider-registry'))
            providers['providers']['proxy-fixture'] = {'family': 'proxy', 'broker': True,
                                                       'underlying_providers': ['underlying-fixture']}
            providers['providers']['underlying-fixture'] = {'family': 'local-openai-compatible', 'broker': broker_flag}
            binding = summaries[2]['dispatch_binding']
            binding.update(provider_key='proxy-fixture', underlying_provider_key='underlying-fixture',
                           provider_family='local-openai-compatible')
            with mock.patch.object(synthesis_inputs, 'load_policy', side_effect=lambda name: providers if name == 'provider-registry' else original_load(name)):
                result = evaluate_zero_trust_consensus(inputs, summaries, required=True)
            third = result['trust_domain_summaries'][2]
            if broker_flag is False:
                self.assertTrue(third['included_for_independence'])
                self.assertEqual(result['independent_trust_domain_count'], 3)
            else:
                self.assertFalse(third['included_for_independence'])
                self.assertEqual(result['independent_trust_domain_count'], 2)
                self.assertEqual(result['consensus_status'], 'blocked')

    def test_available_adjudication_uncertainty_survives_cleared_diagnostics(self):
        scenario=table_scenario('accepted', None, 'none', False, 'dissent', False)
        scenario['adjudications']=[adjudication('unreadable-decision','d-ext',decision=None,evidence=[])]
        result=run(scenario['inputs'],scenario['records'],scenario['adjudications'],**scenario['arguments'])
        summaries=result['input_summaries']
        self.assertTrue(summaries[2]['adjudication_unresolved'])
        summaries[2]['unresolved_data']=[]
        self.check_restrictive(scenario['inputs'],summaries)


    def test_matching_optional_and_readable_exclusion_controls(self):
        for external, peers_external in ((False, False), (True, True), (True, False), (False, True)):
            inputs, summaries = self.scenario(external, peers_external, mode='matching')
            good = evaluate_zero_trust_consensus(inputs, summaries, required=True)
            self.assertEqual(good['consensus_status'], 'informational')
            self.assertEqual(good['recommended_action'], 'none')
        inputs, summaries = self.scenario()
        optional = evaluate_zero_trust_consensus(inputs, summaries[:2], required=False)
        self.assertFalse(optional['blocked_reasons'])
        self.assertFalse(optional['required'])
        inputs, summaries = self.scenario(shape='quarantined')
        excluded = evaluate_zero_trust_consensus(inputs, summaries, required=True)
        self.assertEqual(excluded['consensus_status'], 'informational')
        self.assertEqual(excluded['independent_trust_domain_count'], 2)

    def test_custom_producer_policy_round_trip(self):
        from cwo_core.synthesis_inputs import load_policy
        policy=copy.deepcopy(load_policy('synthesis-policy'))
        policy['input_disposition_policy']['use_as_synthesis_input'].append('reviewed')
        scenario=table_scenario('accepted',None,'none',False,'matching',False)
        for entry in scenario['inputs']:entry['disposition']='reviewed'
        produced=run(scenario['inputs'],scenario['records'],scenario['adjudications'],policy=policy,**scenario['arguments'])
        self.assertEqual(produced['status'],'ready')
        readback=evaluate_zero_trust_consensus(scenario['inputs'],produced['input_summaries'],required=True,synthesis_policy=policy)
        self.assertEqual(readback['consensus_status'],'informational')
        self.assertEqual(readback['recommended_action'],'none')
        self.assertEqual(readback['independent_trust_domain_count'],2)


    def test_missing_dissent_summary(self):
        for external, peers_external in ((False, False), (True, True), (True, False), (False, True)):
            inputs, summaries = self.scenario(external, peers_external)
            self.check_restrictive(inputs, summaries[:2])


    def test_binding_fields_cannot_drop_dissent(self):
        inputs, summaries = self.scenario()
        fields = {'bound': (None, 1, 'true', False), 'provenance_known': (None, 1, 'true', False),
                  'state': (None, [], 'absent', 'unknown'), 'attempted': (None, 1, False),
                  'dispatch_id': (None, [], 'another'), 'return_sha256': (None, [], 'f'*64),
                  'provider_family': (None, [], 'unknown')}
        for field, values in fields.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    mutated = copy.deepcopy(summaries)
                    mutated[2]['dispatch_binding'][field] = value
                    mutated[2]['unresolved_data'] = []
                    self.check_restrictive(inputs, mutated)

    def test_missing_null_wrong_type_and_diagnostic_clearing(self):
        inputs, summaries = self.scenario()
        for field in ('lane', 'synthesis_use', 'dispatch_binding', 'unresolved_data'):
            for value in ('ABSENT', None, [], {}, 7, True, 'unknown'):
                with self.subTest(field=field, value=value):
                    mutated = copy.deepcopy(summaries)
                    if value == 'ABSENT': mutated[2].pop(field)
                    else: mutated[2][field] = value
                    self.check_restrictive(inputs, mutated)


if __name__ == '__main__': unittest.main()
