"""Offline reliability checks for structured narrowing and retained risk."""
import dataclasses
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import prepare_risk_narrowing as narrowing  # noqa: E402
from cwo_core import adjudication_binding as binding  # noqa: E402
from cwo_core import adjudication_source as source  # noqa: E402
from cwo_core import policy, risk_features as risk  # noqa: E402
from tests.test_adjudication_source import SourceFixture  # noqa: E402
from tests.test_policy_current_effects import current_policy  # noqa: E402

_DEFAULT = object()


def clear_caches():
    policy.clear_policy_cache()
    risk._policy.cache_clear()


class ScopeFixture:
    """Declare fake task scope before creating any scope evidence or submission."""
    def __init__(self, root, *, original_text='Fix the typo in the production runbook README',
                 append_segments=(), raw_return=None, bind_support=False):
        self.root = root
        self.source_fixture = SourceFixture(root, raw_return=raw_return)
        self.bind_support = bind_support
        fixture = self.source_fixture
        self.task = narrowing.TaskExpectation(fixture.context, original_text,
            'documentation-edit', ('README.md', 'docs/EXAMPLE_RUNBOOK.md'), 'offline', append_segments)
        self.receipt = source.prepare_source(fixture.source, fixture.context, fixture.record,
            root, observed_support=fixture.support)
        for name in self.task.paths:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'# EXAMPLE runbook\n\nOffline spelling example for a production heading.\n')
        self.evidence_path = 'EXAMPLE_SCOPE_EVIDENCE.json'
        self.author(self.task)

    def author(self, task):
        """Produce real file observations for the already declared fake task."""
        support = self.source_fixture.support if self.bind_support else ()
        self.value = narrowing.scope_evidence(self.root, self.receipt, task,
            ('environment:production',), observed_support=support)
        self.raw = binding._json(self.value)
        (self.root / self.evidence_path).write_bytes(self.raw)
        self.observation = narrowing.observe_scope(self.root, self.evidence_path, self.receipt, task,
            observed_support=support)
        self.record = narrowing.record_for(self.observation)


class RiskNarrowingTests(unittest.TestCase):
    def setUp(self):
        clear_caches()
        self.home = self.enterContext(current_policy())
        self.addCleanup(clear_caches)
        self.fixture = ScopeFixture(self.home)
        self.narrowed_use = mock.Mock()

    def project(self, *, task=None, receipt=None, record=_DEFAULT, observation=_DEFAULT):
        fixture = self.fixture
        task = fixture.task if task is None else task
        result = narrowing.prepare(fixture.receipt if receipt is None else receipt, task,
            fixture.record if record is _DEFAULT else record, self.home,
            observation=fixture.observation if observation is _DEFAULT else observation)
        for name in ('production_ready', 'effect_authority', 'accepted_for_use', 'trusted_host_authority'):
            self.assertIs(result[name], False)
        self.assertIs(result['implementation_blocked'], True)
        self.assertEqual(result['original_assessment'], binding._parse(task.assessment_bytes))
        if result['narrowing_valid']:
            self.narrowed_use(result['effective_assessment'])
        return result

    def refused(self, **kwargs):
        result = self.project(**kwargs)
        self.assertFalse(result['narrowing_valid'])
        self.assertTrue(result['errors'])
        self.assertEqual(result['effective_assessment'], result['original_assessment'])
        self.assertEqual(result['resolved_feature_ids'], [])
        self.assertEqual(result['unresolved_feature_ids'],
            [row['feature'] for row in result['original_assessment']['features']])
        self.narrowed_use.assert_not_called()
        return result

    def observation_refused(self, *, path=None, task=None, receipt=None):
        fixture = self.fixture
        with self.assertRaises(narrowing._REFUSALS):
            narrowing.observe_scope(self.home, fixture.evidence_path if path is None else path,
                fixture.receipt if receipt is None else receipt, fixture.task if task is None else task)
        self.narrowed_use.assert_not_called()

    def assert_invalid_source(self, result):
        view = result['source']
        self.assertIs(view['source_valid'], False)
        self.assertIs(view['inert_valid'], False)
        self.assertNotEqual(view['decision'], 'accepted')
        self.assertEqual(view['resolved_findings'], [])
        self.assertEqual(view['remaining_holds'], self.fixture.source_fixture.result['hold_reasons'])
        self.assertIsNone(view['provenance'])
        self.assertTrue(view['errors'])
        for error in view['errors']:
            self.assertIn(error, result['errors'])

    def test_useful_docs_view_uses_actual_source_evaluator_and_floor(self):
        with mock.patch.object(binding, 'observe_evaluation', wraps=binding.observe_evaluation) as evaluator, \
                mock.patch.object(source, 'prepare_source', wraps=source.prepare_source) as preparer, \
                mock.patch.object(source, 'consume_source', wraps=source.consume_source) as consumer, \
                mock.patch.object(risk, 'assess_risk_features', wraps=risk.assess_risk_features) as assessor, \
                mock.patch.object(risk, '_floor', wraps=risk._floor) as floor:
            self.fixture = ScopeFixture(self.home)
            result = self.project()
        evaluator.assert_called_once()
        preparer.assert_called_once()
        self.assertGreater(consumer.call_count, 0)
        self.assertGreater(assessor.call_count, 0)
        floor.assert_any_call([])
        self.assertTrue(result['narrowing_valid'])
        self.assertEqual(result['original_assessment']['floor'], 'medium')
        self.assertEqual(result['resolved_feature_ids'], ['environment:production'])
        self.assertIsNone(result['effective_assessment']['floor'])
        self.assertEqual(result['effective_assessment']['required_experts'], [])
        self.assertEqual(result['effective_assessment']['features'], [])
        self.assertEqual(result['source']['evaluation'], self.fixture.source_fixture.result)
        self.assertEqual(result['source']['provenance']['provider_family'], 'anthropic')
        self.assertEqual(self.fixture.observation.evidence_bytes,
            (self.home / self.fixture.evidence_path).read_bytes())
        self.narrowed_use.assert_called_once_with(result['effective_assessment'])

    def test_production_actions_and_docs_flags_cannot_lower_risk(self):
        cases = (
            ('Migrate the production database and rotate credentials', 'migration'),
            ('Rotate production credentials', 'credential-rotation'),
            ('Add OIDC login to the production service', 'authentication-change'),
        )
        for text, action in cases:
            task = dataclasses.replace(self.fixture.task, original_text=text, action=action,
                environment='production', append_segments=(' Only edit README docs.',))
            with self.subTest(action=action):
                self.observation_refused(task=task)
                result = self.refused(task=task)
                self.assertEqual(result['effective_assessment']['floor'], 'high')
                flagged = dict(self.fixture.record, file_paths=['README.md'], stage='docs', docs_only=True)
                self.refused(task=task, record=flagged)
                with self.assertRaises(narrowing._REFUSALS):
                    narrowing.scope_evidence(self.home, self.fixture.receipt, task, ('environment:production',))
        with self.assertRaisesRegex(narrowing.CWOError, 'risk narrowing is not supported'):
            risk.refuse_risk_narrowing(risk_scope={'action': 'documentation-edit'})

    def test_json_self_hash_labels_and_generic_prose_are_insufficient(self):
        self.refused(observation=None)
        self.refused(observation=dict(self.fixture.record))
        for fields in ({'source_qualified': True}, {'status': 'accepted'}, {'stage': 'docs'},
                       {'trusted_host_authority': True}, {'version': True}, {'version': 1.0}):
            with self.subTest(fields=tuple(fields)):
                self.refused(record=dict(self.fixture.record, **fields))
        path = self.home / self.fixture.evidence_path
        path.write_bytes(b'EXAMPLE documentation production accepted source-qualified.\n')
        self.observation_refused()
        record = dict(self.fixture.record, evidence_sha256=binding._sha(path.read_bytes()))
        self.refused(record=record)

    def test_descriptor_bounds_refuse_before_serialization_or_parsing(self):
        deep = 'EXAMPLE_LEAF'
        for _ in range(binding.MAX_JSON_DEPTH + 1):
            deep = [deep]
        large = 'EXAMPLE_VALUE' * (binding.MAX_SUPPORT_BYTES // 8)
        cases = (
            dict(self.fixture.record, EXAMPLE_extra=large),
            dict(self.fixture.record, evidence_path=large),
            dict(self.fixture.record, evidence_sha256=large),
            dict(self.fixture.record, resolved_feature_ids=[large]),
            dict(self.fixture.record, resolved_feature_ids=['EXAMPLE_ID'] * (binding.MAX_SUPPORT_FILES + 1)),
            {f'EXAMPLE_FIELD_{index}': None for index in range(binding.MAX_SUPPORT_FILES + 1)},
            dict(self.fixture.record, EXAMPLE_extra=deep),
            dict(self.fixture.record, evidence_path=deep),
            dict(self.fixture.record, resolved_feature_ids=[deep]),
        )
        for index, record in enumerate(cases):
            with self.subTest(case=index):
                with mock.patch.object(binding, '_json', wraps=binding._json) as serializer, \
                        mock.patch.object(binding, '_parse', wraps=binding._parse) as parser:
                    with self.assertRaises(narrowing._REFUSALS):
                        narrowing._snapshot_descriptor(record)
                    serializer.assert_not_called()
                    parser.assert_not_called()
                with mock.patch.object(narrowing, '_snapshot_descriptor',
                        wraps=narrowing._snapshot_descriptor) as snapshot:
                    self.refused(record=record)
                snapshot.assert_called_once_with(record)

    def test_descriptor_primitive_types_and_encoded_byte_bound_refuse(self):
        cases = (
            {'version': False}, {'version': 0}, {'version': 0.0}, {'version': 1.0},
            {'record_type': b'EXAMPLE_RECORD'}, {'evidence_path': None},
            {'source_binding_sha256': 1}, {'resolved_feature_ids': ('environment:production',)},
            {'resolved_feature_ids': []}, {'resolved_feature_ids': [True]},
            {'resolved_feature_ids': [1.0]}, {'resolved_feature_ids': ['EXAMPLE_ID', 'EXAMPLE_ID']},
        )
        for index, fields in enumerate(cases):
            with self.subTest(case=index):
                self.refused(record=dict(self.fixture.record, **fields))
        with mock.patch.object(narrowing, '_MAX_DESCRIPTOR_BYTES', 1):
            with mock.patch.object(binding, '_json', wraps=binding._json) as serializer, \
                    mock.patch.object(binding, '_parse', wraps=binding._parse) as parser:
                with self.assertRaisesRegex(ValueError, 'reliability descriptor snapshot exceeds'):
                    narrowing._snapshot_descriptor(self.fixture.record)
                serializer.assert_called_once()
                parser.assert_not_called()
            self.refused()

    def test_every_independent_context_field_and_task_dimension_is_bound(self):
        for name in dataclasses.asdict(self.fixture.task.context):
            value = binding._sha(b'EXAMPLE_OTHER_PACKET') if name == 'packet_sha256' else 'EXAMPLE_OTHER'
            context = dataclasses.replace(self.fixture.task.context, **{name: value})
            with self.subTest(context=name):
                self.refused(task=dataclasses.replace(self.fixture.task, context=context))
        changes = ({'original_text': self.fixture.task.original_text + ' EXAMPLE spelling note.'},
            {'append_segments': (' EXAMPLE offline spelling note.',)},
            {'action': 'migration'}, {'environment': 'production'}, {'paths': ('docs/EXAMPLE_OTHER.md',)})
        for change in changes:
            with self.subTest(task=tuple(change)):
                self.refused(task=dataclasses.replace(self.fixture.task, **change))

    def test_scope_evidence_bytes_and_binding_rejection_matrix(self):
        rows: list[tuple[str, dict, bytes, dict]] = []
        original_id = 'test_each_evidence_binding_dimension_requires_actual_matching_bytes'
        dimensions = [('task', key) for key in self.fixture.value['task']]
        dimensions += [('source', key) for key in self.fixture.value['source']]
        for section, key in dimensions:
            value = binding._parse(self.fixture.raw)
            value[section][key] = 'EXAMPLE_CONFLICT'
            raw = binding._json(value)
            rows.append((original_id, {'section': section, 'field': key}, raw,
                         dict(self.fixture.record, evidence_sha256=binding._sha(raw))))
        for key in ('risk_policy_sha256', 'original_assessment_sha256'):
            value = binding._parse(self.fixture.raw)
            value[key] = binding._sha(b'EXAMPLE_OTHER_BYTES')
            rows.append((original_id, {'field': key}, binding._json(value), self.fixture.record))
        original_id = 'test_document_manifest_and_resolution_claims_must_match_exact_scope'
        for key, replacement in (('documents', []), ('documents', [self.fixture.value['documents'][0]] * 2),
                ('resolutions', [{'feature_id': 'environment:production', 'resolution': 'accepted',
                                  'paths': ['README.md']}])):
            value = binding._parse(self.fixture.raw)
            value[key] = replacement
            rows.append((original_id, {'field': key, 'replacement': replacement}, binding._json(value), self.fixture.record))
        original_id = 'test_strict_scope_json_and_duplicate_keys_refuse'
        cases = (b'', b'{', b'[]', b'null', b'{"x":NaN}', b'{"x":1e309}', b'\xff',
            b'{"resolutions":[],"resolutions":[]}', b'[' * 65 + b']' * 65)
        for index, raw in enumerate(cases):
            rows.append((original_id, {'case': index}, raw, self.fixture.record))
        for original_id, labels, raw, record in rows:
            (self.home / self.fixture.evidence_path).write_bytes(raw)
            with self.subTest(original_id=original_id, **labels):
                self.observation_refused()
                self.refused(record=record)

    def test_resolution_rows_reject_unknown_absent_duplicate_and_unsupported_features(self):
        rows = ([], [{'feature_id': 'EXAMPLE_UNKNOWN'}], [{'feature_id': 'asset:database'}],
            [{'feature_id': 'environment:production'}] * 2, [{'feature_id': None}], [None], 'EXAMPLE_ROW')
        for resolutions in rows:
            value = binding._parse(self.fixture.raw)
            value['resolutions'] = resolutions
            (self.home / self.fixture.evidence_path).write_bytes(binding._json(value))
            self.observation_refused()
            self.refused()
        self.fixture = ScopeFixture(self.home,
            original_text='Fix the typo in production credentials documentation')
        value = binding._parse(self.fixture.raw)
        value['resolutions'][0]['feature_id'] = 'asset:credentials'
        (self.home / self.fixture.evidence_path).write_bytes(binding._json(value))
        result = self.refused()
        self.assertIn('unsupported risk reduction rows: asset:credentials', result['errors'][0])
        self.assertIn('asset:credentials', result['unresolved_feature_ids'])


    def test_scope_paths_and_empty_scope_are_refused(self):
        for paths in ((), ('README.md', 'README.md'), ('../README.md',), ('/README.md',)):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                dataclasses.replace(self.fixture.task, paths=paths)
        for paths in (('scripts/EXAMPLE.md',), ('docs/EXAMPLE.py',)):
            task = dataclasses.replace(self.fixture.task, paths=paths)
            self.observation_refused(task=task)
            self.refused(task=task)
        for record in ({}, [], None, {'action': 'documentation-edit'}):
            self.refused(record=record)

    def test_changed_missing_oversized_and_symlink_support_restores_original_risk(self):
        names = (self.fixture.evidence_path, self.fixture.task.paths[0])
        for name in names:
            path = self.home / name
            raw = path.read_bytes()
            for replacement in (raw + b'\n', b' ' * (binding.MAX_SUPPORT_BYTES + 1)):
                path.write_bytes(replacement)
                self.refused()
            path.unlink()
            self.observation_refused()
            self.refused()
            target = self.home / 'EXAMPLE_TARGET'
            target.write_bytes(raw)
            path.symlink_to(target)
            self.observation_refused()
            self.refused()
            path.unlink()
            path.write_bytes(raw)

    def test_unreadable_support_and_invalid_selected_paths_refuse(self):
        reader = binding.read_support
        for name in (self.fixture.evidence_path, *self.fixture.task.paths):
            def unreadable(root, selected, blocked=name):
                if selected == blocked:
                    raise PermissionError('EXAMPLE reliability read refused')
                return reader(root, selected)
            with mock.patch.object(binding, 'read_support', side_effect=unreadable):
                self.observation_refused()
                self.refused()
        for path in ('../EXAMPLE_SCOPE_EVIDENCE.json', str(self.home / self.fixture.evidence_path),
                     '', '.', 'EXAMPLE_MISSING.json'):
            self.observation_refused(path=path)
        observed = dataclasses.replace(self.fixture.observation, evidence_path='EXAMPLE_MISSING.json')
        self.refused(observation=observed)

    def test_parent_symlink_and_nonregular_support_refuse(self):
        directory = self.home / 'docs'
        target = self.home / 'EXAMPLE_DOCUMENTS'
        directory.rename(target)
        directory.symlink_to(target, target_is_directory=True)
        self.observation_refused()
        self.refused()
        directory.unlink()
        target.rename(directory)
        path = self.home / self.fixture.evidence_path
        path.unlink()
        path.mkdir()
        self.observation_refused()
        self.refused()


    def test_current_dispatch_and_receipt_dependencies_are_rechecked(self):
        fixture = self.fixture.source_fixture
        path = self.home / fixture.path
        raw = path.read_bytes()
        path.write_bytes(raw + b'\n')
        with mock.patch.object(narrowing, '_dispatch_scope', wraps=narrowing._dispatch_scope) as dispatch_scope:
            result = self.refused()
        dispatch_scope.assert_not_called()
        self.assert_invalid_source(result)
        path.unlink()
        self.refused()
        path.write_bytes(raw)
        receipt = self.fixture.receipt
        changed = dataclasses.replace(receipt.source.evaluation, raw_return=b'EXAMPLE_OTHER_RETURN')
        altered = dataclasses.replace(receipt.source, evaluation=changed)
        for bad in (dataclasses.replace(receipt, source=altered),
                dataclasses.replace(receipt, binding_bytes=b'{}'), 'EXAMPLE_MALFORMED_RECEIPT'):
            self.refused(receipt=bad)
        for name in dataclasses.asdict(fixture.context):
            changed_dispatch = dict(fixture.dispatch)
            changed_dispatch[name] = 'EXAMPLE_DISPATCH_CONFLICT'
            fixture.write_dispatch(changed_dispatch)
            self.refused()
        path.write_bytes(raw)

    def rebound_source(self, observed):
        fixture = self.fixture.source_fixture
        record = binding._parse(binding._json(fixture.record))
        record['evaluation_sha256'] = observed.evaluation.evaluation_sha256
        support = []
        for item in fixture.support:
            value = binding._parse(item.raw)
            value.update(context=dataclasses.asdict(observed.context),
                return_sha256=observed.evaluation.return_sha256,
                evaluation_sha256=observed.evaluation.evaluation_sha256)
            raw = binding._json(value)
            (self.home / item.artifact).write_bytes(raw)
            support.append(binding.SupportObservation(item.artifact, item.finding_id, raw))
            for entry in record['supporting_evidence']:
                if entry['artifact'] == item.artifact:
                    entry['sha256'] = binding._sha(raw)
        return source.prepare_source(observed, fixture.context, record,
            self.home, observed_support=tuple(support))

    def test_conflicting_actual_dispatch_scope_cannot_override_independent_task(self):
        fixture = self.fixture.source_fixture
        for name, value in (('action', 'migration'), ('environment', 'production'),
                            ('paths', ['scripts/EXAMPLE.py']), ('original_text', 'EXAMPLE_OTHER_TASK'),
                            ('append_segments', [' EXAMPLE_OTHER_APPEND'])):
            fixture.write_dispatch(dict(fixture.dispatch, **{name: value}))
            observed = source.observe_source(self.home, fixture.path, fixture.raw_return, fixture.context)
            receipt = self.rebound_source(observed)
            joined = source.consume_source(receipt, fixture.context, self.home)
            self.assertIs(joined['source_valid'], True)
            self.assertEqual(joined['decision'], 'accepted')
            self.assertEqual(joined['adjudication_restrictions'], [])
            with mock.patch.object(narrowing, '_dispatch_scope',
                    wraps=narrowing._dispatch_scope) as dispatch_scope:
                result = self.refused(receipt=receipt)
            dispatch_scope.assert_called_once_with(receipt, self.fixture.task)
            self.assertIn('actual dispatch conflicts with independent risk task: ' + name, result['errors'])
            self.observation_refused(receipt=receipt)
        fixture.write_dispatch()

    def test_risk_policy_bytes_schema_cache_and_source_policies_are_current(self):
        path = policy.POLICY_DIR / 'risk-features.yaml'
        original = path.read_bytes()
        for raw in (original + b'\n', b'{', b'{}', b'{"features":{},"features":{}}'):
            path.write_bytes(raw)
            clear_caches()
            self.observation_refused()
            self.refused()
        path.write_bytes(original)
        clear_caches()
        narrowing._risk_policy()
        document = binding._parse(original)
        document['features']['environment:production']['floor'] = 'high'
        path.write_bytes(binding._json(document))
        self.refused()
        path.write_bytes(original)
        clear_caches()
        for name in binding.POLICIES:
            path = policy.POLICY_DIR / (name + '.yaml')
            raw = path.read_bytes()
            path.write_bytes(raw + b'\n')
            clear_caches()
            with self.subTest(policy=name):
                self.refused()
            path.write_bytes(raw)
            clear_caches()

    def test_fresh_task_rejects_numeric_policy_versions_with_warm_caches(self):
        path = policy.POLICY_DIR / 'risk-features.yaml'
        original = path.read_bytes()
        loaded = policy._load_policy_cached('risk-features.yaml')
        assessed = risk._policy()
        loaded_bytes, assessed_bytes = binding._json(loaded), binding._json(assessed)
        for version in (True, 1.0, False, 0, 0.0):
            document = binding._parse(original)
            document['version'] = version
            path.write_bytes(binding._json(document))
            with self.subTest(version_type=type(version).__name__, version=version):
                with self.assertRaises(narrowing._REFUSALS):
                    dataclasses.replace(self.fixture.task)
                self.assertEqual(binding._json(loaded), loaded_bytes)
                self.assertEqual(binding._json(assessed), assessed_bytes)
                self.assertEqual(binding._json(policy.load_policy('risk-features')), loaded_bytes)
                self.assertIs(risk._policy(), assessed)
        path.write_bytes(original)
        self.assertEqual(dataclasses.replace(self.fixture.task), self.fixture.task)
        self.assertEqual(binding._json(loaded), loaded_bytes)
        self.assertEqual(binding._json(assessed), assessed_bytes)

    def test_both_policy_cache_representations_use_strict_json_comparison(self):
        original = (policy.POLICY_DIR / 'risk-features.yaml').read_bytes()
        for owner, name in ((policy, 'load_policy'), (risk, '_policy')):
            for version in (True, 1.0):
                document = binding._parse(original)
                document['version'] = version
                with self.subTest(cache=name, version_type=type(version).__name__):
                    with mock.patch.object(owner, name, return_value=document):
                        with self.assertRaisesRegex(ValueError, 'reliability policy cache differs'):
                            dataclasses.replace(self.fixture.task)
        self.assertEqual(dataclasses.replace(self.fixture.task), self.fixture.task)

    def test_current_policy_schema_runs_even_when_both_cache_values_match(self):
        path = policy.POLICY_DIR / 'risk-features.yaml'
        original = path.read_bytes()
        for version in (True, 1.0):
            document = binding._parse(original)
            document['version'] = version
            path.write_bytes(binding._json(document))
            with mock.patch.object(policy, 'load_policy', return_value=document), \
                    mock.patch.object(risk, '_policy', return_value=document):
                with self.assertRaisesRegex(ValueError, 'does not match schemas/risk-features'):
                    dataclasses.replace(self.fixture.task)
        path.write_bytes(original)
        self.assertEqual(dataclasses.replace(self.fixture.task), self.fixture.task)

    def test_rejected_quarantined_and_malformed_source_never_narrow(self):
        fixture = self.fixture.source_fixture
        for decision in ('rejected', 'quarantined', 'EXAMPLE_MALFORMED_DECISION'):
            record = dict(fixture.record, decision=decision, supporting_evidence=[])
            receipt = source.prepare_source(fixture.source, fixture.context, record,
                self.home, observed_support=())
            self.observation_refused(receipt=receipt)
            result = self.refused(receipt=receipt)
            if decision != 'EXAMPLE_MALFORMED_DECISION':
                self.assertEqual(result['source']['decision'], decision)
                self.assertIn(decision, result['source']['adjudication_restrictions'])
                path = self.home / fixture.path
                raw = path.read_bytes()
                path.write_bytes(raw + b'\n')
                try:
                    invalid = self.refused(receipt=receipt)
                    self.assert_invalid_source(invalid)
                    self.assertEqual(invalid['source']['decision'], decision)
                    self.assertIn(decision, invalid['source']['adjudication_restrictions'])
                finally:
                    path.write_bytes(raw)

    def test_appends_require_exact_new_evidence_and_keep_new_risky_features(self):
        task = self.fixture.task
        for append in (' EXAMPLE spelling note.', ' Inspect OIDC.'):
            task = dataclasses.replace(task, append_segments=(*task.append_segments, append))
            self.refused(task=task, observation=None)
            self.refused(task=task)
            self.fixture.author(task)
            result = self.project(task=task)
            self.assertEqual(result['resolved_feature_ids'], ['environment:production'])
            if 'asset:authentication' in result['unresolved_feature_ids']:
                self.assertEqual(result['effective_assessment']['floor'], 'high')
                self.assertIn('security', result['effective_assessment']['required_experts'])
            self.narrowed_use.reset_mock()
        self.assertIn('asset:authentication', result['unresolved_feature_ids'])

    def test_feature_formed_in_append_history_survives_supported_partial_resolution(self):
        self.fixture = ScopeFixture(self.home, original_text='Inspect EXAMPLE OI',
            append_segments=('DC', 's in production documentation.'))
        result = self.project()
        self.assertIn('asset:authentication', result['unresolved_feature_ids'])
        self.assertIn('security', result['effective_assessment']['required_experts'])
        self.assertEqual(result['effective_assessment']['floor'], 'high')
        self.assertTrue(all(row['resolved'] is None for row in result['original_assessment']['features']))

    def test_change_during_support_read_and_saved_state_replacement_refuse(self):
        reader = binding.read_support
        path = self.home / self.fixture.source_fixture.path
        raw = path.read_bytes()
        def interleave(root, name):
            observed = reader(root, name)
            if name == self.fixture.task.paths[0]:
                path.write_bytes(raw + b'\n')
            return observed
        with mock.patch.object(binding, 'read_support', side_effect=interleave):
            result = self.refused()
        self.assert_invalid_source(result)
        path.write_bytes(raw)
        observed = dataclasses.replace(self.fixture.observation, evidence_bytes=b'{}')
        self.refused(observation=observed)
        observed = dataclasses.replace(self.fixture.observation, document_bytes=(b'EXAMPLE_OTHER_BYTES',))
        self.refused(observation=observed)
        observed = dataclasses.replace(self.fixture.observation, source_binding_bytes=b'{}')
        self.refused(observation=observed)

    def test_evidence_parse_failure_keeps_latest_source_refusal(self):
        reader = binding.read_support
        path = self.home / self.fixture.source_fixture.path
        raw = path.read_bytes()
        (self.home / self.fixture.evidence_path).write_bytes(b'{')
        def interleave(root, name):
            observed = reader(root, name)
            if name == self.fixture.evidence_path:
                path.write_bytes(raw + b'\n')
            return observed
        with mock.patch.object(binding, 'read_support', side_effect=interleave):
            result = self.refused()
        self.assert_invalid_source(result)

    def test_descriptor_failure_still_rechecks_actual_source(self):
        snapshot = narrowing._snapshot_descriptor
        path = self.home / self.fixture.source_fixture.path
        raw = path.read_bytes()
        def interleave(record):
            path.write_bytes(raw + b'\n')
            return snapshot(record)
        with mock.patch.object(narrowing, '_snapshot_descriptor', side_effect=interleave):
            result = self.refused(record={})
        self.assert_invalid_source(result)

    def test_detected_source_invalidation_survives_later_file_restoration(self):
        reader = binding.read_support
        consume = source.consume_source
        path = self.home / self.fixture.source_fixture.path
        raw = path.read_bytes()
        refusals = []
        def interleave(root, name):
            observed = reader(root, name)
            if name == self.fixture.task.paths[0]:
                path.write_bytes(raw + b'\n')
            return observed
        def restore(receipt, context, root):
            view = consume(receipt, context, root)
            if view['source_valid'] is not True:
                refusals.append(view)
                path.write_bytes(raw)
            return view
        with mock.patch.object(binding, 'read_support', side_effect=interleave), \
                mock.patch.object(source, 'consume_source', side_effect=restore):
            result = self.refused()
        self.assert_invalid_source(result)
        self.assertTrue(refusals)
        for view in refusals:
            for error in view['errors']:
                self.assertIn(error, result['source']['errors'])
                self.assertIn(error, result['errors'])

    def test_observations_and_original_results_are_immutable_snapshots(self):
        for obj, name, value in ((self.fixture.observation, 'evidence_bytes', b'{}'),
                (self.fixture.task, 'original_text', 'EXAMPLE_OTHER_TASK')):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(obj, name, value)
        with self.assertRaises(ValueError):
            dataclasses.replace(self.fixture.observation, document_bytes=([b'EXAMPLE_MUTABLE'],))
        result = self.project()
        result['original_assessment']['features'].clear()
        self.fixture.record['version'] = 'EXAMPLE_CHANGED'
        self.narrowed_use.reset_mock()
        result = self.project(record=narrowing.record_for(self.fixture.observation))
        self.assertEqual(len(result['original_assessment']['features']), 1)
        self.assertEqual(result['source']['evaluation'], self.fixture.source_fixture.result)


class OfflineRiskPlanTests(unittest.TestCase):
    def setUp(self):
        clear_caches()
        self.home = self.enterContext(current_policy())
        self.addCleanup(clear_caches)
        self.fixture = ScopeFixture(self.home, bind_support=True)

    def plan(self, **changes):
        fixture = self.fixture
        arguments = dict(receipt=fixture.receipt, task=fixture.task, record=fixture.record,
            root=self.home, observation=fixture.observation,
            observed_support=fixture.source_fixture.support)
        arguments.update(changes)
        return narrowing.plan_offline(**arguments)

    def test_actual_current_caller_returns_useful_lower_risk_plan(self):
        with mock.patch.object(narrowing, '_risk_plan', wraps=narrowing._risk_plan) as planner, \
                mock.patch.object(risk, 'assess_risk_features', wraps=risk.assess_risk_features) as assessor, \
                mock.patch.object(narrowing, 'ensure_risk_feature_experts',
                    wraps=narrowing.ensure_risk_feature_experts) as experts:
            result = self.plan()
        planner.assert_called_once()
        self.assertGreater(assessor.call_count, 0)
        experts.assert_called_once()
        self.assertTrue(result['offline_plan_ready'])
        self.assertEqual(result['original_assessment']['floor'], 'medium')
        self.assertIsNone(result['effective_assessment']['floor'])
        self.assertEqual(result['plan']['risk'], 'low')
        self.assertEqual(result['plan']['required_experts'], [])
        self.assertEqual(result['plan']['paths'], list(self.fixture.task.paths))
        self.assertEqual(result['plan']['risk_assessment'], result['effective_assessment'])
        for name in ('production_ready', 'effect_authority', 'accepted_for_use', 'trusted_host_authority'):
            self.assertIs(result[name], False)
        self.assertIs(result['implementation_blocked'], True)

    def refused(self, **changes):
        result = self.plan(**changes)
        self.assertFalse(result['offline_plan_ready'])
        self.assertIsNone(result['plan'])
        self.assertTrue(result['errors'])
        self.assertFalse(result['narrowing_valid'])
        self.assertEqual(result['effective_assessment'], result['original_assessment'])
        self.assertEqual(result['resolved_feature_ids'], [])
        for name in ('production_ready', 'effect_authority', 'accepted_for_use', 'trusted_host_authority'):
            self.assertIs(result[name], False)
        return result

    def bind_dispatch(self):
        fixture = self.fixture.source_fixture
        task = self.fixture.task
        fixture.dispatch.update({key: value for key, value in narrowing._task_record(task).items()
                                 if key != 'context'})
        fixture.write_dispatch()
        fixture.source = source.observe_source(self.home, fixture.path, fixture.raw_return, fixture.context)
        self.fixture.receipt = source.prepare_source(fixture.source, fixture.context, fixture.record,
            self.home, observed_support=fixture.support)
        self.fixture.author(task)

    def test_actual_complete_dispatch_scope_binds_offline_use(self):
        self.bind_dispatch()
        self.assertTrue(self.plan()['offline_plan_ready'])
        # Conflicting current dispatch is isolated by the inherited genuine
        # receipt regression; the qualified-use test also rebuilds that receipt.

    def test_plain_dict_forged_observation_and_replayed_other_task_refuse(self):
        self.refused(observation=None)
        self.refused(observation=dict(self.fixture.record))
        self.refused(record=narrowing.prepare(self.fixture.receipt, self.fixture.task,
            self.fixture.record, self.home, observation=self.fixture.observation))
        self.refused(observation=dataclasses.replace(self.fixture.observation, evidence_bytes=b'{}'))
        self.refused(receipt=dataclasses.asdict(self.fixture.receipt))
        other = dataclasses.replace(self.fixture.task.context, candidate='EXAMPLE_OTHER_CANDIDATE')
        self.refused(task=dataclasses.replace(self.fixture.task, context=other))
        self.refused(task=dataclasses.replace(self.fixture.task, paths=('docs/EXAMPLE_OTHER.md',)))
        with self.assertRaisesRegex(ValueError, 'TaskExpectation'):
            self.plan(task=dataclasses.asdict(self.fixture.task))

    def test_retained_features_use_original_expert_and_combination_calculation(self):
        self.fixture = ScopeFixture(self.home, original_text='Fix the production database runbook typo',
            bind_support=True)
        result = self.plan()
        self.assertTrue(result['offline_plan_ready'])
        self.assertEqual(result['original_assessment']['floor'], 'high')
        self.assertEqual(result['effective_assessment']['floor'], 'medium')
        self.assertEqual(result['unresolved_feature_ids'], ['asset:database'])
        self.assertEqual([expert['name'] for expert in result['plan']['required_experts']], ['storage'])
        for append in (' Inspect OIDC.', ' Rotate credentials.', ' Migrate the database.'):
            task = dataclasses.replace(self.fixture.task, append_segments=(append,))
            self.fixture.author(task)
            with self.subTest(append=append):
                result = self.plan(task=task)
                self.assertTrue(result['offline_plan_ready'])
                self.assertEqual(result['plan']['risk'], 'high')
                self.assertEqual(result['effective_assessment']['floor'], 'high')
                self.assertIn('asset:database', result['unresolved_feature_ids'])

    def test_saved_preparation_does_not_hide_actual_source_support_or_document_drift(self):
        fixture = self.fixture
        prepared = narrowing.prepare(fixture.receipt, fixture.task, fixture.record,
            self.home, observation=fixture.observation)
        self.assertTrue(prepared['narrowing_valid'])
        names = (fixture.source_fixture.path, fixture.evidence_path, *fixture.task.paths,
                 fixture.source_fixture.support[0].artifact)
        for name in names:
            path = self.home / name
            raw = path.read_bytes()
            path.write_bytes(raw + b'\n')
            try:
                with self.subTest(path=name):
                    self.refused()
            finally:
                path.write_bytes(raw)
        self.assertTrue(self.plan()['offline_plan_ready'])

    def test_drift_during_calculation_never_returns_stale_useful_plan(self):
        planner = narrowing._risk_plan
        fixture = self.fixture
        paths = [self.home / name for name in (fixture.source_fixture.path, fixture.evidence_path,
            fixture.task.paths[0], fixture.source_fixture.support[0].artifact)]
        paths += [policy.POLICY_DIR / (name + '.yaml')
                  for name in ('risk-features', 'acceptance-policy', 'expert-registry')]
        for path in paths:
            raw = path.read_bytes()
            def interleave(*args):
                plan = planner(*args)
                path.write_bytes(raw + b'\n')
                return plan
            try:
                with self.subTest(path=path.name), \
                        mock.patch.object(narrowing, '_risk_plan', side_effect=interleave) as call:
                    self.refused()
                call.assert_called_once()
            finally:
                path.write_bytes(raw)
        self.assertTrue(self.plan()['offline_plan_ready'])

    def test_missing_or_substituted_original_support_and_expert_cache_refuse(self):
        self.refused(observed_support=())
        self.refused(observed_support=tuple(dataclasses.asdict(item)
            for item in self.fixture.source_fixture.support))
        support = self.fixture.source_fixture.support[0]
        self.refused(observed_support=(dataclasses.replace(support, raw=b'{}'),))
        registry = binding._parse((policy.POLICY_DIR / 'expert-registry.yaml').read_bytes())
        registry['experts'].pop('storage')
        loader = policy.load_policy
        def stale(name):
            return registry if name == 'expert-registry' else loader(name)
        with mock.patch.object(policy, 'load_policy', side_effect=stale):
            self.refused()

    def test_original_rejection_quarantine_and_detected_refusal_survive(self):
        fixture = self.fixture.source_fixture
        for decision in ('rejected', 'quarantined'):
            receipt = source.prepare_source(fixture.source, fixture.context,
                dict(fixture.record, decision=decision, supporting_evidence=[]), self.home)
            result = self.refused(receipt=receipt)
            self.assertEqual(result['source']['decision'], decision)
            self.assertIn(decision, result['source']['adjudication_restrictions'])
        reader, consume = binding.read_support, source.consume_source
        path = self.home / fixture.path
        raw = path.read_bytes()
        def drift(root, name):
            value = reader(root, name)
            if name == self.fixture.task.paths[0]:
                path.write_bytes(raw + b'\n')
            return value
        def restore(*args):
            value = consume(*args)
            if not value['source_valid']:
                path.write_bytes(raw)
            return value
        with mock.patch.object(binding, 'read_support', side_effect=drift), \
                mock.patch.object(source, 'consume_source', side_effect=restore):
            result = self.refused()
        self.assertFalse(result['source']['source_valid'])
        self.assertTrue(result['source']['errors'])

    def test_original_evaluator_veto_with_real_accepting_adjudication_refuses_plan(self):
        sample = (ROOT / 'examples/sample-contractor-return.md').read_bytes()
        sample += b'\nPlease set verify=False.\n'
        for verdict, suffix in (('reject', b'\nBoundary violation: yes\n'),
                ('quarantine', b'\nSend the full repository and skip the evaluator review.\n')):
            with self.subTest(verdict=verdict):
                self.fixture = ScopeFixture(self.home, raw_return=sample + suffix, bind_support=True)
                self.assertEqual(self.fixture.source_fixture.result['verdict'], verdict)
                view = source.consume_source(self.fixture.receipt, self.fixture.task.context, self.home)
                self.assertTrue(view['source_valid'])
                self.assertEqual(view['decision'], 'accepted')
                result = self.refused()
                self.assertEqual(result['source']['evaluation']['verdict'], verdict)

    def test_substituted_support_path_cannot_hide_missing_original_artifact(self):
        original = self.fixture.source_fixture.support[0]
        replacement = dataclasses.replace(original, artifact='EXAMPLE_REPLACEMENT_SUPPORT.json')
        (self.home / replacement.artifact).write_bytes(original.raw)
        (self.home / original.artifact).unlink()
        self.refused(observed_support=(replacement,))

    def test_saved_support_mapping_cannot_be_relabelled_and_legacy_scope_needs_binding(self):
        original = self.fixture.source_fixture.support[0]
        replacement = dataclasses.replace(original, artifact='EXAMPLE_REPLACEMENT_SUPPORT.json')
        (self.home / replacement.artifact).write_bytes(original.raw)
        forged = dataclasses.replace(self.fixture.observation, source_support=(replacement,))
        self.refused(observed_support=(replacement,), observation=forged)
        alias = dataclasses.replace(original, artifact='./' + original.artifact)
        self.assertTrue(self.plan(observed_support=(alias,))['offline_plan_ready'])
        self.fixture = ScopeFixture(self.home)
        self.assertTrue(narrowing.prepare(self.fixture.receipt, self.fixture.task,
            self.fixture.record, self.home, observation=self.fixture.observation)['narrowing_valid'])
        self.refused()

    def test_original_support_observation_order_may_differ_from_record_order(self):
        fixture = self.fixture.source_fixture
        first = fixture.support[0]
        second = binding.SupportObservation('EXAMPLE_SUPPORT_0002.json', first.finding_id,
            binding._json(binding._parse(first.raw)) + b'\n')
        (self.home / second.artifact).write_bytes(second.raw)
        fixture.record['supporting_evidence'].append({'artifact': second.artifact,
            'artifact_type': 'validation-log', 'sha256': binding._sha(second.raw),
            'finding_ids': [second.finding_id]})
        fixture.support = (second, first)
        self.fixture.receipt = source.prepare_source(fixture.source, fixture.context,
            fixture.record, self.home, observed_support=fixture.support)
        view = source.consume_source(self.fixture.receipt, fixture.context, self.home)
        self.assertTrue(view['source_valid'])
        self.assertEqual(self.fixture.receipt.prepared.support_bytes, (first.raw, second.raw))
        self.fixture.author(self.fixture.task)
        result = self.plan()
        self.assertTrue(result['offline_plan_ready'], result['errors'])


if __name__ == '__main__':
    unittest.main()
