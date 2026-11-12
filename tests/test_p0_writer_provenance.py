"""P0 writer checks; fake model effects and one real offline N1 sandbox."""
from __future__ import annotations

from contextlib import nullcontext, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import dispatch_work as dispatch  # noqa: E402
import normalize_contractor_return as normalize  # noqa: E402
import registered_n1_factory as native  # noqa: E402
import test_registered_n1_factory as N  # noqa: E402
import test_registered_native_pool_host as P  # noqa: E402
from cwo_core.errors import CWOPolicyError  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from cwo_core.host_return_intake import MAX_RETURN_BYTES, record_received_return, _record_capture  # noqa: E402


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class WriterChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.store = HostRecordStore.for_tests(self.root / 'host')
        self.enterContext(using_test_store(self.store))

    def dispatch(self, identity='executor', *, target=None):
        return self.store.write_dispatch(
            dispatch_id=identity, dispatch_role='peer-review' if target else 'executor',
            provider='openai', model_family='gpt', model_id='gpt-6.1-sol',
            reasoning_effort='xhigh', session_id=identity + '-session',
            request_sha256=sha(b'exact request'), review_target=target,
            evaluation_metadata={'dispatch_mode': 'manual_ui'})

    def test_preparation_records_unknown_model_effort_and_session_honestly(self):
        """Check: preparation never promotes configured labels to actual identity."""
        record_id = dispatch.record_prepared_dispatch(
            'manual', provider='anthropic_manual', executor='claude_code_manual', request_sha256=sha(b'prompt'))
        record = self.store.get(record_id)
        self.assertEqual(record['provider'], 'anthropic')
        self.assertEqual(record['provider_key'], 'anthropic_manual')
        self.assertEqual(record['dispatch_role'], 'executor')
        self.assertTrue(all(record[field] is None for field in (
            'model_family', 'model_id', 'reasoning_effort', 'session_id')))
        args = SimpleNamespace(audit=False, bead='task')
        route = {'selected_executor': {'provider_key': 'openai', 'dispatch_mode': 'manual_ui'},
                 'recommended_executor': 'codex_native'}
        dispatch.record_route_preparation(args, route, 'task', 'raw-manual', 'prompt', None, manual_phase=True)
        args.audit = True
        dispatch.record_route_preparation(args, route, 'task', 'raw-manual', 'prompt', None)
        self.assertEqual(len(self.store.find('dispatch')), 1)
        dispatch.record_route_preparation(args, route, 'task', 'raw-manual', 'prompt', None, manual_phase=True)
        raw = self.store.require_dispatch('raw-manual')
        self.assertEqual(raw['request_sha256'], sha(b'prompt'))
        self.assertTrue(raw['evaluation_metadata']['peer_review_required'])
        envelope = {'model': 'EXAMPLE-model', 'messages': [], 'request_options': {'max_tokens': 7}}
        dispatch.record_route_preparation(args, route, 'task', 'local-preview', None, envelope)
        request = {'model': 'EXAMPLE-model', 'messages': [], 'temperature': 0, 'max_tokens': 7}
        self.assertEqual(self.store.require_dispatch('local-preview')['request_sha256'], sha(json.dumps(request).encode()))

    def test_packet_writer_records_provenance_before_export(self):
        """Check: a validated packet's host record exists before its manual export."""
        import tests.test_packet_production_provenance as packets
        from cwo_core.host_records import configured_store
        from tests.test_policy_current_effects import current_policy
        helper = packets.ProvenanceCase()
        with current_policy() as home:
            packet = helper.build(home, dispatch_id='packet-writer')
            path = helper.write(home, packet, 'packet.json')
            store = configured_store()
            def export(_screened):
                observed = store.require_dispatch('packet-writer')
                self.assertEqual(observed['packet_sha256'], packet['packet_sha256'])
                self.assertEqual(observed['bead_id'], packet['bead_id'])
                self.assertEqual(observed['executor'], packet['executor'])
                self.assertTrue(observed['evaluation_metadata']['peer_review_required'])
            with patch.object(sys, 'argv', ['dispatch_work.py', '--packet', str(path)]), \
                    patch.object(dispatch, 'write_export', side_effect=export) as write:
                dispatch.main()
            write.assert_called_once()

    def test_local_cli_records_before_invocation_and_gate_remains_first(self):
        """Checks: no effect without host provenance; shipped local gate remains off."""
        argv = ['dispatch_work.py', 'Summarize this short public note for a local review.',
                '--local-ok', '--prefer-local', '--local-model', 'EXAMPLE-model',
                '--local-base-url', 'http://127.0.0.1:8000', '--local-max-tokens', '7',
                '--dispatch-id', 'local', '--execute-local', '--json']
        requests = []
        def scope(_envelope, post, _preflight, _qualified):
            requests.append(post.data)
            return nullcontext(None)
        def effect(*_args, **_kwargs):
            record = self.store.require_dispatch('local')
            self.assertIsNone(record['model_id'])
            self.assertEqual(record['request_sha256'], sha(requests[0]))
            raise SystemExit('EXAMPLE provenance recorded before resolution')
        with patch.object(sys, 'argv', argv), redirect_stdout(StringIO()), \
                patch.object(dispatch, 'LOCAL_INVOCATION_AVAILABLE', True), \
                patch.object(dispatch, '_local_review_scope', side_effect=scope), \
                patch.object(dispatch, 'pinned_local_endpoint_address', side_effect=effect) as invoke:
            with self.assertRaisesRegex(SystemExit, 'provenance recorded before resolution'):
                dispatch.main()
        self.assertEqual(invoke.call_count, 1)
        with patch.object(sys, 'argv', argv), \
                patch.object(dispatch, 'LOCAL_INVOCATION_AVAILABLE', False), \
                patch.object(dispatch, 'configured_store') as configured, \
                patch.object(dispatch, 'execute_local_envelope') as invoke:
            with self.assertRaises(SystemExit):
                dispatch.main()
        configured.assert_not_called()
        invoke.assert_not_called()

    def test_rehearsal_exports_have_no_authority_and_unaudited_execution_refuses(self):
        """Checks: static rehearsal exports need no store; actual execution needs audited provenance."""
        base = ['dispatch_work.py', 'Summarize this short public note.', '--local-ok', '--prefer-local',
                '--rehearsal', '--waiver-reason', 'offline export fixture', '--json']
        for extra in ([], ['--no-audit']):
            output = StringIO()
            with self.subTest(extra=extra), patch.object(sys, 'argv', [*base, *extra]), \
                    redirect_stdout(output), patch.object(dispatch, 'configured_store') as configured, \
                    patch.object(dispatch, 'record_audit_event') as audit:
                dispatch.main()
            self.assertIsNone(json.loads(output.getvalue())['local_response'])
            configured.assert_not_called()
            audit.assert_not_called()
        with patch.object(sys, 'argv', [*base, '--no-audit', '--execute-local']), \
                patch.object(dispatch, 'LOCAL_INVOCATION_AVAILABLE', True), \
                patch.object(dispatch, 'configured_store') as configured, \
                patch.object(dispatch, 'execute_local_envelope') as execute:
            with self.assertRaisesRegex(SystemExit, 'requires audited host provenance'):
                dispatch.main()
        configured.assert_not_called()
        execute.assert_not_called()
        args = dispatch.argparse.Namespace(local_api_key_env=None, local_timeout=None,
            local_base_url='http://127.0.0.1:8000', local_model='EXAMPLE-model', execute_local=True, audit=False)
        task = 'Documentation review for internal example notes.'
        route = dispatch.classify_work(task, local_ok=True, prefer_local=True)
        envelope = dispatch.build_local_envelope(task=task, route=route, dispatch_id='unaudited',
                                                bead_id='task', epic_id=None, args=args)
        with patch.object(dispatch, 'LOCAL_INVOCATION_AVAILABLE', True), \
                patch.object(dispatch, 'configured_store') as configured, \
                patch.object(dispatch, 'pinned_local_endpoint_address') as resolve:
            with self.assertRaisesRegex(SystemExit, 'requires audited host provenance'):
                dispatch.execute_local_envelope(envelope, route['selected_executor'], args)
        configured.assert_not_called()
        resolve.assert_not_called()

    def test_local_record_reuse_requires_the_exact_dispatch_request(self):
        """Check: an existing preparation cannot authorize a changed local request."""
        envelope = {'dispatch_id': 'reuse', 'executor_key': 'codex_native', 'bead_id': 'task'}
        selected = {'provider_key': 'openai', 'dispatch_mode': 'local_openai_compatible'}
        first = dispatch.record_local_execution(envelope, selected, sha(b'request'))
        self.assertEqual(dispatch.record_local_execution(envelope, selected, sha(b'request')), first)
        for changed, provider, digest in (
                (envelope, selected, sha(b'changed')),
                ({**envelope, 'bead_id': 'another'}, selected, sha(b'request')),
                ({**envelope, 'executor_key': 'another'}, selected, sha(b'request')),
                (envelope, {**selected, 'provider_key': 'another'}, sha(b'request'))):
            with self.subTest(envelope=changed, provider=provider, digest=digest), \
                    self.assertRaisesRegex(SystemExit, 'differs from its recorded host dispatch'):
                dispatch.record_local_execution(changed, provider, digest)
        self.assertEqual(len(self.store.find('dispatch')), 1)

    def test_local_screen_and_reservation_refusals_precede_host_writes(self):
        """Check: local authorization refusals occur before host provenance is written."""
        from cwo_core.outbound_screen import OutboundRefused
        base = ['dispatch_work.py', 'Documentation review for internal example notes.',
                '--local-ok', '--prefer-local', '--local-model', 'EXAMPLE-model',
                '--local-base-url', 'http://127.0.0.1:8000', '--execute-local', '--json']
        for label in ('screen', 'reservation'):
            argv = list(base)
            if label == 'screen':
                argv[1] += ' password_source=hunter2'
            with self.subTest(check=label), patch.object(sys, 'argv', argv), \
                    patch.object(dispatch, 'LOCAL_INVOCATION_AVAILABLE', True), \
                    patch.object(dispatch, '_local_review_scope', side_effect=SystemExit('EXAMPLE reservation refused')), \
                    patch.object(dispatch, 'configured_store') as configured, \
                    patch.object(dispatch, 'pinned_local_endpoint_address') as resolve:
                with self.assertRaises(OutboundRefused if label == 'screen' else SystemExit):
                    dispatch.main()
            configured.assert_not_called()
            resolve.assert_not_called()

    def test_normalizer_records_exact_bytes_and_unknown_dispatch_refuses_output(self):
        """Checks: return intake verifies host dispatch and hashes original CRLF bytes."""
        self.dispatch()
        raw = b'Work completed.\r\nEvidence attached.\r\n'
        source, output = self.root / 'return.md', self.root / 'bundle.json'
        source.write_bytes(raw)
        argv = ['normalize_contractor_return.py', '--file', str(source),
                '--dispatch-id', 'executor', '--output', str(output)]
        with patch.object(sys, 'argv', argv):
            normalize.main()
        receipt = self.store.require_return('executor', sha(raw))
        self.assertEqual(receipt['dispatch_record_sha256'], self.store.require_dispatch('executor')['_record_sha256'])
        self.assertTrue(output.exists())
        output.write_text('sentinel')
        with patch.object(sys, 'argv', [*argv[:-3], 'caller-written', '--output', str(output)]):
            with self.assertRaises(ValueError):
                normalize.main()
        self.assertEqual(output.read_text(), 'sentinel')

    def test_intake_bound_and_verified_replay(self):
        """Checks: byte bound and verified reuse precede any new receipt."""
        self.dispatch()
        raw = b'exact received text\n'
        first = record_received_return(self.store, 'executor', raw)
        self.assertEqual(record_received_return(self.store, 'executor', raw), first)
        self.assertEqual(len(self.store.find('return-received')), 1)
        with self.assertRaisesRegex(CWOPolicyError, 'bounded exact bytes'):
            record_received_return(self.store, 'executor', b'x' * (MAX_RETURN_BYTES + 1))
        self.assertEqual(len(self.store.find('return-received')), 1)

    def test_peer_intake_binds_actual_identity_target_and_canonical_decision(self):
        """Checks: peer receipts bind actual identity, both target digests and strict JSON."""
        self.dispatch()
        record_received_return(self.store, 'executor', b'work')
        target = {'dispatch_id': 'executor', 'return_sha256': sha(b'work'),
                  'evaluation_sha256': sha(b'evaluation')}
        self.dispatch('reviewer', target=target)
        value = {'record_type': 'cwo-peer-review', 'version': 2, 'decision': 'passed',
                 'reviewer_identity': {'provider': 'openai', 'model_family': 'gpt',
                     'model_id': 'gpt-6.1-sol', 'reasoning_effort': 'xhigh', 'dispatch_id': 'reviewer'},
                 'return_sha256': target['return_sha256'], 'evaluation_sha256': target['evaluation_sha256']}
        for field in ('model_id', 'return_sha256', 'evaluation_sha256'):
            changed = json.loads(json.dumps(value))
            if field == 'model_id':
                changed['reviewer_identity'][field] = 'gpt-6-astra'
            else:
                changed[field] = sha(b'wrong')
            with self.subTest(check=field), self.assertRaises(CWOPolicyError):
                record_received_return(self.store, 'reviewer', json.dumps(changed).encode())
        self.assertFalse(self.store.find('return-received', dispatch_id='reviewer'))
        with self.assertRaises(CWOPolicyError):
            record_received_return(self.store, 'reviewer', (json.dumps(value)[:-1] + ',"decision":"passed"}').encode())
        raw = (json.dumps(value, indent=2) + '\n').encode()
        record_received_return(self.store, 'reviewer', raw)
        canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
        self.store.require_return('reviewer', sha(raw))
        self.store.require_return('reviewer', sha(canonical))

    def test_manual_cli_cannot_supply_a_host_captured_or_peer_return(self):
        """M1: public intake checks recorded role/mode before any write or output."""
        raw = b'caller supplied decision'
        source, output = self.root / 'caller.md', self.root / 'output.json'
        source.write_bytes(raw)
        output.write_bytes(b'sentinel')
        target = {'dispatch_id': 'work', 'return_sha256': sha(b'work'),
                  'evaluation_sha256': sha(b'evaluation')}
        for index, (role, mode) in enumerate((
                ('peer-review', 'manual_ui'), ('peer-review', 'registered-native-n1'),
                ('executor', 'registered-native-n1'), ('executor', 'registered-native-pool'),
                ('executor', 'local_openai_compatible'), ('executor', 'local_secure_review'),
                ('executor', 'future-host-mode'), ('executor', None))):
            identity = 'refusal-' + str(index)
            self.store.write_dispatch(dispatch_id=identity, dispatch_role=role,
                provider='openai', model_family='gpt', model_id='gpt-6.1-sol',
                reasoning_effort='xhigh', session_id=identity, request_sha256=sha(b'request'),
                review_target=target if role == 'peer-review' else None,
                evaluation_metadata={'dispatch_mode': mode})
            before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            argv = ['normalize_contractor_return.py', '--file', str(source), '--dispatch-id', identity,
                    '--dispatch-mode', 'manual_ui', '--output', str(output)]
            with self.subTest(role=role, mode=mode), patch.object(sys, 'argv', argv):
                with self.assertRaisesRegex(CWOPolicyError, 'recorded manual executor'):
                    normalize.main()
            self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                     for p in self.root.rglob('*') if p.is_file()})
        self.dispatch('manual-control')
        with patch.object(sys, 'argv', ['normalize_contractor_return.py', '--file', str(source),
                '--dispatch-id', 'manual-control', '--output', str(output)]):
            normalize.main()
        self.assertEqual(self.store.require_return('manual-control', sha(raw))['capture_provenance'],
                         'manual-intake-v1')
        self.assertNotEqual(output.read_bytes(), b'sentinel')

    def test_single_host_capture_binds_raw_and_canonical_and_refuses_legacy_authority(self):
        """M1: one captured review cannot be replaced; ambiguous old receipts grant nothing."""
        self.dispatch()
        target = {'dispatch_id': 'executor', 'return_sha256': sha(b'work'),
                  'evaluation_sha256': sha(b'evaluation')}
        self.dispatch('reviewer', target=target)
        value = {'record_type': 'cwo-peer-review', 'version': 2, 'decision': 'passed',
                 'reviewer_identity': {'provider': 'openai', 'model_family': 'gpt',
                     'model_id': 'gpt-6.1-sol', 'reasoning_effort': 'xhigh', 'dispatch_id': 'reviewer'},
                 'return_sha256': target['return_sha256'], 'evaluation_sha256': target['evaluation_sha256']}
        raw = (json.dumps(value, indent=2) + '\n').encode()
        first = record_received_return(self.store, 'reviewer', raw)
        try:
            retry = record_received_return(self.store, 'reviewer', raw)
        except CWOPolicyError as failure:
            self.fail('Exact captured bytes must reuse their single receipt: ' + str(failure))
        self.assertEqual(retry, first)
        canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
        try:
            canonical_receipt = self.store.require_return('reviewer', sha(canonical))
        except CWOPolicyError as failure:
            self.fail('Canonical and raw decisions must resolve to one receipt: ' + str(failure))
        self.assertEqual(canonical_receipt['_record_sha256'], first)
        self.assertEqual(self.store.require_return('reviewer', sha(raw))['_record_sha256'], first)
        self.assertEqual(len(self.store.find('return-received', dispatch_id='reviewer')), 1)
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        for changed in (json.dumps(value).encode(), canonical):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'already has a return'):
                record_received_return(self.store, 'reviewer', changed)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                 for p in self.root.rglob('*') if p.is_file()})
        self.dispatch('legacy-reviewer', target=target)
        self.store.write_return_received('legacy-reviewer', sha(b'legacy caller return'))
        with self.assertRaisesRegex(ValueError, 'capture provenance'):
            self.store.require_return('legacy-reviewer', sha(b'legacy caller return'))

    def test_capture_byte_contract_canonical_shape_and_retry_custody_are_independent(self):
        """M1: exact bytes/size, canonical SHA shape and genuine retry provenance are enforced."""
        self.dispatch('bounded')
        for raw in (bytearray(b'not exact bytes'), b'x' * (MAX_RETURN_BYTES + 1)):
            before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            with self.subTest(bound=type(raw).__name__), self.assertRaises(CWOPolicyError):
                _record_capture(self.store, 'bounded', raw, 'host-capture-v1')
            self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                     for p in self.root.rglob('*') if p.is_file()})
        with self.assertRaises(CWOPolicyError):
            self.store.write_return_received('bounded', sha(b'raw'), capture_provenance='host-capture-v1',
                                             canonical_return_sha256='malformed')
        self.assertFalse(self.store.find('return-received', dispatch_id='bounded'))
        for identity, provenance, canonical in (('legacy', None, None),
                ('canonical-conflict', 'host-capture-v1', sha(b'unrelated canonical'))):
            self.dispatch(identity)
            self.store.write_return_received(identity, sha(b'raw'), capture_provenance=provenance,
                                             canonical_return_sha256=canonical)
            before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            with self.subTest(retry=identity), self.assertRaises(CWOPolicyError):
                record_received_return(self.store, identity, b'raw')
            self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                     for p in self.root.rglob('*') if p.is_file()})

    def test_under_lock_capture_uniqueness_and_reader_role_mode_selectors(self):
        """M1: each selector independently requires host custody and a single capture."""
        target = {'dispatch_id': 'work', 'return_sha256': sha(b'work'),
                  'evaluation_sha256': sha(b'evaluation')}
        cases = [('peer-review', 'manual_ui', None, None),
                 ('executor', 'registered-native-n1', None, None),
                 ('executor', 'manual_ui', None, 'host-capture-v1'),
                 ('executor', 'manual_ui', 'host-capture-v1', None)]
        for number, (role, mode, first, second) in enumerate(cases):
            identity = 'selector-' + str(number)
            self.store.write_dispatch(dispatch_id=identity, dispatch_role=role, provider='openai',
                model_family='gpt', model_id='gpt-6.1-sol', reasoning_effort='xhigh', session_id=identity,
                request_sha256=sha(b'request'), review_target=target if role == 'peer-review' else None,
                evaluation_metadata={'dispatch_mode': mode})
            self.store.write_return_received(identity, sha(b'first'), capture_provenance=first)
            before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            with self.subTest(selector=number), self.assertRaises(CWOPolicyError):
                self.store.write_return_received(identity, sha(b'second'), capture_provenance=second)
            if number < 2:
                with self.assertRaises(CWOPolicyError):
                    self.store.require_return(identity, sha(b'first'))
            self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                     for p in self.root.rglob('*') if p.is_file()})

    def factory(self):
        fixture = N.FactoryTests('runTest')
        fixture.setUp()
        self.addCleanup(N.cleanup_helper, self, fixture)
        case = fixture.case()
        return fixture, case

    def test_native_actual_session_record_precedes_task_and_return_validation(self):
        """Checks: actual checked session precedes turn; exact custody return precedes validation."""
        fixture, case = self.factory()
        factory = fixture.factory(case)
        original_receive = N.RpcProcess.receive
        def receive(process, message):
            if message.get('method') == 'turn/start':
                record = fixture.host_records.require_dispatch(factory.dispatch_id)
                self.assertEqual(record['session_id'], factory.server.thread_id)
                self.assertEqual(record['model_id'], case.spec['model'])
                self.assertEqual(record['provider'], case.spec['provider'])
                self.assertEqual(record['reasoning_effort'], case.spec['effort'])
                self.assertIsNone(record['model_family'])  # EXAMPLE provider has no registered family.
            return original_receive(process, message)
        validate = native.validation.validate_artifact
        def validation(*args):
            fixture.host_records.require_return(factory.dispatch_id, sha((case.host.state / 'operation.json').read_bytes()))
            return validate(*args)
        with patch.object(N.RpcProcess, 'receive', receive), \
                patch.object(native.validation, 'validate_artifact', side_effect=validation):
            factory.run()
        self.assertIsNotNone(factory.dispatch_record_sha256)
        self.assertIsNotNone(factory.return_record_sha256)

    def test_native_return_custody_mismatch_refuses_receipt_and_validation(self):
        """Check: a substituted received report cannot acquire a host return receipt."""
        fixture, case = self.factory()
        factory = fixture.factory(case)
        original = native.native._read
        def substitute(root, name, cap):
            raw = original(root, name, cap)
            if name == 'operation.json' and factory.execution is not None:
                return json.dumps({**json.loads(raw), 'error': 'substituted return'}).encode()
            return raw
        with patch.object(native.native, '_read', substitute):
            with self.assertRaisesRegex(ValueError, 'differs from host custody'):
                factory.run()
        self.assertIsNone(factory.token)
        self.assertFalse(fixture.host_records.find('return-received'))

    def test_native_admission_and_recheck_exclude_worker_and_spool(self):
        """Checks: native admission, guard and actual launch roots exclude store/audit."""
        fixture, case = self.factory()
        for root in (case.host.worker, case.home):
            bad = HostRecordStore.for_tests(root / 'worker-controlled-provenance')
            with self.subTest(check='admission', root=root), \
                    patch.object(native, 'configured_store', return_value=bad):
                with self.assertRaisesRegex(ValueError, 'worker writable root'):
                    fixture.factory(case)
        factory = fixture.factory(case)
        original = factory.host_records
        factory.host_records = HostRecordStore.for_tests(case.home / 'provenance')
        with self.assertRaisesRegex(ValueError, 'worker writable root'):
            factory.guard()
        factory.host_records = original
        with self.assertRaisesRegex(ValueError, 'worker writable root'):
            native._Containment(factory)._command(
                [str(Path(sys.executable).resolve())], original.state_root, 100, 101)
        self.assertFalse(fixture.spawned)

    def test_native_peer_artifact_count_size_and_digest_refuse_receipt(self):
        """Checks: peer intake reads the one exact immutable captured decision."""
        state = self.root / 'native-state'
        artifact = state / 'artifact'
        artifact.mkdir(parents=True)
        raw = b'{"decision":"passed"}'
        blob = artifact / 'file-0000'
        blob.write_bytes(raw); blob.chmod(0o400)
        entry = {'blob': 'file-0000', 'size': len(raw), 'sha256': sha(raw)}
        factory = SimpleNamespace(host=SimpleNamespace(state=state), review_target={},
                                  host_records=self.store, dispatch_id='reviewer', return_record_sha256=None)
        for entries in ([], [{**entry, 'size': len(raw) + 1}], [{**entry, 'sha256': sha(b'wrong')}]):
            report = {'artifact': {'files': entries}}
            (state / 'operation.json').write_bytes(native._snapshot(report))
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, 'one exact|differ from the captured'):
                native.RegisteredN1Factory.record_native_return(factory, report)
        self.assertIsNone(factory.return_record_sha256)
        self.assertFalse(self.store.state_root.exists())

    def test_pool_rechecks_all_actual_member_write_roots(self):
        """Check: complete pool cohort revalidation includes each spool home."""
        fixture = P.PoolTests('runTest')
        self.addCleanup(N.cleanup_helper, self, fixture)
        fixture.cohort(size=1)
        controller = fixture.config.controllers[0]
        fixture.config.host_records = HostRecordStore.for_tests(
            controller.host.state / 'fake-server' / 'codex-home' / 'provenance')
        with self.assertRaisesRegex(ValueError, 'worker writable root'):
            fixture.host.validate_authority(fixture.config.request('validate-only'))
        self.assertFalse((controller.host.state / 'registered-startup.json').exists())

    def test_native_review_target_refuses_unknown_binding_and_changed_target_before_effect(self):
        """Checks: trusted reviewer configuration still needs an existing exact executor receipt."""
        fixture = N.FactoryTests('runTest')
        fixture.setUp()
        self.addCleanup(N.cleanup_helper, self, fixture)
        store = fixture.host_records
        executor = dict(dispatch_id='original', dispatch_role='executor', provider='openai',
                        model_family='gpt', model_id='gpt-6.1-sol', reasoning_effort='xhigh',
                        session_id='original-session', request_sha256=sha(b'request'))
        store.write_dispatch(**executor)
        store.write_return_received('original', sha(b'work'))
        target = {'dispatch_id': 'original', 'return_sha256': sha(b'work'),
                  'evaluation_sha256': sha(b'evaluation')}
        store.write_dispatch(**{**executor, 'dispatch_id': 'peer', 'dispatch_role': 'peer-review',
                                'review_target': target})
        store.write_return_received('peer', sha(b'peer-return'))
        dispatch_id = 'n1-' + sha(native._snapshot({
            'operation_id': 'EXAMPLE-operation', 'state': str(fixture.repositories.root / 'EXAMPLE-host')}))
        decision = {'record_type': 'cwo-peer-review', 'version': 2, 'decision': 'passed',
                    'return_sha256': target['return_sha256'], 'evaluation_sha256': target['evaluation_sha256'],
                    'reviewer_identity': {**{key: executor[key] for key in (
                        'provider', 'model_family', 'model_id', 'reasoning_effort')}, 'dispatch_id': dispatch_id}}
        raw = (json.dumps(decision, indent=2) + '\n').encode()
        self.enterContext(patch.object(N.fixtures.host_fixtures, 'OUTPUT', raw))
        case = fixture.case(provider='openai')
        for bad in ({}, {**target, 'evaluation_sha256': 'not-a-digest'},
                    {**target, 'return_sha256': sha(b'unknown-return')},
                    {**target, 'dispatch_id': 'peer', 'return_sha256': sha(b'peer-return')}):
            with self.subTest(target=bad), self.assertRaises(ValueError):
                fixture.factory(case, review_target=bad)
        factory = fixture.factory(case, review_target=target)
        factory.guard()
        factory.review_target['evaluation_sha256'] = sha(b'changed')
        with self.assertRaisesRegex(ValueError, 'target changed'):
            factory.guard()
        self.assertFalse(fixture.spawned)
        factory.review_target = dict(target)
        factory.run()
        observed = store.require_dispatch(factory.dispatch_id)
        self.assertEqual(observed['model_family'], 'gpt')
        self.assertEqual(observed['review_target'], target)
        store.require_return(factory.dispatch_id, sha(raw))
        store.require_return(factory.dispatch_id, sha(json.dumps(
            decision, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()))

    def test_real_offline_n1_sandbox_cannot_write_host_store_or_audit(self):
        """Check: real N1 launcher mounts permit worker writes and exclude host provenance."""
        record_id = self.dispatch()
        marker = self.store.root / (record_id + '.json')
        marker_before = marker.read_bytes()
        new_record = self.store.root / ('f' * 64 + '.json')
        audit_before = self.store.audit_file.read_bytes()
        worker, home = self.root / 'worker', self.root / 'spool'
        worker.mkdir(); (worker / '.git').mkdir(); home.mkdir()
        factory = SimpleNamespace(spec={'launcher': '/usr/bin/bwrap', 'configuration_files': {}},
                                  host=SimpleNamespace(worker=worker), host_records=self.store)
        code = ('import json,pathlib; results={}; '
                'paths=' + repr([str(marker), str(new_record), str(self.store.audit_file)]) + '\n'
                'for name in paths:\n'
                ' try: pathlib.Path(name).write_text("worker-forged"); results[name]="written"\n'
                ' except OSError: results[name]="refused"\n'
                'pathlib.Path("worker-positive").write_text("allowed"); print(json.dumps(results))\n')
        read_gate, write_gate = os.pipe()
        read_info, write_info = os.pipe()
        try:
            os.write(write_gate, b'1')
            # The sandbox binds the system runtime and the interpreter binary only, so a
            # relocated interpreter (one whose libpython lives in its own prefix) cannot load.
            interpreter = str(Path('/usr/bin/python3' if os.path.exists('/usr/bin/python3') else sys.executable).resolve())
            argv = native._Containment(factory)._command(
                [interpreter, '-I', '-S', '-c', code], home, read_gate, write_info)
            result = subprocess.run(argv, pass_fds=(read_gate, write_info), capture_output=True, text=True, timeout=15)
        finally:
            for descriptor in (read_gate, write_gate, read_info, write_info):
                os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(json.loads(result.stdout).values()), {'refused'})
        self.assertEqual((worker / 'worker-positive').read_text(), 'allowed')
        self.assertEqual(marker.read_bytes(), marker_before)
        self.assertFalse(new_record.exists())
        self.assertEqual(self.store.audit_file.read_bytes(), audit_before)


if __name__ == '__main__':
    unittest.main()
