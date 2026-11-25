"""Prepare a known output through the ordinary protected controller."""
from argparse import Namespace
from contextlib import ExitStack, chdir, redirect_stderr
import ctypes
from functools import partial
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import shlex
from shutil import rmtree
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_delegate_internal_work as effects
from tests.test_candidate_identity import bead
from tests import test_offline_n1_host as offline

import cwo
import everyday_delegation
import registered_delegation_foreground as foreground
import registered_delegation_preparation as preparation
from cwo_core import host_records, manual_delivery, requirement_baseline


class DelegationPreparationTests(unittest.TestCase):
    def setUp(self):
        repositories = offline.OfflineN1HostTests('runTest')
        # Thread-start sends the worker path. Use the registered factory
        # fixture's short private temporary parent.
        with patch.object(tempfile, 'tempdir', '/tmp'):
            repositories.setUp()
        self.addCleanup(repositories.doCleanups)
        self.root, self.project = repositories.root, repositories.target
        self.git = repositories.git
        self.store = host_records.HostRecordStore.for_tests(self.root / 'EXAMPLE-host-records')
        self.enterContext(patch.object(host_records, 'configured_store', return_value=self.store))
        self.enterContext(patch.object(preparation.runtime, 'configured_store', return_value=self.store))
        self.database = sha256(b'EXAMPLE database').hexdigest()
        baseline = {'record_type': 'cwo-requirement-baseline', 'version': 1, 'bead_id': 'example-bead',
                    'baseline_version': 1, 'criteria': [{
                        'id': 'result-file', 'requirement': 'Produce the scoped result file.',
                        'reference': 'Example assignment', 'expected_outcome': 'Deliver the exact text.',
                        'applicability': 'required', 'evidence_kind': 'artifact'}]}
        self.chain = requirement_baseline.resolve_chain(baseline)
        reference = requirement_baseline.reference_line(self.chain['bead_id'], 1, self.chain['digest'])
        self.bead = bead(self.chain['bead_id'], reference)
        self.enterContext(patch.object(manual_delivery, 'project_beads', side_effect=self.read_project_db))
        self.home = self.root / 'EXAMPLE-worker-login'
        self.home.mkdir(mode=0o700)
        (self.home / 'auth.json').write_text('EXAMPLE authentication fixture', encoding='utf-8')
        (self.home / 'auth.json').chmod(0o600)
        self.enterContext(patch.object(preparation.workflow.login_config, 'read_worker_login_home', return_value=self.home))
        login_state = self.root / 'EXAMPLE-login-state'
        self.enterContext(patch.object(preparation.runtime.qualification, 'worker_login_state', return_value=login_state))
        self.enterContext(patch.object(preparation.shutil, 'which', return_value=str(Path(sys.executable).resolve())))

    def read_bead(self, arguments):
        self.assertEqual(arguments[0], 'show')
        return json.dumps([self.bead])

    def read_project_db(self, root):
        self.assertEqual(root, self.project)
        return self.database, self.read_bead

    def writable_project_db(self, root):
        self.assertEqual(root, self.project)
        return self.database, self.deliver_bead

    def deliver_bead(self, arguments):
        command = arguments[0]
        if command == 'show':
            return self.read_bead(arguments)
        if command == 'dep':
            return '[]'
        if command == 'comment':
            self.bead['comments'].append({'text': arguments[-1]})
            (self.project / 'EXAMPLE-project-beads.json').write_text(json.dumps(self.bead), encoding='utf-8')
            return ''
        self.assertEqual(command, 'close')
        self.bead.update(status='closed', close_reason=arguments[arguments.index('--reason') + 1])
        return ''

    def prepare(self, **changes):
        request = {'project': self.project, 'database': self.database,
                   'task': 'Update the project documentation for the scoped result file.',
                   'chain': self.chain, 'output_path': 'result.txt', 'output_text': "Literal 'text' $(ignored)\n"}
        return preparation.prepare(**dict(request, **changes))

    def seed_wide_project(self):
        directory = self.project / ('example-' + 'a' * 72) / ('example-' + 'b' * 72)
        directory.mkdir(parents=True)
        for index in range(48):
            (directory / (f'example-{index:02d}-' + 'c' * 65 + '.txt')).write_bytes(b'EXAMPLE\n')
        self.git(self.project, 'add', '--', directory.relative_to(self.project))
        self.git(self.project, 'commit', '--quiet', '-m', 'Add the wide manifest fixture')

    def test_wide_manifest_fits_fixed_output_admission(self):
        self.seed_wide_project()
        pending = self.prepare()
        self.addCleanup(preparation.discard_unretained, pending)
        original = pending._host._initial
        route = json.loads(pending._receipt.route_input_bytes)
        node = route['nodes'][0]
        request_budget = (route['limits']['tokens'] - route['projection_policy']['input_overhead_tokens']
                          - node['execution']['output_tokens_upper'])
        self.assertTrue(original['target']['complete'])
        self.assertGreater(len(preparation.runtime.native._json_bytes(original)), request_budget)
        self.assertLess(len(pending._receipt.request_bytes), 8192)
        custody = node['execution']['options']['registered_n1']['custody']
        self.assertNotIn('initial', custody)
        self.assertEqual(custody['initial_sha256'], preparation.runtime.native._digest(original))
        self.assertFalse(pending._verifier._current()['operations'])
        self.assertFalse(pending._ledger.root.exists())

    def test_prepare_builds_fresh_bounded_offer_without_signing_ops(self):
        original_sign = preparation.authority.sign_controller_directive
        with patch.object(preparation.authority, 'sign_controller_directive', wraps=original_sign) as sign:
            pending = self.prepare()
        self.assertIs(type(pending), preparation.approval.PendingDelegationApproval)
        self.assertEqual(sign.call_count, 1)
        plan, operation = json.loads(pending._plans)[0]
        spec = plan['registered_n1']
        self.assertEqual(spec['validation_policy']['outputs'][0]['sha256'], sha256(b"Literal 'text' $(ignored)\n").hexdigest())
        self.assertEqual(shlex.split(spec['command']),
                         ['/usr/bin/printf', '%s', "Literal 'text' $(ignored)\n", '>', 'result.txt'])
        self.assertEqual(operation['write_paths'], ['result.txt'])
        self.assertEqual(pending.approval_scope['project'], str(self.project))
        self.assertEqual(pending.approval_scope['target'], str(pending._host.target))
        self.assertNotEqual(pending._host.target, self.project)
        self.assertNotEqual(pending._host.target, pending._host.worker)
        self.assertEqual(pending.approval_scope['baseline_sha256'], self.chain['digest'])
        self.assertEqual(pending.approval_scope['database_sha256'], self.database)
        self.assertEqual(pending.approval_scope['disclosure'], 'provider-only')
        self.assertFalse(pending._ledger.root.exists())
        self.assertFalse(pending._verifier._current()['operations'])
        self.assertFalse((self.project / 'result.txt').exists())
        self.assertFalse((pending._host.worker / 'result.txt').exists())
        self.assertFalse(pending._host.worker.is_relative_to(self.store.state_root))

    def test_prepare_refuses_unbound_or_unsafe_requests_before_key_creation(self):
        failures = ({'database': '0' * 64}, {'output_path': '../result.txt'}, {'output_path': '.beads/data'},
                    {'output_path': '.env'}, {'output_text': '\0'}, {'output_text': 'a' * 2049})
        for changes in failures:
            with self.subTest(changes=changes.keys()), self.assertRaises(ValueError):
                self.prepare(**changes)
        self.bead['comments'] = []
        with self.assertRaisesRegex(ValueError, 'baseline'):
            self.prepare()
        self.assertFalse(self.store.state_root.exists())

    def test_skipped_setup_refuses_before_project_lookup(self):
        with (patch.object(preparation.workflow.login_config, 'read_worker_login_home', return_value=None),
              patch.object(manual_delivery, 'project_beads', side_effect=AssertionError('unexpected Beads lookup')),
              self.assertRaisesRegex(ValueError, 'Delegation is not set up')):
            self.prepare()
        self.assertFalse(self.store.state_root.exists())

    def test_existing_identical_output_and_overwide_replacement_refuse_before_key_creation(self):
        for proposal in ({'output_path': 'seed.txt', 'output_text': 'FAKE_SEED\n'}, {'output_text': 'x\n' * 81}):
            with self.subTest(proposal=proposal), self.assertRaisesRegex(ValueError, 'proposed'):
                self.prepare(**proposal)
        self.assertFalse(self.store.state_root.exists())
        custody = preparation._offer_parent(self.store)
        self.assertEqual(list(custody.iterdir()), [])

    def test_prepared_assignment_reopens_with_same_project_key_and_original_scope(self):
        pending = self.prepare()
        another = self.prepare()
        self.assertEqual(pending._verifier._key, another._verifier._key)
        self.assertNotEqual(pending.approval_scope, another.approval_scope)
        workflow = self.fixture_redeem(pending)
        preparation.entry.retain_approved_assignment(workflow)
        task = json.loads(pending._receipt.selected_node_bytes)['prompt']
        with chdir(self.project):
            reopened = preparation.entry.open_assignment(task, self.chain)
        self.assertEqual(reopened.config._standing_approval()[0], pending.approval_scope)
        self.assertFalse(reopened.verifier._current()['operations'])
        self.assertIsNone(reopened.factory)
        self.assertFalse(reopened.verifier._current()['operations'])
        self.assertFalse(reopened.config.ledger.root.exists())

    def test_legacy_inline_custody_reopens_with_original_signed_admission(self):
        original = preparation._specification

        def inline(host, ledger, *args):
            spec = original(host, ledger, *args)
            spec['custody'] = preparation.runtime.custody_binding(host, ledger, compact=False)
            return spec

        with patch.object(preparation, '_specification', side_effect=inline):
            pending = self.prepare()
        workflow = self.fixture_redeem(pending)
        preparation.entry.retain_approved_assignment(workflow)
        task = json.loads(pending._receipt.selected_node_bytes)['prompt']
        with chdir(self.project):
            reopened = preparation.entry.open_assignment(task, self.chain)
        self.assertEqual(reopened.config.receipt, pending._receipt)
        self.assertEqual(reopened.config.native_bundle, workflow.config.native_bundle)
        self.assertEqual(reopened.config._standing_approval(), workflow.config._standing_approval())
        self.assertEqual(reopened.config.native_bundle[0]['registered_n1']['custody']['initial'], pending._host._initial)

    def test_compact_approval_refuses_target_drift_before_retention(self):
        pending = self.prepare()
        self.addCleanup(preparation.discard_unretained, pending)
        (pending._host.target / 'seed.txt').write_bytes(b'EXAMPLE same-commit target drift\n')
        with self.assertRaisesRegex(ValueError, 'Current repository state differs from original compact custody'):
            self.fixture_redeem(pending)
        self.assertFalse(pending._verifier._current()['operations'])
        self.assertFalse(pending._ledger.root.exists())
        preparation.discard_unretained(pending)
        self.assertFalse(pending._host.state.parent.exists())

    def test_retained_compact_approval_refuses_target_drift_or_replaced_worker(self):
        pending = self.prepare()
        workflow = self.fixture_redeem(pending)
        preparation.entry.retain_approved_assignment(workflow)
        task = json.loads(pending._receipt.selected_node_bytes)['prompt']
        host = pending._host
        extra = host.target / 'unexpected.txt'
        with chdir(self.project):
            extra.write_bytes(b'EXAMPLE untracked target drift\n')
            with self.assertRaisesRegex(ValueError, 'Original compact registered custody differs'):
                preparation.entry.open_assignment(task, self.chain)
            extra.unlink()
            self.assertEqual(preparation.entry.open_assignment(task, self.chain).config.receipt, pending._receipt)
            host.worker.rename(host.worker.with_name('retired-worker'))
            preparation._clone(host.target, host.worker)
            with self.assertRaisesRegex(ValueError, 'Original compact registered custody differs'):
                preparation.entry.open_assignment(task, self.chain)
        self.assertFalse(pending._verifier._current()['operations'])
        self.assertFalse(pending._ledger.root.exists())

    def test_registered_packet_binds_exact_request_and_model_projection_without_capability_assertions(self):
        pending = self.prepare()
        workflow = self.fixture_redeem(pending)
        task = json.loads(pending._receipt.selected_node_bytes)['prompt']
        native, publication = [bundle[1] for bundle in json.loads(pending._plans)]
        with patch.object(preparation.workflow.D, 'build_native_worker_packet', side_effect=AssertionError('unexpected generic packet')):
            delegation, packet = preparation.workflow.D.authorize(workflow, task, native, publication,
                                                                    database=self.database)
        self.assertEqual(delegation['dispatch']['executor'], 'internal_worker_luna')
        self.assertEqual(packet['scope']['allowed_paths'], ['result.txt'])
        self.assertEqual(packet['scope']['project'], str(self.project))
        self.assertEqual(packet['packet_type'], 'cwo-registered-delegation-packet')
        self.assertEqual(packet['request_sha256'], pending.approval_scope['request_sha256'])
        self.assertEqual(packet['model_task_sha256'], sha256(preparation.runtime._model_task(
            pending._receipt, workflow.config.native_bundle[0]['registered_n1'], workflow.config.policy.report)).hexdigest())
        self.assertFalse(workflow.verifier._current()['operations'])

    def test_registered_packet_refuses_changed_request_scope_and_packet_hash(self):
        pending = self.prepare()
        workflow = self.fixture_redeem(pending)
        task = json.loads(pending._receipt.selected_node_bytes)['prompt']
        native, publication = [bundle[1] for bundle in json.loads(pending._plans)]
        authorize = preparation.workflow.D.authorize
        with self.assertRaisesRegex(ValueError, 'original admitted task'):
            authorize(workflow, task + ' extra', native, publication, database=self.database)
        with self.assertRaisesRegex(ValueError, 'write scope'):
            authorize(workflow, task, dict(native, write_paths=['other.txt']), publication, database=self.database)
        delegation, _packet = authorize(workflow, task, native, publication, database=self.database)
        delegation['dispatch']['packet_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'registered delegation packet'):
            preparation.workflow.D.current(workflow, delegation)
        self.assertFalse(workflow.verifier._current()['operations'])
        self.assertFalse(workflow.config.ledger.root.exists())

    def test_generic_packet_refuses_missing_current_provider_evidence(self):
        original = effects.make_workflow(self, capabilities={})
        workflow = original.workflow
        with self.assertRaisesRegex(ValueError, 'Current delegation route refused'):
            workflow.delegate(original.task, database=effects.DATABASE)
        self.assertFalse(workflow.verifier._current()['operations'])
        self.assertFalse(workflow.config.ledger.root.exists())
        self.assertFalse(original.fixture.spawned)

    def test_declined_and_failed_retention_custody_cleans_without_removing_retained_offer(self):
        declined = self.prepare()
        preparation.discard_unretained(declined)
        self.assertFalse(declined._host.state.parent.exists())
        retained = self.prepare()
        original_write = preparation.entry._write_approval

        def lose_reply(*args, **kwargs):
            original_write(*args, **kwargs)
            raise OSError('EXAMPLE lost retention reply')

        with (patch.object(preparation.entry, '_write_approval', side_effect=lose_reply),
              self.assertRaisesRegex(OSError, 'lost retention reply')):
            preparation.entry.retain_approved_assignment(self.fixture_redeem(retained))
        preparation.discard_unretained(retained)
        self.assertTrue(retained._host.state.parent.exists())
        competing = self.prepare()
        with self.assertRaisesRegex(ValueError, 'Another original approval'):
            preparation.entry.retain_approved_assignment(self.fixture_redeem(competing))
        preparation.discard_unretained(competing)
        self.assertFalse(competing._host.state.parent.exists())
        self.assertTrue(retained._host.state.parent.exists())

    def test_prepared_registered_packet_dispatches_and_closes_after_independent_review(self):
        self.seed_wide_project()
        fixture, inputs, task = self.fake_execution()
        workflow, case = inputs.workflow, inputs.case
        baseline = self.project / 'EXAMPLE-baseline.json'
        observed = []
        original = effects.tools.NamespacedFiniteRpcProcess.result

        def record_before_turn(process, method, params):
            if method == 'turn/start':
                factory = workflow.factory
                dispatch = self.store.require_dispatch(factory.dispatch_id)
                self.assertEqual(dispatch['session_id'], case.scenario.thread_id)
                self.assertEqual(dispatch['provider'], 'openai')
                self.assertEqual(dispatch['model_id'], case.spec['model'])
                self.assertEqual(dispatch['evaluation_metadata']['registered_task']['model_task_sha256'],
                                 sha256(params['input'][0]['text'].encode()).hexdigest())
                observed.append(dispatch)
            return original(process, method, params)

        def lose_delivery_reply(arguments):
            result = self.deliver_bead(arguments)
            if arguments[0] == 'comment' and 'Manual delivery receipt ' in arguments[-1]:
                raise SystemExit('EXAMPLE delivery reply lost')
            return result

        summary = 'Exact prepared candidate ready for hand review.'
        with (patch.object(effects.tools.NamespacedFiniteRpcProcess, 'result', record_before_turn),
              patch.object(manual_delivery, 'project_beads', return_value=(self.database, lose_delivery_reply)),
              patch.object(manual_delivery, 'delivery_session', return_value='EXAMPLE-delivery'),
              self.assertRaisesRegex(SystemExit, 'delivery reply lost')):
            effects.run_fixture(self, inputs, call=lambda: everyday_delegation.delegate(
                workflow, task, baseline=baseline, summary=summary))
        attempt = fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'completed')
        self.assertEqual(pending_target := case.host._observe()['target'], case.host._initial['target'])
        effects_at_failure = len(self.bead['comments'])
        recovered = self.reopen(task, case.ledger)
        self.assertEqual(recovered.config.receipt, workflow.config.receipt)
        self.assertEqual(recovered.config.native_bundle, workflow.config.native_bundle)
        self.assertEqual(recovered.config._standing_approval(), workflow.config._standing_approval())
        self.assert_expired_workflow_refuses_replaced_ledger_parent(recovered, task)
        with (patch.object(recovered.config.ledger, 'clock', return_value=recovered.config.receipt.expires_at),
              patch.object(manual_delivery, 'project_beads', side_effect=self.writable_project_db),
              patch.object(manual_delivery, 'delivery_session', return_value='EXAMPLE-restart')):
            result = everyday_delegation.delegate(recovered, task, baseline=baseline, summary=summary, resume=True)
        self.assertIsNone(recovered.factory)
        self.assertEqual(len(self.bead['comments']), effects_at_failure)
        self.assertEqual(len(observed), 1)
        self.assertEqual(fixture.attempt(case), attempt)
        self.assertEqual(self.bead['status'], 'in_progress')
        self.assertEqual(result['project'], str(self.project))
        self.assertNotEqual(case.host.target, self.project)
        self.assertTrue((self.project / 'EXAMPLE-project-beads.json').exists())
        self.assertEqual(case.host._observe()['target'], case.host._initial['target'])
        self.assertEqual((case.host.worker / 'result.txt').read_bytes(), offline.OUTPUT)
        self.assertFalse((case.host.target / 'result.txt').exists())
        args = Namespace(**result, reviewed_candidate=result['candidate_sha256'], note='Verified the exact candidate.')
        with (patch.object(manual_delivery, 'project_beads', side_effect=self.writable_project_db),
              patch.object(manual_delivery, 'reviewer_session', return_value=('uid:1000', ('EXAMPLE-delivery',))),
              self.assertRaisesRegex(ValueError, 'delivering session')):
            manual_delivery.accept_delivery(args)
        with (patch.object(manual_delivery, 'project_beads', side_effect=self.writable_project_db),
              patch.object(manual_delivery, 'reviewer_session', return_value=('uid:1000', ('EXAMPLE-reviewer',)))):
            closed = manual_delivery.accept_delivery(args)
        self.assertEqual(closed['dispatch_id'], observed[0]['dispatch_id'])
        self.assertTrue(closed['closed'])
        self.assertEqual(case.host._observe()['target'], pending_target)

    def assert_expired_workflow_refuses_replaced_ledger_parent(self, workflow, task):
        ledger = workflow.config.ledger
        parent = ledger.root.parent
        original = parent.with_name('original-control')
        with ExitStack() as restore:
            parent.rename(original)
            restore.callback(original.rename, parent)
            parent.mkdir(mode=0o700)
            restore.callback(parent.rmdir)
            for original_child in original.iterdir():
                if original_child.name == ledger.root.name:
                    continue
                replacement_child = parent / original_child.name
                original_child.rename(replacement_child)
                restore.callback(replacement_child.rename, original_child)
            ledger.root.mkdir()
            ledger.root.chmod(0o755)
            restore.callback(rmtree, ledger.root)
            resume = partial(workflow.resume_delegation, task, database=self.database)
            with (patch.object(ledger, 'clock', return_value=workflow.config.receipt.expires_at) as clock,
                  patch.object(ledger, 'attempt', wraps=ledger.attempt) as attempt):
                for action, reason in ((workflow.run, 'replay-only recovery'),
                                       (resume, 'Original compact registered custody differs')):
                    with self.assertRaises(ValueError) as refusal:
                        action()
                    observed = (clock.call_count, attempt.call_count, ledger.root.stat().st_mode & 0o777,
                                sorted(path.name for path in ledger.root.iterdir()))
                    self.assertEqual(observed, (0, 0, 0o755, []))
                    self.assertIn(reason, str(refusal.exception))

    def test_compact_dispatch_refuses_target_drift_before_claims(self):
        fixture, inputs, task = self.fake_execution()
        config = inputs.workflow.config
        (config.host.target / 'seed.txt').write_bytes(b'EXAMPLE state changed after reopening\n')
        with self.assertRaisesRegex(ValueError, 'Current repository state differs from original compact custody'):
            effects.run_fixture(self, inputs, call=lambda: inputs.workflow.delegate(task, database=self.database))
        self.assertIsNone(inputs.workflow.factory)
        self.assertFalse(fixture.spawned)
        self.assertFalse(config.store.read_state()['operations'])
        self.assertFalse(config.ledger.root.exists())
        self.assertFalse(list(config.state.iterdir()))

    def test_drifted_actual_thread_refuses_before_task_turn_or_output(self):
        fixture, inputs, task = self.fake_execution()
        inputs.case.drift = True
        with self.assertRaisesRegex(ValueError, 'profile readback'):
            effects.run_fixture(self, inputs, call=lambda: inputs.workflow.delegate(task, database=self.database))
        self.assertEqual(len(fixture.spawned), 1)
        self.assertIn('thread/start', fixture.spawned[0].methods)
        self.assertNotIn('turn/start', fixture.spawned[0].methods)
        self.assertIsNone(inputs.workflow.factory.dispatch_record_sha256)
        self.assertFalse((inputs.case.host.worker / 'result.txt').exists())

    def fake_execution(self):
        task, _baseline, accepted = self.foreground_offer(offline.OUTPUT.decode())
        self.assertFalse(accepted['isError'], accepted)
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        fixture = effects.F.FactoryTests('runTest')
        fixture.setUp()
        self.addCleanup(effects.F.cleanup_helper, self, fixture)
        case = fixture.case(production=True, no_fake_scheduler=True, archive_schedule='settled')
        ctypes.CDLL.return_value.renameat2 = rename
        workflow = self.reopen(task, case.ledger)
        config = workflow.config
        case.host, case.ledger, case.receipt = config.host, config.ledger, config.receipt
        case.spec = config.native_bundle[0]['registered_n1']
        case.scenario = effects.F.fixtures.AdmittedFakeServer(case.host.state / 'fake-server', case.host.worker, '')
        case.home = case.scenario.codex_home
        case.scenario.ledger, case.scenario.admission = case.ledger, case.receipt
        case.scenario.expected_observers = ['RegisteredN1Factory._observer']
        case.scenario.initialize_home = preparation.runtime.qualification.LOGIN_MOUNT

        class FactoryReference:
            @property
            def server(self):
                return workflow.factory.server

        case.factory = FactoryReference()
        return fixture, SimpleNamespace(workflow=workflow, case=case), task

    def reopen(self, task, ledger):
        ledger_init = type(ledger).__init__
        defaults = dict(ledger_init.__kwdefaults__, owner_probe=ledger.owner_probe)
        with chdir(self.project), patch.object(ledger_init, '__kwdefaults__', defaults):
            return preparation.entry.open_assignment(task, self.chain)

    @staticmethod
    def fixture_redeem(pending):
        verifier = pending._verifier
        directive = preparation.authority.sign_controller_directive(
            verification_key=verifier._key, actor_id=verifier._actor, identity_source=verifier._identity,
            action_sha256=preparation.workflow.digest(pending.approval_scope), directive_id='EXAMPLE-human-fixture',
            parent_receipt_sha256=verifier._directive_hash)
        return pending.create_workflow(directive)

    def foreground_offer(self, output, *, accept=True, expect_question=True):
        task = 'Update the project documentation for the scoped result file.'
        baseline = self.project / 'EXAMPLE-baseline.json'
        baseline.write_text(json.dumps(self.chain['baseline']), encoding='utf-8')
        decision = {'action': 'accept', 'content': {'approve': True}} if accept else {'action': 'decline'}
        request_id = 'cwo-standing-EXAMPLE'
        frames = [
            {'id': 1, 'method': 'initialize', 'params': {'capabilities': {'elicitation': {'form': {}}}}},
            {'method': 'notifications/initialized'},
            {'id': 2, 'method': 'tools/call', 'params': {'name': 'authorize_assignment', 'arguments': {
                'task': task, 'baseline': baseline.name, 'output_path': 'result.txt', 'output_text': output}}},
            {'id': request_id, 'result': decision},
        ]
        source = StringIO(''.join(json.dumps({'jsonrpc': '2.0', **frame}) + '\n' for frame in frames))
        sink = StringIO()
        with patch.object(foreground, 'uuid4', return_value=SimpleNamespace(hex='EXAMPLE')):
            foreground.serve(source, sink, self.project)
        _initialized, *questions, answer = map(json.loads, sink.getvalue().splitlines())
        self.assertEqual([question['method'] for question in questions],
                         ['elicitation/create'] if expect_question else [])
        if expect_question:
            self.assertEqual(questions[0]['id'], request_id)
        self.assertEqual(answer['id'], 2)
        return task, baseline, answer['result']

    def test_foreground_renews_an_expired_unstarted_approval(self):
        now = int(time.time())
        output = offline.OUTPUT.decode()
        ledger = preparation.admission.ledger_api.InvocationLedger
        with patch.object(ledger, 'current_time', side_effect=lambda: now):
            task, baseline, accepted = self.foreground_offer(output)
            self.assertFalse(accepted['isError'], accepted)
            with chdir(self.project):
                original = preparation.entry.open_assignment(task, self.chain)
                now = original.config.receipt.expires_at
                stderr = StringIO()
                with redirect_stderr(stderr), self.assertRaises(SystemExit) as failure:
                    cwo.main(['delegate', '--task', task, '--baseline', str(baseline), '--summary', 'Hand review'])
                self.assertEqual(failure.exception.code, 1)
                self.assertIn('admission is expired', stderr.getvalue())
                self.assertIn('approve a fresh admission', stderr.getvalue())

                _task, _baseline, declined = self.foreground_offer(output, accept=False)
                self.assertTrue(declined['isError'], declined)
                self.assertFalse(list(original.config.state.iterdir()))

                _task, _baseline, renewed = self.foreground_offer(output)
                self.assertFalse(renewed['isError'], renewed)
                current = preparation.entry.open_assignment(task, self.chain)
                self.assertGreater(current.config.receipt.expires_at, now)
                self.assertNotEqual(current.config.host.state, original.config.host.state)
                now = original.config.receipt.issued_at
                with self.assertRaisesRegex(ValueError, 'Existing or unknown controller intent'):
                    original.delegate(task, database=self.database)
                for attempt in (original, current):
                    self.assertFalse(attempt.verifier._current()['operations'])
                    self.assertFalse(attempt.config.ledger.root.exists())
                    self.assertIsNone(attempt.factory)

    def test_foreground_can_retry_after_interrupted_approval_replacement(self):
        now = int(time.time())
        output = offline.OUTPUT.decode()
        ledger = preparation.admission.ledger_api.InvocationLedger
        write = host_records._write_at

        def interrupt(directory, name, raw, **options):
            if options.get('replace') and name.startswith('standing-delegation-'):
                raise OSError('EXAMPLE lost selector update')
            return write(directory, name, raw, **options)

        with patch.object(ledger, 'current_time', side_effect=lambda: now), chdir(self.project):
            task, _baseline, accepted = self.foreground_offer(output)
            self.assertFalse(accepted['isError'], accepted)
            original = preparation.entry.open_assignment(task, self.chain)
            now = original.config.receipt.expires_at
            with patch.object(host_records, '_write_at', side_effect=interrupt):
                _task, _baseline, error = self.foreground_offer(output)
            self.assertTrue(error['isError'])
            self.assertIn('host state unavailable or unsafe', error['content'][0]['text'])
            self.assertEqual(preparation.entry.open_assignment(task, self.chain).config.host.state,
                             original.config.host.state)
            now = original.config.receipt.issued_at
            with self.assertRaisesRegex(ValueError, 'Existing or unknown controller intent'):
                original.delegate(task, database=self.database)
            _task, _baseline, renewed = self.foreground_offer(output)
            self.assertFalse(renewed['isError'], renewed)
            current = preparation.entry.open_assignment(task, self.chain)
            self.assertNotEqual(current.config.host.state, original.config.host.state)
            self.assertFalse(original.verifier._current()['operations'])
            self.assertFalse(original.config.ledger.root.exists())

    def test_foreground_cannot_renew_an_expired_claimed_approval(self):
        now = int(time.time())
        output = offline.OUTPUT.decode()
        ledger = preparation.admission.ledger_api.InvocationLedger
        with patch.object(ledger, 'current_time', side_effect=lambda: now), chdir(self.project):
            task, _baseline, accepted = self.foreground_offer(output)
            self.assertFalse(accepted['isError'], accepted)
            original = preparation.entry.open_assignment(task, self.chain)
            _plan, operation, _directive = original.config.native_bundle
            original.config.store.claim_operation(operation['operation_id'], preparation.workflow.digest(operation),
                                                  operation['plan_sha256'], operation['revocation_generation'])
            now = original.config.receipt.expires_at
            self.foreground_offer(output, expect_question=False)
            current = preparation.entry.open_assignment(task, self.chain)
            self.assertEqual(current.config.host.state, original.config.host.state)
            self.assertEqual(current.verifier._current()['operations'][operation['operation_id']]['state'], 'claimed')
            self.assertFalse(list(current.config.state.iterdir()))

    def test_foreground_discards_refused_offer_and_preserves_retained_offer(self):
        output = offline.OUTPUT.decode()
        _task, _baseline, refused = self.foreground_offer(output, accept=False)
        self.assertTrue(refused['isError'])
        self.assertIn('did not approve', refused['content'][0]['text'])
        custody = preparation._offer_parent(self.store)
        self.assertEqual(list(custody.iterdir()), [])
        self.assertEqual(list(self.store.state_root.glob('standing-delegation-*.json')), [])

        task, _baseline, accepted = self.foreground_offer(output)
        self.assertFalse(accepted['isError'], accepted)
        with chdir(self.project):
            original = preparation.entry.open_assignment(task, self.chain)
        self.assertEqual(list(custody.iterdir()), [original.config.host.state.parent])
        self.assertFalse(original.verifier._current()['operations'])
        self.assertFalse(original.config.ledger.root.exists())
