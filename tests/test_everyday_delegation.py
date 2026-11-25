"""Exercise protected dispatch through the installed hand acceptance entry point."""
from __future__ import annotations

from contextlib import chdir, redirect_stderr, redirect_stdout
from argparse import Namespace
import ctypes
from io import StringIO
import json
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from tests import test_delegate_internal_work as native
from tests.test_candidate_identity import bead

import cwo
import everyday_delegation
import registered_delegation_foreground as foreground
from cwo_core import candidate_identity, manual_delivery, requirement_baseline


class EverydayDelegationFlowTests(unittest.TestCase):
    def setUp(self, *, separate_project=False):
        bead_id = native.F.example_route(tiny=True)['parent_id']
        baseline = {'record_type': 'cwo-requirement-baseline', 'version': 1,
                    'bead_id': bead_id, 'baseline_version': 1, 'criteria': [{
                        'id': 'result-file', 'requirement': 'Produce the scoped result file.',
                        'reference': 'Example assignment', 'expected_outcome': 'The exact result is delivered.',
                        'applicability': 'required', 'evidence_kind': 'artifact'}]}
        self.baseline_digest = requirement_baseline.record_digest(baseline)
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        self.inputs = native.make_workflow(self, baseline_sha256=self.baseline_digest, from_setup=True,
                                           separate_project=separate_project)
        # Keep descriptor-based file publication real under the fake spawn libc.
        ctypes.CDLL.return_value.renameat2 = rename
        self.workflow = self.inputs.workflow
        self.baseline = self.workflow.config.host.state.parent / 'EXAMPLE-baseline.json'
        self.baseline.write_text(json.dumps(baseline), encoding='utf-8')
        self.task = bead(bead_id, requirement_baseline.reference_line(bead_id, 1, self.baseline_digest))
        self.effects = []
        self.lose_delivery_reply = True
        self.fail_before_delivery = False
        self.project_beads = self.enterContext(patch.object(manual_delivery, 'project_beads',
                                                            return_value=(native.DATABASE, self.bd)))
        self.enterContext(patch.object(manual_delivery, 'delivery_session', return_value='EXAMPLE-lead'))

    def bd(self, argv):
        if argv[0] == 'show':
            return json.dumps([self.task])
        if argv[0] == 'dep':
            return '[]'
        if self.fail_before_delivery and argv[0] == 'comment' and 'Manual delivery receipt ' in argv[-1]:
            self.fail_before_delivery = False
            raise SystemExit('EXAMPLE comment not posted')
        self.effects.append(argv)
        if argv[0] == 'comment':
            self.task['comments'].append({'text': argv[-1]})
            if self.lose_delivery_reply and 'Manual delivery receipt ' in argv[-1]:
                self.lose_delivery_reply = False
                raise SystemExit('EXAMPLE comment reply lost')
        elif argv[0] == 'close':
            self.task.update(status='closed', close_reason=argv[argv.index('--reason') + 1])
        else:
            self.fail(f'Unexpected Beads command {argv}')
        return ''

    def accept(self, result, process):
        arguments = ['accept-delivery', '--bead', result['bead'], '--repo', result['repo'],
                     '--baseline', result['baseline'], '--candidate', result['candidate'],
                     '--reviewed-candidate', result['candidate_sha256'],
                     '--note', 'Checked the result file.', '--json']
        if 'project' in result:
            arguments.extend(['--project', result['project']])
        stdout, stderr = StringIO(), StringIO()
        with (patch.object(manual_delivery, 'reviewer_session', return_value=('uid:1000', (process,))),
              patch.object(sys, 'argv', sys.argv[:]), redirect_stdout(stdout), redirect_stderr(stderr),
              self.assertRaises(SystemExit) as exit):
            cwo.main(arguments)
        return exit.exception.code, stdout.getvalue(), stderr.getvalue()

    def delegate_command(self, workflow, summary, *, resume=False, task=None):
        arguments = ['delegate', '--task', task or self.inputs.task, '--baseline', str(self.baseline),
                     '--summary', summary]
        if resume:
            arguments.append('--resume')
        stdout, stderr = StringIO(), StringIO()
        with (patch.object(sys, 'argv', sys.argv[:]), redirect_stdout(stdout), redirect_stderr(stderr),
              self.assertRaises(SystemExit) as exit):
            if workflow is None:
                cwo.main(arguments)
            else:
                cwo.main(arguments, delegation_workflow=workflow)
        return exit.exception.code, stdout.getvalue(), stderr.getvalue()

    def restart(self):
        host = self.workflow.config.host
        settings = dict(self.inputs.settings, host=native.W.H.OfflineN1Host(host.state, host.target, host.worker))
        return native.W.RegisteredN1Workflow(native.W.ControllerConfiguration(**settings))

    def choose_foreground_approval(self, pending, *, output_text):
        request_id = UUID(int=524)
        args = {'task': self.inputs.task, 'baseline': str(self.baseline),
                'output_path': 'result.txt', 'output_text': output_text}
        messages = [
            {'method': 'initialize', 'id': 1, 'params': {'protocolVersion': '2025-11-25',
                                                        'capabilities': {'elicitation': {}}}},
            {'method': 'notifications/initialized'},
            {'method': 'tools/call', 'id': 2, 'params': {'name': 'authorize_assignment', 'arguments': args}},
            {'id': 'cwo-standing-' + request_id.hex, 'result': {'action': 'accept', 'content': {'approve': True}}},
        ]
        source = StringIO(''.join(json.dumps({'jsonrpc': '2.0', **message}) + '\n' for message in messages))
        response = StringIO()
        compiler = Mock(return_value=pending)
        with (patch.object(foreground, 'uuid4', return_value=request_id),
              patch.dict(sys.modules, {'registered_delegation_preparation': SimpleNamespace(prepare=compiler)})):
            foreground.serve(source, response, self.workflow.config.host.target)
        return [json.loads(line) for line in response.getvalue().splitlines()], compiler

    def test_registered_delegation_delivers_exact_candidate_and_independent_cli_closes(self):
        summary = 'Ready for independent review of the result file.'
        code, _, error = native.run_fixture(self, self.inputs, call=lambda: self.delegate_command(self.workflow, summary))
        self.assertEqual(code, 1)
        self.assertIn('comment reply lost', error)
        with (patch.object(manual_delivery, 'project_beads', return_value=('0' * 64, self.bd)),
              self.assertRaisesRegex(ValueError, 'original native dispatch must bind .* Beads database')):
            everyday_delegation.deliver(self.workflow, baseline=self.baseline, summary=summary)
        factory = self.workflow.factory
        recovered = self.restart()
        accounting = self.inputs.fixture.attempt(self.inputs.case)
        self.inputs.case.ledger.clock.now = self.inputs.case.receipt.expires_at
        with (patch.object(manual_delivery, 'delivery_session', return_value='EXAMPLE-restarted-lead'),
              patch.object(native.W.R.live_availability, 'REGISTERED_N1_LIVE_AVAILABLE', False)):
            code, _, error = self.delegate_command(recovered, summary, resume=True, task='EXAMPLE other work')
            self.assertEqual(code, 1)
            self.assertIn('original admitted task', error)
            code, output, error = self.delegate_command(recovered, summary, resume=True)
        self.assertEqual(code, 0, error)
        self.assertIsNone(recovered.factory)
        result = json.loads(output)
        self.assertEqual(self.inputs.fixture.attempt(self.inputs.case), accounting)
        self.assertEqual(self.task['status'], 'in_progress')
        self.assertEqual(len(self.effects), 2)
        self.assertEqual(self.effects[0][-1], candidate_identity.candidate_reference_line(
            self.task['id'], result['candidate_sha256']))
        self.assertEqual(result['delivery_comment'].strip(), self.effects[1][-1])
        store = factory.host_records
        posted = [event for event in store.audit_events() if event['event_type'] == manual_delivery.RECORDED]
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]['dispatch_id'], factory.dispatch_id)
        self.assertEqual(posted[0]['baseline_sha256'], self.baseline_digest)
        self.assertEqual(posted[0]['manual_database_sha256'], native.DATABASE)
        with self.assertRaisesRegex(ValueError, 'use the original registered delivery'):
            manual_delivery.record_delivery(Namespace(**result), 'Unbound repost of the same candidate.')
        code, _, error = self.accept(result, 'EXAMPLE-lead')
        self.assertNotEqual(code, 0)
        self.assertIn('delivering session', error)
        self.assertEqual(self.task['status'], 'in_progress')
        code, output, error = self.accept(result, 'EXAMPLE-independent-reviewer')
        self.assertEqual(code, 0, error)
        accepted = json.loads(output)
        self.assertTrue(accepted['closed'])
        self.assertEqual(accepted['candidate_sha256'], result['candidate_sha256'])
        self.assertEqual(accepted['dispatch_id'], factory.dispatch_id)
        self.assertEqual(accepted['return_sha256'], posted[0]['return_sha256'])
        self.assertEqual(self.task['status'], 'closed')
        self.assertEqual([call[0] for call in self.effects], ['comment', 'comment', 'close'])
        self.assertFalse((self.workflow.config.host.target / 'result.txt').exists())
        host = self.workflow.config.host
        self.assertEqual(result['repo'], str(host.worker))
        self.assertEqual(result['project'], str(host.target))
        self.assertTrue(self.project_beads.call_args_list)
        self.assertEqual({call.args[0] for call in self.project_beads.call_args_list}, {host.target})

    def test_resume_after_failed_post_preserves_independence_of_both_sessions(self):
        self.fail_before_delivery = True
        self.lose_delivery_reply = False
        summary = 'Ready for independent review.'
        with self.assertRaisesRegex(SystemExit, 'comment not posted'):
            native.run_fixture(self, self.inputs, call=lambda: everyday_delegation.delegate(
                self.workflow, self.inputs.task, baseline=self.baseline, summary=summary))
        with patch.object(manual_delivery, 'delivery_session', return_value='EXAMPLE-restarted-lead'):
            result = everyday_delegation.deliver(self.workflow, baseline=self.baseline, summary=summary)
        self.assertEqual(len(self.effects), 2)
        for session in ('EXAMPLE-lead', 'EXAMPLE-restarted-lead'):
            code, _, error = self.accept(result, session)
            self.assertEqual(code, 1)
            self.assertIn('delivering session', error)
        code, _, error = self.accept(result, 'EXAMPLE-independent-reviewer')
        self.assertEqual(code, 0, error)

    def test_command_inputs_do_not_supply_a_trusted_workflow(self):
        with chdir(self.workflow.config.host.target):
            code, _, error = self.delegate_command(None, 'Review this candidate.')
        self.assertEqual(code, 1)
        self.assertIn('No protected standing approval matches', error)
        self.assertEqual(self.effects, [])

    def test_installed_skipped_setup_reports_the_existing_setup_command(self):
        with (patch.object(native.W.login_config, 'read_worker_login_home', return_value=None),
              patch.object(manual_delivery, 'project_beads', side_effect=AssertionError('unexpected project lookup'))):
            code, _, error = self.delegate_command(None, 'Review this candidate.')
        self.assertEqual(code, 1)
        self.assertIn(native.W.delegation_setup_message(), error)
        self.assertEqual(self.effects, [])

    def test_retained_approval_cannot_replace_its_controller_or_custody(self):
        import registered_delegation_entry as entry

        entry.retain_approved_assignment(self.workflow)
        store = self.inputs.fixture.host_records.state_root
        approval, = store.glob('standing-delegation-*.json')
        key, = (store / entry._KEY_DIRECTORY).glob('*.key')
        original = approval.read_bytes()
        envelope = json.loads(original)
        self.assertNotIn('verification_key', envelope['approval'])
        with chdir(self.workflow.config.host.target):
            envelope['approval']['authority_state'][0] = str(self.workflow.config.host.state)
            approval.write_text(json.dumps(envelope))
            code, _, error = self.delegate_command(None, 'Review this candidate.')
            self.assertEqual(code, 1)
            self.assertIn('does not match the protected project controller', error)
            approval.write_bytes(original)
            key.write_bytes(b'EXAMPLE substitute trust anchor')
            code, _, error = self.delegate_command(None, 'Review this candidate.')
            self.assertEqual(code, 1)
            self.assertIn('does not match the protected project controller', error)
        self.assertFalse(self.workflow.config.store.read_state()['operations'])
        self.assertEqual(self.effects, [])

    def test_installed_lead_selects_the_retained_signed_assignment(self):
        from registered_delegation_approval import prepare_assignment
        from tests.test_registered_delegation_approval import fixture_preparation

        preparation = fixture_preparation(self.inputs)
        pending = prepare_assignment(**preparation)
        self.assertFalse(self.workflow.config.store.read_state()['operations'])
        output_text = native.F.fixtures.host_fixtures.OUTPUT.decode()
        ledger_class = type(self.inputs.case.ledger)
        ledger_defaults = dict(ledger_class.__init__.__kwdefaults__, clock=self.inputs.case.ledger.clock,
                               owner_probe=self.inputs.case.ledger.owner_probe)
        with patch.object(ledger_class.__init__, '__kwdefaults__', ledger_defaults):
            responses, compiler = self.choose_foreground_approval(pending, output_text=output_text)
            self.assertEqual(responses[1]['method'], 'elicitation/create')
            self.assertFalse(responses[-1]['result']['isError'], responses)
            compiler.assert_called_once()
            reused, compiler = self.choose_foreground_approval(pending, output_text=output_text)
            self.assertEqual(len(reused), 2)
            self.assertFalse(reused[-1]['result']['isError'], reused)
            compiler.assert_not_called()
            changed, compiler = self.choose_foreground_approval(pending, output_text=output_text + 'changed')
            self.assertTrue(changed[-1]['result']['isError'], changed)
            compiler.assert_not_called()
        summary = 'Ready for independent review.'
        case = self.inputs.case
        original_init = native.W.RegisteredN1Workflow.__init__
        selected = []

        def observe_selection(workflow, config):
            original_init(workflow, config)
            selected.append(workflow)
            self.inputs.workflow, case.host = workflow, config.host

        class SelectedWorkflow:
            @property
            def factory(inner):
                return selected[-1].factory if selected else None

            @property
            def server(inner):
                return inner.factory.server

        self.inputs.workflow = SelectedWorkflow()
        case.factory = self.inputs.workflow
        with (chdir(self.workflow.config.host.target),
              patch.object(ledger_class.__init__, '__kwdefaults__', ledger_defaults),
              patch.object(native.W.RegisteredN1Workflow, '__init__', observe_selection)):
            with chdir(self.workflow.config.host.worker):
                code, _, error = self.delegate_command(None, summary)
            self.assertEqual(code, 1)
            self.assertIn('No protected standing approval matches', error)
            code, _, error = self.delegate_command(None, summary, task='EXAMPLE unapproved task')
            self.assertEqual(code, 1)
            self.assertIn('No protected standing approval matches', error)
            self.assertEqual(selected, [])
            code, _, error = native.run_fixture(self, self.inputs,
                call=lambda: self.delegate_command(None, summary))
            self.assertEqual(code, 1)
            self.assertIn('comment reply lost', error)
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0].factory.operation_id, preparation['native_operation_id'])
            self.assertEqual(selected[0].config._standing_approval()[0], pending.approval_scope)
            charged = self.inputs.fixture.attempt(case)
            self.assertEqual(charged['outcome'], 'completed')
            case.ledger.clock.now = case.receipt.expires_at
            with patch.object(native.W.R.live_availability, 'REGISTERED_N1_LIVE_AVAILABLE', False):
                code, output, error = self.delegate_command(None, summary, resume=True)
            self.assertEqual(code, 0, error)
            result = json.loads(output)
            self.assertEqual(result['bead'], self.task['id'])
            self.assertEqual(self.inputs.fixture.attempt(case), charged)
            self.assertIsNone(selected[-1].factory)
        code, _, error = self.accept(result, 'EXAMPLE-lead')
        self.assertNotEqual(code, 0)
        self.assertIn('delivering session', error)
        code, output, error = self.accept(result, 'EXAMPLE-independent-reviewer')
        self.assertEqual(code, 0, error)
        self.assertTrue(json.loads(output)['closed'])

    def test_completed_custody_can_recover_after_admission_expiration(self):
        native.run_fixture(self, self.inputs)
        recovered = self.restart()
        self.inputs.case.ledger.clock.now = self.inputs.case.receipt.expires_at
        self.assertTrue(recovered.recover()['validation_complete'])
        self.assertIsNone(recovered.factory)

    def test_missing_baseline_reference_blocks_dispatch_and_delivery(self):
        self.task['comments'].clear()
        with self.assertRaisesRegex(ValueError, 'baseline'):
            everyday_delegation.delegate(self.workflow, self.inputs.task, baseline=self.baseline,
                                         summary='Review the result.')
        self.assertIsNone(self.workflow.factory)
        self.assertFalse(self.workflow.config.store.read_state()['operations'])
        self.assertEqual(self.effects, [])

    def test_different_database_refuses_before_any_dispatch_claim(self):
        with (patch.object(manual_delivery, 'project_beads', return_value=('0' * 64, self.bd)),
              self.assertRaisesRegex(ValueError, 'must use the original Beads database')):
            everyday_delegation.delegate(self.workflow, self.inputs.task, baseline=self.baseline,
                                         summary='Review the result.')
        self.assertIsNone(self.workflow.factory)
        self.assertFalse(self.workflow.config.store.read_state()['operations'])
        self.assertEqual(self.effects, [])


if __name__ == '__main__':
    unittest.main()
