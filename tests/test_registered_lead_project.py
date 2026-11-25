"""Witness a normal registered delivery while the original lead project Beads bytes change."""
from __future__ import annotations

from contextlib import chdir
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_everyday_delegation as fixture
from tests import test_delegate_internal_work as native

import registered_delegation_entry as entry
from cwo_core import requirement_baseline


class RegisteredLeadProjectTests(unittest.TestCase):
    accept = fixture.EverydayDelegationFlowTests.accept
    delegate_command = fixture.EverydayDelegationFlowTests.delegate_command

    def setUp(self):
        fixture.EverydayDelegationFlowTests.setUp(self, separate_project=True)
        self.project = self.workflow.config.project
        self.project_state = self.project / '.beads' / 'EXAMPLE-state.json'
        self.project_state.parent.mkdir()
        self.project_state.write_text('[]\n', encoding='utf-8')

    def bd(self, argv):
        if argv[0] in ('comment', 'close'):
            self.project_state.write_text(json.dumps([*self.effects, argv]) + '\n', encoding='utf-8')
        return fixture.EverydayDelegationFlowTests.bd(self, argv)

    def test_project_database_changes_do_not_drift_registered_target_or_retry(self):
        workflow, host = self.workflow, self.workflow.config.host
        self.assertNotEqual(self.project, host.target)
        wrong = native.StandingDelegation(baseline_sha256=self.baseline_digest, database_sha256=native.DATABASE,
                                          capability_evidence={}, cache_profile={}, project=str(host.target))
        with self.assertRaisesRegex(ValueError, 'separate immutable native target'):
            native.W.D.project_checkout(host, wrong)
        scope, _ = workflow.config._standing_approval()
        self.assertEqual(scope['project'], str(self.project))
        self.assertEqual(scope['target'], str(host.target))
        expected = host._initial['target']
        entry.retain_approved_assignment(workflow)
        baseline = requirement_baseline.resolve_chain(json.loads(self.baseline.read_text()))

        summary = 'Ready for independent review of the exact registered result.'
        code, _, error = native.run_fixture(self, self.inputs, call=lambda: self.delegate_command(workflow, summary))
        self.assertEqual(code, 1, error)
        self.assertIn('comment reply lost', error)
        self.assertEqual([item[0] for item in json.loads(self.project_state.read_bytes())], ['comment', 'comment'])
        self.assertEqual(host._observe()['target'], expected)
        accounting = self.inputs.fixture.attempt(self.inputs.case)

        ledger = self.inputs.case.ledger
        clock_defaults = dict(type(ledger).__init__.__kwdefaults__, clock=ledger.clock, owner_probe=ledger.owner_probe)
        with patch.object(type(ledger).__init__, '__kwdefaults__', clock_defaults):
            with chdir(host.target), self.assertRaisesRegex(ValueError, 'No protected standing approval'):
                entry.open_assignment(self.inputs.task, baseline)
            with chdir(self.project):
                recovered = entry.open_assignment(self.inputs.task, baseline)
                code, output, error = self.delegate_command(recovered, summary, resume=True)
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertIsNone(recovered.factory)
        self.assertEqual(self.inputs.fixture.attempt(self.inputs.case), accounting)
        self.assertEqual(result['project'], str(self.project))
        self.assertEqual(Path(result['repo']), host.worker)
        self.assertEqual(recovered.config.host.target, host.target)
        self.assertEqual(recovered.config._standing_approval()[0], scope)
        code, output, error = self.accept(result, 'EXAMPLE-independent-reviewer')
        self.assertEqual(code, 0, error)
        self.assertTrue(json.loads(output)['closed'])
        self.assertEqual([item[0] for item in json.loads(self.project_state.read_bytes())],
                         ['comment', 'comment', 'close'])
        self.assertEqual(host._observe()['target'], expected)
        self.assertEqual({call.args[0] for call in self.project_beads.call_args_list}, {self.project, host.target})

        self.project.rename(self.project.with_name('EXAMPLE-original-project'))
        self.inputs.fixture.repositories.clone(self.project.name)
        with chdir(self.project), self.assertRaisesRegex(ValueError, 'original standing approval.*scope'):
            entry.open_assignment(self.inputs.task, baseline)


if __name__ == '__main__':
    unittest.main()
