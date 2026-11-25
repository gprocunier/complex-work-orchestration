"""Delivery custody through the existing foreground hand-close command."""
from __future__ import annotations

from argparse import Namespace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import everyday_delegation_delivery as delivery  # noqa: E402
from cwo_core import candidate_identity as ci, manual_delivery as manual, requirement_baseline as rb  # noqa: E402
from tests import test_candidate_identity as candidate_fixtures  # noqa: E402
from tests import test_manual_acceptance as hand  # noqa: E402
from tests import test_registered_n1_workflow as native  # noqa: E402


class DelegatedDeliveryTests(unittest.TestCase):
    def test_a_workflow_without_original_completion_cannot_deliver(self):
        with self.assertRaisesRegex(ValueError, 'original registered workflow'):
            delivery.record_delivery(object(), None, 'EXAMPLE original completion is required')

    def test_acceptance_claim_cannot_switch_to_a_later_delivery(self):
        fixture = hand.ManualAcceptanceTests('runTest')
        self.addCleanup(native.F.cleanup_helper, self, fixture)
        fixture.setUp()
        fixture.deliver()
        original = fixture.store.audit_events()[0]['event_hash']
        fixture.deliver()
        before = fixture.store.audit_events()
        arguments = hand.narrative.parser().parse_args([
            *fixture.inputs, '--disposition', 'pending-acceptance', '--why', 'EXAMPLE delivery'])
        binding = manual.Delivery.from_args(arguments).binding('fixture-database')

        with self.assertRaisesRegex(ValueError, 'delivery changed before acceptance'):
            manual._claim(fixture.store, fixture.bead, binding, 'uid:1000', ('reviewer-process',),
                          'EXAMPLE reviewed candidate', pending_hash=original)

        self.assertEqual(fixture.store.audit_events(), before)
        self.assertEqual([args[0] for args in fixture.effects], ['comment', 'comment'])

    def test_legacy_native_completion_and_drifted_candidate_cannot_record_delivery(self):
        helper = native.WorkflowTests('runTest')
        self.addCleanup(native.F.cleanup_helper, self, helper)
        helper.setUp()
        helper.run_native(archive_schedule='settled')
        host = helper.workflow.config.host
        output = host.worker / 'result.txt'
        original = output.read_bytes()
        baseline = candidate_fixtures.fixture('baseline-v1.json')
        chain = rb.resolve_chain(baseline)
        baseline_file = host.state.parent / 'baseline.json'
        baseline_file.write_text(json.dumps(baseline), encoding='utf-8')
        candidate_file = host.state.parent / 'candidate.json'
        args = Namespace(bead=chain['bead_id'], repo=str(host.worker), baseline=str(baseline_file),
                         candidate=str(candidate_file), amendment=[])
        original_audit = helper.fixture.host_records.audit_events()

        for content, expected in ((b'EXAMPLE changed candidate\n', 'candidate bytes'),
                                  (original, 'original signed delegation custody')):
            with self.subTest(expected=expected):
                output.write_bytes(content)
                head = candidate_fixtures.git(host.worker, 'rev-parse', 'HEAD')
                candidate = ci.capture_candidate(host.worker, chain=chain, base_commit=head, scope_paths=['result.txt'])
                candidate_file.write_text(json.dumps(candidate), encoding='utf-8')
                bead = candidate_fixtures.bead(args.bead, rb.reference_line(args.bead, 1, chain['digest']),
                                               ci.candidate_reference_line(args.bead, ci.candidate_digest(candidate)))
                beads = candidate_fixtures.BeadsSpy(bead)
                with patch.object(manual, 'project_beads', return_value=('EXAMPLE-db', beads.run_bd)), \
                        patch.object(manual, 'delivery_session', return_value='EXAMPLE-delivering-process'):
                    with self.assertRaisesRegex(ValueError, expected):
                        delivery.record_delivery(helper.workflow, args, 'EXAMPLE bounded delivery')
                self.assertEqual(beads.writes(), [])
                self.assertEqual(helper.fixture.host_records.audit_events(), original_audit)
