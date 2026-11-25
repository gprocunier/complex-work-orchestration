"""Linked start accounting in disposable qualification ledgers."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha256
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cwo_core import native_pool_qualification_stage as stage
from cwo_core.invocation_ledger import InvocationLedger, InvocationLedgerError
from cwo_core.native_pool_transaction import NativePoolTransactionError
import run_native_pool_qualification as controller


def reserve_fixture_start(ledger, name, *, budget_id=stage.CAMPAIGN_BUDGET_ID):
    payload = name.encode()
    digest = sha256(payload).hexdigest()
    reservation = ledger.reserve(budget_id=budget_id, request_id=name, request_sha256=digest, admission_sha256=digest,
                                 amount={"starts": 1}, expires_at=ledger.current_time() + 300)
    return reservation, payload


def record_fixture_starts(ledger, count, *, failed_index=None):
    for index in range(count):
        reserved, payload = reserve_fixture_start(ledger, f"prior-request-{index}")
        ledger.begin_invocation(reserved["reservation_id"], payload)
        outcome = "failed" if index == failed_index else "completed"
        ledger.finish(reserved["reservation_id"], outcome, reason="inert ledger witness")


class QualificationBudgetTests(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        root = Path(stack.enter_context(TemporaryDirectory()))
        stack.enter_context(patch.object(stage, "contained_campaign_ledger_root", return_value=root))
        self.ledger = InvocationLedger(root)
        self.expiry = int(self.ledger.current_time()) + 300
        self.original = self.ledger.open_budget(stage.CAMPAIGN_BUDGET_ID, {"starts": 20},
                                                scope_sha256=stage.CAMPAIGN_SCOPE_SHA256)

    def _document(self):
        with self.ledger._locked() as (_root, document):
            return document

    def _enroll(self, limit, *, count=6, expiry=None):
        stage._require_campaign_enrollment(expires_at=self.expiry if expiry is None else expiry,
                                           run_count=count, campaign_start_limit=limit)

    def _allowance(self, limit, *, binding="b" * 64):
        approval = stage._CampaignApproval(binding, "e" * 64, self.expiry, (), os.getpid(), None,
                                           stage._CAMPAIGN_APPROVAL_TOKEN, campaign_start_limit=limit)
        accounting = stage.PoolQualificationAccounting(self.ledger, self.expiry, approval)
        return SimpleNamespace(accounting=accounting, stage_sha256=binding, check_custody=lambda: None)

    @staticmethod
    def _run(index):
        return SimpleNamespace(plan={"transaction_id": f"new-{index}", "plan_sha256": "c" * 64})

    def test_six_start_roster_crosses_the_original_immutable_allowance(self):
        record_fixture_starts(self.ledger, 16, failed_index=3)
        unstarted, _ = reserve_fixture_start(self.ledger, "not-started")
        self.ledger.release(unstarted["reservation_id"])
        before = self._document()
        with self.assertRaisesRegex(NativePoolTransactionError, "campaign-start-cap-exhausted"):
            stage._require_campaign_enrollment(expires_at=self.expiry, run_count=6)
        self._enroll(30)
        enrollment = self._document()
        self.assertEqual(enrollment["attempts"], before["attempts"])
        self.assertEqual(enrollment["budgets"][self.original["budget_id"]], self.original)
        status = stage.campaign_start_status(self.ledger)
        self.assertEqual((status["charged"], status["cap"], status["remaining"]), (16, 30, 14))
        base, increment = status["budget_ids"]

        allowance = self._allowance(30)
        new_reservations = []
        with patch.object(stage, "_require_contained_availability"), stage._campaign_custody(self.ledger.root):
            for index, expected in enumerate((base, base, base, base, increment, increment)):
                reservation, payload = stage._reserve_campaign_start(self._run(index), allowance)
                intent = self.ledger.begin_invocation(reservation, payload)
                self.assertEqual(intent["budget_id"], expected)
                self.ledger.finish(reservation, "completed", reason="inert ledger witness")
                new_reservations.append(reservation)

            with self.assertRaisesRegex(InvocationLedgerError, "admission replay"):
                stage._reserve_campaign_start(self._run(0), allowance)
            retry = self._allowance(30, binding="d" * 64)
            with self.assertRaisesRegex(InvocationLedgerError, "one request is invoked at most once"):
                stage._reserve_campaign_start(self._run(0), retry)

        status = stage.campaign_start_status(self.ledger)
        self.assertEqual((status["charged"], status["cap"], status["remaining"]), (22, 30, 8))
        after = self._document()
        self.assertEqual(after["budgets"], enrollment["budgets"])
        self.assertEqual({key: after["attempts"][key] for key in before["attempts"]}, before["attempts"])
        started, _ = controller._started_campaign_runs(stage, self.ledger, 30)
        self.assertEqual(len(started), 22)
        self.assertEqual([started[key] for key in new_reservations], list(range(17, 23)))
        self.assertNotIn(unstarted["reservation_id"], started)
        with self.assertRaisesRegex(controller.QualificationControllerError, "qualification-record-budget-drift"):
            controller._started_campaign_runs(stage, self.ledger, 20)

    def test_increment_is_idempotent_but_cannot_skip_or_roll_back_capacity(self):
        self._enroll(26)
        first = self._document()
        self._enroll(26)
        self.assertEqual(self._document(), first)
        for limit in (20, 25, 37, 61, True):
            with self.subTest(limit=limit), self.assertRaisesRegex(NativePoolTransactionError, "campaign-start-"):
                self._enroll(limit)
            self.assertEqual(self._document(), first)
        self._enroll(30)
        status = stage.campaign_start_status(self.ledger)
        base, first_increment, second_increment = status["budget_ids"]
        self.assertEqual(status["remaining_by_budget"], {base: 20, first_increment: 6, second_increment: 4})
        self.assertEqual(self._document()["budgets"][first_increment], first["budgets"][first_increment])
        for limit in (40, 50, 60):
            self._enroll(limit)
        self.assertEqual(stage.campaign_start_status(self.ledger)["cap"], 60)

    def test_expired_and_concurrent_enrollment_do_not_append_rows(self):
        before = self._document()
        with self.assertRaisesRegex(InvocationLedgerError, "budget opening authority has expired"):
            self._enroll(30, expiry=int(self.ledger.current_time()) - 1)
        with stage._campaign_custody(self.ledger.root), ThreadPoolExecutor(max_workers=1) as workers:
            with self.assertRaisesRegex(NativePoolTransactionError, "pool-qualification-campaign-already-running"):
                workers.submit(self._enroll, 30).result(timeout=5)
            self.assertEqual(stage.campaign_start_status(self.ledger)["cap"], 20)
        self.assertEqual(self._document(), before)
        self._enroll(30)
        self.assertEqual(stage.campaign_start_status(self.ledger)["cap"], 30)

    def test_increment_expiring_while_waiting_for_the_ledger_lock_refuses(self):
        before = self._document()
        waiting = Event()
        clock = self.expiry - 1
        enrollment_ledger = InvocationLedger(self.ledger.root, clock=lambda: clock)
        prepare = enrollment_ledger._prepare_root

        def announce_wait():
            root = prepare()
            waiting.set()
            return root

        with patch.object(stage, "InvocationLedger", return_value=enrollment_ledger), \
             patch.object(enrollment_ledger, "_prepare_root", side_effect=announce_wait), \
             ThreadPoolExecutor(max_workers=1) as workers:
            with self.ledger._locked():
                enrollment = workers.submit(self._enroll, 30)
                self.assertTrue(waiting.wait(5))
                clock = self.expiry
            with self.assertRaisesRegex(InvocationLedgerError, "budget opening authority has expired"):
                enrollment.result(timeout=5)
        self.assertEqual(self._document(), before)

    def test_active_original_reservation_blocks_increment_and_preserves_history(self):
        existing, payload = reserve_fixture_start(self.ledger, "active")
        before = self._document()
        with self.assertRaisesRegex(NativePoolTransactionError, "campaign-start-unresolved"):
            self._enroll(30)
        self.assertEqual(self._document(), before)
        self.ledger.begin_invocation(existing["reservation_id"], payload)
        self.ledger.mark_reconciliation_required(existing["reservation_id"], reason="inert unknown outcome")
        before = self._document()
        with self.assertRaisesRegex(NativePoolTransactionError, "campaign-start-unresolved"):
            self._enroll(30)
        self.assertEqual(self._document(), before)
        self.ledger.reconcile(existing["attempt_id"], reason="inert manual reconciliation")
        self._enroll(30)
        self.assertEqual(stage.campaign_start_status(self.ledger)["charged"], 1)

    def test_forged_scope_for_an_increment_refuses_instead_of_counting_it(self):
        self.ledger.open_budget(self.original["budget_id"] + ":increment:1", {"starts": 10}, scope_sha256="f" * 64)
        with self.assertRaisesRegex(NativePoolTransactionError, "campaign-allowance-link-invalid"):
            self._enroll(30)
        with self.assertRaisesRegex(NativePoolTransactionError, "campaign-allowance-link-invalid"):
            stage.campaign_start_status(self.ledger)

    def test_multi_start_attempt_refuses_before_opening_an_increment(self):
        digest = "f" * 64
        self.ledger.reserve(budget_id=self.original["budget_id"], request_id="batched-starts",
                            request_sha256=digest, admission_sha256=digest, amount={"starts": 2},
                            expires_at=self.expiry)
        before = self._document()
        with self.assertRaisesRegex(NativePoolTransactionError, "campaign-start-charge-drift"):
            self._enroll(30)
        self.assertEqual(self._document(), before)
