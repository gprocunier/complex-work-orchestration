"""Offline authorization witnesses at the registered browser effect boundary."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import browser_action_dispatch as actions  # noqa: E402
from cwo_core.invocation_ledger import InvocationLedger, InvocationLedgerError  # noqa: E402
from cwo_core.outbound_screen import screen_outbound  # noqa: E402
from cwo_core.prepared_outbound import PreparedSource  # noqa: E402


BODY = "EXAMPLE private synthetic conversation body"
REQUEST_ID = "0123456789abcdef0123456789abcdef"


class Clock:
    def __init__(self):
        self.now = 1000000.0

    def __call__(self):
        return self.now


class OfflineAdapter:
    def __init__(self, context):
        self.context = context
        self.effects = []
        self.states = ["pressed"]
        self.failure = None
        self.on_effect = None
        self.on_snapshot = None

    def snapshot(self):
        if self.on_snapshot:
            self.on_snapshot()
        return self.context

    def send(self, target, submission, *, timeout_seconds, max_output_bytes):
        self.effects.append(("send", target, submission, timeout_seconds, max_output_bytes))
        if self.on_effect:
            self.on_effect()
        if self.failure:
            raise self.failure
        return self.states.pop(0)

    def create_share(self, selection, *, timeout_seconds, max_output_bytes):
        self.effects.append(("share", selection, timeout_seconds, max_output_bytes))
        if self.on_effect:
            self.on_effect()
        if self.failure:
            raise self.failure
        return b"EXAMPLE-private-offline-creation-receipt"


class BrowserActionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.clock = Clock()
        self.ledger = InvocationLedger(Path(self.directory.name) / "ledger", clock=self.clock)
        self.source = {"packet": "EXAMPLE packet", "options": {"label": "EXAMPLE"}}
        self.prepared = PreparedSource.capture(self.source).bind(
            self.source, screen_outbound(BODY, surface="EXAMPLE browser action"))
        self.context = {
            "source": self.source, "payload": BODY,
            "request": {"packet_sha256": "a" * 64, "dispatch_id": "EXAMPLE-dispatch",
                        "request_id": REQUEST_ID, "subject_sha256": "b" * 64},
            "execution": {"executor": "EXAMPLE-browser", "provider": "EXAMPLE-offline",
                          "adapter_id": "EXAMPLE-adapter", "adapter_version": "1",
                          "model": "EXAMPLE-model", "effort": "EXAMPLE-effort",
                          "options": {"selectors": {"send": "EXAMPLE-selector"},
                                      "destination": "https://chatgpt.com"}},
            "limits": {"timeout_seconds": 10, "max_output_bytes": 256, "max_send_probes": 2},
            "share": {"origin": "https://chatgpt.com", "conversation_id": "EXAMPLE-conversation",
                      "messages": [{"message_id": "EXAMPLE-user", "role": "user", "content": BODY},
                                   {"message_id": "EXAMPLE-answer", "role": "assistant", "content": "EXAMPLE answer"}],
                      "purpose": "EXAMPLE independent review"},
        }
        self.scope = {"aggregate_id": "EXAMPLE-stable-sprint-budget", "purpose": "EXAMPLE offline review"}
        self.budget = {"effect_calls": 8, "payload_bytes": 10000,
                       "output_bytes": 1024, "runtime_milliseconds": 40000}
        self.adapter = OfflineAdapter(self.context)
        self.parent = self.make_parent()

    def make_parent(self, **changes):
        return actions.RegisteredBrowserParent(self.prepared, **{
            "ledger": self.ledger, "aggregate_scope": self.scope,
            "aggregate_limits": self.budget, "adapter": self.adapter, **changes})

    def ticket(self):
        return self.parent.issue_send(expires_at=self.clock.now + 100)

    def send(self, ticket=None):
        with self.parent.send(self.ticket() if ticket is None else ticket) as guard:
            guard.check()
            self.assertEqual(guard.press("EXAMPLE-button"), "pressed")
        return guard.result

    def share_ticket(self):
        return self.parent.authorize_create_share(
            purpose=self.context["share"]["purpose"], expires_at=self.clock.now + 100)

    def attempts(self):
        return list(json.loads((self.ledger.root / "ledger.json").read_bytes())["attempts"].values())

    def test_send_positive_accounts_at_real_adapter_boundary(self):
        def boundary():
            self.assertEqual(self.attempts()[0]["state"], "invocation-intent")
            self.clock.now += 0.125

        self.adapter.on_effect = boundary
        with self.parent.send(self.ticket()) as guard:
            self.assertEqual(guard.press("EXAMPLE-button"), "pressed")
            self.clock.now += 0.125
            guard.observe_output(18, sha256=hashlib.sha256(b"EXAMPLE full reply").hexdigest())
        result = guard.result
        self.assertEqual(result.status, "pressed")
        self.assertFalse(result.remote_usage_known)
        expected = REQUEST_ID + "\n" + BODY
        self.assertEqual(hashlib.sha256(self.adapter.effects[0][2].encode()).hexdigest(),
                         hashlib.sha256(expected.encode()).hexdigest())
        attempt = self.attempts()[0]
        self.assertEqual(attempt["observed_usage"], {
            "effect_calls": 1, "payload_bytes": len(expected.encode()),
            "output_bytes": 18, "runtime_milliseconds": 250})
        self.assertEqual(attempt["outcome"], "completed")
        self.assertEqual(attempt["charge"], attempt["amount"])
        self.assertEqual(result.admission_sha256, attempt["admission_sha256"])
        self.assertEqual(guard.admission_sha256, result.admission_sha256)
        self.assertEqual(guard.action_sha256, result.action_sha256)
        self.assertEqual(attempt["request_id"], "browser-action:" + result.action_sha256)
        self.assertNotEqual(result.admission_sha256, result.action_sha256)

    def test_full_persisted_admission_changes_while_dispatch_key_is_stable(self):
        original, results = copy.deepcopy(self.context), []
        cases = (("execution", "model", original["execution"]["model"]),
                 ("execution", "model", "EXAMPLE-other-model"),
                 ("execution", "options", {"selectors": {"send": "EXAMPLE-other"}}),
                 ("limits", "max_output_bytes", 128),
                 ("request", "request_id", "f" * 32))
        for index, (section, key, value) in enumerate(cases):
            with self.subTest(section=section, key=key, case=index):
                self.context.clear()
                self.context.update(copy.deepcopy(original))
                self.context[section][key] = value
                ledger = InvocationLedger(Path(self.directory.name) / str(index), clock=self.clock)
                parent = self.make_parent(ledger=ledger)
                with parent.send(parent.issue_send(expires_at=self.clock.now + 100)) as guard:
                    intent = guard.check()
                    self.assertEqual(guard.admission_sha256, intent["admission_sha256"])
                    guard.press("EXAMPLE-button")
                attempt = ledger.attempt(guard.result.reservation_id)
                self.assertEqual(guard.result.admission_sha256, attempt["admission_sha256"])
                self.assertEqual(attempt["request_id"], "browser-action:" + guard.result.action_sha256)
                results.append(guard.result)
                with self.assertRaises(InvocationLedgerError):
                    with parent.send(parent.issue_send(expires_at=self.clock.now + 200)):
                        self.fail("dispatch replay entered")
                self.adapter.states = ["pressed"]
        self.assertEqual(len({result.action_sha256 for result in results}), 1)
        self.assertEqual(len({result.admission_sha256 for result in results}), len(cases))

    def test_share_positive_is_explicit_and_exactly_one_creation(self):
        result = self.parent.create_share(self.share_ticket())
        self.assertEqual(result.status, "created")
        self.assertEqual(len(self.adapter.effects), 1)
        self.assertEqual(self.adapter.effects[0][0], "share")
        self.assertTrue(json.loads(self.adapter.effects[0][1]) == self.context["share"],
                        "whole selected content must match")
        self.assertEqual(self.attempts()[0]["observed_usage"]["effect_calls"], 1)

    def test_absent_constructed_copied_deserialized_and_foreign_tickets_refuse(self):
        issued = self.ticket()
        foreign = self.make_parent().issue_send(expires_at=self.clock.now + 100)
        bad = [None, actions.SendTicket(), copy.copy(issued), copy.deepcopy(issued),
               {"authorized": True}, foreign]
        for ticket in bad:
            with self.subTest(kind=type(ticket).__name__):
                with self.assertRaises(actions.BrowserActionRefused):
                    with self.parent.send(ticket):
                        self.fail("unissued authority entered")
        self.assertEqual(self.adapter.effects, [])
        self.send(issued)

    def test_share_flags_and_forged_copied_foreign_authority_refuse(self):
        ticket = self.share_ticket()
        foreign = self.make_parent().authorize_create_share(
            purpose=self.context["share"]["purpose"], expires_at=self.clock.now + 100)
        for bad in (None, {"create_share": True}, actions.ShareTicket(), copy.copy(ticket), foreign):
            with self.assertRaises(actions.BrowserActionRefused):
                self.parent.create_share(bad)
        self.assertEqual(self.adapter.effects, [])
        self.parent.create_share(ticket)

    def test_stale_send_and_share_refuse_with_zero_effects(self):
        send, share = self.ticket(), self.share_ticket()
        self.clock.now += 101
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(send):
                self.fail("expired authority entered")
        with self.assertRaises(actions.BrowserActionRefused):
            self.parent.create_share(share)
        self.assertEqual(self.adapter.effects, [])

    def test_independent_request_source_options_and_limits_drift(self):
        cases = [("payload", None), ("source", "packet"), ("request", "packet_sha256"),
                 ("request", "dispatch_id"), ("request", "request_id"),
                 ("request", "subject_sha256"), ("execution", "model"),
                 ("execution", "effort"), ("execution", "options"),
                 ("limits", "timeout_seconds"), ("limits", "max_output_bytes"),
                 ("limits", "max_send_probes")]
        original = copy.deepcopy(self.context)
        for section, key in cases:
            with self.subTest(section=section, key=key):
                ticket = self.ticket()
                if key is None:
                    self.context[section] += "EXAMPLE drift"
                else:
                    self.context[section][key] = "EXAMPLE drift"
                with self.assertRaises(actions.BrowserActionRefused):
                    with self.parent.send(ticket):
                        self.fail("drift entered")
                self.context.clear()
                self.context.update(copy.deepcopy(original))
        self.assertEqual(self.adapter.effects, [])
        self.send()

    def test_wrong_whole_share_conversation_content_order_and_purpose(self):
        for field in ("origin", "conversation_id", "messages", "purpose"):
            original = copy.deepcopy(self.context["share"])
            ticket = self.share_ticket()
            self.context["share"][field] = "EXAMPLE wrong binding"
            with self.assertRaises(actions.BrowserActionRefused):
                self.parent.create_share(ticket)
            self.context["share"] = original
        ticket = self.share_ticket()
        self.context["share"]["messages"].reverse()
        with self.assertRaises(actions.BrowserActionRefused):
            self.parent.create_share(ticket)
        self.context["share"]["messages"].reverse()
        self.assertEqual(self.adapter.effects, [])
        self.parent.create_share(ticket)

    def test_wrong_purpose_cannot_issue_authority(self):
        with self.assertRaises(actions.BrowserActionRefused):
            self.parent.authorize_create_share(purpose="EXAMPLE different purpose", expires_at=self.clock.now + 100)
        self.assertEqual(self.adapter.effects, [])
        self.parent.create_share(self.share_ticket())

    def test_replay_reissue_and_restart_do_not_reset_action(self):
        ticket = self.ticket()
        self.send(ticket)
        tickets = [ticket, self.ticket()]
        for replay in tickets:
            with self.assertRaises(InvocationLedgerError):
                self.send(replay)
        restarted = self.make_parent()
        fresh = restarted.issue_send(expires_at=self.clock.now + 200)
        with self.assertRaises(InvocationLedgerError):
            with restarted.send(fresh):
                self.fail("restart reset replay")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_share_replay_and_reissue_refuse(self):
        ticket = self.share_ticket()
        self.parent.create_share(ticket)
        for replay in (ticket, self.share_ticket()):
            with self.assertRaises(InvocationLedgerError):
                self.parent.create_share(replay)
        self.assertEqual(len(self.adapter.effects), 1)

    def test_exhaustion_is_shared_between_send_and_share(self):
        tight = {**self.budget, "effect_calls": 2}
        self.parent = self.make_parent(aggregate_limits=tight)
        self.send()
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 1)

    def test_restart_cannot_substitute_larger_aggregate_or_scope(self):
        self.send()
        for changes in ({"aggregate_limits": {**self.budget, "effect_calls": 100}},
                        {"aggregate_scope": {**self.scope, "purpose": "EXAMPLE changed scope"}}):
            with self.assertRaises(InvocationLedgerError):
                parent = self.make_parent(**changes)
                with parent.send(parent.issue_send(expires_at=self.clock.now + 100)):
                    self.fail("budget substitution entered")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_restart_new_request_nonce_cannot_replay_same_packet_dispatch(self):
        self.send()
        self.context["request"]["request_id"] = "f" * 32
        restarted = self.make_parent()
        ticket = restarted.issue_send(expires_at=self.clock.now + 200)
        with self.assertRaises(InvocationLedgerError):
            with restarted.send(ticket) as guard:
                guard.press("EXAMPLE second button")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_share_nonce_and_purpose_churn_cannot_replay_same_disclosure(self):
        self.parent.create_share(self.share_ticket())
        self.context["request"]["request_id"] = "e" * 32
        self.context["share"]["purpose"] = "EXAMPLE new purpose"
        restarted = self.make_parent()
        ticket = restarted.authorize_create_share(purpose="EXAMPLE new purpose", expires_at=self.clock.now + 200)
        with self.assertRaises(InvocationLedgerError):
            restarted.create_share(ticket)
        self.assertEqual(len(self.adapter.effects), 1)

    def test_distinct_requests_share_aggregate_despite_document_observation_change(self):
        tight = {**self.budget, "effect_calls": 4}
        self.parent = self.make_parent(aggregate_limits=tight)
        self.send()
        self.context["request"]["dispatch_id"] = "EXAMPLE-second-dispatch"
        self.context["request"]["request_id"] = "d" * 32
        self.context["execution"]["options"]["conversation_url"] = "https://chatgpt.com/c/EXAMPLE-second"
        self.context["execution"]["options"]["model_observation"] = {"document": "EXAMPLE-second"}
        self.parent = self.make_parent(aggregate_limits=tight)
        self.adapter.states = ["pressed"]
        self.send()
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        document = json.loads((self.ledger.root / "ledger.json").read_bytes())
        self.assertEqual(len(document["budgets"]), 1)
        self.assertEqual(len(self.adapter.effects), 2)

    def test_send_then_later_selected_share_uses_original_aggregate(self):
        tight = {**self.budget, "effect_calls": 3}
        self.parent = self.make_parent(aggregate_limits=tight)
        self.send()
        self.context["execution"]["options"]["conversation_url"] = "https://chatgpt.com/c/EXAMPLE-observed"
        self.context["share"]["conversation_id"] = "EXAMPLE-observed"
        self.parent = self.make_parent(aggregate_limits=tight)
        self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 2)
        self.context["request"]["dispatch_id"] = "EXAMPLE-third-dispatch"
        parent = self.make_parent(aggregate_limits=tight)
        with self.assertRaises(InvocationLedgerError):
            with parent.send(parent.issue_send(expires_at=self.clock.now + 100)):
                self.fail("shared aggregate reset")

    def test_request_id_bootstrap_requires_original_32_lowercase_hex_protocol(self):
        for invalid in ("EXAMPLE-request", "A" * 32, "a" * 31, "a" * 33, "g" * 32):
            self.context["request"]["request_id"] = invalid
            with self.assertRaises(actions.BrowserActionRefused):
                self.make_parent()
        self.assertEqual(self.adapter.effects, [])

    def test_one_byte_response_cap_does_not_count_pressed_control_word(self):
        self.context["limits"]["max_output_bytes"] = 1
        self.parent = self.make_parent()
        with self.parent.send(self.ticket()) as guard:
            guard.press("EXAMPLE button")
            guard.observe_output(1, sha256=hashlib.sha256(b"x").hexdigest())
        self.assertEqual(guard.result.output_bytes, 1)
        self.assertEqual(self.attempts()[0]["observed_usage"]["output_bytes"], 1)

    def test_intent_observer_drift_has_no_next_effect(self):
        def observer(event):
            if event["event"] == "invocation-intent":
                self.context["execution"]["options"]["selectors"]["send"] = "EXAMPLE late drift"

        self.parent = self.make_parent(observers=(observer,))
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()):
                self.fail("late observer drift entered")
        self.assertEqual(self.adapter.effects, [])
        self.assertNotEqual(self.attempts()[0]["charge"]["effect_calls"], 0)

    def test_prefill_frame_callback_drift_refuses_final_send(self):
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()) as guard:
                self.context["source"]["options"]["label"] = "EXAMPLE frame callback drift"
                guard.press("EXAMPLE button")
        self.assertEqual(self.adapter.effects, [])

    def test_expiry_after_intent_refuses_final_send(self):
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()) as guard:
                self.clock.now += 101
                guard.press("EXAMPLE button")
        self.assertEqual(self.adapter.effects, [])

    def test_waiting_is_definite_no_click_and_can_probe_within_bound(self):
        self.adapter.states = ["waiting", "pressed"]
        with self.parent.send(self.ticket()) as guard:
            self.assertEqual(guard.press("EXAMPLE button"), "waiting")
            self.assertEqual(guard.press("EXAMPLE button"), "pressed")
        self.assertEqual(self.attempts()[0]["observed_usage"]["effect_calls"], 2)

    def test_waiting_probe_limit_and_callback_drift_prevent_next_effect(self):
        self.adapter.states = ["waiting", "waiting"]
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()) as guard:
                guard.press("EXAMPLE button")
                guard.press("EXAMPLE button")
                guard.press("EXAMPLE button")
        self.assertEqual(len(self.adapter.effects), 2)

    def test_pressed_cannot_be_followed_by_second_effect(self):
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()) as guard:
                guard.press("EXAMPLE button")
                guard.press("EXAMPLE button")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_adapter_replacement_refuses_before_effect(self):
        ticket = self.ticket()
        self.adapter.send = lambda *args, **kwargs: self.fail("replacement effect")
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(ticket):
                self.fail("adapter replacement entered")
        self.assertEqual(self.adapter.effects, [])

    def test_original_prepared_screen_binding_cannot_change(self):
        ticket = self.ticket()
        object.__setattr__(self.prepared.payload, "surface", "EXAMPLE substituted screen surface")
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(ticket):
                self.fail("changed prepared metadata entered")
        self.assertEqual(self.adapter.effects, [])

    def test_original_source_file_bytes_are_rechecked(self):
        source_file = Path(self.directory.name) / "EXAMPLE-input.txt"
        source_file.write_bytes(b"EXAMPLE original bytes")
        capture = PreparedSource.capture(self.source, [(source_file, source_file.read_bytes())])
        self.prepared = capture.bind(self.source, self.prepared.payload)
        parent = self.make_parent()
        ticket = parent.issue_send(expires_at=self.clock.now + 100)
        source_file.write_bytes(b"EXAMPLE substituted bytes")
        with self.assertRaises(actions.BrowserActionRefused):
            with parent.send(ticket):
                self.fail("changed source bytes entered")
        self.assertEqual(self.adapter.effects, [])

    def test_dispatch_accepts_no_replacement_effect_limits_or_budget(self):
        for extra in ({"adapter": self.adapter}, {"limits": {}}, {"budget": {}}):
            with self.assertRaises(TypeError):
                self.parent.send(self.ticket(), **extra)
        self.assertEqual(self.adapter.effects, [])
        self.send()

    def test_ambiguous_failure_is_private_charged_and_never_retried(self):
        self.adapter.failure = RuntimeError(BODY)
        with self.assertRaises(actions.BrowserActionRefused) as caught:
            self.send()
        self.assertFalse(BODY in str(caught.exception), "adapter diagnostic must be body-free")
        self.assertEqual(self.attempts()[0]["outcome"], "unknown")
        self.assertEqual(self.attempts()[0]["charge"], self.attempts()[0]["amount"])
        with self.assertRaises(InvocationLedgerError):
            self.send()
        self.assertEqual(len(self.adapter.effects), 1)

    def test_interrupt_retains_conservative_reconciliation(self):
        self.adapter.failure = KeyboardInterrupt(BODY)
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.send()
        self.assertFalse(BODY in str(caught.exception), "interrupt diagnostic must be body-free")
        attempt = self.attempts()[0]
        self.assertEqual(attempt["state"], "reconciliation-required")
        self.assertEqual(attempt["charge"], attempt["amount"])
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 1)

    def test_output_overrun_records_observed_bytes_and_blocks_successor(self):
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()) as guard:
                guard.press("EXAMPLE button")
                guard.observe_output(2000)
        attempt = self.attempts()[0]
        self.assertEqual(attempt["observed_usage"]["output_bytes"], 2000)
        self.assertEqual(attempt["charge"]["output_bytes"], 2000)
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 1)

    def test_narrow_send_keeps_unobserved_response_output_unknown(self):
        result = self.send()
        self.assertIsNone(result.output_bytes)
        self.assertIsNone(result.output_sha256)
        self.assertNotIn("output_bytes", self.attempts()[0]["observed_usage"])
        self.assertEqual(self.attempts()[0]["charge"]["output_bytes"], 256)

    def test_full_response_lifecycle_deadline_is_measured_after_pressed(self):
        with self.assertRaises(actions.InvocationTimeout):
            with self.parent.send(self.ticket()) as guard:
                guard.press("EXAMPLE button")
                self.clock.now += 50
                guard.observe_output(18)
        self.assertEqual(self.attempts()[0]["observed_usage"]["output_bytes"], 18)
        self.assertEqual(self.attempts()[0]["charge"]["runtime_milliseconds"], 50000)
        self.assertEqual(self.attempts()[0]["outcome"], "failed")

    def test_output_observation_requires_pressed_and_is_one_complete_capture(self):
        with self.parent.send(self.ticket()) as guard:
            with self.assertRaises(actions.BrowserActionRefused):
                guard.observe_output(18)
            guard.press("EXAMPLE button")
            guard.observe_output(18)
            with self.assertRaises(actions.BrowserActionRefused):
                guard.observe_output(18)

    def test_control_state_is_not_response_output(self):
        self.adapter.states = [BODY * 100]
        with self.assertRaises(actions.BrowserActionRefused):
            self.send()
        self.assertIsNone(self.attempts()[0]["observed_usage"])
        self.assertEqual(len(self.adapter.effects), 1)

    def test_snapshot_refusal_message_cannot_disclose_body(self):
        def refuse_snapshot():
            raise actions.BrowserActionRefused(BODY)

        self.adapter.on_snapshot = refuse_snapshot
        with self.assertRaises(actions.BrowserActionRefused) as caught:
            self.ticket()
        self.assertFalse(BODY in str(caught.exception), "snapshot diagnostic must be body-free")
        self.assertEqual(self.adapter.effects, [])

    def test_unrepresentable_elapsed_overrun_requires_reconciliation(self):
        with patch.object(actions.time, "monotonic", return_value=0) as monotonic:
            with self.assertRaises(actions.BrowserActionRefused):
                with self.parent.send(self.ticket()) as guard:
                    guard.press("EXAMPLE button")
                    monotonic.return_value = 2**60
        self.assertEqual(self.attempts()[0]["state"], "reconciliation-required")
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 1)

    def test_elapsed_overrun_is_charged_as_observed(self):
        self.adapter.on_effect = lambda: setattr(self.clock, "now", self.clock.now + 50)
        with self.assertRaises(actions.InvocationTimeout):
            self.send()
        self.assertEqual(self.attempts()[0]["charge"]["runtime_milliseconds"], 50000)
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 1)

    def test_no_probe_or_expiry_bounds_accept_nan_bool_zero_or_overflow(self):
        for field, value in (("timeout_seconds", float("nan")), ("timeout_seconds", float("inf")),
                             ("timeout_seconds", 0), ("max_output_bytes", True),
                             ("max_send_probes", 0), ("max_send_probes", 2**60)):
            saved = self.context["limits"][field]
            self.context["limits"][field] = value
            with self.assertRaises(actions.BrowserActionRefused):
                self.make_parent()
            self.context["limits"][field] = saved
        self.assertEqual(self.adapter.effects, [])
        self.send()

    def test_copied_active_guard_cannot_duplicate_effect(self):
        with self.parent.send(self.ticket()) as guard:
            copied = copy.copy(guard)
            with self.assertRaises(actions.BrowserActionRefused):
                copied.press("EXAMPLE copied guard")
            guard.press("EXAMPLE original guard")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_guard_claim_precedes_reentrant_snapshot_callback(self):
        with self.parent.send(self.ticket()) as guard:
            def reenter():
                self.adapter.on_snapshot = None
                guard.press("EXAMPLE reentrant button")

            self.adapter.on_snapshot = reenter
            with self.assertRaises(actions.BrowserActionRefused):
                guard.press("EXAMPLE original button")
        self.assertEqual(len(self.adapter.effects), 0)

    def test_ticket_expiry_is_rechecked_after_snapshot_callback(self):
        class ExpiringAdapter(OfflineAdapter):
            expire = False

            def snapshot(adapter):
                if adapter.expire:
                    self.clock.now += 2
                return adapter.context

        adapter = ExpiringAdapter(self.context)
        parent = self.make_parent(adapter=adapter)
        ticket = parent.issue_send(expires_at=self.clock.now + 1)
        with parent.send(ticket) as guard:
            adapter.expire = True
            with self.assertRaises(actions.BrowserActionRefused):
                guard.press("EXAMPLE button")
        self.assertEqual(adapter.effects, [])

    def test_context_exit_enforces_whole_lifecycle_deadline_without_capture(self):
        with self.assertRaises(actions.InvocationTimeout):
            with self.parent.send(self.ticket()) as guard:
                guard.press("EXAMPLE button")
                self.clock.now += 50
        self.assertEqual(self.attempts()[0]["outcome"], "failed")
        self.assertEqual(self.attempts()[0]["charge"]["runtime_milliseconds"], 50000)

    def test_share_content_and_message_identity_drift_are_independent(self):
        for field in ("content", "message_id", "role"):
            ticket = self.share_ticket()
            message = self.context["share"]["messages"][0]
            saved = message[field]
            message[field] = "EXAMPLE substituted value"
            with self.assertRaises(actions.BrowserActionRefused):
                self.parent.create_share(ticket)
            message[field] = saved
        self.assertEqual(self.adapter.effects, [])
        self.parent.create_share(ticket)

    def test_share_observer_drift_prevents_the_one_creation_effect(self):
        def observer(event):
            if event["event"] == "invocation-intent":
                self.context["share"]["messages"][0]["content"] = "EXAMPLE changed whole disclosure"

        parent = self.make_parent(observers=(observer,))
        ticket = parent.authorize_create_share(purpose=self.context["share"]["purpose"],
                                               expires_at=self.clock.now + 100)
        with self.assertRaises(actions.BrowserActionRefused):
            parent.create_share(ticket)
        self.assertEqual(self.adapter.effects, [])

    def test_share_ambiguous_failure_preserves_privacy_and_charge(self):
        self.adapter.failure = RuntimeError(BODY)
        with self.assertRaises(actions.BrowserActionRefused) as caught:
            self.parent.create_share(self.share_ticket())
        self.assertFalse(BODY in str(caught.exception), "share diagnostic must be body-free")
        self.assertEqual(self.attempts()[0]["outcome"], "unknown")
        with self.assertRaises(InvocationLedgerError):
            self.parent.create_share(self.share_ticket())
        self.assertEqual(len(self.adapter.effects), 1)

    def test_share_interrupt_remains_unresolved_and_blocks_send(self):
        self.adapter.failure = KeyboardInterrupt(BODY)
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.parent.create_share(self.share_ticket())
        self.assertFalse(BODY in str(caught.exception), "share interruption must be body-free")
        self.assertEqual(self.attempts()[0]["state"], "reconciliation-required")
        with self.assertRaises(InvocationLedgerError):
            self.send()
        self.assertEqual(len(self.adapter.effects), 1)

    def test_drift_after_definite_waiting_prevents_next_effect(self):
        self.adapter.states = ["waiting", "pressed"]
        with self.assertRaises(actions.BrowserActionRefused):
            with self.parent.send(self.ticket()) as guard:
                self.assertEqual(guard.press("EXAMPLE button"), "waiting")
                self.context["execution"]["options"]["selectors"]["send"] = "EXAMPLE readiness drift"
                guard.press("EXAMPLE button")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_result_ledger_diagnostics_and_stdout_contain_no_body(self):
        output = io.StringIO()
        with redirect_stdout(output):
            send = self.send()
            share = self.parent.create_share(self.share_ticket())
        ledger = (self.ledger.root / "ledger.json").read_text()
        for rendered in (repr(send), repr(share), repr(self.ticket()), repr(self.parent),
                         json.dumps(send.metadata()), json.dumps(share.metadata()), ledger, output.getvalue()):
            self.assertFalse(BODY in rendered, "private content must be absent")
            self.assertFalse("EXAMPLE-private-offline-creation-receipt" in rendered,
                             "private creation receipt must be absent")
        self.assertIsNone(send.output_sha256)


if __name__ == "__main__":
    unittest.main()
