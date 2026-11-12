"""EXAMPLE no-model qualification of the original advisory HTTP consumer."""
from __future__ import annotations

import json
import contextvars
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import qualified_review_dispatch as review  # noqa: E402
from tests.test_invocation_ledger import FakeClock, FakeOwners  # noqa: E402
from tests.test_route_feasibility_preparation import record, bind  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402

admission = review.admission
planner = admission.planner
ledger_api = admission.ledger_api
EXAMPLE_FINAL = "EXAMPLE review: the supplied source is consistent with the stated output contract; retain independent evaluator and architect review before implementation."


def workflow():
    route = record(alternatives=True)
    route["purpose"] = "EXAMPLE read-only evidence review and its dependent synthesis and validation."
    for node in route["nodes"]:
        node["execution"].update(executor="local_secure_review_worker", provider="local_inference",
                                 model="EXAMPLE-review-model", effort="EXAMPLE-effort",
                                 options={"reasoning_effort": "EXAMPLE-effort", "max_tokens": 32})
        node["estimate_source"]["requested_model"] = "EXAMPLE-review-model"
        node["unit_estimate"] = planner.work_sizing.evaluate_work_estimate(node["estimate_source"], policy=route["policy"])
        node["source_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(node["estimate_source"])
        node["unit_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(node["unit_estimate"])
        node["additional_input_tokens_upper"] = 2000
        node["rendered_request"] = planner.render_request(node)
    bind(route)
    planned = planner.prepare(route)
    if planned["status"] != "within-declared-limits":
        raise AssertionError("EXAMPLE whole route must pass the original planner.")
    route["limits"] = planned["totals"].copy()
    return bind(route)


class ExampleResponse:
    status = 200

    def __init__(self, *, usable=True, content=EXAMPLE_FINAL):
        self.usable, self.content = usable, content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, cap):
        return json.dumps({"model": "EXAMPLE-review-model", "choices": [{
            "finish_reason": "stop" if self.usable else "length",
            "message": {"content": self.content},
        }]}).encode()[:cap]


class ExampleHTTP:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.usable = True
        self.on_call = None
        self.content = EXAMPLE_FINAL

    def open(self, req, *, timeout):
        self.calls.append((req, timeout))
        if self.on_call:
            self.on_call()
        if self.failure:
            raise self.failure
        # Synthetic provider verifies/applies the requested word cap; this is
        # not a real tokenizer, billing observation or latency measurement.
        payload = json.loads(req.data)
        bounded = " ".join(self.content.split()[:payload["max_tokens"]])
        return ExampleResponse(usable=self.usable, content=bounded)


class QualifiedReviewTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.enterContext(using_test_store(HostRecordStore.for_tests(Path(self.directory.name) / 'host-records')))
        self.clock, self.owners = FakeClock(), FakeOwners()
        self.ledger = ledger_api.InvocationLedger(Path(self.directory.name) / "EXAMPLE-ledger",
                                                  clock=self.clock, owner_probe=self.owners)
        self.route = workflow()
        self.host = self.make_host()
        self.http = ExampleHTTP()
        self.effects = []
        self.addCleanup(patch.stopall)
        patch.object(review.dispatch, "LOCAL_INVOCATION_AVAILABLE", True).start()
        patch.object(review.dispatch, "pinned_local_endpoint_address", side_effect=self.resolve).start()
        patch.object(review.dispatch, "_build_local_opener", side_effect=self.opener).start()

    def make_host(self, route=None):
        return review.RegisteredReviewHost(self.route if route is None else route,
                                          ledger=self.ledger, base_url="http://127.0.0.1:8000")

    def resolve(self, *args, **kwargs):
        self.effects.append("DNS")
        return "127.0.0.1"

    def opener(self, *args):
        self.effects.append("opener")
        return self.http

    def ticket(self, node="plan", *, expires=None):
        return self.host.issue(node, now=self.clock.now,
                               expires_at=self.clock.now + 1000 if expires is None else expires)

    def document(self):
        path = self.ledger.root / ledger_api.LEDGER_FILE
        return json.loads(path.read_bytes()) if path.exists() else ledger_api.empty_ledger()

    def run_ticket(self, ticket=None, **kwargs):
        return self.host.dispatch(self.ticket() if ticket is None else ticket, **kwargs)

    def test_original_consumer_produces_useful_review_with_exact_bound_arguments(self):
        ticket = self.ticket()
        observed = []

        def observer(event):
            if event["event"] == "invocation-intent":
                persisted = self.document()["attempts"][event["attempt"]["attempt_id"]]
                self.assertEqual(persisted["state"], "invocation-intent")
                self.assertTrue(persisted["observers"])
                self.assertEqual(self.effects, [])
                observed.append("persisted")
                with self.assertRaises(ledger_api.InvocationLedgerError):
                    self.run_ticket(ticket)

        result = self.run_ticket(ticket, observer=observer)
        self.assertEqual(observed, ["persisted"])
        self.assertEqual(result["review"]["final_content"], EXAMPLE_FINAL)
        self.assertTrue(result["review"]["usable_final_content"])
        self.assertEqual(len(self.http.calls), 1)
        req, timeout = self.http.calls[0]
        payload = json.loads(req.data)
        actual_text = json.loads(payload["messages"][-1]["content"].split("Task:\n", 1)[1])
        original = json.loads(ticket.prepared.request_bytes)
        self.assertEqual(actual_text, {key: original[key] for key in ("prompt", "wrappers", "attachments", "sources")})
        self.assertEqual({key: payload[key] for key in ("model", "reasoning_effort", "max_tokens", "temperature")},
                         {"model": "EXAMPLE-review-model", "temperature": 0,
                          **self.route["nodes"][0]["execution"]["options"]})
        self.assertEqual(timeout, json.loads(ticket.prepared.amounts_bytes)["runtime_seconds"])
        self.assertGreater(result["applied"]["http_overhead_bytes"], 0)
        self.assertEqual(result["attempt"]["charge"], result["attempt"]["amount"])
        self.assertIsNone(result["attempt"]["observed_usage"])
        for field in admission.FALSE_FIELDS:
            self.assertIs(result[field], False)

    def test_unissued_copied_foreign_number_only_and_expired_tickets_have_no_effects(self):
        valid = self.ticket()
        foreign = self.make_host().issue("plan", now=self.clock.now, expires_at=self.clock.now + 10)
        for ticket in (None, 600, {"ready": True}, replace(valid), foreign):
            with self.subTest(kind=type(ticket).__name__), self.assertRaises(admission.AdmissionError):
                self.host.dispatch(ticket)
        self.clock.now = valid.prepared.expires_at
        with self.assertRaises(admission.AdmissionError):
            self.run_ticket(valid)
        self.assertEqual(self.effects, [])
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.document()["attempts"], {})

    def test_one_original_aggregate_drives_dependent_review_synthesis_validation(self):
        mapping = {}
        for node_id in ("plan", "review", "synthesis", "validation"):
            result = self.run_ticket(self.ticket(node_id), node_attempts=mapping)
            self.assertEqual(result["review"]["final_content"], EXAMPLE_FINAL)
            mapping[node_id] = result["attempt"]["attempt_id"]
        document = self.document()
        self.assertEqual(len(document["budgets"]), 1)
        self.assertEqual(len(self.http.calls), 4)
        self.assertEqual(ledger_api.validate_ledger(document), [])
        for attempt in document["attempts"].values():
            self.assertEqual(attempt["charge"], attempt["amount"])

    def test_replay_race_and_restarted_host_cannot_reset_aggregate(self):
        ticket = self.ticket()

        def contender():
            try:
                return self.run_ticket(ticket)
            except (admission.AdmissionError, ledger_api.InvocationLedgerError):
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(contextvars.copy_context().run, contender) for _ in range(2)]
            results = [future.result() for future in futures]
        self.assertEqual(sum(result is not None for result in results), 1)
        restarted = self.make_host()
        with self.assertRaises(ledger_api.InvocationLedgerError):
            restarted.dispatch(restarted.issue("plan", now=self.clock.now, expires_at=self.clock.now + 1000))
        self.assertEqual(len(self.http.calls), 1)

    def test_policy_and_environment_drift_refuse_before_dns(self):
        ticket = self.ticket()
        with patch.object(review, "_policies", return_value=()):
            with self.assertRaisesRegex(admission.AdmissionError, "policy or route drifted"):
                self.run_ticket(ticket)
        with patch.dict("os.environ", {"CWO_LOCAL_OPENAI_API_KEY": "EXAMPLE"}):
            # Full header bytes are screened and bound at the actual scope;
            # no bearer values are retained in receipts or printed.
            with self.assertRaisesRegex(admission.AdmissionError, "URL, headers or body drifted"):
                self.run_ticket(ticket)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.effects, [])

    def test_restarted_endpoint_cannot_inherit_original_scope_for_a_child(self):
        parent = self.run_ticket()
        changed = review.RegisteredReviewHost(self.route, ledger=self.ledger, base_url="http://127.0.0.1:8001")
        ticket = changed.issue("sibling", now=self.clock.now, expires_at=self.clock.now + 1000)
        with self.assertRaises(ledger_api.InvocationLedgerError):
            changed.dispatch(ticket, node_attempts={"plan": parent["attempt"]["attempt_id"]})
        self.assertEqual(len(self.http.calls), 1)
        self.assertEqual(len(self.document()["budgets"]), 1)

    def test_custom_scope_cannot_bypass_original_consumer_with_flag_enabled_for_fake(self):
        from argparse import Namespace
        binding = json.loads(self.host._bindings["plan"])
        with self.assertRaises(admission.AdmissionError):
            review.dispatch.execute_local_envelope(binding["envelope"], binding["selected"],
                                                   Namespace(**binding["args"]), qualified_review={"ready": True})
        self.assertEqual(self.effects, [])
        self.assertEqual(self.document()["attempts"], {})

    def test_observer_expiry_and_timeout_keep_terminal_charges_and_hold_children(self):
        ticket = self.ticket(expires=self.clock.now + 10)

        def expire(event):
            if event["event"] == "request":
                self.clock.now = ticket.prepared.expires_at

        with self.assertRaises(admission.AdmissionError):
            self.run_ticket(ticket, observer=expire)
        self.assertEqual(self.http.calls, [])
        attempt = next(iter(self.document()["attempts"].values()))
        self.assertEqual(attempt["charge"], attempt["amount"])
        self.assertEqual(attempt["outcome"], "unknown")
        with self.assertRaises((admission.AdmissionError, ledger_api.InvocationLedgerError)):
            self.run_ticket(self.ticket("review"), node_attempts={"plan": attempt["attempt_id"]})

    def test_local_cutoff_preserves_unknown_usage_and_never_retries(self):
        self.http.failure = TimeoutError("EXAMPLE local cutoff")
        ticket = self.ticket()
        with self.assertRaises(ledger_api.InvocationTimeout):
            self.run_ticket(ticket)
        attempt = next(iter(self.document()["attempts"].values()))
        self.assertEqual(attempt["outcome"], "timeout")
        self.assertIsNone(attempt["observed_usage"])
        self.assertEqual(attempt["charge"], attempt["amount"])
        with self.assertRaises(ledger_api.InvocationLedgerError):
            self.run_ticket(self.ticket())
        self.assertEqual(len(self.http.calls), 1)

    def test_crash_around_effect_retains_reconciliation_and_blocks_successors(self):
        self.http.failure = KeyboardInterrupt("EXAMPLE ambiguous interruption")
        with self.assertRaises(KeyboardInterrupt):
            self.run_ticket()
        before = self.document()
        parent = next(iter(before["attempts"].values()))
        self.assertEqual(parent["state"], "reconciliation-required")
        self.assertEqual(parent["charge"], parent["amount"])
        for node in ("plan", "retry", "fallback", "sibling", "review"):
            with self.subTest(node=node), self.assertRaises((admission.AdmissionError, ledger_api.InvocationLedgerError)):
                self.run_ticket(self.ticket(node), node_attempts={"plan": parent["attempt_id"]})
        self.assertEqual(before, self.document())
        self.assertEqual(len(self.http.calls), 1)

    def test_failed_parent_retry_and_fallback_use_the_original_totals(self):
        self.http.usable = False
        first = self.run_ticket()
        mapping = {"plan": first["attempt"]["attempt_id"]}
        self.http.usable = True
        for node in ("retry", "fallback"):
            result = self.run_ticket(self.ticket(node), node_attempts=mapping)
            self.assertEqual(result["attempt"]["lineage"]["parent_attempt_id"], mapping["plan"])
            self.assertEqual(result["attempt"]["budget_id"], first["attempt"]["budget_id"])
        document = self.document()
        self.assertEqual(len(document["budgets"]), 1)
        self.assertEqual(len(self.http.calls), 3)
        self.assertEqual(ledger_api.validate_ledger(document), [])

    def test_held_dependents_do_not_stop_independent_sibling_in_same_aggregate(self):
        first = self.run_ticket()
        mapping = {"plan": first["attempt"]["attempt_id"]}
        self.http.usable = False
        failed = self.run_ticket(self.ticket("review"), node_attempts=mapping)
        mapping["review"] = failed["attempt"]["attempt_id"]
        with self.assertRaises(ledger_api.InvocationLedgerError):
            self.run_ticket(self.ticket("synthesis"), node_attempts=mapping)
        self.http.usable = True
        sibling = self.run_ticket(self.ticket("sibling"), node_attempts=mapping)
        self.assertEqual(sibling["review"]["final_content"], EXAMPLE_FINAL)
        self.assertEqual(sibling["attempt"]["budget_id"], first["attempt"]["budget_id"])
        self.assertEqual(len(self.document()["budgets"]), 1)
        self.assertEqual(len(self.http.calls), 3)

    def test_fake_provider_applies_output_boundary_and_final_clock_cutoff(self):
        self.http.content = "EXAMPLE " * 100
        result = self.run_ticket()
        self.assertEqual(len(result["review"]["final_content"].split()), 32)
        self.assertEqual(json.loads(self.http.calls[0][0].data)["max_tokens"], 32)

    def test_original_response_read_cutoff_does_not_deliver_a_final(self):
        ticket = self.ticket()
        self.http.on_call = lambda: setattr(self.clock, "now", ticket.prepared.expires_at)
        with self.assertRaises(admission.AdmissionError):
            self.run_ticket(ticket)
        parent = next(iter(self.document()["attempts"].values()))
        self.assertEqual(parent["outcome"], "unknown")
        self.assertEqual(parent["charge"], parent["amount"])
        with self.assertRaises(ledger_api.InvocationLedgerError):
            self.run_ticket(self.ticket("review"), node_attempts={"plan": parent["attempt_id"]})

    def test_nonfinal_original_response_holds_dependents(self):
        self.http.usable = False
        result = self.run_ticket()
        self.assertFalse(result["review"]["usable_final_content"])
        self.assertEqual(result["attempt"]["outcome"], "failed")
        with self.assertRaises(ledger_api.InvocationLedgerError):
            self.run_ticket(self.ticket("review"), node_attempts={"plan": result["attempt"]["attempt_id"]})
        self.assertEqual(len(self.http.calls), 1)

    def test_default_flag_refuses_host_and_custom_scope_before_effects(self):
        with patch.object(review.dispatch, "LOCAL_INVOCATION_AVAILABLE", False):
            with self.assertRaisesRegex(SystemExit, "controlled local invocation is unavailable"):
                self.host.dispatch({"ready": True})
            with self.assertRaisesRegex(SystemExit, "controlled local invocation is unavailable"):
                review.dispatch.execute_local_envelope({}, {}, object(), qualified_review={"ready": True})
        self.assertEqual(self.effects, [])
        self.assertEqual(self.document()["attempts"], {})

    def test_registered_input_is_frozen_and_incomplete_http_sizing_is_refused(self):
        original = self.host._route_bytes
        self.route["nodes"][0]["prompt"] = "EXAMPLE changed input"
        self.assertEqual(self.host._route_bytes, original)
        bad = workflow()
        for node in bad["nodes"]:
            node["additional_input_tokens_upper"] = 0
        with self.assertRaisesRegex(admission.AdmissionError, "serialization/wrapper overhead"):
            self.make_host(bind(bad))
        unknown = workflow()
        unknown["projection_policy"] = {"mode": "unknown", "tokens_per_utf8_byte_upper": None,
            "input_overhead_tokens": None, "billing": None, "rationale": "EXAMPLE unknown", "uncertainty": "EXAMPLE unknown"}
        with self.assertRaises(admission.AdmissionError):
            self.make_host(bind(unknown))

    def test_observer_http_error_keeps_identity_without_endpoint_reads_or_closes(self):
        body = Mock()
        body.read.return_value = b"EXAMPLE observer-owned body"
        sentinel = HTTPError("http://127.0.0.1/EXAMPLE-observer", 503, "EXAMPLE observer", {}, body)
        self.addCleanup(sentinel.close)

        def observer(event):
            if event["event"] == "request":
                raise sentinel

        received = None
        try:
            self.run_ticket(observer=observer)
        except BaseException as failure:
            received = failure
        with self.subTest(check="identity"):
            self.assertIs(received, sentinel)
        with self.subTest(check="body-unread"):
            body.read.assert_not_called()
        with self.subTest(check="body-unclosed"):
            body.close.assert_not_called()
        self.assertEqual(self.http.calls, [])
        attempt = next(iter(self.document()["attempts"].values()))
        self.assertEqual(attempt["charge"], attempt["amount"])

    def test_observer_stop_iteration_identity_survives_entry_request_and_terminal(self):
        for stage in ("invocation-intent", "request", "terminal"):
            with self.subTest(stage=stage):
                self.ledger = ledger_api.InvocationLedger(Path(self.directory.name) / ("EXAMPLE-" + stage),
                                                          clock=self.clock, owner_probe=self.owners)
                self.host = self.make_host()
                sentinel = StopIteration("EXAMPLE observer stop")

                def observer(event):
                    if event["event"] == stage:
                        raise sentinel

                with self.assertRaises(StopIteration) as caught:
                    self.run_ticket(observer=observer)
                self.assertIs(caught.exception, sentinel)

    def test_terminal_notifications_cannot_expire_admission_or_runtime_before_return(self):
        for cutoff in ("admission", "runtime"):
            with self.subTest(cutoff=cutoff):
                self.ledger = ledger_api.InvocationLedger(Path(self.directory.name) / ("EXAMPLE-terminal-" + cutoff),
                                                          clock=self.clock, owner_probe=self.owners)
                self.host = self.make_host()
                ticket = self.ticket()
                deadline = self.clock.now + json.loads(ticket.prepared.amounts_bytes)["runtime_seconds"]
                self.assertLess(deadline, ticket.prepared.expires_at)

                def observer(event):
                    if event["event"] == "terminal":
                        self.clock.now = ticket.prepared.expires_at if cutoff == "admission" else deadline

                with self.assertRaises(admission.AdmissionError):
                    self.run_ticket(ticket, observer=observer)
                attempt = next(iter(self.document()["attempts"].values()))
                self.assertEqual(attempt["state"], "terminal")
                self.assertEqual(attempt["outcome"], "completed")
                self.assertEqual(attempt["charge"], attempt["amount"])
                self.assertIsNone(attempt["observed_usage"])


if __name__ == "__main__":
    unittest.main()
