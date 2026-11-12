"""Offline admission checks use real planning and disposable ledger accounting."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import Mock, patch

from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import prepare_local_admission as adapter
import prepare_route_feasibility as planner
import prepare_route_ledger_reconciliation as reconciliation
import test_invocation_ledger as fixtures
from test_route_feasibility_preparation import bind, record

ledger_api = reconciliation.ledger
UNSET = object()


def example_route(*, tiny=False, alternatives=False):
    route = record(tiny=tiny, alternatives=alternatives)
    route["aggregate_id"] = "EXAMPLE-local-admission"
    route["run_id"] = "EXAMPLE-offline-run"
    for node in route["nodes"]:
        node["execution"]["options"] = {
            "temperature": 0.25, "stop": ["EXAMPLE-stop"],
            "EXAMPLE-option": {"label": "EXAMPLE-offline", "enabled": True},
        }
        node["rendered_request"] = planner.render_request(node)
    bind(route)
    planned = planner.prepare(route)
    if planned["status"] != "within-declared-limits":
        raise AssertionError("EXAMPLE route must retain known, complete resource amounts.")
    route["limits"] = dict(planned["totals"])
    return bind(route)


class ObserverUsageCase(NamedTuple):
    original: str
    mode: str


class LocalAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.clock, self.owners = fixtures.FakeClock(), fixtures.FakeOwners()
        self.store = ledger_api.InvocationLedger(
            Path(self.directory.name) / "EXAMPLE-ledger", clock=self.clock, owner_probe=self.owners)
        self.route = example_route(alternatives=True)
        self.plan = planner.prepare(self.route)
        self.receipt = self.make_receipt()

    def make_receipt(self, route=None, *, now=None, node_id="plan"):
        now = self.clock.now if now is None else now
        return adapter.prepare(self.route if route is None else route, node_id,
                               now=now, expires_at=now + 60)

    def disk_bytes(self):
        path = self.store.root / ledger_api.LEDGER_FILE
        return path.read_bytes() if path.exists() else None

    def snapshot(self):
        raw = self.disk_bytes()
        return ledger_api.empty_ledger() if raw is None else json.loads(raw)

    def only_attempt(self):
        attempts = self.snapshot()["attempts"]
        self.assertEqual(len(attempts), 1)
        return next(iter(attempts.values()))

    def control_receipt(self, node_id, label):
        self.clock, self.owners = fixtures.FakeClock(), fixtures.FakeOwners()
        self.store = ledger_api.InvocationLedger(
            Path(self.directory.name) / f"EXAMPLE-{label}-{node_id}",
            clock=self.clock, owner_probe=self.owners)
        mapping = {}
        if node_id != "plan":
            mapping["plan"] = self.consume_node("plan")["attempt_id"]
        return self.make_receipt(node_id=node_id), mapping

    def sibling_deadline_receipt(self, parent_state, label, *, selected_first=False):
        self.clock, self.owners = fixtures.FakeClock(), fixtures.FakeOwners()
        self.store = ledger_api.InvocationLedger(
            Path(self.directory.name) / f"EXAMPLE-sibling-deadline-{label}",
            clock=self.clock, owner_probe=self.owners)
        parent_admission = self.make_receipt()
        self.store.open_budget(parent_admission.budget_id, json.loads(parent_admission.limits_bytes),
                               scope_sha256=parent_admission.scope_sha256)
        parent = self.store.reserve(
            budget_id=parent_admission.budget_id, request_id="plan",
            request_sha256=ledger_api.request_sha256(parent_admission.request_bytes),
            admission_sha256=adapter._receipt_sha256(parent_admission),
            amount=json.loads(parent_admission.amounts_bytes), expires_at=parent_admission.expires_at,
            lineage={"kind": "initial", "parent_attempt_id": None}, refuse_while_unresolved=True)
        if parent_state == "invocation-intent":
            parent = self.store.begin_invocation(parent["reservation_id"], parent_admission.request_bytes)
        elif parent_state == "terminal":
            parent = self.store.invoke(
                parent["reservation_id"], parent_admission.request_bytes,
                fixtures.FakeEffect(result=ledger_api.EffectResult(
                    "completed", dict.fromkeys(planner.RESOURCES, 0))))
        self.assertEqual(parent["state"], parent_state)
        self.clock.now = parent["expires_at"] - 2
        expiry = parent["expires_at"] - 1 if selected_first else self.clock.now + 60
        receipt = adapter.prepare(self.route, "sibling", now=self.clock.now, expires_at=expiry)
        self.assertEqual(receipt.expires_at, expiry)
        return receipt, parent

    def assert_control_charges(self, receipt):
        document = self.snapshot()
        self.assertEqual(ledger_api.validate_ledger(document), [])
        for attempt in document["attempts"].values():
            self.assertEqual(attempt["charge"], attempt["amount"])
            self.assertEqual(attempt["charge"], ledger_api.derived_charge(attempt))
        summary = self.store.summary(receipt.budget_id)
        self.assertEqual(summary["limits"], json.loads(receipt.limits_bytes))
        self.assertEqual(summary["charged"], {
            name: sum(attempt["charge"][name] for attempt in document["attempts"].values())
            for name in planner.RESOURCES})
        self.assertEqual(set(document["budgets"]), {receipt.budget_id})
        self.assertEqual(document["budgets"][receipt.budget_id]["scope_sha256"], receipt.scope_sha256)
        return document

    @contextmanager
    def delay_sibling_final_gate(self, stage, deadline):
        boundary = {"observed": False, "armed": False}
        advanced = []
        real_live, real_locked = adapter._live, self.store._locked

        def advance(label):
            if boundary["armed"] and label == stage and not advanced:
                self.assertLess(self.clock.now, deadline)
                self.clock.now = deadline
                advanced.append(label)

        def observer(event):
            if event["event"] == "invocation-intent":
                boundary["observed"] = True

        def live(admission, ledger):
            real_live(admission, ledger)
            if boundary["observed"]:
                boundary["armed"] = True

        @contextmanager
        def locked():
            with real_locked() as state:
                advance("lock")
                yield state

        def delayed(read, label):
            def checked(*args, **kwargs):
                value = read(*args, **kwargs)
                advance(label)
                return value
            return checked

        with ExitStack() as stack:
            stack.enter_context(patch.object(adapter, "_live", side_effect=live))
            stack.enter_context(patch.object(self.store, "_locked", side_effect=locked))
            for target, name, label in (
                    (self.owners, "status", "status"), (self.owners, "current", "owner"),
                    (self.store, "_charged", "charge"), (adapter, "_read_policy_bytes", "policy")):
                stack.enter_context(patch.object(
                    target, name, side_effect=delayed(getattr(target, name), label)))
            yield observer
        self.assertTrue(boundary["armed"])
        self.assertEqual(advanced, [stage])

    def final_liveness_control(self, node_id, stage, *, remaining):
        receipt, mapping = self.control_receipt(node_id, f"final-{stage}-{remaining}")
        boundary = {"observed": False, "armed": False}
        advanced = []
        effect = Mock(return_value=ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0)))
        real_live, real_locked = adapter._live, self.store._locked

        def advance(label):
            if boundary["armed"] and label == stage and not advanced:
                self.assertLess(self.clock.now, receipt.expires_at)
                self.clock.now = receipt.expires_at - remaining
                advanced.append(label)

        def observer(event):
            if event["event"] == "invocation-intent":
                boundary["observed"] = True

        def live(admission, ledger):
            real_live(admission, ledger)
            if boundary["observed"]:
                boundary["armed"] = True

        @contextmanager
        def locked():
            with real_locked() as state:
                advance("lock")
                yield state

        def delayed(read, label):
            def checked(*args, **kwargs):
                value = read(*args, **kwargs)
                advance(label)
                return value
            return checked

        def invoke():
            return adapter.invoke_offline(
                receipt, self.route, node_id, ledger=self.store, effect=effect,
                observer=observer, node_attempts=mapping)

        with ExitStack() as stack:
            stack.enter_context(patch.object(adapter, "_live", side_effect=live))
            stack.enter_context(patch.object(self.store, "_locked", side_effect=locked))
            for target, name, label in (
                    (self.owners, "status", "status"), (self.owners, "current", "owner"),
                    (self.store, "_charged", "charge"), (adapter, "_read_policy_bytes", "policy")):
                stack.enter_context(patch.object(
                    target, name, side_effect=delayed(getattr(target, name), label)))
            if remaining:
                self.assertEqual(invoke()["attempt"]["outcome"], "completed")
                effect.assert_called_once()
            else:
                with self.assertRaisesRegex(adapter.AdmissionError, "expired"):
                    invoke()
                effect.assert_not_called()
        self.assertTrue(boundary["armed"])
        self.assertEqual(advanced, [stage])
        document = self.assert_control_charges(receipt)
        selected = next(item for item in document["attempts"].values() if item["request_id"] == node_id)
        self.assertEqual(selected["state"], "terminal")
        self.assertEqual(selected["outcome"], "completed" if remaining else "unknown")
        self.assertEqual(selected["amount"], json.loads(receipt.amounts_bytes))

    def test_final_liveness_observes_delays_for_primary_and_dependent_effects(self):
        for node_id in ("plan", "review"):
            for stage in ("lock", "status", "owner", "charge", "policy"):
                for remaining in (0, 1):
                    with self.subTest(node_id=node_id, stage=stage, remaining=remaining):
                        self.final_liveness_control(node_id, stage, remaining=remaining)

    def sibling_deadline_control(self, parent_state, stage, *, remaining, completed,
                                 selected_first=False):
        label = f"{parent_state}-{stage}-{remaining}-{selected_first}"
        receipt, parent = self.sibling_deadline_receipt(
            parent_state, label, selected_first=selected_first)
        deadline = receipt.expires_at if selected_first else parent["expires_at"]
        effect = Mock(return_value=ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0)))
        with self.delay_sibling_final_gate(stage, deadline - remaining) as observer:
            def invoke():
                return adapter.invoke_offline(
                    receipt, self.route, "sibling", ledger=self.store, effect=effect,
                    observer=observer, node_attempts={"plan": parent["attempt_id"]})

            if completed:
                self.assertEqual(invoke()["attempt"]["outcome"], "completed")
            else:
                error = adapter.AdmissionError if selected_first else ledger_api.InvocationLedgerError
                with self.assertRaisesRegex(error, "expired"):
                    invoke()
        self.assertEqual(effect.call_count, int(completed))
        document = self.assert_control_charges(receipt)
        self.assertEqual(len(document["attempts"]), 2)
        self.assertEqual(document["attempts"][parent["attempt_id"]], parent)
        selected = next(item for item in document["attempts"].values()
                        if item["request_id"] == "sibling")
        self.assertEqual(selected["state"], "terminal")
        self.assertEqual(selected["outcome"], "completed" if completed else "unknown")
        self.assertEqual(selected["amount"], json.loads(receipt.amounts_bytes))
        self.assertEqual(selected["expires_at"], receipt.expires_at)
        self.assertLess(parent["sequence"], selected["sequence"])
        self.assertLessEqual(parent["created_at"], selected["created_at"])
        self.assertEqual(selected["lineage"], {
            "kind": "sibling", "parent_attempt_id": parent["attempt_id"]})
        if selected_first:
            self.assertLess(receipt.expires_at, parent["expires_at"])
            self.assertLess(self.clock.now, parent["expires_at"])
        else:
            self.assertLess(parent["expires_at"], receipt.expires_at)
            self.assertLess(self.clock.now, receipt.expires_at)

    def test_reserved_sibling_parent_deadline_follows_final_gate_delays(self):
        for stage in ("lock", "status", "owner", "charge", "policy"):
            for remaining in (0, 1):
                with self.subTest(stage=stage, remaining=remaining):
                    self.sibling_deadline_control(
                        "reserved", stage, remaining=remaining, completed=bool(remaining))

    def test_started_and_completed_sibling_parents_outlive_reservation_deadlines(self):
        for parent_state in ("invocation-intent", "terminal"):
            for stage in ("lock", "status", "owner", "charge", "policy"):
                with self.subTest(parent_state=parent_state, stage=stage):
                    self.sibling_deadline_control(parent_state, stage, remaining=0, completed=True)

    def test_sibling_admission_earlier_expiry_still_refuses(self):
        for stage in ("lock", "status", "owner", "charge", "policy"):
            with self.subTest(stage=stage):
                self.sibling_deadline_control(
                    "reserved", stage, remaining=0, completed=False, selected_first=True)

    def test_completed_parent_deadline_allows_ordinary_dependent(self):
        _sibling, parent = self.sibling_deadline_receipt("terminal", "EXAMPLE-dependent")
        receipt = self.make_receipt(node_id="review")
        self.clock.now = parent["expires_at"]
        effect = Mock(return_value=ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0)))
        result = adapter.invoke_offline(
            receipt, self.route, "review", ledger=self.store, effect=effect,
            node_attempts={"plan": parent["attempt_id"]})
        effect.assert_called_once()
        self.assertEqual(result["attempt"]["outcome"], "completed")
        self.assertEqual(result["attempt"]["expires_at"], receipt.expires_at)
        self.assertEqual(result["attempt"]["amount"], json.loads(receipt.amounts_bytes))
        self.assertEqual(result["attempt"]["lineage"], {
            "kind": "successor", "parent_attempt_id": parent["attempt_id"]})
        document = self.assert_control_charges(receipt)
        self.assertEqual(document["attempts"][parent["attempt_id"]], parent)

    def unavailable_owner_control(self, node_id, status):
        receipt, mapping = self.control_receipt(node_id, f"unavailable-owner-{status}")
        request = b"EXAMPLE-unavailable-owner-request"
        intents = []
        effect = Mock(return_value=ledger_api.EffectResult("completed"))

        def observer(event):
            if event["event"] == "invocation-intent":
                intents.append(fixtures.begin_unavailable_owner_intent(
                    self.store, self.owners, request, status=status,
                    budget_id=receipt.budget_id, request_id="EXAMPLE-unavailable-owner-node",
                    request_sha256=ledger_api.request_sha256(request),
                    admission_sha256=ledger_api.request_sha256(b"EXAMPLE-unavailable-owner-admission"),
                    amount=dict.fromkeys(planner.RESOURCES, 1), expires_at=receipt.expires_at))

        with self.assertRaisesRegex(ledger_api.InvocationLedgerError, "unresolved intent"):
            adapter.invoke_offline(
                receipt, self.route, node_id, ledger=self.store, effect=effect,
                observer=observer, node_attempts=mapping)
        effect.assert_not_called()
        self.assertEqual(len(intents), 1)
        intent = intents[0]
        self.assertNotEqual(intent["owner"], self.owners.current())
        self.assertEqual(self.owners.status(intent["owner"]), status)
        self.assertEqual((intent["state"], intent["outcome"]), ("invocation-intent", None))
        document = self.assert_control_charges(receipt)
        self.assertEqual(document["attempts"][intent["attempt_id"]], intent)
        selected = next(item for item in document["attempts"].values() if item["request_id"] == node_id)
        self.assertEqual((selected["state"], selected["outcome"]), ("terminal", "unknown"))
        self.assertEqual(selected["amount"], json.loads(receipt.amounts_bytes))

    def test_observer_unavailable_owner_intent_refuses_primary_and_dependent_effects(self):
        for node_id in ("plan", "review"):
            for status in ("gone", "unknown"):
                with self.subTest(node_id=node_id, status=status):
                    self.unavailable_owner_control(node_id, status)

    def assert_preflight_refused(self, receipt, route=UNSET, node_id="plan",
                                 node_attempts=None):
        before = self.disk_bytes()
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        with patch.object(self.store, "open_budget", wraps=self.store.open_budget) as opened:
            with patch.object(self.store, "reserve", wraps=self.store.reserve) as reserved:
                with patch.object(self.store, "invoke", wraps=self.store.invoke) as invoked:
                    with self.assertRaises(ValueError):
                        adapter.invoke_offline(receipt, self.route if route is UNSET else route, node_id,
                                               ledger=self.store, effect=effect,
                                               node_attempts=node_attempts)
        opened.assert_not_called()
        reserved.assert_not_called()
        invoked.assert_not_called()
        effect.assert_not_called()
        self.assertEqual(self.disk_bytes(), before)

    def test_completed_sibling_remains_usable_after_parent_failure(self):
        for node in self.route["nodes"]:
            if node["id"] == "fallback":
                node["depends_on"] = ["plan", "sibling"]
        for role in self.route["task_contract"]["required_roles"]:
            if role["id"] == "fallback":
                role["depends_on"] = ["plan", "sibling"]
        bind(self.route)
        self.plan = planner.prepare(self.route)
        self.assertEqual(self.plan["status"], "within-declared-limits")
        self.receipt = self.make_receipt()
        mapping, events = {}, []

        def failed_parent(_request, _execution, _limits, _report):
            current = next(item for item in self.snapshot()["attempts"].values()
                           if item["request_id"] == "plan")
            self.assertEqual(current["state"], "invocation-intent")
            mapping["plan"] = current["attempt_id"]
            events.append("parent-pending")
            sibling = self.consume_node("sibling", mapping)
            mapping["sibling"] = sibling["attempt_id"]
            self.assertEqual(sibling["outcome"], "completed")
            self.assertEqual(self.snapshot()["attempts"][mapping["plan"]]["state"], "invocation-intent")
            events.append("sibling-completed")
            self.assert_preflight_refused(self.make_receipt(node_id="fallback"), node_id="fallback",
                                          node_attempts=mapping)
            return ledger_api.EffectResult("failed", dict.fromkeys(planner.RESOURCES, 0))

        parent = self.consume_node("plan", effect=failed_parent)
        self.assertEqual(parent["outcome"], "failed")
        events.append("parent-failed")
        sibling = self.snapshot()["attempts"][mapping["sibling"]]
        self.assertEqual(sibling["outcome"], "completed")
        fallback = self.consume_node("fallback", mapping)
        events.append("fallback-completed")
        self.assertEqual(fallback["outcome"], "completed")
        self.assertEqual(fallback["lineage"], {
            "kind": "fallback", "parent_attempt_id": parent["attempt_id"]})
        self.assertLess(parent["sequence"], sibling["sequence"])
        self.assertLess(sibling["sequence"], fallback["sequence"])
        self.assertEqual(events, [
            "parent-pending", "sibling-completed", "parent-failed", "fallback-completed"])

    def invoke_unmatched_attempt(self, receipt, request, reservation, mode):
        limits = json.loads(receipt.limits_bytes)
        if mode == "reconciliation-required":
            failure = KeyboardInterrupt("EXAMPLE unmatched effect interrupted.")
            extra_effect = fixtures.FakeEffect(raises=failure)
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.store.invoke(reservation["reservation_id"], request, extra_effect)
            self.assertIs(raised.exception, failure)
        else:
            usage = ({name: limit + 1 for name, limit in limits.items()} if mode == "overage"
                     else dict.fromkeys(planner.RESOURCES, 0))
            extra_effect = fixtures.FakeEffect(result=ledger_api.EffectResult("completed", usage))
            self.store.invoke(reservation["reservation_id"], request, extra_effect)
        self.assertEqual(extra_effect.calls, [request])
        extra = self.store.attempt(reservation["reservation_id"])
        charged = self.store.summary(receipt.budget_id)["charged"]
        self.assertEqual(extra["state"], "reconciliation-required" if mode == "reconciliation-required" else "terminal")
        if mode == "overage":
            self.assertTrue(all(charged[name] > limit for name, limit in limits.items()))
        return extra, charged

    def assert_observer_result(self, receipt, mapping, mode, effect, observer):
        if mode == "within":
            result = adapter.invoke_offline(
                receipt, self.route, receipt.node_id, ledger=self.store, effect=effect,
                observer=observer, node_attempts=mapping)
            self.assertEqual(result["attempt"]["outcome"], "completed")
            effect.assert_called_once()
            for flag in adapter.FALSE_FIELDS:
                self.assertIs(result[flag], False)
            return
        error = adapter.AdmissionError if mode == "overage" else ledger_api.InvocationLedgerError
        with self.assertRaises(error):
            adapter.invoke_offline(
                receipt, self.route, receipt.node_id, ledger=self.store, effect=effect,
                observer=observer, node_attempts=mapping)
        effect.assert_not_called()

    def observer_control(self, node_id, mode, *, after_live=False):
        self.store = ledger_api.InvocationLedger(
            Path(self.directory.name) / f"EXAMPLE-observer-{node_id}-{mode}-{after_live}",
            clock=self.clock, owner_probe=self.owners)
        mapping = {}
        if node_id != "plan":
            mapping["plan"] = self.consume_node("plan")["attempt_id"]
        receipt = self.make_receipt(node_id=node_id)
        limits = json.loads(receipt.limits_bytes)
        self.store.open_budget(receipt.budget_id, limits, scope_sha256=receipt.scope_sha256)
        request = b"EXAMPLE-unmatched-request"
        reservation = self.store.reserve(
            budget_id=receipt.budget_id, request_id="EXAMPLE-unmatched-node",
            request_sha256=ledger_api.request_sha256(request),
            admission_sha256=ledger_api.request_sha256(b"EXAMPLE-unmatched-admission"),
            amount=dict.fromkeys(planner.RESOURCES, 1), expires_at=self.clock.now + 60,
        )
        changed, events = [], []
        effect = Mock(return_value=ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0)))

        def observer(event):
            if event["event"] == "invocation-intent":
                current = self.snapshot()["attempts"][event["attempt"]["attempt_id"]]
                self.assertEqual(current["state"], "invocation-intent")
                self.assertEqual(current["observers"], [observer.__qualname__])
                events.append(event["event"])
                if not after_live:
                    changed.append(self.invoke_unmatched_attempt(receipt, request, reservation, mode))

        real_live = adapter._live

        def checked_live(admission, ledger):
            real_live(admission, ledger)
            if after_live and events:
                changed.append(self.invoke_unmatched_attempt(receipt, request, reservation, mode))

        with patch.object(adapter, "_live", side_effect=checked_live):
            self.assert_observer_result(receipt, mapping, mode, effect, observer)
        self.assertEqual(events, ["invocation-intent"])
        self.assertEqual(len(changed), 1)
        extra, charged = changed[0]
        self.assertEqual(self.store.attempt(reservation["reservation_id"]), extra)
        summary = self.store.summary(receipt.budget_id)
        self.assertEqual(summary["charged"], charged)
        self.assertEqual(summary["limits"], limits)
        document = self.snapshot()
        self.assertEqual(set(document["budgets"]), {receipt.budget_id})
        self.assertEqual(document["budgets"][receipt.budget_id]["scope_sha256"], receipt.scope_sha256)
        current = next(item for item in document["attempts"].values() if item["request_id"] == node_id)
        self.assertEqual(current["amount"], json.loads(receipt.amounts_bytes))
        self.assertEqual(current["charge"], json.loads(receipt.amounts_bytes))

    def test_observer_usage_primary_and_dependent_rows(self):
        rows = (
            ObserverUsageCase('test_observer_overage_refuses_primary_and_dependent_effects', "overage"),
            ObserverUsageCase('test_observer_reconciliation_refuses_primary_and_dependent_effects', "reconciliation-required"),
            ObserverUsageCase('test_known_observer_usage_allows_primary_and_dependent_effects', "within"),
        )
        for row in rows:
            for node_id in ("plan", "review"):
                with self.subTest(original=row.original, node_id=node_id):
                    self.observer_control(node_id, row.mode)


    def test_final_accounting_follows_live_checks_for_primary_and_dependent_effects(self):
        for node_id in ("plan", "review"):
            for mode in ("overage", "reconciliation-required"):
                with self.subTest(node_id=node_id, mode=mode):
                    self.observer_control(node_id, mode, after_live=True)

    def test_positive_receives_exact_request_options_and_persisted_intent(self):
        events, requests = [], []
        selected = next(node for node in self.plan["nodes"] if node["id"] == "plan")

        def observer(event):
            events.append(event["event"])
            persisted = self.snapshot()["attempts"][event["attempt"]["attempt_id"]]
            self.assertEqual(persisted["state"], event["attempt"]["state"])
            self.assertEqual(persisted["observers"], [observer.__qualname__])

        def effect(request, execution, limits, report):
            requests.append(request)
            current = self.only_attempt()
            self.assertEqual(current["state"], "invocation-intent")
            self.assertEqual(current["observers"], [observer.__qualname__])
            self.assertEqual(events, ["invocation-intent"])
            self.assertEqual(request, self.route["nodes"][0]["rendered_request"].encode("utf-8"))
            self.assertEqual(execution, self.route["nodes"][0]["execution"])
            self.assertEqual(limits, selected["amounts"])
            self.assertEqual(set(limits), set(planner.RESOURCES))
            self.assertEqual(current["request_sha256"], ledger_api.request_sha256(request))
            report("EXAMPLE-progress", {"detail": "EXAMPLE effect observed persisted intent."})
            return ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0))

        with patch.object(planner, "prepare", wraps=planner.prepare) as planned:
            with patch.object(ledger_api, "derived_charge", wraps=ledger_api.derived_charge) as charged:
                result = adapter.invoke_offline(self.receipt, self.route, "plan",
                                                ledger=self.store, effect=effect, observer=observer)
        self.assertGreater(planned.call_count, 0)
        self.assertGreater(charged.call_count, 0)
        self.assertEqual(requests, [self.receipt.request_bytes])
        self.assertEqual(events, ["invocation-intent", "EXAMPLE-progress", "terminal"])
        for field in adapter.FALSE_FIELDS:
            self.assertIs(result[field], False)
            self.assertIs(getattr(self.receipt, field), False)
        self.assertEqual(result["api"], "offline-only-local-admission-v1")
        attempt = result["attempt"]
        self.assertEqual(attempt["charge"], ledger_api.derived_charge(attempt))
        self.assertEqual(attempt["amount"], selected["amounts"])
        budget = self.snapshot()["budgets"][self.route["aggregate_id"]]
        self.assertEqual(budget["limits"], self.route["limits"])
        context = reconciliation.scope_context(self.route)
        self.assertEqual(budget["scope_sha256"], reconciliation.scope_sha256(context))

    def test_snapshot_is_immutable_and_caller_changes_cannot_edit_it(self):
        route = copy.deepcopy(self.route)
        receipt = self.make_receipt(route)
        route["nodes"].clear()
        self.assertEqual(json.loads(receipt.route_input_bytes), self.route)
        self.assertEqual(json.loads(receipt.selected_node_bytes), self.route["nodes"][0])
        self.assertEqual(json.loads(receipt.plan_bytes), self.plan)
        with self.assertRaises(FrozenInstanceError):
            receipt.node_id = "EXAMPLE-drift"
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        adapter.invoke_offline(receipt, self.route, "plan", ledger=self.store, effect=effect)
        effect.assert_called_once()

    def test_absent_number_only_diagnostic_and_malformed_records_are_refused(self):
        malformed = object.__new__(adapter.PreparedAdmission)
        for receipt in (None, 42, {}, self.plan, {"tokens": 42}, malformed):
            with self.subTest(kind=type(receipt).__name__):
                self.assert_preflight_refused(receipt)
        for field in ("route_input_bytes", "selected_node_bytes", "request_bytes", "policy_bytes",
                      "plan_bytes", "aggregate_context_bytes", "scope_sha256", "budget_id",
                      "amounts_bytes", "limits_bytes", "planned_totals_bytes", "execution_bytes", "node_id"):
            value = getattr(self.receipt, field)
            changed = value + b" EXAMPLE-drift" if type(value) is bytes else value + "-EXAMPLE-drift"
            with self.subTest(field=field):
                self.assert_preflight_refused(replace(self.receipt, **{field: changed}))
        self.assert_preflight_refused(replace(self.receipt, amounts_bytes=b"42"))
        self.assert_preflight_refused(replace(self.receipt, request_bytes=bytearray(self.receipt.request_bytes)))

    def test_request_mutations_refuse_in_planning_or_binding(self):
        for field in ("prompt", "wrappers", "attachments", "sources", "rendered_request"):
            route = copy.deepcopy(self.route)
            node = route["nodes"][0]
            if field in ("prompt", "rendered_request"):
                node[field] += " EXAMPLE changed input."
            else:
                node[field][0]["text"] += " EXAMPLE changed input."
            if field != "rendered_request":
                node["rendered_request"] = planner.render_request(node)
            self.assert_preflight_refused(self.receipt, bind(route))

    def test_execution_mutations_refuse_in_planning_or_binding_without_model_substitution(self):
        for field in ("executor", "provider", "model", "effort", "options", "tool_surface", "output_tokens_upper"):
            route = copy.deepcopy(self.route)
            node = route["nodes"][0]
            execution = node["execution"]
            if field == "options":
                execution[field]["EXAMPLE-option"]["enabled"] = False
            elif field == "tool_surface":
                execution[field] = ["EXAMPLE-tool"]
            elif field == "output_tokens_upper":
                execution[field] += 1
            else:
                execution[field] += "-EXAMPLE-drift"
            node["rendered_request"] = planner.render_request(node)
            self.assert_preflight_refused(self.receipt, bind(route))

    def test_scope_limits_and_unselected_nodes_retain_whole_route_binding(self):
        for field in ("aggregate_id", "run_id", "purpose", "output"):
            route = copy.deepcopy(self.route)
            route[field] += "-EXAMPLE-drift"
            self.assert_preflight_refused(self.receipt, bind(route))
        for resource in planner.RESOURCES:
            route = copy.deepcopy(self.route)
            route["limits"][resource] += 1
            self.assert_preflight_refused(self.receipt, bind(route))
        route = copy.deepcopy(self.route)
        route["nodes"][1]["prompt"] = route["nodes"][1]["prompt"].replace("Prepare", "EXAMPLE", 1)
        self.assertNotEqual(route["nodes"][1]["prompt"], self.route["nodes"][1]["prompt"])
        route["nodes"][1]["rendered_request"] = planner.render_request(route["nodes"][1])
        bind(route)
        self.assertEqual(planner.prepare(route)["status"], "within-declared-limits")
        self.assert_preflight_refused(self.receipt, route)

    def test_stale_malformed_and_incomplete_original_inputs_are_refused(self):
        route = copy.deepcopy(self.route)
        route["nodes"][0]["prompt"] += " EXAMPLE stale input."
        self.assert_preflight_refused(self.receipt, route)
        route = copy.deepcopy(self.route)
        route["nodes"].pop()
        self.assert_preflight_refused(self.receipt, bind(route))
        for route in (None, 42, {}, {"status": "within-declared-limits", "totals": self.plan["totals"]}):
            self.assert_preflight_refused(self.receipt, route)

    def test_inline_policy_must_match_current_file_even_after_rehashing(self):
        route = copy.deepcopy(self.route)
        route["policy"]["name"] = "EXAMPLE-rehashed-policy"
        route["policy_sha256"] = planner.canonical_authority_sha256(route["policy"])
        for node in route["nodes"]:
            unit = planner.work_sizing.evaluate_work_estimate(node["estimate_source"], policy=route["policy"])
            node["unit_estimate"] = unit
            node["unit_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(unit)
        bind(route)
        self.assertEqual(planner.prepare(route)["status"], "within-declared-limits")
        with self.assertRaises(ValueError):
            self.make_receipt(route)
        self.assert_preflight_refused(self.receipt, route)

    def test_current_policy_byte_and_content_drift_are_refused(self):
        policy = copy.deepcopy(self.route["policy"])
        policy["name"] = "EXAMPLE-current-policy-drift"
        for raw in (self.receipt.policy_bytes + b"\n", reconciliation._encode(policy)):
            with patch.object(adapter, "_read_policy_bytes", return_value=raw):
                self.assert_preflight_refused(self.receipt)

    def test_unknown_noninteger_and_zero_resources_never_become_allowances(self):
        for resource in planner.RESOURCES:
            for value in (None, True, 0, 1.5, -1):
                route = copy.deepcopy(self.route)
                route["limits"][resource] = value
                with self.subTest(resource=resource, value=value):
                    with self.assertRaises(ValueError):
                        self.make_receipt(bind(route))
        route = copy.deepcopy(self.route)
        route["projection_policy"]["billing"] = None
        with self.assertRaises(ValueError):
            self.make_receipt(bind(route))
        route = copy.deepcopy(self.route)
        billing = route["projection_policy"]["billing"]
        for field in ("input_microunits_per_token_upper", "output_microunits_per_token_upper",
                      "fixed_microunits_per_attempt_upper"):
            billing[field] = 0
        bind(route)
        self.assertEqual(planner.prepare(route)["status"], "within-declared-limits")
        with self.assertRaises(ValueError):
            self.make_receipt(route)
        self.assertIsNone(self.disk_bytes())

    def test_expiry_future_issue_and_invalid_time_bounds_refuse_before_writes(self):
        self.clock.now = self.receipt.expires_at
        self.assert_preflight_refused(self.receipt)
        self.clock.now = self.receipt.issued_at
        self.assert_preflight_refused(self.make_receipt(now=self.clock.now + 1))
        for issued, expiry in ((True, 20), (0, float("nan")), (0, float("inf")),
                               (-1, 20), (0, ledger_api.MAX_TIME + 1), (0, 0),
                               (0, adapter.MAX_LIFETIME_SECONDS + 1)):
            with self.assertRaises(ValueError):
                adapter.prepare(self.route, "plan", now=issued, expires_at=expiry)

    def test_replay_and_new_receipt_cannot_repeat_the_primary(self):
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        adapter.invoke_offline(self.receipt, self.route, "plan", ledger=self.store, effect=effect)
        before = self.disk_bytes()
        self.clock.now += 1
        for receipt in (self.receipt, self.make_receipt()):
            with self.assertRaises(ledger_api.InvocationLedgerError):
                adapter.invoke_offline(receipt, self.route, "plan", ledger=self.store, effect=effect)
        effect.assert_called_once()
        self.assertEqual(self.disk_bytes(), before)

    def test_racing_consumers_allow_at_most_one_effect(self):
        barrier = threading.Barrier(2)
        lock, calls = threading.Lock(), []

        def effect(_request, _execution, _limits, _report):
            with lock:
                calls.append("EXAMPLE-effect")
            return ledger_api.EffectResult("completed")

        def consume():
            store = ledger_api.InvocationLedger(self.store.root, clock=self.clock, owner_probe=self.owners)
            barrier.wait(timeout=10)
            try:
                adapter.invoke_offline(self.receipt, self.route, "plan", ledger=store, effect=effect)
                return "completed"
            except ledger_api.InvocationLedgerError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(consume) for _ in range(2)]
            results = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(results), ["completed", "refused"])
        self.assertEqual(calls, ["EXAMPLE-effect"])
        self.assertEqual(self.only_attempt()["state"], "terminal")


    def test_existing_budget_limits_and_scope_cannot_reset(self):
        for mode in ("limits", "scope"):
            self.store = ledger_api.InvocationLedger(
                Path(self.directory.name) / ("EXAMPLE-" + mode), clock=self.clock, owner_probe=self.owners)
            limits = json.loads(self.receipt.limits_bytes)
            scope = self.receipt.scope_sha256
            if mode == "limits":
                limits["tokens"] += 1
            else:
                scope = ledger_api.request_sha256(b"EXAMPLE-other-scope")
            self.store.open_budget(self.receipt.budget_id, limits, scope_sha256=scope)
            before = self.disk_bytes()
            effect = Mock(return_value=ledger_api.EffectResult("completed"))
            with self.assertRaises(ledger_api.InvocationLedgerError):
                adapter.invoke_offline(self.receipt, self.route, "plan", ledger=self.store, effect=effect)
            effect.assert_not_called()
            self.assertEqual(self.disk_bytes(), before)

    def test_failed_effect_retains_the_full_real_ledger_charge(self):
        effect = Mock(return_value=ledger_api.EffectResult("failed", dict.fromkeys(planner.RESOURCES, 0)))
        result = adapter.invoke_offline(self.receipt, self.route, "plan", ledger=self.store, effect=effect)
        self.assertEqual(result["attempt"]["outcome"], "failed")
        self.assertEqual(result["attempt"]["charge"], json.loads(self.receipt.amounts_bytes))
        self.assertEqual(result["attempt"]["charge"], ledger_api.derived_charge(result["attempt"]))

    def test_timeout_unknown_and_crash_ambiguity_remain_charged(self):
        cases = ((ledger_api.InvocationTimeout("EXAMPLE timeout"), "terminal", "timeout"),
                 (RuntimeError("EXAMPLE outcome unknown"), "terminal", "unknown"),
                 (KeyboardInterrupt("EXAMPLE interrupted effect"), "reconciliation-required", None))
        for index, (failure, state, outcome) in enumerate(cases):
            self.store = ledger_api.InvocationLedger(
                Path(self.directory.name) / f"EXAMPLE-failure-{index}", clock=self.clock, owner_probe=self.owners)
            effect = Mock(side_effect=failure)
            with self.assertRaises(type(failure)) as raised:
                adapter.invoke_offline(self.receipt, self.route, "plan", ledger=self.store, effect=effect)
            self.assertIs(raised.exception, failure)
            attempt = self.only_attempt()
            self.assertEqual((attempt["state"], attempt["outcome"]), (state, outcome))
            self.assertEqual(attempt["charge"], ledger_api.derived_charge(attempt))
            self.assertEqual(attempt["charge"], json.loads(self.receipt.amounts_bytes))
            with self.assertRaises(ledger_api.InvocationLedgerError):
                adapter.invoke_offline(self.receipt, self.route, "plan", ledger=self.store, effect=effect)
            effect.assert_called_once()

    def test_expiry_during_observation_refuses_the_fake_effect_and_keeps_charge(self):
        def observer(event):
            if event["event"] == "invocation-intent":
                self.clock.now = self.receipt.expires_at
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        with self.assertRaises(ValueError):
            adapter.invoke_offline(self.receipt, self.route, "plan",
                                   ledger=self.store, effect=effect, observer=observer)
        effect.assert_not_called()
        self.assertEqual(self.only_attempt()["charge"], json.loads(self.receipt.amounts_bytes))

    def test_tiny_primary_retains_signature_and_initial_lineage(self):
        route = example_route(tiny=True)
        receipt = self.make_receipt(route)
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        result = adapter.invoke_offline(receipt, route, "plan", ledger=self.store, effect=effect)
        effect.assert_called_once()
        self.assertEqual(result["attempt"]["lineage"], {"kind": "initial", "parent_attempt_id": None})
        self.assertEqual(len(json.loads(receipt.plan_bytes)["nodes"]), 1)

    def test_policy_drift_during_observation_refuses_the_fake_effect(self):
        current = [self.receipt.policy_bytes]

        def observer(event):
            if event["event"] == "invocation-intent":
                current[0] += b"\n"

        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        with patch.object(adapter, "_read_policy_bytes", side_effect=lambda: current[0]):
            with self.assertRaises(ValueError):
                adapter.invoke_offline(self.receipt, self.route, "plan",
                                       ledger=self.store, effect=effect, observer=observer)
        effect.assert_not_called()
        self.assertEqual(self.only_attempt()["charge"], json.loads(self.receipt.amounts_bytes))

    def consume_node(self, node_id, node_attempts=None, *, effect=None):
        receipt = self.make_receipt(node_id=node_id)
        original = next(node for node in self.route["nodes"] if node["id"] == node_id)
        planned = next(node for node in self.plan["nodes"] if node["id"] == node_id)

        def observer(event):
            persisted = self.snapshot()["attempts"][event["attempt"]["attempt_id"]]
            self.assertEqual(persisted["state"], event["attempt"]["state"])
            self.assertEqual(persisted["observers"], [observer.__qualname__])

        def checked_effect(request, execution, limits, report):
            attempts = self.snapshot()["attempts"]
            current = next(item for item in attempts.values() if item["request_id"] == node_id)
            self.assertEqual(current["state"], "invocation-intent")
            self.assertEqual(current["observers"], [observer.__qualname__])
            self.assertEqual(request, original["rendered_request"].encode("utf-8"))
            self.assertEqual(execution, original["execution"])
            self.assertEqual(limits, planned["amounts"])
            self.assertEqual(current["amount"], planned["amounts"])
            report("EXAMPLE-progress", {"detail": "EXAMPLE persisted offline intent."})
            if effect is not None:
                return effect(request, execution, limits, report)
            return ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0))

        result = adapter.invoke_offline(receipt, self.route, node_id,
                                        ledger=self.store, effect=checked_effect,
                                        observer=observer, node_attempts=node_attempts)
        for flag in adapter.FALSE_FIELDS:
            self.assertIs(result[flag], False)
            self.assertIs(getattr(receipt, flag), False)
        return result["attempt"]

    def reconciliation_input(self, mapping):
        context = reconciliation.scope_context(self.route)
        return {"type": reconciliation.WRAPPER_TYPE, "version": 1,
                "route_input": copy.deepcopy(self.route), "ledger_snapshot": self.snapshot(),
                "expected": {"budget_id": self.route["aggregate_id"],
                             "scope_sha256": reconciliation.scope_sha256(context),
                             "context": context, "limits": dict(self.route["limits"])},
                "node_attempts": {node["id"]: mapping.get(node["id"]) for node in self.route["nodes"]}}

    def change_dependencies(self):
        changes = {"synthesis": (["plan"], "plan"),
                   "validation": (["review", "synthesis"], "review"),
                   "sibling": (["review", "synthesis"], "review")}
        for node in self.route["nodes"]:
            if node["id"] in changes:
                dependencies, parent = changes[node["id"]]
                node.update(depends_on=list(dependencies), lineage_parent=parent)
        for role in self.route["task_contract"]["required_roles"]:
            if role["id"] in changes:
                role["depends_on"] = list(changes[role["id"]][0])
        bind(self.route)
        self.plan = planner.prepare(self.route)
        self.assertEqual(self.plan["status"], "within-declared-limits")
        self.receipt = self.make_receipt()

    def recorded_attempt(self, node_id, *, request_id=None, request=None, amount=None,
                         budget_id=None, lineage=None, release=False):
        original = next(node for node in self.route["nodes"] if node["id"] == node_id)
        planned = next(node for node in self.plan["nodes"] if node["id"] == node_id)
        request = original["rendered_request"].encode("utf-8") if request is None else request
        budget_id = self.route["aggregate_id"] if budget_id is None else budget_id
        self.store.open_budget(budget_id, self.route["limits"], scope_sha256=self.receipt.scope_sha256)
        reserved = self.store.reserve(
            budget_id=budget_id, request_id=node_id if request_id is None else request_id,
            request_sha256=ledger_api.request_sha256(request),
            admission_sha256=ledger_api.request_sha256(
                f"EXAMPLE-ledger-admission-{len(self.snapshot()['attempts'])}".encode()),
            amount=planned["amounts"] if amount is None else amount,
            expires_at=self.clock.now + 60, lineage=lineage,
        )
        if release:
            return self.store.release(reserved["reservation_id"], reason="EXAMPLE unused offline reservation.")
        return self.store.invoke(
            reserved["reservation_id"], request,
            fixtures.FakeEffect(result=ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0))),
        )

    def test_sequential_graph_and_actual_reconciliation_compatibility(self):
        mapping = {}
        for sequence, node_id in enumerate(("plan", "review", "synthesis", "validation"), 1):
            attempt = self.consume_node(node_id, mapping)
            mapping[node_id] = attempt["attempt_id"]
            self.assertEqual(attempt["sequence"], sequence)
            self.assertEqual(attempt["created_at"], self.clock.now)
            node = next(node for node in self.route["nodes"] if node["id"] == node_id)
            parent = node["lineage_parent"]
            self.assertEqual(attempt["lineage"], {
                "kind": "initial" if parent is None else "successor",
                "parent_attempt_id": None if parent is None else mapping[parent]})
        payload = self.reconciliation_input(mapping)
        result = reconciliation.prepare(payload)
        self.assertEqual(result["status"], "within-declared-limits")
        self.assertFalse(result["completeness_gap"])
        self.assertEqual(result["scope_sha256"], self.receipt.scope_sha256)
        self.assertEqual({row["node_id"]: row["attempt_id"] for row in result["nodes"]},
                         payload["node_attempts"])
        self.assertEqual(result["actual_charged"], self.store.summary(self.receipt.budget_id)["charged"])
        for flag in reconciliation.FALSE_FIELDS:
            self.assertIs(result[flag], False)

    def test_pending_sibling_and_additional_dependencies_use_real_sequence(self):
        self.change_dependencies()
        mapping = {"plan": self.consume_node("plan")["attempt_id"]}

        def review_effect(_request, _execution, _limits, _report):
            review = next(item for item in self.snapshot()["attempts"].values()
                          if item["request_id"] == "review")
            self.assertEqual(review["state"], "invocation-intent")
            mapping["review"] = review["attempt_id"]
            self.assert_preflight_refused(self.make_receipt(node_id="sibling"), node_id="sibling",
                                          node_attempts=mapping)
            synthesis = self.consume_node("synthesis", {"plan": mapping["plan"]})
            mapping["synthesis"] = synthesis["attempt_id"]
            sibling = self.consume_node("sibling", mapping)
            mapping["sibling"] = sibling["attempt_id"]
            self.assertLess(review["sequence"], sibling["sequence"])
            return ledger_api.EffectResult("completed", dict.fromkeys(planner.RESOURCES, 0))

        review = self.consume_node("review", mapping, effect=review_effect)
        self.assertEqual(review["attempt_id"], mapping["review"])
        validation = self.consume_node("validation", mapping)
        mapping["validation"] = validation["attempt_id"]
        attempts = self.snapshot()["attempts"]
        self.assertEqual([attempts[mapping[name]]["sequence"] for name in
                          ("plan", "review", "synthesis", "sibling", "validation")], [1, 2, 3, 4, 5])
        self.assertTrue(all(item["created_at"] == self.clock.now for item in attempts.values()))
        self.assertEqual(reconciliation.prepare(self.reconciliation_input(mapping))["status"],
                         "within-declared-limits")

    def test_retry_and_fallback_require_failed_parent_and_never_replay(self):
        failed = Mock(return_value=ledger_api.EffectResult("failed", dict.fromkeys(planner.RESOURCES, 0)))
        parent = self.consume_node("plan", effect=failed)
        mapping = {"plan": parent["attempt_id"]}
        self.assertEqual(parent["charge"], json.loads(self.receipt.amounts_bytes))
        self.assert_preflight_refused(self.make_receipt(node_id="review"), node_id="review",
                                      node_attempts=mapping)
        for kind in ("retry", "fallback"):
            attempt = self.consume_node(kind, mapping)
            self.assertEqual(attempt["lineage"], {"kind": kind, "parent_attempt_id": parent["attempt_id"]})
            mapping[kind] = attempt["attempt_id"]
            self.clock.now += 1
            self.assert_preflight_refused(self.make_receipt(node_id=kind), node_id=kind,
                                          node_attempts={"plan": parent["attempt_id"]})
        self.assertEqual(self.store.summary(self.receipt.budget_id)["charged"],
                         {key: sum(ledger_api.derived_charge(item)[key]
                                   for item in self.snapshot()["attempts"].values()) for key in planner.RESOURCES})

    def test_prior_mapping_refuses_missing_extra_duplicate_mismatched_and_bounded_records(self):
        parent = self.consume_node("plan")
        attempt_id = parent["attempt_id"]
        cases = (None, {}, [], {"EXAMPLE-missing": attempt_id}, {"plan": "EXAMPLE-missing"},
                 {"plan": True}, {"plan": []}, {"review": attempt_id},
                 {"plan": attempt_id, "synthesis": attempt_id},
                 {f"EXAMPLE-node-{index}": attempt_id for index in range(planner.MAX_NODES + 1)})
        receipt = self.make_receipt(node_id="review")
        for mapping in cases:
            with self.subTest(mapping_type=type(mapping).__name__):
                self.assert_preflight_refused(receipt, node_id="review", node_attempts=mapping)
        for node_id in ("retry", "fallback"):
            self.assert_preflight_refused(self.make_receipt(node_id=node_id), node_id=node_id,
                                          node_attempts={"plan": attempt_id})

    def test_real_prior_attempts_must_match_budget_request_digest_amount_and_lineage(self):
        for index, mutation in enumerate(("budget", "request", "digest", "amount", "lineage")):
            self.store = ledger_api.InvocationLedger(
                Path(self.directory.name) / f"EXAMPLE-mapped-{index}", clock=self.clock, owner_probe=self.owners)
            options = {}
            if mutation == "budget":
                options["budget_id"] = "EXAMPLE-other-aggregate"
            elif mutation == "request":
                options["request_id"] = "EXAMPLE-other-node"
            elif mutation == "digest":
                options["request"] = b"EXAMPLE mismatched offline request."
            elif mutation == "amount":
                options["amount"] = json.loads(self.receipt.amounts_bytes)
                options["amount"]["tokens"] -= 1
            parent = self.recorded_attempt("plan", **options)
            mapping = {"plan": parent["attempt_id"]}
            node_id = "review"
            if mutation == "lineage":
                child = self.recorded_attempt("review", lineage={
                    "kind": "retry", "parent_attempt_id": parent["attempt_id"]})
                mapping["review"] = child["attempt_id"]
                node_id = "synthesis"
            self.assertEqual(ledger_api.validate_ledger(self.snapshot()), [])
            self.assert_preflight_refused(self.make_receipt(node_id=node_id), node_id=node_id,
                                          node_attempts=mapping)

    def test_equal_timestamps_refuse_actual_later_additional_dependency(self):
        self.change_dependencies()
        parent = self.consume_node("plan")
        review = self.consume_node("review", {"plan": parent["attempt_id"]})
        validation = self.recorded_attempt("validation", lineage={
            "kind": "successor", "parent_attempt_id": review["attempt_id"]})
        synthesis = self.recorded_attempt("synthesis", lineage={
            "kind": "successor", "parent_attempt_id": parent["attempt_id"]})
        self.assertGreater(synthesis["sequence"], validation["sequence"])
        self.assertEqual(synthesis["created_at"], validation["created_at"])
        mapping = {item["request_id"]: item["attempt_id"] for item in
                   (parent, review, validation, synthesis)}
        self.assert_preflight_refused(self.make_receipt(node_id="sibling"), node_id="sibling",
                                      node_attempts=mapping)

    def test_timeout_unknown_and_crash_refuse_all_following_effects(self):
        failures = (ledger_api.InvocationTimeout("EXAMPLE timeout"),
                    RuntimeError("EXAMPLE unknown effect"), KeyboardInterrupt("EXAMPLE interrupted effect"))
        for index, failure in enumerate(failures):
            self.store = ledger_api.InvocationLedger(
                Path(self.directory.name) / f"EXAMPLE-causal-{index}", clock=self.clock, owner_probe=self.owners)
            with self.assertRaises(type(failure)):
                self.consume_node("plan", effect=Mock(side_effect=failure))
            parent = self.only_attempt()
            self.assertEqual(parent["charge"], ledger_api.derived_charge(parent))
            self.assertEqual(parent["charge"], json.loads(self.receipt.amounts_bytes))
            for node_id in ("review", "retry", "fallback", "sibling"):
                self.assert_preflight_refused(self.make_receipt(node_id=node_id), node_id=node_id,
                                              node_attempts={"plan": parent["attempt_id"]})

    def test_released_request_and_renewed_receipt_cannot_restart_a_node(self):
        parent = self.recorded_attempt("plan", release=True)
        self.assertEqual(parent["outcome"], "released")
        self.clock.now += 1
        self.assert_preflight_refused(self.make_receipt())
        self.assert_preflight_refused(self.make_receipt(node_id="sibling"), node_id="sibling",
                                      node_attempts={"plan": parent["attempt_id"]})

    def test_dependent_expiry_and_feasible_drift_refuse_before_effects(self):
        parent = self.consume_node("plan")
        mapping = {"plan": parent["attempt_id"]}
        receipt = self.make_receipt(node_id="review")
        self.clock.now = receipt.expires_at
        self.assert_preflight_refused(receipt, node_id="review", node_attempts=mapping)
        self.clock.now = receipt.issued_at
        route = copy.deepcopy(self.route)
        route["nodes"][1]["execution"]["options"]["temperature"] = 0.75
        route["nodes"][1]["rendered_request"] = planner.render_request(route["nodes"][1])
        bind(route)
        self.assertEqual(route["limits"], self.route["limits"])
        self.assertEqual(planner.prepare(route)["status"], "within-declared-limits")
        self.assert_preflight_refused(receipt, route, node_id="review", node_attempts=mapping)

    def test_feasible_selected_request_options_and_reestimated_source_drift_are_bound(self):
        for mutation in ("prompt", "options", "source", "estimate"):
            route = copy.deepcopy(self.route)
            node = route["nodes"][0]
            if mutation == "prompt":
                node["prompt"] = node["prompt"].replace("Prepare", "EXAMPLE", 1)
            elif mutation == "options":
                node["execution"]["options"]["temperature"] = 0.75
            elif mutation == "source":
                node["sources"][0]["text"] = "xyz"
                manifest = node["estimate_source"]["context_manifest"]
                entry = next(item for item in manifest if item["path"] == node["sources"][0]["id"])
                raw = node["sources"][0]["text"].encode("utf-8")
                entry.update(bytes=len(raw), sha256=ledger_api.request_sha256(raw))
            else:
                node["estimate_source"]["estimates"]["context_tokens_p90"] += 1
            node["source_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(node["estimate_source"])
            node["unit_estimate"] = planner.work_sizing.evaluate_work_estimate(
                node["estimate_source"], policy=route["policy"])
            node["unit_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(node["unit_estimate"])
            node["rendered_request"] = planner.render_request(node)
            bind(route)
            self.assertEqual(route["limits"], self.route["limits"])
            self.assertEqual(planner.prepare(route)["status"], "within-declared-limits", mutation)
            self.assertNotEqual(route["bound_input_sha256"], self.route["bound_input_sha256"])
            self.assert_preflight_refused(self.receipt, route)

    def test_adapter_snapshot_preserves_reconciliation_unknown_usage_reporting(self):
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        parent = self.consume_node("plan", effect=effect)
        payload = self.reconciliation_input({"plan": parent["attempt_id"]})
        result = reconciliation.prepare(payload)
        self.assertEqual(result["status"], "unassessable")
        self.assertTrue(result["completeness_gap"])
        self.assertEqual(result["actual_charged"], parent["charge"])
        self.assertEqual(result["unmapped_attempts"], [])
        for flag in reconciliation.FALSE_FIELDS:
            self.assertIs(result[flag], False)

    def test_sibling_can_use_a_declared_reserved_parent(self):
        reserve, siblings = self.store.reserve, []

        def reserve_with_sibling(**options):
            parent = reserve(**options)
            if options["request_id"] == "plan":
                siblings.append(self.consume_node("sibling", {"plan": parent["attempt_id"]}))
                self.assertEqual(self.snapshot()["attempts"][parent["attempt_id"]]["state"], "reserved")
            return parent

        with patch.object(self.store, "reserve", side_effect=reserve_with_sibling):
            parent = self.consume_node("plan")
        self.assertEqual(len(siblings), 1)
        self.assertEqual(siblings[0]["lineage"],
                         {"kind": "sibling", "parent_attempt_id": parent["attempt_id"]})

    def test_unmapped_unknown_attempt_blocks_a_ready_dependent(self):
        parent = self.consume_node("plan")
        request = b"EXAMPLE unmatched offline request."
        reservation = self.store.reserve(
            budget_id=self.receipt.budget_id, request_id="EXAMPLE-unmatched-node",
            request_sha256=ledger_api.request_sha256(request),
            admission_sha256=ledger_api.request_sha256(b"EXAMPLE-unmatched-admission"),
            amount=json.loads(self.receipt.amounts_bytes), expires_at=self.clock.now + 60,
        )
        with self.assertRaises(RuntimeError):
            self.store.invoke(reservation["reservation_id"], request,
                              fixtures.FakeEffect(raises=RuntimeError("EXAMPLE unknown unmatched effect.")))
        charged = self.store.summary(self.receipt.budget_id)["charged"]
        self.assertEqual(charged, {
            key: parent["charge"][key] + reservation["amount"][key] for key in planner.RESOURCES})
        self.assert_preflight_refused(self.make_receipt(node_id="review"), node_id="review",
                                      node_attempts={"plan": parent["attempt_id"]})
        self.assertEqual(self.store.summary(self.receipt.budget_id)["charged"], charged)

    def test_exhausted_aggregate_refuses_without_an_extra_effect_or_budget(self):
        limits = json.loads(self.receipt.limits_bytes)
        self.store.open_budget(self.receipt.budget_id, limits, scope_sha256=self.receipt.scope_sha256)
        self.store.reserve(
            budget_id=self.receipt.budget_id, request_id="EXAMPLE-blocker",
            request_sha256=ledger_api.request_sha256(b"EXAMPLE-blocker-request"),
            admission_sha256=ledger_api.request_sha256(b"EXAMPLE-blocker-admission"),
            amount=limits, expires_at=self.receipt.expires_at,
        )
        before = self.disk_bytes()
        effect = Mock(return_value=ledger_api.EffectResult("completed"))
        with self.assertRaisesRegex(ledger_api.InvocationLedgerError, "aggregate allowance exhausted"):
            adapter.invoke_offline(self.receipt, self.route, "plan", ledger=self.store, effect=effect)
        effect.assert_not_called()
        self.assertEqual(self.disk_bytes(), before)
        self.assertEqual(self.store.summary(self.receipt.budget_id)["charged"], limits)


if __name__ == "__main__":
    unittest.main()
