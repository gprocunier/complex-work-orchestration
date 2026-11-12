"""Disposable fake effects produce snapshots for pure preparation checks."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import prepare_route_feasibility as planner
import prepare_route_ledger_reconciliation as consumer
import test_invocation_ledger as fixtures
from test_route_feasibility_preparation import bind, record

ledger = consumer.ledger


def expected_for(route):
    context = consumer.scope_context(route)
    return {"budget_id": route["aggregate_id"], "scope_sha256": consumer.scope_sha256(context),
            "context": copy.deepcopy(context), "limits": dict(route["limits"])}


def cli(payload=None, *, raw=None):
    if raw is None:
        raw = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
    output = io.StringIO()
    code = consumer.main(io.BytesIO(raw), output)
    return code, json.loads(output.getvalue())


class Producer:
    """Use an actual disposable ledger with a fake clock, owners and effects."""

    def __init__(self, route):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "EXAMPLE-ledger"
        self.clock, self.owners = fixtures.FakeClock(), fixtures.FakeOwners()
        self.store = ledger.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
        self.expected = expected_for(route)
        self.store.open_budget(route["aggregate_id"], route["limits"], scope_sha256=self.expected["scope_sha256"])
        self.route = route
        self.prepared = planner.prepare(route)
        if self.prepared["status"] != "within-declared-limits":
            raise AssertionError("EXAMPLE fixture route must have known bounded allowances")
        self.serial, self.mapping = 0, dict.fromkeys(node["id"] for node in route["nodes"])

    def add(self, node, *, mode="completed", budget=None, request_id=None, lineage=None):
        raw_node = next(item for item in self.route["nodes"] if item["id"] == node["id"])
        request = raw_node["rendered_request"].encode("utf-8")
        if lineage is None:
            parent = node["lineage_parent"]
            lineage = {"kind": {"primary": "initial", "dependent": "successor"}.get(node["kind"], node["kind"]),
                       "parent_attempt_id": None if parent is None else self.mapping[parent]}
        reservation = self.store.reserve(
            budget_id=budget or self.route["aggregate_id"], request_id=request_id or node["id"],
            request_sha256=hashlib.sha256(request).hexdigest(),
            admission_sha256=hashlib.sha256(f"EXAMPLE-admission-{self.serial}".encode()).hexdigest(),
            amount=node["amounts"], expires_at=self.clock.now + 300, lineage=lineage,
        )
        self.serial += 1
        self.mapping[node["id"]] = reservation["attempt_id"]
        if mode == "reserved":
            return reservation
        if mode == "released":
            self.store.release(reservation["reservation_id"], reason="EXAMPLE unused reservation")
            return reservation
        usage = {key: 0 for key in consumer.RESOURCES}
        if mode == "overage":
            usage["tokens"] = self.route["limits"]["tokens"] + 1
        failure = {
            "unknown": RuntimeError("EXAMPLE remote outcome unknown"),
            "timeout": ledger.InvocationTimeout("EXAMPLE timeout"),
            "cancelled": ledger.InvocationCancelled("EXAMPLE local cancellation"),
            "reconciliation-required": KeyboardInterrupt("EXAMPLE interruption"),
        }.get(mode)
        if failure is None:
            self.store.invoke(reservation["reservation_id"], request, fixtures.FakeEffect(result=ledger.EffectResult("completed", usage)))
        else:
            with unittest.TestCase().assertRaises(type(failure)) as raised:
                self.store.invoke(reservation["reservation_id"], request, fixtures.FakeEffect(raises=failure))
            if raised.exception is not failure:
                raise AssertionError("EXAMPLE effect failure identity changed")
        return reservation

    def snapshot(self):
        """Read private fixture state only before running the pure consumer."""
        return json.loads((self.root / ledger.LEDGER_FILE).read_text(encoding="utf-8"))


class RouteLedgerPreparationTest(unittest.TestCase):
    def fixture(self, *, tiny=True, alternatives=False, modes=None, limits=None):
        route = record(tiny=tiny, alternatives=alternatives)
        route["aggregate_id"] = "EXAMPLE-aggregate"
        if limits is not None:
            route["limits"] = dict(limits)
        bind(route)
        producer = Producer(route)
        self.addCleanup(producer.directory.cleanup)
        for node in producer.prepared["nodes"]:
            mode = (modes or {}).get(node["id"], "completed")
            if mode != "unstarted":
                producer.add(node, mode=mode)
        return producer, self.wrap(producer)

    @staticmethod
    def wrap(producer):
        return {"type": consumer.WRAPPER_TYPE, "version": 1, "route_input": copy.deepcopy(producer.route),
                "ledger_snapshot": producer.snapshot(), "expected": copy.deepcopy(producer.expected),
                "node_attempts": dict(producer.mapping)}

    def check(self, payload, status):
        result = consumer.prepare(payload)
        code, other = cli(payload)
        self.assertEqual((result["status"], other["status"]), (status, status))
        self.assertEqual(result, other)
        self.assertEqual(code, 0 if status == "within-declared-limits" else 2 if status == "invalid" else 1)
        for field in consumer.FALSE_FIELDS:
            self.assertIs(result[field], False)
        return result

    @staticmethod
    def recontext(payload):
        route = payload["route_input"]
        bind(route)
        expected = expected_for(route)
        budget = payload["ledger_snapshot"]["budgets"][route["aggregate_id"]]
        expected["limits"] = copy.deepcopy(budget["limits"])
        budget["scope_sha256"] = expected["scope_sha256"]
        payload["expected"] = expected

    def dependency_fixture(self, order):
        route = record(tiny=False)
        route["aggregate_id"] = "EXAMPLE-aggregate"
        dependencies = {"synthesis": ["plan"], "validation": ["review", "synthesis"]}
        for node in route["nodes"]:
            if node["id"] in dependencies:
                node["depends_on"] = list(dependencies[node["id"]])
                node["lineage_parent"] = "plan" if node["id"] == "synthesis" else "review"
        for role in route["task_contract"]["required_roles"]:
            if role["id"] in dependencies:
                role["depends_on"] = list(dependencies[role["id"]])
        bind(route)
        producer = Producer(route)
        self.addCleanup(producer.directory.cleanup)
        producer.clock.now = 1_000_000.0
        nodes = {node["id"]: node for node in producer.prepared["nodes"]}
        for identity in order:
            producer.add(nodes[identity])
        payload = self.wrap(producer)
        self.assertEqual(ledger.validate_ledger(payload["ledger_snapshot"]), [])
        attempts = payload["ledger_snapshot"]["attempts"]
        for sequence, identity in enumerate(order, 1):
            attempt = attempts[payload["node_attempts"][identity]]
            self.assertEqual(attempt["sequence"], sequence)
            self.assertEqual(attempt["created_at"], producer.clock.now)
            self.assertTrue(all(entry["at"] == producer.clock.now for entry in attempt["history"]))
        return producer, payload

    def test_equal_timestamps_accept_correct_additional_dependency_order(self):
        producer, payload = self.dependency_fixture(("plan", "review", "synthesis", "validation"))
        result = self.check(payload, "within-declared-limits")
        self.assertEqual(result["actual_charged"], producer.prepared["totals"])
        self.assertEqual(result["conservative_total"], producer.prepared["totals"])
        self.assertEqual(result["still_committed"], dict.fromkeys(consumer.RESOURCES, 0))

    def test_equal_timestamps_refuse_later_additional_dependency_sequence(self):
        _, payload = self.dependency_fixture(("plan", "review", "validation", "synthesis"))
        attempts, mapping = payload["ledger_snapshot"]["attempts"], payload["node_attempts"]
        child = attempts[mapping["validation"]]
        lineage_parent = attempts[mapping["review"]]
        dependency = attempts[mapping["synthesis"]]
        self.assertEqual(child["lineage"], {"kind": "successor", "parent_attempt_id": mapping["review"]})
        self.assertLess(lineage_parent["sequence"], child["sequence"])
        self.assertGreater(dependency["sequence"], child["sequence"])
        self.assertEqual(dependency["created_at"], child["created_at"])
        self.assertEqual(dependency["history"][-1]["at"], child["created_at"])
        self.check(payload, "invalid")

    def test_tiny_whole_and_alternative_routes_use_real_allowances_and_charges(self):
        for tiny, alternatives in ((True, False), (False, False), (False, True)):
            with self.subTest(tiny=tiny, alternatives=alternatives):
                producer, payload = self.fixture(tiny=tiny, alternatives=alternatives)
                before = consumer._digest(payload)
                result = self.check(payload, "within-declared-limits")
                self.assertEqual(consumer._digest(payload), before)
                self.assertEqual(len(result["nodes"]), len(producer.route["nodes"]))
                for resource in consumer.RESOURCES:
                    self.assertEqual(result["actual_charged"][resource], producer.prepared["totals"][resource])
                    self.assertEqual(result["conservative_total"][resource], result["actual_charged"][resource])
                    self.assertEqual(result["still_committed"][resource], 0)
        producer, payload = self.fixture(
            tiny=False, alternatives=True,
            modes={"plan": "reserved", "review": "unstarted", "synthesis": "unstarted",
                   "validation": "unstarted", "retry": "unstarted", "fallback": "unstarted"})
        result = self.check(payload, "within-declared-limits")
        self.assertEqual(result["conservative_total"], producer.prepared["totals"])

    def test_unstarted_and_releasing_obligations_keep_the_full_plan(self):
        for mode in ("unstarted", "released", "expired", "drift-refused"):
            producer, payload = self.fixture(modes={"plan": mode if mode in ("unstarted", "released") else "reserved"})
            if mode in ("expired", "drift-refused"):
                reservation = next(iter(producer.snapshot()["attempts"].values()))
                if mode == "expired":
                    producer.clock.now += 301
                    producer.store.recover()
                else:
                    with self.assertRaises(ledger.InvocationLedgerError):
                        producer.store.begin_invocation(reservation["reservation_id"], b"EXAMPLE changed request")
                payload = self.wrap(producer)
            result = self.check(payload, "within-declared-limits")
            for resource in consumer.RESOURCES:
                self.assertEqual(result["actual_charged"][resource], 0)
                self.assertEqual(result["still_committed"][resource], producer.prepared["totals"][resource])
                self.assertEqual(result["conservative_total"][resource], producer.prepared["totals"][resource])

    def test_unknown_reconciliation_timeout_and_cancellation_stay_charged(self):
        for mode in ("unknown", "reconciliation-required", "timeout", "cancelled"):
            producer, payload = self.fixture(modes={"plan": mode})
            result = self.check(payload, "unassessable")
            self.assertEqual(result["actual_charged"], producer.prepared["totals"])
            self.assertEqual(result["conservative_total"], producer.prepared["totals"])
            if mode == "reconciliation-required":
                attempt_id = producer.mapping["plan"]
                producer.store.reconcile(attempt_id, reason="EXAMPLE fixture reconciliation retains its charge")
                self.check(self.wrap(producer), "unassessable")

    def test_observed_overage_and_hidden_attempts_are_conserved(self):
        producer, payload = self.fixture(modes={"plan": "overage"})
        result = self.check(payload, "over-budget")
        self.assertGreater(result["actual_charged"]["tokens"], result["limits"]["tokens"])
        for mode, status in (("completed", "unassessable"), ("overage", "over-budget")):
            producer, payload = self.fixture()
            saved = dict(producer.mapping)
            hidden = producer.add(producer.prepared["nodes"][0], mode=mode, request_id="EXAMPLE-hidden")
            producer.mapping = saved
            payload = self.wrap(producer)
            result = self.check(payload, status)
            self.assertEqual(result["unmapped_attempts"][0]["attempt_id"], hidden["attempt_id"])
            self.assertEqual(result["actual_charged"]["tokens"], sum(
                ledger.derived_charge(attempt)["tokens"] for attempt in payload["ledger_snapshot"]["attempts"].values()))
            self.assertTrue(result["completeness_gap"])

    def test_mapping_is_closed_distinct_and_confined_to_the_selected_budget(self):
        producer, original = self.fixture(tiny=False)
        cases = []
        duplicate = copy.deepcopy(original)
        duplicate["node_attempts"]["review"] = duplicate["node_attempts"]["plan"]
        cases.append(duplicate)
        for key, value in (("plan", True), ("plan", 1), ("plan", {}), ("EXAMPLE-extra", None)):
            candidate = copy.deepcopy(original)
            candidate["node_attempts"][key] = value
            cases.append(candidate)
        omitted = copy.deepcopy(original)
        omitted["node_attempts"].pop("review")
        cases.append(omitted)
        wrong = copy.deepcopy(original)
        wrong["node_attempts"]["plan"] = "EXAMPLE-missing"
        cases.append(wrong)
        for payload in cases:
            self.check(payload, "invalid")
        producer.store.open_budget("EXAMPLE-other", producer.route["limits"], scope_sha256=producer.expected["scope_sha256"])
        producer.add(producer.prepared["nodes"][0], budget="EXAMPLE-other")
        self.check(self.wrap(producer), "invalid")

    def test_expected_context_and_budget_drift_are_refused(self):
        _, original = self.fixture()
        for field in consumer.CONTEXT_FIELDS:
            payload = copy.deepcopy(original)
            payload["expected"]["context"][field] = "EXAMPLE changed context"
            self.check(payload, "invalid")
        for field, value in (("budget_id", "EXAMPLE-other"), ("scope_sha256", "0" * 64)):
            payload = copy.deepcopy(original)
            payload["expected"][field] = value
            self.check(payload, "invalid")
        for resource in consumer.RESOURCES:
            for value in (True, 1.0, 0, None):
                payload = copy.deepcopy(original)
                payload["expected"]["limits"][resource] = value
                self.check(payload, "invalid")
        payload = copy.deepcopy(original)
        payload["ledger_snapshot"]["budgets"]["EXAMPLE-aggregate"]["limits"]["requests"] = 1
        self.check(payload, "invalid")
        payload = copy.deepcopy(original)
        unselected = copy.deepcopy(payload["ledger_snapshot"]["budgets"]["EXAMPLE-aggregate"])
        unselected.update(budget_id="EXAMPLE-unselected")
        unselected["limits"]["tokens"] = True
        payload["ledger_snapshot"]["budgets"]["EXAMPLE-unselected"] = unselected
        self.check(payload, "invalid")

    def test_request_policy_amount_and_lineage_drift_are_refused(self):
        _, original = self.fixture(tiny=False)
        for field in ("prompt", "wrappers", "attachments", "execution"):
            payload = copy.deepcopy(original)
            node = payload["route_input"]["nodes"][0]
            if field == "prompt":
                node[field] += " EXAMPLE changed input"
            elif field == "execution":
                node[field]["options"]["EXAMPLE-option"] = True
            else:
                node[field][0]["text"] += " EXAMPLE changed input"
            node["rendered_request"] = planner.render_request(node)
            self.recontext(payload)
            self.check(payload, "invalid")
        for mutation in ("request", "amount", "lineage", "parent", "dependency-time", "policy"):
            payload = copy.deepcopy(original)
            attempts = payload["ledger_snapshot"]["attempts"]
            attempt = attempts[payload["node_attempts"]["review"]]
            if mutation == "request":
                attempt["request_id"] = "EXAMPLE-other-node"
            elif mutation == "amount":
                attempt["amount"]["tokens"] += 1
                attempt["charge"] = ledger.derived_charge(attempt)
            elif mutation == "lineage":
                attempt["lineage"]["kind"] = "retry"
            elif mutation == "parent":
                attempt = attempts[payload["node_attempts"]["synthesis"]]
                attempt["lineage"]["parent_attempt_id"] = payload["node_attempts"]["plan"]
            elif mutation == "dependency-time":
                parent = attempts[payload["node_attempts"]["plan"]]
                parent["history"][-1]["at"] = attempt["created_at"] + 1
            else:
                payload["route_input"]["policy"]["work_sizing"]["version"] = 2
            self.check(payload, "invalid")

    def test_unknown_projections_and_limits_cannot_claim_a_fit(self):
        for unknown in ("projection", "tokens", "cost_microunits"):
            _, payload = self.fixture()
            if unknown == "projection":
                payload["route_input"]["projection_policy"].update(
                    mode="unknown", tokens_per_utf8_byte_upper=None, input_overhead_tokens=None, billing=None)
            else:
                payload["route_input"]["limits"][unknown] = None
            self.recontext(payload)
            result = self.check(payload, "unassessable")
            self.assertIn("unknown", result["checks"].values())
        _, payload = self.fixture(modes={"plan": "overage"})
        payload["route_input"]["projection_policy"].update(
            mode="unknown", tokens_per_utf8_byte_upper=None, input_overhead_tokens=None, billing=None)
        self.recontext(payload)
        self.check(payload, "over-budget")

    def test_input_bounds_and_parser_failures_are_structured(self):
        _, original = self.fixture()
        for value in (True, -1, 1.5, 2**53):
            payload = copy.deepcopy(original)
            payload["route_input"]["limits"]["tokens"] = value
            self.check(payload, "invalid")
        for payload in (None, {}, {"EXAMPLE": object()}):
            self.assertEqual(consumer.prepare(payload)["status"], "invalid")
        raw_cases = (b"\xff", b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
                     b'{"x":' + b"9" * 5000 + b"}", b"[" * 2000, b" " * (consumer.MAX_BYTES + 1))
        for raw in raw_cases:
            code, result = cli(raw=raw)
            self.assertEqual(code, 2)
            for field in consumer.FALSE_FIELDS:
                self.assertIs(result[field], False)
        payload = copy.deepcopy(original)
        payload["route_input"]["nodes"][0]["prompt"] = "\ud800"
        self.assertEqual(consumer.prepare(payload)["status"], "invalid")
        deep = None
        for _ in range(consumer.MAX_DEPTH + 1):
            deep = [deep]
        self.assertEqual(consumer.prepare(deep)["status"], "invalid")
        self.assertEqual(consumer.prepare([None] * (consumer.MAX_ENTRIES + 1))["status"], "invalid")
        with patch.object(consumer.json, "loads", side_effect=RecursionError("EXAMPLE parser failure")):
            output = io.StringIO()
            self.assertEqual(consumer.main(io.BytesIO(b"{}"), output), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "invalid")

    def test_record_bounds_precede_real_producers(self):
        _, payload = self.fixture()
        payload["ledger_snapshot"]["attempts"] = dict.fromkeys(f"EXAMPLE-{i}" for i in range(consumer.MAX_ATTEMPTS + 1))
        with patch.object(planner, "prepare", wraps=planner.prepare) as plan:
            with patch.object(ledger, "validate_ledger", wraps=ledger.validate_ledger) as validate:
                self.check(payload, "invalid")
                plan.assert_not_called()
                validate.assert_not_called()

    def test_copies_survive_reentrant_caller_changes(self):
        _, payload = self.fixture()
        real_prepare = planner.prepare
        expected = consumer.prepare(payload)
        def prepare(route):
            payload["node_attempts"].clear()
            payload["ledger_snapshot"]["attempts"].clear()
            payload["route_input"]["nodes"].clear()
            return real_prepare(route)
        with patch.object(planner, "prepare", side_effect=prepare):
            self.assertEqual(consumer.prepare(payload), expected)
        _, payload = self.fixture()
        real_validate = ledger.validate_ledger
        expected = consumer.prepare(payload)
        def validate(document):
            errors = real_validate(document)
            document["attempts"].clear()
            payload["expected"].clear()
            return errors
        with patch.object(ledger, "validate_ledger", side_effect=validate):
            self.assertEqual(consumer.prepare(payload), expected)
        with patch.object(consumer, "_binding", side_effect=RuntimeError("EXAMPLE unrelated failure")):
            with self.assertRaisesRegex(RuntimeError, "EXAMPLE unrelated"):
                consumer.prepare(self.fixture()[1])

    def test_named_effect_guards_and_real_producer_calls(self):
        _, payload = self.fixture()
        _, over_budget = self.fixture(modes={"plan": "overage"})
        _, unresolved = self.fixture(modes={"plan": "unknown"})
        import dispatch_work
        from cwo_core import local_invocation
        watched = (
            ("builtins.open", lambda: open("EXAMPLE-never-opened")),
            ("io.open", lambda: Path("EXAMPLE-never-opened").read_bytes()),
            ("os.open", lambda: os.open("EXAMPLE-never-opened", os.O_RDONLY)),
            ("subprocess.Popen", lambda: subprocess.run(["EXAMPLE-never-run"], check=True)),
            ("os.system", lambda: os.system("EXAMPLE-never-run")),
            ("urllib.request.urlopen", lambda: urllib.request.urlopen("https://EXAMPLE.invalid")),
            ("urllib.request.OpenerDirector.open", lambda: urllib.request.OpenerDirector().open("https://EXAMPLE.invalid")),
            ("socket.socket.connect", lambda: socket.socket.connect(None, ("EXAMPLE.invalid", 1))),
            ("dispatch_work.execute_local_envelope", lambda: dispatch_work.execute_local_envelope()),
            ("cwo_core.local_invocation.open_ledger", lambda: local_invocation.open_ledger()),
            ("cwo_core.invocation_ledger.InvocationLedger.__init__", lambda: ledger.InvocationLedger()),
            ("cwo_core.invocation_ledger.InvocationLedger._locked", lambda: ledger.InvocationLedger._locked(None)),
            ("cwo_core.invocation_ledger.InvocationLedger.reserve", lambda: ledger.InvocationLedger.reserve(None)),
            ("cwo_core.invocation_ledger.InvocationLedger.recover", lambda: ledger.InvocationLedger.recover(None)),
            ("cwo_core.invocation_ledger.InvocationLedger._save", lambda: ledger.InvocationLedger._save(None)),
            ("cwo_core.invocation_ledger.InvocationLedger.invoke", lambda: ledger.InvocationLedger.invoke(None)),
            ("cwo_core.invocation_ledger.ProcOwnerProbe.current", lambda: ledger.ProcOwnerProbe.current(None)),
            ("cwo_core.work_sizing.load_policy", lambda: planner.work_sizing.load_policy("EXAMPLE")),
            ("cwo_core.work_sizing.build_policy_fit_commitment",
             lambda: planner.work_sizing.build_policy_fit_commitment(None)),
            ("cwo_core.work_sizing.build_worker_commitment_from_receipt",
             lambda: planner.work_sizing.build_worker_commitment_from_receipt(None, None)),
        )
        with ExitStack() as stack:
            spies = [stack.enter_context(patch(name, side_effect=AssertionError("EXAMPLE guarded effect")))
                     for name, _probe in watched]
            for (_, probe), spy in zip(watched, spies):
                with self.assertRaisesRegex(AssertionError, "EXAMPLE guarded effect"):
                    probe()
                spy.reset_mock()
            validators = stack.enter_context(patch.object(ledger, "validate_ledger", wraps=ledger.validate_ledger))
            charges = stack.enter_context(patch.object(ledger, "derived_charge", wraps=ledger.derived_charge))
            plans = stack.enter_context(patch.object(planner, "prepare", wraps=planner.prepare))
            self.check(payload, "within-declared-limits")
            self.check(over_budget, "over-budget")
            self.check(unresolved, "unassessable")
            invalid = copy.deepcopy(payload)
            invalid["node_attempts"].clear()
            self.check(invalid, "invalid")
            for spy in spies:
                spy.assert_not_called()
            self.assertGreater(validators.call_count, 0)
            self.assertGreater(charges.call_count, 0)
            self.assertGreater(plans.call_count, 0)


if __name__ == "__main__":
    unittest.main()
