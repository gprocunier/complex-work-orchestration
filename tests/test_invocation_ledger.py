"""Reservation state machine, aggregate accounting and crash ambiguity, with fake effects.

Every effect here is a fake that counts its calls and records the bytes it received. No model, network or
browser is used. Controlled local invocation stays unavailable; the only production caller of the ledger
is the local invocation route wiring (``cwo_core.local_invocation``), behind the disabled flag.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

MODULE = "cwo_core.invocation_ledger"
BUDGET = "epic-cwo-41"
SCOPE = hashlib.sha256(b"epic cwo-41 local review").hexdigest()
LIMITS = {"requests": 4, "input_tokens": 4000, "output_tokens": 2000, "seconds": 600}
AMOUNT = {"requests": 1, "input_tokens": 1000, "output_tokens": 500, "seconds": 150}
REQUEST = b'{"model":"test-model","messages":[{"role":"user","content":"Review the notes."}],"max_tokens":500}'


def ledger_module() -> Any:
    """Imported per test, so a missing implementation fails each test rather than the whole file."""
    return importlib.import_module(MODULE)


def admission(label: str) -> str:
    return hashlib.sha256(f"admission:{label}".encode()).hexdigest()


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeOwners:
    """Owner identities without /proc. ``me`` is this process; ``gone`` and ``unknown`` simulate other owners."""

    def __init__(self) -> None:
        self.me = {"pid": 4242, "start_ticks": 7, "boot_id_sha256": "b" * 64}
        self.gone: set[tuple[int, int]] = set()
        self.unknown: set[tuple[int, int]] = set()

    def current(self) -> dict[str, Any]:
        return dict(self.me)

    def status(self, owner: dict[str, Any]) -> str:
        key = (owner["pid"], owner["start_ticks"])
        return "gone" if key in self.gone else "unknown" if key in self.unknown else "alive"

    def crash(self) -> None:
        """The current owner dies; a new process with another identity takes over."""
        self.gone.add((self.me["pid"], self.me["start_ticks"]))
        self.me = {**self.me, "pid": self.me["pid"] + 1}


def begin_unavailable_owner_intent(ledger: Any, owners: FakeOwners, request: bytes, *,
                                  status: str, **reservation: Any) -> dict[str, Any]:
    """Persist real ledger intent under a separate fake owner, retaining its unresolved charge."""
    unavailable = {"gone": owners.gone, "unknown": owners.unknown}[status]
    current = owners.me
    owners.me = {**current, "pid": current["pid"] + 1}
    try:
        reserved = ledger.reserve(**reservation)
        intent = ledger.begin_invocation(reserved["reservation_id"], request)
    finally:
        owners.me = current
    unavailable.add((intent["owner"]["pid"], intent["owner"]["start_ticks"]))
    return intent


class FakeEffect:
    """Stands in for the HTTP POST. Counts calls and records the exact bytes it was given."""

    def __init__(self, result: Any = None, raises: BaseException | None = None, during: Any = None) -> None:
        self.calls: list[bytes] = []
        self.result = result
        self.raises = raises
        self.during = during

    def __call__(self, request_bytes: bytes, report: Any) -> Any:
        self.calls.append(request_bytes)
        if self.during is not None:
            self.during(request_bytes, report)
        if self.raises is not None:
            raise self.raises
        return self.result if self.result is not None else ledger_module().EffectResult("completed")


class LedgerTestCase(unittest.TestCase):
    limits = LIMITS

    def setUp(self) -> None:
        self.mod = ledger_module()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "ledger"
        self.clock = FakeClock()
        self.owners = FakeOwners()
        self.ledger = self.mod.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
        self.ledger.open_budget(BUDGET, self.limits, scope_sha256=SCOPE)

    def reserve(self, label: str = "a", *, amount: dict[str, int] | None = None, lineage: Any = None,
                request: bytes = REQUEST, ttl: float = 300.0, budget: str = BUDGET) -> dict[str, Any]:
        return self.ledger.reserve(
            budget_id=budget, request_id=f"req-{label}", request_sha256=hashlib.sha256(request).hexdigest(),
            admission_sha256=admission(label), amount=dict(amount or AMOUNT), expires_at=self.clock.now + ttl,
            lineage=lineage,
        )

    def reserve_then_invoke(self, label: str, effect: Any, **reserve_options: Any) -> dict[str, Any]:
        """The connected path a caller takes: reserve, then invoke the effect with that reservation."""
        reservation = self.reserve(label, **reserve_options)
        return self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)

    def charged(self) -> dict[str, int]:
        return self.ledger.summary(BUDGET)["charged"]

    def ledger_document(self) -> dict[str, Any]:
        return json.loads((self.root / "ledger.json").read_text(encoding="utf-8"))

    def write_document(self, document: dict[str, Any]) -> None:
        (self.root / "ledger.json").write_text(json.dumps(document), encoding="utf-8")

    def assert_refused(self, call: Any, *fragments: str) -> None:
        with self.assertRaises(self.mod.InvocationLedgerError) as raised:
            call()
        for fragment in fragments:
            self.assertIn(fragment, str(raised.exception))


class ParentDeadlineTests(LedgerTestCase):
    def test_live_parent_intent_remains_valid_at_its_reservation_deadline(self) -> None:
        parent = self.reserve("EXAMPLE-parent", ttl=2)
        self.ledger.begin_invocation(parent["reservation_id"], REQUEST)
        sibling = self.reserve(
            "EXAMPLE-sibling", ttl=60,
            lineage={"kind": "sibling", "parent_attempt_id": parent["attempt_id"]})
        self.assertLess(parent["expires_at"], sibling["expires_at"])
        self.clock.now = parent["expires_at"]
        self.assertEqual(self.ledger.recover(BUDGET), [])
        self.assertEqual(self.ledger.attempt(parent["reservation_id"])["state"],
                         "invocation-intent")
        self.assert_refused(lambda: self.ledger.release(parent["reservation_id"]),
                            "stays charged")
        effect = FakeEffect(result=self.mod.EffectResult(
            "completed", dict.fromkeys(AMOUNT, 0)))
        final = self.ledger.invoke(sibling["reservation_id"], REQUEST, effect)
        self.assertEqual(effect.calls, [REQUEST])
        self.assertEqual(final["outcome"], "completed")
        self.assertEqual(self.ledger.attempt(parent["reservation_id"])["state"],
                         "invocation-intent")
        finished = self.ledger.finish(
            parent["reservation_id"], "completed",
            reason="EXAMPLE parent completed after its reservation deadline.",
            observed_usage=dict.fromkeys(AMOUNT, 0))
        self.assertEqual(finished["outcome"], "completed")
        self.assertEqual(finished["expires_at"], parent["expires_at"])
        self.assertEqual(self.charged(), {dimension: 2 * amount for dimension, amount in AMOUNT.items()})
        self.assertEqual(self.mod.validate_ledger(self.ledger_document()), [])


class RefusalsProduceZeroEffectsTests(LedgerTestCase):
    """Absent, number-only, malformed, forged, stale, drifted or replayed inputs and an exhausted aggregate.

    Tests that call ``reserve`` alone are standalone reservation refusals: they show that nothing is recorded or
    charged, and no effect is reachable from them. Tests that count effects go through ``invoke`` or the connected
    ``reserve_then_invoke`` path.
    """

    def test_an_absent_reservation_never_invokes(self) -> None:
        effect = FakeEffect()
        self.assert_refused(lambda: self.ledger.invoke("inv-reservation-absent", REQUEST, effect), "no reservation")
        self.assertEqual(effect.calls, [])

    def test_unrecorded_reservation_input_family(self) -> None:
        """Both standalone refusal matrices keep the same genuinely empty budget."""
        before = self.ledger_document()
        malformed = {
            "missing dimension": {"amount": {k: v for k, v in AMOUNT.items() if k != "seconds"}},
            "extra dimension": {"amount": {**AMOUNT, "dollars": 1}},
            "zero units": {"amount": {**AMOUNT, "requests": 0}},
            "negative units": {"amount": {**AMOUNT, "output_tokens": -1}},
            "boolean units": {"amount": {**AMOUNT, "requests": True}},
            "float units": {"amount": {**AMOUNT, "seconds": 1.5}},
            "short request digest": {"request_sha256": "abc"},
            "uppercase admission digest": {"admission_sha256": "A" * 64},
            "absent admission": {"admission_sha256": None},
            "bad request id": {"request_id": "../req"},
            "unknown budget": {"budget_id": "epic-none"},
            "stale expiry": {"expires_at": self.clock.now},
            "non-finite expiry": {"expires_at": float("inf")},
            "unknown lineage kind": {"lineage": {"kind": "reset", "parent_attempt_id": None}},
            "initial with parent": {"lineage": {"kind": "initial", "parent_attempt_id": "inv-attempt-x"}},
            "child of nothing": {"lineage": {"kind": "retry", "parent_attempt_id": "inv-attempt-x"}},
        }
        rows = (
            ("test_a_number_only_amount_is_refused", "n",
             [(amount, {"amount": amount}) for amount in (1, 500, 1.5, "500", None, [1, 1, 1, 1])],
             ("amount",), False),
            ("test_malformed_reservations_are_refused_before_anything_is_recorded", "m",
             list(malformed.items()), (), True),
        )
        for row_id, label, cases, fragments, check_charge in rows:
            good = {"budget_id": BUDGET, "request_id": "req-" + label, "request_sha256": "0" * 64,
                    "admission_sha256": admission(label), "amount": dict(AMOUNT),
                    "expires_at": self.clock.now + 60}
            for name, change in cases:
                with self.subTest(row=row_id, case=name):
                    request = copy.deepcopy({**good, **change})
                    self.assert_refused(lambda: self.ledger.reserve(**request), *fragments)
            summary = self.ledger.summary(BUDGET)
            if check_charge:
                self.assertEqual(sum(summary["attempts_by_state"].values()), 0)
                self.assertEqual(summary["charged"], {dimension: 0 for dimension in LIMITS})
            else:
                self.assertEqual(summary["attempts_by_state"]["reserved"], 0)
            self.assertEqual(self.ledger_document(), before)


    def test_a_stale_reservation_never_invokes_or_resumes(self) -> None:
        reservation = self.reserve(ttl=30)
        self.clock.now += 30
        effect = FakeEffect()
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect), "expired")
        self.clock.now -= 29  # even with the clock moved back, an expired reservation stays terminal
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect), "already used")
        attempt = self.ledger.attempt(reservation["reservation_id"])
        self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "expired"))
        self.assertEqual(effect.calls, [])
        self.assertEqual(self.charged(), {dimension: 0 for dimension in LIMITS})

    def test_drifted_request_bytes_never_invoke_and_invalidate_the_reservation(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect()
        drifted = REQUEST.replace(b'"max_tokens":500', b'"max_tokens":5000')
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], drifted, effect),
                            "changed since reservation")
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect), "already used")
        attempt = self.ledger.attempt(reservation["reservation_id"])
        self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "drift-refused"))
        self.assertEqual(effect.calls, [])

    def test_a_replayed_reservation_invokes_at_most_once(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect()
        self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect),
                            "already used", "a replay never invokes")
        self.assertEqual(len(effect.calls), 1)


    def test_another_process_cannot_use_the_reservation(self) -> None:
        reservation = self.reserve()
        self.owners.me = {**self.owners.me, "pid": 9999}
        effect = FakeEffect()
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect),
                            "belongs to another process")
        self.assert_refused(lambda: self.ledger.release(reservation["reservation_id"]), "belongs to another process")
        self.assertEqual(effect.calls, [])
        self.assertEqual(self.ledger.attempt(reservation["reservation_id"])["state"], "reserved")

    def test_a_forged_or_edited_ledger_refuses_every_operation(self) -> None:
        reservation = self.reserve("a")
        spent = self.reserve("b")
        self.ledger.invoke(spent["reservation_id"], REQUEST, FakeEffect())
        original = self.ledger_document()
        spent_id = spent["attempt_id"]
        reserved_id = reservation["attempt_id"]

        def edit(change: Any) -> dict[str, Any]:
            document = json.loads(json.dumps(original))
            change(document)
            return document

        forged_attempt = json.loads(json.dumps(original["attempts"][reserved_id]))
        forged_attempt.update(attempt_id="inv-attempt-forged", reservation_id="inv-reservation-forged",
                              admission_sha256=admission("forged"), sequence=99, charge={d: 0 for d in LIMITS})
        cases = {
            "spent attempt reset to reserved": lambda d: d["attempts"][spent_id].update(
                state="reserved", outcome=None),
            "charge lowered": lambda d: d["attempts"][spent_id].update(charge={k: 0 for k in LIMITS}),
            "limits raised": lambda d: d["budgets"][BUDGET]["limits"].update(requests=400),
            "uncharged forged reservation": lambda d: d["attempts"].update({"inv-attempt-forged": forged_attempt}),
            "history skips intent": lambda d: d["attempts"][spent_id]["history"].pop(1),
            "duplicate admission": lambda d: d["attempts"][reserved_id].update(
                admission_sha256=original["attempts"][spent_id]["admission_sha256"]),
            "unknown state": lambda d: d["attempts"][reserved_id].update(state="approved"),
            "future version": lambda d: d.update(version=2),
            "extra field": lambda d: d.update(note="trust me"),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                document = edit(change)
                if name == "limits raised":
                    # Raising limits keeps every record internally consistent, but the budget no longer matches what
                    # was opened, so re-opening it with the admitted limits is refused.
                    self.write_document(document)
                    self.assert_refused(lambda: self.ledger.open_budget(BUDGET, LIMITS, scope_sha256=SCOPE),
                                        "different limits")
                    continue
                self.write_document(document)
                effect = FakeEffect()
                self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect), "invalid")
                self.assert_refused(lambda: self.reserve("c"), "invalid")
                self.assertEqual(effect.calls, [])
        self.write_document(original)
        (self.root / "ledger.json").write_text('{"ledger_type": "cwo-invocation-ledger", "ledger_type": "x"}')
        self.assert_refused(lambda: self.reserve("c"), "repeats key")
        (self.root / "ledger.json").write_text("not json")
        self.assert_refused(lambda: self.reserve("c"), "not valid JSON")


    def test_malformed_caller_types_are_refused_cleanly(self) -> None:
        """Unhashable or wrongly typed arguments are refusals, not TypeError, and invoke nothing."""
        reservation = self.reserve("a")
        effect = FakeEffect()
        calls = {
            "array budget_id to reserve": lambda: self.ledger.reserve(
                budget_id=[BUDGET], request_id="req-x", request_sha256="0" * 64, admission_sha256=admission("x"),
                amount=dict(AMOUNT), expires_at=self.clock.now + 60),
            "object budget_id to reserve": lambda: self.ledger.reserve(
                budget_id={"id": BUDGET}, request_id="req-x", request_sha256="0" * 64,
                admission_sha256=admission("x"), amount=dict(AMOUNT), expires_at=self.clock.now + 60),
            "object lineage parent": lambda: self.reserve(
                "y", lineage={"kind": "retry", "parent_attempt_id": {"id": reservation["attempt_id"]}}),
            "array budget_id to summary": lambda: self.ledger.summary([BUDGET]),
            "array attempt_id to reconcile": lambda: self.ledger.reconcile([reservation["attempt_id"]], reason="x"),
            "text request to invoke": lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST.decode(), effect),
            "text request to begin": lambda: self.ledger.begin_invocation(reservation["reservation_id"], REQUEST.decode()),
        }
        for name, call in calls.items():
            with self.subTest(case=name):
                self.assert_refused(call)
        self.assertEqual(effect.calls, [])
        self.assertEqual(self.ledger.attempt(reservation["reservation_id"])["state"], "reserved")


    def test_budget_limits_never_change_or_reset(self) -> None:
        self.reserve()
        self.assertEqual(self.ledger.open_budget(BUDGET, LIMITS, scope_sha256=SCOPE)["limits"], LIMITS)
        for limits, scope in (({**LIMITS, "requests": 40}, SCOPE), (LIMITS, "f" * 64), ({"requests": 4}, SCOPE)):
            with self.subTest(limits=limits, scope=scope):
                self.assert_refused(lambda: self.ledger.open_budget(BUDGET, limits, scope_sha256=scope),
                                    "limits never change")
        self.assertEqual(self.charged(), AMOUNT)

    def test_a_symlinked_ledger_or_root_is_refused(self) -> None:
        self.reserve()
        target = self.root.parent / "elsewhere.json"
        os.replace(self.root / "ledger.json", target)
        os.symlink(target, self.root / "ledger.json")
        self.assert_refused(lambda: self.reserve("b"), "non-symlink")
        # Isolate the root guard from the ledger-file guard checked above.
        (self.root / "ledger.json").unlink()
        os.replace(target, self.root / "ledger.json")
        link = self.root.parent / "linked-root"
        os.symlink(self.root, link)
        ledger = self.mod.InvocationLedger(link, clock=self.clock, owner_probe=self.owners)
        self.assert_refused(lambda: ledger.summary(BUDGET), "symlink")

    def test_a_replayed_admission_is_never_reserved_again(self) -> None:
        first = self.reserve("same")
        self.ledger.release(first["reservation_id"])
        self.assert_refused(lambda: self.reserve("same"), "admission replay")
        self.assertEqual(self.ledger.summary(BUDGET)["attempts_by_state"]["terminal"], 1)

    def test_an_exhausted_aggregate_refuses_and_records_nothing(self) -> None:
        """Connected path: the reservation is refused, so the effect behind it is never called."""
        for label in "abcd":
            self.reserve(label)
        effect = FakeEffect()
        self.assert_refused(lambda: self.reserve_then_invoke("e", effect), "aggregate allowance exhausted",
                            "nothing was reserved")
        self.assertEqual(self.ledger.summary(BUDGET)["attempts_by_state"]["reserved"], 4)
        self.assertEqual(effect.calls, [])
        # One dimension alone exhausts the budget even when the others have room.
        ledger = self.mod.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
        ledger.open_budget("epic-tokens", LIMITS, scope_sha256=SCOPE)
        self.assert_refused(
            lambda: self.reserve_then_invoke("t", effect, budget="epic-tokens", amount={**AMOUNT, "output_tokens": 2001}),
            "output_tokens",
        )
        self.assertEqual(effect.calls, [])
        self.assertEqual(ledger.summary("epic-tokens")["charged"], {dimension: 0 for dimension in LIMITS})


    def test_malformed_types_in_a_stored_ledger_are_refused_cleanly(self) -> None:
        """Wrong JSON types are refused as an invalid ledger, never raised as TypeError or accepted as equal."""
        reservation = self.reserve("a")
        spent = self.reserve("b")
        self.ledger.invoke(spent["reservation_id"], REQUEST, FakeEffect())
        original = self.ledger_document()
        spent_id, reserved_id = spent["attempt_id"], reservation["attempt_id"]
        follower = json.loads(json.dumps(original["attempts"][reserved_id]))
        follower.update(attempt_id="inv-attempt-follower", reservation_id="inv-reservation-follower",
                        admission_sha256=admission("follower"), sequence=3,
                        lineage={"kind": "retry", "parent_attempt_id": {"attempt": spent_id}})
        cases = {
            "array reservation_id": lambda d: d["attempts"][reserved_id].update(reservation_id=["inv-reservation-x"]),
            "object reservation_id": lambda d: d["attempts"][reserved_id].update(reservation_id={"id": "x"}),
            "array admission digest": lambda d: d["attempts"][reserved_id].update(admission_sha256=[admission("a")]),
            "array budget_id": lambda d: d["attempts"][reserved_id].update(budget_id=[BUDGET]),
            "object lineage parent": lambda d: d["attempts"].update({"inv-attempt-follower": follower}),
            "array sequence on a follower": lambda d: d["attempts"].update({"inv-attempt-follower": {
                **follower, "sequence": [3], "lineage": {"kind": "retry", "parent_attempt_id": spent_id}}}),
            "array history state": lambda d: d["attempts"][spent_id]["history"][1].update(
                state=["invocation-intent"]),
            "array current state": lambda d: d["attempts"][reserved_id].update(state=["reserved"]),
            "boolean charge": lambda d: d["attempts"][spent_id]["charge"].update(requests=True),
            "float charge": lambda d: d["attempts"][spent_id]["charge"].update(seconds=150.0),
            "charge as a list": lambda d: d["attempts"][spent_id].update(charge=[1, 1000, 500, 150]),
            "charge missing a dimension": lambda d: d["attempts"][spent_id]["charge"].pop("seconds"),
            "float version": lambda d: d.update(version=1.0),
            "boolean version": lambda d: d.update(version=True),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                document = json.loads(json.dumps(original))
                change(document)
                errors = self.mod.validate_ledger(document)
                self.assertIsInstance(errors, list)
                self.assertNotEqual(errors, [])
                self.write_document(document)
                effect = FakeEffect()
                self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect), "invalid")
                self.assert_refused(lambda: self.reserve("c"), "invalid")
                self.assert_refused(lambda: self.ledger.summary(BUDGET), "invalid")
                self.assertEqual(effect.calls, [])
        self.write_document(original)
        self.assertEqual(self.mod.validate_ledger(original), [])


class OneReservationOneInvocationTests(LedgerTestCase):
    def test_a_valid_reservation_invokes_once_with_the_exact_reserved_bytes(self) -> None:
        reservation = self.reserve()
        mutable = bytearray(REQUEST)
        effect = FakeEffect(during=lambda _bytes, _report: mutable.extend(b"tampered"))
        final = self.ledger.invoke(reservation["reservation_id"], mutable, effect)
        self.assertEqual(effect.calls, [REQUEST])
        self.assertIsInstance(effect.calls[0], bytes)
        self.assertEqual((final["state"], final["outcome"]), ("terminal", "completed"))
        self.assertEqual([entry["state"] for entry in final["history"]], ["reserved", "invocation-intent", "terminal"])
        self.assertEqual(self.charged(), AMOUNT)

    def test_racing_consumers_of_one_reservation_invoke_at_most_once(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect()
        contenders = 8
        barrier = threading.Barrier(contenders)
        outcomes: list[str] = []
        lock = threading.Lock()

        def contend() -> None:
            ledger = self.mod.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
            barrier.wait()
            try:
                ledger.invoke(reservation["reservation_id"], REQUEST, effect)
                result = "invoked"
            except self.mod.InvocationLedgerError as exc:
                result = "refused" if "already used" in str(exc) else f"error: {exc}"
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=contend) for _ in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["invoked"] + ["refused"] * (contenders - 1))
        self.assertEqual(len(effect.calls), 1)
        self.assertEqual(self.charged(), AMOUNT)


    def test_a_synchronous_callback_sees_persisted_intent_and_registered_observers(self) -> None:
        reservation = self.reserve()
        seen: list[dict[str, Any]] = []

        def observer(event: dict[str, Any]) -> None:
            on_disk = self.mod.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
            seen.append({"event": event["event"], "state": event["attempt"]["state"],
                         "observers": event["attempt"]["observers"],
                         "persisted": None if event["event"] == "terminal"
                         else on_disk.attempt(reservation["reservation_id"])["state"]})

        effect = FakeEffect(during=lambda _bytes, report: report("first-token", {"chars": 3}))
        self.ledger.invoke(reservation["reservation_id"], REQUEST, effect, observers=[observer])
        name = observer.__qualname__
        self.assertEqual(seen, [
            {"event": "invocation-intent", "state": "invocation-intent", "observers": [name], "persisted": "invocation-intent"},
            {"event": "first-token", "state": "invocation-intent", "observers": [name], "persisted": "invocation-intent"},
            {"event": "terminal", "state": "terminal", "observers": [name], "persisted": None},
        ])

    def test_an_observer_failure_before_the_effect_stops_it_and_stays_charged(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect()

        def failing(event: dict[str, Any]) -> None:
            raise RuntimeError("observer unavailable")

        with self.assertRaises(RuntimeError):
            self.ledger.invoke(reservation["reservation_id"], REQUEST, effect, observers=[failing])
        attempt = self.ledger.attempt(reservation["reservation_id"])
        self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "aborted-before-effect"))
        self.assertEqual(effect.calls, [])
        self.assertEqual(self.charged(), AMOUNT)

    def test_a_reentrant_mutation_from_inside_the_ledger_lock_is_refused(self) -> None:
        with self.ledger._locked():
            self.assert_refused(lambda: self.reserve("b"), "reentrant")


    def test_racing_reservations_never_exceed_the_aggregate(self) -> None:
        contenders = 12
        barrier = threading.Barrier(contenders)
        granted: list[str] = []
        refused: list[str] = []
        lock = threading.Lock()

        def contend(index: int) -> None:
            ledger = self.mod.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
            barrier.wait()
            try:
                ledger.reserve(budget_id=BUDGET, request_id=f"req-{index}", request_sha256="0" * 64,
                               admission_sha256=admission(f"race-{index}"), amount=AMOUNT,
                               expires_at=self.clock.now + 60)
                bucket = granted
            except self.mod.InvocationLedgerError as exc:
                self.assertIn("exhausted", str(exc))
                bucket = refused
            with lock:
                bucket.append(str(index))

        threads = [threading.Thread(target=contend, args=(index,)) for index in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((len(granted), len(refused)), (4, contenders - 4))
        self.assertEqual(self.charged(), {dimension: 4 * units for dimension, units in AMOUNT.items()})

    def test_racing_processes_never_exceed_the_aggregate(self) -> None:
        """Separate processes with real owner identities contend for one budget through the file lock."""
        script = (
            "import sys, hashlib\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from cwo_core.invocation_ledger import InvocationLedger, InvocationLedgerError\n"
            "ledger = InvocationLedger(sys.argv[2])\n"
            "index = sys.argv[3]\n"
            "try:\n"
            "    ledger.reserve(budget_id='epic-procs', request_id='req-' + index, request_sha256='0' * 64,\n"
            "                   admission_sha256=hashlib.sha256(index.encode()).hexdigest(),\n"
            "                   amount={'requests': 1}, expires_at=4102444800.0)\n"
            "    print('granted')\n"
            "except InvocationLedgerError as exc:\n"
            "    print('refused' if 'exhausted' in str(exc) else 'error ' + str(exc))\n"
            "sys.stdout.flush()\n"
            "sys.stdin.read()  # stay alive: a reservation whose owner exited before intent is released\n"
        )
        root = self.root.parent / "procs"
        self.mod.InvocationLedger(root).open_budget("epic-procs", {"requests": 3}, scope_sha256=SCOPE)
        processes = [
            subprocess.Popen([sys.executable, "-c", script, str(ROOT / "scripts"), str(root), str(index)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for index in range(8)
        ]
        results = sorted(process.stdout.readline().strip() for process in processes)
        for process in processes:
            process.communicate(timeout=120)
        self.assertEqual(results, ["granted"] * 3 + ["refused"] * 5)
        self.assertEqual(self.mod.InvocationLedger(root).summary("epic-procs")["charged"], {"requests": 3})


class ConservativeAccountingTests(LedgerTestCase):
    def outcome_of(self, effect: FakeEffect, expected: type[BaseException] | None) -> dict[str, Any]:
        reservation = self.reserve(str(len(self.ledger_document()["attempts"])))
        if expected is None:
            return self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
        with self.assertRaises(expected):
            self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
        return self.ledger.attempt(reservation["reservation_id"])

    def test_timeout_cancellation_and_unknown_failure_are_charged_in_full(self) -> None:
        cases = (
            ("timeout", self.mod.InvocationTimeout("admitted 150 s elapsed")),
            ("cancelled", self.mod.InvocationCancelled("operator cancelled")),
            ("unknown", ConnectionResetError("connection reset after send")),
        )
        for outcome, raised in cases:
            with self.subTest(outcome=outcome):
                effect = FakeEffect(raises=raised)
                attempt = self.outcome_of(effect, type(raised))
                self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]), ("terminal", outcome, AMOUNT))
                self.assertIsNone(attempt["observed_usage"])
                self.assertEqual(len(effect.calls), 1)
        summary = self.ledger.summary(BUDGET)
        self.assertEqual(summary["charged"], {dimension: 3 * units for dimension, units in AMOUNT.items()})
        self.assertEqual(summary["usage_unknown"], 3)

    def test_an_unrecognized_result_is_charged_in_full(self) -> None:
        attempt = self.outcome_of(FakeEffect(result={"status": "completed"}), self.mod.InvocationLedgerError)
        self.assertEqual((attempt["outcome"], attempt["charge"]), ("unknown", AMOUNT))

    def test_completion_without_usage_is_charged_in_full(self) -> None:
        attempt = self.outcome_of(FakeEffect(), None)
        self.assertEqual((attempt["outcome"], attempt["charge"], attempt["observed_usage"]), ("completed", AMOUNT, None))
        self.assertEqual(self.ledger.summary(BUDGET)["usage_unknown"], 1)


    def test_usage_outside_the_budget_dimensions_is_not_recorded_and_is_charged_in_full(self) -> None:
        for usage in ({"dollars": 3}, {"output_tokens": -1}, {"output_tokens": 1.5}, [1]):
            with self.subTest(usage=usage):
                effect = FakeEffect(result=self.mod.EffectResult("completed", usage))  # type: ignore[arg-type]
                attempt = self.outcome_of(effect, self.mod.InvocationLedgerError)
                self.assertEqual((attempt["state"], attempt["outcome"], attempt["observed_usage"], attempt["charge"]),
                                 ("terminal", "unknown", None, AMOUNT))

    def test_cancellation_releases_only_before_intent(self) -> None:
        reservation = self.reserve("a")
        released = self.ledger.release(reservation["reservation_id"])
        self.assertEqual((released["outcome"], released["charge"]), ("released", {d: 0 for d in LIMITS}))
        reservation = self.reserve("b")
        self.ledger.begin_invocation(reservation["reservation_id"], REQUEST)
        self.assert_refused(lambda: self.ledger.release(reservation["reservation_id"]), "stays charged")
        self.assertEqual(self.charged(), AMOUNT)

    def test_retries_fallbacks_successors_and_siblings_share_one_aggregate(self) -> None:
        parent = self.reserve("parent")
        with self.assertRaises(self.mod.InvocationTimeout):
            self.ledger.invoke(parent["reservation_id"], REQUEST, FakeEffect(raises=self.mod.InvocationTimeout()))
        totals = [self.charged()["requests"]]
        for kind in ("retry", "fallback", "successor"):
            child = self.reserve(kind, lineage={"kind": kind, "parent_attempt_id": parent["attempt_id"]})
            self.assertEqual(child["budget_id"], BUDGET)
            totals.append(self.charged()["requests"])
        self.assertEqual(totals, [1, 2, 3, 4])
        self.assert_refused(
            lambda: self.reserve("sibling", lineage={"kind": "sibling", "parent_attempt_id": parent["attempt_id"]}),
            "exhausted",
        )
        self.assertEqual(self.ledger.summary(BUDGET)["remaining"]["requests"], 0)

    def test_a_child_cannot_move_to_a_fresh_budget(self) -> None:
        parent = self.reserve("parent")
        self.ledger.release(parent["reservation_id"])
        self.ledger.open_budget("epic-fresh", LIMITS, scope_sha256=SCOPE)
        for kind in ("retry", "fallback", "successor", "sibling"):
            with self.subTest(kind=kind):
                self.assert_refused(
                    lambda: self.reserve(kind, budget="epic-fresh",
                                         lineage={"kind": kind, "parent_attempt_id": parent["attempt_id"]}),
                    "cannot move to a fresh budget",
                )
        self.assertEqual(self.ledger.summary("epic-fresh")["charged"], {d: 0 for d in LIMITS})


    def test_terminal_attempts_never_resume(self) -> None:
        reservation = self.reserve()
        self.ledger.invoke(reservation["reservation_id"], REQUEST, FakeEffect())
        for call in (
            lambda: self.ledger.begin_invocation(reservation["reservation_id"], REQUEST),
            lambda: self.ledger.finish(reservation["reservation_id"], "completed", reason="again"),
            lambda: self.ledger.mark_reconciliation_required(reservation["reservation_id"], reason="again"),
            lambda: self.ledger.release(reservation["reservation_id"]),
            lambda: self.ledger.reconcile(reservation["attempt_id"], reason="again"),
        ):
            self.assert_refused(call)
        self.assertEqual(self.charged(), AMOUNT)


    def test_lower_observed_usage_releases_nothing_and_higher_usage_is_charged(self) -> None:
        lower = {"requests": 1, "input_tokens": 10, "output_tokens": 20, "seconds": 2}
        attempt = self.outcome_of(FakeEffect(result=self.mod.EffectResult("completed", lower)), None)
        self.assertEqual((attempt["observed_usage"], attempt["charge"]), (lower, AMOUNT))
        higher = {"output_tokens": 1700}
        attempt = self.outcome_of(FakeEffect(result=self.mod.EffectResult("failed", higher)), None)
        self.assertEqual(attempt["charge"], {**AMOUNT, "output_tokens": 1700})
        self.assertEqual(self.charged()["output_tokens"], 2200)
        self.assertEqual(self.ledger.summary(BUDGET)["remaining"]["output_tokens"], -200)
        self.assert_refused(lambda: self.reserve("after-overrun"), "exhausted")

    def test_a_following_attempt_needs_a_terminal_parent(self) -> None:
        parent = self.reserve("parent")
        for kind in ("retry", "fallback", "successor"):
            with self.subTest(kind=kind):
                self.assert_refused(
                    lambda: self.reserve(kind, lineage={"kind": kind, "parent_attempt_id": parent["attempt_id"]}),
                    "needs a terminal parent",
                )
        sibling = self.reserve("sibling", lineage={"kind": "sibling", "parent_attempt_id": parent["attempt_id"]})
        self.assertEqual(sibling["state"], "reserved")


class CrashAmbiguityTests(LedgerTestCase):
    def test_a_crash_before_intent_releases_only_what_cannot_have_been_used(self) -> None:
        reservation = self.reserve()
        self.owners.crash()
        changes = self.ledger.recover(BUDGET)
        self.assertEqual(changes, [{"attempt_id": reservation["attempt_id"], "from": "reserved", "to": "terminal",
                                    "outcome": "released"}])
        self.assertEqual(self.charged(), {d: 0 for d in LIMITS})

    def test_a_crash_after_intent_requires_reconciliation_and_is_never_retried_silently(self) -> None:
        reservation = self.reserve("a")
        self.ledger.begin_invocation(reservation["reservation_id"], REQUEST)
        self.owners.crash()
        changes = self.ledger.recover()
        self.assertEqual([(c["from"], c["to"]) for c in changes], [("invocation-intent", "reconciliation-required")])
        summary = self.ledger.summary(BUDGET)
        self.assertEqual((summary["charged"], summary["reconciliation_required"]), (AMOUNT, [reservation["attempt_id"]]))
        effect = FakeEffect()
        self.assert_refused(lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect), "already used")
        self.assertEqual(effect.calls, [])
        lineage = {"kind": "retry", "parent_attempt_id": reservation["attempt_id"]}
        self.assert_refused(lambda: self.reserve("retry", lineage=lineage), "never retried silently")
        reconciled = self.ledger.reconcile(reservation["attempt_id"], reason="operator: provider has no request record")
        self.assertEqual((reconciled["outcome"], reconciled["charge"]), ("reconciled", AMOUNT))
        retry = self.reserve("retry", lineage=lineage)
        self.assertEqual(retry["state"], "reserved")
        self.assertEqual(self.charged(), {d: 2 * u for d, u in AMOUNT.items()})

    def test_reserving_sweeps_dead_owners_without_releasing_charged_intent(self) -> None:
        before_intent = self.reserve("a")
        after_intent = self.reserve("b")
        self.ledger.begin_invocation(after_intent["reservation_id"], REQUEST)
        for label in "cd":
            self.reserve(label)
        self.owners.crash()
        replacement = self.reserve("e")
        self.assertEqual(replacement["state"], "reserved")
        self.assertEqual(self.ledger.attempt(before_intent["reservation_id"])["outcome"], "released")
        self.assertEqual(self.ledger.attempt(after_intent["reservation_id"])["state"], "reconciliation-required")
        # c and d also belonged to the dead owner and are released; b stays charged.
        self.assertEqual(self.charged(), {d: 2 * u for d, u in AMOUNT.items()})


    def test_recovery_found_by_a_reserve_refused_for_its_parent_state_is_persisted(self) -> None:
        """A dead owner's released reservation and marked intent are kept when the reserve is refused later."""
        me = self.owners.me
        self.owners.me = {**me, "pid": 5000}  # another process, still alive, holds a reservation
        live = self.reserve("live")
        self.owners.me = me
        stale = self.reserve("stale")
        parent = self.reserve("parent")
        self.ledger.begin_invocation(parent["reservation_id"], REQUEST)
        self.owners.crash()
        # A retry of the live reservation is refused for its parent state, after the sweep has run.
        self.assert_refused(
            lambda: self.reserve("follow", lineage={"kind": "retry", "parent_attempt_id": live["attempt_id"]}),
            "needs a terminal parent",
        )
        stored = self.ledger_document()["attempts"]
        self.assertEqual((stored[stale["attempt_id"]]["state"], stored[stale["attempt_id"]]["outcome"]),
                         ("terminal", "released"))
        self.assertEqual(stored[parent["attempt_id"]]["state"], "reconciliation-required")
        self.assertEqual(stored[live["attempt_id"]]["state"], "reserved")
        self.ledger.reconcile(parent["attempt_id"], reason="operator: provider has no request record")

    def test_an_owner_of_unknown_status_is_left_alone(self) -> None:
        reservation = self.reserve("a")
        self.ledger.begin_invocation(reservation["reservation_id"], REQUEST)
        self.owners.unknown.add((self.owners.me["pid"], self.owners.me["start_ticks"]))
        self.owners.me = {**self.owners.me, "pid": 1}
        self.assertEqual(self.ledger.recover(), [])
        self.assertEqual(self.ledger.attempt(reservation["reservation_id"])["state"], "invocation-intent")

    def test_an_interrupt_during_the_effect_requires_reconciliation(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect(raises=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
        attempt = self.ledger.attempt(reservation["reservation_id"])
        self.assertEqual((attempt["state"], attempt["charge"]), ("reconciliation-required", AMOUNT))
        self.assertEqual(len(effect.calls), 1)

    def _crashing_child(self, root: Path, marker: Path, stage: str) -> subprocess.CompletedProcess[str]:
        script = (
            "import os, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from cwo_core.invocation_ledger import InvocationLedger\n"
            "ledger = InvocationLedger(sys.argv[2])\n"
            "stage, marker = sys.argv[3], sys.argv[4]\n"
            "request = b'exact prepared request'\n"
            "import hashlib\n"
            "reservation = ledger.reserve(budget_id='epic-crash', request_id='req-crash',\n"
            "    request_sha256=hashlib.sha256(request).hexdigest(), admission_sha256='c' * 64,\n"
            "    amount={'requests': 1, 'output_tokens': 500}, expires_at=4102444800.0)\n"
            "if stage == 'before-intent':\n"
            "    os._exit(9)\n"
            "def effect(sent, report):\n"
            "    with open(marker, 'ab') as handle:\n"
            "        handle.write(sent + b'\\n')\n"
            "    os._exit(9)\n"
            "ledger.invoke(reservation['reservation_id'], request, effect)\n"
        )
        return subprocess.run([sys.executable, "-c", script, str(ROOT / "scripts"), str(root), stage, str(marker)],
                              capture_output=True, text=True, timeout=120)

    def test_a_real_process_crash_around_the_effect(self) -> None:
        """A child process takes a reservation with its real owner identity and is killed by os._exit."""
        for stage, expected_state, expected_charge, effect_lines in (
            ("before-intent", "terminal", {"requests": 0, "output_tokens": 0}, 0),
            ("during-effect", "reconciliation-required", {"requests": 1, "output_tokens": 500}, 1),
        ):
            with self.subTest(stage=stage):
                root = self.root.parent / f"crash-{stage}"
                marker = self.root.parent / f"effect-{stage}.log"
                ledger = self.mod.InvocationLedger(root)
                ledger.open_budget("epic-crash", {"requests": 2, "output_tokens": 1000}, scope_sha256=SCOPE)
                completed = self._crashing_child(root, marker, stage)
                self.assertEqual(completed.returncode, 9, completed.stderr)
                ledger.recover()
                document = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
                (attempt,) = document["attempts"].values()
                self.assertEqual((attempt["state"], attempt["charge"]), (expected_state, expected_charge))
                lines = marker.read_bytes().splitlines() if marker.exists() else []
                self.assertEqual(lines, [b"exact prepared request"] * effect_lines)


    def test_recovery_found_by_a_refused_reserve_is_persisted(self) -> None:
        """A follower's reserve sweeps the dead parent and is refused; the recovery state survives the refusal."""
        parent = self.reserve("parent")
        self.ledger.begin_invocation(parent["reservation_id"], REQUEST)
        self.owners.crash()
        lineage = {"kind": "retry", "parent_attempt_id": parent["attempt_id"]}
        self.assert_refused(lambda: self.reserve("retry", lineage=lineage), "requires reconciliation",
                            "never retried silently")
        stored = self.ledger_document()["attempts"][parent["attempt_id"]]
        self.assertEqual((stored["state"], stored["charge"]), ("reconciliation-required", AMOUNT))
        fresh = self.mod.InvocationLedger(self.root, clock=self.clock, owner_probe=self.owners)
        self.assertEqual(fresh.summary(BUDGET)["reconciliation_required"], [parent["attempt_id"]])
        reconciled = fresh.reconcile(parent["attempt_id"], reason="operator: provider has no request record")
        self.assertEqual((reconciled["outcome"], reconciled["charge"]), ("reconciled", AMOUNT))
        retry = self.reserve("retry", lineage=lineage)
        self.assertEqual(retry["state"], "reserved")
        self.assertEqual(self.charged(), {d: 2 * u for d, u in AMOUNT.items()})


class InterruptionAfterIntentTests(LedgerTestCase):
    """Once intent is durable, any escape from the lifecycle leaves no attempt pending in invocation-intent."""

    limits = {dimension: 10 * units for dimension, units in LIMITS.items()}  # room for each case and its retry

    def assert_recovery_as_specified(self, reservation: dict[str, Any]) -> None:
        """The owner is still alive, so recovery changes nothing; reconciliation closes the attempt, still charged,
        and only then can a retry follow."""
        self.assertEqual(self.ledger.recover(), [])
        attempt = self.ledger.attempt(reservation["reservation_id"])
        self.assertEqual((attempt["state"], attempt["charge"]), ("reconciliation-required", AMOUNT))
        lineage = {"kind": "retry", "parent_attempt_id": reservation["attempt_id"]}
        self.assert_refused(lambda: self.reserve(f"retry-{reservation['request_id']}", lineage=lineage),
                            "never retried silently")
        reconciled = self.ledger.reconcile(reservation["attempt_id"], reason="operator: provider shows no request")
        self.assertEqual((reconciled["outcome"], reconciled["charge"]), ("reconciled", AMOUNT))
        self.assertEqual(self.reserve(f"retry-{reservation['request_id']}", lineage=lineage)["state"], "reserved")

    def interrupt_result_recording(self, interruption: BaseException, *, on_reservation: str | None = None) -> None:
        real_finish = self.ledger.finish

        def finish(reservation_id: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if on_reservation in (None, reservation_id):
                raise interruption
            return real_finish(reservation_id, *args, **kwargs)

        self.ledger.finish = finish  # type: ignore[method-assign]

    def test_an_interrupt_during_observer_notification_requires_reconciliation(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect()

        def interrupting(event: dict[str, Any]) -> None:
            if event["event"] == "invocation-intent":
                raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.ledger.invoke(reservation["reservation_id"], REQUEST, effect, observers=[interrupting])
        self.assertEqual(effect.calls, [])
        self.assert_recovery_as_specified(reservation)

    def test_an_interrupt_during_result_recording_requires_reconciliation(self) -> None:
        for name, interruption in (("keyboard interrupt", KeyboardInterrupt()), ("system exit", SystemExit(3)),
                                   ("storage error", OSError("disk full while recording the result"))):
            with self.subTest(case=name):
                reservation = self.reserve(name.replace(" ", "-"))
                effect = FakeEffect(result=self.mod.EffectResult("completed", {"output_tokens": 10}))
                self.interrupt_result_recording(interruption, on_reservation=reservation["reservation_id"])
                with self.assertRaises(type(interruption)):
                    self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
                del self.ledger.finish
                self.assertEqual(effect.calls, [REQUEST])
                self.assert_recovery_as_specified(reservation)

    def test_an_interrupt_after_one_of_several_effects_keeps_terminal_records(self) -> None:
        reservations = [self.reserve(label) for label in ("first", "second", "third")]
        effect = FakeEffect(result=self.mod.EffectResult("completed", {"output_tokens": 10}))
        self.interrupt_result_recording(KeyboardInterrupt(), on_reservation=reservations[1]["reservation_id"])
        with self.assertRaises(KeyboardInterrupt):
            for reservation in reservations:
                self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
        del self.ledger.finish
        self.assertEqual(effect.calls, [REQUEST, REQUEST])
        first = self.ledger.attempt(reservations[0]["reservation_id"])
        self.assertEqual((first["state"], first["outcome"], first["observed_usage"]),
                         ("terminal", "completed", {"output_tokens": 10}))
        self.assertEqual(self.ledger.attempt(reservations[2]["reservation_id"])["state"], "reserved")
        self.assert_recovery_as_specified(reservations[1])
        self.assertEqual(self.ledger.attempt(reservations[0]["reservation_id"]), first)
        released = self.ledger.release(reservations[2]["reservation_id"])
        self.assertEqual(released["charge"], {dimension: 0 for dimension in LIMITS})

    def test_an_interrupt_after_the_result_is_recorded_keeps_the_terminal_record(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect(result=self.mod.EffectResult("completed", {"output_tokens": 10}))

        def interrupting(event: dict[str, Any]) -> None:
            if event["event"] == "terminal":
                raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.ledger.invoke(reservation["reservation_id"], REQUEST, effect, observers=[interrupting])
        attempt = self.ledger.attempt(reservation["reservation_id"])
        self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]), ("terminal", "completed", AMOUNT))
        self.assertEqual(len(effect.calls), 1)
        self.assertEqual(self.ledger.recover(), [])

    def test_an_interrupt_after_intent_is_written_but_before_it_returns_requires_reconciliation(self) -> None:
        reservation = self.reserve()
        effect = FakeEffect()
        real_save = self.ledger._save

        def save(root: Path, document: dict[str, Any]) -> None:
            real_save(root, document)
            if document["attempts"][reservation["attempt_id"]]["state"] == "invocation-intent":
                raise KeyboardInterrupt()

        self.ledger._save = save  # type: ignore[method-assign]
        with self.assertRaises(KeyboardInterrupt):
            self.ledger.invoke(reservation["reservation_id"], REQUEST, effect)
        del self.ledger._save
        self.assertEqual(effect.calls, [])
        self.assert_recovery_as_specified(reservation)


class DurableProvisioningTests(unittest.TestCase):
    """Directories the ledger may have created are made durable (each parent fsynced) before any effect."""

    def setUp(self) -> None:
        self.mod = ledger_module()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.events: list[tuple[str, Any]] = []

    def record_fsync(self, descriptor: int) -> None:
        info = os.fstat(descriptor)
        self.events.append(("fsync", (info.st_dev, info.st_ino)))
        os.fsync(descriptor)

    @staticmethod
    def identity(path: Path) -> tuple[int, int]:
        info = os.stat(path)
        return (info.st_dev, info.st_ino)

    def run_first_use(self, root: Path) -> None:
        clock, owners = FakeClock(), FakeOwners()
        ledger = self.mod.InvocationLedger(root, clock=clock, owner_probe=owners, fsync=self.record_fsync)
        ledger.open_budget(BUDGET, LIMITS, scope_sha256=SCOPE)
        reservation = ledger.reserve(budget_id=BUDGET, request_id="req-a", request_sha256=hashlib.sha256(REQUEST).hexdigest(),
                                     admission_sha256=admission("a"), amount=dict(AMOUNT), expires_at=clock.now + 60)

        def effect(request_bytes: bytes, report: Any) -> Any:
            self.events.append(("effect", None))
            return self.mod.EffectResult("completed")

        ledger.invoke(reservation["reservation_id"], REQUEST, effect)

    def assert_parents_fsynced_in_order_before_the_effect(self, parents: list[Path]) -> None:
        effect_at = self.events.index(("effect", None))
        expected = [("fsync", self.identity(parent)) for parent in parents]
        before = self.events[:effect_at]
        positions = []
        for wanted in expected:
            start = positions[-1] + 1 if positions else 0
            self.assertIn(wanted, before[start:], f"no fsync of {wanted} in order before the first effect")
            positions.append(before.index(wanted, start))

    def test_newly_created_directories_have_their_parents_fsynced_before_the_first_effect(self) -> None:
        root = self.base / "audit" / "nested" / "ledger"
        self.run_first_use(root)
        self.assert_parents_fsynced_in_order_before_the_effect(
            [self.base, self.base / "audit", self.base / "audit" / "nested"])
        self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)

    def test_directories_left_by_an_interrupted_first_use_are_still_made_durable(self) -> None:
        """A process killed after mkdir and before the parent fsync leaves the directories in place."""
        root = self.base / "audit" / "ledger"
        os.makedirs(root, mode=0o700)
        self.run_first_use(root)
        self.assert_parents_fsynced_in_order_before_the_effect([self.base, self.base / "audit"])


class SchemaAndContainmentTests(unittest.TestCase):
    def test_the_schema_matches_the_runtime_record(self) -> None:
        mod = ledger_module()
        schema = json.loads((ROOT / "schemas" / "invocation-ledger.schema.json").read_text(encoding="utf-8"))
        attempt = schema["$defs"]["attempt"]
        self.assertEqual(schema["required"], list(mod.LEDGER_FIELDS))
        self.assertEqual(schema["properties"]["version"], {"const": mod.LEDGER_VERSION})
        self.assertEqual(schema["$defs"]["budget"]["required"], list(mod.BUDGET_FIELDS))
        self.assertEqual(attempt["required"], list(mod.ATTEMPT_FIELDS))
        self.assertEqual(attempt["properties"]["state"]["enum"], list(mod.STATES))
        self.assertEqual(attempt["properties"]["outcome"]["anyOf"][0]["enum"], list(mod.OUTCOMES))
        self.assertEqual(attempt["properties"]["lineage"]["properties"]["kind"]["enum"], list(mod.LINEAGE_KINDS))
        self.assertEqual(attempt["properties"]["owner"]["required"], list(mod.OWNER_FIELDS))

    @staticmethod
    def importers_of(module: str) -> list[str]:
        found = []
        for path in sorted((ROOT / "scripts").rglob("*.py")):
            if path.stem == module:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = []
                if isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] + [alias.name for alias in node.names]
                elif isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                if any(name.rsplit(".", 1)[-1] == module for name in names):
                    found.append(path.relative_to(ROOT).as_posix())
        return sorted(set(found))

    def test_local_invocation_stays_unavailable_and_ledger_importers_are_explicit(self) -> None:
        """The disabled production route and offline adapter have an explicit ledger importer inventory.
        Any additional importer requires a deliberate change to this reliability check."""
        import dispatch_work

        self.assertIs(dispatch_work.LOCAL_INVOCATION_AVAILABLE, False)
        self.assertEqual(self.importers_of("invocation_ledger"), [
            "scripts/cwo_core/local_invocation.py",
            # Experimental fake host reads persisted admission; production stays disabled.
            "scripts/offline_admitted_n1.py",
            "scripts/prepare_local_admission.py",
            "scripts/qualified_review_dispatch.py",
        ])
        self.assertEqual(self.importers_of("local_invocation"), [
            "scripts/dispatch_work.py", "scripts/qualified_review_dispatch.py",
        ])


class StateMachineAndOverflowTests(LedgerTestCase):
    """One transition table, fail-closed validation of unknown states, oversized numbers and caller types."""


    def test_an_unknown_stored_state_or_transition_refuses_every_operation_with_zero_effects(self) -> None:
        reservation = self.reserve("a")
        cases = {
            "unknown current state": lambda a: (a.update(state="paused"), a["history"][-1].update(state="paused")),
            "unknown history state": lambda a: a["history"].insert(0, dict(a["history"][0], state="prepared")),
            "skipped transition": lambda a: (a.update(state="terminal", outcome="completed"),
                                             a["history"].append({"state": "terminal", "outcome": "completed",
                                                                  "at": a["created_at"], "reason": "forged"})),
        }
        original = self.ledger_document()
        for label, mutate in cases.items():
            with self.subTest(label):
                document = json.loads(json.dumps(original))
                mutate(document["attempts"][reservation["attempt_id"]])
                self.write_document(document)
                self.assertTrue(self.mod.validate_ledger(document))
                effect = FakeEffect()
                for call in (lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect),
                             lambda: self.reserve("b"), lambda: self.ledger.summary(BUDGET)):
                    self.assert_refused(call, "invalid")
                self.assertEqual(effect.calls, [])
        self.write_document(original)

    def test_oversized_integer_timestamps_are_validation_diagnostics_not_overflow(self) -> None:
        """10**1000 in a stored or caller time is refused with a diagnostic."""
        reservation = self.reserve("a")
        original = self.ledger_document()
        huge = 10**1000
        cases = {
            "budget created_at": lambda d: d["budgets"][BUDGET].update(created_at=huge),
            "attempt created_at": lambda d: d["attempts"][reservation["attempt_id"]].update(created_at=huge),
            "attempt expires_at": lambda d: d["attempts"][reservation["attempt_id"]].update(expires_at=huge),
            "history at": lambda d: d["attempts"][reservation["attempt_id"]]["history"][0].update(at=huge),
            "float infinity": lambda d: d["attempts"][reservation["attempt_id"]].update(expires_at=float("inf")),
        }
        for label, mutate in cases.items():
            with self.subTest(stored=label):
                document = json.loads(json.dumps(original))
                mutate(document)
                errors = self.mod.validate_ledger(document)  # must not raise OverflowError
                self.assertTrue(errors)
                (self.root / "ledger.json").write_text(json.dumps(document).replace("Infinity", "1e999"),
                                                       encoding="utf-8")
                effect = FakeEffect()
                for call in (lambda: self.ledger.invoke(reservation["reservation_id"], REQUEST, effect),
                             lambda: self.reserve("b"), lambda: self.ledger.summary(BUDGET)):
                    self.assert_refused(call, "invalid")
                self.assertEqual(effect.calls, [])
        with self.subTest(stored="integer longer than the interpreter converts"):
            text = json.dumps(original).replace(f'"sequence": {reservation["sequence"]}', '"sequence": ' + "9" * 5000)
            self.assertIn("9" * 5000, text)
            (self.root / "ledger.json").write_text(text, encoding="utf-8")
            self.assert_refused(lambda: self.ledger.summary(BUDGET), "not valid JSON")
        self.write_document(original)
        for value in (huge, -huge, float("inf"), float("nan"), 2.0**80):
            with self.subTest(caller_expires_at=value):
                self.assert_refused(lambda: self.ledger.reserve(
                    budget_id=BUDGET, request_id="req-c", request_sha256=hashlib.sha256(REQUEST).hexdigest(),
                    admission_sha256=admission("c"), amount=dict(AMOUNT), expires_at=value), "expires_at")
        for value in (huge, float("inf"), float("nan"), -1, "now", None):
            with self.subTest(clock=value):
                ledger = self.mod.InvocationLedger(self.root, clock=lambda: value, owner_probe=self.owners)
                self.assert_refused(lambda: ledger.reserve(
                    budget_id=BUDGET, request_id="req-d", request_sha256=hashlib.sha256(REQUEST).hexdigest(),
                    admission_sha256=admission("d"), amount=dict(AMOUNT), expires_at=2_000_000.0), "clock")
                self.assert_refused(ledger.current_time, "clock")
        self.assertEqual(self.ledger_document(), original)


    def _clock_hook(self, hook: Any, on_call: int) -> None:
        calls = {"n": 0}
        base = self.clock

        def clock() -> float:
            calls["n"] += 1
            if calls["n"] == on_call:
                hook()
            return base()

        self.ledger.clock = clock

    def test_a_write_outside_the_lock_during_an_operation_is_refused_and_not_overwritten(self) -> None:
        self.reserve("a")
        foreign = json.loads((self.root / "ledger.json").read_text(encoding="utf-8"))
        foreign["budgets"][BUDGET]["created_at"] += 1  # a valid, different document written without the lock
        foreign_text = json.dumps(foreign)
        self._clock_hook(lambda: (self.root / "ledger.json").write_text(foreign_text, encoding="utf-8"), 1)
        self.assert_refused(lambda: self.reserve("b"), "changed outside the lock", "concurrent update")
        self.assertEqual((self.root / "ledger.json").read_text(encoding="utf-8"), foreign_text)
        self.ledger.clock = self.clock
        self.assertEqual(self.ledger.summary(BUDGET)["attempts_by_state"]["reserved"], 1)

    def test_a_replaced_lock_file_during_an_operation_is_refused(self) -> None:
        self.reserve("a")
        before = (self.root / "ledger.json").read_bytes()

        def replace_lock() -> None:
            (self.root / "ledger.lock").unlink()
            (self.root / "ledger.lock").write_text("", encoding="utf-8")

        self._clock_hook(replace_lock, 1)
        self.assert_refused(lambda: self.reserve("b"), "lock file was replaced", "concurrent update")
        self.assertEqual((self.root / "ledger.json").read_bytes(), before)

    def test_overflow_amounts_limits_and_usage_are_refused(self) -> None:
        before = self.ledger_document()
        for amount in ({**AMOUNT, "requests": 2**53}, {**AMOUNT, "requests": 10**1000}):
            with self.subTest(amount=amount["requests"]):
                self.assert_refused(lambda: self.reserve("x", amount=amount), "amount")
        for limits in ({"requests": 10**1000}, {"requests": 2**53}, {"requests": float("inf")}):
            with self.subTest(limits=limits):
                self.assert_refused(lambda: self.ledger.open_budget("other", limits, scope_sha256=SCOPE), "limits")
        self.assertEqual(self.ledger_document(), before)
        effect = FakeEffect(result=self.mod.EffectResult("completed", {"requests": 10**1000}))
        self.assert_refused(lambda: self.reserve_then_invoke("big", effect), "usage was refused")
        self.assertEqual(len(effect.calls), 1)
        self.assertEqual(self.charged(), AMOUNT)

    def test_non_mapping_lineage_is_refused_before_conversion(self) -> None:
        """A number, a string or a list raises InvocationLedgerError, not TypeError or ValueError."""
        before = self.ledger_document()
        for lineage in (3, "retry", ["kind", "retry"], b"retry", 2.5, True, object()):
            with self.subTest(lineage=repr(lineage)):
                with self.assertRaises(self.mod.InvocationLedgerError) as raised:
                    self.reserve("x", lineage=lineage)
                self.assertIn("lineage must be a mapping", str(raised.exception))
        self.assertEqual(self.ledger_document(), before)

    def test_the_transition_table_is_the_single_authority_and_unknown_states_are_refused(self) -> None:
        table = self.mod._ALLOWED_TRANSITIONS
        self.assertEqual(set(table), set(self.mod.STATES))
        for state in self.mod.STATES:
            for next_state in self.mod.STATES:
                for outcome in (None, *self.mod.OUTCOMES):
                    with self.subTest(state=state, next_state=next_state, outcome=outcome):
                        permitted = next_state in table[state] and (
                            outcome in table[state][next_state] if next_state == "terminal" else outcome is None)
                        self.assertEqual(self.mod.transition_error(state, next_state, outcome) is None, permitted)
        for bad in ("prepared", "bogus", None, ["reserved"], {"state": "reserved"}, 3):
            with self.subTest(unknown=bad):
                self.assertIsNotNone(self.mod.transition_error(bad, "terminal", "released"))
                self.assertIsNotNone(self.mod.transition_error("reserved", bad, None))
        attempt = self.reserve()
        stored = self.ledger_document()["attempts"][attempt["attempt_id"]]
        stored["state"] = "paused"
        self.assert_refused(lambda: self.mod.InvocationLedger._transition(stored, "terminal", "released", 1.0, "x"),
                            "not a ledger state")


class UnresolvedOutcomeTests(LedgerTestCase):
    """With ``refuse_while_unresolved`` an unknown outcome counts as consumed and blocks a blind retry."""

    limits = {dimension: 10 * units for dimension, units in LIMITS.items()}

    def guarded(self, label: str, request_id: str | None = None) -> dict[str, Any]:
        return self.ledger.reserve(
            budget_id=BUDGET, request_id=request_id or f"req-{label}", request_sha256=hashlib.sha256(REQUEST).hexdigest(),
            admission_sha256=admission(label), amount=dict(AMOUNT), expires_at=self.clock.now + 300,
            refuse_while_unresolved=True,
        )

    def test_a_crash_after_intent_blocks_every_new_reservation_in_the_budget_until_reconciled(self) -> None:
        crashed = self.reserve("a")
        self.ledger.begin_invocation(crashed["reservation_id"], REQUEST)
        self.owners.crash()
        before = self.charged()
        self.assert_refused(lambda: self.guarded("b"), "requires reconciliation", "blocks a blind retry")
        self.assertEqual(self.ledger.attempt(crashed["reservation_id"])["state"], "reconciliation-required")
        self.assertEqual(self.charged(), before)
        unguarded = self.reserve("c")  # A sibling may still reserve under the default policy.
        self.ledger.release(unguarded["reservation_id"])
        self.ledger.reconcile(crashed["attempt_id"], reason="operator: provider has no request record")
        self.assertEqual(self.guarded("d")["state"], "reserved")
        self.assertEqual(self.ledger.attempt(crashed["reservation_id"])["charge"], AMOUNT)

    def test_intent_under_an_owner_of_unknown_status_blocks_new_reservations(self) -> None:
        pending = self.reserve("a")
        self.ledger.begin_invocation(pending["reservation_id"], REQUEST)
        self.owners.unknown.add((self.owners.me["pid"], self.owners.me["start_ticks"]))
        self.owners.me = {**self.owners.me, "pid": 1}
        self.assert_refused(lambda: self.guarded("b"), "owner whose status is unknown", "blocks a blind retry")

    def test_one_request_is_never_reserved_again_unless_it_was_released(self) -> None:
        first = self.guarded("first", request_id="req-same")
        self.assert_refused(lambda: self.guarded("second", request_id="req-same"), "already has attempt")
        self.ledger.release(first["reservation_id"])
        released_retry = self.guarded("third", request_id="req-same")
        self.ledger.invoke(released_retry["reservation_id"], REQUEST, FakeEffect())
        self.assert_refused(lambda: self.guarded("fourth", request_id="req-same"), "already has attempt",
                            "never retried blindly")


class InvocationContextTests(LedgerTestCase):
    """``invocation()`` runs an inline effect under the same lifecycle as ``invoke``."""

    limits = {dimension: 10 * units for dimension, units in LIMITS.items()}

    def test_each_way_out_of_the_body_records_its_outcome(self) -> None:
        cases = (
            (None, "terminal", "completed"),
            (self.mod.InvocationTimeout("slow"), "terminal", "timeout"),
            (self.mod.InvocationCancelled("stop"), "terminal", "cancelled"),
            (RuntimeError("boom"), "terminal", "unknown"),
            (KeyboardInterrupt(), "reconciliation-required", None),
            (SystemExit("stopped"), "reconciliation-required", None),
        )
        for index, (raised, state, outcome) in enumerate(cases):
            with self.subTest(raised=type(raised).__name__):
                reservation = self.reserve(f"case-{index}")
                ran = []
                try:
                    with self.ledger.invocation(reservation["reservation_id"], REQUEST) as handle:
                        ran.append(handle.request_bytes)
                        if raised is not None:
                            raise raised
                except BaseException as exc:  # noqa: BLE001 - each case re-raises its own exception
                    self.assertIs(exc, raised)
                attempt = self.ledger.attempt(reservation["reservation_id"])
                self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]), (state, outcome, AMOUNT))
                self.assertEqual(ran, [REQUEST])

    def test_a_synchronous_observer_sees_persisted_intent_before_the_body_runs(self) -> None:
        reservation = self.reserve("a")
        seen: list[tuple[str, str]] = []

        def observer(event: dict[str, Any]) -> None:
            stored = self.ledger_document()["attempts"][event["attempt"]["attempt_id"]]
            seen.append((event["event"], stored["state"]))

        with self.ledger.invocation(reservation["reservation_id"], REQUEST, observers=[observer]) as handle:
            seen.append(("body", self.ledger_document()["attempts"][reservation["attempt_id"]]["state"]))
            handle.report("request", {"kind": "post"})
            handle.record("completed", {"requests": 1})
        self.assertEqual(seen, [("invocation-intent", "invocation-intent"), ("body", "invocation-intent"),
                                ("request", "invocation-intent"), ("terminal", "terminal")])
        self.assertEqual(self.ledger.attempt(reservation["reservation_id"])["observers"], [observer.__qualname__])

    def test_the_body_never_runs_for_a_refused_intent_and_a_bad_record_is_charged_in_full(self) -> None:
        stale = self.reserve("stale", ttl=1)
        self.clock.now += 5
        ran = []
        with self.assertRaises(self.mod.InvocationLedgerError):
            with self.ledger.invocation(stale["reservation_id"], REQUEST):
                ran.append(True)
        self.assertEqual(ran, [])
        bad = self.reserve("bad")
        with self.assertRaises(self.mod.InvocationLedgerError):
            with self.ledger.invocation(bad["reservation_id"], REQUEST) as handle:
                handle.record("partly")
        attempt = self.ledger.attempt(bad["reservation_id"])
        self.assertEqual((attempt["outcome"], attempt["charge"]), ("unknown", AMOUNT))


if __name__ == "__main__":
    unittest.main()
