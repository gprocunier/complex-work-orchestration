"""Offline witnesses for terminal cyber-policy refusal handling."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cwo_core.cyber_fallback import (
    CyberFallbackController,
    CyberFallbackError,
    SecurityMarkStore,
)
from cwo_core.invocation_ledger import EffectResult, InvocationLedger


PACKET = b'{"packet_id":"EXAMPLE-security-work","task":"EXAMPLE authorized review"}'
CYBER_MODEL = "gpt-6-sol"
AMOUNT = {"requests": 1, "tokens": 100, "seconds": 10}
LIMITS = {key: value * 3 for key, value in AMOUNT.items()}
ZERO_USAGE = dict.fromkeys(AMOUNT, 0)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class FakeOwners:
    def __init__(self) -> None:
        self.owner = {"pid": 4242, "start_ticks": 7, "boot_id_sha256": "b" * 64}

    def current(self) -> dict:
        return dict(self.owner)

    def status(self, _owner: dict) -> str:
        return "alive"


class FakeDispatch:
    def __init__(self, *results: dict) -> None:
        self.results = list(results)
        self.calls: list[dict] = []

    def __call__(self, request: dict) -> dict:
        self.calls.append(request)
        return self.results.pop(0)


class CyberFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cwo-cyber-fallback-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clock = FakeClock()
        self.ledger = InvocationLedger(self.root / "ledger", clock=self.clock, owner_probe=FakeOwners())
        self.budget_id = "EXAMPLE-security-budget"
        self.ledger.open_budget(
            self.budget_id,
            LIMITS,
            scope_sha256=hashlib.sha256(b"EXAMPLE security budget").hexdigest(),
        )
        reservation = self.ledger.reserve(
            budget_id=self.budget_id,
            request_id="EXAMPLE-security-work",
            request_sha256=hashlib.sha256(PACKET).hexdigest(),
            admission_sha256=hashlib.sha256(b"EXAMPLE primary admission").hexdigest(),
            amount=AMOUNT,
            expires_at=self.clock.now + 60,
        )
        self.original = self.ledger.invoke(
            reservation["reservation_id"],
            PACKET,
            lambda _packet, _report: EffectResult("failed", ZERO_USAGE),
        )
        self.refusal = {
            "summary": {
                "terminal_blockers": {"provider-safety-policy-refusal": "cyberPolicy"},
            }
        }
        self.ordinary_failure = {"summary": {"terminal_blockers": {}}}
        self.available = {
            "role": "cyber_fallback",
            "model": CYBER_MODEL,
            "required_access_program": "daybreakBlue",
            "codex_config": {"daybreak": True},
            "status": "available",
            "reason": "required-access-program-advertised",
        }
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.records: list[dict] = []

    def mark_store(
        self,
        *,
        source: str = "user",
        path: Path | None = None,
        scope: str = "work-item",
        mark_id: str = "EXAMPLE-security-work",
    ) -> SecurityMarkStore:
        mark_path = path or self.root / f"mark-{source}.json"
        value = {
            "version": 1,
            "marks": [{
                "scope": scope,
                "id": mark_id,
                "source": source,
                "marked_by": "EXAMPLE operator",
                "marked_at": "2026-11-23T09:00:00-05:00",
            }],
        }
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        mark_path.write_bytes(raw)
        os.chmod(mark_path, 0o600)
        return SecurityMarkStore(
            mark_path,
            hashlib.sha256(raw).hexdigest(),
            prohibited_write_roots=(self.workspace,),
        )

    def controller(self, store: SecurityMarkStore) -> CyberFallbackController:
        return CyberFallbackController(self.ledger, store, self.records.append, clock=self.clock)

    def recover(self, controller: CyberFallbackController, dispatch: FakeDispatch, *, mark=..., refusal=None,
                role=None) -> dict:
        if mark is ...:
            mark = controller.mark_store.issue(work_item_id="EXAMPLE-security-work")
        return controller.recover(
            packet=PACKET,
            work_item_id="EXAMPLE-security-work",
            project_id="EXAMPLE-project",
            original_attempt=self.original,
            original_result=self.refusal if refusal is None else refusal,
            original_dispatch={
                "model": "gpt-6.2-sol",
                "effort": "xhigh",
                "service_tier": "default",
            },
            fallback_role=self.available if role is None else role,
            mark=mark,
            dispatch=dispatch,
        )

    def test_structured_cyber_refusal_never_reserves_invokes_or_dispatches(self) -> None:
        store = self.mark_store()
        controller = self.controller(store)
        dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})
        original_summary = self.ledger.summary(self.budget_id)

        with (
            patch.object(self.ledger, "reserve", wraps=self.ledger.reserve) as reserve,
            patch.object(self.ledger, "invoke", wraps=self.ledger.invoke) as invoke,
        ):
            result = self.recover(controller, dispatch)

        self.assertEqual(dispatch.calls, [])
        reserve.assert_not_called()
        invoke.assert_not_called()
        self.assertEqual(self.ledger.summary(self.budget_id), original_summary)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["original_attempt"], self.original)
        self.assertNotIn("fallback_attempt", result)
        self.assertEqual(result["blocker"], {"classification": "cyberPolicy", "cause": "provider-safety-policy-refusal"})
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0], {
            "record_type": "cwo-cyber-fallback",
            "version": 1,
            "event": "blocker",
            "reason": "cyber_refusal",
            "parent_attempt_id": self.original["attempt_id"],
            "packet_sha256": self.original["request_sha256"],
            "blocker": result["blocker"],
        })

    def test_ordinary_failures_are_unchanged_by_refusal_audit(self) -> None:
        dispatch = FakeDispatch()
        controller = self.controller(self.mark_store())
        for refusal in (
            {"summary": {"terminal_blockers": {"provider-safety-policy-refusal": "misalignmentPolicyViolation"}}},
            {"summary": {"terminal_blockers": {"provider-safety-policy-refusal": "otherPolicy"}}},
            {"summary": {"terminal_blockers": {"provider-safety-policy-refusal": ["cyberPolicy"]}}},
            {"summary": {"error": "cyberPolicy"}},
            self.ordinary_failure,
        ):
            with self.subTest(refusal=refusal):
                result = self.recover(controller, dispatch, refusal=refusal)
                self.assertEqual(result["status"], "unchanged")
        self.assertEqual(dispatch.calls, [])
        self.assertEqual(self.records, [])

    def test_missing_or_forged_legacy_inputs_cannot_change_the_terminal_blocker(self) -> None:
        controller = self.controller(self.mark_store())
        dispatch = FakeDispatch()
        for mark, role in (
            (None, self.available),
            ({"source": "user"}, self.available),
            (..., {**self.available, "status": "unavailable"}),
        ):
            with self.subTest(mark=mark, role=role):
                result = self.recover(controller, dispatch, mark=mark, role=role)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["blocker"]["cause"], "provider-safety-policy-refusal")
        self.assertEqual(dispatch.calls, [])

    def test_worker_lead_forged_and_overlapping_marks_are_rejected(self) -> None:
        for source in ("worker", "lead"):
            with self.subTest(source=source), self.assertRaisesRegex(CyberFallbackError, "user action"):
                self.mark_store(source=source).issue(work_item_id="EXAMPLE-security-work")

        with self.assertRaisesRegex(CyberFallbackError, "outside worker and lead write roots"):
            self.mark_store(path=self.workspace / "mark.json")

        store = self.mark_store(path=self.root / "mark-forged.json")
        with self.assertRaisesRegex(CyberFallbackError, "verified user mark"):
            store.verify({"source": "user"}, work_item_id="EXAMPLE-security-work", project_id=None)

    def test_refusal_audit_requires_the_original_charged_packet(self) -> None:
        controller = self.controller(self.mark_store())
        with self.assertRaisesRegex(CyberFallbackError, "exact packet"):
            controller.recover(
                packet=b"EXAMPLE different packet",
                work_item_id="EXAMPLE-security-work",
                project_id=None,
                original_attempt=self.original,
                original_result=self.refusal,
                original_dispatch={},
                fallback_role={},
                mark=None,
                dispatch=FakeDispatch(),
            )
        self.assertEqual(self.records, [])


if __name__ == "__main__":
    unittest.main()
