"""Fake-only automatic fallback for explicitly marked security work."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from cwo_core.cyber_fallback import (
    CyberFallbackController,
    CyberFallbackError,
    SecurityMarkStore,
)
from cwo_core.invocation_ledger import EffectResult, InvocationLedger
from cwo_core.model_identities import cyber_fallback_availability
from cwo_core.policy import load_policy


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
        self.role_config = load_policy("model-roles")
        self.role_config["roles"]["cyber_fallback"] = {
            "model": CYBER_MODEL,
            "required_access_program": "daybreakBlue",
            "codex_config": {"daybreak": True},
        }
        self.available = cyber_fallback_availability(
            config=self.role_config,
            catalog={
                "data": [{
                    "id": CYBER_MODEL,
                    "model": CYBER_MODEL,
                    "hidden": False,
                    "availableAccessPrograms": {"cyber": ["daybreakBlue"]},
                }],
                "nextCursor": None,
            },
        )
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

    def test_marked_refusal_dispatches_one_linked_unchanged_fallback(self) -> None:
        store = self.mark_store()
        controller = self.controller(store)
        dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})

        result = self.recover(controller, dispatch)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(dispatch.calls), 1)
        request = dispatch.calls[0]
        self.assertIs(request["packet"], PACKET)
        self.assertEqual(request["packet_sha256"], self.original["request_sha256"])
        self.assertEqual(request["reason"], "cyber_refusal")
        self.assertEqual(request["classification"], "cyberPolicy")
        self.assertEqual(request["role"], "cyber_fallback")
        self.assertEqual(request["model"], CYBER_MODEL)
        self.assertEqual(request["codex_config"], {"daybreak": True})
        self.assertEqual((request["effort"], request["service_tier"]), ("xhigh", "default"))
        self.assertEqual(request["parent_attempt_id"], self.original["attempt_id"])
        self.assertEqual(request["mark"]["marked_by"], "EXAMPLE operator")
        self.assertEqual(request["mark"]["marked_at"], "2026-11-23T09:00:00-05:00")
        fallback = result["fallback_attempt"]
        self.assertEqual(
            fallback["lineage"],
            {"kind": "fallback", "parent_attempt_id": self.original["attempt_id"]},
        )
        self.assertEqual(
            self.ledger.summary(self.budget_id)["charged"],
            {key: value * 2 for key, value in AMOUNT.items()},
        )
        self.assertEqual([row["event"] for row in self.records], ["invocation-intent", "terminal"])
        self.assertTrue(all(row["reason"] == "cyber_refusal" for row in self.records))
        self.assertTrue(all(row["mark"]["marked_by"] == "EXAMPLE operator" for row in self.records))

    def test_configured_model_drives_the_fallback_request(self) -> None:
        self.role_config["roles"]["cyber_fallback"]["model"] = "gpt-7-sol"
        self.role_config["roles"]["cyber_fallback"]["previous"] = CYBER_MODEL
        role = cyber_fallback_availability(
            config=self.role_config,
            catalog={
                "data": [{
                    "id": "gpt-7-sol",
                    "model": "gpt-7-sol",
                    "hidden": False,
                    "availableAccessPrograms": {"cyber": ["daybreakBlue"]},
                }],
                "nextCursor": None,
            },
        )
        dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})

        result = self.recover(self.controller(self.mark_store()), dispatch, role=role)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(dispatch.calls[0]["model"], "gpt-7-sol")
        self.assertEqual(dispatch.calls[0]["codex_config"], {"daybreak": True})

    def test_fallback_caps_effort_and_forces_standard_tier(self) -> None:
        for original_effort, expected in (("max", "xhigh"), ("ultra", "xhigh"), ("xhigh", "xhigh"), ("high", "high")):
            with self.subTest(effort=original_effort):
                self.setUp()
                dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})
                controller = self.controller(self.mark_store())
                result = controller.recover(
                    packet=PACKET,
                    work_item_id="EXAMPLE-security-work",
                    project_id="EXAMPLE-project",
                    original_attempt=self.original,
                    original_result=self.refusal,
                    original_dispatch={"model": "gpt-6.2-sol", "effort": original_effort, "service_tier": "priority"},
                    fallback_role=self.available,
                    mark=controller.mark_store.issue(work_item_id="EXAMPLE-security-work"),
                    dispatch=dispatch,
                )
                self.assertEqual(result["status"], "completed")
                self.assertEqual(dispatch.calls[0]["effort"], expected)
                self.assertEqual(dispatch.calls[0]["service_tier"], "default")
                self.assertTrue(all(row["service_tier"] == "default" and row["effort"] == expected for row in self.records))

    def test_fallback_refuses_a_non_sol_family_model(self) -> None:
        for model in ("gpt-6.2-astra", "gpt-6-luna", "gpt-6-terra"):
            with self.subTest(model=model), self.assertRaisesRegex(CyberFallbackError, "Daybreak Blue"):
                self.recover(self.controller(self.mark_store()), FakeDispatch(), role={**self.available, "model": model})

    def test_only_a_cyber_policy_refusal_triggers_recovery(self) -> None:
        dispatch = FakeDispatch()
        controller = self.controller(self.mark_store())
        for refusal in (
            {"summary": {"terminal_blockers": {"provider-safety-policy-refusal": "misalignmentPolicyViolation"}}},
            {"summary": {"terminal_blockers": {"provider-safety-policy-refusal": "otherPolicy"}}},
            self.ordinary_failure,
        ):
            with self.subTest(refusal=refusal):
                result = self.recover(controller, dispatch, refusal=refusal)
                self.assertEqual(result["status"], "unchanged")
        self.assertEqual(dispatch.calls, [])
        self.assertEqual(self.records, [])

    def test_project_mark_covers_work_once_and_spent_handle_is_rejected(self) -> None:
        store = self.mark_store(scope="project", mark_id="EXAMPLE-project")
        mark = store.issue(work_item_id="EXAMPLE-security-work", project_id="EXAMPLE-project")
        controller = self.controller(store)

        result = self.recover(
            controller,
            FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE}),
            mark=mark,
        )

        self.assertEqual(result["status"], "completed")
        with self.assertRaisesRegex(CyberFallbackError, "already consumed"):
            store.verify(mark, work_item_id="EXAMPLE-security-work", project_id="EXAMPLE-project")

    def test_unmarked_unavailable_and_non_refusal_failures_never_dispatch(self) -> None:
        cases = (
            (None, self.refusal, self.available, "work-not-marked"),
            (..., self.refusal, {**self.available, "status": "unavailable", "reason": "access-program-not-advertised"},
             "fallback-role-unavailable"),
            (..., self.ordinary_failure, self.available, None),
        )
        for mark, refusal, role, cause in cases:
            with self.subTest(cause=cause):
                store = self.mark_store(path=self.root / f"mark-{cause or 'ordinary'}.json")
                controller = self.controller(store)
                dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})
                result = self.recover(controller, dispatch, mark=mark, refusal=refusal, role=role)
                self.assertEqual(dispatch.calls, [])
                self.assertEqual(result.get("blocker", {}).get("cause"), cause)

    def test_worker_lead_forged_and_overlapping_marks_are_rejected(self) -> None:
        for source in ("worker", "lead"):
            with self.subTest(source=source), self.assertRaisesRegex(CyberFallbackError, "user action"):
                self.mark_store(source=source).issue(work_item_id="EXAMPLE-security-work")

        with self.assertRaisesRegex(CyberFallbackError, "outside worker and lead write roots"):
            self.mark_store(path=self.workspace / "mark.json")

        store = self.mark_store(path=self.root / "mark-forged.json")
        controller = self.controller(store)
        with self.assertRaisesRegex(CyberFallbackError, "verified user mark"):
            self.recover(controller, FakeDispatch(), mark={"source": "user"})

        mark = store.issue(work_item_id="EXAMPLE-security-work")
        forged_role = {**self.available, "model": "gpt-6.2-sol"}
        dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})
        with self.assertRaisesRegex(CyberFallbackError, "Daybreak Blue"):
            self.recover(controller, dispatch, mark=mark, role=forged_role)
        self.assertEqual(dispatch.calls, [])

    def test_fallback_refusal_blocks_and_cannot_launch_a_third_attempt(self) -> None:
        store = self.mark_store()
        controller = self.controller(store)
        dispatch = FakeDispatch({
            "outcome": "failed",
            "usage": ZERO_USAGE,
            "summary": {"terminal_blockers": {"provider-safety-policy-refusal": "cyberPolicy"}},
        })

        first = self.recover(controller, dispatch)
        self.assertEqual(first["blocker"]["cause"], "fallback-refused")
        self.assertEqual(len(dispatch.calls), 1)

        second_dispatch = FakeDispatch({"outcome": "completed", "usage": ZERO_USAGE})
        second = self.recover(controller, second_dispatch)
        self.assertEqual(second["blocker"]["cause"], "fallback-already-attempted")
        self.assertEqual(second_dispatch.calls, [])
        self.assertEqual(
            self.ledger.summary(self.budget_id)["charged"],
            {key: value * 2 for key, value in AMOUNT.items()},
        )


if __name__ == "__main__":
    unittest.main()
