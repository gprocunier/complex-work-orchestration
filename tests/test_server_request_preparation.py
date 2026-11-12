from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import server_request_preparation as prep


def request(method: str = prep.COMMAND, request_id: int | str = 1, **changes) -> dict:
    params = {"threadId": "t", "turnId": "u", "itemId": "i", "startedAtMs": 100}
    if method == prep.COMMAND:
        params.update(command="echo fake", cwd="/fake", kind="command")
    if method == prep.PERMISSIONS:
        params.update(cwd="/fake", permissions={"network": {"enabled": True}})
    params.update(changes)
    return {"id": request_id, "method": method, "params": params}


def context(method: str = prep.COMMAND, **changes) -> prep.FakeItemContext:
    values = {"epoch": "e", "thread_id": "t", "turn_id": "u", "item_id": "i", "method": method}
    if method == prep.COMMAND:
        values.update(command="echo fake", cwd="/fake")
    if method == prep.FILE:
        values.update(paths=("/fake/a",))
    values.update(changes)
    return prep.FakeItemContext(**values)


def harness(method: str = prep.COMMAND, **changes) -> prep.FakeRequestPreparer:
    adapter = prep.FakeRequestPreparer("e", allowed_paths=("/fake/a",), timeout_ms=10)
    adapter.open_turn("t", "u", now=0)
    adapter.observe_item(context(method, **changes), now=0)
    return adapter


def answer(adapter, message, decision="accept") -> tuple:
    adapter.receive(message, epoch="e", now=0)
    work = adapter.next_decision(now=0)
    adapter.prepare(work.correlation, decision, now=0)
    return adapter.drain_replies(now=0)


class ServerRequestPreparationTests(unittest.TestCase):
    def test_new_consumer_prepares_one_action_with_separate_metadata(self):
        for method in (prep.COMMAND, prep.FILE):
            with self.subTest(method=method):
                adapter = harness(method)
                replies = answer(adapter, request(method))
                self.assertEqual(len(replies), 1)
                reply = replies[0]
                self.assertEqual(json.loads(reply.frame_json), {"id": 1, "result": {"decision": "accept"}})
                self.assertEqual(reply.correlation, prep.Correlation("e", 1, "t", "u", "i", None))
                metadata = asdict(reply)
                self.assertTrue(metadata["experimental"])
                self.assertFalse(metadata["qualified"])
                self.assertEqual(metadata["captured_version"], "0.164.0")
                self.assertIn("unqualified", metadata["evidence_qualifier"])
                self.assertIn("not authenticated", metadata["context_provenance"])
                self.assertNotIn("qualified", json.loads(reply.frame_json))
                self.assertEqual(adapter.drain_replies(now=0), ())
                with self.assertRaises(prep.PreparationError):
                    adapter.receive(request(method), epoch="e", now=0)

    def test_notification_and_response_are_unaffected(self):
        adapter = harness()
        messages = ({"method": "item/updated", "params": {"threadId": "t", "text": "data"}},
                    {"id": "r", "result": [1, False, None]},
                    {"id": 3, "error": {"code": -1, "message": "failure", "data": {"a": 1}}})
        for message in messages:
            typed = adapter.receive(message, epoch="e", now=0)
            self.assertIsInstance(typed, (prep.Response, prep.Notification))
            self.assertEqual(json.loads(typed.frame_json), message)
        self.assertIsNone(adapter.next_decision(now=0))
        self.assertEqual(adapter.drain_replies(now=0), ())

    def test_malformed_and_ambiguous_shapes(self):
        malformed = [
            [], {}, {"id": True, "result": {}}, {"id": 1, "result": {}, "error": {}},
            {"id": 1, "method": "x", "params": {}, "result": {}},
            {"method": prep.COMMAND, "params": request()["params"]},
            {"id": None, "method": "x", "params": {}}, {"id": 2**63, "result": {}},
            {"id": 1, "error": {"code": False, "message": "bad"}},
            {"id": 1, "method": "x", "params": []},
            request(startedAtMs=True), request(kind="other"), request(approvalId=False),
            request(commandActions=[{"type": "read", "command": "cat"}]),
            request(availableDecisions=["cached"]),
            request(prep.PERMISSIONS, permissions={"network": {"enabled": "yes"}}),
            request(prep.PERMISSIONS, permissions={"unknown": {}}),
            request(prep.FILE, paths=["/fake/a"]),
        ]
        missing = request()
        del missing["params"]["startedAtMs"]
        malformed.append(missing)
        for message in malformed:
            with self.subTest(message=message), self.assertRaises(prep.PreparationError):
                prep.classify_message(message)
        for message in ({"method": "n", "params": {"x": float("nan")}},
                        {"method": "n", "params": {"x": "a" * 8193}}):
            with self.assertRaises(prep.PreparationError):
                prep.classify_message(message)

    def test_captured_optional_shapes_and_snapshot(self):
        message = request(
            kind="writeStdin", approvalId="callback", environmentId=None,
            additionalPermissions={"fileSystem": {"entries": [
                {"access": "deny", "path": {"type": "special", "value": {"kind": "root"}}}
            ]}},
            availableDecisions=[{"acceptWithExecpolicyAmendment": {"execpolicy_amendment": ["echo"]}}],
        )
        typed = prep.classify_message(message)
        message["params"]["itemId"] = "mutated"
        self.assertIsInstance(typed, prep.ServerRequest)
        self.assertEqual(json.loads(typed.params_json)["itemId"], "i")

    def test_integer_and_string_ids_and_callback_identity(self):
        adapter = harness(approval_id="a")
        adapter.observe_item(context(approval_id="b"), now=0)
        adapter.receive(request(request_id=1, approvalId="a"), epoch="e", now=0)
        adapter.receive(request(request_id="1", approvalId="b"), epoch="e", now=0)
        for expected in (1, "1"):
            work = adapter.next_decision(now=0)
            self.assertIs(type(work.correlation.request_id), type(expected))
            adapter.prepare(work.correlation, "decline", now=0)
        self.assertEqual([json.loads(r.frame_json)["id"] for r in adapter.drain_replies(now=0)], [1, "1"])
        with self.assertRaisesRegex(prep.PreparationError, "duplicate-approval"):
            adapter.receive(request(request_id=3, approvalId="a"), epoch="e", now=0)

    def test_decisions_do_not_grant_sessions_rules_or_permissions(self):
        adapter = harness()
        adapter.receive(request(), epoch="e", now=0)
        work = adapter.next_decision(now=0)
        for decision in ("acceptForSession", "cached", {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": []}},
                         {"applyNetworkPolicyAmendment": {"network_policy_amendment": {"action": "allow", "host": "x"}}}):
            with self.assertRaises(prep.PreparationError):
                adapter.prepare(work.correlation, decision, now=0)
        adapter.prepare(work.correlation, "decline", now=0)
        self.assertEqual(json.loads(adapter.drain_replies(now=0)[0].frame_json)["result"], {"decision": "decline"})
        adapter = harness(prep.PERMISSIONS)
        adapter.receive(request(prep.PERMISSIONS), epoch="e", now=0)
        work = adapter.next_decision(now=0)
        for decision in ("accept", "cancel", "session"):
            with self.assertRaises(prep.PreparationError):
                adapter.prepare(work.correlation, decision, now=0)
        adapter.prepare(work.correlation, "decline", now=0)
        self.assertEqual(json.loads(adapter.drain_replies(now=0)[0].frame_json), {"id": 1, "result": {"permissions": {}}})

    def test_cancel_and_unsupported_replies_are_method_correct(self):
        for method in (prep.COMMAND, prep.FILE):
            reply = answer(harness(method), request(method), "cancel")[0]
            self.assertEqual(json.loads(reply.frame_json)["result"], {"decision": "cancel"})
            self.assertTrue(reply.interruption_required)
        adapter = harness()
        cases = (
            ("item/tool/call", {"threadId": "t", "turnId": "u", "callId": "c", "tool": "fake", "arguments": {}}),
            ("item/tool/requestUserInput", {"threadId": "t", "turnId": "u", "itemId": "i", "isBlocking": True, "questions": []}),
            ("mcpServer/elicitation/request", {"threadId": "t", "serverName": "fake", "mode": "form", "message": "fake", "requestedSchema": {"type": "object", "properties": {}}}),
            ("unknown", {}),
        )
        for index, (method, params) in enumerate(cases, 1):
            adapter.receive({"id": index, "method": method, "params": params}, epoch="e", now=0)
            reply = adapter.drain_replies(now=0)[0]
            self.assertEqual(json.loads(reply.frame_json), {"id": index, "error": {"code": -32601, "message": "Unsupported server request"}})
            self.assertTrue(reply.interruption_required)
            self.assertIsNone(reply.correlation)
        self.assertIsNone(adapter.next_decision(now=0))

    def test_file_paths_are_fake_context_only_with_sensitive_negative_control(self):
        def outcome(paths):
            reply = answer(harness(prep.FILE, paths=paths), request(prep.FILE, reason="rename to /fake/a"))[0]
            return json.loads(reply.frame_json)["result"]["decision"]
        self.assertEqual(outcome(()), "decline")
        self.assertEqual(outcome(("/elsewhere",)), "decline")
        self.assertEqual(outcome(("/fake/a",)), "accept")
        with patch.object(prep, "_accept_is_safe", return_value=True):
            self.assertEqual(outcome(()), "accept")
        reply = answer(harness(prep.FILE), request(prep.FILE, grantRoot="/fake"))[0]
        self.assertEqual(json.loads(reply.frame_json)["result"], {"decision": "decline"})

    def test_command_overlay_and_remote_context_never_prepare_accept(self):
        for field, value in (("additionalPermissions", {}), ("environmentId", "remote"),
                             ("proposedExecpolicyAmendment", ["echo"]), ("availableDecisions", ["decline"]),
                             ("networkApprovalContext", {"host": "x", "protocol": "https"})):
            with self.subTest(field=field):
                reply = answer(harness(), request(**{field: value}))[0]
                self.assertEqual(json.loads(reply.frame_json)["result"], {"decision": "decline"})
        reply = answer(harness(command="different"), request())[0]
        self.assertEqual(json.loads(reply.frame_json)["result"], {"decision": "decline"})

    def test_reordered_cross_thread_and_forged_correlation_refuse(self):
        adapter = prep.FakeRequestPreparer("e")
        with self.assertRaises(prep.PreparationError):
            adapter.receive(request(), epoch="e", now=0)
        adapter.open_turn("t", "u", now=0)
        adapter.observe_item(context(), now=0)
        with self.assertRaisesRegex(prep.PreparationError, "duplicate-request-id"):
            adapter.receive(request(), epoch="e", now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.receive(request(request_id=2, threadId="other"), epoch="e", now=0)
        with self.assertRaisesRegex(prep.PreparationError, "duplicate-approval-callback"):
            adapter.receive(request(request_id=3), epoch="e", now=0)
        adapter.observe_item(context(item_id="j"), now=0)
        adapter.receive(request(request_id=4, itemId="j"), epoch="e", now=0)
        work = adapter.next_decision(now=0)
        for forged in (replace(work.correlation, thread_id="other"), replace(work.correlation, approval_id="wrong"),
                       replace(work.correlation, request_id="4"), replace(work.correlation, epoch="old")):
            with self.assertRaises(prep.PreparationError):
                adapter.prepare(forged, "accept", now=0)
        adapter.prepare(work.correlation, "decline", now=0)
        self.assertEqual(len(adapter.drain_replies(now=0)), 1)

    def test_terminal_revokes_queued_positive_and_refuses_late_decision(self):
        adapter = harness()
        adapter.receive(request(), epoch="e", now=0)
        work = adapter.next_decision(now=0)
        adapter.prepare(work.correlation, "accept", now=0)
        adapter.terminal("t", "u", now=0)
        self.assertEqual([json.loads(r.frame_json) for r in adapter.drain_replies(now=0)],
                         [{"id": 1, "result": {"decision": "cancel"}}])
        self.assertEqual(adapter.drain_replies(now=0), ())
        with self.assertRaises(prep.PreparationError):
            adapter.prepare(work.correlation, "accept", now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.receive(request(request_id=2), epoch="e", now=0)
        for method in (prep.COMMAND, prep.FILE, prep.PERMISSIONS):
            adapter = harness(method)
            adapter.receive(request(method), epoch="e", now=0)
            adapter.terminal("t", "u", now=0)
            result = json.loads(adapter.drain_replies(now=0)[0].frame_json)["result"]
            self.assertEqual(result, {"permissions": {}} if method == prep.PERMISSIONS else {"decision": "cancel"})

    def test_blocked_decider_does_not_block_receive_deadline_or_eof(self):
        adapter = harness()
        adapter.receive(request(), epoch="e", now=0)
        ready, release = threading.Event(), threading.Event()
        outcomes = []
        def decider():
            work = adapter.next_decision(now=0)
            ready.set()
            release.wait(2)
            try:
                adapter.prepare(work.correlation, "accept", now=10)
            except prep.PreparationError:
                outcomes.append("refused")
        worker = threading.Thread(target=decider)
        worker.start()
        try:
            self.assertTrue(ready.wait(1))
            notification = {"method": "progress", "params": {}}
            self.assertIsInstance(adapter.receive(notification, epoch="e", now=1), prep.Notification)
            self.assertIsInstance(adapter.receive({"id": 99, "result": {}}, epoch="e", now=2), prep.Response)
            replies = adapter.drain_replies(now=10)
            self.assertEqual(json.loads(replies[0].frame_json)["result"], {"decision": "decline"})
            self.assertTrue(replies[0].interruption_required)
            adapter.eof(now=10)
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, ["refused"])

    def test_racing_decisions_prepare_once(self):
        adapter = harness()
        adapter.receive(request(), epoch="e", now=0)
        work = adapter.next_decision(now=0)
        barrier = threading.Barrier(3, timeout=2)
        outcomes = []
        def decide():
            barrier.wait()
            try:
                adapter.prepare(work.correlation, "decline", now=0)
                outcomes.append("prepared")
            except prep.PreparationError:
                outcomes.append("refused")
        workers = [threading.Thread(target=decide) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual(outcomes, ["prepared", "refused"])
        self.assertEqual(len(adapter.drain_replies(now=0)), 1)

    def test_eof_reconnect_and_all_storage_budgets_fail_closed(self):
        adapter = harness()
        adapter.receive(request(), epoch="e", now=0)
        work = adapter.next_decision(now=0)
        adapter.eof(now=1)
        adapter.reconnect("new", now=2)
        with self.assertRaises(prep.PreparationError):
            adapter.prepare(work.correlation, "accept", now=2)
        with self.assertRaises(prep.PreparationError):
            adapter.receive(request(), epoch="e", now=2)
        adapter.open_turn("t", "u", now=2)
        adapter.observe_item(context(epoch="new"), now=2)
        adapter.receive(request(), epoch="new", now=2)
        self.assertIsNotNone(adapter.next_decision(now=2))
        with self.assertRaises(prep.PreparationError):
            adapter.reconnect("e", now=2)
        adapter = prep.FakeRequestPreparer("e", max_pending=1, max_requests=1, max_contexts=1, max_epochs=1)
        adapter.open_turn("t", "u", now=0)
        adapter.observe_item(context(), now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.observe_item(context(item_id="j"), now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.open_turn("other", "turn", now=0)
        adapter.receive(request(), epoch="e", now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.receive(request(request_id=2), epoch="e", now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.next_decision(now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.reconnect("new", now=0)
        adapter = prep.FakeRequestPreparer("e", max_pending=1, max_requests=2)
        adapter.receive({"id": 1, "method": "unknown", "params": {}}, epoch="e", now=0)
        with self.assertRaisesRegex(prep.PreparationError, "pending-and-reply-bound"):
            adapter.receive({"id": 2, "method": "unknown", "params": {}}, epoch="e", now=0)
        with self.assertRaises(prep.PreparationError):
            adapter.drain_replies(now=0)

    def test_fresh_identical_actions_require_fresh_decisions(self):
        adapter = harness()
        self.assertEqual(len(answer(adapter, request())), 1)
        adapter.observe_item(context(item_id="j"), now=0)
        adapter.receive(request(request_id=2, itemId="j"), epoch="e", now=0)
        self.assertEqual(adapter.drain_replies(now=0), ())
        work = adapter.next_decision(now=0)
        adapter.prepare(work.correlation, "decline", now=0)
        self.assertEqual(json.loads(adapter.drain_replies(now=0)[0].frame_json)["result"], {"decision": "decline"})

    def test_provisional_schema_is_not_a_product_pin(self):
        from cwo_core.codex_protocol_pin import PinError, pin_for
        with self.assertRaises(PinError):
            pin_for("0.164.0")


class ServerRequestPreparationRegressionTests(unittest.TestCase):
    def pending_case(self, method, state):
        adapter = harness(method)
        adapter.receive(request(method), epoch="e", now=0)
        work = None
        if state != "queued":
            work = adapter.next_decision(now=0)
            if state != "deciding":
                adapter.prepare(work.correlation, state, now=0)
        return adapter, work

    def assert_single_reply(self, adapter, result, *, now, interrupt, request_id=1):
        replies = adapter.drain_replies(now=now)
        self.assertEqual(len(replies), 1)
        frame = json.loads(replies[0].frame_json)
        self.assertIn("id", frame)
        self.assertIs(type(frame["id"]), type(request_id))
        self.assertEqual(frame, {"id": request_id, "result": result})
        self.assertEqual(replies[0].interruption_required, interrupt)
        self.assertEqual(adapter.drain_replies(now=now), ())

    def test_refused_callbacks_stay_tombstoned_after_late_context(self):
        for method in (prep.COMMAND, prep.FILE, prep.PERMISSIONS):
            for active in (False, True):
                with self.subTest(method=method, active=active):
                    adapter = prep.FakeRequestPreparer("e", allowed_paths=("/fake/a",))
                    if active:
                        adapter.open_turn("t", "u", now=0)
                    with self.assertRaises(prep.PreparationError):
                        adapter.receive(request(method), epoch="e", now=0)
                    if not active:
                        adapter.open_turn("t", "u", now=0)
                    adapter.observe_item(context(method), now=0)
                    with self.assertRaisesRegex(prep.PreparationError, "duplicate-request-id"):
                        adapter.receive(request(method), epoch="e", now=0)
                    with self.assertRaisesRegex(prep.PreparationError, "duplicate-approval-callback"):
                        adapter.receive(request(method, request_id=2), epoch="e", now=0)
                    self.assertIsNone(adapter.next_decision(now=0))
                    self.assertEqual(adapter.drain_replies(now=0), ())
                    adapter.observe_item(context(method, item_id="j"), now=0)
                    adapter.receive(request(method, request_id=3, itemId="j"), epoch="e", now=0)
                    work = adapter.next_decision(now=0)
                    self.assertIsNotNone(work)
                    decision = "decline" if method == prep.PERMISSIONS else "accept"
                    adapter.prepare(work.correlation, decision, now=0)
                    result = {"permissions": {}} if method == prep.PERMISSIONS else {"decision": "accept"}
                    self.assert_single_reply(adapter, result, now=0, interrupt=False, request_id=3)

    def test_callback_tombstones_bind_method_approval_thread_and_turn(self):
        cases = (
            (prep.FILE, {}, {}),
            (prep.COMMAND, {"approval_id": "fresh"}, {"approvalId": "fresh"}),
            (prep.COMMAND, {"thread_id": "other"}, {"threadId": "other"}),
            (prep.COMMAND, {"turn_id": "other"}, {"turnId": "other"}),
        )
        for method, item_changes, params_changes in cases:
            with self.subTest(method=method, changes=item_changes):
                adapter = prep.FakeRequestPreparer("e", allowed_paths=("/fake/a",))
                adapter.open_turn("t", "u", now=0)
                with self.assertRaises(prep.PreparationError):
                    adapter.receive(request(), epoch="e", now=0)
                if "thread_id" in item_changes:
                    adapter.open_turn("other", "u", now=0)
                if "turn_id" in item_changes:
                    adapter.terminal("t", "u", now=0)
                    adapter.open_turn("t", "other", now=0)
                adapter.observe_item(context(method, **item_changes), now=0)
                replies = answer(adapter, request(method, request_id=2, **params_changes))
                self.assertEqual(len(replies), 1)
                self.assertEqual(json.loads(replies[0].frame_json), {"id": 2, "result": {"decision": "accept"}})

    def test_terminal_at_deadline_keeps_queued_and_deciding_denials(self):
        for method in (prep.COMMAND, prep.FILE, prep.PERMISSIONS):
            for state in ("queued", "deciding"):
                with self.subTest(method=method, state=state):
                    adapter, work = self.pending_case(method, state)
                    adapter.terminal("t", "u", now=10)
                    result = {"permissions": {}} if method == prep.PERMISSIONS else {"decision": "decline"}
                    self.assert_single_reply(adapter, result, now=10, interrupt=True)
                    self.assertIsNone(adapter.next_decision(now=10))
                    if work is not None:
                        with self.assertRaises(prep.PreparationError):
                            adapter.prepare(work.correlation, "decline", now=10)

    def test_terminal_preserves_prepared_negative_frames(self):
        cases = ((prep.COMMAND, "decline"), (prep.COMMAND, "cancel"),
                 (prep.FILE, "decline"), (prep.FILE, "cancel"), (prep.PERMISSIONS, "decline"))
        for method, decision in cases:
            for now in (0, 10):
                with self.subTest(method=method, decision=decision, now=now):
                    adapter, work = self.pending_case(method, decision)
                    adapter.terminal("t", "u", now=now)
                    result = {"permissions": {}} if method == prep.PERMISSIONS else {"decision": decision}
                    self.assert_single_reply(adapter, result, now=now, interrupt=decision == "cancel")
                    with self.assertRaises(prep.PreparationError):
                        adapter.prepare(work.correlation, "decline", now=now)

    def test_terminal_replaces_undrained_acceptance_with_cancel(self):
        for method in (prep.COMMAND, prep.FILE):
            for now in (0, 10):
                with self.subTest(method=method, now=now):
                    adapter, work = self.pending_case(method, "accept")
                    adapter.terminal("t", "u", now=now)
                    self.assert_single_reply(adapter, {"decision": "cancel"}, now=now, interrupt=True)
                    with self.assertRaises(prep.PreparationError):
                        adapter.prepare(work.correlation, "accept", now=now)

    def test_terminal_after_drain_does_not_replace_consumed_acceptance(self):
        for method in (prep.COMMAND, prep.FILE):
            with self.subTest(method=method):
                adapter, work = self.pending_case(method, "accept")
                self.assert_single_reply(adapter, {"decision": "accept"}, now=0, interrupt=False)
                adapter.terminal("t", "u", now=10)
                self.assertEqual(adapter.drain_replies(now=10), ())
                with self.assertRaises(prep.PreparationError):
                    adapter.prepare(work.correlation, "accept", now=10)

    def test_terminal_preserves_other_turn_and_unsupported_reply_order(self):
        adapter = harness()
        adapter.open_turn("other", "v", now=0)
        adapter.observe_item(context(thread_id="other", turn_id="v"), now=0)
        adapter.receive(request(), epoch="e", now=0)
        adapter.receive(request(request_id=2, threadId="other", turnId="v"), epoch="e", now=0)
        for _ in range(2):
            work = adapter.next_decision(now=0)
            adapter.prepare(work.correlation, "accept", now=0)
        adapter.receive({"id": 3, "method": "unknown", "params": {}}, epoch="e", now=0)
        adapter.terminal("t", "u", now=0)
        frames = [json.loads(reply.frame_json) for reply in adapter.drain_replies(now=0)]
        self.assertEqual(frames, [
            {"id": 1, "result": {"decision": "cancel"}},
            {"id": 2, "result": {"decision": "accept"}},
            {"id": 3, "error": {"code": -32601, "message": "Unsupported server request"}},
        ])
        self.assertEqual(adapter.drain_replies(now=0), ())
        adapter.terminal("other", "v", now=0)
        self.assertEqual(adapter.drain_replies(now=0), ())

    def race_terminal_and_drain(self, adapter, *, now):
        barrier = threading.Barrier(3, timeout=2)
        replies, failures = [], []
        def run(action):
            try:
                barrier.wait()
                result = action()
                if result is not None:
                    replies.extend(result)
            except Exception as error:
                failures.append(error)
        workers = [
            threading.Thread(target=run, args=(lambda: adapter.terminal("t", "u", now=now),)),
            threading.Thread(target=run, args=(lambda: adapter.drain_replies(now=now),)),
        ]
        for worker in workers:
            worker.start()
        try:
            barrier.wait()
        except threading.BrokenBarrierError as error:
            failures.append(error)
        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        return tuple(replies) + adapter.drain_replies(now=now)

    def test_terminal_drain_race_consumes_one_prepared_frame(self):
        for method in (prep.COMMAND, prep.FILE):
            for decision in ("accept", "decline", "cancel"):
                for now in (0, 10):
                    with self.subTest(method=method, decision=decision, now=now):
                        adapter, work = self.pending_case(method, decision)
                        replies = self.race_terminal_and_drain(adapter, now=now)
                        self.assertEqual(len(replies), 1)
                        frame = json.loads(replies[0].frame_json)
                        expected = ({"decision": "accept"}, {"decision": "cancel"}) if decision == "accept" else ({"decision": decision},)
                        self.assertEqual(frame["id"], 1)
                        self.assertIn(frame["result"], expected)
                        self.assertEqual(set(frame), {"id", "result"})
                        self.assertEqual(replies[0].interruption_required, frame["result"] == {"decision": "cancel"})
                        self.assertEqual(adapter.drain_replies(now=now), ())
                        with self.assertRaises(prep.PreparationError):
                            adapter.prepare(work.correlation, "decline", now=now)

    def test_terminal_drain_race_at_deadline_keeps_denial(self):
        for method in (prep.COMMAND, prep.FILE, prep.PERMISSIONS):
            for state in ("queued", "deciding", "decline"):
                with self.subTest(method=method, state=state):
                    adapter, _ = self.pending_case(method, state)
                    replies = self.race_terminal_and_drain(adapter, now=10)
                    self.assertEqual(len(replies), 1)
                    result = {"permissions": {}} if method == prep.PERMISSIONS else {"decision": "decline"}
                    self.assertEqual(json.loads(replies[0].frame_json), {"id": 1, "result": result})
                    self.assertEqual(replies[0].interruption_required, state != "decline")
                    self.assertEqual(adapter.drain_replies(now=10), ())


if __name__ == "__main__":
    unittest.main()
