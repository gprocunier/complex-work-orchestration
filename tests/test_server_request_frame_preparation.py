from __future__ import annotations

from typing import NamedTuple

from dataclasses import asdict
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_server_request_frames as frames
from cwo_core import server_request_preparation as prep

EPOCH = "EXAMPLE-epoch"
FLAGS = (
    "operative", "qualified", "effect_authority",
    "production_ready", "current_transport_wired",
)


def request(method: str = prep.COMMAND, request_id: int | str = 1, **changes) -> dict:
    params = {"threadId": "EXAMPLE-thread", "turnId": "EXAMPLE-turn",
              "itemId": "EXAMPLE-item", "startedAtMs": 0}
    if method == prep.COMMAND:
        params.update(command="EXAMPLE command data", cwd="/EXAMPLE", kind="command")
    if method == prep.PERMISSIONS:
        params.update(cwd="/EXAMPLE", permissions={"network": {"enabled": True}})
    params.update(changes)
    return {"id": request_id, "method": method, "params": params}


def context(method: str = prep.COMMAND, **changes) -> prep.FakeItemContext:
    values = {"epoch": EPOCH, "thread_id": "EXAMPLE-thread", "turn_id": "EXAMPLE-turn",
              "item_id": "EXAMPLE-item", "method": method}
    if method == prep.COMMAND:
        values.update(command="EXAMPLE command data", cwd="/EXAMPLE")
    if method == prep.FILE:
        values.update(paths=("/EXAMPLE/file",))
    values.update(changes)
    return prep.FakeItemContext(**values)


def harness(*, method=prep.COMMAND, consumer_limits=None, reader_limits=None, register=True):
    consumer = prep.FakeRequestPreparer(
        EPOCH, allowed_paths=("/EXAMPLE/file",), timeout_ms=10, **(consumer_limits or {}),
    )
    if register:
        consumer.open_turn("EXAMPLE-thread", "EXAMPLE-turn", now=0)
        consumer.observe_item(context(method), now=0)
    return consumer, frames.FakeFrameReader(consumer, **(reader_limits or {}))


def line(value, ending=b"\n") -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + ending


class ServerRequestFramePreparationTests(unittest.TestCase):
    def setUp(self):
        self.guards = []
        self.process_guard = self.watch(subprocess, "Popen", "process")
        self.watch(subprocess, "run", "process run")
        self.watch(os, "system", "process command")
        self.watch(os, "popen", "process pipe")
        self.socket_guard = self.watch(socket, "socket", "socket")
        self.watch(socket, "create_connection", "socket connection")
        from cwo_core.supervision.transport import app_server
        from cwo_core import native_turn_dispatch
        self.model_guard = self.watch(app_server, "AppServer", "model transport")
        self.dispatch_guards = [
            self.watch(native_turn_dispatch, name, "current dispatch")
            for name, value in vars(native_turn_dispatch).copy().items()
            if inspect.isfunction(value) and value.__module__ == native_turn_dispatch.__name__
        ]
        self.assertTrue(self.dispatch_guards)

    def watch(self, owner, name, label):
        guard = patch.object(owner, name, side_effect=RuntimeError("EXAMPLE reliability guard: " + label))
        observed = guard.start()
        self.addCleanup(guard.stop)
        self.guards.append(observed)
        return observed

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def flags(self, value):
        for name in FLAGS:
            self.assertIs(getattr(value, name), False)

    def closed(self, consumer):
        with consumer._lock:
            self.assertTrue(consumer._closed)
            self.assertEqual(len(consumer._queue), 0)
            self.assertEqual(len(consumer._replies), 0)
            self.assertTrue(all(entry.state == "revoked" for entry in consumer._entries.values()))
        with self.assertRaises(prep.PreparationError):
            consumer.next_decision(now=0)
        with self.assertRaises(prep.PreparationError):
            consumer.drain_replies(now=0)

    def failure(self, consumer, reader, raw, *, code=None, prefix=0, total=None):
        with self.assertRaises(frames.FramePreparationError) as caught:
            reader.feed(raw, epoch=EPOCH, now=0)
        error = caught.exception
        self.flags(error)
        self.flags(error.status)
        self.assertTrue(error.fatal)
        self.assertEqual(error.delivered_count, prefix)
        if total is not None:
            self.assertEqual(error.delivered_total, total)
        if code is not None:
            self.assertEqual(error.code, code)
        self.assertTrue(error.status.closed)
        self.assertEqual(error.status.buffered_bytes, 0)
        self.closed(consumer)
        return error

    def test_named_positive_effect_guards(self):
        for guard in (self.process_guard, self.socket_guard, self.model_guard, self.dispatch_guards[0]):
            with self.assertRaisesRegex(RuntimeError, "EXAMPLE reliability guard"):
                guard("EXAMPLE positive guard control")
            guard.reset_mock()

    def test_complete_requests_use_actual_classifier_and_method_replies(self):
        for method in (prep.COMMAND, prep.FILE, prep.PERMISSIONS):
            with self.subTest(method=method):
                consumer, reader = harness(method=method)
                with patch.object(prep, "classify_message", wraps=prep.classify_message) as classifier:
                    batch = reader.feed(line(request(method)), epoch=EPOCH, now=0)
                classifier.assert_called_once()
                self.flags(batch)
                self.assertEqual(tuple(asdict(batch)[name] for name in FLAGS), (False,) * 5)
                self.assertIsInstance(batch.delivered[0], prep.ServerRequest)
                work = consumer.next_decision(now=0)
                self.assertEqual(work.context, context(method))
                self.assertEqual(consumer.drain_replies(now=0), ())
                consumer.prepare(work.correlation, "decline", now=0)
                reply = consumer.drain_replies(now=0)[0]
                expected = {"permissions": {}} if method == prep.PERMISSIONS else {"decision": "decline"}
                self.assertEqual(json.loads(reply.frame_json), {"id": 1, "result": expected})
                self.assertNotIn("operative", json.loads(reply.frame_json))

    def test_split_utf8_and_json_at_every_boundary(self):
        raw = line(request(reason="EXAMPLE café 🧪"))
        for offset in range(len(raw) + 1):
            with self.subTest(offset=offset):
                consumer, reader = harness()
                first = reader.feed(raw[:offset], epoch=EPOCH, now=0)
                second = reader.feed(raw[offset:], epoch=EPOCH, now=0)
                self.assertEqual(len(first.delivered) + len(second.delivered), 1)
                self.assertEqual(reader.snapshot().received_bytes, len(raw))
                self.assertIsNotNone(consumer.next_decision(now=0))
        consumer, reader = harness()
        for octet in raw:
            reader.feed(bytes([octet]), epoch=EPOCH, now=0)
        self.assertEqual(reader.snapshot().delivered_frames, 1)
        self.assertIsNotNone(consumer.next_decision(now=0))

    def test_typed_notifications_responses_and_ordered_independent_context(self):
        consumer, reader = harness()
        consumer.open_turn("EXAMPLE-other-thread", "EXAMPLE-other-turn", now=0)
        other = context(prep.FILE, thread_id="EXAMPLE-other-thread", turn_id="EXAMPLE-other-turn")
        consumer.observe_item(other, now=0)
        values = (
            {"method": "EXAMPLE/notice", "params": {"text": "EXAMPLE café"}},
            {"id": "EXAMPLE-response", "result": [False, None, -2**63, 2**63 - 1, 1e308]},
            request(),
            request(prep.FILE, "1", threadId="EXAMPLE-other-thread", turnId="EXAMPLE-other-turn"),
        )
        batch = reader.feed(b"".join(line(value, b"\r\n") for value in values), epoch=EPOCH, now=0)
        self.assertEqual(tuple(type(value) for value in batch.delivered),
                         (prep.Notification, prep.Response, prep.ServerRequest, prep.ServerRequest))
        works = (consumer.next_decision(now=0), consumer.next_decision(now=0))
        self.assertEqual(tuple(work.context for work in works), (context(), other))
        for work in works:
            consumer.prepare(work.correlation, "decline", now=0)
        self.assertEqual([json.loads(reply.frame_json)["id"] for reply in consumer.drain_replies(now=0)],
                         [1, "1"])

    def test_malformed_envelopes_use_actual_typed_validation(self):
        cases = (
            [], {}, {"id": True, "result": {}}, {"id": 1, "result": {}, "error": {}},
            {"id": 1, "method": "EXAMPLE/unknown", "params": {}, "result": {}},
            {"method": prep.COMMAND, "params": request()["params"]},
            request(startedAtMs=True), request(kind="EXAMPLE-invalid"),
            request(prep.PERMISSIONS, permissions={"network": {"enabled": "EXAMPLE-invalid"}}),
            request(prep.FILE, paths=["/EXAMPLE/file"]),
            {"id": 1, "error": {"code": False, "message": "EXAMPLE failure"}},
        )
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                consumer, reader = harness()
                with patch.object(prep, "classify_message", wraps=prep.classify_message) as classifier:
                    self.failure(consumer, reader, line(value))
                classifier.assert_called_once()

    def test_duplicate_keys_at_nested_levels_and_escaped_aliases(self):
        cases = (
            b'{"id":1,"id":2,"result":{}}\n',
            b'{"id":1,"result":{"EXAMPLE-key":1,"EXAMPLE-key":2}}\n',
            b'{"id":1,"result":[{"EXAMPLE-key":1,"EXAMPLE-key":2}]}\n',
            br'{"id":1,"result":{"EXAMPLE-a":1,"EXAMPLE-\u0061":2}}' + b"\n",
        )
        for index, raw in enumerate(cases):
            with self.subTest(index=index):
                consumer, reader = harness()
                self.failure(consumer, reader, raw, code="duplicate-textual-key")

    def test_invalid_text_blank_lines_and_native_parse_failures(self):
        for raw in (b"\n", b"\r\n", b" \t\r\n", b"{\n", b"\xff\n",
                    b'{"id":1,"result":0} EXAMPLE\n'):
            consumer, reader = harness()
            self.failure(consumer, reader, raw)
        for error in (ValueError, OverflowError, RecursionError):
            consumer, reader = harness()
            with patch.object(frames.json, "loads", side_effect=error("EXAMPLE native limit")):
                self.failure(consumer, reader, line({"id": 1, "result": {}}),
                             code="invalid-json-or-native-limit")

    def test_integer_and_float_domain_edges(self):
        for number in ("9223372036854775808", "-9223372036854775809", "1" * 5000,
                       "NaN", "Infinity", "-Infinity", "1e309"):
            consumer, reader = harness()
            raw = ('{"id":1,"result":' + number + '}\n').encode("ascii")
            self.failure(consumer, reader, raw)
        for request_id in (1.0, True):
            consumer, reader = harness()
            self.failure(consumer, reader, line({"id": request_id, "result": {}}), code="request-id")

    def test_depth_nodes_strings_and_container_bounds(self):
        result = "EXAMPLE leaf"
        for _ in range(15):
            result = [result]
        consumer, reader = harness()
        self.assertEqual(len(reader.feed(line({"id": 1, "result": result}), epoch=EPOCH, now=0).delivered), 1)
        consumer, reader = harness()
        self.failure(consumer, reader, line({"id": 1, "result": [result]}))
        result = [[0] * 255 for _ in range(15)] + [[0] * 252]
        consumer, reader = harness()
        reader.feed(line({"id": 1, "result": result}), epoch=EPOCH, now=0)
        result[-1].append(0)
        consumer, reader = harness()
        self.failure(consumer, reader, line({"id": 1, "result": result}))
        for positive, negative in (
            ([0] * 256, [0] * 257), ("EXAMPLE " * 1024, "EXAMPLE " * 1024 + "E"),
            ({"EXAMPLE " * 32: 0}, {"EXAMPLE " * 32 + "E": 0}),
            ({f"EXAMPLE-{index}": 0 for index in range(256)}, {f"EXAMPLE-{index}": 0 for index in range(257)}),
        ):
            consumer, reader = harness()
            reader.feed(line({"id": 1, "result": positive}), epoch=EPOCH, now=0)
            consumer, reader = harness()
            self.failure(consumer, reader, line({"id": 1, "result": negative}))
        consumer, reader = harness()
        self.failure(consumer, reader, line({"id": 1, "result": ["EXAMPLE " + "é" * 8184] * 2}), code="message-bytes")
        consumer, reader = harness()
        with patch.object(frames.json, "loads") as parser:
            self.failure(consumer, reader, b"[" * 2000 + b"]" * 2000 + b"\n", code="message-size-or-depth")
        parser.assert_not_called()

    def test_raw_normalized_byte_limits_and_crlf_margin(self):
        overhead = len(line({"id": 1, "result": [""] * 8})) - 1
        result = ["EXAMPLE " * 1024] * 7 + [("EXAMPLE " * 1024)[:65536 - overhead - 7 * 8192]]
        raw = line({"id": 1, "result": result})
        self.assertEqual(len(raw), 65537)
        consumer, reader = harness()
        reader.feed(raw, epoch=EPOCH, now=0)
        raw = line({"id": 1, "result": "EXAMPLE"})[:-1]
        consumer, reader = harness(reader_limits={"max_frame_bytes": len(raw)})
        reader.feed(raw + b"\r", epoch=EPOCH, now=0)
        self.assertEqual(reader.snapshot().buffered_bytes, len(raw) + 1)
        self.assertEqual(len(reader.feed(b"\n", epoch=EPOCH, now=0).delivered), 1)
        consumer, reader = harness(reader_limits={"max_frame_bytes": 8})
        reader.feed(b" " * 8, epoch=EPOCH, now=0)
        with patch.object(frames.json, "loads") as parser:
            self.failure(consumer, reader, b"E", code="frame-byte-bound")
        parser.assert_not_called()
        self.assertEqual(reader.snapshot().received_bytes, 8)
        consumer, reader = harness(reader_limits={"max_chunk_bytes": 4})
        self.failure(consumer, reader, b"EXAMPLE", code="chunk-byte-bound")
        self.assertEqual(reader.snapshot().received_bytes, 0)

    def test_ordered_prefix_and_total_message_limits(self):
        notice = line({"method": "EXAMPLE/notice", "params": {}})
        for limits, raw, code in (
            ({}, line(request()) + b"{\n", "invalid-json-or-native-limit"),
            ({"max_frames": 1}, notice + notice, "message-count-bound"),
            ({"max_total_bytes": len(notice) + 2}, notice + b"   ", "total-byte-bound"),
        ):
            consumer, reader = harness(reader_limits=limits)
            error = self.failure(consumer, reader, raw, code=code, prefix=1, total=1)
            self.assertEqual(len(error.delivered), 1)
            self.assertEqual(reader.snapshot().delivered_frames, 1)
            with self.assertRaises(frames.FramePreparationError) as caught:
                reader.feed(notice, epoch=EPOCH, now=0)
            self.assertFalse(caught.exception.fatal)

    def test_fatal_error_clears_prepared_replies_and_keeps_tombstones(self):
        consumer, reader = harness()
        reader.feed(line(request()), epoch=EPOCH, now=0)
        work = consumer.next_decision(now=0)
        consumer.prepare(work.correlation, "decline", now=0)
        error = self.failure(consumer, reader, b"{\n", prefix=0, total=1)
        self.assertEqual(error.delivered, ())
        self.assertIn((int, 1), consumer._entries)
        self.assertTrue(consumer._callbacks)
        with self.assertRaises(prep.PreparationError):
            consumer.prepare(work.correlation, "accept", now=0)

    def test_queue_reply_and_history_limits_use_real_consumer(self):
        for unsupported, history in ((False, False), (True, False), (False, True)):
            consumer, reader = harness(consumer_limits={"max_pending": 1, "max_requests": 1 if history else 2})
            consumer.observe_item(context(item_id="EXAMPLE-second-item"), now=0)
            first = {"id": 1, "method": "EXAMPLE/unsupported", "params": {}} if unsupported else request()
            reader.feed(line(first), epoch=EPOCH, now=0)
            if history:
                work = consumer.next_decision(now=0)
                consumer.prepare(work.correlation, "decline", now=0)
                consumer.drain_replies(now=0)
            expected = "request-history-bound" if history else "pending-and-reply-bound"
            self.failure(consumer, reader, line(request(request_id=2, itemId="EXAMPLE-second-item")),
                         code=expected, total=1)

    def test_clean_and_partial_eof_then_fresh_epoch(self):
        for unfinished in (b"{", b"\xc3", line({"id": 1, "result": {}})[:-1]):
            consumer, reader = harness()
            reader.feed(line(request()) + unfinished, epoch=EPOCH, now=0)
            with self.assertRaises(frames.FramePreparationError) as caught:
                reader.eof(epoch=EPOCH, now=1)
            self.assertEqual(caught.exception.code, "partial-eof-frame")
            self.assertEqual(caught.exception.delivered_total, 1)
            self.flags(caught.exception)
            self.closed(consumer)
        consumer, reader = harness()
        reader.feed(line(request()), epoch=EPOCH, now=0)
        old = consumer.next_decision(now=0)
        batch = reader.eof(epoch=EPOCH, now=1)
        self.flags(batch)
        self.assertTrue(batch.status.closed)
        self.closed(consumer)
        consumer.reconnect("EXAMPLE-next-epoch", now=2)
        consumer.open_turn("EXAMPLE-thread", "EXAMPLE-turn", now=2)
        consumer.observe_item(context(epoch="EXAMPLE-next-epoch"), now=2)
        fresh = frames.FakeFrameReader(consumer)
        fresh.feed(line(request()), epoch="EXAMPLE-next-epoch", now=2)
        with self.assertRaises(frames.FramePreparationError):
            reader.feed(line(request()), epoch=EPOCH, now=2)
        self.assertIsNotNone(consumer.next_decision(now=2))
        with self.assertRaises(prep.PreparationError):
            consumer.prepare(old.correlation, "accept", now=2)

    def test_refused_callback_and_terminal_require_fresh_context(self):
        consumer, reader = harness(register=False)
        self.failure(consumer, reader, line(request()), code="inactive-or-cross-thread-turn")
        self.assertIn((int, 1), consumer._entries)
        with self.assertRaises(prep.PreparationError):
            consumer.reconnect(EPOCH, now=0)
        consumer.reconnect("EXAMPLE-fresh", now=0)
        consumer.open_turn("EXAMPLE-thread", "EXAMPLE-turn", now=0)
        consumer.observe_item(context(epoch="EXAMPLE-fresh"), now=0)
        reader = frames.FakeFrameReader(consumer)
        reader.feed(line(request()), epoch="EXAMPLE-fresh", now=0)
        work = consumer.next_decision(now=0)
        consumer.prepare(work.correlation, "accept", now=0)
        consumer.terminal("EXAMPLE-thread", "EXAMPLE-turn", now=0)
        self.assertEqual(json.loads(consumer.drain_replies(now=0)[0].frame_json),
                         {"id": 1, "result": {"decision": "cancel"}})
        with self.assertRaises(prep.PreparationError):
            consumer.prepare(work.correlation, "accept", now=0)

    def test_stale_epoch_time_and_chunk_type_are_nonfatal(self):
        consumer, reader = harness()
        for kwargs in ({"epoch": "EXAMPLE-stale", "now": 0}, {"epoch": EPOCH, "now": True},
                       {"epoch": EPOCH, "now": 2**63}):
            with self.assertRaises(frames.FramePreparationError) as caught:
                reader.feed(b"", **kwargs)
            self.assertFalse(caught.exception.fatal)
            self.flags(caught.exception)
        with self.assertRaises(frames.FramePreparationError):
            reader.feed(bytearray(b"EXAMPLE"), epoch=EPOCH, now=0)
        reader.feed(b"{", epoch=EPOCH, now=2)
        with self.assertRaises(frames.FramePreparationError):
            reader.feed(b"", epoch=EPOCH, now=1)
        self.assertFalse(reader.snapshot().closed)
        reader.feed(b'"id":1,"result":{}}\n', epoch=EPOCH, now=2)
        self.assertIsNone(consumer.next_decision(now=2))

    def test_reentrant_delivery_and_close_observe_committed_state(self):
        consumer, reader = harness()
        original_receive = prep.FakeRequestPreparer.receive
        original_eof = prep.FakeRequestPreparer.eof
        observed = []
        def receive(owner, value, **kwargs):
            state = reader.snapshot()
            observed.append((state.completed_frames, state.delivered_frames, state.buffered_bytes))
            self.assertTrue(state.delivering)
            for action in (reader.feed, reader.eof):
                with self.assertRaises(frames.FramePreparationError) as caught:
                    if action == reader.feed:
                        action(b"", epoch=EPOCH, now=0)
                    else:
                        action(epoch=EPOCH, now=0)
                self.assertEqual(caught.exception.code, "reentrant-operation")
                self.assertFalse(caught.exception.fatal)
            return original_receive(owner, value, **kwargs)
        def close(owner, **kwargs):
            state = reader.snapshot()
            self.assertTrue(state.closed)
            self.assertEqual(state.buffered_bytes, 0)
            with self.assertRaises(frames.FramePreparationError) as caught:
                reader.feed(b"", epoch=EPOCH, now=0)
            self.assertEqual(caught.exception.code, "reentrant-operation")
            return original_eof(owner, **kwargs)
        with patch.object(prep.FakeRequestPreparer, "receive", receive):
            batch = reader.feed(line({"id": 1, "result": {}}) + line(request()), epoch=EPOCH, now=0)
        self.assertEqual(len(batch.delivered), 2)
        self.assertEqual(observed, [(1, 0, 0), (2, 1, 0)])
        with patch.object(prep.FakeRequestPreparer, "eof", close):
            self.failure(consumer, reader, b"{\n", total=2)

    def test_feed_and_eof_races_have_no_post_close_delivery(self):
        for _ in range(8):
            consumer, reader = harness()
            barrier = threading.Barrier(3, timeout=2)
            results, failures = [], []
            def run(action):
                try:
                    barrier.wait()
                    results.append(action())
                except frames.FramePreparationError as error:
                    results.append(error)
                except Exception as error:
                    failures.append(error)
            workers = [
                threading.Thread(target=run, args=(lambda: reader.feed(line(request()), epoch=EPOCH, now=0),),
                                 daemon=True),
                threading.Thread(target=run, args=(lambda: reader.eof(epoch=EPOCH, now=0),), daemon=True),
            ]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(2)
                self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(len(results), 2)
            self.assertIn(reader.snapshot().delivered_frames, (0, 1))
            self.closed(consumer)
            with self.assertRaises(frames.FramePreparationError):
                reader.feed(line(request()), epoch=EPOCH, now=0)

    def test_eof_waits_for_inflight_receive_without_deadlock(self):
        consumer, reader = harness()
        entered, release, closing, finished = (threading.Event() for _ in range(4))
        original = prep.FakeRequestPreparer.receive
        outcomes, failures = [], []
        def receive(owner, value, **kwargs):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("EXAMPLE test release timeout")
            return original(owner, value, **kwargs)
        def send():
            try:
                outcomes.append(reader.feed(line(request()), epoch=EPOCH, now=0))
            except Exception as error:
                failures.append(error)
        def close():
            closing.set()
            try:
                outcomes.append(reader.eof(epoch=EPOCH, now=0))
            except Exception as error:
                failures.append(error)
            finally:
                finished.set()
        sender = threading.Thread(target=send, daemon=True)
        closer = threading.Thread(target=close, daemon=True)
        with patch.object(prep.FakeRequestPreparer, "receive", receive):
            sender.start()
            try:
                self.assertTrue(entered.wait(1))
                closer.start()
                self.assertTrue(closing.wait(1))
                self.assertFalse(finished.wait(0.02))
            finally:
                release.set()
                sender.join(2)
                if closer.ident is not None:
                    closer.join(2)
        self.assertFalse(sender.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(sum(len(result.delivered) for result in outcomes), 1)
        self.closed(consumer)

    def test_duplicate_ids_and_callbacks_close_without_resurrection(self):
        for duplicate in (request(), request(request_id=2)):
            consumer, reader = harness()
            reader.feed(line(request()), epoch=EPOCH, now=0)
            self.failure(consumer, reader, line(duplicate), total=1)

    def test_external_reconnect_does_not_let_old_reader_close_new_epoch(self):
        consumer, reader = harness()
        reader.feed(b"{", epoch=EPOCH, now=0)
        consumer.reconnect("EXAMPLE-moved", now=1)
        consumer.open_turn("EXAMPLE-thread", "EXAMPLE-turn", now=1)
        consumer.observe_item(context(epoch="EXAMPLE-moved"), now=1)
        fresh = frames.FakeFrameReader(consumer)
        fresh.feed(line(request()), epoch="EXAMPLE-moved", now=1)
        with self.assertRaises(frames.FramePreparationError):
            reader.feed(line(request()), epoch=EPOCH, now=1)
        self.assertTrue(reader.snapshot().closed)
        work = consumer.next_decision(now=1)
        self.assertEqual(work.correlation.epoch, "EXAMPLE-moved")
        self.assertFalse(consumer._closed)

    def test_configuration_bounds_and_read_callables_are_refused(self):
        for name, maximum in (("max_frame_bytes", 65536), ("max_chunk_bytes", 65538),
                              ("max_total_bytes", 16777216), ("max_frames", 4096)):
            for value in (True, 0, maximum + 1):
                consumer, _ = harness()
                with self.assertRaises(frames.FramePreparationError) as caught:
                    frames.FakeFrameReader(consumer, **{name: value})
                self.flags(caught.exception)
        with patch("builtins.open", side_effect=RuntimeError("EXAMPLE read guard")) as read:
            with self.assertRaises(frames.FramePreparationError):
                frames.FakeFrameReader(read)
            read.assert_not_called()

    def test_depth_scanner_visits_unfinished_text_once(self):
        visits = [0]
        class CountedText(str):
            def __iter__(self):
                for character in super().__iter__():
                    visits[0] += 1
                    yield character
        text = CountedText('{"id":1,"result":"EXAMPLE ' + '\\"' * 128)
        frames._check_depth(text)
        self.assertEqual(visits[0], len(text))

    def test_escaped_quotes_and_escape_parity_keep_json_diagnostics(self):
        brackets = "{[" * 24 + "]}" * 24
        for count in range(8):
            with self.subTest(count=count):
                value = 'EXAMPLE "' + brackets + '"' + "\\" * count
                consumer, reader = harness()
                batch = reader.feed(line({"id": 1, "result": value}), epoch=EPOCH, now=0)
                self.assertEqual(json.loads(batch.delivered[0].frame_json)["result"], value)
                self.assertIsNone(consumer.next_decision(now=0))
                raw = (b'{"id":1,"result":"EXAMPLE ' + brackets.encode("ascii")
                       + b"\\" * count + b'"}\n')
                consumer, reader = harness()
                if count % 2:
                    with patch.object(frames.json, "loads", wraps=json.loads) as parser:
                        self.failure(consumer, reader, raw, code="invalid-json-or-native-limit")
                    parser.assert_called_once()
                else:
                    batch = reader.feed(raw, epoch=EPOCH, now=0)
                    decoded = json.loads(batch.delivered[0].frame_json)["result"]
                    self.assertEqual(decoded, "EXAMPLE " + brackets + "\\" * (count // 2))

    def test_lexical_container_boundary_preserves_empty_container_positive(self):
        consumer, reader = harness()
        raw = b'{"id":1,"result":' + b"[" * 16 + b"]" * 16 + b"}\n"
        batch = reader.feed(raw, epoch=EPOCH, now=0)
        self.assertIsInstance(batch.delivered[0], prep.Response)
        self.assertEqual(batch.status.delivered_frames, 1)
        consumer, reader = harness()
        raw = b'{"id":1,"result":' + b"[" * 17 + b"]" * 17 + b"}\n"
        with patch.object(frames.json, "loads") as parser:
            self.failure(consumer, reader, raw, code="message-size-or-depth")
        parser.assert_not_called()

    def check_complete_long_escaped_string(self):
        """Run the legal scalar control only in the bounded Python child."""
        consumer, reader = harness()
        raw = b'{"id":1,"result":"' + b'\\"' * 8192 + b'"}\n'
        batch = reader.feed(raw, epoch=EPOCH, now=0)
        self.flags(batch)
        self.flags(batch.status)
        self.assertEqual(len(batch.delivered), 1)
        self.assertIsInstance(batch.delivered[0], prep.Response)
        decoded = json.loads(batch.delivered[0].frame_json)["result"]
        self.assertEqual(len(decoded), 8192)
        self.assertEqual(decoded.count('"'), 8192)
        self.assertEqual(batch.status.received_bytes, len(raw))
        self.assertEqual(batch.status.completed_frames, 1)
        self.assertEqual(batch.status.delivered_frames, 1)
        self.assertEqual(batch.status.buffered_bytes, 0)
        self.assertFalse(batch.status.closed)
        self.assertIsNone(consumer.next_decision(now=0))
        self.assertEqual(consumer.drain_replies(now=0), ())
        reader.eof(epoch=EPOCH, now=0)
        self.closed(consumer)

    def check_unfinished_long_escaped_strings(self):
        """Contain parser stalls in the bounded child with real EOF cleanup."""
        prefix = line(request()) + line(
            {"id": "EXAMPLE-unsupported", "method": "EXAMPLE/unsupported", "params": {}},
        )
        for index, tail in enumerate((b'\\"' * 30000, b"\\" * 60000, b"\\" * 59999)):
            unfinished = b'{"id":2,"result":"' + tail + b"\n"
            for same_call in (False, True):
                with self.subTest(index=index, same_call=same_call):
                    consumer, reader = harness()
                    if not same_call:
                        batch = reader.feed(prefix, epoch=EPOCH, now=0)
                        self.assertEqual(len(batch.delivered), 2)
                    raw = (prefix if same_call else b"") + unfinished
                    with patch.object(consumer, "eof", wraps=consumer.eof) as closing:
                        error = self.failure(
                            consumer, reader, raw, code="invalid-json-or-native-limit",
                            prefix=2 if same_call else 0, total=2,
                        )
                    closing.assert_called_once_with(now=0)
                    self.assertEqual(error.status.received_bytes, len(prefix) + len(unfinished))
                    self.assertEqual(error.status.completed_frames, 3)
                    self.assertEqual(len(consumer._entries), 2)
                    self.assertNotIn((int, 2), consumer._entries)
                    self.assertTrue(consumer._callbacks)


class FrameCostCase(NamedTuple):
    original: str
    check: str


class ServerRequestFrameReaderCostTests(unittest.TestCase):
    def run_bounded_check(self, name):
        child = (
            "import sys, unittest\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import test_server_request_frame_preparation as checks\n"
            "suite = unittest.TestSuite(\n"
            "    checks.ServerRequestFramePreparationTests(name)\n"
            "    for name in ('test_named_positive_effect_guards', sys.argv[2]))\n"
            "result = unittest.TextTestRunner(verbosity=0).run(suite)\n"
            "sys.exit(not result.wasSuccessful())\n"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", child, str(ROOT / "tests"), name],
            cwd=ROOT, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_escaped_string_child_bound_rows(self):
        rows = (
            FrameCostCase('test_complete_long_escaped_string_within_child_bound', "check_complete_long_escaped_string"),
            FrameCostCase('test_unfinished_long_escaped_strings_within_child_bound', "check_unfinished_long_escaped_strings"),
        )
        for row in rows:
            with self.subTest(original=row.original):
                self.run_bounded_check(row.check)


if __name__ == "__main__":
    unittest.main()
