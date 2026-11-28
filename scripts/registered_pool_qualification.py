"""Protected runtime for an original ordinary contained pool cohort."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from threading import Event, Lock, Thread, current_thread
from time import monotonic, monotonic_ns, sleep
from types import MethodType
from typing import Any

from cwo_core import native_live_availability, server_request_preparation as protocol
from cwo_core.beads import run_bd_structured
from cwo_core.native_control import build_control_turn_contract
from cwo_core.native_pool_admission import (
    BeadsClaimAdapter,
    FixedCohortAdmissionCapability,
    PoolAdmissionReservation,
    build_admission_child_binding,
    validate_reservation_receipt,
)
from cwo_core.native_pool_config import build_pool_contract
from cwo_core.native_pool_contracts import (
    POOL_POLL_INTERVAL_MS,
    canonical_sha256,
    validate_capability_receipt,
    write_private_artifact,
    zero_usage,
)
from cwo_core.native_pool_deferred_attestation import writer_arguments_match
from cwo_core.native_pool_deferred_context import DeferredAttestationError
from cwo_core.native_pool_leases import PoolLeaseRegistry
from cwo_core.native_pool_preflight import effective_child_packet_sha256, run_pool_preflight
from cwo_core.native_pool_transaction import (
    PLAN_VERSION,
    AdmittedPoolLaunch,
    NativePoolTransactionError,
    TransactionJournal,
    TransactionRuntime,
    validate_transaction_plan,
)
from cwo_core.native_pool_workspace import PoolWorkspaceMonitor, capture_workspace_snapshot
from cwo_core.native_session_boundary import (
    NativeSessionBoundaryError,
    NativeSessionPartialRecordError,
    assert_prefix_intact,
    capture_boundary,
    locate_unique_session,
    record_indices,
    session_source_identity,
    trusted_terminal_event,
    trusted_turn_context,
)
from cwo_core.supervision.transport.app_server import (
    AppServerError,
    _QUALIFICATION_RPC,
    _checked_native_frame,
    _qualification_wire_guard,
)
from cwo_core.supervision.transport.private_io import load_private_bytes
from cwo_core.policy_schema import strict_json_loads
from prepare_server_request_frames import _decode as decode_protocol_frame
from registered_app_server_transport import RegisteredAppServer
from registered_finite_tool_calls import FiniteToolError, QualifiedToolEvidence, RegisteredFiniteToolCalls
from registered_n1_factory import _DeadlineInput
from registered_n1_qualification import EFFORT, FINITE_TOOL_NAMESPACE, LOGIN_MOUNT, MODEL, TIER
from registered_host_root_boundary import require_private_roots
from registered_pool_configuration import PoolContainmentError, WRITER_TOOL
from registered_pool_containment import _calibration_close_phase
from registered_server_requests import RegisteredServerRequests


_START_RPCS = frozenset({"thread/start", "turn/start"})
_CONTROL_RPCS = frozenset({"turn/interrupt", "thread/archive"})
_ROLLOUT_BYTES = 8_388_608
_ROLLOUT_RECHECK_SECONDS = .01
_CALLBACK_REPLY_BYTES = 4096
_ORDINARY_SCOPE = "stock-codex-registered-contained-pool"
_ORDINARY_MODE = "ordinary"
_CALIBRATION_MODE = "callback-calibration"
_CALIBRATION_REFUSAL = b"The registered writer is closed during callback calibration."
_OPPORTUNITY_FIELD = "capability_opportunity_sha256"
_AUTHORITY_FIELDS = frozenset({
    "scope", "mode", "fixture_root", "journal_path", "control_root", "spools", "host", "artifacts",
    "reservation_sha256", "render_request", "preflight_template", "release_artifacts",
    "readiness_evidence", "work_estimates", "initial_states", "beads",
})
_HOST_FIELDS = frozenset({"executable", "executable_sha256", "launcher", "launcher_sha256",
                          "validator", "validator_sha256"})


class PoolQualificationAdapterError(ValueError):
    """The original qualification authority, observation or settlement differed."""


class _CompleteRolloutGrowth(PoolQualificationAdapterError):
    """The owned file grew beyond a complete, strictly parsed boundary."""

    def __init__(self, boundary, source_identity_sha256):
        super().__init__("pool-qualification-adapter-rollout-drift")
        self.prefix = {key: boundary[key] for key in ("byte_offset", "boundary_sha256")}
        self.source_identity_sha256 = source_identity_sha256


_TRANSPORT_FAILURE_TYPES = {kind: kind.__name__ for kind in (
    AppServerError, DeferredAttestationError, FiniteToolError, NativePoolTransactionError,
    NativeSessionBoundaryError, PoolContainmentError, PoolQualificationAdapterError,
    TimeoutError, protocol.PreparationError,
)} | {NativeSessionPartialRecordError: NativeSessionBoundaryError.__name__}
_TRANSPORT_FAILURE_SOURCES = frozenset({
    "effect-write", "protocol-read", "registered-reply", "request-ingress", "writer-callback",
})


def _require(condition, reason):
    if not condition:
        raise PoolQualificationAdapterError("pool-qualification-adapter-" + reason)


def _digest(data):
    return sha256(data).hexdigest()


def _regular_rollout_stamp(path, *, allow_empty=False):
    info = path.lstat()
    minimum = 0 if allow_empty else 1
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and not info.st_mode & 0o022 and minimum <= info.st_size <= _ROLLOUT_BYTES, "rollout-custody")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _capture_rollout(path, thread_id, *, baseline=None, allow_empty=False, observe_growth=False):
    allow_empty = allow_empty and (baseline is None or baseline["byte_offset"] == 0)
    stamp = _regular_rollout_stamp(path, allow_empty=allow_empty)
    source = session_source_identity(path, thread_id)
    if stamp[2] == 0:
        # Bind the empty file even if Codex starts filling it during this observation.
        boundary = {"byte_offset": 0, "record_count": 0, "boundary_sha256": _digest(b""), "token_snapshot": None}
        records = []
        same_stamp = stamp[:2] == _regular_rollout_stamp(path, allow_empty=True)[:2]
    else:
        boundary, records = capture_boundary(path, thread_id, baseline=baseline)
        after = _regular_rollout_stamp(path)
        if observe_growth and stamp[:2] == after[:2] and stamp[2] <= boundary["byte_offset"] < after[2]:
            _require(source == session_source_identity(path, thread_id), "rollout-drift")
            raise _CompleteRolloutGrowth(boundary, source)
        same_stamp = stamp == after
    _require(same_stamp and source == session_source_identity(path, thread_id),
             "rollout-drift")
    return {**boundary, "source_identity_sha256": source}, records


@dataclass(frozen=True, slots=True)
class _PendingWriter:
    request_id: int | str
    params_json: str
    request_sha256: str

    @property
    def params(self) -> dict[str, Any]:
        """Read a copy of the parameters validated from the original frame."""
        return json.loads(self.params_json)


class _ObservedInput(_DeadlineInput):
    def fileno(self):
        return self.descriptor


class _WorkerWire(RegisteredAppServer):
    """One original app-server connection with a fixed one-shot callback."""

    def __init__(self, worker):
        from registered_pool_containment import PoolWorkerContainment

        _require(type(self) is _WorkerWire and type(worker) is _PoolWorker and type(worker.parent) is _PoolParent
                 and type(worker.containment) is PoolWorkerContainment, "original-wire-owner-required")
        self.factory = worker
        self.transport_failure = None
        self._transport_failure_lock = Lock()
        self._transport_failure_observation = None
        self.thread_id = self._wire_turn = self._pending = None
        self._items = {}
        self._sent = {}
        self._replies = {}
        self._request_ids = set()
        self._response_ids = set()
        self.marker = self.terminal = None
        self._callback_thread = None
        self._retiring = Event()
        self.requests = RegisteredServerRequests(self)
        self.qualified_tool_evidence = QualifiedToolEvidence(self)
        super().__init__(requested_model=MODEL, reasoning_effort=EFFORT)

    def _default_executable(self):
        return self.factory.containment.spec["executable"]

    def _requested_home(self):
        return LOGIN_MOUNT

    def _launch_process(self, command, environment):
        _require(command == [self._default_executable(), "app-server", "--stdio"], "launch-command")
        process = self.factory.containment.launch_appserver()
        self.lifetime = self.factory.containment._appserver
        _require(self.lifetime.process is process, "original-process-custody")
        _containment_observation(self.factory.containment, "appserver-contained", readonly=True,
                                 network="registered-provider-tunnel", login=True)
        process.stdin = _ObservedInput(process.stdin, self._fail_transport)
        return process

    def _prepare_rpc_state(self):
        super()._prepare_rpc_state()
        _QUALIFICATION_RPC.register(self, (self.factory.require_effect, self._check_effect_rpc, TIER))

    def _check_effect_rpc(self, method, frame):
        self.factory.require_effect()
        _require(type(frame.get("id")) is int and method not in self._sent, "effect-rpc-replay")
        if method == "thread/start":
            self.factory.containment.require_thread_start(frame["params"])
        else:
            _require(set(self._sent) == {"thread/start"} and self.thread_id is not None, "turn-before-thread")
            self.factory.containment.require_turn_selectors(frame["params"], thread_id=self.thread_id)
            _require(frame["params"] == self.factory.turn_parameters(), "turn-input-drift")

    def verify_profile_guard(self):
        """Check the bound pre-write guard with a widened selector kept on the host."""
        method = "turn/start"
        params = self.factory.turn_parameters()
        frame = {"id": self._request_id + 1, "method": method, "params": params}
        _qualification_wire_guard(self, method, frame)
        widened = {**frame, "params": {**params, "permissions": ":workspace-write"}}
        try:
            _qualification_wire_guard(self, method, widened)
        except PoolContainmentError as failure:
            _require(str(failure) == "Unexpected qualification turn selectors.", "wrong-profile-guard-refusal")
            return True
        return False

    def request(self, method, params, *, timeout=30):
        _require(method in _START_RPCS | _CONTROL_RPCS | {"initialize"}, "rpc-unavailable")
        self.factory.require_effect()
        if method in _CONTROL_RPCS:
            expected = {"threadId": self.thread_id}
            if method == "turn/interrupt":
                expected["turnId"] = self.factory.turn_id
            _require(params == expected and all(expected.values()), "control-rpc-binding")
        return super().request(method, params, timeout=min(timeout, self.factory.remaining()))

    def _write_payload(self, payload, *, method, timeout):
        _require(method not in self._sent, "one-shot-rpc-replayed")
        return super()._write_payload(payload, method=method, timeout=min(timeout, self.factory.remaining()))

    def notify(self, method, params):
        _require(method == "initialized" and params == {}, "notification-unavailable")
        return super().notify(method, params)

    def _write_wire_bytes(self, fd, frame, deadline, method, binding):
        writer = self.process.stdin
        while not writer._lock.acquire(blocking=False):
            remaining = deadline - monotonic()
            if remaining <= 0:
                self._write_fault("pool-qualification-protocol-writer-busy")
            self._condition.wait(min(.01, remaining))
        try:
            writer.flush()
            super()._write_wire_bytes(fd, frame, deadline, method, binding)
        finally:
            writer._lock.release()
        if method in _START_RPCS | _CONTROL_RPCS:
            message = decode_protocol_frame(frame)
            _require(method not in self._sent, "observed-effect-rpc-repeated")
            self._sent[method] = (message["id"], _digest(frame))

    def _checked_write_frame(self, binding, frame, deadline, method):
        try:
            if method == "turn/start" and self.factory.patch_mode:
                from registered_contained_pool_host import require_patch_preimage

                require_patch_preimage(self.factory.parent._ordinary.children[self.factory.child_id], deadline=deadline)
            return _checked_native_frame(binding, frame, deadline, method)
        except Exception as failure:
            self._fail_transport(failure, source="effect-write")
            raise

    def _write_fault(self, reason):
        failure = AppServerError(reason)
        self._fail_transport(failure, source="effect-write")
        raise failure

    def exchange(self, method):
        with self._condition:
            request_id, request_digest = self._sent[method]
            result, response_digest = self._replies[request_id]
            return deepcopy(result), {"request_id": request_id, "request_sha256": request_digest,
                                      "response_sha256": response_digest}

    def _protocol_lines(self):
        total = 0
        try:
            for line in self._bounded_protocol_lines():
                raw = line.encode("utf-8")
                total += len(raw)
                _require(total <= 8_388_608, "protocol-byte-limit")
                message = decode_protocol_frame(raw)
                self._ingress = protocol.classify_message(message), _digest(raw)
                if type(self._ingress[0]) is protocol.Response:
                    with self._condition:
                        self._observe_response(message, self._ingress[1])
                yield line
                if self.transport_failure is not None:
                    return
            _require(self._retiring.is_set(), "process-ended-before-cleanup")
        except Exception as failure:
            self._fail_transport(failure, source="protocol-read")

    def _observe_response(self, message, digest):
        request_id = message["id"]
        _require(type(request_id) is int and 0 < request_id <= self._request_id
                 and request_id not in self._response_ids, "response-binding")
        self._response_ids.add(request_id)
        observed = dict(self._sent.values())
        if request_id > 1:
            _require(request_id in observed, "response-before-physical-write")
        result = message.get("result")
        if request_id in observed and type(result) is dict:
            self._replies[request_id] = deepcopy(result), digest
        if request_id == self._sent.get("turn/start", (None,))[0] and "error" not in message:
            turn = result.get("turn") if type(result) is dict else None
            _require(type(turn) is dict and protocol._text(turn.get("id")) and turn.get("status") == "inProgress"
                     and turn.get("items") == [] and self._wire_turn is None, "turn-acknowledgement")
            self._wire_turn = self.thread_id, turn["id"], request_id

    def _receive_method(self, message):
        try:
            if "id" in message:
                self._receive_request(message)
            else:
                self._observe_notification(message)
        except Exception as failure:
            self._fail_transport(failure, source="request-ingress")

    def _receive_request(self, message):
        key = protocol._id_key(message["id"])
        _require(key not in self._request_ids and len(self._request_ids) < 64, "server-request-replay")
        self._request_ids.add(key)
        if message["method"] != "item/tool/call":
            self.requests.receive(message)
            return
        pending = self._take_writer(message)
        thread = Thread(target=self._run_callback, args=(pending,), daemon=True, name="cwo-pool-writer-callback")
        thread.start()
        self._callback_thread = thread

    def _take_writer(self, message):
        request, params = RegisteredFiniteToolCalls._params(
            message, namespace=FINITE_TOOL_NAMESPACE, permitted_tools=(WRITER_TOOL,))
        _require(writer_arguments_match(params["arguments"], patch_mode=self.factory.patch_mode), "writer-policy")
        classified, digest = self._ingress
        _require(request == classified, "callback-without-original-frame")
        identity = self._identity(params)
        with self.requests.lock:
            item = self._items.get(identity, {})
            _require(self._pending is None and self._turn_is_open(identity[:2])
                     and item.get("type") == "dynamicToolCall" and item.get("status") == "inProgress"
                     and item.get("namespace") == params["namespace"] and item.get("tool") == params["tool"]
                     and item.get("arguments") == params["arguments"], "callback-without-original-item")
            self._pending = _PendingWriter(request.request_id, request.params_json, digest)
            self.qualified_tool_evidence.admit(request, params)
            return self._pending

    @staticmethod
    def _identity(params):
        return params["threadId"], params["turnId"], params["callId"]

    def _turn_is_open(self, turn):
        return (self._wire_turn is not None and self._wire_turn[:2] == turn and not self._retiring.is_set()
                and not self.requests.refusal_only and self.qualified_tool_evidence._completion_turn_open(turn))

    def _require_pending(self, pending):
        identity = self._identity(pending.params)
        _require(self._pending is pending and self._turn_is_open(identity[:2])
                 and identity not in self.requests.completed_items and self.process.poll() is None,
                 "callback-no-longer-pending")

    def _calibration_reply_revoked(self, pending):
        identity = self._identity(pending.params)
        wire = self._wire_turn
        call = self.qualified_tool_evidence.calls.get(identity)
        return (self.factory.parent.calibration_only and self._pending is pending
                and wire is not None and wire[:2] == identity[:2] == self.requests.cancelled_turn
                and call is not None and call.epoch == self.connection_epoch_sha256
                and call.request_key == protocol._id_key(pending.request_id)
                and not self.requests.closed and not self.requests.refusal_only and not self._retiring.is_set()
                and self.transport_failure is None and self.process.poll() is None)

    def _observe_notification(self, message):
        method, params = message["method"], message["params"]
        item = params.get("item", {})
        if method == "item/completed":
            self._observe_completion(params, item)
        elif method == "turn/completed":
            self._observe_terminal(params)
        self.requests.observe(message)

    def _observe_completion(self, params, item):
        if item.get("type") == "dynamicToolCall":
            with self.requests.lock:
                if not self._revoked_calibration_completion(params, item):
                    self.qualified_tool_evidence.complete(params, item)
        elif item.get("type") == "agentMessage" and item.get("phase") == "final_answer":
            turn = params.get("threadId"), params.get("turnId")
            with self.requests.lock:
                _require(self._turn_is_open(turn) and self.marker is None and type(item.get("text")) is str,
                         "final-marker-binding")
                self.marker = item["text"]

    def _revoked_calibration_completion(self, params, item):
        identity = params.get("threadId"), params.get("turnId"), item.get("id")
        pending = self._pending
        if (self.terminal is not None or pending is None or identity != self._identity(pending.params)
                or not self._calibration_reply_revoked(pending)):
            return False
        call = self.qualified_tool_evidence.calls[identity]
        text = _CALIBRATION_REFUSAL.decode("utf-8")
        _require(call.reply_sent and not call.reply_failed and call.reply == (False, text)
                 and not call.completed and identity not in self.requests.completed_items
                 and item.get("status") == "failed" and item.get("success") is False
                 and item.get("contentItems") == [{"type": "inputText", "text": text}]
                 and all(item.get(key) == pending.params[key] for key in ("namespace", "tool", "arguments")),
                 "revoked-calibration-completion-drift")
        # An exact acknowledgment can race the local interrupt. It has no positive
        # completion authority once the turn was revoked.
        return True

    def _observe_terminal(self, params):
        turn = params.get("turn", {})
        with self.requests.lock:
            identity = params.get("threadId"), turn.get("id")
            _require(self._wire_turn is not None and identity == self._wire_turn[:2] and self.terminal is None,
                     "terminal-binding")
            self.qualified_tool_evidence.observe_turn_terminal(params)
            self.terminal = turn.get("status")
            _require(self.terminal in {"completed", "interrupted", "failed"}, "terminal-status")

    def _decision(self, method, params):
        return "decline"

    def _run_callback(self, pending):
        try:
            calibrating = self.factory.parent.calibration_only
            if calibrating:
                result = self.factory.refuse_calibration_write()
            else:
                result = self.factory.write(pending)
            self._commit_callback_reply(pending, result, success=not calibrating)
        except Exception as failure:
            self._fail_transport(failure, source="writer-callback")

    def _commit_callback_reply(self, pending, output, *, success):
        response = {"id": pending.request_id, "result": {
            "contentItems": [{"type": "inputText", "text": output.decode("utf-8")}], "success": success}}
        frame = (json.dumps(response, separators=(",", ":")) + "\n").encode()
        _require(len(frame) <= _CALLBACK_REPLY_BYTES, "callback-reply-byte-limit")
        request = {"id": pending.request_id, "params": pending.params}
        writer = self.process.stdin
        while self.factory.remaining() > 0:
            self.factory.require_effect()
            with self._condition:
                if not getattr(self, "_wire_writing", False) and writer._lock.acquire(blocking=False):
                    try:
                        if self._try_reply(writer, frame, request, response, pending):
                            return
                    finally:
                        writer._lock.release()
                self._condition.wait(min(.01, self.factory.remaining()))

    def _try_reply(self, writer, frame, request, response, pending):
        with self.requests.lock:
            # The exact writer-held calibration callback loses the right to reply when
            # the original controller interrupts. No reply or effect was attempted.
            if self._calibration_reply_revoked(pending):
                return True
            self._require_pending(pending)
            writer.flush()
            evidence = self.qualified_tool_evidence
            call = evidence.begin_reply(request, response, self.factory.limits.deadline)
            try:
                _require(os.write(writer.descriptor, frame) == len(frame), "non-atomic-callback-reply")
            except (BlockingIOError, InterruptedError):
                evidence.cancel_reply(call)
                return False
            except BaseException:
                evidence.finish_reply(call, False)
                raise
            evidence.finish_reply(call, True)
            return True

    def _fail_transport(self, failure, *, source="registered-reply"):
        with self._condition:
            self._publish_transport_failure(failure, source=source)
            self._condition.notify_all()

    def _publish_transport_failure(self, failure, *, source="registered-reply"):
        # The wire condition and reply registry can publish independently.
        with self._transport_failure_lock:
            if self.transport_failure is None:
                self.transport_failure = failure
                if not self._retiring.is_set():
                    self._transport_failure_observation = (source, type(failure), datetime.now(timezone.utc))
        self._reader_error = "pool-qualification-original-wire-failed"

    def take_transport_failure_observation(self):
        """Consume the diagnostic once, after the original containment attempted close."""
        with self._transport_failure_lock:
            observation = self._transport_failure_observation
            self._transport_failure_observation = None
        if observation is None:
            return None
        source, kind, observed_at = observation
        return {"source": source if source in _TRANSPORT_FAILURE_SOURCES else "unknown",
                "error_type": _TRANSPORT_FAILURE_TYPES.get(kind, "unknown"),
                "observed_at": observed_at.isoformat(timespec="milliseconds")}

    def close(self, cutoff=None):
        """Close the original containment and check every local reader has stopped."""
        if cutoff is None:
            cutoff = monotonic() + 1
        with self._close_lock:
            self._closing = True
            with self._transport_failure_lock:
                self._retiring.set()
            _QUALIFICATION_RPC.pop(self, None)
            try:
                with _calibration_close_phase("protocol_close_us"):
                    self.requests.close()
            finally:
                try:
                    receipt = self.factory.containment.close()
                finally:
                    with _calibration_close_phase("protocol_close_us"):
                        closed = self._join_protocol_threads(cutoff)
            return {"all_contained": receipt.get("cleanup_confirmed") is True,
                    "resources_closed": closed, "errors": [] if closed else ["protocol-reader-still-running"]}

    def _join_protocol_threads(self, cutoff):
        for reader in self._reader_threads:
            if reader is not current_thread() and reader.ident is not None:
                reader.join(max(0, cutoff - monotonic()))
        threads = list(self.requests.threads)
        if self._callback_thread is not None:
            threads.append(self._callback_thread)
        for thread in threads:
            if thread is not current_thread():
                thread.join(max(0, cutoff - monotonic()))
        return not any(thread.is_alive() for thread in (*self._reader_threads, *threads))


def _containment_observation(containment, stage, *, readonly, network, login):
    observations = [row["observation"] for row in containment.receipt()["observations"] if row["stage"] == stage]
    expected = {"filesystem_ready": True, "worktree_readonly": readonly, "network": network,
                "managed_login_projection": login}
    _require(len(observations) == 1 and all(observations[0].get(key) == value for key, value in expected.items()),
             "original-containment-receipt-required")


class _PoolWorker:
    """An original pending callback and the host lifetime that can fulfill it."""

    def __init__(self, parent, child, task, worktree, spool, login_slot):
        self.parent, self.child, self.task = parent, child, task
        self._patch_preimage_sha256 = task.get("patch_preimage_sha256")
        self.worktree, self.spool, self.login_slot = worktree, spool, login_slot
        self.child_id = child["child_id"]
        self.containment = self.wire = None
        self.thread_id = self.turn_id = None
        self._rollout = self._startup = self._startup_prefix = self._writer_prefix = None
        self._calibration_prefix = None
        self._turn_ready = Event()
        self._result = self._archived = None
        self._start_ns = self._end_ns = None
        self._writer_done = False
        self._writer_authorization = None
        self._widening_refused = None

    @property
    def limits(self):
        return self.parent.limits

    @property
    def patch_mode(self) -> bool:
        return self._patch_preimage_sha256 is not None

    def _writer_selection(self) -> tuple[str | None, str | None]:
        expected, preimage = self.task["expected_utf8"], self._patch_preimage_sha256
        if self.patch_mode:
            _require(expected is None and type(preimage) is str and re.fullmatch(r"[0-9a-f]{64}", preimage) is not None,
                     "patch-writer-task-invalid")
        else:
            _require(type(expected) is str, "fixed-writer-task-invalid")
        return expected, preimage

    @property
    def production_login_home(self) -> Path:
        ordinary = self.parent._ordinary
        selected = ordinary.children.get(self.child_id)
        _require(selected is not None and isinstance(selected.login_home, Path),
                 "original-production-login-required")
        home = _private_path(selected.login_home)
        details = home.lstat()
        _require((details.st_dev, details.st_ino) == selected.login_identity and stat.S_ISDIR(details.st_mode)
                 and details.st_uid == os.geteuid() and stat.S_IMODE(details.st_mode) == 0o700,
                 "original-production-login-custody-drift")
        return home

    def remaining(self):
        return self.limits.remaining()

    def require_effect(self):
        _require(type(self.parent) is _PoolParent and self.parent.workers.get(self.child_id) is self,
                 "original-worker-not-retained")
        self.parent.require_effect()
        if self.wire is not None:
            _require(not self.wire._retiring.is_set() and self.wire.transport_failure is None,
                     "worker-wire-no-longer-available")

    def record(self, stage, observation):
        # Approval records contain only the original declined method and ID.
        self.containment.record(stage, {key: observation[key] for key in ("id", "method", "decision")})

    def start(self):
        from registered_pool_containment import PoolWorkerContainment

        self.require_effect()
        expected_utf8, patch_preimage_sha256 = self._writer_selection()
        identity = canonical_sha256(capture_workspace_snapshot(self.worktree, allowed_paths=self.child["write_paths"])["identity"])
        _require(identity == self.child["worktree_identity_sha256"], "worker-worktree-identity-drift")
        self.limits.before_session(self.child_id)
        self.parent.session_attempted()
        self.containment = PoolWorkerContainment(
            worker_id=self.child_id, worktree=self.worktree, spool=self.spool, login_slot=self.login_slot,
            protected_roots=self.parent.protected_roots, write_path=self.task["write_path"],
            expected_utf8=expected_utf8, patch_preimage_sha256=patch_preimage_sha256,
            require_effect=self.require_effect, peer_worktrees=self._peer_worktrees(),
            **self.parent.host_inputs,
        )
        self.wire = _WorkerWire(self)
        selectors = self.containment.thread_start_selectors()
        response, _ = self.wire.request("thread/start", selectors)
        observed, exchange = self.wire.exchange("thread/start")
        _require(response == observed, "startup-response-drift")
        self.containment.require_thread_readback(response)
        thread = response["thread"]
        self.thread_id = self.wire.thread_id = thread["id"]
        self.wire.started_threads[self.thread_id] = None
        self._rollout = self.containment.rollout_path(thread.get("path"), thread_id=self.thread_id)
        self._startup = self._attest_startup(exchange, identity)
        self._widening_refused = self.wire.verify_profile_guard()
        _require(self._widening_refused, "original-profile-widening-refusal-required")
        self.limits.ack_session(self.child_id, self.thread_id)
        return self._startup

    def _peer_worktrees(self):
        return tuple(self.parent._worktree_for(key) for key in self.parent.tasks if key != self.child_id)

    def _read_startup_prefix(self):
        if not os.path.lexists(self._rollout):
            try:
                locate_unique_session(self.spool, self.thread_id)
            except NativeSessionBoundaryError as failure:
                if str(failure) == "trusted session file is missing":
                    return None
                raise
            raise PoolQualificationAdapterError("pool-qualification-adapter-unreported-startup-rollout")
        boundary, rows = self._capture_active_rollout()
        _require(len(rows) == 1 and rows[0]["type"] == "session_meta", "materialized-startup-is-not-preturn")
        self._verify_session_meta(rows)
        return boundary

    def _attest_startup(self, exchange, worktree_identity):
        from cwo_core.native_pool_deferred_attestation import verify_deferred_startup
        from cwo_core.native_pool_deferred_context import QUALIFICATION_PROFILE

        self._startup_prefix = self._read_startup_prefix()
        prefix = self._startup_prefix or {}
        plan = self.parent.plan
        readback = {"thread_id": self.thread_id, "model": MODEL, "effort": EFFORT, "service_tier": TIER,
                    "profile": QUALIFICATION_PROFILE, "worktree": str(self.worktree), "session_path": str(self._rollout),
                    "epoch": self.wire.connection_epoch_sha256, "owner_identity_sha256": self.containment.owner_identity_sha256,
                    "worktree_identity_sha256": worktree_identity, "session_sha256": prefix.get("boundary_sha256"),
                    "session_source_identity_sha256": prefix.get("source_identity_sha256"), "thread_start": exchange}
        return verify_deferred_startup(
            plan, journal=self.parent.journal, child_id=self.child_id, approved_plan_sha256=plan["plan_sha256"],
            trusted_factories={plan["runtime_adapter_path"]: plan["runtime_adapter_sha256"]}, readback=readback,
            worktree=self.worktree, session_path=self._rollout, connection_epoch_sha256=self.wire.connection_epoch_sha256,
            effort=EFFORT, profile=QUALIFICATION_PROFILE, prompt_sha256=self._prompt_sha256(), deadline=self.limits.deadline,
        )

    def _prompt_sha256(self):
        return _digest(self.task["prompt"].encode("utf-8"))

    def turn_parameters(self):
        return {"threadId": self.thread_id, "model": MODEL, "effort": EFFORT, "serviceTier": TIER,
                "input": [{"type": "text", "text": self.task["prompt"], "text_elements": []}]}

    def start_turn(self):
        self.limits.before_turn(self.child_id, self.thread_id)
        self._start_ns = monotonic_ns()
        result, _ = self.wire.request("turn/start", self.turn_parameters())
        observed, exchange = self.wire.exchange("turn/start")
        turn_id = result["turn"]["id"]
        _require(result == observed and self.wire._wire_turn == (self.thread_id, turn_id, exchange["request_id"]),
                 "turn-response-drift")
        self.turn_id = turn_id
        self.wire.started_threads[self.thread_id] = turn_id
        self.limits.ack_turn(self.child_id, self.thread_id, turn_id)
        self._turn_ready.set()
        return turn_id

    def _capture_active_rollout(self, *, baseline=None, allow_empty=False, observe_growth=False):
        located = locate_unique_session(self.spool, self.thread_id, reported_path=self._rollout)
        _require(located.path == self._rollout and located.store == "sessions", "active-rollout-path-drift")
        try:
            boundary, rows = _capture_rollout(located.path, self.thread_id, baseline=baseline,
                                               allow_empty=allow_empty, observe_growth=observe_growth)
        except (NativeSessionPartialRecordError, _CompleteRolloutGrowth) as advance:
            _require(located.source_identity_sha256 == advance.source_identity_sha256, "active-rollout-source-drift")
            raise
        _require(located.source_identity_sha256 == boundary["source_identity_sha256"], "active-rollout-source-drift")
        return boundary, rows

    def _verify_session_meta(self, rows):
        meta = [item.get("payload") for item in rows if item.get("type") == "session_meta"]
        _require(len(meta) == 1 and rows[0].get("type") == "session_meta" and type(meta[0]) is dict
                 and meta[0].get("cwd") == str(self.worktree) and meta[0].get("history_mode") == "legacy",
                 "rollout-session-meta-binding")

    def calibration_context_ready(self):
        self.require_effect()
        _require(self.parent.calibration_only and self.turn_id is not None, "original-calibration-turn-required")
        prefix = self._calibration_prefix or self._startup_prefix
        try:
            boundary, rows = self._capture_active_rollout(baseline=prefix, allow_empty=True)
        except NativeSessionBoundaryError as failure:
            if prefix is not None or os.path.lexists(self._rollout) or str(failure) != "trusted session file is missing":
                raise
            _require(self.wire.terminal is None, "calibration-worker-ended-before-interrupt")
            return False
        _require(prefix is None or boundary["source_identity_sha256"] == prefix["source_identity_sha256"],
                 "calibration-rollout-replaced")
        if rows:
            self._verify_session_meta(rows)
        _require(self.wire.terminal is None and trusted_terminal_event(rows, turn_id=self.turn_id) is None,
                 "calibration-worker-ended-before-interrupt")
        self._calibration_prefix = boundary
        contexts = record_indices(rows, "turn_context")
        if not contexts:
            return False
        _require(len(contexts) == 1, "calibration-turn-context-not-singular")
        trusted_turn_context(rows, turn_id=self.turn_id, model=MODEL, effort=EFFORT)
        return True

    def _capture_pending_rollout(self, pending):
        try:
            return self._capture_active_rollout(baseline=self._startup_prefix, observe_growth=True)
        except (NativeSessionPartialRecordError, _CompleteRolloutGrowth) as advance:
            # This callback may re-observe one append. The strict reader must verify all earlier bytes.
            sleep(min(_ROLLOUT_RECHECK_SECONDS, self.remaining()))
            self._recheck_pending(pending)
            boundary, records = self._capture_active_rollout(baseline=advance.prefix)
            _require(boundary["source_identity_sha256"] == advance.source_identity_sha256,
                     "callback-rollout-replaced")
            self._recheck_pending(pending)
            return boundary, records

    def _attest_turn(self, pending):
        from cwo_core.native_pool_deferred_attestation import attest_deferred_turn

        boundary, records = self._capture_pending_rollout(pending)
        self._verify_session_meta(records)
        index, _ = trusted_turn_context(records, turn_id=self.turn_id, model=MODEL, effort=EFFORT)
        _require(trusted_terminal_event(records, turn_id=self.turn_id) is None, "callback-after-durable-terminal")
        if self._startup_prefix is not None:
            _require(boundary["source_identity_sha256"] == self._startup_prefix["source_identity_sha256"],
                     "startup-rollout-replaced")
        _, startup_wire = self.wire.exchange("thread/start")
        _, turn_wire = self.wire.exchange("turn/start")
        owner, epoch = self.containment.owner_identity_sha256, self.wire.connection_epoch_sha256
        provenance = {"thread_start": startup_wire, "turn_start": {**turn_wire, "turn_id": self.turn_id,
                        "prompt_sha256": self._prompt_sha256()}, "turn_context_index": index,
                      "turn_context": {"turn_id": self.turn_id, "model": MODEL, "effort": EFFORT},
                      "startup_rollout_prefix_sha256": (self._startup_prefix or {}).get("boundary_sha256")}
        evidence = {"thread_id": self.thread_id, "turn_id": self.turn_id, "epoch": epoch,
                    "owner_identity_sha256": owner, "session_path": str(self._rollout),
                    "startup_to_turn": provenance, "terminal_boundary": boundary}
        params = pending.params
        callback = {"request_id": pending.request_id, "request_sha256": pending.request_sha256,
                    "thread_id": params["threadId"], "turn_id": params["turnId"], "epoch": epoch,
                    "owner_identity_sha256": owner, "tool": f"{params['namespace']}.{params['tool']}",
                    "arguments": params["arguments"]}
        acknowledgement = {"child_id": self.child_id, "thread_id": self.thread_id, "turn_id": self.turn_id}
        self._writer_prefix = boundary
        return attest_deferred_turn(self._startup, turn_ack=acknowledgement, evidence=evidence,
                                    pending_callback=callback, patch_mode=self.patch_mode)

    def write(self, pending):
        _require(not self.parent.calibration_only, "calibration-writer-closed")
        _require(self._turn_ready.wait(self.remaining()), "turn-acknowledgement-unavailable")
        self._recheck_pending(pending)
        proof = self._attest_turn(pending)
        self.limits.record_provisional_turn_proof(proof)
        self.limits.charge_tool(self.child_id, self.thread_id, self.turn_id, pending.request_id)
        self._writer_authorization = _PoolWriterAuthorization(self, pending, proof)
        try:
            output = self.containment.run_writer(pending.params["callId"],
                authorize=self._writer_authorization, deadline=self.limits.deadline)
        finally:
            self._writer_authorization = None
        self.limits.ack_tool(self.child_id, self.thread_id, self.turn_id, pending.request_id)
        self._writer_done = True
        return output

    def refuse_calibration_write(self):
        _require(self.parent.calibration_only, "calibration-refusal-outside-calibration")
        _require(self._turn_ready.wait(self.remaining()), "turn-acknowledgement-unavailable")
        # The non-writing reply is checked under the original request lock at commit.
        return _CALIBRATION_REFUSAL

    def calibration_writer_refused(self):
        """Read the original same-turn refusal after its reply and item completion."""
        _require(self.parent.calibration_only, "calibration-refusal-outside-calibration")
        return self._original_writer_refused(_CALIBRATION_REFUSAL)

    def _original_writer_refused(self, refusal):
        wire = self.wire
        if wire is None or self.turn_id is None:
            return False
        with wire.requests.lock:
            pending = wire._pending
            if pending is None:
                return False
            identity = wire._identity(pending.params)
            evidence = wire.qualified_tool_evidence
            call = evidence.calls.get(identity)
            return (identity[:2] == (self.thread_id, self.turn_id) and call is not None
                    and call.reply == (False, refusal.decode("utf-8"))
                    and evidence.completion(identity) == "committed")

    def _recheck_pending(self, pending):
        self.require_effect()
        with self.wire.requests.lock:
            self.wire._require_pending(pending)

    def _authorize_writer(self, pending, proof, release):
        self.require_effect()
        _require(not self.parent.calibration_only, "calibration-writer-closed")
        _containment_observation(self.containment, "tool-contained", readonly=False, network="isolated", login=False)
        stamp = _regular_rollout_stamp(self._rollout)
        assert_prefix_intact(self._rollout, self._writer_prefix)
        source = session_source_identity(self._rollout, self.thread_id)
        with self.wire.requests.lock:
            self.wire._require_pending(pending)
            _require(stamp == _regular_rollout_stamp(self._rollout) and source == proof.session_source_identity_sha256
                     and self.containment.owner_identity_sha256 == proof.startup.owner_identity_sha256
                     and self.wire.connection_epoch_sha256 == proof.startup.connection_epoch_sha256,
                     "writer-gate-custody-drift")
            self.limits.authorize_writer(self.child_id, self.thread_id, self.turn_id, pending.request_id,
                                        pending.request_sha256, release)

    def poll(self):
        self.require_effect()
        # The reader publishes terminal status once under the request lock.
        # A pending writer may hold that lock across its release checks.
        if self.wire.terminal is None:
            return None
        with self.wire.requests.lock:
            terminal = self.wire.terminal
        if self._result is None:
            self._result = self._verify_result(terminal)
            self._end_ns = monotonic_ns()
        return self._result

    def _verify_result(self, status):
        from cwo_core.native_pool_qualification_evidence import observe_worker_tools

        prefix = self._writer_prefix or self._calibration_prefix or self._startup_prefix
        boundary, rows = self._capture_active_rollout(baseline=prefix)
        _require(prefix is None or boundary["source_identity_sha256"] == prefix["source_identity_sha256"],
                 "terminal-source-drift")
        self._verify_session_meta(rows)
        trusted_turn_context(rows, turn_id=self.turn_id, model=MODEL, effort=EFFORT)
        terminal = trusted_terminal_event(rows, turn_id=self.turn_id)
        _require(terminal is not None and terminal["status"] == status, "durable-terminal-missing")
        task_completed = (status == "completed" and not self.parent.calibration_only
                          and self._verify_marker(rows[terminal["record_index"]]["payload"]))
        tools = observe_worker_tools(rows, turn_id=self.turn_id)
        return {"terminal": terminal, "boundary": boundary, "tools": asdict(tools), "task_completed": task_completed}

    def _verify_marker(self, terminal_payload):
        pending = self.wire._pending
        _require(self._writer_done and self._writer_prefix is not None and pending is not None,
                 "successful-terminal-requires-original-writer")
        identity = self.wire._identity(pending.params)
        with self.wire.requests.lock:
            completion = self.wire.qualified_tool_evidence.completion(identity)
            _require(completion == "committed" and self.wire.marker is not None
                     and terminal_payload.get("last_agent_message") == self.wire.marker, "completion-marker-drift")
            return self.wire.marker == self.task["completion_marker"]

    def retained_tools(self):
        from cwo_core.native_pool_qualification_evidence import WorkerToolObservation, observe_worker_tools

        if self._result is not None:
            return self._result["tools"]
        if self.turn_id is None or self._rollout is None:
            return asdict(WorkerToolObservation())
        try:
            prefix = self._writer_prefix or self._calibration_prefix or self._startup_prefix
            source = locate_unique_session(self.spool, self.thread_id)
            boundary, rows = _capture_rollout(source.path, self.thread_id, baseline=prefix)
            _require(prefix is None or boundary["source_identity_sha256"] == prefix["source_identity_sha256"],
                     "retained-tool-rollout-source-drift")
            self._verify_session_meta(rows)
            trusted_turn_context(rows, turn_id=self.turn_id, model=MODEL, effort=EFFORT)
            return asdict(observe_worker_tools(rows, turn_id=self.turn_id))
        except (OSError, ValueError):
            return asdict(WorkerToolObservation())

    def interrupt(self):
        if self.turn_id is None or self.wire.terminal is not None or self.wire.transport_failure is not None:
            return
        self.wire.requests.cancel_turn(self.thread_id, self.turn_id)
        self.wire.interrupt_turn(self.thread_id, self.turn_id, timeout=min(15, self.remaining()))
        response, _ = self.wire.exchange("turn/interrupt")
        _require(response == {}, "interrupt-acknowledgement-drift")

    def archive(self):
        _require(self._archived is None and self.poll() is not None, "archive-without-observed-completion")
        self.wire.archive_thread(self.thread_id)
        response, exchange = self.wire.exchange("thread/archive")
        _require(response == {}, "archive-acknowledgement-drift")
        source = locate_unique_session(self.spool, self.thread_id)
        baseline = self._result["boundary"]
        _require(source.store == "archived_sessions" and source.source_identity_sha256 == baseline["source_identity_sha256"],
                 "archive-did-not-preserve-original-rollout")
        archived, _ = _capture_rollout(source.path, self.thread_id, baseline=baseline)
        _require(archived["source_identity_sha256"] == source.source_identity_sha256, "archive-source-replaced")
        self._archived = exchange

    def close(self, cutoff):
        if self.wire is None:
            return self.containment is None or self.containment.close().get("cleanup_confirmed") is True
        settled = self.wire.close(cutoff)
        if self._start_ns is not None and self._end_ns is None:
            self._end_ns = monotonic_ns()
        return settled["all_contained"] and settled["resources_closed"]


_POOL_WORKER_EFFECT = _PoolWorker.require_effect


@dataclass(frozen=True, slots=True)
class _PoolWriterAuthorization:
    worker: _PoolWorker
    pending: _PendingWriter
    proof: object

    def __call__(self, release):
        self.worker._authorize_writer(self.pending, self.proof, release)


class _WorkerControl:
    """Coordinator callbacks backed by one original worker and state file."""

    def __init__(self, worker, contract):
        self.worker, self.contract = worker, contract

    def callbacks(self):
        return {key: getattr(self, key) for key in
                ("arm", "send_input", "mark_dispatched", "check", "interrupt", "finalize", "close", "sleep")}

    def arm(self, *, state_file, control_turn_id):
        self.worker.require_effect()
        _require((state_file, control_turn_id) == (self.contract["state_file"], self.contract["control_turn_id"]),
                 "control-arm-binding")
        return {"ack": "armed"}

    def send_input(self, *, agent_id, message):
        _require(agent_id == self.worker.thread_id and message == self.worker.task["prompt"], "control-input-binding")
        return {"submission_id": self.worker.start_turn()}

    def mark_dispatched(self, *, submission_id, **_binding):
        _require(submission_id == self.worker.turn_id and self.worker._turn_ready.is_set(), "control-dispatch-binding")

    def check(self, **_binding):
        result = self.worker.poll()
        if result is None:
            return {"decision": "continue"}
        calibrated = self.worker.parent.calibration_only and result["terminal"]["status"] == "interrupted"
        return {"decision": "complete" if result["task_completed"] or calibrated else "interrupt"}

    def interrupt(self, **_binding):
        self.worker.interrupt()

    def finalize(self, *, control_action, **_binding):
        result = self.worker._result
        if self.worker.parent.calibration_only:
            _require(control_action == "interrupt-confirmed" and result is not None
                     and result["terminal"]["status"] == "interrupted", "calibration-interruption-required")
        if control_action == "worker-completed":
            _require(result is not None and result["task_completed"], "control-finalize-without-completion")

    def close(self, **_binding):
        worker = self.worker
        try:
            if worker._result is not None and worker._archived is None:
                with _calibration_close_phase("archive_us"):
                    worker.archive()
        finally:
            worker.parent.cancel_unreleased_cohort()
            _require(worker.close(worker.limits.deadline), "control-close-unconfirmed")
        return {"ack": "closed"}

    def sleep(self, *, seconds):
        sleep(min(seconds, self.worker.remaining()))

    def evidence(self, state_file):
        _require(state_file == self.contract["state_file"], "control-evidence-binding")
        worker = self.worker
        result = worker._result
        session_disposition, artifact_disposition = "accepted-with-warning", "independent-validation-required"
        if result is not None:
            if result["task_completed"]:
                session_disposition, artifact_disposition = "accepted", "accepted"
            elif not worker.parent.calibration_only:
                # The coordinator closes an unsuccessful worker as interrupted.
                session_disposition, artifact_disposition = "quarantined", "rejected"
        # Verified provider counters belong to the terminal rollout boundary.
        # Pool accounting requires stable token availability through settlement.
        usage = zero_usage()
        usage.update(tool_calls=int(worker._writer_done), mutations=int(worker._writer_done))
        if worker._start_ns is not None:
            elapsed = (worker._end_ns or monotonic_ns()) - worker._start_ns
            usage["runtime_seconds"] = (elapsed + 999_999_999) // 1_000_000_000
        return {"state_sha256": canonical_sha256({"terminal": result, "archive": worker._archived}),
                "usage": usage, "protected_fault": False, "control_loss": False, "failure_class": None,
                "recovery_evidence_sha256": None, "reasons": [],
                "session_disposition": session_disposition, "artifact_disposition": artifact_disposition}


def _private_path(raw):
    path = Path(raw)
    _require(path.is_absolute() and path == path.resolve() and path != path.parent, "noncanonical-private-path")
    return path


def _inside(path, root):
    _require(path != root and path.is_relative_to(root), "controller-output-outside-control-root")
    return path


def _private_artifact(path, digest, label):
    data = load_private_bytes(path, label)
    _require(_digest(data) == digest, "protected-artifact-drift")
    return data


def _check_factory_source(plan):
    path = Path(__file__).resolve()
    details = path.lstat()
    _require(Path(plan["runtime_adapter_path"]) == path and stat.S_ISREG(details.st_mode)
             and details.st_uid in (0, os.geteuid()) and details.st_nlink == 1 and not details.st_mode & 0o022
             and _digest(path.read_bytes()) == plan["runtime_adapter_sha256"], "installed-factory-source-drift")


def _read_authority(path, digest):
    contents = _private_artifact(path, digest, "contained-pool-authority")
    value = strict_json_loads(contents.decode("utf-8"))
    _require(type(value) is dict and value.get("scope") == _ORDINARY_SCOPE, "unknown-controller-authority")
    _check_authority_phase(value)
    return value


def _check_authority_phase(value):
    mode = value.get("mode")
    if mode == _ORDINARY_MODE:
        opportunity = value.get(_OPPORTUNITY_FIELD)
        _require(value.keys() == _AUTHORITY_FIELDS | {_OPPORTUNITY_FIELD} and type(opportunity) is str
                 and re.fullmatch(r"[0-9a-f]{64}", opportunity) is not None, "invalid-qualification-authority")
    else:
        _require(mode == _CALIBRATION_MODE and value.keys() == _AUTHORITY_FIELDS, "invalid-calibration-authority")


def _check_admission(admission, authority):
    _require(type(admission) is PoolAdmissionReservation and type(admission.capability) is FixedCohortAdmissionCapability
             and admission.capability.state == "available" and admission.admitted, "original-admission-required")
    _require(type(admission.receipt) is dict and not validate_reservation_receipt(admission.receipt)
             and admission.receipt["reservation_sha256"] == authority["reservation_sha256"], "admission-receipt-drift")
    beads = authority["beads"]
    required_beads = {"directory", "database", "actor"}
    _require(type(beads) is dict and required_beads <= beads.keys() <= required_beads | {"timeout"}, "beads-binding-invalid")
    claim = admission.claim_adapter
    _require(type(claim) is BeadsClaimAdapter and claim._runner is run_bd_structured
             and (str(claim.directory), claim.database, claim.actor, claim.timeout)
                 == (beads["directory"], beads["database"], beads["actor"], beads.get("timeout")),
             "protected-beads-reader-required")


class _PoolParent:
    """One selected source, approved plan and immutable controller inputs."""

    def __init__(self, plan, authority_path, admission, capability, ordinary):
        self.plan = deepcopy(plan)
        self._ordinary = ordinary
        self.authority_path = _private_path(authority_path)
        self.authority = self._read_authority()
        self._capability = capability
        _check_admission(admission, self.authority)
        self.admission = admission
        self.receipt = deepcopy(dict(admission.receipt))
        self.claim_adapter = BeadsClaimAdapter(**self.authority["beads"])
        self.workers, self.controls = {}, {}
        self.limits = None
        self._started = 0
        self._prepare_paths()
        self._prepare_children()
        if self.calibration_only:
            _require(capability is None, "calibration-capability-attachment-refused")
        else:
            self._validate_capability()

    @property
    def calibration_only(self):
        return self.authority["mode"] == _CALIBRATION_MODE

    def _prepare_paths(self):
        settings = self.authority
        fixture = _private_path(settings["fixture_root"])
        root = _private_path(settings["control_root"])
        _require(not (fixture.is_relative_to(root) or root.is_relative_to(fixture)), "fixture-and-control-roots-overlap")
        require_private_roots((fixture, root, self.authority_path.parent))
        details = root.lstat()
        _require(stat.S_ISDIR(details.st_mode) and details.st_uid == os.geteuid() and not details.st_mode & 0o022,
                 "control-root-not-private")
        self.fixture_root, self.control_root = fixture, root
        self.protected_roots = self._controller_roots()
        journal_path = _inside(_private_path(settings["journal_path"]), root)
        self.journal = TransactionJournal(journal_path, self.plan["transaction_id"])
        self.files = {key: root / name for key, name in (("state_file", "pool-state.json"),
            ("decision_file", "pool-decision.json"), ("control_file", "pool-control.json"))}
        self.leases = PoolLeaseRegistry(self._lease_registry_path())

    def _controller_roots(self):
        roots = (self.control_root, self.authority_path.parent)
        return (*roots, self._ordinary.project, self._ordinary.integration_root, self._ordinary.ledger.root,
                self._ordinary.lease_registry_path)

    def _lease_registry_path(self):
        return self._ordinary.lease_registry_path

    def _worktree_for(self, child_id):
        return self._ordinary.children[child_id].worktree

    def _integration_root(self):
        return self._ordinary.integration_root

    def _prepare_children(self):
        children = self.plan["children"]
        self.children = {row["child_id"]: row for row in children}
        self.tasks = self._selected_tasks(children)
        spools = self.authority["spools"]
        _require(type(spools) is dict and spools.keys() == self.children.keys(), "worker-spool-set-drift")
        self.spools = {key: _private_path(value) for key, value in spools.items()}
        self._verify_spool_topology()

    def _selected_tasks(self, children):
        from registered_pool_ordinary_runtime import ordinary_pool_tasks

        return ordinary_pool_tasks(self._ordinary, children, self.authority)

    def _verify_spool_topology(self):
        custody = {spool.parent for spool in self.spools.values()}
        _require(len(custody) == len(self.spools), "worker-spool-custody-reused")
        for root in (self.fixture_root, *self.protected_roots, *custody):
            _require(not any(other != root and (other.is_relative_to(root) or root.is_relative_to(other))
                             for other in custody), "worker-spool-overlap")
        _require(not custody.intersection((self.fixture_root, *self.protected_roots)), "worker-spool-visible-to-parent")
        require_private_roots((*custody, *self.spools.values()))

    def _read_host_inputs(self):
        host = self.authority["host"]
        _require(type(host) is dict and _HOST_FIELDS <= host.keys() <= _HOST_FIELDS | {"model_catalog"}, "host-inputs-invalid")
        inputs = {key: host[key] for key in _HOST_FIELDS}
        if catalog := host.get("model_catalog"):
            path, digest = catalog["path"], catalog["sha256"]
            inputs["model_catalog"] = (_private_artifact(_private_path(path), digest, "contained-pool-catalog"), digest)
        return inputs

    def bind_limits(self, limits):
        from cwo_core.native_pool_deferred_context import _ContainedPoolAdmission
        from cwo_core.native_pool_qualification_stage import PoolQualificationRunLimits

        _require(type(limits) is PoolQualificationRunLimits and self.limits is None, "original-stage-limits-required")
        self._require_stage_mode(limits)
        admission = getattr(limits, "_contained_admission", None)
        _require(type(admission) is _ContainedPoolAdmission and admission._claimed
                 and admission._selection.runtime.start_worker_session.__self__ is self
                 and self._original_stage_custody(limits), "original-contained-stage-limits-required")
        self.limits = limits
        self.require_effect()

    def _require_stage_mode(self, limits):
        _require(self.calibration_only is (getattr(limits, "calibration_only", False) is True),
                 "original-stage-mode-drift")

    def _original_stage_custody(self, limits):
        allowance = limits._allowance
        return allowance.ordinary is self._ordinary

    def require_effect(self):
        native_live_availability.require_registered_contained_pool_live()
        _require(self.limits is not None, "stage-limits-unbound")
        self._require_stage_mode(self.limits)
        self.limits.remaining()
        self.limits._require_intent()

    def cancel_unreleased_cohort(self):
        # A closed worker can no longer contribute to the one-shot barrier.
        # Release the waiting receivers before joining their transport threads.
        if self.calibration_only:
            return
        limits = self.limits
        with limits._condition:
            if not limits._tools_released:
                limits._close_locked()

    def read_bead(self, bead_id):
        native_live_availability.require_registered_contained_pool_live()
        self._ordinary.require_current()
        _require(bead_id in {child["bead_id"] for child in self.children.values()}, "unbound-bead-read")
        return self.claim_adapter.show_exact(bead_id)

    def _verify_artifacts(self):
        _check_factory_source(self.plan)
        observed = self._read_authority()
        _require(observed == self.authority, "retained-authority-drift")
        for name in ("candidate_manifest", "controller_overlay"):
            path = _private_path(self.authority["artifacts"][name])
            _private_artifact(path, self.plan[name + "_sha256"], "contained-pool-" + name)

    def _read_authority(self):
        return _read_authority(self.authority_path, self.plan["authority_sha256"])

    def _validate_capability(self):
        from cwo_core.native_pool_deferred_context import QUALIFICATION_ADAPTER_VERSION, QUALIFICATION_SURFACE
        from registered_pool_qualification_capability import (
            ConnectedPoolCallbackCapability,
            require_connected_callback_capability,
        )

        _require(not self.calibration_only and type(self._capability) is ConnectedPoolCallbackCapability,
                 "original-connected-capability-required")
        receipt = require_connected_callback_capability(self._capability, self, self.authority[_OPPORTUNITY_FIELD])
        _require(not validate_capability_receipt(receipt) and receipt["adapter_version"] == QUALIFICATION_ADAPTER_VERSION
                 and receipt["execution_surface"] == QUALIFICATION_SURFACE
                 and receipt["requested_cap"] == len(self.children), "independent-connected-capability-required")
        return deepcopy(receipt)

    def _validate_policy(self):
        from cwo_core.native_tool_isolation import contained_pool_tool_policy, contained_pool_tool_surface

        rows = self.authority["preflight_template"]["children"]
        _require({row["child_id"] for row in rows} == self.children.keys() and len(rows) == len(self.children),
                 "preflight-child-set-drift")
        for row in rows:
            task = self.tasks[row["child_id"]]
            _require(row.get("tool_policy") == contained_pool_tool_policy()
                     and row.get("tool_surface") == contained_pool_tool_surface()
                     and row.get("prompt") == task["prompt"] and row.get("worktree") == str(self._worktree_for(row["child_id"])),
                     "preflight-contained-policy-drift")

    def _validate_static_admission(self):
        bindings = {row["child_id"]: row for row in self.receipt["child_bindings"]}
        _require(bindings.keys() == self.children.keys(), "admitted-child-set-drift")
        for child_id, child in self.children.items():
            binding = bindings[child_id]
            pinned = ("bead_id", "work_unit_id", "requested_model", "worktree_identity_sha256")
            _require(all(binding[field] == child[field] for field in pinned)
                     and binding == self._derive_admitted_binding(child_id), "admitted-child-before-session-drift")

    def prepare(self, plan):
        self.require_effect()
        _require(plan == self.plan, "approved-plan-drift")
        self._verify_artifacts()
        events = self.journal.read()
        _require(bool(events) and events[0]["details"].get("plan_sha256") == plan["plan_sha256"]
                 and any(row["event_type"] == "qualification-accounting-intent" for row in events), "original-run-journal-required")
        _check_admission(self.admission, self.authority)
        if not self.calibration_only:
            self._validate_capability()
        self._validate_policy()
        self._validate_static_admission()
        self.host_inputs = self._read_host_inputs()
        return {key: plan[key] for key in ("candidate_manifest_sha256", "controller_overlay_sha256",
                                           "authority_sha256", "runtime_adapter_sha256")}

    def release(self, plan, _context, _readiness):
        self.require_effect()
        _require(plan == self.plan, "release-plan-drift")
        self._verify_artifacts()
        return deepcopy(self.authority["release_artifacts"])

    def session_count(self):
        return self._started

    def session_attempted(self):
        self._started += 1

    def start_prelude(self, *_args):
        raise PoolQualificationAdapterError("pool-qualification-adapter-prelude-unavailable")

    def start_worker(self, child, context):
        self.require_effect()
        child_id = child["child_id"]
        _require(self.children.get(child_id) == child and child_id not in self.workers
                 and context["transaction_allocation"]["child_id"] == child_id, "worker-allocation-drift")
        task = self.tasks[child_id]
        worker = _PoolWorker(self, child, task, self._worktree_for(child_id), self.spools[child_id], self._login_slot(task))
        self.workers[child_id] = worker
        return worker.start()

    @staticmethod
    def _login_slot(task):
        return int(task["worker_slot"].rsplit("-", 1)[1])

    def _bind_worker_control(self, render):
        child_id = render["child_id"]
        worker = self.workers[child_id]
        root = self.control_root
        state_file = _inside(_private_path(render["state_file"]), root)
        control_file = _inside(_private_path(render["control_contract_file"]), root)
        _require(state_file != control_file and not os.path.lexists(state_file) and not os.path.lexists(control_file),
                 "controller-artifact-already-present")
        control = build_control_turn_contract(state_file=str(state_file), agent_id=worker.thread_id,
            control_turn_id=render["control_turn_id"], task_sha256=worker._prompt_sha256(), poll_interval_ms=POOL_POLL_INTERVAL_MS)
        ids = {"agent_id": worker.thread_id, "session_id": worker.thread_id}
        state = deepcopy(self.authority["initial_states"][child_id])
        write_private_artifact(state_file, {**state, **ids})
        write_private_artifact(control_file, control)
        self.controls[child_id] = _WorkerControl(worker, control)
        return {**render, **ids}

    def _live_revalidate(self, binding):
        self.require_effect()
        self._verify_artifacts()
        return self._derive_admitted_binding(binding["child_id"])

    def _derive_admitted_binding(self, child_id):
        effective = next(row for row in self.authority["preflight_template"]["children"] if row["child_id"] == child_id)
        worktree = self._worktree_for(child_id)
        scope = self.children[child_id]["write_paths"]
        identity = canonical_sha256(capture_workspace_snapshot(worktree, allowed_paths=scope)["identity"])
        bead_id = self.children[child_id]["bead_id"]
        return build_admission_child_binding(self.authority["readiness_evidence"],
            self.authority["work_estimates"][bead_id], bead_id=bead_id, child_id=child_id,
            packet_id=effective["packet_id"], packet_sha256=effective_child_packet_sha256(effective),
            worktree_identity_sha256=identity)

    def _launch_options(self, contract, capability):
        monitor = PoolWorkspaceMonitor(contract, integration_root=self._integration_root(),
            child_worktrees={key: worker.worktree for key, worker in self.workers.items()})
        guards = {key: worker.containment._workspace_capture_guard for key, worker in self.workers.items()
                  if worker.patch_mode}

        def compare_workspaces(*, contract: Mapping[str, Any], phase: str) -> dict[str, Any]:
            return monitor.compare(contract=contract, phase=phase, child_capture_guards=guards)

        return {**self.files, "lease_registry": self.leases, "claim_adapter": self.claim_adapter,
                "live_revalidate": self._live_revalidate, "capability_receipt": capability,
                "pool_callbacks": {"monotonic_ns": monotonic_ns, "now_utc": lambda: datetime.now(timezone.utc),
                    "sleep": self._pool_sleep, "read_child_evidence": self._child_evidence, "compare_workspaces": compare_workspaces}}

    def _pool_sleep(self, *, seconds):
        sleep(min(seconds, self.limits.remaining()))

    def _child_evidence(self, *, child_id, state_file):
        return self.controls[child_id].evidence(state_file)

    def bind_admitted_launch(self, plan, allocations, _context):
        self.require_effect()
        _require(not self.calibration_only, "calibration-cannot-bind-productive-launch")
        self._require_original_cohort(plan, allocations)
        _check_admission(self.admission, self.authority)
        capability = self._validate_capability()
        render = deepcopy(self.authority["render_request"])
        _require(render["integration_root"] == str(self._integration_root()), "integration-root-drift")
        render["children"] = [self._bind_worker_control(child) for child in render["children"]]
        render["admission_reservation"] = self.receipt
        contract = build_pool_contract(render, capability_receipt=capability, enable_concurrency=True)
        request = self._bind_preflight(contract)
        preflight = run_pool_preflight(request)
        _require(preflight.get("accepted") is True, "original-pool-preflight-refused")
        return AdmittedPoolLaunch(self.receipt, self.admission.capability, contract, request, preflight,
            {key: control.contract for key, control in self.controls.items()},
            {key: task["prompt"] for key, task in self.tasks.items()},
            {key: control.callbacks() for key, control in self.controls.items()}, self._launch_options(contract, capability))

    def _require_original_cohort(self, plan, allocations):
        threads = {key: worker.thread_id for key, worker in self.workers.items()}
        _require(plan == self.plan and not self.controls and len(allocations) == len(self.children)
                 and threads.keys() == self.children.keys() and all(threads.values())
                 and {row["child_id"]: row["session_id"] for row in allocations} == threads,
                 "admitted-startup-set-drift")

    def bind_calibration_controls(self, plan, allocations, _context):
        """Bind the original controls without building a productive dispatch contract."""
        self.require_effect()
        _require(self.calibration_only, "calibration-control-scope-required")
        self._require_original_cohort(plan, allocations)
        self._verify_artifacts()
        self._require_render_children()
        for child in self.authority["render_request"]["children"]:
            self._bind_worker_control(child)
        return dict(self.controls)

    def _require_render_children(self):
        children = self.authority["render_request"]["children"]
        _require(len(children) == len(self.children) and {row["child_id"] for row in children} == self.children.keys(),
                 "control-render-child-set-drift")

    def _bind_preflight(self, contract):
        request = deepcopy(self.authority["preflight_template"])
        request.update(pool_contract=contract, admission_reservation=self.receipt)
        for row in request["children"]:
            thread_id = self.workers[row["child_id"]].thread_id
            row.update(session_id=thread_id, agent_id=thread_id)
        return request

    def cleanup(self, cutoff):
        settled = True
        for worker in self.workers.values():
            try:
                settled = bool(worker.close(cutoff)) and settled
            except Exception:
                settled = False
        return settled

    def contain(self, _started, _reason, _context):
        cutoff = monotonic() + 1
        if self.limits is not None:
            self.limits._close()
        return {"all_contained": self.cleanup(cutoff)}

    def validate(self, launched, _context):
        _require(not self.calibration_only, "calibration-cannot-validate-productive-launch")
        self.cancel_unreleased_cohort()
        settled = self.cleanup(self.limits.deadline)
        workers = {key: self._settlement(worker) for key, worker in self.workers.items()}
        accepted = settled and launched.get("pool_receipt", {}).get("accepting") is True
        accepted = accepted and len(workers) == len(self.children) and all(row["task_completed"] and row["wire_settled"]
                                                                          for row in workers.values())
        validation = {"accepted": accepted, "healthy_evidence_retained": settled, "atomic_promotion_authorized": False,
                      "worker_observations": workers}
        return validation

    @staticmethod
    def _settlement(worker):
        startup = worker._startup
        profile = None if startup is None else {"id": startup.profile,
            "owner_identity_sha256": startup.owner_identity_sha256, "widening_refused": worker._widening_refused}
        return {"archive": worker._archived, "tools": worker.retained_tools(),
                "task_completed": worker._result is not None and worker._result["task_completed"],
                "wire_settled": worker._archived is not None and worker.wire.transport_failure is None,
                "thread_profile": profile,
                "host": None if worker.containment is None else worker.containment.receipt()}

    def runtime(self):
        return TransactionRuntime(self.session_count, self.read_bead, self.prepare, self.start_prelude,
            self.release, self.release, self.start_worker, self.bind_admitted_launch, self.contain, self.validate)


def _retain_transport_failures(start_worker):
    """Append private diagnostics after the protected controller settles a stopped run."""
    if (type(start_worker) is not MethodType or type(start_worker.__self__) is not _PoolParent
            or start_worker.__func__ is not _PoolParent.start_worker):
        return
    for worker in start_worker.__self__.workers.values():
        try:
            if worker.wire is not None and worker.containment._closed:
                observation = worker.wire.take_transport_failure_observation()
                if observation is not None:
                    worker.containment.record("transport-failed", observation)
        except Exception:
            # An optional receipt cannot replace the already computed settlement.
            pass


def build_pool_qualification_runtime(plan, *, authority_path, admission, capability=None, ordinary=None):
    """Assemble the original runtime and stage hooks from approved input data only.

    The admission capability and connected callback receipt already exist when
    selected. This factory verifies their original bindings without issuing or
    consuming them, launching a process or changing any filesystem state.
    """
    _require(not validate_transaction_plan(plan) and plan["version"] == PLAN_VERSION and plan["selected_model"] == MODEL
             and plan["prelude_session_count"] == 0 and len(plan["children"]) in (2, 3)
             and plan["budget"]["cumulative_before"] == 0, "contained-disposable-plan-required")
    _check_factory_source(plan)
    from registered_pool_ordinary_runtime import require_ordinary_custody

    require_ordinary_custody(ordinary)
    parent = _PoolParent(plan, authority_path, admission, capability, ordinary)
    return parent.runtime(), parent.bind_limits, parent.cleanup
