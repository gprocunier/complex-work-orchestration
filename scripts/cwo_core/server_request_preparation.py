"""Inert, fake-only preparation of provisional 0.164 server-request replies.

No transport, reader, callback, persistence or authority is supplied here.
The captured schema syntax is experimental and unqualified.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
import math
import threading
from typing import Any

CAPTURED_VERSION = "0.164.0"
EVIDENCE_QUALIFIER = "captured-provisional-schema-only; experimental; unqualified"
CONTEXT_PROVENANCE = "caller-supplied fake pre-effect context; not authenticated production provenance"
COMMAND = "item/commandExecution/requestApproval"
FILE = "item/fileChange/requestApproval"
PERMISSIONS = "item/permissions/requestApproval"
_METHODS = frozenset({COMMAND, FILE, PERMISSIONS})
_SERVER_METHODS = _METHODS | frozenset({
    "item/tool/requestUserInput", "mcpServer/elicitation/request", "item/tool/call",
    "account/chatgptAuthTokens/refresh", "attestation/generate", "currentTime/read",
    "applyPatchApproval", "execCommandApproval",
})
_PENDING = frozenset({"queued", "deciding"})


class PreparationError(ValueError):
    """A malformed message or refused fake preparation transition."""


def _shape(required: dict, optional: dict | None = None) -> dict:
    return {"required": required, "optional": optional or {}}


_NETWORK_RULE = _shape({"action": frozenset({"allow", "deny"}), "host": str})
_DECISION = (
    frozenset({"accept", "acceptForSession", "decline", "cancel"}),
    _shape({"acceptWithExecpolicyAmendment": _shape({"execpolicy_amendment": [str]})}),
    _shape({"applyNetworkPolicyAmendment": _shape({"network_policy_amendment": _NETWORK_RULE})}),
)
_SPECIAL = (
    _shape({"kind": frozenset({"root", "minimal", "tmpdir", "slash_tmp"})}),
    _shape({"kind": frozenset({"project_roots"})}, {"subpath": (str, None)}),
    _shape({"kind": frozenset({"unknown"}), "path": str}, {"subpath": (str, None)}),
)
_PATH = (
    _shape({"type": frozenset({"path"}), "path": str}),
    _shape({"type": frozenset({"glob_pattern"}), "pattern": str}),
    _shape({"type": frozenset({"special"}), "value": _SPECIAL}),
)
_FILESYSTEM = _shape({}, {
    "entries": ([_shape({"access": frozenset({"read", "write", "deny"}), "path": _PATH})], None),
    "read": ([str], None), "write": ([str], None),
    "globScanMaxDepth": (range(1, 2**63), None),
})
_PROFILE = _shape({}, {
    "fileSystem": (_FILESYSTEM, None),
    "network": (_shape({}, {"enabled": (bool, None)}), None),
})
_ACTION = (
    _shape({"type": frozenset({"read"}), "command": str, "name": str, "path": str}),
    _shape({"type": frozenset({"listFiles"}), "command": str}, {"path": (str, None)}),
    _shape({"type": frozenset({"search"}), "command": str},
           {"path": (str, None), "query": (str, None)}),
    _shape({"type": frozenset({"unknown"}), "command": str}),
)
_COMMON = {"threadId": str, "turnId": str, "itemId": str, "startedAtMs": int}
_PARAMS = {
    COMMAND: _shape(_COMMON, {
        "approvalId": (str, None), "kind": frozenset({"command", "writeStdin"}),
        "command": (str, None), "cwd": (str, None), "reason": (str, None),
        "environmentId": (str, None), "commandActions": ([_ACTION], None),
        "additionalPermissions": (_PROFILE, None), "availableDecisions": ([_DECISION], None),
        "proposedExecpolicyAmendment": ([str], None),
        "proposedNetworkPolicyAmendments": ([_NETWORK_RULE], None),
        "networkApprovalContext": (_shape({
            "host": str, "protocol": frozenset({"http", "https", "socks5Tcp", "socks5Udp"}),
        }), None),
    }),
    FILE: _shape(_COMMON, {"reason": (str, None), "grantRoot": (str, None)}),
    PERMISSIONS: _shape(dict(_COMMON, cwd=str, permissions=_PROFILE), {
        "reason": (str, None), "environmentId": (str, None),
    }),
}


def _valid(value: Any, spec: Any) -> bool:
    if spec is None:
        return value is None
    if isinstance(spec, type):
        return type(value) is spec
    if type(spec) is tuple:
        return any(_valid(value, branch) for branch in spec)
    if type(spec) is frozenset:
        return type(value) is str and value in spec
    if type(spec) is range:
        return type(value) is int and value in spec
    if type(spec) is list:
        return type(value) is list and all(_valid(item, spec[0]) for item in value)
    if type(value) is not dict:
        return False
    required, optional = spec["required"], spec["optional"]
    return (
        required.keys() <= value.keys() <= required.keys() | optional.keys()
        and all(_valid(item, (required | optional)[name]) for name, item in value.items())
    )


def _measure(value: Any, budget: list[int], depth: int = 0) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > 16:
        raise PreparationError("message-size-or-depth")
    if type(value) is dict:
        if len(value) > 256 or any(type(k) is not str or len(k) > 256 for k in value):
            raise PreparationError("message-object")
        children = value.values()
    elif type(value) is list:
        if len(value) > 256:
            raise PreparationError("message-array")
        children = value
    else:
        if not _scalar_ok(value):
            raise PreparationError("message-scalar")
        return
    for item in children:
        _measure(item, budget, depth + 1)


def _scalar_ok(value: Any) -> bool:
    kind = type(value)
    if kind is str:
        return len(value) <= 8192
    if kind is int:
        return -(2**63) <= value < 2**63
    if kind is float:
        return math.isfinite(value)
    return value is None or kind is bool


def _json(value: Any) -> str:
    _measure(value, [4096])
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded) > 65536:
        raise PreparationError("message-bytes")
    return encoded


def _text(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 256 and "\x00" not in value


def _id_key(value: Any) -> tuple[type, int | str]:
    if type(value) is int and -(2**63) <= value < 2**63:
        return int, value
    if _text(value):
        return str, value
    raise PreparationError("request-id")


@dataclass(frozen=True)
class Response:
    request_id: int | str
    frame_json: str


@dataclass(frozen=True)
class Notification:
    method: str
    frame_json: str


@dataclass(frozen=True)
class ServerRequest:
    request_id: int | str
    method: str
    params_json: str


def _check_approval_params(method: str, params: dict) -> None:
    if not _valid(params, _PARAMS[method]):
        raise PreparationError("approval-params")
    if any(not _text(params[name]) for name in ("threadId", "turnId", "itemId")):
        raise PreparationError("approval-correlation")
    if params.get("approvalId") is not None and not _text(params["approvalId"]):
        raise PreparationError("approval-id")


def _check_response_error(error: Any) -> None:
    if (type(error) is not dict or not {"code", "message"} <= error.keys()
            or set(error) - {"code", "message", "data"}
            or type(error["code"]) is not int or type(error["message"]) is not str):
        raise PreparationError("response-error")


def classify_message(value: Any) -> Response | Notification | ServerRequest:
    """Classify a strict bounded object, without any lifecycle or decision work."""
    frame = _json(value)
    message = json.loads(frame)
    if type(message) is not dict:
        raise PreparationError("message-not-object")
    keys = set(message)
    if "method" in message:
        if keys not in ({"method", "params"}, {"id", "method", "params"}):
            raise PreparationError("ambiguous-method-envelope")
        method, params = message["method"], message["params"]
        if not _text(method) or type(params) is not dict:
            raise PreparationError("method-or-params")
        if "id" not in message:
            if method in _SERVER_METHODS:
                raise PreparationError("server-request-id-required")
            return Notification(method, frame)
        _id_key(message["id"])
        if method in _PARAMS:
            _check_approval_params(method, params)
        return ServerRequest(message["id"], method, _json(params))
    if keys not in ({"id", "result"}, {"id", "error"}):
        raise PreparationError("ambiguous-response-envelope")
    _id_key(message["id"])
    if "error" in message:
        _check_response_error(message["error"])
    return Response(message["id"], frame)


@dataclass(frozen=True)
class Correlation:
    epoch: str
    request_id: int | str
    thread_id: str
    turn_id: str
    item_id: str
    approval_id: str | None


@dataclass(frozen=True)
class FakeItemContext:
    epoch: str
    thread_id: str
    turn_id: str
    item_id: str
    method: str
    approval_id: str | None = None
    kind: str = "command"
    command: str | None = None
    cwd: str | None = None
    paths: tuple[str, ...] = ()
    provenance: str = field(default=CONTEXT_PROVENANCE, init=False)


@dataclass(frozen=True)
class DecisionWork:
    correlation: Correlation
    method: str
    params_json: str
    context: FakeItemContext


@dataclass(frozen=True)
class PreparedReply:
    epoch: str
    correlation: Correlation | None
    frame_json: str
    interruption_required: bool
    captured_version: str = field(default=CAPTURED_VERSION, init=False)
    evidence_qualifier: str = field(default=EVIDENCE_QUALIFIER, init=False)
    experimental: bool = field(default=True, init=False)
    qualified: bool = field(default=False, init=False)
    context_provenance: str = field(default=CONTEXT_PROVENANCE, init=False)


@dataclass
class _Entry:
    request: ServerRequest
    work: DecisionWork | None
    deadline: int
    state: str = "queued"


def _context_key(context: FakeItemContext) -> tuple:
    return (context.thread_id, context.turn_id, context.item_id, context.method, context.approval_id)


def _in_turn(correlation: Correlation | None, thread_id: str, turn_id: str) -> bool:
    return (
        correlation is not None
        and (correlation.thread_id, correlation.turn_id) == (thread_id, turn_id)
    )


def _paths(value: Any) -> bool:
    if type(value) is not tuple or len(value) > 64:
        return False
    if any(type(p) is not str or len(p) > 4096 for p in value):
        return False
    return len(set(value)) == len(value) and all(
        p.startswith("/") and "\x00" not in p
        and all(part not in {"", ".", ".."} for part in p[1:].split("/"))
        for p in value
    )


def _command_matches_context(params: dict, context: FakeItemContext) -> bool:
    return (
        type(context.command) is str and bool(context.command)
        and type(context.cwd) is str and bool(context.cwd)
        and params.get("command") == context.command and params.get("cwd") == context.cwd
        and params.get("kind", "command") == context.kind
        and (context.kind != "writeStdin" or context.approval_id is not None)
    )


def _accept_is_safe(work: DecisionWork, allowed_paths: tuple[str, ...]) -> bool:
    params, context = json.loads(work.params_json), work.context
    if work.method == FILE:
        return params.get("grantRoot") is None and bool(context.paths) and set(context.paths) <= set(allowed_paths)
    blocked = ("additionalPermissions", "environmentId", "networkApprovalContext",
               "proposedExecpolicyAmendment", "proposedNetworkPolicyAmendments")
    if any(params.get(name) is not None for name in blocked):
        return False
    available = params.get("availableDecisions")
    if available is not None and "accept" not in available:
        return False
    return _command_matches_context(params, context)


def _result(work: DecisionWork, decision: Any, allowed_paths: tuple[str, ...]) -> dict:
    if type(decision) is not str or decision not in {"accept", "decline", "cancel"}:
        raise PreparationError("one-action-decision-required")
    if work.method == PERMISSIONS:
        if decision != "decline":
            raise PreparationError("permission-grants-and-universal-cancel-forbidden")
        return {"permissions": {}}
    if decision == "accept" and not _accept_is_safe(work, allowed_paths):
        decision = "decline"
    return {"decision": decision}


def _limit(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PreparationError("bound-invalid")
    return value


class FakeRequestPreparer:
    """Nonblocking in-memory consumer; all time is explicit monotone fake milliseconds.

    No callbacks run under or outside the lock. Work becomes visible only after
    registration; a blocked external decider cannot block receive/expiry/EOF.
    """

    def __init__(
        self, epoch: str, *, allowed_paths: tuple[str, ...] = (),
        timeout_ms: int = 1000, max_pending: int = 16, max_requests: int = 256,
        max_contexts: int = 128, max_epochs: int = 8,
    ) -> None:
        if not _text(epoch) or not _paths(allowed_paths):
            raise PreparationError("fake-configuration")
        self._timeout = _limit(timeout_ms, 1, 60000)
        self._capacity = _limit(max_pending, 1, 256)
        self._request_bound = _limit(max_requests, self._capacity, 4096)
        self._context_bound = _limit(max_contexts, 1, 4096)
        self._epoch_bound = _limit(max_epochs, 1, 64)
        self._allowed_paths = tuple(allowed_paths)
        self._epoch, self._epochs = epoch, {epoch}
        self._last_now, self._closed = 0, False
        self._lock = threading.RLock()
        self._entries: dict[tuple, _Entry] = {}
        self._callbacks: set[tuple] = set()
        self._queue: deque[tuple] = deque()
        self._replies: deque[PreparedReply] = deque()
        self._active: dict[str, str] = {}
        self._turns: set[tuple[str, str]] = set()
        self._items: dict[tuple, FakeItemContext] = {}

    def _open(self, epoch: str) -> None:
        if self._closed or epoch != self._epoch:
            raise PreparationError("closed-or-stale-epoch")

    def _tick(self, now: int) -> None:
        _limit(now, self._last_now, 2**63 - 1)
        self._last_now = now
        for token, entry in self._entries.items():
            if entry.state in _PENDING and now >= entry.deadline:
                self._emit(token, _result(entry.work, "decline", self._allowed_paths), True)

    def _emit(self, token: tuple, result: dict, interrupt: bool, *, error: bool = False) -> None:
        entry = self._entries[token]
        frame = {"id": entry.request.request_id, "error" if error else "result": result}
        correlation = entry.work.correlation if entry.work is not None else None
        entry.state = "prepared"
        if token in self._queue:
            self._queue.remove(token)
        self._replies.append(PreparedReply(self._epoch, correlation, _json(frame), interrupt))

    def open_turn(self, thread_id: str, turn_id: str, *, now: int) -> None:
        with self._lock:
            self._open(self._epoch)
            self._tick(now)
            if not _text(thread_id) or not _text(turn_id):
                raise PreparationError("turn-identity")
            if thread_id in self._active or (thread_id, turn_id) in self._turns:
                raise PreparationError("turn-reused-or-active")
            if len(self._turns) >= self._context_bound:
                raise PreparationError("turn-bound")
            self._turns.add((thread_id, turn_id))
            self._active[thread_id] = turn_id

    def observe_item(self, context: FakeItemContext, *, now: int) -> None:
        """Register caller-supplied fake context before receiving an approval."""
        with self._lock:
            if type(context) is not FakeItemContext:
                raise PreparationError("fake-item-type")
            self._open(context.epoch)
            self._tick(now)
            self._check_item(context)
            token = _context_key(context)
            if token in self._items or len(self._items) >= self._context_bound:
                raise PreparationError("item-reused-or-bound")
            self._items[token] = context

    def _check_item(self, context: FakeItemContext) -> None:
        if any(not _text(v) for v in (context.thread_id, context.turn_id, context.item_id)):
            raise PreparationError("item-identity")
        if self._active.get(context.thread_id) != context.turn_id or type(context.method) is not str or context.method not in _METHODS:
            raise PreparationError("item-turn-or-method")
        if context.approval_id is not None and not _text(context.approval_id):
            raise PreparationError("item-approval-id")
        if not _paths(context.paths) or type(context.kind) is not str or context.kind not in {"command", "writeStdin"}:
            raise PreparationError("item-paths-or-kind")
        if any(v is not None and (type(v) is not str or len(v) > 8192) for v in (context.command, context.cwd)):
            raise PreparationError("item-command-or-cwd")

    def receive(self, value: Any, *, epoch: str, now: int) -> Response | Notification | ServerRequest:
        message = classify_message(value)
        with self._lock:
            self._open(epoch)
            self._tick(now)
            if not isinstance(message, ServerRequest):
                return message
            token = _id_key(message.request_id)
            if token in self._entries:
                raise PreparationError("duplicate-request-id")
            if len(self._entries) >= self._request_bound:
                self.eof(now=now)
                raise PreparationError("request-history-bound")
            occupied = len(self._replies) + sum(e.state in _PENDING for e in self._entries.values())
            if occupied >= self._capacity:
                self.eof(now=now)
                raise PreparationError("pending-and-reply-bound")
            self._entries[token] = _Entry(message, None, now, "refused")
            work = self._correlate(message) if message.method in _METHODS else None
            self._entries[token] = _Entry(message, work, min(now + self._timeout, 2**63 - 1))
            if work is None:
                self._emit(token, {"code": -32601, "message": "Unsupported server request"}, True, error=True)
            else:
                self._queue.append(token)
            return message

    def _correlate(self, request: ServerRequest) -> DecisionWork:
        params = json.loads(request.params_json)
        correlation = Correlation(self._epoch, request.request_id, params["threadId"],
                                  params["turnId"], params["itemId"], params.get("approvalId"))
        token = self._reserve_callback(request, params)
        if self._active.get(correlation.thread_id) != correlation.turn_id:
            raise PreparationError("inactive-or-cross-thread-turn")
        context = self._items.get(token)
        if context is None:
            raise PreparationError("pre-effect-fake-item-required")
        return DecisionWork(correlation, request.method, request.params_json, context)

    def _reserve_callback(self, request: ServerRequest, params: dict) -> tuple:
        token = (params["threadId"], params["turnId"], params["itemId"],
                 request.method, params.get("approvalId"))
        callback = (self._epoch,) + token
        if callback in self._callbacks:
            raise PreparationError("duplicate-approval-callback")
        if len(self._callbacks) >= self._request_bound:
            self.eof(now=self._last_now)
            raise PreparationError("callback-history-bound")
        self._callbacks.add(callback)
        return token

    def next_decision(self, *, now: int) -> DecisionWork | None:
        with self._lock:
            self._open(self._epoch)
            self._tick(now)
            if not self._queue:
                return None
            entry = self._entries[self._queue.popleft()]
            entry.state = "deciding"
            return entry.work

    def prepare(self, correlation: Correlation, decision: str, *, now: int) -> None:
        with self._lock:
            if type(correlation) is not Correlation:
                raise PreparationError("correlation-type")
            self._open(correlation.epoch)
            self._tick(now)
            entry = self._entries.get(_id_key(correlation.request_id))
            if entry is None or entry.work is None or entry.work.correlation != correlation:
                raise PreparationError("correlation-mismatch")
            if entry.state != "deciding":
                raise PreparationError("decision-stale-or-duplicate")
            result = _result(entry.work, decision, self._allowed_paths)
            self._emit(_id_key(correlation.request_id), result, decision == "cancel")

    def drain_replies(self, *, now: int) -> tuple[PreparedReply, ...]:
        with self._lock:
            self._open(self._epoch)
            self._tick(now)
            replies = tuple(self._replies)
            self._replies.clear()
            return replies

    def _terminal_reply(self, reply: PreparedReply, thread_id: str, turn_id: str) -> PreparedReply:
        if not _in_turn(reply.correlation, thread_id, turn_id):
            return reply
        frame = json.loads(reply.frame_json)
        if frame.get("result") != {"decision": "accept"}:
            return reply
        entry = self._entries[_id_key(frame["id"])]
        frame["result"] = _result(entry.work, "cancel", self._allowed_paths)
        return PreparedReply(reply.epoch, reply.correlation, _json(frame), True)

    def terminal(self, thread_id: str, turn_id: str, *, now: int) -> None:
        with self._lock:
            self._open(self._epoch)
            self._tick(now)
            if not _text(thread_id) or not _text(turn_id) or self._active.get(thread_id) != turn_id:
                raise PreparationError("terminal-turn-mismatch")
            del self._active[thread_id]
            self._replies = deque(
                self._terminal_reply(reply, thread_id, turn_id) for reply in self._replies
            )
            for token, entry in self._entries.items():
                if entry.work is not None and _in_turn(entry.work.correlation, thread_id, turn_id):
                    if entry.state in _PENDING:
                        decision = "decline" if entry.request.method == PERMISSIONS else "cancel"
                        self._emit(token, _result(entry.work, decision, self._allowed_paths), True)
                    else:
                        entry.state = "revoked"
            self._items = {k: v for k, v in self._items.items() if (v.thread_id, v.turn_id) != (thread_id, turn_id)}

    def eof(self, *, now: int) -> None:
        with self._lock:
            self._tick(now)
            self._closed = True
            self._queue.clear()
            self._replies.clear()
            self._active.clear()
            self._items.clear()
            for entry in self._entries.values():
                entry.state = "revoked"

    def reconnect(self, epoch: str, *, now: int) -> None:
        with self._lock:
            if not _text(epoch) or epoch in self._epochs or len(self._epochs) >= self._epoch_bound:
                raise PreparationError("epoch-reused-or-bound")
            self._tick(now)
            self._epoch = epoch
            self._epochs.add(epoch)
            self._closed = False
            self._entries.clear()
            self._callbacks.clear()
            self._queue.clear()
            self._replies.clear()
            self._active.clear()
            self._turns.clear()
            self._items.clear()


__all__ = [
    "CAPTURED_VERSION", "EVIDENCE_QUALIFIER", "CONTEXT_PROVENANCE",
    "COMMAND", "FILE", "PERMISSIONS", "PreparationError",
    "Response", "Notification", "ServerRequest", "Correlation",
    "FakeItemContext", "DecisionWork", "PreparedReply",
    "classify_message", "FakeRequestPreparer",
]
