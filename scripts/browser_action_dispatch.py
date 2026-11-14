"""Offline trusted-parent browser actions using the existing invocation ledger.

Bootstrap, never configuration, supplies the original adapter and authority.
Tickets are cooperative same-process capabilities, not serialized grants. The
ledger supplies durable one-use intent and conservative aggregate accounting;
it does not grant live browser or sharing authority. No live route is restored.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import dataclass

from cwo_core.invocation_ledger import (
    MAX_TIME, MAX_UNITS, InvocationLedger, InvocationTimeout,
    request_sha256,
)
from cwo_core.prepared_outbound import PreparedOutbound
from cwo_core.outbound_screen import OutboundRefused


DIMENSIONS = {"effect_calls", "payload_bytes", "output_bytes", "runtime_milliseconds"}
ACTION_OBSERVATIONS = {"conversation_url", "model_observation", "document_id"}


class BrowserActionRefused(ValueError):
    """Safe static diagnostic; original packet, request and result stay private."""


def _require(condition, message):
    if not condition:
        raise BrowserActionRefused(message)


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise BrowserActionRefused("Browser action context is not finite JSON.") from None


def _positive(value):
    return type(value) is int and 0 < value <= MAX_UNITS


def _text(value):
    return type(value) is str and bool(value.strip())


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _request_id(value):
    return type(value) is str and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def _aggregate_execution(execution):
    return {**execution, "options": {key: value for key, value in execution["options"].items()
                                     if key not in ACTION_OBSERVATIONS}}


def _keys(value, keys):
    return type(value) is dict and set(value) == set(keys.split())


def _method(adapter, name):
    method = getattr(adapter, name, None)
    _require(callable(method), "Original browser adapter method is required.")
    return method


def _same_method(current, original):
    return (getattr(current, "__self__", None) is getattr(original, "__self__", None)
            and getattr(current, "__func__", current) is getattr(original, "__func__", original))


def _safe_failure(failure):
    if isinstance(failure, KeyboardInterrupt):
        raise KeyboardInterrupt("Browser action interrupted; outcome is unknown.") from None
    if isinstance(failure, SystemExit):
        raise SystemExit("Browser action interrupted; outcome is unknown.") from None
    if isinstance(failure, InvocationTimeout):
        raise InvocationTimeout("Browser action exceeded its local deadline.") from None
    if isinstance(failure, Exception):
        raise BrowserActionRefused("Browser action adapter failed; outcome is unknown.") from None
    raise BaseException("Browser action interrupted; outcome is unknown.") from None


def _observer(original):
    def observe(event):
        try:
            original(event)
        except BaseException as failure:
            _safe_failure(failure)
    return observe


def _validate_limits(limits):
    _require(_keys(limits, "timeout_seconds max_output_bytes max_send_probes"),
             "Browser action requires exact finite local limits.")
    duration = limits["timeout_seconds"]
    _require(type(duration) in (int, float) and 0 < duration <= MAX_UNITS / 1000,
             "Browser action timeout must be finite and positive.")
    _require(_positive(limits["max_output_bytes"]) and _positive(limits["max_send_probes"]),
             "Browser action output and probe limits must be positive units.")


def _validate_context(context):
    _require(_keys(context, "source payload request execution limits share"),
             "Browser action requires the complete original context.")
    request, execution = context["request"], context["execution"]
    _require(_keys(request, "packet_sha256 dispatch_id request_id subject_sha256"),
             "Browser action request identities are incomplete.")
    _require(_digest(request["packet_sha256"]) and _digest(request["subject_sha256"])
             and _text(request["dispatch_id"]) and _request_id(request["request_id"]),
             "Browser action request identities are invalid.")
    _require(_keys(execution, "executor provider adapter_id adapter_version model effort options"),
             "Browser action execution descriptor is incomplete.")
    _require(all(_text(execution[key]) for key in execution if key != "options")
             and type(execution["options"]) is dict, "Browser action execution descriptor is invalid.")
    _require(_text(context["payload"]), "Browser action requires exact nonempty payload bytes.")
    _validate_limits(context["limits"])
    if context["share"] is not None:
        _validate_selection(context["share"])


def _validate_selection(selection):
    _require(_keys(selection, "origin conversation_id messages purpose"),
             "Share authorization needs a whole selected conversation.")
    _require(selection["origin"] in
             ("https://chatgpt.com", "https://chat.openai.com"), "Share origin is unsupported.")
    _require(_text(selection["conversation_id"]) and _text(selection["purpose"]),
             "Share authorization requires conversation and purpose.")
    messages = selection["messages"]
    _require(type(messages) is list and bool(messages), "Share authorization requires ordered content.")
    seen = set()
    for message in messages:
        _require(_keys(message, "message_id role content"), "Share message binding is incomplete.")
        _require(_text(message["message_id"]) and message["message_id"] not in seen
                 and message["role"] in ("user", "assistant", "system", "tool")
                 and type(message["content"]) is str, "Share message binding is invalid.")
        seen.add(message["message_id"])


@dataclass(frozen=True, slots=True, eq=False)
class SendTicket:
    """Opaque exact-object capability; constructing or copying one grants nothing."""


@dataclass(frozen=True, slots=True, eq=False)
class ShareTicket:
    """Explicit whole-conversation authorization, held only in its original parent."""


@dataclass(frozen=True, slots=True)
class ActionResult:
    status: str
    action_sha256: str
    admission_sha256: str
    reservation_id: str
    output_sha256: str | None
    output_bytes: int | None
    remote_usage_known: bool = False

    def metadata(self):
        return {name: getattr(self, name) for name in self.__slots__}


class RegisteredBrowserParent:
    """Freeze one original request/selection and register its exact offline adapter.

    The scope names a stable aggregate across requests and restarts. Its ledger
    identifier depends only on the aggregate identity, while immutable execution,
    limits and scope are checked by open_budget. No host/expiry nonce resets it.
    """

    def __init__(self, prepared, *, ledger, aggregate_scope, aggregate_limits, adapter, observers=()):
        _require(type(prepared) is PreparedOutbound and type(ledger) is InvocationLedger,
                 "Browser parent requires original prepared bytes and InvocationLedger.")
        _require(type(aggregate_scope) is dict and _text(aggregate_scope.get("aggregate_id"))
                 and _text(aggregate_scope.get("purpose")), "Browser aggregate scope is incomplete.")
        _require(type(aggregate_limits) is dict and set(aggregate_limits) == DIMENSIONS
                 and all(_positive(value) for value in aggregate_limits.values()),
                 "Browser aggregate requires applicable positive resource dimensions.")
        self._prepared, self._ledger, self._adapter = prepared, ledger, adapter
        self._methods = {name: _method(adapter, name) for name in ("snapshot", "send", "create_share")}
        self._context_bytes = self._snapshot()
        context = json.loads(self._context_bytes)
        _validate_context(context)
        self._prepared_metadata = _canonical(prepared.metadata())
        self._check_prepared(context)
        self._scope_bytes = _canonical(aggregate_scope)
        self._limits_bytes = _canonical(aggregate_limits)
        self._aggregate_id = "browser:" + request_sha256(_canonical(aggregate_scope["aggregate_id"]))
        self._scope_sha256 = request_sha256(_canonical({
            "scope": aggregate_scope, "limits": aggregate_limits,
            "execution": _aggregate_execution(context["execution"]), "action_limits": context["limits"],
            "wire_transform": "browser-send-stamp-newline-v1/share-canonical-utf8-v1"}))
        self._observers = tuple(_observer(original) for original in observers)
        self._tickets, self._active, self._lock = {}, {}, threading.Lock()
        self._validate_amounts()

    def _snapshot(self):
        try:
            return _canonical(self._methods["snapshot"]())
        except BaseException as failure:
            _safe_failure(failure)

    def _check_prepared(self, context):
        try:
            _require(_canonical(self._prepared.metadata()) == self._prepared_metadata,
                     "Original browser prepared metadata changed.")
            self._prepared.require_unchanged(context["source"], context["payload"])
        except (Exception, OutboundRefused):
            raise BrowserActionRefused("Browser prepared source or request changed.") from None

    def _current(self):
        _require(all(_same_method(_method(self._adapter, name), original)
                     for name, original in self._methods.items()), "Registered browser adapter changed.")
        current = self._snapshot()
        _require(current == self._context_bytes, "Original browser request, execution or limits changed.")
        context = json.loads(current)
        self._check_prepared(context)
        return context

    def _wire(self, kind):
        context = json.loads(self._context_bytes)
        if kind == "send":
            return (context["request"]["request_id"] + "\n" + context["payload"]).encode("utf-8")
        return _canonical(context["share"])

    def _amount(self, kind):
        limits = json.loads(self._context_bytes)["limits"]
        calls = limits["max_send_probes"] if kind == "send" else 1
        return {"effect_calls": calls, "payload_bytes": len(self._wire(kind)) * calls,
                "output_bytes": limits["max_output_bytes"],
                "runtime_milliseconds": math.ceil(limits["timeout_seconds"] * 1000)}

    def _validate_amounts(self):
        for kind in ("send", "share"):
            _require(all(_positive(value) for value in self._amount(kind).values()),
                     "Browser reservation exceeds representable positive units.")

    def _issue(self, kind, expires_at):
        context = self._current()
        now = self._ledger.current_time()
        _require(type(expires_at) in (int, float) and now < expires_at <= MAX_TIME,
                 "Browser action expiry must be finite and in the future.")
        if kind == "share":
            _require(context["share"] is not None, "No whole conversation was selected for sharing.")
        ticket = SendTicket() if kind == "send" else ShareTicket()
        with self._lock:
            self._tickets[ticket] = (kind, expires_at)
        return ticket

    def issue_send(self, *, expires_at):
        return self._issue("send", expires_at)

    def authorize_create_share(self, *, purpose, expires_at):
        selection = self._current()["share"]
        _require(selection is not None and _text(purpose) and selection["purpose"] == purpose,
                 "Share authorization purpose differs from the original selection.")
        return self._issue("share", expires_at)

    def _registered(self, ticket, kind):
        expected = SendTicket if kind == "send" else ShareTicket
        _require(type(ticket) is expected, "An original parent-issued browser action ticket is required.")
        with self._lock:
            record = self._tickets.get(ticket)
        _require(record is not None and record[0] == kind,
                 "Unissued, copied or foreign browser action ticket.")
        self._current()
        _require(self._ledger.current_time() < record[1], "Browser action ticket has expired.")
        return record[1]

    def _action_sha256(self, kind):
        context = json.loads(self._context_bytes)
        identity = {"kind": kind, "packet_sha256": context["request"]["packet_sha256"],
                    "dispatch_id": context["request"]["dispatch_id"]}
        if kind == "share":
            identity["selection"] = {key: value for key, value in context["share"].items() if key != "purpose"}
        return request_sha256(_canonical(identity))

    def _reserve(self, ticket, kind):
        expiry = self._registered(ticket, kind)
        self._ledger.open_budget(self._aggregate_id, json.loads(self._limits_bytes),
                                 scope_sha256=self._scope_sha256)
        action = self._action_sha256(kind)
        admission = request_sha256(_canonical({"action": action, "context": request_sha256(self._context_bytes),
                                               "prepared": request_sha256(self._prepared_metadata),
                                               "scope": self._scope_sha256}))
        return self._ledger.reserve(budget_id=self._aggregate_id, request_id="browser-action:" + action,
                                    request_sha256=request_sha256(self._wire(kind)), admission_sha256=admission,
                                    amount=self._amount(kind), expires_at=expiry, refuse_while_unresolved=True)

    def send(self, ticket):
        return _BrowserAction(self, ticket, "send")

    def create_share(self, ticket):
        with _BrowserAction(self, ticket, "share") as action:
            action._create()
        return action.result


class _BrowserAction:
    """One ledger invocation; only definite waiting permits another bounded probe."""

    def __init__(self, parent, ticket, kind):
        self._parent, self._ticket, self._kind = parent, ticket, kind
        self._handle = self._invocation = None
        self._entered = self._closed = self._measured_failure = False
        self._calls = self._supplied = 0
        self._output_size = self._output_sha256 = None
        self._action_sha256 = self._admission_sha256 = None
        self._state = "not-entered"
        self._effect_lock = threading.Lock()
        self.result = None

    def __enter__(self):
        _require(not self._entered, "Browser action guard is one use.")
        self._entered = True
        attempt = self._parent._reserve(self._ticket, self._kind)
        self._action_sha256 = attempt["request_id"].removeprefix("browser-action:")
        self._admission_sha256 = attempt["admission_sha256"]
        with self._parent._lock:
            self._parent._active[attempt["reservation_id"]] = self
        self._start_time = self._parent._ledger.current_time()
        self._start_mono = time.monotonic()
        self._limits = json.loads(self._parent._context_bytes)["limits"]
        self._invocation = self._parent._ledger.invocation(
            attempt["reservation_id"], self._parent._wire(self._kind), observers=self._parent._observers)
        self._handle = self._invocation.__enter__()
        try:
            self.check()
        except BaseException as failure:
            self._invocation.__exit__(type(failure), failure, failure.__traceback__)
            self._closed = True
            raise
        self._state = "ready"
        return self

    @property
    def action_sha256(self):
        """Stable dispatch replay key from the persisted reservation."""
        return self._action_sha256

    @property
    def admission_sha256(self):
        """Exact admission fingerprint from the persisted reservation."""
        return self._admission_sha256

    def _elapsed(self):
        return max(0, time.monotonic() - self._start_mono,
                   self._parent._ledger.current_time() - self._start_time)

    def _usage(self):
        elapsed = self._elapsed()
        if not math.isfinite(elapsed) or elapsed > MAX_UNITS / 1000:
            self._parent._ledger.mark_reconciliation_required(
                self._handle.reservation_id, reason="measured local elapsed usage exceeds representable units")
            raise BrowserActionRefused("Browser action elapsed usage requires reconciliation.")
        usage = {"effect_calls": self._calls, "payload_bytes": self._supplied,
                 "runtime_milliseconds": math.ceil(elapsed * 1000)}
        if self._output_size is not None:
            usage["output_bytes"] = self._output_size
        return usage

    def check(self):
        _require(self._handle is not None and not self._closed, "Browser action guard is not active.")
        self._require_original_guard()
        parent = self._parent
        parent._registered(self._ticket, self._kind)
        parent._ledger.open_budget(parent._aggregate_id, json.loads(parent._limits_bytes),
                                   scope_sha256=parent._scope_sha256)
        summary = parent._ledger.summary(parent._aggregate_id)
        _require(all(value >= 0 for value in summary["remaining"].values()),
                 "Browser aggregate has an observed overrun.")
        _require(not summary["reconciliation_required"], "Browser aggregate requires reconciliation.")
        _require(self._elapsed() < self._limits["timeout_seconds"], "Browser action deadline expired.")
        # No user callback follows this persisted owner/request/intent check.
        return self._handle.require_intent()

    def _require_original_guard(self):
        with self._parent._lock:
            _require(self._parent._active.get(self._handle.reservation_id) is self,
                     "Copied or foreign browser action guard is refused.")

    def _call(self, method, argument):
        self.check()
        remaining = self._limits["timeout_seconds"] - self._elapsed()
        _require(remaining > 0, "Browser action deadline expired.")
        self._calls += 1
        self._supplied += len(self._parent._wire(self._kind))
        self._state = "ambiguous"
        try:
            return method(argument, timeout_seconds=remaining,
                          max_output_bytes=self._limits["max_output_bytes"])
        except BaseException as failure:
            _safe_failure(failure)

    def _output_bounds(self):
        if self._output_size > self._limits["max_output_bytes"]:
            self._measured_failure = True
            raise BrowserActionRefused("Browser action exceeded its output bound.")
        if self._elapsed() >= self._limits["timeout_seconds"]:
            self._measured_failure = True
            raise InvocationTimeout("Browser action exceeded its local deadline.")

    def observe_output(self, bytes_count, *, sha256=None):
        """Observe one complete captured response without accepting its body.

        The trusted capture boundary supplies the exact UTF-8 count/digest.
        Without this hook, response output usage stays unknown, never zero.
        """
        _require(self._kind == "send" and self._state == "pressed" and not self._closed
                 and self._output_size is None, "Output observation needs one active completed Send.")
        _require(type(bytes_count) is int and 0 <= bytes_count <= MAX_UNITS
                 and (sha256 is None or _digest(sha256)), "Output observation is invalid.")
        self._output_size, self._output_sha256 = bytes_count, sha256
        self._output_bounds()
        self.check()

    def _returned_before_deadline(self):
        if self._elapsed() >= self._limits["timeout_seconds"]:
            self._measured_failure = True
            raise InvocationTimeout("Browser action exceeded its local deadline.")

    def press(self, target):
        _require(self._effect_lock.acquire(blocking=False), "Browser Send is already entering its effect.")
        try:
            return self._press(target)
        finally:
            self._effect_lock.release()

    def _press(self, target):
        _require(self._kind == "send" and self._state in ("ready", "waiting"),
                 "Browser Send cannot be retried after a final or ambiguous result.")
        _require(self._calls < self._limits["max_send_probes"], "Browser Send probe allowance is exhausted.")
        method = self._parent._methods["send"]
        submission = self._parent._wire("send").decode("utf-8")

        def effect(argument, **options):
            return method(argument, submission, **options)

        state = self._call(effect, target)
        _require(type(state) is str and state in ("pressed", "waiting", "refused"),
                 "Browser Send returned an invalid observation.")
        self._state = state
        self._returned_before_deadline()
        return state

    def _create(self):
        _require(self._kind == "share" and self._state == "ready", "Share action is one use.")
        raw = self._call(self._parent._methods["create_share"], self._parent._wire("share"))
        _require(type(raw) is bytes, "Offline share creation returned an invalid observation.")
        self._output_size, self._output_sha256 = len(raw), hashlib.sha256(raw).hexdigest()
        self._output_bounds()
        self._state = "created"

    def __exit__(self, kind, failure, traceback):
        self._require_original_guard()
        self._closed = True
        deadline_failure = failure is None and self._elapsed() >= self._limits["timeout_seconds"]
        if deadline_failure:
            self._measured_failure = True
        try:
            if failure is None or self._measured_failure:
                status = "completed" if not self._measured_failure and self._state in ("pressed", "created") else "failed"
                self._handle.record(status, self._usage())
                self._invocation.__exit__(None, None, None)
                self.result = ActionResult(self._state, self.action_sha256, self.admission_sha256,
                                           self._handle.reservation_id, self._output_sha256,
                                           self._output_size)
            else:
                self._invocation.__exit__(kind, failure, traceback)
        except BaseException as settlement:
            current = self._parent._ledger.attempt(self._handle.reservation_id)
            if current["state"] == "invocation-intent":
                self._invocation.__exit__(type(settlement), settlement, settlement.__traceback__)
            raise
        if deadline_failure:
            raise InvocationTimeout("Browser action exceeded its local deadline.")
        return False
