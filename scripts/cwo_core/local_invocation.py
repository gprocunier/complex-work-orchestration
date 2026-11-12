"""Reservation, aggregate accounting and crash ambiguity at the controlled local HTTP route (issue #41).

``dispatch_work.execute_local_envelope`` enters ``reserved_local_invocation`` after every binding check and both
outbound screens, and before endpoint resolution, its first network effect. Everything from resolution to the
response runs inside the context, so:

- **Reservation.** One attempt is reserved, under the ledger lock, against the epic's aggregate budget (or the
  global budget without an epic). The budget has two dimensions, ``attempts`` and ``requests``, sized from
  ``quota_policy.local_worker_dispatches_per_epic``: N attempts and 2N requests. An attempt reserves one attempt
  and one request for the POST, plus one request when the profile requires the model preflight, so the preflight
  is charged to the same allowance. The ledger records the owner process, the digest of the exact requests (method,
  URL, headers with credentials by digest, body digest) and an attempt binding digest; an invoked dispatch is one
  use. Reuse of a demonstrably unused released reservation remains a separate policy question.
- **Intent before the effect.** Intent and the registered observers are persisted and fsynced before the context
  body runs. Each request then passes ``LocalHttpGate``: the persisted attempt is re-read (still in intent, this
  owner, these bytes), atomically claims its one-use slot before notifying observers synchronously, and checks
  frozen request bytes after callbacks immediately before transport. Preflight must be validated before POST.
- **Accounting.** A normal exit records ``completed`` with the requests actually sent; the charge is never below
  the reservation. A refusal or failure raised by the route after intent (``SystemExit``, including outbound
  screening) records ``unknown``; a timeout records ``timeout``; both are charged in full and the original exception
  propagates unchanged. An interrupt (``KeyboardInterrupt``) or a crash leaves the attempt
  ``reconciliation-required``.
- **Crash ambiguity.** Reservations are taken with ``refuse_while_unresolved``: while any attempt in the budget
  requires reconciliation or holds intent under an owner not known to be alive, and while the same dispatch already
  has an attempt that was not released, nothing is reserved and nothing is sent. A handled terminal unknown or
  timeout is charged in full and permits a separately admitted successor, not reuse of the invoked dispatch.
  An unresolved crash requires reconciliation; no terminal result proves the remote service stopped.

This does not restore the route. ``dispatch_work.LOCAL_INVOCATION_AVAILABLE`` stays False and refuses before any of
this is reached; workload-derived sizing and the admission record (restoration criteria 1 to 3) are still missing.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from urllib.request import OpenerDirector, Request
from collections.abc import Callable, Iterator, Mapping
from contextlib import ContextDecorator, contextmanager
from typing import Any

from .invocation_ledger import (
    MAX_UNITS,
    InvocationHandle,
    InvocationLedger,
    InvocationLedgerError,
    InvocationTimeout,
    InvocationCancelled,
    request_sha256,
    add_failure_note,
)
from .policy import load_contracting_controls

ROUTE = "local-http"
QUOTA_KEY = "local_worker_dispatches_per_epic"
DIMENSIONS = ("attempts", "requests")
RESERVATION_TTL_SECONDS = 60.0
BINDING_TYPE = "cwo-local-http-attempt-binding"
BINDING_VERSION = 1
# Envelope fields bound into the attempt binding digest besides the exact requests.
BOUND_ENVELOPE_FIELDS = (
    "executor_key", "provider_key", "access_profile", "local_profile", "model_profile", "model", "messages_sha256",
    "transport_binding_sha256", "tls_binding_sha256", "request_options", "share_boundary",
)
# Synchronous observers registered (by name, in the ledger) before every local invocation. Empty in shipped code.
OBSERVERS: list[Callable[[dict[str, Any]], None]] = []
_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie"}


def open_ledger() -> InvocationLedger:
    """The ledger every controlled local invocation reserves against: ``CWO_INVOCATION_LEDGER_ROOT``, or the
    invocation ledger under the audit directory."""
    return InvocationLedger()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def local_http_budget(epic_id: Any) -> tuple[str, dict[str, int], str]:
    """``(budget_id, limits, scope_sha256)`` of the aggregate budget a local invocation charges."""
    quotas = load_contracting_controls().get("quota_policy")
    quota = quotas.get(QUOTA_KEY) if isinstance(quotas, Mapping) else None
    if type(quota) is not int or not 0 < quota <= MAX_UNITS // 2:
        raise InvocationLedgerError(
            f"quota_policy.{QUOTA_KEY} must be a positive integer of at most {MAX_UNITS // 2} to size the aggregate "
            "budget"
        )
    epic_sha256 = _sha256_text(str(epic_id)) if epic_id else None
    budget_id = f"local-http-epic-{epic_sha256[:40]}" if epic_sha256 else "local-http-global"
    scope = _canonical({"route": ROUTE, "quota_key": QUOTA_KEY, "epic_sha256": epic_sha256})
    return budget_id, {"attempts": quota, "requests": 2 * quota}, hashlib.sha256(scope).hexdigest()


def request_entry(req: Any) -> dict[str, Any]:
    """The bound form of one HTTP request: method, URL, headers (credentials by digest) and body digest."""
    data = req.data
    body = b"" if data is None else bytes(data)
    headers = sorted(
        [name.lower(), "sha256:" + _sha256_text(str(value)) if name.lower() in _SENSITIVE_HEADERS else str(value)]
        for name, value in req.header_items()
    )
    return {"method": req.get_method(), "url": req.full_url, "headers": headers,
            "body_sha256": hashlib.sha256(body).hexdigest(), "body_bytes": len(body)}


def reserved_requests(post: Any, preflight: Any | None) -> dict[str, dict[str, Any] | None]:
    return {"post": request_entry(post), "preflight": None if preflight is None else request_entry(preflight)}


def request_id_for(envelope: Mapping[str, Any]) -> str:
    dispatch_id = envelope.get("dispatch_id")
    if not isinstance(dispatch_id, str) or not dispatch_id:
        raise InvocationLedgerError("the local envelope has no dispatch_id to bind the attempt to")
    return "local-dispatch-" + _sha256_text(dispatch_id)[:40]


def attempt_binding_sha256(envelope: Mapping[str, Any], *, budget_id: str, request_id: str, request_digest: str,
                           amount: Mapping[str, int]) -> str:
    """One use per dispatch: the same dispatch and requests always give the same digest, so a replay is refused.

    This binds the attempt to its requests and envelope; it is not the admission record of restoration criterion 2.
    """
    bound = {field: envelope.get(field) for field in BOUND_ENVELOPE_FIELDS}
    return hashlib.sha256(_canonical({
        "type": BINDING_TYPE, "version": BINDING_VERSION, "route": ROUTE, "budget_id": budget_id,
        "request_id": request_id, "request_sha256": request_digest, "amount": dict(amount), "envelope": bound,
    })).hexdigest()


def _reserve(envelope: Mapping[str, Any], expected: Mapping[str, Any], record: bytes) -> tuple[InvocationLedger, dict]:
    """Open the budget and reserve one attempt, or refuse before anything is sent."""
    try:
        ledger = open_ledger()
        budget_id, limits, scope_sha256 = local_http_budget(envelope.get("epic_id"))
        ledger.open_budget(budget_id, limits, scope_sha256=scope_sha256)
        amount = {"attempts": 1, "requests": 1 if expected["preflight"] is None else 2}
        request_id = request_id_for(envelope)
        digest = request_sha256(record)
        reservation = ledger.reserve(
            budget_id=budget_id, request_id=request_id, request_sha256=digest,
            admission_sha256=attempt_binding_sha256(envelope, budget_id=budget_id, request_id=request_id,
                                                    request_digest=digest, amount=amount),
            amount=amount, expires_at=ledger.current_time() + RESERVATION_TTL_SECONDS, refuse_while_unresolved=True,
        )
    except (InvocationLedgerError, OSError) as exc:
        raise SystemExit(f"controlled local invocation refused: {exc}. Nothing was sent.") from exc
    return ledger, reservation


class _OriginalFailure:
    """Carry provenance without invoking fallible exception formatting.

    Diagnostic rendering delegates to the original: the ledger's defensive
    formatter then handles an unrenderable secondary observer consistently.
    """

    def __init__(self, original: BaseException) -> None:
        super().__init__()
        self.original = original

    def __repr__(self) -> str:
        return repr(self.original)


class _RouteStopped(_OriginalFailure, Exception):
    """A route exit or observer failure that must bypass transport handlers."""


class _RouteTimeout(_OriginalFailure, InvocationTimeout):
    """A timeout carried through the ledger as a timeout."""


class _RouteCancelled(_OriginalFailure, InvocationCancelled):
    """An observer cancellation, not a transport exception."""


def _is_timeout(exc: BaseException) -> bool:
    if issubclass(type(exc), (TimeoutError, InvocationTimeout)):
        return True
    try:
        return issubclass(type(getattr(exc, "reason", None)), TimeoutError)
    except BaseException:
        # Classification reads secondary metadata, never a second effect.
        # A failing accessor cannot replace the primary observer exception.
        return False


def _handler_ids(handlers: Any) -> tuple[int, ...]:
    return tuple(id(handler) for handler in handlers)


def _processor_ids(processors: Any) -> tuple[Any, ...]:
    return tuple((name, _handler_ids(handlers)) for name, handlers in sorted(processors.items(), key=lambda item: repr(item[0])))


def _opener_configuration(opener: Any) -> tuple[Any, ...] | None:
    """Snapshot the actual urllib processing graph, including public add_handler.

    Non-urllib objects are trusted fake/adapter transports, not a claim to
    authenticate arbitrary caller-controlled Python objects or method bodies.
    """
    if not isinstance(opener, OpenerDirector):
        return None
    return (
        _handler_ids(opener.handlers),
        _processor_ids(opener.process_request),
        _processor_ids(opener.process_response),
        _processor_ids(opener.handle_open),
        tuple((protocol, _processor_ids(methods)) for protocol, methods in sorted(opener.handle_error.items())),
        tuple(tuple(header) for header in opener.addheaders),
    )


class LocalHttpGate:
    """The only opener the route sends through: each request must be a reserved one, in order, once."""

    def __init__(self, handle: InvocationHandle, expected: Mapping[str, dict[str, Any] | None]) -> None:
        self._handle = handle
        self._expected = json.loads(_canonical(expected))
        self._opener: Any = None
        self._opener_configuration: tuple[Any, ...] | None = None
        self._lock = threading.Lock()
        self._states: dict[str, str] = {}
        self._preflight_validated = expected.get("preflight") is None
        self._preflight_completed: float | None = None
        self._maximum_gap_ms: int | None = None
        self.preflight_to_post_ms: int | None = None
        self.sent: list[str] = []
        self.timed_out = False

    def bind(self, opener: Any) -> LocalHttpGate:
        with self._lock:
            if self._opener is not None or self._states:
                raise SystemExit("controlled local invocation refused: transport is already bound or consumed")
            self._opener = opener
            self._opener_configuration = _opener_configuration(opener)
        return self

    def usage(self) -> dict[str, int]:
        return {"attempts": 1, "requests": len(self.sent)}

    def _admit(self, req: Any) -> str:
        kind = "preflight" if req.get_method() == "GET" else "post"
        expected = self._expected.get(kind)
        if expected is None:
            problem = f"the reservation names no {kind} request"
        elif kind in self._states:
            problem = f"the reserved {kind} request was already sent once"
        elif kind == "post" and not self._preflight_validated:
            problem = "the reserved model preflight must be sent before the POST and its model result validated"
        elif request_entry(req) != expected:
            problem = f"the {kind} request changed after it was reserved"
        else:
            return kind
        raise SystemExit(f"controlled local invocation refused: {problem}; the attempt stays charged in full and "
                         "nothing more is sent.")

    def validated_preflight(self, *, completed_monotonic: float, maximum_gap_ms: int) -> None:
        """Arm one numeric deadline only after the route validates the GET result.

        No callback is accepted: final ledger work must precede a pure clock
        check with no further observer able to terminate or alter the attempt.
        """
        if (type(completed_monotonic) not in (int, float) or not math.isfinite(completed_monotonic)
                or completed_monotonic > time.monotonic()
                or type(maximum_gap_ms) is not int or maximum_gap_ms < 0):
            raise SystemExit("controlled local invocation refused: invalid preflight deadline")
        with self._lock:
            if self._preflight_validated or self._states.get("preflight") != "completed":
                raise SystemExit("controlled local invocation refused: model preflight has not completed")
            self._preflight_completed = float(completed_monotonic)
            self._maximum_gap_ms = maximum_gap_ms
            self._preflight_validated = True

    def _check_preflight_deadline(self, kind: str) -> None:
        if kind == "post" and self._preflight_completed is not None:
            elapsed_ms = max(0.0, (time.monotonic() - self._preflight_completed) * 1000)
            self.preflight_to_post_ms = int(elapsed_ms)
            if elapsed_ms > self._maximum_gap_ms:
                raise SystemExit("local model preflight expired before POST; "
                    f"gap_ms={self.preflight_to_post_ms}, maximum_ms={self._maximum_gap_ms}")

    def open(self, req: Any, *, timeout: float) -> Any:
        # No data, method, URL or header overrides are supported. A distinct
        # Request protects transport bytes from mutation of the caller's object.
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise SystemExit("controlled local invocation refused: timeout must be finite and positive")
        frozen = Request(req.full_url, data=None if req.data is None else bytes(req.data),
                         headers=dict(req.header_items()), method=req.get_method())
        with self._lock:
            kind = self._admit(frozen)
            sent_before = len(self.sent)
            opener = self._opener
            self._states[kind] = "in-flight"
            self.sent.append(kind)
        # Never hold a non-reentrant lock across arbitrary synchronous callbacks.
        # The one-use claim already exists when any observer can reenter.
        try:
            try:
                self._handle.report("request", {"kind": kind, "sent_before": sent_before})
            except InvocationLedgerError as exc:
                raise SystemExit(f"controlled local invocation refused: {exc}; nothing more is sent.") from exc
            if request_entry(req) != self._expected[kind] or request_entry(frozen) != self._expected[kind]:
                raise SystemExit("controlled local invocation refused: request changed during observer work; "
                                 "the attempt stays charged in full and nothing more is sent.")
            if _opener_configuration(opener) != self._opener_configuration:
                raise SystemExit("controlled local invocation refused: transport processing changed during callbacks; "
                                 "the attempt stays charged in full and nothing more is sent.")
            try:
                self._handle.require_intent()
            except InvocationLedgerError as exc:
                raise SystemExit(f"controlled local invocation refused: {exc}; nothing more is sent.") from exc
            # All callback and final ledger work precedes this pure deadline.
            self._check_preflight_deadline(kind)
            response = opener.open(frozen, timeout=timeout)
        except BaseException as exc:
            with self._lock:
                self._states[kind] = "failed"
                self.timed_out = self.timed_out or _is_timeout(exc)
            raise
        with self._lock:
            self._states[kind] = "completed"
        return response


@contextmanager
def _ledger_outcome(gate: LocalHttpGate) -> Iterator[None]:
    """Carry the route's own exits through the ledger as ordinary outcomes (charged in full), not interrupts."""
    try:
        yield
    except SystemExit as exc:
        raise (_RouteTimeout(exc) if gate.timed_out else _RouteStopped(exc)) from exc
    except TimeoutError as exc:
        raise _RouteTimeout(exc) from exc


def _route_observer(observer):
    def wrapped(event):
        try:
            observer(event)
        except Exception as failure:
            # Preserve provenance past ALL dispatcher transport handlers. An
            # observer's HTTPError is not an endpoint response to read/close.
            carrier = (_RouteTimeout if _is_timeout(failure) else
                       _RouteCancelled if issubclass(type(failure), InvocationCancelled) else _RouteStopped)
            raise carrier(failure) from failure
    wrapped.__qualname__ = getattr(observer, '__qualname__', type(observer).__name__)
    return wrapped


@contextmanager
def _reserved_local_scope(envelope: Mapping[str, Any], post: Any, preflight: Any | None = None
                          ) -> Iterator[LocalHttpGate]:
    expected = reserved_requests(post, preflight)
    record = _canonical(expected)
    ledger, reservation = _reserve(envelope, expected, record)
    with ledger.invocation(reservation["reservation_id"], record,
                           observers=tuple(_route_observer(observer) for observer in OBSERVERS)) as handle:
        handle.require_intent()
        gate = LocalHttpGate(handle, expected)
        with _ledger_outcome(gate):
            yield gate
        handle.record("completed", gate.usage())


def _raise_route_failure(stopped: Any) -> None:
    for note in getattr(stopped, '__notes__', ()):
        add_failure_note(stopped.original, note)
    raise stopped.original


def _raise_ledger_refusal(failure: BaseException) -> None:
    raise SystemExit(f"controlled local invocation refused: {failure}.") from failure


def _context_call(call: Callable[..., Any], *args: Any) -> Any:
    try:
        return call(*args)
    except (_RouteStopped, _RouteTimeout, _RouteCancelled) as stopped:
        _raise_route_failure(stopped)
    except InvocationLedgerError as exc:
        _raise_ledger_refusal(exc)


class _ReservedLocalInvocation(ContextDecorator):
    def __init__(self, envelope: Mapping[str, Any], post: Any, preflight: Any | None) -> None:
        self._args = (envelope, post, preflight)
        self._context = _reserved_local_scope(*self._args)

    def _recreate_cm(self) -> _ReservedLocalInvocation:
        return type(self)(*self._args)

    def __enter__(self) -> LocalHttpGate:
        return _context_call(self._context.__enter__)

    def __exit__(self, kind: Any, failure: BaseException | None, traceback: Any) -> bool:
        handled = _context_call(self._context.__exit__, kind, failure, traceback)
        if not handled and issubclass(type(failure), (_RouteStopped, _RouteTimeout, _RouteCancelled)):
            _raise_route_failure(failure)
        if not handled and issubclass(type(failure), InvocationLedgerError):
            _raise_ledger_refusal(failure)
        return handled


def reserved_local_invocation(envelope: Mapping[str, Any], post: Any, preflight: Any | None = None
                              ) -> _ReservedLocalInvocation:
    """Persist intent before resolution; restore primary failures outside generators."""
    return _ReservedLocalInvocation(envelope, post, preflight)
