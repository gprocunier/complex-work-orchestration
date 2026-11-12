"""Finite registered advisory-review composition; public HTTP activation stays disabled.

The host freezes a whole original planning input at bootstrap. Tickets are local
capabilities issued by that host, never serialized readiness/grant documents.
Registration qualifies cooperative wiring only, not permission for a live call.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import dispatch_work as dispatch
import prepare_local_admission as admission
from cwo_core import local_invocation as http
from cwo_core.invocation_ledger import InvocationLedger, InvocationTimeout, request_sha256
from cwo_core.routing import classify_work

POLICIES = ("executor-registry.yaml", "provider-registry.yaml", "access-profiles.yaml",
            "contracting-controls.yaml", "peer-review-policy.yaml")
POLICY_ROOT = Path(__file__).resolve().parents[1] / "policy"


def _require(condition, message):
    if not condition:
        raise admission.AdmissionError(message)


def _bytes(value):
    return admission.reconciliation._snapshot(value)[1]


def _policies():
    return tuple((name, (POLICY_ROOT / name).read_bytes()) for name in POLICIES)


@dataclass(frozen=True, slots=True, eq=False)
class ReviewTicket:
    """Identity-registered local receipt; constructing/copying one grants nothing."""

    host: object
    node_id: str
    prepared: admission.PreparedAdmission


@dataclass(frozen=True, slots=True, eq=False)
class CompletedReview:
    """Opaque original-host identity; a constructed or copied value is inert."""


@dataclass(frozen=True)
class ReviewObservation:
    """Actual original request/result/terminal ledger snapshots, without authority."""
    ticket: ReviewTicket
    binding_bytes: bytes
    result_bytes: bytes
    attempt_bytes: bytes


def _review_route():
    task = "Review security evidence without editing."
    route = classify_work(task, text_segments=[task], local_ok=True,
                          prefer_local=True, local_profile="generic-openai-compatible",
                          requested_roles=["security"])
    _require(route["recommended_executor"] == "local_secure_review_worker",
             "The registered read-only local review route is unavailable.")
    # The original resolver includes a fresh observation time and its digest.
    # Compare every substantive route field, without treating time as drift.
    route["operative_route"] = {key: value for key, value in route["operative_route"].items()
                                if key not in ("evaluated_at", "route_sha256")}
    return route


def _execution(node, selected):
    execution = node["execution"]
    _require(execution["executor"] == selected["key"]
             and execution["provider"] == selected["provider_key"],
             "Registered execution must match the original local review provider/executor.")
    _require(execution["tool_surface"] == [], "This review adapter grants no tools.")
    options = execution["options"]
    _require(options.get("reasoning_effort") == execution["effort"]
             and options.get("max_tokens") == execution["output_tokens_upper"],
             "Actual effort and output controls must be present in the original execution options.")
    return execution


def _arguments(execution, amounts, base_url):
    return argparse.Namespace(
        local_base_url=base_url, local_model=execution["model"],
        local_timeout=amounts["runtime_seconds"], local_max_tokens=execution["output_tokens_upper"],
        local_api_key_env=None, local_thinking="default", execute_local=True,
        local_allow_private_dns=False, local_ca_bundle=None, local_insecure_tls=False,
        allow_offline_access_profile=False,
    )


def _wire_body(envelope):
    return json.dumps({"model": envelope["model"], "messages": envelope["messages"],
                       "temperature": 0, **envelope["request_options"]}).encode("utf-8")


def _review_text(node):
    # Execution belongs in the API fields, while all prompt, wrapper, file and
    # attachment text is copied losslessly into the user message. The original
    # admitted JSON is the canonical source for both parts of this mapping.
    return json.dumps({key: node[key] for key in ("prompt", "wrappers", "attachments", "sources")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _wire_entry(envelope, transport):
    headers = {"Content-Type": "application/json", "X-CWO-Dispatch-ID": envelope["dispatch_id"]}
    secret = os.environ.get(str(transport.get("api_key_env") or ""))
    if transport["auth_mode"] == "bearer-env" and secret:
        headers["Authorization"] = "Bearer " + secret
    req = dispatch.request.Request(
        dispatch.endpoint_url(transport["base_url"], transport["endpoint_path"]),
        data=_wire_body(envelope), headers=headers, method="POST")
    return http.request_entry(req)


class RegisteredReviewHost:
    """Own one finite registered graph and the original ledger, without live authority.

    Bootstrap is a host responsibility. Dispatch accepts only issued ticket
    identities and never accepts an alternative route, effect, model or limit.
    Restarting the host cannot reset attempts or aggregate totals in its ledger.
    """

    def __init__(self, route_input, *, ledger, base_url):
        _require(type(ledger) is InvocationLedger, "The original InvocationLedger is required.")
        _require(type(base_url) is str, "The host must register its exact endpoint.")
        # Literal endpoints keep bootstrap validation free of DNS effects.
        ipaddress.ip_address(dispatch.urlparse(base_url).hostname)
        dispatch.validate_local_endpoint_base_url(base_url)
        self._route_bytes = _bytes(route_input)
        self._ledger = ledger
        self._base_url = base_url
        self._policy_bytes = _policies()
        self._routing = _bytes(_review_route())
        self._lock = threading.Lock()
        self._tickets = {}
        self._prepared = {}
        self._completed = {}
        self._completion_tickets = {}
        self._submitted = set()
        self._designations = {}
        self._bindings = self._register()
        self._seal_registration()

    def _route(self):
        return json.loads(self._route_bytes)

    def _register(self):
        route, _, _, plan, _ = admission._plan(self._route())
        selected = json.loads(self._routing)["selected_executor"]
        planned = {node["id"]: node for node in plan["nodes"]}
        return {node["id"]: self._build(node, planned[node["id"]]["amounts"], selected)
                for node in route["nodes"]}

    def _seal_registration(self):
        # Extend the original scope with the host's exact wire/policy binding.
        # This is an actually checked acceptance criterion, not a second budget
        # or a self-reported grant. A restarted host cannot change the endpoint
        # or headers and inherit the old aggregate's scope.
        manifest = {"input_sha256": request_sha256(self._route_bytes),
                    "bindings": {node: request_sha256(raw) for node, raw in self._bindings.items()},
                    "policies": {name: request_sha256(raw) for name, raw in self._policy_bytes}}
        self.registration_sha256 = request_sha256(_bytes(manifest))
        route = self._route()
        route["acceptance"].append("Registered advisory HTTP binding: " + self.registration_sha256)
        route["bound_input_sha256"] = admission.planner.input_sha256(route)
        self._route_bytes = _bytes(route)
        admission._plan(self._route())

    def _build(self, node, amounts, selected):
        execution = _execution(node, selected)
        args = _arguments(execution, amounts, self._base_url)
        # The original envelope builder, including its full system wrapper,
        # receives the complete original rendered bytes/files/attachments.
        routing = json.loads(self._routing)
        routing["selected_executor"]["transport"]["request_options"] = execution["options"]
        envelope = dispatch.build_local_envelope(
            task=_review_text(node), route=routing,
            dispatch_id=self._route()["run_id"] + ":" + node["id"],
            bead_id=self._route()["parent_id"], epic_id=self._route()["aggregate_id"], args=args)
        envelope = json.loads(_bytes(envelope))
        _require(envelope["model_preflight_required"] is False,
                 "This finite adapter supports the registered no-preflight profile only.")
        _require(envelope["request_options"] == execution["options"], "Original HTTP options drifted.")
        overhead = max(0, len(_wire_body(envelope)) - len(node["rendered_request"].encode("utf-8")))
        _require(node["additional_input_tokens_upper"] >= overhead *
                 self._route()["projection_policy"]["tokens_per_utf8_byte_upper"],
                 "Whole-route sizing omits the measured original HTTP serialization/wrapper overhead.")
        return _bytes({"envelope": envelope, "args": vars(args), "selected": selected,
                       "evaluation_requirements": {"peer_review_required": routing["peer_review_required"],
                           "provider_conflict_domains": routing.get("provider_conflict_domains", [])},
                       "request_entry": _wire_entry(envelope, dispatch.local_transport(selected, args)),
                       "base_transport": dispatch.local_transport(selected, args),
                       "http_overhead_bytes": overhead})

    def issue(self, node_id, *, now, expires_at):
        _require(node_id in self._bindings, "The node is outside the finite host registration.")
        prepared = admission.prepare(self._route(), node_id, now=now, expires_at=expires_at)
        ticket = ReviewTicket(self, node_id, prepared)
        with self._lock:
            self._tickets[id(ticket)] = ticket
            self._prepared[id(ticket)] = prepared
        return ticket

    def _registered(self, ticket):
        _require(type(ticket) is ReviewTicket and ticket.host is self,
                 "A ticket from this registered review host is required.")
        with self._lock:
            _require(self._tickets.get(id(ticket)) is ticket
                     and self._prepared.get(id(ticket)) is ticket.prepared,
                     "Unissued, copied or changed review ticket is refused.")
        _require(ticket.node_id == ticket.prepared.node_id, "Registered node identity drifted.")
        _require(_policies() == self._policy_bytes and _bytes(_review_route()) == self._routing,
                 "Registered review policy or route drifted.")
        return ticket.prepared

    def dispatch(self, ticket, *, node_attempts=None, observer=None):
        # Preserve the original shipped refusal before even consulting tickets.
        if not dispatch.LOCAL_INVOCATION_AVAILABLE:
            raise SystemExit(dispatch.LOCAL_INVOCATION_UNAVAILABLE)
        self._registered(ticket)
        self._begin_submission(ticket)
        binding = json.loads(self._bindings[ticket.node_id])
        scope = _ReviewScope(self, ticket, binding, node_attempts, observer)
        result = dispatch.execute_local_envelope(
            binding["envelope"], binding["selected"], argparse.Namespace(**binding["args"]),
            qualified_review=scope)
        self._complete(scope, result)
        return {"review": result, "attempt": scope.final,
                "applied": {"execution": json.loads(ticket.prepared.execution_bytes),
                            "allowance": json.loads(ticket.prepared.amounts_bytes),
                            "registration_sha256": self.registration_sha256,
                            "http_request": binding["request_entry"],
                            "http_overhead_bytes": binding["http_overhead_bytes"]},
                **dict.fromkeys(admission.FALSE_FIELDS, False)}

    def _complete(self, scope, result):
        _require(scope.result_bytes == _bytes(result), "Original completed review result drifted.")
        if not scope.completed:
            return None
        _require(scope.final is not None and scope.final["outcome"] == "completed",
                 "Original review has no completed ledger observation.")
        token = CompletedReview()
        observed = ReviewObservation(scope.ticket, self._bindings[scope.ticket.node_id],
                                     scope.result_bytes, _bytes(scope.final))
        with self._lock:
            self._completed[token] = observed
            self._completion_tickets[id(scope.ticket)] = token
        self.observe_completion(token)
        return token

    def completed(self, ticket):
        """Find only the actual completion for a previously registered ticket."""
        with self._lock:
            token = self._completion_tickets.get(id(ticket))
        observed = self.observe_completion(token)
        _require(observed.ticket is ticket, "Completion differs from its original ticket.")
        return token

    def designate_review(self, ticket, basis):
        """Freeze the exact control basis before this node starts submission."""
        self._registered(ticket)
        _require(type(basis) is bytes, "A review designation needs immutable basis bytes.")
        with self._lock:
            _require(ticket.node_id not in self._submitted,
                     "Designate the original reviewer before controlled submission starts.")
            previous = self._designations.get(id(ticket), basis)
            _require(previous == basis, "Original review designation cannot be changed.")
            self._designations[id(ticket)] = basis

    def _begin_submission(self, ticket):
        # Share the designation lock: a synchronous/in-flight observer cannot
        # enroll authority after submission starts. The original ledger still
        # owns reservation, replay, errors and conservative aggregate charges.
        with self._lock:
            self._submitted.add(ticket.node_id)

    def require_designated_review(self, ticket, basis):
        with self._lock:
            _require(self._designations.get(id(ticket)) == basis,
                     "Original completed review has no matching pre-submission designation.")

    def observe_completion(self, token):
        """Revalidate identity, request, policy and the actual terminal ledger."""
        _require(type(token) is CompletedReview, "An original completed review is required.")
        with self._lock:
            observed = self._completed.get(token)
        _require(observed is not None, "Unissued, copied or foreign review completion.")
        try:
            current = self._current_completion(observed)
            with self._lock:
                _require(self._completed.get(token) is observed,
                         "Original review completion was revoked during validation.")
            return current
        except BaseException:
            with self._lock:
                self._completed.pop(token, None)
            raise

    def require_active_completion(self, ticket):
        """No-callout veto for a terminally revoked completion at actual use."""
        with self._lock:
            token = self._completion_tickets.get(id(ticket))
            observed = self._completed.get(token)
            _require(observed is not None and observed.ticket is ticket,
                     "Original completed review is unavailable or terminally revoked.")

    def _current_completion(self, observed):
        self._registered(observed.ticket)
        attempt = json.loads(observed.attempt_bytes)
        current = self._ledger.attempt(attempt["reservation_id"])
        _require(_bytes(current) == observed.attempt_bytes,
                 "Original completed review ledger observation changed.")
        return observed


class _CheckedHandle:
    """Revalidate original graph/policy/expiry after every synchronous callback."""

    def __init__(self, handle, scope, prior, deadline):
        self.handle, self.scope, self.prior, self.deadline = handle, scope, prior, deadline

    def require_intent(self):
        host, ticket = self.scope.host, self.scope.ticket
        prepared = host._registered(ticket)
        admission._live(prepared, host._ledger)
        admission._graph_state(prepared, self.prior, host._ledger, self.handle.require_intent()["attempt_id"])
        _require(host._ledger.current_time() < self.deadline, "The admitted review runtime is exhausted.")
        return self.handle.require_intent()

    def report(self, kind, detail=None):
        self.handle.report(kind, detail)


class _DeadlineOpener:
    def __init__(self, opener, handle, timeout):
        self.opener, self.handle, self.timeout = opener, handle, timeout
        self.configuration = http._opener_configuration(opener)

    def open(self, req, *, timeout):
        _require(timeout == self.timeout, "Executable timeout differs from admitted allowance.")
        self.handle.require_intent()
        _require(http._opener_configuration(self.opener) == self.configuration,
                 "Original opener configuration changed during observer callbacks.")
        remaining = self.handle.deadline - self.handle.scope.host._ledger.current_time()
        try:
            return self.opener.open(req, timeout=min(timeout, remaining))
        except TimeoutError as exc:
            raise InvocationTimeout("Local HTTP cutoff; remote usage and cancellation are unknown.") from exc


class _ReviewGate(http.LocalHttpGate):
    def __init__(self, handle, expected, timeout):
        super().__init__(handle, expected)
        self.timeout = timeout

    def bind(self, opener):
        return super().bind(_DeadlineOpener(opener, self._handle, self.timeout))


class _ReviewScope:
    def __init__(self, host, ticket, binding, node_attempts, observer):
        self.host, self.ticket, self.binding = host, ticket, binding
        self.prior = admission._prior_attempts(ticket.prepared, node_attempts)
        self.observer, self.final = observer, None
        self.completed = False
        self.result_bytes = None

    def _observe(self, event):
        if event["event"] == "invocation-intent":
            _require(event["attempt"]["request_sha256"] == request_sha256(self.ticket.prepared.request_bytes),
                     "The persisted review intent differs from its registered request.")

    def _reserve(self):
        prepared = self.host._registered(self.ticket)
        ledger = self.host._ledger
        admission._validated(prepared, self.host._route(), self.ticket.node_id,
                             ledger, self.host.dispatch, self.observer)
        prior = admission._prior_attempts(prepared, self.prior)
        lineage = admission._graph_state(prepared, prior, ledger)
        ledger.open_budget(prepared.budget_id, json.loads(prepared.limits_bytes), scope_sha256=prepared.scope_sha256)
        reserved = ledger.reserve(
            budget_id=prepared.budget_id, request_id=prepared.node_id,
            request_sha256=request_sha256(prepared.request_bytes),
            admission_sha256=admission._receipt_sha256(prepared), amount=json.loads(prepared.amounts_bytes),
            expires_at=prepared.expires_at, lineage=lineage, refuse_while_unresolved=True)
        return prepared, prior, reserved

    @contextmanager
    def enter(self, envelope, post, preflight):
        _require(_bytes(envelope) == _bytes(self.binding["envelope"]), "Original review envelope drifted.")
        _require(preflight is None and post.data == _wire_body(envelope), "Original HTTP request drifted.")
        _require(http.request_entry(post) == self.binding["request_entry"],
                 "Registered HTTP URL, headers or body drifted.")
        prepared, prior, reserved = self._reserve()
        ledger = self.host._ledger
        observers = (self._observe,) if self.observer is None else (self._observe, self.observer)
        observers = tuple(http._route_observer(observer) for observer in observers)
        timeout = json.loads(prepared.amounts_bytes)["runtime_seconds"]
        deadline = min(prepared.expires_at, ledger.current_time() + timeout)
        with ledger.invocation(reserved["reservation_id"], prepared.request_bytes, observers=observers) as handle:
            checked = _CheckedHandle(handle, self, prior, deadline)
            checked.require_intent()
            gate = _ReviewGate(checked, http.reserved_requests(post, preflight), timeout)
            # Preserve original SystemExit/interrupt/timeout disposition and full
            # conservative four-resource charges, without a second HTTP budget.
            with http._ledger_outcome(gate):
                yield gate
            checked.require_intent()
            handle.record("completed" if self.completed else "failed", None)
        self.final = handle.final
        # Completion persists and notifies terminal observers inside __exit__.
        # Delivery gets a final check after those callbacks, without rewriting
        # the terminal attempt or releasing its conservative charge.
        self.host._registered(self.ticket)
        admission._live(prepared, ledger)
        _require(ledger.current_time() < deadline, "The admitted review runtime is exhausted before delivery.")


def invocation_scope(scope, envelope, post, preflight):
    _scope(scope)
    return _ReviewContext(scope.enter(envelope, post, preflight))


class _ReviewContext:
    def __init__(self, context):
        self.context = context

    def __enter__(self):
        return _review_context_call(self.context.__enter__)

    def __exit__(self, kind, failure, traceback):
        handled = _review_context_call(self.context.__exit__, kind, failure, traceback)
        if not handled and isinstance(failure, (http._RouteStopped, http._RouteTimeout, http._RouteCancelled)):
            http._raise_route_failure(failure)
        return handled


def _review_context_call(call, *args):
    try:
        return call(*args)
    except (http._RouteStopped, http._RouteTimeout, http._RouteCancelled) as stopped:
        http._raise_route_failure(stopped)


def _scope(scope):
    _require(type(scope) is _ReviewScope, "A host-created review scope is required.")
    _require(type(scope.host) is RegisteredReviewHost, "The original registered host is required.")
    scope.host._registered(scope.ticket)
    _require(_bytes(scope.binding) == scope.host._bindings[scope.ticket.node_id],
             "The scope differs from the finite host registration.")


def admitted_transport(scope, transport):
    _scope(scope)
    _require(_bytes(transport) == _bytes(scope.binding["base_transport"]),
             "Original endpoint/model/timeout/transport drifted.")
    return {**transport, "request_options": json.loads(scope.ticket.prepared.execution_bytes)["options"]}


def evaluation_requirements(scope, envelope):
    """Return only the original host's pinned pre-dispatch hold requirements."""
    _scope(scope)
    _require(_bytes(envelope) == _bytes(scope.binding['envelope']), 'Original review envelope drifted.')
    return json.loads(_bytes(scope.binding['evaluation_requirements']))


def observe_result(scope, result):
    _scope(scope)
    _require(scope.result_bytes is None, "Original review result was already observed.")
    scope.result_bytes = _bytes(result)
    scope.completed = result.get("usable_final_content") is True
