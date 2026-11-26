"""Stage and consume whole-workload admission for ordinary local HTTP."""
from __future__ import annotations

import json
import socket
import time
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread, Timer

import prepare_local_admission as planning
from cwo_core import local_invocation as http
from cwo_core.host_records import HostRecordError
from cwo_core.invocation_ledger import LOCK_FILE, request_sha256
from cwo_core.packets import redact_text

RECORD_KEY = 'local_workload_admission'
INTENT_EVENT_TYPE = 'local_http_workload_invocation_intent'
WORKLOAD_FIELDS = {'route_input', 'node_id', 'node_attempts'}


def _require(condition, reason):
    if not condition:
        raise SystemExit(f'local HTTP workload admission refused: {reason}')


def _encode(value):
    return planning.reconciliation._encode(value)


@dataclass(frozen=True, slots=True)
class LocalWorkload:
    """Original controller input, held as detached canonical bytes."""

    original: bytes = field(repr=False)

    @classmethod
    def read(cls, path, captures):
        source = Path(path).absolute()
        try:
            with source.open('rb') as stream:
                raw = stream.read(planning.reconciliation.MAX_BYTES + 1)
            _require(len(raw) <= planning.reconciliation.MAX_BYTES, 'workload file exceeds its byte limit')
            value = planning.reconciliation._decode(raw)
            value, original = planning.reconciliation._snapshot(value)
        except (OSError, ValueError, RecursionError) as exc:
            raise SystemExit('local HTTP workload admission refused: invalid workload file') from exc
        _require(type(value) is dict and set(value) == WORKLOAD_FIELDS, 'workload fields differ')
        captures.append((str(source), raw))
        return cls(original)

    def inputs(self):
        return json.loads(self.original)

    def route_node(self):
        workload = self.inputs()
        route = workload['route_input']
        _require(type(route) is dict and type(route.get('nodes')) is list, 'original workload has no route graph')
        matches = [node for node in route['nodes'] if type(node) is dict and node.get('id') == workload['node_id']]
        _require(len(matches) == 1, 'workload must select one declared route node')
        return route, matches[0]

    def task(self):
        _, node = self.route_node()
        _require(type(node.get('prompt')) is str, 'workload prompt must be text')
        sections = [node['prompt']]
        for label in ('wrappers', 'attachments', 'sources'):
            entries = node.get(label)
            _require(type(entries) is list, 'workload request components must be lists')
            sections.extend(_render_entry(label, entry) for entry in entries)
        return redact_text('\n\n'.join(sections), require_policy_patterns=True)


def _render_entry(label, entry):
    _require(type(entry) is dict and type(entry.get('id')) is str and type(entry.get('text')) is str,
             'workload entry must have an identity and text')
    return f'{label} [{entry["id"]}]\n{entry["text"]}'


def _check_execution(workload, envelope, post, prepared):
    route, node = workload.route_node()
    execution = json.loads(prepared.execution_bytes)
    options = envelope['request_options']
    _require(envelope['bead_id'] == route['parent_id'] and envelope['epic_id'] == route['aggregate_id'],
             'original workload parent or aggregate differs from dispatch')
    _require(envelope['messages'][-1]['content'].partition('\n\nTask:\n')[2] == workload.task(),
             'rendered dispatch differs from the original redacted workload request')
    _require((execution['executor'], execution['provider'], execution['model'], execution['options']) ==
             (envelope['executor_key'], envelope['provider_key'], envelope['model'], options),
             'original executor, provider, model or request options differ')
    _require(not execution['tool_surface'] and execution['effort'] == options.get('reasoning_effort', 'default'),
             'original effort or tool surface differs')
    _require(options.get('max_tokens') == execution['output_tokens_upper'] > 0,
             'request requires the original positive output-token limit')
    _require(0 < envelope['timeout_seconds'] <= json.loads(prepared.amounts_bytes)['runtime_seconds'],
             'HTTP timeout exceeds the original workload runtime allowance')
    overhead = max(0, len(post.data) - len(prepared.request_bytes))
    _require(node['additional_input_tokens_upper'] >= overhead * route['projection_policy']['tokens_per_utf8_byte_upper'],
             'whole-workload sizing omits HTTP serialization overhead')


def _prepare(workload, envelope, post, preflight, *, issue, expiry, ledger_identity):
    original = workload.inputs()
    try:
        prepared = planning.prepare(original['route_input'], original['node_id'], now=issue, expires_at=expiry)
        prior = planning._prior_attempts(prepared, original['node_attempts'])
    except (ValueError, OSError) as exc:
        raise SystemExit('local HTTP workload admission refused: original workload failed planning or lineage checks') from exc
    _check_execution(workload, envelope, post, prepared)
    binding = {
        'version': 1, 'issued_at': issue, 'expires_at': expiry,
        'workload_sha256': planning._receipt_sha256(prepared),
        'requests_sha256': request_sha256(_encode(http.reserved_requests(post, preflight))),
        'envelope_sha256': request_sha256(_encode({key: value for key, value in envelope.items()
                                                   if key != 'execution_enabled'})),
        'prior_attempts_sha256': request_sha256(_encode(prior)),
        'ledger_sha256': ledger_identity,
    }
    return prepared, prior, {**binding, 'binding_sha256': request_sha256(_encode(binding))}


def _ledger_identity(ledger, *, provision=False):
    if not provision:
        _require((ledger.root / LOCK_FILE).is_file(), 'original reservation ledger is missing')
    try:
        with ledger._locked() as (root, _document):
            info = root.stat()
            return request_sha256(_encode([str(root), info.st_dev, info.st_ino, ledger._guard()['lock']]))
    except (ValueError, OSError) as exc:
        raise SystemExit('local HTTP workload admission refused: original reservation ledger unavailable') from exc


def stage(workload, envelope, post, preflight):
    """Create metadata for the original host dispatch record without opening a connection."""
    ledger = http.open_ledger()
    now = ledger.current_time()
    prepared, prior, binding = _prepare(workload, envelope, post, preflight, issue=now,
        expiry=now + planning.MAX_LIFETIME_SECONDS, ledger_identity=_ledger_identity(ledger, provision=True))
    try:
        planning._graph_state(prepared, prior, ledger)
        ledger.open_budget(prepared.budget_id, json.loads(prepared.limits_bytes), scope_sha256=prepared.scope_sha256)
    except (ValueError, OSError) as exc:
        raise SystemExit('local HTTP workload admission refused: original graph or aggregate is unavailable') from exc
    return binding


def require_saved(store, dispatch_id):
    try:
        record = store.require_dispatch(dispatch_id)
    except HostRecordError as exc:
        raise SystemExit('local HTTP workload admission requires the original staged host record') from exc
    metadata = record.get('evaluation_metadata', {}).get(RECORD_KEY)
    _require(type(metadata) is dict and all(key in metadata for key in ('issued_at', 'expires_at')),
             'original host record contains no workload admission')
    return record, metadata


class _NetworkDeadline:
    """Bound local waiting and close connected transport at the original cutoff."""

    def __init__(self, remaining):
        self.remaining = remaining
        self.timers = []

    def resolve(self, resolver, *args, **options):
        result = Future()

        def resolve_only():
            try:
                result.set_result(resolver(*args, **options))
            except BaseException as failure:
                result.set_exception(failure)

        timeout = self.remaining()
        # The platform resolver can outlive a local cutoff. It never receives
        # an opener, request body, credentials, or authority to connect.
        Thread(target=resolve_only, daemon=True).start()
        try:
            return result.result(timeout=timeout)
        except TimeoutError as exc:
            raise http.InvocationTimeout('local HTTP endpoint lookup timed out') from exc

    @staticmethod
    def _disconnect(connection):
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def watch(self, connection):
        timer = Timer(self.remaining(), self._disconnect, args=(connection,))
        timer.daemon = True
        self.timers.append(timer)
        timer.start()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        for timer in self.timers:
            timer.cancel()


class _WorkloadIntent:
    def __init__(self, handle, ledger, prepared, prior, store, record, binding, validate_configuration, deadline):
        self.handle, self.ledger, self.prepared, self.prior = handle, ledger, prepared, prior
        self.store, self.record, self.binding = store, record, binding
        self.validate_configuration, self.deadline = validate_configuration, deadline
        self.completed = False
        self.network = _NetworkDeadline(self.remaining)

    def record_intent(self):
        attempt = self.handle.require_intent()
        self.store.record_audit_event({'event_type': INTENT_EVENT_TYPE, 'dispatch_id': self.record['dispatch_id'],
            'local_http_dispatch_record_sha256': self.record['_record_sha256'],
            'local_http_attempt_id': attempt['attempt_id'], 'local_http_admission_sha256': self.binding['binding_sha256']})

    def require_live(self):
        self.validate_configuration()
        record, _ = require_saved(self.store, self.record['dispatch_id'])
        _require(record['_record_sha256'] == self.record['_record_sha256'], 'original host admission changed')
        _require(_ledger_identity(self.ledger) == self.binding['ledger_sha256'], 'original reservation ledger changed')
        live = self.handle.require_intent()
        _require(live['admission_sha256'] == self.binding['binding_sha256'], 'persisted admission differs')
        try:
            self.store.require_audit_event(INTENT_EVENT_TYPE, local_http_attempt_id=live['attempt_id'],
                local_http_admission_sha256=self.binding['binding_sha256'],
                local_http_dispatch_record_sha256=self.record['_record_sha256'])
        except HostRecordError as exc:
            raise SystemExit('local HTTP workload admission refused: original host intent is unavailable') from exc
        try:
            planning._graph_state(self.prepared, self.prior, self.ledger, live['attempt_id'])
        except (ValueError, OSError) as exc:
            raise SystemExit('local HTTP workload admission refused: original graph, policy or expiry drifted') from exc
        self.remaining()

    def remaining(self):
        remaining = min(self.prepared.expires_at - self.ledger.current_time(), self.deadline - time.monotonic())
        if remaining <= 0:
            raise http.InvocationTimeout('local HTTP workload admission deadline expired; remote status is unknown')
        return remaining


def _reserve(ledger, prepared, prior, binding):
    try:
        planning._live(prepared, ledger)
        lineage = planning._graph_state(prepared, prior, ledger)
        return ledger.reserve(
            budget_id=prepared.budget_id, request_id=prepared.node_id,
            request_sha256=request_sha256(prepared.request_bytes), admission_sha256=binding['binding_sha256'],
            amount=json.loads(prepared.amounts_bytes), expires_at=prepared.expires_at,
            lineage=lineage, refuse_while_unresolved=True)
    except (ValueError, OSError, http.InvocationLedgerError) as exc:
        raise SystemExit('local HTTP workload admission refused: original allowance, dependencies or time are unavailable') from exc


@contextmanager
def invocation_scope(workload, envelope, post, preflight, store, validate_configuration):
    record, saved = require_saved(store, envelope['dispatch_id'])
    ledger = http.open_ledger()
    identity = _ledger_identity(ledger)
    _require(identity == saved.get('ledger_sha256'), 'original reservation ledger changed')
    prepared, prior, binding = _prepare(workload, envelope, post, preflight, issue=saved['issued_at'],
                                        expiry=saved['expires_at'], ledger_identity=identity)
    _require(_encode(binding) == _encode(saved), 'request or workload differs from the original host admission')
    already_consumed = any(event.get('event_type') == INTENT_EVENT_TYPE
                           and event.get('local_http_admission_sha256') == binding['binding_sha256']
                           for event in store.audit_events())
    _require(not already_consumed, 'original host workload admission already has a durable invocation intent')
    reservation = _reserve(ledger, prepared, prior, binding)
    deadline = time.monotonic() + envelope['timeout_seconds']
    gate = None
    try:
        with ledger.invocation(reservation['reservation_id'], prepared.request_bytes) as handle:
            intent = _WorkloadIntent(handle, ledger, prepared, prior, store, record, binding, validate_configuration, deadline)
            try:
                with http.reserved_local_invocation(envelope, post, preflight, ledger=ledger) as gate, intent.network:
                    gate.bind_workload(intent)
                    intent.record_intent()
                    yield gate
                    intent.require_live()
            except SystemExit as exc:
                failure = http._RouteTimeout if gate is not None and gate.timed_out else http._RouteStopped
                raise failure(exc) from exc
            except TimeoutError as exc:
                raise http._RouteTimeout(exc) from exc
            handle.record('completed' if intent.completed else 'failed', None)
    except (http._RouteStopped, http._RouteTimeout, http._RouteCancelled) as stopped:
        http._raise_route_failure(stopped)
