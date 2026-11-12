"""Finite EXAMPLE profile/input adapter for the original cooperative offline host.

This supplies no production transport or OS containment qualification. The only
process is a fixed cooperative stdio fixture, launched inside the offline runner.
"""
from __future__ import annotations

import dataclasses
import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import weakref
from contextlib import contextmanager

import offline_admitted_n1 as admitted
import prepare_delivery_closure as closure
import prepare_server_request_frames as frames
import profile_preparation_diagnostics as profiles
from cwo_core import server_request_preparation as requests

_CAPABILITIES = {"EXAMPLE_FINITE": "finite", "EXAMPLE_STDIN": "authorized-stdin"}
_FALSE = dict.fromkeys(("effect_authority", "production_ready", "qualified", "accepted_for_use"), False)
_lock = threading.RLock()
_selections = weakref.WeakKeyDictionary()
_grants = weakref.WeakKeyDictionary()
_history = {}
_server_history = weakref.WeakKeyDictionary()
_server_selections = weakref.WeakKeyDictionary()
_entries = weakref.WeakKeyDictionary()
_SERVER_TYPE = None
_SERVER_START = None
_CLOCK_TYPE = None
_OWNER_TYPE = None
_CHILD = """import hashlib,json,sys
raw=sys.stdin.buffer.read(65537)
assert len(raw)<=65536
record=json.loads(raw)
chars=record['chars'].encode('utf-8')
print(json.dumps({'input_sha256':hashlib.sha256(chars).hexdigest(),
 'context':record['context'],'output':'EXAMPLE cooperative input output\\n'}))
"""


class InputError(ValueError):
    """A pre-effect refusal in the finite fake adapter."""


def _need(condition, message):
    if not condition:
        raise InputError(message)


def _encode(value):
    return closure.validation._snapshot(value, 65536)


def _issued(registry, kind, token):
    _need(type(token) is kind and token in registry, "An original issued input token is required.")
    return registry[token]


class OfflineProfileAdapter(admitted.native.LiveThreadAdapter):
    """Original native driver with an explicit fake named-profile start validator."""

    def _validate_effective_boundary(self, boundary):
        _profile_start(boundary, self.worktree)
        # Validate the remaining original invariants without changing the actual
        # issued request, captured boundary, response, or dispatched server.
        view = copy.deepcopy(boundary)
        request = view["thread_start"]["request"]
        for key in ("permissions", "approvalsReviewer", "ephemeral"):
            request.pop(key)
        request.update(sandbox="workspace-write" if self.mutable else "read-only", approvalPolicy="never")
        view["thread_start"]["response"]["approvalPolicy"] = "never"
        view["thread_response"]["approvalPolicy"] = "never"
        super()._validate_effective_boundary(view)


_PROFILE_VALIDATOR = OfflineProfileAdapter._validate_effective_boundary


def require_original_adapter(adapter):
    _need(type(adapter) is OfflineProfileAdapter, "The exact original or offline profile adapter is required.")
    for name, (original, static) in admitted.native._METHODS.items():
        expected = _PROFILE_VALIDATOR if name == "_validate_effective_boundary" else original
        bound = getattr(adapter, name)
        observed = bound if static else getattr(bound, "__func__", None)
        _need(observed is expected and (static or getattr(bound, "__self__", None) is adapter),
              "Original native adapter methods and the exact offline profile validator are required.")


def _profile_start(boundary, worker):
    request = boundary["thread_start"]["request"]
    response = boundary["thread_start"]["response"]
    _need(_encode(response) == _encode(boundary["thread_response"])
          and _encode(response.get("thread")) == _encode(boundary["thread"]),
          "Original issued response, adapter response and thread must agree before validation.")
    selected = request.get("permissions")
    _need(selected in _CAPABILITIES, "The actually issued thread requires a known named profile.")
    expected = {"model": response["model"], "allowProviderModelFallback": False,
        "permissions": selected, "approvalPolicy": "untrusted", "approvalsReviewer": "user",
        "ephemeral": True, "cwd": str(worker), "runtimeWorkspaceRoots": [str(worker)]}
    _need(_encode(request) == _encode(expected), "Actual thread selectors, approval settings or workspace differ.")
    _need(response.get("activePermissionProfile") == {"id": selected, "extends": None}
          and response.get("approvalPolicy") == "untrusted" and response.get("approvalsReviewer") == "user",
          "Actual named-profile readback or approval settings differ from the issued thread.")
    return selected


def ExampleProfileServer(root, worker, task, preparation):
    """Load the EXAMPLE fixture only when explicitly constructing a fake server."""
    global _SERVER_TYPE, _SERVER_START, _CLOCK_TYPE, _OWNER_TYPE
    if _SERVER_TYPE is None:
        kind, clock_type, owner_type = _example_server_type()
        with _lock:
            if _SERVER_TYPE is None:
                _SERVER_TYPE, _SERVER_START = kind, kind.start_turn
                _CLOCK_TYPE, _OWNER_TYPE = clock_type, owner_type
    return _SERVER_TYPE(root, worker, task, preparation)


def _example_server_type():
    from test_offline_admitted_n1 import AdmittedFakeServer
    from test_invocation_ledger import FakeClock, FakeOwners

    class _ExampleProfileServer(AdmittedFakeServer):
        """Issue the actual fake thread; input enters only at original native dispatch."""

        def __init__(self, root, worker, task, preparation):
            super().__init__(root, worker, task)
            _need(profiles.diagnose(preparation)["preparation_accepted"], "Invalid fake profile preparation.")
            self._profile_preparation = _encode(preparation)

        def thread_response(self, *, mutable=False):
            response = super().thread_response(mutable=mutable)
            preparation = json.loads(self._profile_preparation)
            request = self._effective_thread_start_evidence[self.thread_id]["request"]
            request.pop("sandbox")
            request.update(preparation["thread_start"])
            selected = request["permissions"]
            response.update(approvalPolicy="untrusted", approvalsReviewer="user",
                            activePermissionProfile={"id": selected, "extends": None})
            self._effective_thread_start_evidence[self.thread_id] = copy.deepcopy({"request": request, "response": response})
            return response

        def start_turn(self, thread_id, message):
            with _server_entry(self, thread_id, message):
                return super().start_turn(thread_id, message)

    return _ExampleProfileServer, FakeClock, FakeOwners


@contextmanager
def _server_entry(server, thread_id, message):
    with _lock:
        reference = _server_selections.get(server)
        selection = reference() if reference is not None else None
    with _selected(selection) as data:
        _need(data.adapter._boundary_phase == "dispatch-attempted"
              and thread_id == data.adapter.thread_id and message == data.admission.request_bytes.decode("utf-8"),
              "Input consumer entry must follow the original final dispatch checks.")
        with _lock:
            _need(server not in _entries, "The original input consumer is already entered.")
            _entries[server] = (selection, thread_id, message, threading.get_ident())
        try:
            yield
        finally:
            with _lock:
                del _entries[server]


class _Token:
    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise InputError("Input tokens must be issued, never constructed.")

    def __reduce_ex__(self, protocol):
        raise InputError("Input tokens cannot be copied or serialized.")


class InputSelection(_Token):
    __slots__ = ()


class InputGrant(_Token):
    __slots__ = ()

    @property
    def report(self):
        with _lock:
            grant = _issued(_grants, InputGrant, self)
            return {**json.loads(grant.context), "input_sha256": hashlib.sha256(grant.chars).hexdigest(),
                    **_FALSE, "containment_scope": "cooperative EXAMPLE stdio fixture only"}


@dataclasses.dataclass(frozen=True)
class _Selection:
    declaration: object
    admission: object
    route: object
    node: str
    ledger: object
    host: object
    adapter: object
    server: object
    control: object
    pins: object
    preparation: object
    process: object
    handles: tuple
    context: bytes
    item: object
    timestamp: int


@dataclasses.dataclass
class _Grant:
    selection: object
    chars: bytes
    context: bytes
    used: bool = False


class ExampleInputProcess:
    """One fixed cooperative child, not a command executor or isolation backend."""

    def __init__(self, worker):
        self.worker = admitted.native._path(worker)
        self.exchanges = []

    def _exchange(self, chars, context, worker):
        _need(os.environ.get("CWO_PY") in ("312", "314"), "The fixed offline runner is required.")
        _need(not self.exchanges, "The EXAMPLE input process is one-shot; retry is forbidden.")
        record = {"chars": chars, "context": json.loads(_encode(context))}
        payload = _encode({"chars": chars.decode("utf-8"), "context": record["context"]})
        self.exchanges.append(record)
        child = subprocess.Popen([sys.executable, "-I", "-S", "-c", _CHILD], cwd=worker,
            env={}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output, error = child.communicate(payload, timeout=5)
        except BaseException:
            child.kill()
            child.wait()
            raise
        _need(child.returncode == 0 and not error and len(output) <= 65536,
              "The cooperative EXAMPLE child failed; no retry is permitted.")
        observed = json.loads(output)
        _need(observed["context"] == context
              and observed["input_sha256"] == hashlib.sha256(chars).hexdigest(),
              "The actual EXAMPLE child input observation differs.")
        return {**observed, "output": observed["output"].encode("utf-8"), **_FALSE}


_EXCHANGE = ExampleInputProcess._exchange


def _configuration(preparation, adapter, worker, thread_id):
    server = adapter.server
    report = profiles.diagnose(preparation)
    _need(report["preparation_accepted"], "The original fake profile preparation refused configuration.")
    _need(set(preparation) == {"fake", "schema_version", "bundle", "experimental_api", "inventory", "thread_start"},
          "The selected no-grants configuration must be complete and unamended.")
    thread = preparation["thread_start"]
    selected = thread["permissions"]
    _need(selected in _CAPABILITIES, "Unknown selected EXAMPLE input profile.")
    _need(thread == {"permissions": selected, "approvalPolicy": "untrusted", "approvalsReviewer": "user",
                     "cwd": str(worker), "ephemeral": True}, "Selected approval settings or workspace widened.")
    _need(type(server) is _SERVER_TYPE and server.start_turn.__func__ is _SERVER_START,
          "The actual original offline profile producer and dispatch consumer are required.")
    _need(server._profile_preparation == _encode(preparation)
          and _profile_start(adapter._current_effective_boundary(), worker) == selected,
          "Preparation must bind the actual issued thread configuration and readback.")
    expected = {"profile": selected, "policy_id": preparation["inventory"]["expected_policy_id"],
                "thread_id": thread_id, "cwd": str(worker), "input_capability": _CAPABILITIES[selected],
                "network": False, "grants": [], "rules": [], "hooks": []}
    observed = getattr(server, "offline_profile_observation", None)
    _need(_encode(observed) == _encode(expected),
          "Required effective fake profile metadata is missing, unknown, widened or drifted.")
    return expected


def _no_effect(*args):
    raise InputError("Selection validation cannot invoke an effect.")


def _binding(declaration, admission, route_input, node_id, ledger, host, adapter, contract,
             configuration_pins, preparation, process):
    declared = closure._declared(declaration)
    _need(declared.host is host, "The original issued declaration must select this host.")
    _fake_state_handles(ledger)
    fresh = admitted.admission_api._validated(admission, route_input, node_id, ledger, _no_effect, None)
    owner = ledger._current_owner()
    _need(ledger.owner_probe.status(owner) == "alive", "The original fake owner must be known alive.")
    return _scope_binding(declaration, fresh, host, adapter, contract, configuration_pins,
                          preparation, process, owner)


def _scope_binding(declaration, admission, host, adapter, contract, configuration_pins,
                   preparation, process, owner):
    """Check protected scope without clock, owner, ledger or user callouts."""
    declared = closure._declared(declaration)
    _need(declared.host is host, "The original issued declaration must select this host.")
    _need(closure.validation._host(host) == declared.roots
          and closure.validation._snapshot(host._initial) == declared.initial
          and closure.validation._snapshot(host._observe()) == declared.initial,
          "The original declared candidate or host identities drifted.")
    task = admission.request_bytes.decode("utf-8")
    admitted.native._task_contract("EXAMPLE_INPUT", task, contract)
    admitted.native._adapter_binding(adapter, contract, task, host.worker, host.state)
    _need(type(process) is ExampleInputProcess and type(process.worker) is type(host.worker)
          and process.worker == host.worker and type(process.exchanges) is list,
          "The selected original EXAMPLE process and worker must match.")
    metadata = _configuration(preparation, adapter, host.worker, adapter.thread_id)
    return {**metadata, "admission_sha256": admitted.admission_api._receipt_sha256(admission),
            "owner": owner, "candidate": host._initial["target"], "control": contract,
            "declaration": declaration.report, "configuration_pins": admitted.native._pins(configuration_pins)}


def _item(server, adapter):
    item = getattr(server, "offline_input_context", None)
    _need(type(item) is requests.FakeItemContext and _plain_item(item),
          "Original pre-effect fake stdin context is required.")
    _need(item.kind == "writeStdin" and item.method == requests.COMMAND,
          "The original stdin method and kind are required.")
    _need((item.thread_id, item.turn_id, item.cwd, item.command) == (
        adapter.thread_id, server.turn_result_id, str(adapter.worktree), "EXAMPLE_INPUT_PROCESS"),
        "The original thread, turn, command and workspace context must match.")
    timestamp = getattr(server, "offline_input_started_at", None)
    _need(type(timestamp) is int and 0 <= timestamp < 2**63, "Known original input timestamp is required.")
    return item, timestamp


def _plain_item(item):
    texts = (item.epoch, item.thread_id, item.turn_id, item.item_id, item.approval_id)
    strings = (item.kind, item.method, item.command, item.cwd, item.provenance)
    return (all(requests._text(value) for value in texts)
            and all(type(value) is str for value in strings) and requests._paths(item.paths))


def _item_record(item):
    record = dataclasses.asdict(item)
    record["paths"] = list(item.paths)
    return record


def select_input(declaration, *, admission=None, route_input=None, node_id=None, ledger=None,
                 host=None, adapter=None, contract=None, configuration_pins=None,
                 preparation=None, process=None):
    """Bind one original declaration/admission and actual selected fake server observation."""
    closure._declared(declaration)
    _need(type(adapter) is OfflineProfileAdapter, "An actual offline named-profile adapter is required.")
    with adapter._boundary_lock:
        context = _binding(declaration, admission, route_input, node_id, ledger, host, adapter,
                           contract, configuration_pins, preparation, process)
        item, timestamp = _item(adapter.server, adapter)
        context["item"] = _item_record(item)
        context["started_at_ms"] = timestamp
        handles = admitted._ledger_handles(ledger)
        admitted._check_ledger(ledger, handles, host)
        _need(host._load() is None and adapter.turn_id is None and not adapter._effective_boundary_armed,
              "Input selection must precede the original invocation.")
        data = _Selection(declaration, admission, route_input, node_id, ledger, host, adapter,
            adapter.server, contract, configuration_pins, preparation, process,
            handles, _encode(context), item, timestamp)
        token = object.__new__(InputSelection)
        with _lock:
            _selections[token] = data
            _server_selections[adapter.server] = weakref.ref(token)
        return token


def _current(selection):
    with _lock:
        data = _issued(_selections, InputSelection, selection)
    _need(data.adapter.server is data.server, "The selected original fake server changed.")
    admitted._check_ledger(data.ledger, data.handles, data.host)
    context = _binding(data.declaration, data.admission, data.route, data.node, data.ledger,
        data.host, data.adapter, data.control, data.pins, data.preparation, data.process)
    item, timestamp = _item(data.server, data.adapter)
    context.update(item=_item_record(item), started_at_ms=timestamp)
    _need(_encode(context) == data.context, "Selected input receipt, owner, profile, capability or context drifted.")
    return data


@contextmanager
def _selected(selection):
    # Never hold the registry lock while acquiring native locks or validating.
    with _lock:
        data = _issued(_selections, InputSelection, selection)
    with data.adapter._boundary_lock:
        yield _current(selection)


def _approval(data, raw, decision):
    item = data.item
    consumer = requests.FakeRequestPreparer(item.epoch)
    consumer.open_turn(item.thread_id, item.turn_id, now=0)
    consumer.observe_item(item, now=0)
    batch = frames.FakeFrameReader(consumer).feed(raw, epoch=item.epoch, now=0)
    _need(len(batch.delivered) == 1 and batch.status.buffered_bytes == 0,
          "Exactly one complete original approval frame is required.")
    work = consumer.next_decision(now=0)
    _need(work is not None and work.method == requests.COMMAND, "A correlated command approval is required.")
    params = json.loads(work.params_json)
    _need(params["startedAtMs"] == data.timestamp, "Unknown required input timestamp.")
    consumer.prepare(work.correlation, decision, now=0)
    replies = consumer.drain_replies(now=0)
    _need(len(replies) == 1 and json.loads(replies[0].frame_json)["result"] == {"decision": "accept"},
          "The original no-grants approval consumer denied the input.")


def authorize_input(selection, raw, chars, *, decision):
    """Check actual raw approval through original consumers; issue a byte-bound one-shot token."""
    with _selected(selection) as data:
        _reserve_approval(data)
        _need(type(chars) is bytes and len(chars) <= 4096, "Input requires bounded exact UTF-8 bytes.")
        chars.decode("utf-8", errors="strict")
        _approval(data, raw, decision)
        _need(not chars or json.loads(data.context)["input_capability"] == "authorized-stdin",
              "The selected finite profile refuses nonempty input before the process.")
        token = object.__new__(InputGrant)
        with _lock:
            _grants[token] = _Grant(selection, chars, data.context)
        return token


def _reserve_approval(data):
    with _lock:
        root = str(data.handles[0])
        _need(root in _history or len(_history) < 256, "The finite approval ledger-history bound was reached.")
        history = _history.setdefault(root, set())
        server_history = _server_history.setdefault(data.server, set())
        _need(data.item.approval_id not in history and data.item.approval_id not in server_history
              and len(history) < 256 and len(server_history) < 256, "Approval identity reused or history bound reached.")
        # Retain denials and handle recreation; no edited frame can retry this identity.
        history.add(data.item.approval_id)
        server_history.add(data.item.approval_id)


def _intent(data, selection):
    with _lock:
        entry = _entries.get(data.server)
    _need(data.adapter._boundary_phase == "dispatch-attempted"
          and entry == (selection, data.adapter.thread_id, data.admission.request_bytes.decode("utf-8"), threading.get_ident()),
          "Delivery requires actual entry into the original native dispatch consumer.")
    _need(data.adapter._effective_boundary_send_reserved and data.adapter._effective_boundary_armed,
          "Delivery requires the actual original native send boundary.")
    stored = data.host._load()
    _need(stored is not None and stored["status"] == "reconciliation-required" and stored["receipt"] is None,
          "Delivery requires the original durable host invocation intent.")
    inputs = stored["binding"]
    _need(inputs["contract"] == data.control and inputs["task"] == data.admission.request_bytes.decode("utf-8")
          and inputs["configuration_pins"] == json.loads(data.context)["configuration_pins"],
          "The durable native input bindings differ from the selected input.")
    admitted._intent(data.ledger, data.admission)


def _fake_state_handles(ledger):
    _root, clock, owner, _fsync = admitted._ledger_handles(ledger)
    _need(type(clock) is _CLOCK_TYPE and type(owner) is _OWNER_TYPE,
          "The original fake clock and owner readback capability is required.")
    return clock, owner


def _unavailable_owner(value, key):
    _need(type(value) is set and len(value) <= 256, "Bounded original fake owner status sets are required.")
    for pair in value:
        _need(type(pair) is tuple and len(pair) == 2 and all(type(part) is int for part in pair),
              "Original fake owner status keys require plain integer pairs.")
    return key in value


def _guarded_facts(data, expected_owner):
    """Read actual registered fake producer state without invoking any callback."""
    clock, probe = _fake_state_handles(data.ledger)
    clock_state = object.__getattribute__(clock, "__dict__")
    owner_state = object.__getattribute__(probe, "__dict__")
    _need(type(clock_state) is dict and type(owner_state) is dict,
          "Original fake provider state dictionaries are required.")
    current = owner_state.get("me")
    _need(type(current) is dict and _encode(current) == _encode(expected_owner),
          "The actual selected owner changed during a callback.")
    current = json.loads(_encode(current))
    key = current["pid"], current["start_ticks"]
    _need(not _unavailable_owner(owner_state.get("gone"), key)
          and not _unavailable_owner(owner_state.get("unknown"), key),
          "The actual selected fake owner is gone or unknown.")
    now = clock_state.get("now")
    admitted.admission_api._time(now)
    _need(data.admission.issued_at <= now < data.admission.expires_at,
          "The actual fake admission clock is expired or outside its issue window.")
    return current


def _final_scope(data):
    """After the final ledger callout, compare scope and capture an immutable cwd."""
    admitted._check_ledger(data.ledger, data.handles, data.host)
    expected = json.loads(data.context)
    owner = _guarded_facts(data, expected["owner"])
    context = _scope_binding(data.declaration, data.admission, data.host, data.adapter,
        data.control, data.pins, data.preparation, data.process, owner)
    item, timestamp = _item(data.server, data.adapter)
    context.update(item=_item_record(item), started_at_ms=timestamp)
    _need(_encode(context) == data.context,
          "Protected input scope changed during the final owner or ledger callout.")
    worker = admitted.native._path(context["cwd"])
    _guarded_facts(data, owner)
    return worker


def deliver_input(selection, grant, chars, *, context):
    """Called at the original fake server send; direct or replayed dictionaries cannot deliver."""
    with _selected(selection) as data:
        with _lock:
            issued = _issued(_grants, InputGrant, grant)
        _need(issued.selection is selection and not issued.used and type(chars) is bytes
              and chars == issued.chars and issued.context == data.context,
              "A fresh original grant bound to the exact selection and bytes is required.")
        _need(type(context) is requests.FakeItemContext and context == data.item,
              "Delivery must preserve the original complete input context.")
        _intent(data, selection)
        admitted.admission_api._live(data.admission, data.ledger)
        _intent(data, selection)
        worker = _final_scope(data)
        with _lock:
            _need(not issued.used, "The original input grant was already used.")
            issued.used = True
        return _EXCHANGE(data.process, chars, json.loads(issued.context), worker)
