"""Finite host-owned dynamic tools for the registered N=1 transport.

Offline registration requires the fake server's exact Responses capture. Live
qualification uses the original app-server exchange and records finite tool
input at the owned pipe. Native builtin shell and write_stdin are separate.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import select
import stat
import threading
from dataclasses import dataclass
import time
from pathlib import Path

from cwo_core import server_request_preparation as protocol
from registered_n1_qualification import FINITE_TOOL_NAMESPACE


class FiniteToolError(ValueError):
    """A finite tool request was refused before any process input."""


_COMMAND = 'finite_command'
_POLL = 'finite_poll'
_COMMAND_SCHEMA = {'type': 'object', 'properties': {'command': {'type': 'string'}},
                   'required': ['command'], 'additionalProperties': False}
_POLL_SCHEMA = {'type': 'object', 'properties': {'commandCallId': {'type': 'string'},
                                             'chars': {'type': 'string'}},
                'required': ['commandCallId', 'chars'], 'additionalProperties': False}
_DESCRIPTIONS = {
    _COMMAND: 'Run the one registered finite command in its owned worktree.',
    _POLL: 'Poll with exactly empty input; returns JSON stdout and running status. Nonempty input is refused.',
}
_QUALIFICATION_DESCRIPTIONS = {
    _COMMAND: 'Run the one registered finite command in its owned worktree. '
              'Returns JSON with commandCallId, stdout, and running.',
    _POLL: 'Poll using commandCallId from the finite_command result and chars set to an empty string. '
           'Returns JSON stdout and running status. Nonempty input is refused.',
}
_SCHEMAS = {_COMMAND: _COMMAND_SCHEMA, _POLL: _POLL_SCHEMA}
_CAPTURE_NAME = 'finite-tool-capture.json'
_CAPTURE_TOKEN = object()
_DECISION_TOKEN = object()
_HISTORY_PASSTHROUGH = 'internal_chat_message_metadata_passthrough'
_HISTORY_ITEM_FIELDS = {'id', 'id_allocation', _HISTORY_PASSTHROUGH}
FAKE_CAPTURE_MODE = 'captured-host-tools'
LIVE_CAPTURE_MODE = 'captured-live-host-tools'
CAPTURE_MODES = frozenset({FAKE_CAPTURE_MODE, LIVE_CAPTURE_MODE})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tool_specs(*, live_capture=False):
    descriptions = _QUALIFICATION_DESCRIPTIONS if live_capture else _DESCRIPTIONS
    tools = [{'type': 'function', 'name': name, 'description': descriptions[name],
              'inputSchema': copy.deepcopy(_SCHEMAS[name])} for name in (_COMMAND, _POLL)]
    if not live_capture:
        return tools
    return [{'type': 'namespace', 'name': FINITE_TOOL_NAMESPACE,
             'description': 'Registered finite command and empty input poll.', 'tools': tools}]


def _response_tools():
    return [{'type': 'function', 'name': name, 'description': _DESCRIPTIONS[name],
             'parameters': copy.deepcopy(_SCHEMAS[name])} for name in (_COMMAND, _POLL)]


def _text(value):
    return type(value) is str and 0 < len(value) <= 256


def require_exact_capture(model, captured_request):
    """Reject every observed tool other than the two registered host tools.

    This checks the full request shape; the protected host must separately
    establish that the bytes came from its selected model connection.
    """
    if (type(captured_request) is not dict
            or set(captured_request) != {'model', 'tools'}
            or captured_request['model'] != model
            or captured_request['tools'] != _response_tools()):
        raise FiniteToolError('Captured catalog exposes an unregistered or native builtin tool.')
    return _digest(captured_request)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise FiniteToolError('Duplicate captured model-request field.')
        value[key] = item
    return value


@dataclass
class _QualifiedCall:
    request_key: tuple
    epoch: str
    tool: str
    arguments: bytes
    poll_input: str | None = None
    reply: tuple[bool, str] | None = None
    reply_deadline: float | None = None
    reply_sent: bool = False
    reply_failed: bool = False
    completed: bool = False


def _typed_reply(content, success):
    if (type(success) is not bool or type(content) is not list or len(content) != 1
            or type(content[0]) is not dict or set(content[0]) != {'type', 'text'}
            or content[0]['type'] != 'inputText' or type(content[0]['text']) is not str):
        raise FiniteToolError('Qualification requires the original typed finite tool result.')
    return success, content[0]['text']


class QualifiedToolEvidence:
    """One qualification transport's original call, write and notification facts.

    All mutations occur under the original server request lock. Reads take
    that lock after the trusted rollout descriptor has been captured.
    """

    def __init__(self, server):
        self.server = server
        self.calls = {}
        self.completed_turn = None
        self.settlement = threading.Condition(server.requests.lock)

    @staticmethod
    def _identity(params):
        return params['threadId'], params['turnId'], params['callId']

    def admit(self, request, params):
        identity = self._identity(params)
        self.calls[identity] = _QualifiedCall(protocol._id_key(request.request_id),
            self.server.connection_epoch_sha256, params['tool'], _canonical(params['arguments']))
        self.settlement.notify_all()

    def poll_input(self, observed, outcome, delivered):
        identity = observed['thread'], observed['turn'], observed['call']
        with self.server.requests.lock:
            call = self.calls.get(identity)
            if (call is None or call.tool != _POLL or call.epoch != observed['epoch']
                    or call.request_key != protocol._id_key(observed['request_id'])
                    or call.poll_input is not None or delivered != b''
                    or outcome not in {'empty-poll', 'refused-nonempty'}):
                raise FiniteToolError('Qualification poll input observation differs from the original call.')
            call.poll_input = outcome

    def begin_reply(self, message, response, deadline):
        result = response.get('result')
        if result is None:
            return None
        params = message['params']
        call = self.calls.get(self._identity(params))
        reply = _typed_reply(result.get('contentItems'), result.get('success'))
        if (call is None or call.epoch != self.server.connection_epoch_sha256
                or call.request_key != protocol._id_key(message['id']) or call.tool != params['tool']
                or call.arguments != _canonical(params['arguments']) or call.reply is not None):
            raise FiniteToolError('Qualification reply differs from the original finite call.')
        if call.tool == _POLL and call.poll_input != ('empty-poll' if reply[0] else 'refused-nonempty'):
            if reply[0] or call.poll_input is not None:
                raise FiniteToolError('Qualification poll result differs from its zero-byte input record.')
            return None
        call.reply = reply
        call.reply_deadline = deadline
        return call

    def cancel_reply(self, call):
        if call is not None:
            if call.completed:
                self.fail_reply(call)
                raise FiniteToolError('Qualification completion preceded an unwritten tool reply.')
            call.reply = None
            call.reply_deadline = None

    def fail_reply(self, call):
        if call is not None:
            with self.settlement:
                call.reply_failed = True
                self.settlement.notify_all()

    def finish_reply(self, call, committed):
        if call is not None:
            call.reply_sent = committed
            call.reply_failed = not committed
            self.settlement.notify_all()

    def observe_turn_terminal(self, params):
        turn = params.get('turn', {})
        identity = params.get('threadId'), turn.get('id')
        if turn.get('status') == 'completed' and self._completion_turn_open(identity):
            self.completed_turn = identity

    def can_settle_terminal_reply(self, call, binding):
        return (call is not None and call.completed and not call.reply_failed
                and self.completed_turn == binding[2:4]
                and self.server.transport_failure is None and not self.server.requests.closed
                and self.server.requests.cancelled_turn != self.completed_turn)

    def _completion_turn_open(self, turn):
        requests = self.server.requests
        wire_turn = self.server._wire_turn
        return (wire_turn is not None and wire_turn[:2] == turn
                and not requests.closed
                and turn not in requests.terminals and turn not in requests.trusted_terminals
                and turn != requests.cancelled_turn and self.server.transport_failure is None)

    def complete(self, params, item):
        identity = params.get('threadId'), params.get('turnId'), item.get('id')
        call = self.calls.get(identity)
        reply = _typed_reply(item.get('contentItems'), item.get('success'))
        if (call is None or call.epoch != self.server.connection_epoch_sha256
                or not self._completion_turn_open(identity[:2])
                or item.get('namespace') != FINITE_TOOL_NAMESPACE or item.get('tool') != call.tool
                or _canonical(item.get('arguments')) != call.arguments
                or item.get('status') != ('completed' if reply[0] else 'failed')
                or call.completed or call.reply != reply):
            raise FiniteToolError('Qualification completion differs from the original finite reply attempt.')
        call.completed = True

    def completion(self, identity):
        call = self.calls.get(identity)
        if call is None or not call.completed:
            return None
        return 'committed' if call.reply_sent else 'pending'

    def project(self, thread, turn, records, receipts, terminal):
        # The reader may observe the durable call before the original callback
        # is accepted. Only an exact original completion can attest a result.
        with self.server.requests.lock:
            self._project(thread, turn, records, receipts, terminal)

    def _project(self, thread, turn, records, receipts, terminal):
        calls, outputs = _rollout_finite_pairs(records, turn)
        if len(calls) != len(receipts):
            raise FiniteToolError('Qualification rollout contains unregistered or unmatched tool activity.')
        for receipt in receipts:
            call_id = receipt['call_id']
            raw = calls.get(call_id)
            if raw is None or raw[0] != receipt['tool']:
                raise FiniteToolError('Qualification rollout tool identity differs from the paired receipt.')
            output = outputs.get(call_id)
            expected = ('paired', 'paired-unknown') if output is not None else ('unpaired', 'unpaired-call')
            if (receipt.get('pairing_status'), receipt['typed_result']['kind']) != expected:
                raise FiniteToolError('Qualification rollout is not one exact direct call and text result.')
            identity = thread, turn, call_id
            call = (self._wait_original_call(identity) if output is None and not terminal
                    else self.calls.get(identity))
            result = self._result(raw, output, call)
            if result == 'paired-pending' and terminal:
                self._wait_terminal_reply(call, output)
                result = self._result(raw, output, call)
            receipt['typed_result']['kind'] = result
            receipt['_registered_finite'] = True
        if terminal and any(identity[:2] == (thread, turn) and identity[2] not in calls
                            for identity in self.calls):
            raise FiniteToolError('Qualification terminal rollout omitted an original finite call.')

    def _wait_original_call(self, identity):
        # An advancing rollout can briefly lead the protocol reader. Wait
        # on its existing next obligation with the request lock released.
        turn = identity[:2]
        if identity not in self.calls and self._completion_turn_open(turn):
            lifecycle = self.server.finite_input.lifecycle
            with lifecycle.condition:
                deadlines = [entry[2] for entry in lifecycle.pending.values()]
                if lifecycle.edge_deadline is not None:
                    deadlines.append(lifecycle.edge_deadline)
            if deadlines:
                self.settlement.wait_for(
                    lambda: identity in self.calls or not self._completion_turn_open(turn),
                    timeout=max(0, min(deadlines) - time.monotonic()))
        return self.calls.get(identity)

    def _wait_terminal_reply(self, call, output):
        # The trusted terminal may be durable before the in-flight writer
        # publishes its full result. No later action reads this condition.
        if output is not None and call.completed and call.reply_deadline is not None:
            self.settlement.wait_for(lambda: call.reply_sent or call.reply_failed,
                                     timeout=max(0, call.reply_deadline - time.monotonic()))
            if call.reply_sent:
                return
        raise FiniteToolError('Qualification turn ended before original finite evidence settled.')

    def _result(self, raw, output, call):
        if call is None:
            raise FiniteToolError('Qualification rollout has no original finite callback.')
        if call.epoch != self.server.connection_epoch_sha256 or (call.tool, call.arguments) != raw:
            raise FiniteToolError('Qualification rollout arguments differ from the original finite call.')
        if output is None:
            return 'paired-pending'
        if call.reply is None or call.reply[1] != output:
            raise FiniteToolError('Qualification rollout output differs from the original finite reply.')
        if not call.completed or not call.reply_sent:
            return 'paired-pending'
        return 'paired-success' if call.reply[0] else 'paired-failure'


def _rollout_finite_pairs(records, turn):
    calls, outputs, item_ids = {}, {}, set()
    for record in records:
        item = record.get('payload')
        if record.get('type') != 'response_item' or type(item) is not dict:
            continue
        kind = item.get('type')
        if kind not in ('function_call', 'function_call_output'):
            continue
        _check_rollout_history(item, turn)
        if item['id'] in item_ids:
            raise FiniteToolError('Qualification rollout metadata repeats a response item ID.')
        item_ids.add(item['id'])
        if kind == 'function_call':
            call, tool, arguments = _rollout_finite_call(item)
            if call in calls:
                raise FiniteToolError('Repeated qualification rollout call.')
            calls[call] = tool, arguments
        else:
            call = item.get('call_id')
            if (set(item) - _HISTORY_ITEM_FIELDS != {'type', 'call_id', 'output'} or not _text(call)
                    or call not in calls or call in outputs or type(item['output']) is not str):
                raise FiniteToolError('Qualification rollout output shape or order differs.')
            outputs[call] = item['output']
    return calls, outputs


def _uint64(value):
    return type(value) is int and 0 <= value < 2 ** 64


def _history_item_allocation(value):
    return (type(value) is dict and not set(value) - {'prefix', 'salt', 'ordinal', 'value', 'suffix'}
            and _text(value.get('salt')) and _uint64(value.get('ordinal')) and _uint64(value.get('value'))
            and all(key not in value or _text(value[key]) for key in ('prefix', 'suffix')))


def _history_payload_metadata(item, turn):
    metadata = item.get(_HISTORY_PASSTHROUGH)
    if type(metadata) is not dict or set(metadata) - {'turn_id', 'create_time'} or metadata.get('turn_id') != turn:
        return False
    created = metadata.get('create_time', 0)
    return type(created) in (int, float) and 0 <= created < 2 ** 64


def _check_rollout_history(item, turn):
    if (not _text(item.get('id')) or not _history_payload_metadata(item, turn)
            or ('id_allocation' in item and not _history_item_allocation(item['id_allocation']))):
        raise FiniteToolError('Qualification rollout metadata differs from the original turn or retained item shape.')


def _rollout_finite_call(item):
    call, tool, arguments = item.get('call_id'), item.get('name'), item.get('arguments')
    if (set(item) - _HISTORY_ITEM_FIELDS != {'type', 'call_id', 'name', 'namespace', 'arguments'}
            and set(item) - _HISTORY_ITEM_FIELDS != {'type', 'call_id', 'name', 'namespace', 'arguments', 'status'}):
        raise FiniteToolError('Qualification rollout call is outside the direct finite namespace.')
    if (item.get('status', 'completed') != 'completed'
            or item.get('namespace') != FINITE_TOOL_NAMESPACE or not _text(call)
            or tool not in (_COMMAND, _POLL) or type(arguments) is not str):
        raise FiniteToolError('Qualification rollout call is outside the direct finite namespace.')
    try:
        parsed = json.loads(arguments, object_pairs_hook=_unique_object)
        if type(parsed) is dict:
            return call, tool, _canonical(parsed)
    except (ValueError, RecursionError) as exc:
        raise FiniteToolError('Qualification rollout lacks exact finite arguments.') from exc
    raise FiniteToolError('Qualification rollout lacks exact finite arguments.')


class CapturedToolSurface:
    """One-use observation bound to the selected owned app-server lifetime."""

    def __init__(self, token, server, lifetime, epoch, raw, identity):
        if token is not _CAPTURE_TOKEN:
            raise FiniteToolError('A protected tool observation is required.')
        self.server, self.lifetime, self.epoch = server, lifetime, epoch
        self._raw = raw
        self.identity = identity
        self.raw_sha256 = hashlib.sha256(raw).hexdigest()
        self.used = False

    @property
    def payload(self):
        # A caller never receives the stored parsed object to mutate in place.
        return json.loads(self._raw.decode('utf-8'), object_pairs_hook=_unique_object)

    def __reduce_ex__(self, protocol):
        raise FiniteToolError('Captured tool observations cannot be serialized.')


def _read_capture_file(path):
    # Open must not wait for a writer before we can reject a special file.
    # This is the shared observation for startup, registration and every
    # command/gate/reply recheck; type validation precedes all file reads.
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
                or not 0 < info.st_size <= 65536):
            raise FiniteToolError('The fake-server capture file is not protected and bounded.')
        raw = os.read(descriptor, 65537)
        after = os.fstat(descriptor)
        identity = info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        observed = after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        if len(raw) != info.st_size or observed != identity:
            raise FiniteToolError('The fake-server capture changed while read.')
    finally:
        os.close(descriptor)
    return raw, identity


def read_fake_server_capture(server):
    """Read only the selected offline fake server's bounded actual observation.

    The protected factory must select this offline mode before the thread starts.
    A capture is corroborating evidence; it never grants native live authority.
    """
    server.factory.require_finite_fake_capture()
    lifetime = server.lifetime
    if (lifetime.factory is not server.factory or lifetime.process is not server.process
            or lifetime.receipt is None or lifetime._ending or lifetime.contained
            or server.connection_epoch_sha256 is None or server.requests.closed):
        raise FiniteToolError('The original fake-server process is not current.')
    raw, identity = _read_capture_file(Path(server.factory.home) / _CAPTURE_NAME)
    payload = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    if type(payload) is not dict or set(payload) != {'start', 'response', 'request'}:
        raise FiniteToolError('The fake-server capture has an unsupported shape.')
    return CapturedToolSurface(_CAPTURE_TOKEN, server, lifetime,
                               server.connection_epoch_sha256, raw, identity)


@dataclass(frozen=True)
class _RegistrationObservation:
    # This in-process observation retains the factory-issued capture object.
    # Digests corroborate exact bytes; neither digest grants registration.
    capture: CapturedToolSurface
    server: object
    factory: object
    lifetime: object
    source: object
    epoch: str
    raw: bytes
    identity: object
    catalog_sha256: str
    generation: int


class FiniteToolDecision:
    """Private one-call decision issued by the protected factory callback."""

    def __init__(self, token, factory, tool, params):
        if token is not _DECISION_TOKEN:
            raise FiniteToolError('An issued finite-tool decision is required.')
        self.factory, self.tool = factory, tool
        self.params_sha256 = _digest(params)
        self.used = False

    def __reduce_ex__(self, protocol):
        raise FiniteToolError('Finite-tool decisions cannot be serialized.')


def issue_finite_tool_decision(factory, tool, params):
    """Call only inside the protected factory's fresh per-call review callback."""
    factory.require_effect()
    if tool not in {_COMMAND, _POLL} or type(params) is not dict:
        raise FiniteToolError('An exact finite-tool request is required.')
    return FiniteToolDecision(_DECISION_TOKEN, factory, tool, params)


class RegisteredFiniteToolCalls:
    """Parent-selected producer bound to one original registered transport.

    The producer is inert until an exact captured catalog is armed. The
    original factory must call ``receive`` only for ``item/tool/call`` and
    must close this object with its registered transport lifetime.
    """

    def __init__(self, server):
        self.server = server
        self.factory = server.factory
        self.live_capture = self.factory.spec.get('finite_tool_mode') == LIVE_CAPTURE_MODE
        self.namespace = FINITE_TOOL_NAMESPACE if self.live_capture else None
        self.lock = threading.RLock()
        self.state = 'unregistered'
        self.epoch = None
        self.thread = None
        self.catalog_sha256 = None
        self.start_sha256 = None
        self.capture_identity = self.capture_sha256 = None
        self.calls = set()
        self.command_call_id = None
        self.lifetime = None
        self.process = None
        self.inflight = None
        self.launch_decision = None

    @staticmethod
    def thread_parameters(*, live_capture=False):
        """The pinned experimental thread/start.dynamicTools wire field."""
        return {'dynamicTools': _tool_specs(live_capture=live_capture)}

    def _require_capture_source(self):
        if self.live_capture:
            self.factory.require_finite_live_capture()
        else:
            self.factory.require_finite_fake_capture()

    def _read_capture(self):
        if not self.live_capture:
            return _read_capture_file(Path(self.factory.home) / _CAPTURE_NAME)
        server = self.server
        evidence = server._effective_thread_start_evidence.get(server.thread_id)
        if type(evidence) is not dict or set(evidence) != {'request', 'response'}:
            raise FiniteToolError('The original app-server thread exchange is unavailable.')
        raw = _canonical({'start': evidence['request'], 'response': evidence['response']})
        if not 0 < len(raw) <= 65536:
            raise FiniteToolError('The original app-server thread exchange exceeds its bound.')
        return raw, evidence

    def _same_capture_identity(self, left, right):
        return left is right if self.live_capture else left == right

    def _open_capture(self):
        if not self.live_capture:
            return read_fake_server_capture(self.server)
        raw, identity = self._read_capture()
        return CapturedToolSurface(_CAPTURE_TOKEN, self.server, self.server.lifetime,
                                   self.server.connection_epoch_sha256, raw, identity)

    def _catalog_digest(self, start, payload):
        if self.live_capture:
            if start.get('dynamicTools') != _tool_specs(live_capture=True):
                raise FiniteToolError('The original app-server tool registration differs.')
            return _digest(start['dynamicTools'])
        return require_exact_capture(self.factory.spec['model'], payload['request'])

    def _require_capture_binding(self, start, response, captured):
        # The bounded file read and JSON validation may block. Neither the
        # reader's request lock nor the state lock is held during observation.
        if (type(captured) is not CapturedToolSurface or captured.used
                or captured.server is not self.server
                or captured.lifetime is not self.server.lifetime
                or captured.epoch != self.server.connection_epoch_sha256):
            raise FiniteToolError('Captured startup or source binding differs.')
        gate = self.server.finite_input
        with gate.lock:
            if gate.state != 'unselected' or gate.capture_phase != 'unselected':
                raise FiniteToolError('Finite registration was revoked before capture observation.')
            generation = gate.generation
        raw, identity = self._read_capture()
        if (not self._same_capture_identity(identity, captured.identity)
                or hashlib.sha256(raw).hexdigest() != captured.raw_sha256
                or raw != captured._raw):
            raise FiniteToolError('The captured catalog changed before registration.')
        payload = captured.payload
        if payload['start'] != start or payload['response'] != response:
            raise FiniteToolError('Captured startup or source binding differs.')
        catalog = self._catalog_digest(start, payload)
        return _RegistrationObservation(captured, self.server, self.factory,
                                        captured.lifetime, self.factory._source,
                                        captured.epoch, raw, identity, catalog, generation)

    def _capture_observation_current(self, observed):
        captured = observed.capture
        return (observed.server is self.server and observed.factory is self.factory
                and self.factory.server is self.server
                and observed.source is self.factory._source
                and observed.lifetime is self.server.lifetime
                and captured.server is self.server
                and captured.lifetime is observed.lifetime
                and captured.epoch == observed.epoch == self.server.connection_epoch_sha256
                and captured._raw == observed.raw
                and self._same_capture_identity(captured.identity, observed.identity))

    def _startup_current(self, observed, start, response):
        thread = response.get('thread') if type(response) is dict else None
        return (start == self.factory._thread_start_parameters()
                and response == self.server._profile_response
                and type(thread) is dict and _text(thread.get('id'))
                and thread.get('turns') == []
                and observed.lifetime.receipt is not None
                and observed.lifetime.process is self.server.process
                and not observed.lifetime._ending and not observed.lifetime.contained)

    def _transport_open(self):
        return (self.server.transport_failure is None
                and not self.server.requests.closed
                and not self.server.requests.refusal_only)

    def _registration_current(self, observed, start, response):
        # Bounded in-memory comparisons under the state and request locks.
        # The issued capture/factory/lifetime objects are authority inputs;
        # serialized hashes are byte evidence, never independent grants.
        gate = self.server.finite_input
        return (self.state == 'unregistered' and not observed.capture.used
                and gate.state == 'unselected'
                and gate.capture_phase == 'unselected'
                and gate.generation == observed.generation
                and self._capture_observation_current(observed)
                and self._startup_current(observed, start, response)
                and self._transport_open())

    def _begin_registration(self, observed, start, response):
        gate = self.server.finite_input
        with self.lock, gate.lock, self.server.requests.lock:
            if not self._registration_current(observed, start, response):
                raise FiniteToolError('Finite registration changed during capture observation.')
            observed.capture.used = True
            self.thread = response['thread']['id']
            self.epoch = observed.epoch
            self.start_sha256 = _digest(start)
            self.catalog_sha256 = observed.catalog_sha256
            self.capture_identity = observed.identity
            self.capture_sha256 = observed.capture.raw_sha256
            self.state = 'registering'
            gate.capture_phase = 'registering'
            gate.generation += 1

    def _finish_registration(self, observed, start, response):
        gate = self.server.finite_input
        with self.lock, gate.lock, self.server.requests.lock:
            if (self.state != 'registering'
                    or gate.state != 'unselected'
                    or gate.capture_phase != 'registering'
                    or gate.generation != observed.generation + 1
                    or not self._transport_open()
                    or not self._capture_record_current(observed, start, response)):
                if self.state == 'registering':
                    self.state = 'failed'
                if gate.capture_phase == 'registering':
                    gate.capture_phase = 'revoked'
                    gate.generation += 1
                raise FiniteToolError('Finite registration closed during catalog record.')
            self.state = 'registered'
            gate.capture_phase = 'registered'
            gate.generation += 1

    def _capture_record_current(self, observed, start, response):
        return (observed.capture.used
                and self._capture_observation_current(observed)
                and self._startup_current(observed, start, response))

    def _record_catalog(self, observed):
        detail = {'start_sha256': self.start_sha256, 'catalog_sha256': observed.catalog_sha256,
                  'thread': self.thread, 'epoch': self.epoch}
        if self.live_capture:
            detail.update(source='registered-app-server', exchange_sha256=self.capture_sha256)
        self.factory.record('finite-tool-catalog', detail)

    def register(self, start, response):
        """Publish a real captured catalog only after the reader can still fault.

        File and original-authority observations happen outside both state
        locks. Each publication uses a short in-memory commit fence.
        """
        self._require_capture_source()
        self.factory.require_effect()
        self.factory.guard()
        observed = self._require_capture_binding(start, response, self._open_capture())
        self._require_capture_source()
        self.factory.require_effect()
        self.factory.guard()
        self._begin_registration(observed, start, response)
        try:
            self._record_catalog(observed)
            self._require_capture_source()
            self.factory.require_effect()
            self.factory.guard()
        except BaseException:
            gate = self.server.finite_input
            with self.lock, gate.lock:
                if self.state == 'registering':
                    self.state = 'failed'
                if gate.capture_phase == 'registering':
                    gate.capture_phase = 'revoked'
                    gate.generation += 1
            raise
        self._finish_registration(observed, start, response)

    def _current_transport(self, thread, turn, call):
        server = self.server
        return (self.state in {'registered', 'active'}
                and server.finite_input.capture_phase == 'registered'
                and server.connection_epoch_sha256 == self.epoch
                and server.transport_failure is None and not server.requests.closed
                and not server.requests.refusal_only
                and server._wire_turn is not None and server._wire_turn[:2] == (thread, turn)
                and thread == self.thread
                and (thread, turn) not in server.requests.terminals
                and (thread, turn) not in server.requests.trusted_terminals
                and (thread, turn) != server.requests.cancelled_turn
                and (thread, turn, call) not in server.requests.completed_items)

    def _current_adapter(self, thread, turn):
        adapter = self.factory.adapter
        return (adapter is not None and adapter.server is self.server
                and adapter.thread_id == thread and adapter._effective_boundary_armed
                and (adapter.turn_id == turn or
                     (adapter.turn_id is None and adapter._boundary_phase == 'dispatch-attempted'
                      and adapter._effective_boundary_send_reserved))
                and adapter._effective_boundary['thread_response'] == self.server._profile_response)

    def _current_item(self, params):
        item = self.server._items.get((params['threadId'], params['turnId'], params['callId']))
        return (type(item) is dict and item.get('type') == 'dynamicToolCall'
                and item.get('status') == 'inProgress' and item.get('id') == params['callId']
                and item.get('tool') == params['tool']
                and item.get('namespace') == self.namespace
                and item.get('arguments') == params['arguments'])

    def _current(self, params):
        thread, turn, call = params['threadId'], params['turnId'], params['callId']
        return (self._current_transport(thread, turn, call)
                and self._current_adapter(thread, turn) and self._current_item(params))

    def _require_call_current(self, params):
        with self.lock, self.server.requests.lock:
            if self.inflight != params['callId'] or not self._current(params):
                raise FiniteToolError('The original finite tool call is no longer current.')

    @staticmethod
    def _require_deadline(deadline):
        now = time.monotonic()
        if type(deadline) not in (int, float) or not now < deadline <= now + 15.1:
            raise FiniteToolError('The queued finite tool call expired before effect.')

    @staticmethod
    def _deadline_or_default(deadline):
        return time.monotonic() + 15 if deadline is None else deadline

    def release_gate(self, descriptor, params, deadline):
        """Open one fresh child gate under the final call/turn/expiry fence."""
        if type(descriptor) is not int or type(params) is not dict:
            raise FiniteToolError('A selected owned gate and call are required.')
        gate = self.server.finite_input
        with self.lock, gate.lock, self.server.requests.lock, gate.lifecycle.condition:
            self._require_deadline(deadline)
            if (self.inflight != params.get('callId') or not self._current(params)
                    or gate.state != 'unselected' or gate.pending_lifetime is None
                    or not gate.lifecycle.call_live(params['callId'], {'gate-closed'})):
                raise FiniteToolError('The original command ended before gate release.')
            os.set_blocking(descriptor, False)
            # The phase admission linearizes immediately before the one-byte
            # nonblocking effect while the same locks exclude revocation.
            gate.lifecycle.move('gate-release', call=params['callId'])
            try:
                released = os.write(descriptor, b'1')
            except BaseException:
                gate.lifecycle.finish('fault')
                raise
            if released != 1:
                gate.lifecycle.finish('fault')
                raise FiniteToolError('The selected child gate was not released atomically.')

    def require_launch(self, params, deadline, decision):
        """Only the producer's current issued command may create a retained child."""
        if type(params) is not dict:
            raise FiniteToolError('A producer-issued command call is required.')
        gate = self.server.finite_input
        with self.lock, gate.lock, self.server.requests.lock, gate.lifecycle.condition:
            self._require_deadline(deadline)
            if (self.state != 'registered' or self.lifetime is not None
                    or self.inflight != params.get('callId')
                    or params.get('tool') != _COMMAND or not self._current(params)
                    or not gate.lifecycle.call_live(params['callId'], {'command-intent'})
                    or type(decision) is not FiniteToolDecision
                    or decision is not self.launch_decision or not decision.used
                    or decision.factory is not self.factory or decision.tool != _COMMAND
                    or decision.params_sha256 != _digest(params)):
                raise FiniteToolError('No current source-approved command may launch.')
            self.launch_decision = None

    def _require_capture_current(self):
        self._require_capture_source()
        raw, identity = self._read_capture()
        if (not self._same_capture_identity(identity, self.capture_identity)
                or hashlib.sha256(raw).hexdigest() != self.capture_sha256):
            surface = 'app-server exchange' if self.live_capture else 'fake-server catalog'
            raise FiniteToolError(f'Captured {surface} changed after registration.')

    @staticmethod
    def _params(message, *, namespace=None):
        request = protocol.classify_message(message)
        if type(request) is not protocol.ServerRequest or request.method != 'item/tool/call':
            raise FiniteToolError('Only the pinned dynamic tool request is supported.')
        params = json.loads(request.params_json)
        if (set(params) not in ({'arguments', 'callId', 'threadId', 'tool', 'turnId'},
                                {'arguments', 'callId', 'namespace', 'threadId', 'tool', 'turnId'})
                or any(not _text(params.get(key)) for key in ('callId', 'threadId', 'turnId'))
                or params.get('namespace') != namespace or params['tool'] not in {_COMMAND, _POLL}
                or type(params['arguments']) is not dict):
            raise FiniteToolError('Dynamic tool identity or fields differ.')
        return request, params

    def receive(self, message, *, deadline=None):
        """Handle one actual server request and return its pinned response frame.

        The registered server sends the returned frame through its existing
        bounded protocol writer. A refusal returns a method-valid failure,
        never an accepting substitute.
        """
        request, params = self._params(message, namespace=self.namespace)
        deadline = self._deadline_or_default(deadline)
        self._require_capture_current()
        with self.lock, self.server.requests.lock:
            call = params['callId']
            key = protocol._id_key(request.request_id)
            if (self.inflight is not None or call in self.calls or key in self.calls
                    or not self._current(params)):
                raise FiniteToolError('Stale, repeated or mismatched tool call.')
            self.calls.update((call, key))
            self.inflight = call
            if self.live_capture:
                self.server.qualified_tool_evidence.admit(request, params)
        try:
            self.server.finite_input.lifecycle.require_request(key, call)
            self._require_deadline(deadline)
            decision = self.factory.decide_finite_tool(params['tool'], params)
            if (type(decision) is not FiniteToolDecision or decision.used
                    or decision.factory is not self.factory or decision.tool != params['tool']
                    or decision.params_sha256 != _digest(params)):
                raise FiniteToolError('Fresh source-approved tool decision is required.')
            decision.used = True
            self._require_deadline(deadline)
            self.server.finite_input.lifecycle.move(
                'decide-command' if params['tool'] == _COMMAND else 'decide-poll',
                call=call)
            if params['tool'] == _COMMAND:
                data = self._command(params, deadline, decision)
            elif self.live_capture:
                data = self._poll_input(params, deadline, request=request)
            else:
                data = self._poll(params, deadline)
            self._require_call_current(params)
            self._require_capture_current()
            return {'id': request.request_id, 'result': {
                'contentItems': [{'type': 'inputText', 'text': self._output_text(params, data)}],
                'success': True}}
        except (FiniteToolError, ValueError) as failure:
            self._cleanup_failed_call(params['tool'], failure)
            self.factory.record('finite-tool-refusal', {
                'tool': params['tool'], 'call': params['callId'], 'reason': type(failure).__name__, 'message': str(failure)})
            return {'id': request.request_id, 'result': {
                'contentItems': [{'type': 'inputText', 'text': 'finite-tool-request-refused'}],
                'success': False}}
        finally:
            with self.lock:
                self.inflight = None
                self.launch_decision = None

    def _cleanup_failed_call(self, tool, failure):
        gate = self.server.finite_input
        if (tool != _COMMAND and gate.state != 'revoked'):
            return
        if all(lifetime is None for lifetime in (
                self.lifetime, gate.lifetime, gate.pending_lifetime, gate.closed_lifetime)):
            return
        gate.close(failure)
        with self.lock:
            if self.state != 'closed':
                self.state = 'failed'

    def _command_output_text(self, call, data):
        stdout = data.decode('utf-8', 'strict')
        if not self.live_capture:
            return stdout
        return _canonical({'commandCallId': call, 'stdout': stdout,
                           'running': self.server.finite_input.terminal_code is None}).decode('utf-8')

    def _output_text(self, params, data):
        tool = params['tool']
        if tool == _COMMAND and type(data) is bytes:
            return self._command_output_text(params['callId'], data)
        if (tool == _POLL and type(data) is dict and type(data.get('stdout')) is bytes
                and data.get('stdin_bytes') == b'' and type(data.get('running')) is bool):
            return _canonical({'stdout': data['stdout'].decode('utf-8', 'strict'),
                               'running': data['running']}).decode('utf-8')
        raise FiniteToolError('A bounded original tool output is required.')

    def refresh_terminal_reply(self, message, response, deadline):
        """Include a clean exit first observed after the producer's initial read."""
        if response.get('result', {}).get('success') is not True:
            return
        if self.server.finite_input.observe_process() != 'clean-exited':
            return
        params = message.get('params', {})
        tool = params.get('tool')
        item = response['result']['contentItems'][0]
        if item.get('type') != 'inputText' or type(item.get('text')) is not str:
            raise FiniteToolError('The original finite reply changed before commit.')
        tail = self.server.finite_input.drain_terminal_output(
            self.process.stdout.fileno(), b'', deadline, params=params)
        payload = self._terminal_reply_payload(tool, params, item['text'])
        original = item['text'] if payload is None else payload['stdout']
        merged = original.encode('utf-8') + tail
        if len(merged) > 4096:
            raise FiniteToolError('The naturally completed tool output exceeded its bound.')
        text = merged.decode('utf-8', 'strict')
        if payload is not None:
            payload.update(stdout=text, running=False)
            text = _canonical(payload).decode('utf-8')
        item['text'] = text

    def _terminal_reply_payload(self, tool, params, text):
        if tool == _COMMAND and not self.live_capture:
            return None
        if tool not in {_COMMAND, _POLL}:
            raise FiniteToolError('Only the selected finite reply can be refreshed.')
        fields = {'running', 'stdout'}
        if tool == _COMMAND:
            fields.add('commandCallId')
        payload = json.loads(text)
        if (type(payload) is not dict or set(payload) != fields
                or (tool == _COMMAND and payload['commandCallId'] != params['callId'])
                or type(payload['running']) is not bool or type(payload['stdout']) is not str):
            description = 'command' if tool == _COMMAND else 'poll'
            raise FiniteToolError(f'The original finite {description} result changed before commit.')
        return payload

    def _command(self, params, deadline, decision):
        if (self.state != 'registered' or self.lifetime is not None
                or params['arguments'] != {'command': self.factory.spec['command']}):
            raise FiniteToolError('Only the fresh parent-selected command may launch.')
        self.factory.require_effect()
        self._require_capture_current()
        gate = self.server.finite_input
        token, generation, lifecycle_generation = gate.reserve_command_intent(params, deadline)
        try:
            self.factory.record('finite-tool-command-intent', {
                'operation': self.factory.operation_id, 'thread': params['threadId'],
                'turn': params['turnId'], 'item': params['callId'],
                'command_sha256': hashlib.sha256(self.factory.spec['command'].encode()).hexdigest(),
                'epoch': self.epoch, 'catalog_sha256': self.catalog_sha256,
                'reservation_generation': generation,
                'reservation_lifecycle_generation': lifecycle_generation,
                'intent_state': 'reserved'})
            self.factory.require_effect()
            self._require_deadline(deadline)
            self._require_capture_current()
            self._require_call_current(params)
        except BaseException as failure:
            gate._abort_intent(token, 'command', params['callId'], generation,
                               lifecycle_generation, failure)
            raise
        gate.publish_command_intent(token, generation, lifecycle_generation,
                                    params, deadline)
        with self.lock:
            self.launch_decision = decision
        import registered_n1_factory as registered
        lifetime = registered._Containment(self.factory, role='tool')
        try:
            process = lifetime.launch(['/usr/bin/sh', '-c', self.factory.spec['command']],
                                      self.factory.home, tool_call=params, deadline=deadline,
                                      tool_decision=decision)
            if process.stdin is None or process.stdout is None:
                raise FiniteToolError('Owned tool pipes are unavailable.')
            with self.lock:
                if self.state != 'registered':
                    raise FiniteToolError('Tool registration ended during launch.')
                self.lifetime, self.process = lifetime, process
                self.command_call_id = params['callId']
            self.server.finite_input.bind_owned_process(lifetime)
            self.server.finite_input.bind_dynamic_command(
                params['threadId'], params['turnId'], params['callId'])
            self._require_call_current(params)
            with self.lock:
                if self.state != 'registered':
                    raise FiniteToolError('Tool registration ended during binding.')
                self.state = 'active'
            data = self._read_output(deadline, params)
            self._require_call_current(params)
            self._require_capture_current()
            return data
        except BaseException as failure:
            gate.close(failure)
            with self.lock:
                if self.state != 'closed':
                    self.state = 'failed'
            raise

    def _poll(self, params, deadline):
        return self._poll_input(params, deadline)

    def _poll_input(self, params, deadline, *, request=None):
        self._require_deadline(deadline)
        gate = self.server.finite_input
        gate.observe_process()
        args = params['arguments']
        if (set(args) != {'commandCallId', 'chars'}
                or args['commandCallId'] != self.command_call_id
                or type(args['chars']) is not str or len(args['chars'].encode('utf-8')) > 4096
                or self.state != 'active'):
            raise FiniteToolError('Poll command or byte shape differs.')
        chars = args['chars'].encode('utf-8')
        # The exact original bytes reach the invocation gate before any process input.
        capture_arguments = {}
        if request is not None:
            capture_arguments['captured'] = gate.capture_poll_input(request, params, chars)
        ticket = gate.reserve(
            chars, thread_id=params['threadId'], turn_id=params['turnId'],
            item_id=self.command_call_id, approval_id=params['callId'],
            deadline=min(deadline, time.monotonic() + 1), **capture_arguments)
        gate.lifecycle.move('poll-observe', call=params['callId'])
        observation = gate.poll(ticket)
        if observation['stdin_bytes'] != b'' or type(observation['running']) is not bool:
            raise FiniteToolError('Finite poll observation differs.')
        if request is not None:
            gate.record_poll_input(capture_arguments['captured'], 'empty-poll', observation['stdin_bytes'])
        return observation

    def _read_output(self, deadline, params):
        descriptor = self.process.stdout.fileno()
        if select.select([descriptor], [], [], 0.1)[0]:
            try:
                data = self.server.finite_input.read_stdout(descriptor, deadline, params=params)
            except BlockingIOError:
                return b''
            state = self.server.finite_input.observe_process()
            if (not data and state != 'clean-exited') or len(data) > 4096:
                raise FiniteToolError('Owned tool EOF or output bound ended the finite command.')
            if state == 'clean-exited':
                data = self.server.finite_input.drain_terminal_output(
                    descriptor, data, deadline, params=params)
            data.decode('utf-8', 'strict')
            return data
        if self.server.finite_input.observe_process() == 'clean-exited':
            return self.server.finite_input.drain_terminal_output(
                descriptor, b'', deadline, params=params)
        return b''

    def close(self):
        with self.lock:
            self.state = 'closed'
            lifetime = self.lifetime
        # A concurrent closer must observe the same result. Returning solely
        # because the producer state says closed would hide an in-flight owner.
        self.server.finite_input.close()
        if lifetime is not None:
            lifetime.settle_termination()
