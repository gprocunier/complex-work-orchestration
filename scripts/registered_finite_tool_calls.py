"""Finite host-owned dynamic tools for the registered N=1 fake-server route.

The app-server's native shell and write_stdin are not mediated here. A caller
must provide an exact loopback Responses capture before a turn; any catalog
containing those builtins refuses registration. Native tool qualification remains separate.
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
_SCHEMAS = {_COMMAND: _COMMAND_SCHEMA, _POLL: _POLL_SCHEMA}
_CAPTURE_NAME = 'finite-tool-capture.json'
_CAPTURE_TOKEN = object()
_DECISION_TOKEN = object()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tool_specs():
    return [{'type': 'function', 'name': name, 'description': _DESCRIPTIONS[name],
             'inputSchema': copy.deepcopy(_SCHEMAS[name])} for name in (_COMMAND, _POLL)]


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


class CapturedToolSurface:
    """One-use offline observation, issued from the owned fake server spool."""

    def __init__(self, token, server, lifetime, epoch, raw, identity):
        if token is not _CAPTURE_TOKEN:
            raise FiniteToolError('A protected fake-server observation is required.')
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
    identity: tuple
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
    def thread_parameters():
        """The pinned experimental thread/start.dynamicTools wire field."""
        return {'dynamicTools': _tool_specs()}

    def _expected_start(self):
        expected = dict(self.factory.spec['thread_start'], model=self.factory.spec['model'],
                        allowProviderModelFallback=False,
                        cwd=str(self.factory.host.worker),
                        runtimeWorkspaceRoots=[str(self.factory.host.worker)])
        expected.update(self.thread_parameters())
        return expected

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
        raw, identity = _read_capture_file(Path(self.factory.home) / _CAPTURE_NAME)
        if (identity != captured.identity or hashlib.sha256(raw).hexdigest() != captured.raw_sha256
                or raw != captured._raw):
            raise FiniteToolError('The captured catalog changed before registration.')
        payload = captured.payload
        if payload['start'] != start or payload['response'] != response:
            raise FiniteToolError('Captured startup or source binding differs.')
        catalog = require_exact_capture(self.factory.spec['model'], payload['request'])
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
                and captured._raw == observed.raw and captured.identity == observed.identity)

    def _startup_current(self, observed, start, response):
        thread = response.get('thread') if type(response) is dict else None
        return (start == self._expected_start()
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

    def register(self, start, response, captured_request):
        """Publish a real captured catalog only after the reader can still fault.

        File and original-authority observations happen outside both state
        locks. Each publication uses a short in-memory commit fence.
        """
        self.factory.require_finite_fake_capture()
        self.factory.require_effect()
        self.factory.guard()
        observed = self._require_capture_binding(start, response, captured_request)
        self.factory.require_finite_fake_capture()
        self.factory.require_effect()
        self.factory.guard()
        self._begin_registration(observed, start, response)
        try:
            self.factory.record('finite-tool-catalog', {
                'start_sha256': self.start_sha256, 'catalog_sha256': observed.catalog_sha256,
                'thread': self.thread, 'epoch': self.epoch})
            self.factory.require_finite_fake_capture()
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
                and item.get('namespace') is None
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
        self.factory.require_finite_fake_capture()
        raw, identity = _read_capture_file(Path(self.factory.home) / _CAPTURE_NAME)
        if (identity != self.capture_identity
                or hashlib.sha256(raw).hexdigest() != self.capture_sha256):
            raise FiniteToolError('Captured fake-server catalog changed after registration.')

    @staticmethod
    def _params(message):
        request = protocol.classify_message(message)
        if type(request) is not protocol.ServerRequest or request.method != 'item/tool/call':
            raise FiniteToolError('Only the pinned dynamic tool request is supported.')
        params = json.loads(request.params_json)
        if (set(params) not in ({'arguments', 'callId', 'threadId', 'tool', 'turnId'},
                                {'arguments', 'callId', 'namespace', 'threadId', 'tool', 'turnId'})
                or any(not _text(params.get(key)) for key in ('callId', 'threadId', 'turnId'))
                or params.get('namespace') is not None or params['tool'] not in {_COMMAND, _POLL}
                or type(params['arguments']) is not dict):
            raise FiniteToolError('Dynamic tool identity or fields differ.')
        return request, params

    def receive(self, message, *, deadline=None):
        """Handle one actual server request and return its pinned response frame.

        The registered server sends the returned frame through its existing
        bounded protocol writer. A refusal returns a method-valid failure,
        never an accepting substitute.
        """
        request, params = self._params(message)
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
            else:
                data = self._poll(params, deadline)
            self._require_call_current(params)
            self._require_capture_current()
            return {'id': request.request_id, 'result': {
                'contentItems': [{'type': 'inputText', 'text': self._output_text(params['tool'], data)}],
                'success': True}}
        except (FiniteToolError, ValueError) as failure:
            self._cleanup_failed_call(params['tool'], failure)
            self.factory.record('finite-tool-refusal', {
                'tool': params['tool'], 'call': params['callId'], 'reason': type(failure).__name__})
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

    @staticmethod
    def _output_text(tool, data):
        if tool == _COMMAND and type(data) is bytes:
            return data.decode('utf-8', 'strict')
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
        if tool == _COMMAND:
            original = item['text']
        elif tool == _POLL:
            payload = json.loads(item['text'])
            if (type(payload) is not dict or set(payload) != {'running', 'stdout'}
                    or type(payload['running']) is not bool or type(payload['stdout']) is not str):
                raise FiniteToolError('The original finite poll result changed before commit.')
            original = payload['stdout']
        else:
            raise FiniteToolError('Only the selected finite reply can be refreshed.')
        merged = original.encode('utf-8') + tail
        if len(merged) > 4096:
            raise FiniteToolError('The naturally completed tool output exceeded its bound.')
        text = merged.decode('utf-8', 'strict')
        item['text'] = text if tool == _COMMAND else _canonical(
            {'stdout': text, 'running': False}).decode('utf-8')

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
        self._require_deadline(deadline)
        self.server.finite_input.observe_process()
        args = params['arguments']
        if (set(args) != {'commandCallId', 'chars'}
                or args['commandCallId'] != self.command_call_id
                or type(args['chars']) is not str or len(args['chars'].encode('utf-8')) > 4096
                or self.state != 'active'):
            raise FiniteToolError('Poll command or byte shape differs.')
        chars = args['chars'].encode('utf-8')
        # The exact original bytes reach the invocation gate before any process input.
        ticket = self.server.finite_input.reserve(
            chars, thread_id=params['threadId'], turn_id=params['turnId'],
            item_id=self.command_call_id, approval_id=params['callId'],
            deadline=min(deadline, time.monotonic() + 1))
        self.server.finite_input.lifecycle.move('poll-observe', call=params['callId'])
        observation = self.server.finite_input.poll(ticket)
        if observation['stdin_bytes'] != b'' or type(observation['running']) is not bool:
            raise FiniteToolError('Finite poll observation differs.')
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
