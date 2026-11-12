"""Bounded server request consumer for the registered server's actual wire observations.

This module supplies no authority. The original factory selects the host/command
and validates admission and maintenance authority for each decision and commit.
No FakeRequestPreparer context participates in a production grant.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import json
import os
import threading
import time

from cwo_core import server_request_preparation as protocol

# Captured command/file item terminal states; projections grant no context.
_ITEM_TERMINAL = frozenset({'completed', 'failed', 'declined'})


@dataclass
class _Pending:
    request: protocol.ServerRequest
    correlation: protocol.Correlation | None
    deadline: float
    state: str = 'queued'
    frame: bytes | None = None
    refusal: str | None = None
    expired: bool = False
    accepting: bool = False
    delivery: str = 'precommit'
    dispatch: object = None


class RegisteredServerRequests:
    """One finite connection, one decider, one independent deadline monitor.

    Reader transitions only touch bounded memory. Callouts never hold this lock
    or the original reader condition. Replies use a single nonblocking atomic
    pipe write, serialized with the original writer; backpressure is retried by
    the monitor until the same finite deadline. Reconnect is unsupported.
    """

    def __init__(self, server):
        self.server = server
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.closed = False
        self.refusal_only = False
        self.epoch = None
        self.entries = {}
        self.queue = deque()
        self.callbacks = set()
        self.approvals = set()
        self.terminals = set()
        self.completed_items = set()
        self.cancelled_turn = None
        self.trusted_terminals = set()
        self.threads = []

    def _start(self):
        if self.epoch is not None:
            return
        self.epoch = self.server.connection_epoch_sha256
        for name, target in (('decision', self._decide_loop), ('deadline', self._monitor)):
            thread = threading.Thread(target=target, name='cwo-registered-' + name, daemon=True)
            self.threads.append(thread)
            thread.start()

    def receive(self, message):
        request = protocol.classify_message(message)
        if type(request) is not protocol.ServerRequest:
            raise protocol.PreparationError('registered-server-request-required')
        with self.lock:
            if self.closed:
                raise protocol.PreparationError('registered-connection-closed')
            self._start()
            self._register(request)
        self.wake.set()

    def _latch_negative(self, kind, scope=None):
        # The plain registry has no shared reducer.
        pass

    def _commit_ingress(self, entry):
        return True

    def _commit_reply(self, entry):
        return None

    def _reply_result(self, entry, dispatch, result):
        pass

    def _register(self, request):
        key = protocol._id_key(request.request_id)
        if key in self.entries or len(self.entries) >= 64:
            raise protocol.PreparationError('registered-request-reused-or-bound')
        if sum(e.state != 'sent' for e in self.entries.values()) >= 16:
            raise protocol.PreparationError('registered-pending-bound')
        params = json.loads(request.params_json)
        correlation = None
        if request.method in {protocol.COMMAND, protocol.FILE, protocol.PERMISSIONS}:
            correlation = protocol.Correlation(self.epoch, request.request_id, params['threadId'],
                params['turnId'], params['itemId'], params.get('approvalId'))
        if correlation is not None:
            self._reserve(correlation, request.method)
        entry = _Pending(request, correlation, time.monotonic() + 5)
        self.entries[key] = entry
        if correlation is None:
            self._ready(entry, {'code': -32601, 'message': 'Unsupported server request'},
                        'Unknown required server request.', error=True)
        elif self._revoked(entry):
            self._refuse(entry, None, cancel=True)
        elif not self._current(entry):
            self._refuse(entry, 'Stale, reordered or post-terminal server request.')
        elif not self._commit_ingress(entry):
            self._refuse(entry, 'Original ingress lost the shared authority race.', cancel=True)
        elif (correlation.thread_id, correlation.turn_id, correlation.item_id) not in self.server._items:
            result = {'permissions': {}} if request.method == protocol.PERMISSIONS else {'decision': 'decline'}
            self._ready(entry, result)
        else:
            self.queue.append(key)

    def _reserve(self, correlation, method):
        c = correlation
        callback = c.thread_id, c.turn_id, c.item_id, method, c.approval_id
        if callback in self.callbacks or (c.approval_id is not None and c.approval_id in self.approvals):
            raise protocol.PreparationError('Repeated approval identity is refused.')
        self.callbacks.add(callback)
        if c.approval_id is not None:
            self.approvals.add(c.approval_id)

    def _current(self, entry):
        c = entry.correlation
        if (self.closed or self.refusal_only or self.server.transport_failure is not None or self.server.lifetime._ending
                or c is None or c.epoch != self.server.connection_epoch_sha256):
            return False
        if (c.thread_id, c.turn_id) in self.terminals or self._revoked(entry):
            return False
        item = c.thread_id, c.turn_id, c.item_id
        if item in self.completed_items:
            return False
        wire = self.server._wire_turn
        return wire is not None and wire[:2] == (c.thread_id, c.turn_id)

    def _locally_cancelled(self, entry):
        c = entry.correlation
        return c is not None and (c.thread_id, c.turn_id) == self.cancelled_turn

    def _revoked(self, entry):
        c = entry.correlation
        return self._locally_cancelled(entry) or (c is not None and
                (c.thread_id, c.turn_id) in self.trusted_terminals)

    def observe_trusted_terminal(self, thread_id, turn_id, boundary):
        """Negative evidence after the original adapter's trusted source checks."""
        terminal = boundary.get('terminal_event')
        if type(terminal) is not dict or terminal.get('status') not in {'completed', 'failed', 'interrupted'}:
            return
        with self.lock:
            wire = self.server._wire_turn
            if wire is None or wire[:2] != (thread_id, turn_id):
                raise protocol.PreparationError('registered-trusted-terminal-correlation')
            self._latch_negative('turn', (thread_id, turn_id))
            self.trusted_terminals.add((thread_id, turn_id))
            for entry in self.entries.values():
                if self._revoked(entry) and entry.state not in {'sent', 'revoked'} and entry.refusal is None:
                    self._refuse(entry, None, cancel=True)
        self.wake.set()

    def cancel_turn(self, thread_id, turn_id):
        """Revoke locally before the original interrupt RPC; no terminal claim."""
        with self.lock:
            wire = self.server._wire_turn
            if wire is None or wire[:2] != (thread_id, turn_id):
                raise protocol.PreparationError('registered-local-interrupt-correlation')
            self._latch_negative('turn', (thread_id, turn_id))
            self.cancelled_turn = (thread_id, turn_id)
            for entry in self.entries.values():
                if self._locally_cancelled(entry) and entry.state not in {'sent', 'revoked'} and entry.refusal is None:
                    self._refuse(entry, None, cancel=True)
        self.wake.set()

    def observe(self, message):
        """Called by the original reader, never by a caller-supplied context."""
        params = message['params']
        method = message['method']
        with self.lock:
            if method == 'item/started':
                self._item(params)
            elif method == 'item/completed':
                item = params.get('item', {})
                self._terminal_item(params.get('threadId'), params.get('turnId'), item.get('id'))
            elif method == 'turn/started':
                self._observe_turn_projection(params.get('threadId'), params.get('turn', {}))
            elif method == 'thread/started':
                self._observe_thread_projection(params.get('thread', {}))
            elif method in {'turn/completed', 'turn/failed', 'turn/interrupted'}:
                turn = params.get('turn', {})
                self._terminal(params.get('threadId'), turn.get('id', params.get('turnId')))
            elif method in {'thread/closed', 'thread/archived'}:
                wire = self.server._wire_turn
                if wire is None or wire[0] != params.get('threadId'):
                    raise protocol.PreparationError('registered-thread-terminal-before-bound-turn')
                self._terminal(*wire[:2])
        self.wake.set()

    def _item(self, params):
        item = params.get('item', {})
        key = params.get('threadId'), params.get('turnId'), item.get('id')
        if any(not protocol._text(v) for v in key):
            raise protocol.PreparationError('registered-item-correlation')
        if key in self.server._items or len(self.server._items) >= 128:
            raise protocol.PreparationError('registered-item-reused-or-bound')
        if self.server._wire_turn is None or key[:2] != self.server._wire_turn[:2]:
            raise protocol.PreparationError('registered-item-before-turn')
        if key[:2] in self.terminals:
            raise protocol.PreparationError('registered-post-terminal-item')
        self.server._items[key] = json.loads(json.dumps(item))

    def observe_response(self, message):
        result = message.get('result')
        if type(result) is not dict or type(result.get('thread')) is not dict:
            return
        with self.lock:
            self._observe_thread_projection(result['thread'])
        self.wake.set()

    def observe_turn_response(self, thread_id, turn):
        # The factory has checked the actual pending response ID and epoch.
        # A returned projection supplies only negative evidence, never context.
        with self.lock:
            self._observe_turn_projection(thread_id, turn)
        self.wake.set()

    def _observe_thread_projection(self, thread):
        for turn in thread.get('turns', []):
            self._observe_turn_projection(thread.get('id'), turn)

    def _observe_turn_projection(self, thread_id, turn):
        if type(turn) is not dict:
            raise protocol.PreparationError('registered-turn-projection-shape')
        if turn.get('status') in {'completed', 'failed', 'interrupted'}:
            self._terminal(thread_id, turn.get('id'))
            return
        for item in turn.get('items', []):
            if type(item) is dict and item.get('status') in _ITEM_TERMINAL:
                self._terminal_item(thread_id, turn.get('id'), item.get('id'))

    def _terminal(self, thread, turn):
        # Retain only the actual dispatched turn; unrelated historical turns do
        # not create unbounded state or supply authority for another connection.
        wire = self.server._wire_turn
        if wire is None or wire[:2] != (thread, turn):
            raise protocol.PreparationError('registered-terminal-before-bound-turn')
        self._latch_negative('turn', (thread, turn))
        self.terminals.add((thread, turn))
        self._revoke()

    def _terminal_item(self, thread, turn, item):
        key = thread, turn, item
        wire = self.server._wire_turn
        if wire is None or wire[:2] != (thread, turn) or key not in self.server._items:
            raise protocol.PreparationError('registered-item-terminal-before-start')
        self._latch_negative('item', key)
        self.completed_items.add(key)
        self._revoke()

    def _revoke(self):
        for entry in self.entries.values():
            if entry.correlation is not None and entry.state not in {'sent', 'revoked'} and not self._current(entry):
                self._refuse(entry, 'Terminal event invalidated pending approval.', cancel=True)

    def _ready(self, entry, result, refusal=None, *, error=False):
        frame = {'id': entry.request.request_id, 'error' if error else 'result': result}
        entry.frame = (json.dumps(frame, separators=(',', ':')) + '\n').encode()
        if refusal is not None:
            self._latch_negative('refused')
        entry.state, entry.refusal = 'ready', refusal
        entry.accepting = not error and result == {'decision': 'accept'}
        # A replacement frame has no physical accepting attempt. Keep an
        # active write ticket in its caller, not on this mutable entry.
        entry.dispatch = None
        if refusal is not None:
            self.refusal_only = True

    def _refuse(self, entry, reason, *, cancel=False):
        if entry.state == 'revoked':
            return
        if entry.state == 'committing':
            self._abort_inflight_reply()
            entry.state, entry.delivery, entry.frame = 'revoked', 'ambiguous', None
            entry.refusal = reason
            return
        # Preserve the originating fatal reply; other revoked entries cannot
        # authorize execution or preempt that required error's delivery.
        if self.refusal_only and entry.refusal is None:
            reason = None
        result = {'permissions': {}} if entry.request.method == protocol.PERMISSIONS else {
            'decision': 'cancel' if cancel else 'decline'}
        self._ready(entry, result, reason)

    def _abort_inflight_reply(self):
        # Called inside the short request fence, before publishing negative
        # evidence. This descriptor replacement never waits for the writer.
        if any(e.state == 'committing' for e in self.entries.values()):
            self.server.process.stdin.abort()

    def _publish_progress(self):
        # The plain registry has no reducer; the registered host overrides it.
        pass

    def _take(self):
        with self.lock:
            if self.closed or not self.queue:
                return None
            entry = self.entries[self.queue.popleft()]
            if entry.state != 'queued':
                return None
            entry.state = 'deciding'
            return entry

    def _decide_loop(self):
        while not self.closed:
            entry = self._take()
            if entry is None:
                self.wake.wait(.01)
                continue
            try:
                self._decide(entry)
            except BaseException as failure:
                self.server._fail_transport(failure)
                return

    def _decide(self, entry):
        params = json.loads(entry.request.params_json)
        decision = self.server._decision(entry.request.method, params)
        if decision not in {'accept', 'decline', 'cancel'}:
            raise protocol.PreparationError('registered-one-action-decision-required')
        if entry.request.method == protocol.PERMISSIONS and decision != 'decline':
            raise protocol.PreparationError('registered-permission-grant-refused')
        # Publish each pending callout before leaving the short request fence.
        # Intake can revoke it while authority or storage is blocked.
        if not self._callout(entry, 'deciding', 'authority'):
            return
        self.server.factory.require_effect()
        if not self._callout(entry, 'authority', 'record'):
            return
        self.server.factory.record('approval', {'id': entry.request.request_id,
            'method': entry.request.method, 'params': params, 'decision': decision})
        with self.lock:
            if self.closed or entry.state != 'record':
                return
            if not self._current(entry) or time.monotonic() >= entry.deadline:
                self._refuse(entry, 'Approval expired or was invalidated.', cancel=True)
            else:
                result = {'permissions': {}} if entry.request.method == protocol.PERMISSIONS else {'decision': decision}
                self._ready(entry, result, 'Cancelled server request.' if decision == 'cancel' else None)
        self.wake.set()

    def _callout(self, entry, expected, stage):
        with self.lock:
            if self.closed or entry.state != expected:
                return False
            entry.state = stage
            self._publish_progress()
            return True

    def _revalidate(self, entry, now):
        if now >= entry.deadline:
            self._latch_negative('request', entry.request.request_id)
        entry.expired = entry.expired or now >= entry.deadline
        if entry.refusal is not None:
            return
        if entry.correlation is not None and (self.refusal_only or self._revoked(entry)) and entry.refusal is None:
            self._refuse(entry, None, cancel=True)
        elif entry.correlation is not None and not self._current(entry):
            self._refuse(entry, 'Approval was invalidated before delivery.', cancel=True)
        elif entry.correlation is not None and now >= entry.deadline:
            self._refuse(entry, 'Approval expired before delivery.')

    def _write(self, entry):
        writer = self.server.process.stdin
        if not writer._lock.acquire(blocking=False):
            return False
        try:
            writer.flush()
            with self.lock:
                if self.closed or entry.state != 'ready':
                    return None
                self._revalidate(entry, time.monotonic())
                frame = entry.frame
                if len(frame) > 4096:
                    raise protocol.PreparationError('registered-atomic-reply-bound')
                # The reducer commits the immutable dispatch intent while
                # ingress and every negative source still share this fence.
                frame = self._begin_reply_dispatch(entry, frame)
                dispatch = entry.dispatch
                accepting = entry.accepting
                entry.state = 'committing'
                entry.delivery = 'committing'
                self._publish_progress()
            try:
                timer = None
                if accepting:
                    timer = threading.Timer(max(0, entry.deadline - time.monotonic()),
                                            self._expire_committing, args=(entry,))
                    timer.daemon = True
                    timer.start()
                try:
                    count = os.write(writer.descriptor, frame)
                finally:
                    if timer is not None:
                        timer.cancel()
            except (BlockingIOError, InterruptedError):
                self._reply_result(entry, dispatch, 'not-sent')
                with self.lock:
                    if entry.state == 'committing':
                        entry.state = 'ready'
                        entry.delivery = 'precommit'
                        self._publish_progress()
                return False
            except OSError:
                self._reply_result(entry, dispatch, 'unknown-send')
                with self.lock:
                    entry.delivery = 'ambiguous'
                    entry.state = 'revoked'
                    self._publish_progress()
                raise
            if count != len(frame):
                self._reply_result(entry, dispatch, 'wire-partial' if count > 0 else 'not-sent')
                with self.lock:
                    entry.delivery = 'ambiguous'
                    entry.state = 'revoked'
                    self._publish_progress()
                raise protocol.PreparationError('registered-partial-reply')
            self._reply_result(entry, dispatch, 'wire-sent')
            with self.lock:
                if self.closed or entry.state != 'committing':
                    entry.delivery = 'ambiguous'
                    raise protocol.PreparationError('registered-reply-revoked-during-write')
                entry.state = 'sent'
                entry.delivery = 'sent'
                self._publish_progress()
                return True
        finally:
            writer._lock.release()
            if writer._closing:
                writer.close()

    def _begin_reply_dispatch(self, entry, frame):
        if entry.accepting:
            entry.dispatch = self._commit_reply(entry)
            if entry.dispatch is None:
                self._refuse(entry, None, cancel=True)
                return entry.frame
        return frame

    def _expire_committing(self, entry):
        failure = TimeoutError('registered-reply-deadline')
        with self.lock:
            if entry.state != 'committing' or time.monotonic() < entry.deadline:
                return
            self.server._publish_transport_failure(failure)
            entry.expired = True
            self._refuse(entry, 'Registered reply deadline exceeded.', cancel=True)
            self._publish_progress()
        self.wake.set()
        self.server._fail_transport(failure)

    def _deliver(self, entry, now):
        with self.lock:
            if self.closed or entry.state != 'ready':
                return None
            self._revalidate(entry, now)
        # Acquiring the writer never holds the consumer lock. The writer
        # revalidates inside its actual commit section after acquisition.
        sent = self._write(entry)
        if sent is None:
            return None
        if sent:
            if entry.refusal is not None:
                return protocol.PreparationError(entry.refusal)
        elif time.monotonic() >= entry.deadline:
            return TimeoutError('registered-reply-deadline')
        return None

    def _fatal_reply_waiting(self, now):
        # Caller holds the consumer lock; this bounded scan performs no I/O.
        return any(e.refusal is not None and e.state != 'sent' and now < e.deadline
                   for e in self.entries.values())

    def _tick(self):
        with self.lock:
            if self.closed:
                return None
            now = time.monotonic()
            for entry in self.entries.values():
                if entry.state in {'queued', 'deciding', 'authority', 'record'} and now >= entry.deadline:
                    self._latch_negative('request', entry.request.request_id)
                    entry.expired = True
                    self._refuse(entry, 'Registered decision deadline exceeded.')
            ready = [entry for entry in self.entries.values() if entry.state == 'ready']
        failure = None
        for entry in ready:
            delivered = self._deliver(entry, now)
            if isinstance(delivered, TimeoutError):
                # An elapsed request deadline never waits for a later reply.
                return delivered
            failure = delivered or failure
        # Give every already-known required fatal reply its bounded delivery
        # opportunity, including an unsupported error behind an earlier entry.
        with self.lock:
            if any(e.expired for e in self.entries.values()):
                return TimeoutError('registered-request-deadline')
            waiting = self._fatal_reply_waiting(now)
        return None if waiting else failure

    def _monitor(self):
        while True:
            self.wake.clear()
            try:
                failure = self._tick()
            except BaseException as error:
                failure = error
            if failure is not None:
                self.server._fail_transport(failure)
            if self.closed:
                failure = self.server.transport_failure
                if failure is not None:
                    self.server.lifetime.cleanup_failure(failure)
                return
            self.wake.wait(.01)

    def close(self):
        with self.lock:
            self._latch_negative('closed')
            self._abort_inflight_reply()
            if not self.closed and any(e.expired or e.state != 'sent' or e.refusal is not None
                                       for e in self.entries.values()):
                self.server._publish_transport_failure(protocol.PreparationError(
                    'Registered connection closed with an unresolved or fatal required reply.'))
            self.closed = True
            self.queue.clear()
            for entry in self.entries.values():
                if entry.delivery == 'committing':
                    entry.delivery = 'ambiguous'
                entry.state = 'revoked'
                entry.frame = None
        self.wake.set()
