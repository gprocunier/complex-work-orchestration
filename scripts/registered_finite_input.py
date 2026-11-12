"""Issued empty-poll gate for a host-owned registered tool process.

This is an offline component. The native app-server builtin write_stdin does
not call it; the registered factory never treats an approval callback as proof
of input bytes. A caller must wire a host-owned tool process before use.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
import hashlib
import json
import math
import os
import select
import stat
import threading
import time
import weakref

import linux_owned_children as owned
from cwo_core import server_request_preparation as protocol


class FiniteInputError(ValueError):
    """An input attempt was consumed without delivery."""


@dataclass
class _Poll:
    owner: object
    process: object
    lifetime: object
    epoch: str
    thread: str
    turn: str
    item: str
    approval: str
    deadline: float
    revocation_generation: int
    used: bool = False


@dataclass(frozen=True)
class _Authority:
    capability: object
    receipt: object
    ledger: object
    host: object
    ledger_handles: object
    host_bytes: bytes
    policy_bytes: bytes
    source: object
    spec_bytes: bytes


class PollTicket:
    """In-process issued identity; never a serialized capability."""

    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise FiniteInputError('Poll tickets must be issued by the registered host.')

    def __reduce_ex__(self, protocol):
        raise FiniteInputError('Poll tickets cannot be serialized.')


class ReplyTicket:
    """Opaque process-local identity for one observed tool reply attempt."""

    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise FiniteInputError('Reply tickets must be issued by the registered host.')

    def __reduce_ex__(self, protocol):
        raise FiniteInputError('Reply tickets cannot be serialized.')


@dataclass
class _Reply:
    factory: object
    producer: object
    lifetime: object
    process: object
    birth: object
    receipt: object
    epoch: str
    authority: object
    message: object
    response: object
    params_sha256: str
    frame_sha256: str
    deadline: float
    phase: str
    generation: int
    used: bool = False


class _FiniteLifecycle:
    """One monotone turn/transport/tool progress reducer.

    This is the host wait authority, not a replacement for server request correlation,
    retained-child custody, or the producer/gate one-use effect fences. Each caller
    publishes an event only after its original fence commits. The selected
    epoch/turn, typed request key, item and original intake deadline identify
    every live transition. No callout runs under this condition.
    """

    TERMINAL = frozenset({'terminal', 'refused', 'fault', 'closed'})
    # The original server-request/host branch is reduced here too. The registry and retained-child owner
    # remain the authority; these edges make their publication order explicit.
    ORIGINAL_REQUEST_EDGES = {
        None: frozenset({'queued', 'ready'}),
        'queued': frozenset({'deciding', 'ready', 'revoked'}),
        'deciding': frozenset({'authority', 'ready', 'revoked'}),
        'authority': frozenset({'record', 'ready', 'revoked'}),
        'record': frozenset({'ready', 'revoked'}),
        'ready': frozenset({'ready', 'committing', 'revoked'}),
        'committing': frozenset({'ready', 'sent', 'revoked'}),
        'sent': frozenset({'revoked'}),
        'revoked': frozenset(),
    }
    ORIGINAL_CLEANUP_EDGES = {
        'unclaimed': frozenset({'pending', 'unknown'}),
        'pending': frozenset({'pending', 'contained', 'unknown'}),
        'contained': frozenset({'contained', 'unknown'}),
        'unknown': frozenset({'unknown'}),
    }
    WAITING = frozenset({'await-command', 'command-queued', 'command-deciding',
                         'command-intent', 'pending-birth', 'gate-closed',
                         'command-effect', 'command-replied', 'command-completed',
                         'poll-queued', 'poll-deciding', 'poll-intent',
                         'poll-observing', 'poll-replied', 'request-queued'})

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.condition = threading.Condition()
        self.phase = 'unselected'
        self.generation = 0
        self.epoch = self.turn = self.command = self.poll = None
        self.edge_deadline = None
        self.pending = {}
        self._cleanup = 'none'
        self._tool = 'none'
        self._cleanup_source = None
        self.output_bytes = 0
        self.eof = False
        self.original_requests = {}
        self.original_deliveries = {}
        self.original_bindings = {}
        self.original_deadlines = {}
        self.original_expired = set()
        self.original_accepts = set()
        self.original_terminal = False
        self.original_fault = False
        self.original_closed = False
        self.original_cleanup = 'unclaimed'
        self.original_output = 'withheld'
        # The reducer owns the short commit/revoke arbitration. Registry state
        # is a projection and cannot itself authorize a later physical effect.
        self.authority_order = 0
        # The key points to the current attempt. Each ordered ticket retains
        # its own physical result, including a prior confirmed no-byte result.
        self.authority_commits = {}
        self.authority_outcomes = {}
        self.authority_attempt_results = {}
        self.authority_revocations = []
        self.authority_global_revoked = False
        self.authority_revoked_turns = set()
        self.authority_revoked_items = set()
        self.authority_revoked_requests = set()

    def _authority_open(self, binding):
        if binding is None or len(binding) != 6 or self.authority_global_revoked:
            return False
        return (binding[2:4] not in self.authority_revoked_turns
                and binding[2:5] not in self.authority_revoked_items
                and binding[1] not in self.authority_revoked_requests)

    def authority_open(self, binding):
        with self.condition:
            return self._authority_open(binding)

    def command_reply_dispatched(self, identity):
        """Recognize a prior immutable command reply during fast item intake."""
        with self.condition:
            return any(kind == 'tool-reply' and binding[2:5] == identity
                       and self.authority_attempt_results[ticket] in (None, 'wire-sent')
                       for (kind, binding), ticket in self.authority_commits.items())

    def authority_reply_finishable(self, binding):
        """Item completion may follow prior dispatch; turn/fault may not."""
        with self.condition:
            return (not self.authority_global_revoked
                    and binding[2:4] not in self.authority_revoked_turns
                    and binding[1] not in self.authority_revoked_requests)

    def authority_revoke(self, kind, scope=None):
        """Latch a negative before any public registry flag or blocked observer."""
        with self.condition:
            if kind in {'fault', 'closed', 'refused'}:
                target, value = 'global', None
                if self.authority_global_revoked:
                    return False
                self.authority_global_revoked = True
            elif kind == 'turn':
                target, value = 'turn', scope
                if scope in self.authority_revoked_turns:
                    return False
                self.authority_revoked_turns.add(scope)
            elif kind == 'item':
                target, value = 'item', scope
                if scope in self.authority_revoked_items:
                    return False
                self.authority_revoked_items.add(scope)
            elif kind == 'request':
                target, value = 'request', scope
                if scope in self.authority_revoked_requests:
                    return False
                self.authority_revoked_requests.add(scope)
            else:
                raise FiniteInputError('Unknown authority revocation.')
            self.authority_order += 1
            self.authority_revocations.append((self.authority_order, kind, target, value))
            for key, outcome in self.authority_outcomes.items():
                if not self._authority_open(key[1]):
                    if outcome == 'authority-dispatched':
                        self.authority_outcomes[key] = 'ambiguous-after-revocation'
                    elif outcome == 'precommit-retry':
                        self.authority_outcomes[key] = 'revoked-before-physical-send'
            return True

    def authority_dispatch(self, kind, binding):
        """Start one ordered physical attempt under the shared commit/revoke owner.

        A confirmed no-byte result leaves the same binding retry-ready, but
        the next physical attempt needs a new ticket and order. Other active
        or completed attempts cannot be dispatched again on that binding.
        """
        with self.condition:
            if not self._authority_open(binding):
                return None
            key = kind, tuple(binding)
            if (key in self.authority_commits
                    and self.authority_outcomes[key] != 'precommit-retry'):
                return None
            if len(self.authority_attempt_results) >= 65536:
                raise FiniteInputError('Protected dispatch history bound was exceeded.')
            self.authority_order += 1
            ticket = (self.authority_order, kind, tuple(binding))
            self.authority_commits[key] = ticket
            self.authority_outcomes[key] = 'authority-dispatched'
            self.authority_attempt_results[ticket] = None
            return ticket

    def authority_result(self, ticket, result):
        with self.condition:
            key = ticket[1:]
            if (self.authority_commits.get(key) != ticket
                    or self.authority_attempt_results.get(ticket, False) is not None):
                raise FiniteInputError('Unknown or completed protected dispatch intent.')
            if result not in {'wire-sent', 'wire-partial', 'gate-opened',
                              'effect-applied', 'not-sent', 'unknown-send'}:
                raise FiniteInputError('Unknown protected dispatch outcome.')
            self.authority_attempt_results[ticket] = result
            if result == 'not-sent' and self._authority_open(ticket[2]):
                self.authority_outcomes[key] = 'precommit-retry'
            elif not self._authority_open(ticket[2]):
                self.authority_outcomes[key] = (
                    'wire-sent-after-revocation' if result == 'wire-sent'
                    else 'effect-applied-before-containment' if result in {'gate-opened', 'effect-applied'}
                    else 'revoked-before-physical-send' if result == 'not-sent'
                    else 'ambiguous-after-revocation')
            else:
                self.authority_outcomes[key] = result
            return self.authority_outcomes[key]

    def original_request_event(self, key, state, *, binding=None, deadline=None,
                               expired=False, accepted=False, delivery=None):
        with self.condition:
            previous = self._original_binding(key, binding, deadline)
            self._original_edge(key, previous, state, expired, accepted)
            prior_delivery = self.original_deliveries.get(key, 'precommit')
            if delivery is None:
                delivery = ({'committing': 'committing', 'sent': 'sent'}.get(state)
                            or (prior_delivery if state == 'revoked' else 'precommit'))
            allowed = {'precommit': {'precommit', 'committing'},
                       'committing': {'precommit', 'committing', 'sent', 'ambiguous'},
                       'sent': {'sent'}, 'ambiguous': {'ambiguous'}}
            if delivery not in allowed[prior_delivery] or (delivery == 'sent' and state not in {'sent', 'revoked'}):
                raise FiniteInputError('Original physical reply crossed a lifecycle edge.')
            if accepted and delivery != 'sent':
                raise FiniteInputError('Original acceptance lacks physical completion.')
            changed = (state != previous or delivery != prior_delivery
                       or (expired and key not in self.original_expired))
            self.original_requests[key] = state
            self.original_deliveries[key] = delivery
            if expired:
                self.original_expired.add(key)
            if accepted:
                self.original_accepts.add(key)
            if changed:
                self._publish()
            return changed

    def _original_binding(self, key, binding, deadline):
        previous = self.original_requests.get(key)
        if deadline is not None and (type(deadline) not in (int, float)
                                     or not math.isfinite(deadline)):
            raise FiniteInputError('Original request deadline is invalid.')
        if previous is None:
            if len(self.original_requests) >= 64:
                raise FiniteInputError('Original request history bound was exceeded.')
            self.original_bindings[key] = binding
            self.original_deadlines[key] = deadline
        elif (self.original_bindings[key] != binding
              or self.original_deadlines[key] != deadline):
            raise FiniteInputError('Original request identity or deadline changed.')
        return previous

    def _original_edge(self, key, previous, state, expired, accepted):
        if state != previous and state not in self.ORIGINAL_REQUEST_EDGES[previous]:
            raise FiniteInputError('Original request crossed a lifecycle edge.')
        if accepted and previous != 'sent' and self._cleanup_source is not None:
            self._require_accept_dispatch(key)
        if (accepted and previous != 'sent'
                and (state != 'sent' or self.original_fault or self.original_closed
                     or self.original_terminal or expired
                     or key in self.original_expired)):
            raise FiniteInputError('Original acceptance followed revocation.')

    def _require_accept_dispatch(self, key):
        binding = self.original_bindings[key]
        if (not self._authority_open(binding)
                or self.authority_outcomes.get(('reply-grant', binding)) != 'wire-sent'):
            raise FiniteInputError('Original acceptance lacks shared dispatch authority.')

    def original_transport_event(self, event):
        with self.condition:
            if event == 'terminal':
                if self.turn is not None:
                    self.authority_revoke('turn', self.turn)
                if self.original_terminal:
                    return False
                self.original_terminal = True
            elif event == 'fault':
                self.authority_revoke('fault')
                if self.original_fault:
                    return False
                self.original_fault = True
                self.original_output = 'revoked'
            elif event == 'closed':
                self.authority_revoke('closed')
                if self.original_closed:
                    return False
                self.original_closed = True
            else:
                raise FiniteInputError('Unknown original transport event.')
            self._publish()
            return True

    def original_cleanup_event(self, event):
        with self.condition:
            if (event == self.original_cleanup
                    or (event == 'pending' and self.original_cleanup in {'contained', 'unknown'})
                    or (event == 'contained' and self.original_cleanup == 'unknown')):
                return False
            if event not in self.ORIGINAL_CLEANUP_EDGES[self.original_cleanup]:
                raise FiniteInputError('Original cleanup crossed a lifecycle edge.')
            self.original_cleanup = event
            if event == 'unknown':
                self.original_output = 'revoked'
            self._publish()
            return True

    def original_output_event(self, event):
        with self.condition:
            if event == 'revoked':
                if self.original_output == 'published':
                    raise FiniteInputError('Published original output cannot be revoked.')
                self.original_output = 'revoked'
            elif event == 'published':
                if (self.original_output != 'withheld' or self.original_fault
                        or not self.original_closed or self.original_cleanup != 'contained'
                        or self.original_expired
                        or 'ambiguous' in self.original_deliveries.values()
                        or any(state != 'revoked' and state != 'sent'
                               for state in self.original_requests.values())):
                    raise FiniteInputError('Original output lacks completed lifecycle.')
                self.original_output = 'published'
            else:
                raise FiniteInputError('Unknown original output event.')
            self._publish()

    def _publish(self):
        self.generation += 1
        self.condition.notify_all()

    def select(self, epoch, turn, deadline):
        with self.condition:
            if (self.phase != 'unselected' or self.turn is not None
                    or type(epoch) is not str or type(turn) is not tuple
                    or len(turn) != 2 or type(deadline) not in (int, float)):
                raise FiniteInputError('The original turn selection changed.')
            self.epoch, self.turn = epoch, turn
            self.phase, self.edge_deadline = 'await-command', deadline
            self._publish()

    def queue(self, key, tool, turn, call, deadline):
        with self.condition:
            if self.phase in self.TERMINAL:
                return False
            if (self.turn != turn or key in self.pending
                    or type(deadline) not in (int, float)):
                raise FiniteInputError('The queued original request identity changed.')
            self.pending[key] = (tool, call, deadline, 'queued')
            if tool == 'finite_command' and self.command is None:
                self.command = call
                self.phase, self.edge_deadline = 'command-queued', None
            elif tool == 'finite_poll' and self.phase == 'command-completed':
                self.poll = call
                self.phase, self.edge_deadline = 'poll-queued', None
            elif self.phase == 'await-command':
                self.phase, self.edge_deadline = 'request-queued', None
            self._publish()
            return True

    def require_request(self, key, call):
        with self.condition:
            entry = self.pending.get(key)
            if (self.phase in self.TERMINAL or entry is None
                    or entry[1] != call or self.clock() >= entry[2]):
                raise FiniteInputError('No live original queued request remains.')

    def call_live(self, call, phases):
        """A short effect fence for the actual queued dynamic worker call."""
        with self.condition:
            matches = [entry for entry in self.pending.values() if entry[1] == call]
            return (self.phase in phases and len(matches) == 1
                    and self.clock() < matches[0][2])

    def require_success_reply(self, key, call):
        # Called under the original producer/gate/request final fence, before
        # either ticket issuance or the nonblocking frame write.
        self.require_request(key, call)

    def move(self, event, *, key=None, call=None):
        """Record a committed producer/gate edge; reject stale generations."""
        transitions = {
            'decide-command': ({'command-queued'}, 'command-deciding'),
            'command-intent': ({'command-deciding'}, 'command-intent'),
            'pending-birth': ({'command-intent'}, 'pending-birth'),
            'gate-closed': ({'pending-birth'}, 'gate-closed'),
            'gate-release': ({'gate-closed'}, 'command-effect'),
            'decide-poll': ({'poll-queued'}, 'poll-deciding'),
            'poll-intent': ({'poll-deciding'}, 'poll-intent'),
            'poll-observe': ({'poll-intent'}, 'poll-observing'),
        }
        allowed, target = transitions[event]
        with self.condition:
            if self.phase in self.TERMINAL:
                raise FiniteInputError('Terminal lifecycle cannot authorize another effect.')
            if key is None:
                matches = [candidate for candidate, entry in self.pending.items()
                           if entry[1] == call]
                key = matches[0] if len(matches) == 1 else None
            expected = self.command if 'command' in event or event in {
                'pending-birth', 'gate-closed', 'gate-release'} else self.poll
            if (self.phase not in allowed or expected != call
                    or key not in self.pending
                    or self.pending[key][1] != call):
                raise FiniteInputError('The original lifecycle event is stale.')
            tool, item, deadline, _ = self.pending[key]
            if self.clock() >= deadline:
                raise FiniteInputError('The original queued request deadline expired.')
            self.pending[key] = (tool, item, deadline, target)
            self.phase = target
            self._move_tool(event)
            self._publish()
            return True

    def _move_tool(self, event):
        tool_phase = {'pending-birth': 'pending-birth',
                      'gate-closed': 'gate-closed', 'gate-release': 'running'}.get(event)
        if tool_phase is not None:
            self._tool = tool_phase

    def reply(self, key, tool, call, success):
        with self.condition:
            if self.phase in self.TERMINAL:
                return False
            entry = self.pending.get(key)
            if entry is None or entry[:2] != (tool, call):
                raise FiniteInputError('The original reply request identity changed.')
            del self.pending[key]
            if not success:
                self.phase, self.edge_deadline = 'refused', None
            elif tool == 'finite_command':
                if self.phase not in {'command-effect', 'pending-birth', 'gate-closed',
                                      'command-intent', 'command-deciding', 'command-queued'}:
                    raise FiniteInputError('Command reply crossed a lifecycle phase.')
                self.phase = 'command-replied'
                self.edge_deadline = self.clock() + 15
            elif tool == 'finite_poll':
                if self.phase not in {'poll-observing', 'poll-intent', 'poll-deciding',
                                      'poll-queued'}:
                    raise FiniteInputError('Poll reply crossed a lifecycle phase.')
                self.phase = 'poll-replied'
                self.edge_deadline = self.clock() + 15
            else:
                raise FiniteInputError('Unknown dynamic tool cannot reply successfully.')
            self._publish()
            return True

    def complete(self, turn, call):
        with self.condition:
            if self.phase in self.TERMINAL:
                return False
            if self.turn != turn or self.command != call or self.phase != 'command-replied':
                raise FiniteInputError('Command completion did not follow its reply.')
            self.phase = 'command-completed'
            self.edge_deadline = self.clock() + 15
            for tool, item, _deadline, _state in self.pending.values():
                if tool == 'finite_poll':
                    self.poll = item
                    self.phase, self.edge_deadline = 'poll-queued', None
                    break
            self._publish()
            return True

    def finish(self, event, *, turn=None):
        with self.condition:
            if event == 'terminal' and self.turn != turn:
                return False
            if event == 'fault':
                self.authority_revoke('fault')
                self.phase = 'fault'
            elif event == 'closed' and self.phase != 'fault':
                self.authority_revoke('closed')
                self.phase = 'closed'
            elif event == 'terminal' and self.phase not in {'fault', 'closed'}:
                self.authority_revoke('turn', turn)
                self.phase = 'terminal'
            elif event == 'refused' and self.phase not in self.TERMINAL:
                self.authority_revoke('refused')
                self.phase = 'refused'
            else:
                return False
            self.edge_deadline = None
            self.pending.clear()
            self._publish()
            return True

    @property
    def cleanup(self):
        # A selected gate supplies the authoritative cleanup classification.
        # Standalone reducer tests continue to use the locally reduced state.
        if self._cleanup_source is not None:
            phase = self._cleanup_source()
            return {'unselected': 'none', 'owned-active': 'none',
                    'cleanup-pending': 'pending', 'contained': 'contained',
                    'unknown': 'unknown'}[phase]
        return self._cleanup

    @property
    def tool(self):
        if self._cleanup_source is not None:
            phase = self._cleanup_source()
            if phase in {'cleanup-pending', 'contained', 'unknown'}:
                return phase
        return self._tool

    def tool_event(self, event, size=0):
        with self.condition:
            if event == 'read':
                if self._tool not in {'running', 'clean-exited'} or not 0 <= size <= 4097:
                    raise FiniteInputError('A live original tool read is required.')
                self.output_bytes += size
                if self.output_bytes > 4096:
                    self._tool = 'fault'
            elif event == 'clean-exit':
                if self._tool != 'running':
                    raise FiniteInputError('The original tool exit phase changed.')
                self._tool = 'clean-exited'
            elif event == 'eof':
                if self._tool != 'clean-exited':
                    raise FiniteInputError('Original clean exit is required before EOF.')
                self.eof = True
            else:
                raise FiniteInputError('Unknown owned tool observation.')
            self._publish()

    def cleanup_event(self, phase):
        with self.condition:
            if phase == 'pending' and self._cleanup in {'none', 'contained'}:
                self._cleanup = 'pending'
                self._tool = 'cleanup-pending'
            elif phase == 'unknown' and self._cleanup != 'unknown':
                self._cleanup = 'unknown'
                self._tool = 'unknown'
            elif phase == 'contained' and self._cleanup == 'pending':
                self._cleanup = 'contained'
                self._tool = 'contained'
            else:
                return False
            self._publish()
            return True

    def wait(self, host_deadline=None):
        """Sleep to the earliest live obligation, never a later queued bound."""
        with self.condition:
            generation = self.generation
            while self.phase in self.WAITING and generation == self.generation:
                deadlines = [entry[2] for entry in self.pending.values()]
                if self.edge_deadline is not None:
                    deadlines.append(self.edge_deadline)
                if not deadlines:
                    return False
                now = self.clock()
                if min(deadlines) <= now:
                    return True
                if host_deadline is not None:
                    if host_deadline <= now:
                        return False
                    deadlines.append(host_deadline)
                self.condition.wait(timeout=min(deadlines) - now)
            return False


class RegisteredFiniteInput:
    """One original factory/transport binding and finite host-owned tool.

    The lock covers revocation and the last process I/O fence. Authority
    callouts happen before that fence; all facts used there are rechecked while
    locked. No approval of native builtin stdin is made here.
    """

    def __init__(self, factory, server):
        self.factory = factory
        self.server = server
        # Resolve original class/function identity before any lifecycle lock.
        import registered_n1_factory as registered
        self._containment_type = registered._Containment
        self._cleanup_observation_type = registered.CleanupObservation
        self._snapshot_spec = registered._snapshot
        self.lock = threading.RLock()
        self._cleanup_condition = threading.Condition(self.lock)
        self.state = 'unselected'
        self.capture_phase = 'unselected'
        self.lifetime = None
        self.pending_lifetime = None
        self.closed_lifetime = None
        self.process = None
        self.epoch = None
        self.input_stream = self.output_stream = None
        self.input_fd = self.output_fd = None
        self.input_stat = self.output_stat = None
        self.authority = None
        self.used_approvals = set()
        self.tickets = weakref.WeakKeyDictionary()
        self.reply_tickets = weakref.WeakKeyDictionary()
        self.dynamic_command = None
        self.terminal_code = None
        self.terminal_eof_proven = False
        self.output_bytes_seen = 0
        self._read_dispatch_index = 0
        self.generation = 0
        self.revocation_generation = 0
        self.intent_reservations = {}
        self._cleanup_inflight = 0
        self._cleanup_committed = False
        self._cleanup_publication_failed = False
        self.lifecycle = _FiniteLifecycle()
        self.lifecycle._cleanup_source = self.cleanup_phase

    def _cleanup_lifetime(self):
        return self.lifetime or self.pending_lifetime or self.closed_lifetime

    @property
    def cleanup_attempted(self):
        with self.lock:
            lifetime = self._cleanup_lifetime()
            return self._cleanup_committed or (lifetime is not None
                and bool(lifetime.observation_snapshot()[0]))

    @property
    def cleanup_observations(self):
        with self.lock:
            lifetime = self._cleanup_lifetime()
            return [] if lifetime is None else list(lifetime.observation_snapshot()[0])

    @property
    def cleanup_unresolved(self):
        return self.cleanup_phase() == 'unknown'

    def cleanup_phase(self):
        # This is the single reader classification for gate, reducer and
        # capture. Physical and record facts remain independently inspectable.
        with self.lock:
            lifetime = self._cleanup_lifetime()
            if lifetime is None:
                return 'unselected'
            (results, pending, failed, owner_failed, physical,
             recorded, ending) = lifetime.observation_snapshot()
            if failed or owner_failed or self._cleanup_publication_failed:
                return 'unknown'
            if self._cleanup_inflight or pending:
                return 'cleanup-pending'
            if self._cleanup_committed:
                return 'contained' if results and physical and recorded else 'unknown'
            return 'cleanup-pending' if self.state == 'revoked' or ending else 'owned-active'

    def bind_dynamic_command(self, thread, turn, call):
        """Retain one issued command identity after its dynamic response."""
        with self.lock, self.server.requests.lock:
            item = self.server._items.get((thread, turn, call))
            producer = getattr(self.server, 'finite_tools', None)
            if (self.state != 'active' or self.dynamic_command is not None
                    or producer is None or producer.command_call_id != call
                    or producer.lifetime is not self.lifetime
                    or producer.process is not self.process
                    or type(item) is not dict or item.get('type') != 'dynamicToolCall'
                    or item.get('id') != call or item.get('tool') != 'finite_command'
                    or item.get('namespace') is not None
                    or item.get('arguments') != {'command': self.factory.spec['command']}
                    or self.server._wire_turn is None or self.server._wire_turn[:2] != (thread, turn)):
                raise FiniteInputError('The original dynamic command binding differs.')
            self.dynamic_command = (thread, turn, call, self.lifetime, self.process)
            self.generation += 1

    def _issued_lifetime(self, lifetime):
        return (type(lifetime) is self._containment_type
                and lifetime.factory is self.factory and lifetime.role == 'tool'
                and type(lifetime.receipt) is owned.OwnedChildReceipt
                and lifetime.birth is not None
                and lifetime.birth.receipt is lifetime.receipt
                and lifetime.birth.child is lifetime.process)

    def _live_lifetime(self, lifetime):
        return (lifetime.namespace_handle is not None and lifetime.process is not None
                and lifetime.command == ('/usr/bin/sh', '-c', self.factory.spec['command'])
                and not lifetime._ending and not lifetime.contained
                and self.server.transport_failure is None and not self.server.requests.closed)

    def _notify_cleanup_waiters(self):
        # Called under the gate lock. A failed wake is a failed publication,
        # never a reason to return a healthy close.
        try:
            self._cleanup_condition.notify_all()
        except BaseException:
            self._cleanup_publication_failed = True

    def _mark_cleanup_publication_failed(self):
        with self._cleanup_condition:
            self._cleanup_publication_failed = True
            self._notify_cleanup_waiters()

    def _observation_committed(self, lifetime):
        with self._cleanup_condition:
            if self._cleanup_lifetime() is not lifetime:
                self._cleanup_publication_failed = True
            phase = self.cleanup_phase()
            self._notify_cleanup_waiters()
        if phase in {'unknown', 'cleanup-pending', 'contained'}:
            self._publish_cleanup_event(
                'pending' if phase == 'cleanup-pending' else phase)

    def publish_pending_lifetime(self, lifetime):
        """Give fault cleanup the retained child before launch callouts block."""
        with self.lock:
            if (self.state != 'unselected' or self.pending_lifetime is not None
                    or not self._issued_lifetime(lifetime)
                    or lifetime.process is None or lifetime.receipt is None):
                raise FiniteInputError('A fresh original pending tool birth is required.')
            lifetime.set_observation_listener(self._observation_committed)
            self.pending_lifetime = lifetime
            self.generation += 1
            self.lifecycle.move('pending-birth', call=self.server.finite_tools.inflight)

    def bind_owned_process(self, lifetime):
        """Select a process created by this original factory's retained-child owner."""

        self.factory.require_effect()
        with self.lock, self.server.requests.lock:
            if (self.state != 'unselected' or self.pending_lifetime is not lifetime
                    or not self._issued_lifetime(lifetime)
                    or not self._live_lifetime(lifetime)):
                raise FiniteInputError('A fresh original owned tool process is required.')
            process = lifetime.process
            if process.stdin is None or process.stdout is None:
                raise FiniteInputError('The selected tool needs real stdin and stdout pipes.')
            input_fd, output_fd = process.stdin.fileno(), process.stdout.fileno()
            input_stat, output_stat = self._pipe_stat(input_fd), self._pipe_stat(output_fd)
            if input_fd == output_fd or input_stat == output_stat:
                raise FiniteInputError('Distinct selected tool pipes are required.')
            os.set_blocking(output_fd, False)
            self.lifetime, self.process = lifetime, process
            self.pending_lifetime = None
            self.epoch = self.server.connection_epoch_sha256
            self.input_stream, self.output_stream = process.stdin, process.stdout
            self.input_fd, self.output_fd = input_fd, output_fd
            self.input_stat, self.output_stat = input_stat, output_stat
            self.authority = self._authority_snapshot()
            self.state = 'active'
            self.generation += 1

    def _authority_snapshot(self):
        factory = self.factory
        return _Authority(factory.capability, factory.receipt, factory.ledger, factory.host,
                          factory._ledger_handles, factory._host_bytes, factory.policy_bytes,
                          factory._source, self._snapshot_spec(factory.spec))

    def _current_authority(self):
        return self._same_authority(self._authority_snapshot(), self.authority)

    @staticmethod
    def _same_authority(actual, expected):
        if expected is None:
            return False
        return (actual.capability is expected.capability and actual.receipt is expected.receipt
                and actual.ledger is expected.ledger and actual.host is expected.host
                and actual.ledger_handles is expected.ledger_handles
                and actual.host_bytes == expected.host_bytes
                and actual.policy_bytes == expected.policy_bytes
                and actual.source == expected.source
                and actual.spec_bytes == expected.spec_bytes)

    @staticmethod
    def _pipe_stat(descriptor):
        info = os.fstat(descriptor)
        if type(descriptor) is not int or descriptor < 0 or not stat.S_ISFIFO(info.st_mode):
            raise FiniteInputError('Selected tool stream is not a kernel pipe.')
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def reserve(self, chars, *, thread_id, turn_id, item_id, approval_id, deadline):
        """Consume an identity even on denial; never cache a declined input."""
        with self.lock:
            if not self._fresh_approval(approval_id):
                raise FiniteInputError('A fresh bounded approval identity is required.')
            self.used_approvals.add(approval_id)
        self.factory.require_effect()
        self._check_poll_input(chars, (thread_id, turn_id, item_id), deadline)
        # Reservation is the admission linearization. Persistence is a
        # blocking callout and cannot hold the reader's request lock. A
        # terminal during persistence leaves only this preterminal intent and
        # a durable abort diagnostic; it never issues a ticket.
        with self.lock, self.server.requests.lock, self.lifecycle.condition:
            if (not time.monotonic() < deadline <= time.monotonic() + 5
                    or self.lifecycle.phase in self.lifecycle.TERMINAL
                    or not self._current(thread_id, turn_id, item_id, approval_id)):
                raise FiniteInputError('The original registered tool item is no longer active.')
            producer = self.server.finite_tools
            if producer is not None and producer.inflight == approval_id:
                self.lifecycle.move('poll-intent', call=approval_id)
            token = object()
            generation = self.revocation_generation
            lifecycle_generation = self.lifecycle.generation
            self.intent_reservations[token] = ('poll', approval_id, generation,
                                               lifecycle_generation)
        try:
            self.factory.record('finite-poll-intent', {
                'operation': self.factory.operation_id, 'approval_id': approval_id,
                'thread_id': thread_id, 'turn_id': turn_id, 'item_id': item_id,
                'input_sha256': hashlib.sha256(chars).hexdigest(),
                'connection_epoch': self.epoch, 'reservation_generation': generation,
                'reservation_lifecycle_generation': lifecycle_generation,
                'intent_state': 'reserved'})
            with self.lock, self.server.requests.lock, self.lifecycle.condition:
                if (self.intent_reservations.pop(token, None) != ('poll', approval_id, generation,
                                                                     lifecycle_generation)
                        or generation != self.revocation_generation
                        or self.lifecycle.phase in self.lifecycle.TERMINAL
                        or not time.monotonic() < deadline
                        or not self._current(thread_id, turn_id, item_id, approval_id)):
                    raise FiniteInputError('The reserved poll ended during intent persistence.')
                ticket = object.__new__(PollTicket)
                self.tickets[ticket] = _Poll(self.factory, self.process, self.lifetime, self.epoch,
                                            thread_id, turn_id, item_id, approval_id, deadline,
                                            generation)
                return ticket
        except BaseException as failure:
            self._abort_intent(token, 'poll', approval_id, generation,
                               lifecycle_generation, failure)
            raise

    def reserve_command_intent(self, params, deadline):
        """Admit the exact current command before its blocking intent record."""
        producer = self.server.finite_tools
        call = params['callId']
        with producer.lock, self.lock, self.server.requests.lock, self.lifecycle.condition:
            if (producer.inflight != call or producer.state != 'registered'
                    or self.capture_phase != 'registered'
                    or not time.monotonic() < deadline
                    or not producer._current(params)):
                raise FiniteInputError('No live command may reserve an intent.')
            self.lifecycle.move('command-intent', call=call)
            token = object()
            generation = self.revocation_generation
            lifecycle_generation = self.lifecycle.generation
            self.intent_reservations[token] = ('command', call, generation,
                                               lifecycle_generation)
            return token, generation, lifecycle_generation

    def publish_command_intent(self, token, generation, lifecycle_generation,
                               params, deadline):
        """A durable preterminal reservation grants launch only if still live."""
        producer = self.server.finite_tools
        call = params['callId']
        try:
            with producer.lock, self.lock, self.server.requests.lock, self.lifecycle.condition:
                if (self.intent_reservations.pop(token, None) != ('command', call, generation,
                                                                      lifecycle_generation)
                        or generation != self.revocation_generation
                        or self.lifecycle.phase in self.lifecycle.TERMINAL
                        or not time.monotonic() < deadline
                        or producer.inflight != call or not producer._current(params)):
                    raise FiniteInputError('The command intent ended before publication.')
        except BaseException as failure:
            self._abort_intent(token, 'command', call, generation,
                               lifecycle_generation, failure)
            raise

    def _abort_intent(self, token, kind, call, generation,
                      lifecycle_generation, failure):
        with self.lock, self.lifecycle.condition:
            self.intent_reservations.pop(token, None)
            abort_generation = self.lifecycle.generation
        # An abort is historical evidence only; persistence failure cannot
        # replace the primary revoked/unknown failure or grant an effect.
        try:
            self.factory.record('finite-' + kind + '-intent-aborted', {
                'operation': self.factory.operation_id, 'call': call,
                'reservation_generation': generation,
                'reservation_lifecycle_generation': lifecycle_generation,
                'abort_lifecycle_generation': abort_generation})
        except BaseException as secondary:
            failure.add_note('Intent abort record failed: ' + type(secondary).__name__)

    def _fresh_approval(self, approval_id):
        return (type(approval_id) is str and 0 < len(approval_id) <= 256
                and approval_id not in self.used_approvals and len(self.used_approvals) < 256)

    @staticmethod
    def _check_poll_input(chars, identity, deadline):
        if type(chars) is not bytes or len(chars) > 4096:
            raise FiniteInputError('Exact bounded UTF-8 input bytes are required.')
        try:
            chars.decode('utf-8', errors='strict')
        except UnicodeError as error:
            raise FiniteInputError('Input must be exact UTF-8 bytes.') from error
        if chars:
            raise FiniteInputError('The finite profile refuses nonempty input before process delivery.')
        if (any(type(value) is not str or not 0 < len(value) <= 256 for value in identity)
                or type(deadline) not in (int, float)
                or not time.monotonic() < deadline <= time.monotonic() + 5):
            raise FiniteInputError('Bounded current input identity and deadline are required.')

    def _current_transport(self, thread, turn, item, approval):
        server = self.server
        key = thread, turn, item
        wire = server._wire_turn
        return (self.state == 'active' and server.connection_epoch_sha256 == self.epoch
                and server.transport_failure is None and not server.requests.closed
                and not server.requests.refusal_only
                and wire is not None and wire[:2] == (thread, turn)
                and ((self.dynamic_command is not None)
                     or key not in server.requests.completed_items)
                and (thread, turn) not in server.requests.terminals
                and (thread, turn) not in server.requests.trusted_terminals
                and (thread, turn) != server.requests.cancelled_turn
                and (self._accepted_command(thread, turn, item)
                     if self.dynamic_command is None else self._dynamic_current(thread, turn, item, approval)))

    def _dynamic_current(self, thread, turn, item, approval):
        producer = getattr(self.server, 'finite_tools', None)
        return (self.dynamic_command == (thread, turn, item, self.lifetime, self.process)
                and self.server._command_reply_committed == (thread, turn, item)
                and (thread, turn, item) in self.server.requests.completed_items
                and producer is not None and producer.command_call_id == item
                and producer.lifetime is self.lifetime and producer.process is self.process
                and (thread, turn, approval) not in self.server.requests.completed_items)

    def _accepted_command(self, thread, turn, item):
        for entry in self.server.requests.entries.values():
            c = entry.correlation
            if (entry.state == 'sent' and entry.refusal is None and c is not None
                    and (c.thread_id, c.turn_id, c.item_id) == (thread, turn, item)
                    and entry.request.method == protocol.COMMAND
                    and json.loads(entry.request.params_json).get('kind', 'command') == 'command'
                    and json.loads(entry.frame)['result'] == {'decision': 'accept'}):
                return True
        return False

    def _current_process(self):
        return (self._issued_lifetime(self.lifetime) and self._live_lifetime(self.lifetime)
                and self.lifetime.process is self.process and self._pipes_current()
                and ((self.terminal_code is None and self.process.returncode is None
                      and self._pid_alive())
                     or (self.terminal_code == 0 and self.process.returncode in (None, 0)
                         and not self._pid_alive())))

    def _observation_target(self):
        with self.lock:
            lifetime, process = self.lifetime, self.process
            if (self.state != 'active' or not self._issued_lifetime(lifetime)
                    or not self._live_lifetime(lifetime) or lifetime.process is not process):
                raise FiniteInputError('The selected owned process is no longer current.')
            return lifetime, process, lifetime.namespace_handle

    def observe_process(self):
        """Classify a retained tool's running or same-handle terminal status."""
        lifetime, process, handle = self._observation_target()
        try:
            status, exited = self._sample_status(process, handle)
        except (OSError, ValueError) as error:
            with self.lock:
                self.state = 'revoked'
            raise FiniteInputError('Owned process exit observation is unknown.') from error
        return self._commit_observed_status(lifetime, process, handle, status, exited)

    @staticmethod
    def _sample_status(process, handle):
        # The namespace pidfd can become ready just before the retained-child parent
        # publishes its exit code. Reconcile only outside reader/turn locks.
        for _ in range(3):
            status = process.poll()
            exited = bool(select.select([handle], [], [], 0)[0])
            if (status is None and not exited) or (type(status) is int and exited):
                return status, exited
            time.sleep(.01)
        return status, exited

    def _commit_observed_status(self, lifetime, process, handle, status, exited):
        with self.lock, self.server.requests.lock, self.lifecycle.condition:
            if (self.state != 'active' or self.lifetime is not lifetime or self.process is not process
                    or lifetime.namespace_handle != handle or not self._live_lifetime(lifetime)
                    or not self._turn_readable()):
                raise FiniteInputError('The owned process changed during exit observation.')
            if status is None and not exited and self.terminal_code is None:
                return 'running'
            if type(status) is int and exited and status == 0:
                return self._mark_clean_exit()
            self.state = 'revoked'
            self.generation += 1
            if type(status) is int and exited:
                self.terminal_code = status
                raise FiniteInputError('The owned tool exited with a nonzero status.')
            raise FiniteInputError('Owned process exit and retained handle disagree.')

    def _turn_readable(self):
        """Use under the gate and server request locks after any status wait."""
        turn = self.lifecycle.turn
        return (self.lifecycle.phase not in self.lifecycle.TERMINAL
                and turn not in self.server.requests.terminals
                and turn not in self.server.requests.trusted_terminals
                and turn != self.server.requests.cancelled_turn)

    def _mark_clean_exit(self):
        if self.terminal_code not in (None, 0):
            self.state = 'revoked'
            raise FiniteInputError('The owned terminal status changed.')
        if self.terminal_code is None:
            self.generation += 1
            self.lifecycle.tool_event('clean-exit')
        self.terminal_code = 0
        return 'clean-exited'

    def _pid_alive(self):
        try:
            return not select.select([self.lifetime.namespace_handle], [], [], 0)[0]
        except (OSError, ValueError) as error:
            self.state = 'revoked'
            raise FiniteInputError('The retained process handle became unknown.') from error

    def _pipes_current(self):
        try:
            current = (self.process.stdin is self.input_stream
                       and self.process.stdout is self.output_stream
                       and self.process.stdin.fileno() == self.input_fd
                       and self.process.stdout.fileno() == self.output_fd
                       and self._pipe_stat(self.input_fd) == self.input_stat
                       and self._pipe_stat(self.output_fd) == self.output_stat
                       and not os.get_blocking(self.output_fd))
        except (OSError, ValueError, TypeError):
            current = False
        if not current:
            self.state = 'revoked'
            raise FiniteInputError('The selected tool pipe identity drifted.')
        return True

    def _current_adapter(self, thread, turn):
        adapter = self.factory.adapter
        return (adapter is not None and adapter.server is self.server
                and adapter.thread_id == thread and adapter._effective_boundary_armed
                and (adapter.turn_id == turn or
                     (adapter.turn_id is None and adapter._boundary_phase == 'dispatch-attempted'
                      and adapter._effective_boundary_send_reserved))
                and self.server._profile_response == adapter._effective_boundary['thread_response'])

    def _current_item(self, thread, turn, item, approval):
        if self.dynamic_command is not None:
            observed = self.server._items.get((thread, turn, approval))
            return (type(observed) is dict and observed.get('type') == 'dynamicToolCall'
                    and observed.get('status') == 'inProgress' and observed.get('id') == approval
                    and observed.get('tool') == 'finite_poll' and observed.get('namespace') is None
                    and observed.get('arguments') == {'commandCallId': item, 'chars': ''})
        observed = self.server._items.get((thread, turn, item))
        return (type(observed) is dict
                and observed.get('type') == 'commandExecution'
                and observed.get('status') == 'inProgress'
                and observed.get('command') == self.factory.spec['command']
                and observed.get('cwd') == str(self.factory.host.worker))

    def _current(self, thread, turn, item, approval):
        return (self._current_authority() and self._current_transport(thread, turn, item, approval)
                and self._current_process() and self._current_adapter(thread, turn)
                and self._current_item(thread, turn, item, approval))

    def poll(self, ticket, *, timeout=0):
        """Poll the selected tool stdout and status with exact empty input.

        No byte is written to stdin. The empty request only observes the tool
        process, matching the native empty-poll semantics. EOF and uncertainty
        consume the ticket and revoke the adapter.
        """
        issued = self._consume_ticket(ticket)
        self.factory.require_effect()
        try:
            if self.dynamic_command is not None:
                return self._poll_dynamic(issued, timeout)
            return self._poll_legacy(issued, timeout)
        except (OSError, ValueError, FiniteInputError) as failure:
            if self.state == 'revoked' and self.server.transport_failure is None:
                self.server._fail_transport(failure)
            raise

    def _poll_dynamic(self, issued, timeout):
        """Wait on a duplicated pipe outside reader/lifecycle locks, then fence."""
        with self.lock, self.server.requests.lock:
            if not self._valid_ticket(issued, timeout):
                raise FiniteInputError('Poll authority, correlation or lifetime expired.')
            descriptor = os.dup(self.output_fd)
            os.set_blocking(descriptor, False)
        try:
            data = self._read_output(issued, timeout, descriptor)
            if self.observe_process() == 'clean-exited':
                data = self.drain_terminal_output(descriptor, data, issued.deadline, issued=issued)
        except (OSError, ValueError, FiniteInputError):
            with self.lock:
                self.state = 'revoked'
            raise
        finally:
            os.close(descriptor)
        with self.lock, self.server.requests.lock:
            if not self._valid_ticket(issued, timeout):
                self.state = 'revoked'
                raise FiniteInputError('Tool lifetime ended during polling.')
            return {'stdout': data, 'stdin_bytes': b'', 'running': self.terminal_code is None}

    def _consume_ticket(self, ticket):
        with self.lock:
            if type(ticket) is not PollTicket or ticket not in self.tickets:
                raise FiniteInputError('An issued poll ticket is required.')
            issued = self.tickets[ticket]
            if issued.used:
                raise FiniteInputError('A poll ticket cannot be replayed.')
            issued.used = True
            return issued

    def _poll_legacy(self, issued, timeout):
        # Even the older command-item route releases both state locks before
        # its bounded select/read. A terminal reader can revoke while it waits.
        with self.lock, self.server.requests.lock:
            if not self._valid_ticket(issued, timeout):
                raise FiniteInputError('Poll authority, correlation or lifetime expired.')
            descriptor = os.dup(self.output_fd)
            os.set_blocking(descriptor, False)
        try:
            data = self._read_output(issued, timeout, descriptor)
        except (OSError, ValueError, FiniteInputError):
            with self.lock:
                self.state = 'revoked'
                self.generation += 1
            raise
        finally:
            os.close(descriptor)
        with self.lock, self.server.requests.lock:
            if not self._valid_ticket(issued, timeout):
                self.state = 'revoked'
                self.generation += 1
                raise FiniteInputError('Tool lifetime ended during polling.')
            return {'stdout': data, 'stdin_bytes': b'', 'running': True}

    def _valid_ticket(self, issued, timeout):
        return (issued.owner is self.factory and issued.process is self.process
                and issued.lifetime is self.lifetime and issued.epoch == self.epoch
                and issued.revocation_generation == self.revocation_generation
                and self.lifecycle.phase not in self.lifecycle.TERMINAL
                and (self.server.finite_tools is None
                     or self.server.finite_tools.inflight != issued.approval
                     or self.lifecycle.call_live(issued.approval, {'poll-intent', 'poll-observing'}))
                and time.monotonic() < issued.deadline
                and type(timeout) in (int, float) and 0 <= timeout <= 0.1
                and self._current(issued.thread, issued.turn, issued.item, issued.approval))

    def _read_output(self, issued, timeout, descriptor=None):
        descriptor = self.output_fd if descriptor is None else descriptor
        remaining = issued.deadline - time.monotonic()
        if remaining <= 0:
            raise FiniteInputError('The poll deadline expired before pipe observation.')
        if select.select([descriptor], [], [], min(timeout, remaining))[0]:
            try:
                data = self.read_stdout(descriptor, issued.deadline, issued=issued)
            except BlockingIOError:
                return b''
            if not data and self.dynamic_command is not None:
                if self.observe_process() == 'clean-exited':
                    return b''
            if not data or len(data) > 4096:
                raise FiniteInputError('Tool EOF or output bound ended the finite poll.')
            return data
        if time.monotonic() >= issued.deadline:
            raise FiniteInputError('The poll deadline expired during pipe observation.')
        return b''

    def dispatch_registered_gate(self, descriptor, params, deadline):
        """Commit the actual owned-child gate through the common lifecycle owner.

        The one-byte nonblocking write happens after the short arbitration.
        A later negative can classify it as prior-inflight and containment
        still owns the child; it cannot create a fresh authorization.
        """
        producer = self.server.finite_tools
        if type(descriptor) is not int or type(params) is not dict or producer is None:
            raise FiniteInputError('A selected owned gate and call are required.')
        os.set_blocking(descriptor, False)
        with producer.lock, self.lock, self.server.requests.lock, self.lifecycle.condition:
            binding, ticket = self._authorize_registered_gate(producer, params, deadline)
        try:
            released = os.write(descriptor, b'1')
        except BaseException:
            self.lifecycle.authority_result(ticket, 'unknown-send')
            self.lifecycle.finish('fault')
            raise
        if released != 1:
            self.lifecycle.authority_result(ticket, 'not-sent')
            self.lifecycle.finish('fault')
            raise FiniteInputError('The selected child gate was not released atomically.')
        self.lifecycle.authority_result(ticket, 'gate-opened')
        if not self.lifecycle.authority_open(binding):
            raise FiniteInputError('The prior-inflight child gate needs containment.')

    def _authorize_registered_gate(self, producer, params, deadline):
        producer._require_deadline(deadline)
        call = params.get('callId')
        if (producer.inflight != call or not producer._current(params)
                or self.state != 'unselected' or self.pending_lifetime is None
                or not self.lifecycle.call_live(call, {'gate-closed'})):
            raise FiniteInputError('The original command ended before gate release.')
        matches = [key for key, entry in self.lifecycle.pending.items()
                   if entry[1] == call]
        binding = ((producer.epoch, matches[0][1], params['threadId'],
                    params['turnId'], call, call) if len(matches) == 1 else None)
        ticket = self.lifecycle.authority_dispatch('registered-gate', binding)
        if ticket is None:
            raise FiniteInputError('The registered gate lost shared authority.')
        self.lifecycle.move('gate-release', call=call)
        return binding, ticket

    def _read_effect_current(self, descriptor, deadline, count):
        return (type(deadline) in (int, float) and time.monotonic() < deadline
                and self.state == 'active' and self._turn_readable()
                and self._current_authority() and self._current_process()
                and self._pipe_stat(descriptor) == self.output_stat
                and not os.get_blocking(descriptor)
                and type(count) is int and 1 <= count <= 4097)

    def _read_request_current(self, issued, params, producer):
        if issued is not None:
            return params is None and self._valid_ticket(issued, 0)
        if type(params) is not dict or producer is None:
            return False
        call = params.get('callId')
        phases = {'command-effect'} if params.get('tool') == 'finite_command' else {'poll-observing'}
        if (call not in producer.calls or producer.inflight not in (None, call)
                or not producer._current(params) or not self.lifecycle.call_live(call, phases)):
            return False
        matches = [key for key, entry in self.lifecycle.pending.items()
                   if entry[1] == call]
        if len(matches) != 1:
            return False
        self.lifecycle.require_request(matches[0], call)
        return True

    def read_stdout(self, descriptor, deadline, *, issued=None, params=None, count=4097):
        """Linearize one nonblocking physical read and its full byte charge.

        Readiness and status/capture callbacks run outside state locks. This
        fence serializes the actual nonblocking read with server request publication,
        refusal and gate revocation. A denied fence consumes no pipe bytes.
        """
        producer = self.server.finite_tools if params is not None else None
        with producer.lock if producer is not None else nullcontext():
            with self.lock, self.server.requests.lock, self.lifecycle.condition:
                if (not self._read_effect_current(descriptor, deadline, count)
                        or not self._read_request_current(issued, params, producer)):
                    raise FiniteInputError('The original stdout read effect is no longer authorized.')
                if issued is not None:
                    binding = (issued.epoch, issued.approval, issued.thread,
                               issued.turn, issued.approval, issued.approval)
                else:
                    call = params['callId']
                    matches = [key for key, entry in self.lifecycle.pending.items()
                               if entry[1] == call]
                    binding = ((producer.epoch, matches[0][1], params['threadId'],
                                params['turnId'], call, call)
                               if len(matches) == 1 else None)
                self._read_dispatch_index += 1
                ticket = self.lifecycle.authority_dispatch(
                    'stdout-read-%d' % self._read_dispatch_index, binding)
                if ticket is None:
                    raise FiniteInputError('The original stdout read lost shared authority.')
        try:
            data = os.read(descriptor, count)
        except BaseException:
            self.lifecycle.authority_result(ticket, 'not-sent')
            raise
        self.lifecycle.authority_result(ticket, 'effect-applied')
        self.account_output(data)
        if not self.lifecycle.authority_open(binding):
            raise FiniteInputError('The prior-inflight stdout read cannot publish output.')
        return data

    def account_output(self, data):
        """Charge every host-consumed stdout byte to one owned command."""
        if type(data) is not bytes:
            raise FiniteInputError('The owned output byte shape changed.')
        if not data:
            return
        with self.lock:
            self.output_bytes_seen += len(data)
            self.generation += 1
            self.lifecycle.tool_event('read', len(data))
            if self.state != 'active' or self.output_bytes_seen > 4096:
                self.state = 'revoked'
                self.generation += 1
                raise FiniteInputError('The owned command exceeded its cumulative stdout bound.')

    def drain_terminal_output(self, descriptor, initial, deadline, *, issued=None, params=None):
        """Read a known clean owned exit through EOF within the finite byte bound."""
        with self.lock:
            if (self.state != 'active' or self.terminal_code != 0
                    or self._pipe_stat(descriptor) != self.output_stat
                    or type(initial) is not bytes or len(initial) > 4096):
                raise FiniteInputError('Clean terminal output identity or bound differs.')
        end = min(deadline, time.monotonic() + .1)
        data = bytearray(initial)
        while time.monotonic() < end:
            if not select.select([descriptor], [], [], max(0, end - time.monotonic()))[0]:
                break
            try:
                chunk = self.read_stdout(descriptor, deadline, issued=issued, params=params,
                                         count=4097 - len(data))
            except BlockingIOError:
                continue
            if not chunk:
                with self.lock, self.server.requests.lock, self.lifecycle.condition:
                    if (self.state != 'active' or self.terminal_code != 0
                            or not self._turn_readable()):
                        raise FiniteInputError('Clean terminal output ended after revocation.')
                    if not self.terminal_eof_proven:
                        self.generation += 1
                    self.terminal_eof_proven = True
                    self.lifecycle.tool_event('eof')
                return bytes(data)
            data.extend(chunk)
            if len(data) > 4096:
                break
        raise FiniteInputError('Clean owned exit did not have bounded stdout EOF.')

    @staticmethod
    def _reply_digest(value):
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
        return hashlib.sha256(encoded).hexdigest()

    def issue_reply_observation(self, producer, message, response, deadline, frame, refusal):
        """Bind one response attempt to source, call, child and observed phase."""
        params = message.get('params', {})
        self._require_reply_shape(message, response, deadline, frame, params)
        success = response.get('result', {}).get('success') is True
        with producer.lock, self.lock, self.server.requests.lock, self.lifecycle.condition:
            if success:
                self.lifecycle.require_success_reply(
                    protocol._id_key(message['id']), params.get('callId'))
                # The request registry may have committed a terminal or item projection while
                # reducer publication was pending. Never issue a success ticket
                # on the reducer phase alone.
                self._reply_item(producer, message, False)
                if not self.lifecycle.call_live(params.get('callId'),
                        {'command-effect'} if params.get('tool') == 'finite_command'
                        else {'poll-observing'}):
                    raise FiniteInputError('The original reply phase cannot issue a ticket.')
            if (producer is not self.server.finite_tools or producer.factory is not self.factory
                    or time.monotonic() >= deadline or self.server.connection_epoch_sha256 != producer.epoch):
                raise FiniteInputError('The finite reply source or deadline changed.')
            phase = self._reply_phase(producer, success, refusal)
            if phase is None:
                return None
            ticket = object.__new__(ReplyTicket)
            lifetime = self.lifetime
            self.reply_tickets[ticket] = _Reply(
                self.factory, producer, lifetime, self.process,
                None if lifetime is None else lifetime.birth,
                None if lifetime is None else lifetime.receipt,
                producer.epoch, self._authority_snapshot(), message, response,
                self._reply_digest(params), hashlib.sha256(frame).hexdigest(),
                deadline, phase, self.generation)
            return ticket

    @staticmethod
    def _require_reply_shape(message, response, deadline, frame, params):
        if (type(params) is not dict or type(response) is not dict
                or type(response.get('id')) is not type(message.get('id'))
                or response.get('id') != message.get('id')
                or type(frame) is not bytes or type(deadline) not in (int, float)):
            raise FiniteInputError('The finite reply identity or frame differs.')

    def _reply_phase(self, producer, success, refusal):
        if not success:
            return 'fault' if refusal else 'refused'
        if self.state != 'active' or producer.lifetime is not self.lifetime:
            raise FiniteInputError('The selected tool reply lost its owned process.')
        if not self._current_authority():
            raise FiniteInputError('The selected tool reply lost its original authority.')
        if not self._current_process():
            return None
        if self.terminal_code == 0 and not self.terminal_eof_proven:
            raise FiniteInputError('A clean exit without bounded EOF cannot reply.')
        return 'clean-exited' if self.terminal_code == 0 else 'running'

    def _reply_binding_current(self, issued, producer, message, response, deadline, frame):
        lifetime = issued.lifetime
        return (issued.factory is self.factory and issued.producer is producer
                and issued.message is message and issued.response is response
                and issued.deadline == deadline and issued.epoch == producer.epoch
                and self.server.connection_epoch_sha256 == issued.epoch
                and issued.params_sha256 == self._reply_digest(message.get('params', {}))
                and issued.frame_sha256 == hashlib.sha256(frame).hexdigest()
                and self._same_authority(self._authority_snapshot(), issued.authority)
                and issued.lifetime is self.lifetime and issued.process is self.process
                and (lifetime is None or (issued.birth is lifetime.birth
                                          and issued.receipt is lifetime.receipt)))

    def commit_reply_observation(self, ticket, producer, message, response, deadline,
                                 frame, writer, refusal):
        """Dispatch a bound reply before physical write, then reconcile it."""
        with producer.lock, self.lock, self.server.requests.lock, self.lifecycle.condition:
            issued = self._consume_reply_observation(ticket)
            self._require_reply_binding(issued, producer, message, response, deadline, frame)
            item = self._reply_item(producer, message, refusal)
            success = response.get('result', {}).get('success') is True
            if success:
                call = message['params'].get('callId')
                self.lifecycle.require_success_reply(protocol._id_key(message['id']), call)
                if not self.lifecycle.call_live(call,
                        {'command-effect'} if message['params'].get('tool') == 'finite_command'
                        else {'poll-observing'}):
                    raise FiniteInputError('The original reply phase cannot commit a frame.')
            if not self._reply_phase_current(issued):
                return False
            binding = (issued.epoch, message['id'], item[0], item[1], item[2],
                       message['params'].get('callId'))
            dispatch = self.lifecycle.authority_dispatch('tool-reply', binding) if success else None
            if success and dispatch is None:
                raise FiniteInputError('The finite reply lost shared authority.')
        try:
            written = self._write_reply_frame(writer, frame)
        except BaseException:
            if dispatch is not None:
                self.lifecycle.authority_result(dispatch, 'unknown-send')
            raise
        if dispatch is not None:
            self.lifecycle.authority_result(dispatch, 'wire-sent' if written else 'not-sent')
        if not written:
            return False
        with producer.lock, self.lock, self.server.requests.lock, self.lifecycle.condition:
            if dispatch is not None and not self.lifecycle.authority_reply_finishable(binding):
                raise FiniteInputError('The prior-inflight tool reply is ambiguous.')
            self.server._mark_command_reply(message, response, item)
            self.server._sync_finite_progress_locked()
            return True

    def _consume_reply_observation(self, ticket):
        issued = self.reply_tickets.get(ticket) if type(ticket) is ReplyTicket else None
        if issued is None or issued.used:
            raise FiniteInputError('An issued one-use finite reply observation is required.')
        issued.used = True
        return issued

    def _require_reply_binding(self, issued, producer, message, response, deadline, frame):
        if (not self._reply_binding_current(issued, producer, message, response, deadline, frame)
                or (issued.phase in ('running', 'clean-exited')
                    and not self._current_authority())
                or time.monotonic() >= deadline or self.server.requests.closed
                or self.server.transport_failure is not None):
            raise FiniteInputError('The finite reply source, lifetime or deadline changed.')

    def _reply_item(self, producer, message, refusal):
        params = message['params']
        identity = params.get('threadId'), params.get('turnId')
        item = (*identity, params.get('callId'))
        if not refusal and (identity in self.server.requests.terminals
                or identity in self.server.requests.trusted_terminals
                or identity == self.server.requests.cancelled_turn
                or item in self.server.requests.completed_items
                or not producer._current(params)):
            raise FiniteInputError('The finite reply item or turn ended.')
        return item

    def _reply_phase_current(self, issued):
        if issued.phase == 'refused':
            return issued.generation == self.generation
        if issued.phase == 'fault':
            return True
        if self.state != 'active':
            raise FiniteInputError('The selected tool closed before reply.')
        if issued.generation != self.generation:
            return False
        if not self._current_process():
            return False if issued.phase == 'running' else self._invalid_clean_reply()
        if issued.phase != ('clean-exited' if self.terminal_code == 0 else 'running'):
            return False
        if issued.phase == 'clean-exited' and not self.terminal_eof_proven:
            raise FiniteInputError('Clean terminal EOF proof disappeared.')
        return True

    @staticmethod
    def _write_reply_frame(writer, frame):
        writer.flush()
        try:
            count = os.write(writer.descriptor, frame)
        except (BlockingIOError, InterruptedError):
            return False
        if count != len(frame):
            raise FiniteInputError('The finite tool reply was partially written.')
        return True

    @staticmethod
    def _invalid_clean_reply():
        raise FiniteInputError('A clean exit lost its same-handle proof before reply.')

    def _publish_cleanup_event(self, phase):
        # Reducer publication is an acknowledgement, not the truth record.
        # Even a rejected event or failed wake leaves consumer reads tied to
        # the gate classification and latches publication failure.
        try:
            accepted = self.lifecycle.cleanup_event(phase)
            if not accepted and self.lifecycle._cleanup != phase:
                self._mark_cleanup_publication_failed()
        except BaseException:
            self._mark_cleanup_publication_failed()
            try:
                with self.lifecycle.condition:
                    self.lifecycle.condition.notify_all()
            except BaseException:
                pass

    def revoke(self):
        self.lifecycle.authority_revoke('closed')
        with self.lock:
            self.state = 'revoked'
            self.capture_phase = 'revoked'
            self.generation += 1
            self.revocation_generation += 1
            pending = self._cleanup_lifetime() is not None
            for issued in self.tickets.values():
                issued.used = True
        if pending:
            self._publish_cleanup_event('pending')

    def _publish_cleanup_observation(self, lifetime, observation, prior_result):
        if (type(observation) is not self._cleanup_observation_type
                or observation is prior_result):
            lifetime._record_observation(kind='invalid-observation')
        with self._cleanup_condition:
            self._cleanup_inflight -= 1
            self._cleanup_committed = True
            phase = self.cleanup_phase()
            self._notify_cleanup_waiters()
        self._publish_cleanup_event(
            'unknown' if phase == 'unknown' else
            'contained' if phase == 'contained' else 'pending')

    def _publish_failed_cleanup_wait(self, lifetime, kind):
        # The failure was latched under the gate lock before this callout.
        # A synchronous listener or reducer may reenter without that lock.
        try:
            lifetime._record_observation(kind=kind)
        finally:
            self._publish_cleanup_event('unknown')

    def _await_cleanup_classification(self, deadline):
        # Spend only the remainder of this closer's original observation
        # budget. Condition.wait releases the gate lock while a peer finishes.
        with self._cleanup_condition:
            while True:
                phase = self.cleanup_phase()
                if phase != 'cleanup-pending':
                    return phase
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    kind = 'timeout'
                else:
                    try:
                        self._cleanup_condition.wait(remaining)
                        continue
                    except BaseException:
                        kind = 'observer-failed'
                # This is the failed close's linearization point. A peer may
                # finish before the typed result is appended outside the lock,
                # but can never turn this failed observation healthy.
                self._cleanup_publication_failed = True
                lifetime = self._cleanup_lifetime()
                self._notify_cleanup_waiters()
                break
        self._publish_failed_cleanup_wait(lifetime, kind)
        return 'unknown'

    def close(self, failure=None):
        # A failed owned-tool launch can reach this gate before the outer
        # transport fault. Latch its negative under the shared owner before
        # publishing the revoked gate state or starting bounded containment.
        self.lifecycle.authority_revoke('fault' if failure is not None else 'closed')
        deadline = time.monotonic() + 10
        # Reserve under the gate lock before any effect, wait or diagnostic
        # callout. Every closer, including a later closer, has a bounded
        # observation and may not publish healthy over a pending peer.
        with self.lock:
            self.state = 'revoked'
            self.capture_phase = 'revoked'
            self.generation += 1
            self.revocation_generation += 1
            for issued in self.tickets.values():
                issued.used = True
            lifetime = self.lifetime or self.pending_lifetime
            self.lifetime = self.pending_lifetime = None
            if lifetime is not None:
                self.closed_lifetime = lifetime
            else:
                lifetime = self.closed_lifetime
            if lifetime is not None:
                self._cleanup_inflight += 1
        if lifetime is None:
            return
        self._publish_cleanup_event('pending')
        prior_result = getattr(lifetime._observation_local, 'result', None)
        observation = None
        try:
            if failure is None:
                lifetime.settle_termination()
                observation = lifetime._observation_local.result
            else:
                observation = lifetime.cleanup_failure(failure)
        except BaseException as secondary:
            observation = lifetime.cleanup_observation(secondary)
            raise
        finally:
            self._publish_cleanup_observation(lifetime, observation, prior_result)
        phase = self.cleanup_phase()
        if failure is None and phase == 'cleanup-pending':
            phase = self._await_cleanup_classification(deadline)
        if phase != 'contained':
            if failure is None:
                raise FiniteInputError('The original tool lifetime remains unresolved.')
            try:
                failure.add_note('The original tool lifetime remains unresolved.')
            except BaseException:
                pass
