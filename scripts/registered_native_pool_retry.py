"""Read signed retry observations from the original registered serial pool."""

from __future__ import annotations

import hashlib

import registered_native_pool_host as P

R = P.R
_need, _encode = P._need, P._encode
_HOST = P.RegisteredNativePoolHost
_HOST_METHODS = R.admitted._method_table(_HOST)


def issue_controller(parent, *, retry_id, state_directory):
    raise ValueError("registered-serial-pool-retry-retired")


def observe_retry(host, retry_id):
    """Read original signed retry status without adopting, issuing or dispatching.

    Lost in-memory failure custody forbids a fresh execution claim, but does
    not prevent the protected parent from inspecting durable observations.
    """
    R.admitted._original_methods(host, _HOST, _HOST_METHODS)
    _need(R.admission.ledger_api._is_id(retry_id), 'A bounded retry identity is required.')
    name = 'retry-' + hashlib.sha256(retry_id.encode()).hexdigest()
    with host._locked():
        unknown = {'retry_id': retry_id, 'state': 'unknown', 'redispatch_permitted': False, **R._FALSE}
        if not (host.config.state / (name + '-intent.json')).exists():
            return unknown
        intent = host._load(name + '-intent.json')
        _need(intent['action']['pool'] == host.config.binding
              and intent['action']['retry_id'] == retry_id, 'Original signed retry binding changed.')
        if not (host.config.state / (name + '-terminal.json')).exists():
            return unknown
        return _terminal(host, name + '-terminal.json', intent)


def _terminal(host, name, intent):
    terminal = host._load(name)
    _need(terminal['retry_id'] == intent['action']['retry_id']
          and terminal['worker_id'] == intent['action']['worker_id']
          and terminal['intent_sha256'] == hashlib.sha256(_encode(intent)).hexdigest(),
          'Retry terminal belongs to another intent or member.')
    return terminal


class ApprovedPoolRetry:
    """Retired execution interface retained to refuse prior callers."""

    def __init__(self, host, *, worker_id, retry_id, controller):
        raise ValueError("registered-serial-pool-retry-retired")

    def adopt_execution(self, *, adoption_id, disclosure_consent):
        raise ValueError("registered-serial-pool-retry-retired")

    def run(self):
        R.live_availability.require_pool_live()
        R.live_availability.require_n1_live()
        raise ValueError("registered-serial-pool-retry-retired")
