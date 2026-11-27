#!/usr/bin/env python3
"""Publish operator approvals and serve configured lead authority requests."""

import argparse
from functools import partial
from pathlib import Path
import signal
import sys

from cwo_core.errors import CWOError
from cwo_core.host_records import configured_store
from cwo_core.host_return_intake import MAX_RETURN_BYTES
from cwo_core.lead_authority import ApprovalStore, AuthorityError, AuthorityHost, configured_authority_layout
from cwo_core.outbound_approval import OUTBOUND_APPROVAL, outbound_approval_payload
from cwo_core.policy_schema import strict_json_loads
from evaluate_synthesis import evaluate_protected_synthesis, validate_synthesis_approval


_REQUEST_VALIDATORS = {
    "synthesis": validate_synthesis_approval,
    OUTBOUND_APPROVAL: outbound_approval_payload,
}


def _publish(layout, operation):
    approvals = ApprovalStore(layout)
    raw = sys.stdin.buffer.read(MAX_RETURN_BYTES + 1)
    if len(raw) > MAX_RETURN_BYTES:
        raise AuthorityError("operator approval exceeds its byte limit")
    payload = strict_json_loads(raw.decode("utf-8"))
    _REQUEST_VALIDATORS[operation](payload)
    print(approvals.publish(operation, payload))


def _stop(*_):
    raise KeyboardInterrupt


def _serve(layout):
    records = configured_store()
    if records.state_root != layout.state_root:
        raise AuthorityError("original host records must use the protected authority state root")
    handlers = {"synthesis": partial(evaluate_protected_synthesis, records),
                OUTBOUND_APPROVAL: outbound_approval_payload}
    with AuthorityHost(layout, handlers) as host:
        previous = signal.signal(signal.SIGTERM, _stop)
        try:
            while True:
                host.serve_once()
        finally:
            signal.signal(signal.SIGTERM, previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="Serve approved lead requests from the fixed host configuration.")
    publish = commands.add_parser("publish", help="Read an operator approval JSON object from standard input.")
    publish.add_argument("operation", choices=tuple(_REQUEST_VALIDATORS))
    args = parser.parse_args()
    try:
        layout = configured_authority_layout()
        if not Path(__file__).resolve().is_relative_to(layout.source_root):
            raise AuthorityError("authority host entry point requires the protected installation")
        if args.command == "publish":
            _publish(layout, args.operation)
        else:
            _serve(layout)
    except KeyboardInterrupt:
        return
    except (CWOError, OSError, ValueError, RecursionError) as failure:
        raise SystemExit(str(failure)) from failure


if __name__ == "__main__":
    main()
