"""Errors raised by the Codex app-server transport.

Moved unchanged from ``scripts/run_native_pool_live_canaries.py``, which still
re-exports these names.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from cwo_core.native_turn_dispatch import validate_turn_dispatch_record


class AppServerError(RuntimeError):
    pass


class AppServerRpcError(AppServerError):
    """One request-correlated JSON-RPC error with trusted local method context."""

    def __init__(
        self,
        *,
        method: str,
        code: int,
        request_id: int,
        latency_ms: float,
    ) -> None:
        if not isinstance(method, str) or not method:
            raise ValueError("app-server-rpc-error-method-invalid")
        if type(code) is not int:
            raise ValueError("app-server-rpc-error-code-invalid")
        if type(request_id) is not int or request_id < 0:
            raise ValueError("app-server-rpc-error-request-id-invalid")
        if (
            isinstance(latency_ms, bool)
            or not isinstance(latency_ms, (int, float))
            or not math.isfinite(float(latency_ms))
            or float(latency_ms) < 0
        ):
            raise ValueError("app-server-rpc-error-latency-invalid")
        self.method = method
        self.code = code
        self.request_id = request_id
        self.latency_ms = float(latency_ms)
        super().__init__(f"app-server-request-failed:{method}:{code}")


class AmbiguousTurnStartError(AppServerError):
    """A single turn write whose server-side effect required containment."""

    def __init__(self, record: Mapping[str, Any]) -> None:
        errors = validate_turn_dispatch_record(record)
        if errors:
            raise ValueError("ambiguous-turn-start-record-invalid:" + ";".join(errors))
        self.record = dict(record)
        super().__init__(f"turn-start-{record['status']}:{record['ambiguity_reason']}")
