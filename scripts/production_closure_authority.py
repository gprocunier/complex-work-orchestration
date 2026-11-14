"""Host-record authority for the disabled production closure adapter.

No caller-written approval file is an authority source. The store and audit log
come from host configuration, independently of the worker and custody roots.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cwo_core import host_acceptance, host_records


def _snapshot(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _require_delivery_context(value: dict, bead_id: str) -> None:
    if type(value) is not dict or set(value) != {"task", "scope", "candidate"}:
        raise ValueError("delivery context requires exact task, baseline and candidate digests")
    if value["task"] != bead_id or any(type(value[key]) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) is None for key in ("scope", "candidate")):
        raise ValueError("delivery context requires the current task, baseline and candidate digests")


@dataclass(frozen=True)
class Authority:
    store: Any
    acceptance_record: str
    bead_id: str
    return_sha256: str
    evaluation_sha256: str
    database_identity: bytes
    decision: bytes
    delivery_context: bytes

    def check(self, database: str) -> dict[str, Any]:
        identity = self.store.require_database_identity(Path(database))
        if _snapshot(identity) != self.database_identity:
            raise ValueError("registered workspace database identity changed")
        decision = host_acceptance.require_acceptance(
            self.store, self.acceptance_record, bead_id=self.bead_id,
            return_sha256=self.return_sha256, evaluation_sha256=self.evaluation_sha256,
            database_identity=identity, delivery_context=json.loads(self.delivery_context))
        if _snapshot(decision) != self.decision:
            raise ValueError("verified autonomous acceptance decision changed")
        return identity

    def record_closure(self) -> None:
        self.store.record_audit_event({
            "event_type": "production_closure_consumed",
            "bead_id": self.bead_id,
            "acceptance_record_sha256": self.acceptance_record,
            "return_sha256": self.return_sha256,
            "evaluation_sha256": self.evaluation_sha256,
            "database_identity": json.loads(self.database_identity),
        })


def capture(*, database: str, bead_id: str, acceptance_record: str,
            return_sha256: str, evaluation_sha256: str,
            delivery_context: dict,
            worker_writable_roots: tuple[Path, ...] = ()) -> Authority:
    _require_delivery_context(delivery_context, bead_id)
    store = host_records.configured_store()
    store.require_outside_worker_roots(worker_writable_roots)
    identity = store.require_database_identity(Path(database))
    decision = host_acceptance.require_acceptance(
        store, acceptance_record, bead_id=bead_id, return_sha256=return_sha256,
        evaluation_sha256=evaluation_sha256, database_identity=identity, delivery_context=delivery_context)
    return Authority(store, acceptance_record, bead_id, return_sha256,
                     evaluation_sha256, _snapshot(identity), _snapshot(decision), _snapshot(delivery_context))
