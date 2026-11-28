"""Host-record authority for the verified production closure adapter.

No caller-written approval file is an authority source. The store and audit log
come from host configuration, independently of the worker and custody roots.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cwo_core import audit, host_acceptance, host_records


def _snapshot(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _require_delivery_context(value: dict, bead_id: str) -> None:
    if type(value) is not dict or set(value) != {"task", "scope", "candidate"}:
        raise ValueError("delivery context requires exact task, baseline and candidate digests")
    if value["task"] != bead_id or any(type(value[key]) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) is None for key in ("scope", "candidate")):
        raise ValueError("delivery context requires the current task, baseline and candidate digests")


def _require_consumption(events: list[dict[str, Any]], acceptance_record: str,
                         owned_event: str | None = None) -> None:
    consumed = [event for event in events
                if event.get("event_type") == "production_closure_consumed"
                and event.get("acceptance_record_sha256") == acceptance_record]
    if owned_event is None:
        if consumed:
            raise ValueError("this acceptance has already been consumed")
    elif len(consumed) != 1 or consumed[0].get("event_hash") != owned_event:
        raise ValueError("production closure consumption intent changed")


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
    consumption_event: str | None = None

    @property
    def evidence_disposition(self) -> str:
        record = self.store.get(json.loads(self.decision)["evaluation_record"], record_type="evaluation")
        return record["evaluation"]["recommended_disposition"]

    def require_observation(self, digest: str) -> None:
        context = json.loads(self.decision).get("source_context")
        if type(context) is not dict or context.get("observation_sha256") != digest:
            raise ValueError("final review does not bind the exact complete observations")

    def check(self, database: str) -> dict[str, Any]:
        _require_consumption(self.store.audit_events(), self.acceptance_record, self.consumption_event)
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

    def record_closure(self) -> Authority:
        """Claim once before any Beads write, retaining authority only for this attempt.

        The existing host audit lock makes the replay check and durable intent
        append atomic across registrations and processes. No Beads call runs
        under that lock; subsequent checks still reverify the full acceptance.
        """
        event = {
            "event_type": "production_closure_consumed",
            "bead_id": self.bead_id,
            "acceptance_record_sha256": self.acceptance_record,
            "return_sha256": self.return_sha256,
            "evaluation_sha256": self.evaluation_sha256,
            "database_identity": json.loads(self.database_identity),
        }
        with self.store._guarded_state(create=True) as (state, lock):
            _require_consumption(host_records._audit_snapshot(state, self.store.limits), self.acceptance_record)
            receipt = audit.record_audit_event(event, self.store.audit_file,
                _directory_fd=state, _limits=self.store.limits, _lock_fd=lock)
        return replace(self, consumption_event=receipt["event_hash"])


def capture(*, database: str, bead_id: str, acceptance_record: str,
            return_sha256: str, evaluation_sha256: str,
            delivery_context: dict,
            worker_writable_roots: tuple[Path, ...] = ()) -> Authority:
    _require_delivery_context(delivery_context, bead_id)
    store = host_records.configured_store()
    store.require_outside_worker_roots(worker_writable_roots)
    _require_consumption(store.audit_events(), acceptance_record)
    identity = store.require_database_identity(Path(database))
    decision = host_acceptance.require_acceptance(
        store, acceptance_record, bead_id=bead_id, return_sha256=return_sha256,
        evaluation_sha256=evaluation_sha256, database_identity=identity, delivery_context=delivery_context)
    return Authority(store, acceptance_record, bead_id, return_sha256,
                     evaluation_sha256, _snapshot(identity), _snapshot(decision), _snapshot(delivery_context))
