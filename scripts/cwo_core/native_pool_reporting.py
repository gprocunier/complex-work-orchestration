"""Safe status and audit projections for native supervision pools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .audit import record_audit_event
from .native_pool_contracts import (
    pool_capacity_limits,
    validate_pool_contract,
    validate_pool_receipt,
    validate_pool_state,
)


STATUS_REPORT_TYPE = "cwo-native-supervision-pool-status"
STATUS_REPORT_VERSION = 1
_EXECUTING_CHILD_STATUSES = {
    "armed",
    "running",
    "interrupt-pending",
    "interrupt-confirmed",
}


class NativePoolReportingError(ValueError):
    """Raised when pool status cannot be proven from bound artifacts."""


def _remaining(limit: int, used: int) -> int:
    return max(0, limit - used)


def build_pool_status_report(
    contract: Mapping[str, Any],
    state: Mapping[str, Any],
    receipt: Mapping[str, Any] | None = None,
    *,
    policy_document: Mapping[str, Any] | None = None,
    admission_reservation: Mapping[str, Any] | None = None,
    dispatch_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete local status view without task inputs or filesystem paths."""
    capacity_limits = pool_capacity_limits(policy_document)
    contract_errors = validate_pool_contract(
        contract,
        capacity_limits=capacity_limits,
        admission_reservation=admission_reservation,
    )
    if contract_errors:
        raise NativePoolReportingError("pool-contract-invalid:" + ";".join(contract_errors))
    state_errors = validate_pool_state(state, contract=contract)
    if state_errors:
        raise NativePoolReportingError("pool-state-invalid:" + ";".join(state_errors))
    if receipt is not None:
        receipt_errors = validate_pool_receipt(
            receipt,
            contract=contract,
            terminal_state=state,
            admission_reservation=admission_reservation,
            dispatch_receipt=dispatch_receipt,
            capacity_limits=capacity_limits,
        )
        if receipt_errors:
            raise NativePoolReportingError("pool-receipt-invalid:" + ";".join(receipt_errors))

    hard_budget = dict(contract["aggregate_hard_budget"])
    usage = dict(state["aggregate_usage"])
    usage_fields = ("tool_calls", "runtime_seconds", "compactions", "full_suite_runs", "mutations")
    usage_view = {
        field: {
            "used": usage[field],
            "limit": hard_budget[field],
            "remaining": _remaining(hard_budget[field], usage[field]),
        }
        for field in usage_fields
    }
    usage_view["tokens"] = dict(usage["tokens"])

    receipt_dispositions = {
        item["child_id"]: {
            "runtime_disposition": item["runtime_disposition"],
            "session_disposition": item["session_disposition"],
            "artifact_disposition": item["artifact_disposition"],
        }
        for item in (receipt.get("child_dispositions", []) if receipt is not None else [])
    }
    receipt_leases = {
        item["lease_id"]: item
        for item in (receipt.get("lease_evidence", []) if receipt is not None else [])
    }
    children: list[dict[str, Any]] = []
    leases: list[dict[str, Any]] = []
    admitted = 0
    executing = 0
    awaiting_close = 0
    for contract_child, state_child in zip(contract["children"], state["children"]):
        status = state_child["status"]
        admitted += int(status != "created")
        executing += int(status in _EXECUTING_CHILD_STATUSES)
        awaiting_close += int(status == "completed")
        child_disposition = receipt_dispositions.get(contract_child["child_id"], {})
        children.append(
            {
                "ordinal": contract_child["ordinal"],
                "child_id": contract_child["child_id"],
                "status": status,
                "runtime_disposition": state_child["runtime_disposition"],
                "usage": dict(state_child["last_cumulative_usage"]),
                "last_deadline_ns": state_child["last_deadline_ns"],
                "next_deadline_ns": state_child["next_deadline_ns"],
                "session_disposition": child_disposition.get("session_disposition"),
                "artifact_disposition": child_disposition.get("artifact_disposition"),
            }
        )
        lease = receipt_leases.get(contract_child["lease_id"])
        leases.append(
            {
                "child_id": contract_child["child_id"],
                "lease_id": contract_child["lease_id"],
                "bound": state_child["status"] != "created",
                "lifecycle_state": lease.get("lifecycle_state") if lease is not None else None,
                "lease_sha256": lease.get("lease_sha256") if lease is not None else None,
            }
        )

    report: dict[str, Any] = {
        "report_type": STATUS_REPORT_TYPE,
        "version": STATUS_REPORT_VERSION,
        "pool_id": contract["pool_id"],
        "pool_epoch": contract["pool_epoch"],
        "contract_sha256": contract["contract_sha256"],
        "state_sha256": state["state_sha256"],
        "receipt_sha256": receipt.get("receipt_sha256") if receipt is not None else None,
        "status": state["status"],
        "completion_policy": contract.get(
            "completion_policy", "all-or-nothing"
        ),
        "state_sequence": state["state_sequence"],
        "capacity": {
            "configured_workers": len(contract["children"]),
            "max_active_workers": contract["max_active_workers"],
            "admitted_workers": admitted,
            "executing_workers": executing,
            "awaiting_close_workers": awaiting_close,
            "terminal_workers": len(state["terminal_children"]),
        },
        "aggregate_usage": usage_view,
        "timing": {
            "pool_started_monotonic_ns": state["pool_started_monotonic_ns"],
            "pool_wall_seconds": state["pool_wall_seconds"],
            "worker_seconds": state["worker_seconds"],
            "poll_overhead_seconds": state["poll_overhead_seconds"],
            "max_callback_latency_ms": receipt.get("timing", {}).get("max_callback_latency_ms") if receipt is not None else None,
            "max_poll_gap_ms": receipt.get("timing", {}).get("max_poll_gap_ms") if receipt is not None else None,
            "poll_interval_ms": contract["scheduler"]["poll_interval_ms"],
            "poll_lag_tolerance_ms": contract["scheduler"]["poll_lag_tolerance_ms"],
        },
        "children": children,
        "leases": leases,
        "reasons": list(state["reasons"]),
        "pool_disposition": receipt.get("pool_disposition") if receipt is not None else None,
        "accepting": receipt.get("accepting") if receipt is not None else None,
    }
    return report


def native_pool_audit_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    """Project a status report to the path-free audit allowlist."""
    if report.get("report_type") != STATUS_REPORT_TYPE:
        raise NativePoolReportingError("native-pool-status-report-type-invalid")
    capacity = report.get("capacity", {})
    aggregate = report.get("aggregate_usage", {})
    timing = report.get("timing", {})
    children = report.get("children", [])
    leases = report.get("leases", [])
    return {
        "version": STATUS_REPORT_VERSION,
        "pool_id": report.get("pool_id"),
        "pool_epoch": report.get("pool_epoch"),
        "contract_sha256": report.get("contract_sha256"),
        "state_sha256": report.get("state_sha256"),
        "receipt_sha256": report.get("receipt_sha256"),
        "status": report.get("status"),
        "max_active_workers": capacity.get("max_active_workers"),
        "configured_workers": capacity.get("configured_workers"),
        "admitted_workers": capacity.get("admitted_workers"),
        "executing_workers": capacity.get("executing_workers"),
        "terminal_workers": capacity.get("terminal_workers"),
        "aggregate_tool_calls": aggregate.get("tool_calls", {}).get("used"),
        "aggregate_runtime_seconds": aggregate.get("runtime_seconds", {}).get("used"),
        "aggregate_compactions": aggregate.get("compactions", {}).get("used"),
        "aggregate_full_suite_runs": aggregate.get("full_suite_runs", {}).get("used"),
        "aggregate_mutations": aggregate.get("mutations", {}).get("used"),
        "pool_wall_seconds": timing.get("pool_wall_seconds"),
        "worker_seconds": timing.get("worker_seconds"),
        "poll_overhead_seconds": timing.get("poll_overhead_seconds"),
        "lease_states": [
            item.get("lifecycle_state") or "active"
            for item in leases
            if isinstance(item, Mapping) and item.get("bound") is True
        ],
        "session_dispositions": [item.get("session_disposition") for item in children if isinstance(item, Mapping) and item.get("session_disposition")],
        "artifact_dispositions": [item.get("artifact_disposition") for item in children if isinstance(item, Mapping) and item.get("artifact_disposition")],
        "pool_disposition": report.get("pool_disposition"),
        "accepting": report.get("accepting"),
    }


def record_pool_audit_event(
    report: Mapping[str, Any],
    *,
    event_type: str,
    bead_id: str,
    audit_file: Path | None = None,
) -> dict[str, Any]:
    if event_type not in {
        "native_pool_rendered",
        "native_pool_status",
        "native_pool_interrupt_requested",
        "native_pool_terminal",
    }:
        raise NativePoolReportingError("native-pool-audit-event-type-invalid")
    if not isinstance(bead_id, str) or not bead_id.strip():
        raise NativePoolReportingError("native-pool-audit-bead-id-required")
    return record_audit_event(
        {
            "event_type": event_type,
            "telemetry_kind": "native_supervision_pool",
            "telemetry_status": str(report.get("status") or "unknown"),
            "dispatch_id": str(report.get("pool_id") or ""),
            "bead_id": bead_id,
            "native_pool_summary": native_pool_audit_summary(report),
        },
        audit_file,
    )
