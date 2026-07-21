"""Supported productive launcher for an exact admitted native-worker cohort."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

from .native_pool import _build_admitted_pool_coordinator
from .native_pool_admission import (
    ClaimAdapter,
    FixedCohortAdmissionCapability,
    LiveRevalidationCallback,
    NativePoolAdmissionError,
    build_dispatch_context,
    consume_pool_admission,
    revalidate_reservation_live,
    validate_reservation_receipt,
)
from .native_pool_contracts import (
    ADMITTED_POOL_VERSION,
    canonical_sha256,
    validate_pool_contract,
)
from .native_pool_leases import PoolLeaseError, PoolLeaseRegistry
from .native_pool_preflight import (
    ADMITTED_PREFLIGHT_VERSION,
    run_pool_preflight,
    validate_pool_preflight_result,
)


def run_admitted_native_pool(
    reservation_receipt: Mapping[str, Any],
    admission_capability: FixedCohortAdmissionCapability,
    contract: Mapping[str, Any],
    preflight_request: Mapping[str, Any],
    preflight_result: Mapping[str, Any],
    child_contracts: Mapping[str, Mapping[str, Any]],
    task_inputs: Mapping[str, str],
    child_callbacks: Mapping[str, Mapping[str, Callable[..., Any]]],
    *,
    claim_adapter: ClaimAdapter,
    live_revalidate: LiveRevalidationCallback,
    pool_callbacks: Mapping[str, Callable[..., Any]],
    lease_registry: PoolLeaseRegistry,
    capability_receipt: Mapping[str, Any] | None = None,
    state_file: Path | str | None = None,
    decision_file: Path | str | None = None,
    control_file: Path | str | None = None,
    policy_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one fixed N<=2 cohort after consuming its exact live authority."""

    reservation_errors = validate_reservation_receipt(reservation_receipt)
    if reservation_errors:
        raise NativePoolAdmissionError(
            "admitted-launch-reservation-invalid:" + ";".join(reservation_errors)
        )
    if reservation_receipt.get("status") != "admitted":
        raise NativePoolAdmissionError("admitted-launch-reservation-not-admitted")
    if type(admission_capability) is not FixedCohortAdmissionCapability:
        raise NativePoolAdmissionError("admitted-launch-capability-type-invalid")
    if admission_capability.state != "available":
        raise NativePoolAdmissionError(
            "admitted-launch-capability-not-available:"
            + admission_capability.state
        )
    if contract.get("version") != ADMITTED_POOL_VERSION:
        raise NativePoolAdmissionError("admitted-launch-v2-contract-required")
    contract_errors = validate_pool_contract(
        contract,
        admission_reservation=reservation_receipt,
    )
    if contract_errors:
        raise NativePoolAdmissionError(
            "admitted-launch-contract-invalid:" + ";".join(contract_errors)
        )
    if (
        preflight_request.get("version") != ADMITTED_PREFLIGHT_VERSION
        or preflight_request.get("stage") != "pre-dispatch"
        or preflight_request.get("pool_contract") != contract
        or preflight_request.get("admission_reservation") != reservation_receipt
    ):
        raise NativePoolAdmissionError("admitted-launch-preflight-chain-mismatch")
    preflight_errors = validate_pool_preflight_result(
        preflight_result,
        expected_stage="pre-dispatch",
        expected_contract_sha256=contract["contract_sha256"],
        expected_admission_reservation_sha256=reservation_receipt[
            "reservation_sha256"
        ],
    )
    if preflight_errors:
        raise NativePoolAdmissionError(
            "admitted-launch-preflight-result-invalid:"
            + ";".join(preflight_errors)
        )
    replayed_preflight = run_pool_preflight(preflight_request)
    if (
        preflight_result.get("accepted") is not True
        or preflight_result.get("decision") != "accept"
        or dict(preflight_result) != replayed_preflight
    ):
        raise NativePoolAdmissionError("admitted-launch-preflight-not-exact-accept")

    child_ids = [str(child["child_id"]) for child in contract["children"]]
    acquired = lease_registry.acquire_many(contract, child_ids)
    commit_invoked = False
    try:
        revalidate_reservation_live(
            reservation_receipt,
            claim_adapter=claim_adapter,
            live_revalidate=live_revalidate,
        )
        lease_set_sha256 = canonical_sha256({"leases": acquired})
        dispatch_context = build_dispatch_context(
            reservation_receipt,
            pool_contract_sha256=contract["contract_sha256"],
            preflight_request_sha256=preflight_result["request_sha256"],
            preflight_result_sha256=preflight_result["result_sha256"],
            lease_set_sha256=lease_set_sha256,
        )
        terminal: dict[str, Any] = {}

        def commit(dispatch_receipt: Mapping[str, Any]) -> None:
            nonlocal commit_invoked
            commit_invoked = True
            coordinator = _build_admitted_pool_coordinator(
                contract,
                child_contracts,
                task_inputs,
                child_callbacks,
                pool_callbacks=pool_callbacks,
                lease_registry=lease_registry,
                capability_receipt=capability_receipt,
                preacquired_leases=acquired,
                reservation_receipt=reservation_receipt,
                dispatch_receipt=dispatch_receipt,
                state_file=state_file,
                decision_file=decision_file,
                control_file=control_file,
                policy_document=policy_document,
            )
            terminal["pool_receipt"] = coordinator.run()

        dispatch = consume_pool_admission(
            admission_capability,
            reservation_receipt,
            dispatch_context,
            commit=commit,
        )
        return {
            "dispatch_receipt": dispatch,
            "pool_receipt": deepcopy(terminal["pool_receipt"]),
        }
    except BaseException:
        if not commit_invoked:
            try:
                lease_registry.release_uncommitted_many(contract, acquired)
            except PoolLeaseError as containment_error:
                raise NativePoolAdmissionError(
                    "admitted-launch-precommit-lease-containment-failed"
                ) from containment_error
        raise
