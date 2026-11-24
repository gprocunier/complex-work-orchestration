"""Protected embedding entry for the contained pool qualification campaign."""

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path

from cwo_core.beads import run_bd_structured
from cwo_core.invocation_ledger import InvocationLedger
from cwo_core.native_authority import canonical_authority_sha256, canonical_json_object
from cwo_core.native_pool_admission import (
    AdmissionCandidate, BeadsClaimAdapter, PoolAdmissionReservation, reserve_pool_cohort,
)
from cwo_core.native_pool_qualification_fixtures import POOL_QUALIFICATION_COHORT_SIZES
from cwo_core.native_pool_qualification_stage import CAMPAIGN_BUDGET_ID, CAMPAIGN_START_CAP
from cwo_core import native_pool_qualification_stage as stage
from cwo_core.private_artifact import PrivateDirectory
from registered_host_root_boundary import require_private_roots
from registered_pool_qualification import build_pool_qualification_runtime
from run_native_pool_qualification import (
    ProtectedPoolQualificationParent,
    QualificationControllerError,
    _require_source,
    _verify_directive,
    run_protected_pool_qualification,
)

ADMISSION_SCOPE = "cwo-contained-pool-qualification-disposable-claims-v1"


@dataclass(frozen=True, slots=True)
class PoolQualificationAdmission:
    """Original ready-set inputs for one enrolled disposable cohort."""

    candidate: AdmissionCandidate
    claim_adapter: BeadsClaimAdapter
    nonce: str
    live_revalidate: Callable[[Mapping], Mapping]


def _require(condition, reason):
    if not condition:
        raise QualificationControllerError(reason)


def _identity(directory):
    info = os.fstat(directory.descriptor)
    return [info.st_dev, info.st_ino]


def _claim_target(adapter):
    _require(type(adapter) is BeadsClaimAdapter and adapter._runner is run_bd_structured,
             "original-disposable-beads-adapter-required")
    database = Path(adapter.database)
    _require(database.is_absolute() and database.resolve() == database and database != adapter.directory
             and database.is_relative_to(adapter.directory), "disposable-beads-database-required")
    require_private_roots((adapter.directory,))
    with PrivateDirectory.open(adapter.directory) as directory:
        return {"directory": str(directory.path), "identity": _identity(directory),
                "database": str(database), "actor": adapter.actor, "timeout": adapter.timeout}


def _admission_binding(cohort):
    _require(type(cohort) is PoolQualificationAdmission and type(cohort.candidate) is AdmissionCandidate,
             "original-admission-inputs-required")
    _require(type(cohort.nonce) is str and cohort.nonce.strip() and callable(cohort.live_revalidate),
             "disposable-admission-nonce-and-revalidation-required")
    candidate = cohort.candidate
    return {"target": _claim_target(cohort.claim_adapter), "nonce": cohort.nonce,
            "candidate": canonical_json_object({
                "readiness_evidence": candidate.readiness_evidence, "work_estimates": candidate.work_estimates,
                "proportionality_assessment": candidate.proportionality_assessment,
                "child_bindings": candidate.child_bindings,
            })}


def _validate_roster(admissions, calibrations):
    _require(type(admissions) is tuple and type(calibrations) is tuple
             and 0 < len(admissions) + len(calibrations) <= CAMPAIGN_START_CAP,
             "disposable-admission-roster-required")
    items = admissions + calibrations
    _require(all(type(item) is PoolQualificationAdmission and type(item.candidate) is AdmissionCandidate
                 for item in items), "original-admission-inputs-required")
    repeats = len(admissions) // len(POOL_QUALIFICATION_COHORT_SIZES)
    sizes = tuple(len(item.candidate.child_bindings) for item in admissions)
    _require(repeats and sizes == tuple(size for size in POOL_QUALIFICATION_COHORT_SIZES for _ in range(repeats)),
             "disposable-admission-cohort-order-invalid")
    _require({len(item.candidate.child_bindings) for item in calibrations} == set(POOL_QUALIFICATION_COHORT_SIZES),
             "disposable-calibration-cohorts-required")


def _admission_action(request, admissions, calibrations, expiry):
    targets = [(row["target"]["database"], issue) for row in (*admissions, *calibrations)
               for issue in row["candidate"]["child_bindings"]]
    _require(len(set(targets)) == len(targets), "disposable-admission-cohort-reused")
    return canonical_authority_sha256({"scope": ADMISSION_SCOPE, "request": request,
                                       "campaign": CAMPAIGN_BUDGET_ID, "start_limit": CAMPAIGN_START_CAP,
                                       "expires_at": expiry, "admissions": list(admissions),
                                       "calibrations": list(calibrations)})


def _request_binding(request_path, directory):
    _require(request_path.is_absolute() and request_path.resolve() == request_path and request_path.name
             and not request_path.name.startswith("."), "owner-private-qualification-request-required")
    require_private_roots((directory.path,))
    return {"path": str(request_path), "identity": _identity(directory)}


def admission_action_sha256(request_path, admissions, calibration_admissions, *, expires_at):
    """Bind enrolled claim inputs before the protected controller can write Beads."""
    _validate_roster(admissions, calibration_admissions)
    with PrivateDirectory.open(request_path.parent) as directory:
        return _admission_action(_request_binding(request_path, directory),
                                 tuple(map(_admission_binding, admissions)),
                                 tuple(map(_admission_binding, calibration_admissions)), expires_at)


def _json_bytes(document):
    return json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True).encode("utf-8")


def _reserve(directory, prefix, cohort, binding, guard):
    target = binding["target"]
    adapter = cohort.claim_adapter
    claimed = set()

    def before_claim(actor, bead_id):
        guard()
        _require(_claim_target(adapter) == target and bead_id in binding["candidate"]["child_bindings"],
                 "approved-disposable-claim-target-changed")
        claimed.add(bead_id)
        directory.write(f"{prefix}.claim-{len(claimed)}.json",
                        _json_bytes({"disposition": "claim-intent", "target": target,
                                     "attempt_actor": actor, "bead_id": bead_id}))
        guard()

    guard()
    guarded = BeadsClaimAdapter(directory=target["directory"], database=target["database"], actor=target["actor"],
                                timeout=target["timeout"], before_claim=before_claim)
    reservation = reserve_pool_cohort(AdmissionCandidate(**binding["candidate"]), claim_adapter=guarded,
                                       admission_nonce=binding["nonce"],
                                       live_revalidate=cohort.live_revalidate)
    directory.write(f"{prefix}.reservation.json", _json_bytes(reservation.receipt))
    _require(reservation.admitted, "disposable-qualification-cohort-not-admitted")
    return reservation


def _reserve_selected(directory, parent, admissions, calibrations, directive, expires_at):
    selected = tuple(map(_admission_binding, admissions))
    measured = tuple(map(_admission_binding, calibrations))
    request = _request_binding(parent.request_path, directory)
    action = _admission_action(request, selected, measured, expires_at)

    def guard():
        _require_source()
        _verify_directive(parent, directive, action, expires_at)
        with PrivateDirectory.open(parent.request_path.parent) as current:
            _require(_request_binding(parent.request_path, current) == request, "protected-request-custody-changed")

    guard()
    ledger_root = stage.contained_campaign_ledger_root()
    with stage._campaign_custody(ledger_root):
        stage._require_campaign_budget(stage.PoolQualificationAccounting(InvocationLedger(ledger_root), expires_at),
                                       len(selected) + len(measured))
    reserved = tuple(_reserve(directory, f"{parent.request_path.name}.{index}", cohort, binding, guard)
                     for index, (cohort, binding) in enumerate(zip(admissions + calibrations, selected + measured), 1))
    return replace(parent, admissions=reserved[:len(admissions)], calibration_admissions=reserved[len(admissions):])


def run_registered_pool_qualification(request_path, *, verification_key, actor_id, identity_source, admissions,
                                      calibration_admissions, admission_directive, admission_expires_at,
                                      stage_approved_request):
    """Run one protected, signed campaign request through the registered factory.

    The enrolled host supplies the original admission inputs, a signed directive
    for the exact private disposable claim targets, and a staging callback.
    The callback receives receipt projections and returns the final owner-approved
    request after sealing the corresponding plans and authority files. The host
    retains the one-shot admissions in process throughout sizing, approval and
    qualification. Claim intent records and reservation receipts stay beside
    the request, including when a later step refuses.
    """
    _require_source()
    _validate_roster(admissions, calibration_admissions)
    _require(callable(stage_approved_request), "protected-request-staging-required")
    parent = ProtectedPoolQualificationParent(request_path, verification_key, actor_id, identity_source, (),
                                              build_pool_qualification_runtime)
    with PrivateDirectory.open(request_path.parent) as directory:
        _require(directory.contains(request_path.name) is False, "qualification-request-already-staged")
        _require(directory.contains(f"{request_path.name}.1.claim-1.json") is False,
                 "qualification-claim-custody-already-present")
        try:
            parent = _reserve_selected(directory, parent, admissions, calibration_admissions,
                                       deepcopy(admission_directive), admission_expires_at)
            request = stage_approved_request(_receipt_projections(parent.admissions),
                                             _receipt_projections(parent.calibration_admissions))
            directory.write(request_path.name, _json_bytes(request))
            return run_protected_pool_qualification(parent, include_pass_record=True)
        except BaseException as failure:
            for path in directory.published_paths:
                failure.add_note(f"Original qualification custody retained at {path}.")
            raise


def _receipt_projections(reservations: tuple[PoolAdmissionReservation, ...]) -> tuple[dict, ...]:
    return tuple(deepcopy(reservation.receipt) for reservation in reservations)
