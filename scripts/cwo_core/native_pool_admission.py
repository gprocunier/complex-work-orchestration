"""Fixed-cohort Beads admission for bounded native supervision pools.

P1-13A readiness and P1-3 proportionality artifacts are candidate evidence.
This module is the narrow boundary that turns them into claim-backed authority.
Serialized receipts remain evidence; only the exact, live, one-shot capability
returned by :func:`reserve_pool_cohort` can authorize one dispatch commit.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
from threading import Lock
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .beads import BdCommandResult, run_bd_structured
from .beads_ready_set import READY_SET_AUTHORITY, SNAPSHOT_TYPE, SNAPSHOT_VERSION
from .native_pool_proportionality import (
    ASSESSMENT_TYPE,
    ASSESSMENT_VERSION,
    PoolProportionalityError,
    pool_proportionality_check,
    validate_pool_proportionality_assessment,
)
from .native_recovery_authority import RecoveryAuthorityError, fixed_cohort_sha256
from .policy import load_policy
from .work_sizing import canonical_work_estimate_sha256


RESERVATION_TYPE = "cwo-native-pool-admission-reservation:v2"
DISPATCH_TYPE = "cwo-native-pool-admission-dispatch:v2"
ADMISSION_VERSION = 2
RESERVATION_SCHEMA = "schemas/native-pool-admission-reservation.schema.json"
DISPATCH_SCHEMA = "schemas/native-pool-admission-dispatch.schema.json"
RESERVATION_AUTHORITY = "reservation-evidence-only"
DISPATCH_AUTHORITY = "dispatch-evidence-only"
CLAIM_MUTABLE_FIELDS = frozenset({"status", "assignee", "updated_at", "started_at"})
CLAIM_OUTCOMES = frozenset(
    {
        "claimed",
        "claimed-after-timeout",
        "claimed-after-command-error",
        "claim-lost",
        "claim-show-failed",
        "preowned-replay",
    }
)

CHILD_BINDING_FIELDS = frozenset(
    {
        "bead_id",
        "work_unit_id",
        "child_id",
        "packet_id",
        "packet_sha256",
        "candidate_sha256",
        "work_estimate_sha256",
        "worker_commitment_sha256",
        "lease_scope_sha256",
        "worktree_identity_sha256",
        "hard_budget",
        "requested_model",
        "admitted_child_sha256",
    }
)
CLAIM_FIELDS = frozenset(
    {
        "bead_id",
        "actor",
        "outcome",
        "pre_show_sha256",
        "post_show_sha256",
        "command_sha256",
        "command_returncode",
        "command_timed_out",
        "owned",
        "claim_sha256",
    }
)
RESERVATION_FIELDS_V2 = frozenset(
    {
        "reservation_type",
        "version",
        "schema",
        "reservation_id",
        "admission_nonce",
        "created_at",
        "claim_actor",
        "readiness_snapshot_sha256",
        "readiness_evidence_sha256",
        "work_estimate_set_sha256",
        "native_worker_policy_sha256",
        "proportionality_policy_sha256",
        "proportionality_assessment_sha256",
        "selected_cohort_sha256",
        "candidate_mode",
        "issue_ids",
        "child_bindings",
        "claims",
        "child_bindings_sha256",
        "claim_set_sha256",
        "retained_owned_issue_ids",
        "recompute_count",
        "status",
        "fixed_cohort_sha256",
        "authority",
        "dispatch_authorized",
        "reservation_sha256",
    }
)
DISPATCH_CONTEXT_FIELDS_V2 = frozenset(
    {
        "reservation_sha256",
        "fixed_cohort_sha256",
        "pool_contract_sha256",
        "preflight_request_sha256",
        "preflight_result_sha256",
        "lease_set_sha256",
        "child_bindings_sha256",
        "live_revalidation_sha256",
    }
)
DISPATCH_FIELDS_V2 = frozenset(
    {
        "dispatch_type",
        "version",
        "schema",
        "dispatch_id",
        "consumed_at",
        *DISPATCH_CONTEXT_FIELDS_V2,
        "authority",
        "dispatch_authorized",
        "dispatch_sha256",
    }
)

# Public aliases retain the initial P1-13B import surface while making the
# version boundary explicit for the v2-only admission authority.
RESERVATION_FIELDS = RESERVATION_FIELDS_V2
DISPATCH_CONTEXT_FIELDS = DISPATCH_CONTEXT_FIELDS_V2
DISPATCH_FIELDS = DISPATCH_FIELDS_V2


class NativePoolAdmissionError(ValueError):
    """Fail-closed admission error with stable evidence-safe messages."""


def canonical_admission_sha256(value: Any) -> str:
    """Hash exact canonical JSON and reject projections that cannot round-trip."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativePoolAdmissionError("admission-value-not-canonical-json") from exc
    return hashlib.sha256(encoded).hexdigest()


def _sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonempty(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _iso(value: dt.datetime | str | None = None) -> str:
    if value is None:
        parsed = dt.datetime.now(dt.timezone.utc)
    elif type(value) is str:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NativePoolAdmissionError("admission-time-invalid") from exc
    elif type(value) is dt.datetime:
        parsed = value
    else:
        raise NativePoolAdmissionError("admission-time-invalid")
    if parsed.tzinfo is None:
        raise NativePoolAdmissionError("admission-time-must-be-aware")
    return (
        parsed.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop(field, None)
    result[field] = canonical_admission_sha256(result)
    return result


def _strict(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise NativePoolAdmissionError(f"{label}-must-be-exact-dict")
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing:
        raise NativePoolAdmissionError(f"{label}-missing-fields:" + ",".join(missing))
    if unknown:
        raise NativePoolAdmissionError(f"{label}-unknown-fields:" + ",".join(unknown))
    return dict(value)


def _verify_seal(value: Mapping[str, Any], field: str, label: str) -> None:
    observed = value.get(field)
    unsigned = dict(value)
    unsigned.pop(field, None)
    if not _sha256(observed) or observed != canonical_admission_sha256(unsigned):
        raise NativePoolAdmissionError(f"{label}-sha256-mismatch")


@dataclass(frozen=True, slots=True)
class AdmissionCandidate:
    readiness_evidence: Mapping[str, Any]
    work_estimates: Mapping[str, Mapping[str, Any]]
    proportionality_assessment: Mapping[str, Any]
    child_bindings: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class ClaimTransition:
    receipt: Mapping[str, Any]
    post_issue: Mapping[str, Any] | None

    @property
    def owned(self) -> bool:
        return self.receipt.get("owned") is True


class ClaimAdapter(Protocol):
    actor: str

    def show_exact(self, bead_id: str) -> Mapping[str, Any]: ...

    def claim(self, bead_id: str) -> ClaimTransition: ...


class BeadsClaimAdapter:
    """Per-issue compare-and-set claim adapter with exact-show reconciliation."""

    def __init__(
        self,
        *,
        directory: Path | str,
        database: Path | str,
        actor: str,
        timeout: int | None = None,
        runner: Callable[..., BdCommandResult] = run_bd_structured,
    ) -> None:
        self.directory = Path(directory).absolute()
        self.database = str(database).strip()
        self.actor = str(actor).strip()
        self.timeout = timeout
        self._runner = runner
        if not self.directory.is_dir():
            raise NativePoolAdmissionError("claim-directory-must-exist")
        if not self.database:
            raise NativePoolAdmissionError("claim-database-must-be-explicit")
        if not self.actor:
            raise NativePoolAdmissionError("claim-actor-must-be-explicit")

    def _run(self, args: Sequence[str]) -> BdCommandResult:
        result = self._runner(
            tuple(args),
            directory=self.directory,
            database=self.database,
            actor=self.actor,
            timeout=self.timeout,
        )
        if type(result) is not BdCommandResult:
            raise NativePoolAdmissionError("claim-runner-result-type-invalid")
        return result

    @staticmethod
    def _decode_show(result: BdCommandResult, bead_id: str) -> dict[str, Any]:
        if not result.succeeded:
            raise NativePoolAdmissionError(f"exact-show-failed:{bead_id}")
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise NativePoolAdmissionError(
                f"exact-show-json-invalid:{bead_id}"
            ) from exc
        if type(decoded) is list:
            if len(decoded) != 1 or type(decoded[0]) is not dict:
                raise NativePoolAdmissionError(
                    f"exact-show-cardinality-invalid:{bead_id}"
                )
            issue = dict(decoded[0])
        elif type(decoded) is dict:
            issue = dict(decoded)
        else:
            raise NativePoolAdmissionError(f"exact-show-shape-invalid:{bead_id}")
        if issue.get("id") != bead_id:
            raise NativePoolAdmissionError(f"exact-show-id-mismatch:{bead_id}")
        return issue

    def show_exact(self, bead_id: str) -> Mapping[str, Any]:
        issue_id = str(bead_id).strip()
        if not issue_id:
            raise NativePoolAdmissionError("claim-bead-id-empty")
        return self._decode_show(
            self._run(("show", issue_id, "--json")),
            issue_id,
        )

    def claim(self, bead_id: str) -> ClaimTransition:
        issue_id = str(bead_id).strip()
        pre = dict(self.show_exact(issue_id))
        pre_hash = canonical_admission_sha256(pre)
        pre_assignee = pre.get("assignee")
        if pre.get("status") != "open" or pre_assignee not in (None, ""):
            receipt = _claim_receipt(
                issue_id,
                actor=self.actor,
                outcome="preowned-replay",
                pre_show_sha256=pre_hash,
                post_show_sha256=pre_hash,
                result=None,
                owned=False,
            )
            return ClaimTransition(receipt=receipt, post_issue=pre)

        result = self._run(("update", issue_id, "--claim", "--json"))
        try:
            post = dict(self.show_exact(issue_id))
        except NativePoolAdmissionError:
            receipt = _claim_receipt(
                issue_id,
                actor=self.actor,
                outcome="claim-show-failed",
                pre_show_sha256=pre_hash,
                post_show_sha256=None,
                result=result,
                owned=False,
            )
            return ClaimTransition(receipt=receipt, post_issue=None)

        post_hash = canonical_admission_sha256(post)
        owned = _is_exact_claim_transition(pre, post, actor=self.actor)
        if owned and _claim_immutable_projection(pre) != _claim_immutable_projection(
            post
        ):
            owned = False
        if owned and result.timed_out:
            outcome = "claimed-after-timeout"
        elif owned and result.returncode != 0:
            outcome = "claimed-after-command-error"
        elif owned:
            outcome = "claimed"
        else:
            outcome = "claim-lost"
        receipt = _claim_receipt(
            issue_id,
            actor=self.actor,
            outcome=outcome,
            pre_show_sha256=pre_hash,
            post_show_sha256=post_hash,
            result=result,
            owned=owned,
        )
        return ClaimTransition(receipt=receipt, post_issue=post)


def _claim_immutable_projection(issue: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in issue.items() if key not in CLAIM_MUTABLE_FIELDS
    }


def _is_exact_claim_transition(
    pre: Mapping[str, Any], post: Mapping[str, Any], *, actor: str
) -> bool:
    """Accept only the documented CAS delta, including Beads ``started_at``."""

    return (
        pre.get("status") == "open"
        and pre.get("assignee") in (None, "")
        and pre.get("started_at") in (None, "")
        and post.get("status") == "in_progress"
        and post.get("assignee") == actor
        and _nonempty(post.get("started_at"))
        and _claim_immutable_projection(pre) == _claim_immutable_projection(post)
    )


def _claim_receipt(
    bead_id: str,
    *,
    actor: str,
    outcome: str,
    pre_show_sha256: str,
    post_show_sha256: str | None,
    result: BdCommandResult | None,
    owned: bool,
) -> dict[str, Any]:
    command_sha256 = (
        canonical_admission_sha256(list(result.command)) if result else None
    )
    return _seal(
        {
            "bead_id": bead_id,
            "actor": actor,
            "outcome": outcome,
            "pre_show_sha256": pre_show_sha256,
            "post_show_sha256": post_show_sha256,
            "command_sha256": command_sha256,
            "command_returncode": result.returncode if result else None,
            "command_timed_out": result.timed_out if result else False,
            "owned": owned,
        },
        "claim_sha256",
    )


def validate_claim_receipt(value: Any) -> list[str]:
    try:
        receipt = _strict(value, CLAIM_FIELDS, "claim")
        if not _nonempty(receipt.get("bead_id")) or not _nonempty(receipt.get("actor")):
            raise NativePoolAdmissionError("claim-identity-invalid")
        if receipt.get("outcome") not in CLAIM_OUTCOMES:
            raise NativePoolAdmissionError("claim-outcome-invalid")
        if not _sha256(receipt.get("pre_show_sha256")):
            raise NativePoolAdmissionError("claim-pre-show-sha256-invalid")
        post_hash = receipt.get("post_show_sha256")
        if post_hash is not None and not _sha256(post_hash):
            raise NativePoolAdmissionError("claim-post-show-sha256-invalid")
        command_hash = receipt.get("command_sha256")
        if command_hash is not None and not _sha256(command_hash):
            raise NativePoolAdmissionError("claim-command-sha256-invalid")
        if (
            type(receipt.get("command_timed_out")) is not bool
            or type(receipt.get("owned")) is not bool
        ):
            raise NativePoolAdmissionError("claim-state-invalid")
        if receipt["owned"] is not (receipt["outcome"].startswith("claimed")):
            raise NativePoolAdmissionError("claim-owned-outcome-mismatch")
        if receipt["owned"] is True and post_hash is None:
            raise NativePoolAdmissionError("claim-owned-post-show-sha256-missing")
        _verify_seal(receipt, "claim_sha256", "claim")
    except NativePoolAdmissionError as exc:
        return [str(exc)]
    return []


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    readiness = dict(value)
    if (
        readiness.get("ready_set_authority") != READY_SET_AUTHORITY
        or readiness.get("dispatch_authorized") is not False
    ):
        raise NativePoolAdmissionError("readiness-authority-invalid")
    snapshot = readiness.get("beads_readiness_snapshot")
    if type(snapshot) is not dict:
        raise NativePoolAdmissionError("readiness-snapshot-must-be-exact-dict")
    result = dict(snapshot)
    if (
        result.get("snapshot_type") != SNAPSHOT_TYPE
        or result.get("version") != SNAPSHOT_VERSION
    ):
        raise NativePoolAdmissionError("readiness-snapshot-header-invalid")
    observed = result.get("snapshot_sha256")
    unsigned = dict(result)
    unsigned.pop("snapshot_sha256", None)
    if not _sha256(observed) or observed != canonical_admission_sha256(unsigned):
        raise NativePoolAdmissionError("readiness-snapshot-sha256-mismatch")
    if readiness.get("beads_readiness_snapshot_sha256") != observed:
        raise NativePoolAdmissionError("readiness-top-level-snapshot-sha256-mismatch")
    return result


def _projections(snapshot: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = snapshot.get("issue_projections")
    if type(raw) is not list:
        raise NativePoolAdmissionError("readiness-issue-projections-invalid")
    result: dict[str, dict[str, Any]] = {}
    for item in raw:
        if type(item) is not dict or not _nonempty(item.get("id")):
            raise NativePoolAdmissionError("readiness-issue-projection-invalid")
        issue_id = item["id"]
        if issue_id in result:
            raise NativePoolAdmissionError("readiness-issue-projection-duplicate")
        observed = item.get("issue_projection_sha256")
        unsigned = dict(item)
        unsigned.pop("issue_projection_sha256", None)
        if not _sha256(observed) or observed != canonical_admission_sha256(unsigned):
            raise NativePoolAdmissionError(
                f"readiness-issue-projection-sha256-mismatch:{issue_id}"
            )
        result[issue_id] = dict(item)
    return result


def build_admission_child_binding(
    readiness_evidence: Mapping[str, Any],
    work_estimate: Mapping[str, Any],
    *,
    bead_id: str,
    child_id: str,
    packet_id: str,
    packet_sha256: str,
    worktree_identity_sha256: str,
) -> dict[str, Any]:
    """Derive one child binding from the validated Bead projection and estimate."""

    snapshot = _snapshot(readiness_evidence)
    projection = _projections(snapshot).get(bead_id)
    if projection is None:
        raise NativePoolAdmissionError("child-binding-bead-not-in-snapshot")
    artifacts = projection.get("candidate_artifacts")
    if type(artifacts) is not dict:
        raise NativePoolAdmissionError("child-binding-candidate-artifacts-missing")
    estimate = dict(work_estimate)
    if estimate.get("bead_id") != bead_id:
        raise NativePoolAdmissionError("child-binding-work-estimate-bead-mismatch")
    work_unit_id = estimate.get("work_unit_id")
    if not _nonempty(work_unit_id):
        raise NativePoolAdmissionError("child-binding-work-unit-id-invalid")
    estimate_hash = canonical_work_estimate_sha256(estimate)
    if artifacts.get("work_estimate_sha256") != estimate_hash:
        raise NativePoolAdmissionError("child-binding-work-estimate-sha256-mismatch")
    allowance = estimate.get("aggregate_allowance")
    requested_model = estimate.get("requested_model")
    if type(allowance) is not dict:
        raise NativePoolAdmissionError("child-binding-work-budget-missing")
    hard_budget = {
        "tool_calls": allowance.get("tool_calls_hard"),
        "runtime_seconds": allowance.get("runtime_seconds_hard"),
        "compactions": allowance.get("max_compactions"),
    }
    if (
        any(type(item) is not int or item < 0 for item in hard_budget.values())
        or hard_budget["tool_calls"] < 1
        or hard_budget["runtime_seconds"] < 1
    ):
        raise NativePoolAdmissionError("child-binding-work-budget-invalid")
    if not _nonempty(requested_model):
        raise NativePoolAdmissionError("child-binding-requested-model-invalid")
    for label, value in (
        ("child-id", child_id),
        ("packet-id", packet_id),
    ):
        if not _nonempty(value):
            raise NativePoolAdmissionError(f"child-binding-{label}-invalid")
    for label, value in (
        ("packet-sha256", packet_sha256),
        ("worktree-identity-sha256", worktree_identity_sha256),
        ("candidate-sha256", artifacts.get("candidate_sha256")),
        ("worker-commitment-sha256", artifacts.get("worker_commitment_sha256")),
        ("lease-scope-sha256", artifacts.get("lease_scope_sha256")),
    ):
        if not _sha256(value):
            raise NativePoolAdmissionError(f"child-binding-{label}-invalid")
    return _seal(
        {
            "bead_id": bead_id,
            "work_unit_id": work_unit_id,
            "child_id": child_id,
            "packet_id": packet_id,
            "packet_sha256": packet_sha256,
            "candidate_sha256": artifacts["candidate_sha256"],
            "work_estimate_sha256": estimate_hash,
            "worker_commitment_sha256": artifacts["worker_commitment_sha256"],
            "lease_scope_sha256": artifacts["lease_scope_sha256"],
            "worktree_identity_sha256": worktree_identity_sha256,
            "hard_budget": hard_budget,
            "requested_model": requested_model,
        },
        "admitted_child_sha256",
    )


def validate_admission_child_binding(
    value: Any,
    *,
    bead_id: str | None = None,
    projection: Mapping[str, Any] | None = None,
    work_estimate: Mapping[str, Any] | None = None,
) -> list[str]:
    try:
        binding = _strict(value, CHILD_BINDING_FIELDS, "child-binding")
        for field in (
            "bead_id",
            "work_unit_id",
            "child_id",
            "packet_id",
            "requested_model",
        ):
            if not _nonempty(binding.get(field)):
                raise NativePoolAdmissionError(
                    f"child-binding-{field.replace('_', '-')}-invalid"
                )
        for field in CHILD_BINDING_FIELDS - {
            "bead_id",
            "work_unit_id",
            "child_id",
            "packet_id",
            "hard_budget",
            "requested_model",
        }:
            if not _sha256(binding.get(field)):
                raise NativePoolAdmissionError(
                    f"child-binding-{field.replace('_', '-')}-invalid"
                )
        _verify_seal(binding, "admitted_child_sha256", "child-binding")
        budget = _strict(
            binding.get("hard_budget"),
            frozenset({"tool_calls", "runtime_seconds", "compactions"}),
            "child-binding-hard-budget",
        )
        if (
            any(type(item) is not int or item < 0 for item in budget.values())
            or budget["tool_calls"] < 1
            or budget["runtime_seconds"] < 1
        ):
            raise NativePoolAdmissionError("child-binding-hard-budget-invalid")
        if bead_id is not None and binding["bead_id"] != bead_id:
            raise NativePoolAdmissionError("child-binding-bead-mismatch")
        if projection is not None:
            artifacts = projection.get("candidate_artifacts")
            if type(artifacts) is not dict:
                raise NativePoolAdmissionError(
                    "child-binding-candidate-artifacts-missing"
                )
            for field in (
                "candidate_sha256",
                "work_estimate_sha256",
                "worker_commitment_sha256",
                "lease_scope_sha256",
            ):
                if binding[field] != artifacts.get(field):
                    raise NativePoolAdmissionError(
                        f"child-binding-{field.replace('_', '-')}-mismatch"
                    )
        if work_estimate is not None:
            estimate = dict(work_estimate)
            if estimate.get("bead_id") != binding["bead_id"]:
                raise NativePoolAdmissionError("child-binding-estimate-bead-mismatch")
            if estimate.get("work_unit_id") != binding["work_unit_id"]:
                raise NativePoolAdmissionError("child-binding-work-unit-mismatch")
            if (
                canonical_work_estimate_sha256(estimate)
                != binding["work_estimate_sha256"]
            ):
                raise NativePoolAdmissionError("child-binding-estimate-sha256-mismatch")
            allowance = estimate.get("aggregate_allowance")
            if type(allowance) is not dict:
                raise NativePoolAdmissionError("child-binding-estimate-budget-missing")
            expected_budget = {
                "tool_calls": allowance.get("tool_calls_hard"),
                "runtime_seconds": allowance.get("runtime_seconds_hard"),
                "compactions": allowance.get("max_compactions"),
            }
            if binding["hard_budget"] != expected_budget:
                raise NativePoolAdmissionError("child-binding-hard-budget-mismatch")
            if binding["requested_model"] != estimate.get("requested_model"):
                raise NativePoolAdmissionError("child-binding-requested-model-mismatch")
    except (NativePoolAdmissionError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


@dataclass(frozen=True, slots=True)
class _ValidatedCandidate:
    source: AdmissionCandidate
    snapshot: Mapping[str, Any]
    projections: Mapping[str, Mapping[str, Any]]
    issue_ids: tuple[str, ...]
    selected_cohort_sha256: str
    candidate_mode: str
    fixed_cohort_sha256: str
    normalized_bindings: tuple[Mapping[str, Any], ...]


def _cohort_for_candidate(
    readiness: Mapping[str, Any], assessment: Mapping[str, Any]
) -> tuple[list[str], str, str]:
    selected = assessment.get("selected_cohort")
    if type(selected) is dict:
        issue_ids = selected.get("issue_ids")
        cohort_hash = selected.get("cohort_sha256")
        mode = assessment.get("candidate_mode")
    elif assessment.get("decision") == "single" and _nonempty(
        assessment.get("fallback_issue_id")
    ):
        fallback = assessment["fallback_issue_id"]
        matching = [
            item
            for item in readiness.get("compatible_ready_sets", [])
            if type(item) is dict and item.get("issue_ids") == [fallback]
        ]
        if len(matching) != 1:
            raise NativePoolAdmissionError("single-candidate-cohort-missing")
        issue_ids = [fallback]
        cohort_hash = matching[0].get("cohort_sha256")
        mode = "single"
    else:
        raise NativePoolAdmissionError("proportionality-assessment-has-no-candidate")
    if (
        type(issue_ids) is not list
        or not issue_ids
        or any(not _nonempty(issue_id) for issue_id in issue_ids)
    ):
        raise NativePoolAdmissionError("selected-cohort-issue-ids-invalid")
    if len(issue_ids) != len(set(issue_ids)):
        raise NativePoolAdmissionError("selected-cohort-issue-ids-duplicate")
    if not _sha256(cohort_hash):
        raise NativePoolAdmissionError("selected-cohort-sha256-invalid")
    matching = [
        item
        for item in readiness.get("compatible_ready_sets", [])
        if type(item) is dict and item.get("cohort_sha256") == cohort_hash
    ]
    if len(matching) != 1 or matching[0].get("issue_ids") != issue_ids:
        raise NativePoolAdmissionError("selected-cohort-readiness-binding-mismatch")
    if mode not in {"single", "released-capacity", "offline-unreleased-candidate"}:
        raise NativePoolAdmissionError("selected-cohort-candidate-mode-invalid")
    return list(issue_ids), cohort_hash, str(mode)


def _validate_candidate(
    candidate: AdmissionCandidate,
    *,
    policy_document: Mapping[str, Any] | None,
) -> _ValidatedCandidate:
    if type(candidate) is not AdmissionCandidate:
        raise NativePoolAdmissionError("admission-candidate-type-invalid")
    readiness = deepcopy(dict(candidate.readiness_evidence))
    estimates = deepcopy(dict(candidate.work_estimates))
    assessment = deepcopy(dict(candidate.proportionality_assessment))
    bindings = deepcopy(dict(candidate.child_bindings))
    snapshot = _snapshot(readiness)
    projections = _projections(snapshot)

    assessment_errors = validate_pool_proportionality_assessment(
        assessment,
        policy_document=policy_document,
    )
    if assessment_errors:
        raise NativePoolAdmissionError(
            "proportionality-assessment-invalid:" + ";".join(assessment_errors)
        )
    if (
        assessment.get("assessment_type") != ASSESSMENT_TYPE
        or assessment.get("version") != ASSESSMENT_VERSION
        or assessment.get("authority") != READY_SET_AUTHORITY
        or assessment.get("dispatch_authorized") is not False
    ):
        raise NativePoolAdmissionError("proportionality-assessment-header-invalid")
    if assessment.get("readiness_snapshot_sha256") != snapshot["snapshot_sha256"]:
        raise NativePoolAdmissionError("assessment-readiness-snapshot-mismatch")
    if assessment.get("readiness_evidence_sha256") != canonical_admission_sha256(
        readiness
    ):
        raise NativePoolAdmissionError("assessment-readiness-evidence-mismatch")
    compatible = readiness.get("compatible_ready_sets")
    if type(compatible) is not list:
        raise NativePoolAdmissionError("readiness-compatible-cohorts-invalid")
    required_estimate_ids = {
        issue_id
        for cohort in compatible
        if type(cohort) is dict and type(cohort.get("issue_ids")) is list
        for issue_id in cohort["issue_ids"]
    }
    if set(estimates) != required_estimate_ids:
        raise NativePoolAdmissionError("work-estimate-set-mismatch")
    estimate_bindings: list[dict[str, str]] = []
    for issue_id in sorted(required_estimate_ids):
        estimate = estimates.get(issue_id)
        projection = projections.get(issue_id)
        artifacts = projection.get("candidate_artifacts") if projection else None
        if type(estimate) is not dict or type(artifacts) is not dict:
            raise NativePoolAdmissionError(f"work-estimate-binding-missing:{issue_id}")
        estimate_hash = canonical_work_estimate_sha256(estimate)
        if (
            estimate.get("bead_id") != issue_id
            or artifacts.get("work_estimate_sha256") != estimate_hash
        ):
            raise NativePoolAdmissionError(f"work-estimate-binding-mismatch:{issue_id}")
        estimate_bindings.append(
            {"id": issue_id, "work_estimate_sha256": estimate_hash}
        )
    if assessment.get("work_estimate_set_sha256") != canonical_admission_sha256(
        estimate_bindings
    ):
        raise NativePoolAdmissionError("assessment-work-estimate-set-mismatch")

    document = (
        dict(policy_document)
        if policy_document is not None
        else load_policy("native-worker-execution")
    )
    if assessment.get("override_authorization") is None:
        try:
            recomputed = pool_proportionality_check(
                readiness,
                estimates,
                requested_workers=assessment["requested_workers"],
                measured_fixed_overhead_ms=assessment["measured_fixed_overhead_ms"],
                policy_document=document,
            )
        except (PoolProportionalityError, KeyError, TypeError, ValueError) as exc:
            raise NativePoolAdmissionError(
                "proportionality-assessment-recompute-failed"
            ) from exc
        if recomputed != assessment:
            raise NativePoolAdmissionError(
                "proportionality-assessment-recompute-mismatch"
            )

    issue_ids, cohort_hash, candidate_mode = _cohort_for_candidate(
        readiness, assessment
    )
    if len(issue_ids) >= 4:
        raise NativePoolAdmissionError("cohort-size-four-or-more-forbidden")
    if set(bindings) != set(issue_ids):
        raise NativePoolAdmissionError("child-binding-set-mismatch")
    normalized: list[Mapping[str, Any]] = []
    child_ids: set[str] = set()
    packet_ids: set[str] = set()
    work_unit_ids: set[str] = set()
    for issue_id in issue_ids:
        projection = projections.get(issue_id)
        estimate = estimates.get(issue_id)
        if projection is None or type(estimate) is not dict:
            raise NativePoolAdmissionError(f"selected-cohort-input-missing:{issue_id}")
        errors = validate_admission_child_binding(
            bindings[issue_id],
            bead_id=issue_id,
            projection=projection,
            work_estimate=estimate,
        )
        if errors:
            raise NativePoolAdmissionError(
                f"child-binding-invalid:{issue_id}:" + ";".join(errors)
            )
        binding = dict(bindings[issue_id])
        if binding["child_id"] in child_ids:
            raise NativePoolAdmissionError("child-binding-child-id-duplicate")
        if binding["packet_id"] in packet_ids:
            raise NativePoolAdmissionError("child-binding-packet-id-duplicate")
        if binding["work_unit_id"] in work_unit_ids:
            raise NativePoolAdmissionError("child-binding-work-unit-id-duplicate")
        child_ids.add(binding["child_id"])
        packet_ids.add(binding["packet_id"])
        work_unit_ids.add(binding["work_unit_id"])
        normalized.append(binding)
    fixed_items = [
        {
            "bead_id": binding["bead_id"],
            "work_unit_id": binding["work_unit_id"],
            "admitted_child_sha256": binding["admitted_child_sha256"],
        }
        for binding in normalized
    ]
    try:
        cohort_identity = fixed_cohort_sha256(fixed_items)
    except RecoveryAuthorityError as exc:
        raise NativePoolAdmissionError("fixed-cohort-invalid") from exc
    frozen = AdmissionCandidate(readiness, estimates, assessment, bindings)
    return _ValidatedCandidate(
        source=frozen,
        snapshot=snapshot,
        projections=projections,
        issue_ids=tuple(issue_ids),
        selected_cohort_sha256=cohort_hash,
        candidate_mode=candidate_mode,
        fixed_cohort_sha256=cohort_identity,
        normalized_bindings=tuple(normalized),
    )


_CAPABILITY_TOKEN = object()


class FixedCohortAdmissionCapability:
    """Exact-type, nonserializable authority for one fixed-cohort commit."""

    __slots__ = (
        "_reservation_sha256",
        "_fixed_cohort_sha256",
        "_child_bindings_sha256",
        "_state",
        "_lock",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("fixed-cohort-admission-capability-subclass-forbidden")

    def __init__(
        self,
        *,
        reservation_sha256: str,
        fixed_cohort_sha256_value: str,
        child_bindings_sha256: str,
        token: object,
    ) -> None:
        if token is not _CAPABILITY_TOKEN:
            raise NativePoolAdmissionError(
                "fixed-cohort-admission-capability-construction-forbidden"
            )
        self._reservation_sha256 = reservation_sha256
        self._fixed_cohort_sha256 = fixed_cohort_sha256_value
        self._child_bindings_sha256 = child_bindings_sha256
        self._state = "available"
        self._lock = Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def __copy__(self) -> None:
        raise TypeError("fixed-cohort-admission-capability-copy-forbidden")

    def __deepcopy__(self, memo: Any) -> None:
        del memo
        raise TypeError("fixed-cohort-admission-capability-copy-forbidden")

    def __reduce__(self) -> None:
        raise TypeError("fixed-cohort-admission-capability-serialization-forbidden")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("fixed-cohort-admission-capability-serialization-forbidden")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(state={self.state!r})"


@dataclass(frozen=True, slots=True)
class PoolAdmissionReservation:
    receipt: Mapping[str, Any]
    capability: FixedCohortAdmissionCapability | None

    @property
    def admitted(self) -> bool:
        return self.receipt.get("status") == "admitted" and self.capability is not None


RebuildCallback = Callable[
    [AdmissionCandidate, frozenset[str], str], AdmissionCandidate | None
]
LiveRevalidationCallback = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _exact_preclaim_show(
    validated: _ValidatedCandidate,
    adapter: ClaimAdapter,
    issue_id: str,
) -> None:
    issue = dict(adapter.show_exact(issue_id))
    projection = validated.projections[issue_id]
    if canonical_admission_sha256(issue) != projection.get("exact_show_raw_sha256"):
        raise NativePoolAdmissionError(f"preclaim-exact-show-drift:{issue_id}")
    if issue.get("status") != "open" or issue.get("assignee") not in (None, ""):
        raise NativePoolAdmissionError(f"preclaim-issue-not-unassigned-open:{issue_id}")


def _live_revalidate_claimed_cohort(
    validated: _ValidatedCandidate,
    *,
    adapter: ClaimAdapter,
    claims: Sequence[Mapping[str, Any]],
    live_revalidate: LiveRevalidationCallback,
) -> None:
    owned_by_id = {
        str(claim["bead_id"]): claim for claim in claims if claim.get("owned") is True
    }
    for binding in validated.normalized_bindings:
        issue_id = str(binding["bead_id"])
        claim = owned_by_id.get(issue_id)
        if claim is None:
            raise NativePoolAdmissionError(
                f"live-revalidation-claim-missing:{issue_id}"
            )
        current = dict(adapter.show_exact(issue_id))
        if (
            current.get("status") != "in_progress"
            or current.get("assignee") != adapter.actor
            or canonical_admission_sha256(current) != claim.get("post_show_sha256")
        ):
            raise NativePoolAdmissionError(f"live-revalidation-claim-drift:{issue_id}")
        observed = live_revalidate(deepcopy(dict(binding)))
        if type(observed) is not dict or observed != dict(binding):
            raise NativePoolAdmissionError(
                f"live-revalidation-binding-drift:{issue_id}"
            )


def _reservation_receipt(
    validated: _ValidatedCandidate,
    *,
    admission_nonce: str,
    claim_actor: str,
    claims: Sequence[Mapping[str, Any]],
    retained_owned: Sequence[str],
    recompute_count: int,
    status: str,
    created_at: str,
) -> dict[str, Any]:
    assessment = validated.source.proportionality_assessment
    child_bindings = [dict(item) for item in validated.normalized_bindings]
    claim_receipts = [dict(item) for item in claims]
    reservation_seed = {
        "admission_nonce": admission_nonce,
        "claim_actor": claim_actor,
        "assessment_sha256": assessment["assessment_sha256"],
        "fixed_cohort_sha256": validated.fixed_cohort_sha256,
    }
    reservation_id = canonical_admission_sha256(reservation_seed)
    return _seal(
        {
            "reservation_type": RESERVATION_TYPE,
            "version": ADMISSION_VERSION,
            "schema": RESERVATION_SCHEMA,
            "reservation_id": reservation_id,
            "admission_nonce": admission_nonce,
            "created_at": created_at,
            "claim_actor": claim_actor,
            "readiness_snapshot_sha256": validated.snapshot["snapshot_sha256"],
            "readiness_evidence_sha256": assessment["readiness_evidence_sha256"],
            "work_estimate_set_sha256": assessment["work_estimate_set_sha256"],
            "native_worker_policy_sha256": assessment["native_worker_policy_sha256"],
            "proportionality_policy_sha256": assessment[
                "proportionality_policy_sha256"
            ],
            "proportionality_assessment_sha256": assessment["assessment_sha256"],
            "selected_cohort_sha256": validated.selected_cohort_sha256,
            "candidate_mode": validated.candidate_mode,
            "issue_ids": list(validated.issue_ids),
            "child_bindings": child_bindings,
            "claims": claim_receipts,
            "child_bindings_sha256": canonical_admission_sha256(child_bindings),
            "claim_set_sha256": canonical_admission_sha256(claim_receipts),
            "retained_owned_issue_ids": sorted(set(retained_owned)),
            "recompute_count": recompute_count,
            "status": status,
            "fixed_cohort_sha256": validated.fixed_cohort_sha256,
            "authority": RESERVATION_AUTHORITY,
            "dispatch_authorized": False,
        },
        "reservation_sha256",
    )


def reserve_pool_cohort(
    candidate: AdmissionCandidate,
    *,
    claim_adapter: ClaimAdapter,
    admission_nonce: str,
    live_revalidate: LiveRevalidationCallback,
    rebuild: RebuildCallback | None = None,
    policy_document: Mapping[str, Any] | None = None,
    productive: bool = True,
    now: dt.datetime | str | None = None,
) -> PoolAdmissionReservation:
    """Claim one fixed cohort, stopping at first loss and rebuilding at most once."""

    if type(candidate) is not AdmissionCandidate:
        raise NativePoolAdmissionError("admission-candidate-type-invalid")
    if not _nonempty(admission_nonce):
        raise NativePoolAdmissionError("admission-nonce-required")
    if not callable(live_revalidate):
        raise NativePoolAdmissionError("live-revalidation-callback-required")
    if rebuild is not None and not callable(rebuild):
        raise NativePoolAdmissionError("rebuild-callback-invalid")
    actor = getattr(claim_adapter, "actor", None)
    if not _nonempty(actor):
        raise NativePoolAdmissionError("claim-adapter-actor-invalid")

    raw_selected = candidate.proportionality_assessment.get("selected_cohort")
    raw_issue_ids = (
        raw_selected.get("issue_ids") if isinstance(raw_selected, Mapping) else None
    )
    if isinstance(raw_issue_ids, list) and len(raw_issue_ids) >= 4:
        raise NativePoolAdmissionError("cohort-size-four-or-more-forbidden")

    validated = _validate_candidate(candidate, policy_document=policy_document)
    if len(validated.issue_ids) >= 4:
        raise NativePoolAdmissionError("cohort-size-four-or-more-forbidden")
    if productive and len(validated.issue_ids) == 3:
        raise NativePoolAdmissionError("productive-cohort-size-three-unreleased")
    created_at = _iso(now)
    if not productive:
        receipt = _reservation_receipt(
            validated,
            admission_nonce=admission_nonce,
            claim_actor=actor,
            claims=[],
            retained_owned=[],
            recompute_count=0,
            status="offline-candidate",
            created_at=created_at,
        )
        return PoolAdmissionReservation(receipt=receipt, capability=None)

    claims: list[Mapping[str, Any]] = []
    owned: set[str] = set()
    recompute_count = 0
    excluded_loss: str | None = None
    while True:
        if owned - set(validated.issue_ids):
            raise NativePoolAdmissionError("rebuild-omitted-retained-owned-claim")
        if excluded_loss is not None and excluded_loss in validated.issue_ids:
            raise NativePoolAdmissionError("rebuild-reincluded-lost-claim")

        for issue_id in sorted(set(validated.issue_ids) - owned):
            _exact_preclaim_show(validated, claim_adapter, issue_id)

        lost_issue: str | None = None
        for issue_id in sorted(set(validated.issue_ids) - owned):
            transition = claim_adapter.claim(issue_id)
            if type(transition) is not ClaimTransition:
                raise NativePoolAdmissionError("claim-transition-type-invalid")
            claim = dict(transition.receipt)
            claim_errors = validate_claim_receipt(claim)
            if claim_errors:
                raise NativePoolAdmissionError(
                    f"claim-receipt-invalid:{issue_id}:" + ";".join(claim_errors)
                )
            if claim.get("bead_id") != issue_id or claim.get("actor") != actor:
                raise NativePoolAdmissionError(
                    f"claim-receipt-binding-mismatch:{issue_id}"
                )
            claims.append(claim)
            if transition.owned:
                owned.add(issue_id)
                continue
            lost_issue = issue_id
            break

        if lost_issue is None:
            _live_revalidate_claimed_cohort(
                validated,
                adapter=claim_adapter,
                claims=claims,
                live_revalidate=live_revalidate,
            )
            receipt = _reservation_receipt(
                validated,
                admission_nonce=admission_nonce,
                claim_actor=actor,
                claims=claims,
                retained_owned=sorted(owned),
                recompute_count=recompute_count,
                status="admitted",
                created_at=created_at,
            )
            errors = validate_reservation_receipt(receipt)
            if errors:
                raise NativePoolAdmissionError(
                    "reservation-receipt-invalid:" + ";".join(errors)
                )
            bindings_hash = canonical_admission_sha256(receipt["child_bindings"])
            capability = FixedCohortAdmissionCapability(
                reservation_sha256=receipt["reservation_sha256"],
                fixed_cohort_sha256_value=receipt["fixed_cohort_sha256"],
                child_bindings_sha256=bindings_hash,
                token=_CAPABILITY_TOKEN,
            )
            return PoolAdmissionReservation(receipt=receipt, capability=capability)

        if rebuild is None or recompute_count == 1:
            receipt = _reservation_receipt(
                validated,
                admission_nonce=admission_nonce,
                claim_actor=actor,
                claims=claims,
                retained_owned=sorted(owned),
                recompute_count=recompute_count,
                status="claim-lost",
                created_at=created_at,
            )
            return PoolAdmissionReservation(receipt=receipt, capability=None)
        recompute_count = 1
        excluded_loss = lost_issue
        replacement = rebuild(validated.source, frozenset(owned), lost_issue)
        if replacement is None:
            receipt = _reservation_receipt(
                validated,
                admission_nonce=admission_nonce,
                claim_actor=actor,
                claims=claims,
                retained_owned=sorted(owned),
                recompute_count=recompute_count,
                status="claim-lost",
                created_at=created_at,
            )
            return PoolAdmissionReservation(receipt=receipt, capability=None)
        validated = _validate_candidate(replacement, policy_document=policy_document)
        if len(validated.issue_ids) >= 4:
            raise NativePoolAdmissionError("cohort-size-four-or-more-forbidden")
        if len(validated.issue_ids) == 3:
            raise NativePoolAdmissionError("productive-cohort-size-three-unreleased")


def validate_reservation_receipt(value: Any) -> list[str]:
    try:
        receipt = _strict(value, RESERVATION_FIELDS, "reservation")
        if (
            receipt.get("reservation_type") != RESERVATION_TYPE
            or receipt.get("version") != ADMISSION_VERSION
            or receipt.get("schema") != RESERVATION_SCHEMA
        ):
            raise NativePoolAdmissionError("reservation-header-invalid")
        if not _sha256(receipt.get("reservation_id")):
            raise NativePoolAdmissionError("reservation-id-invalid")
        for field in ("admission_nonce", "claim_actor"):
            if not _nonempty(receipt.get(field)):
                raise NativePoolAdmissionError(
                    f"reservation-{field.replace('_', '-')}-invalid"
                )
        _iso(receipt.get("created_at"))
        for field in (
            "readiness_snapshot_sha256",
            "readiness_evidence_sha256",
            "work_estimate_set_sha256",
            "native_worker_policy_sha256",
            "proportionality_policy_sha256",
            "proportionality_assessment_sha256",
            "selected_cohort_sha256",
            "fixed_cohort_sha256",
        ):
            if not _sha256(receipt.get(field)):
                raise NativePoolAdmissionError(
                    f"reservation-{field.replace('_', '-')}-invalid"
                )
        if receipt.get("candidate_mode") not in {
            "single",
            "released-capacity",
            "offline-unreleased-candidate",
        }:
            raise NativePoolAdmissionError("reservation-candidate-mode-invalid")
        issue_ids = receipt.get("issue_ids")
        bindings = receipt.get("child_bindings")
        claims = receipt.get("claims")
        retained = receipt.get("retained_owned_issue_ids")
        if (
            type(issue_ids) is not list
            or not issue_ids
            or any(not _nonempty(item) for item in issue_ids)
            or len(issue_ids) != len(set(issue_ids))
        ):
            raise NativePoolAdmissionError("reservation-issue-ids-invalid")
        if type(bindings) is not list or len(bindings) != len(issue_ids):
            raise NativePoolAdmissionError("reservation-child-bindings-invalid")
        binding_by_bead: dict[str, dict[str, Any]] = {}
        for binding in bindings:
            errors = validate_admission_child_binding(binding)
            if errors:
                raise NativePoolAdmissionError(
                    "reservation-child-binding-invalid:" + ";".join(errors)
                )
            bead_id = binding["bead_id"]
            if bead_id in binding_by_bead:
                raise NativePoolAdmissionError("reservation-child-binding-duplicate")
            binding_by_bead[bead_id] = dict(binding)
        if set(binding_by_bead) != set(issue_ids):
            raise NativePoolAdmissionError("reservation-child-binding-set-mismatch")
        if receipt["child_bindings_sha256"] != canonical_admission_sha256(bindings):
            raise NativePoolAdmissionError("reservation-child-bindings-sha256-mismatch")
        try:
            expected_fixed = fixed_cohort_sha256(
                [
                    {
                        "bead_id": binding["bead_id"],
                        "work_unit_id": binding["work_unit_id"],
                        "admitted_child_sha256": binding["admitted_child_sha256"],
                    }
                    for binding in bindings
                ]
            )
        except RecoveryAuthorityError as exc:
            raise NativePoolAdmissionError("reservation-fixed-cohort-invalid") from exc
        if receipt["fixed_cohort_sha256"] != expected_fixed:
            raise NativePoolAdmissionError("reservation-fixed-cohort-sha256-mismatch")
        if type(claims) is not list:
            raise NativePoolAdmissionError("reservation-claims-invalid")
        if receipt["claim_set_sha256"] != canonical_admission_sha256(claims):
            raise NativePoolAdmissionError("reservation-claim-set-sha256-mismatch")
        owned_ids: set[str] = set()
        lost_count = 0
        for claim in claims:
            errors = validate_claim_receipt(claim)
            if errors:
                raise NativePoolAdmissionError(
                    "reservation-claim-invalid:" + ";".join(errors)
                )
            if claim["actor"] != receipt["claim_actor"]:
                raise NativePoolAdmissionError("reservation-claim-actor-mismatch")
            if claim["owned"] is True:
                if claim["bead_id"] in owned_ids:
                    raise NativePoolAdmissionError("reservation-owned-claim-duplicate")
                owned_ids.add(claim["bead_id"])
            else:
                lost_count += 1
        if type(retained) is not list or retained != sorted(set(retained)):
            raise NativePoolAdmissionError("reservation-retained-owned-invalid")
        if set(retained) != owned_ids or not owned_ids <= set(issue_ids):
            raise NativePoolAdmissionError("reservation-retained-owned-mismatch")
        recompute_count = receipt.get("recompute_count")
        if type(recompute_count) is not int or recompute_count not in {0, 1}:
            raise NativePoolAdmissionError("reservation-recompute-count-invalid")
        if lost_count > recompute_count + 1:
            raise NativePoolAdmissionError("reservation-claim-loss-count-invalid")
        status = receipt.get("status")
        if status not in {"admitted", "claim-lost", "offline-candidate"}:
            raise NativePoolAdmissionError("reservation-status-invalid")
        if status == "admitted" and (
            set(issue_ids) != owned_ids or not 1 <= len(issue_ids) <= 2 or not claims
        ):
            raise NativePoolAdmissionError("reservation-admitted-claims-incomplete")
        if status == "claim-lost" and lost_count < 1:
            raise NativePoolAdmissionError("reservation-claim-lost-evidence-missing")
        if status == "offline-candidate" and (claims or retained):
            raise NativePoolAdmissionError("reservation-offline-contains-claims")
        if (
            receipt.get("authority") != RESERVATION_AUTHORITY
            or receipt.get("dispatch_authorized") is not False
        ):
            raise NativePoolAdmissionError("reservation-authority-invalid")
        _verify_seal(receipt, "reservation_sha256", "reservation")
    except (NativePoolAdmissionError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def _reservation_live_evidence_sha256(
    reservation_receipt: Mapping[str, Any],
) -> str:
    claims_by_bead = {
        claim["bead_id"]: claim
        for claim in reservation_receipt["claims"]
        if claim["owned"] is True
    }
    return canonical_admission_sha256(
        {
            "reservation_sha256": reservation_receipt["reservation_sha256"],
            "claim_actor": reservation_receipt["claim_actor"],
            "observations": [
                {
                    "bead_id": binding["bead_id"],
                    "claim_sha256": claims_by_bead[binding["bead_id"]]["claim_sha256"],
                    "post_show_sha256": claims_by_bead[binding["bead_id"]][
                        "post_show_sha256"
                    ],
                    "admitted_child_sha256": binding["admitted_child_sha256"],
                }
                for binding in reservation_receipt["child_bindings"]
            ],
        }
    )


def revalidate_reservation_live(
    reservation_receipt: Mapping[str, Any],
    *,
    claim_adapter: ClaimAdapter,
    live_revalidate: LiveRevalidationCallback,
) -> str:
    """Recheck exact Beads ownership and child bindings immediately before commit."""

    errors = validate_reservation_receipt(reservation_receipt)
    if errors:
        raise NativePoolAdmissionError("reservation-invalid:" + ";".join(errors))
    if reservation_receipt.get("status") != "admitted":
        raise NativePoolAdmissionError("reservation-not-admitted")
    actor = getattr(claim_adapter, "actor", None)
    if actor != reservation_receipt["claim_actor"]:
        raise NativePoolAdmissionError("live-revalidation-claim-actor-mismatch")
    if not callable(live_revalidate):
        raise NativePoolAdmissionError("live-revalidation-callback-required")
    claims_by_bead = {
        claim["bead_id"]: claim
        for claim in reservation_receipt["claims"]
        if claim["owned"] is True
    }
    for binding in reservation_receipt["child_bindings"]:
        issue_id = binding["bead_id"]
        claim = claims_by_bead[issue_id]
        current = dict(claim_adapter.show_exact(issue_id))
        if (
            current.get("status") != "in_progress"
            or current.get("assignee") != actor
            or canonical_admission_sha256(current) != claim["post_show_sha256"]
        ):
            raise NativePoolAdmissionError(f"live-revalidation-claim-drift:{issue_id}")
        observed = live_revalidate(deepcopy(dict(binding)))
        if type(observed) is not dict or observed != dict(binding):
            raise NativePoolAdmissionError(
                f"live-revalidation-binding-drift:{issue_id}"
            )
    return _reservation_live_evidence_sha256(reservation_receipt)


def build_dispatch_context(
    reservation_receipt: Mapping[str, Any],
    *,
    pool_contract_sha256: str,
    preflight_request_sha256: str,
    preflight_result_sha256: str,
    lease_set_sha256: str,
) -> dict[str, Any]:
    errors = validate_reservation_receipt(reservation_receipt)
    if errors:
        raise NativePoolAdmissionError("reservation-invalid:" + ";".join(errors))
    if reservation_receipt.get("status") != "admitted":
        raise NativePoolAdmissionError("reservation-not-admitted")
    supplied = {
        "pool_contract_sha256": pool_contract_sha256,
        "preflight_request_sha256": preflight_request_sha256,
        "preflight_result_sha256": preflight_result_sha256,
        "lease_set_sha256": lease_set_sha256,
    }
    for field, value in supplied.items():
        if not _sha256(value):
            raise NativePoolAdmissionError(
                f"dispatch-context-{field.replace('_', '-')}-invalid"
            )
    return {
        "reservation_sha256": reservation_receipt["reservation_sha256"],
        "fixed_cohort_sha256": reservation_receipt["fixed_cohort_sha256"],
        **supplied,
        "child_bindings_sha256": canonical_admission_sha256(
            reservation_receipt["child_bindings"]
        ),
        "live_revalidation_sha256": _reservation_live_evidence_sha256(
            reservation_receipt
        ),
    }


def validate_dispatch_context(value: Any) -> list[str]:
    try:
        context = _strict(value, DISPATCH_CONTEXT_FIELDS, "dispatch-context")
        for field in DISPATCH_CONTEXT_FIELDS:
            if not _sha256(context.get(field)):
                raise NativePoolAdmissionError(
                    f"dispatch-context-{field.replace('_', '-')}-invalid"
                )
    except NativePoolAdmissionError as exc:
        return [str(exc)]
    return []


def validate_dispatch_receipt(
    value: Any,
    *,
    reservation_receipt: Mapping[str, Any] | None = None,
) -> list[str]:
    try:
        receipt = _strict(value, DISPATCH_FIELDS, "dispatch")
        if (
            receipt.get("dispatch_type") != DISPATCH_TYPE
            or receipt.get("version") != ADMISSION_VERSION
            or receipt.get("schema") != DISPATCH_SCHEMA
        ):
            raise NativePoolAdmissionError("dispatch-header-invalid")
        if not _nonempty(receipt.get("dispatch_id")):
            raise NativePoolAdmissionError("dispatch-id-invalid")
        _iso(receipt.get("consumed_at"))
        context_errors = validate_dispatch_context(
            {field: receipt.get(field) for field in DISPATCH_CONTEXT_FIELDS}
        )
        if context_errors:
            raise NativePoolAdmissionError(
                "dispatch-context-invalid:" + ";".join(context_errors)
            )
        if (
            receipt.get("authority") != DISPATCH_AUTHORITY
            or receipt.get("dispatch_authorized") is not True
        ):
            raise NativePoolAdmissionError("dispatch-authority-invalid")
        if reservation_receipt is not None:
            reservation_errors = validate_reservation_receipt(reservation_receipt)
            if reservation_errors:
                raise NativePoolAdmissionError(
                    "dispatch-reservation-invalid:" + ";".join(reservation_errors)
                )
            if (
                receipt["reservation_sha256"]
                != reservation_receipt["reservation_sha256"]
                or receipt["fixed_cohort_sha256"]
                != reservation_receipt["fixed_cohort_sha256"]
                or receipt["child_bindings_sha256"]
                != canonical_admission_sha256(reservation_receipt["child_bindings"])
            ):
                raise NativePoolAdmissionError("dispatch-reservation-binding-mismatch")
        _verify_seal(receipt, "dispatch_sha256", "dispatch")
    except (NativePoolAdmissionError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


DispatchCallback = Callable[[Mapping[str, Any]], None]


def consume_pool_admission(
    capability: FixedCohortAdmissionCapability,
    reservation_receipt: Mapping[str, Any],
    dispatch_context: Mapping[str, Any],
    *,
    commit: DispatchCallback,
    precommit: DispatchCallback | None = None,
    postcommit: DispatchCallback | None = None,
    now: dt.datetime | str | None = None,
) -> dict[str, Any]:
    """Atomically consume authority; safe precommit failures release it.

    Once the commit callback starts, any exception is outcome-ambiguous and the
    capability remains retired.  A later postcommit failure is also terminal.
    """

    if type(capability) is not FixedCohortAdmissionCapability:
        raise NativePoolAdmissionError("fixed-cohort-admission-capability-type-invalid")
    if not callable(commit):
        raise NativePoolAdmissionError("dispatch-commit-callback-required")
    if precommit is not None and not callable(precommit):
        raise NativePoolAdmissionError("dispatch-precommit-callback-invalid")
    if postcommit is not None and not callable(postcommit):
        raise NativePoolAdmissionError("dispatch-postcommit-callback-invalid")

    with capability._lock:
        if capability._state != "available":
            raise NativePoolAdmissionError(
                f"fixed-cohort-admission-capability-not-available:{capability._state}"
            )
        capability._state = "in-flight"
        commit_started = False
        try:
            reservation_errors = validate_reservation_receipt(reservation_receipt)
            if reservation_errors:
                raise NativePoolAdmissionError(
                    "dispatch-reservation-invalid:" + ";".join(reservation_errors)
                )
            context_errors = validate_dispatch_context(dispatch_context)
            if context_errors:
                raise NativePoolAdmissionError(
                    "dispatch-context-invalid:" + ";".join(context_errors)
                )
            if (
                reservation_receipt.get("status") != "admitted"
                or reservation_receipt.get("reservation_sha256")
                != capability._reservation_sha256
                or reservation_receipt.get("fixed_cohort_sha256")
                != capability._fixed_cohort_sha256
                or canonical_admission_sha256(reservation_receipt.get("child_bindings"))
                != capability._child_bindings_sha256
            ):
                raise NativePoolAdmissionError("dispatch-capability-binding-mismatch")
            expected_context = build_dispatch_context(
                reservation_receipt,
                pool_contract_sha256=dispatch_context["pool_contract_sha256"],
                preflight_request_sha256=dispatch_context["preflight_request_sha256"],
                preflight_result_sha256=dispatch_context["preflight_result_sha256"],
                lease_set_sha256=dispatch_context["lease_set_sha256"],
            )
            if dict(dispatch_context) != expected_context:
                raise NativePoolAdmissionError("dispatch-context-binding-mismatch")
            if precommit is not None:
                precommit(deepcopy(dict(dispatch_context)))
            consumed_at = _iso(now)
            dispatch_id = canonical_admission_sha256(
                {
                    "reservation_sha256": capability._reservation_sha256,
                    "dispatch_context": dict(dispatch_context),
                }
            )
            dispatch = _seal(
                {
                    "dispatch_type": DISPATCH_TYPE,
                    "version": ADMISSION_VERSION,
                    "schema": DISPATCH_SCHEMA,
                    "dispatch_id": dispatch_id,
                    "consumed_at": consumed_at,
                    **dict(dispatch_context),
                    "authority": DISPATCH_AUTHORITY,
                    "dispatch_authorized": True,
                },
                "dispatch_sha256",
            )
            dispatch_errors = validate_dispatch_receipt(
                dispatch,
                reservation_receipt=reservation_receipt,
            )
            if dispatch_errors:
                raise NativePoolAdmissionError(
                    "dispatch-receipt-invalid:" + ";".join(dispatch_errors)
                )
            commit_started = True
            commit(deepcopy(dispatch))
            capability._state = "retired"
            if postcommit is not None:
                postcommit(deepcopy(dispatch))
            return dispatch
        except BaseException:
            if commit_started:
                capability._state = "retired"
            else:
                capability._state = "available"
            raise
