"""Deterministic, model-free admission checks for native supervision pools.

The same engine is run twice by a launcher.  The ``pre-allocation`` pass
rejects every defect that can be known before an empty worker session exists.
The ``pre-dispatch`` pass additionally binds those inputs to the exact rendered
pool contract before a worker receives a turn.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Mapping
import uuid

from .native_authority import (
    AUTHORIZED_SCOPE_RANK,
    AuthorityProvenanceError,
    VerifiedAuthority,
    validate_authority_provenance,
    verify_operator_directive,
)
from .native_pool_capacity import load_pool_capacity
from .native_pool_contracts import (
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    REQUIRED_CAPABILITY_CALLBACKS,
    canonical_sha256,
    validate_completion_evidence_policy,
    validate_pool_contract,
)
from .native_pool_schedulability import (
    PoolSchedulabilityError,
    scheduling_budget_proof,
)
from .native_tool_isolation import (
    NativeToolIsolationError,
    prompt_preflight,
    validate_tool_policy,
    validate_tool_surface_snapshot,
)


PREFLIGHT_REQUEST_TYPE = "cwo-native-supervision-pool-preflight-request"
PREFLIGHT_REQUEST_SCHEMA = (
    "schemas/native-supervision-pool-preflight-request.schema.json"
)
PREFLIGHT_RESULT_TYPE = "cwo-native-supervision-pool-preflight-result"
PREFLIGHT_RESULT_SCHEMA = "schemas/native-supervision-pool-preflight-result.schema.json"
PREFLIGHT_VERSION = 1
PREFLIGHT_STAGES = frozenset({"pre-allocation", "pre-dispatch"})

REQUEST_FIELDS = frozenset(
    {
        "preflight_type",
        "version",
        "schema",
        "stage",
        "launch_id",
        "campaign_nonce",
        "pool_id",
        "pool_epoch",
        "integration_root",
        "artifact_directories",
        "requested_workers",
        "released_capacity",
        "aggregate_hard_budget",
        "children",
        "fallback",
        "productive_dogfood_delivery_prerequisite",
        "callback_certification",
        "poll_interval_ms",
        "pool_contract",
        "overrides",
    }
)
CHILD_FIELDS = frozenset(
    {
        "child_id",
        "packet_id",
        "packet_sha256",
        "attempt_nonce",
        "session_id",
        "agent_id",
        "lease_id",
        "worktree",
        "isolation_class",
        "completion_evidence_policy",
        "tool_policy",
        "prompt",
        "prompt_preflight",
        "tool_surface",
        "hard_budget",
        "declared_write_paths",
        "integration_target_paths",
    }
)
BUDGET_FIELDS = frozenset(
    {"tool_calls", "runtime_seconds", "compactions", "full_suite_runs", "mutations"}
)
FALLBACK_FIELDS = frozenset({"main_thread", "recovery"})
CALLBACK_CERTIFICATION_FIELDS = frozenset(
    {"certified_callback_max_ms", "certified_scheduler_overhead_ms"}
)
OVERRIDE_FIELDS = frozenset({"rule_id", "reason"})
RESULT_FIELDS = frozenset(
    {
        "result_type",
        "version",
        "schema",
        "stage",
        "request_sha256",
        "contract_sha256",
        "decision",
        "accepted",
        "findings",
        "override_authority",
        "result_sha256",
    }
)
FINDING_FIELDS = frozenset(
    {
        "rule_id",
        "severity",
        "evidence",
        "remediation",
        "waivable",
        "overridden",
        "override_reason_sha256",
        "authority_provenance",
    }
)

_OVERRIDE_TOKEN = object()


class NativePoolPreflightError(ValueError):
    """Raised when deterministic admission rejects a launch."""


class VerifiedPoolPreflightOverride:
    """Opaque, action-bound operator authorization for preflight overrides."""

    __slots__ = ("_action_sha256", "_authority")

    def __init__(
        self,
        *,
        action_sha256: str,
        authority: VerifiedAuthority,
        token: object,
    ) -> None:
        if token is not _OVERRIDE_TOKEN:
            raise NativePoolPreflightError("preflight-override-construction-forbidden")
        self._action_sha256 = action_sha256
        self._authority = authority

    @property
    def action_sha256(self) -> str:
        return self._action_sha256

    def authority_provenance(self) -> dict[str, Any]:
        return self._authority.serialize()


def _safe_request_sha256(value: Any) -> str:
    try:
        return canonical_sha256(value)
    except (TypeError, ValueError):
        return canonical_sha256(
            {
                "unserializable_request_type": (
                    f"{type(value).__module__}.{type(value).__qualname__}"
                )
            }
        )


def pool_preflight_override_action_sha256(request: Mapping[str, Any]) -> str:
    """Return the exact action digest an operator directive must authorize."""

    return canonical_sha256(
        {
            "action_type": "native-pool-preflight-override",
            "request_sha256": _safe_request_sha256(dict(request)),
        }
    )


def verify_pool_preflight_override(
    request: Mapping[str, Any],
    directive: Mapping[str, Any],
    *,
    verification_key: bytes,
    expected_actor_id: str,
    expected_identity_source: str,
) -> VerifiedPoolPreflightOverride:
    """Verify an operator directive against one exact preflight request."""

    action_sha256 = pool_preflight_override_action_sha256(request)
    authority = verify_operator_directive(
        directive,
        verification_key=verification_key,
        expected_actor_id=expected_actor_id,
        expected_identity_source=expected_identity_source,
        expected_action_sha256=action_sha256,
    )
    if (
        authority.source_type != "operator-directive"
        or authority.actor_role != "operator"
        or AUTHORIZED_SCOPE_RANK.get(authority.authorized_scope, -1)
        < AUTHORIZED_SCOPE_RANK["complete-task"]
    ):
        raise AuthorityProvenanceError("pool-preflight-override-scope-insufficient")
    return VerifiedPoolPreflightOverride(
        action_sha256=action_sha256,
        authority=authority,
        token=_OVERRIDE_TOKEN,
    )


def _canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return str(parsed) == value


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _integer(value: Any, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _number(value: Any, minimum: float = 0.0) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and float(value) >= minimum
        and float(value) not in {float("inf"), float("-inf")}
        and float(value) == float(value)
    )


def _value_sha256(value: Any) -> str:
    try:
        return canonical_sha256(value)
    except (TypeError, ValueError):
        return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


def effective_child_packet_sha256(child: Mapping[str, Any]) -> str:
    """Bind the static effective child inputs without copying prompt text."""

    prompt = child.get("prompt")
    prompt_sha256 = (
        hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if isinstance(prompt, str)
        else _value_sha256(prompt)
    )
    prompt_receipt = child.get("prompt_preflight")
    tool_surface = child.get("tool_surface")
    return canonical_sha256(
        {
            "binding_type": "cwo-native-pool-effective-child-packet-v1",
            "child_id": child.get("child_id"),
            "packet_id": child.get("packet_id"),
            "attempt_nonce": child.get("attempt_nonce"),
            "lease_id": child.get("lease_id"),
            "worktree_sha256": _value_sha256(child.get("worktree")),
            "isolation_class": child.get("isolation_class"),
            "completion_evidence_policy": child.get("completion_evidence_policy"),
            "tool_policy": child.get("tool_policy"),
            "prompt_sha256": prompt_sha256,
            "prompt_preflight_sha256": (
                prompt_receipt.get("preflight_sha256")
                if isinstance(prompt_receipt, Mapping)
                else None
            ),
            "tool_surface_sha256": (
                tool_surface.get("surface_sha256")
                if isinstance(tool_surface, Mapping)
                else None
            ),
            "hard_budget": child.get("hard_budget"),
            "declared_write_paths": child.get("declared_write_paths"),
            "integration_target_paths": child.get("integration_target_paths"),
        }
    )


def _finding(
    rule_id: str,
    severity: str,
    evidence: Mapping[str, Any],
    remediation: str,
    *,
    waivable: bool = False,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "evidence": deepcopy(dict(evidence)),
        "remediation": remediation,
        "waivable": waivable,
        "overridden": False,
        "override_reason_sha256": None,
        "authority_provenance": None,
    }


def _shape_finding(
    rule_id: str,
    value: Any,
    expected_fields: frozenset[str],
    subject: str,
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return _finding(
            rule_id,
            "error",
            {"subject": subject, "observed_type": type(value).__name__},
            f"Provide {subject} as an object with the exact documented fields.",
        )
    missing = sorted(expected_fields - set(value))
    unknown = sorted(set(value) - expected_fields)
    if not missing and not unknown:
        return None
    return _finding(
        rule_id,
        "error",
        {"subject": subject, "missing": missing, "unknown": unknown},
        f"Provide {subject} with no missing or unknown fields.",
    )


def _budget_errors(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["must-be-object"]
    errors: list[str] = []
    missing = sorted(BUDGET_FIELDS - set(value))
    unknown = sorted(set(value) - BUDGET_FIELDS)
    if missing:
        errors.append("missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("unknown-fields:" + ",".join(unknown))
    for field in ("tool_calls", "runtime_seconds"):
        if not _integer(value.get(field), 1):
            errors.append(f"{field}-invalid")
    for field in ("compactions", "full_suite_runs", "mutations"):
        if not _integer(value.get(field)):
            errors.append(f"{field}-invalid")
    return sorted(set(errors))


def evaluate_scheduling_admission(
    requested_workers: int,
    certified_callback_max_ms: Mapping[str, Any],
    certified_scheduler_overhead_ms: int | float,
    poll_interval_ms: int | float,
) -> dict[str, Any]:
    """Compatibility facade over the one shared schedulability proof."""

    if (
        not isinstance(certified_callback_max_ms, Mapping)
        or set(certified_callback_max_ms) != set(REQUIRED_CAPABILITY_CALLBACKS)
    ):
        raise NativePoolPreflightError(
            "scheduling-callback-ceilings-fields-invalid"
        )
    try:
        proof = scheduling_budget_proof(
            requested_workers=requested_workers,
            certified_callback_max_ms=certified_callback_max_ms,
            certified_scheduler_overhead_ms=(
                certified_scheduler_overhead_ms
            ),
            poll_interval_ms=poll_interval_ms,
        )
    except PoolSchedulabilityError as error:
        raise NativePoolPreflightError(str(error)) from error
    return proof.as_dict()


def _path_overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _path_component_symlink(path: Path) -> bool:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            return True
    return False


def _nearest_existing_parent(path: Path) -> Path | None:
    candidate = path.parent
    while candidate != candidate.parent:
        if candidate.exists() or candidate.is_symlink():
            return candidate
        candidate = candidate.parent
    return candidate if candidate.exists() else None


def _safe_directory_findings(
    directories: Any,
    *,
    integration_root: Any,
    worktrees: list[Path],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(directories, list) or not directories:
        return [
            _finding(
                "directory.artifact-set",
                "error",
                {"observed_type": type(directories).__name__},
                "Declare at least one absolute artifact directory.",
            )
        ]
    normalized: list[Path] = []
    for index, raw in enumerate(directories):
        digest = _value_sha256(raw)
        if not _nonempty(raw) or not Path(str(raw)).is_absolute():
            findings.append(
                _finding(
                    "directory.safe-artifact-path",
                    "error",
                    {"index": index, "path_sha256": digest, "reason": "not-absolute"},
                    "Use a dedicated absolute artifact directory.",
                )
            )
            continue
        path = Path(str(raw))
        if _path_component_symlink(path):
            findings.append(
                _finding(
                    "directory.safe-artifact-path",
                    "error",
                    {
                        "index": index,
                        "path_sha256": digest,
                        "reason": "symlink-component",
                    },
                    "Use a path with no symlink components.",
                )
            )
            continue
        resolved = path.resolve(strict=False)
        normalized.append(resolved)
        if path.exists():
            metadata = path.stat()
            mode = stat.S_IMODE(metadata.st_mode)
            if not path.is_dir():
                findings.append(
                    _finding(
                        "directory.safe-artifact-path",
                        "error",
                        {
                            "index": index,
                            "path_sha256": digest,
                            "reason": "not-directory",
                        },
                        "Move the colliding file and provide a dedicated directory.",
                    )
                )
            elif metadata.st_uid != os.geteuid() or mode & 0o077:
                findings.append(
                    _finding(
                        "directory.safe-artifact-path",
                        "error",
                        {
                            "index": index,
                            "path_sha256": digest,
                            "reason": "ownership-or-mode",
                            "mode": oct(mode),
                        },
                        "Use an operator-owned directory with mode 0700.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "directory.existing-safe",
                        "info",
                        {"index": index, "path_sha256": digest, "mode": oct(mode)},
                        "No change is required; repeated use is idempotent.",
                        waivable=True,
                    )
                )
        else:
            parent = _nearest_existing_parent(path)
            if parent is None or parent.is_symlink() or not parent.is_dir():
                findings.append(
                    _finding(
                        "directory.safe-artifact-path",
                        "error",
                        {
                            "index": index,
                            "path_sha256": digest,
                            "reason": "unsafe-parent",
                        },
                        "Create a private operator-owned parent directory first.",
                    )
                )
            else:
                metadata = parent.stat()
                mode = stat.S_IMODE(metadata.st_mode)
                if (
                    metadata.st_uid != os.geteuid()
                    or mode & 0o077
                    or not os.access(parent, os.W_OK | os.X_OK)
                ):
                    findings.append(
                        _finding(
                            "directory.safe-artifact-path",
                            "error",
                            {
                                "index": index,
                                "path_sha256": digest,
                                "reason": "unsafe-parent",
                                "parent_mode": oct(mode),
                            },
                            "Use a writable operator-owned parent with mode 0700.",
                        )
                    )
    for index, left in enumerate(normalized):
        for right in normalized[index + 1 :]:
            if _path_overlaps(left, right):
                findings.append(
                    _finding(
                        "directory.artifact-collision",
                        "error",
                        {
                            "left_sha256": _value_sha256(str(left)),
                            "right_sha256": _value_sha256(str(right)),
                        },
                        "Use disjoint artifact directories.",
                    )
                )
    protected: list[tuple[str, Path]] = []
    if _nonempty(integration_root) and Path(str(integration_root)).is_absolute():
        protected.append(
            ("integration-root", Path(str(integration_root)).resolve(strict=False))
        )
    protected.extend(("worktree", path.resolve(strict=False)) for path in worktrees)
    for artifact in normalized:
        for label, protected_path in protected:
            if _path_overlaps(artifact, protected_path):
                findings.append(
                    _finding(
                        "directory.protected-path-collision",
                        "error",
                        {
                            "artifact_sha256": _value_sha256(str(artifact)),
                            "protected_sha256": _value_sha256(str(protected_path)),
                            "protected_kind": label,
                        },
                        "Place artifacts outside integration and worker worktrees.",
                    )
                )
    return findings


def _validate_relative_paths(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["must-be-array"]
    errors: list[str] = []
    normalized: list[str] = []
    for item in value:
        if not _nonempty(item):
            errors.append("contains-invalid-path")
            continue
        path = PurePosixPath(str(item))
        if (
            path.is_absolute()
            or item in {".", ".."}
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != item
        ):
            errors.append("contains-unsafe-path")
            continue
        normalized.append(str(item))
    if len(normalized) != len(set(normalized)):
        errors.append("contains-duplicate-path")
    return sorted(set(errors))


def _apply_overrides(
    findings: list[dict[str, Any]],
    request: Mapping[str, Any],
    authorization: VerifiedPoolPreflightOverride | None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    raw_overrides = request.get("overrides")
    if not isinstance(raw_overrides, list):
        findings.append(
            _finding(
                "override.request-shape",
                "error",
                {"observed_type": type(raw_overrides).__name__},
                "Provide overrides as an array, normally empty.",
            )
        )
        raw_overrides = []
    authority_provenance: dict[str, Any] | None = None
    authority_valid = False
    if authorization is not None:
        if not isinstance(authorization, VerifiedPoolPreflightOverride):
            findings.append(
                _finding(
                    "override.authorization-required",
                    "error",
                    {"reason": "unverified-object"},
                    "Use an action-bound directive verified by the trusted verifier.",
                )
            )
        elif authorization.action_sha256 != pool_preflight_override_action_sha256(
            request
        ):
            findings.append(
                _finding(
                    "override.authorization-required",
                    "error",
                    {"reason": "action-binding-mismatch"},
                    "Issue a fresh directive for this exact preflight request.",
                )
            )
        else:
            authority_provenance = authorization.authority_provenance()
            authority_valid = True
    if not raw_overrides:
        if authorization is not None:
            findings.append(
                _finding(
                    "override.unrequested-authority",
                    "error",
                    {"request_sha256": _safe_request_sha256(dict(request))},
                    "Omit override authority when no override is requested.",
                )
            )
        return findings, authority_provenance

    observed_rules: set[str] = set()
    for index, raw_override in enumerate(raw_overrides):
        if not isinstance(raw_override, Mapping) or set(raw_override) != set(
            OVERRIDE_FIELDS
        ):
            findings.append(
                _finding(
                    "override.request-shape",
                    "error",
                    {"index": index},
                    "Provide exactly rule_id and a non-empty reason.",
                )
            )
            continue
        rule_id = raw_override.get("rule_id")
        reason = raw_override.get("reason")
        if not _nonempty(rule_id) or not _nonempty(reason):
            findings.append(
                _finding(
                    "override.request-shape",
                    "error",
                    {"index": index},
                    "Provide exactly rule_id and a non-empty reason.",
                )
            )
            continue
        if str(rule_id) in observed_rules:
            findings.append(
                _finding(
                    "override.duplicate-rule",
                    "error",
                    {"rule_id": str(rule_id)},
                    "Request at most one override per rule ID.",
                )
            )
            continue
        observed_rules.add(str(rule_id))
        matches = [item for item in findings if item["rule_id"] == rule_id]
        if not matches:
            findings.append(
                _finding(
                    "override.rule-not-found",
                    "error",
                    {"rule_id": str(rule_id)},
                    "Remove stale overrides that do not match a current finding.",
                )
            )
            continue
        if any(item["waivable"] is not True for item in matches):
            findings.append(
                _finding(
                    "override.non-waivable-rule",
                    "error",
                    {"rule_id": str(rule_id)},
                    "Correct the authority, containment, security, integrity, or hard-cap defect.",
                )
            )
            continue
        if not authority_valid:
            findings.append(
                _finding(
                    "override.authorization-required",
                    "error",
                    {"rule_id": str(rule_id)},
                    "Provide a verified operator directive bound to this exact request.",
                )
            )
            continue
        assert authority_provenance is not None
        for item in matches:
            item["overridden"] = True
            item["override_reason_sha256"] = hashlib.sha256(
                str(reason).strip().encode("utf-8")
            ).hexdigest()
            item["authority_provenance"] = deepcopy(authority_provenance)
    return findings, authority_provenance


def run_pool_preflight(
    request: Mapping[str, Any],
    *,
    override_authorization: VerifiedPoolPreflightOverride | None = None,
) -> dict[str, Any]:
    """Return a deterministic result; no model or worker session is consulted."""

    capacity_limits = load_pool_capacity()
    request_sha256 = _safe_request_sha256(request)
    findings: list[dict[str, Any]] = []
    if not isinstance(request, Mapping):
        request_map: dict[str, Any] = {}
        findings.append(
            _finding(
                "request.shape",
                "error",
                {"observed_type": type(request).__name__},
                "Provide a JSON object matching the preflight request schema.",
            )
        )
    else:
        request_map = dict(request)
        shape = _shape_finding("request.shape", request_map, REQUEST_FIELDS, "request")
        if shape is not None:
            findings.append(shape)

    if (
        request_map.get("preflight_type") != PREFLIGHT_REQUEST_TYPE
        or request_map.get("version") != PREFLIGHT_VERSION
        or request_map.get("schema") != PREFLIGHT_REQUEST_SCHEMA
    ):
        findings.append(
            _finding(
                "request.header",
                "error",
                {
                    "header_sha256": _value_sha256(
                        {
                            "preflight_type": request_map.get("preflight_type"),
                            "version": request_map.get("version"),
                            "schema": request_map.get("schema"),
                        }
                    )
                },
                "Use the current native pool preflight type, version, and schema.",
            )
        )
    stage = request_map.get("stage")
    if stage not in PREFLIGHT_STAGES:
        findings.append(
            _finding(
                "request.stage",
                "error",
                {"observed_sha256": _value_sha256(stage)},
                "Select pre-allocation or pre-dispatch.",
            )
        )

    for field in ("launch_id", "campaign_nonce", "pool_id", "pool_epoch"):
        value = request_map.get(field)
        if not _canonical_uuid(value):
            findings.append(
                _finding(
                    "identity.canonical-uuid",
                    "error",
                    {"field": field, "value_sha256": _value_sha256(value)},
                    "Use a lowercase canonical RFC 4122 UUID string.",
                )
            )

    integration_root = request_map.get("integration_root")
    if not _nonempty(integration_root) or not Path(str(integration_root)).is_absolute():
        findings.append(
            _finding(
                "directory.integration-root",
                "error",
                {"path_sha256": _value_sha256(integration_root)},
                "Provide the absolute integration-root path.",
            )
        )

    aggregate_budget = request_map.get("aggregate_hard_budget")
    aggregate_budget_errors = _budget_errors(aggregate_budget)
    if aggregate_budget_errors:
        findings.append(
            _finding(
                "budget.aggregate-shape",
                "error",
                {"errors": aggregate_budget_errors},
                "Provide all aggregate hard-budget dimensions as valid integers.",
            )
        )

    requested_workers = request_map.get("requested_workers")
    released_capacity = request_map.get("released_capacity")
    if not _integer(requested_workers, 1):
        findings.append(
            _finding(
                "capacity.requested-workers",
                "error",
                {"value_sha256": _value_sha256(requested_workers)},
                "Request at least one worker using an integer.",
            )
        )
    if (
        not _integer(released_capacity, 1)
        or int(released_capacity)
        > capacity_limits.released_max_active_workers
    ):
        findings.append(
            _finding(
                "capacity.released-limit",
                "error",
                {
                    "released_capacity": released_capacity,
                    "released_max_active_workers": (
                        capacity_limits.released_max_active_workers
                    ),
                    "hard_max_active_workers": (
                        capacity_limits.hard_max_active_workers
                    ),
                },
                "Use the capacity currently released by repository policy.",
            )
        )
    elif _integer(requested_workers, 1) and requested_workers > released_capacity:
        findings.append(
            _finding(
                "capacity.released-limit",
                "error",
                {
                    "requested_workers": requested_workers,
                    "released_capacity": released_capacity,
                },
                "Reduce the cohort to the currently released capacity.",
            )
        )

    children_value = request_map.get("children")
    children = children_value if isinstance(children_value, list) else []
    if not isinstance(children_value, list) or not children:
        findings.append(
            _finding(
                "children.shape",
                "error",
                {"observed_type": type(children_value).__name__},
                "Declare one effective-environment record per child.",
            )
        )
    if _integer(requested_workers, 1) and len(children) != requested_workers:
        findings.append(
            _finding(
                "children.cardinality",
                "error",
                {"requested_workers": requested_workers, "child_count": len(children)},
                "Make the fixed child cohort equal requested_workers.",
            )
        )

    normalized_children: list[Mapping[str, Any]] = []
    worktrees: list[Path] = []
    budget_sum = {field: 0 for field in BUDGET_FIELDS}
    budgets_complete = not aggregate_budget_errors
    identities: dict[str, list[Any]] = {
        field: []
        for field in (
            "child_id",
            "packet_id",
            "packet_sha256",
            "attempt_nonce",
            "session_id",
            "agent_id",
            "lease_id",
        )
    }
    mutable_targets: list[tuple[int, str]] = []
    for index, raw_child in enumerate(children):
        shape = _shape_finding(
            "child.shape", raw_child, CHILD_FIELDS, f"child[{index}]"
        )
        if shape is not None:
            findings.append(shape)
        if not isinstance(raw_child, Mapping):
            budgets_complete = False
            continue
        child = dict(raw_child)
        normalized_children.append(child)
        for field in identities:
            identities[field].append(child.get(field))
        if not _nonempty(child.get("child_id")):
            findings.append(
                _finding(
                    "identity.child-id",
                    "error",
                    {"child_index": index},
                    "Provide a stable non-empty child ID.",
                )
            )
        for field in ("packet_id", "attempt_nonce", "lease_id"):
            if not _canonical_uuid(child.get(field)):
                findings.append(
                    _finding(
                        "identity.canonical-uuid",
                        "error",
                        {
                            "child_index": index,
                            "field": field,
                            "value_sha256": _value_sha256(child.get(field)),
                        },
                        "Use a lowercase canonical RFC 4122 UUID string.",
                    )
                )
        expected_packet_sha256 = effective_child_packet_sha256(child)
        if (
            not _sha256(child.get("packet_sha256"))
            or child.get("packet_sha256") != expected_packet_sha256
        ):
            findings.append(
                _finding(
                    "contract.packet-binding",
                    "error",
                    {
                        "child_index": index,
                        "expected_sha256": expected_packet_sha256,
                        "observed_sha256": _value_sha256(child.get("packet_sha256")),
                    },
                    "Recompute the child packet digest from the exact effective inputs.",
                )
            )
        if stage == "pre-allocation":
            if child.get("session_id") is not None or child.get("agent_id") is not None:
                findings.append(
                    _finding(
                        "identity.preallocation-session-state",
                        "error",
                        {"child_index": index},
                        "Leave session_id and agent_id null before allocation.",
                    )
                )
        elif stage == "pre-dispatch":
            for field in ("session_id", "agent_id"):
                if not _canonical_uuid(child.get(field)):
                    findings.append(
                        _finding(
                            "identity.canonical-uuid",
                            "error",
                            {
                                "child_index": index,
                                "field": field,
                                "value_sha256": _value_sha256(child.get(field)),
                            },
                            "Use the canonical UUID returned by the trusted session service.",
                        )
                    )
            if child.get("session_id") != child.get("agent_id"):
                findings.append(
                    _finding(
                        "identity.session-agent-binding",
                        "error",
                        {"child_index": index},
                        "Bind the child agent to the exact allocated session.",
                    )
                )

        raw_worktree = child.get("worktree")
        if not _nonempty(raw_worktree) or not Path(str(raw_worktree)).is_absolute():
            findings.append(
                _finding(
                    "directory.worktree",
                    "error",
                    {"child_index": index, "path_sha256": _value_sha256(raw_worktree)},
                    "Provide an absolute child worktree path.",
                )
            )
        else:
            worktrees.append(Path(str(raw_worktree)))

        isolation = child.get("isolation_class")
        if isolation not in {"read-only-shared", "mutable-isolated"}:
            findings.append(
                _finding(
                    "topology.isolation-class",
                    "error",
                    {"child_index": index, "value_sha256": _value_sha256(isolation)},
                    "Select read-only-shared or mutable-isolated.",
                )
            )
        completion_errors = validate_completion_evidence_policy(
            child.get("completion_evidence_policy"),
            isolation_class=str(isolation),
            prefix=f"child[{index}]-completion-evidence-policy",
        )
        if completion_errors:
            findings.append(
                _finding(
                    "completion.policy-satisfiable",
                    "error",
                    {"child_index": index, "errors": completion_errors},
                    "Declare completion evidence satisfiable by the child isolation mode.",
                )
            )

        tool_policy = child.get("tool_policy")
        tool_policy_errors = validate_tool_policy(
            tool_policy, prefix=f"child[{index}]-tool-policy"
        )
        if tool_policy_errors:
            findings.append(
                _finding(
                    "tools.policy",
                    "error",
                    {"child_index": index, "errors": tool_policy_errors},
                    "Use the strict worker tool policy.",
                )
            )
        if isinstance(tool_policy, Mapping):
            surface_errors = validate_tool_surface_snapshot(
                child.get("tool_surface"), tool_policy
            )
            if surface_errors:
                findings.append(
                    _finding(
                        "tools.effective-surface",
                        "error",
                        {"child_index": index, "errors": surface_errors},
                        "Make the effective server allowlist exactly match the requested policy.",
                    )
                )

        try:
            observed_prompt = prompt_preflight(child.get("prompt"), tool_policy)
        except (NativeToolIsolationError, TypeError, ValueError) as exc:
            findings.append(
                _finding(
                    "prompt.input",
                    "error",
                    {"child_index": index, "error": str(exc)},
                    "Provide the exact non-empty rendered prompt and a valid tool policy.",
                )
            )
        else:
            if observed_prompt["findings"]:
                findings.append(
                    _finding(
                        "prompt.trigger-conflict",
                        "error",
                        {
                            "child_index": index,
                            "prompt_sha256": observed_prompt["prompt_sha256"],
                            "findings": observed_prompt["findings"],
                        },
                        "Remove unintended skill, router, subagent, or forbidden-tool directives.",
                    )
                )
            if child.get("prompt_preflight") != observed_prompt:
                findings.append(
                    _finding(
                        "prompt.receipt-binding",
                        "error",
                        {
                            "child_index": index,
                            "observed_preflight_sha256": observed_prompt[
                                "preflight_sha256"
                            ],
                            "provided_sha256": _value_sha256(
                                child.get("prompt_preflight")
                            ),
                        },
                        "Bind the exact prompt-preflight receipt to the effective prompt.",
                    )
                )

        child_budget = child.get("hard_budget")
        child_budget_errors = _budget_errors(child_budget)
        if child_budget_errors:
            budgets_complete = False
            findings.append(
                _finding(
                    "budget.child-shape",
                    "error",
                    {"child_index": index, "errors": child_budget_errors},
                    "Provide every per-child hard-budget dimension.",
                )
            )
        else:
            assert isinstance(child_budget, Mapping)
            for field in BUDGET_FIELDS:
                budget_sum[field] += int(child_budget[field])
            completion = child.get("completion_evidence_policy")
            minimum_tool_calls = (
                completion.get("minimum_tool_calls")
                if isinstance(completion, Mapping)
                else None
            )
            if (
                _integer(minimum_tool_calls)
                and minimum_tool_calls > child_budget["tool_calls"]
            ):
                findings.append(
                    _finding(
                        "completion.budget-satisfiable",
                        "error",
                        {
                            "child_index": index,
                            "minimum_tool_calls": minimum_tool_calls,
                            "tool_call_budget": child_budget["tool_calls"],
                        },
                        "Increase the child tool-call budget or reduce required evidence.",
                    )
                )
            if isolation == "mutable-isolated" and child_budget["mutations"] < 1:
                findings.append(
                    _finding(
                        "completion.budget-satisfiable",
                        "error",
                        {
                            "child_index": index,
                            "mutation_budget": child_budget["mutations"],
                        },
                        "Reserve at least one mutation for a mutable child.",
                    )
                )
            if isolation == "read-only-shared" and child_budget["mutations"] != 0:
                findings.append(
                    _finding(
                        "completion.budget-satisfiable",
                        "error",
                        {
                            "child_index": index,
                            "mutation_budget": child_budget["mutations"],
                        },
                        "Set the mutation budget to zero for a read-only child.",
                    )
                )

        write_paths = child.get("declared_write_paths")
        write_errors = _validate_relative_paths(write_paths)
        if write_errors:
            findings.append(
                _finding(
                    "topology.declared-write-paths",
                    "error",
                    {"child_index": index, "errors": write_errors},
                    "Use unique canonical relative declared write paths.",
                )
            )
        target_paths = child.get("integration_target_paths")
        target_errors = _validate_relative_paths(target_paths)
        if target_errors:
            findings.append(
                _finding(
                    "topology.target-paths",
                    "error",
                    {"child_index": index, "errors": target_errors},
                    "Use unique canonical relative integration target paths.",
                )
            )
        elif isolation == "mutable-isolated":
            if not target_paths:
                findings.append(
                    _finding(
                        "topology.target-paths",
                        "error",
                        {"child_index": index, "reason": "mutable-targets-empty"},
                        "Declare at least one integration target for a mutable child.",
                    )
                )
            else:
                mutable_targets.extend((index, str(path)) for path in target_paths)
        elif isolation == "read-only-shared" and target_paths:
            findings.append(
                _finding(
                    "topology.target-paths",
                    "error",
                    {"child_index": index, "reason": "read-only-targets-present"},
                    "Remove integration targets from read-only children.",
                )
            )
        if isolation == "read-only-shared" and write_paths:
            findings.append(
                _finding(
                    "topology.declared-write-paths",
                    "error",
                    {"child_index": index, "reason": "read-only-writes-present"},
                    "Remove declared writes from read-only children.",
                )
            )
        if isolation == "mutable-isolated" and not write_errors and not target_errors:
            if not write_paths:
                findings.append(
                    _finding(
                        "topology.declared-write-paths",
                        "error",
                        {"child_index": index, "reason": "mutable-writes-empty"},
                        "Declare at least one write path for a mutable child.",
                    )
                )
            else:
                for write_path in write_paths:
                    write_parts = PurePosixPath(str(write_path)).parts
                    if not any(
                        PurePosixPath(str(target)).parts
                        == write_parts[: len(PurePosixPath(str(target)).parts)]
                        for target in target_paths
                    ):
                        findings.append(
                            _finding(
                                "topology.write-outside-target",
                                "error",
                                {
                                    "child_index": index,
                                    "write_path_sha256": _value_sha256(write_path),
                                },
                                "Keep every declared write under an integration target.",
                            )
                        )

    for field, values in identities.items():
        comparable = [value for value in values if value is not None]
        if len(comparable) != len(set(comparable)):
            findings.append(
                _finding(
                    "identity.unique-child-binding",
                    "error",
                    {"field": field},
                    "Use a unique value for every child identity and nonce field.",
                )
            )

    if budgets_complete and isinstance(aggregate_budget, Mapping):
        expected = {field: int(aggregate_budget[field]) for field in BUDGET_FIELDS}
        if budget_sum != expected:
            findings.append(
                _finding(
                    "budget.aggregate-equality",
                    "error",
                    {"aggregate": expected, "per_child_sum": budget_sum},
                    "Make per-child hard budgets add up exactly to the aggregate authorization.",
                )
            )

    for index, (left_child, left) in enumerate(mutable_targets):
        left_parts = PurePosixPath(left).parts
        for right_child, right in mutable_targets[index + 1 :]:
            if left_child == right_child:
                continue
            right_parts = PurePosixPath(right).parts
            if (
                left_parts == right_parts[: len(left_parts)]
                or right_parts == left_parts[: len(right_parts)]
            ):
                findings.append(
                    _finding(
                        "topology.mutable-overlap",
                        "error",
                        {
                            "left_child_index": left_child,
                            "right_child_index": right_child,
                            "left_path_sha256": _value_sha256(left),
                            "right_path_sha256": _value_sha256(right),
                        },
                        "Assign non-overlapping mutable integration targets.",
                    )
                )

    findings.extend(
        _safe_directory_findings(
            request_map.get("artifact_directories"),
            integration_root=integration_root,
            worktrees=worktrees,
        )
    )

    fallback = request_map.get("fallback")
    fallback_shape = _shape_finding(
        "fallback.shape", fallback, FALLBACK_FIELDS, "fallback"
    )
    if fallback_shape is not None:
        findings.append(fallback_shape)
    if not isinstance(fallback, Mapping) or any(
        not _nonempty(fallback.get(field)) for field in FALLBACK_FIELDS
    ):
        findings.append(
            _finding(
                "fallback.declared",
                "error",
                {"fallback_sha256": _value_sha256(fallback)},
                "Declare both main-thread and recovery fallback modes.",
            )
        )

    if request_map.get("productive_dogfood_delivery_prerequisite") is not False:
        findings.append(
            _finding(
                "delivery.productive-dogfood-prerequisite",
                "error",
                {
                    "observed_sha256": _value_sha256(
                        request_map.get("productive_dogfood_delivery_prerequisite")
                    )
                },
                "Keep productive dogfood explicitly outside the repair delivery gate.",
            )
        )

    certification = request_map.get("callback_certification")
    certification_shape = _shape_finding(
        "scheduling.certification-shape",
        certification,
        CALLBACK_CERTIFICATION_FIELDS,
        "callback_certification",
    )
    if certification_shape is not None:
        findings.append(certification_shape)
    if isinstance(certification, Mapping) and _integer(requested_workers, 1):
        try:
            admission = evaluate_scheduling_admission(
                requested_workers,
                certification.get("certified_callback_max_ms"),
                certification.get("certified_scheduler_overhead_ms"),
                request_map.get("poll_interval_ms"),
            )
        except NativePoolPreflightError as exc:
            findings.append(
                _finding(
                    "scheduling.certification",
                    "error",
                    {"error": str(exc)},
                    "Provide the complete certified callback envelope and poll interval.",
                )
            )
        else:
            if not admission["accepted"]:
                findings.append(
                    _finding(
                        "scheduling.response-time-bound",
                        "error",
                        admission,
                        "Reduce N or improve independently certified callback ceilings.",
                    )
                )

    contract = request_map.get("pool_contract")
    contract_sha256: str | None = None
    if stage == "pre-allocation":
        if contract is not None:
            findings.append(
                _finding(
                    "contract.preallocation-absence",
                    "error",
                    {"contract_sha256": _value_sha256(contract)},
                    "Leave pool_contract null until the exact contract is rendered.",
                )
            )
    elif stage == "pre-dispatch":
        if not isinstance(contract, Mapping):
            findings.append(
                _finding(
                    "contract.required",
                    "error",
                    {"observed_type": type(contract).__name__},
                    "Provide the exact rendered pool contract before dispatch.",
                )
            )
        else:
            contract_sha256 = (
                str(contract.get("contract_sha256"))
                if isinstance(contract.get("contract_sha256"), str)
                else None
            )
            contract_errors = validate_pool_contract(
                contract,
                capacity_limits=capacity_limits,
            )
            if contract_errors:
                findings.append(
                    _finding(
                        "contract.integrity",
                        "error",
                        {"errors": contract_errors},
                        "Render a valid sealed pool contract from trusted inputs.",
                    )
                )
            binding_errors: list[str] = []
            for request_field, contract_field in (
                ("pool_id", "pool_id"),
                ("pool_epoch", "pool_epoch"),
                ("requested_workers", "max_active_workers"),
                ("aggregate_hard_budget", "aggregate_hard_budget"),
            ):
                if request_map.get(request_field) != contract.get(contract_field):
                    binding_errors.append(
                        f"{request_field}-to-{contract_field}-mismatch"
                    )
            contract_children = contract.get("children")
            if not isinstance(contract_children, list) or len(contract_children) != len(
                normalized_children
            ):
                binding_errors.append("children-cardinality-mismatch")
            else:
                for index, (effective, rendered) in enumerate(
                    zip(normalized_children, contract_children)
                ):
                    if not isinstance(rendered, Mapping):
                        binding_errors.append(f"child[{index}]-not-object")
                        continue
                    for field in (
                        "child_id",
                        "packet_id",
                        "packet_sha256",
                        "attempt_nonce",
                        "session_id",
                        "agent_id",
                        "lease_id",
                        "isolation_class",
                        "completion_evidence_policy",
                        "tool_policy",
                        "declared_write_paths",
                        "integration_target_paths",
                    ):
                        if effective.get(field) != rendered.get(field):
                            binding_errors.append(f"child[{index}]-{field}-mismatch")
            scheduler = contract.get("scheduler")
            if isinstance(scheduler, Mapping) and isinstance(certification, Mapping):
                callback_max = certification.get("certified_callback_max_ms")
                expected_check = (
                    callback_max.get("check")
                    if isinstance(callback_max, Mapping)
                    and capacity_limits.requires_capability_receipt(
                        request_map.get("requested_workers")
                    )
                    else None
                )
                expected_overhead = (
                    certification.get("certified_scheduler_overhead_ms")
                    if capacity_limits.requires_capability_receipt(
                        request_map.get("requested_workers")
                    )
                    else None
                )
                if scheduler.get("certified_max_check_ms") != expected_check:
                    binding_errors.append("scheduler-check-certification-mismatch")
                if (
                    scheduler.get("certified_max_scheduler_overhead_ms")
                    != expected_overhead
                ):
                    binding_errors.append("scheduler-overhead-certification-mismatch")
                if scheduler.get("poll_interval_ms") != request_map.get(
                    "poll_interval_ms"
                ):
                    binding_errors.append("scheduler-poll-interval-mismatch")
            if binding_errors:
                findings.append(
                    _finding(
                        "contract.effective-environment-binding",
                        "error",
                        {"errors": sorted(set(binding_errors))},
                        "Re-render from the exact effective environment and re-run preflight.",
                    )
                )

    findings, override_provenance = _apply_overrides(
        findings, request_map, override_authorization
    )
    findings.sort(
        key=lambda item: (
            item["rule_id"],
            item["severity"],
            canonical_sha256(item["evidence"]),
        )
    )
    accepted = not any(
        item["severity"] == "error" and item["overridden"] is not True
        for item in findings
    )
    result = {
        "result_type": PREFLIGHT_RESULT_TYPE,
        "version": PREFLIGHT_VERSION,
        "schema": PREFLIGHT_RESULT_SCHEMA,
        "stage": stage if stage in PREFLIGHT_STAGES else None,
        "request_sha256": request_sha256,
        "contract_sha256": contract_sha256,
        "decision": "accept" if accepted else "reject",
        "accepted": accepted,
        "findings": findings,
        "override_authority": override_provenance,
    }
    result["result_sha256"] = canonical_sha256(result)
    return result


def validate_pool_preflight_result(
    value: Any,
    *,
    expected_stage: str | None = None,
    expected_contract_sha256: str | None = None,
) -> list[str]:
    """Validate a sanitized preflight receipt without replaying raw inputs."""

    if not isinstance(value, Mapping):
        return ["preflight-result-must-be-object"]
    errors: list[str] = []
    result = dict(value)
    missing = sorted(RESULT_FIELDS - set(result))
    unknown = sorted(set(result) - RESULT_FIELDS)
    if missing:
        errors.append("preflight-result-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("preflight-result-unknown-fields:" + ",".join(unknown))
    if (
        result.get("result_type") != PREFLIGHT_RESULT_TYPE
        or result.get("version") != PREFLIGHT_VERSION
        or result.get("schema") != PREFLIGHT_RESULT_SCHEMA
    ):
        errors.append("preflight-result-header-invalid")
    stage = result.get("stage")
    if stage not in PREFLIGHT_STAGES:
        errors.append("preflight-result-stage-invalid")
    if expected_stage is not None and stage != expected_stage:
        errors.append("preflight-result-stage-mismatch")
    if not _sha256(result.get("request_sha256")):
        errors.append("preflight-result-request-sha256-invalid")
    contract_sha256 = result.get("contract_sha256")
    if stage == "pre-allocation" and contract_sha256 is not None:
        errors.append("preflight-result-preallocation-contract-unexpected")
    if stage == "pre-dispatch" and not _sha256(contract_sha256):
        errors.append("preflight-result-predispatch-contract-invalid")
    if (
        expected_contract_sha256 is not None
        and contract_sha256 != expected_contract_sha256
    ):
        errors.append("preflight-result-contract-mismatch")

    findings = result.get("findings")
    normalized_findings: list[Mapping[str, Any]] = []
    if not isinstance(findings, list):
        errors.append("preflight-result-findings-invalid")
    else:
        for index, raw in enumerate(findings):
            if not isinstance(raw, Mapping) or set(raw) != set(FINDING_FIELDS):
                errors.append(f"preflight-result-finding[{index}]-fields-invalid")
                continue
            finding = dict(raw)
            normalized_findings.append(finding)
            if not _nonempty(finding.get("rule_id")):
                errors.append(f"preflight-result-finding[{index}]-rule-id-invalid")
            if finding.get("severity") not in {"error", "warning", "info"}:
                errors.append(f"preflight-result-finding[{index}]-severity-invalid")
            if not isinstance(finding.get("evidence"), Mapping):
                errors.append(f"preflight-result-finding[{index}]-evidence-invalid")
            if not _nonempty(finding.get("remediation")):
                errors.append(f"preflight-result-finding[{index}]-remediation-invalid")
            if not isinstance(finding.get("waivable"), bool) or not isinstance(
                finding.get("overridden"), bool
            ):
                errors.append(
                    f"preflight-result-finding[{index}]-override-state-invalid"
                )
            authority = finding.get("authority_provenance")
            if finding.get("overridden") is True:
                if finding.get("waivable") is not True:
                    errors.append(
                        f"preflight-result-finding[{index}]-nonwaivable-override"
                    )
                if not _sha256(finding.get("override_reason_sha256")):
                    errors.append(
                        f"preflight-result-finding[{index}]-override-reason-invalid"
                    )
                authority_errors = validate_authority_provenance(authority)
                errors.extend(
                    f"preflight-result-finding[{index}]-authority:{item}"
                    for item in authority_errors
                )
                if isinstance(authority, Mapping) and (
                    authority.get("source_type") != "operator-directive"
                    or authority.get("actor_role") != "operator"
                ):
                    errors.append(
                        f"preflight-result-finding[{index}]-operator-authority-invalid"
                    )
            elif (
                finding.get("override_reason_sha256") is not None
                or authority is not None
            ):
                errors.append(
                    f"preflight-result-finding[{index}]-inactive-override-evidence"
                )

    observed_accepted = not any(
        item.get("severity") == "error" and item.get("overridden") is not True
        for item in normalized_findings
    )
    if result.get("accepted") is not observed_accepted:
        errors.append("preflight-result-accepted-mismatch")
    expected_decision = "accept" if observed_accepted else "reject"
    if result.get("decision") != expected_decision:
        errors.append("preflight-result-decision-mismatch")
    override_authority = result.get("override_authority")
    if override_authority is not None:
        authority_errors = validate_authority_provenance(override_authority)
        errors.extend(
            "preflight-result-override-authority:" + item for item in authority_errors
        )
        if isinstance(override_authority, Mapping) and (
            override_authority.get("source_type") != "operator-directive"
            or override_authority.get("actor_role") != "operator"
        ):
            errors.append("preflight-result-override-authority-invalid")
    for index, finding in enumerate(normalized_findings):
        if (
            finding.get("overridden") is True
            and finding.get("authority_provenance") != override_authority
        ):
            errors.append(
                f"preflight-result-finding[{index}]-override-authority-mismatch"
            )
    observed_hash = result.get("result_sha256")
    unsigned = dict(result)
    unsigned.pop("result_sha256", None)
    if not _sha256(observed_hash) or observed_hash != canonical_sha256(unsigned):
        errors.append("preflight-result-sha256-mismatch")
    return sorted(set(errors))


def require_pool_preflight(
    request: Mapping[str, Any],
    *,
    override_authorization: VerifiedPoolPreflightOverride | None = None,
) -> dict[str, Any]:
    """Run preflight and raise with stable rule IDs when dispatch is forbidden."""

    result = run_pool_preflight(request, override_authorization=override_authorization)
    if result["accepted"] is not True:
        rules = sorted(
            {
                item["rule_id"]
                for item in result["findings"]
                if item["severity"] == "error" and item["overridden"] is not True
            }
        )
        raise NativePoolPreflightError("pool-preflight-rejected:" + ",".join(rules))
    return result


def default_callback_certification() -> dict[str, Any]:
    """Return the exact repository-certified callback inputs for launchers."""

    return {
        "certified_callback_max_ms": dict(CERTIFIED_CALLBACK_MAX_MS),
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
    }
