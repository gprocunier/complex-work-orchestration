"""Typed capacity policy and schema-parity helpers for native pools."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from .paths import REPO_ROOT
from .policy import load_policy


CAPACITY_POLICY_VERSION = 1
CAPACITY_POLICY_FIELDS = frozenset(
    {
        "version",
        "default_max_active_workers",
        "released_max_active_workers",
        "hard_max_active_workers",
        "concurrency_enabled_by_default",
        "requires_explicit_opt_in",
        "requires_fresh_capability_receipt",
        "operator_activation_required_for_increase",
    }
)
CAPACITY_SCHEMA_PATHS = (
    "schemas/native-supervision-pool-contract.schema.json",
    "schemas/native-supervision-pool-contract-v2.schema.json",
    "schemas/native-supervision-pool-decision.schema.json",
    "schemas/native-supervision-pool-preflight-request.schema.json",
    "schemas/native-supervision-pool-preflight-request-v2.schema.json",
    "schemas/native-supervision-pool-receipt.schema.json",
    "schemas/native-supervision-pool-receipt-v2.schema.json",
    "schemas/native-supervision-pool-render-request.schema.json",
    "schemas/native-supervision-pool-render-request-v2.schema.json",
    "schemas/native-pool-admission-reservation.schema.json",
    "schemas/native-supervision-pool-state.schema.json",
    "schemas/native-supervision-adapter-capability-receipt.schema.json",
    "schemas/audit-event.schema.json",
)


class NativePoolCapacityPolicyError(ValueError):
    """Raised when the canonical pool-capacity policy is malformed."""


@dataclass(frozen=True, slots=True)
class PoolCapacityLimits:
    """Validated limits loaded from ``native-worker-execution.yaml``."""

    default_max_active_workers: int
    released_max_active_workers: int
    hard_max_active_workers: int
    concurrency_enabled_by_default: bool
    requires_explicit_opt_in: bool
    requires_fresh_capability_receipt: bool
    operator_activation_required_for_increase: bool

    @property
    def supported_capacities(self) -> tuple[int, ...]:
        return tuple(range(1, self.hard_max_active_workers + 1))

    def validates_requested_capacity(self, requested: Any) -> bool:
        return (
            isinstance(requested, int)
            and not isinstance(requested, bool)
            and 1 <= requested <= self.hard_max_active_workers
        )

    def is_released(self, requested: Any) -> bool:
        return self.validates_requested_capacity(requested) and (
            requested <= self.released_max_active_workers
        )

    def requires_concurrency_opt_in(self, requested: Any) -> bool:
        return self.validates_requested_capacity(requested) and (
            requested > self.default_max_active_workers
        )

    def requires_capability_receipt(self, requested: Any) -> bool:
        return self.validates_requested_capacity(requested) and requested > 1


def _strict_integer(value: Any, *, minimum: int = 1) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _capacity_mapping(
    policy_document: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    document = (
        policy_document
        if policy_document is not None
        else load_policy("native-worker-execution")
    )
    pool = document.get("native_supervision_pool")
    if not isinstance(pool, Mapping):
        raise NativePoolCapacityPolicyError("native-supervision-pool-policy-missing")
    capacity = pool.get("capacity")
    if not isinstance(capacity, Mapping):
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-missing"
        )
    unknown = sorted(set(capacity) - CAPACITY_POLICY_FIELDS)
    missing = sorted(CAPACITY_POLICY_FIELDS - set(capacity))
    if unknown:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-unknown-fields:"
            + ",".join(unknown)
        )
    if missing:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-missing-fields:"
            + ",".join(missing)
        )
    return capacity


def load_pool_capacity(
    policy_document: Mapping[str, Any] | None = None,
) -> PoolCapacityLimits:
    """Load and validate the repository's one operative capacity source."""

    capacity = _capacity_mapping(policy_document)
    if capacity.get("version") != CAPACITY_POLICY_VERSION:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-version-invalid"
        )
    integer_fields = (
        "default_max_active_workers",
        "released_max_active_workers",
        "hard_max_active_workers",
    )
    for field in integer_fields:
        if not _strict_integer(capacity.get(field)):
            raise NativePoolCapacityPolicyError(
                f"native-supervision-pool-capacity-policy-invalid:{field}"
            )
    boolean_fields = (
        "concurrency_enabled_by_default",
        "requires_explicit_opt_in",
        "requires_fresh_capability_receipt",
        "operator_activation_required_for_increase",
    )
    for field in boolean_fields:
        if not isinstance(capacity.get(field), bool):
            raise NativePoolCapacityPolicyError(
                f"native-supervision-pool-capacity-policy-invalid:{field}"
            )

    limits = PoolCapacityLimits(
        default_max_active_workers=int(capacity["default_max_active_workers"]),
        released_max_active_workers=int(capacity["released_max_active_workers"]),
        hard_max_active_workers=int(capacity["hard_max_active_workers"]),
        concurrency_enabled_by_default=bool(capacity["concurrency_enabled_by_default"]),
        requires_explicit_opt_in=bool(capacity["requires_explicit_opt_in"]),
        requires_fresh_capability_receipt=bool(
            capacity["requires_fresh_capability_receipt"]
        ),
        operator_activation_required_for_increase=bool(
            capacity["operator_activation_required_for_increase"]
        ),
    )
    if not (
        limits.default_max_active_workers
        <= limits.released_max_active_workers
        <= limits.hard_max_active_workers
    ):
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-order-invalid"
        )
    if limits.default_max_active_workers != 1:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-default-must-be-one"
        )
    if limits.concurrency_enabled_by_default:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-concurrency-default-invalid"
        )
    if not limits.requires_explicit_opt_in:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-opt-in-required"
        )
    if not limits.requires_fresh_capability_receipt:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-capability-required"
        )
    if not limits.operator_activation_required_for_increase:
        raise NativePoolCapacityPolicyError(
            "native-supervision-pool-capacity-policy-operator-activation-required"
        )
    return limits


def operative_pool_policy(
    policy_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the checked-in operative policy, rejecting caller substitutions.

    Alternate policy documents remain useful to offline evaluators, but a
    productive reservation or launch must not turn such a document into live
    capacity authority.
    """

    operative = load_policy("native-worker-execution")
    try:
        operative_copy = json.loads(
            json.dumps(operative, separators=(",", ":"))
        )
        operative_snapshot = json.loads(
            json.dumps(operative_copy, sort_keys=True, separators=(",", ":"))
        )
        supplied_snapshot = (
            operative_snapshot
            if policy_document is None
            else json.loads(
                json.dumps(policy_document, sort_keys=True, separators=(",", ":"))
            )
        )
    except (TypeError, ValueError) as error:
        raise NativePoolCapacityPolicyError(
            "productive-pool-policy-not-canonical-json"
        ) from error
    if supplied_snapshot != operative_snapshot:
        raise NativePoolCapacityPolicyError(
            "productive-pool-policy-not-operative"
        )
    return operative_copy


def load_operative_pool_capacity(
    policy_document: Mapping[str, Any] | None = None,
) -> PoolCapacityLimits:
    """Load productive limits only from the exact checked-in policy."""

    return load_pool_capacity(operative_pool_policy(policy_document))


def _schema_documents(
    repo_root: Path,
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for relative in CAPACITY_SCHEMA_PATHS:
        path = repo_root / relative
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise NativePoolCapacityPolicyError(
                f"pool-capacity-schema-unreadable:{relative}:{type(error).__name__}"
            ) from error
        if not isinstance(value, dict):
            raise NativePoolCapacityPolicyError(
                f"pool-capacity-schema-not-object:{relative}"
            )
        documents[relative] = value
    return documents


def _contract_capacity_rule(capacity: int) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "children": {"minItems": capacity, "maxItems": capacity},
    }
    if capacity == 1:
        properties["scheduler"] = {
            "properties": {
                "certified_max_check_ms": {"type": "null"},
                "certified_max_scheduler_overhead_ms": {"type": "null"},
            },
        }
        properties["capability_receipt_sha256"] = {"type": "null"}
    else:
        properties["capability_receipt_sha256"] = {"$ref": "#/$defs/sha256"}
    return {
        "if": {"properties": {"max_active_workers": {"const": capacity}}},
        "then": {"properties": properties},
    }


def _set_capacity_constraints(
    documents: Mapping[str, dict[str, Any]],
    limits: PoolCapacityLimits,
) -> None:
    hard = limits.hard_max_active_workers
    capacities = list(limits.supported_capacities)

    # Both contract versions support the bounded offline N=3 fixture.
    # Productive admission remains gated by the live released limit.
    versions = ("", "-v2")
    for version in versions:
        contract = documents[f"schemas/native-supervision-pool-contract{version}.schema.json"]
        contract["properties"]["children"]["maxItems"] = hard
        contract["properties"]["max_active_workers"] = {"enum": capacities}
        contract["$defs"]["child"]["properties"]["ordinal"]["maximum"] = hard - 1
        contract["allOf"] = [_contract_capacity_rule(capacity) for capacity in capacities]

    for version in versions:
        render = documents[f"schemas/native-supervision-pool-render-request{version}.schema.json"]
        render["properties"]["max_active_workers"] = {"enum": capacities}
        render["properties"]["children"]["maxItems"] = hard

    state = documents["schemas/native-supervision-pool-state.schema.json"]
    state["properties"]["scheduler_cursor"]["maximum"] = hard - 1
    state["properties"]["children"]["maxItems"] = hard
    state["$defs"]["child"]["properties"]["ordinal"]["maximum"] = hard - 1

    decision = documents["schemas/native-supervision-pool-decision.schema.json"]
    decision["properties"]["deadlines"]["maxItems"] = hard

    for version in versions:
        receipt = documents[f"schemas/native-supervision-pool-receipt{version}.schema.json"]
        for field in (
            "admission_order",
            "terminal_order",
            "child_dispositions",
            "child_terminal_receipts",
            "lease_evidence",
        ):
            receipt["properties"][field]["maxItems"] = hard

    preflight = documents["schemas/native-supervision-pool-preflight-request.schema.json"]["properties"]
    preflight["released_capacity"]["maximum"] = hard

    admitted_preflight = documents[
        "schemas/native-supervision-pool-preflight-request-v2.schema.json"
    ]["properties"]
    for field in ("requested_workers", "released_capacity"):
        admitted_preflight[field]["maximum"] = hard
    admitted_preflight["children"]["maxItems"] = hard

    reservation = documents["schemas/native-pool-admission-reservation.schema.json"]
    admission_fields = ("issue_ids", "child_bindings")
    for field in (*admission_fields, "retained_owned_issue_ids"):
        reservation["properties"][field]["maxItems"] = hard
    for rule in reservation["allOf"]:
        condition = rule.get("if", {}).get("properties", {}).get("status", {})
        if condition.get("const") == "admitted":
            for field in admission_fields:
                rule["then"]["properties"][field]["maxItems"] = hard

    capability = documents[
        "schemas/native-supervision-adapter-capability-receipt.schema.json"
    ]
    capability["properties"]["requested_cap"] = {
        "type": "integer",
        "minimum": 2,
        "maximum": hard,
    }

    audit = documents["schemas/audit-event.schema.json"]
    summary = audit["properties"]["native_pool_summary"]["properties"]
    for field in (
        "max_active_workers",
        "configured_workers",
        "admitted_workers",
        "executing_workers",
        "terminal_workers",
    ):
        summary[field]["maximum"] = hard


def expected_capacity_schema_documents(
    *,
    repo_root: Path = REPO_ROOT,
    limits: PoolCapacityLimits | None = None,
) -> dict[str, dict[str, Any]]:
    """Return schemas with all capacity constraints derived from policy."""

    effective_limits = limits or load_pool_capacity()
    documents = _schema_documents(repo_root)
    _set_capacity_constraints(documents, effective_limits)
    return documents


def capacity_schema_errors(
    *,
    repo_root: Path = REPO_ROOT,
    limits: PoolCapacityLimits | None = None,
) -> list[str]:
    """Report any schema constraint that drifted from canonical policy."""

    effective_limits = limits or load_pool_capacity()
    observed = _schema_documents(repo_root)
    expected = _schema_documents(repo_root)
    _set_capacity_constraints(expected, effective_limits)
    return [
        f"pool-capacity-schema-drift:{relative}"
        for relative in CAPACITY_SCHEMA_PATHS
        if observed[relative] != expected[relative]
    ]


def write_capacity_schema_documents(
    *,
    repo_root: Path = REPO_ROOT,
    limits: PoolCapacityLimits | None = None,
) -> tuple[str, ...]:
    """Regenerate capacity-bound schemas after the one policy edit."""

    documents = expected_capacity_schema_documents(
        repo_root=repo_root,
        limits=limits,
    )
    changed: list[str] = []
    for relative, document in documents.items():
        path = repo_root / relative
        rendered = json.dumps(document, indent=2, sort_keys=False) + "\n"
        if path.read_text(encoding="utf-8") != rendered:
            path.write_text(rendered, encoding="utf-8")
            changed.append(relative)
    return tuple(changed)
