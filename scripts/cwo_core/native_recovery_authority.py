"""Process-local recovery capabilities for native supervisor admission.

Serialized retry receipts and recovery decisions are audit evidence only.  This
module retains the exact object identity of a recovery action and its immutable
scalar bindings.  Phase 1 can mint only provisional, non-dispatching actions;
P1-13B must provide the future ledger-origin admission authority before the
native supervisor may turn one into productive execution.
"""

from __future__ import annotations

import json
import fcntl
import os
import stat
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, Iterator

from cwo_core.native_recovery_policy import (
    PROVISIONAL_ADMISSION_GRADE,
    canonical_recovery_json,
    canonical_recovery_sha256,
    validate_recovery_audit_decision,
)
from cwo_core.native_live_allocation_ledger import (
    NativeLiveAllocationLedgerError,
    NativeLiveAllocationLedgerStore,
    VerifiedContainedTurnDispatch,
)
from cwo_core.native_retry import validate_retry_authorization


_ACTION_MINT = object()
_STORE_MINT = object()


class RecoveryAuthorityError(ValueError):
    """Raised when a recovery capability or one of its bindings fails closed."""


class VerifiedRecoveryAction:
    """Opaque process-local handle retained by exactly one action store."""

    __slots__ = ()

    def __new__(cls, mint: object | None = None) -> VerifiedRecoveryAction:
        if cls is not VerifiedRecoveryAction or mint is not _ACTION_MINT:
            raise TypeError("verified-recovery-action-mint-forbidden")
        return super().__new__(cls)

    def __reduce__(self) -> object:
        raise TypeError("verified-recovery-action-serialization-forbidden")


@dataclass(frozen=True)
class _RecoveryActionBinding:
    projection: tuple[tuple[str, str | int | bool], ...]


def _safe_projection(
    retry_authorization: Mapping[str, Any],
    recovery_decision: Mapping[str, Any],
) -> dict[str, str | int | bool]:
    projection: dict[str, str | int | bool] = {
        "retry_receipt_sha256": retry_authorization["receipt_sha256"],
        "retry_evidence_sha256": retry_authorization["retry_evidence_sha256"],
        "retry_packet_id": retry_authorization["retry_packet_id"],
        "bead_id": retry_authorization["bead_id"],
        "requested_model": retry_authorization["requested_model"],
        "attested_model": retry_authorization["attested_model"],
        "work_sha256": retry_authorization["work_sha256"],
        "attempt_from": retry_authorization["attempt_from"],
        "attempt_to": retry_authorization["attempt_to"],
        "recovery_decision_sha256": recovery_decision["decision_sha256"],
        "evidence_sha256": recovery_decision["evidence_sha256"],
        "classification_evidence_sha256": recovery_decision[
            "classification_evidence_sha256"
        ],
        "recovery_class": recovery_decision["recovery_class"],
        "recovery_action": recovery_decision["action"],
        "fixed_cohort_sha256": recovery_decision["fixed_cohort_sha256"],
        "admitted_bead_id": recovery_decision["admitted_bead_id"],
        "admitted_child_sha256": recovery_decision["admitted_child_sha256"],
        "admission_grade": recovery_decision["admission_grade"],
        "dispatch_authorized": recovery_decision["dispatch_authorized"],
        "newly_ready_refill_allowed": recovery_decision[
            "newly_ready_refill_allowed"
        ],
        "fixed_cohort_required": recovery_decision["fixed_cohort_required"],
    }
    projection["projection_sha256"] = canonical_recovery_sha256(
        projection,
        domain="native-recovery-supervisor-action-audit-v1",
    )
    return projection


def _canonical_plain_snapshot(value: Any, *, label: str) -> dict[str, Any]:
    """Snapshot an untrusted value once, then use only exact built-in objects."""

    try:
        rendered = canonical_recovery_json(value)
        snapshot = json.loads(rendered)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RecoveryAuthorityError(f"{label}-not-canonical-json") from exc
    if type(snapshot) is not dict or canonical_recovery_json(snapshot) != rendered:
        raise RecoveryAuthorityError(f"{label}-not-canonical-object")
    return snapshot


def _require_exact_recovery_decision_types(decision: Mapping[str, Any]) -> None:
    string_fields = {
        "decision_type",
        "schema",
        "recovery_class",
        "action",
        "stop_scope",
        "required_authority",
        "classification_evidence_sha256",
        "evidence_sha256",
        "fixed_cohort_sha256",
        "admitted_bead_id",
        "admitted_child_sha256",
        "admission_grade",
        "decision_sha256",
    }
    integer_fields = {
        "version",
        "replacement_budget",
        "replacement_count",
        "replacements_remaining",
        "construction_attempt_budget",
        "construction_attempt_count",
        "construction_attempts_remaining",
    }
    boolean_fields = {
        "dispatch_authorized",
        "newly_ready_refill_allowed",
        "fixed_cohort_required",
    }
    if (
        any(type(decision.get(field)) is not str for field in string_fields)
        or any(type(decision.get(field)) is not int for field in integer_fields)
        or any(type(decision.get(field)) is not bool for field in boolean_fields)
        or type(decision.get("signals")) is not dict
        or any(
            type(value) is not bool
            for value in decision.get("signals", {}).values()
        )
    ):
        raise RecoveryAuthorityError("recovery-decision-exact-types-invalid")


class RecoveryActionStore:
    """One-shot identity registry for provisional recovery actions.

    The public factory intentionally cannot mint dispatch authority.  It only
    binds a valid retry receipt to a valid P1-7 provisional recovery decision.
    A later package may add a separate trusted admission factory; weakening
    this factory is not that interface.
    """

    __slots__ = ("_entries", "_lock", "_mint")

    def __init__(self) -> None:
        self._entries: dict[
            int, tuple[VerifiedRecoveryAction, _RecoveryActionBinding]
        ] = {}
        self._lock = Lock()
        self._mint = _STORE_MINT

    def _require_exact_store(self) -> None:
        if (
            type(self) is not RecoveryActionStore
            or getattr(self, "_mint", None) is not _STORE_MINT
        ):
            raise RecoveryAuthorityError("recovery-action-store-invalid")

    def issue_provisional(
        self,
        retry_authorization: Mapping[str, Any],
        recovery_decision: Mapping[str, Any],
    ) -> VerifiedRecoveryAction:
        """Retain one exact non-dispatching action for in-process inspection."""

        self._require_exact_store()
        retry_snapshot = _canonical_plain_snapshot(
            retry_authorization,
            label="recovery-action-retry-authorization",
        )
        decision_snapshot = _canonical_plain_snapshot(
            recovery_decision,
            label="recovery-action-decision",
        )
        _require_exact_recovery_decision_types(decision_snapshot)
        if (
            any(
                type(retry_snapshot.get(field)) is not str
                for field in (
                    "receipt_sha256",
                    "retry_evidence_sha256",
                    "retry_packet_id",
                    "bead_id",
                    "requested_model",
                    "attested_model",
                    "work_sha256",
                )
            )
            or type(retry_snapshot.get("attempt_from")) is not int
            or type(retry_snapshot.get("attempt_to")) is not int
        ):
            raise RecoveryAuthorityError(
                "recovery-action-retry-binding-exact-types-invalid"
            )
        retry_errors = validate_retry_authorization(retry_snapshot)
        if retry_errors:
            raise RecoveryAuthorityError(
                "recovery-action-retry-authorization-invalid:"
                + ";".join(retry_errors)
            )
        decision_errors = validate_recovery_audit_decision(decision_snapshot)
        if decision_errors:
            raise RecoveryAuthorityError(
                "recovery-action-decision-invalid:" + ";".join(decision_errors)
            )
        if (
            decision_snapshot.get("admission_grade")
            != PROVISIONAL_ADMISSION_GRADE
            or decision_snapshot.get("dispatch_authorized") is not False
            or decision_snapshot.get("fixed_cohort_required") is not True
            or decision_snapshot.get("newly_ready_refill_allowed") is not False
        ):
            raise RecoveryAuthorityError(
                "recovery-action-factory-requires-provisional-fixed-cohort"
            )
        if decision_snapshot.get("admitted_bead_id") != retry_snapshot.get(
            "bead_id"
        ):
            raise RecoveryAuthorityError("recovery-action-bead-binding-mismatch")

        projection = _safe_projection(retry_snapshot, decision_snapshot)
        if any(
            type(value) not in {str, int, bool}
            for value in projection.values()
        ):
            raise RecoveryAuthorityError("recovery-action-projection-scalar-invalid")
        binding = _RecoveryActionBinding(tuple(projection.items()))
        capability = VerifiedRecoveryAction(_ACTION_MINT)
        with self._lock:
            key = id(capability)
            if key in self._entries:
                raise RecoveryAuthorityError("recovery-action-identity-collision")
            self._entries[key] = (capability, binding)
        return capability

    def _binding_locked(
        self, action: object
    ) -> tuple[int, _RecoveryActionBinding]:
        if type(action) is not VerifiedRecoveryAction:
            raise RecoveryAuthorityError("verified-recovery-action-type-invalid")
        key = id(action)
        entry = self._entries.get(key)
        if entry is None or entry[0] is not action:
            raise RecoveryAuthorityError(
                "verified-recovery-action-not-registered-or-spent"
            )
        return key, entry[1]

    def inspect(
        self, action: object
    ) -> Mapping[str, str | int | bool]:
        """Return immutable scalar audit bindings without consuming the action."""

        self._require_exact_store()
        with self._lock:
            _, binding = self._binding_locked(action)
            return MappingProxyType(dict(binding.projection))

    def consume(
        self, action: object
    ) -> Mapping[str, str | int | bool]:
        """Atomically consume the exact registered object before side effects."""

        self._require_exact_store()
        with self._lock:
            key, binding = self._binding_locked(action)
            del self._entries[key]
            return MappingProxyType(dict(binding.projection))


FIXED_COHORT_STATE_TYPE = "cwo-native-fixed-cohort-recovery-controller"
FIXED_COHORT_STATE_VERSION = 1
FIXED_COHORT_STATE_SCHEMA = "cwo-native-fixed-cohort-recovery-controller:v1"
FIXED_COHORT_STATE_FILE = "controller-state.json"
FIXED_COHORT_LOCK_FILE = "controller.lock"

_FIXED_COHORT_STATE_FIELDS = frozenset(
    {
        "state_type",
        "version",
        "schema",
        "admission_grade",
        "dispatch_authorized",
        "fixed_cohort_sha256",
        "fixed_cohort",
        "bead_states",
        "revision",
        "state_sha256",
    }
)
_FIXED_COHORT_ITEM_FIELDS = frozenset(
    {"bead_id", "work_unit_id", "admitted_child_sha256"}
)
_FIXED_COHORT_BEAD_STATE_FIELDS = frozenset(
    {
        "bead_id",
        "replacement_count",
        "construction_attempt_count",
        "terminal",
    }
)
_FIXED_COHORT_ALLOWED_CLASSES = frozenset(
    {
        "deterministic-construction-failure",
        "pre-dispatch-transport-failure",
        "contained-semantic-no-op",
        "individual-child-failure",
    }
)
_FIXED_COHORT_CLASS_BOUNDARIES = MappingProxyType({
    "deterministic-construction-failure": (
        "verified-project-manager",
        "child",
    ),
    "pre-dispatch-transport-failure": (
        "pm-controller-plus-supervisor-policy",
        "child",
    ),
    "contained-semantic-no-op": (
        "pm-controller-plus-verified-containment",
        "child",
    ),
    "individual-child-failure": (
        "pm-controller-plus-verified-containment",
        "child",
    ),
})
_FIXED_COHORT_ALLOWED_ACTIONS = frozenset(
    {
        "reconstruct-same-admitted-bead",
        "replace-same-admitted-bead",
        "return-same-admitted-bead-to-main-thread",
    }
)
_FIXED_ACTION_BINDING_FIELDS = frozenset(
    {
        "decision_sha256",
        "evidence_sha256",
        "classification_evidence_sha256",
        "recovery_evidence_binding_sha256",
        "evidence_kind",
        "evidence_state_revision",
        "evidence_state_sha256",
        "ledger_result_sha256",
        "ledger_work_unit_id",
        "ledger_thread_id",
        "ledger_turn_intent_id",
        "ledger_turn_id",
        "ledger_dispatch_record_sha256",
        "ledger_dispatch_transport_binding_sha256",
        "ledger_containment_evidence_sha256",
        "ledger_containment_audit_event_hash",
        "fixed_cohort_sha256",
        "bead_id",
        "admitted_work_unit_id",
        "admitted_child_sha256",
        "replacement_count",
        "construction_attempt_count",
        "state_revision",
        "state_sha256",
        "recovery_class",
        "action",
        "required_authority",
        "stop_scope",
        "admission_grade",
        "dispatch_authorized",
        "execution_binding_sha256",
    }
)
_FIXED_EVIDENCE_BINDING_FIELDS = frozenset(
    {
        "recovery_class",
        "bead_id",
        "admitted_work_unit_id",
        "admitted_child_sha256",
        "evidence_sha256",
        "evidence_kind",
        "required_authority",
        "stop_scope",
        "evidence_state_revision",
        "evidence_state_sha256",
        "ledger_result_sha256",
        "ledger_work_unit_id",
        "ledger_thread_id",
        "ledger_turn_intent_id",
        "ledger_turn_id",
        "ledger_dispatch_record_sha256",
        "ledger_dispatch_transport_binding_sha256",
        "ledger_containment_evidence_sha256",
        "ledger_containment_audit_event_hash",
        "recovery_evidence_binding_sha256",
    }
)

_FIXED_ACTION_MINT = object()
_FIXED_STORE_MINT = object()
_FIXED_ROOT_MINT = object()
_FIXED_EVIDENCE_MINT = object()
_FIXED_ROOT_REGISTRY_LOCK = Lock()
_FIXED_ROOT_REGISTRY: dict[
    int,
    tuple[object, str, str, int, str, int, int, int, int],
] = {}


class FixedCohortControllerRoot:
    """Live, process-local root for one durable controller directory."""

    __slots__ = ()

    def __new__(cls, mint: object | None = None) -> FixedCohortControllerRoot:
        if cls is not FixedCohortControllerRoot or mint is not _FIXED_ROOT_MINT:
            raise TypeError("fixed-cohort-controller-root-mint-forbidden")
        return super().__new__(cls)

    def __reduce__(self) -> object:
        raise TypeError("fixed-cohort-controller-root-serialization-forbidden")


class VerifiedRecoveryEvidence:
    """Opaque one-shot source-evidence witness retained by one store."""

    __slots__ = ()

    def __new__(cls, mint: object | None = None) -> VerifiedRecoveryEvidence:
        if cls is not VerifiedRecoveryEvidence or mint is not _FIXED_EVIDENCE_MINT:
            raise TypeError("verified-recovery-evidence-mint-forbidden")
        return super().__new__(cls)

    def __reduce__(self) -> object:
        raise TypeError("verified-recovery-evidence-serialization-forbidden")


class VerifiedFixedCohortRecoveryAction:
    """Opaque one-shot handle for one durable provisional transition."""

    __slots__ = ()

    def __new__(
        cls, mint: object | None = None
    ) -> VerifiedFixedCohortRecoveryAction:
        if cls is not VerifiedFixedCohortRecoveryAction or mint is not _FIXED_ACTION_MINT:
            raise TypeError("verified-fixed-cohort-recovery-action-mint-forbidden")
        return super().__new__(cls)

    def __reduce__(self) -> object:
        raise TypeError(
            "verified-fixed-cohort-recovery-action-serialization-forbidden"
        )


@dataclass(frozen=True)
class _FixedCohortActionBinding:
    projection: tuple[tuple[str, str | int | bool], ...]


@dataclass(frozen=True)
class _RecoveryEvidenceBinding:
    projection: tuple[tuple[str, str | int | bool], ...]


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _normalize_fixed_cohort(value: Any) -> list[dict[str, str]]:
    if type(value) is not list or not value:
        raise RecoveryAuthorityError("fixed-cohort-must-be-nonempty-list")
    normalized: list[dict[str, str]] = []
    bead_ids: set[str] = set()
    work_unit_ids: set[str] = set()
    child_ids: set[str] = set()
    for item in value:
        if type(item) is not dict or set(item) != _FIXED_COHORT_ITEM_FIELDS:
            raise RecoveryAuthorityError("fixed-cohort-item-fields-invalid")
        bead_id = item["bead_id"]
        work_unit_id = item["work_unit_id"]
        child_sha256 = item["admitted_child_sha256"]
        if type(bead_id) is not str or not bead_id.strip():
            raise RecoveryAuthorityError("fixed-cohort-bead-id-invalid")
        if type(work_unit_id) is not str or not work_unit_id.strip():
            raise RecoveryAuthorityError("fixed-cohort-work-unit-id-invalid")
        if not _is_sha256(child_sha256):
            raise RecoveryAuthorityError("fixed-cohort-child-sha256-invalid")
        if (
            bead_id in bead_ids
            or work_unit_id in work_unit_ids
            or child_sha256 in child_ids
        ):
            raise RecoveryAuthorityError("fixed-cohort-item-duplicate")
        bead_ids.add(bead_id)
        work_unit_ids.add(work_unit_id)
        child_ids.add(child_sha256)
        normalized.append(
            {
                "bead_id": bead_id,
                "work_unit_id": work_unit_id,
                "admitted_child_sha256": child_sha256,
            }
        )
    return sorted(normalized, key=lambda item: item["bead_id"])


def fixed_cohort_sha256(value: Any) -> str:
    """Return the domain-separated identity of an exact sorted cohort."""

    normalized = _normalize_fixed_cohort(value)
    return canonical_recovery_sha256(
        normalized,
        domain="native-recovery-fixed-cohort-v1",
    )


def _state_sha256(state: Mapping[str, Any]) -> str:
    body = dict(state)
    body.pop("state_sha256", None)
    return canonical_recovery_sha256(
        body,
        domain="native-recovery-fixed-cohort-controller-state-v1",
    )


def _render_controller_state(state: Mapping[str, Any]) -> str:
    return canonical_recovery_json(dict(state)) + "\n"


def _validate_controller_state(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _FIXED_COHORT_STATE_FIELDS:
        raise RecoveryAuthorityError("fixed-cohort-state-fields-invalid")
    if (
        type(value.get("state_type")) is not str
        or value.get("state_type") != FIXED_COHORT_STATE_TYPE
        or type(value.get("version")) is not int
        or value.get("version") != FIXED_COHORT_STATE_VERSION
        or type(value.get("schema")) is not str
        or value.get("schema") != FIXED_COHORT_STATE_SCHEMA
        or type(value.get("admission_grade")) is not str
        or value.get("admission_grade") != PROVISIONAL_ADMISSION_GRADE
        or type(value.get("dispatch_authorized")) is not bool
        or value.get("dispatch_authorized") is not False
        or type(value.get("fixed_cohort_sha256")) is not str
        or type(value.get("state_sha256")) is not str
    ):
        raise RecoveryAuthorityError("fixed-cohort-state-header-invalid")
    revision = value.get("revision")
    if type(revision) is not int or revision < 0:
        raise RecoveryAuthorityError("fixed-cohort-state-revision-invalid")

    cohort = _normalize_fixed_cohort(value.get("fixed_cohort"))
    if cohort != value["fixed_cohort"]:
        raise RecoveryAuthorityError("fixed-cohort-state-order-invalid")
    cohort_sha256 = fixed_cohort_sha256(cohort)
    if value.get("fixed_cohort_sha256") != cohort_sha256:
        raise RecoveryAuthorityError("fixed-cohort-state-cohort-hash-mismatch")

    bead_states = value.get("bead_states")
    if type(bead_states) is not list or len(bead_states) != len(cohort):
        raise RecoveryAuthorityError("fixed-cohort-bead-states-invalid")
    expected_beads = [item["bead_id"] for item in cohort]
    observed_beads: list[str] = []
    expected_revision = 0
    for bead_state in bead_states:
        if (
            type(bead_state) is not dict
            or set(bead_state) != _FIXED_COHORT_BEAD_STATE_FIELDS
        ):
            raise RecoveryAuthorityError("fixed-cohort-bead-state-fields-invalid")
        bead_id = bead_state.get("bead_id")
        replacement_count = bead_state.get("replacement_count")
        construction_count = bead_state.get("construction_attempt_count")
        terminal = bead_state.get("terminal")
        if type(bead_id) is not str:
            raise RecoveryAuthorityError("fixed-cohort-bead-state-id-invalid")
        if type(replacement_count) is not int or replacement_count not in {0, 1}:
            raise RecoveryAuthorityError(
                "fixed-cohort-replacement-count-invalid"
            )
        if type(construction_count) is not int or construction_count not in {0, 1}:
            raise RecoveryAuthorityError(
                "fixed-cohort-construction-count-invalid"
            )
        if type(terminal) is not bool:
            raise RecoveryAuthorityError("fixed-cohort-terminal-invalid")
        if terminal and replacement_count == 0 and construction_count == 0:
            raise RecoveryAuthorityError(
                "fixed-cohort-terminal-without-used-budget"
            )
        expected_revision += replacement_count + construction_count + int(terminal)
        observed_beads.append(bead_id)
    if observed_beads != expected_beads:
        raise RecoveryAuthorityError("fixed-cohort-bead-state-order-invalid")
    if revision != expected_revision:
        raise RecoveryAuthorityError("fixed-cohort-state-revision-invariant-invalid")
    if not _is_sha256(value.get("state_sha256")):
        raise RecoveryAuthorityError("fixed-cohort-state-sha256-invalid")
    if value["state_sha256"] != _state_sha256(value):
        raise RecoveryAuthorityError("fixed-cohort-state-hash-mismatch")
    return value


def _absolute_path(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(Path(value).expanduser())))


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-symlink-component"
            )


def _require_private_directory(path: Path) -> os.stat_result:
    _reject_symlink_components(path)
    try:
        identity = path.lstat()
    except OSError as exc:
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-directory-unreadable"
        ) from exc
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != os.getuid()
        or stat.S_IMODE(identity.st_mode) != 0o700
    ):
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-directory-not-private"
        )
    return identity


def _require_private_file(path: Path, *, label: str) -> os.stat_result:
    if path.is_symlink():
        raise RecoveryAuthorityError(f"{label}-symlink-forbidden")
    try:
        identity = path.lstat()
    except OSError as exc:
        raise RecoveryAuthorityError(f"{label}-unreadable") from exc
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != os.getuid()
        or stat.S_IMODE(identity.st_mode) != 0o600
        or identity.st_nlink != 1
    ):
        raise RecoveryAuthorityError(f"{label}-not-private")
    return identity


def _create_private_file(path: Path) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-private-file-create-failed"
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class _ControllerFlockGuard:
    path: Path
    descriptor: int
    device: int
    inode: int

    def require_stable(self) -> None:
        opened = os.fstat(self.descriptor)
        current = _require_private_file(
            self.path,
            label="fixed-cohort-controller-lock",
        )
        expected = (
            self.device,
            self.inode,
            os.getuid(),
            0o600,
            1,
        )
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_nlink,
        ) != expected or (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            current.st_nlink,
        ) != expected:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-lock-identity-changed"
            )


@contextmanager
def _controller_flock(
    path: Path,
    *,
    exclusive: bool,
    expected_identity: tuple[int, int] | None = None,
) -> Iterator[_ControllerFlockGuard]:
    before = _require_private_file(path, label="fixed-cohort-controller-lock")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-lock-open-failed"
        ) from exc
    try:
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_uid != os.getuid()
            or stat.S_IMODE(identity.st_mode) != 0o600
            or identity.st_nlink != 1
            or (identity.st_dev, identity.st_ino)
            != (before.st_dev, before.st_ino)
            or (
                expected_identity is not None
                and (identity.st_dev, identity.st_ino) != expected_identity
            )
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-lock-not-private"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        guard = _ControllerFlockGuard(
            path=path,
            descriptor=descriptor,
            device=identity.st_dev,
            inode=identity.st_ino,
        )
        guard.require_stable()
        yield guard
        guard.require_stable()
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_controller_state(path: Path) -> dict[str, Any]:
    before = _require_private_file(
        path,
        label="fixed-cohort-controller-state",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-state-open-failed"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_uid,
                stat.S_IMODE(opened.st_mode),
                opened.st_nlink,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
            )
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-state-identity-changed"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            rendered = handle.read(1_000_001)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(rendered.encode("utf-8")) > 1_000_000:
        raise RecoveryAuthorityError("fixed-cohort-controller-state-too-large")
    final = _require_private_file(
        path,
        label="fixed-cohort-controller-state",
    )
    if (
        (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_nlink,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
        )
        != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_nlink,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
        )
        or (opened.st_size, opened.st_mtime_ns)
        != (after.st_size, after.st_mtime_ns)
        or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_nlink,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
        )
        != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_nlink,
            final.st_uid,
            stat.S_IMODE(final.st_mode),
        )
    ):
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-state-changed-during-read"
        )
    try:
        state = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-state-json-invalid"
        ) from exc
    state = _validate_controller_state(state)
    if rendered != _render_controller_state(state):
        raise RecoveryAuthorityError(
            "fixed-cohort-controller-state-noncanonical"
        )
    return state


def _atomic_write_controller_state(path: Path, state: Mapping[str, Any]) -> None:
    _validate_controller_state(dict(state))
    rendered = _render_controller_state(state)
    if path.exists() or path.is_symlink():
        _require_private_file(path, label="fixed-cohort-controller-state")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".controller-state.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        _require_private_file(path, label="fixed-cohort-controller-state")
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _new_controller_state(cohort: list[dict[str, str]]) -> dict[str, Any]:
    normalized = _normalize_fixed_cohort(cohort)
    state: dict[str, Any] = {
        "state_type": FIXED_COHORT_STATE_TYPE,
        "version": FIXED_COHORT_STATE_VERSION,
        "schema": FIXED_COHORT_STATE_SCHEMA,
        "admission_grade": PROVISIONAL_ADMISSION_GRADE,
        "dispatch_authorized": False,
        "fixed_cohort_sha256": fixed_cohort_sha256(normalized),
        "fixed_cohort": normalized,
        "bead_states": [
            {
                "bead_id": item["bead_id"],
                "replacement_count": 0,
                "construction_attempt_count": 0,
                "terminal": False,
            }
            for item in normalized
        ],
        "revision": 0,
    }
    state["state_sha256"] = _state_sha256(state)
    return _validate_controller_state(state)


def _bead_state(
    state: Mapping[str, Any], bead_id: str
) -> tuple[dict[str, str], dict[str, Any]]:
    cohort_matches = [
        item for item in state["fixed_cohort"] if item["bead_id"] == bead_id
    ]
    state_matches = [
        item for item in state["bead_states"] if item["bead_id"] == bead_id
    ]
    if len(cohort_matches) != 1 or len(state_matches) != 1:
        raise RecoveryAuthorityError("fixed-cohort-bead-not-admitted")
    return cohort_matches[0], state_matches[0]


class FixedCohortRecoveryActionStore:
    """Durable, create-once controller for a frozen provisional cohort.

    The store durably enforces one reconstruction and one replacement budget
    per admitted Bead, but remains categorically nonauthorizing.  Its action
    type is intentionally distinct from the supervisor bridge action type.
    P1-13B still owns any future productive admission authority.
    """

    __slots__ = (
        "_directory",
        "_state_path",
        "_lock_path",
        "_lock_device",
        "_lock_inode",
        "_entries",
        "_evidence_entries",
        "_registry_lock",
        "_root",
        "_mint",
    )

    def __init__(
        self,
        directory: Path,
        *,
        root: FixedCohortControllerRoot | None,
        lock_identity: tuple[int, int],
        mint: object,
    ) -> None:
        if type(self) is not FixedCohortRecoveryActionStore or mint is not _FIXED_STORE_MINT:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-construction-forbidden"
            )
        self._directory = directory
        self._state_path = directory / FIXED_COHORT_STATE_FILE
        self._lock_path = directory / FIXED_COHORT_LOCK_FILE
        self._lock_device, self._lock_inode = lock_identity
        self._entries: dict[
            int,
            tuple[
                VerifiedFixedCohortRecoveryAction,
                _FixedCohortActionBinding,
            ],
        ] = {}
        self._evidence_entries: dict[
            int,
            tuple[VerifiedRecoveryEvidence, _RecoveryEvidenceBinding],
        ] = {}
        self._registry_lock = Lock()
        self._root = root
        self._mint = _FIXED_STORE_MINT

    @classmethod
    def create(
        cls,
        directory: str | os.PathLike[str],
        cohort: Any,
    ) -> tuple[
        FixedCohortRecoveryActionStore,
        FixedCohortControllerRoot,
    ]:
        if cls is not FixedCohortRecoveryActionStore:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-subclass-forbidden"
            )
        normalized = _normalize_fixed_cohort(cohort)
        target = _absolute_path(directory)
        _reject_symlink_components(target.parent)
        if target.exists() or target.is_symlink():
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-directory-already-exists"
            )
        try:
            target.mkdir(mode=0o700)
            target.chmod(0o700)
        except OSError as exc:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-directory-create-failed"
            ) from exc
        directory_identity = _require_private_directory(target)
        lock_path = target / FIXED_COHORT_LOCK_FILE
        state_path = target / FIXED_COHORT_STATE_FILE
        _create_private_file(lock_path)
        lock_identity = _require_private_file(
            lock_path,
            label="fixed-cohort-controller-lock",
        )
        expected_lock_identity = (
            lock_identity.st_dev,
            lock_identity.st_ino,
        )
        with _controller_flock(
            lock_path,
            exclusive=True,
            expected_identity=expected_lock_identity,
        ):
            if state_path.exists() or state_path.is_symlink():
                raise RecoveryAuthorityError(
                    "fixed-cohort-controller-state-already-exists"
                )
            _atomic_write_controller_state(
                state_path,
                _new_controller_state(normalized),
            )
        with _controller_flock(
            lock_path,
            exclusive=False,
            expected_identity=expected_lock_identity,
        ):
            state = _read_controller_state(state_path)
        root = FixedCohortControllerRoot(_FIXED_ROOT_MINT)
        with _FIXED_ROOT_REGISTRY_LOCK:
            key = id(root)
            if key in _FIXED_ROOT_REGISTRY:
                raise RecoveryAuthorityError(
                    "fixed-cohort-controller-root-identity-collision"
                )
            _FIXED_ROOT_REGISTRY[key] = (
                root,
                str(target),
                state["fixed_cohort_sha256"],
                state["revision"],
                state["state_sha256"],
                directory_identity.st_dev,
                directory_identity.st_ino,
                lock_identity.st_dev,
                lock_identity.st_ino,
            )
        return cls(
            target,
            root=root,
            lock_identity=expected_lock_identity,
            mint=_FIXED_STORE_MINT,
        ), root

    @classmethod
    def open(
        cls,
        directory: str | os.PathLike[str],
        *,
        root: object | None = None,
    ) -> FixedCohortRecoveryActionStore:
        if cls is not FixedCohortRecoveryActionStore:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-subclass-forbidden"
            )
        target = _absolute_path(directory)
        directory_identity = _require_private_directory(target)
        lock_path = target / FIXED_COHORT_LOCK_FILE
        lock_identity = _require_private_file(
            lock_path,
            label="fixed-cohort-controller-lock",
        )
        expected_lock_identity = (
            lock_identity.st_dev,
            lock_identity.st_ino,
        )
        with _controller_flock(
            lock_path,
            exclusive=False,
            expected_identity=expected_lock_identity,
        ):
            state = _read_controller_state(target / FIXED_COHORT_STATE_FILE)
        retained_root: FixedCohortControllerRoot | None = None
        if root is not None:
            if type(root) is not FixedCohortControllerRoot:
                raise RecoveryAuthorityError(
                    "fixed-cohort-controller-root-type-invalid"
                )
            with _FIXED_ROOT_REGISTRY_LOCK:
                entry = _FIXED_ROOT_REGISTRY.get(id(root))
                if (
                    entry is None
                    or entry[0] is not root
                    or entry[1] != str(target)
                    or entry[2] != state["fixed_cohort_sha256"]
                    or entry[3] != state["revision"]
                    or entry[4] != state["state_sha256"]
                    or entry[5] != directory_identity.st_dev
                    or entry[6] != directory_identity.st_ino
                    or entry[7] != lock_identity.st_dev
                    or entry[8] != lock_identity.st_ino
                ):
                    raise RecoveryAuthorityError(
                        "fixed-cohort-controller-root-not-registered"
                    )
            retained_root = root
        return cls(
            target,
            root=retained_root,
            lock_identity=expected_lock_identity,
            mint=_FIXED_STORE_MINT,
        )

    def _require_exact_store(self) -> None:
        if (
            type(self) is not FixedCohortRecoveryActionStore
            or getattr(self, "_mint", None) is not _FIXED_STORE_MINT
        ):
            raise RecoveryAuthorityError("fixed-cohort-controller-store-invalid")
        _require_private_directory(self._directory)
        lock_identity = _require_private_file(
            self._lock_path,
            label="fixed-cohort-controller-lock",
        )
        if (lock_identity.st_dev, lock_identity.st_ino) != (
            self._lock_device,
            self._lock_inode,
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-lock-identity-mismatch"
            )

    def _require_root(self, root: object) -> None:
        self._require_exact_store()
        if type(root) is not FixedCohortControllerRoot:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-root-type-invalid"
            )
        if self._root is not root:
            raise RecoveryAuthorityError(
                "fixed-cohort-controller-root-store-mismatch"
            )
        directory_identity = _require_private_directory(self._directory)
        with _FIXED_ROOT_REGISTRY_LOCK:
            entry = _FIXED_ROOT_REGISTRY.get(id(root))
            if (
                entry is None
                or entry[0] is not root
                or entry[1] != str(self._directory)
                or entry[5] != directory_identity.st_dev
                or entry[6] != directory_identity.st_ino
                or entry[7] != self._lock_device
                or entry[8] != self._lock_inode
            ):
                raise RecoveryAuthorityError(
                    "fixed-cohort-controller-root-not-registered"
                )

    def _require_root_for_state(
        self,
        root: object,
        state: Mapping[str, Any],
    ) -> None:
        self._require_root(root)
        directory_identity = _require_private_directory(self._directory)
        with _FIXED_ROOT_REGISTRY_LOCK:
            entry = _FIXED_ROOT_REGISTRY.get(id(root))
            if (
                entry is None
                or entry[0] is not root
                or entry[1] != str(self._directory)
                or entry[2] != state["fixed_cohort_sha256"]
                or entry[3] != state["revision"]
                or entry[4] != state["state_sha256"]
                or entry[5] != directory_identity.st_dev
                or entry[6] != directory_identity.st_ino
                or entry[7] != self._lock_device
                or entry[8] != self._lock_inode
            ):
                raise RecoveryAuthorityError(
                    "fixed-cohort-controller-root-head-mismatch"
                )

    def _update_root_head(
        self,
        root: object,
        state: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_state_sha256: str,
        lock_guard: _ControllerFlockGuard,
    ) -> None:
        directory_identity = _require_private_directory(self._directory)
        with _FIXED_ROOT_REGISTRY_LOCK:
            entry = _FIXED_ROOT_REGISTRY.get(id(root))
            if (
                entry is None
                or entry[0] is not root
                or entry[1] != str(self._directory)
                or entry[2] != state["fixed_cohort_sha256"]
                or entry[3] != expected_revision
                or entry[4] != expected_state_sha256
                or entry[5] != directory_identity.st_dev
                or entry[6] != directory_identity.st_ino
                or entry[7] != self._lock_device
                or entry[8] != self._lock_inode
                or state["revision"] != expected_revision + 1
            ):
                raise RecoveryAuthorityError(
                    "fixed-cohort-controller-root-head-cas-failed"
                )
            lock_guard.require_stable()
            _FIXED_ROOT_REGISTRY[id(root)] = (
                root,
                str(self._directory),
                state["fixed_cohort_sha256"],
                state["revision"],
                state["state_sha256"],
                directory_identity.st_dev,
                directory_identity.st_ino,
                self._lock_device,
                self._lock_inode,
            )

    def read_state(self) -> dict[str, Any]:
        """Return a detached audit copy without creating action authority."""

        self._require_exact_store()
        with _controller_flock(
            self._lock_path,
            exclusive=False,
            expected_identity=(self._lock_device, self._lock_inode),
        ):
            state = _read_controller_state(self._state_path)
        return json.loads(canonical_recovery_json(state))

    @staticmethod
    def _build_evidence_binding(
        state: Mapping[str, Any],
        *,
        recovery_class: str,
        bead_id: str,
        admitted_work_unit_id: str,
        admitted_child_sha256: str,
        evidence_sha256: str,
        evidence_kind: str,
        ledger_items: Mapping[str, str] | None = None,
    ) -> dict[str, str | int | bool]:
        ledger = ledger_items or {}
        required_authority, stop_scope = _FIXED_COHORT_CLASS_BOUNDARIES[
            recovery_class
        ]
        binding: dict[str, str | int | bool] = {
            "recovery_class": recovery_class,
            "bead_id": bead_id,
            "admitted_work_unit_id": admitted_work_unit_id,
            "admitted_child_sha256": admitted_child_sha256,
            "evidence_sha256": evidence_sha256,
            "evidence_kind": evidence_kind,
            "required_authority": required_authority,
            "stop_scope": stop_scope,
            "evidence_state_revision": state["revision"],
            "evidence_state_sha256": state["state_sha256"],
            "ledger_result_sha256": ledger.get("ledger_result_sha256", ""),
            "ledger_work_unit_id": ledger.get("ledger_work_unit_id", ""),
            "ledger_thread_id": ledger.get("ledger_thread_id", ""),
            "ledger_turn_intent_id": ledger.get("ledger_turn_intent_id", ""),
            "ledger_turn_id": ledger.get("ledger_turn_id", ""),
            "ledger_dispatch_record_sha256": ledger.get(
                "ledger_dispatch_record_sha256", ""
            ),
            "ledger_dispatch_transport_binding_sha256": ledger.get(
                "ledger_dispatch_transport_binding_sha256", ""
            ),
            "ledger_containment_evidence_sha256": ledger.get(
                "ledger_containment_evidence_sha256", ""
            ),
            "ledger_containment_audit_event_hash": ledger.get(
                "ledger_containment_audit_event_hash", ""
            ),
        }
        binding["recovery_evidence_binding_sha256"] = canonical_recovery_sha256(
            binding,
            domain="native-recovery-fixed-cohort-source-evidence-binding-v1",
        )
        return binding

    def _register_evidence_binding(
        self,
        binding: Mapping[str, str | int | bool],
    ) -> VerifiedRecoveryEvidence:
        witness = VerifiedRecoveryEvidence(_FIXED_EVIDENCE_MINT)
        retained = _RecoveryEvidenceBinding(tuple(binding.items()))
        with self._registry_lock:
            key = id(witness)
            if key in self._evidence_entries:
                raise RecoveryAuthorityError(
                    "verified-recovery-evidence-identity-collision"
                )
            self._evidence_entries[key] = (witness, retained)
        return witness

    def register_controller_observation(
        self,
        root: object,
        *,
        recovery_class: str,
        bead_id: str,
        admitted_work_unit_id: str,
        admitted_child_sha256: str,
        evidence_sha256: str,
    ) -> VerifiedRecoveryEvidence:
        """Register one exact controller observation behind root identity."""

        self._require_root(root)
        if recovery_class not in {
            "deterministic-construction-failure",
            "pre-dispatch-transport-failure",
        }:
            raise RecoveryAuthorityError(
                "controller-recovery-evidence-class-invalid"
            )
        if (
            type(bead_id) is not str
            or not bead_id.strip()
            or type(admitted_work_unit_id) is not str
            or not admitted_work_unit_id.strip()
            or not _is_sha256(admitted_child_sha256)
            or not _is_sha256(evidence_sha256)
        ):
            raise RecoveryAuthorityError(
                "controller-recovery-evidence-fields-invalid"
            )
        with _controller_flock(
            self._lock_path,
            exclusive=False,
            expected_identity=(self._lock_device, self._lock_inode),
        ):
            state = _read_controller_state(self._state_path)
            self._require_root_for_state(root, state)
            cohort_item, bead_state = _bead_state(state, bead_id)
            if (
                bead_state["terminal"] is True
                or cohort_item["work_unit_id"] != admitted_work_unit_id
                or cohort_item["admitted_child_sha256"]
                != admitted_child_sha256
            ):
                raise RecoveryAuthorityError(
                    "controller-recovery-evidence-cohort-mismatch"
                )
            binding = self._build_evidence_binding(
                state,
                recovery_class=recovery_class,
                bead_id=bead_id,
                admitted_work_unit_id=admitted_work_unit_id,
                admitted_child_sha256=admitted_child_sha256,
                evidence_sha256=evidence_sha256,
                evidence_kind="controller-observation",
            )
        return self._register_evidence_binding(binding)

    def register_contained_ledger_evidence(
        self,
        root: object,
        *,
        recovery_class: str,
        bead_id: str,
        admitted_work_unit_id: str,
        admitted_child_sha256: str,
        ledger_store: object,
        ledger_witness: object,
        expected_thread_id: str,
        expected_turn_intent_id: str,
    ) -> VerifiedRecoveryEvidence:
        """Consume an exact ledger witness and retain its immutable result.

        The work-unit comparison is a provisional fixed-cohort boundary.  It
        does not prove that the caller-supplied child digest came from that
        ledger generation; P1-13B must bind the full admission-origin identity.
        """

        self._require_root(root)
        if recovery_class not in {
            "contained-semantic-no-op",
            "individual-child-failure",
        }:
            raise RecoveryAuthorityError(
                "ledger-recovery-evidence-class-invalid"
            )
        if type(ledger_store) is not NativeLiveAllocationLedgerStore:
            raise RecoveryAuthorityError(
                "ledger-recovery-evidence-store-type-invalid"
            )
        if type(ledger_witness) is not VerifiedContainedTurnDispatch:
            raise RecoveryAuthorityError(
                "ledger-recovery-evidence-witness-type-invalid"
            )
        if (
            type(bead_id) is not str
            or not bead_id.strip()
            or type(admitted_work_unit_id) is not str
            or not admitted_work_unit_id.strip()
            or not _is_sha256(admitted_child_sha256)
            or type(expected_thread_id) is not str
            or type(expected_turn_intent_id) is not str
        ):
            raise RecoveryAuthorityError(
                "ledger-recovery-evidence-fields-invalid"
            )
        try:
            raw_result = ledger_store.consume_verified_contained_turn_dispatch(
                ledger_witness,
                expected_thread_id=expected_thread_id,
                expected_turn_intent_id=expected_turn_intent_id,
            )
        except NativeLiveAllocationLedgerError as exc:
            raise RecoveryAuthorityError(
                "ledger-recovery-evidence-consume-failed"
            ) from exc
        result = _canonical_plain_snapshot(
            dict(raw_result),
            label="ledger-recovery-evidence-result",
        )
        required_strings = (
            "bead_id",
            "work_unit_id",
            "thread_id",
            "turn_intent_id",
            "turn_id",
            "dispatch_record_sha256",
            "dispatch_transport_binding_sha256",
            "containment_evidence_sha256",
            "containment_audit_event_hash",
        )
        if (
            result.get("verification_grade") != "ledger-chain-only"
            or result.get("dispatch_authorized") is not False
            or result.get("bead_id") != bead_id
            or result.get("work_unit_id") != admitted_work_unit_id
            or any(type(result.get(field)) is not str for field in required_strings)
            or any(
                not _is_sha256(result.get(field))
                for field in (
                    "dispatch_record_sha256",
                    "dispatch_transport_binding_sha256",
                    "containment_evidence_sha256",
                    "containment_audit_event_hash",
                )
            )
            or result.get("thread_id") != expected_thread_id
            or result.get("turn_intent_id") != expected_turn_intent_id
        ):
            raise RecoveryAuthorityError(
                "ledger-recovery-evidence-result-invalid"
            )
        ledger_items = {
            "ledger_result_sha256": canonical_recovery_sha256(
                result,
                domain="native-recovery-fixed-cohort-ledger-result-v1",
            ),
            "ledger_work_unit_id": result["work_unit_id"],
            "ledger_thread_id": result["thread_id"],
            "ledger_turn_intent_id": result["turn_intent_id"],
            "ledger_turn_id": result["turn_id"],
            "ledger_dispatch_record_sha256": result[
                "dispatch_record_sha256"
            ],
            "ledger_dispatch_transport_binding_sha256": result[
                "dispatch_transport_binding_sha256"
            ],
            "ledger_containment_evidence_sha256": result[
                "containment_evidence_sha256"
            ],
            "ledger_containment_audit_event_hash": result[
                "containment_audit_event_hash"
            ],
        }
        with _controller_flock(
            self._lock_path,
            exclusive=False,
            expected_identity=(self._lock_device, self._lock_inode),
        ):
            state = _read_controller_state(self._state_path)
            self._require_root_for_state(root, state)
            cohort_item, bead_state = _bead_state(state, bead_id)
            if (
                bead_state["terminal"] is True
                or cohort_item["work_unit_id"] != admitted_work_unit_id
                or cohort_item["admitted_child_sha256"]
                != admitted_child_sha256
            ):
                raise RecoveryAuthorityError(
                    "ledger-recovery-evidence-cohort-mismatch"
                )
            binding = self._build_evidence_binding(
                state,
                recovery_class=recovery_class,
                bead_id=bead_id,
                admitted_work_unit_id=admitted_work_unit_id,
                admitted_child_sha256=admitted_child_sha256,
                evidence_sha256=result["containment_evidence_sha256"],
                evidence_kind="verified-contained-ledger-dispatch",
                ledger_items=ledger_items,
            )
        return self._register_evidence_binding(binding)

    def _pop_evidence(
        self,
        witness: object,
    ) -> _RecoveryEvidenceBinding:
        if type(witness) is not VerifiedRecoveryEvidence:
            raise RecoveryAuthorityError("verified-recovery-evidence-type-invalid")
        with self._registry_lock:
            key = id(witness)
            entry = self._evidence_entries.get(key)
            if entry is None or entry[0] is not witness:
                raise RecoveryAuthorityError(
                    "verified-recovery-evidence-not-registered-or-spent"
                )
            del self._evidence_entries[key]
            return entry[1]

    @staticmethod
    def _decision_binding(
        state: Mapping[str, Any],
        decision: Mapping[str, Any],
        evidence: Mapping[str, Any],
    ) -> dict[str, str | int | bool]:
        bead_id = decision["admitted_bead_id"]
        cohort_item, bead_state = _bead_state(state, bead_id)
        binding: dict[str, str | int | bool] = {
            "decision_sha256": decision["decision_sha256"],
            "evidence_sha256": decision["evidence_sha256"],
            "classification_evidence_sha256": decision[
                "classification_evidence_sha256"
            ],
            "recovery_evidence_binding_sha256": evidence[
                "recovery_evidence_binding_sha256"
            ],
            "evidence_kind": evidence["evidence_kind"],
            "evidence_state_revision": evidence["evidence_state_revision"],
            "evidence_state_sha256": evidence["evidence_state_sha256"],
            "ledger_result_sha256": evidence["ledger_result_sha256"],
            "ledger_work_unit_id": evidence["ledger_work_unit_id"],
            "ledger_thread_id": evidence["ledger_thread_id"],
            "ledger_turn_intent_id": evidence["ledger_turn_intent_id"],
            "ledger_turn_id": evidence["ledger_turn_id"],
            "ledger_dispatch_record_sha256": evidence[
                "ledger_dispatch_record_sha256"
            ],
            "ledger_dispatch_transport_binding_sha256": evidence[
                "ledger_dispatch_transport_binding_sha256"
            ],
            "ledger_containment_evidence_sha256": evidence[
                "ledger_containment_evidence_sha256"
            ],
            "ledger_containment_audit_event_hash": evidence[
                "ledger_containment_audit_event_hash"
            ],
            "fixed_cohort_sha256": state["fixed_cohort_sha256"],
            "bead_id": bead_id,
            "admitted_work_unit_id": cohort_item["work_unit_id"],
            "admitted_child_sha256": cohort_item["admitted_child_sha256"],
            "replacement_count": bead_state["replacement_count"],
            "construction_attempt_count": bead_state[
                "construction_attempt_count"
            ],
            "state_revision": state["revision"],
            "state_sha256": state["state_sha256"],
            "recovery_class": decision["recovery_class"],
            "action": decision["action"],
            "required_authority": decision["required_authority"],
            "stop_scope": decision["stop_scope"],
            "admission_grade": PROVISIONAL_ADMISSION_GRADE,
            "dispatch_authorized": False,
        }
        binding["execution_binding_sha256"] = canonical_recovery_sha256(
            binding,
            domain="native-recovery-fixed-cohort-execution-binding-v1",
        )
        return binding

    @staticmethod
    def _require_decision_matches_state(
        state: Mapping[str, Any],
        decision: Mapping[str, Any],
    ) -> None:
        if decision["recovery_class"] not in _FIXED_COHORT_ALLOWED_CLASSES:
            raise RecoveryAuthorityError(
                "fixed-cohort-decision-class-not-child-local"
            )
        required_authority, stop_scope = _FIXED_COHORT_CLASS_BOUNDARIES[
            decision["recovery_class"]
        ]
        if (
            decision["action"] not in _FIXED_COHORT_ALLOWED_ACTIONS
            or decision["stop_scope"] != stop_scope
            or decision["required_authority"] != required_authority
            or decision["admission_grade"] != PROVISIONAL_ADMISSION_GRADE
            or decision["dispatch_authorized"] is not False
            or decision["fixed_cohort_required"] is not True
            or decision["newly_ready_refill_allowed"] is not False
            or decision["fixed_cohort_sha256"]
            != state["fixed_cohort_sha256"]
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-decision-boundary-invalid"
            )
        cohort_item, bead_state = _bead_state(
            state,
            decision["admitted_bead_id"],
        )
        if bead_state["terminal"] is True:
            raise RecoveryAuthorityError("fixed-cohort-bead-terminal")
        if decision["recovery_class"] == "deterministic-construction-failure":
            expected_action = (
                "reconstruct-same-admitted-bead"
                if bead_state["construction_attempt_count"] == 0
                and bead_state["replacement_count"] == 0
                else "return-same-admitted-bead-to-main-thread"
            )
        else:
            expected_action = (
                "replace-same-admitted-bead"
                if bead_state["replacement_count"] == 0
                else "return-same-admitted-bead-to-main-thread"
            )
        if (
            decision["admitted_child_sha256"]
            != cohort_item["admitted_child_sha256"]
            or decision["replacement_count"]
            != bead_state["replacement_count"]
            or decision["construction_attempt_count"]
            != bead_state["construction_attempt_count"]
            or decision["action"] != expected_action
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-decision-durable-binding-mismatch"
            )

    def issue(
        self,
        root: object,
        recovery_decision: Mapping[str, Any],
        evidence_witness: object,
    ) -> VerifiedFixedCohortRecoveryAction:
        """Mint a one-shot identity only for an exact current decision."""

        self._require_root(root)
        retained_evidence = self._pop_evidence(evidence_witness)
        evidence = dict(retained_evidence.projection)
        if set(evidence) != _FIXED_EVIDENCE_BINDING_FIELDS:
            raise RecoveryAuthorityError(
                "fixed-cohort-recovery-evidence-binding-fields-invalid"
            )
        evidence_body = dict(evidence)
        evidence_binding_sha256 = evidence_body.pop(
            "recovery_evidence_binding_sha256",
            None,
        )
        if evidence_binding_sha256 != canonical_recovery_sha256(
            evidence_body,
            domain="native-recovery-fixed-cohort-source-evidence-binding-v1",
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-recovery-evidence-binding-hash-mismatch"
            )
        decision = _canonical_plain_snapshot(
            recovery_decision,
            label="fixed-cohort-recovery-decision",
        )
        _require_exact_recovery_decision_types(decision)
        errors = validate_recovery_audit_decision(decision)
        if errors:
            raise RecoveryAuthorityError(
                "fixed-cohort-recovery-decision-invalid:" + ";".join(errors)
            )
        with _controller_flock(
            self._lock_path,
            exclusive=False,
            expected_identity=(self._lock_device, self._lock_inode),
        ):
            state = _read_controller_state(self._state_path)
            self._require_root_for_state(root, state)
            self._require_decision_matches_state(state, decision)
            expected_kind = (
                "controller-observation"
                if decision["recovery_class"]
                in {
                    "deterministic-construction-failure",
                    "pre-dispatch-transport-failure",
                }
                else "verified-contained-ledger-dispatch"
            )
            if (
                evidence["recovery_class"] != decision["recovery_class"]
                or evidence["bead_id"] != decision["admitted_bead_id"]
                or evidence["admitted_work_unit_id"]
                != _bead_state(state, decision["admitted_bead_id"])[0][
                    "work_unit_id"
                ]
                or evidence["admitted_child_sha256"]
                != decision["admitted_child_sha256"]
                or evidence["evidence_sha256"] != decision["evidence_sha256"]
                or evidence["required_authority"]
                != decision["required_authority"]
                or evidence["stop_scope"] != decision["stop_scope"]
                or evidence["evidence_kind"] != expected_kind
                or evidence["evidence_state_revision"] != state["revision"]
                or evidence["evidence_state_sha256"] != state["state_sha256"]
            ):
                raise RecoveryAuthorityError(
                    "fixed-cohort-recovery-evidence-decision-mismatch"
                )
            binding = _FixedCohortActionBinding(
                tuple(self._decision_binding(state, decision, evidence).items())
            )
        action = VerifiedFixedCohortRecoveryAction(_FIXED_ACTION_MINT)
        with self._registry_lock:
            key = id(action)
            if key in self._entries:
                raise RecoveryAuthorityError(
                    "fixed-cohort-recovery-action-identity-collision"
                )
            self._entries[key] = (action, binding)
        return action

    def _pop_binding(
        self,
        action: object,
    ) -> _FixedCohortActionBinding:
        if type(action) is not VerifiedFixedCohortRecoveryAction:
            raise RecoveryAuthorityError(
                "verified-fixed-cohort-recovery-action-type-invalid"
            )
        with self._registry_lock:
            key = id(action)
            entry = self._entries.get(key)
            if entry is None or entry[0] is not action:
                raise RecoveryAuthorityError(
                    "verified-fixed-cohort-recovery-action-not-registered-or-spent"
                )
            del self._entries[key]
            return entry[1]

    @staticmethod
    def _validate_consumption_binding(
        state: Mapping[str, Any],
        binding: Mapping[str, Any],
    ) -> tuple[dict[str, str], dict[str, Any]]:
        if set(binding) != _FIXED_ACTION_BINDING_FIELDS:
            raise RecoveryAuthorityError(
                "fixed-cohort-execution-binding-fields-invalid"
            )
        body = dict(binding)
        observed_sha256 = body.pop("execution_binding_sha256", None)
        expected_sha256 = canonical_recovery_sha256(
            body,
            domain="native-recovery-fixed-cohort-execution-binding-v1",
        )
        if observed_sha256 != expected_sha256:
            raise RecoveryAuthorityError(
                "fixed-cohort-execution-binding-hash-mismatch"
            )
        if (
            binding.get("admission_grade") != PROVISIONAL_ADMISSION_GRADE
            or binding.get("dispatch_authorized") is not False
            or binding.get("fixed_cohort_sha256")
            != state["fixed_cohort_sha256"]
            or binding.get("state_revision") != state["revision"]
            or binding.get("state_sha256") != state["state_sha256"]
            or binding.get("recovery_class")
            not in _FIXED_COHORT_ALLOWED_CLASSES
            or binding.get("action") not in _FIXED_COHORT_ALLOWED_ACTIONS
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-execution-binding-stale-or-invalid"
            )
        required_authority, stop_scope = _FIXED_COHORT_CLASS_BOUNDARIES[
            binding["recovery_class"]
        ]
        if (
            binding.get("required_authority") != required_authority
            or binding.get("stop_scope") != stop_scope
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-execution-binding-authority-invalid"
            )
        bead_id = binding.get("bead_id")
        if type(bead_id) is not str:
            raise RecoveryAuthorityError(
                "fixed-cohort-execution-binding-bead-invalid"
            )
        cohort_item, bead_state = _bead_state(state, bead_id)
        if (
            bead_state["terminal"] is True
            or binding.get("admitted_work_unit_id")
            != cohort_item["work_unit_id"]
            or binding.get("admitted_child_sha256")
            != cohort_item["admitted_child_sha256"]
            or binding.get("replacement_count")
            != bead_state["replacement_count"]
            or binding.get("construction_attempt_count")
            != bead_state["construction_attempt_count"]
        ):
            raise RecoveryAuthorityError(
                "fixed-cohort-execution-binding-cas-mismatch"
            )
        return cohort_item, bead_state

    def consume(
        self,
        root: object,
        action: object,
    ) -> Mapping[str, str | int | bool]:
        """Spend identity first, then atomically persist one durable transition."""

        self._require_root(root)
        retained = self._pop_binding(action)
        binding = dict(retained.projection)
        with _controller_flock(
            self._lock_path,
            exclusive=True,
            expected_identity=(self._lock_device, self._lock_inode),
        ) as lock_guard:
            state = _read_controller_state(self._state_path)
            self._require_root_for_state(root, state)
            _, bead_state = self._validate_consumption_binding(state, binding)
            lock_guard.require_stable()
            previous_revision = state["revision"]
            previous_state_sha256 = state["state_sha256"]
            action_name = binding["action"]
            if action_name == "reconstruct-same-admitted-bead":
                if bead_state["construction_attempt_count"] != 0:
                    raise RecoveryAuthorityError(
                        "fixed-cohort-construction-attempt-exhausted"
                    )
                bead_state["construction_attempt_count"] = 1
            elif action_name == "replace-same-admitted-bead":
                if bead_state["replacement_count"] != 0:
                    raise RecoveryAuthorityError(
                        "fixed-cohort-replacement-exhausted"
                    )
                bead_state["replacement_count"] = 1
            elif action_name == "return-same-admitted-bead-to-main-thread":
                if (
                    bead_state["replacement_count"] == 0
                    and bead_state["construction_attempt_count"] == 0
                ):
                    raise RecoveryAuthorityError(
                        "fixed-cohort-return-before-budget-use"
                    )
                bead_state["terminal"] = True
            else:
                raise RecoveryAuthorityError(
                    "fixed-cohort-execution-action-invalid"
                )
            state["revision"] = previous_revision + 1
            state["state_sha256"] = _state_sha256(state)
            lock_guard.require_stable()
            _atomic_write_controller_state(self._state_path, state)
            lock_guard.require_stable()
            self._update_root_head(
                root,
                state,
                expected_revision=previous_revision,
                expected_state_sha256=previous_state_sha256,
                lock_guard=lock_guard,
            )

        projection: dict[str, str | int | bool] = {
            "decision_sha256": binding["decision_sha256"],
            "evidence_sha256": binding["evidence_sha256"],
            "classification_evidence_sha256": binding[
                "classification_evidence_sha256"
            ],
            "recovery_evidence_binding_sha256": binding[
                "recovery_evidence_binding_sha256"
            ],
            "evidence_kind": binding["evidence_kind"],
            "ledger_result_sha256": binding["ledger_result_sha256"],
            "execution_binding_sha256": binding["execution_binding_sha256"],
            "fixed_cohort_sha256": binding["fixed_cohort_sha256"],
            "bead_id": binding["bead_id"],
            "admitted_work_unit_id": binding["admitted_work_unit_id"],
            "admitted_child_sha256": binding["admitted_child_sha256"],
            "action": action_name,
            "required_authority": binding["required_authority"],
            "stop_scope": binding["stop_scope"],
            "replacement_count": bead_state["replacement_count"],
            "construction_attempt_count": bead_state[
                "construction_attempt_count"
            ],
            "terminal": bead_state["terminal"],
            "consumed_revision": previous_revision,
            "persisted_revision": state["revision"],
            "prior_state_sha256": previous_state_sha256,
            "persisted_state_sha256": state["state_sha256"],
            "admission_grade": PROVISIONAL_ADMISSION_GRADE,
            "dispatch_authorized": False,
        }
        projection["audit_projection_sha256"] = canonical_recovery_sha256(
            projection,
            domain="native-recovery-fixed-cohort-consumption-audit-v1",
        )
        return MappingProxyType(projection)
