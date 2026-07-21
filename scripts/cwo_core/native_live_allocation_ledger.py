"""Private, audited allocation ledger for one native live-canary campaign."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
from typing import Any, Iterator, Mapping
import uuid

from .audit import (
    audit_event_payload_hash,
    record_audit_event,
)
from .native_canary_contracts import canonical_sha256
from .native_turn_dispatch import (
    validate_turn_absence_proof,
    validate_turn_dispatch_record,
)


LEDGER_TYPE = "cwo-native-live-allocation-ledger:v1"
LEDGER_SCHEMA = "schemas/native-live-allocation-ledger.schema.json"
LEDGER_VERSION = 1
LEDGER_TYPE_V2 = "cwo-native-live-allocation-ledger:v2"
LEDGER_SCHEMA_V2 = "schemas/native-live-allocation-ledger-v2.schema.json"
LEDGER_VERSION_V2 = 2
EXPECTED_ROLES = (
    "capability-calibration",
    "read-only-0",
    "read-only-1",
    "mutable-0",
    "mutable-1",
    "interrupt-0",
    "interrupt-1",
)
LEDGER_FIELDS = {
    "ledger_type",
    "version",
    "schema",
    "ledger_id",
    "bindings",
    "sequence",
    "entries",
    "head_entry_sha256",
    "state_sha256",
}
BINDING_FIELDS = {
    "bead_id",
    "authorization_id",
    "authorization_raw_sha256",
    "authorization_canonical_sha256",
    "campaign_nonce",
    "live_generation",
    "predecessor_generation",
    "checkpoint_commit",
    "guarded_primary_diff_sha256",
    "predecessor_containment_sha256",
    "pre_mutation_steering_receipt_sha256",
    "pre_live_steering_receipt_sha256",
    "certification_policy_sha256",
    "controller_identity",
    "connection_epoch_sha256",
    "retention_class",
    "expected_roles",
}
BINDING_FIELDS_V2 = {
    "bead_id",
    "work_unit_id",
    "authorization_id",
    "authorization_raw_sha256",
    "authorization_canonical_sha256",
    "campaign_manifest_sha256",
    "campaign_nonce",
    "live_generation",
    "predecessor_generation",
    "candidate_commit",
    "candidate_tree",
    "origin_main_commit",
    "guarded_primary_diff_sha256",
    "predecessor_containment_sha256",
    "frozen_release_patch_sha256",
    "pre_mutation_steering_receipt_sha256",
    "pre_live_steering_receipt_sha256",
    "opus_review_sha256",
    "certification_policy_sha256",
    "controller_identity",
    "connection_epoch_sha256",
    "retention_class",
    "expected_roles",
}
OWNER_FIELDS = {"pid", "start_ticks", "boot_id_sha256"}
ENTRY_FIELDS = {
    "sequence",
    "event",
    "role",
    "ordinal",
    "allocation_intent_id",
    "thread_id",
    "turn_intent_id",
    "turn_id",
    "evidence_sha256",
    "outcome",
    "previous_entry_sha256",
    "entry_sha256",
    "audit_event_hash",
}
EVENTS = {
    "allocation-intent",
    "thread-bound",
    "turn-intent",
    "turn-bound",
    "interrupt-observed",
    "archive-observed",
    "containment-audited",
    "certification-bound",
}


class NativeLiveAllocationLedgerError(ValueError):
    """Raised when durable allocation authority cannot be proven."""


@dataclass
class _LedgerSemanticIndex:
    allocation_intents: dict[str, dict[str, Any]] = dataclass_field(
        default_factory=dict
    )
    bound_threads: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    turn_intents: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    bound_turns: set[str] = dataclass_field(default_factory=set)
    resolved_turn_intents: set[str] = dataclass_field(default_factory=set)
    roles_seen: set[str] = dataclass_field(default_factory=set)
    turn_intents_by_thread: dict[str, list[str]] = dataclass_field(default_factory=dict)
    turn_ids_by_thread: dict[str, list[str]] = dataclass_field(default_factory=dict)
    lifecycle_events: set[tuple[str, str, str]] = dataclass_field(default_factory=set)
    lifecycle_kinds: set[tuple[str, str]] = dataclass_field(default_factory=set)
    certification_count: int = 0

    def clone(self) -> _LedgerSemanticCandidate:
        """Return a constant-size transactional overlay for one transition."""

        return _LedgerSemanticCandidate(self)

    def allocation_intent(self, allocation_id: str) -> dict[str, Any] | None:
        return self.allocation_intents.get(allocation_id)

    def role_seen(self, role: str) -> bool:
        return role in self.roles_seen

    def add_allocation_intent(
        self, allocation_id: str, role: str, entry: Mapping[str, Any]
    ) -> None:
        self.allocation_intents[allocation_id] = dict(entry)
        self.roles_seen.add(role)

    def thread_binding(self, thread_id: str) -> dict[str, Any] | None:
        return self.bound_threads.get(thread_id)

    def add_thread_binding(self, thread_id: str, entry: Mapping[str, Any]) -> None:
        self.bound_threads[thread_id] = dict(entry)

    def turn_intent(self, turn_intent_id: str) -> dict[str, Any] | None:
        return self.turn_intents.get(turn_intent_id)

    def add_turn_intent(
        self,
        turn_intent_id: str,
        thread_id: str,
        entry: Mapping[str, Any],
    ) -> None:
        self.turn_intents[turn_intent_id] = dict(entry)
        self.turn_intents_by_thread.setdefault(thread_id, []).append(turn_intent_id)

    def latest_turn_intent_id(self, thread_id: str) -> str | None:
        values = self.turn_intents_by_thread.get(thread_id, [])
        return values[-1] if values else None

    def turn_bound(self, turn_id: str) -> bool:
        return turn_id in self.bound_turns

    def turn_intent_resolved(self, turn_intent_id: str) -> bool:
        return turn_intent_id in self.resolved_turn_intents

    def resolve_turn_intent(self, turn_intent_id: str) -> None:
        self.resolved_turn_intents.add(turn_intent_id)

    def add_bound_turn(
        self, turn_intent_id: str, turn_id: str, thread_id: str
    ) -> None:
        self.resolve_turn_intent(turn_intent_id)
        self.bound_turns.add(turn_id)
        self.turn_ids_by_thread.setdefault(thread_id, []).append(turn_id)

    def latest_turn_id(self, thread_id: str) -> str | None:
        values = self.turn_ids_by_thread.get(thread_id, [])
        return values[-1] if values else None

    def add_lifecycle(self, event: str, thread_id: str, outcome: str) -> None:
        self.lifecycle_events.add((event, thread_id, outcome))
        self.lifecycle_kinds.add((event, thread_id))

    def lifecycle_seen(self, event: str, thread_id: str, outcome: str) -> bool:
        return (event, thread_id, outcome) in self.lifecycle_events

    def lifecycle_kind_seen(self, event: str, thread_id: str) -> bool:
        return (event, thread_id) in self.lifecycle_kinds

    def increment_certification(self) -> None:
        self.certification_count += 1


@dataclass
class _LedgerSemanticCandidate:
    """Copy-on-write semantic clone used until one append is durable."""

    base: _LedgerSemanticIndex
    allocation_intents: dict[str, dict[str, Any]] = dataclass_field(
        default_factory=dict
    )
    bound_threads: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    turn_intents: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    bound_turns: set[str] = dataclass_field(default_factory=set)
    resolved_turn_intents: set[str] = dataclass_field(default_factory=set)
    roles_seen: set[str] = dataclass_field(default_factory=set)
    turn_intents_by_thread: dict[str, list[str]] = dataclass_field(default_factory=dict)
    turn_ids_by_thread: dict[str, list[str]] = dataclass_field(default_factory=dict)
    lifecycle_events: set[tuple[str, str, str]] = dataclass_field(default_factory=set)
    lifecycle_kinds: set[tuple[str, str]] = dataclass_field(default_factory=set)
    certification_increment: int = 0

    @property
    def certification_count(self) -> int:
        return self.base.certification_count + self.certification_increment

    def allocation_intent(self, allocation_id: str) -> dict[str, Any] | None:
        return self.allocation_intents.get(
            allocation_id, self.base.allocation_intent(allocation_id)
        )

    def role_seen(self, role: str) -> bool:
        return role in self.roles_seen or self.base.role_seen(role)

    def add_allocation_intent(
        self, allocation_id: str, role: str, entry: Mapping[str, Any]
    ) -> None:
        self.allocation_intents[allocation_id] = dict(entry)
        self.roles_seen.add(role)

    def thread_binding(self, thread_id: str) -> dict[str, Any] | None:
        return self.bound_threads.get(thread_id, self.base.thread_binding(thread_id))

    def add_thread_binding(self, thread_id: str, entry: Mapping[str, Any]) -> None:
        self.bound_threads[thread_id] = dict(entry)

    def turn_intent(self, turn_intent_id: str) -> dict[str, Any] | None:
        return self.turn_intents.get(
            turn_intent_id, self.base.turn_intent(turn_intent_id)
        )

    def add_turn_intent(
        self,
        turn_intent_id: str,
        thread_id: str,
        entry: Mapping[str, Any],
    ) -> None:
        self.turn_intents[turn_intent_id] = dict(entry)
        self.turn_intents_by_thread.setdefault(thread_id, []).append(turn_intent_id)

    def latest_turn_intent_id(self, thread_id: str) -> str | None:
        values = self.turn_intents_by_thread.get(thread_id, [])
        return values[-1] if values else self.base.latest_turn_intent_id(thread_id)

    def turn_bound(self, turn_id: str) -> bool:
        return turn_id in self.bound_turns or self.base.turn_bound(turn_id)

    def turn_intent_resolved(self, turn_intent_id: str) -> bool:
        return (
            turn_intent_id in self.resolved_turn_intents
            or self.base.turn_intent_resolved(turn_intent_id)
        )

    def resolve_turn_intent(self, turn_intent_id: str) -> None:
        self.resolved_turn_intents.add(turn_intent_id)

    def add_bound_turn(
        self, turn_intent_id: str, turn_id: str, thread_id: str
    ) -> None:
        self.resolve_turn_intent(turn_intent_id)
        self.bound_turns.add(turn_id)
        self.turn_ids_by_thread.setdefault(thread_id, []).append(turn_id)

    def latest_turn_id(self, thread_id: str) -> str | None:
        values = self.turn_ids_by_thread.get(thread_id, [])
        return values[-1] if values else self.base.latest_turn_id(thread_id)

    def add_lifecycle(self, event: str, thread_id: str, outcome: str) -> None:
        self.lifecycle_events.add((event, thread_id, outcome))
        self.lifecycle_kinds.add((event, thread_id))

    def lifecycle_seen(self, event: str, thread_id: str, outcome: str) -> bool:
        return (event, thread_id, outcome) in self.lifecycle_events or (
            self.base.lifecycle_seen(event, thread_id, outcome)
        )

    def lifecycle_kind_seen(self, event: str, thread_id: str) -> bool:
        return (event, thread_id) in self.lifecycle_kinds or (
            self.base.lifecycle_kind_seen(event, thread_id)
        )

    def increment_certification(self) -> None:
        self.certification_increment += 1

    def commit(self) -> _LedgerSemanticIndex:
        """Apply the validated constant-size delta to the trusted index."""

        self.base.allocation_intents.update(self.allocation_intents)
        self.base.bound_threads.update(self.bound_threads)
        self.base.turn_intents.update(self.turn_intents)
        self.base.bound_turns.update(self.bound_turns)
        self.base.resolved_turn_intents.update(self.resolved_turn_intents)
        self.base.roles_seen.update(self.roles_seen)
        for thread_id, values in self.turn_intents_by_thread.items():
            self.base.turn_intents_by_thread.setdefault(thread_id, []).extend(values)
        for thread_id, values in self.turn_ids_by_thread.items():
            self.base.turn_ids_by_thread.setdefault(thread_id, []).extend(values)
        self.base.lifecycle_events.update(self.lifecycle_events)
        self.base.lifecycle_kinds.update(self.lifecycle_kinds)
        self.base.certification_count += self.certification_increment
        return self.base


@dataclass(frozen=True)
class _PrivateFileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _TrustedLedgerCoordinates:
    ledger_type: Any
    version: Any
    schema: Any
    ledger_id: Any
    bindings_sha256: str
    sequence: Any
    entry_count: int
    head_entry_sha256: Any
    state_sha256: Any
    ledger_file: _PrivateFileIdentity
    audit_file: _PrivateFileIdentity
    audit_event_count: int
    audit_head_sha256: Any
    absence_proof_files: tuple[tuple[str, _PrivateFileIdentity], ...]


def _hash(value: Any, *, domain: str) -> str:
    return canonical_sha256(value, domain=domain)


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


def _entry_sha256(entry: Mapping[str, Any]) -> str:
    body = {
        key: value
        for key, value in entry.items()
        if key not in {"entry_sha256", "audit_event_hash"}
    }
    return _hash(body, domain="native-live-allocation-ledger-entry")


def _state_sha256(state: Mapping[str, Any]) -> str:
    return _hash(
        {key: value for key, value in state.items() if key != "state_sha256"},
        domain="native-live-allocation-ledger-state",
    )


def _strict_private_regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise NativeLiveAllocationLedgerError(f"{label}-unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise NativeLiveAllocationLedgerError(f"{label}-not-private-regular-file")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise NativeLiveAllocationLedgerError(f"{label}-permissions-invalid")
    return info


def _private_file_identity(info: os.stat_result) -> _PrivateFileIdentity:
    return _PrivateFileIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _path_private_identity(path: Path, label: str) -> _PrivateFileIdentity:
    return _private_file_identity(_strict_private_regular(path, label))


def _require_private_file_descriptor(
    descriptor: int,
    label: str,
) -> _PrivateFileIdentity:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise NativeLiveAllocationLedgerError(f"{label}-not-private-regular-file")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise NativeLiveAllocationLedgerError(f"{label}-permissions-invalid")
    return _private_file_identity(info)


def _require_stable_private_path(
    path: Path,
    label: str,
    expected: _PrivateFileIdentity,
) -> None:
    if _path_private_identity(path, label) != expected:
        raise NativeLiveAllocationLedgerError(f"{label}-identity-changed")


def _strict_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise NativeLiveAllocationLedgerError("ledger-directory-unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise NativeLiveAllocationLedgerError("ledger-directory-invalid")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise NativeLiveAllocationLedgerError("ledger-directory-permissions-invalid")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_private_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_write(path: Path, value: Mapping[str, Any]) -> None:
    _strict_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _strict_private_regular(path, "ledger-file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        payload = json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n"
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600, follow_symlinks=False)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_private_json(path: Path) -> dict[str, Any]:
    value, _identity = _read_private_json_with_identity(path)
    return value


def _read_private_json_with_identity(
    path: Path,
) -> tuple[dict[str, Any], _PrivateFileIdentity]:
    before_path = _path_private_identity(path, "ledger-file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            before_read = _require_private_file_descriptor(
                handle.fileno(), "ledger-file"
            )
            if before_read != before_path:
                raise NativeLiveAllocationLedgerError("ledger-file-identity-changed")
            value = json.load(handle)
            identity = _require_private_file_descriptor(handle.fileno(), "ledger-file")
            if identity != before_read:
                raise NativeLiveAllocationLedgerError("ledger-file-identity-changed")
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeLiveAllocationLedgerError("ledger-file-unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _require_stable_private_path(path, "ledger-file", identity)
    if not isinstance(value, dict):
        raise NativeLiveAllocationLedgerError("ledger-file-not-object")
    return value, identity


def _verified_turn_absence_proof(
    directory: Path,
    state: Mapping[str, Any],
    entry: Mapping[str, Any],
    *,
    expected_proof_sha256: str | None = None,
) -> tuple[dict[str, Any], _PrivateFileIdentity]:
    """Load and bind one canonical private absence proof to its ledger intent."""

    turn_intent_id = entry.get("turn_intent_id")
    if not _is_uuid(turn_intent_id):
        raise NativeLiveAllocationLedgerError("turn-intent-absence-proof-link-invalid")
    proof_path = directory / "turn-absence" / f"{turn_intent_id}.json"
    try:
        _strict_private_directory(proof_path.parent)
        proof, identity = _read_private_json_with_identity(proof_path)
    except NativeLiveAllocationLedgerError as exc:
        raise NativeLiveAllocationLedgerError(
            "turn-intent-absence-proof-link-invalid"
        ) from exc
    errors = validate_turn_absence_proof(proof)
    intent_entries = [
        candidate
        for candidate in state.get("entries", [])
        if isinstance(candidate, Mapping)
        and candidate.get("event") == "turn-intent"
        and candidate.get("turn_intent_id") == turn_intent_id
    ]
    if (
        errors
        or len(intent_entries) != 1
        or proof.get("proof_sha256") != entry.get("evidence_sha256")
        or (
            expected_proof_sha256 is not None
            and proof.get("proof_sha256") != expected_proof_sha256
        )
        or proof.get("ledger_id") != state.get("ledger_id")
        or proof.get("thread_id") != entry.get("thread_id")
        or proof.get("turn_intent_id") != turn_intent_id
        or proof.get("turn_intent_entry_sha256")
        != intent_entries[0].get("entry_sha256")
    ):
        raise NativeLiveAllocationLedgerError("turn-intent-absence-proof-link-invalid")
    dispatch = proof.get("dispatch_record")
    if (
        not isinstance(dispatch, Mapping)
        or validate_turn_dispatch_record(dispatch)
        or dispatch.get("ledger_head_entry_sha256")
        != intent_entries[0].get("entry_sha256")
    ):
        raise NativeLiveAllocationLedgerError("turn-intent-absence-proof-link-invalid")
    return proof, identity


def _validate_persisted_turn_absence_proofs(
    directory: Path,
    state: Mapping[str, Any],
) -> tuple[tuple[str, _PrivateFileIdentity], ...]:
    identities: list[tuple[str, _PrivateFileIdentity]] = []
    for entry in state.get("entries", []):
        if (
            isinstance(entry, Mapping)
            and entry.get("event") == "containment-audited"
            and entry.get("outcome") == "turn-intent-verified-absent"
        ):
            proof, identity = _verified_turn_absence_proof(directory, state, entry)
            proof_path = directory / "turn-absence" / (
                f"{proof['turn_intent_id']}.json"
            )
            identities.append((str(proof_path), identity))
    return tuple(identities)


def _read_private_bytes_with_identity(
    path: Path,
    label: str,
) -> tuple[bytes, _PrivateFileIdentity]:
    before_path = _path_private_identity(path, label)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            before_read = _require_private_file_descriptor(handle.fileno(), label)
            if before_read != before_path:
                raise NativeLiveAllocationLedgerError(f"{label}-identity-changed")
            payload = handle.read()
            identity = _require_private_file_descriptor(handle.fileno(), label)
            if identity != before_read:
                raise NativeLiveAllocationLedgerError(f"{label}-identity-changed")
    except OSError as exc:
        raise NativeLiveAllocationLedgerError(f"{label}-unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _require_stable_private_path(path, label, identity)
    return payload, identity


def _read_private_audit_tail(
    path: Path,
) -> tuple[dict[str, Any] | None, _PrivateFileIdentity]:
    before_path = _path_private_identity(path, "ledger-audit")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            before_read = _require_private_file_descriptor(
                handle.fileno(), "ledger-audit"
            )
            if before_read != before_path:
                raise NativeLiveAllocationLedgerError("ledger-audit-identity-changed")
            if before_read.size == 0:
                identity = _require_private_file_descriptor(
                    handle.fileno(), "ledger-audit"
                )
                if identity != before_read:
                    raise NativeLiveAllocationLedgerError(
                        "ledger-audit-identity-changed"
                    )
                value: dict[str, Any] | None = None
            else:
                handle.seek(-1, os.SEEK_END)
                if handle.read(1) != b"\n":
                    raise NativeLiveAllocationLedgerError("ledger-audit-tail-invalid")
                end = before_read.size - 1
                position = end
                chunks: list[bytes] = []
                while position > 0:
                    start = max(0, position - 4096)
                    handle.seek(start)
                    chunk = handle.read(position - start)
                    newline = chunk.rfind(b"\n")
                    if newline >= 0:
                        chunks.insert(0, chunk[newline + 1 :])
                        break
                    chunks.insert(0, chunk)
                    position = start
                raw = b"".join(chunks)
                if not raw:
                    raise NativeLiveAllocationLedgerError("ledger-audit-tail-invalid")
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise NativeLiveAllocationLedgerError(
                        "ledger-audit-tail-invalid"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise NativeLiveAllocationLedgerError("ledger-audit-tail-invalid")
                value = decoded
                identity = _require_private_file_descriptor(
                    handle.fileno(), "ledger-audit"
                )
                if identity != before_read:
                    raise NativeLiveAllocationLedgerError(
                        "ledger-audit-identity-changed"
                    )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _require_stable_private_path(path, "ledger-audit", identity)
    return value, identity


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    _strict_private_directory(path.parent)
    if not path.exists():
        _create_private_file(path)
        _fsync_directory(path.parent)
    _strict_private_regular(path, "ledger-lock")
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _validate_bindings(
    value: Any,
    errors: list[str],
    *,
    version: int,
) -> dict[str, Any]:
    expected_fields = BINDING_FIELDS if version == LEDGER_VERSION else BINDING_FIELDS_V2
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        errors.append("ledger-bindings-fields-invalid")
        return {}
    bindings = dict(value)
    identity_fields = ["bead_id"]
    if version == LEDGER_VERSION_V2:
        identity_fields.append("work_unit_id")
    if any(
        not isinstance(bindings.get(field), str) or not bindings[field].strip()
        for field in identity_fields
    ):
        errors.append("ledger-binding-work-unit-identity-invalid")
    hash_fields = [
        "authorization_raw_sha256",
        "authorization_canonical_sha256",
        "guarded_primary_diff_sha256",
        "predecessor_containment_sha256",
        "pre_mutation_steering_receipt_sha256",
        "pre_live_steering_receipt_sha256",
        "certification_policy_sha256",
        "connection_epoch_sha256",
    ]
    if version == LEDGER_VERSION_V2:
        hash_fields.extend(
            [
                "campaign_manifest_sha256",
                "frozen_release_patch_sha256",
                "opus_review_sha256",
            ]
        )
    for field in hash_fields:
        if not _is_hash(bindings.get(field)):
            errors.append(f"ledger-binding-{field}-invalid")
    for field in ("authorization_id", "campaign_nonce"):
        if not _is_uuid(bindings.get(field)):
            errors.append(f"ledger-binding-{field}-invalid")
    commit_fields = (
        ["checkpoint_commit"]
        if version == LEDGER_VERSION
        else ["candidate_commit", "candidate_tree", "origin_main_commit"]
    )
    for field in commit_fields:
        candidate = bindings.get(field)
        if (
            not isinstance(candidate, str)
            or len(candidate) != 40
            or any(character not in "0123456789abcdef" for character in candidate)
        ):
            errors.append(f"ledger-binding-{field}-invalid")
    live_generation = bindings.get("live_generation")
    predecessor_generation = bindings.get("predecessor_generation")
    if version == LEDGER_VERSION and (live_generation, predecessor_generation) != (
        4,
        3,
    ):
        errors.append("ledger-binding-generation-invalid")
    if version == LEDGER_VERSION_V2 and (
        isinstance(live_generation, bool)
        or not isinstance(live_generation, int)
        or isinstance(predecessor_generation, bool)
        or not isinstance(predecessor_generation, int)
        or predecessor_generation < 0
        or live_generation != predecessor_generation + 1
    ):
        errors.append("ledger-binding-generation-invalid")
    if bindings.get("retention_class") != "private-local-until-bead-closure":
        errors.append("ledger-binding-retention-class-invalid")
    if bindings.get("expected_roles") != list(EXPECTED_ROLES):
        errors.append("ledger-binding-expected-roles-invalid")
    owner = bindings.get("controller_identity")
    if not isinstance(owner, Mapping) or set(owner) != OWNER_FIELDS:
        errors.append("ledger-binding-controller-identity-invalid")
    else:
        if any(
            isinstance(owner.get(field), bool)
            or not isinstance(owner.get(field), int)
            or owner.get(field, 0) < 1
            for field in ("pid", "start_ticks")
        ) or not _is_hash(owner.get("boot_id_sha256")):
            errors.append("ledger-binding-controller-identity-invalid")
    return bindings


def _load_audit_events(
    *,
    audit_file: Path | None,
    audit_bytes: bytes | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    audits: list[dict[str, Any]] = []
    if audit_file is not None and audit_bytes is not None:
        return audits, ["ledger-audit-source-ambiguous"]
    if audit_file is not None:
        try:
            audit_bytes, _identity = _read_private_bytes_with_identity(
                audit_file, "ledger-audit"
            )
        except NativeLiveAllocationLedgerError:
            return [], ["ledger-audit-chain-invalid"]
    if audit_bytes is not None:
        try:
            if not isinstance(audit_bytes, bytes) or (
                audit_bytes and not audit_bytes.endswith(b"\n")
            ):
                raise ValueError("partial audit snapshot")
            decoded = audit_bytes.decode("utf-8")
            previous_hash: str | None = None
            for line in decoded.splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("audit event is not an object")
                if event.get("event_hash") != audit_event_payload_hash(event):
                    raise ValueError("audit event hash mismatch")
                if previous_hash is None:
                    if event.get("previous_event_hash") is not None:
                        raise ValueError("first audit event is linked")
                elif event.get("previous_event_hash") != previous_hash:
                    raise ValueError("audit chain mismatch")
                previous_hash = event.get("event_hash")
                audits.append(event)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return [], ["ledger-audit-chain-invalid"]
    return audits, errors


def _audit_anchor_matches(
    audit: Mapping[str, Any] | None,
    entry: Mapping[str, Any],
    *,
    ledger_id: Any,
    index_number: int,
) -> bool:
    return bool(
        audit is not None
        and audit.get("event_hash") == entry.get("audit_event_hash")
        and audit.get("event_type") == "native_live_allocation_ledger_entry"
        and audit.get("dispatch_id") == ledger_id
        and audit.get("packet_sha256") == entry.get("entry_sha256")
        and audit.get("phase") == entry.get("event")
        and audit.get("validation_lineage_attempt") == index_number
    )


def _validate_entry_transition(
    raw: Any,
    *,
    index_number: int,
    previous_entry_sha256: str | None,
    semantic_index: _LedgerSemanticIndex | _LedgerSemanticCandidate,
    ledger_id: Any,
    audit: Mapping[str, Any] | None,
    require_audit_hash: bool,
    verify_audit_anchor: bool,
) -> tuple[list[str], str | None]:
    """Validate one link and apply its semantic transition to ``semantic_index``."""

    errors: list[str] = []
    if not isinstance(raw, Mapping) or set(raw) != ENTRY_FIELDS:
        return [f"ledger-entry-{index_number}-fields-invalid"], previous_entry_sha256
    entry = dict(raw)
    if entry.get("sequence") != index_number:
        errors.append(f"ledger-entry-{index_number}-sequence-invalid")
    event = entry.get("event")
    if event not in EVENTS:
        errors.append(f"ledger-entry-{index_number}-event-invalid")
    if entry.get("previous_entry_sha256") != previous_entry_sha256:
        errors.append(f"ledger-entry-{index_number}-previous-hash-mismatch")
    expected_entry_hash = _entry_sha256(entry)
    if entry.get("entry_sha256") != expected_entry_hash:
        errors.append(f"ledger-entry-{index_number}-sha256-mismatch")
    next_previous = (
        entry.get("entry_sha256") if _is_hash(entry.get("entry_sha256")) else None
    )
    if require_audit_hash and not _is_hash(entry.get("audit_event_hash")):
        errors.append(f"ledger-entry-{index_number}-audit-hash-invalid")
    elif verify_audit_anchor and not _audit_anchor_matches(
        audit,
        entry,
        ledger_id=ledger_id,
        index_number=index_number,
    ):
        errors.append(f"ledger-entry-{index_number}-audit-anchor-missing")

    role = entry.get("role")
    ordinal = entry.get("ordinal")
    allocation_id = entry.get("allocation_intent_id")
    thread_id = entry.get("thread_id")
    turn_intent_id = entry.get("turn_intent_id")
    turn_id = entry.get("turn_id")
    evidence_sha256 = entry.get("evidence_sha256")
    if event == "certification-bound":
        semantic_index.increment_certification()
        if any(
            item is not None
            for item in (
                role,
                ordinal,
                allocation_id,
                thread_id,
                turn_intent_id,
                turn_id,
            )
        ):
            errors.append(f"ledger-entry-{index_number}-certification-identity-invalid")
        if not _is_hash(evidence_sha256) or entry.get("outcome") != "bound":
            errors.append(f"ledger-entry-{index_number}-certification-invalid")
        return errors, next_previous
    if role not in EXPECTED_ROLES or ordinal != EXPECTED_ROLES.index(role):
        errors.append(f"ledger-entry-{index_number}-role-ordinal-invalid")
        return errors, next_previous
    if event == "allocation-intent":
        if (
            not _is_uuid(allocation_id)
            or semantic_index.allocation_intent(str(allocation_id)) is not None
            or semantic_index.role_seen(role)
            or any(
                item is not None
                for item in (thread_id, turn_intent_id, turn_id, evidence_sha256)
            )
            or entry.get("outcome") != "pending"
        ):
            errors.append(f"ledger-entry-{index_number}-allocation-intent-invalid")
        else:
            semantic_index.add_allocation_intent(allocation_id, role, entry)
    elif event == "thread-bound":
        expected = semantic_index.allocation_intent(str(allocation_id))
        if (
            expected is None
            or (expected.get("role"), expected.get("ordinal")) != (role, ordinal)
            or not isinstance(thread_id, str)
            or not thread_id
            or semantic_index.thread_binding(thread_id) is not None
            or any(
                item is not None for item in (turn_intent_id, turn_id, evidence_sha256)
            )
            or entry.get("outcome") != "bound"
        ):
            errors.append(f"ledger-entry-{index_number}-thread-binding-invalid")
        else:
            semantic_index.add_thread_binding(thread_id, entry)
    elif event == "turn-intent":
        bound = semantic_index.thread_binding(str(thread_id))
        if (
            bound is None
            or (
                bound.get("role"),
                bound.get("ordinal"),
                bound.get("allocation_intent_id"),
            )
            != (role, ordinal, str(allocation_id))
            or not _is_uuid(turn_intent_id)
            or semantic_index.turn_intent(str(turn_intent_id)) is not None
            or turn_id is not None
            or evidence_sha256 is not None
            or entry.get("outcome") != "pending"
        ):
            errors.append(f"ledger-entry-{index_number}-turn-intent-invalid")
        else:
            semantic_index.add_turn_intent(turn_intent_id, str(thread_id), entry)
    elif event == "turn-bound":
        intent = semantic_index.turn_intent(str(turn_intent_id))
        if (
            intent is None
            or (intent.get("thread_id"), intent.get("allocation_intent_id"))
            != (str(thread_id), str(allocation_id))
            or not isinstance(turn_id, str)
            or not turn_id
            or semantic_index.turn_bound(turn_id)
            or semantic_index.turn_intent_resolved(str(turn_intent_id))
            or evidence_sha256 is not None
            or entry.get("outcome") != "bound"
        ):
            errors.append(f"ledger-entry-{index_number}-turn-binding-invalid")
        else:
            semantic_index.add_bound_turn(
                str(turn_intent_id), turn_id, str(thread_id)
            )
    elif event in {
        "interrupt-observed",
        "archive-observed",
        "containment-audited",
    }:
        bound = semantic_index.thread_binding(str(thread_id))
        if bound is None or (
            bound.get("role"),
            bound.get("ordinal"),
            bound.get("allocation_intent_id"),
        ) != (role, ordinal, str(allocation_id)):
            errors.append(f"ledger-entry-{index_number}-lifecycle-thread-invalid")
        if turn_intent_id is not None:
            intent = semantic_index.turn_intent(str(turn_intent_id))
            if intent is None or (
                intent.get("thread_id"),
                intent.get("allocation_intent_id"),
            ) != (str(thread_id), str(allocation_id)):
                errors.append(
                    f"ledger-entry-{index_number}-lifecycle-turn-intent-invalid"
                )
        if turn_id is not None and (
            not isinstance(turn_id, str)
            or not turn_id
            or not semantic_index.turn_bound(turn_id)
        ):
            errors.append(f"ledger-entry-{index_number}-lifecycle-turn-invalid")
        if event == "containment-audited" and not _is_hash(evidence_sha256):
            errors.append(f"ledger-entry-{index_number}-containment-evidence-invalid")
        absent_resolution = (
            event == "containment-audited"
            and entry.get("outcome") == "turn-intent-verified-absent"
        )
        containment_success = (
            event == "containment-audited"
            and entry.get("outcome") in {"contained", "already-contained"}
        )
        if absent_resolution:
            intent = semantic_index.turn_intent(str(turn_intent_id))
            if (
                intent is None
                or semantic_index.turn_intent_resolved(str(turn_intent_id))
                or turn_id is not None
            ):
                errors.append(
                    f"ledger-entry-{index_number}-turn-intent-containment-invalid"
                )
            else:
                semantic_index.resolve_turn_intent(str(turn_intent_id))
        if event == "containment-audited" and not (
            absent_resolution or containment_success
        ):
            errors.append(f"ledger-entry-{index_number}-containment-outcome-invalid")
        if containment_success and not semantic_index.lifecycle_kind_seen(
            "archive-observed", str(thread_id)
        ):
            errors.append(f"ledger-entry-{index_number}-containment-before-archive")
        if not isinstance(entry.get("outcome"), str) or not entry.get("outcome"):
            errors.append(f"ledger-entry-{index_number}-lifecycle-outcome-invalid")
        if isinstance(thread_id, str) and isinstance(entry.get("outcome"), str):
            semantic_index.add_lifecycle(event, thread_id, entry["outcome"])
    return errors, next_previous


def _validate_live_allocation_ledger_with_index(
    value: Any,
    *,
    audit_file: Path | None = None,
    audit_bytes: bytes | None = None,
) -> tuple[
    list[str],
    _LedgerSemanticIndex,
    list[dict[str, Any]],
    int,
]:
    errors: list[str] = []
    semantic_index = _LedgerSemanticIndex()
    if not isinstance(value, Mapping) or set(value) != LEDGER_FIELDS:
        return ["ledger-fields-invalid"], semantic_index, [], 0
    ledger = dict(value)
    version = ledger.get("version")
    expected_header = {
        LEDGER_VERSION: (LEDGER_TYPE, LEDGER_SCHEMA),
        LEDGER_VERSION_V2: (LEDGER_TYPE_V2, LEDGER_SCHEMA_V2),
    }.get(version)
    if (
        expected_header is None
        or (ledger.get("ledger_type"), ledger.get("schema")) != expected_header
    ):
        errors.append("ledger-header-invalid")
        version = 0
    if not _is_uuid(ledger.get("ledger_id")):
        errors.append("ledger-id-invalid")
    _validate_bindings(ledger.get("bindings"), errors, version=version)
    sequence = ledger.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        errors.append("ledger-sequence-invalid")
        sequence = -1
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        errors.append("ledger-entries-invalid")
        entries = []
    if sequence != len(entries):
        errors.append("ledger-sequence-count-mismatch")

    audits, audit_errors = _load_audit_events(
        audit_file=audit_file,
        audit_bytes=audit_bytes,
    )
    errors.extend(audit_errors)
    previous: str | None = None
    verify_audit_anchor = audit_file is not None or audit_bytes is not None
    if verify_audit_anchor and len(audits) != len(entries):
        errors.append("ledger-audit-entry-count-mismatch")
    for index_number, raw in enumerate(entries, 1):
        entry_errors, previous = _validate_entry_transition(
            raw,
            index_number=index_number,
            previous_entry_sha256=previous,
            semantic_index=semantic_index,
            ledger_id=ledger.get("ledger_id"),
            audit=(audits[index_number - 1] if index_number <= len(audits) else None),
            require_audit_hash=True,
            verify_audit_anchor=verify_audit_anchor,
        )
        errors.extend(entry_errors)
    if semantic_index.certification_count > 1:
        errors.append("ledger-certification-binding-duplicate")
    if ledger.get("head_entry_sha256") != previous:
        errors.append("ledger-head-mismatch")
    if ledger.get("state_sha256") != _state_sha256(ledger):
        errors.append("ledger-state-sha256-mismatch")
    return sorted(set(errors)), semantic_index, audits, len(entries)


def validate_live_allocation_ledger(
    value: Any,
    *,
    audit_file: Path | None = None,
    audit_bytes: bytes | None = None,
) -> list[str]:
    errors, _semantic_index, _audits, _entry_checks = (
        _validate_live_allocation_ledger_with_index(
            value,
            audit_file=audit_file,
            audit_bytes=audit_bytes,
        )
    )
    return errors


def summarize_live_allocation_ledger(
    value: Mapping[str, Any],
    *,
    ledger_file_sha256: str,
) -> dict[str, Any]:
    """Derive the public campaign summary from a validated ledger value."""

    if not _is_hash(ledger_file_sha256):
        raise NativeLiveAllocationLedgerError("ledger-file-sha256-invalid")
    errors = validate_live_allocation_ledger(value)
    if errors:
        raise NativeLiveAllocationLedgerError("ledger-invalid:" + ";".join(errors))
    entries = value["entries"]
    allocation_entries = [
        entry for entry in entries if entry["event"] == "allocation-intent"
    ]
    thread_entries = [entry for entry in entries if entry["event"] == "thread-bound"]
    turn_intents = [entry for entry in entries if entry["event"] == "turn-intent"]
    turn_entries = [entry for entry in entries if entry["event"] == "turn-bound"]
    contained_turn_intents = [
        entry
        for entry in entries
        if entry["event"] == "containment-audited"
        and entry["outcome"] == "turn-intent-verified-absent"
    ]
    bound_allocations = {entry["allocation_intent_id"] for entry in thread_entries}
    resolved_turn_intents = {
        entry["turn_intent_id"]
        for entry in [*turn_entries, *contained_turn_intents]
    }
    return {
        "ledger_type": value["ledger_type"],
        "version": value["version"],
        "ledger_id": value["ledger_id"],
        "live_generation": value["bindings"]["live_generation"],
        "campaign_manifest_sha256": value["bindings"].get("campaign_manifest_sha256"),
        "sequence": value["sequence"],
        "head_entry_sha256": value["head_entry_sha256"],
        "state_sha256": value["state_sha256"],
        "ledger_file_sha256": ledger_file_sha256,
        "allocation_intent_count": len(allocation_entries),
        "thread_bound_count": len(thread_entries),
        "turn_intent_count": len(turn_intents),
        "turn_bound_count": len(turn_entries),
        "unresolved_allocation_intent_count": sum(
            entry["allocation_intent_id"] not in bound_allocations
            for entry in allocation_entries
        ),
        "unresolved_turn_intent_count": sum(
            entry["turn_intent_id"] not in resolved_turn_intents
            for entry in turn_intents
        ),
        "allocated_roles": [entry["role"] for entry in allocation_entries],
    }


class NativeLiveAllocationLedgerStore:
    """Fsync-backed ledger with a validated, process-local semantic head.

    Incremental metrics cover only one-entry transition validation. JSON parsing,
    state hashing/writing, and the shared audit helper remain physical O(n) work.
    """

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory).absolute()
        self.path = self.directory / "ledger.json"
        self.lock_path = self.directory / "ledger.lock"
        self.audit_file = self.directory / "audit.jsonl"
        self._instance_lock = threading.RLock()
        self._metrics_lock = threading.Lock()
        self._trusted: _TrustedLedgerCoordinates | None = None
        self._semantic_index: _LedgerSemanticIndex | None = None
        self._metrics: dict[str, int | float] = {
            "append_attempt_count": 0,
            "append_success_count": 0,
            "append_seconds": 0.0,
            "full_validation_count": 0,
            "full_validation_entry_count": 0,
            "full_validation_seconds": 0.0,
            "incremental_transition_validation_count": 0,
            "incremental_transition_validation_entry_count": 0,
            "incremental_transition_validation_seconds": 0.0,
        }

    def _add_metrics(self, **increments: int | float) -> None:
        with self._metrics_lock:
            for key, increment in increments.items():
                self._metrics[key] += increment

    def metrics(self) -> dict[str, int | float]:
        """Return process-local validation and physical append measurements."""

        with self._metrics_lock:
            return dict(self._metrics)

    def _disarm(self) -> None:
        self._trusted = None
        self._semantic_index = None

    @staticmethod
    def _bindings_sha256(state: Mapping[str, Any]) -> str:
        bindings = state.get("bindings")
        if not isinstance(bindings, Mapping):
            return ""
        return _hash(
            dict(bindings),
            domain="native-live-allocation-ledger-trusted-bindings",
        )

    def _arm(
        self,
        state: Mapping[str, Any],
        semantic_index: _LedgerSemanticIndex,
        *,
        ledger_file: _PrivateFileIdentity,
        audit_file: _PrivateFileIdentity,
        audit_event_count: int,
        audit_head_sha256: Any,
        absence_proof_files: tuple[
            tuple[str, _PrivateFileIdentity], ...
        ] = (),
    ) -> None:
        entries = state["entries"]
        self._trusted = _TrustedLedgerCoordinates(
            ledger_type=state.get("ledger_type"),
            version=state.get("version"),
            schema=state.get("schema"),
            ledger_id=state.get("ledger_id"),
            bindings_sha256=self._bindings_sha256(state),
            sequence=state.get("sequence"),
            entry_count=len(entries),
            head_entry_sha256=state.get("head_entry_sha256"),
            state_sha256=state.get("state_sha256"),
            ledger_file=ledger_file,
            audit_file=audit_file,
            audit_event_count=audit_event_count,
            audit_head_sha256=audit_head_sha256,
            absence_proof_files=absence_proof_files,
        )
        self._semantic_index = semantic_index

    def _full_validate_locked(self, failure_prefix: str) -> dict[str, Any]:
        started = time.perf_counter()
        entry_checks = 0
        try:
            state, ledger_identity = _read_private_json_with_identity(self.path)
            audit_bytes, audit_identity = _read_private_bytes_with_identity(
                self.audit_file, "ledger-audit"
            )
            errors, semantic_index, audits, entry_checks = (
                _validate_live_allocation_ledger_with_index(
                    state,
                    audit_bytes=audit_bytes,
                )
            )
            if errors:
                raise NativeLiveAllocationLedgerError(
                    failure_prefix + ":" + ";".join(errors)
                )
            absence_proof_files = _validate_persisted_turn_absence_proofs(
                self.directory, state
            )
            _require_stable_private_path(self.path, "ledger-file", ledger_identity)
            _require_stable_private_path(
                self.audit_file, "ledger-audit", audit_identity
            )
            self._arm(
                state,
                semantic_index,
                ledger_file=ledger_identity,
                audit_file=audit_identity,
                audit_event_count=len(audits),
                audit_head_sha256=(audits[-1].get("event_hash") if audits else None),
                absence_proof_files=absence_proof_files,
            )
            return state
        except BaseException:
            self._disarm()
            raise
        finally:
            self._add_metrics(
                full_validation_count=1,
                full_validation_entry_count=entry_checks,
                full_validation_seconds=time.perf_counter() - started,
            )

    def _full_validation_operation(self) -> dict[str, Any]:
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                return self._full_validate_locked("ledger-invalid")

    def _require_trusted_locked(
        self,
    ) -> tuple[
        dict[str, Any],
        _TrustedLedgerCoordinates,
        _LedgerSemanticIndex,
        dict[str, Any] | None,
    ]:
        trusted = self._trusted
        semantic_index = self._semantic_index
        if trusted is None or semantic_index is None:
            raise NativeLiveAllocationLedgerError("ledger-store-not-open")
        try:
            state, ledger_identity = _read_private_json_with_identity(self.path)
            audit_tail, audit_identity = _read_private_audit_tail(self.audit_file)
            entries = state.get("entries")
            coordinates_match = bool(
                ledger_identity == trusted.ledger_file
                and audit_identity == trusted.audit_file
                and state.get("ledger_type") == trusted.ledger_type
                and state.get("version") == trusted.version
                and state.get("schema") == trusted.schema
                and state.get("ledger_id") == trusted.ledger_id
                and self._bindings_sha256(state) == trusted.bindings_sha256
                and state.get("sequence") == trusted.sequence
                and isinstance(entries, list)
                and len(entries) == trusted.entry_count
                and state.get("head_entry_sha256") == trusted.head_entry_sha256
                and state.get("state_sha256") == trusted.state_sha256
                and trusted.audit_event_count == trusted.entry_count
                and (audit_tail.get("event_hash") if audit_tail is not None else None)
                == trusted.audit_head_sha256
                and all(
                    _path_private_identity(Path(path), "turn-absence-proof")
                    == identity
                    for path, identity in trusted.absence_proof_files
                )
            )
            if not coordinates_match:
                raise NativeLiveAllocationLedgerError("ledger-store-stale")
            return state, trusted, semantic_index, audit_tail
        except BaseException:
            self._disarm()
            raise

    def initialize(
        self,
        bindings: Mapping[str, Any],
        *,
        version: int = LEDGER_VERSION,
    ) -> dict[str, Any]:
        with self._instance_lock:
            self._disarm()
            if self.directory.exists() or self.directory.is_symlink():
                raise NativeLiveAllocationLedgerError("ledger-directory-already-exists")
            self.directory.mkdir(mode=0o700)
            _strict_private_directory(self.directory)
            for path in (
                self.lock_path,
                self.audit_file,
                self.audit_file.with_name("audit.jsonl.lock"),
            ):
                _create_private_file(path)
            _fsync_directory(self.directory)
            headers = {
                LEDGER_VERSION: (LEDGER_TYPE, LEDGER_SCHEMA),
                LEDGER_VERSION_V2: (LEDGER_TYPE_V2, LEDGER_SCHEMA_V2),
            }
            if version not in headers:
                raise NativeLiveAllocationLedgerError("ledger-version-invalid")
            ledger_type, schema = headers[version]
            state = {
                "ledger_type": ledger_type,
                "version": version,
                "schema": schema,
                "ledger_id": str(uuid.uuid4()),
                "bindings": dict(bindings),
                "sequence": 0,
                "entries": [],
                "head_entry_sha256": None,
            }
            state["state_sha256"] = _state_sha256(state)
            started = time.perf_counter()
            entry_checks = 0
            try:
                errors, _index, _audits, entry_checks = (
                    _validate_live_allocation_ledger_with_index(
                        state,
                        audit_bytes=b"",
                    )
                )
                if errors:
                    raise NativeLiveAllocationLedgerError(
                        "ledger-initial-state-invalid:" + ";".join(errors)
                    )
            finally:
                self._add_metrics(
                    full_validation_count=1,
                    full_validation_entry_count=entry_checks,
                    full_validation_seconds=time.perf_counter() - started,
                )
            _atomic_private_write(self.path, state)
            with _exclusive_lock(self.lock_path):
                return self._full_validate_locked("ledger-initial-state-invalid")

    def open(self) -> dict[str, Any]:
        """Fully validate an existing ledger and arm its trusted head."""

        return self._full_validation_operation()

    def load(self) -> dict[str, Any]:
        """Compatibility full-validation read; successful loads re-arm trust."""

        return self._full_validation_operation()

    def validate(self) -> dict[str, Any]:
        """Explicitly perform full ledger and audit validation."""

        return self._full_validation_operation()

    def checkpoint(self) -> dict[str, Any]:
        """Fully validate and refresh the trusted checkpoint coordinates."""

        return self._full_validation_operation()

    def close(self) -> dict[str, Any]:
        """Fully validate the final state, then disarm this store instance."""

        with self._instance_lock:
            try:
                with _exclusive_lock(self.lock_path):
                    return self._full_validate_locked("ledger-invalid")
            finally:
                self._disarm()

    def _append(self, **fields: Any) -> dict[str, Any]:
        append_started = time.perf_counter()
        success = False
        try:
            with self._instance_lock:
                with _exclusive_lock(self.lock_path):
                    try:
                        state, trusted, semantic_index, _audit_tail = (
                            self._require_trusted_locked()
                        )
                        pre_append_guard = fields.get("_pre_append_guard")
                        guarded_absence_proof: (
                            tuple[str, _PrivateFileIdentity] | None
                        ) = None
                        if pre_append_guard is not None:
                            if not callable(pre_append_guard):
                                raise NativeLiveAllocationLedgerError(
                                    "ledger-pre-append-guard-invalid"
                                )
                            guarded_absence_proof = pre_append_guard(
                                state, trusted, semantic_index
                            )
                            if (
                                not isinstance(guarded_absence_proof, tuple)
                                or len(guarded_absence_proof) != 2
                                or not isinstance(guarded_absence_proof[0], str)
                                or not isinstance(
                                    guarded_absence_proof[1], _PrivateFileIdentity
                                )
                            ):
                                raise NativeLiveAllocationLedgerError(
                                    "ledger-pre-append-guard-result-invalid"
                                )
                        sequence = trusted.entry_count + 1
                        entry = {
                            "sequence": sequence,
                            "event": fields.get("event"),
                            "role": fields.get("role"),
                            "ordinal": fields.get("ordinal"),
                            "allocation_intent_id": fields.get("allocation_intent_id"),
                            "thread_id": fields.get("thread_id"),
                            "turn_intent_id": fields.get("turn_intent_id"),
                            "turn_id": fields.get("turn_id"),
                            "evidence_sha256": fields.get("evidence_sha256"),
                            "outcome": fields.get("outcome"),
                            "previous_entry_sha256": trusted.head_entry_sha256,
                            "audit_event_hash": None,
                        }
                        entry["entry_sha256"] = _entry_sha256(entry)
                        candidate_index = semantic_index.clone()
                        validation_started = time.perf_counter()
                        try:
                            errors, next_head = _validate_entry_transition(
                                entry,
                                index_number=sequence,
                                previous_entry_sha256=trusted.head_entry_sha256,
                                semantic_index=candidate_index,
                                ledger_id=trusted.ledger_id,
                                audit=None,
                                require_audit_hash=False,
                                verify_audit_anchor=False,
                            )
                            if candidate_index.certification_count > 1:
                                errors.append("ledger-certification-binding-duplicate")
                            if next_head != entry["entry_sha256"]:
                                errors.append("ledger-head-mismatch")
                        finally:
                            self._add_metrics(
                                incremental_transition_validation_count=1,
                                incremental_transition_validation_entry_count=1,
                                incremental_transition_validation_seconds=(
                                    time.perf_counter() - validation_started
                                ),
                            )
                        if errors:
                            raise NativeLiveAllocationLedgerError(
                                "ledger-transition-invalid:"
                                + ";".join(sorted(set(errors)))
                            )

                        absence_proof_files = trusted.absence_proof_files
                        if guarded_absence_proof is not None:
                            proof_path, proof_identity = guarded_absence_proof
                            if (
                                _path_private_identity(
                                    Path(proof_path), "turn-absence-proof"
                                )
                                != proof_identity
                            ):
                                raise NativeLiveAllocationLedgerError(
                                    "turn-intent-absence-proof-identity-changed"
                                )
                            absence_proof_files = tuple(
                                item
                                for item in absence_proof_files
                                if item[0] != proof_path
                            ) + (guarded_absence_proof,)

                        # Every remaining operation can mutate durable state. Trust is
                        # deliberately absent until both writes and their identities
                        # have been verified.
                        self._disarm()
                        audit = record_audit_event(
                            {
                                "event_type": ("native_live_allocation_ledger_entry"),
                                "bead_id": state["bindings"]["bead_id"],
                                "dispatch_id": trusted.ledger_id,
                                "packet_sha256": entry["entry_sha256"],
                                "phase": entry["event"],
                                "role": entry["role"] or "ledger",
                                "completion_state": entry["outcome"],
                                "validation_lineage_attempt": sequence,
                                "telemetry_target_event_hash": (
                                    entry["previous_entry_sha256"]
                                ),
                            },
                            audit_file=self.audit_file,
                        )
                        os.chmod(self.audit_file, 0o600, follow_symlinks=False)
                        os.chmod(
                            self.audit_file.with_name("audit.jsonl.lock"),
                            0o600,
                            follow_symlinks=False,
                        )
                        audit_tail, audit_identity = _read_private_audit_tail(
                            self.audit_file
                        )
                        expected_audit_bytes = len(
                            (json.dumps(audit, sort_keys=True) + "\n").encode("utf-8")
                        )
                        audit_advanced_once = bool(
                            audit_tail == audit
                            and audit_identity.device == trusted.audit_file.device
                            and audit_identity.inode == trusted.audit_file.inode
                            and audit_identity.size
                            == trusted.audit_file.size + expected_audit_bytes
                            and audit.get("previous_event_hash")
                            == trusted.audit_head_sha256
                            and audit.get("event_hash")
                            == audit_event_payload_hash(audit)
                        )
                        entry["audit_event_hash"] = audit.get("event_hash")
                        if not audit_advanced_once or not _audit_anchor_matches(
                            audit_tail,
                            entry,
                            ledger_id=trusted.ledger_id,
                            index_number=sequence,
                        ):
                            raise NativeLiveAllocationLedgerError(
                                "ledger-audit-transition-invalid"
                            )

                        updated = {
                            **state,
                            "sequence": sequence,
                            "entries": [*state["entries"], entry],
                            "head_entry_sha256": entry["entry_sha256"],
                        }
                        updated["state_sha256"] = _state_sha256(updated)
                        _atomic_private_write(self.path, updated)
                        ledger_identity = _path_private_identity(
                            self.path, "ledger-file"
                        )
                        _require_stable_private_path(
                            self.audit_file, "ledger-audit", audit_identity
                        )
                        _require_stable_private_path(
                            self.path, "ledger-file", ledger_identity
                        )
                        committed_index = candidate_index.commit()
                        self._arm(
                            updated,
                            committed_index,
                            ledger_file=ledger_identity,
                            audit_file=audit_identity,
                            audit_event_count=trusted.audit_event_count + 1,
                            audit_head_sha256=audit["event_hash"],
                            absence_proof_files=absence_proof_files,
                        )
                        success = True
                        return dict(entry)
                    except BaseException:
                        self._disarm()
                        raise
        finally:
            self._add_metrics(
                append_attempt_count=1,
                append_success_count=int(success),
                append_seconds=time.perf_counter() - append_started,
            )

    def allocation_intent(self, role: str) -> str:
        if role not in EXPECTED_ROLES:
            raise NativeLiveAllocationLedgerError("ledger-role-invalid")
        intent_id = str(uuid.uuid4())
        self._append(
            event="allocation-intent",
            role=role,
            ordinal=EXPECTED_ROLES.index(role),
            allocation_intent_id=intent_id,
            outcome="pending",
        )
        return intent_id

    def bind_thread(self, allocation_intent_id: str, thread_id: str) -> None:
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                _state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                intent = semantic_index.allocation_intent(allocation_intent_id)
        if intent is None:
            raise NativeLiveAllocationLedgerError("allocation-intent-missing")
        self._append(
            event="thread-bound",
            role=intent["role"],
            ordinal=intent["ordinal"],
            allocation_intent_id=allocation_intent_id,
            thread_id=thread_id,
            outcome="bound",
        )

    def _thread_binding(
        self,
        thread_id: str,
        *,
        lifecycle: tuple[str, str] | None = None,
    ) -> tuple[dict[str, Any], str | None, str | None, bool]:
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                _state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                binding = semantic_index.thread_binding(thread_id)
                if binding is None:
                    raise NativeLiveAllocationLedgerError("thread-binding-missing")
                duplicate = bool(
                    lifecycle is not None
                    and semantic_index.lifecycle_seen(
                        lifecycle[0], thread_id, lifecycle[1]
                    )
                )
                return (
                    dict(binding),
                    semantic_index.latest_turn_intent_id(thread_id),
                    semantic_index.latest_turn_id(thread_id),
                    duplicate,
                )

    def turn_intent(self, thread_id: str) -> str:
        binding, existing, _turn_id, _duplicate = self._thread_binding(thread_id)
        if existing is not None:
            raise NativeLiveAllocationLedgerError("turn-intent-duplicate")
        turn_intent_id = str(uuid.uuid4())
        self._append(
            event="turn-intent",
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            outcome="pending",
        )
        return turn_intent_id

    def _turn_intent_resolved(self, turn_intent_id: str) -> bool:
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                _state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                return semantic_index.turn_intent_resolved(turn_intent_id)

    def turn_intent_resolution(self, turn_intent_id: str) -> dict[str, Any]:
        """Return the trusted durable resolution for one exact turn intent."""

        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                intent = semantic_index.turn_intent(turn_intent_id)
                if intent is None:
                    raise NativeLiveAllocationLedgerError("turn-intent-missing")
                bound = [
                    entry
                    for entry in state["entries"]
                    if entry.get("event") == "turn-bound"
                    and entry.get("turn_intent_id") == turn_intent_id
                ]
                absent = [
                    entry
                    for entry in state["entries"]
                    if entry.get("event") == "containment-audited"
                    and entry.get("outcome") == "turn-intent-verified-absent"
                    and entry.get("turn_intent_id") == turn_intent_id
                ]
                if len(bound) + len(absent) > 1:
                    raise NativeLiveAllocationLedgerError(
                        "turn-intent-resolution-ambiguous"
                    )
                if bound:
                    return {
                        "resolution": "turn-bound",
                        "thread_id": intent["thread_id"],
                        "turn_id": bound[0]["turn_id"],
                        "evidence_sha256": None,
                    }
                if absent:
                    _verified_turn_absence_proof(self.directory, state, absent[0])
                    return {
                        "resolution": "verified-absent",
                        "thread_id": intent["thread_id"],
                        "turn_id": None,
                        "evidence_sha256": absent[0]["evidence_sha256"],
                    }
                return {
                    "resolution": "pending",
                    "thread_id": intent["thread_id"],
                    "turn_id": None,
                    "evidence_sha256": None,
                }

    def persist_turn_absence_proof(
        self, proof: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Durably stage one canonical proof before its atomic ledger binding."""

        errors = validate_turn_absence_proof(proof)
        if errors:
            raise NativeLiveAllocationLedgerError(
                "turn-intent-absence-proof-invalid:" + ";".join(errors)
            )
        turn_intent_id = str(proof["turn_intent_id"])
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                intent = semantic_index.turn_intent(turn_intent_id)
                if (
                    intent is None
                    or semantic_index.turn_intent_resolved(turn_intent_id)
                    or proof.get("ledger_id") != state.get("ledger_id")
                    or proof.get("thread_id") != intent.get("thread_id")
                    or proof.get("turn_intent_entry_sha256")
                    != intent.get("entry_sha256")
                ):
                    raise NativeLiveAllocationLedgerError(
                        "turn-intent-absence-proof-link-invalid"
                    )
                proof_directory = self.directory / "turn-absence"
                if proof_directory.exists() or proof_directory.is_symlink():
                    _strict_private_directory(proof_directory)
                else:
                    proof_directory.mkdir(mode=0o700)
                    _fsync_directory(self.directory)
                proof_path = proof_directory / f"{turn_intent_id}.json"
                _atomic_private_write(proof_path, proof)
                persisted, _identity = _read_private_json_with_identity(proof_path)
                if persisted != dict(proof):
                    raise NativeLiveAllocationLedgerError(
                        "turn-intent-absence-proof-persistence-invalid"
                    )
                return persisted

    def bind_turn(self, thread_id: str, turn_intent_id: str, turn_id: str) -> None:
        binding, expected_intent, existing_turn, _duplicate = self._thread_binding(
            thread_id
        )
        resolved = self._turn_intent_resolved(turn_intent_id)
        if expected_intent != turn_intent_id or existing_turn is not None or resolved:
            raise NativeLiveAllocationLedgerError("turn-intent-binding-mismatch")
        self._append(
            event="turn-bound",
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            turn_id=turn_id,
            outcome="bound",
        )

    def resolve_turn_intent_absent(
        self,
        thread_id: str,
        turn_intent_id: str,
        *,
        proof_sha256: str,
    ) -> None:
        """Atomically bind a canonical persisted absence proof to one intent."""

        if not _is_hash(proof_sha256):
            raise NativeLiveAllocationLedgerError(
                "turn-intent-absence-proof-sha256-invalid"
            )
        binding, expected_intent, existing_turn, _duplicate = self._thread_binding(
            thread_id
        )
        if expected_intent != turn_intent_id or existing_turn is not None:
            raise NativeLiveAllocationLedgerError("turn-intent-resolution-mismatch")

        def verify_persisted_proof(
            state: Mapping[str, Any],
            _trusted: _TrustedLedgerCoordinates,
            semantic_index: _LedgerSemanticIndex,
        ) -> tuple[str, _PrivateFileIdentity]:
            intent = semantic_index.turn_intent(turn_intent_id)
            live_binding = semantic_index.thread_binding(thread_id)
            if (
                intent is None
                or live_binding is None
                or intent.get("thread_id") != thread_id
                or intent.get("allocation_intent_id")
                != binding.get("allocation_intent_id")
                or semantic_index.turn_intent_resolved(turn_intent_id)
            ):
                raise NativeLiveAllocationLedgerError(
                    "turn-intent-resolution-mismatch"
                )
            synthetic_entry = {
                "thread_id": thread_id,
                "turn_intent_id": turn_intent_id,
                "evidence_sha256": proof_sha256,
            }
            proof, identity = _verified_turn_absence_proof(
                self.directory,
                state,
                synthetic_entry,
                expected_proof_sha256=proof_sha256,
            )
            proof_path = self.directory / "turn-absence" / (
                f"{proof['turn_intent_id']}.json"
            )
            return str(proof_path), identity

        self._append(
            event="containment-audited",
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            evidence_sha256=proof_sha256,
            outcome="turn-intent-verified-absent",
            _pre_append_guard=verify_persisted_proof,
        )

    def record_lifecycle(self, thread_id: str, event: str, outcome: str) -> None:
        if event not in {"interrupt-observed", "archive-observed"}:
            raise NativeLiveAllocationLedgerError("lifecycle-event-invalid")
        binding, turn_intent_id, turn_id, duplicate = self._thread_binding(
            thread_id,
            lifecycle=(event, outcome),
        )
        if duplicate:
            return
        self._append(
            event=event,
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            turn_id=turn_id,
            outcome=outcome,
        )

    def record_containment_audit(
        self,
        thread_id: str,
        *,
        outcome: str,
        evidence: Mapping[str, Any],
    ) -> None:
        if outcome == "turn-intent-verified-absent":
            raise NativeLiveAllocationLedgerError(
                "containment-outcome-reserved-for-turn-intent-resolution"
            )
        if outcome not in {"contained", "already-contained"}:
            raise NativeLiveAllocationLedgerError(
                "containment-outcome-not-success"
            )
        binding, turn_intent_id, turn_id, _duplicate = self._thread_binding(thread_id)
        self._append(
            event="containment-audited",
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            turn_id=turn_id,
            evidence_sha256=_hash(
                dict(evidence), domain="native-live-containment-audit"
            ),
            outcome=outcome,
        )

    def bind_certification(self, receipt_sha256: str) -> None:
        if not _is_hash(receipt_sha256):
            raise NativeLiveAllocationLedgerError(
                "certification-receipt-sha256-invalid"
            )
        self._append(
            event="certification-bound",
            evidence_sha256=receipt_sha256,
            outcome="bound",
        )

    def has_lifecycle(self, thread_id: str, event: str) -> bool:
        if event not in {"interrupt-observed", "archive-observed"}:
            return False
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                _state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                return semantic_index.lifecycle_kind_seen(event, thread_id)

    def has_successful_containment(self, thread_id: str) -> bool:
        """Return whether an exact containment-success audit exists."""

        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                _state, _trusted, semantic_index, _tail = self._require_trusted_locked()
                return any(
                    semantic_index.lifecycle_seen(
                        "containment-audited", thread_id, outcome
                    )
                    for outcome in ("contained", "already-contained")
                )

    def has_containment_audit(self, thread_id: str) -> bool:
        """Compatibility alias restricted to successful containment outcomes."""

        return self.has_successful_containment(thread_id)

    def summary(self) -> dict[str, Any]:
        with self._instance_lock:
            with _exclusive_lock(self.lock_path):
                state = self._full_validate_locked("ledger-invalid")
                payload, identity = _read_private_bytes_with_identity(
                    self.path, "ledger-file"
                )
                if self._trusted is None or identity != self._trusted.ledger_file:
                    self._disarm()
                    raise NativeLiveAllocationLedgerError("ledger-store-stale")
                return summarize_live_allocation_ledger(
                    state,
                    ledger_file_sha256=hashlib.sha256(payload).hexdigest(),
                )
