"""Owner-private one-shot ledger for the native activation preview.

This ledger is intentionally independent from the historical seven-role live
campaign ledger.  It records one fixed activation attempt and has no resume,
retry, refill, or replacement transition.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import uuid


LEDGER_TYPE = "cwo-native-tool-activation-ledger"
LEDGER_VERSION = 1
LEDGER_SCHEMA = "schemas/native-tool-activation-ledger.schema.json"
PROFILE_ROLES = {
    "n1-read-only": ("calibration", "read-only-0"),
    "n2-read-only": ("calibration", "read-only-0", "read-only-1"),
    "n1-mutable": ("calibration", "mutable-0"),
}
WORKER_ROLES = {
    profile: tuple(role for role in roles if role != "calibration")
    for profile, roles in PROFILE_ROLES.items()
}
EVENTS = frozenset(
    {
        "claim-acquired",
        "approval-consume-intent",
        "approval-verified",
        "activation-dispatch-intent",
        "allocation-intent",
        "thread-bound",
        "turn-intent",
        "turn-bound",
        "terminal",
    }
)
LEDGER_FIELDS = frozenset(
    {
        "ledger_type",
        "version",
        "schema",
        "ledger_id",
        "profile",
        "plan_sha256",
        "claim_sha256",
        "action_sha256",
        "campaign_nonce",
        "expected_roles",
        "created_at",
        "entries",
        "head_entry_sha256",
        "ledger_sha256",
    }
)
ENTRY_FIELDS = frozenset(
    {
        "sequence",
        "event",
        "recorded_at",
        "role",
        "intent_id",
        "subject_id",
        "detail_sha256",
        "previous_entry_sha256",
        "entry_sha256",
    }
)


class NativeActivationLedgerError(ValueError):
    """Fail-closed activation ledger error with stable messages."""


def canonical_activation_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeActivationLedgerError(
            "activation-value-not-canonical-json"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _is_uuid(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def activation_iso(value: dt.datetime | None = None) -> str:
    current = value or dt.datetime.now(dt.timezone.utc)
    if not isinstance(current, dt.datetime) or current.tzinfo is None:
        raise NativeActivationLedgerError("activation-time-invalid")
    return (
        current.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(path)
    if not absolute.is_absolute():
        raise NativeActivationLedgerError("activation-path-not-absolute")
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor /= part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise NativeActivationLedgerError(
                "activation-path-unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise NativeActivationLedgerError(
                "activation-symlink-component-forbidden"
            )


def fsync_private_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise NativeActivationLedgerError(
                "activation-directory-permissions-invalid"
            )
        os.fsync(descriptor)
    except NativeActivationLedgerError:
        raise
    except OSError as exc:
        raise NativeActivationLedgerError(
            "activation-directory-fsync-failed"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def ensure_private_directory(path: Path, *, create: bool = True) -> Path:
    supplied = Path(path)
    if not supplied.is_absolute():
        raise NativeActivationLedgerError("activation-path-not-absolute")
    _reject_symlink_components(supplied)
    if create:
        missing: list[Path] = []
        cursor = supplied
        while not cursor.exists():
            missing.append(cursor)
            if cursor.parent == cursor:
                raise NativeActivationLedgerError(
                    "activation-directory-unavailable"
                )
            cursor = cursor.parent
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
            except OSError as exc:
                raise NativeActivationLedgerError(
                    "activation-directory-create-failed"
                ) from exc
            try:
                parent_descriptor = os.open(
                    directory.parent,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
            except OSError as exc:
                raise NativeActivationLedgerError(
                    "activation-directory-parent-fsync-failed"
                ) from exc
    try:
        metadata = supplied.lstat()
    except OSError as exc:
        raise NativeActivationLedgerError(
            "activation-directory-unavailable"
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise NativeActivationLedgerError(
            "activation-directory-permissions-invalid"
        )
    fsync_private_directory(supplied)
    return supplied


def _validate_open_private_file(
    descriptor: int,
    path: Path,
    *,
    label: str,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise NativeActivationLedgerError(f"{label}-file-invalid")
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise NativeActivationLedgerError(f"{label}-path-invalid") from exc
    if (
        stat.S_ISLNK(path_metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise NativeActivationLedgerError(f"{label}-inode-mismatch")
    return metadata


def write_exclusive_private_bytes(
    path: Path,
    raw: bytes,
    *,
    label: str,
) -> None:
    if not isinstance(raw, bytes):
        raise NativeActivationLedgerError(f"{label}-bytes-required")
    ensure_private_directory(path.parent, create=False)
    _reject_symlink_components(path)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        _validate_open_private_file(descriptor, path, label=label)
    except FileExistsError as exc:
        raise NativeActivationLedgerError(f"{label}-already-exists") from exc
    except NativeActivationLedgerError:
        raise
    except OSError as exc:
        raise NativeActivationLedgerError(f"{label}-write-failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    fsync_private_directory(path.parent)


def write_exclusive_private_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    label: str,
) -> None:
    raw = (
        json.dumps(
            deepcopy(dict(value)),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    write_exclusive_private_bytes(path, raw, label=label)


def read_private_bytes(
    path: Path,
    *,
    label: str,
    maximum_bytes: int = 8 * 1024 * 1024,
) -> bytes:
    _reject_symlink_components(path)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = _validate_open_private_file(
            descriptor,
            path,
            label=label,
        )
        if metadata.st_size > maximum_bytes:
            raise NativeActivationLedgerError(f"{label}-too-large")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes:
            raise NativeActivationLedgerError(f"{label}-too-large")
        return raw
    except NativeActivationLedgerError:
        raise
    except OSError as exc:
        raise NativeActivationLedgerError(f"{label}-read-failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_private_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_private_bytes(path, label=label))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeActivationLedgerError(f"{label}-json-invalid") from exc
    if type(value) is not dict:
        raise NativeActivationLedgerError(f"{label}-object-required")
    return value


def replace_private_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    label: str,
) -> None:
    ensure_private_directory(path.parent, create=False)
    _reject_symlink_components(path)
    if path.exists():
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            _validate_open_private_file(descriptor, path, label=label)
        finally:
            os.close(descriptor)
    encoded = (
        json.dumps(
            deepcopy(dict(value)),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.tmp-",
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary = Path(temporary_name)
        temporary_metadata = temporary.lstat()
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_uid != os.geteuid()
            or temporary_metadata.st_nlink != 1
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
        ):
            raise NativeActivationLedgerError(f"{label}-temporary-invalid")
        os.replace(temporary, path)
        temporary_name = ""
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            _validate_open_private_file(descriptor, path, label=label)
        finally:
            os.close(descriptor)
            descriptor = -1
        fsync_private_directory(path.parent)
    except NativeActivationLedgerError:
        raise
    except OSError as exc:
        raise NativeActivationLedgerError(f"{label}-replace-failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


@contextmanager
def locked_private_file(path: Path, *, label: str) -> Iterator[None]:
    ensure_private_directory(path.parent, create=False)
    _reject_symlink_components(path)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        _validate_open_private_file(descriptor, path, label=label)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_open_private_file(descriptor, path, label=label)
        yield
    except NativeActivationLedgerError:
        raise
    except OSError as exc:
        raise NativeActivationLedgerError(f"{label}-lock-failed") from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _entry_unsigned(
    *,
    sequence: int,
    event: str,
    role: str | None,
    intent_id: str | None,
    subject_id: str | None,
    detail_sha256: str,
    previous_entry_sha256: str | None,
    recorded_at: str,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "event": event,
        "recorded_at": recorded_at,
        "role": role,
        "intent_id": intent_id,
        "subject_id": subject_id,
        "detail_sha256": detail_sha256,
        "previous_entry_sha256": previous_entry_sha256,
    }


def _validate_entry_shape(entry: Any, sequence: int) -> dict[str, Any]:
    if type(entry) is not dict or set(entry) != ENTRY_FIELDS:
        raise NativeActivationLedgerError("activation-ledger-entry-fields-invalid")
    if entry.get("sequence") != sequence or entry.get("event") not in EVENTS:
        raise NativeActivationLedgerError("activation-ledger-entry-header-invalid")
    for field in ("detail_sha256", "entry_sha256"):
        if not _is_sha256(entry.get(field)):
            raise NativeActivationLedgerError(
                f"activation-ledger-entry-{field.replace('_', '-')}-invalid"
            )
    unsigned = dict(entry)
    observed = unsigned.pop("entry_sha256")
    if observed != canonical_activation_sha256(unsigned):
        raise NativeActivationLedgerError(
            "activation-ledger-entry-sha256-mismatch"
        )
    return dict(entry)


def _replay_entries(
    entries: list[Any],
    *,
    expected_roles: tuple[str, ...],
) -> dict[str, Any]:
    previous: str | None = None
    phase = "new"
    allocation_index = 0
    pending_allocation: tuple[str, str] | None = None
    thread_by_role: dict[str, str] = {}
    pending_turn: tuple[str, str, str] | None = None
    turn_roles = expected_roles
    turn_index = 0
    terminal = False
    for sequence, raw in enumerate(entries):
        entry = _validate_entry_shape(raw, sequence)
        if entry["previous_entry_sha256"] != previous:
            raise NativeActivationLedgerError(
                "activation-ledger-entry-chain-invalid"
            )
        event = entry["event"]
        role = entry["role"]
        intent_id = entry["intent_id"]
        subject_id = entry["subject_id"]
        if terminal:
            raise NativeActivationLedgerError(
                "activation-ledger-event-after-terminal"
            )
        if event == "claim-acquired":
            if phase != "new" or any(
                value is not None for value in (role, intent_id, subject_id)
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-claim-sequence-invalid"
                )
            phase = "claimed"
        elif event == "approval-consume-intent":
            if phase != "claimed" or any(
                value is not None for value in (role, intent_id, subject_id)
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-approval-intent-sequence-invalid"
                )
            phase = "approval-intent"
        elif event == "approval-verified":
            if phase != "approval-intent" or any(
                value is not None for value in (role, intent_id, subject_id)
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-approval-sequence-invalid"
                )
            phase = "approval-verified"
        elif event == "activation-dispatch-intent":
            if phase != "approval-verified" or any(
                value is not None for value in (role, intent_id, subject_id)
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-dispatch-intent-sequence-invalid"
                )
            phase = "allocating"
        elif event == "allocation-intent":
            if (
                phase != "allocating"
                or pending_allocation is not None
                or allocation_index >= len(expected_roles)
                or role != expected_roles[allocation_index]
                or not _is_uuid(intent_id)
                or subject_id is not None
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-allocation-intent-sequence-invalid"
                )
            pending_allocation = (str(role), str(intent_id))
        elif event == "thread-bound":
            if (
                phase != "allocating"
                or pending_allocation != (role, intent_id)
                or not _is_uuid(subject_id)
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-thread-bind-sequence-invalid"
                )
            thread_by_role[str(role)] = str(subject_id)
            pending_allocation = None
            allocation_index += 1
            if role == "calibration":
                phase = "calibration-turning"
            elif allocation_index == len(expected_roles):
                phase = "worker-turning"
        elif event == "turn-intent":
            expected_role = (
                turn_roles[turn_index] if turn_index < len(turn_roles) else None
            )
            if (
                phase
                not in {
                    "calibration-turning",
                    "worker-turning",
                }
                or pending_turn is not None
                or role != expected_role
                or not _is_uuid(intent_id)
                or subject_id != thread_by_role.get(str(role))
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-turn-intent-sequence-invalid"
                )
            pending_turn = (str(role), str(intent_id), str(subject_id))
        elif event == "turn-bound":
            if (
                phase
                not in {
                    "calibration-turning",
                    "worker-turning",
                }
                or pending_turn
                != (str(role), str(intent_id), thread_by_role.get(str(role)))
                or not _is_uuid(subject_id)
            ):
                raise NativeActivationLedgerError(
                    "activation-ledger-turn-bind-sequence-invalid"
                )
            pending_turn = None
            turn_index += 1
            if role == "calibration":
                phase = "allocating"
            elif turn_index == len(turn_roles):
                phase = "dispatched"
        elif event == "terminal":
            if phase == "new" or role is not None or intent_id is not None:
                raise NativeActivationLedgerError(
                    "activation-ledger-terminal-sequence-invalid"
                )
            terminal = True
            phase = "terminal"
        previous = str(entry["entry_sha256"])
    return {
        "phase": phase,
        "head_entry_sha256": previous,
        "allocation_index": allocation_index,
        "pending_allocation": pending_allocation,
        "thread_by_role": thread_by_role,
        "turn_index": turn_index,
        "pending_turn": pending_turn,
        "terminal": terminal,
    }


def validate_activation_ledger(value: Any) -> list[str]:
    try:
        if type(value) is not dict or set(value) != LEDGER_FIELDS:
            raise NativeActivationLedgerError(
                "activation-ledger-fields-invalid"
            )
        if (
            value.get("ledger_type") != LEDGER_TYPE
            or value.get("version") != LEDGER_VERSION
            or value.get("schema") != LEDGER_SCHEMA
        ):
            raise NativeActivationLedgerError(
                "activation-ledger-header-invalid"
            )
        if not _is_uuid(value.get("ledger_id")):
            raise NativeActivationLedgerError(
                "activation-ledger-id-invalid"
            )
        profile = value.get("profile")
        if profile not in PROFILE_ROLES:
            raise NativeActivationLedgerError(
                "activation-ledger-profile-invalid"
            )
        expected_roles = value.get("expected_roles")
        if expected_roles != list(PROFILE_ROLES[str(profile)]):
            raise NativeActivationLedgerError(
                "activation-ledger-roles-invalid"
            )
        for field in ("plan_sha256", "claim_sha256", "action_sha256"):
            if not _is_sha256(value.get(field)):
                raise NativeActivationLedgerError(
                    f"activation-ledger-{field.replace('_', '-')}-invalid"
                )
        if not _is_uuid(value.get("campaign_nonce")):
            raise NativeActivationLedgerError(
                "activation-ledger-campaign-nonce-invalid"
            )
        entries = value.get("entries")
        if type(entries) is not list:
            raise NativeActivationLedgerError(
                "activation-ledger-entries-invalid"
            )
        replay = _replay_entries(
            entries,
            expected_roles=PROFILE_ROLES[str(profile)],
        )
        if value.get("head_entry_sha256") != replay["head_entry_sha256"]:
            raise NativeActivationLedgerError(
                "activation-ledger-head-invalid"
            )
        unsigned = dict(value)
        observed = unsigned.pop("ledger_sha256")
        if not _is_sha256(observed) or observed != canonical_activation_sha256(
            unsigned
        ):
            raise NativeActivationLedgerError(
                "activation-ledger-sha256-mismatch"
            )
        return []
    except (NativeActivationLedgerError, TypeError, ValueError) as exc:
        return [str(exc)]


def _seal_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop("ledger_sha256", None)
    result["ledger_sha256"] = canonical_activation_sha256(result)
    errors = validate_activation_ledger(result)
    if errors:
        raise NativeActivationLedgerError(
            "activation-ledger-invalid:" + ";".join(errors)
        )
    return result


class NativeActivationLedgerStore:
    """Durable append-only state for one permanently consumed activation."""

    def __init__(self, directory: Path) -> None:
        self.directory = ensure_private_directory(Path(directory), create=False)
        self.ledger_path = self.directory / "ledger.json"
        self.audit_path = self.directory / "audit.jsonl"
        self.lock_path = self.directory / ".ledger.lock"

    @classmethod
    def create(
        cls,
        directory: Path,
        *,
        profile: str,
        plan_sha256: str,
        claim_sha256: str,
        action_sha256: str,
        campaign_nonce: str,
        created_at: str | None = None,
    ) -> NativeActivationLedgerStore:
        if profile not in PROFILE_ROLES:
            raise NativeActivationLedgerError(
                "activation-ledger-profile-invalid"
            )
        target = ensure_private_directory(Path(directory), create=True)
        store = cls(target)
        ledger = {
            "ledger_type": LEDGER_TYPE,
            "version": LEDGER_VERSION,
            "schema": LEDGER_SCHEMA,
            "ledger_id": str(uuid.uuid4()),
            "profile": profile,
            "plan_sha256": plan_sha256,
            "claim_sha256": claim_sha256,
            "action_sha256": action_sha256,
            "campaign_nonce": campaign_nonce,
            "expected_roles": list(PROFILE_ROLES[profile]),
            "created_at": created_at or activation_iso(),
            "entries": [],
            "head_entry_sha256": None,
        }
        write_exclusive_private_json(
            store.ledger_path,
            _seal_ledger(ledger),
            label="activation-ledger",
        )
        write_exclusive_private_bytes(
            store.audit_path,
            b"",
            label="activation-ledger-audit",
        )
        store.append("claim-acquired", detail={"claim_sha256": claim_sha256})
        return store

    def load(self) -> dict[str, Any]:
        value = read_private_json(
            self.ledger_path,
            label="activation-ledger",
        )
        errors = validate_activation_ledger(value)
        if errors:
            raise NativeActivationLedgerError(
                "activation-ledger-invalid:" + ";".join(errors)
            )
        return value

    def summary(self) -> dict[str, Any]:
        """Return the durable lifecycle phase without exposing audit details."""

        ledger = self.load()
        replay = _replay_entries(
            list(ledger["entries"]),
            expected_roles=PROFILE_ROLES[str(ledger["profile"])],
        )
        return {
            "phase": replay["phase"],
            "pending_allocation": replay["pending_allocation"] is not None,
            "pending_turn": replay["pending_turn"] is not None,
            "terminal": replay["terminal"],
        }

    def append(
        self,
        event: str,
        *,
        role: str | None = None,
        intent_id: str | None = None,
        subject_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        if event not in EVENTS:
            raise NativeActivationLedgerError(
                "activation-ledger-event-invalid"
            )
        detail_sha256 = canonical_activation_sha256(dict(detail or {}))
        with locked_private_file(
            self.lock_path,
            label="activation-ledger",
        ):
            ledger = self.load()
            entries = list(ledger["entries"])
            unsigned = _entry_unsigned(
                sequence=len(entries),
                event=event,
                role=role,
                intent_id=intent_id,
                subject_id=subject_id,
                detail_sha256=detail_sha256,
                previous_entry_sha256=ledger["head_entry_sha256"],
                recorded_at=recorded_at or activation_iso(),
            )
            entry = {
                **unsigned,
                "entry_sha256": canonical_activation_sha256(unsigned),
            }
            candidate_entries = [*entries, entry]
            _replay_entries(
                candidate_entries,
                expected_roles=PROFILE_ROLES[str(ledger["profile"])],
            )
            ledger["entries"] = candidate_entries
            ledger["head_entry_sha256"] = entry["entry_sha256"]
            sealed = _seal_ledger(ledger)
            replace_private_json(
                self.ledger_path,
                sealed,
                label="activation-ledger",
            )
            audit_descriptor = -1
            try:
                audit_descriptor = os.open(
                    self.audit_path,
                    os.O_WRONLY
                    | os.O_APPEND
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                _validate_open_private_file(
                    audit_descriptor,
                    self.audit_path,
                    label="activation-ledger-audit",
                )
                line = (
                    json.dumps(
                        entry,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8")
                offset = 0
                while offset < len(line):
                    offset += os.write(audit_descriptor, line[offset:])
                os.fsync(audit_descriptor)
            except NativeActivationLedgerError:
                raise
            except OSError as exc:
                raise NativeActivationLedgerError(
                    "activation-ledger-audit-write-failed"
                ) from exc
            finally:
                if audit_descriptor >= 0:
                    os.close(audit_descriptor)
            return entry

    def allocation_intent(self, role: str) -> str:
        intent_id = str(uuid.uuid4())
        self.append(
            "allocation-intent",
            role=role,
            intent_id=intent_id,
            detail={"role": role},
        )
        return intent_id

    def bind_thread(
        self,
        allocation_intent_id: str,
        role: str,
        thread_id: str,
    ) -> None:
        self.append(
            "thread-bound",
            role=role,
            intent_id=allocation_intent_id,
            subject_id=thread_id,
            detail={"thread_id": thread_id},
        )

    def turn_intent(self, role: str, thread_id: str, prompt: str) -> str:
        intent_id = str(uuid.uuid4())
        self.append(
            "turn-intent",
            role=role,
            intent_id=intent_id,
            subject_id=thread_id,
            detail={
                "thread_id": thread_id,
                "prompt_sha256": hashlib.sha256(
                    prompt.encode("utf-8")
                ).hexdigest(),
            },
        )
        return intent_id

    def bind_turn(
        self,
        role: str,
        turn_intent_id: str,
        turn_id: str,
    ) -> None:
        self.append(
            "turn-bound",
            role=role,
            intent_id=turn_intent_id,
            subject_id=turn_id,
            detail={"turn_id": turn_id},
        )
