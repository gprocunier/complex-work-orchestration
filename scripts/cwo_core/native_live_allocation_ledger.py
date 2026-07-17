"""Private, audited allocation ledger for one native live-canary campaign."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Iterator, Mapping
import uuid

from .audit import iter_audit_events, record_audit_event, verify_audit_log
from .native_canary_contracts import canonical_sha256


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
        uuid.UUID(value)
    except ValueError:
        return False
    return True


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
    _strict_private_regular(path, "ledger-file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeLiveAllocationLedgerError("ledger-file-unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise NativeLiveAllocationLedgerError("ledger-file-not-object")
    return value


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
    if version == LEDGER_VERSION and (live_generation, predecessor_generation) != (4, 3):
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


def validate_live_allocation_ledger(
    value: Any,
    *,
    audit_file: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping) or set(value) != LEDGER_FIELDS:
        return ["ledger-fields-invalid"]
    ledger = dict(value)
    version = ledger.get("version")
    expected_header = {
        LEDGER_VERSION: (LEDGER_TYPE, LEDGER_SCHEMA),
        LEDGER_VERSION_V2: (LEDGER_TYPE_V2, LEDGER_SCHEMA_V2),
    }.get(version)
    if expected_header is None or (
        ledger.get("ledger_type"), ledger.get("schema")
    ) != expected_header:
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

    audits = []
    if audit_file is not None:
        try:
            _strict_private_regular(audit_file, "ledger-audit")
            audits = iter_audit_events(audit_file)
            audit_verification = verify_audit_log(audit_file)
            if audit_verification.get("valid") is not True:
                errors.append("ledger-audit-chain-invalid")
        except (SystemExit, NativeLiveAllocationLedgerError):
            errors.append("ledger-audit-chain-invalid")
    allocation_intents: dict[str, tuple[str, int]] = {}
    bound_threads: dict[str, tuple[str, int, str]] = {}
    turn_intents: dict[str, tuple[str, str]] = {}
    bound_turns: set[str] = set()
    roles_seen: set[str] = set()
    previous: str | None = None
    certification_count = 0
    for index, raw in enumerate(entries, 1):
        if not isinstance(raw, Mapping) or set(raw) != ENTRY_FIELDS:
            errors.append(f"ledger-entry-{index}-fields-invalid")
            continue
        entry = dict(raw)
        if entry.get("sequence") != index:
            errors.append(f"ledger-entry-{index}-sequence-invalid")
        event = entry.get("event")
        if event not in EVENTS:
            errors.append(f"ledger-entry-{index}-event-invalid")
        if entry.get("previous_entry_sha256") != previous:
            errors.append(f"ledger-entry-{index}-previous-hash-mismatch")
        expected_entry_hash = _entry_sha256(entry)
        if entry.get("entry_sha256") != expected_entry_hash:
            errors.append(f"ledger-entry-{index}-sha256-mismatch")
        previous = entry.get("entry_sha256") if _is_hash(entry.get("entry_sha256")) else None
        if not _is_hash(entry.get("audit_event_hash")):
            errors.append(f"ledger-entry-{index}-audit-hash-invalid")
        elif audit_file is not None and not any(
            audit.get("event_hash") == entry.get("audit_event_hash")
            and audit.get("event_type") == "native_live_allocation_ledger_entry"
            and audit.get("dispatch_id") == ledger.get("ledger_id")
            and audit.get("packet_sha256") == entry.get("entry_sha256")
            and audit.get("phase") == event
            and audit.get("validation_lineage_attempt") == index
            for audit in audits
        ):
            errors.append(f"ledger-entry-{index}-audit-anchor-missing")

        role = entry.get("role")
        ordinal = entry.get("ordinal")
        allocation_id = entry.get("allocation_intent_id")
        thread_id = entry.get("thread_id")
        turn_intent_id = entry.get("turn_intent_id")
        turn_id = entry.get("turn_id")
        evidence_sha256 = entry.get("evidence_sha256")
        if event == "certification-bound":
            certification_count += 1
            if any(item is not None for item in (role, ordinal, allocation_id, thread_id, turn_intent_id, turn_id)):
                errors.append(f"ledger-entry-{index}-certification-identity-invalid")
            if not _is_hash(evidence_sha256) or entry.get("outcome") != "bound":
                errors.append(f"ledger-entry-{index}-certification-invalid")
            continue
        if role not in EXPECTED_ROLES or ordinal != EXPECTED_ROLES.index(role):
            errors.append(f"ledger-entry-{index}-role-ordinal-invalid")
            continue
        if event == "allocation-intent":
            if (
                not _is_uuid(allocation_id)
                or allocation_id in allocation_intents
                or role in roles_seen
                or any(item is not None for item in (thread_id, turn_intent_id, turn_id, evidence_sha256))
                or entry.get("outcome") != "pending"
            ):
                errors.append(f"ledger-entry-{index}-allocation-intent-invalid")
            else:
                allocation_intents[allocation_id] = (role, ordinal)
                roles_seen.add(role)
        elif event == "thread-bound":
            expected = allocation_intents.get(str(allocation_id))
            if (
                expected != (role, ordinal)
                or not isinstance(thread_id, str)
                or not thread_id
                or thread_id in bound_threads
                or any(item is not None for item in (turn_intent_id, turn_id, evidence_sha256))
                or entry.get("outcome") != "bound"
            ):
                errors.append(f"ledger-entry-{index}-thread-binding-invalid")
            else:
                bound_threads[thread_id] = (role, ordinal, str(allocation_id))
        elif event == "turn-intent":
            bound = bound_threads.get(str(thread_id))
            if (
                bound != (role, ordinal, str(allocation_id))
                or not _is_uuid(turn_intent_id)
                or turn_intent_id in turn_intents
                or turn_id is not None
                or evidence_sha256 is not None
                or entry.get("outcome") != "pending"
            ):
                errors.append(f"ledger-entry-{index}-turn-intent-invalid")
            else:
                turn_intents[turn_intent_id] = (str(thread_id), str(allocation_id))
        elif event == "turn-bound":
            if (
                turn_intents.get(str(turn_intent_id)) != (str(thread_id), str(allocation_id))
                or not isinstance(turn_id, str)
                or not turn_id
                or turn_id in bound_turns
                or evidence_sha256 is not None
                or entry.get("outcome") != "bound"
            ):
                errors.append(f"ledger-entry-{index}-turn-binding-invalid")
            else:
                bound_turns.add(turn_id)
        elif event in {"interrupt-observed", "archive-observed", "containment-audited"}:
            if bound_threads.get(str(thread_id)) != (role, ordinal, str(allocation_id)):
                errors.append(f"ledger-entry-{index}-lifecycle-thread-invalid")
            if turn_intent_id is not None and turn_intents.get(str(turn_intent_id)) != (
                str(thread_id),
                str(allocation_id),
            ):
                errors.append(f"ledger-entry-{index}-lifecycle-turn-intent-invalid")
            if turn_id is not None and turn_id not in bound_turns:
                errors.append(f"ledger-entry-{index}-lifecycle-turn-invalid")
            if event == "containment-audited" and not _is_hash(evidence_sha256):
                errors.append(f"ledger-entry-{index}-containment-evidence-invalid")
            if not isinstance(entry.get("outcome"), str) or not entry.get("outcome"):
                errors.append(f"ledger-entry-{index}-lifecycle-outcome-invalid")
    if certification_count > 1:
        errors.append("ledger-certification-binding-duplicate")
    if ledger.get("head_entry_sha256") != previous:
        errors.append("ledger-head-mismatch")
    if ledger.get("state_sha256") != _state_sha256(ledger):
        errors.append("ledger-state-sha256-mismatch")
    return sorted(set(errors))


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
    allocation_entries = [entry for entry in entries if entry["event"] == "allocation-intent"]
    thread_entries = [entry for entry in entries if entry["event"] == "thread-bound"]
    turn_intents = [entry for entry in entries if entry["event"] == "turn-intent"]
    turn_entries = [entry for entry in entries if entry["event"] == "turn-bound"]
    bound_allocations = {entry["allocation_intent_id"] for entry in thread_entries}
    bound_turn_intents = {entry["turn_intent_id"] for entry in turn_entries}
    return {
        "ledger_type": value["ledger_type"],
        "version": value["version"],
        "ledger_id": value["ledger_id"],
        "live_generation": value["bindings"]["live_generation"],
        "campaign_manifest_sha256": value["bindings"].get(
            "campaign_manifest_sha256"
        ),
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
            entry["turn_intent_id"] not in bound_turn_intents for entry in turn_intents
        ),
        "allocated_roles": [entry["role"] for entry in allocation_entries],
    }


class NativeLiveAllocationLedgerStore:
    """Fsync-backed, no-follow ledger with one external audit anchor per event."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory).absolute()
        self.path = self.directory / "ledger.json"
        self.lock_path = self.directory / "ledger.lock"
        self.audit_file = self.directory / "audit.jsonl"

    def initialize(
        self,
        bindings: Mapping[str, Any],
        *,
        version: int = LEDGER_VERSION,
    ) -> dict[str, Any]:
        if self.directory.exists() or self.directory.is_symlink():
            raise NativeLiveAllocationLedgerError("ledger-directory-already-exists")
        self.directory.mkdir(mode=0o700)
        _strict_private_directory(self.directory)
        for path in (self.lock_path, self.audit_file, self.audit_file.with_name("audit.jsonl.lock")):
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
        errors = validate_live_allocation_ledger(state, audit_file=self.audit_file)
        if errors:
            raise NativeLiveAllocationLedgerError("ledger-initial-state-invalid:" + ";".join(errors))
        _atomic_private_write(self.path, state)
        return state

    def load(self) -> dict[str, Any]:
        with _exclusive_lock(self.lock_path):
            state = _read_private_json(self.path)
            errors = validate_live_allocation_ledger(state, audit_file=self.audit_file)
            if errors:
                raise NativeLiveAllocationLedgerError("ledger-invalid:" + ";".join(errors))
            return state

    def _append(self, **fields: Any) -> dict[str, Any]:
        with _exclusive_lock(self.lock_path):
            state = _read_private_json(self.path)
            errors = validate_live_allocation_ledger(state, audit_file=self.audit_file)
            if errors:
                raise NativeLiveAllocationLedgerError("ledger-invalid:" + ";".join(errors))
            sequence = state["sequence"] + 1
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
                "previous_entry_sha256": state["head_entry_sha256"],
            }
            entry["entry_sha256"] = _entry_sha256(entry)
            audit = record_audit_event(
                {
                    "event_type": "native_live_allocation_ledger_entry",
                    "bead_id": state["bindings"]["bead_id"],
                    "dispatch_id": state["ledger_id"],
                    "packet_sha256": entry["entry_sha256"],
                    "phase": entry["event"],
                    "role": entry["role"] or "ledger",
                    "completion_state": entry["outcome"],
                    "validation_lineage_attempt": sequence,
                    "telemetry_target_event_hash": entry["previous_entry_sha256"],
                },
                audit_file=self.audit_file,
            )
            os.chmod(self.audit_file, 0o600, follow_symlinks=False)
            os.chmod(self.audit_file.with_name("audit.jsonl.lock"), 0o600, follow_symlinks=False)
            entry["audit_event_hash"] = audit["event_hash"]
            updated = {
                **state,
                "sequence": sequence,
                "entries": [*state["entries"], entry],
                "head_entry_sha256": entry["entry_sha256"],
            }
            updated["state_sha256"] = _state_sha256(updated)
            errors = validate_live_allocation_ledger(updated, audit_file=self.audit_file)
            if errors:
                raise NativeLiveAllocationLedgerError("ledger-transition-invalid:" + ";".join(errors))
            _atomic_private_write(self.path, updated)
            return entry

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
        state = self.load()
        intent = next(
            (
                entry
                for entry in state["entries"]
                if entry["event"] == "allocation-intent"
                and entry["allocation_intent_id"] == allocation_intent_id
            ),
            None,
        )
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

    def _thread_binding(self, thread_id: str) -> tuple[dict[str, Any], str | None, str | None]:
        state = self.load()
        binding = next(
            (
                entry
                for entry in state["entries"]
                if entry["event"] == "thread-bound" and entry["thread_id"] == thread_id
            ),
            None,
        )
        if binding is None:
            raise NativeLiveAllocationLedgerError("thread-binding-missing")
        turn_intent = next(
            (
                entry
                for entry in reversed(state["entries"])
                if entry["event"] == "turn-intent" and entry["thread_id"] == thread_id
            ),
            None,
        )
        turn_bound = next(
            (
                entry
                for entry in reversed(state["entries"])
                if entry["event"] == "turn-bound" and entry["thread_id"] == thread_id
            ),
            None,
        )
        return (
            binding,
            turn_intent["turn_intent_id"] if turn_intent else None,
            turn_bound["turn_id"] if turn_bound else None,
        )

    def turn_intent(self, thread_id: str) -> str:
        binding, existing, _turn_id = self._thread_binding(thread_id)
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

    def bind_turn(self, thread_id: str, turn_intent_id: str, turn_id: str) -> None:
        binding, expected_intent, existing_turn = self._thread_binding(thread_id)
        if expected_intent != turn_intent_id or existing_turn is not None:
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

    def record_lifecycle(self, thread_id: str, event: str, outcome: str) -> None:
        if event not in {"interrupt-observed", "archive-observed"}:
            raise NativeLiveAllocationLedgerError("lifecycle-event-invalid")
        binding, turn_intent_id, turn_id = self._thread_binding(thread_id)
        state = self.load()
        if any(
            entry["event"] == event
            and entry["thread_id"] == thread_id
            and entry["outcome"] == outcome
            for entry in state["entries"]
        ):
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
        binding, turn_intent_id, turn_id = self._thread_binding(thread_id)
        self._append(
            event="containment-audited",
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            turn_id=turn_id,
            evidence_sha256=_hash(dict(evidence), domain="native-live-containment-audit"),
            outcome=outcome,
        )

    def bind_certification(self, receipt_sha256: str) -> None:
        if not _is_hash(receipt_sha256):
            raise NativeLiveAllocationLedgerError("certification-receipt-sha256-invalid")
        self._append(
            event="certification-bound",
            evidence_sha256=receipt_sha256,
            outcome="bound",
        )

    def has_lifecycle(self, thread_id: str, event: str) -> bool:
        if event not in {"interrupt-observed", "archive-observed"}:
            return False
        return any(
            entry["event"] == event and entry["thread_id"] == thread_id
            for entry in self.load()["entries"]
        )

    def summary(self) -> dict[str, Any]:
        state = self.load()
        return summarize_live_allocation_ledger(
            state,
            ledger_file_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
        )
