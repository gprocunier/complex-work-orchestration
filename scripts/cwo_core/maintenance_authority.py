"""Controller-owned maintenance authority; serialized worker data grants nothing.

The embedding controller supplies the verification key, expected operator
identity, closed factory registry, and current-state callbacks from its trusted
configuration. NEVER obtain any of those inputs from a submitted plan, worker
return, or caller-selected trust-file path. Signing records a directive already
adopted by that controller; it does not authenticate a human request by itself.

This module uses the existing operator-directive HMAC format. Its opaque
capabilities are process-local and bound to one verifier. A private state
directory is not protection against an unrestricted same-UID worker: the caller
must enforce a real sandbox/isolation boundary excluding keys and controller
state. Admission here is not model attestation, containment, or product acceptance.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any, Callable, Mapping
import uuid

from .native_authority import (
    AUTHORITY_PROVENANCE_VERSION,
    OPERATOR_DIRECTIVE_FIELDS,
    AuthorityProvenanceError,
    VerifiedAuthority,
    canonical_authority_sha256,
    canonical_json_object,
    verify_operator_directive,
)
from .native_pool_contracts import canonical_sha256 as canonical_plan_sha256


class MaintenanceAuthorityError(ValueError):
    """A maintenance grant, operation, current state, or capability is invalid."""


_TOKEN = object()
_MISSION_FIELDS = frozenset({"mission_type", "version", "mission_id", "objective", "provenance", "scope", "budget", "lifetime"})
_OPERATION_FIELDS = frozenset({"operation_id", "mission_id", "mission_sha256", "revocation_generation", "plan_sha256", "factory_id", "workspace", "model", "role", "write_paths", "reservation"})
_RESERVATION_FIELDS = frozenset({"mode", "sessions", "tool_calls", "runtime_seconds", "cleanup_seconds", "max_concurrency"})
_STATE_FIELDS = frozenset({"state_type", "version", "mission_id", "mission_sha256", "revocation_generation", "status", "operations"})
_OPERATION_STATE_FIELDS = frozenset({"operation_sha256", "plan_sha256", "state", "outcome"})


def _need(condition: bool, reason: str) -> None:
    if condition is not True:
        raise MaintenanceAuthorityError("maintenance-" + reason)


def _object(value: Any, fields: frozenset[str] | set[str] | None, label: str) -> dict[str, Any]:
    _need(type(value) is dict, label + "-object-required")
    try:
        detached = canonical_json_object(value, label="maintenance-" + label)
    except (AuthorityProvenanceError, ValueError, TypeError) as exc:
        raise MaintenanceAuthorityError("maintenance-" + label + "-json-invalid") from exc
    if fields is not None:
        _need(set(detached) == set(fields), label + "-fields-invalid")
    return detached


def _text(value: Any, label: str) -> str:
    _need(type(value) is str and bool(value.strip()) and value == value.strip(), label + "-invalid")
    return value


def _digest(value: Any, label: str) -> str:
    _need(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value), label + "-invalid")
    return value


def _number(value: Any, label: str, minimum: int = 0) -> int:
    _need(type(value) is int and value >= minimum, label + "-invalid")
    return value


def _strings(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    _need(type(value) is list and (bool(value) or not nonempty), label + "-invalid")
    for item in value:
        _text(item, label)
    _need(len(value) == len(set(value)), label + "-duplicate")
    return value


def _absolute(value: Any, label: str) -> Path:
    raw = _text(value, label)
    path = Path(raw)
    _need(path.is_absolute() and str(path) == raw and ".." not in path.parts and path != Path(path.anchor), label + "-path-invalid")
    _need(not any(p.is_symlink() for p in (path, *path.parents)), label + "-symlink-forbidden")
    return path


def _relative_paths(value: Any, label: str) -> list[str]:
    paths = _strings(value, label, nonempty=False)
    for raw in paths:
        path = Path(raw)
        _need(not path.is_absolute() and path.as_posix() == raw and not any(p in {".", ".."} for p in path.parts) and raw != "." and "\\" not in raw, label + "-path-invalid")
    return paths


def mission_sha256(mission: Mapping[str, Any]) -> str:
    """Hash a validated mission; the hash is an identity, never authorization."""
    return canonical_authority_sha256(normalize_maintenance_mission(mission))


def normalize_maintenance_mission(value: Any) -> dict[str, Any]:
    mission = _object(value, _MISSION_FIELDS, "mission")
    _need(mission["mission_type"] == "cwo-maintenance-mission" and type(mission["version"]) is int and mission["version"] == 1, "mission-type-invalid")
    _text(mission["mission_id"], "mission-id")
    _text(mission["objective"], "objective")
    provenance = _object(mission["provenance"], {"adoption_id", "user_request_sha256"}, "provenance")
    _text(provenance["adoption_id"], "adoption-id")
    _digest(provenance["user_request_sha256"], "user-request-sha256")
    scope = _object(mission["scope"], {"effect_scope", "workspace_roots", "models", "roles", "factory_ids"}, "scope")
    _need(scope["effect_scope"] == "cwo-maintenance", "effect-scope-invalid")
    for root in _strings(scope["workspace_roots"], "workspace-roots"):
        _absolute(root, "workspace-root")
    _strings(scope["models"], "models")
    _strings(scope["factory_ids"], "factory-ids")
    _need(set(_strings(scope["roles"], "roles")) <= {"product", "review"}, "roles-invalid")
    _need(_object(mission["budget"], {"mode"}, "mission-budget") == {"mode": "unbounded"}, "mission-budget-mode-invalid")
    _need(_object(mission["lifetime"], {"mode"}, "mission-lifetime") == {"mode": "until-revoked"}, "mission-lifetime-mode-invalid")
    return mission


def _directive(receipt: Any, *, key: bytes, actor: str, identity: str, action: str, parent: str | None) -> VerifiedAuthority:
    value = _object(receipt, OPERATOR_DIRECTIVE_FIELDS, "directive")
    _need(type(value["version"]) is int and value["version"] == AUTHORITY_PROVENANCE_VERSION, "directive-version-invalid")
    _need(value["authorized_scope"] == "complete-task", "directive-scope-invalid")
    _need(value["parent_receipt_sha256"] == parent, "directive-parent-mismatch")
    try:
        stamp = datetime.fromisoformat(_text(value["issued_at"], "directive-issued-at").replace("Z", "+00:00"))
        _need(stamp.tzinfo is not None, "directive-issued-at-timezone-required")
        return verify_operator_directive(value, verification_key=key, expected_actor_id=actor, expected_identity_source=identity, expected_action_sha256=action)
    except (AuthorityProvenanceError, ValueError, TypeError) as exc:
        raise MaintenanceAuthorityError("maintenance-directive-verification-failed") from exc


def sign_controller_directive(*, verification_key: bytes, actor_id: str, identity_source: str, action_sha256: str, directive_id: str, parent_receipt_sha256: str | None = None, issued_at: str | None = None, nonce: str | None = None) -> dict[str, Any]:
    """Serialize the EXISTING directive format after trusted parent adoption.

    This helper has no authority source of its own. The key must be injected by
    the operator controller and must never be available to sandboxed workers.
    """
    _need(type(verification_key) is bytes and bool(verification_key), "verification-key-required")
    for value, label in ((actor_id, "actor"), (identity_source, "identity"), (directive_id, "directive-id")):
        _text(value, label)
    _digest(action_sha256, "action-sha256")
    if parent_receipt_sha256 is not None:
        _digest(parent_receipt_sha256, "parent-sha256")
    body = {"version": AUTHORITY_PROVENANCE_VERSION, "directive_id": directive_id, "action_sha256": action_sha256, "actor_id": actor_id, "identity_source": identity_source, "authorized_scope": "complete-task", "parent_receipt_sha256": parent_receipt_sha256, "issued_at": issued_at or datetime.now(timezone.utc).isoformat(), "nonce": nonce or uuid.uuid4().hex}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    receipt = dict(body, signature=hmac.new(verification_key, encoded, hashlib.sha256).hexdigest())
    _directive(receipt, key=verification_key, actor=actor_id, identity=identity_source, action=action_sha256, parent=parent_receipt_sha256)
    return receipt


def _state(value: Any, mission_id: str, mission_hash: str) -> dict[str, Any]:
    state = _object(value, _STATE_FIELDS, "state")
    _need(state["state_type"] == "cwo-maintenance-authority-state" and type(state["version"]) is int and state["version"] == 1, "state-type-invalid")
    _need(state["mission_id"] == mission_id and state["mission_sha256"] == mission_hash, "state-mission-mismatch")
    _number(state["revocation_generation"], "revocation-generation")
    _need(state["status"] in ("active", "revoked", "completed"), "state-status-invalid")
    operations = _object(state["operations"], None, "state-operations")
    for operation_id, row in operations.items():
        _text(operation_id, "state-operation-id")
        row = _object(row, _OPERATION_STATE_FIELDS, "state-operation")
        _digest(row["operation_sha256"], "state-operation-sha256")
        _digest(row["plan_sha256"], "state-plan-sha256")
        _need(row["state"] in ("claimed", "settled"), "state-operation-status-invalid")
        _need((row["state"] == "claimed" and row["outcome"] == "pending") or (row["state"] == "settled" and row["outcome"] in ("accepted", "contained", "failed")), "state-operation-outcome-invalid")
    return state


class MaintenanceStateStore:
    """Small serial controller ledger, in a precreated private trusted directory.

    The directory is a controller-configured input, NEVER a worker plan field.
    This supplies current-state and one-shot claim callbacks, not authentication.
    No historical accounting is reset and no consumed operation can be removed.
    """

    def __init__(self, directory: str | Path, *, mission_id: str, mission_sha256: str) -> None:
        self.directory = _absolute(str(directory), "state-directory")
        self.mission_id = _text(mission_id, "mission-id")
        self.mission_sha256 = _digest(mission_sha256, "mission-sha256")
        info = self.directory.stat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "state-directory-not-private")
        self._directory_identity = (info.st_dev, info.st_ino)
        self._mutex = threading.RLock()
        self._active = False

    @contextmanager
    def _locked(self):
        with self._mutex:
            _need(not self._active, "state-operation-reentrant")
            self._active = True
            directory_fd = lock_fd = None
            try:
                _absolute(str(self.directory), "state-directory")
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                info = os.fstat(directory_fd)
                _need((info.st_dev, info.st_ino) == self._directory_identity and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "state-directory-replaced")
                lock_fd = os.open("maintenance-state.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
                self._private_file(lock_fd)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                yield directory_fd
            finally:
                if lock_fd is not None:
                    os.close(lock_fd)
                if directory_fd is not None:
                    os.close(directory_fd)
                self._active = False

    @staticmethod
    def _private_file(fd: int) -> None:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "state-file-not-private")

    def _read(self, directory_fd: int) -> dict[str, Any]:
        fd = os.open("maintenance-state.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            self._private_file(fd)
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                value = json.load(stream)
            return _state(value, self.mission_id, self.mission_sha256)
        finally:
            os.close(fd)

    def _write(self, directory_fd: int, value: Mapping[str, Any], *, initialize: bool = False) -> None:
        encoded = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
        temporary = "maintenance-state-" + uuid.uuid4().hex + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(fd)
            if initialize:
                os.link(temporary, "maintenance-state.json", src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
                os.unlink(temporary, dir_fd=directory_fd)
            else:
                os.replace(temporary, "maintenance-state.json", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def initialize(self) -> None:
        with self._locked() as directory_fd:
            value = {"state_type": "cwo-maintenance-authority-state", "version": 1, "mission_id": self.mission_id, "mission_sha256": self.mission_sha256, "revocation_generation": 0, "status": "active", "operations": {}}
            self._write(directory_fd, value, initialize=True)

    def read_state(self) -> dict[str, Any]:
        with self._locked() as directory_fd:
            return self._read(directory_fd)

    def claim_operation(self, operation_id: str, operation_sha256: str, plan_sha256: str, expected_generation: int) -> None:
        _text(operation_id, "operation-id")
        _digest(operation_sha256, "operation-sha256")
        _digest(plan_sha256, "plan-sha256")
        _number(expected_generation, "expected-generation")
        with self._locked() as directory_fd:
            value = self._read(directory_fd)
            _need(value["status"] == "active" and value["revocation_generation"] == expected_generation, "authority-not-current")
            _need(operation_id not in value["operations"], "operation-already-consumed")
            value["operations"][operation_id] = {"operation_sha256": operation_sha256, "plan_sha256": plan_sha256, "state": "claimed", "outcome": "pending"}
            self._write(directory_fd, value)

    def settle(self, operation_id: str, operation_sha256: str, *, outcome: str) -> None:
        _need(type(outcome) is str and outcome in ("accepted", "contained", "failed"), "settlement-outcome-invalid")
        with self._locked() as directory_fd:
            value = self._read(directory_fd)
            row = value["operations"].get(operation_id)
            _need(type(row) is dict and row["operation_sha256"] == operation_sha256 and row["state"] == "claimed", "settlement-operation-mismatch")
            row.update(state="settled", outcome=outcome)
            self._write(directory_fd, value)

    def revoke(self, *, completed: bool = False) -> None:
        _need(type(completed) is bool, "completed-flag-invalid")
        with self._locked() as directory_fd:
            value = self._read(directory_fd)
            _need(value["status"] == "active", "authority-already-inactive")
            value["status"] = "completed" if completed else "revoked"
            value["revocation_generation"] += 1
            self._write(directory_fd, value)


class MaintenanceAuthorityVerifier:
    """Trusted controller configuration; never reconstruct this from a plan."""

    def __init__(self, *, mission: Mapping[str, Any], operator_directive: Mapping[str, Any], verification_key: bytes, expected_actor_id: str, expected_identity_source: str, factory_registry: Mapping[str, Any], state_reader: Callable[[], Mapping[str, Any]], claim_operation: Callable[[str, str, str, int], None]) -> None:
        _need(type(verification_key) is bytes and bool(verification_key), "verification-key-required")
        self._mission = normalize_maintenance_mission(mission)
        self._mission_hash = canonical_authority_sha256(self._mission)
        self._actor = _text(expected_actor_id, "expected-actor")
        self._identity = _text(expected_identity_source, "expected-identity")
        self._authority = _directive(operator_directive, key=verification_key, actor=self._actor, identity=self._identity, action=self._mission_hash, parent=None)
        self._directive_hash = canonical_authority_sha256(operator_directive)
        self._key = verification_key
        self._factories = _object(factory_registry, None, "factory-registry")
        _need(bool(self._factories), "factory-registry-empty")
        for factory_id, descriptor in self._factories.items():
            _text(factory_id, "factory-id")
            descriptor = _object(descriptor, {"adapter_path", "adapter_sha256"}, "factory")
            _absolute(descriptor["adapter_path"], "factory-adapter")
            _digest(descriptor["adapter_sha256"], "factory-adapter-sha256")
        _need(set(self._mission["scope"]["factory_ids"]) <= set(self._factories), "mission-factory-unregistered")
        _need(callable(state_reader) and callable(claim_operation), "trusted-state-callbacks-required")
        self._state_reader = state_reader
        self._claim = claim_operation
        self._pid = os.getpid()
        self._capabilities: dict[str, VerifiedMaintenanceOperation] = {}
        self._mutex = threading.RLock()
        self._active = False
        self._current()

    @contextmanager
    def _serial(self):
        with self._mutex:
            _need(not self._active, "verification-reentrant")
            self._active = True
            try:
                yield
            finally:
                self._active = False

    def _current(self) -> dict[str, Any]:
        _need(os.getpid() == self._pid, "controller-process-mismatch")
        value = _state(self._state_reader(), self._mission["mission_id"], self._mission_hash)
        _need(value["status"] == "active", "authority-not-current")
        return value

    def _validate_operation(self, plan: Any, operation: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        plan = _object(plan, None, "plan")
        operation = _object(operation, _OPERATION_FIELDS, "operation")
        plan_hash = _digest(plan.get("plan_sha256"), "plan-sha256")
        _need(canonical_plan_sha256({k: v for k, v in plan.items() if k != "plan_sha256"}) == plan_hash, "plan-digest-mismatch")
        _need(operation["plan_sha256"] == plan_hash and plan.get("authority_sha256") == self._mission_hash, "operation-plan-authority-mismatch")
        _text(operation["operation_id"], "operation-id")
        _need(operation["mission_id"] == self._mission["mission_id"] and operation["mission_sha256"] == self._mission_hash, "operation-mission-mismatch")
        _number(operation["revocation_generation"], "revocation-generation")
        scope = self._mission["scope"]
        for field, permitted in (("model", scope["models"]), ("role", scope["roles"]), ("factory_id", scope["factory_ids"])):
            _need(type(operation[field]) is str and operation[field] in permitted, "operation-" + field + "-not-authorized")
        _need(plan.get("selected_model") == operation["model"], "operation-model-mismatch")
        workspace = _absolute(operation["workspace"], "workspace")
        _need(workspace.is_dir() and any(workspace.is_relative_to(Path(root)) for root in scope["workspace_roots"]), "workspace-not-authorized")
        paths = _relative_paths(operation["write_paths"], "write-paths")
        _need((operation["role"] == "review" and paths == []) or (operation["role"] == "product" and bool(paths)), "operation-role-write-mismatch")
        for relative in paths:
            _absolute(str(workspace / relative), "write-target")
        children = plan.get("children")
        _need(type(children) is list and 1 <= len(children) <= 3 and all(type(child) is dict for child in children), "operation-children-invalid")
        child_paths = []
        for child in children:
            _need(child.get("requested_model") == operation["model"], "child-model-mismatch")
            declared = _relative_paths(child.get("write_paths"), "child-write-paths")
            read_only = child.get("read_only", False)
            _need(type(read_only) is bool and read_only == (operation["role"] == "review") and read_only == (declared == []), "child-role-mismatch")
            child_paths.extend(declared)
        _need(len(child_paths) == len(set(child_paths)) and sorted(child_paths) == sorted(paths), "child-write-scope-mismatch")
        reservation = _object(operation["reservation"], _RESERVATION_FIELDS, "reservation")
        _need(reservation["mode"] == "finite-operation", "reservation-mode-invalid")
        for field in _RESERVATION_FIELDS - {"mode"}:
            _number(reservation[field], "reservation-" + field, 1)
        _need(len(children) <= reservation["max_concurrency"] <= 3, "reservation-concurrency-invalid")
        required = _number(plan.get("required_session_count"), "required-session-count", 1)
        budget = _object(plan.get("budget"), None, "plan-budget")
        _need(type(budget.get("reserved_sessions")) is int and required <= reservation["sessions"] == budget["reserved_sessions"], "reservation-session-mismatch")
        descriptor = self._factories[operation["factory_id"]]
        _need(plan.get("runtime_adapter_path") == descriptor["adapter_path"] and plan.get("runtime_adapter_sha256") == descriptor["adapter_sha256"], "unregistered-adapter")
        self._check_adapter(descriptor)
        return plan, operation

    @staticmethod
    def _check_adapter(descriptor: Mapping[str, Any]) -> bytes:
        path = _absolute(descriptor["adapter_path"], "factory-adapter")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            _need(stat.S_ISREG(os.fstat(fd).st_mode), "factory-adapter-not-regular")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                source = stream.read()
            _need(hashlib.sha256(source).hexdigest() == descriptor["adapter_sha256"], "factory-adapter-drift")
            return source
        finally:
            os.close(fd)

    def verify_operation(self, plan: Mapping[str, Any], operation: Mapping[str, Any], operation_directive: Mapping[str, Any]) -> "VerifiedMaintenanceOperation":
        """Check signature, closed factory, scope and current state before import.

        Verification does not consume an operation identity. Execution must call
        ``claim()`` BEFORE adapter import; validate-only need not import at all.
        """
        with self._serial():
            plan, operation = self._validate_operation(plan, operation)
            operation_hash = canonical_authority_sha256(operation)
            authority = _directive(operation_directive, key=self._key, actor=self._actor, identity=self._identity, action=operation_hash, parent=self._directive_hash)
            state = self._current()
            _need(state["revocation_generation"] == operation["revocation_generation"], "revocation-generation-mismatch")
            _need(operation["operation_id"] not in state["operations"], "operation-already-consumed")
            # The state reader is an external callback: static observation must
            # follow it, not precede it, at this admission boundary.
            self._validate_operation(plan, operation)
            value = VerifiedMaintenanceOperation(self, plan, operation, authority, _TOKEN)
            self._capabilities[value._identity] = value
            return value

    def _check_capability(self, capability: "VerifiedMaintenanceOperation", *, require_claimed: bool) -> None:
        _need(type(require_claimed) is bool, "require-claimed-flag-invalid")
        _need(type(capability) is VerifiedMaintenanceOperation and self._capabilities.get(capability._identity) is capability and capability._verifier is self, "foreign-or-serialized-capability")
        _need(canonical_authority_sha256(capability._operation) == capability._operation_hash, "capability-operation-drift")
        state = self._current()
        self._validate_operation(capability._plan, capability._operation)
        workspace_info = Path(capability._operation["workspace"]).stat()
        _need((workspace_info.st_dev, workspace_info.st_ino) == capability._workspace_identity, "workspace-replaced")
        operation = capability._operation
        _need(state["revocation_generation"] == operation["revocation_generation"], "revocation-generation-mismatch")
        row = state["operations"].get(operation["operation_id"])
        if require_claimed:
            _need(capability._claimed and row == {"operation_sha256": capability._operation_hash, "plan_sha256": operation["plan_sha256"], "state": "claimed", "outcome": "pending"}, "operation-not-live-claimed")
        else:
            _need(not capability._claimed and row is None, "operation-already-consumed")


class VerifiedMaintenanceOperation:
    """Opaque, non-transferable authority for one signed operation and factory."""

    __slots__ = ("_verifier", "_plan", "_operation", "_operation_hash", "_authority", "_identity", "_workspace_identity", "_claimed", "_claiming")

    def __init__(self, verifier: MaintenanceAuthorityVerifier, plan: dict[str, Any], operation: dict[str, Any], authority: VerifiedAuthority, token: object) -> None:
        _need(token is _TOKEN, "capability-construction-forbidden")
        self._verifier = verifier
        self._plan = plan
        self._operation = operation
        self._operation_hash = canonical_authority_sha256(operation)
        self._authority = authority
        self._identity = uuid.uuid4().hex
        workspace_info = Path(operation["workspace"]).stat()
        self._workspace_identity = (workspace_info.st_dev, workspace_info.st_ino)
        self._claimed = False
        self._claiming = False

    @property
    def adapter_path(self) -> Path:
        return Path(self._plan["runtime_adapter_path"])

    @property
    def operation_sha256(self) -> str:
        return self._operation_hash

    def evidence(self) -> dict[str, Any]:
        """A detached diagnostic copy; this output cannot authorize execution."""
        return {"evidence_type": "cwo-maintenance-operation-admission", "version": 1, "operation": _object(self._operation, _OPERATION_FIELDS, "operation"), "operation_sha256": self._operation_hash, "authority_provenance": self._authority.serialize(), "claimed": self._claimed}

    def revalidate(self, *, require_claimed: bool = True, plan: Mapping[str, Any] | None = None, runtime_scope: Mapping[str, Any] | None = None) -> None:
        with self._verifier._serial():
            _need(not self._claiming, "operation-claim-reentrant")
            if plan is not None:
                supplied = _object(plan, None, "plan")
                _need(canonical_authority_sha256(supplied) == canonical_authority_sha256(self._plan), "capability-plan-mismatch")
            if runtime_scope is not None:
                supplied_scope = _object(runtime_scope, {"workspace", "model", "role", "write_paths"}, "runtime-scope")
                expected_scope = {key: self._operation[key] for key in supplied_scope}
                _need(canonical_authority_sha256(supplied_scope) == canonical_authority_sha256(expected_scope), "runtime-scope-mismatch")
            self._verifier._check_capability(self, require_claimed=require_claimed)

    def bound_plan(self) -> dict[str, Any]:
        """Return a revalidated detached plan for consuming exact scope bindings."""
        with self._verifier._serial():
            self._verifier._check_capability(self, require_claimed=True)
            from copy import deepcopy
            return deepcopy(self._plan)

    def read_adapter_source(self) -> bytes:
        """Return the authorized bytes to compile, never import the path again.

        The caller may compile these bytes with ``str(adapter_path)`` as their
        filename and execute them in its selected installed module namespace.
        No adapter code executes here; the one-shot claim must already exist.
        """
        with self._verifier._serial():
            self._verifier._check_capability(self, require_claimed=True)
            descriptor = self._verifier._factories[self._operation["factory_id"]]
            return self._verifier._check_adapter(descriptor)

    def claim(self) -> None:
        with self._verifier._serial():
            _need(not self._claiming, "operation-claim-reentrant")
            self._verifier._check_capability(self, require_claimed=False)
            self._claiming = True
            try:
                operation = self._operation
                self._verifier._claim(operation["operation_id"], self._operation_hash, operation["plan_sha256"], operation["revocation_generation"])
                self._claimed = True
            finally:
                self._claiming = False
            # Failure after a durable claim does NOT reclaim the attempt identity.
            self._verifier._check_capability(self, require_claimed=True)


def require_maintenance_operation(value: Any, *, plan: Mapping[str, Any] | None = None, verifier: MaintenanceAuthorityVerifier | None = None, require_claimed: bool = True, runtime_scope: Mapping[str, Any] | None = None) -> VerifiedMaintenanceOperation:
    """Reject copied/serialized assertions and recheck the issuing controller."""
    _need(type(value) is VerifiedMaintenanceOperation, "opaque-operation-required")
    _need(type(verifier) is MaintenanceAuthorityVerifier, "trusted-verifier-required")
    _need(value._verifier is verifier, "foreign-controller-capability")
    value.revalidate(require_claimed=require_claimed, plan=plan, runtime_scope=runtime_scope)
    return value
