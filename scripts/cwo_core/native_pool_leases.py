"""Process-safe lifecycle leases for native supervision pools."""

from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping

from .native_pool_contracts import (
    LEASE_SCHEMA,
    LEASE_TYPE,
    VERSION,
    canonical_sha256,
    seal_artifact,
    validate_lease,
    validate_pool_contract,
    validate_pool_state,
    write_private_artifact,
)


REGISTRY_TYPE = "cwo-native-supervision-lease-registry"
REGISTRY_VERSION = 1
REGISTRY_FIELDS = {"registry_type", "version", "leases", "registry_sha256"}
ACTIVE_LEASE_STATES = {"acquired", "held", "release-pending", "orphaned-active"}


class PoolLeaseError(ValueError):
    """Base class for fail-closed pool lease errors."""


class PoolLeaseCollision(PoolLeaseError):
    """Raised when a worktree or logical integration target is already held."""


def _iso(value: dt.datetime | str | None = None) -> str:
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PoolLeaseError("invalid-lease-time") from exc
    elif isinstance(value, dt.datetime):
        parsed = value
    elif value is None:
        parsed = dt.datetime.now(dt.timezone.utc)
    else:
        raise PoolLeaseError("invalid-lease-time")
    if parsed.tzinfo is None:
        raise PoolLeaseError("lease-time-must-be-timezone-aware")
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _boot_id_sha256() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PoolLeaseError("boot-identity-unavailable") from exc
    if not value:
        raise PoolLeaseError("boot-identity-empty")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _process_start_ticks(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise PoolLeaseError("process-identity-unavailable") from exc
    close = raw.rfind(")")
    if close < 0:
        raise PoolLeaseError("process-identity-malformed")
    fields = raw[close + 1 :].split()
    if len(fields) <= 19:
        raise PoolLeaseError("process-identity-incomplete")
    try:
        ticks = int(fields[19])
    except ValueError as exc:
        raise PoolLeaseError("process-identity-malformed") from exc
    if ticks <= 0:
        raise PoolLeaseError("process-start-ticks-invalid")
    return ticks


def capture_owner_identity(pid: int | None = None) -> dict[str, Any]:
    owner_pid = os.getpid() if pid is None else pid
    if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
        raise PoolLeaseError("owner-pid-invalid")
    return {
        "pid": owner_pid,
        "start_ticks": _process_start_ticks(owner_pid),
        "boot_id_sha256": _boot_id_sha256(),
    }


def owner_identity_is_live(owner: Mapping[str, Any]) -> bool:
    try:
        return capture_owner_identity(int(owner.get("pid", 0))) == dict(owner)
    except (PoolLeaseError, TypeError, ValueError):
        return False


def _identity_key(value: Any) -> str:
    if not isinstance(value, Mapping):
        raise PoolLeaseError("lease-identity-invalid")
    return canonical_sha256(
        {
            field: value.get(field)
            for field in (
                "canonical_path_sha256",
                "git_common_dir_sha256",
                "device",
                "inode",
            )
        }
    )


def _paths_overlap(first: list[str], second: list[str]) -> bool:
    for left in first:
        left_parts = PurePosixPath(left).parts
        for right in second:
            right_parts = PurePosixPath(right).parts
            if left_parts == right_parts[: len(left_parts)] or right_parts == left_parts[: len(right_parts)]:
                return True
    return False


def _registry_hash(value: Mapping[str, Any]) -> str:
    return canonical_sha256({key: item for key, item in value.items() if key != "registry_sha256"})


def _seal_registry(leases: list[Mapping[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "registry_type": REGISTRY_TYPE,
        "version": REGISTRY_VERSION,
        "leases": [dict(lease) for lease in leases],
    }
    value["registry_sha256"] = canonical_sha256(value)
    return value


class PoolLeaseRegistry:
    """One process-locked registry retaining leases through verified pool close."""

    def __init__(
        self,
        path: Path | str,
        *,
        owner_alive: Callable[[Mapping[str, Any]], bool] = owner_identity_is_live,
        now: Callable[[], dt.datetime | str] | None = None,
    ) -> None:
        # Preserve the final path component so a pre-existing symlink is
        # detected instead of silently resolved to its target.
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._owner_alive = owner_alive
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if self.path.exists() and self.path.is_symlink():
            raise PoolLeaseError("lease-registry-path-is-symlink")
        if self.lock_path.exists() and self.lock_path.is_symlink():
            raise PoolLeaseError("lease-registry-lock-is-symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _load_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        if self.path.is_symlink():
            raise PoolLeaseError("lease-registry-path-is-symlink")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PoolLeaseError("lease-registry-unreadable") from exc
        if not isinstance(value, Mapping) or set(value) != REGISTRY_FIELDS:
            raise PoolLeaseError("lease-registry-fields-invalid")
        if value.get("registry_type") != REGISTRY_TYPE or value.get("version") != REGISTRY_VERSION:
            raise PoolLeaseError("lease-registry-header-invalid")
        if value.get("registry_sha256") != _registry_hash(value):
            raise PoolLeaseError("lease-registry-sha256-mismatch")
        leases = value.get("leases")
        if not isinstance(leases, list):
            raise PoolLeaseError("lease-registry-leases-invalid")
        result: list[dict[str, Any]] = []
        ids: set[str] = set()
        for lease in leases:
            errors = validate_lease(lease)
            if errors:
                raise PoolLeaseError("lease-registry-artifact-invalid:" + ";".join(errors))
            lease_id = str(lease["lease_id"])
            if lease_id in ids:
                raise PoolLeaseError("lease-registry-duplicate-lease-id")
            ids.add(lease_id)
            result.append(dict(lease))
        return result

    def _write_unlocked(self, leases: list[Mapping[str, Any]]) -> None:
        write_private_artifact(self.path, _seal_registry(leases))

    def snapshot(self) -> list[dict[str, Any]]:
        with self._locked():
            return self._load_unlocked()

    @staticmethod
    def _child(contract: Mapping[str, Any], child_id: str) -> Mapping[str, Any]:
        return next(
            (
                child
                for child in contract.get("children", [])
                if isinstance(child, Mapping) and child.get("child_id") == child_id
            ),
            {},
        )

    def acquire(self, contract: Mapping[str, Any], child_id: str) -> dict[str, Any]:
        errors = validate_pool_contract(contract)
        if errors:
            raise PoolLeaseError("pool-contract-invalid:" + ";".join(errors))
        child = self._child(contract, child_id)
        if not child:
            raise PoolLeaseError("lease-child-unknown")
        now = _iso(self._now())
        lease = seal_artifact(
            {
                "lease_type": LEASE_TYPE,
                "version": VERSION,
                "schema": LEASE_SCHEMA,
                "lease_id": child["lease_id"],
                "pool_id": contract["pool_id"],
                "child_id": child_id,
                "pool_epoch": contract["pool_epoch"],
                "integration_root_identity": contract["topology"]["integration_root_identity"],
                "worktree_identity": child["worktree_identity"],
                "target_paths": list(child["integration_target_paths"]),
                "owner": contract["owner"],
                "lifecycle_state": "acquired",
                "acquired_at": now,
                "updated_at": now,
                "terminal_evidence_sha256": None,
                "release_reason": None,
            },
            "lease_sha256",
        )
        lease_errors = validate_lease(lease, contract=contract)
        if lease_errors:
            raise PoolLeaseError("lease-invalid:" + ";".join(lease_errors))

        with self._locked():
            leases = self._load_unlocked()
            changed = False
            for index, existing in enumerate(leases):
                if existing["lifecycle_state"] not in ACTIVE_LEASE_STATES:
                    continue
                if not self._owner_alive(existing["owner"]) and existing["lifecycle_state"] != "orphaned-active":
                    existing = seal_artifact(
                        {**existing, "lifecycle_state": "orphaned-active", "updated_at": now},
                        "lease_sha256",
                    )
                    leases[index] = existing
                    changed = True
                if existing["lease_id"] == lease["lease_id"]:
                    if changed:
                        self._write_unlocked(leases)
                    raise PoolLeaseCollision("lease-id-already-active")
                same_root = _identity_key(existing["integration_root_identity"]) == _identity_key(
                    lease["integration_root_identity"]
                )
                same_worktree = _identity_key(existing["worktree_identity"]) == _identity_key(
                    lease["worktree_identity"]
                )
                same_pool = (
                    existing["pool_id"] == lease["pool_id"]
                    and existing["pool_epoch"] == lease["pool_epoch"]
                )
                read_only_siblings = same_pool and not existing["target_paths"] and not lease["target_paths"]
                if same_worktree and not read_only_siblings:
                    if changed:
                        self._write_unlocked(leases)
                    raise PoolLeaseCollision("worktree-lease-collision")
                if same_root and _paths_overlap(existing["target_paths"], lease["target_paths"]):
                    if changed:
                        self._write_unlocked(leases)
                    raise PoolLeaseCollision("integration-target-lease-collision")
            leases.append(lease)
            self._write_unlocked(leases)
        return lease

    def _transition(
        self,
        lease_id: str,
        *,
        lifecycle_state: str,
        terminal_evidence_sha256: str | None,
        release_reason: str | None,
    ) -> dict[str, Any]:
        with self._locked():
            leases = self._load_unlocked()
            index = next((i for i, lease in enumerate(leases) if lease["lease_id"] == lease_id), None)
            if index is None:
                raise PoolLeaseError("lease-not-found")
            current = leases[index]
            if current["lifecycle_state"] == "released":
                if lifecycle_state == "released":
                    return current
                raise PoolLeaseError("released-lease-cannot-transition")
            updated = seal_artifact(
                {
                    **current,
                    "lifecycle_state": lifecycle_state,
                    "updated_at": _iso(self._now()),
                    "terminal_evidence_sha256": terminal_evidence_sha256,
                    "release_reason": release_reason,
                },
                "lease_sha256",
            )
            errors = validate_lease(updated)
            if errors:
                raise PoolLeaseError("lease-transition-invalid:" + ";".join(errors))
            leases[index] = updated
            self._write_unlocked(leases)
            return updated

    def hold(self, lease_id: str) -> dict[str, Any]:
        return self._transition(
            lease_id,
            lifecycle_state="held",
            terminal_evidence_sha256=None,
            release_reason=None,
        )

    def mark_release_pending(
        self,
        lease_id: str,
        *,
        terminal_evidence_sha256: str,
        reason: str,
    ) -> dict[str, Any]:
        return self._transition(
            lease_id,
            lifecycle_state="release-pending",
            terminal_evidence_sha256=terminal_evidence_sha256,
            release_reason=reason,
        )

    def release(
        self,
        lease_id: str,
        *,
        terminal_state: Mapping[str, Any],
        reason: str = "pool-closed",
    ) -> dict[str, Any]:
        state_errors = validate_pool_state(terminal_state)
        if state_errors:
            raise PoolLeaseError("terminal-pool-state-invalid:" + ";".join(state_errors))
        if terminal_state.get("status") not in {"completed", "closed"}:
            raise PoolLeaseError("lease-release-requires-completed-or-closed-pool")
        return self._transition(
            lease_id,
            lifecycle_state="released",
            terminal_evidence_sha256=str(terminal_state["state_sha256"]),
            release_reason=reason,
        )

    def cleanup_stale(
        self,
        terminal_states: Mapping[str, Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Clean only dead owners with hash-valid terminal pool evidence."""
        changed: list[dict[str, Any]] = []
        with self._locked():
            leases = self._load_unlocked()
            now = _iso(self._now())
            for index, lease in enumerate(leases):
                if lease["lifecycle_state"] == "released" or self._owner_alive(lease["owner"]):
                    continue
                state = terminal_states.get(str(lease["pool_id"]))
                state_errors = validate_pool_state(state) if isinstance(state, Mapping) else ["missing"]
                if state_errors or state.get("pool_epoch") != lease["pool_epoch"]:
                    lifecycle = "orphaned-active"
                    terminal_hash = None
                    reason = None
                elif state.get("status") in {"completed", "closed"}:
                    lifecycle = "released"
                    terminal_hash = state["state_sha256"]
                    reason = "stale-owner-terminal-pool"
                elif state.get("status") == "control-failed":
                    lifecycle = "release-pending"
                    terminal_hash = state["state_sha256"]
                    reason = "manual-containment-required"
                else:
                    lifecycle = "orphaned-active"
                    terminal_hash = None
                    reason = None
                updated = seal_artifact(
                    {
                        **lease,
                        "lifecycle_state": lifecycle,
                        "updated_at": now,
                        "terminal_evidence_sha256": terminal_hash,
                        "release_reason": reason,
                    },
                    "lease_sha256",
                )
                errors = validate_lease(updated)
                if errors:
                    raise PoolLeaseError("stale-lease-transition-invalid:" + ";".join(errors))
                leases[index] = updated
                changed.append(updated)
            if changed:
                self._write_unlocked(leases)
        return changed
