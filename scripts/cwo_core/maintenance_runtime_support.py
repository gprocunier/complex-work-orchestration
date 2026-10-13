"""Parent-owned inputs for the installed maintenance transaction adapter.

These Python objects are dependency injection, not serialized authority.  A
worker cannot manufacture a context by returning its JSON representation.
The loader must bind the separately verified one-shot operation before use.
No signing key is stored here.  Same-UID hostile code is outside this in-process
trust boundary: worker sandboxing must protect controller state and memory.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping

from .maintenance_authority import require_maintenance_operation
from .native_pool_admission import AdmissionCandidate, BeadsClaimAdapter
from .native_pool_contracts import canonical_sha256


class MaintenanceRuntimeError(ValueError):
    """A maintenance runtime prerequisite or observed boundary was rejected."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise MaintenanceRuntimeError("maintenance-runtime-" + reason)


def private_path(value: Path, *, exists: bool) -> Path:
    require(isinstance(value, Path) and value.is_absolute(), "absolute-path-required")
    require(".." not in value.parts and value != Path(value.anchor), "unsafe-path")
    require(not any(p.is_symlink() for p in (value, *value.parents)), "symlink-forbidden")
    require(value.exists() is exists, "path-existence-mismatch")
    return value


@dataclass(frozen=True, slots=True)
class ValidationCommand:
    """Controller-selected argv, never a worker-provided shell command."""

    argv: tuple[str, ...]
    timeout_seconds: int
    stdout_sha256: str | None = None

    def document(self) -> dict[str, Any]:
        require(type(self.argv) is tuple and bool(self.argv)
                and all(type(v) is str and bool(v) for v in self.argv), "validation-argv-invalid")
        require(type(self.timeout_seconds) is int and self.timeout_seconds > 0,
                "validation-timeout-invalid")
        if self.stdout_sha256 is not None:
            require(type(self.stdout_sha256) is str and len(self.stdout_sha256) == 64
                    and all(c in "0123456789abcdef" for c in self.stdout_sha256),
                    "validation-output-hash-invalid")
        return {"argv": list(self.argv), "timeout_seconds": self.timeout_seconds,
                "stdout_sha256": self.stdout_sha256}


@dataclass(frozen=True, slots=True)
class MaintenanceTask:
    """One operational task, fully bound by plan.packet_blueprint_sha256.

The first installed adapter deliberately supports one child and at most one
product file.  This matches LiveThreadAdapter's existing exact scope contract;
it does not silently pretend to support a broader ProductiveAdapter.
"""

    child_id: str
    packet_id: str
    attempt_nonce: str
    role: str
    worktree: Path
    write_paths: tuple[str, ...]
    work_plan: Mapping[str, Any]
    operative_routing: Mapping[str, Any]
    instruction: str
    hard_budget: Mapping[str, int]
    validation_commands: tuple[ValidationCommand, ...]
    expected_artifacts: Mapping[str, str] = field(default_factory=dict)
    read_only_command_authority: list[Mapping[str, Any]] | None = None

    def blueprint(self) -> dict[str, Any]:
        require(self.role in {"product", "review"}, "task-role-invalid")
        for value in (self.child_id, self.packet_id, self.attempt_nonce, self.instruction):
            require(type(value) is str and bool(value.strip()), "task-text-invalid")
        private_path(self.worktree, exists=True)
        require(self.worktree.is_dir(), "task-worktree-invalid")
        require(type(self.write_paths) is tuple and len(self.write_paths) <= 1,
                "single-product-path-required")
        require((self.role == "review") == (self.write_paths == ()), "task-role-scope-mismatch")
        for path in self.write_paths:
            require(type(path) is str and path not in {"", ".", ".."} and not Path(path).is_absolute()
                    and str(Path(path)) == path and not {".", ".."}.intersection(Path(path).parts),
                    "task-write-path-invalid")
            require(not any(p.is_symlink() for p in (self.worktree / path, *(self.worktree / path).parents)),
                    "task-write-symlink")
        require(set(self.hard_budget) == {"tool_calls", "runtime_seconds", "compactions",
                                         "full_suite_runs", "mutations"}, "task-budget-fields-invalid")
        require(all(type(v) is int and v >= 0 for v in self.hard_budget.values())
                and self.hard_budget["tool_calls"] > 0 and self.hard_budget["runtime_seconds"] > 0,
                "task-budget-invalid")
        require(self.hard_budget["compactions"] == 0, "task-compaction-forbidden")
        require((self.hard_budget["mutations"] == 0) == (self.role == "review"),
                "task-mutation-budget-invalid")
        require(type(self.validation_commands) is tuple and bool(self.validation_commands)
                and all(type(v) is ValidationCommand for v in self.validation_commands),
                "independent-validation-required")
        require(set(self.expected_artifacts) <= set(self.write_paths), "artifact-scope-invalid")
        require(self.role != "product" or set(self.expected_artifacts) == set(self.write_paths),
                "product-artifact-contract-required")
        for digest in self.expected_artifacts.values():
            require(type(digest) is str and len(digest) == 64
                    and all(c in "0123456789abcdef" for c in digest), "artifact-hash-invalid")
        require(self.role != "product" or self.read_only_command_authority is None,
                "product-readonly-command-contract-invalid")
        return deepcopy({
            "child_id": self.child_id, "packet_id": self.packet_id,
            "attempt_nonce": self.attempt_nonce, "role": self.role,
            "worktree": str(self.worktree), "write_paths": list(self.write_paths),
            "work_plan": dict(self.work_plan), "operative_routing": dict(self.operative_routing),
            "instruction": self.instruction, "hard_budget": dict(self.hard_budget),
            "validation_commands": [command.document() for command in self.validation_commands],
            "expected_artifacts": dict(self.expected_artifacts),
            "read_only_command_authority": self.read_only_command_authority,
        })


@dataclass(frozen=True, slots=True)
class MaintenanceRelease:
    """Actual packet produced after fresh precommit and current qualification."""

    packet: Mapping[str, Any]
    # Every dependency is an existing issuer's actual digest and lifetime.
    dependencies: tuple[Mapping[str, Any], ...]


class MaintenanceSessionLedger:
    """Append-only, fsynced mission-epoch RPC intent count, not a budget ceiling.

    A failed/ambiguous thread/start still counts.  No method resets the ledger
    or converts an unknown allocation into a free retry.  Provision this path
    in controller-only storage, outside all worker workspaces.
    """

    def __init__(self, path: Path, *, mission_id: str) -> None:
        require(type(mission_id) is str and bool(mission_id), "ledger-mission-invalid")
        require(isinstance(path, Path) and path.is_absolute(), "ledger-path-invalid")
        self.path, self.mission_id = path, mission_id
        self._pid = os.getpid()

    def initialize(self) -> None:
        private_path(self.path, exists=False)
        require(self.path.parent.is_dir() and stat.S_IMODE(self.path.parent.stat().st_mode) == 0o700
                and self.path.parent.stat().st_uid == os.getuid(), "ledger-parent-not-private")
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextmanager
    def _locked(self):
        require(os.getpid() == self._pid, "ledger-process-mismatch")
        private_path(self.path, exists=True)
        require(self.path.parent.stat().st_uid == os.getuid()
                and stat.S_IMODE(self.path.parent.stat().st_mode) == 0o700, "ledger-parent-not-private")
        fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            details = os.fstat(fd)
            require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1
                    and details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) == 0o600,
                    "ledger-file-not-private")
            fcntl.flock(fd, fcntl.LOCK_EX)
            with os.fdopen(fd, "r+", encoding="utf-8", closefd=False) as handle:
                yield handle
                now = self.path.stat(follow_symlinks=False)
                require((now.st_dev, now.st_ino) == (details.st_dev, details.st_ino), "ledger-replaced")
        finally:
            os.close(fd)

    def _records(self, handle) -> list[dict[str, Any]]:
        handle.seek(0)
        records, previous, identities = [], None, set()
        for ordinal, line in enumerate(handle, 1):
            require(line.endswith("\n"), "ledger-partial-record")
            try:
                record = json.loads(line)
            except (ValueError, TypeError) as exc:
                raise MaintenanceRuntimeError("maintenance-runtime-ledger-json-invalid") from exc
            require(type(record) is dict and set(record) == {"sequence", "mission_id", "operation_id",
                    "allocation", "previous_sha256", "record_sha256"}, "ledger-record-invalid")
            body = {key: value for key, value in record.items() if key != "record_sha256"}
            require(type(record["sequence"]) is int and record["sequence"] == ordinal
                    and record["mission_id"] == self.mission_id and record["previous_sha256"] == previous
                    and record["record_sha256"] == canonical_sha256(body), "ledger-chain-invalid")
            allocation = record["allocation"]
            require(type(allocation) is dict and type(allocation.get("allocation_id")) is str,
                    "ledger-allocation-invalid")
            identity = allocation["allocation_id"]
            require(identity not in identities, "ledger-allocation-replayed")
            identities.add(identity)
            previous = record["record_sha256"]
            records.append(record)
        return records

    def count(self) -> int:
        with self._locked() as handle:
            return len(self._records(handle))

    def record_intent(self, operation_id: str, allocation: Mapping[str, Any]) -> int:
        require(type(operation_id) is str and bool(operation_id), "ledger-operation-invalid")
        require(type(allocation) is dict and set(allocation) == {
            "allocation_id", "allocation_class", "ordinal", "child_id"}, "ledger-intent-invalid")
        require(type(allocation["allocation_id"]) is str and bool(allocation["allocation_id"])
                and allocation["allocation_class"] in {"prelude", "worker"}
                and type(allocation["ordinal"]) is int and allocation["ordinal"] >= 0,
                "ledger-intent-invalid")
        with self._locked() as handle:
            records = self._records(handle)
            require(not any(row["allocation"]["allocation_id"] == allocation["allocation_id"] for row in records),
                    "ledger-allocation-replayed")
            row = {"sequence": len(records) + 1, "mission_id": self.mission_id,
                   "operation_id": operation_id, "allocation": deepcopy(dict(allocation)),
                   "previous_sha256": records[-1]["record_sha256"] if records else None}
            row["record_sha256"] = canonical_sha256(row)
            handle.seek(0, os.SEEK_END)
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return len(records) + 1


@dataclass(slots=True)
class MaintenanceControllerContext:
    """Constructed only by the trusted owner; never loaded from worker JSON.

    ``release_packet`` must use actual qualification/adjudication producers;
    ``admission_candidate`` must use current ready-set/work-estimate producers.
    Their results are independently validated again by the existing product.
    The release hook receives keyword arguments ``plan``, ``task``,
    ``precommit_receipt``, ``current_authority``, ``refresh``,
    ``maintenance_operation`` and ``maintenance_verifier``.  The last two
    remain the original opaque parent objects, never serialized evidence.
    It must return a ``MaintenanceRelease`` containing a checked version-2
    maintenance release; historical version-1 release records cannot dispatch.
    ``precommit_runner`` optionally replaces only the installed producer (for
    providerless fixtures); it receives an ALREADY allocated fresh thread and
    may not allocate another session.  None selects the installed live producer.
    """

    task: MaintenanceTask
    integration_root: Path
    run_dir: Path
    claim_adapter: BeadsClaimAdapter
    session_ledger: MaintenanceSessionLedger
    reasoning_effort: str
    tool_surface_proof: Mapping[str, Any]
    current_authority: Mapping[str, Any]
    release_packet: Callable[..., MaintenanceRelease]
    admission_candidate: Callable[..., AdmissionCandidate]
    precommit_runner: Callable[..., Mapping[str, Any]] | None = None
    qualification: object | None = None
    control_image: Mapping[str, Any] | None = None
    operation: object | None = field(default=None, init=False, repr=False)
    verifier: object | None = field(default=None, init=False, repr=False)
    plan: dict[str, Any] | None = field(default=None, init=False, repr=False)
    runtime_state: object | None = field(default=None, init=False, repr=False)

    def bind_operation(self, operation: object, verifier: object, plan: Mapping[str, Any]) -> None:
        require(self.operation is None and self.plan is None, "context-already-bound")
        require_maintenance_operation(operation, verifier=verifier, plan=plan,
                                      runtime_scope=self.runtime_scope(), require_claimed=True)
        self.operation, self.verifier, self.plan = operation, verifier, deepcopy(dict(plan))

    def runtime_scope(self) -> dict[str, Any]:
        blueprint = self.task.blueprint()
        return {"workspace": blueprint["worktree"], "model": self.task.work_plan["requested_model"],
                "role": self.task.role, "write_paths": list(self.task.write_paths)}

    def require_authority(self, plan: Mapping[str, Any]) -> None:
        require(self.plan == plan, "context-plan-mismatch")
        require_maintenance_operation(self.operation, verifier=self.verifier, plan=plan,
                                      runtime_scope=self.runtime_scope(), require_claimed=True)
