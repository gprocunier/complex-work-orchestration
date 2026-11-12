"""Integrity checks for one cooperative offline worker and a fake server."""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from cwo_core import git_store, workspace_capture
from cwo_core.native_control import (
    NativeControlTurn,
    validate_control_turn_contract,
    validate_control_turn_receipt,
)
from run_native_pool_live_canaries import LiveThreadAdapter

MAX_TASK_BYTES = 64 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_OUTPUTS = 16
MAX_STEPS = 256
CAPTURE_LIMITS = {
    "max_files": 4096, "max_bytes": 16 * 1024 * 1024,
    "max_seconds": 10.0, "max_entries": 20_000,
}
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CALLBACK_FACTORY = LiveThreadAdapter.callbacks
_METHODS = {
    name: (getattr(LiveThreadAdapter, name), isinstance(descriptor, staticmethod))
    for name, descriptor in vars(LiveThreadAdapter).items()
    if callable(getattr(LiveThreadAdapter, name))
}
_FLAGS_FALSE = {"effect_authority": False, "production_ready": False, "accepted_for_use": False}
_STATE_FIELDS = {
    "version", "binding", "binding_sha256", "status", "receipt", "summary",
    "artifact", "result_sha256", "error", "record_sha256", *_FLAGS_FALSE,
}


class OfflineHostError(ValueError):
    """An input or stored observation failed an integrity check."""


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value):
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _freeze(value):
    payload = _json_bytes(value)
    if len(payload) > MAX_RECORD_BYTES:
        raise OfflineHostError("Input exceeds the bounded record size.")
    return json.loads(payload)


def _path(value):
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or len(raw) > 4096 or "\0" in raw:
        raise OfflineHostError("A bounded directory path is required.")
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw or os.path.realpath(raw) != raw:
        raise OfflineHostError("Directory paths must be absolute and canonical without symlinks.")
    return Path(raw)


@contextmanager
def _directory(value):
    path = _path(value)
    descriptor = os.open("/", _FLAGS)
    try:
        for part in path.parts[1:]:
            following = os.open(part, _FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        yield descriptor
    finally:
        os.close(descriptor)


def _identity(path):
    with _directory(path) as descriptor:
        info = os.fstat(descriptor)
        return [info.st_dev, info.st_ino, info.st_mode]


def _within(path, root):
    return path == root or root in path.parents


def _scratch_parent(candidate, repositories):
    try:
        parent = Path(os.path.realpath(candidate, strict=True))
    except FileNotFoundError:
        parent = Path(os.path.realpath(candidate))
    except (OSError, TypeError, ValueError, RecursionError) as exc:
        raise OfflineHostError("Scratch candidate resolution failed before capture.") from exc
    if any(_within(parent, root) for root in repositories):
        raise OfflineHostError("Scratch candidates must stay outside both repositories.")
    return parent


def _validate_scratch(repositories):
    protected = {tuple(_identity(path)[:2]) for root in repositories for path in (root, root / ".git")}
    for candidate in workspace_capture._scratch_candidates():
        parent = _scratch_parent(candidate, repositories)
        pinned = workspace_capture._pin_directory(str(parent))
        if pinned is None:
            continue
        descriptor, _chain = pinned
        try:
            ancestry = workspace_capture._ancestry(descriptor)
            if protected.intersection((info.st_dev, info.st_ino) for info in ancestry):
                raise OfflineHostError("Scratch ancestry overlaps a bound repository.")
        finally:
            os.close(descriptor)


def _relative(value):
    if type(value) is not str or not value or len(value) > 240 or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value):
        raise OfflineHostError("Output paths must use simple relative file names.")
    if any(part in {".", "..", ".git"} for part in value.split("/")):
        raise OfflineHostError("Output paths cannot traverse directories or name Git metadata.")
    return value


def _read(root, relative, cap):
    parts = _relative(relative).split("/")
    with _directory(root) as descriptor:
        current = os.dup(descriptor)
        try:
            for part in parts[:-1]:
                following = os.open(part, _FLAGS, dir_fd=current)
                os.close(current)
                current = following
            kind, data, before = workspace_capture.read_at(current, parts[-1], cap)
            if kind != "file" or before is None or before.st_nlink != 1:
                raise OfflineHostError("A single regular file is required.")
            after = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
            if _file_mark(before) != _file_mark(after) or len(data) != after.st_size:
                raise OfflineHostError("The file changed during its bounded read.")
            return data
        finally:
            os.close(current)


def _file_mark(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _immutable_read(root, name, cap):
    if stat.S_IMODE(os.lstat(root / name).st_mode) != 0o400:
        raise OfflineHostError("Immutable artifact files must retain their read-only mode.")
    return _read(root, name, cap)


def _write_new(path, data, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OfflineHostError("The durable write made no progress.")
            view = view[count:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync(directory):
    with _directory(directory) as descriptor:
        os.fsync(descriptor)


def _metadata(root):
    git = root / ".git"
    _identity(git)
    for required in ("objects", "refs"):
        _identity(git / required)
    for forbidden in ("commondir", "objects/info/alternates", "objects/info/http-alternates"):
        if os.path.lexists(git / forbidden):
            raise OfflineHostError("Shared Git metadata and object alternates are refused.")
    pending = [git]
    seen = set()
    deadline, entries_left = time.monotonic() + 10, 20_000
    while pending:
        directory = pending.pop()
        with _directory(directory) as descriptor:
            seen.add(tuple(_identity(directory)[:2]))
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    _metadata_kind(info)
                    seen.add((info.st_dev, info.st_ino))
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(directory / entry.name)
                    entries_left -= 1
                    if entries_left < 0 or time.monotonic() > deadline:
                        raise OfflineHostError("Git metadata exceeds the inspection bound.")
    return seen


def _metadata_kind(info):
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise OfflineHostError("Git metadata must contain only directories and regular files.")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise OfflineHostError("Hard linked Git metadata is refused.")


def _commit_head(value, budget):
    store = workspace_capture.object_store(value["dirs"][1], value["object_format"], budget)
    try:
        kind, _content = store.read(value["head_commit"])
        if kind != "commit":
            raise OfflineHostError("HEAD must name a verified commit object.")
    except git_store.StoreError as exc:
        raise OfflineHostError("HEAD commit object verification failed.") from exc
    finally:
        store.close()


def _capture(root, repositories):
    _validate_scratch(repositories)
    budget = workspace_capture.Budget.start(**CAPTURE_LIMITS)
    value = _freeze(workspace_capture.capture(root, **CAPTURE_LIMITS))
    if value.get("complete") is not True or value.get("error") or not value.get("head_commit"):
        raise OfflineHostError("A complete repository capture with an actual commit is required.")
    if value["dirs"] != [str(root / ".git"), str(root / ".git"), str(root)]:
        raise OfflineHostError("An ordinary repository with its own Git directory is required.")
    _commit_head(value, budget)
    return value


def _repository(root, raw):
    return {
        "path": str(root), "root": _identity(root), "git": _identity(root / ".git"),
        "objects": _identity(root / ".git" / "objects"),
        "head_commit": raw["head_commit"], "object_format": raw["object_format"],
    }


def _methods(adapter):
    if type(adapter) is not LiveThreadAdapter:
        registered = importlib.import_module("registered_n1_factory")
        if registered.is_registered_adapter(adapter):
            registered.require_adapter(adapter)
            return
        profile = importlib.import_module("offline_profile_input")
        try:
            profile.require_original_adapter(adapter)
        except profile.InputError as exc:
            raise OfflineHostError(str(exc)) from exc
        return
    for name, (original, static) in _METHODS.items():
        bound = getattr(adapter, name)
        observed = bound if static else getattr(bound, "__func__", None)
        if observed is not original or (not static and getattr(bound, "__self__", None) is not adapter):
            raise OfflineHostError("Original bound adapter methods are required.")


def _adapter_binding(adapter, control, task, worker, state):
    _methods(adapter)
    registered = importlib.import_module("registered_n1_factory")
    registered.require_server_or_fixture(adapter)
    if adapter.worktree != worker or adapter.prompt != task:
        raise OfflineHostError("The original worker and task bindings must match.")
    for directory in (adapter.record_dir, adapter.server.codex_home):
        path = _path(directory)
        _identity(path)
        if not _within(path, state):
            raise OfflineHostError("Adapter and fake server records must stay inside host state.")
    with adapter._boundary_lock:
        adapter._require_effective_boundary()
        boundary = _freeze(adapter._effective_boundary)
        if boundary["control_contract"] != control or boundary["thread"]["id"] != adapter.thread_id:
            raise OfflineHostError("The actual bound adapter contract and original thread must match.")
    return boundary


def _task_contract(operation_id, task, control):
    if type(task) is not str or not task or len(task) > MAX_TASK_BYTES or len(task.encode("utf-8")) > MAX_TASK_BYTES:
        raise OfflineHostError("Task input must be bounded nonempty UTF-8 text.")
    if type(operation_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", operation_id):
        raise OfflineHostError("A bounded operation ID is required.")
    if validate_control_turn_contract(control) or control["task_sha256"] != hashlib.sha256(task.encode()).hexdigest():
        raise OfflineHostError("The control contract must bind the exact task bytes.")


def _output_paths(outputs):
    if type(outputs) not in (tuple, list) or not 1 <= len(outputs) <= MAX_OUTPUTS:
        raise OfflineHostError("Declare a bounded nonempty collection of output paths.")
    paths = sorted(_relative(value) for value in outputs)
    if len(paths) != len(set(paths)):
        raise OfflineHostError("Output paths must be distinct.")
    return paths


def _pins(value):
    pins = _freeze(value)
    if type(pins) is not dict or set(pins) != {"w14", "w15"}:
        raise OfflineHostError("Protocol (w14) and native-policy (w15) configuration pins are required.")
    if any(type(value) is not str or not value.strip() or len(value) > 1024 for value in pins.values()):
        raise OfflineHostError("Configuration pins must be bounded nonempty text.")
    return pins


def _inputs(operation_id, task, contract, outputs, max_steps, configuration_pins):
    control = _freeze(contract)
    pins = _pins(configuration_pins)
    _task_contract(operation_id, task, control)
    if type(max_steps) is not int or not 1 <= max_steps <= MAX_STEPS:
        raise OfflineHostError("The declared step count is outside the supported bound.")
    return {"operation_id": operation_id, "task": task, "contract": control,
            "outputs": _output_paths(outputs), "max_steps": max_steps, "configuration_pins": pins}


def _advance(turn, progress, task=None, *, repositories):
    if progress is not None and progress["wait_required"]:
        time.sleep(0.002)
        turn.resume_after_wait()
    _validate_scratch(repositories)
    return turn.step(task)


def _drive(control, task, adapter, max_steps, repositories):
    turn = NativeControlTurn(control, _CALLBACK_FACTORY(adapter))
    progress = None
    for index in range(max_steps):
        progress = _advance(turn, progress, task if index == 0 else None, repositories=repositories)
        if progress["status"] == "terminal":
            return progress["receipt"], False
    progress = turn.request_interrupt("control-lost")
    for _ in range(8):
        progress = _advance(turn, progress, repositories=repositories)
        if progress["status"] == "terminal":
            break
    if progress["status"] != "terminal":
        progress = turn.fail_control("interrupt-cleanup-step-bound-exhausted")
    return progress["receipt"], True


def _completed_receipt(receipt, contract):
    if validate_control_turn_receipt(receipt, contract=contract):
        return False
    if receipt["terminal_state"] != "completed" or receipt["errors"] or not receipt["submission_id"]:
        return False
    if "complete" not in receipt["decisions"]:
        return False
    if any(value not in {"continue", "warn", "complete"} for value in receipt["decisions"]):
        return False
    return bool(receipt["actions"]) and receipt["actions"][-1] == "close"


def _accepted_evidence(evidence):
    if type(evidence) is not dict:
        return False
    expected = {
        "reasons": [], "failure_class": None, "recovery_evidence_sha256": None,
        "session_disposition": "accepted", "artifact_disposition": "accepted",
    }
    return (
        evidence.get("protected_fault") is False
        and evidence.get("control_loss") is False
        and all(key in evidence and evidence[key] == value for key, value in expected.items())
    )


def _successful(receipt, summary, contract):
    if not _completed_receipt(receipt, contract) or type(summary) is not dict:
        return False
    boundary = summary.get("session_boundary")
    if type(boundary) is not dict or boundary.get("trailing_partial"):
        return False
    expected = {
        "archived": True, "interrupted": False, "turn_status": "completed",
        "turn_id": receipt["submission_id"], "thread_id": contract["agent_id"],
        "model_exact": True, "expected_final_token_observed": True,
        "completion_evidence_satisfied": True, "reroute_count": 0,
        "compactions": 0, "forbidden_tool_activity": [],
    }
    return (
        boundary.get("available") is True
        and _accepted_evidence(summary.get("adapter_evidence"))
        and {key: summary.get(key) for key in expected} == expected
    )


def _result_digest(record):
    return _digest({name: record[name] for name in ("binding_sha256", "receipt", "summary", "artifact")})


def _record_binding(binding):
    if type(binding) is not dict or set(binding) != {
        "operation_id", "task", "contract", "outputs", "max_steps", "configuration_pins",
        "target", "target_identity", "worker_identity", "adapter_boundary",
    }:
        raise OfflineHostError("Stored invocation bindings are malformed.")
    try:
        inputs = _inputs(*(binding[key] for key in ("operation_id", "task", "contract", "outputs", "max_steps", "configuration_pins")))
    except (KeyError, TypeError, ValueError) as exc:
        raise OfflineHostError("Stored invocation inputs are malformed.") from exc
    if any(binding[key] != item for key, item in inputs.items()):
        raise OfflineHostError("Stored invocation inputs changed.")


def _record_result(value):
    if value["status"] not in {"reconciliation-required", "artifact-ready"}:
        raise OfflineHostError("Stored lifecycle status is invalid.")
    if value["status"] == "artifact-ready":
        if not _successful(value["receipt"], value["summary"], value["binding"]["contract"]):
            raise OfflineHostError("Stored readiness lacks a completed and closed native observation.")
        if type(value["artifact"]) is not dict or value["result_sha256"] != _result_digest(value):
            raise OfflineHostError("Stored readiness lacks an artifact binding.")
    elif value["artifact"] is not None or value["result_sha256"] is not None:
        raise OfflineHostError("Unsettled execution cannot carry an artifact.")


def _validate_record(value):
    if type(value) is not dict or set(value) != _STATE_FIELDS or type(value["version"]) is not int or value["version"] != 1:
        raise OfflineHostError("Stored state has an unsupported shape.")
    body = {key: item for key, item in value.items() if key != "record_sha256"}
    if _digest(body) != value["record_sha256"] or _digest(value["binding"]) != value["binding_sha256"]:
        raise OfflineHostError("Stored state failed its integrity digest check.")
    if any(value[key] is not False for key in _FLAGS_FALSE):
        raise OfflineHostError("Stored state cannot carry effect authority or acceptance.")
    _record_binding(value["binding"])
    _record_result(value)
    return value


def _verify_entry(directory, entry, path, index):
    if type(entry) is not dict or set(entry) != {"path", "blob", "size", "sha256"}:
        raise OfflineHostError("An artifact file entry is malformed.")
    if entry["path"] != path or entry["blob"] != f"file-{index:04d}":
        raise OfflineHostError("Artifact paths are duplicated, reordered or malformed.")
    data = _immutable_read(directory, entry["blob"], MAX_FILE_BYTES)
    if type(entry["size"]) is not int or len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise OfflineHostError("Immutable artifact bytes changed or are missing.")
    return len(data)


class OfflineN1Host:
    """One cooperative claim; digests do not authenticate owner-writable records."""

    def __init__(self, state_directory: Path, target_repository: Path, worker_repository: Path):
        self.state = _path(state_directory)
        self.target = _path(target_repository)
        self.worker = _path(worker_repository)
        roots = (self.state, self.target, self.worker)
        for root in roots:
            _identity(root)
        if len({tuple(_identity(root)[:2]) for root in roots}) != 3:
            raise OfflineHostError("Host, target and worker directory identities must be distinct.")
        for index, root in enumerate(roots):
            if any(_within(root, other) or _within(other, root) for other in roots[index + 1:]):
                raise OfflineHostError("Host state, target and worker roots must be separate and disjoint.")
        self._state_identity = _identity(self.state)
        self._initial = self._observe()
        if self._initial["worker_identity"]["head_commit"] != self._initial["target_identity"]["head_commit"]:
            raise OfflineHostError("The independent worker clone must start at the target commit.")

    def _observe(self):
        if _identity(self.state) != self._state_identity:
            raise OfflineHostError("The host state directory changed identity.")
        target_metadata = _metadata(self.target)
        worker_metadata = _metadata(self.worker)
        if target_metadata & worker_metadata or tuple(self._state_identity[:2]) in target_metadata | worker_metadata:
            raise OfflineHostError("Worker and target Git stores share metadata.")
        target = _capture(self.target, (self.target, self.worker))
        worker = _capture(self.worker, (self.target, self.worker))
        return {"target": target, "target_identity": _repository(self.target, target),
                "worker_identity": _repository(self.worker, worker)}

    @contextmanager
    def _locked(self, *, create=False):
        if _identity(self.state) != self._state_identity:
            raise OfflineHostError("The host state directory changed identity.")
        flags = (os.O_RDWR | os.O_CREAT) if create else os.O_RDONLY
        descriptor = os.open(self.state / "host.lock", flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OfflineHostError("The host lock must be a single regular file.")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise OfflineHostError("The single worker claim is busy.") from exc
            yield
        finally:
            os.close(descriptor)

    def _load(self):
        try:
            # Distinguish a missing record from a malformed bounded file read.
            os.lstat(self.state / "operation.json")
            data = _read(self.state, "operation.json", MAX_RECORD_BYTES)
        except FileNotFoundError:
            if set(os.listdir(self.state)) - {"host.lock", "records", "fake-server"}:
                raise OfflineHostError("Unsettled host files require reconciliation.")
            return None
        return _validate_record(json.loads(data))

    def _save(self, record):
        if _identity(self.state) != self._state_identity:
            raise OfflineHostError("The host state directory changed identity.")
        body = {key: value for key, value in record.items() if key != "record_sha256"}
        record = {**body, "record_sha256": _digest(body)}
        data = _json_bytes(record)
        if len(data) > MAX_RECORD_BYTES:
            raise OfflineHostError("Stored state exceeds its durable size bound.")
        _write_new(self.state / "operation.next", data)
        os.replace(self.state / "operation.next", self.state / "operation.json")
        _sync(self.state)
        return _freeze(record)

    def status(self, operation_id: str) -> dict:
        """Read stored status without resuming execution or releasing a claim."""
        with self._locked():
            record = self._load()
            if record is None or record["binding"]["operation_id"] != operation_id:
                raise OfflineHostError("The operation ID has no stored claim.")
            return _freeze(record)

    def run(self, operation_id: str, task: str, contract: dict, adapter: LiveThreadAdapter,
            *, outputs: tuple[str, ...], max_steps: int, configuration_pins: dict) -> dict:
        """Persist intent, run one bounded native turn and retain conservative results."""
        inputs = _inputs(operation_id, task, contract, outputs, max_steps, configuration_pins)
        with self._locked(create=True):
            current = self._observe()
            if current != self._initial:
                raise OfflineHostError("Worker identity or expected target state drifted.")
            boundary = _adapter_binding(adapter, inputs["contract"], task, self.worker, self.state)
            existing = self._load()
            return self._execute_bound(inputs, adapter, current, boundary, existing)

    def run_registered(self, factory):
        """Hold the original claim before controlled startup, through cleanup."""
        registered = importlib.import_module("registered_n1_factory")
        registered.require_factory(factory, self)
        with self._locked(create=True):
            if self._observe() != self._initial or self._load() is not None:
                raise OfflineHostError("Registered startup requires a current unclaimed original host.")
            intent = {"operation_id": factory.operation_id,
                      "admission_sha256": factory.spec["admission_sha256"],
                      "registered_specification": factory.spec}
            _write_new(self.state / "registered-startup.json", _json_bytes(intent), 0o400)
            _sync(self.state)
            try:
                adapter, control = factory._prepare_registered_adapter()
                inputs = _inputs(factory.operation_id, factory.receipt.request_bytes.decode(), control,
                    [factory.policy.report["outputs"][0]["path"]], factory.spec["max_steps"],
                    factory.spec["configuration_pins"])
                current = self._observe()
                if current != self._initial:
                    raise OfflineHostError("Worker identity or expected target state drifted during startup.")
                boundary = _adapter_binding(adapter, control, inputs["task"], self.worker, self.state)
                report = self._execute_bound(inputs, adapter, current, boundary, None)
                if report["status"] != "artifact-ready":
                    failure = OfflineHostError(report["error"] or "Registered native execution requires reconciliation.")
                    failure.native_report = report
                    raise failure
                return report
            except BaseException as primary:
                factory._cleanup_owned(primary)
                raise

    def _execute_bound(self, inputs, adapter, current, boundary, existing):
        binding = {**inputs, **current, "adapter_boundary": boundary}
        if existing is not None:
            if existing["binding"] != binding:
                raise OfflineHostError("Mutated replay or a competing operation ID is refused.")
            return _freeze(existing)
        if adapter.turn_id is not None or adapter._effective_boundary_armed or adapter._effective_boundary_send_reserved:
            raise OfflineHostError("A fresh unarmed original adapter is required for a new claim.")
        record = {"version": 1, "binding": binding, "binding_sha256": _digest(binding),
                  "status": "reconciliation-required", "receipt": None, "summary": None,
                  "artifact": None, "result_sha256": None,
                  "error": "Invocation intent is durable; execution requires reconciliation.", **_FLAGS_FALSE}
        self._save(record)
        return self._execute(record, adapter)

    def _execute(self, record, adapter):
        try:
            inputs = record["binding"]
            repositories = (self.target, self.worker)
            receipt, exhausted = _drive(inputs["contract"], inputs["task"], adapter, inputs["max_steps"], repositories)
            record["receipt"] = _freeze(receipt)
            if exhausted:
                raise OfflineHostError("The step bound ended; control is lost and reconciliation is required.")
            _methods(adapter)
            _validate_scratch(repositories)
            summary = _freeze(adapter.final_summary())
            record["summary"] = summary
            _validate_scratch(repositories)
            summary["adapter_evidence"] = _freeze(adapter.evidence())
            if not adapter.archived or not adapter.server.archived or not _successful(receipt, summary, inputs["contract"]):
                raise OfflineHostError("A completed native receipt and actual archive observation are required.")
            artifact = self._collect(inputs)
            record.update(status="artifact-ready", artifact=artifact, error=None)
            record["result_sha256"] = _result_digest(record)
        except Exception as exc:
            # Host checks also fail outside adapter callbacks. Revoke registered
            # requests before the original failure record can block in _save.
            importlib.import_module("registered_n1_factory").observe_execution_failure(adapter, exc)
            record.update(status="reconciliation-required", artifact=None, result_sha256=None,
                          error=f"Execution or collection failed ({type(exc).__name__}: {exc}); reconciliation is required.")
        return self._save(record)

    def _unchanged(self):
        if self._observe() != self._initial:
            raise OfflineHostError("Worker identity or target state changed around artifact collection.")

    def _collect(self, binding):
        self._unchanged()
        directory = self.state / "artifact"
        directory.mkdir(mode=0o700)
        _sync(self.state)
        files = []
        total = 0
        for index, path in enumerate(binding["outputs"]):
            data = _read(self.worker, path, MAX_FILE_BYTES)
            total += len(data)
            if total > MAX_ARTIFACT_BYTES:
                raise OfflineHostError("Worker output exceeds the artifact byte bound.")
            blob = f"file-{index:04d}"
            _write_new(directory / blob, data, 0o400)
            files.append({"path": path, "blob": blob, "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
        body = {"files": files, "worker_identity": binding["worker_identity"], "expected_target": binding["target"]}
        artifact = {**body, "sha256": _digest(body)}
        _write_new(directory / "manifest.json", _json_bytes(artifact), 0o400)
        os.chmod(directory, 0o500)
        _sync(directory)
        _sync(self.state)
        self._unchanged()
        return artifact

    def verify_artifact(self, report: dict, expected_target: dict) -> dict:
        """Recheck stored bytes and target freshness without granting effect authority."""
        result = {"valid": False, "errors": [], **_FLAGS_FALSE}
        try:
            supplied = _freeze(report)
            expected = _freeze(expected_target)
            with self._locked():
                stored = self._load()
                if stored != supplied or stored["status"] != "artifact-ready":
                    raise OfflineHostError("The report is not the stored ready observation.")
                if expected != stored["binding"]["target"]:
                    raise OfflineHostError("The expected target snapshot does not match the invocation.")
                if _capture(self.target, (self.target, self.worker)) != expected:
                    raise OfflineHostError("The target is stale.")
                self._verify_files(stored["artifact"], stored["binding"])
                if _capture(self.target, (self.target, self.worker)) != expected:
                    raise OfflineHostError("The target changed during artifact verification.")
            result["valid"] = True
        except Exception as exc:
            result["errors"] = [f"Artifact verification failed: {type(exc).__name__}: {exc}"]
        return result

    def _verify_files(self, artifact, binding):
        directory = self.state / "artifact"
        if stat.S_IMODE(_identity(directory)[2]) != 0o500:
            raise OfflineHostError("The immutable artifact directory mode changed.")
        if set(artifact) != {"files", "worker_identity", "expected_target", "sha256"}:
            raise OfflineHostError("The artifact manifest has an unsupported shape.")
        manifest = json.loads(_immutable_read(directory, "manifest.json", MAX_RECORD_BYTES))
        body = {key: value for key, value in artifact.items() if key != "sha256"}
        if manifest != artifact or _digest(body) != artifact["sha256"]:
            raise OfflineHostError("The immutable artifact manifest does not match.")
        if artifact["worker_identity"] != binding["worker_identity"] or artifact["expected_target"] != binding["target"]:
            raise OfflineHostError("The artifact worker or target binding changed.")
        files = artifact["files"]
        if type(files) is not list or len(files) != len(binding["outputs"]):
            raise OfflineHostError("The artifact file collection is incomplete.")
        total = 0
        for index, (entry, path) in enumerate(zip(files, binding["outputs"])):
            total += _verify_entry(directory, entry, path, index)
        if total > MAX_ARTIFACT_BYTES or set(os.listdir(directory)) != {"manifest.json", *(entry["blob"] for entry in files)}:
            raise OfflineHostError("The artifact has unexpected files or exceeds its byte bound.")
