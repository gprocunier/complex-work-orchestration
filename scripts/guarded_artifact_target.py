"""Opt-in maintenance publication of original validated bytes to a normal checkout.

No factory is installed here. The trusted embedding controller supplies its
original claimed maintenance capability and separately adopted signed effect
consent. Paths, observations and constructors do not grant execution authority.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import hmac
import json
import os
import stat
from types import FunctionType

import offline_artifact_validation as V
from cwo_core import maintenance_authority as A
from cwo_core.native_authority import canonical_authority_sha256, verify_operator_directive

H = V.HOST
_FALSE = {**H._FLAGS_FALSE, "operative": False}
_MODULES = (V, A)
_FUNCTIONS = {(module, name): value for module in _MODULES for name, value in vars(module).items()
              if type(value) is FunctionType and value.__module__ == module.__name__}
_CLASSES = (A.MaintenanceAuthorityVerifier, A.VerifiedMaintenanceOperation, A.MaintenanceStateStore)
_METHODS = {(cls, name): value for cls in _CLASSES for name, value in vars(cls).items()
            if type(value) is FunctionType}
_REGISTRIES = (V._POLICIES, V._TOKENS)
_ENCODE = V._snapshot
_VERIFY_DIRECTIVE = verify_operator_directive
_SOURCE_PATH = H.Path(__file__).resolve()
_SOURCE_BYTES = _SOURCE_PATH.read_bytes()
_LIMIT = 4 * H.MAX_RECORD_BYTES


def _encode(value):
    return _ENCODE(value, _LIMIT)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _sources():
    if _SOURCE_PATH.read_bytes() != _SOURCE_BYTES:
        raise ValueError("The registered publication source changed.")
    if any(getattr(module, name, None) is not value for (module, name), value in _FUNCTIONS.items()):
        raise ValueError("Original validation or authority functions changed.")
    if any(getattr(cls, name, None) is not value for (cls, name), value in _METHODS.items()):
        raise ValueError("Original authority methods changed.")
    if (A.MaintenanceAuthorityVerifier, A.VerifiedMaintenanceOperation, A.MaintenanceStateStore) != _CLASSES:
        raise ValueError("Original authority types changed.")
    if V._POLICIES is not _REGISTRIES[0] or V._TOKENS is not _REGISTRIES[1]:
        raise ValueError("Original issued-object registries changed.")


def _strip_outputs(capture, paths):
    result = json.loads(_encode(capture))
    for field in ("raw_inventory", "raw_blob_ids", "symlink_targets"):
        result[field] = {key: value for key, value in result[field].items() if key not in paths}
    result["status_lines"] = [line for line in result["status_lines"] if line[3:] not in paths]
    result["ignored_files"] = [path for path in result["ignored_files"] if path not in paths]
    return result


class PublicationError(ValueError):
    """Refusal retaining the primary failure and actual persistence observations."""

    def __init__(self, message, report):
        super().__init__(message)
        self._report = _encode(report)

    @property
    def report(self):
        return json.loads(self._report)


class GuardedArtifactTarget:
    """One recoverable, guarded file transaction; never a multi-file atomic switch."""

    def __init__(self, state_directory, host, issued_policy, *, operation, verifier):
        _sources()
        A.require_maintenance_operation(operation, verifier=verifier)
        self.host, self.policy = host, issued_policy
        self.operation, self.verifier = operation, verifier
        self.authority_store = self._authority_store()
        self.state = H._path(state_directory)
        self.roots = V._host(host)
        self.state_identity = H._identity(self.state)
        self.expected = _encode(host._initial["target"])
        self.policy_bytes = V._issued(V._POLICIES, V.ValidationPolicy, issued_policy)
        self._failure_sequence = 0
        self._known = None
        self._failures = []
        self._check()

    def _authority_store(self):
        reader, claim = self.verifier._state_reader, self.verifier._claim
        store = getattr(reader, "__self__", None)
        if (type(store) is not A.MaintenanceStateStore
                or getattr(reader, "__func__", None) is not A.MaintenanceStateStore.read_state
                or getattr(claim, "__self__", None) is not store
                or getattr(claim, "__func__", None) is not A.MaintenanceStateStore.claim_operation):
            raise ValueError("Publication requires the original bound authority store callbacks.")
        return store

    def _check(self):
        _sources()
        A.require_maintenance_operation(self.operation, verifier=self.verifier)
        if self._authority_store() is not self.authority_store:
            raise ValueError("The original authority store binding changed.")
        if V._host(self.host) != self.roots or H._identity(self.state) != self.state_identity:
            raise ValueError("A bound host or publication state root changed.")
        info = os.lstat(self.state)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Publication state must remain controller-private.")
        for root in (self.host.target, self.host.worker, self.host.state):
            if H._within(self.state, root) or H._within(root, self.state):
                raise ValueError("Publication state and host roots must be disjoint.")
        if info.st_dev != os.stat(self.host.target).st_dev:
            raise ValueError("Publication requires one local filesystem.")
        self._check_policy_scope()
        self._layout()

    def _check_policy_scope(self):
        if V._issued(V._POLICIES, V.ValidationPolicy, self.policy) != self.policy_bytes:
            raise ValueError("The independently selected original policy changed.")
        if self.operation.adapter_path != _SOURCE_PATH:
            raise ValueError("The claimed factory must pin this exact publication adapter.")
        scope = self.operation.evidence()["operation"]
        paths = [entry["path"] for entry in json.loads(self.policy_bytes)["outputs"]]
        if any(path in {".gitignore", ".gitattributes"} for path in paths):
            raise ValueError("Capture-interpreted output files are unsupported.")
        if (scope["workspace"] != str(self.host.target) or scope["role"] != "product"
                or sorted(scope["write_paths"]) != paths):
            raise ValueError("The registered operation must own this exact target/output scope.")

    def _layout(self):
        H._metadata(self.host.target)
        git = self.host.target / ".git"
        for name in ("refs/replace", "info/grafts", "shallow", "config.worktree"):
            if os.path.lexists(git / name):
                raise ValueError("Replacement, shallow and extended Git stores are unsupported.")
        self._packed_layout(git)
        entries = H.git_store.parse_config(self._file_bytes(git, "config", 65536))
        allowed = {"core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
                   "remote.origin.url", "remote.origin.fetch", "user.name", "user.email"}
        for name, value in entries:
            branch = name.startswith("branch.") and name.rsplit(".", 1)[-1] in {"remote", "merge"}
            maintenance_off = (name, value) in {("maintenance.auto", "false"), ("gc.auto", "0")}
            if name not in allowed and not branch and not maintenance_off:
                raise ValueError("Unsupported target Git configuration.")
            if name == "core.bare" and value != "false":
                raise ValueError("A non-bare target checkout is required.")

    def _packed_layout(self, git):
        try:
            packed = self._file_bytes(git, "packed-refs", 65536)
        except FileNotFoundError:
            return
        references = H.git_store.packed_references(packed, len(json.loads(self.expected)["head_commit"]) // 2)
        if any(name == "refs/replace" or name.startswith("refs/replace/") for name in references):
            raise ValueError("Replacement refs in packed storage are unsupported.")

    @contextmanager
    def _directory(self, path):
        path = H._path(path)
        # Register each acquired descriptor before opening the next component.
        # ExitStack retains an active acquisition/body error through every close.
        with ExitStack() as stack:
            descriptor = stack.enter_context(self._descriptor(os.open("/", H._FLAGS)))
            for part in path.parts[1:]:
                descriptor = stack.enter_context(self._descriptor(
                    os.open(part, H._FLAGS, dir_fd=descriptor)))
            yield descriptor

    @contextmanager
    def _guard(self):
        # Existing maintenance mutex retains controller ownership. Directory
        # flock serializes all instances for this target, independent of state path.
        with self.verifier._mutex:
            self._check()
            with self.authority_store.guard_current_state(), self._directory(self.host.target) as target:
                fcntl.flock(target, fcntl.LOCK_EX | fcntl.LOCK_NB)
                primary = None
                try:
                    self._check()
                    yield
                except BaseException as exc:
                    primary = exc
                    raise
                finally:
                    try:
                        fcntl.flock(target, fcntl.LOCK_UN)
                    except BaseException as cleanup:
                        if primary is None:
                            raise
                        self._failures.append("Guard unlock failed: " + V._exception_text(cleanup))

    def binding(self, operation_id, token, original_report):
        """Read-only exact action for the trusted parent's existing directive producer."""
        self._check()
        if type(operation_id) is not str or not H.re.fullmatch(r"[A-Za-z0-9_-]{1,80}", operation_id):
            raise ValueError("A bounded publication operation ID is required.")
        binding, outputs = self._validated(token, original_report)
        return json.loads(_encode({"purpose": "guarded-artifact-publication-v1", "operation_id": operation_id,
                "maintenance_operation": self.operation.operation_sha256,
                "state": [str(self.state), list(self.state_identity)],
                "host_roots": [[path, list(identity)] for path, identity in self.roots], "validation_binding": {"policy": json.loads(binding[0]),
                    "report": json.loads(binding[1]), "target": json.loads(binding[2]), "roots": [[path, list(identity)] for path, identity in binding[3]]},
                "outputs": [{"path": path, "size": len(data), "sha256": _sha(data)} for path, data in outputs]}))

    def _validated(self, token, report):
        _sources()
        binding = V._inputs(self.host, report, json.loads(self.expected), self.policy)
        host, policy, issued_binding, _observation = V._issued(V._TOKENS, V.ValidatedObservation, token)
        if host is not self.host or policy is not self.policy or binding != issued_binding:
            raise ValueError("Original issued host, policy, token and report are required.")
        V._inventory(self.host, report)
        with self.host._locked():
            if V._snapshot(self.host._load()) != binding[1]:
                raise ValueError("The original stored host report changed.")
            self.host._verify_files(report["artifact"], report["binding"])
        outputs = V._blobs(self.host, report)
        for entry, (path, data) in zip(json.loads(self.policy_bytes)["outputs"], outputs):
            H._relative(path)
            if "/" in path:
                raise ValueError("This first target adapter supports root-level output files only.")
            if not V._compare(entry, data)["passed"]:
                raise ValueError("Original independent output comparison refused.")
        return binding, outputs

    def _capture(self):
        self._check()
        return H._capture(self.host.target, (self.host.target, self.host.worker))

    def _sync_directory(self, path):
        with self._directory(path) as descriptor:
            os.fsync(descriptor)

    def _new_file(self, name, data, mode):
        H._relative(name)
        if "/" in name:
            raise ValueError("Publication state files require one literal name.")
        with self._directory(self.state) as parent:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            with self._record_descriptor(parent, name, flags=flags) as descriptor:
                view = memoryview(data)
                while view:
                    count = os.write(descriptor, view)
                    if count <= 0:
                        raise ValueError("The durable state write made no progress.")
                    view = view[count:]
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)

    def _record(self, name, value):
        body = _encode(value)
        mac = hmac.new(self.verifier._key, body, hashlib.sha256).hexdigest()
        self._new_file(name, _encode({"body": value, "mac": mac}), 0o400)
        self._sync_directory(self.state)

    @staticmethod
    def _file_kind(info, limit, modes, owned):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Publication reads require single regular files.")
        if owned and info.st_uid != os.geteuid():
            raise ValueError("Publication payload ownership changed.")
        if modes is not None and stat.S_IMODE(info.st_mode) not in modes:
            raise ValueError("Publication payload mode changed.")
        if not 0 <= info.st_size <= limit:
            raise ValueError("A publication file exceeds its byte bound.")

    @staticmethod
    def _read_file_data(descriptor, expected, limit):
        if H._file_mark(os.fstat(descriptor)) != H._file_mark(expected):
            raise ValueError("The pinned publication file changed before reading.")
        chunks, total = [], 0
        while True:
            data = os.read(descriptor, min(65536, limit + 1 - total))
            if not data:
                break
            total += len(data)
            if total > limit:
                raise ValueError("A publication file exceeds its read bound.")
            chunks.append(data)
        if H._file_mark(os.fstat(descriptor)) != H._file_mark(expected) or total != expected.st_size:
            raise ValueError("The pinned publication file changed during reading.")
        return b"".join(chunks)

    def _file_bytes(self, root, name, limit, *, modes=None, owned=False):
        H._relative(name)
        if "/" in name:
            raise ValueError("Publication file reads require one literal name.")
        with self._directory(root) as parent:
            with self._record_descriptor(parent, name, flags=os.O_PATH) as pinned:
                expected = os.fstat(pinned)
                self._file_kind(expected, limit, modes, owned)
                descriptor = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_CLOEXEC)
                with self._descriptor(descriptor):
                    data = self._read_file_data(descriptor, expected, limit)
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if H._file_mark(current) != H._file_mark(expected):
                    raise ValueError("The publication file pathname changed.")
                return data

    def _record_bytes(self, name):
        return self._file_bytes(self.state, name, _LIMIT, modes={0o400}, owned=True)

    def _load(self, name):
        value = json.loads(self._record_bytes(name))
        if type(value) is not dict or set(value) != {"body", "mac"}:
            raise ValueError("Malformed controller publication record.")
        mac = hmac.new(self.verifier._key, _encode(value["body"]), hashlib.sha256).hexdigest()
        if type(value["mac"]) is not str or not hmac.compare_digest(mac, value["mac"]):
            raise ValueError("Publication record authentication refused.")
        return value["body"]

    @contextmanager
    def _descriptor(self, descriptor):
        try:
            yield descriptor
        except BaseException:
            try:
                os.close(descriptor)
            except BaseException as cleanup:
                self._failures.append("State descriptor cleanup failed: " + V._exception_text(cleanup))
            raise
        else:
            os.close(descriptor)

    @contextmanager
    def _record_descriptor(self, parent, name, *, flags=os.O_RDONLY):
        descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with self._descriptor(descriptor):
            yield descriptor

    def _sync_record(self, name):
        self._load(name)
        with self._directory(self.state) as parent:
            with self._record_descriptor(parent, name) as descriptor:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o400):
                    raise ValueError("A synchronized publication record changed kind.")
                os.fsync(descriptor)
        self._sync_directory(self.state)

    def _consent(self, action, directive):
        authority = _VERIFY_DIRECTIVE(directive, verification_key=self.verifier._key,
            expected_actor_id=self.verifier._actor, expected_identity_source=self.verifier._identity,
            expected_action_sha256=canonical_authority_sha256(action))
        if (authority.authorized_scope != "complete-task"
                or directive["parent_receipt_sha256"] != self.operation.operation_sha256):
            raise ValueError("Execution-purpose consent must bind this original operation.")

    def _old(self, path):
        try:
            info = os.lstat(self.host.target / path)
        except FileNotFoundError:
            return {"present": False}, None
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in {0o644, 0o755}):
            raise ValueError("Output replacement requires an owned single regular ordinary file.")
        data = self._file_bytes(self.host.target, path, H.MAX_FILE_BYTES, modes={0o644, 0o755}, owned=True)
        return {"present": True, "size": len(data), "sha256": _sha(data),
                "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                "mtime_ns": info.st_mtime_ns, "atime_ns": info.st_atime_ns}, data

    def _prepare(self, action, outputs, directive):
        before = self._capture()
        if _encode(before) != self.expected:
            raise ValueError("The original target revision/dirty manifest drifted.")
        if list(self.state.iterdir()):
            raise ValueError("Unrecognized prior publication persistence requires reconciliation.")
        old = [self._old(path) for path, _data in outputs]
        intent = {"action": action, "directive": directive, "before": before,
                  "old": [entry for entry, _data in old]}
        self._record("intent.json", intent)
        for index, ((_path, data), (entry, previous)) in enumerate(zip(outputs, old)):
            if entry["present"]:
                self._new_file(f"old-{index:04d}", previous, 0o400)
            self._new_file(f"new-{index:04d}", data, entry.get("mode", 0o644))
        self._sync_directory(self.state)
        self._record("checkpoint-0000.json", {"action_sha256": _sha(_encode(action)), "applied": 0, "target": before})
        return intent

    def _checkpoint(self, count, intent):
        value = self._load(f"checkpoint-{count:04d}.json")
        if (set(value) != {"action_sha256", "applied", "target"}
                or value["action_sha256"] != _sha(_encode(intent["action"]))
                or type(value["applied"]) is not int or value["applied"] != count):
            raise ValueError("The checkpoint publication binding or count changed.")
        if count == 0 and (value["target"] != intent["before"] or _encode(value["target"]) != self.expected):
            raise ValueError("Checkpoint zero must retain the original expected target.")
        return value

    def _retained_files(self, intent, outputs, applied):
        names = set()
        for index, ((path, data), old) in enumerate(zip(outputs, intent["old"])):
            if old["present"]:
                name = f"old-{index:04d}"
                names.add(name)
                prior = self._file_bytes(self.state, name, H.MAX_FILE_BYTES, modes={0o400}, owned=True)
                if len(prior) != old["size"] or _sha(prior) != old["sha256"]:
                    raise ValueError("The retained original target bytes changed.")
            if index >= applied:
                name = f"new-{index:04d}"
                names.add(name)
                info = os.lstat(self.state / name)
                if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != old.get("mode", 0o644)
                        or self._file_bytes(self.state, name, H.MAX_FILE_BYTES, modes={old.get("mode", 0o644)}, owned=True) != data):
                    raise ValueError("The staged exact candidate bytes changed.")
            elif self._file_bytes(self.host.target, path, H.MAX_FILE_BYTES, modes={0o644, 0o755}, owned=True) != data:
                raise ValueError("Published output bytes changed.")
        return names

    def _inspect(self, intent, outputs, matching_recovery=None):
        count = 0
        while (self.state / f"checkpoint-{count + 1:04d}.json").exists():
            count += 1
            if count > len(outputs):
                raise ValueError("Unknown publication checkpoint.")
        checkpoint = self._checkpoint(count, intent)
        if self._known is not None and self._known["applied"] > count:
            if self._known["action_sha256"] != _sha(_encode(intent["action"])):
                raise ValueError("The known publication observation belongs to another action.")
            checkpoint = self._known
        if self._capture() != checkpoint["target"]:
            raise ValueError("Target drift or an unrecorded partial publication requires reconciliation.")
        names = {"intent.json", *(f"checkpoint-{i:04d}.json" for i in range(count + 1))}
        names |= self._saved_failures(intent)
        if matching_recovery is not None:
            # Original intent/action were authenticated by _run. Current target,
            # checkpoint and existing history are now known before payload I/O.
            self._known = checkpoint
            matching_recovery[0] = True
        names |= self._retained_files(intent, outputs, checkpoint["applied"])
        if (self.state / "receipt.json").exists():
            names.add("receipt.json")
            if self._load("receipt.json") != {"action": intent["action"], "checkpoint": checkpoint}:
                raise ValueError("The original publication receipt changed.")
        if {path.name for path in self.state.iterdir()} != names:
            raise ValueError("Unknown publication state entries require reconciliation.")
        return checkpoint

    def _saved_failures(self, intent):
        names = set()
        for index, path in enumerate(sorted(self.state.glob("failure-*.json"))):
            if path.name != f"failure-{index:04d}.json":
                raise ValueError("Publication failure history is incomplete.")
            record = self._load(path.name)
            if record["action"] != intent["action"]:
                raise ValueError("Publication failure history binding changed.")
            if record["failure"] not in self._failures:
                self._failures.append(record["failure"])
            names.add(path.name)
        self._failure_sequence = len(names)
        return names

    def _remember_failure(self, action, exc):
        # Called only under the same guard, for an already persisted matching
        # operation. Recording failure cannot replace the original exception.
        message = V._exception_text(exc)
        self._failures.append(message)
        try:
            if self._load("intent.json")["action"] != action:
                return
            self._record(f"failure-{self._failure_sequence:04d}.json",
                         {"action": action, "failure": message})
            self._failure_sequence += 1
        except BaseException as recording:
            self._failures.append("Failure persistence unconfirmed: " + V._exception_text(recording))

    def _apply_one(self, index, outputs, checkpoint, counts, token, report, action, directive):
        path, data = outputs[index]
        self._check()
        if self._capture() != checkpoint["target"]:
            raise ValueError("Target changed immediately before publication.")
        self._validated(token, report)
        self._consent(action, directive)
        intent = self._load("intent.json")
        if intent["action"] != action:
            raise ValueError("The persisted publication binding changed.")
        self._retained_files(intent, outputs, index)
        # Intent and old bytes are durable before this actual filesystem boundary.
        with self._directory(self.state) as source, self._directory(self.host.target) as target:
            confirmed = counts["replacements"]
            counts["replace_attempts"] += 1
            counts["replacements"] = None
            os.replace(f"new-{index:04d}", path, src_dir_fd=source, dst_dir_fd=target)
            counts["replacements"] = confirmed + 1
        after = self._capture()
        if (_strip_outputs(after, {path}) != _strip_outputs(checkpoint["target"], {path})
                or self._file_bytes(self.host.target, path, H.MAX_FILE_BYTES, modes={0o644, 0o755}, owned=True) != data):
            raise ValueError("Publication observed unrelated changes or incorrect bytes.")
        self._known = {"action_sha256": _sha(_encode(action)), "applied": index + 1, "target": after}
        self._sync_directory(self.host.target)
        self._sync_directory(self.state)
        self._record(f"checkpoint-{index + 1:04d}.json", self._known)
        return self._known

    def _run(self, action, outputs, token, report, directive, counts, matching_recovery):
        if not (self.state / "intent.json").exists():
            V.consume_validated(self.host, token, report, json.loads(self.expected), self.policy)
            intent = self._prepare(action, outputs, directive)
        else:
            intent = self._load("intent.json")
        if intent["action"] != json.loads(_encode(action)) or intent["directive"] != directive:
            raise ValueError("Mutated replay or a competing operation is refused.")
        checkpoint = self._inspect(intent, outputs, matching_recovery)
        matching_recovery[0] = True
        self._known = checkpoint
        if checkpoint["applied"]:
            self._sync_directory(self.host.target)
        self._sync_directory(self.state)
        checkpoint_name = f"checkpoint-{checkpoint['applied']:04d}.json"
        if not (self.state / checkpoint_name).exists():
            self._record(checkpoint_name, checkpoint)
        self._sync_record(checkpoint_name)
        for name in sorted(self._saved_failures(intent)):
            self._sync_record(name)
        for index in range(checkpoint["applied"], len(outputs)):
            self._validated(token, report)
            self._consent(action, directive)
            checkpoint = self._apply_one(index, outputs, checkpoint, counts, token, report, action, directive)
        self._validated(token, report)
        self._check()
        self._inspect(intent, outputs)
        if not (self.state / "receipt.json").exists():
            self._record("receipt.json", {"action": action, "checkpoint": checkpoint})
        self._sync_record("receipt.json")
        self._inspect(intent, outputs)
        return self._result(counts, True)

    def _audit_guard_failure(self, action, token, report, directive, failure):
        # The old guard may already be released. Reacquire exclusion once,
        # authenticate current applicability, and record history only: no apply.
        try:
            with self._guard():
                _binding, outputs = self._validated(token, report)
                self._consent(action, directive)
                intent = self._load("intent.json")
                if intent["action"] != action or intent["directive"] != directive:
                    raise ValueError("Guard failure history requires the exact original operation.")
                checkpoint = self._inspect(intent, outputs)
                if checkpoint["applied"] != len(outputs):
                    raise ValueError("Completed guard history requires the known published target.")
                self._known = checkpoint
                self._remember_failure(action, failure)
        except BaseException as audit:
            self._failures.append("Guard failure history persistence unconfirmed: " + V._exception_text(audit))

    def _result(self, counts, complete=False):
        return {"publication_complete": complete, "new_invocation": dict(counts),
                "known_applied_files": None if self._known is None else self._known["applied"],
                "completion_uncertain": not complete, "failures": list(self._failures), **_FALSE}

    def publish(self, operation_id, issued_token, original_report, execution_directive):
        """Publish/recover without native redispatch, branch/index effects or rollback."""
        counts = {"replace_attempts": 0, "replacements": 0}
        matching_recovery = [False]
        run_completed = False
        action = None
        try:
            with self._guard():
                action = self.binding(operation_id, issued_token, original_report)
                self._consent(action, execution_directive)
                _binding, outputs = self._validated(issued_token, original_report)
                try:
                    result = self._run(action, outputs, issued_token, original_report, execution_directive, counts, matching_recovery)
                    run_completed = True
                except BaseException as exc:
                    if counts["replace_attempts"] or matching_recovery[0]:
                        self._remember_failure(action, exc)
                    raise
            return result
        except BaseException as exc:
            self._failures.extend(note for note in getattr(exc, "__notes__", ()) if note not in self._failures)
            if run_completed:
                self._audit_guard_failure(action, issued_token, original_report, execution_directive, exc)
            if V._exception_text(exc) not in self._failures:
                self._failures.append(V._exception_text(exc))
            error = PublicationError("Guarded target publication refused.", self._result(counts))
            if not isinstance(exc, Exception):
                exc.publication_report = error.report
                raise
            raise error from exc
