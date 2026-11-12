"""Durable cooperative FAKE file projection with no real promotion authority."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import threading
from contextlib import contextmanager
from types import FunctionType

import offline_artifact_validation as VALIDATION

HOST = VALIDATION.HOST
_CONSUME = VALIDATION.consume_validated
_SNAPSHOT = VALIDATION._snapshot
_POLICY = VALIDATION.ValidationPolicy
_POLICY_REPORT = _POLICY.report.fget
_FUNCTIONS = {
    name: value for name, value in vars(VALIDATION).items()
    if type(value) is FunctionType and value.__module__ == VALIDATION.__name__
}
_REGISTRIES = (VALIDATION._POLICIES, VALIDATION._TOKENS)
_FALSE = {"effect_authority": False, "production_ready": False, "accepted_for_use": False, "operative": False}
_CEILINGS = {"max_files": 2 * HOST.MAX_OUTPUTS, "max_file_bytes": HOST.MAX_FILE_BYTES,
             "max_total_bytes": HOST.MAX_ARTIFACT_BYTES, "max_entries": 256}
_RECORD_LIMIT = 4 * HOST.MAX_RECORD_BYTES
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _encode(value):
    return _SNAPSHOT(value, _RECORD_LIMIT)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _same(left, right):
    return _encode(left) == _encode(right)


def _inode(info):
    return [info.st_dev, info.st_ino]


def _body(record):
    return {key: value for key, value in record.items() if key != "storage_identity"}


def _record_fields(record, fields):
    if type(record) is not dict or len(record) != len(fields):
        raise ValueError("A fake record has an unsupported type or field count.")
    if any(type(key) is not str for key in record):
        raise ValueError("Fake record field names must be plain text.")
    if set(record) != set(fields):
        raise ValueError("A fake record has unknown or missing fields.")


def _sources():
    if any(getattr(VALIDATION, name, None) is not original for name, original in _FUNCTIONS.items()):
        raise ValueError("The original offline validator functions changed.")
    if (VALIDATION.ValidationPolicy is not _POLICY
            or VALIDATION.ValidationPolicy.report.fget is not _POLICY_REPORT
            or VALIDATION._POLICIES is not _REGISTRIES[0]
            or VALIDATION._TOKENS is not _REGISTRIES[1]):
        raise ValueError("The original offline validator identities changed.")


def _effects():
    return {"files_created": 0, "directories_created": 0, "bytes_written": 0,
            "pointer_replace_attempts": 0, "pointer_replacements": 0,
            "fsync_attempts": 0, "fsync_successes": 0}


def _facts():
    return {"intent_present": False, "receipt_present": False, "pointer_state": "unknown",
            "saved_pointer_publications": None, "revision": None, "status": "unknown",
            "claim": None}


def _unknown(facts, counts):
    if facts["saved_pointer_publications"] == 1 or (
            counts["pointer_replace_attempts"] and counts["pointer_replacements"] is None):
        facts["saved_pointer_publications"] = None
    facts.update(pointer_state="unknown", revision=None, status="unknown", claim=None)


def _operation_key(operation_id, binding):
    return _encode({"operation_id": operation_id, "binding": binding})


def _disjoint_paths(paths):
    names = set(paths)
    for path in paths:
        parts = path.split("/")
        if any("/".join(parts[:depth]) in names for depth in range(1, len(parts))):
            raise ValueError("Fake file paths cannot overlap as files and directories.")


class FakePromotionError(ValueError):
    """A fake persistence refusal retaining copied observations and errors."""

    def __init__(self, message, report):
        super().__init__(message)
        self._report = _encode(report)

    @property
    def report(self):
        return json.loads(self._report)


class FakeArtifactTarget:
    """One bounded, recoverable FAKE revision change under cooperative integrity checks."""

    def __init__(self, state_directory, target_directory, host, expected_target, initial_files, *, limits):
        _sources()
        self._host, self._expected = host, _encode(expected_target)
        self._host_roots = VALIDATION._host(host)
        if self._expected != _encode(host._initial["target"]):
            raise ValueError("The fake projection requires the original full host target capture.")
        if self._expected != _encode(VALIDATION._CAPTURE(host.target, (host.target, host.worker))):
            raise ValueError("The original full host target capture is stale.")
        self._limits = self._limits_record(limits)
        self._state, self._target = HOST._path(state_directory), HOST._path(target_directory)
        self._roots = (self._state, self._target, host.state, host.target, host.worker)
        self._root_ids = tuple(tuple(HOST._identity(path)) for path in self._roots)
        self._claim_lock = threading.Lock()
        self._held = None
        self._issued_pair = None
        self._publication = None
        self._prepared = None
        self._check_roots()
        self._initial, self._initial_manifest = self._projection(initial_files)

    @staticmethod
    def _limits_record(limits):
        _record_fields(limits, _CEILINGS)
        if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
            raise ValueError("Fake projection limits must be bounded positive integers.")
        return dict(limits)

    def _root_info(self, index, path):
        if str(path) == "/" or any(HOST._within(path, HOST.Path(root)) for root in ("/dev", "/proc", "/sys")):
            raise ValueError("Fake persistence refuses special roots.")
        if HOST._path(path) != path or tuple(HOST._identity(path)) != self._root_ids[index]:
            raise ValueError("A bound directory changed identity or canonical path.")
        info = os.lstat(path)
        if index < 2 and (info.st_uid, stat.S_IMODE(info.st_mode)) != (os.geteuid(), 0o700):
            raise ValueError("Fake state and projection roots must remain private directories.")
        return tuple(_inode(info))

    def _check_roots(self):
        _sources()
        if VALIDATION._host(self._host) != self._host_roots:
            raise ValueError("The original host directory identities changed.")
        identities = [self._root_info(index, path) for index, path in enumerate(self._roots)]
        if len(set(identities)) != len(identities):
            raise ValueError("Fake state, projection and host roots cannot share identities.")
        for index, path in enumerate(self._roots):
            with HOST._directory(path) as descriptor:
                ancestry = {tuple(_inode(info)) for info in HOST.workspace_capture._ancestry(descriptor)}
                if any(identity in ancestry for other, identity in enumerate(identities) if other != index):
                    raise ValueError("Fake state, projection and host roots cannot be nested.")

    def _check(self):
        self._check_roots()
        if self._held is not None:
            current = os.stat("fake.lock", dir_fd=self._held[1], follow_symlinks=False)
            if _inode(current) != _inode(os.fstat(self._held[0])):
                raise ValueError("The held fake exclusion file changed identity.")
            self._file_kind(current, 0o600)

    @staticmethod
    def _file_kind(info, mode):
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode):
            raise ValueError("Fake persistence requires private single regular files with exact modes.")

    @contextmanager
    def _instance_claim(self):
        if not self._claim_lock.acquire(blocking=False):
            raise ValueError("The fake exclusion guard refuses concurrent entry or reentry.")
        try:
            yield
        finally:
            self._claim_lock.release()

    @contextmanager
    def _guard(self, counts, *, create=False):
        with self._instance_claim():
            self._check_roots()
            with HOST._directory(self._state) as parent:
                flags = _READ_FLAGS
                if create:
                    if self._names(self._state) or self._names(self._target):
                        raise ValueError("Fake initialization requires two empty private fixture directories.")
                    flags |= os.O_CREAT | os.O_EXCL
                descriptor = os.open("fake.lock", flags, 0o600, dir_fd=parent)
                if create:
                    counts["files_created"] += 1
                held = (descriptor, parent)
                try:
                    self._file_kind(os.fstat(descriptor), 0o600)
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._held = held
                    self._check()
                    yield
                finally:
                    if self._held is held:
                        self._held = None
                    os.close(descriptor)

    def _at(self, path, descriptor):
        self._check()
        info = os.fstat(descriptor)
        if HOST._identity(path) != [info.st_dev, info.st_ino, info.st_mode]:
            raise ValueError("A fake persistence directory moved or changed identity.")

    def _names(self, path):
        self._check_roots()
        with HOST._directory(path) as descriptor:
            return set(VALIDATION._names(descriptor, self._limits["max_entries"]))

    def _read(self, path, name, cap):
        self._check()
        info = os.lstat(path / name)
        self._file_kind(info, 0o400)
        if info.st_size > cap:
            raise ValueError("A fake persistence file exceeds its read bound.")
        data = HOST._read(path, name, cap)
        if HOST._file_mark(os.lstat(path / name)) != HOST._file_mark(info):
            raise ValueError("A fake persistence file changed during its read.")
        return data

    def _record(self, path, name):
        data = self._read(path, name, _RECORD_LIMIT)
        record = json.loads(data)
        if type(record) is not dict or not _same(record.get("storage_identity"), _inode(os.lstat(path / name))):
            raise ValueError("A fake metadata file has an invalid storage identity.")
        if _encode(record) != data:
            raise ValueError("Fake metadata must retain its exact bounded canonical encoding.")
        return record

    def _fsync(self, descriptor, counts):
        self._check()
        counts["fsync_attempts"] += 1
        os.fsync(descriptor)
        counts["fsync_successes"] += 1

    def _sync(self, path, counts):
        with HOST._directory(path) as descriptor:
            self._at(path, descriptor)
            self._fsync(descriptor, counts)

    def _sync_file(self, path, name, counts):
        with HOST._directory(path) as parent:
            self._at(path, parent)
            descriptor = os.open(name, _READ_FLAGS, dir_fd=parent)
            try:
                mode = 0o600 if name == "fake.lock" else 0o400
                self._file_kind(os.fstat(descriptor), mode)
                self._fsync(descriptor, counts)
            finally:
                os.close(descriptor)

    def _new(self, path, name, data, counts, *, record=False):
        with HOST._directory(path) as parent:
            self._at(path, parent)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(name, flags, 0o600, dir_fd=parent)
            counts["files_created"] += 1
            try:
                if record:
                    data = _encode({**data, "storage_identity": _inode(os.fstat(descriptor))})
                view = memoryview(data)
                while view:
                    self._linked(path, parent, name, descriptor)
                    count = os.write(descriptor, view)
                    if count <= 0:
                        raise ValueError("A fake persistence write made no progress.")
                    counts["bytes_written"] += count
                    view = view[count:]
                self._linked(path, parent, name, descriptor)
                os.fchmod(descriptor, 0o400)
                self._fsync(descriptor, counts)
            finally:
                os.close(descriptor)
        return json.loads(data) if record else None

    def _linked(self, path, parent, name, descriptor):
        self._at(path, parent)
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self._file_kind(info, 0o600)
        if _inode(info) != _inode(os.fstat(descriptor)):
            raise ValueError("A fake persistence file was substituted during its write.")

    def _new_record(self, path, name, record, counts):
        return self._new(path, name, record, counts, record=True)

    def _manifest_entry(self, index, path, pair):
        size, digest = pair
        if type(size) is not int or not 0 <= size <= self._limits["max_file_bytes"]:
            raise ValueError("A fake file size exceeds its explicit bound.")
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("A fake file digest must be lowercase SHA256 text.")
        return {"path": path, "blob": f"file-{index:04d}", "size": size, "sha256": digest}

    def _file_paths(self, files):
        if type(files) is not dict or len(files) > self._limits["max_files"]:
            raise ValueError("The fake file map exceeds its explicit file bound.")
        if any(type(path) is not str for path in files):
            raise ValueError("Fake file names must be plain text.")
        paths = [VALIDATION._relative(path) for path in files]
        _disjoint_paths(paths)
        if 2 * (len(paths) + 1) + 8 > self._limits["max_entries"]:
            raise ValueError("The complete fake persistence layout exceeds its entry bound.")
        return sorted(paths)

    def _manifest(self, metadata):
        paths = self._file_paths(metadata)
        entries = [self._manifest_entry(index, path, metadata[path]) for index, path in enumerate(paths)]
        if sum(entry["size"] for entry in entries) > self._limits["max_total_bytes"]:
            raise ValueError("The fake file map exceeds its explicit total byte bound.")
        return {"version": 1, "fake": True, "files": entries}

    def _projection_sizes(self, files, paths):
        total = 0
        for path in paths:
            data = files[path]
            if type(data) is not bytes:
                raise ValueError("A fake projection requires independently declared plain bytes.")
            if len(data) > self._limits["max_file_bytes"]:
                raise ValueError("A fake projection file exceeds its explicit byte bound.")
            total += len(data)
            if total > self._limits["max_total_bytes"]:
                raise ValueError("The fake file map exceeds its explicit total byte bound.")

    def _projection(self, files):
        paths = self._file_paths(files)
        self._projection_sizes(files, paths)
        manifest = self._manifest({path: (len(files[path]), _sha(files[path])) for path in paths})
        return tuple((path, files[path]) for path in paths), manifest

    def _seal(self, path):
        with HOST._directory(path) as descriptor:
            self._at(path, descriptor)
            info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != 0o500 or info.st_uid != os.geteuid():
                raise ValueError("A fake immutable generation lost its private read only mode.")
            entries = {}
            for name in sorted(self._names(path)):
                item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                self._file_kind(item, 0o400)
                entries[name] = list(HOST._file_mark(item))
            return {"directory": list(HOST._file_mark(info)), "entries": entries}

    def _generation_files(self, path, entries):
        files = {}
        for index, entry in enumerate(entries):
            if type(entry) is not dict or set(entry) != {"path", "blob", "size", "sha256"}:
                raise ValueError("A fake generation file entry has an unsupported shape.")
            relative = VALIDATION._relative(entry["path"])
            if relative in files:
                raise ValueError("A fake generation contains duplicate file paths.")
            files[relative] = self._read(path, f"file-{index:04d}", self._limits["max_file_bytes"])
        return files

    def _generation(self, name, manifest, seal):
        path = self._target / name
        if type(manifest) is not dict or type(manifest.get("files")) is not list:
            raise ValueError("A fake generation manifest has an unsupported shape.")
        if len(manifest["files"]) > self._limits["max_files"]:
            raise ValueError("A fake generation manifest exceeds its file bound.")
        before = self._seal(path)
        if self._names(path) != {"manifest.json", *(f"file-{index:04d}" for index in range(len(manifest["files"])))}:
            raise ValueError("A fake generation has missing or unknown entries.")
        if self._read(path, "manifest.json", _RECORD_LIMIT) != _encode(manifest):
            raise ValueError("A fake generation manifest differs from its durable binding.")
        projection, actual = self._projection(self._generation_files(path, manifest["files"]))
        if not _same(actual, manifest) or not _same(self._seal(path), before) or not _same(before, seal):
            raise ValueError("A fake immutable generation changed bytes, identity, mode or inventory.")
        return projection

    def _write_generation(self, name, files, counts):
        path = self._target / name
        with HOST._directory(self._target) as parent:
            self._at(self._target, parent)
            os.mkdir(name, 0o700, dir_fd=parent)
            counts["directories_created"] += 1
        projection, manifest = self._projection(dict(files))
        for entry, (_relative, data) in zip(manifest["files"], projection):
            self._new(path, entry["blob"], data, counts)
        self._new(path, "manifest.json", _encode(manifest), counts)
        with HOST._directory(path) as descriptor:
            self._at(path, descriptor)
            os.fchmod(descriptor, 0o500)
            self._fsync(descriptor, counts)
        self._sync(self._target, counts)
        return self._seal(path)

    @staticmethod
    def _pointer(revision, manifest):
        return {"version": 1, "fake": True, "revision": revision,
                "generation": f"generation-{revision:04d}", "manifest_sha256": _sha(_encode(manifest))}

    def _pointer_record(self, pointer, revision, manifest):
        _record_fields(pointer, {"version", "fake", "revision", "generation",
                                 "manifest_sha256", "storage_identity"})
        identity = pointer["storage_identity"]
        if (type(identity) is not list or len(identity) != 2
                or any(type(item) is not int or not 0 <= item < 2 ** 64 for item in identity)):
            raise ValueError("A fake pointer requires a bounded plain storage identity.")
        if not _same(_body(pointer), self._pointer(revision, manifest)):
            raise ValueError("A fake pointer changed its exact revision or manifest binding.")

    def _owner_body(self, initial_seal, initial_pointer):
        return {"version": 1, "fake": True, "limits": self._limits,
                "roots": [list(identity) for identity in self._root_ids],
                "expected_target_sha256": _sha(self._expected),
                "host_roots": [[path, list(identity)] for path, identity in self._host_roots],
                "lock_identity": _inode(os.fstat(self._held[0])),
                "initial_manifest": self._initial_manifest,
                "initial_seal": initial_seal, "initial_pointer": initial_pointer}

    def initialize(self):
        counts = _effects()
        try:
            with self._guard(counts, create=True):
                self._sync_file(self._state, "fake.lock", counts)
                seal = self._write_generation("generation-0000", self._initial, counts)
                pointer = self._new_record(self._target, "current.json", self._pointer(0, self._initial_manifest), counts)
                self._sync(self._target, counts)
                self._new_record(self._state, "owner.json", self._owner_body(seal, pointer), counts)
                self._sync(self._state, counts)
                self._inspect(_facts())
                return {"fake_initialized": True, "fake_promoted": False, "fake_completion": False,
                        "new_invocation": counts, **_FALSE}
        except Exception as exc:
            message = f"Fake initialization refused ({type(exc).__name__}: {exc})."
            raise FakePromotionError(message, self._result(_facts(), counts, [message])) from exc

    def _layout(self, journal):
        state = self._names(self._state)
        target = self._names(self._target)
        if not {"fake.lock", "owner.json"} <= state or state - {"fake.lock", "owner.json", "journal.json", "receipt.json"}:
            raise ValueError("Fake external state has missing or unknown entries.")
        allowed = {"generation-0000", "current.json"}
        if journal is not None:
            allowed |= {"generation-0001", "current.next"}
        if not {"generation-0000", "current.json"} <= target or target - allowed:
            raise ValueError("The fake target has missing, unknown or unbound staging entries.")
        if journal is None and "receipt.json" in state:
            raise ValueError("A fake receipt without its original journal is refused.")

    def _claim_record(self, claim):
        _record_fields(claim, {"operation_id", "binding", "before", "manifest"})
        if type(claim["operation_id"]) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", claim["operation_id"]) is None:
            raise ValueError("A recovered fake operation ID must be bounded plain text.")
        binding = claim["binding"]
        _record_fields(binding, {"report_sha256", "artifact_sha256", "policy_sha256",
                                 "expected_target_sha256"})
        if any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
               for value in binding.values()):
            raise ValueError("Recovered fake bindings require plain lowercase SHA256 text.")

    def _read_journal(self, owner, facts):
        if "journal.json" not in self._names(self._state):
            return None
        facts["intent_present"] = True
        journal = self._record(self._state, "journal.json")
        if set(_body(journal)) != {"version", "fake", "claim", "generation_seal", "after"}:
            raise ValueError("The fake journal has unknown or missing fields.")
        claim = journal["claim"]
        self._claim_record(claim)
        if (type(journal["version"]) is not int or journal["version"] != 1 or journal["fake"] is not True
                or not _same(claim["before"], owner["initial_pointer"])):
            raise ValueError("The fake journal changed its version or initial revision binding.")
        if (claim["binding"]["expected_target_sha256"] != owner["expected_target_sha256"]
                or claim["binding"]["expected_target_sha256"] != _sha(self._expected)):
            raise ValueError("The recovered fake expected target differs from its independent owner "
                             "or original capture.")
        self._pointer_record(journal["after"], 1, claim["manifest"])
        return journal

    def _receipt_body(self, journal):
        return {"version": 1, "fake": True, "journal_sha256": _sha(_encode(journal)),
                "after": journal["after"], "saved_pointer_publications": 1}

    def _inspect_pending(self, journal, pointer, facts):
        self._layout(journal)
        if "current.next" in self._names(self._target):
            if facts["pointer_state"] != "initial" or not _same(self._record(self._target, "current.next"), journal["after"]):
                raise ValueError("The fake staged pointer is unknown or inconsistent.")
        elif journal is not None and facts["pointer_state"] == "initial":
            raise ValueError("The prepared fake operation lost its exact staged pointer.")
        if "receipt.json" in self._names(self._state):
            facts["receipt_present"] = True
            receipt = self._record(self._state, "receipt.json")
            if journal is None or not _same(pointer, journal["after"]) or not _same(_body(receipt), self._receipt_body(journal)):
                raise ValueError("The fake receipt differs from actual journal and pointer observations.")

    def _check_publication(self, claim):
        publication = _encode(claim)
        if self._publication is not None and self._publication != publication:
            raise ValueError("A known fake publication has a different original operation binding.")

    def _inspect(self, facts):
        facts.update(_facts())
        self._check()
        names = self._names(self._state)
        facts.update(intent_present="journal.json" in names, receipt_present="receipt.json" in names)
        owner = self._record(self._state, "owner.json")
        if not _same(_body(owner), self._owner_body(owner["initial_seal"], owner["initial_pointer"])):
            raise ValueError("The fake owner binding differs from the independent initial declaration.")
        self._pointer_record(owner["initial_pointer"], 0, self._initial_manifest)
        self._generation("generation-0000", self._initial_manifest, owner["initial_seal"])
        pointer = self._record(self._target, "current.json")
        if _same(pointer, owner["initial_pointer"]):
            facts.update(pointer_state="initial", saved_pointer_publications=0, revision=0)
        journal = self._read_journal(owner, facts)
        observed = dict(facts)
        if journal is not None and _same(pointer, journal["after"]):
            observed.update(pointer_state="new", saved_pointer_publications=1, revision=1)
        if observed["pointer_state"] == "unknown":
            raise ValueError("The actual fake current pointer has an unknown value or identity.")
        if journal is not None:
            self._generation("generation-0001", journal["claim"]["manifest"], journal["generation_seal"])
        self._inspect_pending(journal, pointer, observed)
        if self._prepared is not None:
            self._prepared_records(owner, journal, None if journal is None else journal["claim"])
        if self._publication is not None:
            if observed["pointer_state"] != "new":
                raise ValueError("A witnessed fake publication cannot resume from the initial pointer.")
            self._check_publication(journal["claim"])
        if journal is not None and self._prepared is None:
            return owner, journal, pointer
        observed.update(claim=None if journal is None else journal["claim"],
                        status="known-published" if observed["pointer_state"] == "new" else "not-published")
        facts.update(observed)
        return owner, journal, pointer

    def _claim_inputs(self, operation_id, report, policy, expected_revision):
        if type(operation_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", operation_id) is None:
            raise ValueError("A fake operation ID must be bounded plain text.")
        if type(expected_revision) is not int or expected_revision != 0:
            raise ValueError("This bounded fake target requires the original expected revision zero.")
        _sources()
        policy_report = _POLICY_REPORT(policy)
        report_bytes = _encode(report)
        if type(report) is not dict or "artifact" not in report:
            raise ValueError("The fake operation requires the original host artifact report.")
        binding = {"report_sha256": _sha(report_bytes),
                   "artifact_sha256": _sha(_encode(report["artifact"])),
                   "policy_sha256": _sha(_encode(policy_report)),
                   "expected_target_sha256": _sha(self._expected)}
        return policy_report, binding

    def _claim(self, operation_id, report, policy, expected_revision, owner):
        policy_report, binding = self._claim_inputs(operation_id, report, policy, expected_revision)
        metadata = {entry["path"]: (entry["size"], entry["sha256"]) for entry in self._initial_manifest["files"]}
        metadata.update({entry["path"]: (entry["size"], entry["sha256"]) for entry in policy_report["outputs"]})
        return {"operation_id": operation_id, "before": owner["initial_pointer"],
                "manifest": self._manifest(metadata),
                "binding": binding}

    def _fresh(self, token, report, policy, claim, owner):
        _sources()
        if self._issued_pair is not None and (self._issued_pair[0] is not token or self._issued_pair[1] is not policy):
            raise ValueError("This fake target instance requires its original issued token and policy objects.")
        outputs = _CONSUME(self._host, token, report, json.loads(self._expected), policy)
        files = dict(self._initial)
        files.update(outputs)
        projection, manifest = self._projection(files)
        if not _same(manifest, claim["manifest"]) or not _same(self._claim(claim["operation_id"], report, policy, 0, owner), claim):
            raise ValueError("Original consumed bytes or invocation bindings changed around fake validation.")
        self._issued_pair = (token, policy)
        return projection

    def _prepared_records(self, owner, journal, claim, *, prepared=None):
        if self._prepared is None:
            self._prepared = prepared
        if (self._prepared is None or journal is None
                or self._prepared != (_encode(owner), _encode(claim), _encode(journal))):
            raise ValueError("The fake prepared owner, claim or journal changed before publication.")
        if not _same(journal["claim"], claim):
            raise ValueError("The fake prepared journal differs from the exact invocation claim.")

    def _prepared_pointer(self, journal):
        if not _same(self._record(self._target, "current.next"), journal["after"]):
            raise ValueError("The fake staged pointer differs from its immutable prepared binding.")

    def _publish(self, counts, token, report, policy, claim, owner, facts):
        with HOST._directory(self._target) as descriptor:
            self._at(self._target, descriptor)
            self._fresh(token, report, policy, claim, owner)
            current_owner, journal, _pointer = self._inspect(facts)
            self._prepared_records(current_owner, journal, claim)
            if facts["pointer_state"] != "initial":
                raise ValueError("The fake expected revision changed immediately before publication.")
            self._prepared_pointer(journal)
            self._at(self._target, descriptor)
            publication = self._prepared[1]
            counts["pointer_replace_attempts"] += 1
            counts["pointer_replacements"] = None
            os.replace("current.next", "current.json", src_dir_fd=descriptor, dst_dir_fd=descriptor)
            self._publication = publication
            facts.update(claim=json.loads(publication), saved_pointer_publications=1)
            counts["pointer_replacements"] = 1

    def _finish(self, journal, token, report, policy, claim, owner, counts, facts):
        owner, journal, _pointer = self._inspect(facts)
        self._prepared_records(owner, journal, claim)
        if facts["pointer_state"] != "new":
            raise ValueError("Fake receipt persistence requires the exact prepared new pointer.")
        if not facts["receipt_present"]:
            self._new_record(self._state, "receipt.json", self._receipt_body(journal), counts)
        self._sync_file(self._state, "receipt.json", counts)
        self._sync(self._state, counts)
        self._fresh(token, report, policy, claim, owner)
        owner, journal, _pointer = self._inspect(facts)
        self._prepared_records(owner, journal, claim)
        if facts["pointer_state"] != "new" or facts["receipt_present"] is not True:
            raise ValueError("Fake completion requires the actual exact new pointer and receipt.")
        return self._result(facts, counts, [], complete=True,
                            invocation=_operation_key(claim["operation_id"], claim["binding"]))

    def _apply(self, operation_id, token, report, policy, revision, counts, facts):
        owner, journal, _pointer = self._inspect(facts)
        claim = self._claim(operation_id, report, policy, revision, owner)
        if journal is not None and not _same(journal["claim"], claim):
            raise ValueError("Mutated fake replay or a competing fake operation is refused.")
        prepared = (_encode(owner), _encode(claim))
        files = self._fresh(token, report, policy, claim, owner)
        if journal is None:
            seal = self._write_generation("generation-0001", files, counts)
            after = self._new_record(self._target, "current.next", self._pointer(1, claim["manifest"]), counts)
            self._sync(self._target, counts)
            journal = self._new_record(self._state, "journal.json",
                                       {"version": 1, "fake": True, "claim": claim, "generation_seal": seal, "after": after}, counts)
        self._prepared_records(owner, journal, claim,
                               prepared=(*prepared, _encode(journal)))
        self._sync_file(self._state, "journal.json", counts)
        self._sync(self._state, counts)
        self._inspect(facts)
        current_owner, current_journal, _pointer = self._inspect(facts)
        self._prepared_records(current_owner, current_journal, claim)
        if facts["pointer_state"] == "initial":
            self._publish(counts, token, report, policy, claim, owner, facts)
        self._sync(self._target, counts)
        self._inspect(facts)
        self._fresh(token, report, policy, claim, owner)
        return self._finish(journal, token, report, policy, claim, owner, counts, facts)

    def _publication_fact(self, facts):
        if self._publication is not None:
            return self._publication
        if facts["pointer_state"] == "new" and facts["status"] == "known-published":
            return _encode(facts["claim"])
        return None

    def _scoped_facts(self, facts, invocation):
        saved = dict(facts)
        claim = saved["claim"]
        if claim is not None and invocation != _operation_key(claim["operation_id"], claim["binding"]):
            saved = _facts()
        publication = self._publication_fact(facts)
        if publication is None:
            return saved, None
        publication = json.loads(publication)
        if invocation == _operation_key(publication["operation_id"], publication["binding"]):
            saved.update(claim=publication, saved_pointer_publications=1)
        elif saved["claim"] is None:
            saved = _facts()
        return saved, {"claim": publication, "saved_pointer_publications": 1}

    def _result(self, facts, counts, errors, *, complete=False, invocation=None):
        saved, publication = self._scoped_facts(facts, invocation)
        promoted = saved["pointer_state"] == "new" and saved["status"] == "known-published"
        applicable = bool(complete and promoted and self._prepared is not None
                          and _encode(saved["claim"]) == self._prepared[1])
        return {"fake": True, "fake_promoted": promoted, "fake_completion": applicable,
                "current_applicable": applicable, "saved_operation": saved,
                "known_publication": publication, "new_invocation": dict(counts),
                "errors": list(errors), **_FALSE}

    def promote(self, operation_id, issued_token, original_report, issued_policy, *, expected_revision):
        """Recover or publish one guarded fake generation using original validated bytes."""
        counts, facts = _effects(), _facts()
        invocation = None
        try:
            _policy_report, binding = self._claim_inputs(operation_id, original_report, issued_policy, expected_revision)
            invocation = _operation_key(operation_id, binding)
            with self._guard(counts):
                try:
                    return self._apply(operation_id, issued_token, original_report, issued_policy, expected_revision, counts, facts)
                except Exception as exc:
                    errors = [f"Fake promotion refused ({type(exc).__name__}: {exc})."]
                    try:
                        self._inspect(facts)
                    except Exception as inspection:
                        _unknown(facts, counts)
                        errors.append(f"Fake state inspection refused ({type(inspection).__name__}: {inspection}).")
                    if counts["pointer_replace_attempts"] and counts["pointer_replacements"] is None:
                        if facts["pointer_state"] in {"initial", "new"}:
                            counts["pointer_replacements"] = int(facts["pointer_state"] == "new")
                    raise FakePromotionError(errors[0],
                                             self._result(facts, counts, errors, invocation=invocation)) from exc
        except FakePromotionError:
            raise
        except Exception as exc:
            _unknown(facts, counts)
            message = f"Fake promotion input, exclusion or root check refused ({type(exc).__name__}: {exc})."
            raise FakePromotionError(message,
                                     self._result(facts, counts, [message], invocation=invocation)) from exc

    def snapshot(self):
        """Read actual bounded fake files and revision without claiming fresh validation."""
        counts, facts = _effects(), _facts()
        with self._guard(counts):
            owner, journal, pointer = self._inspect(facts)
            if _same(pointer, owner["initial_pointer"]):
                files = self._generation("generation-0000", self._initial_manifest, owner["initial_seal"])
            else:
                files = self._generation("generation-0001", journal["claim"]["manifest"], journal["generation_seal"])
            return {"revision": pointer["revision"], "files": dict(files),
                    "fake_projection_only": True, **_FALSE}
