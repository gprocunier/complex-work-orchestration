"""Host-owned, content-addressed provenance; integrity-only, not same-user custody.

Production callers select no record root. Workers must have no writable binding
covering this state. A same-user process can replace records and their anchors;
this is tamper evidence, not a signature or protection against that process.
Acceptance persistence itself grants nothing: the acceptance pipeline verifies
its evaluation, adjudication and hold-clearance references before writing it.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import ctypes
import datetime as dt
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator
import uuid

from .errors import CWOPolicyError
from .paths import HOST_STATE_ROOT, REPO_ROOT


class HostRecordError(CWOPolicyError, ValueError):
    """Authoritative provenance is unavailable, incomplete or corrupt."""


@dataclass(frozen=True)
class RecordLimits:
    max_record_bytes: int = 65536
    max_records: int = 10000
    max_scan_bytes: int = 16777216
    max_audit_bytes: int = 16777216
    max_events: int = 100000
    # Original byte/event guards apply to each segment. History has separate,
    # explicit bounds; no record/quota/provenance history is silently discarded.
    max_segments: int = 16
    max_history_bytes: int = 268435456
    max_history_events: int = 1600000


_TYPES = frozenset({'dispatch', 'return-received', 'acceptance-decision',
                    'workspace-database-identity', 'evaluation', 'adjudication', 'hold-clearance'})
_DIGEST = re.compile(r'[0-9a-f]{64}')
_OVERRIDE: ContextVar[HostRecordStore | None] = ContextVar('host_record_test_store', default=None)


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise HostRecordError(reason)


def _json(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                           allow_nan=False) + '\n').encode('ascii')
    except (TypeError, ValueError, RecursionError) as exc:
        raise HostRecordError('host record requires bounded JSON data') from exc


def _parse(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            _need(key not in result, 'duplicate host JSON key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HostRecordError('malformed host JSON') from exc
    _need(type(value) is dict, 'host JSON must be an object')
    return value


def _sha(value: object) -> str:
    _need(type(value) is str and _DIGEST.fullmatch(value) is not None, 'host record requires a SHA-256 id')
    return value


def _token(value: object) -> str:
    _need(type(value) is str and 0 < len(value) <= 256 and not any(ord(c) < 32 for c in value),
          'host record requires a bounded identity')
    return value


_IDENTITY_FIELDS = ('provider', 'model_family', 'model_id', 'reasoning_effort', 'session_id')
_CORE_FIELDS = ('bead_id', 'executor', 'provider_key', 'packet_sha256', 'request_sha256', *_IDENTITY_FIELDS)


def _same_json(left: Any, right: Any) -> bool:
    return _json(left) == _json(right)


def _metadata(value: Any) -> dict[str, Any]:
    _need(type(value) is dict and all(type(key) is str for key in value),
          'dispatch evaluation metadata must have string keys')
    return value


def _verify_observed_metadata(parent: dict[str, Any], observed: dict[str, Any]) -> None:
    prepared = _metadata(parent.get('evaluation_metadata', {}))
    actual = _metadata(observed.get('evaluation_metadata', {}))
    for key, value in prepared.items():
        _need(key in actual and _same_json(value, actual[key]),
              'observed dispatch cannot change prepared evaluation metadata')


def _verify_observed_dispatch(parent: dict[str, Any], observed: dict[str, Any]) -> None:
    _need(observed.get('prepared_record_sha256') == parent['_record_sha256']
          and observed.get('dispatch_id') == parent['dispatch_id'], 'dispatch observation parent binding mismatch')
    _sha(observed.get('observation_sha256'))
    _need(_same_json(observed.get('dispatch_role'), parent.get('dispatch_role'))
          and _same_json(observed.get('review_target'), parent.get('review_target')),
          'observed dispatch cannot change role or review target')
    for key in _IDENTITY_FIELDS:
        _token(observed.get(key))
    for key in _CORE_FIELDS:
        if parent.get(key) is not None:
            _need(_same_json(parent[key], observed.get(key)), 'observed dispatch cannot change a known identity or core field')
    for key in ('bead_id', 'executor', 'provider_key'):
        if observed.get(key) is not None:
            _token(observed[key])
    for key in ('packet_sha256', 'request_sha256'):
        if observed.get(key) is not None:
            _sha(observed[key])
    _verify_observed_metadata(parent, observed)


def _require_record_inventory(anchors: set[tuple[Any, Any, Any]], present: set[str]) -> None:
    expected = {record_id for record_id, kind, event in anchors if kind in _TYPES
                and event == ('dispatch_prepared' if kind == 'dispatch' else 'host_record_written')}
    _need(expected <= present, 'host audit references a missing record')


def _select_dispatch(records: list[dict[str, Any]]) -> dict[str, Any]:
    prepared = [record for record in records if record.get('stage', 'prepared') == 'prepared']
    observed = [record for record in records if record.get('stage') == 'observed']
    _need(len(prepared) == 1 and len(observed) <= 1 and len(prepared) + len(observed) == len(records),
          'host dispatch is missing, ambiguous or has an unknown stage')
    if observed:
        _verify_observed_dispatch(prepared[0], observed[0])
        return observed[0]
    return prepared[0]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _directory(path: Path, *, create: bool = False, private: bool = False) -> int:
    """Walk descriptors from /; neither final nor intermediate links are followed."""
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
            os.close(fd)
            fd = child
        if private:
            info = os.fstat(fd)
            _need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                  'host state directory must be owner-private')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(directory: int, name: str, maximum: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
              and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
              and 0 <= before.st_size <= maximum, 'host source must be bounded, private and regular')
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        _need(len(data) == before.st_size and len(data) <= maximum
              and _identity(os.fstat(fd)) == _identity(before), 'host source changed while reading')
        return data
    finally:
        os.close(fd)


def _rename_new_at(directory, temporary, name):
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    _need(rename is not None, 'atomic no-replace journal publication is unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # Linux RENAME_NOREPLACE: publish the complete inode or refuse an existing
    # claim. Link/unlink publication would leave nlink=2 after a process crash.
    if rename(directory, os.fsencode(temporary), directory, os.fsencode(name), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), name)


def _write_name(name, replace, atomic_create):
    _need(not replace or not atomic_create, 'host write publication modes conflict')
    return '.write-' + uuid.uuid4().hex if replace or atomic_create else name


def _publish_at(directory, temporary, name, replace, atomic_create):
    if atomic_create:
        _rename_new_at(directory, temporary, name)
    elif replace:
        os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)


def _write_at(directory: int, name: str, raw: bytes, *, replace: bool = False,
              atomic_create: bool = False) -> None:
    temporary = _write_name(name, replace, atomic_create)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _need(count > 0, 'host record write did not progress')
            view = view[count:]
        os.fsync(fd)
        _publish_at(directory, temporary, name, replace, atomic_create)
        os.fsync(directory)
    finally:
        os.close(fd)
        if temporary != name:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def _audit_lock(directory: int, *, create: bool, exclusive: bool) -> int:
    flags = (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    lock = os.open('audit.jsonl.lock', flags, 0o600, dir_fd=directory)
    try:
        info = os.fstat(lock)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
              and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
              'host audit lock must be private and regular')
        fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        return lock
    except BaseException:
        os.close(lock)
        raise


def _audit_snapshot(directory: int, limits: RecordLimits) -> list[dict[str, Any]]:
    """Check all bounded segments through the current global checkpoint."""
    from .audit_segments import audit_snapshot
    return audit_snapshot(directory, limits)


def _verified_record_at(record_id, record_type, anchors, directory, limits):
    _sha(record_id)
    raw = _read_at(directory, record_id + '.json', limits.max_record_bytes)
    _need(hashlib.sha256(raw).hexdigest() == record_id, 'host record digest mismatch')
    value = _parse(raw)
    _need(type(value.get('schema_version')) is int and value['schema_version'] == 1
          and value.get('record_type') in _TYPES,
          'host record schema is invalid')
    _need(record_type is None or value['record_type'] == record_type, 'host record type mismatch')
    _need((record_id, value['record_type'], 'dispatch_prepared' if value['record_type'] == 'dispatch'
           else 'host_record_written') in anchors,
          'host record has no matching chained audit event')
    return {**value, '_record_sha256': record_id}


def _recovery_record_ids(anchors):
    return {record_id for record_id, kind, event in anchors if kind in _TYPES
            and event == ('dispatch_prepared' if kind == 'dispatch' else 'host_record_written')}


def _verify_maintenance_recovery_inventory(directory, anchors, _expected, _pending_id, limits):
    from .host_record_inventory import referenced_inventory
    # Verify every anchor and count every entry/byte. Leave all unrelated
    # entries untouched for the subsequent normal quarantine transaction.
    referenced_inventory(directory, anchors, limits)


def verify_recovery_records(state: int, events: list[dict[str, Any]], limits: RecordLimits,
                            pending: dict[str, Any] | None = None, *, allow_unreferenced: bool = False) -> None:
    """Prove the bounded record inventory before any rotation recovery cleanup."""
    anchors = HostRecordStore._anchors(events)
    expected = _recovery_record_ids(anchors)
    pending_id = pending.get('host_record_sha256') if pending else None
    if pending_id is not None:
        _sha(pending_id)
    if not expected and pending_id is None and not allow_unreferenced:
        return
    directory = os.open('records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
    try:
        HostRecordStore._check_record_directory(directory)
        inventory = _verify_maintenance_recovery_inventory if allow_unreferenced else _verify_recovery_inventory
        inventory(directory, anchors, expected, pending_id, limits)
    finally:
        os.close(directory)


def _verify_recovery_inventory(directory, anchors, expected, pending_id, limits):
    count = scan_bytes = 0
    present = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            count += 1
            _need(count <= limits.max_records, 'host record count bound exceeded')
            _need(re.fullmatch(r'[0-9a-f]{64}\.json', entry.name) is not None, 'unexpected host record entry')
            record_id = entry.name[:-5]
            _need(record_id in expected or record_id == pending_id,
                  'host record has no matching chained audit event')
            scan_bytes += entry.stat(follow_symlinks=False).st_size
            _need(scan_bytes <= limits.max_scan_bytes, 'host record scan byte bound exceeded')
            if record_id in expected:
                _verified_record_at(record_id, None, anchors, directory, limits)
                present.add(record_id)
    _require_record_inventory(anchors, present)


class HostRecordStore:
    """Configured host storage, with explicit test-only location injection."""

    def __init__(self, state_root: Path, *, _test_only: bool = False,
                 worker_writable_roots: tuple[Path, ...] = (), limits: RecordLimits | None = None) -> None:
        self.state_root = Path(state_root)
        self.root = self.state_root / 'records'
        self.audit_file = self.state_root / 'audit.jsonl'
        self.limits = limits or RecordLimits()
        _need(all(type(value) is int and value > 0 for value in vars(self.limits).values()),
              'host record limits must be positive integers')
        _need(self.state_root.is_absolute() and '..' not in self.state_root.parts,
              'host record root must be absolute and canonical')
        if not _test_only:
            _need(self.state_root == HOST_STATE_ROOT, 'production host root must come from workspace configuration')
            self.require_outside_worker_roots((REPO_ROOT,))
        self.require_outside_worker_roots(worker_writable_roots)

    @classmethod
    def from_workspace_config(cls) -> HostRecordStore:
        return cls(HOST_STATE_ROOT)

    @classmethod
    def for_tests(cls, state_root: Path, *, worker_writable_roots: tuple[Path, ...] = (),
                  limits: RecordLimits | None = None) -> HostRecordStore:
        return cls(Path(state_root), _test_only=True, worker_writable_roots=worker_writable_roots, limits=limits)

    def require_outside_worker_roots(self, roots: Any) -> None:
        protected = self.state_root.resolve()
        for raw in roots:
            root = Path(raw).resolve()
            _need(not protected.is_relative_to(root) and not root.is_relative_to(protected),
                  'host records/audit overlap a worker writable root')

    assert_worker_roots_excluded = require_outside_worker_roots

    @contextmanager
    def _state(self, *, create: bool = False) -> Iterator[int]:
        try:
            fd = _directory(self.state_root, create=create, private=True)
            try:
                yield fd
            finally:
                os.close(fd)
        except OSError as exc:
            raise HostRecordError('host state unavailable or unsafe') from exc

    @contextmanager
    def _guarded_state(self, *, create: bool = False) -> Iterator[tuple[int, int]]:
        with self._state(create=create) as fd:
            lock = _audit_lock(fd, create=create, exclusive=create)
            try:
                from .host_record_quarantine import require_no_pending
                require_no_pending(fd)
                if create:
                    from .audit_segments import recover_rotation
                    recover_rotation(fd, self.limits)
                yield fd, lock
            finally:
                os.close(lock)

    def record_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        from .audit import record_audit_event
        with self._state(create=True) as fd:
            return record_audit_event(event, self.audit_file, _directory_fd=fd, _limits=self.limits)

    def audit_events(self) -> list[dict[str, Any]]:
        """Read the same complete verified chain used by record authority."""
        if not self.state_root.exists():
            _need(not self.state_root.is_symlink(), 'host state is a symlink')
            return []
        with self._guarded_state() as (state, _):
            return _audit_snapshot(state, self.limits)

    def require_audit_event(self, event_type: str, **exact_fields: Any) -> dict[str, Any]:
        """Resolve a distinct host pipeline receipt on the same verified chain."""
        _token(event_type)
        with self._guarded_state() as (state, _):
            events = _audit_snapshot(state, self.limits)
            matches = [event for event in events if event.get('event_type') == event_type
                       and all(event.get(key) == value for key, value in exact_fields.items())]
            _need(len(matches) == 1, 'host audit receipt is missing or ambiguous')
            return matches[0]

    def _get(self, record_id: str, record_type: str | None, anchors: set[tuple[Any, Any, Any]], directory: int) -> dict[str, Any]:
        return _verified_record_at(record_id, record_type, anchors, directory, self.limits)

    def get(self, record_id: str, record_type: str | None = None) -> dict[str, Any]:
        _sha(record_id)  # File selection is always by digest, never a path.
        with self._guarded_state() as (state, _):
            events = _audit_snapshot(state, self.limits)
            anchors = self._anchors(events)
            directory = os.open('records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
            try:
                self._check_record_directory(directory)
                return self._get(record_id, record_type, anchors, directory)
            except OSError as exc:
                raise HostRecordError('host record unavailable or unsafe') from exc
            finally:
                os.close(directory)

    @staticmethod
    def _check_record_directory(directory: int) -> None:
        info = os.fstat(directory)
        _need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
              'host record directory must be owner-private')

    def find(self, record_type: str, **exact_fields: Any) -> list[dict[str, Any]]:
        _need(record_type in _TYPES, 'unknown host record type')
        if not self.state_root.exists():
            # This is a read-only absence result; a dangling link still refuses.
            _need(not self.state_root.is_symlink(), 'host state is a symlink')
            return []
        with self._guarded_state() as (state, _):
            events = _audit_snapshot(state, self.limits)
            anchors = self._anchors(events)
            try:
                directory = os.open('records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
            except FileNotFoundError:
                _need(not any(event.get('host_record_sha256') for event in events), 'host record directory missing')
                return []
            try:
                self._check_record_directory(directory)
                from .host_record_inventory import referenced_inventory
                values, _ = referenced_inventory(directory, anchors, self.limits)
                return [value for value in values if value['record_type'] == record_type
                        and all(value.get(key) == item for key, item in exact_fields.items())]
            except OSError as exc:
                raise HostRecordError('host record unavailable or unsafe') from exc
            finally:
                os.close(directory)

    def quarantine_unreferenced(self) -> dict[str, Any]:
        """Explicit local maintenance; never called by a reader or product write.

        A pending transaction is resolved before any new batch is considered.
        Quarantined bytes and their manifest grant no record/effect authority.
        """
        from .host_record_quarantine import quarantine
        return quarantine(self)

    @staticmethod
    def _anchors(events: list[dict[str, Any]]) -> set[tuple[Any, Any, Any]]:
        return {(event.get('host_record_sha256'), event.get('host_record_type'), event.get('event_type'))
                for event in events}

    def require_dispatch(self, dispatch_id: str) -> dict[str, Any]:
        dispatch_id = _token(dispatch_id)
        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in self.find('dispatch'):
            grouped.setdefault(_token(record.get('dispatch_id')), []).append(record)
        selected = {key: _select_dispatch(group) for key, group in grouped.items()}
        _need(dispatch_id in selected, 'host dispatch is missing')
        return selected[dispatch_id]

    def require_return(self, dispatch_id: str, return_sha256: str) -> dict[str, Any]:
        dispatch = self.require_dispatch(dispatch_id)
        digest = _sha(return_sha256)
        records = [record for record in self.find('return-received', dispatch_id=dispatch_id,
                   dispatch_record_sha256=dispatch['_record_sha256'])
                   if digest in (record.get('return_sha256'), record.get('canonical_return_sha256'))]
        if (dispatch['dispatch_role'] == 'peer-review'
                or dispatch.get('evaluation_metadata', {}).get('dispatch_mode') not in (None, 'manual_ui')):
            _need(all(record.get('capture_provenance') == 'host-capture-v1' for record in records),
                  'host return receipt has no verifiable capture provenance')
        _need(len(records) == 1, 'host return receipt is missing or ambiguous')
        return records[0]

    def _record_bytes(self, record_type: str, payload: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
        _need(not any(key in payload for key in ('schema_version', 'record_type', 'created_at', '_record_sha256')),
              'host record envelope cannot be overridden')
        value = {'schema_version': 1, 'record_type': record_type, 'created_at': _now(), **payload}
        raw = _json(value)
        _need(len(raw) <= self.limits.max_record_bytes, 'host record byte bound exceeded')
        return value, raw

    def _write(self, record_type: str, payload: dict[str, Any]) -> str:
        value, raw = self._record_bytes(record_type, payload)
        with self._guarded_state(create=True) as (state, lock):
            return self._write_locked(state, lock, value, raw)

    def _write_locked(self, state: int, lock: int, value: dict[str, Any], raw: bytes) -> str:
        """Append under the caller's existing guarded-state exclusive lock."""
        record_type = value['record_type']
        record_id = hashlib.sha256(raw).hexdigest()
        # Refuse corrupt history before adding a record. Audit append rechecks
        # while holding its shared lock, including normal product events.
        events = _audit_snapshot(state, self.limits)
        anchors = self._anchors(events)
        try:
            os.mkdir('records', 0o700, dir_fd=state)
        except FileExistsError:
            pass
        directory = os.open('records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
        try:
            self._check_record_directory(directory)
            count, scan_bytes, already_exists, matching = self._scan_for_write(
                directory, anchors, record_id, value.get('dispatch_id'))
            if record_type == 'dispatch':
                self._admit_dispatch(value, record_id, matching)
            elif record_type == 'return-received':
                self._admit_receipt(value, matching)
            _need(count + (0 if already_exists else 1) <= self.limits.max_records,
                  'host record count bound exceeded')
            _need(scan_bytes + (0 if already_exists else len(raw)) <= self.limits.max_scan_bytes,
                  'host record scan byte bound exceeded')
            event = {'event_type': 'dispatch_prepared' if record_type == 'dispatch' else 'host_record_written',
                     'host_record_sha256': record_id, 'host_record_type': record_type}
            for key in ('dispatch_id', 'bead_id', 'return_sha256', 'evaluation_sha256'):
                if key in value:
                    event[key] = value[key]
            from .audit import _prepare_private_audit_event
            _prepare_private_audit_event(event, state, self.limits, events)
            self._commit_record(directory, state, lock, record_id, raw, event, already_exists)
        finally:
            os.close(directory)
        return record_id

    def _scan_for_write(self, directory: int, anchors: set[tuple[Any, Any, Any]], record_id: str,
                         dispatch_id: Any) -> tuple[int, int, bool, list[dict[str, Any]]]:
        count = scan_bytes = 0
        already_exists = False
        matching: list[dict[str, Any]] = []
        present: set[str] = set()
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                _need(count <= self.limits.max_records, 'host record count bound exceeded')
                _need(re.fullmatch(r'[0-9a-f]{64}\.json', entry.name) is not None, 'unexpected host record entry')
                scan_bytes += entry.stat(follow_symlinks=False).st_size
                _need(scan_bytes <= self.limits.max_scan_bytes, 'host record scan byte bound exceeded')
                existing = self._get(entry.name[:-5], None, anchors, directory)
                present.add(entry.name[:-5])
                already_exists = already_exists or entry.name == record_id + '.json'
                if existing.get('dispatch_id') == dispatch_id:
                    matching.append(existing)
        _require_record_inventory(anchors, present)
        return count, scan_bytes, already_exists, matching

    @staticmethod
    def _admit_dispatch(value: dict[str, Any], record_id: str, matching: list[dict[str, Any]]) -> None:
        dispatches = [record for record in matching if record['record_type'] == 'dispatch']
        _select_dispatch([*dispatches, {**value, '_record_sha256': record_id}])

    @staticmethod
    def _admit_receipt(value: dict[str, Any], matching: list[dict[str, Any]]) -> None:
        dispatch = _select_dispatch([record for record in matching if record['record_type'] == 'dispatch'])
        _need(value['dispatch_record_sha256'] == dispatch['_record_sha256'],
              'host return receipt does not bind the selected dispatch')
        if (dispatch['dispatch_role'] == 'peer-review'
                or dispatch.get('evaluation_metadata', {}).get('dispatch_mode') not in (None, 'manual_ui')
                or value.get('capture_provenance') == 'host-capture-v1'
                or any(record.get('capture_provenance') == 'host-capture-v1' for record in matching)):
            _need(not any(record['record_type'] == 'return-received'
                          and record.get('dispatch_record_sha256') == value['dispatch_record_sha256']
                          for record in matching), 'host capture already has a return receipt')
        _need(not any(record['record_type'] == 'return-received'
                      and record.get('return_sha256') == value['return_sha256']
                      and record.get('dispatch_record_sha256') == value['dispatch_record_sha256']
                      for record in matching), 'host return receipt is already recorded')

    def _commit_record(self, directory: int, state: int, lock: int, record_id: str, raw: bytes,
                       event: dict[str, Any], already_exists: bool) -> None:
        from .audit import record_audit_event
        try:
            if not already_exists:
                _write_at(directory, record_id + '.json', raw)
            record_audit_event(event, self.audit_file, _directory_fd=state, _limits=self.limits,
                               _lock_fd=lock)
        except BaseException as exc:
            if not already_exists:
                self._remove_unanchored_record(directory, state, record_id, event, exc)
            raise

    def _remove_unanchored_record(self, directory: int, state: int, record_id: str,
                                  event: dict[str, Any], cause: BaseException) -> None:
        try:
            current = _audit_snapshot(state, self.limits)
            anchor = (record_id, event['host_record_type'], event['event_type'])
            if anchor not in self._anchors(current):
                try:
                    os.unlink(record_id + '.json', dir_fd=directory)
                except FileNotFoundError:
                    pass
                os.fsync(directory)
        except BaseException:
            raise HostRecordError('host record write outcome uncertain; cleanup could not be verified, verify before retry') from cause

    def write_dispatch(self, *, dispatch_id: str, dispatch_role: str, provider: str | None,
                       model_family: str | None, model_id: str | None, reasoning_effort: str | None,
                       session_id: str | None, packet_sha256: str | None = None,
                       request_sha256: str | None = None, review_target: dict[str, Any] | None = None,
                       evaluation_metadata: dict[str, Any] | None = None,
                       bead_id: str | None = None, executor: str | None = None,
                       provider_key: str | None = None) -> str:
        _token(dispatch_id)
        _need(dispatch_role in {'executor', 'peer-review'}, 'invalid host dispatch role')
        _need(packet_sha256 is not None or request_sha256 is not None, 'host dispatch requires packet or request digest')
        for digest in (packet_sha256, request_sha256):
            if digest is not None:
                _sha(digest)
        for item in (bead_id, executor, provider_key):
            if item is not None:
                _token(item)
        identity = dict(provider=provider, model_family=model_family, model_id=model_id,
                        reasoning_effort=reasoning_effort, session_id=session_id)
        for item in identity.values():
            if item is not None:
                _token(item)
        if dispatch_role == 'peer-review':
            _need(all(item is not None for item in identity.values()), 'peer-review dispatch identity is incomplete')
            _need(type(review_target) is dict and set(review_target) == {'dispatch_id', 'return_sha256', 'evaluation_sha256'},
                  'peer-review dispatch requires an exact review target')
            _token(review_target['dispatch_id'])
            _sha(review_target['return_sha256'])
            _sha(review_target['evaluation_sha256'])
        else:
            _need(review_target is None, 'executor dispatch cannot claim a review target')
        _metadata(evaluation_metadata if evaluation_metadata is not None else {})
        return self._write('dispatch', dict(dispatch_id=dispatch_id, dispatch_role=dispatch_role, **identity,
            packet_sha256=packet_sha256, request_sha256=request_sha256, review_target=review_target,
            evaluation_metadata=evaluation_metadata or {}, bead_id=bead_id, executor=executor, provider_key=provider_key))

    def write_observed_dispatch(self, dispatch_id: str, *, prepared_record_sha256: str,
                                observation_sha256: str, provider: str, model_family: str, model_id: str,
                                reasoning_effort: str, session_id: str, dispatch_role: str | None = None,
                                bead_id: str | None = None, executor: str | None = None,
                                provider_key: str | None = None, packet_sha256: str | None = None,
                                request_sha256: str | None = None, review_target: dict[str, Any] | None = None,
                                evaluation_metadata: dict[str, Any] | None = None) -> str:
        """Record host-observed completion without replacing its preparation."""
        parent = self.require_dispatch(dispatch_id)
        _sha(prepared_record_sha256)
        fields = {key: value for key, value in parent.items()
                  if key not in {'schema_version', 'record_type', 'created_at', '_record_sha256'}}
        fields.update(stage='observed', prepared_record_sha256=prepared_record_sha256,
                      observation_sha256=_sha(observation_sha256), provider=provider,
                      model_family=model_family, model_id=model_id,
                      reasoning_effort=reasoning_effort, session_id=session_id)
        optional = dict(dispatch_role=dispatch_role, bead_id=bead_id, executor=executor, provider_key=provider_key,
                        packet_sha256=packet_sha256, request_sha256=request_sha256, review_target=review_target)
        fields.update({key: value for key, value in optional.items() if value is not None})
        additions = _metadata(evaluation_metadata if evaluation_metadata is not None else {})
        fields['evaluation_metadata'] = {**_metadata(parent.get('evaluation_metadata', {})), **additions}
        _verify_observed_dispatch(parent, fields)
        return self._write('dispatch', fields)

    def write_return_received(self, dispatch_id: str, return_sha256: str, received_time: str | None = None,
                              *, capture_provenance: str | None = None,
                              canonical_return_sha256: str | None = None) -> str:
        dispatch = self.require_dispatch(dispatch_id)
        _sha(return_sha256)
        if canonical_return_sha256 is not None:
            _sha(canonical_return_sha256)
        return self._write('return-received', dict(capture_provenance=capture_provenance,
            canonical_return_sha256=canonical_return_sha256, dispatch_id=dispatch_id,
            dispatch_record_sha256=dispatch['_record_sha256'], return_sha256=return_sha256,
            received_time=_token(received_time) if received_time is not None else _now()))

    def write_acceptance(self, *, bead_id: str, dispatch_id: str, return_sha256: str,
                         evaluation_sha256: str, database_identity: dict[str, Any],
                         adjudication_result: str, required_holds: list[str],
                         cleared_holds: dict[str, Any], **references: Any) -> str:
        receipt = self.require_return(dispatch_id, return_sha256)
        _token(bead_id)
        _sha(evaluation_sha256)
        _token(adjudication_result)
        _need(type(database_identity) is dict and bool(database_identity), 'acceptance requires database identity')
        _need(type(required_holds) is list and all(type(hold) is str for hold in required_holds)
              and len(set(required_holds)) == len(required_holds), 'acceptance holds must be distinct strings')
        _need(type(cleared_holds) is dict and set(required_holds) == set(cleared_holds),
              'acceptance requires every required hold cleared')
        return self._write('acceptance-decision', dict(bead_id=bead_id, dispatch_id=dispatch_id,
            return_sha256=return_sha256, return_record_sha256=receipt['_record_sha256'],
            evaluation_sha256=evaluation_sha256, database_identity=database_identity,
            adjudication_result=adjudication_result, required_holds=required_holds,
            cleared_holds=cleared_holds, decision_time=_now(), **references))

    def write_record(self, record_type: str, **payload: Any) -> str:
        _need(record_type in {'evaluation', 'adjudication', 'hold-clearance'}, 'use the dedicated host record writer')
        return self._write(record_type, payload)

    @staticmethod
    def _database(database: Path) -> tuple[int, str, dict[str, Any]]:
        database = Path(database)
        _need(database.is_absolute() and '..' not in database.parts, 'database must be an absolute canonical path')
        parent = _directory(database.parent)
        try:
            info = os.stat(database.name, dir_fd=parent, follow_symlinks=False)
            _need((stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                  and info.st_uid == os.getuid() and not info.st_mode & 0o077,
                  'database must be owner-private and cannot be a symlink')
            identity = dict(device=info.st_dev, inode=info.st_ino, owner=info.st_uid,
                            mode=stat.S_IMODE(info.st_mode))
            if stat.S_ISDIR(info.st_mode):
                fd = os.open(database.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                _need(os.fstat(fd).st_ino == info.st_ino and os.fstat(fd).st_dev == info.st_dev,
                      'database identity changed')
                return fd, '.cwo-database-identity.json', identity
            return os.dup(parent), '.' + database.name + '.cwo-database-identity.json', identity
        finally:
            os.close(parent)

    def setup_database_identity(self, database: Path) -> dict[str, Any]:
        """Explicit workspace initialization only; readers never manufacture identity."""
        directory, name, physical = self._database(database)
        try:
            with self._guarded_state(create=True) as (state, lock):
                try:
                    _read_at(directory, name, 4096)
                except FileNotFoundError:
                    identity = {'database_id': uuid.uuid4().hex, **physical}
                    value, raw = self._record_bytes('workspace-database-identity', {
                        'database_identity': identity, 'database_path': str(database)})
                    _write_at(directory, name, _json(identity))
                    self._write_locked(state, lock, value, raw)
                    return identity
        finally:
            os.close(directory)
        return self.require_database_identity(database)

    def workspace_database(self) -> tuple[Path, dict[str, Any]] | None:
        """Trusted initialization selects a database; evidence never supplies it."""
        records = self.find('workspace-database-identity')
        if not records:
            return None
        _need(len(records) == 1,
              'workspace database selection is missing or ambiguous; initialize a fresh workspace')
        database = Path(str(records[0].get('database_path', '')))
        return database, self.require_database_identity(database)

    def require_database_identity(self, database: Path) -> dict[str, Any]:
        try:
            directory, name, physical = self._database(database)
            try:
                identity = _parse(_read_at(directory, name, 4096))
            finally:
                os.close(directory)
            _need(set(identity) == {'database_id', 'device', 'inode', 'owner', 'mode'}
                  and all(identity[key] == value for key, value in physical.items()),
                  'workspace database physical identity mismatch')
            _token(identity['database_id'])
            records = self.find('workspace-database-identity', database_identity=identity)
            _need(len(records) == 1, 'workspace database identity has no unique host record')
            return identity
        except OSError as exc:
            raise HostRecordError('workspace database identity unavailable or unsafe') from exc


def configured_store() -> HostRecordStore:
    return _OVERRIDE.get() or HostRecordStore.from_workspace_config()


@contextmanager
def using_test_store(store: HostRecordStore) -> Iterator[HostRecordStore]:
    """In-process fixture seam; no environment variable or command-line route."""
    token = _OVERRIDE.set(store)
    try:
        yield store
    finally:
        _OVERRIDE.reset(token)
