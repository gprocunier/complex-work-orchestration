"""Explicit bounded orphan maintenance; stored bytes never acquire authority.

The existing audit lock serializes cooperating host writers. This is integrity
protection, not authentication against a same-user process rewriting the store.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import uuid

from . import host_records as h
from .host_record_inventory import referenced_inventory

PENDING = 'records.quarantine.json'
ROOT = 'quarantine'
EVENT = 'host_records_quarantined'
_REFERENCES = {
    'prepared_record_sha256': 'dispatch', 'dispatch_record_sha256': 'dispatch',
    'return_record_sha256': 'return-received', 'evaluation_record': 'evaluation',
    'adjudication_record': 'adjudication', 'acceptance_record_sha256': 'acceptance-decision',
    'adjudication_record_sha256': 'adjudication',
}


def require_no_pending(state):
    try:
        os.stat(PENDING, dir_fd=state, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise h.HostRecordError('host record quarantine is pending; explicit maintenance recovery is required')


@contextmanager
def _directory(parent, name, *, create=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        h.HostRecordStore._check_record_directory(fd)
        yield fd
    finally:
        os.close(fd)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _reference(record_id, kind, values):
    h._sha(record_id)
    h._need(record_id in values and values[record_id]['record_type'] == kind,
            'quarantine inventory has a missing or unanchored typed reference')


def _verify_references(events, records):
    values = {value['_record_sha256']: value for value in records}
    for value in [*events, *records]:
        for key, kind in _REFERENCES.items():
            if key in value:
                _reference(value[key], kind, values)
        if 'host_record_sha256' in value:
            _reference(value['host_record_sha256'], value.get('host_record_type'), values)
        if value.get('record_type') == 'acceptance-decision':
            clearances = value.get('cleared_holds')
            h._need(type(clearances) is dict, 'quarantine acceptance references are malformed')
            for record_id in clearances.values():
                _reference(record_id, 'hold-clearance', values)
        _nested_references(value, values)


def _separation_references(separation, values):
    if separation is None:
        return
    h._need(type(separation) is dict, 'quarantine peer separation is malformed')
    for name in ('executor_dispatch_sha256', 'reviewer_dispatch_sha256'):
        _reference(separation.get(name), 'dispatch', values)


def _nested_references(record, values):
    if record.get('record_type') == 'hold-clearance' or record.get('event_type') == 'return_evaluated':
        _separation_references(record.get('peer_review_separation'), values)
    if record.get('record_type') == 'evaluation':
        for name in ('evaluation', 'pending_evaluation'):
            snapshot = record.get(name)
            if snapshot is not None:
                h._need(type(snapshot) is dict, 'quarantine evaluation snapshot is malformed')
                _separation_references(snapshot.get('peer_review_separation'), values)


def _inventory(state, directory, limits, events):
    values, strays = referenced_inventory(directory, h.HostRecordStore._anchors(events), limits)
    _verify_references(events, values)
    return strays


def _candidate_manual_step(info):
    if stat.S_ISLNK(info.st_mode):
        return 'preserve the link target as needed, then manually remove only this unreferenced symlink and retry maintenance'
    if stat.S_ISDIR(info.st_mode):
        return 'preserve this unreferenced directory outside records/, then manually remove its entry and retry maintenance'
    if stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) != 0o600:
        return 'preserve this unreferenced file, restore its owner-private mode 0600, then retry maintenance'
    return 'preserve this unsupported unreferenced entry outside records/, manually remove its entry, then retry maintenance'


def _read_candidate(directory, name, info, limits):
    try:
        return h._read_at(directory, name, limits.max_record_bytes)
    except (h.HostRecordError, OSError) as failure:
        raise h.HostRecordError(f'unexpected host record entry {name!r}: {failure}; manual step: '
                               + _candidate_manual_step(info)) from failure


def _candidate(directory, name, info, index, limits):
    h._token(name)
    h._need(name not in ('.', '..') and '/' not in name and '\x00' not in name,
            'quarantine source is not a single component')
    raw = _read_candidate(directory, name, info, limits)
    h._need(h._identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == h._identity(info),
            'quarantine source changed during preflight')
    return {'name': name, 'destination': f'item-{index:06d}',
            'identity': list(h._identity(info)), 'sha256': _digest(raw)}


def _plan(state, directory, strays, limits):
    from .audit_segments import active
    head, _, _, before = active(state, limits)
    manifest = {'schema_version': 1, 'transaction': uuid.uuid4().hex,
                'previous_head': base64.b64encode(head).decode() if head is not None else None,
                'audit_before_bytes': len(before), 'audit_before_sha256': _digest(before),
                'files': [_candidate(directory, name, info, index, limits)
                          for index, (name, info) in enumerate(sorted(strays))]}
    raw = h._json(manifest)
    h._need(len(raw) <= limits.max_record_bytes, 'quarantine manifest byte bound exceeded')
    return manifest, raw


def _event(state, manifest, raw, limits, events):
    from .audit import _prepare_private_audit_event
    event = {'event_type': EVENT, 'quarantine_transaction_id': manifest['transaction'],
             'quarantine_manifest_sha256': _digest(raw), 'quarantine_file_count': len(manifest['files'])}
    enriched, _ = _prepare_private_audit_event(event, state, limits, events)
    return enriched


def _journal(manifest, raw, event):
    return {'schema_version': 1, 'transaction': manifest['transaction'],
            'manifest_sha256': _digest(raw), 'phase': 'moving', 'event': event}


def _write_journal(state, journal, limits, *, replace=False, atomic_create=False):
    raw = h._json(journal)
    h._need(len(raw) <= limits.max_record_bytes, 'quarantine journal byte bound exceeded')
    h._write_at(state, PENDING, raw, replace=replace, atomic_create=atomic_create)


def _read_optional(directory, name, maximum):
    try:
        return h._read_at(directory, name, maximum)
    except FileNotFoundError:
        return None


def _source(directory, entry, limits, *, restoring=False):
    raw = _read_optional(directory, entry['name'], limits.max_record_bytes)
    if raw is not None:
        info = os.stat(entry['name'], dir_fd=directory, follow_symlinks=False)
        h._need(restoring or list(h._identity(info)) == entry['identity'],
                'quarantine source identity changed')
        h._need(restoring or _digest(raw) == entry['sha256'], 'quarantine source bytes changed')
    return raw


def _read_descriptor(fd, maximum):
    chunks, remaining = [], maximum + 1
    while remaining:
        chunk = os.read(fd, min(remaining, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _open_verified_file(directory, name, expected, maximum, *, writable=False):
    flags = os.O_RDWR | os.O_APPEND if writable else os.O_RDONLY
    fd = os.open(name, flags | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = os.fstat(fd)
        h._need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'quarantine recovery file must be private, regular and single-link')
        h._need(info.st_size == len(expected) and len(expected) <= maximum,
                'quarantine recovery byte bound differs')
        h._need(_read_descriptor(fd, maximum) == expected
                and h._identity(os.fstat(fd)) == h._identity(info)
                and h._identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == h._identity(info),
                'quarantine recovery file changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _move(directory, files, entry, limits):
    raw = _source(directory, entry, limits)
    h._need(raw is not None, 'quarantine source disappeared before movement')
    fd = _open_verified_file(directory, entry['name'], raw, limits.max_record_bytes)
    try:
        h._need(list(h._identity(os.fstat(fd))) == entry['identity'], 'quarantine source identity changed')
        h._write_at(files, entry['destination'], raw)
        h._need(h._read_at(files, entry['destination'], limits.max_record_bytes) == raw,
                'quarantine destination differs from source')
        h._need(list(h._identity(os.fstat(fd))) == entry['identity']
                and _source(directory, entry, limits) == raw, 'quarantine source changed before unlink')
        os.unlink(entry['name'], dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(fd)


def _check_entry(directory, files, entry, limits, restoring):
    source = _source(directory, entry, limits, restoring=restoring)
    destination = _read_optional(files, entry['destination'], limits.max_record_bytes)
    h._need(source is not None or destination is not None, 'quarantine transaction lost both copies')
    if source is None:
        h._need(_digest(destination) == entry['sha256'], 'quarantine moved bytes changed')
    elif _digest(source) == entry['sha256']:
        h._need(destination is None or source.startswith(destination), 'quarantine pending copy has unknown bytes')
    else:
        h._need(restoring and destination is not None and _digest(destination) == entry['sha256']
                and destination.startswith(source), 'quarantine restore has unknown bytes')
    return source is None


def _check_copies(directory, files, manifest, journal, limits):
    moved = [_check_entry(directory, files, entry, limits, journal['phase'] == 'restoring')
             for entry in manifest['files']]
    if journal['phase'] == 'appending':
        h._need(all(moved), 'quarantine audit phase still has unmoved sources')
    return all(moved)


def _validate_manifest(manifest, journal, limits):
    expected = {'schema_version', 'transaction', 'previous_head', 'audit_before_bytes',
                'audit_before_sha256', 'files'}
    h._need(set(manifest) == expected and type(manifest['schema_version']) is int
            and manifest['schema_version'] == 1,
            'quarantine manifest shape is invalid')
    h._need(manifest['transaction'] == journal['transaction'], 'quarantine transaction binding differs')
    entries = manifest['files']
    h._need(type(entries) is list and 0 < len(entries) <= limits.max_records,
            'quarantine manifest record bound exceeded')
    names = [_validate_entry(entry, index, limits) for index, entry in enumerate(entries)]
    h._need(len(names) == len(set(names)), 'quarantine manifest repeats a source')
    h._need(sum(entry['identity'][4] for entry in entries) <= limits.max_scan_bytes,
            'quarantine manifest scan byte bound exceeded')


def _validate_entry(entry, index, limits):
    h._need(type(entry) is dict and set(entry) == {'name', 'destination', 'identity', 'sha256'},
            'quarantine entry shape is invalid')
    name = h._token(entry['name'])
    h._need(name not in ('.', '..') and '/' not in name and '\x00' not in name,
            'quarantine source is not a single component')
    h._need(entry['destination'] == f'item-{index:06d}', 'quarantine destination is invalid')
    identity = entry['identity']
    h._need(type(identity) is list and len(identity) == 8 and all(type(v) is int for v in identity),
            'quarantine source identity is invalid')
    h._need(0 <= identity[4] <= limits.max_record_bytes, 'quarantine record byte bound exceeded')
    h._sha(entry['sha256'])
    return name


def _validate_journal(journal):
    from .audit import audit_event_payload_hash
    h._need(set(journal) == {'schema_version', 'transaction', 'manifest_sha256', 'phase', 'event'}
            and type(journal['schema_version']) is int and journal['schema_version'] == 1,
            'quarantine journal shape is invalid')
    h._need(type(journal['transaction']) is str and re.fullmatch('[0-9a-f]{32}', journal['transaction']),
            'quarantine transaction name is invalid')
    h._need(journal['phase'] in ('moving', 'appending', 'restoring'), 'quarantine phase is invalid')
    h._sha(journal['manifest_sha256'])
    event = journal['event']
    h._need(type(event) is dict and event.get('event_type') == EVENT
            and event.get('quarantine_transaction_id') == journal['transaction']
            and event.get('quarantine_manifest_sha256') == journal['manifest_sha256']
            and event.get('event_hash') == audit_event_payload_hash(event),
            'quarantine completion event binding differs')
    h._need(not any(key in event for key in ('host_record_sha256', 'host_record_type',
                'acceptance_record_sha256', 'adjudication_record_sha256')),
            'quarantine completion cannot be an authority record')


def _old_head(manifest):
    from .audit_segments import MAX_HEAD_BYTES
    value = manifest['previous_head']
    if value is None:
        return None
    try:
        head = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise h.HostRecordError('quarantine checkpoint encoding is invalid') from error
    h._need(len(head) <= MAX_HEAD_BYTES, 'quarantine checkpoint byte bound exceeded')
    return head


def _old_checkpoint(state, directory, manifest, limits, *, ignored=()):
    from . import audit_segments as segments
    head = _old_head(manifest)
    _, _, _, current = segments.active(state, limits, head)
    size = manifest['audit_before_bytes']
    h._need(type(size) is int and 0 <= size <= len(current), 'quarantine old audit length differs')
    before = current[:size]
    h._need(_digest(before) == manifest['audit_before_sha256'], 'quarantine old audit prefix differs')
    events = segments.verify_checkpoint(state, limits, head, before, ignored=ignored)
    _inventory(state, directory, limits, events)
    return head, before, current


def _recover_rotation(state, directory, manifest, journal, limits, moved):
    from . import audit_segments as segments
    if _read_optional(state, segments.JOURNAL, 2 * limits.max_audit_bytes + segments.MAX_HEAD_BYTES) is None:
        return
    previous, _, raw, index, _ = segments._rotation_pending(state, limits)
    h._need(journal['phase'] == 'appending' and moved and previous == _old_head(manifest)
            and h._parse(raw) == journal['event'], 'quarantine rotation is not its planned event')
    _old_checkpoint(state, directory, manifest, limits, ignored=(segments.segment_name(index),))
    segments.recover_rotation(state, limits)


def _restore_tail(state, head, before, current, journal, limits):
    from .audit import _restore_private_audit, _verify_uncommitted_append
    from .audit_segments import layout, read_head, segment_name
    if journal['phase'] != 'appending':
        h._need(current == before, 'quarantine has an unexplained audit suffix')
    name = segment_name(layout(head)[0])
    if _read_optional(state, name, limits.max_audit_bytes) is None:
        h._need(head is None and read_head(state) is None and before == current == b'',
                'quarantine old audit disappeared')
        return
    _verify_uncommitted_append(state, before if head is not None else None, head,
                              (json.dumps(journal['event'], sort_keys=True) + '\n').encode(), limits)
    fd = _open_verified_file(state, name, current, limits.max_audit_bytes, writable=True)
    try:
        _restore_private_audit(state, fd, before if head is not None else None, head, limits)
    finally:
        os.close(fd)


def _terminal(state, transaction, manifest, journal, status, limits):
    result = {'status': status, 'transaction': manifest['transaction'],
              'manifest_sha256': journal['manifest_sha256'], 'count': len(manifest['files'])}
    raw = h._json(result)
    existing = _read_optional(transaction, 'outcome.json', len(raw))
    if existing is None:
        h._write_at(transaction, 'outcome.json', raw)
    elif existing != raw:
        _complete_restore(transaction, 'outcome.json', existing, raw)
    current = _read_optional(state, PENDING, limits.max_record_bytes)
    if current is not None:
        value = h._parse(current)
        h._need(value['transaction'] == journal['transaction']
                and value['manifest_sha256'] == journal['manifest_sha256'], 'quarantine pending owner differs')
        os.unlink(PENDING, dir_fd=state)
    os.fsync(state)
    return result


def _restore_sources(directory, files, manifest, limits):
    for entry in manifest['files']:
        source = _source(directory, entry, limits, restoring=True)
        if source is not None and _digest(source) == entry['sha256']:
            _sync_restored(directory, entry, limits)
            continue
        raw = h._read_at(files, entry['destination'], limits.max_record_bytes)
        h._need(_digest(raw) == entry['sha256'], 'quarantine rollback bytes changed')
        if source is None:
            h._write_at(directory, entry['name'], raw)
        else:
            _complete_restore(directory, entry['name'], source, raw)
        _sync_restored(directory, entry, limits)
    os.fsync(directory)


def _sync_restored(directory, entry, limits):
    raw = h._read_at(directory, entry['name'], limits.max_record_bytes)
    h._need(_digest(raw) == entry['sha256'], 'quarantine restored source differs')
    fd = _open_verified_file(directory, entry['name'], raw, limits.max_record_bytes)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _complete_restore(directory, name, prefix, raw):
    h._need(raw.startswith(prefix), 'quarantine restore prefix differs')
    fd = _open_verified_file(directory, name, prefix, len(raw), writable=True)
    try:
        view = memoryview(raw)[len(prefix):]
        while view:
            count = os.write(fd, view)
            h._need(count > 0, 'quarantine restore did not progress')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    h._need(h._read_at(directory, name, len(raw)) == raw, 'quarantine restored bytes differ')


def _recover_open(state, directory, transaction, files, manifest, journal, limits):
    from . import audit_segments as segments
    moved = _check_copies(directory, files, manifest, journal, limits)
    _recover_rotation(state, directory, manifest, journal, limits, moved)
    if segments.read_head(state) != _old_head(manifest):
        events = h._audit_snapshot(state, limits)
        _inventory(state, directory, limits, events)
        h._need(journal['phase'] == 'appending' and moved and events
                and events[-1] == journal['event'], 'quarantine audit outcome is uncertain')
        return _terminal(state, transaction, manifest, journal, 'quarantined', limits)
    head, before, current = _old_checkpoint(state, directory, manifest, limits)
    _restore_tail(state, head, before, current, journal, limits)
    journal = {**journal, 'phase': 'restoring'}
    _write_journal(state, journal, limits, replace=True)
    _restore_sources(directory, files, manifest, limits)
    return _terminal(state, transaction, manifest, journal, 'rolled-back', limits)


def _recover(state, directory, limits, fallback=None):
    pending = _read_optional(state, PENDING, limits.max_record_bytes)
    h._need(pending is not None or fallback is not None, 'quarantine journal disappeared')
    journal = h._parse(pending) if pending is not None else fallback
    _validate_journal(journal)
    with _directory(state, ROOT) as root, _directory(root, 'tx-' + journal['transaction']) as transaction:
        raw = h._read_at(transaction, 'manifest.json', limits.max_record_bytes)
        h._need(_digest(raw) == journal['manifest_sha256'], 'quarantine manifest digest differs')
        manifest = h._parse(raw)
        _validate_manifest(manifest, journal, limits)
        h._need(type(journal['event']['quarantine_file_count']) is int
                and journal['event']['quarantine_file_count'] == len(manifest['files']),
                'quarantine completion count differs')
        with _directory(transaction, 'files') as files:
            return _recover_open(state, directory, transaction, files, manifest, journal, limits)


def _begin_open(state, directory, transaction, manifest, raw, event, limits):
    from .audit import _append_private_audit
    h._write_at(transaction, 'manifest.json', raw)
    journal = _journal(manifest, raw, event)
    # The empty destination directory is durable before the pending marker.
    with _directory(transaction, 'files', create=True):
        pass
    try:
        _write_journal(state, journal, limits, atomic_create=True)
        with _directory(transaction, 'files', create=True) as files:
            for entry in manifest['files']:
                _move(directory, files, entry, limits)
            journal = {**journal, 'phase': 'appending'}
            _write_journal(state, journal, limits, replace=True)
            _append_private_audit(event, state, limits)
            return _terminal(state, transaction, manifest, journal, 'quarantined', limits)
    except BaseException as primary:
        try:
            outcome = _recover(state, directory, limits, journal)
        except BaseException as recovery:
            primary.add_note('Quarantine recovery refused: ' + repr(recovery))
            raise h.HostRecordError('quarantine outcome uncertain; evidence preserved') from primary
        if outcome['status'] == 'quarantined':
            raise h.HostRecordError('quarantine committed; confirmation interrupted') from primary
        raise


def _begin(state, directory, limits):
    from .audit_segments import recover_rotation
    # This entry point holds the configured store's EX audit lock throughout
    # recovery, planning, moves and commit. Normal writers remain strict.
    recover_rotation(state, limits, allow_unreferenced=True)
    events = h._audit_snapshot(state, limits)
    strays = _inventory(state, directory, limits, events)
    if not strays:
        return {'status': 'unchanged', 'count': 0}
    manifest, raw = _plan(state, directory, strays, limits)
    event = _event(state, manifest, raw, limits, events)
    # The journal also fits before any store/quarantine mutation.
    journal = _journal(manifest, raw, event)
    h._need(all(len(h._json({**journal, 'phase': phase})) <= limits.max_record_bytes
                for phase in ('moving', 'appending', 'restoring')),
            'quarantine journal byte bound exceeded')
    with _directory(state, ROOT, create=True) as root:
        name = 'tx-' + manifest['transaction']
        os.mkdir(name, 0o700, dir_fd=root)  # Exclusive, never reuse a transaction.
        os.fsync(root)
        with _directory(root, name) as transaction:
            return _begin_open(state, directory, transaction, manifest, raw, event, limits)


def quarantine(store):
    """Configured-store maintenance or recovery, using one existing EX lock."""
    with store._state() as state:
        lock = h._audit_lock(state, create=False, exclusive=True)
        try:
            with _directory(state, 'records') as directory:
                if _read_optional(state, PENDING, store.limits.max_record_bytes) is not None:
                    return _recover(state, directory, store.limits)
                return _begin(state, directory, store.limits)
        finally:
            os.close(lock)
