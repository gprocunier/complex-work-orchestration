"""One bounded audit chain across immutable sealed segments and an active tail.

The checkpoint commits the ordered segment seals. Rotation uses a private
write-ahead journal: a retry proves the old or new checkpoint before recovering.
Readers never repair state or accept an incomplete transaction.
"""
from __future__ import annotations

import base64
import hashlib
import os

from .host_records import HostRecordError, _json, _need, _parse, _read_at, _sha, _write_at

HEAD = 'audit.jsonl.head.json'
JOURNAL = 'audit.rotation.json'
MAX_HEAD_BYTES = 65536


def segment_name(index):
    return 'audit.jsonl' if index == 0 else f'audit.segment-{index:06d}.jsonl'


def read_head(directory):
    try:
        return _read_at(directory, HEAD, MAX_HEAD_BYTES)
    except FileNotFoundError:
        return None


def layout(head):
    if head is None:
        return 0, []
    value = _parse(head)
    seals = value.get('sealed_segments', [])
    index = value.get('active_segment', 0)
    _need(type(seals) is list and type(index) is int and index == len(seals),
          'host audit segment layout is invalid')
    return index, seals


def active(directory, limits, head=None):
    head = read_head(directory) if head is None else head
    index, seals = layout(head)
    try:
        raw = _read_at(directory, segment_name(index), limits.max_audit_bytes)
    except FileNotFoundError:
        _need(head is None, 'host audit log is missing')
        raw = b''
    return head, index, seals, raw


def _events(raw, previous, limits):
    from .audit import audit_event_payload_hash
    _need(not raw or raw.endswith(b'\n'), 'host audit has an incomplete final event')
    events = []
    for line in raw.splitlines():
        _need(len(events) < limits.max_events, 'host audit event bound exceeded')
        event = _parse(line)
        _need(event.get('event_hash') == audit_event_payload_hash(event), 'host audit event digest mismatch')
        _need(event.get('previous_event_hash') == previous, 'host audit chain break')
        previous = event['event_hash']
        events.append(event)
    return events, previous


def _seal(index, raw, events, previous):
    return dict(segment_index=index, byte_count=len(raw), event_count=len(events),
                event_hash=events[-1]['event_hash'], previous_event_hash=previous,
                content_sha256=hashlib.sha256(raw).hexdigest())


def _segment_inventory(directory, index, ignored):
    expected = {segment_name(number) for number in range(1, index + 1)}
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name.startswith('audit.segment-'):
                _need(entry.name in expected or entry.name in ignored,
                      'host audit has an unknown or uncommitted segment')


def _snapshot(directory, limits, *, ignored=()):
    head = read_head(directory)
    _, _, _, raw = active(directory, limits, head)
    return verify_checkpoint(directory, limits, head, raw, ignored=ignored)


def verify_checkpoint(directory, limits, head, raw, *, ignored=()):
    """Verify supplied active bytes against a checkpoint and real sealed history.

    Explicit maintenance recovery uses this before truncating a proven pending
    suffix. Ordinary readers always pass the actual current head and tail.
    """
    index, seals = layout(head)
    _need(index < limits.max_segments, 'host audit segment count bound exceeded')
    _segment_inventory(directory, index, ignored)
    events, previous, total_bytes = [], None, 0
    for number, seal in enumerate(seals):
        sealed_raw = _read_at(directory, segment_name(number), limits.max_audit_bytes)
        current, last = _events(sealed_raw, previous, limits)
        _need(bool(current) and seal == _seal(number, sealed_raw, current, previous),
              'host audit segment seal/content mismatch')
        events.extend(current)
        previous = last
        total_bytes += len(sealed_raw)
        _history_bound(events, total_bytes, limits)
    _need(len(raw) <= limits.max_audit_bytes, 'host audit active byte bound exceeded')
    current, previous = _events(raw, previous, limits)
    events.extend(current)
    total_bytes += len(raw)
    _history_bound(events, total_bytes, limits)
    if head is None:
        _need(not events, 'host audit checkpoint is missing')
        return []
    expected = dict(event_count=len(events), event_hash=previous, byte_count=len(raw))
    if index:
        expected.update(active_segment=index, sealed_segments=seals)
    _need(_parse(head) == expected, 'host audit head mismatch or truncation')
    return events


def _history_bound(events, byte_count, limits):
    _need(len(events) <= limits.max_history_events and byte_count <= limits.max_history_bytes,
          'host audit history bound exceeded')


def audit_snapshot(directory, limits):
    try:
        _read_at(directory, JOURNAL, 2 * limits.max_audit_bytes + MAX_HEAD_BYTES)
    except FileNotFoundError:
        return _snapshot(directory, limits)
    raise HostRecordError('host audit rotation is pending; the next product write must recover it')


def append_plan(directory, limits, raw, prior):
    """Read-only preflight: original bounds are per segment; history stays bounded."""
    head, index, seals, before = active(directory, limits)
    sealed_events = sum(seal['event_count'] for seal in seals)
    rotate = len(before) + len(raw) > limits.max_audit_bytes or len(prior) - sealed_events >= limits.max_events
    _need(len(raw) <= limits.max_audit_bytes, 'host audit event byte bound exceeded')
    _need(index + int(rotate) < limits.max_segments, 'host audit segment count bound exceeded')
    total_bytes = sum(seal['byte_count'] for seal in seals) + len(before) + len(raw)
    _need(len(prior) + 1 <= limits.max_history_events and total_bytes <= limits.max_history_bytes,
          'host audit history bound exceeded')
    return rotate, head, index, seals, before


def append_head(head, *, event_count, event_hash, byte_count):
    value = dict(event_count=event_count, event_hash=event_hash, byte_count=byte_count)
    index, seals = layout(head)
    if index:
        value.update(active_segment=index, sealed_segments=seals)
    return value


def _journal_bytes(previous, next_head, raw):
    return _json(dict(previous_head=base64.b64encode(previous).decode('ascii'), next_head=next_head,
                      event_bytes=base64.b64encode(raw).decode('ascii')))


def _rotation_pending(directory, limits):
    value = _parse(_read_at(directory, JOURNAL, 2 * limits.max_audit_bytes + MAX_HEAD_BYTES))
    required = {'previous_head', 'next_head', 'event_bytes'}
    _need(set(value) in (required, required | {'rollback_ready'})
          and value.get('rollback_ready', True) is True, 'host rotation journal shape is invalid')
    try:
        previous = base64.b64decode(value['previous_head'], validate=True)
        raw = base64.b64decode(value['event_bytes'], validate=True)
    except (TypeError, ValueError) as failure:
        raise HostRecordError('host rotation journal encoding is invalid') from failure
    _need(len(previous) <= MAX_HEAD_BYTES and len(raw) <= limits.max_audit_bytes,
          'host rotation journal exceeds bounds')
    index, seals = layout(previous)
    next_index, next_seals = layout(_json(value['next_head']))
    _need(next_index == index + 1 and next_seals[:-1] == seals,
          'host rotation journal does not extend the old checkpoint')
    events, last = _events(raw, _parse(previous)['event_hash'], limits)
    next_head = value['next_head']
    _need(len(events) == 1 and next_head.get('event_hash') == last
          and next_head.get('byte_count') == len(raw)
          and next_head.get('event_count') == _parse(previous)['event_count'] + 1,
          'host rotation journal event/checkpoint binding mismatch')
    return previous, next_head, raw, next_index, value.get('rollback_ready', False)


def _pending_record(directory, event, prior, limits, *, remove=False, allow_missing=False):
    record_id = event.get('host_record_sha256')
    if record_id is None or any(row.get('host_record_sha256') == record_id for row in prior):
        return
    _sha(record_id)
    records = os.open('records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        from .host_records import HostRecordStore
        HostRecordStore._check_record_directory(records)
        try:
            raw = _read_at(records, record_id + '.json', limits.max_record_bytes)
        except FileNotFoundError:
            if not allow_missing:
                raise
            return
        _need(hashlib.sha256(raw).hexdigest() == record_id, 'uncommitted rotation record changed')
        if remove:
            os.unlink(record_id + '.json', dir_fd=records)
            os.fsync(records)
    finally:
        os.close(records)


def recover_rotation(directory, limits, *, allow_unreferenced=False):
    """Exclusive writers recover only a proven old/new transaction; never guess."""
    try:
        previous, next_head, raw, index, rollback_ready = _rotation_pending(directory, limits)
    except FileNotFoundError:
        return
    current = read_head(directory)
    from .host_records import verify_recovery_records
    if current == _json(next_head):
        events = _snapshot(directory, limits)
        verify_recovery_records(directory, events, limits, allow_unreferenced=allow_unreferenced)
    else:
        _need(current == previous, 'host audit rotation checkpoint outcome is uncertain')
        name = segment_name(index)
        prior = _snapshot(directory, limits, ignored=(name,))
        event = _parse(raw)
        verify_recovery_records(directory, prior, limits, event, allow_unreferenced=allow_unreferenced)
        try:
            pending = _read_at(directory, name, limits.max_audit_bytes)
        except FileNotFoundError:
            pending = None
        if pending is not None:
            _need(raw.startswith(pending), 'uncommitted host audit segment bytes changed')
        _pending_record(directory, event, prior, limits, allow_missing=rollback_ready)
        if not rollback_ready:
            marker = _parse(_journal_bytes(previous, next_head, raw))
            marker['rollback_ready'] = True
            _write_at(directory, JOURNAL, _json(marker), replace=True)
        _pending_record(directory, event, prior, limits, remove=True, allow_missing=True)
        if pending is not None:
            os.unlink(name, dir_fd=directory)
    os.unlink(JOURNAL, dir_fd=directory)
    os.fsync(directory)
    _snapshot(directory, limits)


def commit_rotation(directory, limits, enriched, raw, prior):
    _, head, index, seals, before = append_plan(directory, limits, raw, prior)
    previous = seals[-1]['event_hash'] if seals else None
    segment, _ = _events(before, previous, limits)
    next_seals = [*seals, _seal(index, before, segment, previous)]
    next_head = dict(event_count=len(prior) + 1, event_hash=enriched['event_hash'],
                     byte_count=len(raw), active_segment=index + 1, sealed_segments=next_seals)
    _need(len(_json(next_head)) <= MAX_HEAD_BYTES, 'host audit checkpoint byte bound exceeded')
    _write_at(directory, JOURNAL, _journal_bytes(head, next_head, raw), atomic_create=True)
    try:
        _write_at(directory, segment_name(index + 1), raw)
        _write_at(directory, HEAD, _json(next_head), replace=True)
    except BaseException as failure:
        try:
            committed = read_head(directory) == _json(next_head)
            recover_rotation(directory, limits)
        except BaseException as recovery:
            raise HostRecordError('host audit rotation outcome uncertain; evidence preserved') from recovery
        if committed:
            raise HostRecordError('host audit rotation committed; confirmation interrupted') from failure
        raise
    recover_rotation(directory, limits)
    return enriched
