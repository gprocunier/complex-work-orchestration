"""P0 store checks: each test names a refusal or an authoritative binding."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import fcntl
import stat
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cwo_core import audit, host_records as records, paths  # noqa: E402


import shutil

class HostRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store = records.HostRecordStore.for_tests(self.base / 'host')
        self.digest = hashlib.sha256(b'return').hexdigest()

    def dispatch(self, store=None, dispatch_id='executor', **changes):
        args = dict(dispatch_id=dispatch_id, dispatch_role='executor', provider='openai',
                    model_family='gpt-6', model_id='gpt-6.1-sol', reasoning_effort='xhigh',
                    session_id='thread-1', request_sha256='a' * 64,
                    bead_id='cwor-test', executor='codex-sol', provider_key='openai')
        args.update(changes)
        return (store or self.store).write_dispatch(**args)

    def observed(self, store=None, **changes):
        store = store or self.store
        parent = store.require_dispatch('executor')
        args = dict(prepared_record_sha256=parent['_record_sha256'], observation_sha256='e' * 64,
                    provider='openai', model_family='gpt-6', model_id='gpt-6.1-sol',
                    reasoning_effort='xhigh', session_id='thread-1')
        args.update(changes)
        return store.write_observed_dispatch('executor', **args)

    def observed_raw(self, parent, **changes):
        value = {key: item for key, item in parent.items() if key != '_record_sha256'}
        value.update(stage='observed', prepared_record_sha256=parent['_record_sha256'],
                     observation_sha256='e' * 64, provider='openai', model_family='gpt-6',
                     model_id='gpt-6.1-sol', reasoning_effort='xhigh', session_id='thread-1')
        value.update(changes)
        return self.raw(value)

    def raw(self, value):
        return records._json(value)

    def put(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def anchored_raw(self, store, raw, record_type):
        digest = hashlib.sha256(raw).hexdigest()
        self.put(store.root / (digest + '.json'), raw)
        store.record_audit_event(dict(event_type='dispatch_prepared' if record_type == 'dispatch' else 'host_record_written',
                                     host_record_sha256=digest, host_record_type=record_type))
        return digest

    def acceptance(self, **changes):
        args = dict(bead_id='cwor-test', dispatch_id='executor', return_sha256=self.digest,
                    evaluation_sha256='b' * 64, database_identity={'database_id': 'registered'},
                    adjudication_result='accepted', required_holds=['review'],
                    cleared_holds={'review': {'evidence_record_sha256': 'c' * 64}})
        args.update(changes)
        return self.store.write_acceptance(**args)


    def test_check_missing_reader_is_zero_write_and_env_cannot_select_authority(self):
        self.assertEqual(self.store.find('dispatch'), [])
        with self.assertRaises(records.HostRecordError):
            self.store.get('a' * 64)
        self.assertFalse(self.store.state_root.exists())
        with patch.dict(os.environ, {'CWO_AUDIT_FILE': str(self.base / 'forged.jsonl'),
                                    'CWO_HOST_STATE_ROOT': str(self.base / 'forged')}):
            actual = records.HostRecordStore.from_workspace_config()
        self.assertEqual(actual.state_root, paths.HOST_STATE_ROOT)
        self.assertEqual(actual.audit_file, paths.HOST_AUDIT_LOG)
        with self.assertRaises(records.HostRecordError):
            records.HostRecordStore(self.base / 'caller')
        with self.assertRaises(records.HostRecordError):
            records.HostRecordStore.for_tests(Path('relative'))

    def test_check_single_component_digest_lookup_and_record_type(self):
        dispatch = self.dispatch()
        for value in ('../' + dispatch, str(self.store.root / (dispatch + '.json')), 'x', None):
            with self.subTest(value=value), self.assertRaises(records.HostRecordError):
                self.store.get(value)
        with self.assertRaises(records.HostRecordError):
            self.store.get(dispatch, 'return-received')
        with self.assertRaises(records.HostRecordError):
            self.store.find('caller-type')
        (self.store.root / (dispatch + '.json')).unlink()
        with self.assertRaises(records.HostRecordError):
            self.store.get(dispatch)

    def test_check_worker_binding_lists_exclude_state_store_and_audit(self):
        self.store.assert_worker_roots_excluded((self.base / 'worker', self.base / 'worker-home-spool'))
        for root in (self.base, self.store.state_root, self.store.root, self.store.audit_file):
            with self.subTest(root=root), self.assertRaises(records.HostRecordError):
                self.store.assert_worker_roots_excluded((root,))
        with self.assertRaises(records.HostRecordError):
            records.HostRecordStore.for_tests(self.base / 'worker' / 'host', worker_writable_roots=(self.base / 'worker',))
        self.assertFalse(self.store.state_root.exists())

    def test_check_digest_mismatch_and_unchained_caller_record_refuse(self):
        dispatch = self.dispatch()
        path = self.store.root / (dispatch + '.json')
        original = path.read_bytes()
        self.put(path, original.replace(b'thread-1', b'thread-2'))
        with self.assertRaisesRegex(records.HostRecordError, 'digest mismatch'):
            self.store.get(dispatch)
        self.put(path, original)
        forged = self.raw({'schema_version': 1, 'record_type': 'dispatch', 'created_at': 'now', 'dispatch_id': 'forged'})
        forged_id = hashlib.sha256(forged).hexdigest()
        self.put(self.store.root / (forged_id + '.json'), forged)
        with self.assertRaisesRegex(records.HostRecordError, 'matching chained'):
            self.store.get(forged_id)
        self.assertEqual(self.store.find('dispatch'), [self.store.get(dispatch)])

    def test_check_audit_digest_link_current_head_truncation_and_missing_event_refuse(self):
        for fault in ('event-digest', 'chain-link', 'truncated', 'incomplete', 'missing-log', 'missing-head', 'missing-event'):
            with self.subTest(fault=fault):
                store = records.HostRecordStore.for_tests(self.base / fault)
                first = self.dispatch(store=store)
                store.record_audit_event({'event_type': 'tail'})
                events = audit.iter_audit_events(store.audit_file)
                if fault == 'event-digest':
                    events[1]['event_type'] = 'forged'
                elif fault == 'chain-link':
                    events[1]['previous_event_hash'] = '0' * 64
                    events[1]['event_hash'] = audit.audit_event_payload_hash(events[1])
                elif fault == 'truncated':
                    events.pop()
                elif fault == 'missing-event':
                    events[0].pop('host_record_sha256')
                    events[0]['event_hash'] = audit.audit_event_payload_hash(events[0])
                    events[1]['previous_event_hash'] = events[0]['event_hash']
                    events[1]['event_hash'] = audit.audit_event_payload_hash(events[1])
                if fault in ('event-digest', 'chain-link'):
                    data = b''.join((json.dumps(e, sort_keys=True) + '\n').encode() for e in events)
                    self.put(store.state_root / 'audit.jsonl.head.json', self.raw(dict(event_count=len(events),
                        event_hash=events[-1]['event_hash'], byte_count=len(data))))
                if fault == 'missing-log':
                    store.audit_file.unlink()
                elif fault == 'missing-head':
                    (store.state_root / 'audit.jsonl.head.json').unlink()
                elif fault == 'incomplete':
                    data = store.audit_file.read_bytes()[:-1]
                    self.put(store.audit_file, data)
                    self.put(store.state_root / 'audit.jsonl.head.json', self.raw(dict(event_count=len(events),
                        event_hash=events[-1]['event_hash'], byte_count=len(data))))
                else:
                    data = b''.join((json.dumps(e, sort_keys=True) + '\n').encode() for e in events)
                    self.put(store.audit_file, data)
                    if fault == 'missing-event':
                        self.put(store.state_root / 'audit.jsonl.head.json', self.raw(dict(event_count=len(events),
                            event_hash=events[-1]['event_hash'], byte_count=len(data))))
                with self.assertRaises(records.HostRecordError):
                    store.get(first)
                before = {p: p.read_bytes() for p in store.state_root.rglob('*') if p.is_file()}
                with self.assertRaises(records.HostRecordError):
                    store.write_record('evaluation', score=1)
                self.assertEqual(before, {p: p.read_bytes() for p in store.state_root.rglob('*') if p.is_file()})

    def test_check_record_schema_malformed_json_and_unexpected_entry_refuse(self):
        for raw in (b'[]', b'{', b'{"a":1,"a":2}', b'{"a":NaN}', self.raw({'schema_version': 2, 'record_type': 'dispatch'}),
                    self.raw({'schema_version': True, 'record_type': 'dispatch'}),
                    self.raw({'schema_version': 1.0, 'record_type': 'dispatch'})):
            with self.subTest(raw=raw):
                store = records.HostRecordStore.for_tests(self.base / hashlib.sha256(raw).hexdigest())
                self.dispatch(store=store)
                digest = hashlib.sha256(raw).hexdigest()
                self.anchored_raw(store, raw, 'dispatch')
                with self.assertRaises(records.HostRecordError):
                    store.get(digest)
        store = records.HostRecordStore.for_tests(self.base / 'duplicate-json-key')
        self.dispatch(store=store)
        raw = b'{"schema_version":1,"record_type":"dispatch","dispatch_id":"one","dispatch_id":"two"}'
        digest = self.anchored_raw(store, raw, 'dispatch')
        with self.assertRaises(records.HostRecordError):
            store.get(digest)
        (self.store.root).mkdir(parents=True, mode=0o700)
        self.store.state_root.chmod(0o700)
        self.store.record_audit_event({'event_type': 'empty'})
        dispatch = self.dispatch()
        self.put(self.store.root / (dispatch + '.text'), b'{}')
        self.assertEqual(self.store.find('dispatch'), [self.store.get(dispatch)])
        with self.assertRaises(records.HostRecordError):
            self.store.write_record('evaluation', score=1)

    def test_check_descriptor_io_refuses_symlinks_hardlinks_and_private_mode_changes(self):
        for location in ('parent', 'state', 'records', 'record', 'audit', 'head', 'lock'):
            with self.subTest(location=location):
                real = self.base / (location + '-real')
                store = records.HostRecordStore.for_tests(real / 'host')
                dispatch = self.dispatch(store=store)
                target = {'parent': real, 'state': store.state_root, 'records': store.root,
                          'record': store.root / (dispatch + '.json'), 'audit': store.audit_file,
                          'head': store.state_root / 'audit.jsonl.head.json',
                          'lock': store.state_root / 'audit.jsonl.lock'}[location]
                moved = target.with_name(target.name + '-moved')
                target.rename(moved)
                target.symlink_to(moved, target_is_directory=moved.is_dir())
                with self.assertRaises(records.HostRecordError):
                    store.get(dispatch)
        for location in ('state', 'records', 'record', 'audit', 'head', 'lock', 'hardlink'):
            with self.subTest(mode_location=location):
                store = records.HostRecordStore.for_tests(self.base / ('mode-' + location))
                dispatch = self.dispatch(store=store)
                target = {'state': store.state_root, 'records': store.root,
                          'record': store.root / (dispatch + '.json'), 'audit': store.audit_file,
                          'head': store.state_root / 'audit.jsonl.head.json',
                          'lock': store.state_root / 'audit.jsonl.lock', 'hardlink': store.root / (dispatch + '.json')}[location]
                if location == 'hardlink':
                    os.link(target, self.base / 'hardlinked-record')
                else:
                    target.chmod(0o755 if target.is_dir() else 0o644)
                with self.assertRaises(records.HostRecordError):
                    store.get(dispatch)

    def test_check_byte_record_scan_and_audit_event_bounds(self):
        dispatch = self.dispatch()
        for field, bound in (('max_record_bytes', 10), ('max_scan_bytes', 10), ('max_audit_bytes', 10), ('max_events', 1)):
            with self.subTest(field=field):
                if field == 'max_events':
                    self.store.record_audit_event({'event_type': 'extra'})
                limited = records.HostRecordStore.for_tests(self.store.state_root,
                            limits=replace(records.RecordLimits(), **{field: bound}))
                with self.assertRaises(records.HostRecordError):
                    limited.find('dispatch')
        limited_scan = records.HostRecordStore.for_tests(self.store.state_root,
                    limits=replace(records.RecordLimits(), max_scan_bytes=10))
        with self.assertRaises(records.HostRecordError):
            limited_scan.write_record('evaluation', score=1)
        limited = records.HostRecordStore.for_tests(self.store.state_root,
                    limits=replace(records.RecordLimits(), max_records=1))
        with self.assertRaises(records.HostRecordError):
            limited.write_record('evaluation', value=1)
        self.store.write_record('evaluation', value=1)
        with self.assertRaises(records.HostRecordError):
            limited.find('dispatch')
        with self.assertRaises(records.HostRecordError):
            records.HostRecordStore.for_tests(self.base / 'invalid-limits', limits=records.RecordLimits(max_events=0))
        self.assertEqual(self.store.get(dispatch)['dispatch_id'], 'executor')

    def test_check_dispatch_structure_duplicate_identity_and_review_target(self):
        invalid = [dict(dispatch_id=''), dict(dispatch_role='caller'), dict(request_sha256=None),
                   dict(request_sha256='not-digest'), dict(session_id='\n'), dict(bead_id='\n'),
                   dict(evaluation_metadata=[]), dict(review_target={'return_sha256': self.digest}),
                   dict(dispatch_role='peer-review'),
                   dict(dispatch_role='peer-review', session_id=None, review_target=dict(dispatch_id='executor', return_sha256=self.digest, evaluation_sha256='b' * 64))]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(records.HostRecordError):
                self.dispatch(**change)
        self.assertFalse(self.store.state_root.exists())
        dispatch = self.dispatch(model_id=None, reasoning_effort=None, session_id=None)
        with self.assertRaises(records.HostRecordError):
            self.dispatch()
        self.assertIsNone(self.store.get(dispatch)['session_id'])
        review = self.dispatch(dispatch_id='reviewer', dispatch_role='peer-review', session_id='thread-2',
                   review_target=dict(dispatch_id='executor', return_sha256=self.digest, evaluation_sha256='b' * 64))
        self.assertEqual(self.store.get(review)['review_target']['return_sha256'], self.digest)
        # Independently anchored duplicate ids still cannot be consumed.
        duplicate = self.store.get(dispatch)
        for key in ('_record_sha256', 'schema_version', 'record_type', 'created_at'):
            duplicate.pop(key)
        with patch.object(self.store, '_anchors', wraps=self.store._anchors):
            with self.assertRaises(records.HostRecordError):
                self.store._write('dispatch', duplicate)


    def test_check_database_identity_init_live_binding_and_copied_marker_refusal(self):
        database = self.base / 'database'
        database.mkdir(mode=0o700)
        with self.assertRaises(records.HostRecordError):
            self.store.require_database_identity(database)
        self.assertEqual(list(database.iterdir()), [])
        identity = self.store.setup_database_identity(database)
        self.assertEqual(self.store.require_database_identity(database), identity)
        self.assertEqual(self.store.setup_database_identity(database), identity)
        other = self.base / 'other-database'
        other.mkdir(mode=0o700)
        self.put(other / '.cwo-database-identity.json', (database / '.cwo-database-identity.json').read_bytes())
        with self.assertRaisesRegex(records.HostRecordError, 'physical identity'):
            self.store.require_database_identity(other)
        marker = database / '.cwo-database-identity.json'
        value = json.loads(marker.read_bytes())
        value['database_id'] = 'unanchored'
        self.put(marker, self.raw(value))
        with self.assertRaises(records.HostRecordError):
            self.store.require_database_identity(database)
        marker.unlink()
        marker.symlink_to(other / '.cwo-database-identity.json')
        with self.assertRaises(records.HostRecordError):
            self.store.require_database_identity(database)
        file_db = self.base / 'beads.db'
        self.put(file_db, b'database')
        file_id = self.store.setup_database_identity(file_db)
        self.put(file_db, b'updated database data')
        self.assertEqual(self.store.require_database_identity(file_db), file_id)
        file_db.chmod(0o644)
        with self.assertRaises(records.HostRecordError):
            self.store.require_database_identity(file_db)
        with self.assertRaises(records.HostRecordError):
            self.store.setup_database_identity(Path('relative'))


    def test_check_descriptor_change_during_read_and_zero_progress_during_write(self):
        digest = self.dispatch()
        target = (self.store.root / (digest + '.json')).stat()
        original = os.fstat
        reads = []
        def changing(fd):
            info = original(fd)
            if info.st_ino == target.st_ino and info.st_dev == target.st_dev:
                reads.append(fd)
                if len(reads) == 2:
                    values = {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                              'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')}
                    values['st_ctime_ns'] += 1
                    return SimpleNamespace(**values)
            return info
        with patch.object(os, 'fstat', side_effect=changing), self.assertRaises(records.HostRecordError):
            self.store.get(digest)
        for effect in ('record', 'audit'):
            with self.subTest(effect=effect):
                write = os.write
                calls = []
                def zero_once(fd, data):
                    calls.append(fd)
                    return 0 if len(calls) == 1 else write(fd, data)
                with patch.object(os, 'write', side_effect=zero_once), self.assertRaises(records.HostRecordError):
                    if effect == 'record':
                        self.store.write_record('evaluation', score=1)
                    else:
                        self.store.record_audit_event({'event_type': 'new-event'})

    def test_check_audit_append_bounds_and_post_snapshot_file_state(self):
        for field in ('max_audit_bytes', 'max_events', 'private-race'):
            with self.subTest(field=field):
                store = records.HostRecordStore.for_tests(self.base / field)
                self.dispatch(store=store)
                before = store.audit_file.read_bytes()
                if field == 'private-race':
                    original = records._audit_snapshot
                    def changed(directory, limits):
                        result = original(directory, limits)
                        store.audit_file.chmod(0o644)
                        return result
                    with patch.object(records, '_audit_snapshot', side_effect=changed), self.assertRaises(records.HostRecordError):
                        store.record_audit_event({'event_type': 'new-event'})
                else:
                    limit = len(before) + 1 if field == 'max_audit_bytes' else 1
                    store.limits = replace(store.limits, max_segments=1, **{field: limit})
                    with self.assertRaises(records.HostRecordError):
                        store.record_audit_event({'event_type': 'new-event'})
                self.assertEqual(store.audit_file.read_bytes(), before)

    def test_check_database_init_rejects_noncanonical_private_and_changing_objects(self):
        database = self.base / 'database'
        database.mkdir(mode=0o700)
        with self.assertRaises(records.HostRecordError):
            self.store.setup_database_identity(database / '..')
        database.chmod(0o755)
        with self.assertRaises(records.HostRecordError):
            self.store.setup_database_identity(database)
        database.chmod(0o700)
        original = os.stat
        def changed(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == database.name and kwargs.get('dir_fd') is not None:
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1,
                                       st_uid=info.st_uid, st_mode=info.st_mode)
            return info
        with patch.object(os, 'stat', side_effect=changed), self.assertRaises(records.HostRecordError):
            self.store.setup_database_identity(database)
        self.assertFalse((database / '.cwo-database-identity.json').exists())

    def test_check_capacity_refusal_preserves_usable_records_audit_and_head(self):
        for field, fresh in (('max_events', False), ('max_audit_bytes', False),
                             ('max_records', False), ('max_scan_bytes', False), ('max_scan_bytes', True)):
            with self.subTest(field=field, fresh=fresh):
                store = records.HostRecordStore.for_tests(self.base / (field + str(fresh)))
                first = None if fresh else self.dispatch(store=store)
                before = {p.relative_to(store.state_root): p.read_bytes()
                          for p in store.state_root.rglob('*') if p.is_file()}
                bounds = {'max_events': 1, 'max_audit_bytes': len(store.audit_file.read_bytes()) if not fresh else 1,
                          'max_records': 1, 'max_scan_bytes': 10 if fresh else sum(p.stat().st_size for p in store.root.iterdir())}
                store.limits = replace(store.limits, max_segments=1, **{field: bounds[field]})
                with patch.object(records, '_write_at', wraps=records._write_at) as writes:
                    with self.assertRaises(records.HostRecordError):
                        store.write_record('evaluation', score=2)
                    self.assertEqual(writes.call_count, 0)
                after = {p.relative_to(store.state_root): p.read_bytes()
                         for p in store.state_root.rglob('*') if p.is_file()}
                if fresh:
                    self.assertEqual(list(store.root.iterdir()), [])
                    self.assertFalse(store.audit_file.exists())
                    self.assertFalse((store.state_root / 'audit.jsonl.head.json').exists())
                else:
                    self.assertEqual(after, before)
                store.limits = records.RecordLimits()
                if first:
                    self.assertEqual(store.require_dispatch('executor')['_record_sha256'], first)
                second = store.write_record('evaluation', score=3)
                self.assertEqual(store.get(second)['score'], 3)
                self.assertEqual(len(store.find('evaluation')), 1)

    def test_check_uncommitted_write_failures_restore_usable_store(self):
        for stage in ('record-partial', 'audit-partial', 'audit-fsync', 'head-before'):
            with self.subTest(stage=stage):
                store = records.HostRecordStore.for_tests(self.base / stage)
                self.dispatch(store=store)
                before = {p.relative_to(store.state_root): p.read_bytes()
                          for p in store.state_root.rglob('*') if p.is_file()}
                original_write = os.write
                original_fsync = os.fsync
                original_write_at = records._write_at
                hits = []
                def write(fd, data):
                    if stage == 'audit-partial' and os.readlink('/proc/self/fd/' + str(fd)) == str(store.audit_file):
                        hits.append(fd)
                        if len(hits) == 1:
                            return original_write(fd, data[:7])
                        if len(hits) == 2:
                            raise OSError('injected interrupted audit write')
                    return original_write(fd, data)
                def fsync(fd):
                    if stage == 'audit-fsync' and os.readlink('/proc/self/fd/' + str(fd)) == str(store.audit_file) and not hits:
                        hits.append(fd)
                        raise OSError('injected audit fsync failure')
                    return original_fsync(fd)
                def write_at(directory, name, raw, **kwargs):
                    if stage == 'record-partial' and name != 'audit.jsonl.head.json' and not hits:
                        hits.append(name)
                        original_write_at(directory, name, b'partial', **kwargs)
                        raise KeyboardInterrupt('injected interrupted record write')
                    if stage == 'head-before' and name == 'audit.jsonl.head.json' and not hits:
                        hits.append(name)
                        raise KeyboardInterrupt('injected interrupted checkpoint write')
                    return original_write_at(directory, name, raw, **kwargs)
                with patch.object(os, 'write', side_effect=write), patch.object(os, 'fsync', side_effect=fsync), \
                     patch.object(records, '_write_at', side_effect=write_at), self.assertRaises((OSError, KeyboardInterrupt, records.HostRecordError)):
                    store.write_record('evaluation', score=2)
                self.assertTrue(hits)
                self.assertEqual(before, {p.relative_to(store.state_root): p.read_bytes()
                                         for p in store.state_root.rglob('*') if p.is_file()})
                second = store.write_record('evaluation', score=3)
                self.assertEqual(store.get(second)['score'], 3)
                self.assertEqual(len(store.find('evaluation')), 1)

    def test_check_capacity_walk_stops_before_over_budget_record_reads(self):
        self.dispatch()
        self.store.write_record('evaluation', score=1)
        for field, bound, max_reads in (('max_records', 1, 1), ('max_scan_bytes', 1, 0)):
            with self.subTest(field=field):
                self.store.limits = replace(records.RecordLimits(), **{field: bound})
                with patch.object(self.store, '_get', wraps=self.store._get) as reads:
                    with self.assertRaises(records.HostRecordError):
                        self.store.write_record('evaluation', score=2)
                    self.assertLessEqual(reads.call_count, max_reads)
        self.store.limits = records.RecordLimits()
        self.assertEqual(len(self.store.find('evaluation')), 1)

    def test_check_first_audit_append_failure_leaves_no_partial_files(self):
        original = records._write_at
        hits = []
        def fail_head(directory, name, raw, **kwargs):
            if name == 'audit.jsonl.head.json' and not hits:
                hits.append(name)
                raise KeyboardInterrupt('first checkpoint interrupted')
            return original(directory, name, raw, **kwargs)
        with patch.object(records, '_write_at', side_effect=fail_head), self.assertRaises(KeyboardInterrupt):
            self.store.write_record('evaluation', score=2)
        self.assertFalse(self.store.audit_file.exists())
        self.assertFalse((self.store.state_root / 'audit.jsonl.head.json').exists())
        self.assertEqual(list(self.store.root.iterdir()), [])
        self.assertEqual(self.store.find('evaluation'), [])
        second = self.store.write_record('evaluation', score=3)
        self.assertEqual(self.store.get(second)['score'], 3)

    def test_check_committed_anchor_and_existing_record_survive_interrupted_confirmation(self):
        self.dispatch()
        original = records._write_at
        hits = []
        def committed(directory, name, raw, **kwargs):
            original(directory, name, raw, **kwargs)
            if name == 'audit.jsonl.head.json' and not hits:
                hits.append(name)
                raise KeyboardInterrupt('checkpoint committed before interrupted confirmation')
        with patch.object(records, '_write_at', side_effect=committed), self.assertRaisesRegex(records.HostRecordError, 'committed'):
            self.store.write_record('evaluation', score=2)
        found = self.store.find('evaluation')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['score'], 2)
        with patch.object(records, '_now', return_value='2026-11-02T00:00:00Z'):
            existing = self.store.write_record('evaluation', score=3)
            with patch.object(audit, 'record_audit_event', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                self.store.write_record('evaluation', score=3)
        self.assertEqual(self.store.get(existing)['score'], 3)
        next_id = self.store.write_record('evaluation', score=4)
        self.assertEqual(self.store.get(next_id)['score'], 4)

    def test_check_committed_confirmation_then_transient_verifier_failure_preserves_evidence(self):
        for failure in (OSError, records.HostRecordError):
            with self.subTest(failure=failure):
                store = records.HostRecordStore.for_tests(self.base / failure.__name__)
                store.write_record('evaluation', score=1)
                original_at = records._write_at
                original_snapshot = records._audit_snapshot
                flags = {'committed': False, 'verification_failed': False}
                committed_files = {}
                def committed(directory, name, raw, **kwargs):
                    original_at(directory, name, raw, **kwargs)
                    if name == 'audit.jsonl.head.json' and not flags['committed']:
                        flags['committed'] = True
                        committed_files.update({p.relative_to(store.state_root): p.read_bytes()
                                                for p in store.state_root.rglob('*') if p.is_file()})
                        raise OSError('confirmation failure after complete checkpoint')
                def snapshot(directory, limits):
                    if flags['committed'] and not flags['verification_failed']:
                        flags['verification_failed'] = True
                        raise failure('transient verifier read failure')
                    return original_snapshot(directory, limits)
                with patch.object(records, '_write_at', side_effect=committed), \
                     patch.object(records, '_audit_snapshot', side_effect=snapshot), \
                     self.assertRaisesRegex(records.HostRecordError, 'uncertain'):
                    store.write_record('evaluation', score=2)
                self.assertTrue(all(flags.values()))
                self.assertEqual(committed_files, {p.relative_to(store.state_root): p.read_bytes()
                                                  for p in store.state_root.rglob('*') if p.is_file()})
                self.assertEqual(sorted(item['score'] for item in store.find('evaluation')), [1, 2])
                next_id = store.write_record('evaluation', score=3)
                self.assertEqual(store.get(next_id)['score'], 3)

    def test_check_unrecognized_pending_bytes_are_preserved_with_uncertainty(self):
        self.dispatch()
        original = records._write_at
        changed = []
        def corrupt(directory, name, raw, **kwargs):
            if name == 'audit.jsonl.head.json' and not changed:
                changed.append(name)
                with self.store.audit_file.open('ab') as handle:
                    handle.write(b'UNRECOGNIZED')
                raise OSError('unrecognized bytes before checkpoint')
            return original(directory, name, raw, **kwargs)
        with patch.object(records, '_write_at', side_effect=corrupt), \
             self.assertRaisesRegex(records.HostRecordError, 'uncertain'):
            self.store.write_record('evaluation', score=2)
        self.assertTrue(self.store.audit_file.read_bytes().endswith(b'UNRECOGNIZED'))
        self.assertEqual(len(list(self.store.root.iterdir())), 2)
        with self.assertRaises(records.HostRecordError):
            self.store.find('evaluation')


    def test_check_audit_open_descriptor_type_clause_is_independent(self):
        self.dispatch()
        original = os.fstat
        def nonregular(fd):
            info = original(fd)
            if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY:
                values = {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                          'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')}
                values['st_mode'] = stat.S_IFIFO | 0o600
                return SimpleNamespace(**values)
            return info
        before = self.store.audit_file.read_bytes()
        with patch.object(os, 'fstat', side_effect=nonregular), self.assertRaises(records.HostRecordError):
            self.store.record_audit_event({'event_type': 'new-event'})
        self.assertEqual(self.store.audit_file.read_bytes(), before)
        self.store.record_audit_event({'event_type': 'next-event'})
        self.assertEqual(self.store.require_audit_event('next-event')['event_type'], 'next-event')

    def test_check_individual_owner_file_type_and_unknown_schema_clauses(self):
        digest = self.dispatch()
        fd = os.open(self.store.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertTrue(records._read_at(fd, digest + '.json', 65536))
            with patch.object(os, 'getuid', return_value=os.getuid() + 1), self.assertRaises(records.HostRecordError):
                records._read_at(fd, digest + '.json', 65536)
            fifo = self.store.root / 'private-fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(records.HostRecordError):
                records._read_at(fd, fifo.name, 65536)
            fifo.unlink()
        finally:
            os.close(fd)
        with patch.object(os, 'getuid', return_value=os.getuid() + 1), self.assertRaises(records.HostRecordError):
            fd = records._directory(self.store.state_root, private=True)
            os.close(fd)
        database = self.base / 'owner-database'
        database.mkdir(mode=0o700)
        with patch.object(os, 'getuid', return_value=os.getuid() + 1), self.assertRaises(records.HostRecordError):
            fd, _, _ = self.store._database(database)
            os.close(fd)
        raw = self.raw(dict(schema_version=1, record_type='caller-type'))
        unknown = self.anchored_raw(self.store, raw, 'caller-type')
        with self.assertRaises(records.HostRecordError):
            self.store.get(unknown)

    def test_check_observed_dispatch_is_linked_immutable_and_requires_a_new_receipt(self):
        required = {'peer_review_required': True, 'required': None, 'nested': {'count': 1}}
        prepared = self.dispatch(model_family=None, model_id=None, reasoning_effort=None, session_id=None,
                                 evaluation_metadata=required)
        original = (self.store.root / (prepared + '.json')).read_bytes()
        old_receipt = self.store.write_return_received('executor', self.digest)
        observed = self.observed(packet_sha256='b' * 64, evaluation_metadata={'runtime_source': 'registered-http'})
        current = self.store.require_dispatch('executor')
        self.assertEqual(current['_record_sha256'], observed)
        self.assertEqual(current['stage'], 'observed')
        self.assertEqual(current['prepared_record_sha256'], prepared)
        self.assertEqual(current['observation_sha256'], 'e' * 64)
        self.assertEqual(current['evaluation_metadata'], {**required, 'runtime_source': 'registered-http'})
        self.assertEqual(current['request_sha256'], 'a' * 64)
        self.assertEqual((self.store.root / (prepared + '.json')).read_bytes(), original)
        self.assertEqual(len(self.store.find('dispatch', dispatch_id='executor')), 2)
        self.assertEqual(self.store.get(old_receipt)['dispatch_record_sha256'], prepared)
        with self.assertRaises(records.HostRecordError):
            self.store.require_return('executor', self.digest)
        new_receipt = self.store.write_return_received('executor', self.digest)
        self.assertNotEqual(new_receipt, old_receipt)
        self.assertEqual(self.store.require_return('executor', self.digest)['_record_sha256'], new_receipt)
        self.assertEqual(len(self.store.find('return-received', dispatch_id='executor')), 2)
        for action in (lambda: self.observed(), lambda: self.dispatch(),
                       lambda: self.store.write_return_received('executor', self.digest)):
            with self.assertRaises(records.HostRecordError):
                action()
        self.assertEqual(self.store.require_dispatch('executor')['_record_sha256'], observed)
        stale = dict(dispatch_id='executor', dispatch_record_sha256=prepared,
                     return_sha256='d' * 64, received_time='2026-11-02T00:00:00Z')
        with self.assertRaises(records.HostRecordError):
            self.store._write('return-received', stale)
        events = audit.iter_audit_events(self.store.audit_file)
        anchored = [event['host_record_sha256'] for event in events if event['event_type'] == 'dispatch_prepared']
        self.assertEqual(anchored, [prepared, observed])

    def test_check_observation_preserves_every_known_core_and_typed_metadata_value(self):
        changes = [dict(prepared_record_sha256='0' * 64), dict(observation_sha256='bad'),
                   dict(provider='anthropic'), dict(model_family='other'), dict(model_id='other'),
                   dict(reasoning_effort='medium'), dict(session_id='other'), dict(session_id=None),
                   dict(bead_id='other'), dict(executor='other'), dict(provider_key='other'),
                   dict(packet_sha256='d' * 64), dict(request_sha256='d' * 64),
                   dict(dispatch_role='peer-review'), dict(review_target={'dispatch_id': 'other'}),
                   dict(evaluation_metadata={'flag': 1}), dict(evaluation_metadata={'number': True}),
                   dict(evaluation_metadata={'nested': {'item': 1}}), dict(evaluation_metadata=[])]
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                store = records.HostRecordStore.for_tests(self.base / str(index))
                self.dispatch(store=store, packet_sha256='c' * 64,
                              evaluation_metadata={'flag': True, 'number': 1, 'nested': {'item': True}})
                before = {path: path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()}
                with self.assertRaises(records.HostRecordError):
                    self.observed(store=store, **change)
                self.assertEqual(before, {path: path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()})
        with self.assertRaises(records.HostRecordError):
            self.dispatch(evaluation_metadata={1: True})
        self.assertFalse(self.store.state_root.exists())


    def test_check_observed_identity_must_be_complete_when_preparation_is_unknown(self):
        for field in ('provider', 'model_family', 'model_id', 'reasoning_effort', 'session_id'):
            for invalid in (None, ''):
                with self.subTest(field=field, invalid=invalid):
                    store = records.HostRecordStore.for_tests(self.base / (field + str(invalid)))
                    self.dispatch(store=store, provider=None, model_family=None, model_id=None,
                                  reasoning_effort=None, session_id=None)
                    parent = store.require_dispatch('executor')
                    self.anchored_raw(store, self.observed_raw(parent, **{field: invalid}), 'dispatch')
                    with self.assertRaises(records.HostRecordError):
                        store.require_dispatch('executor')

    def test_check_missing_observation_cannot_revive_a_prepared_receipt(self):
        self.dispatch(model_family=None, model_id=None, reasoning_effort=None, session_id=None)
        self.store.write_return_received('executor', self.digest)
        observed = self.observed()
        (self.store.root / (observed + '.json')).unlink()
        before = self.store.audit_file.read_bytes()
        for action in (lambda: self.store.require_dispatch('executor'),
                       lambda: self.store.require_return('executor', self.digest),
                       lambda: self.store.write_return_received('executor', self.digest),
                       lambda: self.store.write_record('evaluation', score=1)):
            with self.assertRaises(records.HostRecordError):
                action()
        self.assertEqual(self.store.audit_file.read_bytes(), before)

    def test_check_distinct_pipeline_receipt_is_required_exact_and_unambiguous(self):
        dispatch = self.dispatch()
        with self.assertRaises(records.HostRecordError):
            self.store.require_audit_event('host_acceptance_decided', acceptance_record_sha256=dispatch)
        payload = dict(event_type='host_acceptance_decided', acceptance_record_sha256=dispatch,
                       adjudication_record_sha256='a' * 64, host_control_id='acceptance-v1')
        self.store.record_audit_event(payload)
        found = self.store.require_audit_event('host_acceptance_decided', acceptance_record_sha256=dispatch)
        self.assertEqual(found['adjudication_record_sha256'], 'a' * 64)
        self.assertEqual(found['host_control_id'], 'acceptance-v1')
        with self.assertRaises(records.HostRecordError):
            self.store.require_audit_event('host_acceptance_decided', acceptance_record_sha256='f' * 64)
        self.store.record_audit_event(payload)
        with self.assertRaises(records.HostRecordError):
            self.store.require_audit_event('host_acceptance_decided', acceptance_record_sha256=dispatch)

    def test_check_return_dispatch_and_acceptance_hold_bindings(self):
        with self.assertRaises(records.HostRecordError):
            self.store.write_return_received('missing', self.digest)
        self.dispatch()
        with self.assertRaises(records.HostRecordError):
            self.acceptance()
        self.store.write_return_received('executor', self.digest)
        for args in (('executor', 'd' * 64), ('other', self.digest)):
            with self.subTest(args=args), self.assertRaises(records.HostRecordError):
                self.store.require_return(*args)
        with self.assertRaises(records.HostRecordError):
            self.store.write_return_received('executor', self.digest)
        for change in (dict(evaluation_sha256='bad'), dict(database_identity={}), dict(required_holds=['review', 'review']),
                       dict(required_holds=[1]), dict(cleared_holds={}), dict(cleared_holds={'review': {}, 'extra': {}})):
            with self.subTest(change=change), self.assertRaises(records.HostRecordError):
                self.acceptance(**change)
        self.assertEqual(self.store.get(self.acceptance())['adjudication_result'], 'accepted')
        with self.assertRaises(records.HostRecordError):
            self.store.write_record('dispatch', value=1)
        with self.assertRaises(records.HostRecordError):
            self.store.write_record('evaluation', schema_version=2)
        with self.assertRaises(records.HostRecordError):
            self.store.write_record('evaluation', value=float('nan'))
        with self.assertRaises(records.HostRecordError):
            self.store.write_record('evaluation', value='x' * records.RecordLimits().max_record_bytes)


    def test_check_missing_record_directory_dangling_state_and_wrong_receipt_dispatch(self):
        dispatch = self.dispatch()
        receipt = self.store.write_return_received('executor', self.digest)
        value = self.store.get(receipt)
        (self.store.root / (receipt + '.json')).unlink()
        value.pop('_record_sha256')
        value['dispatch_record_sha256'] = '0' * 64
        self.anchored_raw(self.store, self.raw(value), 'return-received')
        with self.assertRaises(records.HostRecordError):
            self.store.require_return('executor', self.digest)
        shutil.rmtree(self.store.root)
        with self.assertRaises(records.HostRecordError):
            self.store.find('dispatch')
        dangling = records.HostRecordStore.for_tests(self.base / 'dangling-state')
        dangling.state_root.symlink_to(self.base / 'absent-directory', target_is_directory=True)
        with self.assertRaises(records.HostRecordError):
            dangling.find('dispatch')
        self.assertTrue(dispatch)


    def test_check_shared_chain_content_address_and_exact_receipt_positive(self):
        with records.using_test_store(self.store), patch.object(audit, 'AUDIT_LOG', paths.HOST_AUDIT_LOG):
            audit.record_audit_event({'event_type': 'packet_built', 'packet_sha256': 'f' * 64})
            dispatch = self.dispatch()
            receipt = self.store.write_return_received('executor', self.digest)
            acceptance = self.acceptance()
            audit.record_audit_event({'event_type': 'closure_consumed', 'database_identity_sha256': 'd' * 64,
                'acceptance_record_sha256': acceptance, 'database_identity': dict(database_id='registered',
                    device=1, inode=2, owner=os.getuid(), mode=0o700)})
        self.assertIs(records.configured_store().__class__, records.HostRecordStore)
        value = self.store.get(dispatch, 'dispatch')
        self.assertEqual(value['_record_sha256'], hashlib.sha256((self.store.root / (dispatch + '.json')).read_bytes()).hexdigest())
        self.assertEqual(value['bead_id'], 'cwor-test')
        self.assertEqual(self.store.require_return('executor', self.digest)['dispatch_record_sha256'], dispatch)
        self.assertEqual(self.store.get(acceptance)['return_record_sha256'], receipt)
        events = audit.iter_audit_events(self.store.audit_file)
        self.assertEqual([e['event_type'] for e in events], ['packet_built', 'dispatch_prepared',
                         'host_record_written', 'host_record_written', 'closure_consumed'])
        self.assertEqual(events[1]['host_record_sha256'], dispatch)
        self.assertEqual(events[-1]['acceptance_record_sha256'], acceptance)
        self.assertEqual(events[-1]['database_identity']['database_id'], 'registered')
        self.assertTrue(audit.verify_audit_log(self.store.audit_file)['valid'])
        for path in (self.store.state_root, self.store.root):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for path in (self.store.root / (dispatch + '.json'), self.store.audit_file,
                     self.store.state_root / 'audit.jsonl.head.json', self.store.state_root / 'audit.jsonl.lock'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_check_reader_refuses_unlinked_incomplete_or_changed_observation(self):
        changes = [dict(stage='caller'), dict(prepared_record_sha256='0' * 64), dict(dispatch_id='other'),
                   dict(observation_sha256=None), dict(provider='other'), dict(model_family=None),
                   dict(model_id=None), dict(reasoning_effort=None), dict(session_id=None),
                   dict(bead_id=None), dict(executor=None), dict(provider_key=None),
                   dict(packet_sha256=None), dict(request_sha256=None), dict(dispatch_role='peer-review'),
                   dict(review_target={}), dict(evaluation_metadata={}), dict(evaluation_metadata=[]),
                   dict(evaluation_metadata={'required': None, 'flag': 1})]
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                store = records.HostRecordStore.for_tests(self.base / str(index))
                self.dispatch(store=store, packet_sha256='c' * 64, evaluation_metadata={'required': None, 'flag': True})
                parent = store.require_dispatch('executor')
                self.anchored_raw(store, self.observed_raw(parent, **change), 'dispatch')
                with self.assertRaises(records.HostRecordError):
                    store.require_dispatch('executor')
        for kind in ('prepared', 'observed'):
            with self.subTest(duplicate=kind):
                store = records.HostRecordStore.for_tests(self.base / kind)
                self.dispatch(store=store)
                parent = store.require_dispatch('executor')
                if kind == 'prepared':
                    value = {key: item for key, item in parent.items() if key != '_record_sha256'}
                    value['session_id'] = 'duplicate'
                    self.anchored_raw(store, self.raw(value), 'dispatch')
                else:
                    self.observed(store=store)
                    self.anchored_raw(store, self.observed_raw(parent, observation_sha256='f' * 64), 'dispatch')
                with self.assertRaises(records.HostRecordError):
                    store.require_dispatch('executor')


if __name__ == '__main__':
    unittest.main()
