"""M3: segmented history remains one verified chain at every product reader."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cwo_core import audit, audit_segments as segments, host_records as records, paths


class AuditSegmentChecks(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = records.HostRecordStore.for_tests(self.base / 'host',
            limits=replace(records.RecordLimits(), max_events=2))
        self.enterContext(records.using_test_store(self.store))
        self.enterContext(patch.object(audit, 'AUDIT_LOG', paths.HOST_AUDIT_LOG))
        self.enterContext(patch.object(audit, 'HOST_AUDIT_LOG', paths.HOST_AUDIT_LOG))

    def emit(self, number):
        return self.store.record_audit_event(dict(event_type='EXAMPLE-event', dispatch_id='EXAMPLE-' + str(number),
            quota_event_type='external_manual_dispatch', epic_id='EXAMPLE-epic', executor_external=True))

    def populated(self):
        return [self.emit(number) for number in range(5)]

    def snapshot(self):
        return {p.relative_to(self.store.state_root): p.read_bytes()
                for p in self.store.state_root.rglob('*') if p.is_file()}

    def test_rotation_preserves_old_records_default_quota_matching_and_verification(self):
        """Checks: automatic segment transition, old anchors and every default audit reader."""
        first = self.store.write_record('evaluation', score=7)
        events = self.populated()
        head = json.loads((self.store.state_root / segments.HEAD).read_bytes())
        self.assertEqual(head['active_segment'], 2)
        self.assertEqual(len(head['sealed_segments']), 2)
        self.assertEqual(self.store.get(first)['score'], 7)
        self.assertEqual(self.store.find('evaluation')[0]['_record_sha256'], first)
        self.assertEqual(audit.count_audit_events('external_manual_dispatch', 'EXAMPLE-epic', True), 5)
        self.assertEqual(len(audit.iter_audit_events()), 6)
        self.assertEqual(len(audit.iter_audit_events(self.store.audit_file)), 6)
        self.assertEqual(audit.matching_audit_events(event_type='EXAMPLE-event')[0]['event_hash'], events[0]['event_hash'])
        self.assertEqual(audit.verify_audit_log()['event_count'], 6)
        self.assertTrue(audit.verify_audit_log(self.store.audit_file)['valid'])
        self.assertEqual(self.store.require_audit_event('EXAMPLE-event', dispatch_id='EXAMPLE-0')['event_hash'], events[0]['event_hash'])
        for path in self.store.state_root.iterdir():
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_each_segment_content_head_seam_order_missing_and_truncation_refuses_zero_write(self):
        """Checks: segment digest/seal, links/events, exact ordering and global current head."""
        self.populated()
        pristine = self.snapshot()
        head_path = self.store.state_root / segments.HEAD
        for fault in ('content', 'event-digest', 'seam', 'seal', 'order', 'missing', 'truncated', 'head', 'unknown'):
            with self.subTest(fault=fault):
                for name, raw in pristine.items():
                    (self.store.state_root / name).write_bytes(raw)
                    (self.store.state_root / name).chmod(0o600)
                path = self.store.audit_file
                if fault == 'content':
                    path.write_bytes(path.read_bytes().replace(b'EXAMPLE-event', b'EXAMPLE-other', 1))
                elif fault in ('event-digest', 'seam'):
                    path = self.store.state_root / segments.segment_name(2)
                    row = json.loads(path.read_bytes())
                    row['previous_event_hash' if fault == 'seam' else 'event_hash'] = '0' * 64
                    if fault == 'seam':
                        row['event_hash'] = audit.audit_event_payload_hash(row)
                    path.write_text(json.dumps(row) + '\n')
                elif fault in ('seal', 'order', 'head'):
                    head = json.loads(head_path.read_bytes())
                    if fault == 'seal':
                        head['sealed_segments'][0]['content_sha256'] = '0' * 64
                    elif fault == 'order':
                        head['sealed_segments'].reverse()
                    else:
                        head['event_count'] -= 1
                    head_path.write_text(json.dumps(head))
                elif fault == 'missing':
                    path.unlink()
                elif fault == 'truncated':
                    path.write_bytes(path.read_bytes()[:-2])
                else:
                    path = self.store.state_root / segments.segment_name(8)
                    path.write_bytes(b'unknown')
                    path.chmod(0o600)
                before = self.snapshot()
                with self.assertRaises((ValueError, OSError)):
                    self.store.audit_events()
                with self.assertRaises((ValueError, OSError)):
                    self.emit(8)
                self.assertFalse(audit.verify_audit_log()['valid'])
                self.assertEqual(before, self.snapshot())
                if fault == 'unknown':
                    path.unlink()
        for name, raw in pristine.items():
            (self.store.state_root / name).write_bytes(raw)
        self.assertEqual(len(self.store.audit_events()), 5)

    def test_segment_private_regular_nofollow_and_worker_root_constraints(self):
        """Checks: sealed segments use the same private descriptor rules as the active tail."""
        self.populated()
        path = self.store.audit_file
        raw = path.read_bytes()
        outside = self.base / 'outside'
        outside.write_bytes(raw)
        outside.chmod(0o600)
        for fault in ('symlink', 'hardlink', 'mode'):
            with self.subTest(fault=fault):
                path.unlink()
                if fault == 'symlink':
                    path.symlink_to(outside)
                elif fault == 'hardlink':
                    os.link(outside, path)
                else:
                    path.write_bytes(raw)
                    path.chmod(0o644)
                before = outside.read_bytes()
                with self.assertRaises((ValueError, OSError)):
                    self.store.audit_events()
                self.assertEqual(outside.read_bytes(), before)
                path.unlink()
                path.write_bytes(raw)
                path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'worker writable'):
            self.store.require_outside_worker_roots((self.base,))
        self.assertEqual(len(self.store.audit_events()), 5)

    def test_explicit_history_segment_and_event_capacity_refuses_before_record_writes(self):
        """Checks: per-segment bounds stay fixed; separate total bounds fail closed."""
        self.populated()
        self.emit(5)  # Three full segments; another event needs segment four.
        total_bytes = sum(p.stat().st_size for p in self.store.state_root.glob('*.jsonl'))
        for field, bound in (('max_segments', 3), ('max_history_events', 6),
                             ('max_history_bytes', total_bytes)):
            self.store.limits = replace(self.store.limits, **{field: bound})
            before = self.snapshot()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.store.write_record('evaluation', score=8)
            self.assertEqual(before, self.snapshot())
            self.store.limits = replace(records.RecordLimits(), max_events=2)
        for field, bound in (('max_segments', 2), ('max_history_events', 5),
                             ('max_history_bytes', total_bytes - 1)):
            self.store.limits = replace(self.store.limits, **{field: bound})
            with self.subTest(reader_bound=field), self.assertRaises(ValueError):
                self.store.audit_events()
            self.store.limits = replace(records.RecordLimits(), max_events=2)
        checkpoint_size = (self.store.state_root / segments.HEAD).stat().st_size
        before = self.snapshot()
        with patch.object(segments, 'MAX_HEAD_BYTES', checkpoint_size + 1):
            with self.assertRaises(Exception):
                self.store.write_record('evaluation', score=8)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.store.write_record('evaluation', score=9), self.store.find('evaluation')[0]['_record_sha256'])

    def test_rotation_failures_recover_old_or_committed_head_without_losing_records(self):
        """Checks: journal/segment/head boundaries retain known committed evidence and recover safely."""
        for stage in ('journal', 'partial-segment', 'head-before', 'head-after'):
            with self.subTest(stage=stage):
                store = records.HostRecordStore.for_tests(self.base / stage,
                    limits=replace(records.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                original = segments._write_at
                hit = []
                def fail(directory, name, raw, **kwargs):
                    selected = ((stage == 'journal' and name == segments.JOURNAL)
                        or (stage == 'partial-segment' and name == segments.segment_name(1))
                        or (stage.startswith('head-') and name == segments.HEAD))
                    if selected and not hit:
                        hit.append(name)
                        if stage == 'partial-segment':
                            original(directory, name, raw[:len(raw)//2], **kwargs)
                        elif stage == 'head-after':
                            original(directory, name, raw, **kwargs)
                        raise KeyboardInterrupt('EXAMPLE rotation interrupted')
                    return original(directory, name, raw, **kwargs)
                with patch.object(segments, '_write_at', side_effect=fail):
                    with self.assertRaises((KeyboardInterrupt, ValueError)):
                        store.write_record('evaluation', score=2)
                self.assertTrue(hit)
                self.assertEqual(store.get(first)['score'], 1)
                self.assertEqual(sorted(row['score'] for row in store.find('evaluation')),
                                 [1, 2] if stage == 'head-after' else [1])
                self.assertFalse((store.state_root / segments.JOURNAL).exists())
                store.write_record('evaluation', score=3)
                self.assertEqual(store.get(first)['score'], 1)

    def crash_rotation(self, store, stage):
        child = os.fork()
        if child == 0:
            original = segments._write_at
            def crash(directory, name, raw, **kwargs):
                selected = ((stage == 'journal' and name == segments.JOURNAL)
                    or (stage in ('partial', 'segment') and name == segments.segment_name(1))
                    or (stage == 'head' and name == segments.HEAD))
                if selected:
                    original(directory, name, raw[:len(raw)//2] if stage == 'partial' else raw, **kwargs)
                    os._exit(77)
                return original(directory, name, raw, **kwargs)
            with patch.object(segments, '_write_at', side_effect=crash):
                store.write_record('evaluation', score=2)
            os._exit(78)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 77)

    def test_actual_process_crash_is_read_only_refused_then_next_writer_recovers(self):
        """Checks: durable journal, partial/full segment and committed-head crash seams."""
        for stage in ('journal', 'partial', 'segment', 'head'):
            with self.subTest(stage=stage):
                store = records.HostRecordStore.for_tests(self.base / ('crash-' + stage),
                    limits=replace(records.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                self.crash_rotation(store, stage)
                before = {p.relative_to(store.state_root): p.read_bytes()
                          for p in store.state_root.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError, 'pending'):
                    store.audit_events()
                self.assertEqual(before, {p.relative_to(store.state_root): p.read_bytes()
                                          for p in store.state_root.rglob('*') if p.is_file()})
                store.write_record('evaluation', score=3)
                self.assertEqual(store.get(first)['score'], 1)
                self.assertEqual(sorted(row['score'] for row in store.find('evaluation')),
                                 [1, 2, 3] if stage == 'head' else [1, 3])
                self.assertFalse((store.state_root / segments.JOURNAL).exists())

    def test_uncertain_crash_recovery_preserves_all_evidence_without_guessing(self):
        """Checks: recovery requires exact prior checkpoint, bounded journal and pending-byte prefix."""
        for fault in ('pending-bytes', 'checkpoint', 'shape', 'encoding', 'head-encoding', 'layout', 'record', 'cleanup-marker'):
            with self.subTest(fault=fault):
                store = records.HostRecordStore.for_tests(self.base / ('uncertain-' + fault),
                    limits=replace(records.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                self.crash_rotation(store, 'segment')
                journal = store.state_root / segments.JOURNAL
                value = json.loads(journal.read_bytes())
                if fault == 'pending-bytes':
                    (store.state_root / segments.segment_name(1)).write_bytes(b'unknown pending bytes')
                elif fault == 'checkpoint':
                    import base64
                    previous = json.loads(base64.b64decode(value['previous_head']))
                    previous['event_count'] += 1
                    value['next_head']['event_count'] += 1
                    value['previous_head'] = base64.b64encode(records._json(previous)).decode()
                    journal.write_text(json.dumps(value))
                elif fault == 'shape':
                    value['caller-extra'] = True
                    journal.write_text(json.dumps(value))
                elif fault == 'encoding':
                    value['event_bytes'] = value['event_bytes'][:3] + '!' + value['event_bytes'][3:]
                    journal.write_text(json.dumps(value))
                elif fault == 'head-encoding':
                    value['previous_head'] = value['previous_head'][:3] + '!' + value['previous_head'][3:]
                    journal.write_text(json.dumps(value))
                elif fault == 'cleanup-marker':
                    value['rollback_ready'] = 1
                    journal.write_text(json.dumps(value))
                elif fault == 'layout':
                    value['next_head']['active_segment'] += 1
                    journal.write_text(json.dumps(value))
                else:
                    path = next(p for p in store.root.iterdir() if p.stem != first)
                    path.write_bytes(path.read_bytes() + b' ')
                before = {p.relative_to(store.state_root): p.read_bytes()
                          for p in store.state_root.rglob('*') if p.is_file()}
                with self.assertRaises(ValueError):
                    store.write_record('evaluation', score=3)
                self.assertEqual(before, {p.relative_to(store.state_root): p.read_bytes()
                                          for p in store.state_root.rglob('*') if p.is_file()})

    def test_byte_capacity_rotates_and_a_single_oversize_event_is_zero_write_refused(self):
        """Checks: the original byte bound applies independently to each segment/event."""
        self.store.limits = records.RecordLimits()
        self.emit(0)
        with self.store._guarded_state() as (directory, _):
            _, raw = audit._prepare_private_audit_event({'event_type': 'EXAMPLE-next'}, directory,
                                                      self.store.limits)
        before_size = self.store.audit_file.stat().st_size
        self.store.limits = replace(self.store.limits, max_audit_bytes=before_size + len(raw) - 1)
        self.store.record_audit_event({'event_type': 'EXAMPLE-next'})
        self.assertEqual(len(self.store.audit_events()), 2)
        self.assertEqual(json.loads((self.store.state_root / segments.HEAD).read_bytes())['active_segment'], 1)
        before = self.snapshot()
        with self.assertRaises(Exception):
            from cwo_core.telemetry import AUDIT_STRING_FIELDS
            self.store.record_audit_event(dict.fromkeys([name for name in AUDIT_STRING_FIELDS if not name.startswith('peer_review')], 'X' * 256))
        self.assertEqual(before, self.snapshot())

    def test_segment_primitives_enforce_exact_layout_events_and_missing_checkpoint(self):
        """Checks: each event digest/link/bound and exact segment-layout type is independently enforced."""
        event = {'event_type': 'EXAMPLE-known-vector'}
        event['event_hash'] = audit.audit_event_payload_hash(event)
        raw = records._json(event)
        self.assertEqual(segments._events(raw, None, self.store.limits), ([event], event['event_hash']))
        linked, previous = [], None
        for number in range(3):
            row = {'event_type': 'EXAMPLE-linked-' + str(number)}
            if previous is not None:
                row['previous_event_hash'] = previous
            previous = row['event_hash'] = audit.audit_event_payload_hash(row)
            linked.append(records._json(row))
        for bad in (raw[:-1], b'\n', b''.join(linked),
                    records._json({**event, 'event_hash': '0' * 64}),
                    records._json({**event, 'previous_event_hash': '0' * 64,
                        'event_hash': audit.audit_event_payload_hash({**event, 'previous_event_hash': '0' * 64})})):
            with self.subTest(raw=bad[:80]), self.assertRaises(ValueError):
                segments._events(bad, None, self.store.limits)
        self.assertEqual(segments.layout(None), (0, []))
        self.assertEqual(segments.layout(records._json({'active_segment': 1, 'sealed_segments': [{}]})), (1, [{}]))
        for bad in ({'active_segment': True, 'sealed_segments': [{}]},
                    {'active_segment': 1, 'sealed_segments': {'a': {}}},
                    {'active_segment': 2, 'sealed_segments': [{}]}):
            with self.subTest(layout=bad), self.assertRaises(ValueError):
                segments.layout(records._json(bad))
        self.populated()
        head = self.store.state_root / segments.HEAD
        saved = head.read_bytes()
        head.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.store.audit_events()
        head.write_bytes(saved)
        head.chmod(0o600)
        with self.store._guarded_state() as (directory, _):
            missing = records._json(dict(active_segment=3, sealed_segments=[{}, {}, {}]))
            with self.assertRaises((ValueError, OSError)):
                segments.active(directory, self.store.limits, missing)

    def test_rotation_journal_bounds_and_exact_extension_are_independent(self):
        """Checks: journal decoded-byte bounds and exact prior-seal extension precede recovery."""
        self.populated()
        previous = (self.store.state_root / segments.HEAD).read_bytes()
        old = json.loads(previous)
        event = {'event_type': 'EXAMPLE-next', 'previous_event_hash': old['event_hash']}
        event['event_hash'] = audit.audit_event_payload_hash(event)
        raw = records._json(event)
        extended = dict(old, active_segment=old['active_segment'] + 1,
                        sealed_segments=[*old['sealed_segments'], {}], event_hash=event['event_hash'],
                        event_count=old['event_count'] + 1, byte_count=len(raw))
        journal = self.store.state_root / segments.JOURNAL
        for fault in ('none', 'extension', 'prefix', 'previous-bound', 'event-bound', 'event-binding',
                      'byte-binding', 'count-binding', 'multi-event'):
            prior, next_head, event_bytes = previous, json.loads(json.dumps(extended)), raw
            limits = self.store.limits
            if fault == 'extension':
                next_head = old
            elif fault == 'prefix':
                next_head['sealed_segments'][0]['content_sha256'] = '0' * 64
            elif fault == 'previous-bound':
                prior = previous + b' ' * segments.MAX_HEAD_BYTES
            elif fault == 'event-bound':
                limits = replace(limits, max_audit_bytes=len(raw) - 1)
            elif fault == 'event-binding':
                next_head['event_hash'] = '0' * 64
            elif fault == 'byte-binding':
                next_head['byte_count'] += 1
            elif fault == 'count-binding':
                next_head['event_count'] += 1
            elif fault == 'multi-event':
                second = {'event_type': 'EXAMPLE-next-2', 'previous_event_hash': event['event_hash']}
                second['event_hash'] = audit.audit_event_payload_hash(second)
                event_bytes += records._json(second)
                next_head.update(event_hash=second['event_hash'], byte_count=len(event_bytes))
            journal.write_bytes(segments._journal_bytes(prior, next_head, event_bytes))
            journal.chmod(0o600)
            with self.store._guarded_state() as (directory, _):
                if fault == 'none':
                    self.assertEqual(segments._rotation_pending(directory, limits),
                                     (previous, extended, raw, old['active_segment'] + 1, False))
                else:
                    with self.subTest(fault=fault), self.assertRaises(ValueError):
                        segments._rotation_pending(directory, limits)
        initial = {'event_count': 1, 'event_hash': old['event_hash'], 'byte_count': 100}
        unchanged = dict(initial, event_count=2, event_hash=event['event_hash'], byte_count=len(raw))
        journal.write_bytes(segments._journal_bytes(records._json(initial), unchanged, raw))
        with self.store._guarded_state() as (directory, _), self.assertRaises(ValueError):
            segments._rotation_pending(directory, self.store.limits)
        journal.unlink()

    def test_every_referenced_record_is_verified_before_any_crash_recovery_cleanup(self):
        """M3: old/current inventory plus pending record must be intact before any cleanup."""
        for stage in ('segment', 'head'):
            for target in ('prior', 'pending'):
                for fault in ('tamper', 'missing'):
                    with self.subTest(stage=stage, target=target, fault=fault):
                        store = records.HostRecordStore.for_tests(self.base / ('records-' + stage + target + fault),
                            limits=replace(records.RecordLimits(), max_events=1))
                        first = store.write_record('evaluation', score=1)
                        self.crash_rotation(store, stage)
                        path = (store.root / (first + '.json') if target == 'prior' else
                                next(p for p in store.root.iterdir() if p.stem != first))
                        if fault == 'tamper':
                            path.write_bytes(path.read_bytes() + b' ')
                        else:
                            path.unlink()
                        before = {p.relative_to(store.state_root): p.read_bytes()
                                  for p in store.state_root.rglob('*') if p.is_file()}
                        with self.assertRaises((ValueError, OSError)):
                            store.write_record('evaluation', score=3)
                        self.assertEqual(before, {p.relative_to(store.state_root): p.read_bytes()
                                                  for p in store.state_root.rglob('*') if p.is_file()})
                        self.assertTrue((store.state_root / segments.JOURNAL).exists())

    def test_actual_crash_during_proven_rollback_resumes_only_after_durable_ready_marker(self):
        """M3: missing pending data is resumable only after a complete verified cleanup proof."""
        store = records.HostRecordStore.for_tests(self.base / 'cleanup-crash',
            limits=replace(records.RecordLimits(), max_events=1))
        store.write_record('evaluation', score=1)
        self.crash_rotation(store, 'segment')
        child = os.fork()
        if child == 0:
            original = os.unlink
            def crash(name, *args, **kwargs):
                original(name, *args, **kwargs)
                if str(name).endswith('.json') and name not in (segments.HEAD, segments.JOURNAL):
                    os._exit(79)
            with patch.object(os, 'unlink', side_effect=crash):
                store.write_record('evaluation', score=3)
            os._exit(80)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 79)
        journal = store.state_root / segments.JOURNAL
        self.assertIs(json.loads(journal.read_bytes()).get('rollback_ready'), True)
        store.write_record('evaluation', score=4)
        self.assertEqual(sorted(row['score'] for row in store.find('evaluation')), [1, 4])
        self.assertFalse(journal.exists())

    def test_recovery_record_inventory_rejects_strays_and_bounds_before_cleanup(self):
        """M3: existing inventory bounds and unknown-record refusal precede recovery writes."""
        import hashlib
        for fault in ('stray', 'filename', 'count', 'bytes'):
            store = records.HostRecordStore.for_tests(self.base / ('inventory-' + fault),
                limits=replace(records.RecordLimits(), max_events=1))
            first = store.write_record('evaluation', score=1)
            self.crash_rotation(store, 'segment')
            if fault == 'stray':
                raw = records._json({'schema_version': 1, 'record_type': 'evaluation', 'score': 99})
                path = store.root / (hashlib.sha256(raw).hexdigest() + '.json')
                path.write_bytes(raw)
                path.chmod(0o600)
            elif fault == 'filename':
                path = store.root / (first + '.evil')
                path.write_bytes(b'unknown filename')
                path.chmod(0o600)
            elif fault == 'count':
                store.limits = replace(store.limits, max_records=1)
            else:
                store.limits = replace(store.limits, max_scan_bytes=1)
            before = {p.relative_to(store.state_root): p.read_bytes()
                      for p in store.state_root.rglob('*') if p.is_file()}
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                store.write_record('evaluation', score=3)
            self.assertEqual(before, {p.relative_to(store.state_root): p.read_bytes()
                                      for p in store.state_root.rglob('*') if p.is_file()})


if __name__ == '__main__':
    unittest.main()
