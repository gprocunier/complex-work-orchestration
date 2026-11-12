"""Fresh-store recovery availability; original reference and write guards stay strict."""
from __future__ import annotations

from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cwo_core import audit, audit_segments as segments, host_record_quarantine as quarantine, host_records as records  # noqa: E402
from tests import test_host_record_quarantine as quarantine_fixtures  # noqa: E402


class HostRecordRecoveryFollowupTests(unittest.TestCase):
    image = quarantine_fixtures.HostRecordQuarantineTests.image
    stray = quarantine_fixtures.HostRecordQuarantineTests.stray
    pending_recovery_input = quarantine_fixtures.HostRecordQuarantineTests.pending_recovery_input

    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def _wait_owned(self, child):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            found, status = os.waitpid(child, os.WNOHANG)
            if found:
                return status
            time.sleep(0.01)
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        self.fail('Owned first-journal crash child did not terminate within five seconds')

    def _crash_first_journal(self, store, kind):
        child = os.fork()
        if child:
            status = self._wait_owned(child)
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
            return status
        module, name = (records, quarantine.PENDING) if kind == 'quarantine' else (segments, segments.JOURNAL)
        original, write = module._write_at, os.write

        def torn(descriptor, raw):
            write(descriptor, raw[:10])
            os.fsync(descriptor)
            os.kill(os.getpid(), signal.SIGKILL)
            os._exit(79)

        def selected(directory, target, raw, **kwargs):
            if target == name:
                with patch.object(os, 'write', side_effect=torn):
                    return original(directory, target, raw, **kwargs)
            return original(directory, target, raw, **kwargs)

        try:
            with patch.object(module, '_write_at', side_effect=selected):
                if kind == 'quarantine':
                    store.quarantine_unreferenced()
                else:
                    store.write_record('evaluation', score=2)
        except BaseException:
            traceback.print_exc()
        os._exit(78)

    def _crash_rotation(self, store, stage):
        child = os.fork()
        if child:
            status = self._wait_owned(child)
            self.assertEqual(os.waitstatus_to_exitcode(status), 77)
            return
        original = segments._write_at
        selected = {'journal': segments.JOURNAL, 'segment': segments.segment_name(1), 'head': segments.HEAD}[stage]

        def interrupted(directory, name, raw, **kwargs):
            result = original(directory, name, raw, **kwargs)
            if name == selected:
                os._exit(77)
            return result

        try:
            with patch.object(segments, '_write_at', side_effect=interrupted):
                store.write_record('evaluation', score=2)
        except BaseException:
            traceback.print_exc()
        os._exit(78)

    def test_atomic_publication_crash_leaves_one_readable_link_and_complete_bytes(self):
        directory = self.base / 'published'
        directory.mkdir(mode=0o700)
        payload = b'EXAMPLE complete private publication bytes'
        child = os.fork()
        if not child:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            original = records._publish_at

            def published(*args):
                original(*args)
                os.kill(os.getpid(), signal.SIGKILL)
                os._exit(79)

            try:
                with patch.object(records, '_publish_at', side_effect=published):
                    records._write_at(descriptor, 'journal', payload, atomic_create=True)
            except BaseException:
                traceback.print_exc()
            os._exit(78)
        status = self._wait_owned(child)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
        self.assertEqual((directory / 'journal').stat().st_nlink, 1)
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ['journal'])
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self.assertEqual(records._read_at(descriptor, 'journal', 1024), payload)
        finally:
            os.close(descriptor)

    def test_atomic_publication_mode_conflict_and_unavailable_primitive_refuse_without_final_entry(self):
        directory = self.base / 'unsupported-publication'
        directory.mkdir(mode=0o700)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(records.HostRecordError, 'publication modes conflict'):
                records._write_at(descriptor, 'journal', b'EXAMPLE', replace=True, atomic_create=True)
            self.assertEqual(list(directory.iterdir()), [])
            caught = None
            with patch.object(records.ctypes, 'CDLL', return_value=SimpleNamespace()):
                try:
                    records._write_at(descriptor, 'journal', b'EXAMPLE', atomic_create=True)
                except Exception as failure:
                    caught = failure
            self.assertIsInstance(caught, records.HostRecordError)
            self.assertIn('publication is unavailable', str(caught))
            self.assertEqual(list(directory.iterdir()), [])
        finally:
            os.close(descriptor)

    def _assert_exclusive_maintenance_lock(self, store):
        descriptor = os.open(store.state_root / 'audit.jsonl.lock', os.O_RDWR | os.O_CLOEXEC)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    def test_pending_rotation_and_unreferenced_entry_recover_through_one_locked_maintenance_path(self):
        for stage in ('journal', 'segment', 'head'):
            with self.subTest(stage=stage):
                store = records.HostRecordStore.for_tests(self.base / stage,
                    limits=replace(records.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                self._crash_rotation(store, stage)
                noise = self.stray(store, raw=b'EXAMPLE unrelated bytes retained across rotation recovery')
                before = self.image(store.state_root)
                with self.assertRaisesRegex(ValueError, 'unexpected host record entry'):
                    store.write_record('evaluation', score=3)
                self.assertEqual(self.image(store.state_root), before)
                original, observations = segments.recover_rotation, []

                def observed(directory, limits, **kwargs):
                    if kwargs.get('allow_unreferenced'):
                        self._assert_exclusive_maintenance_lock(store)
                        observations.append(noise.read_bytes())
                    return original(directory, limits, **kwargs)

                outcome, refusal = None, None
                with patch.object(segments, 'recover_rotation', side_effect=observed):
                    try:
                        outcome = store.quarantine_unreferenced()
                    except records.HostRecordError as failure:
                        refusal = str(failure)
                self.assertIsNone(refusal, 'Explicit maintenance could not recover its pending rotation: ' + str(refusal))
                self.assertIsNotNone(outcome)
                self.assertEqual(observations, [b'EXAMPLE unrelated bytes retained across rotation recovery'])
                self.assertEqual(outcome['status'], 'quarantined')
                self.assertEqual(outcome['count'], 1)
                self.assertFalse(noise.exists())
                self.assertFalse((store.state_root / segments.JOURNAL).exists())
                self.assertEqual(store.get(first)['score'], 1)
                store.write_record('evaluation', score=3)
                self.assertEqual(store.get(first)['score'], 1)

    def test_maintenance_rotation_recovery_still_refuses_reference_and_scan_bound_failures_before_cleanup(self):
        for fault in ('missing-reference', 'changed-reference', 'stray-bytes'):
            with self.subTest(fault=fault):
                store = records.HostRecordStore.for_tests(self.base / fault,
                    limits=replace(records.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                self._crash_rotation(store, 'segment')
                noise = self.stray(store, raw=b'EXAMPLE unexpected bytes that must remain in the scan total')
                record = store.root / (first + '.json')
                if fault == 'missing-reference':
                    record.unlink()
                elif fault == 'changed-reference':
                    record.write_bytes(record.read_bytes() + b' ')
                else:
                    other = sum(path.stat().st_size for path in store.root.iterdir() if path != noise)
                    store.limits = replace(store.limits, max_scan_bytes=other + noise.stat().st_size - 1)
                before = self.image(store.state_root)
                with self.assertRaises(ValueError):
                    store.quarantine_unreferenced()
                self.assertEqual(self.image(store.state_root), before)
                self.assertTrue((store.state_root / segments.JOURNAL).exists())

    def test_unsafe_unreferenced_entry_refusal_names_the_entry_and_manual_remedy_without_changes(self):
        for kind in ('mode', 'symlink', 'directory'):
            with self.subTest(kind=kind):
                store = records.HostRecordStore.for_tests(self.base / kind)
                first = store.write_record('evaluation', score=1)
                name = 'unexpected-' + kind
                path = store.root / name
                if kind == 'mode':
                    path.write_bytes(b'EXAMPLE public-mode file')
                    path.chmod(0o644)
                    remedy = 'mode 0600'
                elif kind == 'symlink':
                    target = self.base / 'EXAMPLE-link-target'
                    target.write_bytes(b'EXAMPLE outside bytes must not be read or changed')
                    path.symlink_to(target)
                    remedy = 'remove only this unreferenced symlink'
                else:
                    path.mkdir()
                    remedy = 'directory outside records/'
                before = self.image(store.state_root)
                with self.assertRaises(records.HostRecordError) as caught:
                    store.quarantine_unreferenced()
                self.assertIn(repr(name), str(caught.exception))
                self.assertIn('manual step:', str(caught.exception))
                self.assertIn(remedy, str(caught.exception))
                self.assertEqual(self.image(store.state_root), before)
                self.assertEqual(store.get(first)['score'], 1)

    def test_initial_rotation_journal_never_replaces_an_unrelated_existing_claim(self):
        store = records.HostRecordStore.for_tests(self.base / 'unrelated-rotation-claim',
            limits=replace(records.RecordLimits(), max_events=1))
        first = store.write_record('evaluation', score=1)
        original, inserted = segments._write_at, []
        unrelated = b'EXAMPLE unrelated journal custody must remain byte-exact'
        head = (store.state_root / segments.HEAD).read_bytes()
        first_bytes = (store.root / (first + '.json')).read_bytes()

        def claim(directory, name, raw, **kwargs):
            if name == segments.JOURNAL and not inserted:
                records._write_at(directory, name, unrelated)
                inserted.append(True)
            return original(directory, name, raw, **kwargs)

        refusal = None
        with patch.object(segments, '_write_at', side_effect=claim):
            try:
                store.write_record('evaluation', score=2)
            except records.HostRecordError as failure:
                refusal = str(failure)
        self.assertTrue(inserted)
        self.assertIsNotNone(refusal)
        self.assertEqual((store.state_root / segments.JOURNAL).read_bytes(), unrelated)
        self.assertEqual((store.state_root / segments.HEAD).read_bytes(), head)
        self.assertEqual((store.root / (first + '.json')).read_bytes(), first_bytes)

    def test_unrelated_transaction_of_the_same_quarantine_event_type_cannot_complete_pending_transaction(self):
        store, first, manifest, planned = self.pending_recovery_input('unrelated-transaction')
        event = {key: planned[key] for key in ('event_type', 'quarantine_transaction_id',
                                             'quarantine_manifest_sha256', 'quarantine_file_count')}
        event['quarantine_transaction_id'] = 'f' * 32
        self.assertNotEqual(event['quarantine_transaction_id'], planned['quarantine_transaction_id'])
        with store._state() as state:
            lock = records._audit_lock(state, create=False, exclusive=True)
            try:
                # Explicit private recovery-input seam; public writers remain
                # gated. This does not claim an unrelated public transaction ran.
                audit._append_private_audit(event, state, store.limits)
                observed = records._audit_snapshot(state, store.limits)
                self.assertNotEqual(segments.read_head(state), quarantine._old_head(manifest))
                self.assertEqual(observed[-1]['event_type'], planned['event_type'])
                self.assertNotEqual(observed[-1], planned)
            finally:
                os.close(lock)
        before = self.image(store.state_root)
        outcome, refusal = None, None
        try:
            outcome = store.quarantine_unreferenced()
        except records.HostRecordError as failure:
            refusal = str(failure)
        self.assertIsNone(outcome)
        self.assertIsNotNone(refusal)
        self.assertIn('outcome is uncertain', refusal)
        self.assertEqual(self.image(store.state_root), before)
        self.assertTrue((store.root / (first + '.json')).is_file())
        self.assertTrue((store.state_root / quarantine.PENDING).is_file())

    def test_only_unexpected_bytes_exceed_the_original_scan_bound_and_refuse_without_mutation(self):
        store = records.HostRecordStore.for_tests(self.base / 'scan-bound')
        first = store.write_record('evaluation', score=1)
        noise = self.stray(store, raw=b'EXAMPLE unexpected bytes are included in the original scan budget')
        referenced_size = (store.root / (first + '.json')).stat().st_size
        limit = referenced_size + noise.stat().st_size - 1
        self.assertLess(referenced_size, limit)
        self.assertLess(limit, referenced_size + noise.stat().st_size)
        store.limits = replace(store.limits, max_scan_bytes=limit)
        before = self.image(store.state_root)
        with self.assertRaisesRegex(records.HostRecordError, 'scan byte bound exceeded'):
            store.quarantine_unreferenced()
        self.assertEqual(self.image(store.state_root), before)
        self.assertFalse((store.state_root / quarantine.PENDING).exists())

    def test_dot_named_unreferenced_entry_is_quarantined_and_audited_with_the_other_entries(self):
        store = records.HostRecordStore.for_tests(self.base / 'hidden')
        first = store.write_record('evaluation', score=1)
        hidden = self.stray(store, name='.hidden', raw=b'EXAMPLE dot-named bytes')
        noise = self.stray(store, name='noise', raw=b'EXAMPLE ordinary bytes')
        originals = {path.name: path.read_bytes() for path in (hidden, noise)}
        outcome = store.quarantine_unreferenced()
        self.assertEqual(outcome['status'], 'quarantined')
        self.assertEqual(outcome['count'], 2)
        transaction = store.state_root / quarantine.ROOT / ('tx-' + outcome['transaction'])
        manifest = json.loads((transaction / 'manifest.json').read_bytes())
        self.assertEqual(sorted(row['name'] for row in manifest['files']), ['.hidden', 'noise'])
        for row in manifest['files']:
            self.assertFalse((store.root / row['name']).exists())
            self.assertEqual((transaction / 'files' / row['destination']).read_bytes(), originals[row['name']])
        events = [row for row in store.audit_events() if row['event_type'] == quarantine.EVENT]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['quarantine_file_count'], 2)
        self.assertEqual(store.quarantine_unreferenced(), {'status': 'unchanged', 'count': 0})
        store.write_record('evaluation', score=3)
        self.assertEqual(store.get(first)['score'], 1)

    def test_first_quarantine_and_rotation_journals_publish_atomically_across_a_real_torn_write(self):
        for kind in ('quarantine', 'rotation'):
            with self.subTest(kind=kind):
                limits = replace(records.RecordLimits(), max_events=1) if kind == 'rotation' else records.RecordLimits()
                store = records.HostRecordStore.for_tests(self.base / kind, limits=limits)
                first = store.write_record('evaluation', score=1)
                first_path = store.root / (first + '.json')
                first_bytes = first_path.read_bytes()
                if kind == 'quarantine':
                    noise = store.root / 'noise'
                    noise.write_bytes(b'EXAMPLE unreferenced bytes')
                    noise.chmod(0o600)
                journal = quarantine.PENDING if kind == 'quarantine' else segments.JOURNAL
                status = self._crash_first_journal(store, kind)
                self.assertFalse((store.state_root / journal).exists(), 'A torn first journal was published at its final name')
                partials = list(store.state_root.glob('.write-*'))
                self.assertEqual(len(partials), 1)
                self.assertEqual(len(partials[0].read_bytes()), 10)
                self.assertEqual(first_path.read_bytes(), first_bytes)
                self.assertEqual(store.get(first)['score'], 1)
                self.assertEqual(len(store.audit_events()), 1)
                outcome = store.quarantine_unreferenced()
                self.assertEqual(outcome['status'], 'quarantined')
                self.assertEqual(outcome['count'], 1)
                store.write_record('evaluation', score=3)
                self.assertEqual(store.get(first)['score'], 1)
                self.assertFalse((store.state_root / journal).exists())
                print('EXAMPLE-FIRST-JOURNAL-CRASH ' + repr({'kind': kind, 'owned_wait_status': status,
                    'unpublished_partial_sha256': hashlib.sha256(partials[0].read_bytes()).hexdigest(),
                    'first_record_sha256': first, 'maintenance_outcome': outcome, 'next_write_passed': True}))
