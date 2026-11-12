"""8yg: real host records survive noise; explicit maintenance grants nothing."""
from __future__ import annotations

from contextlib import ExitStack
import base64
import copy
from dataclasses import replace
import fcntl
import hashlib
import json
import mmap
import os
import select
import signal
from pathlib import Path
import stat
import sys
import time
import traceback
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cwo_core import audit, audit_segments as segments, host_records as h  # noqa: E402
from cwo_core import host_record_quarantine as q  # noqa: E402
from cwo_core.host_acceptance import require_acceptance  # noqa: E402
from tests.host_acceptance_fixtures import provision_acceptance  # noqa: E402
from tests import test_f9_host_provenance_guards as peer_fixtures  # noqa: E402


class HostRecordQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = h.HostRecordStore.for_tests(self.base / 'host')
        self.enterContext(h.using_test_store(self.store))
        self.first = self.store.write_record('evaluation', score=1)

    def stray(self, store=None, name='noise', raw=b'opaque EXAMPLE bytes'):
        path = (store or self.store).root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def image(self, root=None):
        root = root or self.store.state_root
        image = {}
        for path in root.rglob('*'):
            info = path.lstat()
            value = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            if stat.S_ISLNK(info.st_mode):
                value = os.readlink(path)
            image[str(path.relative_to(root))] = (h._identity(info), value)
        return image

    def events(self, store=None):
        return [event for event in (store or self.store).audit_events() if event['event_type'] == q.EVENT]

    def pending_recovery_input(self, name, *, limits=None):
        """Real serialized appending input; no crash or public-writer origin claimed."""
        store = h.HostRecordStore.for_tests(self.base / name, limits=limits)
        first = store.write_record('evaluation', score=1)
        self.stray(store)
        with store._state() as state:
            lock = h._audit_lock(state, create=False, exclusive=True)
            try:
                with q._directory(state, 'records') as directory:
                    prior = h._audit_snapshot(state, store.limits)
                    strays = q._inventory(state, directory, store.limits, prior)
                    manifest, raw = q._plan(state, directory, strays, store.limits)
                    event = q._event(state, manifest, raw, store.limits, prior)
                    with q._directory(state, q.ROOT, create=True) as root:
                        name = 'tx-' + manifest['transaction']
                        os.mkdir(name, 0o700, dir_fd=root)
                        os.fsync(root)
                        with q._directory(root, name) as transaction:
                            h._write_at(transaction, 'manifest.json', raw)
                            with q._directory(transaction, 'files', create=True) as files:
                                journal = q._journal(manifest, raw, event)
                                q._write_journal(state, journal, store.limits)
                                for entry in manifest['files']:
                                    q._move(directory, files, entry, store.limits)
                                q._write_journal(state, {**journal, 'phase': 'appending'},
                                                 store.limits, replace=True)
            finally:
                os.close(lock)
        return store, first, manifest, event

    def descriptor_recovery_input(self, name, *, prefix=None, committed=False):
        """Finite serialized recovery input, without a crash/producer-origin claim."""
        store, first, manifest, event = self.pending_recovery_input(name)
        self.assertEqual(len(manifest['files']), 1)
        entry = manifest['files'][0]
        transaction = store.state_root / q.ROOT / ('tx-' + manifest['transaction'])
        source = store.root / entry['name']
        destination = transaction / 'files' / entry['destination']
        self.assertFalse(source.exists())
        self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), entry['sha256'])
        with store._state() as state:
            lock = h._audit_lock(state, create=False, exclusive=True)
            try:
                if prefix is not None:
                    self.assertTrue(destination.read_bytes().startswith(prefix))
                    journal = json.loads((store.state_root / q.PENDING).read_bytes())
                    q._write_journal(state, {**journal, 'phase': 'restoring'},
                                     store.limits, replace=True)
                    source.write_bytes(prefix)
                    source.chmod(0o600)
                if committed:
                    # Explicit private input seam, not a cooperating public
                    # writer passing the pending gate.
                    actual = audit._append_private_audit(event, state, store.limits)
                    self.assertEqual(actual, event)
                    self.assertNotEqual(segments.read_head(state), q._old_head(manifest))
            finally:
                os.close(lock)
        return store, first, source, destination, transaction

    def foreign_pending_bytes(self, raw, field='transaction'):
        journal = json.loads(raw)
        if field == 'transaction':
            journal[field] = 'f' * 32 if journal[field] != 'f' * 32 else 'e' * 32
            journal['event']['quarantine_transaction_id'] = journal[field]
        else:
            self.assertEqual(field, 'manifest_sha256')
            journal[field] = 'f' * 64 if journal[field] != 'f' * 64 else 'e' * 64
            journal['event']['quarantine_manifest_sha256'] = journal[field]
        journal['event']['event_hash'] = audit.audit_event_payload_hash(journal['event'])
        q._validate_journal(journal)
        return h._json(journal)

    def late_descriptor_restore_row(self, label, kind):
        prefix = b'' if kind == 'fifo' else b'opa'
        store, _, source, destination, _ = self.descriptor_recovery_input(label, prefix=prefix)
        good_copy = destination.read_bytes()
        original = q._open_verified_file
        records_inode = store.root.stat().st_ino
        observed, queue = {}, []
        external = self.base / (label + '-external')
        def late(directory, name, expected, maximum, **kwargs):
            selected = (name == source.name and os.fstat(directory).st_ino == records_inode
                        and kwargs.get('writable') and not observed)
            if selected:
                self.assertEqual(expected, prefix)
                if kind == 'mode':
                    source.chmod(0o644)
                elif kind == 'hardlink':
                    os.link(source, external)
                elif kind == 'content':
                    external.write_bytes(b'BAD')
                    external.chmod(0o600)
                    os.replace(external, source)
                else:
                    self.assertEqual(kind, 'fifo')
                    source.rename(external)
                    os.mkfifo(source, 0o600)
                    fd = os.open(source, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
                    queue.append(fd)
                    payload = b'X' * (maximum + 1)
                    self.assertLessEqual(len(payload), os.fpathconf(fd, 'PC_PIPE_BUF'))
                    self.assertEqual(os.write(fd, payload), len(payload))
                    observed['payload'] = payload
                observed['image'] = self.image(self.base)
            return original(directory, name, expected, maximum, **kwargs)
        try:
            refusal = None
            with patch.object(q, '_open_verified_file', side_effect=late):
                try:
                    store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    refusal = error
            self.assertIn('image', observed, 'The real late-descriptor fixture was not reached')
            self.assertEqual(self.image(self.base), observed['image'],
                             'Recovery changed the late foreign/private-file image before refusing')
            if queue:
                try:
                    remaining = os.read(queue[0], len(observed['payload']))
                except BlockingIOError:
                    remaining = b''
                self.assertEqual(remaining, observed['payload'], 'Recovery consumed real foreign FIFO bytes')
            self.assertIsNotNone(refusal)
            self.assertEqual(destination.read_bytes(), good_copy)
            self.assertTrue((store.state_root / q.PENDING).is_file())
        finally:
            for fd in queue:
                os.close(fd)

    def test_genuine_acceptance_dispatch_and_forged_zero_write_before_and_after_quarantine(self):
        database = self.base / 'database'
        database.mkdir(mode=0o700)
        identity = self.store.setup_database_identity(database)
        beacon = {'bead_id': 'EXAMPLE_8YG', 'database_identity': identity}
        accepted = provision_acceptance(self.store, **beacon)
        genuine = require_acceptance(self.store, **accepted, **beacon)
        noise = self.stray()
        forged = h._json({'schema_version': 1, 'record_type': 'acceptance-decision'})
        forged_id = hashlib.sha256(forged).hexdigest()
        self.stray(name=forged_id + '.json', raw=forged)
        before = self.image()
        with self.assertRaises(h.HostRecordError):
            require_acceptance(self.store, **{**accepted, 'acceptance_record': forged_id}, **beacon)
        self.assertEqual(self.image(), before)
        self.assertEqual(require_acceptance(self.store, **accepted, **beacon), genuine)
        self.assertEqual(self.store.require_dispatch(genuine['dispatch_id'])['dispatch_id'], genuine['dispatch_id'])
        with self.assertRaises(h.HostRecordError):
            self.store.write_record('evaluation', score=2)
        self.assertEqual(self.image(), before)
        result = self.store.quarantine_unreferenced()
        self.assertEqual((result['status'], result['count']), ('quarantined', 2))
        self.assertFalse(noise.exists())
        self.assertEqual(require_acceptance(self.store, **accepted, **beacon), genuine)
        event = self.events()[0]
        self.assertEqual(event['quarantine_manifest_sha256'], result['manifest_sha256'])
        self.assertEqual(event['quarantine_file_count'], 2)
        self.assertFalse({'host_record_sha256', 'host_record_type', 'acceptance_record_sha256'} & set(event))
        with self.assertRaises(h.HostRecordError):
            self.store.get(result['manifest_sha256'])
        with self.assertRaises(h.HostRecordError):
            self.store.get(forged_id)
        self.assertEqual(self.store.quarantine_unreferenced(), {'status': 'unchanged', 'count': 0})
        self.assertEqual(len(self.events()), 1)
        fresh = self.store.write_record('evaluation', score=2)
        self.assertEqual(self.store.get(fresh)['score'], 2)

    def test_unreferenced_links_nonregular_modes_and_oversize_do_not_escape(self):
        for kind in ('symlink', 'hardlink', 'directory', 'fifo', 'mode', 'oversize', 'control-token'):
            with self.subTest(kind=kind):
                store = h.HostRecordStore.for_tests(self.base / kind)
                first = store.write_record('evaluation', score=1)
                external = self.base / (kind + '-external')
                external.write_bytes(b'EXAMPLE outside bytes')
                external.chmod(0o600)
                path = store.root / ('EXAMPLE\ncontrol' if kind == 'control-token' else 'noise')
                if kind == 'symlink':
                    path.symlink_to(external)
                elif kind == 'hardlink':
                    os.link(external, path)
                elif kind == 'directory':
                    path.mkdir(mode=0o700)
                elif kind == 'fifo':
                    os.mkfifo(path, 0o600)
                else:
                    self.stray(store, name=path.name, raw=b'x' * (store.limits.max_record_bytes + 1) if kind == 'oversize' else b'noise')
                    if kind == 'mode':
                        path.chmod(0o644)
                self.assertEqual(store.find('evaluation'), [store.get(first)])
                outside = (external.read_bytes(), h._identity(external.stat()))
                with self.assertRaises(h.HostRecordError):
                    store.quarantine_unreferenced()
                self.assertEqual((external.read_bytes(), h._identity(external.stat())), outside)
                self.assertTrue(os.path.lexists(path))
                self.assertFalse((store.state_root / q.ROOT).exists())

        with self.subTest(original_id='8YG-Q20-quarantine-directory-symlink'):
            store = h.HostRecordStore.for_tests(self.base / 'quarantine-directory-link')
            store.write_record('evaluation', score=1)
            source = self.stray(store)
            foreign = self.base / 'EXAMPLE-foreign-quarantine'
            foreign.mkdir(mode=0o700)
            (store.state_root / q.ROOT).symlink_to(foreign, target_is_directory=True)
            before_store, before_foreign = self.image(store.state_root), self.image(foreign)
            refusal = None
            try:
                store.quarantine_unreferenced()
            except (h.HostRecordError, OSError) as error:
                refusal = error
            self.assertEqual(self.image(foreign), before_foreign)
            self.assertEqual(self.image(store.state_root), before_store)
            self.assertIsNotNone(refusal)
            self.assertEqual(source.read_bytes(), b'opaque EXAMPLE bytes')
            self.assertEqual(list(foreign.iterdir()), [])

    def test_nested_separation_reference_rows_refuse_before_moving_any_bytes(self):
        for container in ('hold-clearance', 'evaluation', 'pending_evaluation', 'return_evaluated'):
            for field in ('executor_dispatch_sha256', 'reviewer_dispatch_sha256'):
                for target in ('dangling', 'unanchored', 'wrong-type'):
                    row = container + '/' + field + '/' + target
                    with self.subTest(original_id=row), ExitStack() as stack:
                        helper = peer_fixtures.F9HostProvenanceGuards('runTest')
                        stack.callback(helper.doCleanups)
                        fixture, _, accepted, review, _, clearance, _, _, _ = helper.reviewed()
                        store = fixture.store
                        dispatch = store.require_dispatch(accepted['dispatch_id'])
                        raw = h._json({**{key: value for key, value in dispatch.items() if key != '_record_sha256'},
                                       'EXAMPLE_unanchored': row})
                        digest = accepted['evaluation_record'] if target == 'wrong-type' else hashlib.sha256(raw).hexdigest()
                        kind = 'hold-clearance' if container == 'hold-clearance' else 'evaluation'
                        source = clearance if kind == 'hold-clearance' else store.get(accepted['evaluation_record'])
                        payload = copy.deepcopy(fixture.record_payload(source))
                        if container == 'return_evaluated':
                            store.record_audit_event({'event_type': 'return_evaluated', 'peer_review_status': 'passed',
                                'peer_review_reviewer': review['reviewer_identity'], 'peer_review_record': review,
                                'peer_review_separation': {**clearance['peer_review_separation'], field: digest}})
                        elif kind == 'hold-clearance':
                            payload['peer_review_separation'][field] = digest
                        else:
                            payload[container]['peer_review_separation'] = {
                                **clearance['peer_review_separation'], field: digest}
                        if container != 'return_evaluated':
                            store.write_record(kind, **payload)
                        if target == 'unanchored':
                            self.stray(store, digest + '.json', raw)
                        noise = self.stray(store)
                        before = self.image(store.state_root)
                        with self.assertRaisesRegex(h.HostRecordError, 'unanchored typed reference'):
                            store.quarantine_unreferenced()
                        self.assertEqual(self.image(store.state_root), before)
                        self.assertTrue(noise.exists())
                        self.assertFalse((store.state_root / q.ROOT).exists())

    def test_genuine_peer_acceptance_survives_quarantine_and_none_is_not_a_reference(self):
        helper = peer_fixtures.F9HostProvenanceGuards('runTest')
        self.addCleanup(helper.doCleanups)
        fixture, record_id, accepted, review, evaluation, clearance, pending, expected, _ = helper.reviewed()
        store = fixture.store
        for value in (evaluation, clearance):
            separation = value['peer_review_separation']
            for name in ('executor_dispatch_sha256', 'reviewer_dispatch_sha256'):
                self.assertEqual(store.get(separation[name], 'dispatch')['record_type'], 'dispatch')
        self.assertIsNone(pending.get('peer_review_separation'))
        store.record_audit_event({'event_type': 'return_evaluated', 'peer_review_status': 'passed',
            'peer_review_reviewer': review['reviewer_identity'], 'peer_review_record': review,
            'peer_review_separation': clearance['peer_review_separation']})
        # Generic None-valued metadata grants no acceptance and has no peer ref.
        store.write_record('evaluation', evaluation={'peer_review_separation': None}, pending_evaluation=None)
        noise = self.stray(store)
        result = store.quarantine_unreferenced()
        self.assertEqual((result['status'], result['count']), ('quarantined', 1))
        self.assertFalse(noise.exists())
        self.assertEqual(require_acceptance(store, record_id, return_sha256=expected['return_sha256'],
            evaluation_sha256=expected['evaluation_sha256'], **fixture.beacon), accepted)

    def test_anchored_corruption_and_known_unanchored_references_refuse_before_quarantine(self):
        with self.subTest(original_id='referenced-record-replaced-after-verification'):
            store = h.HostRecordStore.for_tests(self.base / 'late-referenced-replacement')
            first = store.write_record('evaluation', score=1)
            source = store.root / (first + '.json')
            changed = source.read_bytes().replace(b'"score":1', b'"score":2')
            self.assertNotEqual(changed, source.read_bytes())
            noise = self.stray(store)
            verified = h._verified_record_at
            invalidated = []

            def replace_verified(*args, **kwargs):
                value = verified(*args, **kwargs)
                if args[0] == first and not invalidated:
                    replacement = self.base / 'replacement-reference.json'
                    replacement.write_bytes(changed)
                    replacement.chmod(0o600)
                    os.replace(replacement, source)
                    invalidated.append(self.image(store.state_root))
                return value

            with patch.object(h, '_verified_record_at', side_effect=replace_verified):
                with self.assertRaisesRegex(h.HostRecordError, 'changed around inventory verification'):
                    store.quarantine_unreferenced()
            self.assertEqual(len(invalidated), 1)
            self.assertEqual(self.image(store.state_root), invalidated[0])
            self.assertTrue(noise.exists())
            self.assertFalse((store.state_root / q.ROOT).exists())

        for kind in ('missing', 'digest', 'mode', 'hardlink', 'schema', 'typed-anchor'):
            with self.subTest(kind=kind):
                store = h.HostRecordStore.for_tests(self.base / kind)
                first = store.write_record('evaluation', score=1)
                path = store.root / (first + '.json')
                self.stray(store)
                if kind == 'missing':
                    path.unlink()
                elif kind == 'digest':
                    path.write_bytes(b'changed')
                elif kind == 'mode':
                    path.chmod(0o644)
                elif kind == 'hardlink':
                    os.link(path, self.base / 'EXAMPLE_alias')
                else:
                    raw = b'[]' if kind == 'schema' else h._json({'schema_version': 1, 'record_type': 'adjudication'})
                    digest = hashlib.sha256(raw).hexdigest()
                    self.stray(store, digest + '.json', raw)
                    store.record_audit_event({'event_type': 'host_record_written',
                        'host_record_sha256': digest, 'host_record_type': 'evaluation'})
                before = self.image(store.state_root)
                with self.assertRaises(h.HostRecordError):
                    store.find('evaluation')
                with self.assertRaises(h.HostRecordError):
                    store.quarantine_unreferenced()
                self.assertEqual(self.image(store.state_root), before)
        orphan = h._json({'schema_version': 1, 'record_type': 'evaluation'})
        digest = hashlib.sha256(orphan).hexdigest()
        # Anchor a real reference before creating its unanchored target.
        store = h.HostRecordStore.for_tests(self.base / 'known-reference')
        store.write_record('adjudication', evaluation_record=digest)
        self.stray(store, digest + '.json', orphan)
        before = self.image(store.state_root)
        with self.assertRaisesRegex(h.HostRecordError, 'unanchored typed reference'):
            store.quarantine_unreferenced()
        self.assertEqual(self.image(store.state_root), before)

        with self.subTest(original_id='8YG-Q15-cleared-hold-unanchored-value'):
            store = h.HostRecordStore.for_tests(self.base / 'cleared-hold-value')
            clearance = h._json({'schema_version': 1, 'record_type': 'hold-clearance',
                                 'created_at': 'EXAMPLE', 'EXAMPLE_unanchored': True})
            clearance_id = hashlib.sha256(clearance).hexdigest()
            store._write('acceptance-decision', {'required_holds': ['review'],
                         'cleared_holds': {'review': clearance_id}})
            self.stray(store, clearance_id + '.json', clearance)
            before = self.image(store.state_root)
            refusal = None
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
            self.assertEqual(self.image(store.state_root), before)
            self.assertIsNotNone(refusal)
            self.assertIn('unanchored typed reference', str(refusal))
            self.assertFalse((store.state_root / q.ROOT).exists())

    def test_original_bounds_and_audit_capacity_refuse_before_quarantine_writes(self):
        for change in ({'max_records': 1}, {'max_scan_bytes': 1}, {'max_record_bytes': 128},
                       {'max_history_events': 1}, {'max_events': 1, 'max_segments': 1}):
            with self.subTest(change=change):
                store = h.HostRecordStore.for_tests(self.base / ('bound-' + str(len(list(self.base.iterdir())))))
                store.write_record('evaluation', score=1)
                self.stray(store)
                store.limits = replace(store.limits, **change)
                before = self.image(store.state_root)
                with self.assertRaises(h.HostRecordError):
                    store.quarantine_unreferenced()
                self.assertEqual(self.image(store.state_root), before)

        with self.subTest(original_id='8YG-Q17-manifest-independent-byte-cap'):
            store = h.HostRecordStore.for_tests(self.base / 'manifest-byte-cap')
            store.write_record('evaluation', score=1)
            for index in range(20):
                self.stray(store, f'noise-{index:02d}', b'EXAMPLE small stray')
            with store._guarded_state(create=True) as (state, _):
                with q._directory(state, 'records') as directory:
                    events = h._audit_snapshot(state, store.limits)
                    manifest, raw = q._plan(state, directory,
                        q._inventory(state, directory, store.limits, events), store.limits)
                    event = q._event(state, manifest, raw, store.limits, events)
                    journal = q._journal(manifest, raw, event)
            cap = 2048
            self.assertGreater(len(raw), cap)
            self.assertTrue(all(len(h._json({**journal, 'phase': phase})) <= cap
                                for phase in ('moving', 'appending', 'restoring')))
            self.assertLess(len(h._json(event)), store.limits.max_audit_bytes)
            self.assertTrue(all(len(path.read_bytes()) < cap for path in store.root.iterdir()))
            store.limits = replace(store.limits, max_record_bytes=cap)
            before = self.image(store.state_root)
            refusal = None
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
            self.assertEqual(self.image(store.state_root), before)
            self.assertIsNotNone(refusal)
            self.assertIn('manifest byte bound', str(refusal))
            self.assertFalse((store.state_root / q.ROOT).exists())

        for fits_all in (False, True):
            row = 'journal-phase-exact-fit' if fits_all else 'journal-phase-width-refusal'
            with self.subTest(original_id=row):
                store = h.HostRecordStore.for_tests(self.base / row)
                with store._guarded_state(create=True) as (state, _):
                    os.mkdir('records', 0o700, dir_fd=state)
                    source = self.stray(store, 'orphan', b'EXAMPLE opaque initial orphan')
                    with q._directory(state, 'records') as directory:
                        events = h._audit_snapshot(state, store.limits)
                        strays = q._inventory(state, directory, store.limits, events)
                        manifest, raw = q._plan(state, directory, strays, store.limits)
                        event = q._event(state, manifest, raw, store.limits, events)
                        journal = q._journal(manifest, raw, event)
                        # Real protocol sizes arrange the boundary; the oracle
                        # below is the public outcome and complete store image.
                        sizes = {phase: len(h._json({**journal, 'phase': phase}))
                                 for phase in ('moving', 'appending', 'restoring')}
                self.assertLessEqual(len(raw), sizes['moving'])
                self.assertLess(sizes['moving'], max(sizes.values()))
                cap = max(sizes.values()) if fits_all else sizes['moving']
                bounded = h.HostRecordStore.for_tests(store.state_root,
                    limits=replace(h.RecordLimits(), max_record_bytes=cap))
                before = self.image(store.state_root)
                if fits_all:
                    result = bounded.quarantine_unreferenced()
                    self.assertEqual((result['status'], result['count']), ('quarantined', 1))
                    self.assertFalse(source.exists())
                    copied = next((store.state_root / q.ROOT).glob('tx-*/files/item-000000'))
                    self.assertEqual(copied.read_bytes(), b'EXAMPLE opaque initial orphan')
                    self.assertEqual(len(self.events(bounded)), 1)
                    self.assertEqual(bounded.audit_events()[0]['event_type'], q.EVENT)
                else:
                    with self.assertRaises(h.HostRecordError):
                        bounded.quarantine_unreferenced()
                    self.assertEqual(self.image(store.state_root), before)
                    self.assertEqual(source.read_bytes(), b'EXAMPLE opaque initial orphan')
                    self.assertFalse((store.state_root / q.ROOT).exists())
                self.assertFalse((store.state_root / q.PENDING).exists())

    def test_real_rotation_then_post_maintenance_product_and_audit_writes(self):
        self.store.limits = replace(self.store.limits, max_events=1)
        noise = self.stray()
        result = self.store.quarantine_unreferenced()
        self.assertEqual(result['status'], 'quarantined')
        self.assertFalse(noise.exists())
        self.assertEqual(self.store.get(self.first)['score'], 1)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.store.quarantine_unreferenced(), {'status': 'unchanged', 'count': 0})
        self.assertEqual(len(self.events()), 1)
        self.assertTrue((self.store.state_root / segments.segment_name(1)).is_file())
        fresh = self.store.write_record('evaluation', score=2)
        self.store.record_audit_event({'event_type': 'EXAMPLE post-maintenance'})
        self.assertEqual(self.store.get(fresh)['score'], 2)
        self.assertFalse((self.store.state_root / segments.JOURNAL).exists())

    def test_destination_collision_and_source_replacement_preserve_foreign_bytes(self):
        for kind in ('destination', 'source'):
            with self.subTest(kind=kind):
                store = h.HostRecordStore.for_tests(self.base / kind)
                store.write_record('evaluation', score=1)
                source = self.stray(store)
                original = h._write_at
                injected = []
                def replace_source(directory, name, raw, **kwargs):
                    if name == 'item-000000' and not injected:
                        injected.append(True)
                        if kind == 'destination':
                            original(directory, name, b'EXAMPLE foreign bytes')
                        else:
                            result = original(directory, name, raw, **kwargs)
                            source.rename(store.state_root / 'EXAMPLE original-retained')
                            self.stray(store, raw=b'EXAMPLE foreign bytes')
                            return result
                    return original(directory, name, raw, **kwargs)
                with patch.object(h, '_write_at', side_effect=replace_source):
                    with self.assertRaisesRegex(h.HostRecordError, 'uncertain'):
                        store.quarantine_unreferenced()
                self.assertTrue(injected)
                foreign = source if kind == 'source' else next((store.state_root / q.ROOT).glob('tx-*/files/item-000000'))
                self.assertEqual(foreign.read_bytes(), b'EXAMPLE foreign bytes')
                self.assertTrue((store.state_root / q.PENDING).is_file())
                with self.assertRaisesRegex(h.HostRecordError, 'pending'):
                    store.find('evaluation')

        for shape in ('empty', 'sentinel'):
            with self.subTest(original_id='8YG-N067-transaction-collision-' + shape):
                store = h.HostRecordStore.for_tests(self.base / ('transaction-collision-' + shape))
                store.write_record('evaluation', score=1)
                source = self.stray(store)
                fixed = q.uuid.UUID('1234567890abcdef1234567890abcdef')
                quarantine_root = store.state_root / q.ROOT
                quarantine_root.mkdir(mode=0o700)
                transaction = quarantine_root / ('tx-' + fixed.hex)
                transaction.mkdir(mode=0o700)
                if shape == 'sentinel':
                    sentinel = transaction / 'EXAMPLE-foreign-sentinel'
                    sentinel.write_bytes(b'EXAMPLE foreign transaction bytes')
                    sentinel.chmod(0o600)
                before = self.image(store.state_root)
                with patch.object(q, 'uuid', SimpleNamespace(uuid4=lambda: fixed)):
                    with self.assertRaises(h.HostRecordError) as refusal:
                        store.quarantine_unreferenced()
                self.assertIs(type(refusal.exception.__cause__), FileExistsError)
                self.assertEqual(self.image(store.state_root), before)
                self.assertEqual(source.read_bytes(), b'opaque EXAMPLE bytes')
                self.assertFalse((store.state_root / q.PENDING).exists())
                self.assertEqual(self.events(store), [])

    def test_foreign_audit_suffix_is_not_truncated_using_only_a_valid_old_prefix(self):
        self.stray()
        expected = []
        def foreign(event, state, limits):
            fd = os.open(segments.segment_name(0), os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=state)
            try:
                os.write(fd, b'EXAMPLE foreign audit suffix\n')
                os.fsync(fd)
            finally:
                os.close(fd)
            expected.append(self.image())
            raise OSError('EXAMPLE foreign suffix')
        with patch.object(audit, '_append_private_audit', side_effect=foreign):
            with self.assertRaisesRegex(h.HostRecordError, 'uncertain'):
                self.store.quarantine_unreferenced()
        self.assertEqual(self.image(), expected[0])
        with self.assertRaises(h.HostRecordError):
            self.store.quarantine_unreferenced()
        self.assertEqual(self.image(), expected[0])

        with self.subTest(original_id='foreign-valid-rotation-input'):
            store, first, manifest, planned = self.pending_recovery_input('foreign-rotation',
                limits=replace(h.RecordLimits(), max_events=1))
            with store._state() as state:
                lock = h._audit_lock(state, create=False, exclusive=True)
                try:
                    prior = h._audit_snapshot(state, store.limits)
                    event, raw = audit._prepare_private_audit_event(
                        {'event_type': 'EXAMPLE-valid-foreign-rotation'}, state, store.limits, prior)
                    rotate, head, index, seals, before = segments.append_plan(state, store.limits, raw, prior)
                    self.assertTrue(rotate)
                    previous = seals[-1]['event_hash'] if seals else None
                    active, _ = segments._events(before, previous, store.limits)
                    next_head = dict(event_count=len(prior) + 1, event_hash=event['event_hash'],
                        byte_count=len(raw), active_segment=index + 1,
                        sealed_segments=[*seals, segments._seal(index, before, active, previous)])
                    h._write_at(state, segments.JOURNAL, segments._journal_bytes(head, next_head, raw))
                    h._write_at(state, segments.segment_name(index + 1), raw)
                    observed = segments._rotation_pending(state, store.limits)
                    self.assertEqual(observed, (head, next_head, raw, index + 1, False))
                    self.assertEqual(head, q._old_head(manifest))
                    self.assertNotEqual(h._parse(raw), planned)
                    segments._snapshot(state, store.limits, ignored=(segments.segment_name(index + 1),))
                finally:
                    os.close(lock)
            before = (h._identity(store.state_root.stat()), self.image(store.state_root))
            outcome, refusal = None, None
            try:
                outcome = store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = str(error)
            after = (h._identity(store.state_root.stat()), self.image(store.state_root))
            print('EXAMPLE-Q43-RECOVERY-INPUT ' + repr(dict(before=before, after=after,
                returned=outcome, refusal=refusal, planned=planned, foreign_event=event)))
            self.assertEqual(after, before, f'Foreign rotation evidence changed; return={outcome!r}, refusal={refusal!r}')
            self.assertIsNotNone(refusal)
            self.assertTrue((store.root / (first + '.json')).is_file())

    def test_partial_copy_and_post_unlink_failures_restore_only_planned_orphans(self):
        for stage in ('copy', 'unlink'):
            with self.subTest(stage=stage):
                store = h.HostRecordStore.for_tests(self.base / stage)
                first = store.write_record('evaluation', score=1)
                source = self.stray(store)
                original_write, original_move = h._write_at, q._move
                hit = []
                def write(directory, name, raw, **kwargs):
                    if stage == 'copy' and name == 'item-000000' and not hit:
                        hit.append(True)
                        original_write(directory, name, raw[:3], **kwargs)
                        raise KeyboardInterrupt('EXAMPLE partial copy')
                    return original_write(directory, name, raw, **kwargs)
                def move(*args):
                    result = original_move(*args)
                    if stage == 'unlink' and not hit:
                        hit.append(True)
                        raise KeyboardInterrupt('EXAMPLE source already unlinked')
                    return result
                with patch.object(h, '_write_at', side_effect=write), patch.object(q, '_move', side_effect=move):
                    with self.assertRaises(KeyboardInterrupt):
                        store.quarantine_unreferenced()
                self.assertTrue(hit)
                self.assertEqual(source.read_bytes(), b'opaque EXAMPLE bytes')
                self.assertEqual(store.get(first)['score'], 1)
                self.assertFalse((store.state_root / q.PENDING).exists())
                self.assertEqual(self.events(store), [])
                self.assertEqual(store.quarantine_unreferenced()['status'], 'quarantined')

        with self.subTest(original_id='8YG-N013-successful-corrupt-destination'):
            store = h.HostRecordStore.for_tests(self.base / 'successful-corrupt-destination')
            store.write_record('evaluation', score=1)
            source = self.stray(store)
            original_raw = source.read_bytes()
            corrupt = b'X' * len(original_raw)
            original, copied = h._write_at, []
            def corrupt_copy(directory, name, raw, **kwargs):
                if name == 'item-000000' and not copied:
                    result = original(directory, name, corrupt, **kwargs)
                    copied.append(True)
                    return result
                return original(directory, name, raw, **kwargs)
            refusal = None
            with patch.object(h, '_write_at', side_effect=corrupt_copy):
                try:
                    store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    refusal = error
            self.assertTrue(source.is_file(), 'Quarantine unlinked the only intact source after a corrupt copy')
            self.assertEqual(source.read_bytes(), original_raw)
            self.assertTrue(copied)
            destination = next((store.state_root / q.ROOT).glob('tx-*/files/item-000000'))
            self.assertEqual(destination.read_bytes(), corrupt)
            self.assertTrue((store.state_root / q.PENDING).is_file())
            self.assertIsNotNone(refusal)

        with self.subTest(original_id='8YG-N037-successful-corrupt-source-restore'):
            store, _, source, destination, _ = self.descriptor_recovery_input('successful-corrupt-restore')
            good = destination.read_bytes()
            corrupt = b'X' * len(good)
            records_inode = store.root.stat().st_ino
            original, restored = h._write_at, []
            def corrupt_restore(directory, name, raw, **kwargs):
                if name == source.name and os.fstat(directory).st_ino == records_inode and not restored:
                    result = original(directory, name, corrupt, **kwargs)
                    restored.append(True)
                    return result
                return original(directory, name, raw, **kwargs)
            refusal = None
            with patch.object(h, '_write_at', side_effect=corrupt_restore):
                try:
                    store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    refusal = error
            self.assertTrue((store.state_root / q.PENDING).is_file(),
                            'Recovery finalized a corrupt restored source')
            self.assertTrue(restored)
            self.assertEqual(source.read_bytes(), corrupt)
            self.assertEqual(destination.read_bytes(), good)
            self.assertIsNotNone(refusal)

    def crash(self, store, stage):
        child = os.fork()
        if child == 0:
            original_write, original_journal = h._write_at, q._write_journal
            original_move, original_append = q._move, audit._append_private_audit
            original_rotation = segments._write_at
            def journal(state, value, limits, **kwargs):
                result = original_journal(state, value, limits, **kwargs)
                if stage == value['phase']:
                    os._exit(77)
                return result
            def write(directory, name, raw, **kwargs):
                if stage == 'copy' and name == 'item-000000':
                    original_write(directory, name, raw[:3], **kwargs)
                    os._exit(77)
                return original_write(directory, name, raw, **kwargs)
            def move(*args):
                result = original_move(*args)
                if stage == 'unlink':
                    os._exit(77)
                return result
            def append(*args):
                result = original_append(*args)
                if stage == 'committed':
                    os._exit(77)
                return result
            def partial(state, fd, enriched, raw, *args):
                os.write(fd, raw[:len(raw)//2])
                os.fsync(fd)
                os._exit(77)
            def rotation(directory, name, raw, **kwargs):
                selected = ((stage == 'rotation-journal' and name == segments.JOURNAL)
                            or (stage == 'rotation-segment' and name == segments.segment_name(1))
                            or (stage == 'rotation-head' and name == segments.HEAD))
                result = original_rotation(directory, name, raw, **kwargs)
                if selected:
                    os._exit(77)
                return result
            with patch.object(q, '_write_journal', side_effect=journal), \
                 patch.object(h, '_write_at', side_effect=write), patch.object(q, '_move', side_effect=move), \
                 patch.object(audit, '_append_private_audit', side_effect=append), \
                 patch.object(segments, '_write_at', side_effect=rotation):
                if stage == 'partial-audit':
                    with patch.object(audit, '_commit_private_append', side_effect=partial):
                        store.quarantine_unreferenced()
                else:
                    store.quarantine_unreferenced()
            os._exit(78)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 77)

    def test_actual_crash_is_read_only_refused_then_explicitly_recovers_old_or_committed(self):
        stages = ('moving', 'copy', 'unlink', 'appending', 'partial-audit', 'committed',
                  'rotation-journal', 'rotation-segment', 'rotation-head')
        for stage in stages:
            with self.subTest(stage=stage):
                limits = replace(h.RecordLimits(), max_events=1) if stage.startswith('rotation-') else h.RecordLimits()
                store = h.HostRecordStore.for_tests(self.base / stage, limits=limits)
                first = store.write_record('evaluation', score=1)
                source = self.stray(store)
                self.crash(store, stage)
                before = self.image(store.state_root)
                for action in (lambda: store.find('evaluation'), lambda: store.get(first),
                               lambda: store.write_record('evaluation', score=99),
                               lambda: store.record_audit_event({'event_type': 'EXAMPLE forbidden append'})):
                    with self.assertRaisesRegex(h.HostRecordError, 'pending'):
                        action()
                    self.assertEqual(self.image(store.state_root), before)
                committed = stage in ('committed', 'rotation-head')
                result = store.quarantine_unreferenced()
                self.assertEqual(result['status'], 'quarantined' if committed else 'rolled-back')
                self.assertEqual(store.get(first)['score'], 1)
                self.assertEqual(source.exists(), not committed)
                if source.exists():
                    self.assertEqual(source.read_bytes(), b'opaque EXAMPLE bytes')
                self.assertEqual(len(self.events(store)), int(committed))
                self.assertFalse((store.state_root / q.PENDING).exists())
                self.assertFalse((store.state_root / segments.JOURNAL).exists())

        with self.subTest(original_id='8YG-N015-committed-sole-copy-corruption'):
            store, _, source, destination, _ = self.descriptor_recovery_input(
                'committed-sole-copy-corruption', committed=True)
            self.assertFalse(source.exists())
            destination.write_bytes(b'X' * destination.stat().st_size)
            before = self.image(store.state_root)
            refusal = None
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
            self.assertEqual(self.image(store.state_root), before,
                             'Committed recovery finalized despite a corrupt sole copy')
            self.assertIsNotNone(refusal)
            self.assertTrue((store.state_root / q.PENDING).is_file())

    def test_database_initialization_pending_zero_write_and_same_lock_through_commit(self):
        self.stray()
        self.crash(self.store, 'moving')
        database = self.base / 'database'
        database.mkdir(mode=0o700)
        before = self.image(self.base)
        with self.assertRaisesRegex(h.HostRecordError, 'pending'):
            self.store.setup_database_identity(database)
        self.assertEqual(self.image(self.base), before)

        self.assertFalse((database / '.cwo-database-identity.json').exists())
        self.assertEqual(self.store.quarantine_unreferenced()['status'], 'rolled-back')
        self.assertEqual(self.store.quarantine_unreferenced()['status'], 'quarantined')
        original = h._write_at
        writes, modes = [], []
        def locked(directory, name, raw, **kwargs):
            lock = os.open(self.store.state_root / 'audit.jsonl.lock', os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    modes.append((name, 'exclusive'))
                else:
                    modes.append((name, 'shared'))
                    fcntl.flock(lock, fcntl.LOCK_UN)
            finally:
                os.close(lock)
            writes.append(name)
            return original(directory, name, raw, **kwargs)
        with patch.object(h, '_write_at', side_effect=locked):
            identity = self.store.setup_database_identity(database)
        self.assertIn('.cwo-database-identity.json', writes)
        self.assertTrue(any(name.endswith('.json') and len(name) == 69 for name in writes))
        with self.subTest(original_id='8YG-SETUP-EX-LOCK-shared-competitor'):
            self.assertIn(('.cwo-database-identity.json', 'exclusive'), modes)
            self.assertTrue(any(name.endswith('.json') and len(name) == 69 and mode == 'exclusive'
                                for name, mode in modes))
            self.assertFalse(any(mode == 'shared' for _, mode in modes))
        self.assertEqual(self.store.require_database_identity(database), identity)
        self.assertEqual(self.store.setup_database_identity(database), identity)
        unrecorded = self.base / 'unrecorded'
        unrecorded.mkdir(mode=0o700)
        directory, _, physical = self.store._database(unrecorded)
        os.close(directory)
        unrecorded_identity = {'database_id': 'EXAMPLE_unrecorded', **physical}
        path = unrecorded / '.cwo-database-identity.json'
        path.write_bytes(h._json(unrecorded_identity))
        path.chmod(0o600)
        before = self.image(self.base)
        with self.assertRaisesRegex(h.HostRecordError, 'no unique host record'):
            self.store.setup_database_identity(unrecorded)
        self.assertEqual(self.image(self.base), before)

        for mode in ('quarantine', 'recovery'):
            with self.subTest(original_id='8YG-N060-maintenance-EX-' + mode):
                if mode == 'recovery':
                    store, _, _, _, _ = self.descriptor_recovery_input('lock-mode-recovery')
                else:
                    store = h.HostRecordStore.for_tests(self.base / 'lock-mode-quarantine')
                    store.write_record('evaluation', score=1)
                    self.stray(store)
                original, observed = h._write_at, []
                lock_path = store.state_root / 'audit.jsonl.lock'
                def observe_lock(directory, name, raw, **kwargs):
                    if name in ('manifest.json', q.PENDING, 'item-000000', 'outcome.json', 'noise'):
                        fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        try:
                            for label, flag in (('shared', fcntl.LOCK_SH), ('exclusive', fcntl.LOCK_EX)):
                                admitted = False
                                try:
                                    fcntl.flock(fd, flag | fcntl.LOCK_NB)
                                    admitted = True
                                except BlockingIOError:
                                    pass
                                finally:
                                    if admitted:
                                        fcntl.flock(fd, fcntl.LOCK_UN)
                                observed.append((name, label, admitted))
                        finally:
                            os.close(fd)
                    return original(directory, name, raw, **kwargs)
                with patch.object(h, '_write_at', side_effect=observe_lock):
                    result = store.quarantine_unreferenced()
                self.assertEqual(result['status'], 'rolled-back' if mode == 'recovery' else 'quarantined')
                self.assertTrue(observed, 'No actual transaction write boundary was observed')
                self.assertFalse(any(admitted for _, _, admitted in observed),
                                 'A real peer lock was admitted at a maintenance write boundary')
                self.assertFalse((store.state_root / q.PENDING).exists())
                self.assertEqual(len(self.events(store)), int(mode == 'quarantine'))

    def test_committed_confirmation_error_retains_original_fact_without_duplicate_completion(self):
        self.stray()
        original = audit._append_private_audit
        def interrupted(*args):
            original(*args)
            raise KeyboardInterrupt('EXAMPLE confirmation interrupted')
        with patch.object(audit, '_append_private_audit', side_effect=interrupted):
            with self.assertRaisesRegex(h.HostRecordError, 'committed') as failure:
                self.store.quarantine_unreferenced()
        self.assertIsInstance(failure.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(self.store.get(self.first)['score'], 1)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.store.quarantine_unreferenced(), {'status': 'unchanged', 'count': 0})
        self.assertEqual(len(self.events()), 1)

        with self.subTest(original_id='foreign-valid-final-head-input'):
            store, first, manifest, planned = self.pending_recovery_input('foreign-final-head')
            with store._state() as state:
                lock = h._audit_lock(state, create=False, exclusive=True)
                try:
                    # A private recovery-input seam: cooperating public writers
                    # are gated while pending; no such producer origin is claimed.
                    audit._append_private_audit({'event_type': 'EXAMPLE-valid-foreign-head'}, state, store.limits)
                    events = h._audit_snapshot(state, store.limits)
                    self.assertNotEqual(segments.read_head(state), q._old_head(manifest))
                    self.assertNotEqual(events[-1], planned)
                    with q._directory(state, 'records') as directory:
                        q._inventory(state, directory, store.limits, events)
                finally:
                    os.close(lock)
            before = (h._identity(store.state_root.stat()), self.image(store.state_root))
            outcome, refusal = None, None
            try:
                outcome = store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = str(error)
            after = (h._identity(store.state_root.stat()), self.image(store.state_root))
            print('EXAMPLE-Q45-RECOVERY-INPUT ' + repr(dict(before=before, after=after,
                returned=outcome, refusal=refusal, planned=planned, actual_events=events)))
            self.assertEqual(after, before, f'Foreign audit head was attributed as quarantine; return={outcome!r}, refusal={refusal!r}')
            self.assertIsNotNone(refusal)
            self.assertTrue((store.root / (first + '.json')).is_file())

    def test_crash_during_partial_restore_resumes_only_its_proven_bytes(self):
        for foreign in (False, True):
            with self.subTest(foreign=foreign):
                store = h.HostRecordStore.for_tests(self.base / ('restore-' + str(foreign)))
                first = store.write_record('evaluation', score=1)
                source = self.stray(store)
                child = os.fork()
                if child == 0:
                    original_write, original_move = h._write_at, q._move
                    records_inode = store.root.stat().st_ino
                    def write(directory, name, raw, **kwargs):
                        if name == 'noise' and os.fstat(directory).st_ino == records_inode:
                            original_write(directory, name, raw[:3], **kwargs)
                            os._exit(77)
                        return original_write(directory, name, raw, **kwargs)
                    def move(*args):
                        original_move(*args)
                        raise KeyboardInterrupt('EXAMPLE enter proven rollback')
                    with patch.object(h, '_write_at', side_effect=write), patch.object(q, '_move', side_effect=move):
                        store.quarantine_unreferenced()
                    os._exit(78)
                _, status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 77)
                self.assertEqual(source.read_bytes(), b'opa')
                if foreign:
                    source.write_bytes(b'EXAMPLE foreign restoration bytes')
                    before = self.image(store.state_root)
                    with self.assertRaises(h.HostRecordError):
                        store.quarantine_unreferenced()
                    self.assertEqual(self.image(store.state_root), before)
                else:
                    self.assertEqual(store.quarantine_unreferenced()['status'], 'rolled-back')
                    self.assertEqual(source.read_bytes(), b'opaque EXAMPLE bytes')
                    self.assertEqual(store.get(first)['score'], 1)
                    self.assertEqual(self.events(store), [])

        for label, kind in (
                ('8YG-Q23-late-restore-FIFO-queue', 'fifo'),
                ('8YG-Q25-late-restore-mode', 'mode'),
                ('8YG-Q26-late-restore-hardlink', 'hardlink'),
                ('8YG-N010-late-restore-foreign-prefix', 'content')):
            with self.subTest(original_id=label):
                self.late_descriptor_restore_row(label, kind)

    def test_pending_recovery_rechecks_referenced_records_and_sealed_history_before_cleanup(self):
        for kind in ('record', 'sealed-audit'):
            with self.subTest(kind=kind):
                store = h.HostRecordStore.for_tests(self.base / kind,
                    limits=replace(h.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                store.write_record('evaluation', score=2)
                self.stray(store)
                self.crash(store, 'appending')
                target = (store.root / (first + '.json') if kind == 'record' else store.audit_file)
                target.write_bytes(b'EXAMPLE referenced corruption')
                before = self.image(store.state_root)
                with self.assertRaises(h.HostRecordError):
                    store.quarantine_unreferenced()
                self.assertEqual(self.image(store.state_root), before)

    def test_pending_journal_schema_phase_and_path_corruption_preserve_every_inode(self):
        for kind in ('boolean-version', 'boolean-manifest-version', 'boolean-count', 'float-count',
                     'unknown-phase', 'path', 'malformed', 'oversize'):
            with self.subTest(kind=kind):
                store = h.HostRecordStore.for_tests(self.base / kind)
                store.write_record('evaluation', score=1)
                self.stray(store)
                self.crash(store, 'moving')
                path = store.state_root / q.PENDING
                value = json.loads(path.read_bytes())
                if kind == 'boolean-version':
                    value['schema_version'] = True
                elif kind == 'boolean-manifest-version':
                    manifest_path = store.state_root / q.ROOT / ('tx-' + value['transaction']) / 'manifest.json'
                    manifest = json.loads(manifest_path.read_bytes())
                    manifest['schema_version'] = True
                    manifest_raw = h._json(manifest)
                    manifest_path.write_bytes(manifest_raw)
                    value['manifest_sha256'] = hashlib.sha256(manifest_raw).hexdigest()
                    value['event']['quarantine_manifest_sha256'] = value['manifest_sha256']
                    value['event']['event_hash'] = audit.audit_event_payload_hash(value['event'])
                elif kind in ('boolean-count', 'float-count'):
                    value['event']['quarantine_file_count'] = True if kind == 'boolean-count' else 1.0
                    value['event']['event_hash'] = audit.audit_event_payload_hash(value['event'])
                elif kind == 'unknown-phase':
                    value['phase'] = 'EXAMPLE unrecognized phase'
                elif kind == 'path':
                    value['transaction'] = '../EXAMPLE_escape'
                raw = b'{' if kind == 'malformed' else h._json(value)
                if kind == 'oversize':
                    raw = b'x' * (store.limits.max_record_bytes + 1)
                path.write_bytes(raw)
                before = self.image(store.state_root)
                with self.assertRaises(h.HostRecordError):
                    store.quarantine_unreferenced()
                self.assertEqual(self.image(store.state_root), before)

        # Actual per-check survey misses: serialized private recovery inputs,
        # not a claim that a cooperating producer emits malformed transactions.
        cases = ('valid-moving', 'transaction-format', 'manifest-transaction',
                 'record-count', 'duplicate-source', 'scan-bytes', 'entry-shape',
                 'source-component', 'destination-slot', 'identity-type',
                 'record-size', 'event-binding', 'authority-field', 'old-prefix',
                 'boolean-old-length', 'appending-unmoved', 'strict-base64',
                 'control-token', 'old-head-size', 'late-journal-cap')
        for kind in cases:
            with self.subTest(original_id='protocol-' + kind):
                store = self._protocol_pending_fixture(kind)
                before = self.image(store.state_root)
                if kind == 'valid-moving':
                    self.assertEqual(store.quarantine_unreferenced()['status'], 'rolled-back')
                    self.assertFalse((store.state_root / q.PENDING).exists())
                else:
                    with self.assertRaises(h.HostRecordError):
                        store.quarantine_unreferenced()
                    self.assertEqual(self.image(store.state_root), before)

        with self.subTest(original_id='8YG-Q35-manifest-exact-bytes'):
            store = h.HostRecordStore.for_tests(self.base / 'manifest-byte-drift')
            store.write_record('evaluation', score=1)
            self.stray(store)
            self.crash(store, 'moving')
            journal = json.loads((store.state_root / q.PENDING).read_bytes())
            manifest_path = store.state_root / q.ROOT / ('tx-' + journal['transaction']) / 'manifest.json'
            original = manifest_path.read_bytes()
            self.assertEqual(hashlib.sha256(original).hexdigest(), journal['manifest_sha256'])
            manifest_path.write_bytes(original + b' ')
            self.assertEqual(json.loads(manifest_path.read_bytes()), json.loads(original))
            before = self.image(store.state_root)
            refusal = None
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
            self.assertEqual(self.image(store.state_root), before)
            self.assertIsNotNone(refusal)
            self.assertIn('manifest digest differs', str(refusal))


    def _protocol_pending_fixture(self, kind):
        """Stage exact moving/copy/commit bytes; then change one named input."""
        limits = h.RecordLimits()
        if kind == 'old-head-size':
            # Isolate the unchanged head bound with a legal larger record cap;
            # production defaults and MAX_HEAD_BYTES remain unchanged.
            limits = replace(limits, max_record_bytes=2 * segments.MAX_HEAD_BYTES)
        store = h.HostRecordStore.for_tests(self.base / ('protocol-' + kind), limits=limits)
        if kind not in ('boolean-old-length', 'late-journal-cap'):
            store.write_record('evaluation', score=1)
        count = 2 if kind in ('record-count', 'duplicate-source', 'scan-bytes') else 1
        moved = kind not in ('valid-moving', 'source-component', 'control-token',
                             'boolean-old-length', 'appending-unmoved', 'late-journal-cap')
        with store._guarded_state(create=True) as (state, _):
            with q._directory(state, 'records', create=True):
                pass
            for index in range(count):
                self.stray(store, 'noise-' + str(index), b'x' * 2048 if kind == 'scan-bytes'
                           else b'opaque EXAMPLE bytes')
            # Open after staging: Btrfs bounds enumeration at directory open.
            with q._directory(state, 'records') as directory:
                events = h._audit_snapshot(state, limits)
                strays = q._inventory(state, directory, limits, events)
                self.assertEqual(len(strays), count, 'Protocol input must contain every staged stray')
                manifest, raw = q._plan(state, directory, strays, limits)
                event = q._event(state, manifest, raw, limits, events)
                journal = q._journal(manifest, raw, event)
                with q._directory(state, q.ROOT, create=True) as root:
                    name = 'tx-' + manifest['transaction']
                    os.mkdir(name, 0o700, dir_fd=root)
                    with q._directory(root, name) as transaction, \
                         q._directory(transaction, 'files', create=True) as files:
                        h._write_at(transaction, 'manifest.json', raw)
                        q._write_journal(state, journal, limits)
                        if moved:
                            for entry in manifest['files']:
                                q._move(directory, files, entry, limits)
        transaction = store.state_root / q.ROOT / name
        entry = manifest['files'][0]
        if kind == 'transaction-format':
            invalid = 'G' * 32
            new_path = transaction.with_name('tx-' + invalid)
            transaction.rename(new_path)
            transaction = new_path
            manifest['transaction'] = journal['transaction'] = invalid
        elif kind == 'manifest-transaction':
            manifest['transaction'] = 'f' * 32 if journal['transaction'] != 'f' * 32 else 'e' * 32
        elif kind == 'record-count':
            store.limits = replace(limits, max_records=1)
        elif kind == 'duplicate-source':
            manifest['files'][1]['name'] = entry['name']
        elif kind == 'scan-bytes':
            store.limits = replace(limits, max_scan_bytes=512)
        elif kind == 'entry-shape':
            entry['EXAMPLE_unknown'] = 'not-a-protocol-field'
        elif kind == 'source-component':
            outside = store.state_root / 'EXAMPLE_outside_records'
            (store.root / entry['name']).rename(outside)
            entry['name'] = '../EXAMPLE_outside_records'
            entry['identity'] = list(h._identity(outside.stat()))
        elif kind == 'destination-slot':
            old = transaction / 'files' / entry['destination']
            entry['destination'] = 'EXAMPLE_unrecognized_slot'
            old.rename(transaction / 'files' / entry['destination'])
        elif kind == 'identity-type':
            entry['identity'][0] = True
        elif kind == 'record-size':
            entry['identity'][4] = limits.max_record_bytes + 1
        elif kind == 'event-binding':
            journal['event']['event_type'] = 'EXAMPLE_foreign_completion'
        elif kind == 'authority-field':
            journal['event']['host_record_sha256'] = '0' * 64
        elif kind == 'old-prefix':
            manifest['audit_before_sha256'] = '0' * 64
        elif kind == 'boolean-old-length':
            self.assertEqual(manifest['audit_before_bytes'], 0)
            manifest['audit_before_bytes'] = False
        elif kind == 'appending-unmoved':
            journal['phase'] = 'appending'
        elif kind == 'strict-base64':
            manifest['previous_head'] += '!'
        elif kind == 'control-token':
            new_path = store.root / 'EXAMPLE\ncontrol'
            (store.root / entry['name']).rename(new_path)
            entry['name'] = new_path.name
            entry['identity'] = list(h._identity(new_path.stat()))
        elif kind == 'old-head-size':
            head = base64.b64decode(manifest['previous_head'], validate=True)
            manifest['previous_head'] = base64.b64encode(
                head + b' ' * (segments.MAX_HEAD_BYTES + 1 - len(head))).decode()
            journal['phase'] = 'appending'
        raw = h._json(manifest)
        self.assertLessEqual(len(raw), store.limits.max_record_bytes)
        (transaction / 'manifest.json').write_bytes(raw)
        journal['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        journal['event']['quarantine_manifest_sha256'] = journal['manifest_sha256']
        journal['event']['quarantine_transaction_id'] = journal['transaction']
        journal['event']['quarantine_file_count'] = len(manifest['files'])
        journal['event']['event_hash'] = audit.audit_event_payload_hash(journal['event'])
        (store.state_root / q.PENDING).write_bytes(h._json(journal))
        if kind == 'late-journal-cap':
            # A previously durable moving journal may be read under tighter
            # limits. Its later phase still requires the original writer cap.
            cap = len(h._json(journal))
            self.assertLessEqual(len(raw), cap)
            self.assertGreater(len(h._json({**journal, 'phase': 'restoring'})), cap)
            store.limits = replace(limits, max_record_bytes=cap)
        if kind == 'old-head-size':
            # An internally valid committed event tests refusal of its oversized
            # old-head input; public writers remain blocked by pending state.
            with store._state() as state:
                lock = h._audit_lock(state, create=False, exclusive=True)
                try:
                    committed = audit._append_private_audit(journal['event'], state, store.limits)
                finally:
                    os.close(lock)
            self.assertEqual(committed, journal['event'])
        return store

    def test_manifest_journal_and_outcome_write_confirmation_failures_are_honest(self):
        for boundary in ('manifest', 'pending', 'outcome'):
            with self.subTest(boundary=boundary):
                store = h.HostRecordStore.for_tests(self.base / boundary)
                first = store.write_record('evaluation', score=1)
                source = self.stray(store)
                original, hits = h._write_at, []
                def interrupted(directory, name, raw, **kwargs):
                    selected = name == {'manifest': 'manifest.json', 'pending': q.PENDING,
                                        'outcome': 'outcome.json'}[boundary]
                    if selected and not hits:
                        hits.append(True)
                        original(directory, name, raw[:3] if boundary == 'outcome' else raw, **kwargs)
                        raise OSError('EXAMPLE durable write confirmation lost')
                    return original(directory, name, raw, **kwargs)
                with patch.object(h, '_write_at', side_effect=interrupted):
                    with self.assertRaises(h.HostRecordError):
                        store.quarantine_unreferenced()
                self.assertTrue(hits)
                self.assertEqual(store.get(first)['score'], 1)
                self.assertEqual(source.exists(), boundary != 'outcome')
                self.assertEqual(len(self.events(store)), int(boundary == 'outcome'))
                self.assertFalse((store.state_root / q.PENDING).exists())

        with self.subTest(original_id='8YG-Q47-terminal-outcome-foreign-prefix'):
            store = h.HostRecordStore.for_tests(self.base / 'foreign-outcome-prefix')
            store.write_record('evaluation', score=1)
            self.stray(store)
            self.crash(store, 'committed')
            journal = json.loads((store.state_root / q.PENDING).read_bytes())
            outcome = store.state_root / q.ROOT / ('tx-' + journal['transaction']) / 'outcome.json'
            self.assertFalse(outcome.exists())
            outcome.write_bytes(b'BAD')
            outcome.chmod(0o600)
            before = self.image(store.state_root)
            refusal = None
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
            self.assertEqual(self.image(store.state_root), before)
            self.assertIsNotNone(refusal)
            self.assertIn('restore prefix differs', str(refusal))

        with self.subTest(original_id='8YG-N039-corrupt-successful-outcome-completion'):
            store, _, _, _, transaction = self.descriptor_recovery_input(
                'corrupt-successful-outcome-completion', committed=True)
            pending = store.state_root / q.PENDING
            journal = json.loads(pending.read_bytes())
            expected = h._json({'status': 'quarantined', 'transaction': journal['transaction'],
                               'manifest_sha256': journal['manifest_sha256'], 'count': 1})
            outcome = transaction / 'outcome.json'
            outcome.write_bytes(expected[:3])
            outcome.chmod(0o600)
            info = outcome.stat()
            identity = (info.st_dev, info.st_ino)
            original, writes = os.write, []
            def corrupt_outcome(fd, raw):
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == identity and not writes:
                    wrong = b'X' * len(raw)
                    result = original(fd, wrong)
                    writes.append((bytes(raw), wrong, result))
                    return result
                return original(fd, raw)
            refusal = None
            with patch.object(os, 'write', side_effect=corrupt_outcome):
                try:
                    store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    refusal = error
            self.assertTrue(pending.is_file(), 'Recovery finalized corrupt outcome bytes')
            self.assertTrue(writes)
            requested, wrong, count = writes[0]
            self.assertEqual(count, len(requested))
            self.assertEqual(outcome.read_bytes(), expected[:3] + wrong)
            self.assertIsNotNone(refusal)

        for field in ('transaction', 'manifest_sha256'):
            with self.subTest(original_id='8YG-N035-foreign-terminal-pending-' + field):
                store, _, _, _, _ = self.descriptor_recovery_input('foreign-terminal-' + field, committed=True)
                pending = store.state_root / q.PENDING
                foreign = self.foreign_pending_bytes(pending.read_bytes(), field)
                original, inserted = h._write_at, []
                def foreign_owner(directory, name, raw, **kwargs):
                    result = original(directory, name, raw, **kwargs)
                    if name == 'outcome.json' and not inserted:
                        pending.write_bytes(foreign)
                        pending.chmod(0o600)
                        inserted.append(self.image(store.state_root))
                    return result
                refusal = None
                with patch.object(h, '_write_at', side_effect=foreign_owner):
                    try:
                        store.quarantine_unreferenced()
                    except h.HostRecordError as error:
                        refusal = error
                self.assertTrue(inserted)
                self.assertEqual(self.image(store.state_root), inserted[0],
                                 'Terminal cleanup changed a foreign pending owner')
                self.assertEqual(pending.read_bytes(), foreign)
                self.assertIsNotNone(refusal)

        with self.subTest(original_id='8YG-N066-exclusive-initial-pending-claim'):
            store = h.HostRecordStore.for_tests(self.base / 'exclusive-initial-pending-claim')
            store.write_record('evaluation', score=1)
            source = self.stray(store)
            pending = store.state_root / q.PENDING
            original, inserted = h._write_at, []
            def foreign_claim(directory, name, raw, **kwargs):
                if name == q.PENDING and not inserted:
                    foreign = self.foreign_pending_bytes(raw)
                    original(directory, name, foreign)
                    inserted.append((foreign, self.image(store.state_root)))
                return original(directory, name, raw, **kwargs)
            refusal = None
            with patch.object(h, '_write_at', side_effect=foreign_claim):
                try:
                    store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    refusal = error
            self.assertTrue(inserted)
            self.assertEqual(self.image(store.state_root), inserted[0][1],
                             'An initial pending claim overwrote foreign custody')
            self.assertEqual(pending.read_bytes(), inserted[0][0])
            self.assertEqual(source.read_bytes(), b'opaque EXAMPLE bytes')
            self.assertIsNotNone(refusal)

    def test_actual_fsync_failures_restore_noncommit_and_retain_committed_head(self):
        for boundary in ('pending', 'destination', 'source-directory', 'head-directory'):
            with self.subTest(boundary=boundary):
                store = h.HostRecordStore.for_tests(self.base / boundary)
                first = store.write_record('evaluation', score=1)
                source = self.stray(store)
                original_write, original_fsync = h._write_at, os.fsync
                writing, hit = [], []
                record_inode, state_inode = store.root.stat().st_ino, store.state_root.stat().st_ino
                def write(directory, name, raw, **kwargs):
                    writing.append(name)
                    try:
                        return original_write(directory, name, raw, **kwargs)
                    finally:
                        writing.pop()
                def fsync(fd):
                    info = os.fstat(fd)
                    name = writing[-1] if writing else None
                    selected = ((boundary == 'pending' and name == q.PENDING and stat.S_ISREG(info.st_mode))
                        or (boundary == 'destination' and name == 'item-000000' and stat.S_ISREG(info.st_mode))
                        or (boundary == 'source-directory' and info.st_ino == record_inode)
                        or (boundary == 'head-directory' and name == segments.HEAD and info.st_ino == state_inode))
                    if selected and not hit:
                        hit.append(True)
                        if boundary == 'head-directory':
                            original_fsync(fd)
                        raise OSError('EXAMPLE actual fsync boundary failure')
                    return original_fsync(fd)
                with patch.object(h, '_write_at', side_effect=write), patch.object(os, 'fsync', side_effect=fsync):
                    with self.assertRaises(h.HostRecordError):
                        store.quarantine_unreferenced()
                self.assertTrue(hit)
                self.assertEqual(store.get(first)['score'], 1)
                committed = boundary == 'head-directory'
                self.assertEqual(source.exists(), not committed)
                self.assertEqual(len(self.events(store)), int(committed))
                self.assertFalse((store.state_root / q.PENDING).exists())


    def _refusal_preserves(self, store, expected):
        refusal = None
        try:
            store.quarantine_unreferenced()
        except h.HostRecordError as error:
            refusal = error
        self.assertEqual(self.image(store.state_root), expected)
        self.assertIsNotNone(refusal)

    def _row_N005_preflight_replacement_writes_nothing(self):
        store = h.HostRecordStore.for_tests(self.base / 'N005-preflight')
        store.write_record('evaluation', score=1)
        source = self.stray(store)
        original, observed = h._read_at, {}
        def replace_after_read(directory, name, maximum):
            raw = original(directory, name, maximum)
            if name == source.name and not observed:
                source.rename(store.state_root / 'EXAMPLE-retained-original')
                self.stray(store, raw=raw)
                observed['image'] = self.image(store.state_root)
            return raw
        refusal = None
        with patch.object(h, '_read_at', side_effect=replace_after_read):
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
        self.assertIn('image', observed)
        self.assertEqual(self.image(store.state_root), observed['image'])
        self.assertIsNotNone(refusal)
        self.assertFalse((store.state_root / q.ROOT).exists())

    def _row_N007_recovery_replacement_preserves_pending(self):
        store = self._protocol_pending_fixture('valid-moving')
        journal = json.loads((store.state_root / q.PENDING).read_bytes())
        manifest = json.loads((store.state_root / q.ROOT / ('tx-' + journal['transaction']) / 'manifest.json').read_bytes())
        source = store.root / manifest['files'][0]['name']
        raw = source.read_bytes()
        source.rename(store.state_root / 'EXAMPLE-retained-original')
        source.write_bytes(raw)
        source.chmod(0o600)
        self._refusal_preserves(store, self.image(store.state_root))
        self.assertTrue((store.state_root / q.PENDING).is_file())

    def _row_N008_dirty_mapping_bytes_do_not_match_manifest(self):
        store = h.HostRecordStore.for_tests(self.base / 'N008-mapping')
        store.write_record('evaluation', score=1)
        source = self.stray(store, raw=b'A' * 32)
        original, observed = q._source, {}
        with source.open('r+b') as stream, mmap.mmap(stream.fileno(), 0) as mapping:
            # The first write faults the page writable and dirties real metadata.
            # The later dirty-page write must actually retain its stat identity.
            mapping[0] = ord('A')
            def change_before_source(directory, entry, limits, **kwargs):
                if not observed and not kwargs.get('restoring', False):
                    before = h._identity(source.stat())
                    mapping[0] = ord('B')
                    after = h._identity(source.stat())
                    self.assertEqual(after, before, 'A real unchanged-metadata mapping context was not established')
                    self.assertEqual(list(after), entry['identity'])
                    observed['bytes'] = source.read_bytes()
                    observed['image'] = self.image(store.state_root)
                return original(directory, entry, limits, **kwargs)
            refusal = None
            with patch.object(q, '_source', side_effect=change_before_source):
                try:
                    store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    refusal = error
            self.assertIn('image', observed)
            self.assertTrue(source.is_file(), 'Movement unlinked source bytes that differ from its manifest')
            self.assertEqual(source.read_bytes(), observed['bytes'])
            self.assertEqual(self.image(store.state_root), observed['image'])
            self.assertIsNotNone(refusal)

    def _row_N012_replacement_is_not_copied_before_refusal(self):
        store = h.HostRecordStore.for_tests(self.base / 'N012-before-copy')
        store.write_record('evaluation', score=1)
        source = self.stray(store)
        original, observed = q._open_verified_file, {}
        def replace_before_open(directory, name, expected, maximum, **kwargs):
            if name == source.name and not observed:
                source.rename(store.state_root / 'EXAMPLE-retained-original')
                self.stray(store, raw=expected)
                observed['image'] = self.image(store.state_root)
            return original(directory, name, expected, maximum, **kwargs)
        refusal = None
        with patch.object(q, '_open_verified_file', side_effect=replace_before_open):
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
        self.assertIn('image', observed)
        self.assertEqual(self.image(store.state_root), observed['image'])
        self.assertIsNotNone(refusal)
        self.assertFalse(list((store.state_root / q.ROOT).glob('tx-*/files/item-*')))

    def _row_N033_wrong_phase_preserves_planned_partial_tail(self):
        store, _, _, event = self.pending_recovery_input('N033-wrong-phase')
        path = store.state_root / q.PENDING
        journal = json.loads(path.read_bytes())
        journal['phase'] = 'moving'
        path.write_bytes(h._json(journal))
        raw = (json.dumps(event, sort_keys=True) + '\n').encode()
        with store.audit_file.open('ab') as stream:
            stream.write(raw[:len(raw) // 2])
        self._refusal_preserves(store, self.image(store.state_root))

    def _row_N034_missing_active_after_checkpoint_preserves_state(self):
        store, _, _, _ = self.pending_recovery_input('N034-missing-active')
        original, observed = q._restore_tail, {}
        def remove_after_check(state, head, before, current, journal, limits):
            name = segments.segment_name(segments.layout(head)[0])
            (store.state_root / name).rename(store.state_root / 'EXAMPLE-retained-active')
            observed['image'] = self.image(store.state_root)
            return original(state, head, before, current, journal, limits)
        refusal = None
        with patch.object(q, '_restore_tail', side_effect=remove_after_check):
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
        self.assertIn('image', observed)
        self.assertEqual(self.image(store.state_root), observed['image'])
        self.assertIsNotNone(refusal)

    def _row_N036_late_bad_copy_is_not_restored(self):
        store, _, source, destination, _ = self.descriptor_recovery_input('N036-bad-copy')
        original, observed = q._restore_sources, {}
        corrupt = b'X' * destination.stat().st_size
        def corrupt_before_restore(directory, files, manifest, limits):
            destination.write_bytes(corrupt)
            observed['image'] = self.image(store.state_root)
            return original(directory, files, manifest, limits)
        refusal = None
        with patch.object(q, '_restore_sources', side_effect=corrupt_before_restore):
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
        self.assertIn('image', observed)
        self.assertFalse(source.exists(), 'Recovery wrote a copy that no longer matches its manifest')
        self.assertEqual(self.image(store.state_root), observed['image'])
        self.assertIsNotNone(refusal)

    def _row_N038_one_zero_write_refuses_without_progress(self):
        prefix = b'opa'
        store, _, source, destination, _ = self.descriptor_recovery_input('N038-zero-write', prefix=prefix)
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        original, observed = os.write, {}
        def one_zero(fd, raw):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == source_identity and not observed:
                observed['image'] = self.image(store.state_root)
                return 0
            return original(fd, raw)
        refusal = None
        with patch.object(q.os, 'write', side_effect=one_zero):
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
        self.assertIn('image', observed)
        self.assertEqual(source.read_bytes(), prefix, 'A zero-result write must refuse before a later successful write')
        self.assertEqual(self.image(store.state_root), observed['image'])
        self.assertIsNotNone(refusal)
        self.assertTrue((store.state_root / q.PENDING).is_file())

    def _row_N057_late_symlink_cannot_read_outside_bytes(self):
        store = h.HostRecordStore.for_tests(self.base / 'N057-read-link')
        store.write_record('evaluation', score=1)
        source = self.stray(store)
        outside = self.base / 'EXAMPLE-outside-private'
        outside.write_bytes(b'X' * source.stat().st_size)
        outside.chmod(0o600)
        original_open, original_read, observed = q._open_verified_file, q._read_descriptor, {}
        outside_reads = []
        def replace_before_open(directory, name, expected, maximum, **kwargs):
            if name == source.name and not observed:
                source.rename(store.state_root / 'EXAMPLE-retained-original')
                source.symlink_to(outside)
                observed['image'] = self.image(store.state_root)
            return original_open(directory, name, expected, maximum, **kwargs)
        def observe_real_read(fd, maximum):
            target = os.readlink('/proc/self/fd/' + str(fd))
            raw = original_read(fd, maximum)
            if target == str(outside):
                outside_reads.append(raw)
            return raw
        refusal = None
        with patch.object(q, '_open_verified_file', side_effect=replace_before_open), \
                patch.object(q, '_read_descriptor', side_effect=observe_real_read):
            try:
                store.quarantine_unreferenced()
            except h.HostRecordError as error:
                refusal = error
        self.assertIn('image', observed)
        self.assertEqual(outside_reads, [], 'Maintenance read actual bytes through a late outside symlink')
        self.assertEqual(self.image(store.state_root), observed['image'])
        self.assertEqual(outside.read_bytes(), b'X' * outside.stat().st_size)
        self.assertIsNotNone(refusal)

    def _bounded_fifo_open(self, stage):
        store = h.HostRecordStore.for_tests(self.base / ('bounded-fifo-' + stage))
        store.write_record('evaluation', score=1)
        source = self.stray(store)
        fifo = store.state_root / q.ROOT if stage == 'directory' else source
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                original = q._open_verified_file
                def late(directory, name, expected, maximum, **kwargs):
                    if name == source.name and not fifo.is_fifo():
                        source.rename(store.state_root / 'EXAMPLE-retained-original')
                        os.mkfifo(fifo, 0o600)
                        os.write(write_fd, b'R')
                    return original(directory, name, expected, maximum, **kwargs)
                if stage == 'directory':
                    os.mkfifo(fifo, 0o700)
                    os.write(write_fd, b'R')
                try:
                    with patch.object(q, '_open_verified_file', side_effect=late):
                        result = store.quarantine_unreferenced()
                except h.HostRecordError as error:
                    result = {'status': 'refused', 'message': str(error)}
                os.write(write_fd, b'F' + json.dumps(result).encode() + b'\n')
                os._exit(0)
            except BaseException:
                try:
                    os.write(write_fd, b'E' + traceback.format_exc().encode()[:2000])
                finally:
                    os._exit(1)
        os.close(write_fd)
        completed, result, status, release = False, b'', None, None
        try:
            self.assertTrue(select.select([read_fd], [], [], 5)[0], 'Owned FIFO fixture did not reach its boundary')
            self.assertEqual(os.read(read_fd, 1), b'R')
            before = self.image(store.state_root)
            completed = bool(select.select([read_fd], [], [], 5)[0])
            if not completed:
                # Release only this owned fixture's reader, retaining a parent
                # assertion failure rather than an outer controller timeout.
                release = os.open(fifo, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.assertTrue(select.select([read_fd], [], [], 5)[0], 'Owned FIFO fixture did not finish after release')
            result = os.read(read_fd, 4096)
            deadline = time.monotonic() + 5
            while status is None:
                waited, observed_status = os.waitpid(child, os.WNOHANG)
                if waited:
                    status = observed_status
                else:
                    self.assertLess(time.monotonic(), deadline, 'Owned FIFO fixture did not exit')
                    time.sleep(0.01)
            self.assertTrue(completed, 'A real unexpected FIFO blocked before regular-file refusal')
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, result.decode(errors='replace'))
            self.assertTrue(result.startswith(b'F'), result.decode(errors='replace'))
            self.assertEqual(json.loads(result[1:])['status'], 'refused')
            self.assertEqual(self.image(store.state_root), before)
        finally:
            if release is None and fifo.is_fifo():
                release = os.open(fifo, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            if release is not None:
                os.close(release)
            os.close(read_fd)
            if status is None:
                deadline = time.monotonic() + 5
                while status is None and time.monotonic() < deadline:
                    waited, observed_status = os.waitpid(child, os.WNOHANG)
                    if waited:
                        status = observed_status
                    else:
                        time.sleep(0.01)
                if status is None:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)

    def _row_N058_directory_fifo_is_bounded(self):
        self._bounded_fifo_open('directory')

    def _row_N059_late_readonly_fifo_is_bounded(self):
        self._bounded_fifo_open('source')


    def test_ordering_and_recovery_behavioral_rows(self):
        """Named rows use real store state and bounded private seams."""
        rows = (
            ('8YG-N005', self._row_N005_preflight_replacement_writes_nothing),
            ('8YG-N007', self._row_N007_recovery_replacement_preserves_pending),
            ('8YG-N008', self._row_N008_dirty_mapping_bytes_do_not_match_manifest),
            ('8YG-N012', self._row_N012_replacement_is_not_copied_before_refusal),
            ('8YG-N033', self._row_N033_wrong_phase_preserves_planned_partial_tail),
            ('8YG-N034', self._row_N034_missing_active_after_checkpoint_preserves_state),
            ('8YG-N036', self._row_N036_late_bad_copy_is_not_restored),
            ('8YG-N038', self._row_N038_one_zero_write_refuses_without_progress),
            ('8YG-N057', self._row_N057_late_symlink_cannot_read_outside_bytes),
            ('8YG-N058', self._row_N058_directory_fifo_is_bounded),
            ('8YG-N059', self._row_N059_late_readonly_fifo_is_bounded),
        )
        for original_id, row in rows:
            with self.subTest(original_id=original_id):
                row()


if __name__ == '__main__':
    unittest.main()
