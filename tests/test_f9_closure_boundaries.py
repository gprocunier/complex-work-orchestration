"""Late closure custody checks, using inert EXAMPLE and fake Beads boundaries."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_qualified_closure as closure_fixtures
import qualified_closure as qualified

original = qualified.original


class F9ClosureBoundaries(unittest.TestCase):
    def builders(self):
        fixture = closure_fixtures.QualifiedClosureTests('runTest')
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_F9_84face561514d88c_530c35f70f984e49_custody_canonical_before_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / 'actual'
            actual.mkdir(mode=0o700)
            child = actual / 'child'
            child.mkdir(mode=0o700)
            alias = root / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            descriptor = qualified._directory(child)
            os.close(descriptor)
            with patch.object(qualified.fcntl, 'flock') as flock:
                for path in (Path('EXAMPLE-relative'), alias / 'child'):
                    with self.subTest(path=str(path)), self.assertRaises(original.ClosureError):
                        qualified._directory(path)
                flock.assert_not_called()

    def test_F9_ee9f4d5c157ba03b_029afd7e0e9a43d6_postread_identity_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'contract.json'
            path.write_bytes(b'EXAMPLE immutable control')
            path.chmod(0o600)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, directory)
            self.assertEqual(qualified._read_at(directory, path.name), path.read_bytes())
            real = os.fstat
            for field in ('st_ino', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
                count = 0
                def metadata(fd):
                    nonlocal count
                    info = real(fd)
                    values = {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    count += 1
                    if count == 2:
                        values[field] += 1
                    return SimpleNamespace(**values)
                with self.subTest(field=field), patch.object(qualified.os, 'fstat', side_effect=metadata), \
                        self.assertRaisesRegex(original.ClosureError, 'changed while reading'):
                    qualified._read_at(directory, path.name)

    def test_F9_9ce1ef0ac5bbc2d7_example_database_and_actor_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            bridge = qualified.ExampleBeadsBridge({'id': 'EXAMPLE_TASK', 'comments': [], 'status': 'open'}, Path(temporary))
            prefix = ['--db', bridge.database, '--actor', 'EXAMPLE-qualified-closure']
            self.assertIn('EXAMPLE_TASK', bridge(prefix + ['show', '--json', '--include-comments', '--', 'EXAMPLE_TASK']))
            for index in (1, 3):
                changed = list(prefix)
                changed[index] = 'EXAMPLE-other'
                before = copy.deepcopy(bridge.bead)
                with self.subTest(index=index), self.assertRaises(original.ClosureError):
                    bridge(changed + ['comment', '--', 'EXAMPLE_TASK', 'EXAMPLE summary'])
                self.assertEqual(bridge.bead, before)
                self.assertEqual(bridge.effects, [])

    def test_F9_12335666120d363e_interrupted_retirement_blocks_queued_operation(self):
        fixture = self.builders()
        case = fixture.compact()
        with fixture.registered(case) as (host, effects, _directory):
            state = qualified._state(host)
            with qualified._operation(host):
                pass  # Active registration is a reachable positive control.
            original_lock = state.lock
            released, finished = threading.Event(), threading.Event()
            failures = []
            class InterruptedLock:
                def __enter__(self):
                    original_lock.acquire()
                    return self
                def __exit__(self, kind, _value, _traceback):
                    original_lock.release()
                    if kind is KeyboardInterrupt:
                        released.set()
                        if not finished.wait(5):
                            raise AssertionError('EXAMPLE queued operation did not finish')
            state.lock = InterruptedLock()
            real_freeze = original._freeze
            interrupted = False
            def freeze(value):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt('EXAMPLE retirement interruption')
                return real_freeze(value)
            def queued():
                try:
                    if not released.wait(5):
                        raise AssertionError('EXAMPLE retirement did not release')
                    qualified.observe(host)
                except BaseException as error:
                    failures.append(error)
                finally:
                    finished.set()
            worker = threading.Thread(target=queued)
            worker.start()
            with patch.object(original, '_freeze', side_effect=freeze), \
                    patch.object(qualified, '_guard', side_effect=AssertionError('EXAMPLE retired operation reached guard')) as guard:
                with self.assertRaises(KeyboardInterrupt):
                    qualified._retire(host, state, None)
                worker.join(5)
                self.assertFalse(worker.is_alive())
                guard.assert_not_called()
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], original.ClosureError)
            self.assertIn('retired', str(failures[0]))
            self.assertEqual(effects.effects, [])
            self.assertNotIn(host, qualified._registry)

    def test_F9_98303f257698e928_native_root_identity_at_guard(self):
        fixture = self.builders()
        case = fixture.compact()
        with fixture.registered(case) as (host, effects, directory):
            state = qualified._state(host)
            root = directory / 'EXAMPLE-native-root'
            root.mkdir(mode=0o700)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, descriptor)
            state.native_roots = ((str(root), descriptor, qualified._identity(os.fstat(descriptor))),)
            qualified._guard(state)
            root.rename(directory / 'EXAMPLE-old-root')
            root.mkdir(mode=0o700)
            with self.assertRaisesRegex(original.ClosureError, 'native prerequisite root identity'):
                qualified._guard(state)
            self.assertEqual(effects.effects, [])

    def test_F9_93a68daa49645439_production_class_adapter_remains_original(self):
        fake = Mock(return_value='EXAMPLE response')
        with patch.object(qualified, 'PRODUCTION_CLOSURE_AVAILABLE', True), patch.object(qualified, '_BEADS_CALL', fake):
            bridge = qualified._ProductionBeadsBridge(Path('/EXAMPLE/database'), 'EXAMPLE-actor')
            state = SimpleNamespace(bridge=bridge, retired=False, authority=SimpleNamespace(check=Mock()))
            self.assertEqual(qualified._bd(state, ['show']), 'EXAMPLE response')
            before = fake.call_count
            replacement = Mock(return_value='EXAMPLE wrong adapter')
            with patch.object(qualified._ProductionBeadsBridge, '__call__', replacement), \
                    self.assertRaisesRegex(original.ClosureError, 'original production Beads adapter'):
                qualified._bd(state, ['close'])
            replacement.assert_not_called()
            self.assertEqual(fake.call_count, before)
        self.assertIs(qualified.PRODUCTION_CLOSURE_AVAILABLE, False)

    def test_F9_749efac02a0615e2_observation_is_single_use(self):
        fixture = self.builders()
        case = fixture.compact()
        with fixture.registered(case) as (host, effects, _directory):
            observed = qualified.observe(host)
            with patch.object(original, 'observe') as producer, patch.object(original, 'observe_mixed') as mixed, \
                    self.assertRaisesRegex(original.ClosureError, 'single use'):
                qualified.observe(host)
            producer.assert_not_called()
            mixed.assert_not_called()
            self.assertIs(qualified._state(host).observation, observed)
            self.assertEqual(effects.effects, [])

    def test_F9_1dbc2573ca95a09b_final_bind_guard_before_task_read(self):
        fixture = self.builders()
        case = fixture.compact()
        with fixture.registered(case) as (host, effects, directory):
            binder = original.bind_review
            reads_at_change = []
            with patch.object(qualified, '_task', wraps=qualified._task) as task:
                def changing(*args):
                    result = binder(*args)
                    reads_at_change.append(task.call_count)
                    path = directory / 'contract.json'
                    path.write_bytes(path.read_bytes() + b' ')
                    return result
                with patch.object(original, 'bind_review', side_effect=changing), \
                        self.assertRaisesRegex(original.ClosureError, 'baseline, task or candidate changed'):
                    fixture.reviewed(case, host, directory)
                self.assertEqual(task.call_count, reads_at_change[0])
            self.assertEqual(effects.effects, [])
