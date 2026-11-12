"""Launch boundaries use fake transports and never select ambient Codex state."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from cwo_core import native_live_availability as availability
from cwo_core import codex_tool_surface as surface
from cwo_core.supervision.transport import app_server as raw
import registered_app_server_transport as registered


class _FakeLaunchReached(RuntimeError):
    pass


class R5TransportLaunchTests(unittest.TestCase):
    def test_r5_raw_default_refuses_and_explicit_launch_ignores_ambient_home_and_path(self):
        with (
            mock.patch.object(availability, 'N1_LIVE_AVAILABLE', True),
            mock.patch.dict(os.environ, CODEX_HOME='/EXAMPLE/inherited-home', PATH='/EXAMPLE/inherited-bin'),
            mock.patch.object(raw, '_codex_binary') as find,
            mock.patch.object(raw, 'prepare_capture_binding') as prepare,
            mock.patch.object(raw.Path, 'home', side_effect=AssertionError('Unexpected ambient home lookup')),
            mock.patch.object(raw.subprocess, 'Popen', side_effect=_FakeLaunchReached) as launch,
        ):
            for settings in ({}, {'tool_surface_probe_catalog': Path('/EXAMPLE/catalog.json')},
                             {'executable': '/EXAMPLE/bin/codex'}, {'codex_home': '/EXAMPLE/home'},
                             {'executable': 'codex', 'codex_home': '/EXAMPLE/home'},
                             {'executable': '/EXAMPLE/bin/codex', 'codex_home': 'relative-home'}):
                with self.subTest(settings=settings), self.assertRaisesRegex(
                        raw.AppServerError, 'app-server-explicit-launch-required') as caught:
                    raw.AppServer(**settings)
                self.assertEqual(caught.exception.app_server_cleanup,
                                 {'all_contained': True, 'resources_closed': True, 'errors': []})
            find.assert_not_called()
            prepare.assert_not_called()
            launch.assert_not_called()
            with self.assertRaises(_FakeLaunchReached):
                raw.AppServer(executable='/EXAMPLE/bin/codex', codex_home='/EXAMPLE/isolated-home')
            self.assertEqual(launch.call_args.args[0], ['/EXAMPLE/bin/codex', 'app-server', '--stdio'])
            self.assertEqual(launch.call_args.kwargs['env']['CODEX_HOME'], '/EXAMPLE/isolated-home')
            self.assertEqual(launch.call_args.kwargs['env']['PATH'], '/EXAMPLE/bin')
            # An explicitly requested probe may not silently choose another binary.
            prepare.return_value = {'codex_binary': '/EXAMPLE/different-codex'}
            with self.assertRaisesRegex(raw.AppServerError, 'app-server-explicit-executable-mismatch'):
                raw.AppServer(executable='/EXAMPLE/bin/codex', codex_home='/EXAMPLE/isolated-home',
                              tool_surface_probe_catalog=Path('/EXAMPLE/catalog.json'))
            self.assertEqual(launch.call_count, 1)
            # Recheck the live hold immediately before this explicitly injected fake launch.
            def close_hold(*args):
                availability.N1_LIVE_AVAILABLE = False
                return Path('/EXAMPLE/isolated-home')
            with mock.patch.object(raw, '_explicit_launch_home', side_effect=close_hold), self.assertRaises(
                    availability.NativeLiveUnavailable):
                raw.AppServer(executable='/EXAMPLE/bin/codex', codex_home='/EXAMPLE/isolated-home')
            self.assertEqual(launch.call_count, 1)

    def test_r5_real_probe_helper_refuses_mismatch_before_reads_and_pins_matching_version_home(self):
        """The actual capture helper makes zero unselected process calls."""
        from contextlib import ExitStack
        import subprocess
        with ExitStack() as stack:
            binary = Path('/EXAMPLE/selected/codex')
            find = stack.enter_context(mock.patch.object(surface, '_codex_binary', return_value=Path('/EXAMPLE/ambient/codex')))
            config = stack.enter_context(mock.patch.object(surface, '_load_user_config', return_value=({}, '0' * 64)))
            catalog = stack.enter_context(mock.patch.object(surface, '_catalog_snapshot', return_value={'sha256': '0' * 64, 'entry_sha256': '0' * 64}))
            stack.enter_context(mock.patch.object(surface, '_lockdown_from_snapshot', return_value={}))
            stack.enter_context(mock.patch.object(surface, '_catalog_projection', return_value=(Path('/EXAMPLE/projection.json'), '0' * 64)))
            fingerprint = stack.enter_context(mock.patch.object(surface, 'file_sha256', return_value='0' * 64))
            version = stack.enter_context(mock.patch.object(surface.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='codex-cli EXAMPLE\n', stderr='')))
            with self.assertRaisesRegex(raw.AppServerError, 'app-server-explicit-executable-mismatch'):
                raw._explicit_probe_binding(binary, '/EXAMPLE/home', 'EXAMPLE_MODEL', Path('/EXAMPLE/projection.json'))
            for effect in (config, catalog, fingerprint, version):
                effect.assert_not_called()
            find.return_value = binary
            binding = raw._explicit_probe_binding(binary, '/EXAMPLE/home', 'EXAMPLE_MODEL', Path('/EXAMPLE/projection.json'))
            self.assertEqual(binding['codex_binary'], str(binary))
            self.assertEqual(version.call_args.args[0], [str(binary), '--version'])
            self.assertEqual(version.call_args.kwargs['env']['CODEX_HOME'], '/EXAMPLE/home')
            self.assertEqual(version.call_args.kwargs['env']['PATH'], str(binary.parent) + os.pathsep + os.defpath)
            # Revalidation also rejects an injected capture binding.
            find.return_value = Path('/EXAMPLE/ambient/codex')
            for effect in (config, catalog, fingerprint, version):
                effect.reset_mock()
            with self.assertRaisesRegex(surface.CodexToolSurfaceError, 'codex-capture-binding-drift:codex_binary'):
                surface.require_capture_binding(binding)
            for effect in (config, catalog, fingerprint, version):
                effect.assert_not_called()

    def test_r5_registered_base_probe_refuses_before_home_version_or_config_reads(self):
        with (
            mock.patch.object(registered.RegisteredAppServer, '_requested_home') as home,
            mock.patch.object(registered, 'prepare_capture_binding') as prepare,
            mock.patch.object(raw.subprocess, 'run') as version,
            mock.patch.object(raw.subprocess, 'Popen') as launch,
        ):
            with self.assertRaisesRegex(raw.AppServerError, 'registered-app-server-launcher-required'):
                registered.RegisteredAppServer(tool_surface_probe_catalog=Path('/EXAMPLE/catalog.json'))
            home.assert_not_called()
            prepare.assert_not_called()
            version.assert_not_called()
            launch.assert_not_called()
