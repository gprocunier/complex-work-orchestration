"""Offline reliability checks for the worker surface transport imports."""

from __future__ import annotations

import builtins
from contextlib import contextmanager, redirect_stdout
import importlib
import io
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CONSUMER = "check_codex_worker_surface"
FACADE = "run_native_pool_live_canaries"
APP_SERVER = "cwo_core.supervision.transport.app_server"
ERRORS = "cwo_core.supervision.transport.errors"
_MISSING = object()


@contextmanager
def fresh_consumer(*, fresh_facade=False):
    """Restore the consumer cache and search path after each reliability check."""
    saved_path = sys.path[:]
    names = (CONSUMER, FACADE) if fresh_facade else (CONSUMER,)
    saved_modules = {name: sys.modules.pop(name, _MISSING) for name in names}
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        yield importlib.import_module(CONSUMER)
    finally:
        for name in names:
            sys.modules.pop(name, None)
            if saved_modules[name] is not _MISSING:
                sys.modules[name] = saved_modules[name]
        sys.path[:] = saved_path


class WorkerSurfaceTransportImportTests(unittest.TestCase):
    def setUp(self):
        with fresh_consumer() as consumer:
            self.enterContext(mock.patch.object(consumer.live_availability, 'N1_LIVE_AVAILABLE', True))

    def test_import_uses_owners_when_facade_is_unavailable(self):
        real_import = builtins.__import__

        def unavailable(name, globals=None, locals=None, fromlist=(), level=0):
            if name == FACADE:
                raise ModuleNotFoundError(
                    "EXAMPLE legacy facade is unavailable", name=name
                )
            return real_import(name, globals, locals, fromlist, level)

        with mock.patch.object(builtins, "__import__", unavailable):
            with self.assertRaises(ModuleNotFoundError) as blocked:
                __import__(FACADE)
            self.assertEqual(blocked.exception.name, FACADE)
            with fresh_consumer() as consumer:
                self.assertIs(
                    consumer.AppServer, importlib.import_module(APP_SERVER).AppServer
                )
                self.assertIs(
                    consumer.AppServerError, importlib.import_module(ERRORS).AppServerError
                )

    def test_facade_keeps_the_same_owning_objects(self):
        with fresh_consumer(fresh_facade=True) as consumer:
            facade = importlib.import_module(FACADE)
            app_server = importlib.import_module(APP_SERVER)
            errors = importlib.import_module(ERRORS)
            self.assertIs(facade.AppServer, app_server.AppServer)
            self.assertIs(facade.AppServerError, errors.AppServerError)
            self.assertIs(consumer.AppServer, facade.AppServer)
            self.assertIs(consumer.AppServerError, facade.AppServerError)

    def test_facade_identity_is_independent_of_prior_mocked_cache_and_restores_it(self):
        cached = ModuleType(FACADE)
        cached.AppServer = mock.Mock(name="EXAMPLE cached fake server")
        cached.AppServerError = mock.Mock(name="EXAMPLE cached fake error")
        original_server, original_error = cached.AppServer, cached.AppServerError
        original_path = sys.path[:]
        with mock.patch.dict(sys.modules, {FACADE: cached}):
            self.test_facade_keeps_the_same_owning_objects()
            self.assertIs(sys.modules[FACADE], cached)
            self.assertIs(cached.AppServer, original_server)
            self.assertIs(cached.AppServerError, original_error)
            self.assertEqual(sys.path, original_path)

    def test_capture_preserves_the_owning_error_and_cleanup(self):
        with fresh_consumer() as consumer:
            errors = importlib.import_module(ERRORS)
            failure = errors.AppServerError("EXAMPLE endpoint inventory failure")
            home = Path("EXAMPLE_CODEX_HOME")
            binding = {
                "codex_home": str(home),
                "codex_binary": "EXAMPLE_CODEX_BINARY",
                "lockdown_config_sha256": consumer.canonical_sha256({}),
            }
            started = {
                "model": "EXAMPLE_MODEL",
                "modelProvider": "cwo-loopback-probe",
                "approvalPolicy": "never",
                "sandbox": {"type": "workspaceWrite", "networkAccess": False},
                "thread": {"id": "EXAMPLE_THREAD"},
            }
            cleanup = {
                "all_contained": True, "resources_closed": True, "errors": []
            }
            server = mock.Mock(
                codex_home=home,
                launched_executable="EXAMPLE_CODEX_BINARY",
                started_threads={},
            )
            server.request.return_value = (started, 0.0)
            server.require_zero_mcp_endpoints.side_effect = failure
            server.close.return_value = cleanup
            endpoint = mock.Mock(server_address=("EXAMPLE_OFFLINE_ENDPOINT", 0))
            endpoint.socket.fileno.return_value = -1
            worker_thread = mock.Mock(ident=None)
            worker_thread.is_alive.return_value = False
            threads = SimpleNamespace(
                Event=consumer.threading.Event,
                Thread=mock.Mock(return_value=worker_thread),
                current_thread=consumer.threading.current_thread,
            )
            workspace = mock.Mock()
            workspace.name = "EXAMPLE_WORKSPACE"
            folders = SimpleNamespace(
                TemporaryDirectory=mock.Mock(return_value=workspace)
            )
            evidence = {}
            with (
                mock.patch.object(consumer, "prepare_capture_binding", return_value=binding),
                mock.patch.object(consumer, "probe_thread_config", return_value={}),
                mock.patch.object(consumer, "ThreadingHTTPServer", return_value=endpoint),
                mock.patch.object(consumer, "threading", threads),
                mock.patch.object(consumer, "tempfile", folders),
                mock.patch.object(consumer, "AppServer", return_value=server) as construct,
            ):
                with self.assertRaises(errors.AppServerError) as caught:
                    consumer.capture_tool_request(
                        codex_home=home,
                        requested_model="EXAMPLE_MODEL",
                        timeout_seconds=0.01,
                        evidence=evidence,
                    )
            self.assertIs(caught.exception, failure)
            self.assertIs(consumer.AppServerError, errors.AppServerError)
            construct.assert_called_once_with(
                requested_model="EXAMPLE_MODEL", tool_surface_probe_binding=binding
            )
            server.request.assert_called_once()
            self.assertEqual(server.request.call_args.args[0], "thread/start")
            server.require_zero_mcp_endpoints.assert_called_once_with("EXAMPLE_THREAD")
            self.assertEqual(server.started_threads, {"EXAMPLE_THREAD": None})
            server.close.assert_called_once_with()
            endpoint.server_close.assert_called_once_with()
            worker_thread.start.assert_called_once_with()
            workspace.cleanup.assert_called_once_with()
            self.assertEqual(evidence["process_cleanup"], cleanup)
            self.assertEqual(failure.app_server_cleanup, cleanup)
            self.assertEqual(
                evidence["probe_cleanup"],
                {
                    "all_contained": True,
                    "serving_thread_stopped": True,
                    "listener_closed": True,
                    "errors": [],
                },
            )
            self.assertIs(failure.probe_cleanup, evidence["probe_cleanup"])

    def test_main_reports_the_owning_error_as_failure(self):
        with fresh_consumer() as consumer:
            errors = importlib.import_module(ERRORS)
            failure = errors.AppServerError("EXAMPLE transport failure")
            failure.app_server_cleanup = {
                "all_contained": True, "resources_closed": True, "errors": []
            }
            output = io.StringIO()
            arguments = [
                "EXAMPLE_WORKER_SURFACE",
                "--output", "EXAMPLE_OUTPUT.json",
                "--codex-home", "EXAMPLE_CODEX_HOME",
            ]
            with (
                mock.patch.object(consumer.sys, "argv", arguments),
                mock.patch.object(
                    consumer, "capture_tool_request", side_effect=failure
                ) as capture,
                mock.patch.object(consumer, "_write_private_json") as write,
                redirect_stdout(output),
            ):
                status = consumer.main()
            self.assertEqual(status, 1)
            report = json.loads(output.getvalue())
            self.assertIs(report["accepted"], False)
            self.assertEqual(report["error_type"], "AppServerError")
            self.assertEqual(report["error"], str(failure))
            self.assertEqual(report["app_server_cleanup"], failure.app_server_cleanup)
            capture.assert_called_once()
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
