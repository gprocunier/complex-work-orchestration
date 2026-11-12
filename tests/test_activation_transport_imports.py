"""Check reliable activation imports without starting held effects."""

from __future__ import annotations

from contextlib import ExitStack
import importlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from types import ModuleType
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FACADE = "run_native_pool_live_canaries"
PREVIEW = "run_native_pool_activation_preview"


class _FacadeWithoutMovedTransport(ModuleType):
    """Preserve real facade exports while refusing the migrated names."""

    def __init__(self, facade: ModuleType) -> None:
        super().__init__(facade.__name__, facade.__doc__)
        self._facade = facade

    def __getattribute__(self, name: str):
        if name in {"AppServer", "AppServerError"}:
            raise AttributeError(name)
        facade = ModuleType.__getattribute__(self, "_facade")
        return getattr(facade, name)


def _old_preview_transport_import() -> tuple[type, type]:
    """Exercise the former import as a failure check for the proxy."""

    from run_native_pool_live_canaries import AppServer, AppServerError

    return AppServer, AppServerError


class ActivationTransportImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.dict(sys.modules))
        self.stack.enter_context(mock.patch.object(sys, "path", sys.path[:]))
        sys.path.insert(0, str(ROOT / "scripts"))
        self.effects: list[mock.Mock] = []
        self._block(subprocess, "Popen", "run")
        self._block(os, "system", "fork", "posix_spawn", "posix_spawnp")
        self._block(threading.Thread, "start")
        self._block(
            socket,
            "create_connection",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "gethostbyaddr",
        )
        self._block(
            socket.socket,
            "connect",
            "connect_ex",
            "send",
            "sendall",
            "sendto",
            "sendmsg",
        )
        self.app_server = importlib.import_module(
            "cwo_core.supervision.transport.app_server"
        )
        self.errors = importlib.import_module(
            "cwo_core.supervision.transport.errors"
        )
        self._block(
            self.app_server.AppServer, "__init__", "request", "model_discovery"
        )
        activation = importlib.import_module("cwo_core.native_activation_preview")
        self._block(
            activation,
            "acquire_activation_claim",
            "activation_dry_run",
            "approve_activation_plan",
            "generate_activation_key",
            "prepare_activation_plan",
        )
        ledger = importlib.import_module("cwo_core.native_activation_ledger")
        self._block(ledger.NativeActivationLedgerStore, "create")
        tool_activation = importlib.import_module("cwo_core.native_tool_activation")
        self._block(tool_activation, "verify_tool_enforcement_activation")

    def tearDown(self) -> None:
        for effect in self.effects:
            effect.assert_not_called()

    def _block(self, owner, *names: str) -> None:
        for name in names:
            effect = self.stack.enter_context(
                mock.patch.object(
                    owner,
                    name,
                    side_effect=AssertionError(
                        "EXAMPLE held effect attempted during import"
                    ),
                    create=True,
                )
            )
            self.effects.append(effect)

    def _fresh(self, name: str) -> ModuleType:
        sys.modules.pop(name, None)
        return importlib.import_module(name)

    def test_preview_import_succeeds_without_moved_facade_names(self) -> None:
        facade = self._fresh(FACADE)
        cached_preview = self._fresh(PREVIEW)
        proxy = _FacadeWithoutMovedTransport(facade)
        with mock.patch.dict(sys.modules, {FACADE: proxy}):
            self.assertIs(sys.modules[FACADE], proxy)
            self.assertFalse(hasattr(proxy, "AppServer"))
            self.assertFalse(hasattr(proxy, "AppServerError"))
            with self.assertRaises(ImportError):
                _old_preview_transport_import()
            preview = self._fresh(PREVIEW)
            self.assertIsNot(preview, cached_preview)
            self.assertIs(sys.modules[FACADE], proxy)
            self.assertIs(preview.AppServer, self.app_server.AppServer)
            self.assertIs(preview.AppServerError, self.errors.AppServerError)
            for name, value in vars(facade).items():
                if name not in {"AppServer", "AppServerError"}:
                    with self.subTest(export=name):
                        self.assertIs(getattr(proxy, name), value)
            for name in (
                "CONTROL_TURN_ID",
                "LiveThreadAdapter",
                "calibration",
                "capture_server_tool_surface",
                "contain_started_threads",
                "pool_sleep",
            ):
                with self.subTest(consumer=name):
                    self.assertIs(getattr(preview, name), getattr(facade, name))

    def test_f5_held_route_original_facade_keeps_owner_identities_without_effects(self) -> None:
        facade = self._fresh(FACADE)
        preview = self._fresh(PREVIEW)
        self.assertIs(facade.AppServer, self.app_server.AppServer)
        self.assertIs(facade.AppServerError, self.errors.AppServerError)
        self.assertIs(facade.AppServerRpcError, self.errors.AppServerRpcError)
        self.assertIs(preview.AppServer, self.app_server.AppServer)
        self.assertIs(preview.AppServerError, self.errors.AppServerError)
        self.assertIs(preview.live_availability.N1_LIVE_AVAILABLE, False)
        self.assertIs(preview.live_availability.POOL_LIVE_AVAILABLE, False)


if __name__ == "__main__":
    unittest.main()
