"""Check compatible turn observations without granting current effect authority."""

from __future__ import annotations

import ast
from collections import UserDict
from contextlib import ExitStack, contextmanager
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from types import MappingProxyType, ModuleType
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OWNER = "cwo_core.supervision.turn_observations"
RUNTIME = "cwo_core.maintenance_native_runtime"
FACADE = "run_native_pool_live_canaries"
OWNER_PATH = "scripts/cwo_core/supervision/turn_observations.py"


@contextmanager
def _import_scope():
    """Restore exact module bindings and package caches after import failures."""
    saved_modules = sys.modules.copy()
    saved_path_object, saved_path = sys.path, sys.path[:]
    packages = [
        (module, vars(module).copy())
        for module in saved_modules.values()
        if isinstance(module, ModuleType) and "__path__" in vars(module)
    ]
    try:
        sys.path = [str(ROOT / "scripts"), *saved_path]
        yield
    finally:
        sys.modules.clear()
        sys.modules.update(saved_modules)
        for module, namespace in packages:
            vars(module).clear()
            vars(module).update(namespace)
        sys.path = saved_path_object
        sys.path[:] = saved_path


@contextmanager
def _held_effects():
    """Refuse process and network effects and require zero attempted calls."""
    with ExitStack() as stack:
        effects = []
        for owner, names in (
            (subprocess, ("Popen", "run")),
            (os, ("system", "fork", "posix_spawn", "posix_spawnp")),
            (threading.Thread, ("start",)),
            (socket, ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr")),
            (socket.socket, ("connect", "connect_ex", "send", "sendall", "sendto", "sendmsg")),
        ):
            for name in names:
                effects.append(stack.enter_context(mock.patch.object(
                    owner, name, create=True,
                    side_effect=AssertionError("EXAMPLE held effect was attempted"),
                )))
        try:
            yield
        finally:
            for effect in effects:
                effect.assert_not_called()


def _fresh(name):
    sys.modules.pop(name, None)
    return importlib.import_module(name)


class _FacadeWithoutTurnItems(ModuleType):
    """Keep every original export except the refused legacy helper."""

    def __init__(self, facade):
        super().__init__(facade.__name__, facade.__doc__)
        self._facade = facade

    def __getattribute__(self, name):
        if name == "turn_items":
            raise AttributeError("EXAMPLE legacy turn_items is unavailable")
        facade = ModuleType.__getattribute__(self, "_facade")
        return getattr(facade, name)


def _old_turn_items_import():
    from run_native_pool_live_canaries import turn_items

    return turn_items


class _RefuseFacadeImport:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == FACADE:
            raise AssertionError("EXAMPLE facade import was attempted")
        return None


class _BrokenObservation(UserDict):
    def get(self, key, default=None):
        raise ValueError("EXAMPLE observation lookup failed")


class TurnObservationTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(_import_scope())
        stack.enter_context(_held_effects())
        self.owner = _fresh(OWNER)
        self.facade = _fresh(FACADE)

    def check_observation(self, thread, turn_id, expected_turn, expected_items):
        for module in (self.owner, self.facade):
            with self.subTest(module=module.__name__):
                self.assertIs(module.turn_from_thread(thread, turn_id), expected_turn)
                items = module.turn_items(thread, turn_id)
                self.assertIsInstance(items, list)
                self.assertEqual(len(items), len(expected_items))
                for actual, expected in zip(items, expected_items):
                    self.assertIs(actual, expected)
                if expected_turn is not None:
                    self.assertIsNot(items, expected_turn.get("items"))

    def test_f5_current_facade_source_and_archived_helper_syntax_are_pinned(self):
        source = Path(self.facade.__file__).read_bytes()
        self.assertEqual(
            hashlib.sha256(source).hexdigest(),
            "d31f812a4adea3083223b1d9771a35a6a2901e5d8b05128b63cf9a524709e158",
        )
        # Reconstruct the original facade from exact campaign-adapter
        # additions and the single docstring-line change, retaining occurrence
        # checks before comparing the preserved historical digest.
        historical = source.decode()
        for addition in (
            "        campaign_live_route: bool = True,\n",
            "        self.campaign_live_route = campaign_live_route\n",
            "            self._require_campaign_live_route()\n",
            "                    self._require_campaign_live_route()\n",
            inspect.getsource(self.facade.LiveThreadAdapter._require_campaign_live_route) + "\n",
            "            campaign_live_route=True,\n",
        ):
            lines = historical.splitlines(keepends=True)
            if len(addition.splitlines()) == 1:
                self.assertEqual(lines.count(addition), 1)
                historical = "".join(line for line in lines if line != addition)
            else:
                self.assertEqual(historical.count(addition), 1)
                historical = historical.replace(addition, "")
        current_docstring_line = (
            "    new manifest generation with filesystem observations that do not run repository code.\n"
        )
        original_docstring_line = (
            "    new manifest generation; see ledger disablement W03-guarded-primary-diff.\n"
        )
        self.assertEqual(historical.count(current_docstring_line), 1)
        historical = historical.replace(current_docstring_line, original_docstring_line, 1)
        self.assertEqual(
            hashlib.sha256(historical.encode()).hexdigest(),
            "a07f4f1a7d7f84d7fc22cb9feae4027a43c46379a9665f2814b11eb47cb73682",
        )
        for name, digest in (
            ("turn_from_thread", "67cbf63780dc9e42275a541295ebfa7a2078e755796d39d9a1b836085f370573"),
            ("turn_items", "31876101d8d58e12889513eb357e1433b1c8a98ae3a8991198cea07b49a6123b"),
        ):
            original, moved = getattr(self.facade, name), getattr(self.owner, name)
            self.assertIsNot(moved, original)
            old_source, new_source = inspect.getsource(original), inspect.getsource(moved)
            self.assertEqual(hashlib.sha256(old_source.encode()).hexdigest(), digest)
            self.assertEqual(new_source, old_source)
            self.assertEqual(ast.dump(ast.parse(new_source)), ast.dump(ast.parse(old_source)))

    def test_first_match_preserves_mapping_items_order_and_identity(self):
        first = {"type": "userMessage", "text": "EXAMPLE first"}
        second = UserDict({"type": "agentMessage", "text": "EXAMPLE second"})
        third = MappingProxyType({"type": "agentMessage", "text": "EXAMPLE third"})
        turn = MappingProxyType({"id": "EXAMPLE turn", "items": [None, first, "EXAMPLE ignored", second, third, first]})
        thread = UserDict({"turns": [
            None, {"id": "EXAMPLE other", "items": [third]}, turn,
            {"id": "EXAMPLE turn", "items": [second]}, _BrokenObservation(),
        ]})
        self.check_observation(thread, "EXAMPLE turn", turn, [first, second, third, first])

    def test_none_id_matches_first_missing_or_explicit_none_id(self):
        item = {"text": "EXAMPLE missing identifier"}
        missing = UserDict({"items": [item]})
        explicit = {"id": None, "items": []}
        self.check_observation({"turns": [None, missing, explicit]}, None, missing, [item])
        self.check_observation({"turns": [explicit, missing]}, None, explicit, [])

    def test_missing_empty_and_non_list_turns_have_no_observation(self):
        for label, thread in (
            ("missing", {}), ("empty", {"turns": []}), ("none", {"turns": None}),
            ("tuple", {"turns": ({"id": "EXAMPLE turn"},)}),
            ("mapping", {"turns": {"id": "EXAMPLE turn"}}),
            ("nonmatching", {"turns": [None, 7, "EXAMPLE ignored", {}]}),
        ):
            with self.subTest(case=label):
                self.check_observation(thread, "EXAMPLE turn", None, [])

    def test_first_matching_turn_with_missing_or_non_list_items_stays_selected(self):
        for label, fields in (
            ("missing", {}), ("none", {"items": None}), ("empty", {"items": []}),
            ("tuple", {"items": ({"text": "EXAMPLE ignored"},)}),
            ("mapping", {"items": {"text": "EXAMPLE ignored"}}),
            ("nonmapping", {"items": [None, 7, "EXAMPLE ignored", []]}),
        ):
            with self.subTest(case=label):
                turn = {"id": "EXAMPLE turn", **fields}
                later = {"id": "EXAMPLE turn", "items": [{"text": "EXAMPLE later"}]}
                self.check_observation({"turns": [turn, later]}, "EXAMPLE turn", turn, [])

    def test_list_subclasses_keep_the_existing_list_contract(self):
        class ObservationList(list):
            pass

        item = UserDict({"text": "EXAMPLE list subclass"})
        turn = UserDict({"id": "EXAMPLE turn", "items": ObservationList([item])})
        self.check_observation({"turns": ObservationList([turn])}, "EXAMPLE turn", turn, [item])

    def test_supported_lookup_errors_propagate_unchanged(self):
        for label, thread, error in (
            ("none", None, AttributeError), ("list", [], AttributeError),
            ("text", "EXAMPLE invalid thread", AttributeError),
            ("thread lookup", _BrokenObservation(), ValueError),
            ("turn lookup", {"turns": [_BrokenObservation()]}, ValueError),
        ):
            for name in ("turn_from_thread", "turn_items"):
                with self.subTest(case=label, helper=name):
                    with self.assertRaises(error) as original:
                        getattr(self.facade, name)(thread, "EXAMPLE turn")
                    with self.assertRaises(error) as moved:
                        getattr(self.owner, name)(thread, "EXAMPLE turn")
                    self.assertEqual(moved.exception.args, original.exception.args)


class TurnObservationImportTests(unittest.TestCase):
    def test_fresh_owner_import_never_imports_facade(self):
        with _import_scope(), _held_effects():
            sys.modules.pop(FACADE, None)
            with mock.patch.object(sys, "meta_path", [_RefuseFacadeImport(), *sys.meta_path]):
                owner = _fresh(OWNER)
                self.assertNotIn(FACADE, sys.modules)
                self.assertEqual(Path(owner.__file__).resolve(), ROOT / OWNER_PATH)
                self.assertIsNone(owner.turn_from_thread({}, None))
                self.assertEqual(owner.turn_items({}, None), [])

    def test_real_maintenance_import_refuses_the_predecessor_edge(self):
        with _import_scope(), _held_effects():
            facade = _fresh(FACADE)
            cached = _fresh(RUNTIME)
            proxy = _FacadeWithoutTurnItems(facade)
            sys.modules[FACADE] = proxy
            self.assertFalse(hasattr(proxy, "turn_items"))
            with self.assertRaises(ImportError):
                _old_turn_items_import()
            runtime = _fresh(RUNTIME)
            self.assertIsNot(runtime, cached)
            self.assertIs(runtime.turn_items, sys.modules[OWNER].turn_items)
            self.assertIs(sys.modules[FACADE], proxy)
            for name, value in vars(facade).items():
                if name != "turn_items":
                    with self.subTest(export=name):
                        self.assertIs(getattr(proxy, name), value)
            for name in ("LiveThreadAdapter", "capture_server_tool_surface", "contain_started_threads", "pool_sleep"):
                self.assertIs(getattr(runtime, name), getattr(facade, name))
            server = importlib.import_module("cwo_core.supervision.transport.app_server")
            errors = importlib.import_module("cwo_core.supervision.transport.errors")
            self.assertIs(runtime.AppServer, server.AppServer)
            self.assertIs(runtime.AppServerError, errors.AppServerError)

    def test_scope_restores_exact_state_after_import_and_assertion_failures(self):
        for failure in ("import", "assertion"):
            saved_modules, path_object, path_entries = sys.modules.copy(), sys.path, sys.path[:]
            error = ModuleNotFoundError if failure == "import" else AssertionError
            with self.subTest(failure=failure), self.assertRaises(error):
                with _import_scope(), _held_effects():
                    facade = _fresh(FACADE)
                    sys.modules[FACADE] = _FacadeWithoutTurnItems(facade)
                    if failure == "import":
                        sys.modules[OWNER] = None
                    _fresh(RUNTIME)
                    sys.path.append("EXAMPLE unused import path")
                    self.fail("EXAMPLE intentional assertion failure")
            self.assertIs(sys.path, path_object)
            self.assertEqual(sys.path, path_entries)
            self.assertEqual(sys.modules.keys(), saved_modules.keys())
            for name, module in saved_modules.items():
                self.assertIs(sys.modules[name], module, name)


INSTALLED_PROBE = r'''
def action():
    assert "run_native_pool_live_canaries" not in sys.modules
    owner = importlib.import_module("cwo_core.supervision.turn_observations")
    assert "run_native_pool_live_canaries" not in sys.modules
    item = {"type": "agentMessage", "text": "EXAMPLE installed observation"}
    turn = {"id": "EXAMPLE turn", "items": [None, item]}
    thread = {"turns": [turn, {"id": "EXAMPLE turn", "items": []}]}
    assert owner.turn_from_thread(thread, "EXAMPLE turn") is turn
    items = owner.turn_items(thread, "EXAMPLE turn")
    assert len(items) == 1 and items[0] is item
    runtime = importlib.import_module("cwo_core.maintenance_native_runtime")
    assert runtime.turn_items is owner.turn_items
    assert runtime.turn_items(thread, "EXAMPLE turn")[0] is item
    for name in ("run_native_pool_live_canaries", "prepare_native_worker"):
        assert Path(sys.modules[name].__file__).resolve() == root / "scripts" / (name + ".py")
    for module in list(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename:
            assert not Path(filename).resolve().is_relative_to(source)
    return "EXAMPLE installed observation matched"
observe(action)
'''

MISSING_IMPORT_PROBE = r'''
def action():
    importlib.import_module(payload)
    return "EXAMPLE import unexpectedly succeeded"
observe(action)
'''


class InstalledTurnObservationTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(_import_scope())
        from tests import test_install_dependency_closure as closure

        self.closure = closure.InstalledDependencyClosureTests(
            "test_all_source_modules_and_bounded_first_run_consumers"
        )
        self.addCleanup(self.closure.doCleanups)
        self.closure.setUp()

    def test_disposable_installed_copy_uses_owner_and_maintenance_binding(self):
        self.closure.assert_current()
        self.assertEqual(self.closure.expected[OWNER], OWNER_PATH)
        self.assertEqual(
            (self.closure.install.target / OWNER_PATH).read_bytes(),
            (ROOT / OWNER_PATH).read_bytes(),
        )
        report = self.closure.successful_probe(INSTALLED_PROBE)
        self.assertEqual(report["result"], "EXAMPLE installed observation matched")
        self.closure.assert_current()

    def test_missing_installed_owner_refuses_both_selected_imports(self):
        (self.closure.install.target / OWNER_PATH).unlink()
        self.closure.assert_missing(OWNER_PATH)
        for name in (OWNER, RUNTIME):
            with self.subTest(consumer=name):
                result = self.closure.child(MISSING_IMPORT_PROBE, name)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(
                    "ModuleNotFoundError: No module named 'cwo_core.supervision.turn_observations'",
                    result.stderr,
                )

    def test_missing_unmoved_installed_dependency_refuses_maintenance(self):
        relative = "scripts/cwo_core/maintenance_runtime_support.py"
        (self.closure.install.target / relative).unlink()
        self.closure.assert_missing(relative)
        result = self.closure.child(MISSING_IMPORT_PROBE, RUNTIME)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "ModuleNotFoundError: No module named 'cwo_core.maintenance_runtime_support'",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
