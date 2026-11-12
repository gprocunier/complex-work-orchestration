from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import secrets
import tempfile
import time
from types import ModuleType
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
_EXAMPLE_TIME = time.struct_time((2001, 2, 3, 4, 5, 6, 5, 34, 0))
_EXAMPLE_PREFIX = "20010203T040506Z-424242"
_EXAMPLE_RANDOM = "EXAMPLE_SESSION_RANDOM_0001"


def _load_paths() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_cwo_session_identity_fixture", ROOT / "scripts/cwo_core/paths.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the session identity test module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TempSessionIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = _load_paths()
        self.original_environment = os.environ.copy()
        self.original_default = self.paths._DEFAULT_SESSION_ID
        self.original_gmtime = time.gmtime
        self.original_getpid = os.getpid
        self.original_token_hex = secrets.token_hex
        self.addCleanup(self._assert_restored_state)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(
            patch.dict(os.environ, {"CWO_SESSION_ID": "", "USER": "EXAMPLE_USER"})
        )
        stack.enter_context(patch.object(self.paths, "_DEFAULT_SESSION_ID", None))
        self.clock = stack.enter_context(patch.object(time, "gmtime", return_value=_EXAMPLE_TIME))
        self.pid = stack.enter_context(patch.object(os, "getpid", return_value=424242))
        self.random = stack.enter_context(patch.object(secrets, "token_hex", return_value=_EXAMPLE_RANDOM))

    def _assert_restored_state(self) -> None:
        self.assertTrue(
            dict(os.environ) == self.original_environment,
            "the test did not restore the environment",
        )
        self.assertIs(self.paths._DEFAULT_SESSION_ID, self.original_default)
        self.assertIs(time.gmtime, self.original_gmtime)
        self.assertIs(os.getpid, self.original_getpid)
        self.assertIs(secrets.token_hex, self.original_token_hex)

    def test_same_clock_process_probe(self) -> None:
        first = self.paths.cwo_session_id()
        self.assertTrue(first.startswith(_EXAMPLE_PREFIX))
        os.environ.pop("CWO_SESSION_ID")
        self.assertEqual(self.paths.cwo_session_id(), first)
        with patch.dict(os.environ, {"CWO_SESSION_ID": " ..EXAMPLE session/override--.. "}):
            self.assertEqual(self.paths.cwo_session_id(), "EXAMPLE-session-override")
            self.assertEqual(self.paths._DEFAULT_SESSION_ID, first)
        self.assertEqual(self.paths.cwo_session_id(), first)

        self.random.return_value = "EXAMPLE_SESSION_RANDOM_0002"
        second_module = _load_paths()
        self.assertIsNot(second_module, self.paths)
        self.assertIsNone(second_module._DEFAULT_SESSION_ID)
        with patch.object(second_module, "_DEFAULT_SESSION_ID", None):
            second = second_module.cwo_session_id()
            self.assertEqual(second_module.cwo_session_id(), second)
        self.assertIsNone(second_module._DEFAULT_SESSION_ID)
        self.assertEqual(self.clock.call_args_list, [call(), call()])
        self.assertEqual(self.pid.call_args_list, [call(), call()])
        self.assertTrue(first != second, "independent fallback lifetimes reused an identity")
        self.assertEqual(first, f"{_EXAMPLE_PREFIX}-{_EXAMPLE_RANDOM}")
        self.assertEqual(second, f"{_EXAMPLE_PREFIX}-EXAMPLE_SESSION_RANDOM_0002")
        self.assertEqual(self.random.call_args_list, [call(16), call(16)])

    def test_explicit_overrides_preserve_sanitization(self) -> None:
        self.random.side_effect = AssertionError("an explicit override requested randomness")
        cases = (
            ("EXAMPLE_session-01.ok", "EXAMPLE_session-01.ok"),
            (" ..EXAMPLE session///override--.. ", "EXAMPLE-session-override"),
            (" ...///--- ", "session"),
            (" \t ", "session"),
            ("EXAMPLE_" + "x" * 100, "EXAMPLE_" + "x" * 88),
        )
        for configured, expected in cases:
            with self.subTest(configured=configured):
                with patch.dict(os.environ, {"CWO_SESSION_ID": configured}):
                    self.assertEqual(self.paths.cwo_session_id(), expected)
                    self.assertIsNone(self.paths._DEFAULT_SESSION_ID)
        self.random.assert_not_called()
        self.clock.assert_not_called()
        self.pid.assert_not_called()

    def test_random_failure_does_not_cache_a_fallback(self) -> None:
        self.random.side_effect = OSError("EXAMPLE random source unavailable")
        for _ in range(2):
            with self.assertRaisesRegex(OSError, "EXAMPLE random source unavailable"):
                self.paths.cwo_session_id()
            self.assertIsNone(self.paths._DEFAULT_SESSION_ID)
        self.assertEqual(self.random.call_args_list, [call(16), call(16)])

        self.random.side_effect = None
        recovered = self.paths.cwo_session_id()
        self.assertEqual(recovered, f"{_EXAMPLE_PREFIX}-{_EXAMPLE_RANDOM}")
        self.assertEqual(self.paths.cwo_session_id(), recovered)
        self.assertEqual(self.random.call_args_list, [call(16), call(16), call(16)])

    def test_temp_directory_preview_and_disposable_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cwo-session-identity-test-") as disposable:
            root = Path(disposable).resolve() / "EXAMPLE_TEMP_ROOT"
            with patch.dict(os.environ, {"CWO_TEMP_ROOT": str(root)}):
                expected = (
                    root
                    / f"cwo-EXAMPLE_USER-{_EXAMPLE_PREFIX}-{_EXAMPLE_RANDOM}"
                    / "EXAMPLE-purpose"
                )
                preview = self.paths.cwo_temp_dir(purpose="EXAMPLE purpose", create=False)
                self.assertEqual(preview, expected)
                self.assertFalse(root.exists())
                self.assertEqual(list(root.parent.iterdir()), [])

                created = self.paths.cwo_temp_dir(purpose="EXAMPLE purpose")
                self.assertEqual(created, preview)
                self.assertTrue(created.is_dir())
                self.assertTrue(created.parent.is_dir())
                self.assertEqual(created.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(created.parent.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(self.paths.cwo_temp_dir(create=False), created.parent)
                self.random.assert_called_once_with(16)


if __name__ == "__main__":
    unittest.main()
