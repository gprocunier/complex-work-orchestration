"""Runtime harness metadata is typed before use; declarations grant no permissions."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from cwo_core import harness, policy, policy_schema  # noqa: E402
from test_policy_schema import malformed_policy  # noqa: E402

NAME = "harness-registry"
REQUIRED = (
    "display_name", "status", "license", "primary_command",
    "noninteractive", "structured_output", "prompt_file_friendly",
    "supports_shell", "supports_repo_read", "supports_repo_write", "supports_web", "supports_mcp",
    "supports_local_openai_compatible", "default_timeout_seconds", "permission_model",
    "recommended_cwo_role", "cwo_recommendation",
)
FLAGS = (
    "noninteractive", "structured_output", "prompt_file_friendly",
    "supports_shell", "supports_repo_read", "supports_repo_write", "supports_web", "supports_mcp",
    "supports_local_openai_compatible",
)
STRINGS = (
    "display_name", "status", "license", "primary_command", "permission_model",
    "recommended_cwo_role", "cwo_recommendation",
    "suggested_noninteractive_command", "agent_create_command",
)
ARRAYS = ("safe_default_tools", "mutable_tools")
_MISSING = object()


def edit(path: tuple[str, ...], value: Any = _MISSING) -> Callable[[dict[str, Any]], None]:
    """Replace or remove one field in a temporary real-policy copy."""
    def mutate(document: dict[str, Any]) -> None:
        parent = document
        for key in path[:-1]:
            parent = parent[key]
        if value is _MISSING:
            del parent[path[-1]]
        else:
            parent[path[-1]] = copy.deepcopy(value)

    return mutate


class HarnessRegistrySchemaTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()
        policy_schema.clear_schema_cache()

    @staticmethod
    def consumers() -> dict[str, Callable[[], Any]]:
        return {
            "load": lambda: policy.load_policy(NAME),
            "suffix": lambda: policy.load_policy(NAME + ".yaml"),
            "registry": harness.harness_registry,
            "repository metadata": harness.validate_execution_environment_registry,
        }

    def assert_current(self) -> None:
        policy.clear_policy_cache()
        policy_schema.clear_schema_cache()
        expected = json.loads(
            (ROOT / "policy" / f"{NAME}.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(policy.load_policy(NAME), expected)
        self.assertEqual(policy.load_policy(NAME + ".yaml"), expected)
        self.assertEqual(harness.harness_registry(), expected)
        for key, entry in expected["harnesses"].items():
            with self.subTest(harness=key):
                self.assertEqual(set(REQUIRED) - set(entry), set())
                for field in FLAGS:
                    self.assertIs(type(entry[field]), bool)
                self.assertIs(type(entry["default_timeout_seconds"]), int)
                self.assertGreater(entry["default_timeout_seconds"], 0)
        self.assertEqual(harness.validate_execution_environment_registry(), [])
        self.assertEqual(
            harness._suggested_command(
                harness_key="unknown_future_harness", agent=None, model=None, variant=None,
            ),
            "unknown_future_harness <prompt-file>",
        )

    def assert_refused(self, mutate: Callable[[dict[str, Any]], None] | None = None, *,
                       raw: str | None = None, fragment: str) -> None:
        try:
            self.assert_current()
            with malformed_policy(NAME, mutate, raw):
                for label, call in self.consumers().items():
                    with self.subTest(consumer=label):
                        policy.clear_policy_cache()
                        with self.assertRaises(SystemExit) as raised:
                            call()
                        message = str(raised.exception)
                        self.assertIn("policy/harness-registry.yaml", message)
                        self.assertIn(fragment, message)
                        self.assertNotIn("Traceback", message)
        finally:
            policy.clear_policy_cache()
            policy_schema.clear_schema_cache()

    def test_dynamic_names_and_descriptions_remain_data(self) -> None:
        self.assert_current()
        future = copy.deepcopy(harness.harness_registry()["harnesses"]["opencode"])
        for field in STRINGS:
            future[field] = "future metadata: $(false); do not execute"
        future.update(safe_default_tools=["future-tool"], mutable_tools=[])
        with malformed_policy(NAME, edit(("harnesses",), {"future_harness": future})):
            self.assertEqual(harness.harness_registry()["harnesses"], {"future_harness": future})

    def test_optional_fields_may_be_absent_or_empty_arrays(self) -> None:
        self.assert_current()
        def optional(document: dict[str, Any]) -> None:
            for entry in document["harnesses"].values():
                for field in ("suggested_noninteractive_command", "agent_create_command"):
                    entry.pop(field, None)
                for field in ARRAYS:
                    entry[field] = []

        with malformed_policy(NAME, optional):
            for entry in harness.harness_registry()["harnesses"].values():
                for field in ARRAYS:
                    self.assertEqual(entry[field], [])

    def test_positive_timeouts_have_no_added_upper_limit(self) -> None:
        for value in (1, 1801, 10 ** 100):
            with self.subTest(timeout=value):
                self.assert_current()
                with malformed_policy(NAME, edit(("harnesses", "codex_cli", "default_timeout_seconds"), value)):
                    self.assertEqual(
                        harness.harness_registry()["harnesses"]["codex_cli"]["default_timeout_seconds"], value,
                    )

    def test_empty_mapping_retains_additional_repository_presence_contract(self) -> None:
        self.assert_current()
        with malformed_policy(NAME, edit(("harnesses",), {})):
            self.assertEqual(harness.harness_registry()["harnesses"], {})
            self.assertEqual(
                harness.validate_execution_environment_registry(), ["harness registry must define at least one harness"],
            )

    def test_version_and_schema_are_typed_constants(self) -> None:
        for value in (True, False, 1.0, 2, -1, "1", None):
            with self.subTest(version=value):
                self.assert_refused(edit(("version",), value), fragment="$.version")
        for value in (True, 1, "v1", None):
            with self.subTest(schema=value):
                self.assert_refused(edit(("schema",), value), fragment="$.schema")

    def test_flags_refuse_coercions(self) -> None:
        for field in FLAGS:
            for value in (1, 0, "false", None, [], {}):
                with self.subTest(field=field, value=value):
                    self.assert_refused(edit(("harnesses", "codex_cli", field), value),
                                        fragment=f"{field}: expected boolean")

    def test_timeout_is_a_positive_integer_token(self) -> None:
        for value in (True, False, 1.0, 0, -1, "1800", None, [], {}):
            with self.subTest(timeout=value):
                self.assert_refused(edit(("harnesses", "codex_cli", "default_timeout_seconds"), value),
                                    fragment="$.harnesses.codex_cli.default_timeout_seconds")

    def test_descriptions_are_strings(self) -> None:
        for field in STRINGS:
            for value in (True, 1, None, [], {}):
                with self.subTest(field=field, value=value):
                    self.assert_refused(edit(("harnesses", "opencode", field), value),
                                        fragment=f"{field}: expected string")

    def test_optional_arrays_have_nonempty_string_items(self) -> None:
        for field in ARRAYS:
            for value in (1, True, "read", {}, None, [1], [True], [None], [""], [[]]):
                with self.subTest(field=field, value=value):
                    self.assert_refused(edit(("harnesses", "opencode", field), value), fragment=field)

    def test_required_root_and_common_entry_fields(self) -> None:
        for prefix, fields in (((), ("version", "schema", "harnesses")), (("harnesses", "codex_cli"), REQUIRED)):
            for field in fields:
                with self.subTest(path=prefix + (field,)):
                    self.assert_refused(edit(prefix + (field,)), fragment=f"missing required field {field!r}")

    def test_closed_objects_and_dynamic_entry_containers(self) -> None:
        for prefix in ((), ("harnesses", "codex_cli")):
            with self.subTest(extra=prefix):
                self.assert_refused(edit(prefix + ("unexpected",), True), fragment="unexpected: unexpected field")
        for path in (("harnesses",), ("harnesses", "future_harness")):
            for value in (1, True, None, [], "harness"):
                with self.subTest(path=path, value=value):
                    self.assert_refused(edit(path, value), fragment="expected object")
        self.assert_refused(edit(("harnesses", "future_harness"), {}), fragment="missing required field")

    def test_strict_json_refusals_use_real_policy_readers(self) -> None:
        raw = (ROOT / "policy" / f"{NAME}.yaml").read_text(encoding="utf-8")
        duplicates = (
            ('"version": 1', '"version": 1, "version": 1'),
            ('"codex_cli": {', '"codex_cli": {}, "codex_cli": {'),
            ('"noninteractive": true', '"noninteractive": true, "noninteractive": false'),
            ('"default_timeout_seconds": 1800', '"default_timeout_seconds": 1, "default_timeout_seconds": 1800'),
            ('"safe_default_tools": [', '"safe_default_tools": [], "safe_default_tools": ['),
        )
        for old, new in duplicates:
            with self.subTest(duplicate=old):
                self.assertIn(old, raw)
                self.assert_refused(raw=raw.replace(old, new, 1), fragment="duplicate key")
        for token in ("NaN", "Infinity", "-Infinity", "1e309", "1" + "0" * 400):
            with self.subTest(token=token[:16]):
                self.assert_refused(
                    raw=raw.replace('"default_timeout_seconds": 1800', '"default_timeout_seconds": ' + token, 1),
                    fragment="is not JSON-compatible YAML",
                )
        for raw_document in ("[]", "true", "1", "null", '{"version":'):
            with self.subTest(document=raw_document):
                self.assert_refused(raw=raw_document, fragment="policy/harness-registry.yaml")


if __name__ == "__main__":
    unittest.main()
