"""Access-profile shape and optional advisory-hook compatibility tests.

Historical component tests retain their scoped registration fixture. Current
hook regressions exercise the production mapping without replacing it.
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import access_profiles, policy, policy_schema as ps  # noqa: E402
from cwo_core.codex_hook_enforcement import validate_profile_hooks  # noqa: E402
from cwo_core.errors import CWOValidationError  # noqa: E402

FILENAME = "access-profiles.yaml"
SCHEMA_NAME = "access-profiles.schema.json"
DELETE = object()


def nodes(value: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[tuple[str | int, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from nodes(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from nodes(item, path + (index,))


def changed(document: Any, path: tuple[str | int, ...], replacement: Any) -> Any:
    result = copy.deepcopy(document)
    if not path:
        return copy.deepcopy(replacement)
    parent = result
    for step in path[:-1]:
        parent = parent[step]
    if replacement is DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = copy.deepcopy(replacement)
    return result


class RegisteredAccessProfileHookSchemaTests(unittest.TestCase):
    """Use current registration without a test-only schema mapping."""

    def setUp(self) -> None:
        self.assertEqual(ps.POLICY_SCHEMAS.get(FILENAME), SCHEMA_NAME)
        self.addCleanup(policy.clear_policy_cache)
        tmpdir = self.enterContext(tempfile.TemporaryDirectory())
        policy_dir = Path(tmpdir) / "policy"
        shutil.copytree(ROOT / "policy", policy_dir)
        self.enterContext(mock.patch.object(policy, "POLICY_DIR", policy_dir))
        self.path = policy_dir / FILENAME
        self.document = json.loads(self.path.read_text(encoding="utf-8"))
        self.key = next(iter(self.document["profiles"]))
        self.schema = ps.load_policy_schema(SCHEMA_NAME)
        self.assertEqual(ps.schema_errors(self.schema), [])
        try:
            import jsonschema
        except ImportError as exc:
            self.fail(f"jsonschema from requirements-test.txt is required: {exc}")
        jsonschema.Draft202012Validator.check_schema(self.schema)
        self.reference = jsonschema.Draft202012Validator(self.schema)
        self.good_hooks = {
            "UserPromptSubmit": [{"hooks": [{
                "type": "command", "command": "bd codex-hook UserPromptSubmit",
                "statusMessage": "", "visibilityHint": "quiet",
            }]}],
        }
        self.assert_loaded(self.document)

    def write(self, document: Any) -> None:
        self.path.write_text(json.dumps(document), encoding="utf-8")
        policy.clear_policy_cache()

    def readers(self) -> tuple[Any, ...]:
        return (
            lambda: policy.load_policy("access-profiles"),
            lambda: policy.load_policy(FILENAME),
            access_profiles.access_profile_registry,
        )

    def with_hooks(self, hooks: Any) -> dict[str, Any]:
        return changed(self.document, ("profiles", self.key, "hooks"), hooks)

    def compare(self, document: Any, expected: bool) -> None:
        self.assertEqual(self.reference.is_valid(document), expected)
        self.assertEqual(not ps.validate_instance(document, self.schema), expected)

    def assert_loaded(self, document: Any) -> None:
        before = copy.deepcopy(document)
        self.write(document)
        ps.validate_policy_document(FILENAME, document)
        for read in self.readers():
            self.assertEqual(read(), document)
        expected_profile = copy.deepcopy(document["profiles"][self.key])
        expected_profile.setdefault("key", self.key)
        self.assertEqual(access_profiles.access_profile(self.key), expected_profile)
        validate_profile_hooks(document["profiles"][self.key], profile_name=self.key)
        with mock.patch.object(
            access_profiles, "validate_profile_hooks", wraps=validate_profile_hooks
        ) as hooks_check:
            self.assertEqual(access_profiles.validate_access_profile_registry(), [])
            hooks_check.assert_any_call(document["profiles"][self.key], profile_name=self.key)
        self.assertEqual(document, before)

    def valid_hook_cases(self) -> Iterator[tuple[str, dict[str, Any]]]:
        yield "empty hooks object", {}
        specs = (
            ("SessionStart", "startup|resume|clear", (
                "bd codex-hook SessionStart", "bd prime --memories-only --hook-json",
            )),
            ("UserPromptSubmit", None, ("bd codex-hook UserPromptSubmit",)),
            ("PreCompact", "manual|auto", ("bd codex-hook PreCompact",)),
            ("PostCompact", "manual|auto", ("bd codex-hook PostCompact",)),
        )
        yield "empty event group arrays", {event: [] for event, _, _ in specs}
        all_events = {}
        for event, matcher, commands in specs:
            entries = [{"type": "command", "command": command} for command in commands]
            group = {"hooks": entries}
            if matcher is not None:
                group["matcher"] = matcher
            all_events[event] = [group]
            for command in commands:
                for metadata in (
                    {}, {"statusMessage": ""}, {"statusMessage": "Preparing context"},
                    {"visibilityHint": "quiet"}, {"visibilityHint": "verbose"},
                    {"statusMessage": "", "visibilityHint": "verbose"},
                ):
                    value = copy.deepcopy(group)
                    value["hooks"] = [{"type": "command", "command": command, **metadata}]
                    yield f"{event}: {command}: {metadata!r}", {event: [value]}
            duplicate = copy.deepcopy(group)
            duplicate["hooks"] = entries + copy.deepcopy(entries)
            yield f"{event}: duplicate entries and groups", {event: [duplicate, copy.deepcopy(duplicate)]}
        yield "all allowlisted events", all_events

    def invalid_hook_cases(self) -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
        good = self.with_hooks(self.good_hooks)
        prefix = ("profiles", self.key, "hooks")
        group = ("UserPromptSubmit", 0)
        entry = group + ("hooks", 0)
        cases = [
            ((), None), ((), []),
            (("Stop",), []), (("PreToolUse",), []),
            (("PermissionRequest",), None), (("pretooluse",), []),
            (("UserPromptSubmit",), {}), (("UserPromptSubmit",), None),
            (group, None), (group, []), (group + ("enabled",), True),
            (group + ("matcher",), None), (group + ("matcher",), ""),
            (group + ("hooks",), DELETE), (group + ("hooks",), []),
            (group + ("hooks",), {}), (group + ("hooks",), None),
            (entry, None), (entry, "bd codex-hook UserPromptSubmit"),
            (entry + ("type",), DELETE), (entry + ("type",), "prompt"),
            (entry + ("type",), True), (entry + ("command",), DELETE),
            (entry + ("command",), ["bd", "codex-hook", "UserPromptSubmit"]),
            (entry + ("command",), "bd codex-hook SessionStart"),
            (entry + ("command",), "bd codex-hook UserPromptSubmit "),
            (entry + ("command",), "bd codex-hook UserPromptSubmit; other"),
            (entry + ("statusMessage",), None), (entry + ("statusMessage",), False),
            (entry + ("statusMessage",), {}), (entry + ("statusMessage",), []),
            (entry + ("visibilityHint",), None), (entry + ("visibilityHint",), "hidden"),
            (entry + ("visibilityHint",), True), (entry + ("timeout",), 5),
        ]
        for field in (
            "grant_permission", "grantPermission", "allow", "approve",
            "bypass_review", "bypassReview", "skip_approval", "skipApproval",
        ):
            cases.append((entry + (field,), True))
        for path, replacement in cases:
            yield repr(path), good, changed(good, prefix + path, replacement)
        yield "enforcement_hooks", good, changed(
            good, ("profiles", self.key, "enforcement_hooks"), {}
        )
        for label, hooks in self.valid_hook_cases():
            for event in ("SessionStart", "PreCompact", "PostCompact"):
                if not hooks.get(event):
                    continue
                valid = self.with_hooks(hooks)
                target = prefix + (event, 0, "matcher")
                for replacement in (DELETE, None, "", "manual|auto|startup"):
                    yield f"{label}: matcher {replacement!r}", valid, changed(valid, target, replacement)

    def test_optional_hook_metadata_loads_and_matches_independent_schema(self) -> None:
        for label, hooks in self.valid_hook_cases():
            with self.subTest(case=label):
                document = self.with_hooks(hooks)
                self.compare(document, True)
                self.assert_loaded(document)

    def test_malformed_hooks_refuse_after_real_loader_and_typed_positives(self) -> None:
        for label, good, bad in self.invalid_hook_cases():
            with self.subTest(case=label):
                # Real typed and canonical-reader positives precede every refusal.
                self.assert_loaded(good)
                self.compare(good, True)
                with self.assertRaises(CWOValidationError):
                    validate_profile_hooks(bad["profiles"][self.key], profile_name=self.key)
                self.compare(bad, False)
                self.write(bad)
                readers = self.readers() + (
                    lambda: access_profiles.access_profile(self.key),
                    access_profiles.validate_access_profile_registry,
                )
                for read in readers:
                    with self.assertRaises(ps.PolicySchemaError) as raised:
                        read()
                    self.assertIn(FILENAME, str(raised.exception))
                    self.assertIn(SCHEMA_NAME, str(raised.exception))


class AccessProfileRegistrySchemaTests(unittest.TestCase):
    """Exercise the real bounded validator with explicit TEST ONLY registration."""

    def setUp(self) -> None:
        with (ROOT / "policy" / FILENAME).open(encoding="utf-8") as handle:
            self.document = json.load(handle)
        self.schema = ps.load_policy_schema(SCHEMA_NAME)
        self.assertEqual(ps.schema_errors(self.schema), [])
        # TEST ONLY: this does not supply or assert a production mapping.
        self.enterContext(mock.patch.object(
            ps, "POLICY_SCHEMAS", {**ps.POLICY_SCHEMAS, FILENAME: SCHEMA_NAME}
        ))
        self.addCleanup(policy.clear_policy_cache)
        policy.clear_policy_cache()
        # Every malformed-case test first proves that the real document is valid.
        self.accepts(self.document)

    def accepts(self, document: Any) -> None:
        before = copy.deepcopy(document)
        ps.validate_policy_document(FILENAME, document)
        self.assertEqual(document, before)

    def refuses(self, document: Any, fragment: str) -> None:
        with self.assertRaises(ps.PolicySchemaError) as raised:
            ps.validate_policy_document(FILENAME, document)
        self.assertIn(FILENAME, str(raised.exception))
        self.assertIn(SCHEMA_NAME, str(raised.exception))
        self.assertIn(fragment, str(raised.exception))

    def test_shipped_document_loads_through_explicit_schema(self) -> None:
        self.assertEqual(self.schema, json.loads(
            (ROOT / "schemas" / SCHEMA_NAME).read_text(encoding="utf-8")
        ))
        self.accepts(self.document)

    def test_each_structural_or_scalar_type_is_checked(self) -> None:
        for path, value in nodes(self.document):
            replacement = [] if isinstance(value, dict) else {} if isinstance(value, list) else 0
            if type(value) is int:
                replacement = True
            with self.subTest(path=path, case="wrong type"):
                self.refuses(changed(self.document, path, replacement), "expected")
            with self.subTest(path=path, case="null"):
                self.refuses(changed(self.document, path, None), "found null")

    def test_every_current_record_field_is_required_and_closed(self) -> None:
        for path, value in nodes(self.document):
            if not isinstance(value, dict) or path == ("profiles",):
                continue
            with self.subTest(path=path, case="extra"):
                self.refuses(changed(self.document, path + ("zz_unexpected",), True), "unexpected field")
            for field in value:
                with self.subTest(path=path, missing=field):
                    self.refuses(changed(self.document, path + (field,), DELETE), "missing required field")

    def test_dynamic_map_values_must_be_complete_records(self) -> None:
        self.refuses(changed(self.document, ("profiles", "new-test-profile"), []), "expected object")
        self.refuses(changed(self.document, ("profiles", "new-test-profile"), {}), "missing required field")

    def test_string_array_items_are_checked_including_empty_arrays(self) -> None:
        for path, value in nodes(self.document):
            if isinstance(value, list):
                for item in (False, 1, None, {}, []):
                    with self.subTest(path=path, item=item):
                        self.refuses(changed(self.document, path, [item]), "expected string")

    def test_version_is_an_integer_token_without_a_new_value_bound(self) -> None:
        for value in (True, False, 1.0, 1.5, "1", None):
            with self.subTest(version=value):
                self.refuses(changed(self.document, ("version",), value), "expected integer")
        for value in (-1, 0, 2):
            with self.subTest(version=value):
                self.accepts(changed(self.document, ("version",), value))

    def test_existing_enums_are_preserved(self) -> None:
        key = next(iter(self.document["profiles"]))
        for field, allowed in {
            "status": ("available", "offline", "experimental", "deprecated"),
            "repo_access": ("none", "read-only", "read-write", "bounded"),
        }.items():
            for value in allowed:
                with self.subTest(field=field, value=value):
                    self.accepts(changed(self.document, ("profiles", key, field), value))
            self.refuses(changed(self.document, ("profiles", key, field), "unknown-schema-test-value"), "must be one of")

    def test_no_profile_roster_is_imposed(self) -> None:
        self.accepts(changed(self.document, ("profiles",), {}))
        sample = next(iter(self.document["profiles"].values()))
        self.accepts(changed(self.document, ("profiles",), {"new-test-profile": sample}))

    def test_permitted_empty_and_duplicate_metadata_remain_valid(self) -> None:
        for path, value in nodes(self.document):
            if type(value) is str and path[-1] not in {"schema", "status", "repo_access"}:
                with self.subTest(path=path, case="empty string"):
                    self.accepts(changed(self.document, path, ""))
            if isinstance(value, list):
                if path[-1] != "provider_keys":
                    with self.subTest(path=path, case="empty array"):
                        self.accepts(changed(self.document, path, []))
                if value:
                    with self.subTest(path=path, case="duplicate item"):
                        self.accepts(changed(self.document, path, [value[0], value[0]]))
                with self.subTest(path=path, case="empty string item"):
                    self.accepts(changed(self.document, path, [""]))

    def test_provider_lists_keep_the_existing_nonempty_requirement(self) -> None:
        key = next(iter(self.document["profiles"]))
        self.refuses(changed(self.document, ("profiles", key, "provider_keys"), []), "must have at least 1 items")

    def test_TEST_ONLY_registration_reaches_the_canonical_reader(self) -> None:
        """Future loader integration demonstration; production mapping is untouched."""
        key = next(iter(self.document["profiles"]))
        cases = (
            (("version",), True),
            (("version",), 1.0),
            (("profiles",), []),
            (("profiles", key, "authority", "may_execute"), 1),
        )
        readers = (
            lambda: policy.load_policy("access-profiles"),
            lambda: policy.load_policy("access-profiles.yaml"),
            access_profiles.access_profile_registry,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / FILENAME
            with mock.patch.object(policy, "POLICY_DIR", Path(tmpdir)):
                for target, replacement in cases:
                    with self.subTest(path=target, replacement=replacement):
                        # Positive controls precede each malformed copied policy.
                        path.write_text(json.dumps(self.document), encoding="utf-8")
                        policy.clear_policy_cache()
                        for read in readers:
                            self.assertEqual(read(), self.document)
                        bad = changed(self.document, target, replacement)
                        path.write_text(json.dumps(bad), encoding="utf-8")
                        policy.clear_policy_cache()
                        for read in readers:
                            with self.assertRaises(ps.PolicySchemaError) as raised:
                                read()
                            self.assertIn(FILENAME, str(raised.exception))
                            self.assertIn(SCHEMA_NAME, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
