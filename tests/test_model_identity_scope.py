"""Scoped model-identity lint: current code and policy are checked, archived records are not.

The repository-copy tests run the real scripts/validate_repository.py on a
disposable copy of this checkout, so they also show what a tree without the
lint accepts. The unit tests import the lint inside each test.
"""

from __future__ import annotations

import copy
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

SPARK = "gpt-5.3-codex-spark"
LUNA = "gpt-5.6-luna"
TERRA = "gpt-5.6-terra"
COPY_IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".orchestration-audit", ".beads", ".ruff_cache")


def _lint() -> Any:
    return importlib.import_module("cwo_core.model_identity_scope")


NATIVE = {
    "version": 1,
    "operative_routing": {"primary_model": SPARK},
    "task_selected_routing": {
        "selection": {"approved_portfolio": [LUNA, TERRA], "primary_model": LUNA},
        "operative_roles": {
            LUNA: "luna-first-operative-worker",
            TERRA: "escalation-only-operative-worker",
            SPARK: "historical-nonoperative",
        },
    },
}
REGISTER = {
    "version": 1,
    "schema": "json-compatible-yaml",
    "name": "model-identity-scope",
    "authority": "none",
    "scope": "test register",
    "current_models": [LUNA, TERRA],
    "policy_locations": [
        {"file": "native-worker-execution.yaml", "pointer": "/task_selected_routing", "class": "current",
         "literals": {LUNA: 3, TERRA: 2}, "reason": "active v3"},
        {"file": "native-worker-execution.yaml", "pointer": f"/task_selected_routing/operative_roles/{SPARK}",
         "class": "historical", "literals": {SPARK: 1}, "reason": "historical-nonoperative"},
        {"file": "native-worker-execution.yaml", "pointer": "/operative_routing", "class": "historical",
         "literals": {SPARK: 1}, "reason": "v2"},
    ],
    "source_literals": [
        {"path": "scripts/legacy.py", "literal": SPARK, "count": 1, "class": "unadjudicated", "reason": "legacy"},
        {"path": "scripts/current.py", "literal": LUNA, "count": 1, "class": "current", "reason": "current"},
    ],
}


class LintUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lint = _lint()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "policy").mkdir()
        (self.root / "scripts").mkdir()
        self.native = copy.deepcopy(NATIVE)
        self.register = copy.deepcopy(REGISTER)
        (self.root / "scripts" / "legacy.py").write_text(f'MODEL = "{SPARK}"\n', encoding="utf-8")
        (self.root / "scripts" / "current.py").write_text(f'MODEL = "{LUNA}"\n', encoding="utf-8")
        self.write()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self) -> None:
        (self.root / "policy" / "native-worker-execution.yaml").write_text(json.dumps(self.native), encoding="utf-8")
        (self.root / "policy" / "model-identity-scope.yaml").write_text(json.dumps(self.register), encoding="utf-8")

    def errors(self) -> list[str]:
        self.write()
        return self.lint.lint_model_identities(self.root)

    def assert_error(self, fragment: str) -> None:
        errors = self.errors()
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_classified_tree_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_new_runtime_literal_must_be_classified(self) -> None:
        (self.root / "scripts" / "new_default.py").write_text(f'DEFAULT = "{SPARK}"\n', encoding="utf-8")
        self.assert_error(f"unclassified model identity '{SPARK}' in scripts/new_default.py")

    def test_case_and_prefix_variants_are_identities(self) -> None:
        (self.root / "scripts" / "variant.py").write_text('A = "GPT-5.3-Codex-Spark"\nB = "_gpt-5.6-luna-max"\n', encoding="utf-8")
        errors = self.errors()
        self.assertIn(f"unclassified model identity '{SPARK}' in scripts/variant.py (1 occurrence)", errors)
        self.assertIn("unclassified model identity 'gpt-5.6-luna-max' in scripts/variant.py (1 occurrence)", errors)

    def test_extra_or_removed_frozen_literal_fails(self) -> None:
        (self.root / "scripts" / "legacy.py").write_text(f'MODEL = "{SPARK}"\nOTHER = "{SPARK}"\n', encoding="utf-8")
        self.assert_error(f"scripts/legacy.py '{SPARK}': '{SPARK}' found 2 time(s), register pins 1")
        (self.root / "scripts" / "legacy.py").write_text("MODEL = None\n", encoding="utf-8")
        self.assert_error(f"scripts/legacy.py '{SPARK}': '{SPARK}' found 0 time(s), register pins 1")

    def test_current_policy_location_cannot_name_a_historical_model(self) -> None:
        self.native["task_selected_routing"]["selection"]["fallback"] = SPARK
        self.assert_error(f"current location names '{SPARK}', which is not a current model")

    def test_historical_policy_location_is_frozen(self) -> None:
        self.native["operative_routing"]["primary_model"] = LUNA
        errors = self.errors()
        self.assertIn(f"policy/native-worker-execution.yaml#/operative_routing: '{LUNA}' found 1 time(s), register pins 0", errors)
        self.assertIn(f"policy/native-worker-execution.yaml#/operative_routing: '{SPARK}' found 0 time(s), register pins 1", errors)

    def test_unregistered_policy_location_fails(self) -> None:
        self.native["governance"] = {"worker": {"model": SPARK}}
        self.assert_error(f"unclassified model identity '{SPARK}' at policy/native-worker-execution.yaml#/governance/worker/model")

    def test_location_prefix_respects_segment_boundaries(self) -> None:
        self.native["operative_routing_v9"] = {"model": SPARK}
        self.assert_error("#/operative_routing_v9/model")

    def test_keys_are_scanned(self) -> None:
        self.native["roles"] = {SPARK: "worker"}
        self.assert_error(f"#/roles/{SPARK}")

    def test_current_set_must_agree_with_active_routing(self) -> None:
        self.register["current_models"] = [LUNA, TERRA, SPARK]
        self.assert_error(f"current_models lists '{SPARK}', which task_selected_routing marks historical-nonoperative")
        self.register["current_models"] = [LUNA]
        self.assert_error(f"current_models omits '{TERRA}'")

    def test_current_source_entry_cannot_name_a_historical_model(self) -> None:
        self.register["source_literals"][0]["class"] = "current"
        self.assert_error(f"current location names '{SPARK}'")

    def test_nonoperative_entry_may_name_only_a_historical_nonoperative_model(self) -> None:
        # a current binding to a model the active v3 policy marks historical-nonoperative.
        self.native["environments"] = {"glm": {"worker": {"model": SPARK}}}
        self.register["policy_locations"].append(
            {"file": "native-worker-execution.yaml", "pointer": "/environments/glm", "class": "nonoperative",
             "literals": {SPARK: 1}, "reason": "deprecated binding resolved by the general path"})
        self.assertEqual(self.errors(), [])
        self.native["environments"]["glm"]["worker"]["model"] = LUNA
        self.register["policy_locations"][-1]["literals"] = {LUNA: 1}
        self.assert_error(
            f"nonoperative location names '{LUNA}', which task_selected_routing does not mark historical-nonoperative")
        self.register["source_literals"][1]["class"] = "nonoperative"
        self.assert_error(f"scripts/current.py '{LUNA}': nonoperative location names '{LUNA}'")

    def test_register_is_schema_checked(self) -> None:
        self.register["source_literals"][0]["class"] = "currentish"
        self.assert_error("policy/model-identity-scope.yaml: $.source_literals[0].class: must be one of")
        self.register = copy.deepcopy(REGISTER)
        self.register["authority"] = "dispatch"
        self.assert_error("$.authority: must equal \"none\"")
        self.register = copy.deepcopy(REGISTER)
        self.register["source_literals"][0]["count"] = True
        self.assert_error("$.source_literals[0].count: expected integer, found boolean")

    def test_register_entries_cannot_point_outside_scope(self) -> None:
        self.register["source_literals"].append(
            {"path": "tests/fixture.py", "literal": SPARK, "count": 1, "class": "historical", "reason": "x"}
        )
        self.assert_error("names a source outside scripts/")
        self.register = copy.deepcopy(REGISTER)
        self.register["policy_locations"].append(
            {"file": "model-identity-scope.yaml", "pointer": "", "class": "current", "literals": {LUNA: 1}, "reason": "x"}
        )
        self.assert_error("names a policy file that is not scanned")

    def test_duplicate_register_entries_fail(self) -> None:
        self.register["source_literals"].append(copy.deepcopy(self.register["source_literals"][0]))
        self.assert_error(f"repeats source literal '{SPARK}' in scripts/legacy.py")

    def test_register_itself_and_archived_records_are_not_scanned(self) -> None:
        for relative in ("tests/fixtures/old.json", "schemas/old.schema.json", "calibration/old.json",
                         "docs/old.html", "references/old.md", "examples/old.json", "CHANGELOG.md"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'"{SPARK}" "gpt-4.1" "{LUNA}"\n', encoding="utf-8")
        self.register["scope"] = f"mentions {SPARK} and gpt-9.9-unknown"
        self.assertEqual(self.errors(), [])

    def test_cache_directories_are_skipped_but_symlinks_and_undecodable_files_fail(self) -> None:
        cache = self.root / "scripts" / "__pycache__"
        cache.mkdir()
        (cache / "legacy.cpython-314.pyc").write_bytes(b"\xff" + SPARK.encode())
        self.assertEqual(self.errors(), [])
        (self.root / "scripts" / "blob.bin").write_bytes(b"\xff\xfe")
        self.assert_error("cannot read scripts/blob.bin as UTF-8")
        (self.root / "scripts" / "blob.bin").unlink()
        os.symlink(self.root / "scripts" / "legacy.py", self.root / "scripts" / "alias.py")
        self.assert_error("does not follow symlinks")


class RepositoryRegisterTests(unittest.TestCase):
    def test_repository_lint_passes(self) -> None:
        self.assertEqual(_lint().lint_model_identities(ROOT), [])

    def test_glm_primary_worker_binding_is_classified_nonoperative(self) -> None:
        register = json.loads((ROOT / "policy" / "model-identity-scope.yaml").read_text(encoding="utf-8"))
        entries = {(entry["file"], entry["pointer"]): entry for entry in register["policy_locations"]}
        binding = entries[("execution-environments.yaml", "/profiles/connected-codex-glm-primary/role_bindings")]
        self.assertEqual((binding["class"], binding["literals"]), ("nonoperative", {SPARK: 1}))
        self.assertIn("nonoperative_model_refusal", binding["reason"])
        legacy = entries[("execution-environments.yaml", "/profiles/connected-codex-glm-primary/operative_routing")]
        self.assertEqual((legacy["class"], legacy["literals"]), ("historical", {SPARK: 1}))
        self.assertEqual(
            [key for key, entry in entries.items() if entry["class"] == "nonoperative"],
            [("execution-environments.yaml", "/profiles/connected-codex-glm-primary/role_bindings")],
        )

    def test_register_grants_nothing_and_has_no_runtime_reader(self) -> None:
        register = json.loads((ROOT / "policy" / "model-identity-scope.yaml").read_text(encoding="utf-8"))
        self.assertEqual(register["authority"], "none")
        readers = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "scripts").rglob("*.py")
            if "model-identity-scope" in path.read_text(encoding="utf-8")
            or "model_identity_scope" in path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            readers,
            ["scripts/cwo_core/__init__.py", "scripts/cwo_core/model_identity_scope.py", "scripts/cwo_core/policy_schema.py",
             "scripts/validate_repository.py"],
        )


class RepositoryValidatorCopyTests(unittest.TestCase):
    """The real repository validator, run on a disposable copy with one change."""

    def run_validator(self, change: Any = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            copy_root = Path(tmpdir) / "repo"
            shutil.copytree(ROOT, copy_root, ignore=COPY_IGNORE, symlinks=True)
            if change is not None:
                change(copy_root)
            env = {key: value for key, value in os.environ.items() if not key.startswith("PYTHON")}
            return subprocess.run(
                [sys.executable, "-B", "scripts/validate_repository.py"],
                cwd=copy_root, env=env, capture_output=True, text=True, timeout=900, check=False,
            )

    @staticmethod
    def edit(root: Path, relative: str, old: str, new: str) -> None:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"{old!r} not found in {relative}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_unchanged_copy_passes(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])

    def test_literals_in_archived_records_do_not_fail(self) -> None:
        def change(root: Path) -> None:
            (root / "tests" / "fixtures" / "w10a-archived-note.txt").write_text(f"{SPARK} gpt-9.9-archived\n", encoding="utf-8")
            (root / "calibration" / "w10a-archived-note.txt").write_text("gpt-9.9-archived\n", encoding="utf-8")
            with (root / "CHANGELOG.md").open("a", encoding="utf-8") as handle:
                handle.write("\n- Historical note naming gpt-9.9-archived.\n")

        result = self.run_validator(change)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])

    def test_current_policy_binding_to_a_historical_model_fails(self) -> None:
        def change(root: Path) -> None:
            self.edit(root, "policy/execution-environments.yaml", '"model": "gpt-6.1-sol"', f'"model": "{SPARK}"')

        result = self.run_validator(change)
        self.assertEqual(result.returncode, 1, result.stdout[-2000:])
        self.assertIn(
            f"policy/execution-environments.yaml#/profiles/connected-codex/role_bindings: current location names '{SPARK}'",
            result.stderr,
        )

    def test_new_unclassified_runtime_default_fails(self) -> None:
        def change(root: Path) -> None:
            with (root / "scripts" / "route_work.py").open("a", encoding="utf-8") as handle:
                handle.write(f'\nNEW_DEFAULT_MODEL = "{SPARK}"\n')

        result = self.run_validator(change)
        self.assertEqual(result.returncode, 1, result.stdout[-2000:])
        self.assertIn(f"unclassified model identity '{SPARK}' in scripts/route_work.py (1 occurrence)", result.stderr)

    def test_rewriting_a_frozen_historical_literal_fails(self) -> None:
        def change(root: Path) -> None:
            self.edit(
                root, "scripts/cwo_core/native_live_campaign_contracts.py",
                f'EXACT_OPERATIVE_MODEL = "{SPARK}"', f'EXACT_OPERATIVE_MODEL = "{LUNA}"',
            )

        result = self.run_validator(change)
        self.assertEqual(result.returncode, 1, result.stdout[-2000:])
        self.assertIn(
            f"scripts/cwo_core/native_live_campaign_contracts.py '{SPARK}': '{SPARK}' found 3 time(s), register pins 4",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
