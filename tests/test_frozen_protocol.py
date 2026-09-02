from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.frozen_protocol import (  # noqa: E402
    NEW_PROTOCOL_REQUIRED,
    PROTOCOL_BLOCKED,
    PROTOCOL_READY,
    evaluate_frozen_protocol,
    file_sha256,
    inspect_python_cache_drift,
    repair_python_cache_drift,
    seal_frozen_protocol_lock,
    validate_frozen_protocol_lock,
)


SCRIPT = ROOT / "scripts" / "validate_frozen_protocol.py"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class FrozenProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cwo-protocol-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        for relative, content in (
            ("brief.md", "governing frozen brief\n"),
            ("controller.py", "CONTROLLER = 'frozen'\n"),
            ("manifest.json", '{"status":"frozen"}\n'),
            ("candidate-e.md", "candidate e\n"),
            ("context/report.html", "authoring context v1\n"),
        ):
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.contract = {
            "scenario_count": 3,
            "arms": ["candidate-c", "candidate-e", "candidate-f"],
            "initial_cells": 9,
            "compatibility_smoke_cells": 3,
            "confirmation_max_cells": 6,
            "retry_limit": 0,
            "decision_rule_sha256": _sha("frozen-decision-rule"),
            "immutable_fields": [
                "controller",
                "manifest",
                "tasks",
                "prompts",
                "scoring",
                "thresholds",
                "budget",
                "decision-rule",
            ],
            "forbidden_substitutions": [
                "benchmark-replacement",
                "task-family-replacement",
                "controller-replacement",
            ],
        }
        self.lock = seal_frozen_protocol_lock(
            {
                "schema_version": "cwo-frozen-protocol-lock:v1",
                "protocol_id": "tier2-locked-test",
                "governing_prompt": {
                    "label": "governing-prompt",
                    "path": "brief.md",
                    "sha256": file_sha256(self.base / "brief.md"),
                },
                "execution_bindings": [
                    {
                        "label": "controller",
                        "path": "controller.py",
                        "sha256": file_sha256(self.base / "controller.py"),
                    },
                    {
                        "label": "manifest",
                        "path": "manifest.json",
                        "sha256": file_sha256(self.base / "manifest.json"),
                    },
                    {
                        "label": "candidate-e",
                        "path": "candidate-e.md",
                        "sha256": file_sha256(self.base / "candidate-e.md"),
                    },
                ],
                "run_contract": self.contract,
                "authoring_provenance": [
                    {
                        "label": "context-report",
                        "path": "context/report.html",
                        "sha256": file_sha256(self.base / "context/report.html"),
                    }
                ],
            }
        )
        self.run = {
            "schema_version": "cwo-frozen-protocol-run:v1",
            "protocol_id": self.lock["protocol_id"],
            "lock_sha256": self.lock["lock_sha256"],
            "run_contract": copy.deepcopy(self.contract),
            "steering": {
                "classification": "continue",
                "instruction_sha256": _sha("proceed within frozen protocol"),
                "changed_locked_fields": [],
                "replacement_authorization_sha256": None,
                "repair_class": None,
            },
        }

    def evaluate(self, run: dict | None = None) -> dict:
        return evaluate_frozen_protocol(
            self.lock,
            run or self.run,
            base_dir=self.base,
        )

    def test_exact_frozen_protocol_is_ready(self) -> None:
        report = self.evaluate()
        self.assertEqual(report["decision"], PROTOCOL_READY)
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(report["reasons"], [])
        self.assertFalse(report["authoring_provenance"]["live_gated"])

    def test_execution_binding_and_run_contract_drift_fail_closed(self) -> None:
        (self.base / "controller.py").write_text("changed\n", encoding="utf-8")
        report = self.evaluate()
        self.assertEqual(report["decision"], PROTOCOL_BLOCKED)
        self.assertIn("execution-binding-drift:controller", report["reasons"])

        (self.base / "controller.py").write_text(
            "CONTROLLER = 'frozen'\n", encoding="utf-8"
        )
        changed = copy.deepcopy(self.run)
        changed["run_contract"].update({"scenario_count": 4, "initial_cells": 12})
        report = self.evaluate(changed)
        self.assertEqual(report["decision"], PROTOCOL_BLOCKED)
        self.assertIn("run contract differs from frozen protocol", report["reasons"])

    def test_nonportable_or_parent_paths_fail_closed(self) -> None:
        for invalid in (
            "..",
            "../controller.py",
            "sealed/..",
            "sealed/./controller.py",
            "sealed//controller.py",
            "sealed/controller.py/",
            "sealed\\controller.py",
            "sealed/controll\x00er.py",
        ):
            with self.subTest(path=invalid):
                changed = copy.deepcopy(self.lock)
                changed["execution_bindings"][0]["path"] = invalid
                changed = seal_frozen_protocol_lock(changed)
                errors = validate_frozen_protocol_lock(changed)
                self.assertTrue(
                    any("normalized relative POSIX path" in error for error in errors),
                    errors,
                )

        duplicate = copy.deepcopy(self.lock)
        duplicate["execution_bindings"][1]["path"] = duplicate[
            "execution_bindings"
        ][0]["path"]
        duplicate = seal_frozen_protocol_lock(duplicate)
        self.assertIn(
            "lock.execution_bindings paths must be unique",
            validate_frozen_protocol_lock(duplicate),
        )

    def test_general_steering_does_not_authorize_replacement(self) -> None:
        steering_pressure = (
            "the tests are too narrow",
            "proceed with the complete plan",
            "step over blocking ceremony",
            "repair until completion",
            "full_auto",
        )
        for instruction in steering_pressure:
            with self.subTest(instruction=instruction):
                changed = copy.deepcopy(self.run)
                changed["steering"]["instruction_sha256"] = _sha(instruction)
                changed["run_contract"].update(
                    {"scenario_count": 4, "initial_cells": 12}
                )
                report = self.evaluate(changed)
                self.assertEqual(report["decision"], PROTOCOL_BLOCKED)
                self.assertIn(
                    "run contract differs from frozen protocol", report["reasons"]
                )

    def test_explicit_replacement_requires_a_new_lock(self) -> None:
        changed = copy.deepcopy(self.run)
        changed["steering"] = {
            "classification": "replace-protocol",
            "instruction_sha256": _sha("replace the frozen benchmark explicitly"),
            "changed_locked_fields": ["tasks", "controller"],
            "replacement_authorization_sha256": _sha("operator authorization"),
            "repair_class": None,
        }
        report = self.evaluate(changed)
        self.assertEqual(report["decision"], NEW_PROTOCOL_REQUIRED)
        self.assertIn(
            "authorized-replacement-requires-new-protocol-lock", report["reasons"]
        )

    def test_unauthorized_replacement_is_blocked(self) -> None:
        changed = copy.deepcopy(self.run)
        changed["steering"] = {
            "classification": "replace-protocol",
            "instruction_sha256": _sha("replacement without explicit authorization"),
            "changed_locked_fields": ["tasks"],
            "replacement_authorization_sha256": None,
            "repair_class": None,
        }
        report = self.evaluate(changed)
        self.assertEqual(report["decision"], PROTOCOL_BLOCKED)
        self.assertIn("replacement-authorization-missing", report["reasons"])

    def test_typed_same_scope_repair_preserves_the_lock(self) -> None:
        changed = copy.deepcopy(self.run)
        changed["steering"] = {
            "classification": "same-scope-repair",
            "instruction_sha256": _sha("repair bytecode permission drift"),
            "changed_locked_fields": [],
            "replacement_authorization_sha256": None,
            "repair_class": "mechanical-derived-cache",
        }
        self.assertEqual(self.evaluate(changed)["decision"], PROTOCOL_READY)

    def test_authoring_provenance_drift_is_recorded_but_not_live_gated(self) -> None:
        (self.base / "context/report.html").write_text(
            "legitimate later report revision\n", encoding="utf-8"
        )
        report = self.evaluate()
        self.assertEqual(report["decision"], PROTOCOL_READY)
        self.assertEqual(
            report["authoring_provenance"]["recorded_labels"], ["context-report"]
        )
        self.assertNotIn("context-report", report["live_execution_bindings"])

    def test_recognized_compile_cache_drift_is_repaired_without_source_change(self) -> None:
        sealed = self.base / "sealed"
        sealed.mkdir()
        source = sealed / "engine.py"
        source.write_text("ENGINE = 'sealed'\n", encoding="utf-8")
        source.chmod(0o600)
        before = file_sha256(source)
        cache = sealed / "__pycache__"
        cache.mkdir(mode=0o755)
        (cache / "engine.cpython-314.pyc").write_bytes(b"derived bytecode")
        observed = inspect_python_cache_drift(sealed)
        self.assertEqual(observed["status"], "repairable-derived-cache")

        repaired = repair_python_cache_drift(sealed)
        self.assertEqual(repaired["status"], "repaired")
        self.assertEqual(repaired["after"]["status"], "clean")
        self.assertFalse(cache.exists())
        self.assertEqual(file_sha256(source), before)
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)

    def test_suspicious_cache_content_and_symlinks_are_never_removed(self) -> None:
        sealed = self.base / "sealed-suspicious"
        cache = sealed / "__pycache__"
        cache.mkdir(parents=True)
        note = cache / "note.txt"
        note.write_text("not derived bytecode\n", encoding="utf-8")
        report = repair_python_cache_drift(sealed)
        self.assertEqual(report["status"], "repair-blocked")
        self.assertTrue(note.exists())

        note.unlink()
        target = self.base / "outside.pyc"
        target.write_bytes(b"outside")
        (cache / "linked.pyc").symlink_to(target)
        report = repair_python_cache_drift(sealed)
        self.assertEqual(report["status"], "repair-blocked")
        self.assertTrue((cache / "linked.pyc").is_symlink())

    def test_cli_blocks_drift_and_reports_new_protocol_separately(self) -> None:
        lock_path = self.base / "lock.json"
        run_path = self.base / "run.json"
        lock_path.write_text(json.dumps(self.lock), encoding="utf-8")
        run_path.write_text(json.dumps(self.run), encoding="utf-8")
        ready = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(lock_path),
                "--run-spec",
                str(run_path),
                "--base-dir",
                str(self.base),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(ready.returncode, 0, ready.stderr)
        self.assertEqual(json.loads(ready.stdout)["decision"], PROTOCOL_READY)

        replacement = copy.deepcopy(self.run)
        replacement["steering"] = {
            "classification": "replace-protocol",
            "instruction_sha256": _sha("explicit replacement"),
            "changed_locked_fields": ["tasks"],
            "replacement_authorization_sha256": _sha("explicit authorization"),
            "repair_class": None,
        }
        run_path.write_text(json.dumps(replacement), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(lock_path),
                "--run-spec",
                str(run_path),
                "--base-dir",
                str(self.base),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["decision"], NEW_PROTOCOL_REQUIRED
        )

    def test_cli_cache_repair_requires_typed_authority_and_rejects_symlinks(self) -> None:
        lock_path = self.base / "lock.json"
        run_path = self.base / "run.json"
        lock_path.write_text(json.dumps(self.lock), encoding="utf-8")
        run_path.write_text(json.dumps(self.run), encoding="utf-8")
        cache = self.base / "sealed" / "__pycache__"
        cache.mkdir(parents=True)
        bytecode = cache / "engine.cpython-314.pyc"
        bytecode.write_bytes(b"derived bytecode")
        command = [
            sys.executable,
            str(SCRIPT),
            str(lock_path),
            "--run-spec",
            str(run_path),
            "--base-dir",
            str(self.base),
            "--cache-root",
            "sealed",
            "--repair-derived-cache",
        ]
        unauthorized = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, check=False
        )
        self.assertEqual(unauthorized.returncode, 2, unauthorized.stderr)
        self.assertTrue(bytecode.exists())
        self.assertEqual(
            json.loads(unauthorized.stdout)["cache"][0]["status"],
            "repair-blocked",
        )

        authorized_run = copy.deepcopy(self.run)
        authorized_run["steering"] = {
            "classification": "same-scope-repair",
            "instruction_sha256": _sha("repair derived cache"),
            "changed_locked_fields": [],
            "replacement_authorization_sha256": None,
            "repair_class": "mechanical-derived-cache",
        }
        run_path.write_text(json.dumps(authorized_run), encoding="utf-8")
        authorized = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, check=False
        )
        self.assertEqual(authorized.returncode, 0, authorized.stderr)
        self.assertFalse(cache.exists())

        target = self.base / "sealed-target"
        target_cache = target / "__pycache__"
        target_cache.mkdir(parents=True)
        target_bytecode = target_cache / "engine.cpython-314.pyc"
        target_bytecode.write_bytes(b"derived bytecode")
        (self.base / "sealed-link").symlink_to(target, target_is_directory=True)
        symlink_command = command.copy()
        symlink_command[symlink_command.index("sealed")] = "sealed-link"
        rejected = subprocess.run(
            symlink_command, cwd=ROOT, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("must not traverse a symlink", rejected.stderr)
        self.assertTrue(target_bytecode.exists())

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_json_schemas_accept_the_valid_lock_and_run(self) -> None:
        import jsonschema

        lock_schema = json.loads(
            (ROOT / "schemas/frozen-protocol-lock.schema.json").read_text(
                encoding="utf-8"
            )
        )
        run_schema = json.loads(
            (ROOT / "schemas/frozen-protocol-run.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.validate(self.lock, lock_schema)
        jsonschema.validate(self.run, run_schema)
        invalid_lock = copy.deepcopy(self.lock)
        invalid_lock["execution_bindings"][0]["path"] = "../controller.py"
        invalid_lock = seal_frozen_protocol_lock(invalid_lock)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid_lock, lock_schema)
        invalid_run = copy.deepcopy(self.run)
        invalid_run["steering"]["classification"] = "replace-protocol"
        invalid_run["steering"]["changed_locked_fields"] = ["tasks"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid_run, run_schema)


if __name__ == "__main__":
    unittest.main()
