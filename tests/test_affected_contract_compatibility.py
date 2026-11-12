"""Public checkpoint bindings and portable offline compatibility matrices."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_affected_historical_contract as checkpoint
from tests.real_beads_fixture import configure_git_fixture


def _copy_checkpoint(root):
    manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
    for name in [*manifest["files"], checkpoint.MANIFEST]:
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    return manifest


def _assert_fixture_scope(case, observed):
    case.assertEqual(observed["evidence_scope"], "bounded-neutral-fixture-only")
    case.assertTrue(observed["fixture_evidence_verified"])
    for field in ("historical_artifacts_verified", "historical_semantic_acceptance",
                  "effect_authority", "current_authority"):
        case.assertIs(observed[field], False)
    case.assertIs(observed["archived_metadata"]["reverified"], False)
    case.assertNotIn("source_revision", observed)
    case.assertNotIn("source_tree", observed)


def _invalid_fixture_objects(document):
    evidence = document["portable_contract_evidence"]
    changes = [("schema", "unknown"), ("version", True), ("version", "1"), ("version", 1.0), ("version", 2),
               ("effect_authority", 0), ("effect_authority", True), ("scope", "history-verified"),
               ("provider_v1_schema", []), ("production_pre_move_metadata_sha256", 0),
               ("production_pre_move_identities", []), ("production_generation11_sources", {}),
               ("sources", []), ("sources", {"surface": "incomplete"}),
               ("sources", dict(evidence["sources"], surface=False)),
               ("production_pre_move_identities", list(reversed(evidence["production_pre_move_identities"]))),
               ("production_generation11_sources", dict(evidence["production_generation11_sources"], runner="0" * 64)),
               ("archived_source_projection_sha256", "0" * 64)]
    for key, value in changes:
        changed = deepcopy(document)
        changed["portable_contract_evidence"][key] = value
        yield key + "=" + repr(value), changed
    for key in ("scope", "sources"):
        changed = deepcopy(document)
        del changed["portable_contract_evidence"][key]
        yield "missing-" + key, changed
    changed = deepcopy(document)
    changed["portable_contract_evidence"]["extra"] = False
    yield "extra-field", changed
    changed = deepcopy(document)
    changed["portable_contract_evidence"]["sources"] = dict(evidence["sources"], extra="unused")
    yield "extra-source", changed


def _assert_fixture_file_refusals(case, root, path, raw, manifest):
    for invalid in (raw[:len(raw) // 2], b" " * (checkpoint.ARTIFACT_CAP + 1)):
        path.write_bytes(invalid)
        with case.assertRaises(checkpoint.CompatibilityRefusal):
            checkpoint.verify_fixture_evidence(root, manifest)
    path.unlink()
    path.mkdir()
    with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "fixture missing"):
        checkpoint.verify_fixture_evidence(root, manifest)
    path.rmdir()
    os.mkfifo(path)
    with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "fixture missing"):
        checkpoint.verify_fixture_evidence(root, manifest)
    path.unlink()
    target = root / "neutral.json"
    target.write_bytes(raw)
    path.symlink_to(target)
    with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "fixture missing"):
        checkpoint.verify_fixture_evidence(root, manifest)
    path.unlink()
    path.write_bytes(raw)
    path.chmod(0o755)
    with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "fixture mode mismatch"):
        checkpoint.verify_fixture_evidence(root, manifest)
    path.chmod(0o644)
    parent = path.parent
    renamed = parent.with_name("neutral-inputs")
    parent.rename(renamed)
    parent.symlink_to(renamed, target_is_directory=True)
    with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "fixture missing"):
        checkpoint.verify_fixture_evidence(root, manifest)
    parent.unlink()
    renamed.rename(parent)


def _change_archived_table(files, kind):
    if kind == "remove":
        files.pop(next(iter(files)))
    elif kind == "add":
        files["neutral-extra.py"] = "0" * 64
    else:
        files[next(iter(files))] = "0" * 64


def _fixture_checkpoint_observation():
    """Child observation with real validators and explicit original-Git read spies."""
    from cwo_core import workspace_capture

    actual_git = workspace_capture.trusted_git_completed

    def fixture_git(root, *args, **kwargs):
        if Path(root).resolve() == ROOT:
            raise AssertionError("private repository Git must not be read")
        return actual_git(root, *args, **kwargs)

    with patch.object(checkpoint, "git_bytes", side_effect=AssertionError("private history must not be read")), \
            patch.object(workspace_capture, "trusted_git_completed", side_effect=fixture_git):
        return checkpoint.verify_fixture_checkpoint()


class AffectedContractCompatibilityTests(unittest.TestCase):
    def test_checkpoint_binds_both_consumers_and_approved_source_history(self):
        # File workunits import sibling tests before running cases. Give the
        # positive observation its own actual source closure, without changing
        # the helper's refusal of unrelated modules in the shared parent.
        command = [sys.executable, "-c", "import json; "
                   "from tests.test_affected_contract_compatibility import _fixture_checkpoint_observation; "
                   "print(json.dumps(_fixture_checkpoint_observation(), sort_keys=True))"]
        child = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
        receipt = json.dumps({"argv": command, "exit_code": child.returncode,
                              "stdout": child.stdout, "stderr": child.stderr})
        self.assertEqual(child.returncode, 0, receipt)
        self.assertEqual(child.stderr, "", receipt)
        observed = json.loads(child.stdout)
        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        self.assertEqual(len(manifest["consumer_changes"]), 2)
        _assert_fixture_scope(self, observed)
        self.assertTrue(observed["current_dependency_bindings_verified"])
        self.assertIn("scripts/verify_affected_historical_contract.py", observed["loaded_python_files"]["loaded_local_paths"])
        self.assertEqual(observed["behavior_observations"]["registered_consumers"]["hostless_execution_refusal"],
                         "registered-pool-host-required")
        self.assertEqual(observed["dependency_count"], len(manifest["files"]))
        self.assertIn("scripts/offline_admitted_n1.py", manifest["files"])
        preview = "scripts/run_native_pool_activation_preview.py"
        self.assertIn(preview, manifest["files"])
        self.assertIn(preview, manifest["installed_child_probe"]["roots"])
        self.assertIn(preview, manifest["local_import_edges"][manifest["installed_child_probe"]["producer"]])
        self.assertIn("scripts/qualified_review_dispatch.py",
                      manifest["local_import_edges"]["scripts/dispatch_work.py"])
        self.assertEqual(
            set(manifest["local_import_edges"]["tests/test_local_admission_preparation.py"]),
            {"scripts/prepare_local_admission.py", "scripts/prepare_route_feasibility.py",
             "scripts/prepare_route_ledger_reconciliation.py", "tests/test_invocation_ledger.py",
             "tests/test_route_feasibility_preparation.py"})
        before, after = list(checkpoint.HISTORY)[1:3]
        for path in ("scripts/cwo_core/codex_tool_surface.py",
                     "scripts/cwo_core/supervision/transport/app_server.py",
                     "scripts/cwo_core/supervision/transport/errors.py"):
            self.assertEqual(manifest["historical_files"][before][path],
                             manifest["historical_files"][after][path])

    def test_unknown_record_selected_revision_and_interpreter_refuse_before_git_or_import(self):
        with patch.object(checkpoint, "git_bytes", side_effect=AssertionError("must not read history")):
            for revision in ("d77dd2f824a75bf7c85b6dff9fb83333089d6ad0", "bf36658b5b76845ac662daebb842a80eb8923947", "0" * 40, "EXAMPLE-unknown-revision", "HEAD", "../../EXAMPLE"):
                with self.subTest(revision=revision), self.assertRaisesRegex(
                        checkpoint.CompatibilityRefusal, "record selection forbidden"):
                    checkpoint.verify_checkpoint(source_revision=revision)
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "unsupported interpreter"):
                checkpoint.verify_checkpoint(interpreter=(3, 13))
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "bounded-neutral-fixture-only.*unsupported interpreter"):
                checkpoint.verify_fixture_checkpoint(interpreter=(3, 13))
            with self.assertRaises(TypeError):
                checkpoint.verify_fixture_checkpoint(source_revision="HEAD")

    def test_missing_and_changed_dependency_and_artifact_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "scoped manifest missing"):
                checkpoint.verify_checkpoint(root=root)
            path = root / "EXAMPLE-dependency.py"
            expected = {path.name: checkpoint.digest(b"EXAMPLE trusted bytes")}
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                checkpoint.verify_files(root, expected)
            path.write_bytes(b"EXAMPLE changed bytes")
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency drift"):
                checkpoint.verify_files(root, expected)

    def test_real_unavailable_git_history_refuses_without_rewriting_real_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            configure_git_fixture(root)
            manifest = _copy_checkpoint(root)
            _assert_fixture_scope(self, checkpoint.verify_fixture_evidence(root, manifest))
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "history/artifact unavailable"):
                checkpoint.git_bytes(root, checkpoint.SOURCE)
            with patch.object(checkpoint, "verify_fixture_evidence", side_effect=AssertionError("no fallback")), \
                    patch.object(checkpoint, "verify_fixture_checkpoint", side_effect=AssertionError("no fallback")):
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "history/artifact unavailable"):
                    checkpoint.verify_history(root, manifest)
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "history/artifact unavailable"):
                    checkpoint.verify_checkpoint(root=root)
            (root / checkpoint.FIXTURE_PATH).unlink()
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "public contract fixture missing"):
                checkpoint.verify_fixture_evidence(root, manifest)

    def test_missing_approved_historical_artifact_refuses(self):
        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        altered = deepcopy(manifest)
        altered["historical_files"][checkpoint.SOURCE] = {"EXAMPLE-absent.py": "0" * 64}
        with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "archived source projection mismatch"):
            checkpoint.verify_fixture_evidence(ROOT, altered)
        from tests.historical_policy_fixtures import CONTRACT_EVIDENCE_PATH

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / CONTRACT_EVIDENCE_PATH
            target.parent.mkdir(parents=True)
            value = json.loads((ROOT / CONTRACT_EVIDENCE_PATH).read_bytes())
            value["portable_contract_evidence"]["sources"]["surface"] += "\n"
            target.write_text(json.dumps(value))
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "public contract fixture digest mismatch"):
                checkpoint.verify_fixture_evidence(root, manifest)
            # An editable manifest self-hash cannot authorize changed neutral inputs.
            altered = deepcopy(manifest)
            altered["portable_contract_evidence"]["canonical_sha256"] = checkpoint.digest(
                checkpoint.canonical(value["portable_contract_evidence"]))
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "public contract evidence binding mismatch"):
                checkpoint.verify_fixture_evidence(root, altered)
            target.write_bytes((ROOT / CONTRACT_EVIDENCE_PATH).read_bytes())
            altered = deepcopy(manifest)
            altered["portable_contract_evidence"]["canonical_sha256"] = "0" * 64
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "public contract evidence binding mismatch"):
                checkpoint.verify_fixture_evidence(root, altered)

    def test_strict_history_checks_real_neutral_trees_and_blobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            configure_git_fixture(root)
            (root / "neutral.txt").write_bytes(b"neutral contract input\n")
            subprocess.run(["git", "-C", str(root), "add", "neutral.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "Neutral fixture"], check=True)
            revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            tree = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip()
            files = {"neutral.txt": checkpoint.digest(b"neutral contract input\n")}
            manifest = {"historical_files": {revision: files}}
            with patch.object(checkpoint, "HISTORY", {revision: tree}):
                checkpoint.verify_history(root, manifest)
                for changed, error in (({"missing.txt": "0" * 64}, "history/artifact unavailable"),
                                       ({"neutral.txt": "0" * 64}, "historical source artifact mismatch")):
                    with self.subTest(error=error), self.assertRaisesRegex(checkpoint.CompatibilityRefusal, error):
                        checkpoint.verify_history(root, {"historical_files": {revision: changed}})
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "unapproved manifest history"):
                    checkpoint.verify_history(root, {"historical_files": {"0" * 40: files}})
            with patch.object(checkpoint, "HISTORY", {revision: "0" * 40}):
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "approved source tree mismatch"):
                    checkpoint.verify_history(root, manifest)

    def test_fixture_envelope_rejects_types_rosters_and_noncanonical_json(self):
        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        document = json.loads((ROOT / checkpoint.FIXTURE_PATH).read_bytes())
        valid = json.dumps(document).encode()
        selected = b'{"portable_contract_evidence":' + checkpoint.canonical(document["portable_contract_evidence"])
        malformed = [b"{", b"[]", selected + b',"x": 1, "x": 2}',
                     selected + b',"x": NaN}', selected + b',"x": Infinity}',
                     selected + b',"x": 1e999}', selected + b',"x":' + b'[' * 40 + b'0' + b']' * 40 + b'}']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / checkpoint.FIXTURE_PATH
            path.parent.mkdir(parents=True)
            for label, value in _invalid_fixture_objects(document):
                path.write_text(json.dumps(value))
                with self.subTest(label=label), self.assertRaises(checkpoint.CompatibilityRefusal) as refusal:
                    checkpoint.verify_fixture_evidence(root, manifest)
                self.assertEqual(refusal.exception.evidence_scope, checkpoint.FIXTURE_SCOPE)
            for raw in malformed:
                path.write_bytes(raw)
                with self.subTest(raw=raw[:40]), self.assertRaises(checkpoint.CompatibilityRefusal):
                    checkpoint.verify_fixture_evidence(root, manifest)
            path.write_bytes(valid)
            _assert_fixture_scope(self, checkpoint.verify_fixture_evidence(root, manifest))

    def test_fixture_artifact_refuses_unsafe_paths_modes_and_archived_table_drift(self):
        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / checkpoint.FIXTURE_PATH
            path.parent.mkdir(parents=True)
            raw = (ROOT / checkpoint.FIXTURE_PATH).read_bytes()
            _assert_fixture_file_refusals(self, root, path, raw, manifest)
            path.write_bytes(raw)
            for name in ("../elsewhere.json", "/elsewhere.json", "other.json"):
                changed = deepcopy(manifest)
                changed["portable_contract_evidence"]["path"] = name
                with self.subTest(path=name), self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "binding mismatch"):
                    checkpoint.verify_fixture_evidence(root, changed)
            for key, value in (("schema", "unknown"), ("version", True), ("version", 2),
                               ("effect_authority", 0), ("effect_authority", True)):
                changed = deepcopy(manifest)
                changed["portable_contract_evidence"][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "binding mismatch"):
                    checkpoint.verify_fixture_evidence(root, changed)
            for kind in ("remove", "add", "digest"):
                changed = deepcopy(manifest)
                files = next(iter(changed["historical_files"].values()))
                _change_archived_table(files, kind)
                with self.subTest(kind=kind), self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "archived source projection mismatch"):
                    checkpoint.verify_fixture_evidence(root, changed)

    def test_fixture_checkpoint_keeps_current_modes_rosters_and_loaded_source_closure(self):
        from types import ModuleType

        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        unbound = ModuleType("neutral_unbound_source")
        unbound.__file__ = str(ROOT / "tests/test_comparative_evaluation.py")
        self.assertNotIn("tests/test_comparative_evaluation.py", manifest["files"])
        with patch.dict(sys.modules, {unbound.__name__: unbound}):
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "loaded dependency missing/drifted"):
                checkpoint.verify_fixture_checkpoint()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_checkpoint(root)
            path = root / "scripts/registered_native_pool_host.py"
            path.chmod(manifest["current_file_modes"][str(path.relative_to(root))] ^ 0o100)
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency mode drift"):
                checkpoint.verify_fixture_checkpoint(root=root)
            path.chmod(manifest["current_file_modes"][str(path.relative_to(root))])
            renamed = path.with_suffix(".neutral")
            path.rename(renamed)
            path.symlink_to(renamed)
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                checkpoint.verify_fixture_checkpoint(root=root)
            path.unlink()
            renamed.rename(path)
            # Omission from both tables must not shorten the mandatory current closure.
            key = "policy/provider-registry.yaml"
            del manifest["files"][key]
            del manifest["current_file_modes"][key]
            (root / checkpoint.MANIFEST).write_text(json.dumps(manifest))
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "required current dependency roster mismatch"):
                checkpoint.verify_fixture_checkpoint(root=root)
            manifest_path = root / checkpoint.MANIFEST
            renamed = root / "neutral-manifest.json"
            manifest_path.rename(renamed)
            manifest_path.symlink_to(renamed)
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "scoped manifest missing"):
                checkpoint.verify_fixture_checkpoint(root=root)

    def test_copied_manifest_detects_actual_consumer_drift(self):
        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in manifest["files"]:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            checkpoint.verify_files(root, manifest["files"])
            for name in ("scripts/prepare_local_admission.py", "scripts/run_native_pool_activation_preview.py",
                         "scripts/cwo_core/routing.py", "scripts/cwo_core/risk_features.py",
                         "scripts/dispatch_work.py", "scripts/qualified_review_dispatch.py"):
                changed = root / name
                original = changed.read_bytes()
                changed.write_bytes(original + b"\n# EXAMPLE drift\n")
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, name):
                    checkpoint.verify_files(root, manifest["files"])
                changed.unlink()  # Disposable fixture only; real source/history stay intact.
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                    checkpoint.verify_files(root, manifest["files"])
                changed.write_bytes(original)

    def test_f5_retired_surface_mechanics_keep_current_hold_after_scoped_fake_controls(self):
        # Intentionally repeats only the existing affected transport surface section.
        from cwo_core import native_live_availability
        held_before = native_live_availability.N1_LIVE_AVAILABLE
        result = checkpoint.surface_observations()
        self.assertIs(native_live_availability.N1_LIVE_AVAILABLE, held_before)
        for label in ("v2-historical", "v3-historical", "v4-historical"):
            self.assertEqual(result["verifier"][label]["historical_verifier_errors"], [])
            self.assertEqual(result["entry_points"][label]["app_server_construction"]["popen_calls"], 0)
            self.assertEqual(result["entry_points"][label]["thread_start"]["request_calls"], 0)
        for label in ("v3-relabelled-as-v5", "v4-converted-to-v5"):
            self.assertEqual(result["entry_points"][label]["app_server_construction"]["popen_calls"], 0)
            self.assertEqual(result["entry_points"][label]["thread_start"]["request_calls"], 0)
        self.assertEqual(result["entry_points"]["v5-current"]["app_server_construction"]["popen_calls"], 1)
        self.assertEqual(result["entry_points"]["v5-current"]["thread_start"]["request_calls"], 1)

    def test_real_admission_snapshot_roundtrip_and_negative_outcome_records(self):
        result = checkpoint.admission_observations()
        self.assertEqual(result["adapter-produced-v1"]["status"], "within-declared-limits")
        for label in ("malformed", "tampered-charge", "mismatched-scope", "unsupported-ledger-version"):
            self.assertEqual(result[label]["status"], "invalid")
            self.assertTrue(all(value is False for value in result[label]["availability"].values()))
        refused = result["diagnostic-as-admission"]
        self.assertEqual(refused["selected_effects"], 0)
        self.assertTrue(refused["ledger_bytes_unchanged"])
        self.assertEqual(refused["outcome"], "A complete immutable offline admission is required.")


if __name__ == "__main__":
    unittest.main()
