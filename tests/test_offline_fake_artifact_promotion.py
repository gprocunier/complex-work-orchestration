from __future__ import annotations

import concurrent.futures
import copy
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import offline_fake_artifact_promotion as PROMOTION  # noqa: E402
import offline_artifact_validation as VALIDATION  # noqa: E402
import offline_n1_host as HOST  # noqa: E402
import test_offline_artifact_validation as FIXTURE  # noqa: E402
import test_offline_n1_host as N1  # noqa: E402
from cwo_core.native_control import NativeControlTurn  # noqa: E402

EXAMPLE_INITIAL = {"unrelated.txt": b"EXAMPLE unrelated initial bytes\n"}
EXAMPLE_LIMITS = {"max_files": 8, "max_file_bytes": HOST.MAX_FILE_BYTES,
                  "max_total_bytes": HOST.MAX_ARTIFACT_BYTES, "max_entries": 64}


def read_only_host(method):
    """Opt a case into sharing only the completed, read-only original producer."""
    method.read_only_host = True
    return method


def host_snapshot(fixture, host):
    """Bind shared bytes, modes and identities while ignoring access timestamps."""
    return tuple(
        (str(path.relative_to(fixture.helper.root)), HOST._file_mark(path.lstat()),
         path.read_bytes() if path.is_file() else None)
        for root in (fixture.helper.source, host.target, host.worker, host.state)
        for path in (root, *sorted(root.rglob("*")))
    )


class OfflineFakeArtifactPromotionTests(unittest.TestCase):
    @classmethod
    def read_only_fixture(cls):
        if "_read_only_fixture" not in cls.__dict__:
            owner = cls("runTest")
            cls.addClassCleanup(owner.doCleanups)
            fixture = FIXTURE.HostFixture(owner)
            host, report, adapter, server = fixture.ready()
            cls._read_only_fixture = fixture, host, report, adapter, server
            cls._read_only_snapshot = host_snapshot(fixture, host)
            cls.addClassCleanup(delattr, cls, "_read_only_fixture")
            cls.addClassCleanup(delattr, cls, "_read_only_snapshot")
            cls.addClassCleanup(cls.verify_read_only_fixture)
        return cls._read_only_fixture

    @classmethod
    def verify_read_only_fixture(cls):
        fixture, host, _report, _adapter, _server = cls._read_only_fixture
        cls("runTest").assertEqual(host_snapshot(fixture, host), cls._read_only_snapshot)

    def assert_read_only_host(self):
        self.assertEqual(host_snapshot(self.fixture, self.host), self._read_only_snapshot)

    def setUp(self):
        # Every mutable projection and operation state remains case-local. New
        # tests use a private producer unless they explicitly opt into sharing.
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        method = getattr(type(self), self._testMethodName)
        if getattr(method, "read_only_host", False):
            self.fixture, self.host, report, self.adapter, self.server = self.read_only_fixture()
            self.report = copy.deepcopy(report)
            self.assert_read_only_host()
            self.addCleanup(self.assert_read_only_host)
        else:
            self.fixture = FIXTURE.HostFixture(self)
            self.host, self.report, self.adapter, self.server = self.fixture.ready()
        self.initial = dict(EXAMPLE_INITIAL)
        self.spec = FIXTURE.specification()
        self.policy = VALIDATION.freeze_policy(self.spec)
        self.assertEqual(self.report["status"], "artifact-ready", self.report["error"])
        self.expected = copy.deepcopy(self.report["binding"]["target"])
        self.token = VALIDATION.validate_artifact(self.host, self.report, self.expected, self.policy)
        self.callbacks = copy.deepcopy(self.adapter.callback_latencies)
        self.sequence = 0

    def target(self, *, initial=None, limits=None, initialize=True):
        self.sequence += 1
        state = self.root / f"EXAMPLE_STATE_{self.sequence}"
        projection = self.root / f"EXAMPLE_PROJECTION_{self.sequence}"
        state.mkdir(mode=0o700)
        projection.mkdir(mode=0o700)
        target = PROMOTION.FakeArtifactTarget(state, projection, self.host, self.expected,
                                             self.initial if initial is None else initial, limits=EXAMPLE_LIMITS if limits is None else limits)
        if initialize:
            target.initialize()
        return target

    def invoke(self, target, **changes):
        values = {"operation_id": "EXAMPLE_FAKE_OPERATION", "issued_token": self.token,
                  "original_report": self.report, "issued_policy": self.policy, "expected_revision": 0}
        values.update(changes)
        with N1.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
            with FIXTURE.effect_guard():
                try:
                    return target.promote(**values)
                finally:
                    self.assertEqual(writes, [])
                    self.assertEqual(self.server.sends, 1)
                    self.assertEqual(self.adapter.callback_latencies, self.callbacks)

    def assert_false(self, report):
        for flag in PROMOTION._FALSE:
            self.assertIs(report[flag], False)

    def assert_no_new_bytes(self, report):
        effects = report["new_invocation"]
        for field in ("files_created", "directories_created", "bytes_written", "pointer_replacements"):
            self.assertEqual(effects[field], 0, field)

    def tree(self, target):
        return tuple((str(path), HOST._file_mark(os.lstat(path)))
                     for root in (target._state, target._target) for path in sorted(root.rglob("*")))

    def refuse(self, target, **changes):
        before = self.tree(target)
        with self.assertRaises(PROMOTION.FakePromotionError) as caught:
            self.invoke(target, **changes)
        report = caught.exception.report
        self.assert_false(report)
        self.assert_no_new_bytes(report)
        self.assertFalse(report["current_applicable"])
        self.assertEqual(self.tree(target), before)
        return report

    def rewrite_record(self, path, change):
        identity = PROMOTION._inode(os.lstat(path))
        record = json.loads(path.read_bytes())
        change(record)
        data = PROMOTION._encode(record)
        path.chmod(0o600)
        try:
            path.write_bytes(data)
        finally:
            path.chmod(0o400)
        self.assertEqual(PROMOTION._inode(os.lstat(path)), identity)
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o400)
        return record

    def fresh(self, target):
        policy = VALIDATION.freeze_policy(self.spec)
        token = VALIDATION.validate_artifact(self.host, self.report, self.expected, policy)
        restarted = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                self.initial, limits=dict(EXAMPLE_LIMITS))
        return restarted, policy, token

    def substitute_generation(self, target):
        files = dict(self.initial)
        files["result.txt"] = b"EXAMPLE substituted output bytes\n"
        projection, manifest = target._projection(files)
        directory = target._target / "generation-0001"
        directory.chmod(0o700)
        for entry, (_relative, data) in zip(manifest["files"], projection):
            path = directory / entry["blob"]
            path.chmod(0o600)
            path.write_bytes(data)
            path.chmod(0o400)
        path = directory / "manifest.json"
        path.chmod(0o600)
        path.write_bytes(PROMOTION._encode(manifest))
        path.chmod(0o400)
        directory.chmod(0o500)
        seal = target._seal(directory)
        self.rewrite_record(target._target / "current.json",
                            lambda record: record.update(target._pointer(1, manifest)))
        pointer = json.loads((target._target / "current.json").read_bytes())

        def journal_change(record):
            record["claim"]["manifest"] = manifest
            record["generation_seal"] = seal
            record["after"] = pointer

        self.rewrite_record(target._state / "journal.json", journal_change)
        journal = json.loads((target._state / "journal.json").read_bytes())
        if (target._state / "receipt.json").exists():
            self.rewrite_record(target._state / "receipt.json",
                                lambda record: record.update(target._receipt_body(journal)))

    def published_without_receipt(self):
        target = self.target()
        original = target._new_record
        failure = OSError("EXAMPLE receipt persistence is unavailable.")

        def record(path, name, data, counts):
            if name == "receipt.json":
                raise failure
            return original(path, name, data, counts)

        with patch.object(target, "_new_record", side_effect=record):
            with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                self.invoke(target)
        self.assertIs(caught.exception.__cause__, failure)
        saved = caught.exception.report
        self.assertEqual(saved["new_invocation"]["pointer_replacements"], 1)
        self.assertEqual(saved["known_publication"]["saved_pointer_publications"], 1)
        self.assertFalse(saved["fake_completion"])
        self.assertFalse((target._state / "receipt.json").exists())
        return target, saved

    @read_only_host
    def test_actual_atomic_fake_switch_preserves_unrelated_files_and_real_repositories(self):
        target = self.target()
        self.assertIs(HOST.NativeControlTurn, NativeControlTurn)
        self.assertIs(type(self.adapter), HOST.LiveThreadAdapter)
        worker = (self.host.worker / "result.txt").read_bytes()
        artifact = (self.host.state / "artifact" / "file-0000").read_bytes()
        result = self.invoke(target)
        snapshot = target.snapshot()
        self.assertEqual(snapshot["revision"], 1)
        self.assertEqual(snapshot["files"], {**EXAMPLE_INITIAL, "result.txt": FIXTURE.EXAMPLE_BYTES})
        self.assertEqual((target._target / "generation-0001" / "file-0000").read_bytes(), FIXTURE.EXAMPLE_BYTES)
        self.assertEqual((target._target / "generation-0001" / "file-0001").read_bytes(), EXAMPLE_INITIAL["unrelated.txt"])
        self.assertEqual((self.host.worker / "result.txt").read_bytes(), worker)
        self.assertEqual((self.host.state / "artifact" / "file-0000").read_bytes(), artifact)
        self.assertEqual(result["saved_operation"]["saved_pointer_publications"], 1)
        self.assertEqual(result["saved_operation"]["status"], "known-published")
        self.assertTrue(result["fake_completion"])
        self.assertTrue(result["fake_promoted"])
        self.assertTrue(result["current_applicable"])
        self.assertEqual(result["new_invocation"]["files_created"], 6)
        self.assertEqual(result["new_invocation"]["directories_created"], 1)
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 1)
        self.assert_false(result)

    @read_only_host
    def test_unchanged_prepublication_records_allow_useful_original_consumption(self):
        target = self.target()
        publish = target._publish
        records = []

        def unchanged(*args, **kwargs):
            path = target._state / "journal.json"
            records.append(path.read_bytes())
            return publish(*args, **kwargs)

        with patch.object(target, "_publish", side_effect=unchanged):
            with patch.object(os, "replace", wraps=os.replace) as replaced:
                result = self.invoke(target)
        replaced.assert_called_once()
        self.assertEqual((target._state / "journal.json").read_bytes(), records[0])
        self.assertTrue(result["fake_completion"])
        self.assertEqual(target.snapshot()["revision"], 1)
        self.assertEqual(target.snapshot()["files"], {**EXAMPLE_INITIAL, "result.txt": FIXTURE.EXAMPLE_BYTES})
        self.assert_false(result)

    @read_only_host
    def test_persistent_prepublication_operation_drift_yields_zero_replacements(self):
        target = self.target()
        publish = target._publish
        retained = []

        def changed(*args, **kwargs):
            self.rewrite_record(target._state / "journal.json",
                                lambda value: value["claim"].update(operation_id="EXAMPLE_DIFFERENT_OPERATION"))
            retained.append(self.tree(target))
            return publish(*args, **kwargs)

        with patch.object(target, "_publish", side_effect=changed):
            with patch.object(os, "replace", wraps=os.replace) as replaced:
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(target)
            replaced.assert_not_called()
        report = caught.exception.report
        self.assert_false(report)
        self.assertEqual(report["new_invocation"]["pointer_replace_attempts"], 0)
        self.assertEqual(report["new_invocation"]["pointer_replacements"], 0)
        self.assertFalse(report["fake_completion"])
        self.assertFalse(report["current_applicable"])
        self.assertIn("prepared", report["errors"][0])
        self.assertEqual(self.tree(target), retained[0])
        self.assertTrue((target._target / "generation-0001").exists())
        self.assertTrue((target._target / "current.next").exists())
        self.refuse(target)

    @read_only_host
    def test_prepublication_binding_generation_pointer_and_owner_drift_refuses(self):
        for kind in ("binding", "manifest", "generation_seal", "staged_pointer", "owner"):
            target = self.target()
            publish = target._publish
            retained = []

            def changed(*args, **kwargs):
                journal = target._state / "journal.json"
                if kind == "binding":
                    self.rewrite_record(journal, lambda value: value["claim"]["binding"].update(
                        report_sha256=PROMOTION._sha(b"EXAMPLE different report binding")))
                elif kind == "manifest":
                    self.rewrite_record(journal, lambda value: value["claim"]["manifest"]["files"][0].update(
                        size=0))
                elif kind in ("generation_seal", "owner"):
                    generation = "generation-0000" if kind == "owner" else "generation-0001"
                    blob = target._target / generation / "file-0000"
                    data = blob.read_bytes()
                    blob.chmod(0o600)
                    blob.write_bytes(data)
                    blob.chmod(0o400)
                    seal = target._seal(target._target / generation)
                    path = target._state / "owner.json" if kind == "owner" else journal
                    field = "initial_seal" if kind == "owner" else "generation_seal"
                    self.rewrite_record(path, lambda value: value.update({field: seal}))
                else:
                    staged = target._target / "current.next"
                    after = json.loads(staged.read_bytes())
                    old = target._target / "EXAMPLE_OLD_POINTER"
                    staged.rename(old)
                    after = target._new_record(target._target, "current.next",
                                               PROMOTION._body(after), PROMOTION._effects())
                    old.unlink()
                    self.rewrite_record(journal, lambda value: value.update(after=after))
                retained.append(self.tree(target))
                return publish(*args, **kwargs)

            with self.subTest(kind=kind), patch.object(target, "_publish", side_effect=changed):
                with patch.object(os, "replace", wraps=os.replace) as replaced:
                    with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                        self.invoke(target)
                replaced.assert_not_called()
            report = caught.exception.report
            self.assert_false(report)
            self.assertEqual(report["new_invocation"]["pointer_replacements"], 0)
            self.assertEqual(report["new_invocation"]["pointer_replace_attempts"], 0)
            self.assertFalse(report["fake_completion"])
            self.assertFalse(report["current_applicable"])
            self.assertTrue(report["errors"])
            self.assertEqual(self.tree(target), retained[0])
            self.assertTrue((target._target / "generation-0001").exists())
            self.assertTrue((target._target / "current.next").exists())
            self.refuse(target)

    def test_mutable_worker_cannot_replace_consumed_artifact_bytes(self):
        target = self.target()
        replacement = b"EXAMPLE mutable worker substitution\n"
        (self.host.worker / "result.txt").write_bytes(replacement)
        self.invoke(target)
        self.assertEqual(target.snapshot()["files"]["result.txt"], FIXTURE.EXAMPLE_BYTES)
        self.assertEqual((self.host.worker / "result.txt").read_bytes(), replacement)

    @read_only_host
    def test_initial_projection_is_frozen_before_initialization(self):
        initial = dict(EXAMPLE_INITIAL)
        target = self.target(initial=initial, initialize=False)
        initial["unrelated.txt"] = b"EXAMPLE changed caller declaration\n"
        target.initialize()
        self.assertEqual(target.snapshot()["files"], EXAMPLE_INITIAL)
        self.invoke(target)
        self.assertEqual(target.snapshot()["files"]["unrelated.txt"], EXAMPLE_INITIAL["unrelated.txt"])

    @read_only_host
    def test_identical_and_mutated_replay_retain_original_persistence(self):
        target = self.target()
        first = self.invoke(target)
        before = self.tree(target)
        again = self.invoke(target)
        self.assertEqual(again["saved_operation"], first["saved_operation"])
        self.assert_no_new_bytes(again)
        self.assertEqual(self.tree(target), before)
        changed = copy.deepcopy(self.report)
        changed["summary"]["EXAMPLE_CHANGED"] = True
        for changes in ({"operation_id": "EXAMPLE_OTHER"}, {"original_report": changed},
                        {"issued_token": {}}, {"expected_revision": 1}, {"expected_revision": True}):
            with self.subTest(changes=tuple(changes)):
                refusal = self.refuse(target, **changes)
                expected = 1 if "issued_token" in changes else None
                self.assertEqual(refusal["saved_operation"]["saved_pointer_publications"], expected)
                self.assertEqual(refusal["known_publication"]["saved_pointer_publications"], 1)
                self.assertEqual(refusal["known_publication"]["claim"]["operation_id"], "EXAMPLE_FAKE_OPERATION")
        self.assertEqual(self.server.sends, 1)

    @read_only_host
    def test_reconstruction_requires_fresh_original_issued_objects_and_explicit_limits(self):
        target = self.target()
        self.invoke(target)
        policy = VALIDATION.freeze_policy(self.spec)
        token = VALIDATION.validate_artifact(self.host, self.report, self.expected, policy)
        self.refuse(target, issued_token=token, issued_policy=policy)
        restarted = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                self.initial, limits=EXAMPLE_LIMITS)
        result = self.invoke(restarted, issued_token=token, issued_policy=policy)
        self.assert_no_new_bytes(result)
        self.assertTrue(result["fake_completion"])

    @read_only_host
    def test_reconstructed_completion_requires_original_validated_generation_join(self):
        target = self.target()
        first = self.invoke(target)
        self.assertTrue(first["fake_completion"])
        restarted, policy, token = self.fresh(target)
        original = restarted._sync
        injected = []

        def sync(path, counts):
            original(path, counts)
            if path == restarted._target and not injected:
                self.substitute_generation(restarted)
                injected.append(True)

        with patch.object(restarted, "_sync", side_effect=sync):
            with patch.object(os, "replace", wraps=os.replace) as replaced:
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(restarted, issued_policy=policy, issued_token=token)
            replaced.assert_not_called()
        saved = caught.exception.report
        self.assertEqual(len(injected), 1)
        self.assert_no_new_bytes(saved)
        self.assertFalse(saved["fake_completion"])
        self.assertFalse(saved["current_applicable"])
        self.assertIsNone(saved["known_publication"])
        self.assertIsNone(saved["saved_operation"]["saved_pointer_publications"])
        self.assertIsNone(saved["saved_operation"]["claim"])
        self.assert_false(saved)
        self.assertTrue((restarted._target / "generation-0001" / "file-0000").read_bytes()
                        == b"EXAMPLE substituted output bytes\n")
        original_failure = self.refuse(target)
        self.assertTrue(original_failure["known_publication"] == first["known_publication"])

    @read_only_host
    def test_missing_receipt_cannot_recover_an_unbound_expected_target_digest(self):
        target, saved = self.published_without_receipt()
        witnessed = copy.deepcopy(saved["known_publication"])
        restarted, policy, token = self.fresh(target)
        self.rewrite_record(target._state / "journal.json",
                            lambda value: value["claim"]["binding"].update(expected_target_sha256="0" * 64))
        with patch.object(os, "replace", wraps=os.replace) as replaced:
            with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                self.invoke(restarted, issued_policy=policy, issued_token=token)
            replaced.assert_not_called()
        refusal = caught.exception.report
        self.assert_no_new_bytes(refusal)
        self.assertIsNone(refusal["known_publication"])
        self.assertIsNone(refusal["saved_operation"]["saved_pointer_publications"])
        self.assertIsNone(refusal["saved_operation"]["claim"])
        self.assertFalse(refusal["fake_completion"])
        self.assertFalse(refusal["current_applicable"])
        self.assert_false(refusal)
        self.assertIn("expected target", refusal["errors"][0])
        original_failure = self.refuse(target)
        self.assertTrue(original_failure["known_publication"] == witnessed)
        self.assertEqual(original_failure["saved_operation"]["saved_pointer_publications"], 1)
        other = self.refuse(target, operation_id="EXAMPLE_OTHER")
        self.assertTrue(other["known_publication"] == witnessed)
        self.assertIsNone(other["saved_operation"]["saved_pointer_publications"])
        self.assertIsNone(other["saved_operation"]["claim"])
        self.assertFalse((target._state / "receipt.json").exists())

    @read_only_host
    def test_reconstructed_receipt_and_final_inspection_interleavings_preserve_preparation(self):
        points = ("receipt_entry", "receipt_write", "receipt_file_sync",
                  "receipt_directory_sync", "final_validation", "final_inspection")
        for point in points:
            if point in {"receipt_entry", "receipt_write"}:
                target, _saved = self.published_without_receipt()
            else:
                target = self.target()
                self.assertTrue(self.invoke(target)["fake_completion"])
            restarted, policy, token = self.fresh(target)
            finish, record = restarted._finish, restarted._new_record
            sync_file, sync = restarted._sync_file, restarted._sync
            fresh, inspect = restarted._fresh, restarted._inspect
            state = {"finishing": False, "validated": False, "injected": False}

            def substitute():
                if not state["injected"]:
                    self.substitute_generation(restarted)
                    state["injected"] = True

            def finish_operation(*args, **kwargs):
                state["finishing"] = True
                if point == "receipt_entry":
                    substitute()
                return finish(*args, **kwargs)

            def write_record(path, name, data, counts):
                result = record(path, name, data, counts)
                if state["finishing"] and point == "receipt_write" and name == "receipt.json":
                    substitute()
                return result

            def sync_receipt(path, name, counts):
                sync_file(path, name, counts)
                if state["finishing"] and point == "receipt_file_sync" and name == "receipt.json":
                    substitute()

            def sync_directory(path, counts):
                sync(path, counts)
                if state["finishing"] and point == "receipt_directory_sync" and path == restarted._state:
                    substitute()

            def validate(*args, **kwargs):
                result = fresh(*args, **kwargs)
                if state["finishing"]:
                    state["validated"] = True
                    if point == "final_validation":
                        substitute()
                return result

            def inspect_state(facts):
                if state["validated"] and point == "final_inspection":
                    substitute()
                return inspect(facts)

            with self.subTest(point=point):
                with ExitStack() as stack:
                    stack.enter_context(patch.object(restarted, "_finish", side_effect=finish_operation))
                    stack.enter_context(patch.object(restarted, "_new_record", side_effect=write_record))
                    stack.enter_context(patch.object(restarted, "_sync_file", side_effect=sync_receipt))
                    stack.enter_context(patch.object(restarted, "_sync", side_effect=sync_directory))
                    stack.enter_context(patch.object(restarted, "_fresh", side_effect=validate))
                    stack.enter_context(patch.object(restarted, "_inspect", side_effect=inspect_state))
                    replaced = stack.enter_context(patch.object(os, "replace", wraps=os.replace))
                    with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                        self.invoke(restarted, issued_policy=policy, issued_token=token)
                    replaced.assert_not_called()
                refusal = caught.exception.report
                self.assertTrue(state["injected"])
                self.assertEqual(refusal["new_invocation"]["pointer_replacements"], 0)
                self.assertEqual(refusal["new_invocation"]["pointer_replace_attempts"], 0)
                self.assertEqual(refusal["new_invocation"]["files_created"], int(point == "receipt_write"))
                self.assertEqual(refusal["new_invocation"]["directories_created"], 0)
                self.assertEqual(refusal["new_invocation"]["bytes_written"] > 0, point == "receipt_write")
                self.assertFalse(refusal["fake_completion"])
                self.assertFalse(refusal["current_applicable"])
                self.assertIsNone(refusal["known_publication"])
                self.assertIsNone(refusal["saved_operation"]["saved_pointer_publications"])
                self.assertIsNone(refusal["saved_operation"]["claim"])
                self.assert_false(refusal)

    @read_only_host
    def test_conflicting_reconstruction_never_attributes_a_to_b(self):
        target = self.target()
        first = self.invoke(target)
        policy = VALIDATION.freeze_policy(self.spec)
        token = VALIDATION.validate_artifact(self.host, self.report, self.expected, policy)
        restarted = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                self.initial, limits=dict(EXAMPLE_LIMITS))
        self.rewrite_record(target._state / "journal.json",
                            lambda value: value["claim"].update(operation_id="EXAMPLE_DIFFERENT_OPERATION"))
        with self.assertRaises(PROMOTION.FakePromotionError) as caught:
            self.invoke(restarted, operation_id="EXAMPLE_DIFFERENT_OPERATION",
                        issued_token=token, issued_policy=policy)
        report = caught.exception.report
        self.assert_no_new_bytes(report)
        self.assert_false(report)
        self.assertIsNone(report["saved_operation"]["saved_pointer_publications"])
        self.assertIsNone(report["saved_operation"]["claim"])
        self.assertIsNone(report["known_publication"])
        self.assertFalse(report["fake_promoted"])
        self.assertFalse(report["fake_completion"])
        self.assertFalse(report["current_applicable"])
        for changes in ({"operation_id": "EXAMPLE_DIFFERENT_OPERATION"}, {}):
            refused = self.refuse(target, **changes)
            self.assertEqual(refused["known_publication"], first["known_publication"])
            expected = None if changes else 1
            self.assertEqual(refused["saved_operation"]["saved_pointer_publications"], expected)
            self.assertFalse(refused["fake_completion"])
        self.refuse(restarted, operation_id="EXAMPLE_DIFFERENT_OPERATION", issued_token=token, issued_policy=policy)

    @read_only_host
    def test_recovery_requires_plain_complete_claim_and_consistent_records(self):
        changes = (
            ("journal.json", lambda value: value["claim"].update(operation_id=True)),
            ("journal.json", lambda value: value["claim"]["binding"].update(
                report_sha256=True)),
            ("journal.json", lambda value: value["claim"]["manifest"].update(version=True)),
            ("journal.json", lambda value: value["after"].update(revision=True)),
            ("owner.json", lambda value: value["initial_pointer"].update(
                storage_identity=[True, 1])),
            ("receipt.json", lambda value: value.update(saved_pointer_publications=True)),
        )
        for index, (name, change) in enumerate(changes):
            target = self.target()
            first = self.invoke(target)
            restarted = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                    self.initial, limits=dict(EXAMPLE_LIMITS))
            self.rewrite_record(target._state / name, change)
            with self.subTest(index=index):
                refusal = self.refuse(restarted)
                self.assertIsNone(refusal["saved_operation"]["saved_pointer_publications"])
                self.assertIsNone(refusal["saved_operation"]["claim"])
                self.assertIsNone(refusal["known_publication"])
                self.assertFalse(refusal["fake_completion"])
                original = self.refuse(target)
                self.assertEqual(original["known_publication"], first["known_publication"])

    @read_only_host
    def test_complete_path_prefix_checks_refuse_initial_and_merged_conflicts(self):
        with self.assertRaises(ValueError):
            self.target(initial={"a": b"", "a-EXAMPLE": b"", "a/b": b""}, initialize=False)
        target = self.target(initial={"result.txt-EXAMPLE": b"", "result.txt/child": b""})
        refusal = self.refuse(target)
        self.assertFalse(refusal["fake_completion"])
        self.assertFalse((target._target / "generation-0001").exists())
        self.assertFalse((target._state / "journal.json").exists())
        nearby = {"a": b"", "a-EXAMPLE": b"", "ab/child": b"", "result.txt-EXAMPLE": b""}
        target = self.target(initial=nearby)
        result = self.invoke(target)
        self.assertTrue(result["fake_completion"])
        self.assertEqual(target.snapshot()["files"], {**nearby, "result.txt": FIXTURE.EXAMPLE_BYTES})

    @read_only_host
    def test_limit_subclass_hooks_refuse_before_constructor_writes(self):
        calls = []

        class UnsafeKey(str):
            def __hash__(self):
                calls.append("hash")
                return str.__hash__(self)

            def __eq__(self, other):
                calls.append("equality")
                raise AssertionError("EXAMPLE caller equality must remain unused.")

            def __str__(self):
                calls.append("conversion")
                raise AssertionError("EXAMPLE caller text conversion must remain unused.")

            def __format__(self, specification):
                calls.append("formatting")
                raise AssertionError("EXAMPLE caller formatting must remain unused.")

        limits = {UnsafeKey(key) if key == "max_files" else key: value
                  for key, value in EXAMPLE_LIMITS.items()}
        calls.clear()
        with self.assertRaises(ValueError):
            PROMOTION.FakeArtifactTarget._limits_record(limits)
        with self.assertRaises(ValueError):
            self.target(limits=limits)
        self.assertEqual(calls, [])
        state = self.root / f"EXAMPLE_STATE_{self.sequence}"
        projection = self.root / f"EXAMPLE_PROJECTION_{self.sequence}"
        self.assertEqual(list(state.iterdir()), [])
        self.assertEqual(list(projection.iterdir()), [])

    @read_only_host
    def test_bounds_and_input_records_refuse_before_initial_writes(self):
        for initial in ({"../EXAMPLE_ESCAPE": b"E"}, {"a": b"E", "a/b": b"E"},
                        {"EXAMPLE_BIG": b"E" * (HOST.MAX_FILE_BYTES + 1)},
                        {f"EXAMPLE_{index}": b"E" * HOST.MAX_FILE_BYTES for index in range(5)}):
            with self.assertRaises(ValueError):
                self.target(initial=initial, initialize=False)
        for limits in ({**EXAMPLE_LIMITS, "max_files": True}, {**EXAMPLE_LIMITS, "EXAMPLE_UNKNOWN": 1}):
            with self.assertRaises(ValueError):
                self.target(limits=limits, initialize=False)
        limited = self.target(limits={**EXAMPLE_LIMITS, "max_files": 1})
        self.refuse(limited)
        target = self.target()
        for revision in (-1, 1, True, "0"):
            self.refuse(target, expected_revision=revision)
        self.assertEqual(self.server.sends, 1)

    @read_only_host
    def test_projection_cardinality_and_byte_bounds_precede_hashing(self):
        target = self.target()
        oversized = {f"EXAMPLE_{index}": object() for index in range(EXAMPLE_LIMITS["max_files"] + 1)}
        with patch.object(PROMOTION, "_sha", wraps=PROMOTION._sha) as hashed:
            with self.assertRaisesRegex(ValueError, "file bound"):
                target._projection(oversized)
            hashed.assert_not_called()
        limited = self.target(initial={"EXAMPLE_SEED": b""}, limits={**EXAMPLE_LIMITS, "max_total_bytes": 5})
        for files in ({"EXAMPLE_A": b"aaa", "EXAMPLE_B": b"bbb"},
                      {"EXAMPLE_BIG": b"E" * (HOST.MAX_FILE_BYTES + 1)}):
            with patch.object(PROMOTION, "_sha", wraps=PROMOTION._sha) as hashed, self.assertRaises(ValueError):
                limited._projection(files)
            hashed.assert_not_called()

    @read_only_host
    def test_projection_and_manifest_reject_nonplain_keys_before_name_inspection(self):
        class UnsafeName(str):
            __hash__ = str.__hash__

            def __eq__(self, other):
                raise AssertionError("EXAMPLE caller equality must remain unused.")

            def __str__(self):
                raise AssertionError("EXAMPLE caller text conversion must remain unused.")

            def __format__(self, specification):
                raise AssertionError("EXAMPLE caller formatting must remain unused.")

        target = self.target()
        name = UnsafeName("EXAMPLE_NAME")
        for method, values in ((target._projection, {name: b""}),
                               (target._manifest, {name: (0, None)})):
            with patch.object(VALIDATION, "_relative", wraps=VALIDATION._relative) as relative:
                with self.assertRaisesRegex(ValueError, "plain text"):
                    method(values)
                relative.assert_not_called()

    @read_only_host
    def test_projection_accepts_exact_limits_and_relative_name_bounds(self):
        files = {"EXAMPLE_A": b"EEE", "EXAMPLE_B": b"FFF"}
        limits = {"max_files": 2, "max_file_bytes": 3,
                  "max_total_bytes": 6, "max_entries": 14}
        with patch.object(PROMOTION, "_sha", wraps=PROMOTION._sha) as hashed:
            target = self.target(initial=files, limits=limits, initialize=False)
        self.assertEqual(hashed.call_count, 2)
        target.initialize()
        self.assertEqual(target.snapshot()["files"], files)
        paths = {"/".join(("a" * 64, "b" * 64, "c" * 64, "d" * 45)): b"",
                 "/".join(["EXAMPLE"] * VALIDATION.MAX_DEPTH): b""}
        target = self.target(initial=paths)
        self.assertEqual(target.snapshot()["files"], paths)

    @read_only_host
    def test_failures_before_and_after_pointer_replacement_recover_without_duplicate_publication(self):
        for after in (False, True):
            target = self.target()
            original = target._publish
            def fail(*args, **kwargs):
                if after:
                    original(*args, **kwargs)
                raise OSError("EXAMPLE failure at the fake pointer boundary")
            with patch.object(target, "_publish", side_effect=fail):
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(target)
            saved = caught.exception.report
            self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], int(after))
            self.assertFalse(saved["fake_completion"])
            self.assertEqual(saved["new_invocation"]["pointer_replacements"], int(after))
            restarted = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                    self.initial, limits=dict(EXAMPLE_LIMITS))
            result = self.invoke(restarted)
            self.assertEqual(result["new_invocation"]["pointer_replacements"], int(not after))
            self.assertEqual(result["new_invocation"]["files_created"], 1)
            self.assertTrue(result["fake_completion"])
            self.assertFalse(saved["fake_completion"])

    @read_only_host
    def test_replace_failures_before_and_after_return_keep_conservative_accounting(self):
        for after in (False, True):
            target = self.target()
            replace = os.replace

            def fail(*args, **kwargs):
                if after:
                    replace(*args, **kwargs)
                raise OSError("EXAMPLE replacement return is unavailable.")

            with patch.object(os, "replace", side_effect=fail):
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(target)
            saved = caught.exception.report
            self.assert_false(saved)
            self.assertEqual(saved["new_invocation"]["pointer_replace_attempts"], 1)
            self.assertEqual(saved["new_invocation"]["pointer_replacements"], int(after))
            self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], int(after))
            self.assertFalse(saved["fake_completion"])
            self.assertIn("replacement return", saved["errors"][0])
            result = self.invoke(target)
            self.assertEqual(result["new_invocation"]["pointer_replacements"], int(not after))
            self.assertTrue(result["fake_completion"])
            self.assert_false(result)

    @read_only_host
    def test_unobserved_replace_with_unavailable_inspection_remains_unknown(self):
        target = self.target()
        replace, inspect = os.replace, target._inspect
        attempted = []

        def fail_after(*args, **kwargs):
            replace(*args, **kwargs)
            attempted.append(True)
            raise OSError("EXAMPLE replacement return is unavailable.")

        def inspect_state(facts):
            if attempted:
                raise ValueError("EXAMPLE recovery inspection is unavailable.")
            return inspect(facts)

        with patch.object(os, "replace", side_effect=fail_after) as replaced:
            with patch.object(target, "_inspect", side_effect=inspect_state):
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(target)
                saved = caught.exception.report
                self.assertEqual(saved["new_invocation"]["pointer_replace_attempts"], 1)
                self.assertIsNone(saved["new_invocation"]["pointer_replacements"])
                self.assertIsNone(saved["saved_operation"]["saved_pointer_publications"])
                self.assertIsNone(saved["known_publication"])
                self.assertFalse(saved["fake_completion"])
                self.assertFalse(saved["current_applicable"])
                self.assert_false(saved)
                retry = self.refuse(target)
                self.assertIsNone(retry["saved_operation"]["saved_pointer_publications"])
                self.assertIsNone(retry["known_publication"])
            replaced.assert_called_once()
        result = self.invoke(target)
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 0)
        self.assertTrue(result["fake_completion"])
        self.assert_false(result)

    @read_only_host
    def test_witnessed_publication_survives_sync_and_error_inspection_failure(self):
        target = self.target()
        published = []
        replace, inspect, fsync = os.replace, target._inspect, os.fsync

        def replace_pointer(*args, **kwargs):
            result = replace(*args, **kwargs)
            published.append(True)
            return result

        def inspect_state(facts):
            if published:
                raise ValueError("EXAMPLE fake pointer inspection is unavailable.")
            return inspect(facts)

        def sync_file(descriptor):
            if published and Path(os.readlink(f"/proc/self/fd/{descriptor}")) == target._target:
                raise OSError("EXAMPLE fake pointer directory sync failed.")
            return fsync(descriptor)

        with patch.object(os, "replace", side_effect=replace_pointer), patch.object(target, "_inspect", side_effect=inspect_state):
            with patch.object(os, "fsync", side_effect=sync_file):
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(target)
                saved = caught.exception.report
                self.assertEqual(len(published), 1)
                self.assertEqual(saved["new_invocation"]["pointer_replacements"], 1)
                self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], 1)
                self.assertEqual(saved["saved_operation"]["claim"]["operation_id"], "EXAMPLE_FAKE_OPERATION")
                self.assertEqual(saved["saved_operation"]["claim"]["binding"]["report_sha256"], PROMOTION._sha(PROMOTION._encode(self.report)))
                self.assertEqual(saved["saved_operation"]["pointer_state"], "unknown")
                self.assertFalse(saved["fake_completion"])
                self.assertFalse(saved["current_applicable"])
                self.assertEqual(len(saved["errors"]), 2)
                self.assertIn("directory sync failed", saved["errors"][0])
                self.assertIn("inspection is unavailable", saved["errors"][1])
                self.assertGreater(saved["new_invocation"]["fsync_attempts"], saved["new_invocation"]["fsync_successes"])
                retry = self.refuse(target)
                self.assertEqual(retry["saved_operation"]["saved_pointer_publications"], 1)
                self.assertFalse(retry["fake_completion"])
                self.assertEqual(len(published), 1)
        result = self.invoke(target)
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 0)
        self.assertTrue(result["fake_completion"])
        self.assertFalse(saved["fake_completion"])

    @read_only_host
    def test_receipt_failures_report_known_persistence_and_recovery_checks_actual_pointer(self):
        for after_record in (False, True):
            target = self.target()
            original = target._new_record
            def fail(path, name, record, counts):
                if name == "receipt.json":
                    if after_record:
                        original(path, name, record, counts)
                    raise OSError("EXAMPLE failure at the fake receipt boundary")
                return original(path, name, record, counts)
            with patch.object(target, "_new_record", side_effect=fail):
                with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                    self.invoke(target)
            saved = caught.exception.report
            self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], 1)
            self.assertEqual(saved["saved_operation"]["receipt_present"], after_record)
            self.assertFalse(saved["fake_completion"])
            result = self.invoke(target)
            self.assertEqual(result["new_invocation"]["pointer_replacements"], 0)
            self.assertEqual(result["new_invocation"]["files_created"], int(not after_record))
            self.assertTrue(result["fake_completion"])
            self.assertTrue(saved["errors"])

    @read_only_host
    def test_root_and_metadata_drift_after_replacement_retain_history_without_retry_effects(self):
        for kind in ("root", "pointer", "journal"):
            target = self.target()
            publish = target._publish
            changed = {"root": target._target, "pointer": target._target / "current.json",
                       "journal": target._state / "journal.json"}[kind]
            mode = 0o700 if kind == "root" else 0o400

            def drift(*args, **kwargs):
                publish(*args, **kwargs)
                changed.chmod(0o500 if kind == "root" else 0o600)

            try:
                with patch.object(target, "_publish", side_effect=drift):
                    with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                        self.invoke(target)
                saved = caught.exception.report
                self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], 1)
                self.assertEqual(saved["new_invocation"]["pointer_replacements"], 1)
                self.assertFalse(saved["fake_completion"])
                self.assertFalse(saved["current_applicable"])
                self.assertEqual(saved["saved_operation"]["pointer_state"], "unknown")
                self.assertEqual(saved["known_publication"]["claim"]["operation_id"], "EXAMPLE_FAKE_OPERATION")
                retry = self.refuse(target)
                self.assertEqual(retry["saved_operation"]["saved_pointer_publications"], 1)
                self.assertFalse(retry["fake_completion"])
            finally:
                changed.chmod(mode)
            result = self.invoke(target)
            self.assertEqual(result["new_invocation"]["pointer_replacements"], 0)
            self.assertTrue(result["fake_completion"])

    @read_only_host
    def test_failed_journal_fsync_retains_intent_and_prevents_publication_until_recovery(self):
        target = self.target()
        original = os.fsync
        def fail(descriptor):
            if Path(os.readlink(f"/proc/self/fd/{descriptor}")) == target._state / "journal.json":
                raise OSError("EXAMPLE journal fsync failure")
            return original(descriptor)
        with patch.object(os, "fsync", side_effect=fail):
            with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                self.invoke(target)
        saved = caught.exception.report
        self.assertTrue(saved["saved_operation"]["intent_present"])
        self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], 0)
        self.assertGreater(saved["new_invocation"]["fsync_attempts"], saved["new_invocation"]["fsync_successes"])
        result = self.invoke(target)
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 1)
        self.assertTrue(result["fake_completion"])

    @read_only_host
    def test_failed_directory_fsync_after_pointer_change_reports_known_fake_persistence(self):
        target = self.target()
        original = os.fsync
        def fail(descriptor):
            if Path(os.readlink(f"/proc/self/fd/{descriptor}")) == target._target and json.loads((target._target / "current.json").read_bytes())["revision"] == 1:
                raise OSError("EXAMPLE fake pointer directory fsync failure")
            return original(descriptor)
        with patch.object(os, "fsync", side_effect=fail):
            with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                self.invoke(target)
        saved = caught.exception.report
        self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], 1)
        self.assertFalse(saved["fake_completion"])
        result = self.invoke(target)
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 0)
        self.assertTrue(result["fake_completion"])

    @read_only_host
    def test_unlocated_and_mutated_requests_cannot_borrow_publication_history(self):
        target = self.target()
        original = self.invoke(target)
        changed = copy.deepcopy(self.report)
        changed["summary"]["EXAMPLE_CHANGED"] = True
        with patch.object(target, "_inspect", side_effect=ValueError("EXAMPLE fake inspection is unavailable.")):
            for changes in ({"operation_id": "EXAMPLE_OTHER"}, {"original_report": changed}, {"expected_revision": 1}):
                with self.subTest(changes=tuple(changes)):
                    refusal = self.refuse(target, **changes)
                    self.assertIsNone(refusal["saved_operation"]["saved_pointer_publications"])
                    self.assertIsNone(refusal["saved_operation"]["claim"])
                    self.assertEqual(refusal["known_publication"], original["known_publication"])
                    self.assertFalse(refusal["fake_promoted"])
                    self.assertFalse(refusal["fake_completion"])

    @read_only_host
    def test_partial_journal_write_is_retained_and_refuses_without_new_effects(self):
        target = self.target()
        original = target._new
        write = os.write
        def fail(path, name, data, counts, **kwargs):
            if name != "journal.json":
                return original(path, name, data, counts, **kwargs)
            calls = []
            def partial(descriptor, view):
                if calls:
                    raise OSError("EXAMPLE partial fake journal write")
                calls.append(True)
                return write(descriptor, view[:7])
            with patch.object(os, "write", side_effect=partial):
                return original(path, name, data, counts, **kwargs)
        with patch.object(target, "_new", side_effect=fail):
            with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                self.invoke(target)
        saved = caught.exception.report
        self.assertTrue(saved["saved_operation"]["intent_present"])
        self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], 0)
        self.assertEqual((target._state / "journal.json").stat().st_size, 7)
        self.assertEqual((target._state / "journal.json").stat().st_mode & 0o777, 0o600)
        refusal = self.refuse(target)
        self.assertEqual(refusal["saved_operation"]["saved_pointer_publications"], 0)
        self.assertTrue(refusal["saved_operation"]["intent_present"])

    @read_only_host
    def test_same_instance_promotions_are_exclusive_before_root_inspection(self):
        target = self.target()
        entered, release = threading.Event(), threading.Event()
        roots = target._check_roots
        checks = []

        def pause_roots():
            checks.append(threading.get_ident())
            if len(checks) == 1:
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("EXAMPLE fake root inspection wait exceeded its bound.")
            return roots()

        with N1.repository_write_boundaries((self.host.target, self.host.worker)) as writes, FIXTURE.effect_guard():
            with patch.object(target, "_check_roots", side_effect=pause_roots):
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(target.promote, "EXAMPLE_FAKE_OPERATION", self.token, self.report,
                                             self.policy, expected_revision=0)
                    self.assertTrue(entered.wait(10))
                    try:
                        with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                            target.promote("EXAMPLE_OTHER", self.token, self.report,
                                           self.policy, expected_revision=0)
                        self.assertEqual(len(checks), 1)
                        self.assertIsNone(target._held)
                    finally:
                        release.set()
                    result = future.result(timeout=30)
        self.assertTrue(result["fake_completion"])
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 1)
        self.assert_no_new_bytes(caught.exception.report)
        self.assertFalse(caught.exception.report["fake_completion"])
        self.assertIsNone(target._held)
        self.assertEqual(writes, [])
        self.assertEqual(self.server.sends, 1)
        self.assertEqual(self.adapter.callback_latencies, self.callbacks)

    @read_only_host
    def test_simultaneous_same_instance_guards_preserve_the_winning_claim(self):
        target = self.target()
        start = threading.Barrier(2)
        lost = threading.Event()

        def enter():
            start.wait(timeout=10)
            try:
                with target._guard(PROMOTION._effects()):
                    held = target._held
                    self.assertTrue(lost.wait(10))
                    self.assertIs(target._held, held)
                    target._check()
                    return "winner"
            except (ValueError, BlockingIOError):
                lost.set()
                return "loser"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(enter) for _ in range(2)]
            results = [future.result(timeout=20) for future in futures]
        self.assertCountEqual(results, ["winner", "loser"])
        self.assertIsNone(target._held)
        self.assertEqual(target.snapshot()["revision"], 0)

    @read_only_host
    def test_entry_failures_and_body_exceptions_release_only_their_own_claim(self):
        target = self.target()
        open_file = os.open

        def fail_open(path, *args, **kwargs):
            if path == "fake.lock":
                raise OSError("EXAMPLE fake lock descriptor open failed.")
            return open_file(path, *args, **kwargs)

        failures = (patch.object(target, "_check_roots", side_effect=OSError("EXAMPLE fake root check failed.")),
                    patch.object(os, "open", side_effect=fail_open),
                    patch.object(PROMOTION.fcntl, "flock", side_effect=OSError("EXAMPLE fake file lock failed.")))
        for failure in failures:
            with failure, self.assertRaises(OSError):
                with target._guard(PROMOTION._effects()):
                    self.fail("EXAMPLE failed entry must not acquire a guard.")
            self.assertIsNone(target._held)
            with target._guard(PROMOTION._effects()):
                target._check()
        with self.assertRaisesRegex(RuntimeError, "EXAMPLE body failure"):
            with target._guard(PROMOTION._effects()):
                held = target._held
                with self.assertRaisesRegex(ValueError, "reentry"):
                    with target._guard(PROMOTION._effects()):
                        self.fail("EXAMPLE reentry must not acquire a guard.")
                self.assertIs(target._held, held)
                target._check()
                raise RuntimeError("EXAMPLE body failure")
        self.assertIsNone(target._held)
        with target._guard(PROMOTION._effects()):
            target._check()

    @read_only_host
    def test_competing_claims_cannot_publish_from_one_revision(self):
        target = self.target()
        contender = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                self.initial, limits=EXAMPLE_LIMITS)
        entered, release = threading.Event(), threading.Event()
        original = target._publish
        def pause(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("EXAMPLE fake publication wait exceeded its bound")
            return original(*args, **kwargs)
        with N1.repository_write_boundaries((self.host.target, self.host.worker)) as writes, FIXTURE.effect_guard():
            with patch.object(target, "_publish", side_effect=pause):
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(target.promote, "EXAMPLE_FAKE_OPERATION", self.token, self.report,
                                             self.policy, expected_revision=0)
                    self.assertTrue(entered.wait(10))
                    try:
                        with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                            contender.promote("EXAMPLE_OTHER", self.token, self.report, self.policy, expected_revision=0)
                    finally:
                        release.set()
                    self.assertTrue(future.result(timeout=30)["fake_completion"])
        self.assert_no_new_bytes(caught.exception.report)
        self.assertEqual(writes, [])
        self.assertEqual(self.server.sends, 1)
        self.refuse(contender, operation_id="EXAMPLE_OTHER")

    @read_only_host
    def test_exclusion_reentry_refuses_without_releasing_the_outer_claim(self):
        target = self.target()
        original = target._publish
        def reenter(*args, **kwargs):
            held = target._held
            with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                target.promote("EXAMPLE_FAKE_OPERATION", self.token, self.report, self.policy, expected_revision=0)
            self.assert_no_new_bytes(caught.exception.report)
            self.assertIs(target._held, held)
            target._check()
            return original(*args, **kwargs)
        with patch.object(target, "_publish", side_effect=reenter):
            result = self.invoke(target)
        self.assertEqual(result["new_invocation"]["pointer_replacements"], 1)

    @read_only_host
    def test_unknown_malformed_oversized_and_unsafe_state_refuses_without_writes(self):
        external = self.root / "EXAMPLE_EXTERNAL"
        external.write_bytes(b"EXAMPLE external fixture bytes\n")
        for kind in ("unknown", "mode", "symlink", "fifo", "hardlink", "oversize", "malformed"):
            target = self.target()
            pointer = target._target / "current.json"
            if kind == "unknown":
                (target._state / "EXAMPLE_UNKNOWN").write_bytes(b"EXAMPLE unknown state\n")
            elif kind == "mode":
                pointer.chmod(0o600)
            else:
                pointer.unlink()
                if kind == "symlink":
                    pointer.symlink_to(external)
                elif kind == "fifo":
                    os.mkfifo(pointer, 0o400)
                elif kind == "hardlink":
                    os.link(external, pointer)
                elif kind == "oversize":
                    pointer.write_bytes(b"E" * (PROMOTION._RECORD_LIMIT + 1))
                    pointer.chmod(0o400)
                else:
                    pointer.write_bytes(b"{}")
                    pointer.chmod(0o400)
            with self.subTest(kind=kind):
                self.refuse(target)

    @read_only_host
    def test_immutable_generation_journal_and_pointer_substitution_retains_saved_counts(self):
        for relative in ("current.json", "journal.json", "generation-0001/manifest.json", "generation-0001/file-0000"):
            target = self.target()
            self.invoke(target)
            root = target._state if relative == "journal.json" else target._target
            path = root / relative
            parent_mode = path.parent.stat().st_mode & 0o777
            path.parent.chmod(0o700)
            data = path.read_bytes()
            original = path.stat()
            replacement = path.with_name(path.name + ".EXAMPLE-replacement")
            with replacement.open("xb") as stream:
                stream.write(data)
            replacement.chmod(0o400)
            changed = replacement.stat()
            self.assertNotEqual((changed.st_dev, changed.st_ino), (original.st_dev, original.st_ino))
            os.replace(replacement, path)
            changed = path.stat()
            self.assertNotEqual((changed.st_dev, changed.st_ino), (original.st_dev, original.st_ino))
            path.parent.chmod(parent_mode)
            refusal = self.refuse(target)
            self.assertEqual(refusal["saved_operation"]["saved_pointer_publications"], 1)
            self.assertFalse(refusal["fake_completion"])

    def test_original_artifact_policy_and_target_drift_before_and_after_partial_persistence(self):
        for published in (False, True):
            for kind in ("artifact", "policy", "target"):
                target = self.target()
                original = target._publish
                blob = self.host.state / "artifact" / "file-0000"
                seed = self.host.target / "seed.txt"
                saved_blob = blob.read_bytes()
                saved_seed = seed.read_bytes()
                saved_policy = VALIDATION._POLICIES[self.policy]
                def drift(*args, **kwargs):
                    if published:
                        original(*args, **kwargs)
                    if kind == "artifact":
                        blob.chmod(0o600)
                        blob.write_bytes(b"EXAMPLE artifact drift\n")
                        blob.chmod(0o400)
                    elif kind == "policy":
                        changed = copy.deepcopy(self.spec)
                        changed["outputs"][0]["size"] += 1
                        VALIDATION._POLICIES[self.policy] = PROMOTION._encode(changed)
                    else:
                        seed.write_bytes(b"EXAMPLE target drift\n")
                    if not published:
                        return original(*args, **kwargs)
                    return None
                try:
                    with patch.object(target, "_publish", side_effect=drift):
                        with self.assertRaises(PROMOTION.FakePromotionError) as caught:
                            self.invoke(target)
                    saved = caught.exception.report
                    self.assertEqual(saved["saved_operation"]["saved_pointer_publications"], int(published))
                    self.assertFalse(saved["fake_completion"])
                    refusal = self.refuse(target)
                    expected = None if kind == "policy" else int(published)
                    self.assertEqual(refusal["saved_operation"]["saved_pointer_publications"], expected)
                    if published:
                        self.assertEqual(refusal["known_publication"]["saved_pointer_publications"], 1)
                finally:
                    blob.chmod(0o600)
                    blob.write_bytes(saved_blob)
                    blob.chmod(0o400)
                    seed.write_bytes(saved_seed)
                    VALIDATION._POLICIES[self.policy] = saved_policy
                result = self.invoke(target)
                self.assertEqual(result["new_invocation"]["pointer_replacements"], int(not published))
                self.assertTrue(result["fake_completion"])

    @read_only_host
    def test_reconstruction_with_changed_initial_projection_or_limits_refuses(self):
        target = self.target()
        self.invoke(target)
        for initial, limits in (({"unrelated.txt": b"EXAMPLE wrong initial bytes\n"}, EXAMPLE_LIMITS),
                                (self.initial, {**EXAMPLE_LIMITS, "max_files": 7})):
            restarted = PROMOTION.FakeArtifactTarget(target._state, target._target, self.host, self.expected,
                                                    initial, limits=limits)
            self.refuse(restarted)

    @read_only_host
    def test_constructor_refuses_shared_nested_aliased_and_special_fixture_roots(self):
        target = self.target(initialize=False)
        state, projection = target._state, target._target
        nested = state / "EXAMPLE_NESTED"
        nested.mkdir(mode=0o700)
        inverse = projection / "EXAMPLE_NESTED"
        inverse.mkdir(mode=0o700)
        alias = self.root / "EXAMPLE_ROOT_ALIAS"
        alias.symlink_to(projection, target_is_directory=True)
        special = self.root / "EXAMPLE_ROOT_FIFO"
        os.mkfifo(special)
        pairs = ((state, state), (projection, projection), (state, nested), (inverse, projection),
                 (alias, projection), (state, alias), (special, projection), (state, special),
                 ("/", projection), (state, "/proc"), (self.host.state, projection),
                 (state, self.host.worker), (state, str(projection) + "/../" + projection.name))
        before = self.tree(target)
        with N1.repository_write_boundaries((self.host.target, self.host.worker)) as writes, FIXTURE.effect_guard():
            with patch.object(PROMOTION.FakeArtifactTarget, "_projection", side_effect=AssertionError("EXAMPLE unsafe roots must refuse before projection.")) as project:
                for state_root, projection_root in pairs:
                    with self.subTest(state=str(state_root), target=str(projection_root)):
                        with self.assertRaises((ValueError, OSError)):
                            PROMOTION.FakeArtifactTarget(state_root, projection_root, self.host, self.expected,
                                                         self.initial, limits=EXAMPLE_LIMITS)
                project.assert_not_called()
        self.assertEqual(writes, [])
        self.assertEqual(self.tree(target), before)
        self.assertEqual(self.server.sends, 1)
        self.assertEqual(self.adapter.callback_latencies, self.callbacks)

    def test_plain_subclass_limit_key_refuses_before_initialization_writes(self):
        class NonplainKey(str):
            pass

        limits = {NonplainKey(key) if key == "max_files" else key: value
                  for key, value in EXAMPLE_LIMITS.items()}
        with self.assertRaises(ValueError):
            self.target(limits=limits)
        state = self.root / f"EXAMPLE_STATE_{self.sequence}"
        projection = self.root / f"EXAMPLE_PROJECTION_{self.sequence}"
        self.assertEqual(list(state.iterdir()), [])
        self.assertEqual(list(projection.iterdir()), [])


class MultipleOutputPromotionTests(unittest.TestCase):
    """This producer replaces, rather than supplements, the single-output setup."""

    def test_multiple_named_outputs_remain_inert_separately_stored_files(self):
        outputs = {"result.txt": FIXTURE.EXAMPLE_BYTES,
                   "nested/EXAMPLE_inert.py": b"raise RuntimeError('EXAMPLE inert data')\n"}
        policy = VALIDATION.freeze_policy(FIXTURE.specification(outputs, text=None))
        fixture = FIXTURE.HostFixture(self)
        host, report, adapter, server = fixture.ready(outputs, name="EXAMPLE_MULTI")
        state = fixture.helper.root / "EXAMPLE_STATE"
        projection = fixture.helper.root / "EXAMPLE_PROJECTION"
        state.mkdir(mode=0o700)
        projection.mkdir(mode=0o700)
        target = PROMOTION.FakeArtifactTarget(state, projection, host, report["binding"]["target"], EXAMPLE_INITIAL, limits=EXAMPLE_LIMITS)
        target.initialize()
        token = VALIDATION.validate_artifact(host, report, report["binding"]["target"], policy)
        with N1.repository_write_boundaries((host.target, host.worker)) as writes, FIXTURE.effect_guard():
            result = target.promote("EXAMPLE_MULTI", token, report, policy, expected_revision=0)
        self.assertTrue(result["fake_completion"])
        self.assertEqual(target.snapshot()["files"], {**EXAMPLE_INITIAL, **outputs})
        self.assertEqual(target.snapshot()["revision"], 1)
        self.assertEqual(writes, [])
        self.assertEqual(server.sends, 1)
        self.assertIs(type(adapter), HOST.LiveThreadAdapter)
        for flag in PROMOTION._FALSE:
            self.assertIs(result[flag], False)
