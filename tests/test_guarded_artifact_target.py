"""Actual production adapter effects on disposable EXAMPLE target checkouts only."""
from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path
import sys
import threading
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import guarded_artifact_target as G  # noqa: E402
import offline_artifact_validation as V  # noqa: E402
import test_offline_artifact_validation as F  # noqa: E402
import test_maintenance_authority as M  # noqa: E402
from cwo_core.maintenance_authority import sign_controller_directive  # noqa: E402
from cwo_core.native_authority import canonical_authority_sha256  # noqa: E402


class GuardedArtifactTargetTests(unittest.TestCase):
    def setUp(self):
        self.case()

    def case(self, outputs=None, *, setup_target=None, build_target=True):
        self.fixture = F.HostFixture(self)
        self.policy = V.freeze_policy(F.specification(outputs))
        original_case = self.fixture.helper.case
        def prepare(*args, **kwargs):
            if setup_target is not None:
                setup_target(self.fixture.helper)
            return original_case(*args, **kwargs)
        with patch.object(self.fixture.helper, "case", side_effect=prepare):
            self.host, self.report, self.adapter, self.server = self.fixture.ready(outputs)
        self.expected = copy.deepcopy(self.report["binding"]["target"])
        self.token = V.validate_artifact(self.host, self.report, self.expected, self.policy)
        self.authority = M.MaintenanceAuthorityTests("runTest")
        self.authority.setUp()
        self.addCleanup(self.authority.doCleanups)
        a = self.authority
        a.adapter = Path(G.__file__).resolve()
        a.registry["installed-native-v1"] = {"adapter_path": str(a.adapter),
            "adapter_sha256": G._sha(a.adapter.read_bytes())}
        a.mission["scope"]["workspace_roots"] = [str(self.host.target)]
        a.mission_hash = M.mission_sha256(a.mission)
        a.directive = a.sign(a.mission_hash, "EXAMPLE_TARGET_MISSION")
        # Original state producer, independent signed mission and closed factory.
        controller = a.root / "EXAMPLE_TARGET_CONTROLLER"
        controller.mkdir(mode=0o700)
        a.store = M.MaintenanceStateStore(controller, mission_id=a.mission["mission_id"], mission_sha256=a.mission_hash)
        a.store.initialize()
        a.verifier = a.make_verifier()
        plan, operation, directive = a.operation(workspace=self.host.target)
        if outputs is not None:
            plan["children"][0]["write_paths"] = sorted(outputs)
            operation["write_paths"] = sorted(outputs)
            directive = a.reseal(plan, operation)
        self.operation = a.verifier.verify_operation(plan, operation, directive)
        self.operation.claim()
        self.state = self.fixture.helper.root / "EXAMPLE_PUBLICATION"
        self.state.mkdir(mode=0o700)
        if not build_target:
            return
        self.target = self.make_target()
        self.directive = self.consent()
        self.original_target = G.H._capture(self.host.target, (self.host.target, self.host.worker))
        self.worker = (self.host.worker / "result.txt").read_bytes()

    def make_target(self):
        return G.GuardedArtifactTarget(self.state, self.host, self.policy,
            operation=self.operation, verifier=self.authority.verifier)

    def consent(self, *, operation_id="EXAMPLE_PUBLICATION", target=None):
        target = target or self.target
        action = target.binding(operation_id, self.token, self.report)
        return sign_controller_directive(verification_key=self.authority.key,
            actor_id=self.authority.actor, identity_source=self.authority.identity,
            action_sha256=canonical_authority_sha256(action), directive_id="EXAMPLE_EXECUTION_CONSENT",
            parent_receipt_sha256=self.operation.operation_sha256)

    def invoke(self, *, target=None, **changes):
        values = dict(operation_id="EXAMPLE_PUBLICATION", issued_token=self.token,
            original_report=self.report, execution_directive=self.directive)
        values.update(changes)
        with F.effect_guard():
            try:
                return (target or self.target).publish(**values)
            finally:
                self.assertEqual(self.server.sends, 1)
                self.assertEqual((self.host.worker / "result.txt").read_bytes(), self.worker)

    def tree(self):
        return {str(path.relative_to(self.fixture.helper.root)): (path.read_bytes(), path.stat().st_mode)
                for root in (self.host.target, self.state) for path in root.rglob("*") if path.is_file()}

    def refuse(self, **changes):
        before = self.tree()
        with self.assertRaises(G.PublicationError) as caught:
            self.invoke(**changes)
        result = caught.exception.report
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertEqual(self.tree(), before)
        self.assertFalse(result["publication_complete"])
        return result

    def test_original_bytes_publish_to_real_target_and_identical_replay(self):
        before = self.original_target
        result = self.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 1)
        self.assertEqual((self.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)
        after = G.H._capture(self.host.target, (self.host.target, self.host.worker))
        self.assertEqual(G._strip_outputs(before, {"result.txt"}), G._strip_outputs(after, {"result.txt"}))
        self.assertEqual(self.invoke()["new_invocation"]["replacements"], 0)
        self.assertEqual(self.invoke(target=self.make_target())["new_invocation"]["replacements"], 0)
        self.assertEqual(after, G.H._capture(self.host.target, (self.host.target, self.host.worker)))
        self.assertEqual(self.target._load("intent.json")["action"]["purpose"], "guarded-artifact-publication-v1")
        for flag in G._FALSE:
            self.assertIs(result[flag], False)

    def test_missing_wrong_and_evidence_only_consent_have_no_effects(self):
        self.refuse(execution_directive=None)
        self.refuse(execution_directive=self.token.report)
        wrong = dict(self.directive, action_sha256="0" * 64)
        self.refuse(execution_directive=wrong)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_public_constructor_paths_and_serialized_operation_do_not_grant_authority(self):
        with self.assertRaises(ValueError):
            G.GuardedArtifactTarget(self.state, self.host, self.policy,
                operation=self.operation.evidence(), verifier=self.authority.verifier)
        with self.assertRaises(ValueError):
            G.GuardedArtifactTarget(self.state, self.host, self.policy, operation=None, verifier=None)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_target_policy_token_and_candidate_substitution_refuse_without_effects(self):
        self.refuse(issued_token=self.token.report)
        changed = copy.deepcopy(self.report)
        changed["binding"]["target"]["head_commit"] = "0" * 40
        self.refuse(original_report=changed)
        self.target.policy = V.freeze_policy(F.specification())
        self.refuse()
        self.target.policy = self.policy
        blob = self.host.state / "artifact" / "file-0000"
        blob.chmod(0o600)
        blob.write_bytes(b"EXAMPLE substituted bytes\n")
        blob.chmod(0o400)
        self.refuse()

    def test_target_drift_at_actual_replace_boundary_refuses(self):
        original = self.target._apply_one
        def drift(*args):
            (self.host.target / "EXAMPLE_unrelated.txt").write_text("EXAMPLE unrelated race")
            return original(*args)
        with patch.object(self.target, "_apply_one", side_effect=drift):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertEqual(caught.exception.report["new_invocation"]["replace_attempts"], 0)
        self.assertFalse((self.host.target / "result.txt").exists())

    def test_competing_state_instances_share_actual_target_guard(self):
        other_state = self.fixture.helper.root / "EXAMPLE_COMPETING_STATE"
        other_state.mkdir(mode=0o700)
        other = G.GuardedArtifactTarget(other_state, self.host, self.policy,
            operation=self.operation, verifier=self.authority.verifier)
        with self.target._guard():
            result = self.refuse(target=other)
        self.assertIn("state-operation-reentrant", " ".join(result["failures"]))
        # A different controller's target claim is still refused by the actual
        # nonblocking target lock, independently of authority-state exclusion.
        with self.target._directory(self.host.target) as descriptor:
            G.fcntl.flock(descriptor, G.fcntl.LOCK_EX)
            try:
                result = self.refuse(target=other)
            finally:
                G.fcntl.flock(descriptor, G.fcntl.LOCK_UN)
        self.assertIn("BlockingIOError", " ".join(result["failures"]))
        self.assertEqual(list(other_state.iterdir()), [])
        self.invoke()
        self.refuse(target=other)

    def test_known_publication_receipt_failure_recovers_without_duplicate_effect(self):
        original = self.target._record
        failure = OSError("EXAMPLE receipt persistence failure")
        def record(name, value):
            if name == "receipt.json":
                raise failure
            return original(name, value)
        with patch.object(self.target, "_record", side_effect=record):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertIs(caught.exception.__cause__, failure)
        saved = caught.exception.report
        self.assertEqual(saved["known_applied_files"], 1)
        self.assertTrue(saved["completion_uncertain"])
        self.assertEqual((self.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)
        result = self.invoke(target=self.make_target())
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertTrue(result["publication_complete"])
        self.assertTrue(self.invoke()["failures"])

    def test_failed_intent_persistence_precedes_all_target_effects(self):
        with patch.object(self.target, "_record", side_effect=OSError("EXAMPLE intent unavailable")):
            result = self.refuse()
        self.assertEqual(result["new_invocation"]["replace_attempts"], 0)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_replacement_exception_after_effect_preserves_uncertainty_and_refuses_unknown_recovery(self):
        original = os.replace
        def replaced(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("EXAMPLE interrupted after actual replace")
        with patch.object(os, "replace", side_effect=replaced):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        result = caught.exception.report
        self.assertEqual(result["new_invocation"]["replace_attempts"], 1)
        self.assertTrue(result["completion_uncertain"])
        self.assertEqual((self.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)
        self.refuse()

    def test_mutated_replay_and_postpublication_drift_cannot_publish_again(self):
        self.invoke()
        self.refuse(operation_id="EXAMPLE_MUTATED")
        (self.host.target / "result.txt").write_bytes(b"EXAMPLE drifted published bytes\n")
        self.refuse()

    def test_store_or_original_source_substitution_refuses(self):
        self.invoke()
        checkpoint = self.state / "checkpoint-0001.json"
        checkpoint.chmod(0o600)
        value = json.loads(checkpoint.read_bytes())
        value["body"]["applied"] = 0
        checkpoint.write_text(json.dumps(value))
        checkpoint.chmod(0o400)
        self.refuse()
        with patch.object(V, "consume_validated", side_effect=AssertionError("EXAMPLE substituted validator")):
            self.refuse()

    def test_revocation_after_validation_refuses(self):
        self.authority.store.revoke()
        self.refuse()


    def test_partial_multifile_publication_retains_old_state_and_recovers(self):
        outputs = {"result.txt": F.EXAMPLE_BYTES, "EXAMPLE-second.txt": F.EXAMPLE_BYTES}
        self.case(outputs)
        # The original fixture seeds the second declared file in the common
        # commit; the first output sorted by policy is an existing target file.
        old = (self.host.target / "EXAMPLE-second.txt").stat()
        original = self.target._apply_one
        failure = OSError("EXAMPLE second persistence unavailable")
        def apply(index, *args):
            if index == 1:
                raise failure
            return original(index, *args)
        with patch.object(self.target, "_apply_one", side_effect=apply):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(caught.exception.report["known_applied_files"], 1)
        self.assertEqual((self.state / "old-0000").read_bytes(), F.EXAMPLE_BYTES)
        intent = self.target._load("intent.json")
        self.assertEqual(intent["old"][0]["mode"], old.st_mode & 0o777)
        self.assertEqual(intent["old"][0]["mtime_ns"], old.st_mtime_ns)
        result = self.invoke(target=self.make_target())
        self.assertEqual(result["new_invocation"]["replacements"], 1)
        self.assertTrue(result["publication_complete"])
        self.assertTrue(result["failures"])
        self.assertEqual(self.invoke()["new_invocation"]["replacements"], 0)

    def test_target_fsync_failure_keeps_known_write_for_guarded_recovery(self):
        original = os.fsync
        identity = os.stat(self.host.target)
        def sync(descriptor):
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                raise OSError("EXAMPLE target directory fsync failure")
            return original(descriptor)
        # Do not inject before the real mutation; preparation synchronizes state only.
        with patch.object(os, "fsync", side_effect=sync):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertEqual(caught.exception.report["known_applied_files"], 1)
        self.assertEqual(caught.exception.report["new_invocation"]["replacements"], 1)
        result = self.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertEqual(self.invoke(target=self.make_target())["new_invocation"]["replacements"], 0)

    def test_baseexception_after_publication_keeps_original_failure_and_known_write(self):
        original = self.target._record
        interruption = KeyboardInterrupt("EXAMPLE publication interruption")
        def record(name, value):
            if name == "receipt.json":
                raise interruption
            return original(name, value)
        with patch.object(self.target, "_record", side_effect=record):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.invoke()
        self.assertIs(caught.exception, interruption)
        self.assertEqual(interruption.publication_report["known_applied_files"], 1)
        result = self.invoke(target=self.make_target())
        self.assertTrue(result["publication_complete"])
        self.assertIn("KeyboardInterrupt", " ".join(result["failures"]))
        self.assertEqual(result["new_invocation"]["replacements"], 0)

    def test_configuration_and_target_root_changes_refuse_without_extra_effects(self):
        config = self.host.target / ".git" / "config"
        prior = config.read_bytes()
        config.write_bytes(prior + b"\n[core]\n\tsharedRepository = true\n")
        self.refuse()
        config.write_bytes(prior)
        moved = self.host.target.with_name("EXAMPLE_ORIGINAL_TARGET")
        self.host.target.rename(moved)
        self.host.target.mkdir()
        self.refuse()

    def test_candidate_change_at_actual_publication_boundary_refuses(self):
        original = self.target._apply_one
        def mutate(*args):
            blob = self.host.state / "artifact" / "file-0000"
            blob.chmod(0o600)
            blob.write_bytes(b"EXAMPLE late substituted candidate\n")
            blob.chmod(0o400)
            return original(*args)
        with patch.object(self.target, "_apply_one", side_effect=mutate):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertEqual(caught.exception.report["new_invocation"]["replace_attempts"], 0)
        self.assertFalse((self.host.target / "result.txt").exists())

    def test_recovery_resynchronizes_checkpoint_file_after_failed_file_fsync(self):
        original = os.fsync
        failed = []
        def sync(descriptor):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            if name == "checkpoint-0001.json" and not failed:
                failed.append(name)
                raise OSError("EXAMPLE checkpoint file fsync failure")
            return original(descriptor)
        with patch.object(os, "fsync", side_effect=sync):
            with self.assertRaises(G.PublicationError):
                self.invoke()
        synchronized = []
        def observe(descriptor):
            synchronized.append(Path(os.readlink(f"/proc/self/fd/{descriptor}")).name)
            return original(descriptor)
        with patch.object(os, "fsync", side_effect=observe):
            result = self.invoke(target=self.make_target())
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertIn("checkpoint-0001.json", synchronized)

    def test_review_failure_record_fsync_is_repeated_before_recovery_completion(self):
        original_record, original_sync = self.target._record, os.fsync
        failure = OSError("EXAMPLE primary receipt failure")
        failed = []
        def record(name, value):
            if name == "receipt.json":
                raise failure
            return original_record(name, value)
        def sync(descriptor):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            if name == "failure-0000.json" and not failed:
                failed.append(name)
                raise OSError("EXAMPLE failure record file fsync failure")
            return original_sync(descriptor)
        with patch.object(self.target, "_record", side_effect=record), patch.object(os, "fsync", side_effect=sync):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(failed, ["failure-0000.json"])
        synchronized = []
        def observe(descriptor):
            synchronized.append(Path(os.readlink(f"/proc/self/fd/{descriptor}")).name)
            return original_sync(descriptor)
        with patch.object(os, "fsync", side_effect=observe):
            result = self.invoke(target=self.make_target())
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertIn("failure-0000.json", synchronized)

    def test_review_packed_only_replacement_ref_refuses_before_intent(self):
        def packed(helper):
            head = helper.git(helper.target, "rev-parse", "HEAD").stdout.decode().strip()
            (helper.target / ".git" / "packed-refs").write_text(
                "# pack-refs with: peeled fully-peeled sorted\n" + head + " refs/replace/" + head + "\n")
        self.case(setup_target=packed, build_target=False)
        self.assertFalse((self.host.target / ".git" / "refs" / "replace").exists())
        with self.assertRaisesRegex(ValueError, "[Rr]eplacement"):
            self.make_target()
        self.assertEqual(list(self.state.iterdir()), [])

    def test_review_primary_interruption_survives_guard_unlock_failure(self):
        original_record, original_flock = self.target._record, G.fcntl.flock
        interruption = KeyboardInterrupt("EXAMPLE primary interrupted publication")
        cleanup = OSError("EXAMPLE guard unlock failure")
        def record(name, value):
            if name == "receipt.json":
                raise interruption
            return original_record(name, value)
        def flock(descriptor, operation):
            if operation == G.fcntl.LOCK_UN:
                raise cleanup
            return original_flock(descriptor, operation)
        observed = None
        with patch.object(self.target, "_record", side_effect=record), patch.object(G.fcntl, "flock", side_effect=flock):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        facts = interruption.publication_report
        self.assertEqual(facts["known_applied_files"], 1)
        self.assertIn("guard unlock failure", " ".join(facts["failures"]))
        result = self.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)

    def test_existing_different_executable_output_preserves_unrelated_staged_and_unstaged_dirt(self):
        old_bytes = b"EXAMPLE original executable output\n"
        staged = b"EXAMPLE staged unrelated bytes\n"
        dirty = b"EXAMPLE unstaged unrelated bytes\n"
        def before(helper):
            for root in (helper.target, helper.worker):
                (root / "result.txt").write_bytes(old_bytes)
                (root / "result.txt").chmod(0o755)
            (helper.target / "EXAMPLE-staged.txt").write_bytes(staged)
            helper.git(helper.target, "add", "--", "EXAMPLE-staged.txt")
            (helper.target / "seed.txt").write_bytes(dirty)
        self.case(setup_target=before)
        old = (self.host.target / "result.txt").stat()
        before_capture = self.original_target
        result = self.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual((self.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)
        self.assertEqual((self.host.target / "result.txt").stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.state / "old-0000").read_bytes(), old_bytes)
        retained = self.target._load("intent.json")["old"][0]
        self.assertEqual(retained["mode"], 0o755)
        self.assertEqual(retained["mtime_ns"], old.st_mtime_ns)
        self.assertEqual((self.host.target / "EXAMPLE-staged.txt").read_bytes(), staged)
        self.assertEqual((self.host.target / "seed.txt").read_bytes(), dirty)
        after = G.H._capture(self.host.target, (self.host.target, self.host.worker))
        self.assertEqual(G._strip_outputs(before_capture, {"result.txt"}), G._strip_outputs(after, {"result.txt"}))
        self.assertEqual(self.invoke()["new_invocation"]["replacements"], 0)

    def test_review_directory_close_failure_preserves_primary_interruption(self):
        original_record, original_close = self.target._record, os.close
        identity = os.stat(self.host.target)
        interruption = KeyboardInterrupt("EXAMPLE primary directory interruption")
        armed = []
        def record(name, value):
            if name == "receipt.json":
                armed.append(True)
                raise interruption
            return original_record(name, value)
        def close(descriptor):
            info = os.fstat(descriptor)
            target = (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino)
            original_close(descriptor)
            if armed and target:
                armed.clear()
                raise OSError("EXAMPLE directory close failure")
        observed = None
        with patch.object(self.target, "_record", side_effect=record), patch.object(os, "close", side_effect=close):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        self.assertEqual(interruption.publication_report["known_applied_files"], 1)
        self.assertIn("directory close failure", " ".join(interruption.publication_report["failures"]))
        self.assertEqual(self.invoke()["new_invocation"]["replacements"], 0)

    def test_review_directory_acquisition_failure_reports_no_replace_attempt(self):
        original_open = os.open
        failure = OSError("EXAMPLE target directory acquisition failure")
        def open_directory(path, flags, *args, **kwargs):
            raw = os.fsdecode(path)
            if not os.path.isabs(raw) and kwargs.get("dir_fd") is not None:
                raw = os.path.join(os.readlink(f"/proc/self/fd/{kwargs['dir_fd']}"), raw)
            if os.path.normpath(raw) == str(self.host.target):
                frames = {frame.name for frame in traceback.extract_stack()}
                if "_apply_one" in frames and not frames.intersection(
                        {"_capture", "_check", "_validated", "_consent", "_load", "_retained_files"}):
                    raise failure
            return original_open(path, flags, *args, **kwargs)
        with patch.object(os, "open", side_effect=open_directory), patch.object(os, "replace", wraps=os.replace) as replaced:
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertIs(caught.exception.__cause__, failure)
        replaced.assert_not_called()
        self.assertEqual(caught.exception.report["new_invocation"], {"replace_attempts": 0, "replacements": 0})
        self.assertFalse((self.host.target / "result.txt").exists())

    def test_review_close_failure_after_replace_retains_confirmed_return(self):
        original_replace, original_close = os.replace, os.close
        identity = os.stat(self.host.target)
        armed = []
        failure = OSError("EXAMPLE post-replace directory close failure")
        def replace(*args, **kwargs):
            result = original_replace(*args, **kwargs)
            armed.append(True)
            return result
        def close(descriptor):
            info = os.fstat(descriptor)
            target = (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino)
            original_close(descriptor)
            if armed and target:
                armed.clear()
                raise failure
        with patch.object(os, "replace", side_effect=replace), patch.object(os, "close", side_effect=close):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(caught.exception.report["new_invocation"], {"replace_attempts": 1, "replacements": 1})
        self.assertTrue(caught.exception.report["completion_uncertain"])
        self.assertEqual((self.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)
        self.refuse()

    def test_review_record_fsync_interruption_survives_descriptor_close_failure(self):
        original_sync, original_close = os.fsync, os.close
        interruption = KeyboardInterrupt("EXAMPLE record fsync interruption")
        closing = []
        def sync(descriptor):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            access = G.fcntl.fcntl(descriptor, G.fcntl.F_GETFL) & os.O_ACCMODE
            if name == "receipt.json" and access == os.O_RDONLY:
                closing.append(descriptor)
                raise interruption
            return original_sync(descriptor)
        def close(descriptor):
            original_close(descriptor)
            if closing and descriptor == closing[0]:
                closing.clear()
                raise OSError("EXAMPLE record descriptor close failure")
        observed = None
        with patch.object(os, "fsync", side_effect=sync), patch.object(os, "close", side_effect=close):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        facts = interruption.publication_report
        self.assertEqual(facts["known_applied_files"], 1)
        self.assertIn("record descriptor close failure", " ".join(facts["failures"]))
        result = self.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)

    def test_review_repeated_recovery_failures_survive_reconstruction(self):
        first = OSError("EXAMPLE first receipt persistence failure")
        second = OSError("EXAMPLE second recovery persistence failure")
        def fail_receipt(target, failure):
            original = target._record
            def record(name, value):
                if name == "receipt.json":
                    raise failure
                return original(name, value)
            with patch.object(target, "_record", side_effect=record):
                with self.assertRaises(G.PublicationError) as caught:
                    self.invoke(target=target)
            self.assertIs(caught.exception.__cause__, failure)
            return caught.exception.report
        self.assertEqual(fail_receipt(self.target, first)["new_invocation"]["replacements"], 1)
        self.assertEqual(fail_receipt(self.make_target(), second)["new_invocation"]["replacements"], 0)
        recovered = self.make_target()
        result = self.invoke(target=recovered)
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertIn("EXAMPLE first receipt persistence failure", " ".join(result["failures"]))
        self.assertIn("EXAMPLE second recovery persistence failure", " ".join(result["failures"]))
        self.assertEqual(recovered._load("failure-0001.json")["failure"], "OSError: EXAMPLE second recovery persistence failure")

    def test_review_receipt_writer_interruption_survives_close_failure(self):
        original_sync, original_close = os.fsync, os.close
        interruption = KeyboardInterrupt("EXAMPLE receipt writer fsync interruption")
        closing = []
        def sync(descriptor):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            access = G.fcntl.fcntl(descriptor, G.fcntl.F_GETFL) & os.O_ACCMODE
            if name == "receipt.json" and access == os.O_WRONLY:
                closing.append(descriptor)
                raise interruption
            return original_sync(descriptor)
        def close(descriptor):
            original_close(descriptor)
            if closing and descriptor == closing[0]:
                closing.clear()
                raise OSError("EXAMPLE receipt writer close failure")
        observed = None
        with patch.object(os, "fsync", side_effect=sync), patch.object(os, "close", side_effect=close):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        self.assertEqual(interruption.publication_report["known_applied_files"], 1)
        self.assertIn("receipt writer close failure", " ".join(interruption.publication_report["failures"]))
        result = self.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)

    def test_review_successful_publication_guard_exit_failure_survives_reconstruction(self):
        original = G.fcntl.flock
        failure = OSError("EXAMPLE completed publication unlock failure")
        raised = []
        def flock(descriptor, operation):
            result = original(descriptor, operation)
            if operation == G.fcntl.LOCK_UN and not raised:
                raised.append(True)
                raise failure
            return result
        with patch.object(G.fcntl, "flock", side_effect=flock):
            with self.assertRaises(G.PublicationError) as caught:
                self.invoke()
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(caught.exception.report["known_applied_files"], 1)
        self.assertEqual(caught.exception.report["new_invocation"]["replacements"], 1)
        recovered = self.make_target()
        result = self.invoke(target=recovered)
        self.assertTrue(result["publication_complete"])
        self.assertEqual(result["new_invocation"]["replacements"], 0)
        self.assertIn("EXAMPLE completed publication unlock failure", " ".join(result["failures"]))
        self.assertEqual(recovered._load("failure-0000.json")["failure"], "OSError: EXAMPLE completed publication unlock failure")

    def test_review_record_read_interruption_survives_descriptor_close_failure(self):
        original_read, original_close = os.read, os.close
        interruption = KeyboardInterrupt("EXAMPLE authenticated record read interruption")
        closing = []
        def read(descriptor, count):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            if name == "receipt.json":
                closing.append(descriptor)
                raise interruption
            return original_read(descriptor, count)
        def close(descriptor):
            original_close(descriptor)
            if closing and descriptor == closing[0]:
                closing.clear()
                raise OSError("EXAMPLE authenticated record read close failure")
        observed = None
        with patch.object(os, "read", side_effect=read), patch.object(os, "close", side_effect=close):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        self.assertEqual(interruption.publication_report["known_applied_files"], 1)
        self.assertIn("record read close failure", " ".join(interruption.publication_report["failures"]))
        self.assertEqual(self.invoke()["new_invocation"]["replacements"], 0)

    def test_review_capture_interpreted_gitignore_output_refuses_before_intent(self):
        old = b"# EXAMPLE original ignore policy\n"
        candidate = b"# EXAMPLE_RESULT\nEXAMPLE-untracked.txt\n"
        unrelated = b"EXAMPLE unrelated untracked bytes\n"
        def before(helper):
            (helper.target / ".gitignore").write_bytes(old)
            (helper.target / "EXAMPLE-untracked.txt").write_bytes(unrelated)
        self.case(outputs={"result.txt": F.EXAMPLE_BYTES, ".gitignore": candidate},
                  setup_target=before, build_target=False)
        self.assertEqual(self.report["status"], "artifact-ready")
        self.assertTrue(self.token.report["offline_validation_complete"])
        with self.assertRaisesRegex(ValueError, "[Cc]apture"):
            self.make_target()
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual((self.host.target / ".gitignore").read_bytes(), old)
        self.assertEqual((self.host.target / "EXAMPLE-untracked.txt").read_bytes(), unrelated)

    def test_review_retained_payload_read_interruption_survives_close_failure(self):
        self.case(outputs={"result.txt": F.EXAMPLE_BYTES, "EXAMPLE-second.txt": F.EXAMPLE_BYTES})
        original_apply = self.target._apply_one
        def partial(index, *args):
            if index == 1:
                raise OSError("EXAMPLE partial publication before retained payload read")
            return original_apply(index, *args)
        with patch.object(self.target, "_apply_one", side_effect=partial):
            with self.assertRaises(G.PublicationError):
                self.invoke()
        original_read, original_close = os.read, os.close
        interruption = KeyboardInterrupt("EXAMPLE retained payload read interruption")
        closing = []
        def read(descriptor, count):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            if name == "old-0000":
                closing.append(descriptor)
                raise interruption
            return original_read(descriptor, count)
        def close(descriptor):
            original_close(descriptor)
            if closing and descriptor == closing[0]:
                closing.clear()
                raise OSError("EXAMPLE retained payload close failure")
        observed = None
        with patch.object(os, "read", side_effect=read), patch.object(os, "close", side_effect=close):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        self.assertEqual(interruption.publication_report["new_invocation"]["replacements"], 0)
        self.assertIn("retained payload close failure", " ".join(interruption.publication_report["failures"]))
        recovered = self.invoke(target=self.make_target())
        self.assertEqual(recovered["new_invocation"]["replacements"], 1)
        self.assertIn("EXAMPLE retained payload read interruption", " ".join(recovered["failures"]))

    def test_review_directory_acquisition_interruption_survives_parent_close_failure(self):
        original_open, original_close = os.open, os.close
        interruption = KeyboardInterrupt("EXAMPLE directory acquisition interruption")
        closing = []
        def open_directory(path, flags, *args, **kwargs):
            raw = os.fsdecode(path)
            if not os.path.isabs(raw) and kwargs.get("dir_fd") is not None:
                raw = os.path.join(os.readlink(f"/proc/self/fd/{kwargs['dir_fd']}"), raw)
            if os.path.normpath(raw) == str(self.host.target):
                frames = {frame.name for frame in traceback.extract_stack()}
                if "_apply_one" in frames and not frames.intersection(
                        {"_capture", "_check", "_validated", "_consent", "_load", "_retained_files"}):
                    closing.append(kwargs["dir_fd"])
                    raise interruption
            return original_open(path, flags, *args, **kwargs)
        def close(descriptor):
            original_close(descriptor)
            if closing and descriptor == closing[0]:
                closing.clear()
                raise OSError("EXAMPLE directory acquisition parent close failure")
        observed = None
        with patch.object(os, "open", side_effect=open_directory), patch.object(os, "close", side_effect=close):
            with patch.object(os, "replace", wraps=os.replace) as replaced:
                try:
                    self.invoke()
                except BaseException as exc:
                    observed = exc
        self.assertIs(observed, interruption)
        replaced.assert_not_called()
        self.assertEqual(interruption.publication_report["new_invocation"], {"replace_attempts": 0, "replacements": 0})
        self.assertIn("parent close failure", " ".join(interruption.publication_report["failures"]))

    def test_review_revocation_and_settlement_serialize_with_actual_publication(self):
        for mutation in ("revoke", "settle"):
            with self.subTest(mutation=mutation):
                self.case()
                a = self.authority
                # A distinct original store instance exercises the shared file
                # lock, as well as the selected store's controller mutex.
                store = M.MaintenanceStateStore(a.store.directory,
                    mission_id=a.store.mission_id, mission_sha256=a.store.mission_sha256)
                attempted, committed = threading.Event(), threading.Event()
                failures, before_effect, threads = [], [], []
                def mutate():
                    try:
                        if mutation == "revoke":
                            store.revoke()
                        else:
                            store.settle(self.operation.evidence()["operation"]["operation_id"],
                                self.operation.operation_sha256, outcome="accepted")
                        committed.set()
                    except BaseException as exc:
                        failures.append(exc)
                original_replace, original_flock = os.replace, G.fcntl.flock
                def flock(descriptor, flags):
                    if threading.current_thread().name == "EXAMPLE_AUTHORITY_MUTATION":
                        attempted.set()
                    return original_flock(descriptor, flags)
                def replace(source, destination, **kwargs):
                    if source == "new-0000" and destination == "result.txt":
                        thread = threading.Thread(target=mutate, name="EXAMPLE_AUTHORITY_MUTATION", daemon=True)
                        threads.append(thread)
                        thread.start()
                        self.assertTrue(attempted.wait(2))
                        before_effect.append(committed.wait(0.2))
                    return original_replace(source, destination, **kwargs)
                observed = None
                with patch.object(os, "replace", side_effect=replace), patch.object(G.fcntl, "flock", side_effect=flock):
                    try:
                        result = self.invoke()
                    except BaseException as exc:
                        observed = exc
                for thread in threads:
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(before_effect, [False])
                self.assertIsNone(observed)
                self.assertTrue(committed.is_set())
                self.assertTrue(result["publication_complete"])
                self.assertEqual(result["new_invocation"]["replacements"], 1)
                self.assertEqual((self.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)

    def test_review_authority_guard_cleanup_preserves_publication_interruption(self):
        original_apply, original_close = self.target._apply_one, os.close
        interruption = KeyboardInterrupt("EXAMPLE publication interrupted under authority guard")
        closing = []
        def apply(*args):
            original_apply(*args)
            closing.append(True)
            raise interruption
        def close(descriptor):
            name = Path(os.readlink(f"/proc/self/fd/{descriptor}")).name
            original_close(descriptor)
            if closing and name == "maintenance-state.lock":
                frames = {frame.name for frame in traceback.extract_stack()}
                if "guard_current_state" in frames:
                    closing.clear()
                    raise OSError("EXAMPLE authority guard close failure")
        observed = None
        with patch.object(self.target, "_apply_one", side_effect=apply), patch.object(os, "close", side_effect=close):
            try:
                self.invoke()
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        self.assertEqual(interruption.publication_report["new_invocation"]["replacements"], 1)
        self.assertIn("authority guard close failure", " ".join(interruption.publication_report["failures"]))
        recovered = self.invoke(target=self.make_target())
        self.assertEqual(recovered["new_invocation"]["replacements"], 0)
        self.assertIn("publication interrupted under authority guard", " ".join(recovered["failures"]))

    def prepare_checkpoint_zero(self, call=None):
        original = os.replace
        def fail(source, destination, **kwargs):
            if source == "new-0000":
                raise OSError("EXAMPLE replacement failed before mutation")
            return original(source, destination, **kwargs)
        with patch.object(os, "replace", side_effect=fail):
            with self.assertRaises(G.PublicationError) as caught:
                (call or self.invoke)()
        self.assertEqual(caught.exception.report["known_applied_files"], 0)
        return caught.exception.report

    def test_review_authentic_other_action_checkpoint_cannot_adopt_target_drift(self):
        self.prepare_checkpoint_zero()
        (self.host.target / "seed.txt").write_bytes(b"EXAMPLE later target state\n")
        other = F.HostFixture(self)
        policy = V.freeze_policy(F.specification())
        original_case = other.helper.case
        def same_target(*args, **kwargs):
            other.helper.target = self.host.target
            return original_case(*args, **kwargs)
        with patch.object(other.helper, "case", side_effect=same_target):
            host, report, _adapter, server = other.ready()
        token = V.validate_artifact(host, report, report["binding"]["target"], policy)
        a = self.authority
        plan, operation, directive = a.operation(operation_id="EXAMPLE_OTHER_OPERATION", workspace=self.host.target)
        capability = a.verifier.verify_operation(plan, operation, directive)
        capability.claim()
        state = other.helper.root / "EXAMPLE_OTHER_PUBLICATION"
        state.mkdir(mode=0o700)
        target = G.GuardedArtifactTarget(state, host, policy, operation=capability, verifier=a.verifier)
        action = target.binding("EXAMPLE_OTHER_PUBLICATION", token, report)
        consent = sign_controller_directive(verification_key=a.key, actor_id=a.actor,
            identity_source=a.identity, action_sha256=canonical_authority_sha256(action),
            directive_id="EXAMPLE_OTHER_CONSENT", parent_receipt_sha256=capability.operation_sha256)
        def publish_other():
            with F.effect_guard():
                return target.publish("EXAMPLE_OTHER_PUBLICATION", token, report, consent)
        self.prepare_checkpoint_zero(publish_other)
        self.assertEqual(server.sends, 1)
        # Ordinary intact copy from an actually issued/persisted operation;
        # no forged MAC, accepting report, or hand-built checkpoint.
        destination = self.state / "checkpoint-0000.json"
        destination.chmod(0o600)
        shutil.copyfile(state / "checkpoint-0000.json", destination)
        destination.chmod(0o400)
        before = self.tree()
        with self.assertRaises(G.PublicationError) as caught:
            self.invoke(target=self.make_target())
        self.assertEqual(caught.exception.report["new_invocation"]["replace_attempts"], 0)
        self.assertEqual(self.tree(), before)
        self.assertFalse((self.host.target / "result.txt").exists())

    def test_review_checkpoint_zero_inspection_interruption_survives_reconstruction(self):
        self.prepare_checkpoint_zero()
        original = os.read
        interruption = KeyboardInterrupt("EXAMPLE checkpoint-zero staged read interruption")
        def read(descriptor, count):
            if Path(os.readlink(f"/proc/self/fd/{descriptor}")).name == "new-0000":
                raise interruption
            return original(descriptor, count)
        observed = None
        with patch.object(os, "read", side_effect=read):
            try:
                self.invoke(target=self.make_target())
            except BaseException as exc:
                observed = exc
        self.assertIs(observed, interruption)
        self.assertEqual(interruption.publication_report["new_invocation"]["replace_attempts"], 0)
        recovered = self.invoke(target=self.make_target())
        self.assertEqual(recovered["new_invocation"]["replacements"], 1)
        self.assertIn("EXAMPLE checkpoint-zero staged read interruption", " ".join(recovered["failures"]))


    def test_unsupported_git_store_refuses_before_publication(self):
        replacement = self.host.target / ".git" / "refs" / "replace"
        replacement.mkdir()
        self.refuse()


class DisabledGitMaintenanceTests(unittest.TestCase):
    def test_exact_disabled_settings_preserve_publication_and_other_values_refuse(self):
        # Keep construction in this body: a refusal of the required positive
        # configuration is a failed contract assertion, not a setup error.
        case = GuardedArtifactTargetTests("runTest")
        case._outcome = self._outcome
        self.addCleanup(case.doCleanups)
        case.case(build_target=False)
        case.authority._outcome = self._outcome
        before = case.tree()
        try:
            case.target = case.make_target()
        except ValueError as failure:
            self.fail(f"Disabled Git maintenance must permit the original target: {failure}")
        self.assertEqual(case.tree(), before)
        case.directive = case.consent()
        case.worker = (case.host.worker / "result.txt").read_bytes()
        result = case.invoke()
        self.assertTrue(result["publication_complete"])
        self.assertEqual((case.host.target / "result.txt").read_bytes(), F.EXAMPLE_BYTES)

        refused = (("maintenance.auto", "true"), ("maintenance.auto", "1"),
                   ("maintenance.auto", "0"), ("maintenance.auto", None),
                   ("gc.auto", "1"), ("gc.auto", "-1"), ("gc.auto", "false"),
                   ("gc.auto", "00"), ("gc.auto", None),
                   ("gc.autopacklimit", "0"), ("maintenance.strategy", "false"))
        for name, value in refused:
            with self.subTest(name=name, value=value):
                def changed(helper):
                    # Append rather than replace: an unsafe duplicate refuses
                    # even when a required disabled entry is also present.
                    section, key = name.split(".", 1)
                    rendered = key if value is None else f"{key} = {value}"
                    with (helper.target / ".git" / "config").open("a") as stream:
                        stream.write(f"\n[{section}]\n\t{rendered}\n")
                negative = GuardedArtifactTargetTests("runTest")
                negative._outcome = self._outcome
                self.addCleanup(negative.doCleanups)
                negative.case(setup_target=changed, build_target=False)
                negative.authority._outcome = self._outcome
                before = negative.tree()
                with self.assertRaises(ValueError):
                    negative.make_target()
                self.assertEqual(negative.tree(), before)
                self.assertEqual(negative.server.sends, 1)
