"""Offline fixture isolation at real precommit arm and receipt boundaries."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_supervise_native_worker as supervisor_fixture
from tests import test_native_worker_planning as planning_fixture
from tests import test_receipt_reservation_compatibility as receipt_subject
from tests import test_supervision_identity_allocation as identity_subject
from tests import native_precommit_fixtures as issuer
from tests.private_workspace_fixtures import copy_context_files

from cwo_core import native_precommit, policy


IDENTITY_CONTEXT = "scripts/supervise_native_worker.py"
IDENTITY_METHOD = "test_synchronous_mutation_observers_see_allocation_first"
RECEIPT_METHOD = (
    "test_historical_receipts_reach_reservation_but_cannot_authorize_current_build"
)


class PrivateWorkspaceFixtureIsolationTests(unittest.TestCase):
    @contextlib.contextmanager
    def _sources(self):
        with tempfile.TemporaryDirectory(prefix="cwo-private-source-probe-") as temporary:
            source = Path(temporary) / "source"
            copy_context_files(supervisor_fixture.ROOT, source, [IDENTITY_CONTEXT])
            copy_context_files(planning_fixture.ROOT, source, planning_fixture.PATHS)
            with (
                mock.patch.object(supervisor_fixture, "ROOT", source),
                mock.patch.object(planning_fixture, "ROOT", source),
            ):
                yield source

    @contextlib.contextmanager
    def _case(self, case_type, method):
        case = case_type(method)
        environment = dict(os.environ)
        roots = (supervisor_fixture.ROOT, planning_fixture.ROOT,
                 supervisor_fixture._FIXTURE_ROOT)
        policy_dir, loader = policy.POLICY_DIR, policy._load_policy_cached
        try:
            case.setUp()
            yield case
        finally:
            self.assertTrue(case.doCleanups())
            self.assertEqual(dict(os.environ), environment)
            self.assertEqual(
                (supervisor_fixture.ROOT, planning_fixture.ROOT,
                 supervisor_fixture._FIXTURE_ROOT), roots,
            )
            self.assertEqual(policy.POLICY_DIR, policy_dir)
            self.assertIs(policy._load_policy_cached, loader)
            temporary = getattr(case, "temporary", None)
            if temporary is not None:
                self.assertFalse(temporary.exists())

    def _workspace(self, workspace, source, paths, artifacts):
        self.assertNotEqual(workspace, source)
        self.assertNotIn(source, workspace.parents)
        self.assertNotIn(workspace, source.parents)
        self.assertNotEqual(workspace, artifacts)
        self.assertNotIn(workspace, artifacts.parents)
        self.assertNotIn(artifacts, workspace.parents)
        self.assertEqual(workspace.stat().st_uid, os.getuid())
        git = workspace / ".git"
        self.assertTrue(git.is_dir())
        self.assertFalse(git.is_symlink())
        probe = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse",
             "--show-toplevel", "--git-common-dir"],
            check=True, capture_output=True, text=True,
        )
        toplevel, common = probe.stdout.splitlines()
        self.assertEqual(Path(toplevel).resolve(), workspace.resolve())
        self.assertEqual((workspace / common).resolve(), git.resolve())
        self.assertFalse((git / "commondir").exists())
        self.assertFalse((git / "objects/info/alternates").exists())
        self.assertNotIn("[remote ", (git / "config").read_text(encoding="utf-8"))
        for relative in paths:
            self.assertEqual((workspace / relative).read_bytes(),
                             (source / relative).read_bytes())

    def _identity_context(self, case):
        self.assertEqual(case.packet["scope"]["workdir"], str(case.workspace))
        entry = case.packet["work_plan"]["context_manifest"][0]
        content = (case.workspace / IDENTITY_CONTEXT).read_bytes()
        self.assertEqual(entry["path"], IDENTITY_CONTEXT)
        self.assertEqual(entry["selector"], "whole-file")
        self.assertEqual(entry["bytes"], len(content))
        self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
        readiness, units = supervisor_fixture.supervisor._evaluate_operative_readiness(
            case.packet, supervisor_fixture.supervisor.load_policy("native-worker-execution")
        )
        self.assertEqual(readiness["decision"], "operative-ready")
        self.assertEqual(readiness["reasons"], [])
        self.assertEqual(units[0]["absolute_path"], str(case.workspace / IDENTITY_CONTEXT))
        self.assertEqual(Path(supervisor_fixture.supervisor.__file__).resolve(),
                         supervisor_fixture.SCRIPT.resolve())

    def _identity(self, source, *, positive=False):
        with self._case(
            identity_subject.SupervisionIdentityAllocationTests, IDENTITY_METHOD
        ) as case:
            self._workspace(case.workspace, source, [IDENTITY_CONTEXT], case.root)
            self._identity_context(case)
            self.assertIn("workspace/" + IDENTITY_CONTEXT, case._snapshot())
            self.assertIn("workspace/.git/config", case._snapshot())
            if positive:
                case._positive()
            else:
                getattr(case, IDENTITY_METHOD)()

    def _receipt(self, source):
        with self._case(
            receipt_subject.TestReceiptReservationCompatibility, RECEIPT_METHOD
        ) as case:
            getattr(case, RECEIPT_METHOD)()
            self._workspace(case.workspace, source, planning_fixture.PATHS, case.root)
            self.assertIn("workspace/" + planning_fixture.PATHS[0], case._artifacts())
            self.assertIn("workspace/.git/config", case._artifacts())

    @contextlib.contextmanager
    def _observer(self, source, boundary, *, inside=False):
        real = getattr(issuer, boundary)
        calls = []
        paths = [IDENTITY_CONTEXT] if boundary == "arm_precommit" else planning_fixture.PATHS

        def observed(state_file, *args, **kwargs):
            state = json.loads(Path(state_file).read_text(encoding="utf-8"))
            workspace = Path(state["workdir"])
            metadata = state["workspace_baseline"]
            self.assertEqual(metadata["workdir"], str(workspace))
            self._workspace(workspace, source, paths, Path(state_file).parent)
            self.assertFalse(native_precommit._workspace_report(metadata)["mutation_detected"])
            calls.append(workspace)
            if inside:
                target = workspace / paths[0]
                target.write_bytes(target.read_bytes() + b"\n# owned fixture mutation\n")
            else:
                (source / "unrelated-parallel-writer.txt").write_text(
                    "unrelated private source-root worker", encoding="utf-8"
                )
            self.assertEqual(
                native_precommit._workspace_report(metadata)["mutation_detected"], inside
            )
            result = real(state_file, *args, **kwargs)
            if boundary == "issue_precommit_receipt":
                payload = {key: value for key, value in result.items() if key != "receipt_file"}
                self.assertIs(payload["accepting"], not inside)
                if inside:
                    self.assertIn("workspace-mutation", payload["observed"]["forbidden_events"])
                    self.assertEqual(native_precommit.validate_precommit_receipt(
                        payload, require_accepting=True,
                    ), ["precommit receipt is non-accepting"])
                    self.assertEqual(native_precommit.validate_precommit_receipt(
                        payload, live=True,
                    ), ["intervening workspace mutation invalidates precommit receipt"])
            return result

        with mock.patch.object(issuer, boundary, side_effect=observed):
            yield calls

    def test_identity_is_independent_of_private_source_writer(self):
        with self._sources() as source:
            self._identity(source, positive=True)
            with self._observer(source, "arm_precommit") as calls:
                self._identity(source)
            self.assertEqual(len(calls), 1)

    def test_receipt_compatibility_is_independent_of_private_source_writer(self):
        with self._sources() as source:
            self._receipt(source)
            with self._observer(source, "issue_precommit_receipt") as calls:
                self._receipt(source)
            self.assertEqual(len(calls), 2)

    def test_identity_owned_mutation_still_refuses_at_real_arm(self):
        with self._sources() as source:
            self._identity(source, positive=True)
            with self._observer(source, "arm_precommit", inside=True) as calls:
                with self.assertRaisesRegex(
                    ValueError, "workspace changed between precommit creation and arming"
                ):
                    self._identity(source)
            self.assertEqual(len(calls), 1)
            self.assertFalse(calls[0].exists())

    def test_receipt_owned_mutation_still_produces_nonaccepting_receipt(self):
        with self._sources() as source:
            self._receipt(source)
            with (
                self._observer(source, "issue_precommit_receipt", inside=True) as calls,
                mock.patch.object(
                    receipt_subject.native, "reserve_precommit_receipt",
                    wraps=receipt_subject.native.reserve_precommit_receipt,
                ) as reserve,
                mock.patch.object(
                    receipt_subject.native, "_build_native_worker_packet_unreserved",
                    wraps=receipt_subject.native._build_native_worker_packet_unreserved,
                ) as body,
            ):
                with self.assertRaisesRegex(AssertionError, "precommit receipt is non-accepting"):
                    self._receipt(source)
            reserve.assert_not_called()
            body.assert_not_called()
            self.assertEqual(len(calls), 1)
            self.assertFalse(calls[0].exists())

    def test_owned_context_drift_invalidates_real_readiness_and_live_receipt(self):
        with self._sources() as source, self._case(
            identity_subject.SupervisionIdentityAllocationTests, IDENTITY_METHOD
        ) as case:
            self._workspace(case.workspace, source, [IDENTITY_CONTEXT], case.root)
            self._identity_context(case)
            state = case._positive()
            before = case._snapshot()
            target = case.workspace / IDENTITY_CONTEXT
            target.write_bytes(target.read_bytes() + b"\n# private context drift\n")
            self.assertNotEqual(case._snapshot(), before)
            readiness, _ = supervisor_fixture.supervisor._evaluate_operative_readiness(
                case.packet, supervisor_fixture.supervisor.load_policy("native-worker-execution")
            )
            self.assertEqual(readiness["decision"], "split-required")
            self.assertIn("context_manifest[0].sha256 does not match current content",
                          readiness["reasons"])
            self.assertTrue(supervisor_fixture.supervisor._compare_live_workspace(
                state["observed"]["workspace_baseline"]
            )["mutation_detected"])
            with supervisor_fixture.historical_v2_policy():
                self.assertEqual(native_precommit.validate_precommit_receipt(
                    case.packet["precommit_receipt"], case.packet["work_plan"],
                    live=True, require_accepting=True,
                ), ["intervening workspace mutation invalidates precommit receipt"])


if __name__ == "__main__":
    unittest.main()
