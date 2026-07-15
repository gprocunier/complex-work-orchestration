from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_containment import CONTAINMENT_ERROR, containment_error  # noqa: E402
from cwo_core.native_precommit import canonical_sha256  # noqa: E402
from cwo_core.native_release import (  # noqa: E402
    build_canary_release_evidence,
    build_operative_release_evidence,
    validate_native_release_evidence,
    write_release_evidence,
)


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def canary_plan() -> dict:
    return {
        "work_unit_id": "fsh3-positive-canary",
        "bead_id": "complex-work-orchestration-fsh.3.5",
        "requested_model": "gpt-5.3-codex-spark",
        "task_class": "bounded-implementation",
        "scores": {
            "reasoning_uncertainty": 0,
            "subsystem_coupling": 0,
            "contract_risk": 0,
            "diagnostic_uncertainty": 0,
            "context_breadth": 0,
            "validation_breadth": 0,
        },
        "aggregate_allowance": {
            "tool_calls_soft": 0,
            "tool_calls_hard": 1,
            "runtime_seconds_soft": 30,
            "runtime_seconds_hard": 120,
        },
    }


class NativeReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cwo-native-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = self.root / "registry"
        self.env = mock.patch.dict(
            os.environ,
            {"CWO_NATIVE_RELEASE_REGISTRY_ROOT": str(self.registry)},
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.now_dt = dt.datetime.now(dt.timezone.utc)
        self.now = self.now_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def build(self, **overrides: object) -> dict:
        values = {
            "packet_id": "fsh3-canary-packet",
            "attempt_nonce": "fsh3-canary-attempt",
            "work_plan": canary_plan(),
            "workdir": self.root,
            "ttl_seconds": 900,
            "now": self.now,
        }
        values.update(overrides)
        return build_canary_release_evidence(**values)

    def test_canary_evidence_is_strict_bounded_and_nonoperative(self) -> None:
        evidence = self.build()
        self.assertEqual(validate_native_release_evidence(evidence, now=self.now_dt), [])
        self.assertEqual(evidence["release_state"], "canary-authorized")
        self.assertFalse(evidence["repository_work_authorized"])
        self.assertFalse(evidence["source_mutation_authorized"])
        self.assertEqual(evidence["work_plan_sha256"], canonical_sha256(canary_plan()))
        self.assertEqual(
            containment_error(
                "supervised-worker-fit-request",
                release_evidence=evidence,
            ),
            "",
        )
        for operation in (
            "dispatchable-packet-validation",
            "operative-prompt-render",
            "supervision-start",
            "supervision-arm",
            "native-dispatch",
            "native-retry",
            "native-resume",
            "native-replay-dispatch",
        ):
            with self.subTest(operation=operation):
                self.assertIn(
                    CONTAINMENT_ERROR,
                    containment_error(operation, release_evidence=evidence),
                )

    def test_canary_evidence_rejects_tamper_expiry_and_non_temp_workdir(self) -> None:
        evidence = self.build()
        cases = []
        tampered = copy.deepcopy(evidence)
        tampered["repository_work_authorized"] = True
        tampered["evidence_sha256"] = canonical_sha256(
            {key: value for key, value in tampered.items() if key != "evidence_sha256"}
        )
        cases.append(tampered)
        tampered = copy.deepcopy(evidence)
        tampered["authorized_operations"].append("native-dispatch")
        tampered["evidence_sha256"] = canonical_sha256(
            {key: value for key, value in tampered.items() if key != "evidence_sha256"}
        )
        cases.append(tampered)
        tampered = copy.deepcopy(evidence)
        tampered["evidence_sha256"] = "0" * 64
        cases.append(tampered)
        tampered = copy.deepcopy(evidence)
        tampered["release_state"] = "precommit-validated"
        tampered["evidence_sha256"] = canonical_sha256(
            {key: value for key, value in tampered.items() if key != "evidence_sha256"}
        )
        cases.append(tampered)
        for case in cases:
            with self.subTest(case=case):
                self.assertTrue(validate_native_release_evidence(case, live=False))
        expired = self.now_dt + dt.timedelta(hours=1)
        self.assertTrue(any("not live" in error for error in validate_native_release_evidence(evidence, now=expired)))
        with self.assertRaisesRegex(ValueError, "disposable CWO-owned temp"):
            self.build(packet_id="outside", attempt_nonce="outside", workdir=ROOT)

    def test_duplicate_canary_packet_or_nonce_is_rejected(self) -> None:
        self.build()
        with self.assertRaisesRegex(ValueError, "duplicate native release packet_id"):
            self.build(attempt_nonce="different-attempt")
        with self.assertRaisesRegex(ValueError, "duplicate native release attempt_nonce"):
            self.build(packet_id="different-packet")

    def test_operative_evidence_cannot_issue_before_sprint5(self) -> None:
        with self.assertRaisesRegex(ValueError, "disabled pending Sprint 5"):
            build_operative_release_evidence(
                candidate_packet={},
                adjudication={},
                canary_receipt_sha256="0" * 64,
                now=self.now,
            )

    def test_cli_issues_private_canary_artifact(self) -> None:
        plan_file = self.root / "plan.json"
        output_file = self.root / "release.json"
        plan_file.write_text(json.dumps(canary_plan()), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "manage_native_release.py"),
                "issue-canary",
                "--packet-id",
                "cli-canary-packet",
                "--attempt-nonce",
                "cli-canary-attempt",
                "--work-plan",
                str(plan_file),
                "--workdir",
                str(self.root),
                "--output",
                str(output_file),
                "--now",
                self.now,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "CWO_NATIVE_RELEASE_REGISTRY_ROOT": str(self.registry)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output_file.stat().st_mode & 0o777, 0o600)
        evidence = json.loads(output_file.read_text(encoding="utf-8"))
        self.assertEqual(evidence["release_state"], "canary-authorized")

    def test_canary_evidence_is_rejected_at_all_operative_cli_entry_points(self) -> None:
        evidence = self.build()
        evidence_file = write_release_evidence(self.root / "canary-evidence.json", evidence)
        packet_file = self.root / "canary-packet.json"
        packet_file.write_text(
            json.dumps({"packet_id": evidence["packet_id"], "release_evidence": evidence}),
            encoding="utf-8",
        )
        commands = (
            [sys.executable, str(ROOT / "scripts" / "prepare_native_worker.py"), "render", str(packet_file)],
            [
                sys.executable,
                str(ROOT / "scripts" / "supervise_native_worker.py"),
                "start",
                "--packet",
                str(packet_file),
                "--session-id",
                "canary-session",
                "--session-file",
                "missing",
                "--agent-id",
                "canary-agent",
            ],
            [
                sys.executable,
                str(ROOT / "scripts" / "supervise_native_worker.py"),
                "arm",
                "--state-file",
                "missing",
                "--control-turn-id",
                "canary-control",
                "--release-evidence",
                str(evidence_file),
            ],
            [
                sys.executable,
                str(ROOT / "scripts" / "supervise_native_worker.py"),
                "mark-dispatched",
                "--state-file",
                "missing",
                "--control-turn-id",
                "canary-control",
                "--submission-id",
                "canary-submission",
                "--release-evidence",
                str(evidence_file),
            ],
            [
                sys.executable,
                str(ROOT / "scripts" / "supervise_native_worker.py"),
                "authorize-retry",
                "--state-file",
                "missing",
                "--control-turn-id",
                "canary-control",
                "--retry-packet",
                "missing",
                "--fresh-attestation",
                "missing",
                "--workspace-report",
                "missing",
                "--semantic-result",
                "missing",
                "--release-evidence",
                str(evidence_file),
            ],
        )
        for command in commands:
            with self.subTest(command=command[2:4]):
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    env={**os.environ, "CWO_NATIVE_RELEASE_REGISTRY_ROOT": str(self.registry)},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn(CONTAINMENT_ERROR, result.stderr)

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_release_evidence_matches_strict_schema(self) -> None:
        import jsonschema

        schema = json.loads(
            (ROOT / "schemas" / "native-release-evidence.schema.json").read_text(encoding="utf-8")
        )
        jsonschema.validate(self.build(), schema)


if __name__ == "__main__":
    unittest.main()
