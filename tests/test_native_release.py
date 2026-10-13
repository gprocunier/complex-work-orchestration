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
from tests.historical_policy_fixtures import historical_v2_policy, historical_cli_args

from cwo_core.native_containment import CONTAINMENT_ERROR, containment_error  # noqa: E402
from cwo_core.native_precommit import canonical_sha256  # noqa: E402
from cwo_core.native_release import (  # noqa: E402
    authorize_operative_packet,
    build_canary_release_evidence,
    build_operative_release_evidence,
    reissue_operative_packet_release,
    validate_native_release_evidence,
    write_release_evidence,
)
from cwo_core.paths import cwo_temp_dir  # noqa: E402
from tests.native_precommit_fixtures import issue_accepting_precommit_receipt  # noqa: E402


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def canary_plan() -> dict:
    return {
        "work_unit_id": "fsh3-positive-canary",
        "bead_id": "complex-work-orchestration-fsh.3.5",
        "requested_model": "gpt-5.3-codex-spark",
        "task_class": "bounded-implementation",
        "primary_outcome": "Complete a harmless bounded release canary.",
        "acceptance_checks": ["The canary completes without workspace mutation."],
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


def candidate_packet(workdir: Path, version: object | None = 2) -> dict:
    packet = {
        "stage": "precommit-validated",
        "operative_dispatch_authorized": False,
        "packet_id": "fsh3-operative-packet",
        "work_plan": canary_plan(),
        "precommit_receipt_sha256": "1" * 64,
        "precommit_receipt": {
            "receipt_sha256": "1" * 64,
            "attempt_nonce": "fsh3-operative-attempt",
            "fit_prompt_sha256": "2" * 64,
        },
        "scope": {"workdir": str(workdir)},
    }
    if version is not None:
        packet["version"] = version
    return packet


def operative_adjudication(canary_receipt_sha256: str = "5" * 64) -> dict:
    return {
        "adjudication_type": "cwo-native-operative-release-adjudication",
        "version": 1,
        "bead_id": "complex-work-orchestration-fsh.3.5",
        "decision": "GO",
        "accepted_high_severity_findings": 0,
        "validation_sha256": "3" * 64,
        "critic_evidence_sha256": "4" * 64,
        "canary_receipt_sha256": canary_receipt_sha256,
    }


class NativeReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cwo-native-release-test-")
        self.addCleanup(self.temp.cleanup)
        temp_root = Path(self.temp.name)
        self.env = mock.patch.dict(
            os.environ,
            {
                "CWO_TEMP_ROOT": str(temp_root),
                "CWO_SESSION_ID": "release-fixture-session",
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.root = cwo_temp_dir(scope="session")
        self.registry = self.root / "registry"
        self.env = mock.patch.dict(
            os.environ,
            {
                "CWO_NATIVE_RELEASE_REGISTRY_ROOT": str(self.registry),
                "CWO_PRECOMMIT_REGISTRY_ROOT": str(self.root / "precommit-registry"),
            },
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

    def accepting_canary_receipt(self) -> dict:
        workspace = self.root / "canary-workspace"
        workspace.mkdir(exist_ok=True)
        return issue_accepting_precommit_receipt(
            work_plan=canary_plan(),
            packet_id="fsh3-positive-canary-proof",
            artifact_root=self.root / "canary-receipt",
            workdir=workspace,
            estimates={
                "tool_calls_p50": 1,
                "tool_calls_p90": 1,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 20,
            },
        )

    def fallback_canary_bundle(
        self,
        *,
        quota: str = "exhausted",
        capacity: str = "available",
        evaluated_at: str | None = None,
    ) -> tuple[dict, dict, dict]:
        from cwo_core.operative_routing import (
            LUNA_MODEL,
            build_operative_fallback_fit,
            resolve_operative_route,
        )
        from tests.test_operative_routing import (
            BUDGET,
            NOW,
            cache_profile,
            capability_evidence,
            work_plan as fallback_plan,
        )

        context = {
            "bead_id": "complex-work-orchestration-fsh.3.5",
            "wave_id": "p4vg-wave-0-release-repair",
            "fresh_segment": True,
            "work_lineage_id": "p4vg-fallback-canary",
        }
        plan = fallback_plan(requested_model=LUNA_MODEL, narrow=True)
        plan["bead_id"] = context["bead_id"]
        plan["work_unit_id"] = "p4vg-fallback-release-canary"
        route_time = evaluated_at or NOW
        capabilities = capability_evidence(quota=quota, capacity=capacity)
        if evaluated_at is not None:
            capabilities["observed_at"] = route_time
            for record in capabilities["operative_models"]:
                record["observed_at"] = route_time
        fit = build_operative_fallback_fit(
            work_estimate=plan,
            cache_profile=cache_profile(),
            capability_evidence=capabilities,
            context=context,
            aggregate_budget=BUDGET,
            evaluated_at=route_time,
        )
        decision = resolve_operative_route(
            capability_evidence=capabilities,
            work_estimate=plan,
            fallback_fit=fit,
            context=context,
            aggregate_budget=BUDGET,
            evaluated_at=route_time,
        )
        candidate = next(
            item
            for item in decision["fallback"]["candidates"]
            if item["model"] == LUNA_MODEL
        )
        selection = {
            "version": 2,
            "selection_source": "user-explicit-fallback",
            "selected_model": LUNA_MODEL,
            "selected_executor": candidate["executor"],
            "reason": "User explicitly authorized the recommended eligible fallback.",
            "scope": "current-wave",
            "wave_id": context["wave_id"],
            "selected_at": route_time,
            "actor": "operator@example.test",
            "capability_evidence_sha256": decision["capability_evidence_sha256"],
            "work_estimate_sha256": decision["work_estimate_sha256"],
            "fallback_fit_sha256": decision["fallback_fit_sha256"],
            "policy_sha256": decision["policy_sha256"],
            "candidate_evidence_sha256": candidate["model_evidence_sha256"],
        }
        route = resolve_operative_route(
            capability_evidence=capabilities,
            work_estimate=plan,
            fallback_fit=fit,
            fallback_selection=selection,
            context=context,
            aggregate_budget=BUDGET,
            evaluated_at=route_time,
        )
        return plan, route, context

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

    @mock.patch(
        "cwo_core.operative_routing._now_iso",
        new=lambda: "2026-09-03T19:15:00Z",
    )
    @historical_v2_policy()
    def test_fallback_canary_requires_verified_quota_exhaustion_and_exact_route(self) -> None:
        from tests.test_operative_routing import NOW

        plan, route, _ = self.fallback_canary_bundle()
        evidence = self.build(
            packet_id="fallback-canary",
            attempt_nonce="fallback-canary-attempt",
            work_plan=plan,
            operative_routing=route,
            now=NOW,
        )
        self.assertEqual(evidence["requested_model"], "gpt-5.6-luna")
        self.assertEqual(evidence["operative_routing_sha256"], canonical_sha256(route))
        routing_now = dt.datetime.fromisoformat(NOW.replace("Z", "+00:00"))
        self.assertEqual(validate_native_release_evidence(evidence, now=routing_now), [])

        with self.assertRaisesRegex(ValueError, "valid operative routing"):
            self.build(
                packet_id="fallback-canary-no-route",
                attempt_nonce="fallback-canary-no-route-attempt",
                work_plan=plan,
                operative_routing=None,
                now=NOW,
            )

        capacity_plan, capacity_route, _ = self.fallback_canary_bundle(
            quota="usable",
            capacity="unavailable",
        )
        with self.assertRaisesRegex(ValueError, "verified Spark quota exhaustion"):
            self.build(
                packet_id="fallback-capacity-canary",
                attempt_nonce="fallback-capacity-canary-attempt",
                work_plan=capacity_plan,
                operative_routing=capacity_route,
                now=NOW,
            )

        with self.assertRaisesRegex(ValueError, "must not carry fallback"):
            self.build(operative_routing=route)

    @mock.patch(
        "cwo_core.operative_routing._now_iso",
        new=lambda: "2026-09-03T19:15:00.123456Z",
    )
    @historical_v2_policy()
    def test_fallback_canary_preserves_supplied_microsecond_routing_clock(self) -> None:
        precise_now = "2026-09-03T19:15:00.123456Z"
        plan, route, _ = self.fallback_canary_bundle(evaluated_at=precise_now)
        evidence = self.build(
            packet_id="fallback-canary-microsecond-clock",
            attempt_nonce="fallback-canary-microsecond-clock-attempt",
            work_plan=plan,
            operative_routing=route,
            now=precise_now,
        )
        self.assertEqual(evidence["requested_model"], "gpt-5.6-luna")
        self.assertEqual(
            evidence["operative_routing_sha256"], canonical_sha256(route)
        )

    @mock.patch(
        "cwo_core.operative_routing._now_iso",
        new=lambda: "2026-09-03T19:15:00Z",
    )
    @historical_v2_policy()
    def test_fallback_canary_authorizes_only_the_same_fallback_with_bound_evidence(self) -> None:
        from tests.test_operative_routing import NOW

        plan, route, _ = self.fallback_canary_bundle()
        canary_release = self.build(
            packet_id="fallback-canary-proof",
            attempt_nonce="fallback-canary-proof-attempt",
            work_plan=plan,
            operative_routing=route,
            now=NOW,
        )
        workspace = self.root / "fallback-canary-workspace"
        workspace.mkdir()
        canary_receipt = issue_accepting_precommit_receipt(
            work_plan=plan,
            packet_id="fallback-canary-proof",
            artifact_root=self.root / "fallback-canary-receipt",
            workdir=workspace,
            estimates={
                "tool_calls_p50": 1,
                "tool_calls_p90": 1,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 20,
            },
            model="gpt-5.6-luna",
            operative_routing=route,
            attempt_nonce="fallback-canary-proof-attempt",
        )
        candidate = candidate_packet(self.root)
        candidate.update(
            packet_id="fallback-operative-candidate",
            requested_model="gpt-5.6-luna",
            work_plan=plan,
            operative_routing=route,
        )
        adjudication = operative_adjudication(canary_receipt["receipt_sha256"])
        evidence = build_operative_release_evidence(
            candidate_packet=candidate,
            adjudication=adjudication,
            canary_receipt=canary_receipt,
            canary_release_evidence=canary_release,
            now=NOW,
        )
        self.assertEqual(evidence["requested_model"], "gpt-5.6-luna")

        with self.assertRaisesRegex(ValueError, "requires its release evidence"):
            build_operative_release_evidence(
                candidate_packet=candidate,
                adjudication=adjudication,
                canary_receipt=canary_receipt,
                now=NOW,
            )

        tampered_release = copy.deepcopy(canary_release)
        tampered_release["operative_routing_sha256"] = "f" * 64
        tampered_release["evidence_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in tampered_release.items()
                if key != "evidence_sha256"
            }
        )
        with self.assertRaisesRegex(ValueError, "operative_routing_sha256 binding mismatch"):
            build_operative_release_evidence(
                candidate_packet=candidate,
                adjudication=adjudication,
                canary_receipt=canary_receipt,
                canary_release_evidence=tampered_release,
                now=NOW,
            )

        wrong_model = copy.deepcopy(candidate)
        wrong_model["requested_model"] = "gpt-5.6-terra"
        with self.assertRaisesRegex(ValueError, "fallback canary model must match"):
            build_operative_release_evidence(
                candidate_packet=wrong_model,
                adjudication=adjudication,
                canary_receipt=canary_receipt,
                canary_release_evidence=canary_release,
                now=NOW,
            )

    def test_operative_evidence_requires_strict_go_and_authorizes_exact_packet(self) -> None:
        canary_receipt = self.accepting_canary_receipt()
        canary_hash = canary_receipt["receipt_sha256"]
        candidate = candidate_packet(self.root)
        original_candidate = copy.deepcopy(candidate)
        self.assertEqual(candidate.get("version"), 2)
        packet = authorize_operative_packet(
            candidate_packet=candidate,
            adjudication=operative_adjudication(canary_hash),
            canary_receipt=canary_receipt,
            now=self.now,
        )
        self.assertEqual(candidate, original_candidate)
        evidence = packet["release_evidence"]
        self.assertEqual(packet["stage"], "operative-authorized")
        self.assertTrue(packet["operative_dispatch_authorized"])
        self.assertEqual(packet["release_evidence_sha256"], evidence["evidence_sha256"])
        self.assertEqual(validate_native_release_evidence(evidence, now=self.now_dt), [])
        for operation in evidence["authorized_operations"]:
            with self.subTest(operation=operation):
                self.assertEqual(
                    containment_error(
                        operation,
                        release_evidence=evidence,
                        expected_packet_id=candidate["packet_id"],
                        expected_work_plan_sha256=canonical_sha256(canary_plan()),
                        expected_precommit_receipt_sha256="1" * 64,
                    ),
                    "",
                )

        no_go = operative_adjudication(canary_hash)
        no_go["decision"] = "NO-GO"
        with self.assertRaisesRegex(ValueError, "decision must equal 'GO'"):
            build_operative_release_evidence(
                candidate_packet=candidate,
                adjudication=no_go,
                canary_receipt=canary_receipt,
                now=self.now,
            )
        synthesis_field = operative_adjudication(canary_hash)
        synthesis_field["critic_synthesis_sha256"] = synthesis_field.pop("critic_evidence_sha256")
        with self.assertRaisesRegex(ValueError, "operative adjudication fields are invalid"):
            build_operative_release_evidence(
                candidate_packet=candidate,
                adjudication=synthesis_field,
                canary_receipt=canary_receipt,
                now=self.now,
            )
        with self.assertRaisesRegex(ValueError, "canary_receipt_sha256"):
            build_operative_release_evidence(
                candidate_packet=candidate,
                adjudication=operative_adjudication("6" * 64),
                canary_receipt=canary_receipt,
                now=self.now,
            )
        tampered_canary = copy.deepcopy(canary_receipt)
        tampered_canary["observed"]["function_calls"] = 1
        with self.assertRaisesRegex(ValueError, "canary receipt is invalid"):
            build_operative_release_evidence(
                candidate_packet=candidate,
                adjudication=operative_adjudication(canary_hash),
                canary_receipt=tampered_canary,
                now=self.now,
            )

    def test_operative_release_reissue_preserves_packet_and_appends_lineage(self) -> None:
        canary_receipt = self.accepting_canary_receipt()
        workdir = self.root / "operative-workspace"
        workdir.mkdir()
        operative_receipt = issue_accepting_precommit_receipt(
            work_plan=canary_plan(),
            packet_id="operative-refresh-packet",
            artifact_root=self.root / "operative-refresh-receipt",
            workdir=workdir,
            estimates={
                "tool_calls_p50": 1,
                "tool_calls_p90": 1,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 20,
            },
        )
        candidate = candidate_packet(workdir)
        candidate.update(
            {
                "packet_id": operative_receipt["packet_id"],
                "precommit_receipt": operative_receipt,
                "precommit_receipt_sha256": operative_receipt["receipt_sha256"],
            }
        )
        packet = authorize_operative_packet(
            candidate_packet=candidate,
            adjudication=operative_adjudication(canary_receipt["receipt_sha256"]),
            canary_receipt=canary_receipt,
            now=self.now,
        )
        refreshed_at = (self.now_dt + dt.timedelta(seconds=30)).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        result = reissue_operative_packet_release(
            authorized_packet=packet,
            adjudication=operative_adjudication(canary_receipt["receipt_sha256"]),
            canary_receipt=canary_receipt,
            now=refreshed_at,
        )
        refreshed = result["packet"]
        self.assertEqual(refreshed["packet_id"], packet["packet_id"])
        self.assertEqual(
            refreshed["precommit_receipt_sha256"],
            packet["precommit_receipt_sha256"],
        )
        self.assertEqual(refreshed["work_plan"], packet["work_plan"])
        self.assertNotEqual(
            refreshed["release_evidence_sha256"], packet["release_evidence_sha256"]
        )
        lineage = result["lineage"]
        self.assertEqual(
            lineage["parent_release_evidence_sha256"],
            packet["release_evidence_sha256"],
        )
        self.assertEqual(
            lineage["replacement_release_evidence_sha256"],
            refreshed["release_evidence_sha256"],
        )
        self.assertEqual(
            lineage["lineage_sha256"],
            canonical_sha256(
                {key: value for key, value in lineage.items() if key != "lineage_sha256"}
            ),
        )

    def test_operative_release_rejects_non_v2_candidate_packets(self) -> None:
        canary_receipt = self.accepting_canary_receipt()
        canary_hash = canary_receipt["receipt_sha256"]
        adjudication = operative_adjudication(canary_hash)
        missing = object()
        invalid_versions = (
            ("version-1", 1),
            ("version-3", 3),
            ("version-string", "2"),
            ("version-bool-false", False),
            ("version-bool-true", True),
            ("version-null", None),
            ("version-missing", missing),
        )

        for label, version in invalid_versions:
            with self.subTest(label=label):
                if version is None:
                    candidate = candidate_packet(self.root)
                    candidate["version"] = None
                elif version is missing:
                    candidate = candidate_packet(self.root)
                    candidate.pop("version", None)
                else:
                    candidate = candidate_packet(self.root, version)
                for operation in (
                    build_operative_release_evidence,
                    authorize_operative_packet,
                ):
                    with self.subTest(operation=operation.__name__):
                        with self.assertRaisesRegex(ValueError, "candidate packet version must be integer 2"):
                            operation(
                                candidate_packet=candidate,
                                adjudication=adjudication,
                                canary_receipt=canary_receipt,
                                now=self.now,
                            )

    @mock.patch(
        "cwo_core.operative_routing._now_iso",
        new=lambda: "2026-09-03T19:15:00Z",
    )
    @historical_v2_policy()
    def test_operative_release_accepts_each_selected_fallback_and_rejects_mismatch(self) -> None:
        from tests.test_operative_routing import (
            GPT55_MODEL,
            LUNA_MODEL,
            NOW,
            TERRA_MODEL,
            fallback_bundle,
            select_route,
            work_plan as fallback_plan,
        )

        canary_receipt = self.accepting_canary_receipt()
        adjudication = operative_adjudication(canary_receipt["receipt_sha256"])
        for index, model in enumerate((GPT55_MODEL, TERRA_MODEL, LUNA_MODEL), start=1):
            with self.subTest(model=model):
                plan = fallback_plan(requested_model=model, narrow=model == LUNA_MODEL)
                bundle = fallback_bundle(plan=plan)
                route = select_route(bundle, model)
                candidate = candidate_packet(self.root)
                candidate.update(
                    packet_id=f"fallback-release-{index}",
                    requested_model=model,
                    work_plan=plan,
                    operative_routing=route,
                )
                evidence = build_operative_release_evidence(
                    candidate_packet=candidate,
                    adjudication=adjudication,
                    canary_receipt=canary_receipt,
                    now=NOW,
                )
                self.assertEqual(evidence["requested_model"], model)
                self.assertEqual(evidence["operative_routing_sha256"], canonical_sha256(route))
                routing_now = dt.datetime.fromisoformat(NOW.replace("Z", "+00:00"))
                self.assertEqual(validate_native_release_evidence(evidence, now=routing_now), [])

                mismatched = copy.deepcopy(candidate)
                mismatched["requested_model"] = (
                    TERRA_MODEL if model != TERRA_MODEL else LUNA_MODEL
                )
                with self.assertRaisesRegex(ValueError, "operative routing is invalid"):
                    build_operative_release_evidence(
                        candidate_packet=mismatched,
                        adjudication=adjudication,
                        canary_receipt=canary_receipt,
                        now=NOW,
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
