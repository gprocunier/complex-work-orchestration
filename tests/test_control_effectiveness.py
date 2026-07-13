from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.control_effectiveness import build_control_effectiveness_report  # noqa: E402

SCRIPT = ROOT / "scripts" / "render_control_effectiveness.py"


def supervision_event(
    *,
    event_type: str,
    state_id: str,
    decision: str = "continue",
    reasons: list[str] | None = None,
    late_poll_count: int = 0,
    max_poll_gap_ms: int = 900,
    dispatch_to_first_poll_ms: int = 400,
    compactions: int = 0,
) -> dict:
    return {
        "event_type": event_type,
        "telemetry_kind": "native_supervision",
        "native_supervision_state_id": state_id,
        "native_supervision_decision": decision,
        "native_supervision_reasons": reasons or [],
        "late_poll_count": late_poll_count,
        "max_poll_gap_ms": max_poll_gap_ms,
        "dispatch_to_first_poll_ms": dispatch_to_first_poll_ms,
        "observed_context_compactions": compactions,
    }


def return_event(*, sabotage_score: int, quarantine: bool) -> dict:
    return {
        "event_type": "return_evaluated",
        "sabotage_score": sabotage_score,
        "quarantine_recommended": quarantine,
    }


def sample_events() -> list[dict]:
    return [
        supervision_event(event_type="native_supervision_dispatched", state_id="state-a"),
        supervision_event(
            event_type="native_supervision_decision", state_id="state-a", decision="complete"
        ),
        supervision_event(event_type="native_supervision_dispatched", state_id="state-b"),
        supervision_event(
            event_type="native_supervision_decision",
            state_id="state-b",
            decision="control-lost",
            reasons=["control-lost: poll latency exceeded the configured interval and tolerance"],
            late_poll_count=2,
            max_poll_gap_ms=3200,
        ),
        supervision_event(event_type="native_supervision_dispatched", state_id="state-c"),
        supervision_event(
            event_type="native_supervision_decision",
            state_id="state-c",
            decision="control-lost",
            reasons=["control-lost: trusted attestation mismatch: model-mismatch"],
        ),
        return_event(sabotage_score=55, quarantine=True),
        return_event(sabotage_score=5, quarantine=False),
    ]


class ControlEffectivenessReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit_file = Path(self.tmp.name) / "audit.jsonl"
        self.audit_file.write_text(
            "\n".join(json.dumps(event) for event in sample_events()) + "\n",
            encoding="utf-8",
        )

    def test_report_aggregates_supervision_decisions(self) -> None:
        report = build_control_effectiveness_report(self.audit_file)
        self.assertEqual(report["result_type"], "cwo-control-effectiveness-report")
        supervision = report["supervision"]
        self.assertEqual(supervision["supervised_dispatches"], 3)
        self.assertEqual(supervision["final_decisions"], {"complete": 1, "control-lost": 2})
        losses = supervision["control_losses"]
        self.assertEqual(losses["total"], 2)
        self.assertEqual(losses["spurious_control_plane"], 1)
        self.assertEqual(losses["substantive"], 1)
        self.assertEqual(supervision["poll_health"]["late_poll_states"], 1)
        self.assertEqual(supervision["poll_health"]["max_poll_gap_ms"], 3200)

    def test_report_aggregates_returns_and_rubric(self) -> None:
        report = build_control_effectiveness_report(self.audit_file)
        returns = report["returns"]
        self.assertEqual(returns["evaluated"], 2)
        self.assertEqual(returns["quarantine_recommended"], 1)
        self.assertEqual(returns["max_sabotage_score"], 55)
        rubric = report["rubric"]
        self.assertEqual(rubric["control_loss_target_pct"], 2.0)
        self.assertAlmostEqual(rubric["control_loss_rate_pct"], 66.67, places=1)
        self.assertFalse(rubric["meets_control_loss_target"])

    def test_spurious_dominance_emits_lag_tolerance_hint(self) -> None:
        report = build_control_effectiveness_report(self.audit_file)
        hints = " ".join(report["tuning_hints"])
        self.assertIn("poll_lag_tolerance_ms", hints)

    def test_empty_audit_produces_empty_report(self) -> None:
        empty = Path(self.tmp.name) / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        report = build_control_effectiveness_report(empty)
        self.assertEqual(report["supervision"]["supervised_dispatches"], 0)
        self.assertIsNone(report["rubric"]["control_loss_rate_pct"])

    def test_cli_json_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--audit-file", str(self.audit_file), "--json"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["result_type"], "cwo-control-effectiveness-report")

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "jsonschema not installed")
    def test_report_conforms_to_schema(self) -> None:
        import jsonschema

        schema = json.loads(
            (ROOT / "schemas" / "control-effectiveness-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.validate(build_control_effectiveness_report(self.audit_file), schema)

    def test_cli_missing_audit_file_fails(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--audit-file", str(Path(self.tmp.name) / "absent.jsonl")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("audit file not found", result.stderr)


if __name__ == "__main__":
    unittest.main()
