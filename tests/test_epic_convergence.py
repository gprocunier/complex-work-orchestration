from __future__ import annotations

import json
import multiprocessing
import sys
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import epic_convergence as ec  # noqa: E402
import replay_epic_convergence as replay_script  # type: ignore


def payload(index: int = 1) -> dict:
    return {
        "epic_id": "complex-work-orchestration-pb6",
        "work_unit_id": f"pb6.4-{index}",
        "bead_id": "complex-work-orchestration-pb6.4",
        "packet_id": f"packet-{index}",
        "session_id": f"session-{index}",
        "model": "gpt-5.3-codex-spark",
        "phase": "implementation",
        "event": f"event-{index}",
        "call_category": "productive",
        "usage": {"tool_calls": index, "runtime_seconds": float(index)},
        "artifact_disposition": "accepted",
        "graph_counters": {"beads_total": 7, "graph_depth": 2},
        "timestamp": f"2026-07-14T06:00:0{index}Z",
    }


def append_worker(path: str, index: int) -> None:
    ec.append_record(path, payload(index))


def minimal_payload(index: int = 1) -> dict:
    record = payload(index)
    record["usage"] = {
        "tool_calls": index,
        "runtime_seconds": float(index),
        "input_tokens": 10 * index,
        "output_tokens": 5 * index,
        "total_tokens": 15 * index,
        "context_compactions": 0,
        "full_suite_runs": 0,
    }
    record["graph_counters"] = {
        "beads_total": index,
        "beads_open": index,
        "beads_closed": 0,
        "graph_depth": 2,
        "work_units_total": 1,
        "work_units_open": 0,
        "work_units_closed": 1,
        "routine_repair_children": 0,
        "worker_sessions": 1,
    }
    return record


def run_replay(inputs: list[str], *extra: str) -> dict:
    command = ["--input", *inputs]
    command.extend(extra)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        replay_script.run(command)
    return json.loads(buffer.getvalue())


class EpicConvergenceTests(unittest.TestCase):
    def test_schema_matches_record_contract(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/epic-convergence-ledger.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["record_type"]["const"], ec.RECORD_TYPE)
        self.assertEqual(set(schema["required"]), set(ec.RECORD_FIELDS))
        self.assertEqual(
            set(schema["properties"]["usage"]["oneOf"][1]["required"]),
            set(ec.USAGE_FIELDS),
        )

    def test_hash_is_deterministic_for_key_order(self) -> None:
        first = ec.build_record(payload())
        reversed_payload = dict(reversed(list(payload().items())))
        second = ec.build_record(reversed_payload)
        self.assertEqual(first["record_sha256"], second["record_sha256"])

    def test_historical_unknowns_remain_null(self) -> None:
        source = payload()
        for field in ec.IDENTITY_FIELDS:
            source[field] = None
        source["call_category"] = None
        source["usage"] = {"tool_calls": None}
        source["artifact_disposition"] = None
        source["graph_counters"] = {"beads_total": None}
        source["timestamp"] = None
        record = ec.build_record(source)
        self.assertTrue(all(record[field] is None for field in ec.IDENTITY_FIELDS))
        self.assertIsNone(record["usage"]["tool_calls"])
        self.assertIsNone(record["usage"]["runtime_seconds"])
        self.assertIsNone(record["graph_counters"]["beads_total"])
        self.assertIsNone(record["graph_counters"]["graph_depth"])
        self.assertIsNone(record["timestamp"])

    def test_malformed_values_fail_closed(self) -> None:
        cases = []
        bad = payload()
        bad["usage"] = {"tool_calls": True}
        cases.append(bad)
        bad = payload()
        bad["usage"] = {"runtime_seconds": -0.1}
        cases.append(bad)
        bad = payload()
        bad["graph_counters"] = {"graph_depth": False}
        cases.append(bad)
        bad = payload()
        bad["timestamp"] = "2026-07-14T06:00:00"
        cases.append(bad)
        bad = payload()
        bad["extra"] = "forbidden"
        cases.append(bad)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    ec.build_record(value)

    def test_all_call_categories_validate(self) -> None:
        for category in ec.CALL_CATEGORIES:
            source = payload()
            source["call_category"] = category
            with self.subTest(category=category):
                ec.validate_record(ec.build_record(source))

    def test_tampering_and_chain_breaks_are_rejected(self) -> None:
        first = ec.build_record(payload(1))
        second_source = payload(2)
        second_source["previous_record_sha256"] = first["record_sha256"]
        second = ec.build_record(second_source)
        self.assertTrue(ec.validate_chain([first, second]))
        tampered = dict(second)
        tampered["event"] = "changed"
        with self.assertRaises(ValueError):
            ec.validate_record(tampered)
        broken = dict(second)
        broken["previous_record_sha256"] = None
        broken["record_sha256"] = ec.canonical_record_sha256(broken)
        with self.assertRaises(ValueError):
            ec.validate_chain([first, broken])

    def test_replay_parses_json_objects_and_jsonl_without_rewrite(self) -> None:
        first = minimal_payload(1)
        second = minimal_payload(2)
        first["artifact_disposition"] = "accepted"
        second["artifact_disposition"] = "accepted"
        with tempfile.TemporaryDirectory() as temporary:
            json_path = Path(temporary) / "records.json"
            jsonl_path = Path(temporary) / "records.jsonl"
            json_path.write_text(
                json.dumps([first, second], sort_keys=True),
                encoding="utf-8",
            )
            jsonl_path.write_text(
                "\n".join([json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)])
                + "\n",
                encoding="utf-8",
            )
            before_json = json_path.read_bytes()
            before_jsonl = jsonl_path.read_bytes()
            output_json = run_replay([str(json_path)])
            output_jsonl = run_replay([str(jsonl_path)])
            self.assertEqual(output_json["record_count"], 2)
            self.assertEqual(output_jsonl["record_count"], 2)
            self.assertEqual(json_path.read_bytes(), before_json)
            self.assertEqual(jsonl_path.read_bytes(), before_jsonl)

    def test_replay_rejects_contradictory_tool_call_sources(self) -> None:
        source = minimal_payload(1)
        source["usage"]["tool_calls"] = 1
        source["aggregate"] = {"tool_calls": 2}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.json"
            path.write_text(json.dumps([source], sort_keys=True), encoding="utf-8")
            with self.assertRaises(ValueError):
                run_replay([str(path)])

    def test_replay_rejects_contradictory_category_fallbacks(self) -> None:
        source = minimal_payload(1)
        source.pop("call_category", None)
        source["lane"] = "productive"
        source["phase"] = "fit"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.json"
            path.write_text(json.dumps([source], sort_keys=True), encoding="utf-8")
            with self.assertRaises(ValueError):
                run_replay([str(path)])

    def test_replay_keeps_missing_values_as_null(self) -> None:
        source = {"epic_id": None, "work_unit_id": None}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.json"
            path.write_text(json.dumps([source], sort_keys=True), encoding="utf-8")
            output = run_replay([str(path)])
            self.assertEqual(output["historical_null_counts"]["usage"]["tool_calls"], 1)
            self.assertEqual(output["historical_null_counts"]["usage"]["runtime_seconds"], 1)
            self.assertEqual(output["historical_null_counts"]["graph_counters"]["beads_total"], 1)
            self.assertEqual(output["historical_null_counts"]["artifact_disposition"], 1)
            self.assertEqual(output["record_count"], 1)

    def test_replay_category_totals_and_unknown_records(self) -> None:
        first = minimal_payload(1)
        first["call_category"] = "productive"
        first["artifact_disposition"] = "accepted"
        second = minimal_payload(2)
        second.pop("call_category", None)
        second["phase"] = "validation"
        second["artifact_disposition"] = "accepted"
        third = minimal_payload(3)
        third.pop("call_category", None)
        third["phase"] = "implementation"
        third["artifact_disposition"] = "accepted"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.json"
            path.write_text(
                json.dumps([first, second, third], sort_keys=True),
                encoding="utf-8",
            )
            output = run_replay([str(path)])
            self.assertEqual(output["categories"]["record_counts"]["productive"], 1)
            self.assertEqual(output["categories"]["record_counts"]["validation"], 1)
            self.assertEqual(output["categories"]["record_counts"]["unknown"], 1)
            self.assertEqual(output["unknown_call_records"], 1)
            self.assertEqual(output["categories"]["call_totals"]["productive"], 1)
            self.assertEqual(output["categories"]["call_totals"]["validation"], 2)

    def test_replay_tracks_protected_stops(self) -> None:
        first = minimal_payload(1)
        first["artifact_disposition"] = "rejected"
        first["reason"] = "control loss in the worker lane"
        second = minimal_payload(2)
        second["artifact_disposition"] = "quarantine"
        second["reason"] = "normal failure"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.json"
            path.write_text(json.dumps([first, second], sort_keys=True), encoding="utf-8")
            output = run_replay([str(path)])
            self.assertEqual(output["protected_stops"]["count"], 1)
            self.assertEqual(output["protected_stops"]["preserved"], 1)
            self.assertEqual(output["quarantined"]["segments"], 2)
            self.assertEqual(output["preventable"]["segments"], 1)

    def test_replay_calculates_targets_with_overrides(self) -> None:
        first = minimal_payload(1)
        first["artifact_disposition"] = "accepted"
        second = minimal_payload(2)
        second["artifact_disposition"] = "quarantine"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.json"
            path.write_text(json.dumps([first, second], sort_keys=True), encoding="utf-8")
            output = run_replay(
                [str(path)],
                "--baseline-nonaccepted-segments",
                "10",
                "--baseline-nonaccepted-calls",
                "20",
                "--minimum-avoided-segments",
                "5",
                "--minimum-avoided-calls",
                "15",
                "--minimum-control-plane-reduction",
                "60",
            )
            self.assertEqual(output["targets"]["results"]["current_nonaccepted_segments"], 1)
            self.assertEqual(output["targets"]["results"]["current_nonaccepted_calls"], 2)
            self.assertEqual(output["targets"]["results"]["avoided_nonaccepted_segments"], 9)
            self.assertEqual(output["targets"]["results"]["avoided_nonaccepted_calls"], 18)
            self.assertAlmostEqual(
                output["targets"]["results"]["control_plane_reduction_percent"],
                90.0,
            )
            self.assertTrue(output["targets"]["results"]["segments_target_met"])
            self.assertTrue(output["targets"]["results"]["calls_target_met"])
            self.assertTrue(output["targets"]["results"]["control_plane_reduction_target_met"])

    def test_append_is_additive_and_load_validates_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.jsonl"
            first = ec.append_record(path, payload(1))
            prefix = path.read_bytes()
            second = ec.append_record(path, payload(2))
            self.assertTrue(path.read_bytes().startswith(prefix))
            records = ec.load_records(path)
            self.assertEqual([first, second], records)
            lines = path.read_text(encoding="utf-8").splitlines()
            damaged = json.loads(lines[1])
            damaged["previous_record_sha256"] = None
            damaged["record_sha256"] = ec.canonical_record_sha256(damaged)
            path.write_text(f"{lines[0]}\n{json.dumps(damaged)}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                ec.load_records(path)

    def test_two_process_appends_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.jsonl"
            context = multiprocessing.get_context("fork")
            workers = [
                context.Process(target=append_worker, args=(str(path), index))
                for index in (1, 2)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10)
                self.assertEqual(worker.exitcode, 0)
            records = ec.load_records(path)
            self.assertEqual(len(records), 2)
            self.assertTrue(ec.validate_chain(records))

    def test_unavailable_lock_fails_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.jsonl"
            with patch.object(ec, "_ledger_lock", side_effect=RuntimeError("unavailable")):
                with self.assertRaises(RuntimeError):
                    ec.append_record(path, payload())
            self.assertFalse(path.exists())

    def test_closure_pressure_requires_disposition_and_rejects_repair_child(self) -> None:
        inactive = ec.evaluate_closure_pressure(False, "continue", None)
        self.assertTrue(inactive["allowed"])
        missing = ec.evaluate_closure_pressure(True, "continue", None)
        self.assertFalse(missing["allowed"])
        self.assertEqual(missing["reason"], "explicit-closure-disposition-required")
        repair = ec.evaluate_closure_pressure(
            True, "create-routine-repair-child", "correct"
        )
        self.assertFalse(repair["allowed"])
        accepted = ec.evaluate_closure_pressure(True, "continue", "retain")
        self.assertTrue(accepted["allowed"])
        with self.assertRaises(ValueError):
            ec.evaluate_closure_pressure(True, "continue", "invented")


if __name__ == "__main__":
    unittest.main()
