#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from cwo_core.native_session import (
    _error,
    _evaluate_records,
    _parse_iso_timestamp,
    _session_id_matches,
    _status_to_return_code,
)

SCHEMA_PATH = "schemas/native-worker-session-check.schema.json"
REPO_POLICY = "policy/native-worker-execution.yaml"
SCHEMA_VERSION = 1
DEFAULT_REQUESTED_MODEL = "gpt-5.3-codex-spark"
SUPPORTED_BUDGET_PROFILES = (
    "implementation",
    "validation",
    "review",
    "publish-report-admin",
)


def _load_json_policy() -> dict[str, Any]:
    try:
        raw = Path(REPO_POLICY).read_text(encoding="utf-8")
    except OSError as exc:
        _error(f"unable to read policy {REPO_POLICY!r}: {exc}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _error(f"policy {REPO_POLICY!r} is not valid JSON: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check a native worker session log against native-worker policy budgets."
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--requested-model")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--budget-profile", choices=SUPPORTED_BUDGET_PROFILES)
    source.add_argument("--packet", help="Use requested model and effective budget from a dispatchable native packet v2.")
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--sessions-root", help="Directory containing session JSONL files.")
    source_group.add_argument(
        "--codex-home",
        help="Use <codex_home>/sessions for session discovery.",
    )
    source_group.add_argument(
        "--session-file",
        help="Explicit session JSONL file; skips root search.",
    )
    parser.add_argument(
        "--now",
        help="Optional ISO-8601 timestamp used for incomplete-segment closure.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser.parse_args()


def _load_policy(profile: str) -> dict[str, Any]:
    policy = _load_json_policy()
    lane_budgets = policy.get("lane_budgets")
    if not isinstance(lane_budgets, dict):
        _error("policy lane_budgets missing")
    budget = lane_budgets.get(profile)
    if not isinstance(budget, dict):
        _error(f"budget profile {profile!r} is missing from policy")
    snapshot = {
        "tool_calls_soft": int(budget.get("tool_calls_soft", 0)),
        "tool_calls_hard": int(budget.get("tool_calls_hard", 0)),
        "runtime_seconds_soft": int(budget.get("runtime_seconds_soft", 0)),
        "runtime_seconds_hard": int(budget.get("runtime_seconds_hard", 0)),
        "max_compactions": int(budget.get("max_compactions", 0)),
        "max_full_suite_runs": int(budget.get("max_full_suite_runs", 0)),
    }
    return {
        "profile_name": profile,
        "snapshot": snapshot,
    }


def _sessions_root(codex_home: str | None = None) -> Path:
    if codex_home:
        return Path(codex_home).expanduser().resolve() / "sessions"
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser().resolve() / "sessions"
    return Path.home() / ".codex" / "sessions"


def _iter_json_lines(path: Path, *, strict: bool = True):
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _error(f"unable to read {path}: {exc}", 1)
    for lineno, line in enumerate(raw_lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            yield lineno, json.loads(line)
        except json.JSONDecodeError as exc:
            if not strict:
                continue
            _error(f"{path}:{lineno} contains invalid JSON ({exc})", 1)


def find_session_file(
    session_id: str,
    sessions_root: Path,
    explicit: Path | None = None,
) -> Path:
    if explicit:
        if not explicit.is_file():
            _error(f"session file {explicit} is missing")
        matches = _session_id_matches(explicit, session_id)
        if not matches:
            _error(f"session id {session_id!r} not present in explicit session file {explicit}")
        return explicit

    if not sessions_root.is_dir():
        _error(f"sessions root {sessions_root} is not a directory")
    candidates = [
        path
        for path in sorted(sessions_root.rglob("*.jsonl"))
        if path.is_file() and session_id in path.name and path.suffix == ".jsonl"
    ]
    if not candidates:
        for path in sorted(sessions_root.rglob("*.jsonl")):
            if not path.is_file():
                continue
            if _session_id_matches(path, session_id, strict=False):
                candidates.append(path)
    if not candidates:
        _error(f"missing session file for session id {session_id!r}")
    if len(candidates) > 1:
        _error(f"ambiguous session id {session_id!r} matches {len(candidates)} files")
    return candidates[0]


def main() -> int:
    args = parse_args()
    packet_provenance = None
    interrupt_thresholds = None
    if args.packet:
        from prepare_native_worker import validate_native_worker_packet

        packet_path = Path(args.packet).expanduser().resolve()
        try:
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _error(f"could not load packet {packet_path}: {exc}")
        packet_errors = validate_native_worker_packet(packet, dispatchable=True)
        if packet_errors:
            _error("packet validation failed: " + "; ".join(packet_errors))
        requested_model = str(packet["requested_model"])
        if args.requested_model and args.requested_model.strip() != requested_model:
            _error("--requested-model must match packet requested_model")
        policy = {
            "profile_name": str(packet["lane"]),
            "snapshot": dict(packet["budget"]),
        }
        packet_provenance = packet.get("budget_provenance")
        interrupt_thresholds = packet.get("supervision", {}).get("interrupt_thresholds")
    else:
        policy = _load_policy(args.budget_profile)
        requested_model = (args.requested_model or DEFAULT_REQUESTED_MODEL).strip() or DEFAULT_REQUESTED_MODEL
    sessions_root = Path(args.sessions_root).expanduser().resolve() if args.sessions_root else _sessions_root(args.codex_home)
    explicit = Path(args.session_file).expanduser().resolve() if args.session_file else None
    session_file = find_session_file(args.session_id, sessions_root, explicit)
    records = [record for _, record in _iter_json_lines(session_file)]

    now: dt.datetime | None = None
    if args.now:
        now = _parse_iso_timestamp(args.now)
        if now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)

    segments, aggregate, overall_status, selected_segment = _evaluate_records(
        records, policy["snapshot"], requested_model, now
    )
    payload = {
        "schema": SCHEMA_PATH,
        "version": SCHEMA_VERSION,
        "session_id": args.session_id,
        "session_path": str(session_file),
        "requested_model": requested_model,
        "budget_profile": policy,
        "budget_provenance": packet_provenance,
        "interrupt_thresholds": interrupt_thresholds,
        "attestation_source": selected_segment["attestation_source"],
        "attested_model": selected_segment["attested_model"],
        "status": overall_status,
        "return_status": overall_status,
        "segments": segments,
        "aggregate": aggregate,
        "soft_limit_reasons": sorted(set(selected_segment.get("soft_limit_reasons", []))),
        "hard_stop_reasons": sorted(set(selected_segment.get("hard_stop_reasons", []))),
        "session_disposition": selected_segment["session_disposition"],
        "artifact_disposition": selected_segment["artifact_disposition"],
        "artifact_validation": selected_segment["artifact_validation"],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if overall_status in {"needs-architect-realignment", "budget-exhausted", "model-mismatch"}:
            print(f"Session status: {overall_status} (hard stop)")
        elif overall_status == "soft-limit":
            print("Session status: soft-limit")
        else:
            print("Session status: within-budget")
        print(f"Session file: {session_file}")
        print(f"Segments: {len(segments)}")
    return _status_to_return_code(overall_status)


if __name__ == "__main__":
    raise SystemExit(main())
