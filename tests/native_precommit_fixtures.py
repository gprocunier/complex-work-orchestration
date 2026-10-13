from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import uuid
from typing import Any, Mapping

from cwo_core.paths import cwo_temp_dir, is_cwo_temp_path
from cwo_core.native_precommit import (
    arm_precommit,
    check_precommit,
    create_precommit_state,
    finalize_precommit,
    issue_precommit_receipt,
    make_deterministic_receipt,
    mark_fit_dispatched,
)


MODEL = "gpt-5.3-codex-spark"


def _record(
    *,
    timestamp: str,
    session_id: str,
    response_item: Mapping[str, Any] | None = None,
    event_msg: str | None = None,
    model: str = MODEL,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "timestamp": timestamp,
        "session_id": session_id,
        "turn_context": {
            "model": model,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {
                "input": 1,
                "cached_input": 0,
                "output": 1,
                "reasoning": 0,
                "total": 2,
            },
        },
    }
    if response_item is not None:
        value["type"] = "response_item"
        value["response_item"] = dict(response_item)
    if event_msg is not None:
        value["event_msg"] = event_msg
    return value


def _write_records(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )


def _owned_artifact_root(artifact_root: str | Path) -> Path:
    """Return an artifact directory authorized by the active CWO temp policy.

    Callers may supply an ordinary TemporaryDirectory as an ownership/lifetime
    container.  The production boundary now authorizes only the active session
    or exchange roots, so legacy fixtures are migrated into a private purpose
    directory under that active session root.
    """

    requested = Path(artifact_root).resolve()
    requested.mkdir(parents=True, exist_ok=True)
    if is_cwo_temp_path(requested):
        return requested
    return cwo_temp_dir(
        scope="session",
        purpose=f"native-precommit-fixture-{uuid.uuid4().hex}",
    )


def _ensure_exact_git_worktree(workdir: str | Path) -> None:
    """Give synthetic receipt fixtures the production-required Git identity."""

    root = Path(workdir).resolve()
    probe = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0 and Path(probe.stdout.strip()).resolve() == root:
        return
    subprocess.run(
        ["git", "-C", str(root), "init", "-q"],
        check=True,
        capture_output=True,
        text=True,
    )


def issue_accepting_precommit_receipt(
    *,
    work_plan: Mapping[str, Any],
    packet_id: str,
    artifact_root: str | Path,
    workdir: str | Path,
    estimates: Mapping[str, int],
    model: str = MODEL,
    operative_routing: Mapping[str, Any] | None = None,
    attempt_nonce: str | None = None,
) -> dict[str, Any]:
    """Issue a real zero-tool accepting receipt for receipt-bound packet tests."""

    root = _owned_artifact_root(artifact_root)
    unique = uuid.uuid4().hex
    session_id = f"fixture-session-{unique}"
    session_file = root / f"session-{unique}.jsonl"
    state_file = root / f"state-{unique}.json"
    receipt_file = root / f"receipt-{unique}.json"
    audit_file = root / f"audit-{unique}.jsonl"
    control_turn = f"fixture-control-{unique}"
    _ensure_exact_git_worktree(workdir)
    meta = {
        "timestamp": "2026-07-15T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id},
        "turn_context": {
            "model": model,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {
                "input": 0,
                "cached_input": 0,
                "output": 0,
                "reasoning": 0,
                "total": 0,
            },
        },
    }
    _write_records(session_file, [meta])
    create_precommit_state(
        packet_id=packet_id,
        attempt_nonce=attempt_nonce or f"fixture-attempt-{unique}",
        work_plan=dict(work_plan),
        session_id=session_id,
        session_file=session_file,
        agent_id=f"fixture-agent-{unique}",
        workdir=workdir,
        operative_routing=operative_routing,
        state_file=state_file,
        owner_pid=os.getpid(),
        audit_file=audit_file,
        requested_model=model,
        now="2026-07-15T00:00:00Z",
    )
    arm_precommit(state_file, control_turn, now="2026-07-15T00:00:00.100Z")
    _, code = mark_fit_dispatched(
        state_file,
        control_turn,
        f"fixture-submission-{unique}",
        now="2026-07-15T00:00:00.200Z",
    )
    if code != 0:
        raise AssertionError("fixture precommit dispatch did not succeed")
    response = {
        "decision": "accept",
        "tool_calls_p50": int(estimates["tool_calls_p50"]),
        "tool_calls_p90": int(estimates["tool_calls_p90"]),
        "runtime_seconds_p50": int(estimates["runtime_seconds_p50"]),
        "runtime_seconds_p90": int(estimates["runtime_seconds_p90"]),
    }
    records = [
        meta,
        _record(
            timestamp="2026-07-15T00:00:01Z",
            session_id=session_id,
            response_item={"type": "message", "role": "user", "content": "fit"},
            model=model,
        ),
        _record(
            timestamp="2026-07-15T00:00:02Z",
            session_id=session_id,
            response_item={
                "type": "message",
                "role": "assistant",
                "content": json.dumps(response, sort_keys=True),
            },
            model=model,
        ),
        _record(
            timestamp="2026-07-15T00:00:03Z",
            session_id=session_id,
            event_msg="task_complete",
            model=model,
        ),
    ]
    _write_records(session_file, records)
    _, code = check_precommit(
        state_file,
        control_turn,
        now="2026-07-15T00:00:00.300Z",
    )
    if code != 0:
        raise AssertionError("fixture precommit terminal check did not succeed")
    finalize_precommit(
        state_file,
        control_turn,
        "worker-completed",
        now="2026-07-15T00:00:00.400Z",
    )
    finalize_precommit(
        state_file,
        control_turn,
        "close-confirmed",
        now="2026-07-15T00:00:00.500Z",
    )
    issue_precommit_receipt(state_file, receipt_file=receipt_file)
    return json.loads(receipt_file.read_text(encoding="utf-8"))


def issue_deterministic_precommit_receipt(
    *,
    work_plan: Mapping[str, Any],
    packet_id: str,
    artifact_root: str | Path,
    workdir: str | Path,
    estimates: Mapping[str, int],
) -> dict[str, Any]:
    root = _owned_artifact_root(artifact_root)
    unique = uuid.uuid4().hex
    session_id = f"fixture-deterministic-session-{unique}"
    session_file = root / f"deterministic-session-{unique}.jsonl"
    state_file = root / f"deterministic-state-{unique}.json"
    receipt_file = root / f"deterministic-receipt-{unique}.json"
    audit_file = root / f"deterministic-audit-{unique}.jsonl"
    meta = {
        "timestamp": "2026-07-15T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id},
        "turn_context": {
            "model": MODEL,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {
                "input": 0,
                "cached_input": 0,
                "output": 0,
                "reasoning": 0,
                "total": 0,
            },
        },
    }
    _write_records(session_file, [meta])
    receipt = make_deterministic_receipt(
        packet_id=packet_id,
        attempt_nonce=f"fixture-deterministic-attempt-{unique}",
        work_plan=dict(work_plan),
        session_id=session_id,
        session_file=session_file,
        agent_id=f"fixture-deterministic-agent-{unique}",
        workdir=workdir,
        fit_result={"decision": "accept", "estimates": dict(estimates)},
        control_turn_id=f"fixture-deterministic-control-{unique}",
        state_file=state_file,
        receipt_file=receipt_file,
        owner_pid=os.getpid(),
        audit_file=audit_file,
        now="2026-07-15T00:00:00Z",
    )
    return {key: value for key, value in receipt.items() if key != "receipt_file"}
