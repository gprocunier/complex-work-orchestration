#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
import time
from cwo_core.paths import AUDIT_LOG

from cwo_core.audit import record_audit_event
from cwo_core import telemetry as cwo_telemetry
from cwo_core.util import make_dispatch_id

SPARK_MODEL = "gpt-5.3-codex-spark"
SPARK_EXECUTOR = "internal_worker"
SPARK_PROVIDER_KEY = "internal_codex"
SPARK_PROVIDER_FAMILY = "internal"
SPARK_PROVIDER_RETENTION_CLASS = "internal"
SPARK_TIMEOUT_SECONDS = 120
NATIVE_CHECK_OUTCOME_ALLOWED = {"native-subagent-unavailable", "native-dispatch-rejected"}
NATIVE_FALLBACK_ROUTES = {
    "native-subagent-unavailable": "native-subagent-unavailable",
    "native-dispatch-rejected": "native-dispatch-rejected",
}
_REQUIRED_BRIDGE_AUDIT_FIELDS = (
    "requested_model",
    "actual_model",
    "native_check_outcome",
    "native_check_evidence",
    "native_check_evidence_sha256",
    "native_fallback_route",
)
for _field in _REQUIRED_BRIDGE_AUDIT_FIELDS:
    cwo_telemetry.TELEMETRY_STRING_FIELDS.add(_field)
    cwo_telemetry.AUDIT_STRING_FIELDS.add(_field)


_KNOWN_CLI_NOISE_PATTERNS = (
    "openai codex ",
    "--------",
    "workdir:",
    "model:",
    "provider:",
    "approval:",
    "sandbox:",
    "reasoning effort:",
    "reasoning summaries:",
    "session id:",
)


def _is_known_non_json_status_noise(line: str) -> bool:
    lowered = line.lower().strip()
    return any(lowered.startswith(prefix) for prefix in _KNOWN_CLI_NOISE_PATTERNS)


def _nonempty_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    output: list[str] = []
    for value in values:
        lane = str(value or "").strip()
        if lane and lane not in output:
            output.append(lane)
    return output


def _read_prompt(prompt_path: str | None) -> str:
    if prompt_path:
        try:
            return Path(prompt_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"failed to read prompt file {prompt_path!r}: {exc}") from exc
    return sys.stdin.read()


def _canonicalize_json_text(text: str) -> str:
    return " ".join(text.split())


def _read_native_check_evidence(raw: str | None) -> dict[str, object]:
    if not raw:
        raise SystemExit(
            "native check evidence is required via --native-check-evidence or CWO_SPARK_NATIVE_CHECK_EVIDENCE "
            "and must be machine-readable JSON indicating the native path was unavailable or rejected."
        )
    evidence_path = Path(raw)
    if evidence_path.exists():
        try:
            raw_text = evidence_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"failed to read native check evidence from {raw!r}: {exc}") from exc
    else:
        raw_text = raw
    try:
        evidence = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"native-check-evidence must be valid JSON: {exc}") from exc
    if not isinstance(evidence, dict):
        raise SystemExit("native-check-evidence must be a JSON object")

    outcome = str(evidence.get("outcome") or "").strip()
    if outcome not in NATIVE_CHECK_OUTCOME_ALLOWED:
        allowed = ", ".join(sorted(NATIVE_CHECK_OUTCOME_ALLOWED))
        raise SystemExit(f"native-check-evidence outcome must be one of: {allowed}")

    requested_model = str(evidence.get("requested_model") or evidence.get("model") or "").strip()
    if not requested_model:
        raise SystemExit("native-check-evidence must include requested_model for auditable fallback reasons")
    if requested_model != SPARK_MODEL:
        raise SystemExit(
            f"native-check-evidence requested_model must be {SPARK_MODEL}, not {requested_model}"
        )

    if outcome == "native-dispatch-rejected":
        rejection_reason = str(evidence.get("reason") or "").strip()
        if not rejection_reason:
            raise SystemExit("native-check-evidence outcome native-dispatch-rejected requires a reason")

    evidence_text = _canonicalize_json_text(raw_text)
    evidence_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return {
        "outcome": outcome,
        "evidence_text": evidence_text,
        "evidence_hash": evidence_hash,
        "requested_model": requested_model,
    }


def _extract_model_from_events(events: list[dict[str, Any]]) -> str | None:
    candidate_paths: tuple[tuple[str, ...], ...] = (
        ("model",),
        ("result", "model"),
        ("turn", "model"),
        ("item", "model"),
        ("result", "metadata", "model"),
        ("turn", "metadata", "model"),
        ("metadata", "model"),
    )
    for path in candidate_paths:
        for event in events:
            if not isinstance(event, dict):
                continue
            candidate = event
            for key in path:
                if not isinstance(candidate, dict) or key not in candidate:
                    candidate = None
                    break
                candidate = candidate[key]
            if isinstance(candidate, str):
                model = candidate.strip()
                if model:
                    return model
    return None


def _build_cli_bridge_telemetry(
    *,
    telemetry_status: str,
    telemetry_missing_reason: str | None,
    completion_state: str | None,
    usage: dict[str, int | float | None] | None,
    elapsed: float,
    returncode: int,
    mode: str,
    lanes: list[str],
    requested_model: str,
    actual_model: str,
    native_check_outcome: str,
    native_check_evidence_text: str,
    native_check_evidence_hash: str,
    fallback_route: str,
    workerbee_status: str,
) -> dict[str, Any]:
    usage_items = {} if usage is None else {k: v for k, v in usage.items() if k != "none"}
    return cwo_telemetry.telemetry_fields(
        telemetry_kind="codex_spark_worker",
        telemetry_status=telemetry_status,
        telemetry_missing_reason=telemetry_missing_reason,
        telemetry_source="codex-spark-worker-bridge",
        completion_state=completion_state,
        elapsed_seconds=elapsed,
        exit_status=returncode,
        agent_model_calls=1,
        retry_count=0,
        model=requested_model,
        model_label=requested_model,
        requested_model=requested_model,
        actual_model=actual_model,
        native_check_outcome=native_check_outcome,
        native_check_evidence=native_check_evidence_text,
        native_check_evidence_sha256=native_check_evidence_hash,
        native_fallback_route=fallback_route,
        provider_family=SPARK_PROVIDER_FAMILY,
        provider_retention_class=SPARK_PROVIDER_RETENTION_CLASS,
        workerbee_actual_mode=mode,
        workerbee_actual_model=actual_model,
        workerbee_actual_lanes=lanes,
        workerbee_delegation_status=workerbee_status,
        workerbee_delegation_source="codex_spark_bridge",
        **usage_items,
    )


def _build_audit_payload(
    *,
    dispatch_id: str,
    bead_id: str,
    mode: str,
    lanes: list[str],
    completion_state: str | None,
    telemetry: dict[str, Any],
    requested_model: str,
    actual_model: str,
    native_check_outcome: str,
    native_check_evidence_text: str,
    native_check_evidence_hash: str,
    fallback_route: str,
    sandbox: str,
) -> dict[str, Any]:
    return {
        "event_type": "local_worker_dispatch",
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "executor_key": SPARK_EXECUTOR,
        "provider_key": SPARK_PROVIDER_KEY,
        "executor_external": False,
        "dispatch_mode": "local_worker",
        "share_boundary": "no-outside-sharing",
        "model": requested_model,
        "model_label": requested_model,
        "workerbee_actual_mode": mode,
        "workerbee_actual_model": actual_model,
        "workerbee_actual_lanes": lanes,
        "workerbee_planned_mode": mode,
        "workerbee_planned_model": requested_model,
        "workerbee_planned_lanes": lanes,
        "workerbee_delegation_source": "codex_spark_bridge",
        "requested_model": requested_model,
        "actual_model": actual_model,
        "native_check_outcome": native_check_outcome,
        "native_check_evidence": native_check_evidence_text,
        "native_check_evidence_sha256": native_check_evidence_hash,
        "native_fallback_route": fallback_route,
        "sandbox": sandbox,
        "completion_state": completion_state,
        **telemetry,
    }


def _normalize_escaped_newlines(value: str) -> str:
    return value.replace("\\n", "\n")


def _positive_nonnegative(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and math.isfinite(value) and value >= 0:
        return value
    return None


def _iter_codex_jsonl(payload: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, line in enumerate(payload.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if _is_known_non_json_status_noise(stripped):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"codex returned non-jsonL output on line {index}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise SystemExit(f"codex JSONL line {index} must be an object")
        events.append(parsed)
    return events


def _extract_final_agent_message(events: list[dict[str, Any]]) -> str | None:
    final_message = None
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or event.get("event") or event.get("name") or "").strip()
        if event_type != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        if str(item.get("type") or "").strip() != "agent_message":
            continue
        text = item.get("text")
        if isinstance(text, str):
            final_message = text
    return final_message


def _write_text_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent), prefix=".cwo-return.", suffix=".tmp") as handle:
        handle.write(text)
        temp_path = handle.name
    os.replace(temp_path, path)


def _extract_completion_state(event: dict[str, Any]) -> str | None:
    for path in (
        "completion_state",
        "state",
        "status",
        ("result", "completion_state"),
        ("result", "state"),
        ("result", "status"),
    ):
        if isinstance(path, tuple):
            container = event
            for key in path:
                if not isinstance(container, dict) or key not in container:
                    container = None
                    break
                container = container[key]
            if isinstance(container, str):
                value = container.strip()
                if value:
                    return value
        elif isinstance(event.get(path), str):
            value = str(event[path]).strip()
            if value:
                return value
    return None


def _is_complete_usage(usage: dict[str, int | float | None]) -> bool:
    return usage["input_tokens"] is not None and usage["output_tokens"] is not None


def _extract_usage(event: dict[str, Any]) -> dict[str, int | float | None]:
    default_usage = {
        "input_tokens": None,
        "cached_tokens": None,
        "output_tokens": None,
        "reasoning_tokens": None,
        "total_tokens": None,
    }
    candidates: list[dict[str, Any]] = []
    usage = event.get("usage")
    if isinstance(usage, dict):
        candidates.append(usage)
    result = event.get("result")
    if isinstance(result, dict) and isinstance(result.get("usage"), dict):
        candidates.append(result.get("usage"))
    turn = event.get("turn")
    if isinstance(turn, dict) and isinstance(turn.get("usage"), dict):
        candidates.append(turn.get("usage"))

    latest_complete = None
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        extracted: dict[str, int | float | None] = {
            "input_tokens": None,
            "cached_tokens": None,
            "output_tokens": None,
            "reasoning_tokens": None,
            "total_tokens": None,
        }
        for target, key in (
            ("input_tokens", ("input_tokens", "prompt_tokens")),
            ("cached_tokens", ("cached_tokens", "cache_read_tokens", "cached_input_tokens")),
            ("output_tokens", ("output_tokens", "completion_tokens", "response_output_tokens")),
            ("reasoning_tokens", ("reasoning_tokens", "reasoning", "reasoning_output_tokens")),
            ("total_tokens", ("total_tokens", "total")),
        ):
            for source_key in key:
                if source_key in candidate:
                    numeric = _positive_nonnegative(candidate.get(source_key))
                    if numeric is not None:
                        extracted[target] = numeric
                        break
        if extracted["input_tokens"] is not None and extracted["output_tokens"] is not None:
            # Provider totals are prompt+completion, not prompt-with-cache+reasoning sums.
            # Cached tokens are a subset of input tokens; reasoning tokens are a subset of output tokens.
            extracted["total_tokens"] = extracted["input_tokens"] + extracted["output_tokens"]
            if extracted["cached_tokens"] is not None and extracted["cached_tokens"] > extracted["input_tokens"]:
                extracted["cached_tokens"] = extracted["input_tokens"]
            if (
                extracted["reasoning_tokens"] is not None
                and extracted["output_tokens"] is not None
                and extracted["reasoning_tokens"] > extracted["output_tokens"]
            ):
                extracted["reasoning_tokens"] = extracted["output_tokens"]
        if _is_complete_usage(extracted):
            latest_complete = extracted
    return latest_complete if latest_complete is not None else default_usage


def _find_turn_completed(events: list[dict[str, Any]]) -> tuple[str | None, dict[str, int | float | None] | None, dict[str, Any] | None]:
    for event in events:
        event_type = str(event.get("type") or event.get("event") or event.get("name") or "").strip()
        if event_type != "turn.completed":
            continue
        return (
            _extract_completion_state(event),
            _extract_usage(event),
            event,
        )
    return None, None, None


def _first_error_line(payload: str) -> str:
    payload = _normalize_escaped_newlines(payload)
    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        return stripped
    return ""


def _classify_failure_reason(returncode: int, stdout: str, stderr: str, events: list[dict[str, Any]]) -> str:
    if returncode == 127:
        return "codex-binary-unavailable"
    combined = f"{_normalize_escaped_newlines(stdout)}\n{_normalize_escaped_newlines(stderr)}".lower()
    if "unknown model" in combined or "model is unavailable" in combined or "model unavailable" in combined:
        return "codex-spark-model-unavailable"
    if "no such file" in combined or "command not found" in combined:
        return "codex-binary-unavailable"
    for event in events:
        if str(event.get("type") or event.get("event") or "").strip().lower() in {"error", "turn.error", "error.event"}:
            error_text = event.get("error") or event.get("message") or event.get("reason")
            if isinstance(error_text, str) and error_text.strip():
                return "codex-error: " + " ".join(error_text.split())
    for payload_part in (stderr, stdout):
        text = _first_error_line(payload_part)
        if text:
            return "codex-error: " + " ".join(text.split())[:200]
    return f"codex-exit-status: {returncode}"


def run_bridge(
    *,
    bead_id: str,
    dispatch_id: str,
    mode: str,
    lanes: list[str],
    workdir: Path,
    sandbox: str,
    prompt: str,
    output: Path | None,
    return_file: Path | None,
    audit_file: Path,
    codex_binary: str,
    timeout_seconds: int,
    requested_model: str,
    native_check_outcome: str,
    native_check_evidence_text: str,
    native_check_evidence_hash: str,
    native_fallback_route: str,
) -> int:
    codex_bin = shutil.which(codex_binary) or (str(Path(codex_binary).resolve()) if Path(codex_binary).exists() else None)

    def _finalize(
        *,
        telemetry_status: str,
        telemetry_missing_reason: str | None,
        completion_state: str | None,
        usage_values: dict[str, int | float | None] | None,
        actual_model: str,
        exit_status: int,
        workerbee_status: str,
        elapsed: float,
        return_file_content: str | None = None,
    ) -> int:
        telemetry = _build_cli_bridge_telemetry(
            telemetry_status=telemetry_status,
            telemetry_missing_reason=telemetry_missing_reason,
            completion_state=completion_state,
            usage=usage_values,
            elapsed=elapsed,
            returncode=exit_status,
            mode=mode,
            lanes=lanes,
            requested_model=requested_model,
            actual_model=actual_model,
            native_check_outcome=native_check_outcome,
            native_check_evidence_text=native_check_evidence_text,
            native_check_evidence_hash=native_check_evidence_hash,
            fallback_route=native_fallback_route,
            workerbee_status=workerbee_status,
        )
        telemetry["workerbee_actual_model"] = actual_model
        recorded = record_audit_event(
            _build_audit_payload(
                dispatch_id=dispatch_id,
                bead_id=bead_id,
                mode=mode,
                lanes=lanes,
                completion_state=completion_state,
                telemetry=telemetry,
                requested_model=requested_model,
                actual_model=actual_model,
                native_check_outcome=native_check_outcome,
                native_check_evidence_text=native_check_evidence_text,
                native_check_evidence_hash=native_check_evidence_hash,
                fallback_route=native_fallback_route,
                sandbox=sandbox,
            ),
            audit_file=audit_file,
        )
        artifact = {
            "dispatch_id": dispatch_id,
            "bead_id": bead_id,
            "model": requested_model,
            "requested_model": requested_model,
            "actual_model": actual_model,
            "mode": mode,
            "lanes": lanes,
            "sandbox": sandbox,
            "workdir": str(workdir),
            "telemetry_status": telemetry_status,
            "telemetry_missing_reason": telemetry_missing_reason,
            "completion_state": completion_state,
            "native_check_outcome": native_check_outcome,
            "native_fallback_route": native_fallback_route,
            "elapsed_seconds": elapsed,
            "exit_status": exit_status,
            "audit_event_hash": recorded.get("event_hash"),
        }
        if return_file_content is not None:
            artifact["return_file"] = return_file_content
        if output:
            output.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
        else:
            print(json.dumps(artifact, indent=2, sort_keys=True))
        if telemetry_status != "completed":
            print(f"FAILED: {telemetry_missing_reason}", file=sys.stderr)
            return 1
        return 0

    if not codex_bin:
        reason = "codex-binary-unavailable"
        print(f"FAILED: no codex executable found for {codex_binary}", file=sys.stderr)
        return _finalize(
            telemetry_status="failed",
            telemetry_missing_reason=reason,
            completion_state=None,
            usage_values={},
            actual_model=requested_model,
            exit_status=127,
            workerbee_status="failed",
            elapsed=0.0,
        )

    command = [codex_bin, "exec", "--model", requested_model, "--sandbox", sandbox, "--json", "-"]
    start = time.monotonic()
    try:
        result = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=str(workdir),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        result = subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )
        timed_out = True
    else:
        timed_out = False
    elapsed = round(time.monotonic() - start, 3)
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    events: list[dict[str, Any]] = []
    parse_error = None
    if not timed_out:
        try:
            events = _iter_codex_jsonl(stdout)
        except SystemExit as exc:
            parse_error = str(exc)

    if parse_error is not None:
        return _finalize(
            telemetry_status="failed",
            telemetry_missing_reason="codex-jsonl-parse-failed",
            completion_state=None,
            usage_values={},
            actual_model=requested_model,
            exit_status=result.returncode,
            workerbee_status="failed",
            elapsed=elapsed,
        )

    completion_state, usage, turn_event = _find_turn_completed(events)
    actual_model = _extract_model_from_events(events) or requested_model
    if actual_model != requested_model:
        return _finalize(
            telemetry_status="failed",
            telemetry_missing_reason=f"codex-output-model-substitution:{actual_model}",
            completion_state=None,
            usage_values={},
            actual_model=actual_model,
            exit_status=result.returncode,
            workerbee_status="failed",
            elapsed=elapsed,
        )
    if timed_out:
        reason = "codex-timeout-seconds-exceeded"
        telemetry_status = "failed"
        agent_status = "failed"
        completion_state = None
        usage = {}
    elif result.returncode != 0:
        reason = _classify_failure_reason(result.returncode, stdout, stderr, events)
        telemetry_status = "failed"
        agent_status = "failed"
    elif not turn_event:
        reason = "codex-output-missing-turn-completed"
        telemetry_status = "failed"
        agent_status = "failed"
        usage = {}
    elif usage is None:
        reason = "codex-output-turn-completed-missing-usage"
        telemetry_status = "failed"
        agent_status = "failed"
    else:
        if not all(v is None for v in usage.values()):
            reason = None
            telemetry_status = "completed"
            agent_status = "completed"
        else:
            reason = "codex-output-turn-completed-usage-empty"
            telemetry_status = "failed"
            agent_status = "failed"
            usage = {}

    if telemetry_status == "completed" and return_file is not None:
        final_message = _extract_final_agent_message(events)
        if final_message is None:
            reason = "codex-output-missing-final-agent-message"
            telemetry_status = "failed"
            usage = {}
            agent_status = "failed"
        else:
            try:
                _write_text_atomically(return_file, final_message)
            except OSError:
                reason = "codex-return-file-write-failed"
                telemetry_status = "failed"
                usage = {}
                agent_status = "failed"

    if telemetry_status == "completed" and completion_state is None:
        completion_state = "completed"
    return _finalize(
        telemetry_status=telemetry_status,
        telemetry_missing_reason=reason,
        completion_state=completion_state,
        usage_values=usage or {},
        actual_model=actual_model,
        exit_status=result.returncode,
        workerbee_status=agent_status,
        elapsed=elapsed,
        return_file_content=return_file.as_posix() if return_file is not None else None,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Codex Spark local CLI bridge worker.")
    parser.add_argument("--bead-id", required=True)
    parser.add_argument("--dispatch-id", default=None)
    parser.add_argument("--mode", choices=["read-only", "implementation-capable"], required=True)
    parser.add_argument("--lane", action="append", default=[], required=True)
    parser.add_argument("--workdir", default=".")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--file", help="Read prompt from this file instead of stdin.")
    parser.add_argument("--output", help="Write a bridge artifact JSON file.")
    parser.add_argument("--return-file", help="Write the final agent message to this file.")
    parser.add_argument("--audit-file", default=str(os.environ.get("CWO_AUDIT_FILE", "")) or None)
    parser.add_argument(
        "--native-check-evidence",
        default=os.environ.get("CWO_SPARK_NATIVE_CHECK_EVIDENCE", ""),
        help="Machine-readable JSON evidence that native dispatch was unavailable or rejected.",
    )
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--timeout-seconds", type=int, default=SPARK_TIMEOUT_SECONDS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lanes = _nonempty_list(args.lane)
    if not lanes:
        raise SystemExit("--lane must include at least one canonical lane")
    prompt = _read_prompt(args.file)
    if not prompt.strip():
        raise SystemExit("prompt text is required on stdin or in --file")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be greater than 0")
    workdir = Path(args.workdir).expanduser().resolve()
    if not workdir.is_dir():
        raise SystemExit(f"workdir must be an existing directory: {workdir}")
    output = Path(args.output) if args.output else None
    return_file = Path(args.return_file) if args.return_file else None
    audit_file = Path(args.audit_file) if args.audit_file else None
    native_check = _read_native_check_evidence(args.native_check_evidence)
    if native_check["requested_model"] != SPARK_MODEL:
        raise SystemExit(f"requested model mismatch: {native_check['requested_model']} != {SPARK_MODEL}")
    native_fallback_route = NATIVE_FALLBACK_ROUTES[str(native_check["outcome"])]
    dispatch_id = args.dispatch_id or make_dispatch_id(args.bead_id)
    return run_bridge(
        bead_id=args.bead_id,
        dispatch_id=dispatch_id,
        mode=args.mode,
        lanes=lanes,
        workdir=workdir,
        sandbox=args.sandbox,
        prompt=prompt,
        output=output,
        return_file=return_file,
        audit_file=audit_file or AUDIT_LOG,
        codex_binary=args.codex_binary,
        timeout_seconds=args.timeout_seconds,
        requested_model=SPARK_MODEL,
        native_check_outcome=str(native_check["outcome"]),
        native_check_evidence_text=str(native_check["evidence_text"]),
        native_check_evidence_hash=str(native_check["evidence_hash"]),
        native_fallback_route=native_fallback_route,
    )


if __name__ == "__main__":
    raise SystemExit(main())
