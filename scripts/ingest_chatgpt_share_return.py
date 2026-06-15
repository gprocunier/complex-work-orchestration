#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from orchestration_lib import artifact_hash

CHATGPT_HOSTS = {"chatgpt.com", "www.chatgpt.com", "chat.openai.com"}
DEFAULT_EXECUTOR = "chatgpt_pro_5_5_extended_reasoning_browser"


def is_chatgpt_share_source(source: str) -> bool:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        return (parsed.hostname or "").lower() in CHATGPT_HOSTS and (
            parsed.path.startswith("/s/") or parsed.path.startswith("/share/")
        )
    return Path(source).is_file()


def locate_reader(explicit: str | None = None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    if os.environ.get("CHATGPT_SHARE_READER"):
        candidates.append(Path(os.environ["CHATGPT_SHARE_READER"]).expanduser())
    if os.environ.get("CODEX_SKILLS_DIR"):
        candidates.append(Path(os.environ["CODEX_SKILLS_DIR"]) / "chatgpt-share-local-reader" / "scripts" / "read_chatgpt_share.py")
    if os.environ.get("CODEX_HOME"):
        candidates.append(Path(os.environ["CODEX_HOME"]) / "skills" / "chatgpt-share-local-reader" / "scripts" / "read_chatgpt_share.py")
    candidates.append(Path.home() / ".codex" / "skills" / "chatgpt-share-local-reader" / "scripts" / "read_chatgpt_share.py")
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved
    raise SystemExit("Could not locate chatgpt-share-local-reader script")


def run_reader(reader: Path, source: str, timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [sys.executable, str(reader), source, "--timeout", str(timeout), "--format", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"ChatGPT share extraction timed out after {timeout}s") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or f"reader exited {result.returncode}"
        raise SystemExit(f"ChatGPT share extraction failed: {message}")
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ChatGPT share reader returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("ChatGPT share reader returned a non-object JSON payload")
    return parsed


def extract_assistant_text(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise SystemExit("ChatGPT share reader returned no messages")
    assistant_messages = [
        item for item in messages if isinstance(item, dict) and str(item.get("role", "")).lower() == "assistant"
    ]
    selected = assistant_messages[-1] if assistant_messages else messages[-1]
    text = selected.get("text") if isinstance(selected, dict) else None
    if not isinstance(text, str) or not text.strip():
        raise SystemExit("ChatGPT share reader did not expose assistant text")
    return text.strip(), {
        "message_id": selected.get("id") if isinstance(selected, dict) else None,
        "role": selected.get("role") if isinstance(selected, dict) else None,
        "content_type": selected.get("content_type") if isinstance(selected, dict) else None,
        "message_count": len(messages),
        "method": (payload.get("meta") or {}).get("method") if isinstance(payload.get("meta"), dict) else None,
        "title": payload.get("title"),
        "source": payload.get("source"),
    }


def render_contractor_return(
    assistant_text: str,
    *,
    source: str,
    reader: Path,
    provenance: dict[str, Any],
    bead_id: str | None,
    dispatch_id: str | None,
    share_boundary: str,
    job_description: str,
    packet_sha256: str | None,
    executor: str,
) -> str:
    reader_note = f"{reader} direct-to-ChatGPT/local parser"
    packet_line = packet_sha256 or "not provided"
    bead_line = bead_id or "not provided"
    dispatch_line = dispatch_id or "not provided"
    source_line = source if source.startswith("http") else str(Path(source).resolve())
    return f"""Status: completed
Contractor job description: {job_description}
Summary: ChatGPT share return ingested for architect review. The text below is evidence, not implementation authority.
Files changed: None.
Commands run: {reader_note}.
Boundary violation: No boundary violation observed during local share extraction.
Patch authorization: No patch or direct workspace mutation was authorized.
Secret or personal-data spill: Not observed by the ingest helper; architect must still review the extracted text before reuse.
Scope compliance: Ingested one ChatGPT share response for bead {bead_line} and dispatch {dispatch_line}.
Validation result: Share page parsed with the local ChatGPT share reader. Source: {source_line}.
Provider policy limitations: External OpenAI browser output requires evaluator scoring, peer review when policy requires it, and architect adjudication.
Evidence:
```text
{assistant_text}
```
Evidence provenance: reader={reader}; method={provenance.get('method')}; message_id={provenance.get('message_id')}; messages={provenance.get('message_count')}; packet_sha256={packet_line}
Attestation or reproducibility note: reader_output_sha256={artifact_hash(json.dumps(provenance, sort_keys=True) + assistant_text)}
Share-boundary conformance: Expected boundary was {share_boundary}; the ingest helper read only the provided ChatGPT share URL or local HTML file.
Peer-review disposition: Pending until route policy and provider-conflict requirements are checked.
Alternatives considered: None by the ingest helper; evaluate alternatives in architect adjudication.
Confidence: Medium. Extraction succeeded, but public shares may omit hidden context or some prompts.
Risks or gaps: ChatGPT share format can drift; public shares may omit user prompts; browser output can contain unsupported advice.
Recommended next bead: Evaluate this return, record accepted findings, and revise the execution plan only after architect adjudication.
Escalation needed: No by default. Escalate if the extracted text requests broader disclosure, exposes credentials, bypasses review, or conflicts with policy.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a ChatGPT share link into the contractor return flow.")
    parser.add_argument("source", help="ChatGPT share URL or locally saved share HTML.")
    parser.add_argument("--reader", help="Path to chatgpt-share-local-reader script.")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--bead")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--share-boundary", default="redacted-packet")
    parser.add_argument("--job-description", default="contract-jd-master-plan-review")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--executor", default=DEFAULT_EXECUTOR)
    parser.add_argument("--output", help="Write contractor return Markdown.")
    parser.add_argument("--json", action="store_true", help="Print metadata JSON instead of return Markdown.")
    args = parser.parse_args()

    if not is_chatgpt_share_source(args.source):
        raise SystemExit("source must be a ChatGPT share URL or a local HTML file")
    reader = locate_reader(args.reader)
    payload = run_reader(reader, args.source, args.timeout)
    assistant_text, provenance = extract_assistant_text(payload)
    rendered = render_contractor_return(
        assistant_text,
        source=args.source,
        reader=reader,
        provenance=provenance,
        bead_id=args.bead,
        dispatch_id=args.dispatch_id,
        share_boundary=args.share_boundary,
        job_description=args.job_description,
        packet_sha256=args.packet_sha256,
        executor=args.executor,
    )
    metadata = {
        "ingest_result_type": "chatgpt-share-contractor-return",
        "version": 1,
        "executor": args.executor,
        "bead_id": args.bead,
        "dispatch_id": args.dispatch_id,
        "share_boundary": args.share_boundary,
        "job_description_label": args.job_description,
        "reader": str(reader),
        "source": args.source,
        "assistant_text_sha256": artifact_hash(assistant_text),
        "return_sha256": artifact_hash(rendered),
        "provenance": provenance,
    }
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    if args.json:
        print(json.dumps(metadata, indent=2, sort_keys=True))
    elif not args.output:
        print(rendered)


if __name__ == "__main__":
    main()
