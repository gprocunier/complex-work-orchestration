#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cwo_core.chatgpt_urls import approved_chatgpt_origin, valid_chatgpt_share_url
from cwo_core.paths import assert_safe_output_path
from cwo_core.packets import fenced_block
from cwo_core.private_artifact import PrivateArtifactError, PrivateDirectory, artifact_path, sha256_bytes
from cwo_core.util import atomic_write_text, artifact_hash

DEFAULT_EXECUTOR = "chatgpt_pro_browser_master_reviewer"
PRIVATE_RESPONSE_ARTIFACT_TYPE = "chatgpt-browser-private-response"
MAX_PROVENANCE_BYTES = 1024 * 1024


def is_chatgpt_share_source(source: str) -> bool:
    if source.startswith(("http://", "https://")):
        return valid_chatgpt_share_url(source)
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


# SHA-256 digests of reviewed share-reader scripts that may run. A reader is
# trusted by these pinned bytes in CWO's own code, never by a path or hash the
# caller supplies. None is pinned yet, so legacy share ingestion is unavailable
# until a reviewed reader is added here.
TRUSTED_READER_SHA256: frozenset[str] = frozenset()
READER_UNPINNED_REASON = "share-reader-not-pinned"


MAX_READER_BYTES = 4 * 1024 * 1024


def require_trusted_reader(reader: Path, pins: frozenset[str] = TRUSTED_READER_SHA256) -> bytes:
    """Return the reader's bytes if they match a pin; read once, so what runs is what was checked.

    With no pins nothing is read at all. Otherwise the file is opened without
    following a final symlink and without blocking, must be a regular file,
    and is read up to a fixed size.
    """
    if not pins:
        raise SystemExit(f"{READER_UNPINNED_REASON}: no reviewed reader is pinned in CWO; use --private-artifact for browser returns")
    try:
        descriptor = os.open(reader, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise SystemExit(f"{READER_UNPINNED_REASON}: cannot open {reader}: {exc.strerror or exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_READER_BYTES:
            raise SystemExit(f"{READER_UNPINNED_REASON}: {reader} is not a regular file within {MAX_READER_BYTES} bytes")
        data = os.read(descriptor, MAX_READER_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_READER_BYTES or sha256_bytes(data) not in pins:
        raise SystemExit(
            f"{READER_UNPINNED_REASON}: {reader} does not match a reviewed reader pinned in CWO; "
            "use --private-artifact for browser returns"
        )
    return data


def run_reader(reader: Path, source: str, timeout: int, *, pins: frozenset[str] = TRUSTED_READER_SHA256) -> dict[str, Any]:
    code = require_trusted_reader(reader, pins)
    try:
        result = subprocess.run(
            # Run the verified bytes themselves, not the path, which could be replaced.
            [sys.executable, "-I", "-c", code.decode("utf-8"), source, "--timeout", str(timeout), "--format", "json"],
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
    if assistant_messages:
        selected = assistant_messages[-1]
        selected_text = selected.get("text")
        if not isinstance(selected_text, str) or not selected_text.strip():
            text = None
        elif len(assistant_messages) == 1:
            text = selected_text.strip()
        else:
            selected_id = str(selected.get("id") or "n/a")
            primary = f"## Primary assistant message (id={selected_id})\n\n{selected_text.strip()}"
            archived: list[str] = []
            for index, item in enumerate(assistant_messages[:-1], 1):
                archived_text = item.get("text")
                if not isinstance(archived_text, str) or not archived_text.strip():
                    continue
                message_id = str(item.get("id") or "n/a")
                archived.append(
                    f"### Earlier assistant message {index} of {len(assistant_messages) - 1} "
                    f"(id={message_id}; archival, not primary review)\n\n{archived_text.strip()}"
                )
            archive = "\n\n---\n\n".join(archived)
            text = primary if not archive else primary + "\n\n---\n\n## Earlier Assistant Message Archive\n\n" + archive
    else:
        selected = messages[-1]
        text = selected.get("text") if isinstance(selected, dict) else None
    if not isinstance(text, str) or not text.strip():
        raise SystemExit("ChatGPT share reader did not expose assistant text")
    return text.strip(), {
        "message_id": selected.get("id") if isinstance(selected, dict) else None,
        "assistant_message_ids": [
            item.get("id")
            for item in assistant_messages
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("id")
        ],
        "assistant_message_count": len(assistant_messages),
        "role": selected.get("role") if isinstance(selected, dict) else None,
        "content_type": selected.get("content_type") if isinstance(selected, dict) else None,
        "message_count": len(messages),
        "method": (payload.get("meta") or {}).get("method") if isinstance(payload.get("meta"), dict) else None,
        "title": payload.get("title"),
        "source": payload.get("source"),
    }


HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CONVERSATION_PATH_RE = re.compile(r"/c/([A-Za-z0-9-]{8,})(?:/|$)")
PRIVATE_RESPONSE_VERSION = 4
CAPTURE_CHECKS = (
    "request_turn",
    "response_turn",
    "completion_confirmed",
    "content_stable",
    "conversation_stable",
    "assistant_extraction",
)


def _provenance_errors(provenance: dict[str, Any]) -> list[str]:
    """Required identity and capture fields of a current private response."""
    errors: list[str] = []

    def text(field: str) -> None:
        if not isinstance(provenance.get(field), str) or not provenance[field].strip():
            errors.append(f"{field} must be a non-empty string")

    def digest(field: str, *, prefixed: bool = False) -> None:
        value = provenance.get(field)
        if prefixed and isinstance(value, str) and value.startswith("sha256:"):
            value = value[len("sha256:"):]
        if not isinstance(value, str) or not HEX64.match(value):
            errors.append(f"{field} must be a SHA-256 digest")

    for field in ("dispatch_id", "conversation_id", "conversation_url", "captured_at", "response_file", "executor"):
        text(field)
    digest("packet_sha256")
    digest("response_sha256")
    digest("prompt_sha256", prefixed=True)
    digest("submitted_sha256", prefixed=True)
    if not isinstance(provenance.get("request_id"), str) or not REQUEST_ID_RE.match(provenance["request_id"]):
        errors.append("request_id must be 32 lowercase hexadecimal characters")
    if provenance.get("response_extraction") != "assistant-message":
        errors.append("response_extraction must be assistant-message")
    if not isinstance(provenance.get("assistant_message_id"), str) or not provenance["assistant_message_id"]:
        errors.append("assistant_message_id must be a non-empty string")
    if not isinstance(provenance.get("user_message_id"), str) or not provenance["user_message_id"]:
        errors.append("user_message_id must be a non-empty string")
    conversation_id, conversation_url = provenance.get("conversation_id"), provenance.get("conversation_url")
    if isinstance(conversation_id, str) and isinstance(conversation_url, str):
        match = CONVERSATION_PATH_RE.search(urlparse(conversation_url).path)
        if match is None or match.group(1) != conversation_id:
            errors.append("conversation_url does not name conversation_id")
        if approved_chatgpt_origin(conversation_url) is None:
            errors.append("conversation_url is not on a ChatGPT origin")
    chars = provenance.get("response_chars")
    if not isinstance(chars, int) or isinstance(chars, bool) or chars < 1:
        errors.append("response_chars must be a positive integer")
    checks = provenance.get("capture_checks")
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in CAPTURE_CHECKS):
        errors.append("capture_checks must all be true")
    return errors


def load_private_response(
    provenance_path: Path,
    *,
    packet_sha256: str | None,
    dispatch_id: str | None,
    bead_id: str | None,
) -> tuple[str, dict[str, Any], str]:
    """Verify a private browser response artifact and return (text, provenance, provenance_sha256).

    Both files are read through one pinned descriptor for the owner-only
    artifact directory and must be owner-only regular files without symlinks or
    extra hard links. The provenance must be a current-version record with
    every capture check passed and complete packet, dispatch, prompt, request,
    conversation and response identity; the response digest must match; and any
    caller-supplied packet, dispatch or bead identity must equal the recorded one.
    """
    try:
        absolute = artifact_path(provenance_path)
        directory = PrivateDirectory.open(absolute.parent)
    except PrivateArtifactError as exc:
        raise SystemExit(f"private response directory is unusable: {exc}") from exc
    with directory:
        try:
            provenance_bytes = directory.read(absolute.name, max_bytes=MAX_PROVENANCE_BYTES)
            provenance = json.loads(provenance_bytes.decode("utf-8"))
        except (PrivateArtifactError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SystemExit(f"private response provenance is unreadable: {exc}") from exc
        if not isinstance(provenance, dict) or provenance.get("artifact_type") != PRIVATE_RESPONSE_ARTIFACT_TYPE:
            raise SystemExit("private response provenance has an unexpected artifact type")
        if provenance.get("version") != PRIVATE_RESPONSE_VERSION:
            raise SystemExit("private response provenance has an unsupported version")
        if provenance.get("capture_complete") is not True:
            raise SystemExit("private response capture is incomplete; it cannot be ingested as a complete return")
        errors = _provenance_errors(provenance)
        if errors:
            raise SystemExit("private response provenance is incomplete: " + "; ".join(errors))
        response_file = provenance["response_file"]
        if "/" in response_file or response_file.startswith("."):
            raise SystemExit("private response provenance names an unsafe response file")
        expected = {"packet_sha256": packet_sha256, "dispatch_id": dispatch_id, "bead_id": bead_id}
        for field, value in expected.items():
            if value is not None and provenance.get(field) != value:
                raise SystemExit(f"private response {field} does not match the requested {field}")
        try:
            response_bytes = directory.read(response_file)
        except PrivateArtifactError as exc:
            raise SystemExit(f"private response file is unreadable: {exc}") from exc
    if sha256_bytes(response_bytes) != provenance["response_sha256"]:
        raise SystemExit("private response digest does not match its provenance")
    try:
        decoded = response_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("private response is not valid UTF-8") from exc
    if len(decoded) != provenance["response_chars"]:
        raise SystemExit("private response length does not match its provenance")
    if not decoded.strip():
        raise SystemExit("private response is empty")
    # Returned exactly as captured: surrounding whitespace can be meaningful.
    return decoded, provenance, sha256_bytes(provenance_bytes)


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
    source_kind: str = "share",
) -> str:
    if source_kind == "private-artifact":
        return render_private_contractor_return(
            assistant_text,
            source=source,
            provenance=provenance,
            bead_id=bead_id,
            dispatch_id=dispatch_id,
            share_boundary=share_boundary,
            job_description=job_description,
            packet_sha256=packet_sha256,
        )
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
{fenced_block(assistant_text, 'text')}
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


def render_private_contractor_return(
    assistant_text: str,
    *,
    source: str,
    provenance: dict[str, Any],
    bead_id: str | None,
    dispatch_id: str | None,
    share_boundary: str,
    job_description: str,
    packet_sha256: str | None,
) -> str:
    packet_line = packet_sha256 or provenance.get("packet_sha256") or "not provided"
    bead_line = bead_id or provenance.get("bead_id") or "not provided"
    dispatch_line = dispatch_id or provenance.get("dispatch_id") or "not provided"
    share_created = bool((provenance.get("share") or {}).get("created"))
    return f"""Status: completed
Contractor job description: {job_description}
Summary: Private ChatGPT browser response ingested for architect review. The text below is evidence, not implementation authority.
Files changed: None.
Commands run: Private browser response artifact read and its SHA-256 digest verified against the recorded provenance.
Boundary violation: No boundary violation observed while reading the private artifact.
Patch authorization: No patch or direct workspace mutation was authorized.
Secret or personal-data spill: Not observed by the ingest helper; architect must still review the extracted text before reuse.
Scope compliance: Ingested one private browser response for bead {bead_line} and dispatch {dispatch_line}.
Validation result: Response digest matched provenance {source}. Extraction method: {provenance.get('response_extraction')}.
Provider policy limitations: External OpenAI browser output requires evaluator scoring, peer review when policy requires it, and architect adjudication.
Evidence:
{fenced_block(assistant_text, 'text')}
Evidence provenance: source=private-artifact; conversation_id={provenance.get('conversation_id')}; message_id={provenance.get('assistant_message_id')}; extraction={provenance.get('response_extraction')}; packet_sha256={packet_line}
Attestation or reproducibility note: response_sha256={provenance.get('response_sha256')}; this digest identifies the stored bytes and does not authenticate the operator or provider.
Share-boundary conformance: Expected boundary was {share_boundary}; {"a public share link was also created" if share_created else "no public share link was created"}.
Peer-review disposition: Pending until route policy and provider-conflict requirements are checked.
Alternatives considered: None by the ingest helper; evaluate alternatives in architect adjudication.
Confidence: Medium. The stored bytes match their digest; browser extraction can still miss content if the page layout changed.
Risks or gaps: Same-user processes can read and replace private artifacts before ingestion; browser output can contain unsupported advice.
Recommended next bead: Evaluate this return, record accepted findings, and revise the execution plan only after architect adjudication.
Escalation needed: No by default. Escalate if the extracted text requests broader disclosure, exposes credentials, bypasses review, or conflicts with policy.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a ChatGPT browser review return into the contractor return flow.")
    parser.add_argument("source", nargs="?", help="Legacy: ChatGPT share URL or locally saved share HTML.")
    parser.add_argument(
        "--private-artifact",
        help="Provenance JSON of a private browser response written by chatgpt_browser_review.py.",
    )
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

    if bool(args.source) == bool(args.private_artifact):
        raise SystemExit("provide exactly one of: a legacy share source, or --private-artifact")
    if args.private_artifact:
        provenance_path = Path(args.private_artifact).expanduser()
        assistant_text, provenance, provenance_sha256 = load_private_response(
            provenance_path,
            packet_sha256=args.packet_sha256,
            dispatch_id=args.dispatch_id,
            bead_id=args.bead,
        )
        rendered = render_contractor_return(
            assistant_text,
            source=str(provenance_path),
            reader=provenance_path,
            provenance=provenance,
            bead_id=args.bead,
            dispatch_id=args.dispatch_id,
            share_boundary=args.share_boundary,
            job_description=args.job_description,
            packet_sha256=args.packet_sha256,
            executor=args.executor,
            source_kind="private-artifact",
        )
        metadata = {
            "ingest_result_type": "chatgpt-share-contractor-return",
            "version": 2,
            "source_kind": "private-artifact",
            "executor": args.executor,
            "bead_id": args.bead or provenance.get("bead_id"),
            "dispatch_id": args.dispatch_id or provenance.get("dispatch_id"),
            "share_boundary": args.share_boundary,
            "job_description_label": args.job_description,
            "source": str(provenance_path),
            "provenance_sha256": provenance_sha256,
            "response_sha256": provenance.get("response_sha256"),
            "conversation_id": provenance.get("conversation_id"),
            "assistant_text_sha256": artifact_hash(assistant_text),
            "return_sha256": artifact_hash(rendered),
        }
        if args.output:
            atomic_write_text(assert_safe_output_path(Path(args.output)), rendered)
        if args.json:
            print(json.dumps(metadata, indent=2, sort_keys=True))
        elif not args.output:
            print(rendered)
        return
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
        "version": 2,
        "source_kind": "share",
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
        atomic_write_text(assert_safe_output_path(Path(args.output)), rendered)
    if args.json:
        print(json.dumps(metadata, indent=2, sort_keys=True))
    elif not args.output:
        print(rendered)


if __name__ == "__main__":
    main()
