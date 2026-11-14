"""Offline private intake fixtures; actual preparation, capture checks and audit persistence."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import build_contractor_packet
from cwo_core import audit
from cwo_core.browser_provenance import build_private_provenance, capture_audit_fields
from cwo_core.outbound_screen import require_clean
from cwo_core.prepared_outbound import PreparedSource
from cwo_core.private_artifact import sha256_bytes, write_private_artifact
from cwo_core.util import artifact_hash

ROOT = Path(__file__).resolve().parents[1]


def production_packet(**candidate) -> dict:
    bead = json.loads((ROOT / "examples/sample-bead.json").read_text())
    bead["labels"] = ["contract-jd-master-plan-review", "contractor-only", "no-codex-exec"]
    return build_contractor_packet.build_packet(
        bead_id=candidate.get("candidate_record", {}).get("bead_id", "cwo-1"), bead_json=bead,
        executor="chatgpt_pro_browser_master_reviewer", share_boundary="redacted-packet",
        job_description_label="contract-jd-master-plan-review", allowed_files=[],
        inline_snippets=["Review the retry design."], external_opt_in=True, opt_in_basis="cli-flag",
        quota_info={"quota_checked": True, "quota_remaining": 4}, dispatch_id="dispatch-1", **candidate,
    )


def capture_record(packet: dict, text: str) -> tuple[dict, str]:
    from chatgpt_browser_review import PlaywrightChatGPTRunner, render_packet_prompt
    prompt = render_packet_prompt(packet)
    request_id = "1" * 32
    submitted = prompt + "\nRequest ID: " + request_id
    load_source = PreparedSource.capture({"packet": packet, "options": {"offline": True}})
    source = PreparedSource.capture({"prompt": prompt, "inputs": [load_source.sha256]})
    prepared = source.bind(source.value(), require_clean(submitted, surface="ChatGPT browser Send"))
    url = "https://chatgpt.com/c/conv-0001"
    snapshot = {"url": url, "stamp": request_id, "stopping": False, "messages": [
        {"role": "user", "id": "msg-0", "text": submitted, "marked": False},
        {"role": "assistant", "id": "msg-1", "text": text, "marked": True},
    ]}
    page = SimpleNamespace(url=url, evaluate=lambda *args: copy.deepcopy(snapshot))
    runner = PlaywrightChatGPTRunner({"selectors": {}})
    capture = runner._capture_assistant_response(
        page, "", text, before_messages={"available": True, "messages": []}, prompt=submitted,
        request_id=request_id, before_url=url, pinned_conversation_id="conv-0001",
    )
    browser = {**capture, "response_text": capture["text"], "capture_checks": capture["checks"],
               "capture_incomplete_reasons": capture["incomplete_reasons"], "request_id": request_id,
               "response_extraction": capture["extraction"], "assistant_message_id": capture["message_id"],
               "submitted_sha256": artifact_hash(submitted), **prepared.metadata(), "send_admission_sha256": "d" * 64}
    record = build_private_provenance({**packet, "packet_source_sha256": load_source.sha256}, prompt, browser,
                                      response_file="run.response.txt", captured_at="2026-11-14T00:00:00Z")
    return record, load_source.sha256


def publish_return(directory: Path, text: str, **overrides) -> tuple[Path, list[str]]:
    packet = production_packet()
    identity = {key: packet[key] for key in ("dispatch_id", "bead_id", "packet_sha256")}
    audit.record_audit_event({"event_type": "packet_built", **identity})
    record, source_sha256 = capture_record(packet, text if text.strip() else "placeholder for empty capture refusal")
    record.update(response_sha256=sha256_bytes(text.encode()), response_bytes=len(text.encode()), response_chars=len(text))
    response_name = overrides.pop("response_name", "run.response.txt")
    record["response_file"] = response_name
    record.update(overrides)
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    write_private_artifact(directory, response_name, text.encode())
    path = write_private_artifact(directory, "run.provenance.json", raw)
    packet_path = directory.parent / (directory.name + ".packet.json")
    packet_path.write_text(json.dumps(packet))
    event = audit.record_audit_event({"event_type": "chatgpt_browser_dispatch", **identity,
                                     **capture_audit_fields(record, sha256_bytes(raw))})
    return path, ["--packet", str(packet_path), "--packet-source-sha256", source_sha256,
                  "--capture-event", event["event_hash"]]
