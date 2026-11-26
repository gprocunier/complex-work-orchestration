"""Offline private intake fixtures; actual preparation, capture checks and audit persistence."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import build_contractor_packet
from cwo_core import audit
from cwo_core.browser_provenance import capture_audit_fields
from cwo_core.private_artifact import sha256_bytes, write_private_artifact

ROOT = Path(__file__).resolve().parents[1]
SAVED_CAPTURE = ROOT / "tests/fixtures/browser-capture-v5"


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
    """Vary only the packet identity and response when a test needs new inputs."""
    record = json.loads((SAVED_CAPTURE / "provenance.json").read_bytes())
    record.update({key: packet[key] for key in (
        "dispatch_id", "bead_id", "packet_sha256", "executor", "provider_key", "share_boundary", "subject",
    )})
    record.update(response_sha256=sha256_bytes(text.encode()), response_bytes=len(text.encode()), response_chars=len(text))
    return record, record["packet_source_sha256"]


def saved_capture(directory: Path, store):
    """Stage the unchanged release capture and its independently preserved audit."""
    raw = (SAVED_CAPTURE / "provenance.json").read_bytes()
    record = json.loads(raw)
    response = base64.b64decode((SAVED_CAPTURE / "response.base64").read_bytes().strip(), validate=True)
    write_private_artifact(directory, record["response_file"], response)
    provenance = write_private_artifact(directory, "run.provenance.json", raw)
    packet = write_private_artifact(directory, "packet.json", (SAVED_CAPTURE / "packet.json").read_bytes())
    host_fixture = SAVED_CAPTURE / "host"
    for source in host_fixture.rglob("*"):
        if source.is_file():
            relative = source.relative_to(host_fixture)
            write_private_artifact(store.state_root / relative.parent, relative.name, source.read_bytes())
    write_private_artifact(store.state_root, "audit.jsonl.lock", b"")
    events = (json.loads(line) for line in store.audit_file.read_bytes().splitlines())
    event = next(event for event in events if event["event_type"] == "chatgpt_browser_dispatch")
    return provenance, response, packet, record["packet_source_sha256"], event


def publish_return(directory: Path, text: str, **overrides) -> tuple[Path, list[str]]:
    packet = production_packet()
    identity = {key: packet[key] for key in ("dispatch_id", "bead_id", "packet_sha256")}
    audit.record_audit_event({"event_type": "packet_built", **identity})
    record, source_sha256 = capture_record(packet, text)
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
