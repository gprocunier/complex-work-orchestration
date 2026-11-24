"""Prepare the exact screened ChatGPT browser request from a contractor packet."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import secrets
from typing import Any

from cwo_core.browser_provenance import normalize_browser_request
from cwo_core.outbound_screen import require_clean
from cwo_core.packet_provenance import require_production_contractor_packet
from cwo_core.packets import contractor_packet_language_metadata
from cwo_core.prepared_outbound import PreparedOutbound, PreparedSource
from cwo_core.util import artifact_hash
from generate_manual_dispatch_prompt import load_packet_file, render_packet_prompt


EXECUTOR_KEY = "chatgpt_pro_browser_master_reviewer"
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def bound_request(prompt: str, request_id: str) -> str:
    """Append the request ID that ties the observed user turn to this submission."""
    if not REQUEST_ID_RE.match(request_id):
        raise ValueError("request id must be 32 lowercase hexadecimal characters")
    return f"{prompt.rstrip()}\n\nCWO request id: {request_id}"


def load_browser_packet_prompt(
    path: str,
    options: dict[str, Any],
    *,
    allow_degraded_packet: bool = False,
    allow_unlinked_packet: bool = False,
    audit_file: Path | None = None,
) -> tuple[str, dict[str, Any], PreparedSource, dict[str, Any]]:
    """Load and render a linked packet. The legacy CLI supplies any operator waivers."""
    files: list = []
    packet = load_packet_file(path, captures=files)
    source = {"packet": packet, "options": options}
    capture = PreparedSource.capture(source, files)
    require_production_contractor_packet(
        packet, allow_degraded_packet=allow_degraded_packet, allow_unlinked_packet=allow_unlinked_packet,
        audit_file=audit_file,
    )
    expected_language, expected_language_source = contractor_packet_language_metadata(packet)
    if packet.get("executor") != EXECUTOR_KEY:
        raise SystemExit(f"packet executor must be {EXECUTOR_KEY}")
    profile = packet.get("expert_profile") if isinstance(packet.get("expert_profile"), dict) else {}
    captured = capture.value()
    prompt = render_packet_prompt(captured["packet"])
    capture.require_unchanged(captured)
    capture.require_unchanged(source)
    metadata = {
        "dispatch_id": packet.get("dispatch_id"),
        "bead_id": packet.get("bead_id"),
        "epic_id": packet.get("epic_id"),
        "packet_sha256": packet.get("packet_sha256"),
        "subject": packet.get("subject"),
        "packet_source_sha256": capture.sha256,
        "executor": packet.get("executor"),
        "provider_key": packet.get("provider_key"),
        "provider_family": packet.get("provider_family"),
        "provider_retention_class": packet.get("provider_retention_class"),
        "job_description_label": packet.get("job_description_label"),
        "expert_profile": profile.get("path"),
        "share_boundary": packet.get("share_boundary"),
        "expected_return_language": expected_language,
        "expected_return_language_source": expected_language_source,
    }
    return prompt, metadata, capture, source


def prepare_browser_submission(submitted: str, *, capture: PreparedSource, source: dict[str, Any]) -> PreparedOutbound:
    """Screen the actual Send text and bind it to the original renderer inputs."""
    screened = require_clean(submitted, surface="ChatGPT browser Send")
    return capture.bind(source, screened)


@dataclass(frozen=True)
class PreparedBrowserPacketRequest:
    request_id: str
    packet_source: PreparedSource
    outbound: PreparedOutbound

    @property
    def prompt(self) -> str:
        return self.outbound.source.value()["prompt"]

    @property
    def metadata(self) -> dict[str, Any]:
        return self.outbound.source.value()["metadata"]

    def require_unchanged(self) -> bytes:
        """Recheck the packet file and return the exact screened Send bytes."""
        return self.outbound.require_unchanged(self.outbound.source.value(), self.outbound.payload.data)

    def record_dispatch(self) -> str:
        """Record the exact prepared Send in the trusted host store before submission."""
        from cwo_core.host_records import configured_store

        require_production_contractor_packet(self.packet_source.value()["packet"])
        metadata = self.metadata
        submitted = self.require_unchanged().decode("utf-8")
        return configured_store().write_dispatch(
            dispatch_id=metadata["dispatch_id"], dispatch_role="executor", provider=metadata["provider_family"],
            model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            packet_sha256=metadata["packet_sha256"], request_sha256=self.outbound.payload.sha256,
            bead_id=metadata["bead_id"], executor=metadata["executor"], provider_key=metadata["provider_key"],
            evaluation_metadata={
                "dispatch_mode": "browser_automation",
                "peer_review_required": True,
                "share_boundary": metadata["share_boundary"],
                "job_description_label": metadata["job_description_label"],
                "expected_return_language": metadata["expected_return_language"],
                "expected_return_language_source": metadata["expected_return_language_source"],
                "packet_source_sha256": self.packet_source.sha256,
                "request_id": self.request_id,
                "outbound_prepared_sha256": self.outbound.sha256,
                "submitted_user_sha256": artifact_hash(normalize_browser_request(submitted)),
            },
        )


def prepare_browser_packet_request(
    packet_path: str | Path, *, audit_file: Path | None = None,
) -> PreparedBrowserPacketRequest:
    """Prepare a production packet with a fresh ID for a trusted browser parent."""
    path = str(packet_path)
    prompt, metadata, packet_source, _ = load_browser_packet_prompt(path, {"packet": path}, audit_file=audit_file)
    source = {"prompt": prompt, "inputs": [packet_source.sha256], "metadata": metadata}
    capture = PreparedSource.capture(source, packet_source.files)
    request_id = secrets.token_hex(16)
    outbound = prepare_browser_submission(bound_request(prompt, request_id), capture=capture, source=source)
    return PreparedBrowserPacketRequest(request_id, packet_source, outbound)
