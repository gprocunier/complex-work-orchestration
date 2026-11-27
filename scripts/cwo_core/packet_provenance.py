"""Contractor build provenance and current outbound approval checks.

A packet's content checks (``packets.validate_contractor_packet``: hash, boundary, executor,
nonproduction label and the rest) say what the packet is, not where it came from. Anyone can
edit a packet, for example remove the ``result_class: nonproduction-rehearsal`` label of a
rehearsal packet, and recompute ``packet_sha256``; the edited packet then passes every content
check. A content hash is not provenance.

Production provenance is the ``packet_built`` audit event that ``build_contractor_packet.py``
appends when it builds a packet (``record_audit_event.py`` refuses to write that event type).
A packet is production input only if it passes the content checks without the nonproduction
allowance and a ``packet_built`` event records its dispatch_id, Bead and packet_sha256. An edited
packet has a new hash that no build recorded, and a ``--no-audit`` rehearsal records nothing.

Consumers: ``dispatch_work.py --packet``, ``generate_manual_dispatch_prompt.py --packet``,
``chatgpt_browser_review.py --packet``, ``normalize_contractor_return.py --contractor-packet`` and
``evaluate_return.py --contractor-packet``. A managed export also resolves the current
host approval through the audit event's reference. The dispatch and browser dry-run
waivers for an unlinked packet apply only to local rehearsal or dry-run output.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import matching_audit_events
from .outbound_approval import require_outbound_approval
from .packets import NONPRODUCTION_RESULT_CLASS, require_valid_contractor_packet

PACKET_BUILT_EVENT = "packet_built"


def _identity(packet: dict[str, Any]) -> tuple[str, str | None, str]:
    dispatch_id = packet.get("dispatch_id")
    bead_id = packet.get("bead_id")
    packet_sha256 = packet.get("packet_sha256")
    if not isinstance(dispatch_id, str) or not dispatch_id or not isinstance(packet_sha256, str) or not packet_sha256:
        raise SystemExit("contractor packet has no production provenance: it names no dispatch_id or packet_sha256")
    return dispatch_id, bead_id if isinstance(bead_id, str) and bead_id else None, packet_sha256


def production_packet_provenance(packet: dict[str, Any], *, audit_file: Path | None = None) -> dict[str, Any]:
    """The ``packet_built`` event that vouches for ``packet``; refuse when there is none."""
    dispatch_id, bead_id, packet_sha256 = _identity(packet)
    matches = matching_audit_events(
        event_type=PACKET_BUILT_EVENT,
        dispatch_id=dispatch_id,
        bead_id=bead_id,
        packet_sha256=packet_sha256,
        audit_file=audit_file,
    )
    if not matches:
        raise SystemExit(
            "contractor packet has no production provenance: no packet_built audit event records "
            f"dispatch_id={dispatch_id} bead_id={bead_id} packet_sha256={packet_sha256}; "
            "a recomputed packet_sha256 is not provenance, so build the packet with build_contractor_packet.py "
            "without --rehearsal"
        )
    return matches[-1]


def require_production_contractor_packet(
    packet: dict[str, Any],
    *,
    allow_degraded_packet: bool = False,
    allow_unlinked_packet: bool = False,
    audit_file: Path | None = None,
) -> dict[str, Any] | None:
    """Refuse ``packet`` unless it is valid production input; return its ``packet_built`` event.

    ``allow_unlinked_packet`` is only for the existing operator-only waiver of dispatch and browser
    review, whose callers require ``--waiver-reason`` before calling; it skips the provenance
    lookup (and returns ``None``) but never the content checks or the nonproduction label.
    """
    require_valid_contractor_packet(packet, allow_degraded_packet=allow_degraded_packet)
    if allow_unlinked_packet:
        return None
    return production_packet_provenance(packet, audit_file=audit_file)


def require_packet_export_approval(packet: dict[str, Any], *, allow_degraded_packet: bool = False,
                                   allow_unlinked_packet: bool = False, rehearsal: bool = False,
                                   audit_file: Path | None = None) -> None:
    """Recheck scope and current opt-in before publishing a managed contractor export."""
    if allow_unlinked_packet and not rehearsal:
        raise SystemExit("--allow-unlinked-packet is available only for a local rehearsal")
    event = require_production_contractor_packet(
        packet, allow_degraded_packet=allow_degraded_packet, allow_unlinked_packet=allow_unlinked_packet,
        audit_file=audit_file,
    )
    if rehearsal:
        return
    if packet.get("opt_in_basis") != "host-approval" or packet["bead_summary"].get("id") != packet.get("bead_id"):
        raise SystemExit("contractor packet export requires a build with protected outbound approval")
    require_outbound_approval((event or {}).get("operator_approval_ref"), packet)


def label_rehearsal(prompt: str, rehearsal: bool) -> str:
    return "Local rehearsal only.\n\n" + prompt if rehearsal else prompt


def rehearsal_result(rehearsal: bool) -> dict[str, str]:
    return {"result_class": NONPRODUCTION_RESULT_CLASS} if rehearsal else {}
