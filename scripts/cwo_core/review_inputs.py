"""Bind a managed review's declared inputs to evidence on its actual surface."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .beads import show_bead_json
from .policy import load_policy

INPUT_ROW = re.compile(r"(?mi)^Review input \[([^\]\r\n]+)\]:[ \t]*([^\r\n]*)\r?$")
REVIEW_MARKER = re.compile(r"(?m)^Review input contract: (contract-jd-[a-z0-9-]+)\r?$")
LOCATOR = re.compile(r"(?:\w+://\S+|(?:\.{0,2}/\S+|\S+\.[a-z0-9]{1,8}(?:[#:]\S+)?))", re.I)
SPACED_LOCATOR = re.compile(r"(?:\.{1,2}/)?[\w/ -]+\.[a-z0-9]{1,8}(?:[#:][\w-]+)?", re.I)
PLACEHOLDERS = {
    "", "-", "unknown", "missing", "not supplied", "not provided", "not available", "no evidence", "tbd", "n/a",
    "none", "unavailable", "pending", "not applicable", "to be determined", "to be supplied",
}


def _locator_only(text: str) -> bool:
    directed = re.sub(r"(?i)^(?:see(?: also)?|refer to|consult|read|open|check|look at)\s+", "", text)
    reference = re.sub(
        r"(?i)\s+(?:for (?:more )?(?:details|information|context|evidence|reference)|as needed)$", "", directed,
    )
    locator = reference.strip("`\"'")
    locator = re.sub(r"^\[[^\]]+\]\((\S+)\)$", r"\1", locator)
    return bool(
        locator.casefold() in {"attached", "the attachment", "attachment"}
        or LOCATOR.fullmatch(locator)
        or ((directed != text or locator != reference) and SPACED_LOCATOR.fullmatch(locator))
    )


def concrete_evidence(value: str) -> bool:
    text = value.rstrip(" .!?;:")
    return text.casefold() not in PLACEHOLDERS and "[redacted" not in value.casefold() and not _locator_only(text)


def review_evidence(*texts: object) -> dict[str, str]:
    values: dict[str, set[str]] = {}
    for text in texts:
        for name, raw in INPUT_ROW.findall(str(text or "")):
            value = raw.strip()
            if not concrete_evidence(value):
                continue
            values.setdefault(name.strip().casefold(), set()).add(value)
    return {name: next(iter(items)) for name, items in values.items() if len(items) == 1}


def missing_review_inputs(required: list[str], *texts: object) -> list[str]:
    evidence = review_evidence(*texts)
    return [name for name in required if name.casefold() not in evidence]


def require_review_inputs(required: list[str], *texts: object) -> dict[str, str]:
    evidence = review_evidence(*texts)
    missing = [name for name in required if name.casefold() not in evidence]
    if missing:
        raise SystemExit("review input handoff blocked; missing evidence: " + ", ".join(missing))
    return {name: evidence[name.casefold()] for name in required}


def review_description(
    expert: dict[str, Any], acceptance: object, context: str, metadata: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    required = expert.get("required_inputs", [])
    description = f"Perform {expert['display_name']} review during {expert.get('review_stage', 'pre-implementation')}."
    handling = ("Codex may brief and evaluate this Bead only." if metadata.get("codex_pickup") == "forbidden"
                else "Codex may execute this internal expert review.")
    description += f"\n\nShare boundary: {metadata.get('share_boundary')}\n{handling}"
    output = "\n".join(f"- {item}" for item in expert.get("output_contract", []))
    escalation = "\n".join(f"- {item}" for item in expert.get("escalation_rules", []))
    description += f"\n\nOutput contract:\n{output}\n\n{acceptance}\n\nEscalation rules:\n{escalation}"
    if not required:
        return description, {}
    external = bool(metadata["selected_executor"].get("external"))
    evidence = review_evidence(context) if not external else {}
    missing = [name for name in required if name.casefold() not in evidence]
    rows = "\n".join(f"Review input [{name}]: {evidence.get(name.casefold(), 'not supplied')}" for name in required)
    profile = f"\nExpert profile: {expert.get('persona_file')}" if not external else ""
    description += f"\n\nReview input contract: {expert['job_description_label']}{profile}\n{rows}"
    return description, {"review_input_status": "blocked" if missing else "ready", "missing_review_inputs": missing}


def _one_issue(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, dict):
        issue = value.get("issue", value)
        return issue if isinstance(issue, dict) else {}
    return {}


def _assignment_identity(issue: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    metadata = issue.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    expert = metadata.get("expert") or metadata.get("cwo_metadata_expert") or ""
    labels = issue.get("labels") or issue.get("label_names") or []
    jobs = (
        metadata.get("job_description_label"), metadata.get("cwo_metadata_job_description_label"),
        *(label for label in labels if str(label).startswith("contract-jd-")),
    )
    return str(expert), tuple(label for label in jobs if isinstance(label, str) and label)


def registered_review_profile(job_label: object) -> dict[str, Any]:
    profiles = load_policy("expert-registry").get("experts", {})
    return next((profile for profile in profiles.values() if profile.get("job_description_label") == job_label), {})


def managed_review_profile(bead: Any = None, *, text: str = "", job_label: str = "") -> dict[str, Any]:
    issue = _one_issue(bead)
    expert, assigned_labels = _assignment_identity(issue)
    markers = REVIEW_MARKER.findall(text + "\n" + str(issue.get("description", "")))
    if not markers and not (expert and assigned_labels):
        return {}
    labels = {label for label in (job_label, *assigned_labels, *markers) if label}
    if len(labels) != 1:
        raise SystemExit("review input handoff blocked; review identity does not match the assigned job")
    profile = registered_review_profile(labels.pop())
    if not profile:
        raise SystemExit("review input handoff blocked; the assigned review profile is unknown")
    return profile


def discover_review_issue(bead_id: str | None, *, directory: Path | None = None) -> dict[str, Any]:
    """Read an exact local assignment when Beads is configured in this workspace."""
    cwd = directory or Path.cwd()
    if not bead_id or not (os.environ.get("BEADS_DIR") or any((path / ".beads").is_dir() for path in (cwd, *cwd.parents))):
        return {}
    try:
        issue = _one_issue(show_bead_json(bead_id, directory=cwd))
    except SystemExit as exc:
        message = str(exc).casefold()
        if ("no issue" in message or "no beads database found" in message
                or ("issue" in message and "not found" in message)):
            return {}
        raise
    return issue if issue.get("id") == bead_id else {}


def remove_assignment_profile_reference(summary: dict[str, Any]) -> None:
    for field in ("description", "acceptance_criteria"):
        if isinstance(value := summary.get(field), str):
            summary[field] = re.sub(r"(?m)^Expert profile: experts/[^\r\n]+\n?", "", value)


def packet_review_evidence(summary: object, snippets: object) -> list[object]:
    delivered = [summary.get("description"), summary.get("acceptance_criteria")] if isinstance(summary, dict) else []
    if isinstance(snippets, list):
        delivered.extend(item.get("content") for item in snippets if isinstance(item, dict) and not item.get("truncated"))
    return delivered


def review_persona_matches(included: object, assigned: dict[str, Any]) -> bool:
    return isinstance(included, dict) and included.get("path") == assigned.get("persona_file")


def packet_review_input_errors(packet: dict[str, Any]) -> list[str]:
    contract = packet.get("review_surface_contract")
    summary = packet.get("bead_summary")
    description = str(summary.get("description", "")) if isinstance(summary, dict) else ""
    markers = REVIEW_MARKER.findall(description)
    if not isinstance(contract, dict) or "required_inputs" not in contract:
        return ["managed packet is missing its required review input contract"] if markers else []
    names = contract["required_inputs"]
    job_label = packet.get("job_description_label")
    expert = registered_review_profile(job_label)
    if not names or names != expert.get("required_inputs") or any(marker != job_label for marker in markers):
        return ["packet required review inputs do not match the assigned job"]
    included = packet.get("expert_profile")
    include_flag = packet.get("expert_profile_included") is True
    if include_flag != bool(included) or (include_flag and not review_persona_matches(included, expert)):
        return ["packet included expert profile does not match the assigned job"]
    if missing_review_inputs(names, *packet_review_evidence(summary, packet.get("selected_snippets"))):
        return ["packet review input handoff blocked; required evidence is missing"]
    return []
