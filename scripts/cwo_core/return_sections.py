from __future__ import annotations

import re
from functools import lru_cache

from .policy import load_policy


RETURN_CONTROL_SECTIONS = [
    "Files changed",
    "Commands run",
    "Boundary violation",
    "Patch authorization",
    "Secret or personal-data spill",
    "Secret spill",
    "Personal-data spill",
    "Scope compliance",
    "Provider policy limitations",
    "Policy limitations",
    "Patch artifact",
    "Patch proposal",
    "Provider conflict disposition",
    "Direct workspace mutation",
    "Research evidence",
    "Research contradictions",
    "Research reflection",
    "Review surface",
    "Source inspection",
    "Sources inspected",
    "Sources not inspected",
    "Independent verification",
    "Packet-reported claims",
]


RETURN_SECTION_ALIASES = {
    "share boundary conformance": "Share-boundary conformance",
    "peer review disposition": "Peer-review disposition",
    "attestation repro note": "Attestation or reproducibility note",
    "attestation reproducibility note": "Attestation or reproducibility note",
    "attestation or reproduction note": "Attestation or reproducibility note",
    "risks gaps": "Risks or gaps",
    "risks and gaps": "Risks or gaps",
    "recommended next bead": "Recommended next bead",
    "recommended next action": "Recommended next bead",
    "secret spill": "Secret or personal-data spill",
    "personal data spill": "Secret or personal-data spill",
    "secret or personal data spill": "Secret or personal-data spill",
    "provider limitations": "Provider policy limitations",
    "policy limitations": "Provider policy limitations",
    "patch branch": "Patch proposal",
    "patch diff": "Patch proposal",
    "research evidence items": "Research evidence",
    "research sources": "Research evidence",
    "research contradictions": "Research contradictions",
    "contradictions": "Research contradictions",
    "research reflection": "Research reflection",
    "research replan": "Research reflection",
    "evidence surface": "Review surface",
    "review source surface": "Review surface",
    "source surface": "Review surface",
    "sources reviewed": "Sources inspected",
    "inspected sources": "Sources inspected",
    "sources not reviewed": "Sources not inspected",
    "uninspected sources": "Sources not inspected",
    "independently verified": "Independent verification",
    "independent verification status": "Independent verification",
    "packet reported claims": "Packet-reported claims",
    "packet only claims": "Packet-reported claims",
}


def section_lookup_key(label: str) -> str:
    cleaned = label.strip()
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned)
    cleaned = re.sub(r"^\s*[-*]\s+", "", cleaned)
    cleaned = re.sub(r"^(\*\*|__)(.*?)(\1)$", r"\2", cleaned)
    cleaned = cleaned.strip("`*_ :")
    cleaned = cleaned.replace("&", " and ")
    cleaned = re.sub(r"[^a-zA-Z0-9]+", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip().lower()


@lru_cache(maxsize=1)
def return_section_aliases() -> dict[str, str]:
    policy = load_policy("acceptance-policy")
    canonical: dict[str, str] = {}
    canonical_sections = list(policy.get("contractor_return_required_sections", [])) + list(RETURN_CONTROL_SECTIONS)
    for section in policy.get("contractor_return_required_sections", []):
        canonical[section_lookup_key(section)] = section
    for section in RETURN_CONTROL_SECTIONS:
        canonical[section_lookup_key(section)] = section
    alias_source = str(policy.get("return_section_alias_source", "")).strip().lower()
    if alias_source == "legacy":
        configured_aliases = RETURN_SECTION_ALIASES
    elif alias_source == "policy":
        configured_aliases = policy.get("return_section_aliases")
        if not isinstance(configured_aliases, dict):
            raise SystemExit("acceptance-policy.yaml return_section_alias_source=policy requires return_section_aliases")
    else:
        raise SystemExit("acceptance-policy.yaml must set return_section_alias_source to 'policy' or 'legacy'")
    valid_targets = {section_lookup_key(section) for section in canonical_sections}
    for alias, target in configured_aliases.items():
        if section_lookup_key(str(target)) not in valid_targets:
            raise SystemExit(f"acceptance-policy.yaml alias {alias!r} points at unknown return section {target!r}")
        canonical[section_lookup_key(alias)] = target
    return canonical


def canonical_return_section(label: str) -> str | None:
    return return_section_aliases().get(section_lookup_key(label))


def parse_return_header(line: str) -> tuple[str, str] | None:
    match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)(?:\s*:\s*(.*))?\s*$", line)
    if match:
        label = match.group(1).strip()
        value = (match.group(2) or "").strip()
        canonical = canonical_return_section(label)
        if canonical:
            return canonical, value

    match = re.match(r"^\s*(?:[-*]\s+)?(?:\*\*|__)([^*_]+?)(?::)?(?:\*\*|__)\s*:?\s*(.*)$", line)
    if match:
        label = match.group(1).strip()
        value = match.group(2).strip()
        canonical = canonical_return_section(label)
        if canonical:
            return canonical, value

    match = re.match(r"^\s*([A-Za-z][A-Za-z /-]+)\s*:\s*(.*)$", line)
    if match:
        canonical = canonical_return_section(match.group(1))
        if canonical:
            return canonical, match.group(2).strip()
    return None


def parse_return_sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current: str | None = None
    buffer: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            if current:
                buffer.append(line)
            in_fence = not in_fence
            continue
        if in_fence:
            if current:
                buffer.append(line)
            continue
        parsed = parse_return_header(line)
        if parsed:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current, value = parsed
            buffer = [value] if value else []
        elif current:
            buffer.append(line)
    if current:
        sections[current] = "\n".join(buffer).strip()
    return sections


class SectionReader:
    """Cached normalized lookup for parsed contractor-return sections."""

    def __init__(self, sections: dict[str, str]) -> None:
        self.sections = sections
        self.normalized = {section_lookup_key(key): value for key, value in sections.items()}

    def value(self, *names: str) -> str:
        for name in names:
            canonical = canonical_return_section(name) or name
            value = self.normalized.get(section_lookup_key(canonical))
            if value is not None:
                return value.strip()
        return ""


def section_value(sections: dict[str, str], *names: str) -> str:
    return SectionReader(sections).value(*names)
