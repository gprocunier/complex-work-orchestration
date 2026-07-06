from __future__ import annotations

WORKGRAPH_FALLBACK_MARKER = "Reduced durability fallback"
WORKGRAPH_ITEMS_HEADING = "## Work Items"

FIELD_TYPE = "Type"
FIELD_LANE = "Lane"
FIELD_LABELS = "Labels"
FIELD_DEPENDS_ON_LANES = "Depends on lanes"
FIELD_SKILLS = "Skills"


def normalize_field_label(value: str) -> str:
    return value.strip().lower()
