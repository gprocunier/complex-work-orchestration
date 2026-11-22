"""Resolve selected qualification metadata without granting execution authority.

The chosen configuration describes a target for later qualification. Matching
it does not establish effective configuration or operating-system enforcement.
No process, model, route, or containment boundary is started here.
"""

from __future__ import annotations

import json
from typing import Any

from .policy import load_policy
from .policy_schema import validate_policy_document

POLICY = "qualification-target"


class TargetError(ValueError):
    """The selected target or supplied configuration is invalid."""


def selected_target() -> dict[str, Any]:
    """Return the validated support floor, profile and configuration."""
    try:
        document = load_policy(POLICY)
        validate_policy_document(POLICY + ".yaml", document)
    except (SystemExit, ValueError) as exc:
        raise TargetError(str(exc)) from exc
    return document


def target_for(*, profile: str, configuration: dict[str, Any]) -> dict[str, Any]:
    """Refuse profile or configuration drift and return target metadata.

    JSON comparison distinguishes false from zero. Diagnostics check the
    selected executable's App Server capabilities separately at startup.
    """
    selected = selected_target()["selection"]
    observed = [profile, configuration]
    expected = [selected["profile"], selected["configuration"]]
    try:
        matches = json.dumps(observed, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True)
    except (TypeError, ValueError, RecursionError) as exc:
        raise TargetError("target profile and configuration must be JSON data") from exc
    if not matches:
        raise TargetError("profile or configuration differs from the selected target")
    return selected
