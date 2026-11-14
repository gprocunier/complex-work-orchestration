"""Resolve selected qualification metadata without granting execution authority.

The chosen configuration describes a target for later qualification. Matching
it does not establish effective configuration or operating-system enforcement.
No process, model, route, or containment boundary is started here.
"""

from __future__ import annotations

import json
from typing import Any

from .codex_protocol_pin import pin_for
from .policy import load_policy
from .policy_schema import validate_policy_document

POLICY = "qualification-target"


class TargetError(ValueError):
    """The selected target or a supplied identity does not match."""


def selected_target() -> dict[str, Any]:
    """Return the validated target, bound to its existing protocol/package pin."""
    try:
        document = load_policy(POLICY)
        validate_policy_document(POLICY + ".yaml", document)
        selected = document["selection"]
        pin = pin_for(selected["pin_version"])
        executable = pin["executable"]
    except (SystemExit, ValueError) as exc:
        raise TargetError(str(exc)) from exc
    expected = (executable["sha256"], executable.get("package_json_sha256"), executable.get("target"),
                executable["version_text"], pin["bundles"])
    recorded = (selected["executable_sha256"], selected["package"]["sha256"], selected["package"]["target"],
                document["observations"]["version_text"], document["observations"]["bundles"])
    if recorded != expected:
        raise TargetError("selected identity or observed schema bundles differ from the protocol pin")
    return document


def target_for(*, profile: str, version_text: str, executable_sha256: str,
               package_json_sha256: str, configuration: dict[str, Any]) -> dict[str, Any]:
    """Refuse identity, profile or configuration drift; return metadata only.

    Version text and digests must come from the caller's own observations.
    Configuration is compared as JSON, without treating false and zero as equal.
    This is a qualification-selection check, never a live-dispatch admission.
    """
    selected = selected_target()["selection"]
    observed = [profile, version_text.strip() if type(version_text) is str else version_text,
                executable_sha256, package_json_sha256, configuration]
    expected = [selected["profile"], pin_for(selected["pin_version"])["executable"]["version_text"],
                selected["executable_sha256"], selected["package"]["sha256"], selected["configuration"]]
    try:
        matches = json.dumps(observed, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True)
    except (TypeError, ValueError, RecursionError) as exc:
        raise TargetError("target identity and configuration must be JSON data") from exc
    if not matches:
        raise TargetError("executable, package, profile or configuration differs from the selected target")
    return selected
