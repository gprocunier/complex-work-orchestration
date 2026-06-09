#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from orchestration_lib import POLICY_DIR, REPO_ROOT, load_policy

EMITTED_PACKET_ARTIFACT_TYPES = {
    "assignment_summary",
    "selected_file_snippet",
    "inline_snippet",
    "expert_profile",
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.relative_to(REPO_ROOT)} is not valid JSON: {exc}") from exc


def validate_repository() -> list[str]:
    errors: list[str] = []

    for path in sorted(POLICY_DIR.glob("*.yaml")):
        try:
            load_json(path)
        except ValueError as exc:
            errors.append(str(exc))

    for path in sorted((REPO_ROOT / "schemas").glob("*.json")):
        try:
            load_json(path)
        except ValueError as exc:
            errors.append(str(exc))

    try:
        executors = load_policy("executor-registry").get("executors", {})
        experts = load_policy("expert-registry").get("experts", {})
        controls = load_policy("contracting-controls")
        boundaries = load_policy("share-boundaries").get("boundaries", {})
    except SystemExit as exc:
        return [str(exc)]

    for key, executor in executors.items():
        alias_for = executor.get("alias_for")
        if alias_for and alias_for not in executors:
            errors.append(f"executor {key!r} aliases unknown executor {alias_for!r}")
        if executor.get("external") and executor.get("codex_pickup") != "forbidden":
            errors.append(f"external executor {key!r} must set codex_pickup=forbidden")
        if executor.get("dispatch_mode") == "local_openai_compatible" and executor.get("codex_pickup") != "forbidden":
            errors.append(f"local worker executor {key!r} must set codex_pickup=forbidden")

    labels: dict[str, str] = {}
    for name, expert in experts.items():
        persona = expert.get("persona_file")
        if not persona or not (REPO_ROOT / persona).is_file():
            errors.append(f"expert {name!r} references missing persona_file {persona!r}")
        label = expert.get("job_description_label")
        if not label or not str(label).startswith("contract-jd-"):
            errors.append(f"expert {name!r} has invalid job_description_label {label!r}")
        elif label in labels:
            errors.append(f"experts {labels[label]!r} and {name!r} share duplicate job label {label!r}")
        else:
            labels[label] = name
        for preferred in expert.get("preferred_executors", []):
            if preferred not in executors:
                errors.append(f"expert {name!r} prefers unknown executor {preferred!r}")

    allowed_external = set(controls.get("allowed_external_executors", []))
    for executor in allowed_external:
        if executor not in executors:
            errors.append(f"contracting controls allow unknown executor {executor!r}")
        elif not executors[executor].get("external"):
            errors.append(f"contracting controls allow non-external executor {executor!r}")
    for key, executor in executors.items():
        if executor.get("external") and key not in allowed_external:
            errors.append(f"external executor {key!r} is not listed in contracting controls")

    for name, boundary in boundaries.items():
        whitelist = set(boundary.get("artifact_whitelist", []))
        if "selected_file_snippets" in whitelist:
            errors.append(f"boundary {name!r} uses legacy plural artifact selected_file_snippets")
        if boundary.get("allows_external"):
            missing = sorted(EMITTED_PACKET_ARTIFACT_TYPES - whitelist)
            if missing:
                errors.append(f"boundary {name!r} does not whitelist emitted artifacts: {', '.join(missing)}")

    return errors


def main() -> None:
    errors = validate_repository()
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        raise SystemExit(1)
    print("Repository validation passed.")


if __name__ == "__main__":
    main()
