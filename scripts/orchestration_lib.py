#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO_ROOT / "policy"

RISK_ORDER = ["low", "medium", "high", "critical"]
SENSITIVITY_ORDER = ["public", "redacted", "internal", "restricted"]
EXTERNAL_GUARD_LABELS = ["contractor-only", "no-codex-exec"]


def load_json_compatible_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path} is not JSON-compatible YAML: {exc}. "
            "Policy files intentionally use a JSON-compatible YAML subset so "
            "the helper scripts can run with the Python standard library."
        ) from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a top-level object")
    return value


def load_policy(name: str) -> dict[str, Any]:
    filename = name if name.endswith(".yaml") else f"{name}.yaml"
    path = POLICY_DIR / filename
    if not path.is_file():
        raise SystemExit(f"missing policy file: {path}")
    return load_json_compatible_yaml(path)


def read_text_arg(text: str | None, file_path: str | None) -> str:
    parts: list[str] = []
    if text:
        parts.append(text)
    if file_path:
        parts.append(Path(file_path).read_text(encoding="utf-8"))
    if not parts:
        raise SystemExit("provide task text or --file")
    return "\n\n".join(parts)


def term_hits(text: str, terms: list[str]) -> list[str]:
    haystack = text.lower()
    hits: list[str] = []
    for term in terms:
        needle = term.lower()
        if needle in haystack:
            hits.append(term)
    return hits


def rank_max(values: list[str], order: list[str], default: str) -> str:
    current = default
    for value in values:
        if value in order and order.index(value) > order.index(current):
            current = value
    return current


def detect_sensitivity(text: str, restricted_terms: list[str]) -> str:
    hits = term_hits(text, restricted_terms)
    if hits:
        return "restricted"
    if any(term in text.lower() for term in ["public repo", "public documentation", "public docs"]):
        return "public"
    return "internal"


def score_experts(text: str, expert_registry: dict[str, Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for name, profile in expert_registry.get("experts", {}).items():
        hits = term_hits(text, profile.get("trigger_terms", []))
        if not hits:
            continue
        matches.append(
            {
                "name": name,
                "display_name": profile.get("display_name", name),
                "discipline": profile.get("discipline", name),
                "job_description_label": profile.get("job_description_label", "contract-jd-general-reasoning"),
                "task_class": profile.get("task_class", "domain-review"),
                "default_risk": profile.get("default_risk", "medium"),
                "default_share_boundary": profile.get("default_share_boundary", "redacted-packet"),
                "preferred_external_executor": profile.get("preferred_external_executor", "external_reasoner"),
                "matched_terms": hits,
                "score": len(hits),
                "output_focus": profile.get("output_focus", []),
            }
        )
    matches.sort(key=lambda item: (-int(item["score"]), item["name"]))
    return matches


def boundary_allows_external(share_boundary: str) -> bool:
    boundaries = load_policy("share-boundaries").get("boundaries", {})
    boundary = boundaries.get(share_boundary)
    return bool(boundary and boundary.get("allows_external"))


def classify_work(
    text: str,
    *,
    external_ok: bool = False,
    share_boundary: str = "no-outside-sharing",
) -> dict[str, Any]:
    routing = load_policy("routing-policy")
    experts = score_experts(text, load_policy("expert-registry"))
    sensitivity = detect_sensitivity(text, routing.get("restricted_terms", []))
    risks = [match["default_risk"] for match in experts]
    risk = rank_max(risks, RISK_ORDER, routing.get("defaults", {}).get("risk_level", "low"))
    primary = experts[0] if experts else None
    task_class = primary["task_class"] if primary else routing.get("defaults", {}).get("task_class", "implementation")

    reasons: list[str] = []
    if experts:
        reasons.append(
            "matched expert triggers: "
            + ", ".join(f"{match['name']}({', '.join(match['matched_terms'])})" for match in experts)
        )
    else:
        reasons.append("no expert trigger matched; defaulting to internal worker routing")

    boundary_external = boundary_allows_external(share_boundary)
    external_allowed = external_ok and boundary_external and sensitivity != "restricted"
    if external_ok and not boundary_external:
        reasons.append(f"share boundary {share_boundary!r} does not allow outside contractors")
    if sensitivity == "restricted":
        reasons.append("restricted terms were detected; external contracting is disabled until context is redacted")

    if external_allowed and primary:
        route = "external-contract"
        recommended_executor = primary.get("preferred_external_executor", "external_reasoner")
        guard_labels = EXTERNAL_GUARD_LABELS + [primary["job_description_label"]]
    elif risk in ["high", "critical"]:
        route = "architect-review"
        recommended_executor = "frontier_architect"
        guard_labels = []
    else:
        route = "internal-worker"
        recommended_executor = "internal_worker"
        guard_labels = []

    return {
        "route": route,
        "task_class": task_class,
        "risk_level": risk,
        "data_sensitivity": sensitivity,
        "share_boundary": share_boundary,
        "external_opt_in": external_ok,
        "external_contract_allowed": external_allowed,
        "recommended_executor": recommended_executor,
        "required_experts": experts,
        "guard_labels": guard_labels,
        "architect_review_required": route in ["external-contract", "architect-review"] or risk in ["high", "critical"],
        "beads_required_for_full_handoff": True,
        "reasons": reasons,
    }


def metadata_json(metadata: dict[str, Any]) -> str:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":"))


def require_bd() -> None:
    if not shutil.which("bd"):
        raise SystemExit("bd was not found; install Beads or use --dry-run")


def run_bd(args: list[str]) -> str:
    require_bd()
    completed = subprocess.run(
        ["bd", *args],
        check=False,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or completed.stdout.strip() or "bd command failed")
    return completed.stdout


def parse_created_issue_id(output: str) -> str:
    match = re.search(r"Created issue:\s+([^\s]+)", output)
    if match:
        return match.group(1)
    stripped = output.strip()
    if stripped and " " not in stripped:
        return stripped
    return ""


def create_bead(
    title: str,
    *,
    issue_type: str = "task",
    priority: int = 2,
    parent: str | None = None,
    labels: list[str] | None = None,
    description: str | None = None,
    acceptance: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    args = ["create", title, "--type", issue_type, "--priority", str(priority)]
    if parent:
        args.extend(["--parent", parent])
    if labels:
        args.extend(["--labels", ",".join(labels)])
    if description:
        args.extend(["--description", description])
    if acceptance:
        args.extend(["--acceptance", acceptance])
    if metadata:
        args.extend(["--metadata", metadata_json(metadata)])
    output = run_bd(args)
    return {"id": parse_created_issue_id(output), "title": title, "raw_output": output.strip()}


def show_bead_json(bead_id: str) -> Any:
    output = run_bd(["show", bead_id, "--json"])
    return json.loads(output)


def add_dependency(blocked: str, blocker: str) -> None:
    run_bd(["dep", "add", blocked, blocker])
