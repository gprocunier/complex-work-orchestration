from __future__ import annotations

import copy
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .paths import POLICY_DIR
from .util import rank_allows, rank_max, term_hits


RISK_ORDER = ["low", "medium", "high", "critical"]


SENSITIVITY_ORDER = ["public", "redacted", "internal", "restricted"]


EXTERNAL_GUARD_LABELS = ["contractor-only", "no-codex-exec"]


LOCAL_WORKER_GUARD_LABELS = ["local-worker-only", "no-codex-exec"]


EDITOR_GATE_EXPERT = "editor"


PUBLIC_DOCS_EDITOR_TEXT_TERMS = [
    "public docs",
    "public documentation",
    "public guide",
    "readme",
    "install docs",
    "installation docs",
    "install section",
    "beads install",
    "beads setup",
    "operator docs",
    "github pages",
    "github page",
    "homepage",
    "home page",
    "docs bug",
    "public-docs editor",
    "editor oversharing",
    "internal monologue",
    "docs plus pages",
    "documentation plus github pages",
    "docs and pages",
    "site flow",
    "docs flow",
    "pages flow",
    "documentation architecture",
    "diataxis",
    "diátaxis",
]


PUBLIC_DOCS_PAGE_TEXT_TERMS = [
    "github pages",
    "github page",
    "docs site",
    "documentation site",
    "website",
    "web site",
    "site flow",
    "pages flow",
    "web design",
    "ux",
    "ui",
    "html",
    "css",
    "frontend",
    "diataxis",
    "diátaxis",
]


PUBLIC_DOCS_PATHS = {"README.md", "SKILL.md"}


PUBLIC_DOCS_PAGE_SUFFIXES = {".html", ".css", ".js"}


def executor_aliases(registry: dict[str, Any] | None = None) -> dict[str, str]:
    data = registry or load_policy("executor-registry")
    aliases = data.get("aliases", {})
    if not isinstance(aliases, dict):
        return {}
    return {str(alias): str(target) for alias, target in aliases.items()}


def resolve_executor_key(executor_key: str, registry: dict[str, Any] | None = None) -> str:
    data = registry or load_policy("executor-registry")
    aliases = executor_aliases(data)
    executors = data.get("executors", {})
    current = str(executor_key)
    seen: set[str] = set()
    while current in aliases:
        if current in seen:
            raise SystemExit(f"executor alias cycle includes {current!r}")
        seen.add(current)
        current = aliases[current]
    if current not in executors:
        return str(executor_key)
    return current


def executor_config(executor_key: str, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    data = registry or load_policy("executor-registry")
    canonical = resolve_executor_key(executor_key, data)
    executor = data.get("executors", {}).get(canonical)
    if not isinstance(executor, dict):
        raise SystemExit(f"unknown executor {executor_key!r}; see policy/executor-registry.yaml")
    value = dict(executor)
    value.setdefault("key", canonical)
    if canonical != executor_key:
        value["requested_key"] = executor_key
        value["canonical_key"] = canonical
    return value


def _canonical_executor_or_self(executor_key: str, registry: dict[str, Any]) -> str:
    try:
        return str(executor_config(executor_key, registry).get("key", executor_key))
    except SystemExit:
        return str(executor_key)


def executor_key_matches(candidate_key: str, executor_key: str, registry: dict[str, Any] | None = None) -> bool:
    candidate = str(candidate_key)
    requested = str(executor_key)
    if candidate == "*":
        return True
    if candidate == requested:
        return True
    data = registry or load_policy("executor-registry")
    return _canonical_executor_or_self(candidate, data) == _canonical_executor_or_self(requested, data)


def executor_key_allowed(executor_key: str, allowed_values: Any, registry: dict[str, Any] | None = None) -> bool:
    if isinstance(allowed_values, str):
        values = [allowed_values]
    elif isinstance(allowed_values, list):
        values = [str(value) for value in allowed_values]
    else:
        return False
    data = registry or load_policy("executor-registry")
    return any(executor_key_matches(value, executor_key, data) for value in values)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key {key!r}")
        value[key] = item
    return value


def load_json_compatible_yaml(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(
            f"{path} is not JSON-compatible YAML: {exc}. "
            "Policy files use a JSON-compatible YAML subset so helpers can run with the Python standard library."
        ) from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a top-level object")
    return value


@lru_cache(maxsize=None)
def _load_policy_cached(filename: str) -> dict[str, Any]:
    path = POLICY_DIR / filename
    if not path.is_file():
        raise SystemExit(f"missing policy file: {path}")
    return load_json_compatible_yaml(path)


def clear_policy_cache() -> None:
    _load_policy_cached.cache_clear()


def load_policy(name: str) -> dict[str, Any]:
    filename = name if name.endswith(".yaml") else f"{name}.yaml"
    return copy.deepcopy(_load_policy_cached(filename))


def provider_profile(provider_key: str | None) -> dict[str, Any]:
    providers = load_policy("provider-registry").get("providers", {})
    profile = providers.get(provider_key or "")
    if not isinstance(profile, dict):
        return {}
    value = dict(profile)
    value.setdefault("key", provider_key)
    return value


def provider_metadata_for_executor(executor: dict[str, Any]) -> dict[str, Any]:
    provider = provider_profile(executor.get("provider_key"))
    return {
        "provider_key": provider.get("key"),
        "provider_family": provider.get("family"),
        "provider_trust_tier": provider.get("trust_tier"),
        "provider_retention_class": provider.get("retention_class"),
        "provider_conflict_risk_domains": provider.get("conflict_risk_domains", []),
    }


def detect_provider_conflicts(text: str, provider_registry: dict[str, Any] | None = None) -> list[str]:
    registry = provider_registry or load_policy("provider-registry")
    conflicts: list[str] = []
    for domain, terms in registry.get("conflict_risk_terms", {}).items():
        if term_hits(text, terms):
            conflicts.append(str(domain))
    return sorted(set(conflicts))


def peer_review_policy() -> dict[str, Any]:
    return load_policy("peer-review-policy")


def route_requires_peer_review(
    *,
    route: str,
    risk: str,
    share_boundary: str,
    provider_conflict_domains: list[str],
) -> bool:
    policy = peer_review_policy()
    if bool(policy.get("required_for_routes", {}).get(route)):
        return True
    if bool(policy.get("required_for_share_boundaries", {}).get(share_boundary)):
        return True
    if risk in set(policy.get("required_for_risk_levels", [])):
        return True
    return bool(provider_conflict_domains and policy.get("required_for_provider_conflict", True))


def validate_peer_review_controls(
    *,
    primary_provider_family: str | None = None,
    peer_reviews: list[dict[str, Any]] | None = None,
    minimum_peer_reviews: int | None = None,
    provider_diversity_required: bool | None = None,
) -> dict[str, Any]:
    policy_defaults = peer_review_policy().get("defaults", {})
    minimum = int(
        minimum_peer_reviews
        if minimum_peer_reviews is not None
        else policy_defaults.get("minimum_peer_reviews", 1)
    )
    diversity_required = bool(
        provider_diversity_required
        if provider_diversity_required is not None
        else policy_defaults.get("provider_diversity_required", True)
    )
    reviews = [review for review in (peer_reviews or []) if isinstance(review, dict)]
    passed = [
        review
        for review in reviews
        if str(review.get("status", "")).strip().lower() in {"passed", "pass", "approved", "complete", "completed"}
    ]
    errors: list[str] = []
    if len(passed) < minimum:
        errors.append(f"minimum peer reviews not satisfied: required={minimum} passed={len(passed)}")
    primary = (primary_provider_family or "").strip().lower()
    passed_families = {
        str(review.get("provider_family", "") or review.get("provider", "")).strip().lower()
        for review in passed
        if str(review.get("provider_family", "") or review.get("provider", "")).strip()
    }
    if diversity_required and primary:
        if not passed_families:
            errors.append("provider diversity cannot be verified: peer review provider_family missing")
        elif not any(family != primary for family in passed_families):
            errors.append("provider diversity not satisfied")
    return {
        "valid": not errors,
        "errors": errors,
        "minimum_peer_reviews": minimum,
        "passed_peer_reviews": len(passed),
        "provider_diversity_required": diversity_required,
        "primary_provider_family": primary_provider_family,
        "passed_provider_families": sorted(passed_families),
    }


def share_boundary_disclosure_stage(share_boundary: str) -> str:
    return str(boundary_config(share_boundary).get("disclosure_stage", share_boundary))


def share_boundary_requires_escalation(share_boundary: str) -> bool:
    return bool(boundary_config(share_boundary).get("requires_disclosure_escalation"))


def boundary_config(share_boundary: str) -> dict[str, Any]:
    boundaries = load_policy("share-boundaries").get("boundaries", {})
    boundary = boundaries.get(share_boundary)
    if not isinstance(boundary, dict):
        raise SystemExit(f"unknown share boundary: {share_boundary}")
    return boundary


def boundary_allows_external(share_boundary: str) -> bool:
    return bool(boundary_config(share_boundary).get("allows_external"))


def load_contracting_controls() -> dict[str, Any]:
    return load_policy("contracting-controls")


def executor_external(executor_key: str) -> bool:
    executor = executor_config(executor_key)
    return bool(executor.get("external"))


def executor_dispatch_mode(executor_key: str) -> str:
    executor = executor_config(executor_key)
    return str(executor.get("dispatch_mode", ""))
