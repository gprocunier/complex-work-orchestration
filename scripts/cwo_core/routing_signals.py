from __future__ import annotations

import re
from typing import Any

from .policy import load_policy
from .util import term_hits


def _routing_text_variants(text: str) -> list[str]:
    normalized = re.sub(r"[-_]+", " ", text)
    return [text, normalized] if normalized != text else [text]


def _hits(text: str, terms: list[str]) -> bool:
    return any(term_hits(variant, terms) for variant in _routing_text_variants(text))


def _critic_trigger_registry() -> dict[str, Any]:
    triggers = load_policy("routing-policy").get("architecture_critic_triggers", {})
    return triggers if isinstance(triggers, dict) else {}


def _critic_requested(text: str, executor_key: str) -> bool:
    registry = _critic_trigger_registry()
    config = registry.get("executors", {}).get(executor_key)
    if not isinstance(config, dict):
        return False
    critique_terms = list(registry.get("shared_critique_terms") or []) + list(
        config.get("extra_critique_terms") or []
    )
    return bool(
        _hits(text, list(config.get("provider_terms") or []))
        and _hits(text, list(config.get("context_terms") or []))
        and _hits(text, critique_terms)
    )


def explicit_gemini_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Gemini/Agy design-critic pattern."""
    return _critic_requested(text, "gemini_architecture_critic")


def explicit_claude_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Claude Opus design-critic pattern."""
    return _critic_requested(text, "claude_architecture_critic")


def explicit_glm_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in GLM design-critic pattern."""
    return _critic_requested(text, "rhoai_glm_hardened_architecture_critic")


def requested_architecture_critic_executor_keys(text: str) -> list[str]:
    return [
        executor_key
        for executor_key in _critic_trigger_registry().get("executors", {})
        if _critic_requested(text, executor_key)
    ]


def architecture_review_complexity(text: str, risk: str) -> str:
    if risk == "critical" or _hits(
        text,
        [
            "total-system",
            "total system",
            "irreversible",
            "high-cost",
            "high cost",
            "blast radius",
            "mission critical",
        ],
    ):
        return "critical"
    if _hits(
        text,
        [
            "cross-cutting",
            "cross cutting",
            "security-sensitive",
            "security sensitive",
            "persistent-state",
            "persistent state",
            "public-contract",
            "public contract",
            "multi-provider",
            "multi provider",
            "architecture migration",
        ],
    ):
        return "high"
    return "medium"


def claude_architecture_effort(complexity: str) -> str:
    if complexity == "critical":
        return "max"
    if complexity == "high":
        return "xhigh"
    return "high"


def command_with_claude_effort(command: str, effort: str) -> str:
    return re.sub(r"--effort\s+\S+", f"--effort {effort}", command)


def explicit_chatgpt_master_plan_review_requested(text: str) -> bool:
    """Return true for the ChatGPT Pro Extended Reasoning plan-review lane."""
    return bool(
        _hits(text, ["chatgpt", "gpt 5.5", "5.5 pro", "openai"])
        and _hits(
            text,
            [
                "extended reasoning",
                "master plan",
                "master review",
                "master critique",
                "master reviewer",
                "total work packet",
                "work packet reviewer",
                "final execution plan",
                "final plan review",
                "final review",
                "weigh in as a master review",
            ],
        )
    )


def explicit_openai_deep_research_requested(text: str) -> bool:
    """Return true for the separate ChatGPT Deep Research opt-in lane."""
    return bool(
        _hits(text, ["deep research"])
        and _hits(
            text,
            [
                "openai",
                "chatgpt",
                "chat gpt",
                "gpt",
                "gpt-5",
                "gpt 5",
                "5.5 pro",
            ],
        )
    )
