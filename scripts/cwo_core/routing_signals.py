from __future__ import annotations

import re

from .util import provider_term_intent, term_hits


def _routing_text_variants(text: str) -> list[str]:
    normalized = re.sub(r"[-_]+", " ", text)
    return [text, normalized] if normalized != text else [text]


def _hits(text: str, terms: list[str]) -> bool:
    return any(term_hits(variant, terms) for variant in _routing_text_variants(text))


def _affirmative_provider_hit(text: str, terms: list[str]) -> bool:
    affirmative, excluded = provider_term_intent(text, terms)
    return affirmative and not excluded


def explicit_gemini_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Gemini/Agy design-critic pattern."""
    return bool(
        _affirmative_provider_hit(text, ["gemini", "agy", "antigravity"])
        and _hits(text, ["architect", "architecture", "design"])
        and _hits(
            text,
            [
                "second opinion",
                "second opinions",
                "2nd opinion",
                "2nd opinions",
                "independent opinion",
                "independent opinions",
                "peer opinion",
                "peer opinions",
                "critique",
                "critiques",
                "critic",
                "critics",
                "review",
                "reviews",
            ],
        )
    )


def explicit_claude_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Claude Opus design-critic pattern."""
    return bool(
        _affirmative_provider_hit(text, ["claude", "opus", "anthropic"])
        and _hits(text, ["architect", "architecture", "design"])
        and _hits(
            text,
            [
                "second opinion",
                "second opinions",
                "2nd opinion",
                "2nd opinions",
                "independent opinion",
                "independent opinions",
                "peer opinion",
                "peer opinions",
                "critique",
                "critiques",
                "critic",
                "critics",
                "review",
                "reviews",
            ],
        )
    )


def explicit_glm_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in GLM design-critic pattern."""
    return bool(
        _affirmative_provider_hit(text, ["glm", "glm 5.2", "glm-5.2", "glm52"])
        and _hits(text, ["architect", "architecture", "design", "synthesis"])
        and _hits(
            text,
            [
                "second opinion",
                "second opinions",
                "2nd opinion",
                "2nd opinions",
                "independent opinion",
                "independent opinions",
                "peer opinion",
                "peer opinions",
                "critique",
                "critiques",
                "critic",
                "critics",
                "review",
                "reviews",
                "synthesis",
                "synthesize",
            ],
        )
    )


def architecture_critic_intent_conflicts(text: str) -> list[str]:
    """Return critic executors that are both affirmatively requested and prohibited."""

    architecture_context = _hits(text, ["architect", "architecture", "design", "synthesis"])
    critique_context = _hits(
        text,
        [
            "second opinion",
            "second opinions",
            "2nd opinion",
            "2nd opinions",
            "independent opinion",
            "independent opinions",
            "peer opinion",
            "peer opinions",
            "critique",
            "critiques",
            "critic",
            "critics",
            "review",
            "reviews",
            "synthesis",
            "synthesize",
        ],
    )
    if not (architecture_context and critique_context):
        return []
    conflicts: list[str] = []
    for executor, terms in [
        ("claude_architecture_critic", ["claude", "opus", "anthropic"]),
        ("gemini_architecture_critic", ["gemini", "agy", "antigravity"]),
        (
            "rhoai_glm_hardened_architecture_critic",
            ["glm", "glm 5.2", "glm-5.2", "glm52"],
        ),
    ]:
        affirmative, excluded = provider_term_intent(text, terms)
        if affirmative and excluded:
            conflicts.append(executor)
    return conflicts


def requested_architecture_critic_executor_keys(text: str) -> list[str]:
    keys: list[str] = []
    if explicit_claude_architect_critique_requested(text):
        keys.append("claude_architecture_critic")
    if explicit_gemini_architect_critique_requested(text):
        keys.append("gemini_architecture_critic")
    if explicit_glm_architect_critique_requested(text):
        keys.append("rhoai_glm_hardened_architecture_critic")
    return keys


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
        _affirmative_provider_hit(text, ["chatgpt", "gpt 5.5", "5.5 pro", "openai"])
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
        _affirmative_provider_hit(text, ["deep research"])
        and _affirmative_provider_hit(
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
