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


_ARCHITECTURE_CONTEXT = ["architect", "architecture", "design"]
_CRITIQUE_CONTEXT = [
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
]
_GLM_ARCHITECTURE_CONTEXT = [*_ARCHITECTURE_CONTEXT, "synthesis"]
_GLM_CRITIQUE_CONTEXT = [*_CRITIQUE_CONTEXT, "synthesis", "synthesize"]
_GEMINI_TERMS = ["gemini", "agy", "antigravity"]
_CLAUDE_TERMS = ["claude", "opus", "anthropic"]
_GLM_5_3_TERMS = ["glm 5.3", "glm-5.3", "glm53"]
_GLM_TERMS = ["glm", "glm 5.2", "glm-5.2", "glm52", *_GLM_5_3_TERMS]


def explicit_gemini_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Gemini/Agy design-critic pattern."""
    return (
        _affirmative_provider_hit(text, _GEMINI_TERMS)
        and _hits(text, _ARCHITECTURE_CONTEXT)
        and _hits(text, _CRITIQUE_CONTEXT)
    )


def explicit_claude_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Claude Opus design-critic pattern."""
    return (
        _affirmative_provider_hit(text, _CLAUDE_TERMS)
        and _hits(text, _ARCHITECTURE_CONTEXT)
        and _hits(text, _CRITIQUE_CONTEXT)
    )


def _explicit_glm_critique_requested(text: str, terms: list[str]) -> bool:
    return (
        _affirmative_provider_hit(text, terms)
        and _hits(text, _GLM_ARCHITECTURE_CONTEXT)
        and _hits(text, _GLM_CRITIQUE_CONTEXT)
    )


def explicit_glm_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in GLM design-critic pattern."""
    return _explicit_glm_critique_requested(text, _GLM_TERMS)


def explicit_glm_5_3_architect_critique_requested(text: str) -> bool:
    """Return true only when the GLM-5.3 critic generation is explicit."""
    return _explicit_glm_critique_requested(text, _GLM_5_3_TERMS)


def architecture_critic_intent_conflicts(text: str) -> list[str]:
    """Return critic executors that are both affirmatively requested and prohibited."""

    architecture_context = _hits(text, _GLM_ARCHITECTURE_CONTEXT)
    critique_context = _hits(text, _GLM_CRITIQUE_CONTEXT)
    if not (architecture_context and critique_context):
        return []
    conflicts: list[str] = []
    glm_5_3_requested = explicit_glm_5_3_architect_critique_requested(text)
    for executor, terms in [
        ("claude_architecture_critic", _CLAUDE_TERMS),
        ("gemini_architecture_critic", _GEMINI_TERMS),
        (
            (
                "rhoai_glm_compact_architecture_critic"
                if glm_5_3_requested
                else "rhoai_glm_hardened_architecture_critic"
            ),
            _GLM_TERMS,
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
    if explicit_glm_5_3_architect_critique_requested(text):
        keys.append("rhoai_glm_compact_architecture_critic")
    elif explicit_glm_architect_critique_requested(text):
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
