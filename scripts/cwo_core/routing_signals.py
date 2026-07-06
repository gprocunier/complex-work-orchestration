from __future__ import annotations

import re

from .util import term_hits


def _routing_text_variants(text: str) -> list[str]:
    normalized = re.sub(r"[-_]+", " ", text)
    return [text, normalized] if normalized != text else [text]


def _hits(text: str, terms: list[str]) -> bool:
    return any(term_hits(variant, terms) for variant in _routing_text_variants(text))


def explicit_gemini_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Gemini/Agy design-critic pattern."""
    return bool(
        _hits(text, ["gemini", "agy", "antigravity"])
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
        _hits(text, ["claude", "opus", "anthropic"])
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
        _hits(text, ["glm", "glm 5.2", "glm-5.2", "glm52"])
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


def requested_architecture_critic_executor_keys(text: str) -> list[str]:
    keys: list[str] = []
    if explicit_claude_architect_critique_requested(text):
        keys.append("claude_architecture_critic")
    if explicit_gemini_architect_critique_requested(text):
        keys.append("gemini_architecture_critic")
    if explicit_glm_architect_critique_requested(text):
        keys.append("rhoai_glm_architecture_critic")
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
