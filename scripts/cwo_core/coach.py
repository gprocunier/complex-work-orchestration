from __future__ import annotations

import re
from typing import Any

from .routing import (
    classify_work,
    expert_uses_external_contract,
    resolve_beads_context_depth,
)
from .synthesis import recommend_model_synthesis
from .types import CoachResult
from .util import term_hits

SPARK_MODEL_ALIAS = "gpt-5.3-codex-spark"


PROMPT_COACH_RESULT_REQUIRED_FIELDS = [
    "coach_result_type",
    "version",
    "beads_tracking_required",
    "recommended_orchestration_level",
    "scaffold_sizing",
    "beads_context_depth",
    "beads_context_depth_provenance",
    "rationale",
    "missing_questions",
    "interactive_questions",
    "requires_user_selection_before_plan",
    "selection_before_plan_reason",
    "selection_before_plan_question_ids",
    "enabled_levers",
    "disabled_levers",
    "workerbee_parallelism",
    "workerbee_planned_delegation",
    "model_synthesis",
    "operator_calibration",
    "route",
    "paste_ready_prompt",
    "warnings",
]


def _normalize_workerbee_planned_delegation(workerbee_parallelism: dict[str, Any] | None) -> dict[str, Any]:
    mode = str((workerbee_parallelism or {}).get("recommended_mode") or "none")
    model = (workerbee_parallelism or {}).get("recommended_model")
    if model is not None and not str(model).strip():
        model = None
    registry_tool_mismatch = bool((workerbee_parallelism or {}).get("registry_tool_mismatch"))
    spark_operational_worker = bool((workerbee_parallelism or {}).get("spark_operational_worker"))
    spark_dispatch = (workerbee_parallelism or {}).get("spark_dispatch")
    if not isinstance(spark_dispatch, dict):
        spark_dispatch = {}
    raw_lanes = (workerbee_parallelism or {}).get("suggested_lanes")
    if not isinstance(raw_lanes, list):
        raw_lanes = []
    lanes: list[str] = []
    for lane in raw_lanes:
        text = str(lane or "").strip()
        if text and text not in lanes:
            lanes.append(text)
    return {
        "mode": mode,
        "model": model,
        "lanes": lanes,
        "registry_tool_mismatch": registry_tool_mismatch,
        "hard_stop": bool((workerbee_parallelism or {}).get("hard_stop")),
        "hard_stop_reason": str((workerbee_parallelism or {}).get("hard_stop_reason") or ""),
        "spark_operational_worker": spark_operational_worker,
        "spark_dispatch": spark_dispatch,
    }


def text_has_any(text: str, terms: list[str]) -> bool:
    return bool(term_hits(text, terms))


def prompt_coach_has_full_harness_signal(text: str) -> bool:
    if text_has_any(
        text,
        [
            "use $complex-work-orchestration to scaffold",
            "$complex-work-orchestration to scaffold",
            "scaffold this project",
            "scaffold a project",
            "scaffold the project",
            "full scaffold",
            "full harness",
            "pm coordination",
            "project manager",
            "role/lane",
            "role lane",
            "role lanes",
            "lane tasks",
            "epic",
            "contractor lane",
            "contractor lanes",
            "outside contractor lane",
            "outside contractor lanes",
        ],
    ):
        return True
    return prompt_coach_has_explicit_workerbee_request(text)


def prompt_coach_has_tight_chain_signal(text: str) -> bool:
    return text_has_any(
        text,
        [
            "tight-chain",
            "tight chain",
            "tight review chain",
            "focused review chain",
            "narrow review chain",
            "compact scaffold",
            "minimal scaffold",
            "small scaffold",
            "bounded scaffold",
            "single chain",
        ],
    )


def prompt_coach_spark_failure_clauses(text: str) -> list[str]:
    return [
        clause.strip()
        for clause in re.split(r"(?:[!?;]+|(?<!\d)\.(?!\d))\s*|\n+", text)
        if clause.strip()
    ]


def prompt_coach_has_browser_provider_context(text: str) -> bool:
    return text_has_any(
        text,
        [
            "chatgpt pro",
            "chatgpt plus",
            "chatgpt browser",
            "pro plan",
            "browser lane",
            "browser-based lane",
            "browser mediated lane",
            "browser-mediated lane",
            "in the browser",
            "through the browser",
            "via the browser",
            "browser surface",
            "provider lane",
            "hosted provider",
            "openai provider",
            "through the provider",
            "via the provider",
            "provider surface",
        ],
    )


def prompt_coach_has_native_spark_control_context(text: str) -> bool:
    return text_has_any(
        text,
        [
            "native spark",
            "native dispatch",
            "native spark dispatch",
            "native-spark",
            "native-dispatch",
            "native spark tooling",
            "native spark tool",
            "native tool",
            "native-tool",
            "native tooling",
            "native-tooling",
            "native worker",
            "native-worker",
            "native subagent",
            "native-subagent",
            "spawn tool",
            "spawn-tool",
            "control plane",
            "control-plane",
            "native registry",
            "native-registry",
            "worker registry",
            "workerbee registry",
            "spark tooling",
            "spark tool",
            "spark capability",
            "spark dispatch",
            "spark route",
            "spark workerbee",
            "spark worker",
            "spark model",
            "codex 5.3 spark",
            "gpt-5.3-codex-spark",
            "local spark",
            "local codex cli",
            "local cli",
            "local tool surface",
            "local tool-surface",
            "spark tool surface",
            "spark tool-surface",
            "registry_tool_mismatch",
            "registry/tool",
            "registry-tool",
            "registry tool",
            "registry and tool",
            "model override",
        ],
    )


def prompt_coach_has_explicit_native_spark_scope(text: str) -> bool:
    return text_has_any(
        text,
        [
            "native spark",
            "native dispatch",
            "native spark dispatch",
            "native-spark",
            "native-dispatch",
            "native spark tooling",
            "native spark tool",
            "native tool",
            "native-tool",
            "native tooling",
            "native-tooling",
            "native worker",
            "native-worker",
            "native subagent",
            "native-subagent",
            "native registry",
            "native-registry",
            "control plane",
            "control-plane",
            "local spark",
            "local codex cli",
            "local cli",
            "local tool surface",
            "local tool-surface",
            "spark tool surface",
            "spark tool-surface",
        ],
    )


def prompt_coach_has_workerbee_execution_context(text: str) -> bool:
    return text_has_any(
        text,
        [
            "workerbee dispatch",
            "workerbee execution",
            "workerbee route",
            "workerbee tooling",
        ],
    )


def prompt_coach_is_native_spark_failure_clause(text: str) -> bool:
    return bool(
        "spark" in text
        and (
            not prompt_coach_has_browser_provider_context(text)
            or prompt_coach_clause_has_explicit_native_spark_failure(text)
        )
        and (
            prompt_coach_has_native_spark_control_context(text)
            or prompt_coach_has_workerbee_execution_context(text)
            or prompt_coach_clause_has_bare_direct_spark_absence(text)
        )
    )


SPARK_MODEL_PATTERN = r"(?:codex\s+5\.3\s+|gpt-5\.3-codex-)?spark"
SPARK_FAILURE_STATE_PATTERN = r"(?:(?:is|are|was|were|may|might|will|would|can|could)\s+)*"
SPARK_UNAVAILABLE_PATTERN = (
    r"(?:is(?:\s+not|n't)\s+available|are(?:\s+not|n't)\s+available|"
    r"not\s+(?:be\s+)?available|unavailable|absent|missing|not\s+installed)"
)


def prompt_coach_clause_has_direct_spark_absence(text: str) -> bool:
    spark_subject = (
        rf"\b{SPARK_MODEL_PATTERN}\b"
        r"(?:\s+(?:native\s+)?(?:model|capability|dispatch|route|workerbee|worker|tooling|tool|spawn\s+tool))?"
    )
    return bool(
        re.search(
            rf"{spark_subject}\s+{SPARK_FAILURE_STATE_PATTERN}{SPARK_UNAVAILABLE_PATTERN}\b",
            text,
        )
        or re.search(rf"\bno\s+(?:native\s+)?{SPARK_MODEL_PATTERN}\b", text)
        or re.search(rf"\b(?:cannot|can't)\s+use\s+{SPARK_MODEL_PATTERN}\b", text)
        or re.search(
            rf"\b{SPARK_UNAVAILABLE_PATTERN}\b(?:\s*[:=-]\s*|\s+)(?:the\s+)?{spark_subject}",
            text,
        )
        or re.search(
            rf"\b(?:does\s+not|doesn't)\s+(?:expose|include|list)\b.{{0,40}}\b{SPARK_MODEL_PATTERN}\b",
            text,
        )
        or re.search(rf"\bomits?\b.{{0,40}}\b{SPARK_MODEL_PATTERN}\b", text)
    )


def prompt_coach_clause_has_bare_direct_spark_absence(text: str) -> bool:
    return bool(
        re.search(
            rf"\bspark\b\s+{SPARK_FAILURE_STATE_PATTERN}{SPARK_UNAVAILABLE_PATTERN}\b",
            text,
        )
    )


def prompt_coach_clause_has_native_tool_absence(text: str) -> bool:
    spark_tool_subject = (
        rf"(?:(?:native|local)\s+)?{SPARK_MODEL_PATTERN}\s+"
        r"(?:tooling|tool(?:\s+surface|-surface)?|spawn(?:\s+|-)tool|registry)"
    )
    native_tool_subject = (
        r"(?:native|local)\s+(?:spark\s+)?"
        r"(?:tooling|tool(?:\s+surface|-surface)?|spawn(?:\s+|-)tool|worker(?:bee)?|subagent|registry)"
    )
    return bool(
        re.search(
            rf"\b(?:{spark_tool_subject}|{native_tool_subject})\b\s+"
            rf"{SPARK_FAILURE_STATE_PATTERN}{SPARK_UNAVAILABLE_PATTERN}\b",
            text,
        )
        or re.search(
            rf"\b{SPARK_UNAVAILABLE_PATTERN}\b(?:\s*[:=-]\s*|\s+)(?:the\s+)?"
            rf"(?:{spark_tool_subject}|{native_tool_subject})\b",
            text,
        )
        or re.search(
            rf"\b{SPARK_MODEL_PATTERN}\b\s+{SPARK_FAILURE_STATE_PATTERN}(?:absent|missing)\b.{{0,40}}"
            r"\b(?:native\s+)?(?:worker|workerbee)\s+registry\b",
            text,
        )
        or re.search(
            r"\b(?:native\s+)?(?:worker|workerbee)\s+registry\b.{{0,40}}"
            rf"\b(?:does\s+not|doesn't)\s+(?:expose|include|list)\b.{{0,40}}\b{SPARK_MODEL_PATTERN}\b",
            text,
        )
    )


def prompt_coach_clause_has_explicit_native_spark_absence(text: str) -> bool:
    explicit_subject = (
        rf"(?:(?:native|local)\s+{SPARK_MODEL_PATTERN}"
        r"(?:\s+(?:model|capability|dispatch|route|workerbee|worker|tooling|"
        r"tool(?:\s+surface|-surface)?|spawn(?:\s+|-)tool|registry))?"
        rf"|{SPARK_MODEL_PATTERN}\s+(?:tool\s+surface|tool-surface))"
    )
    return bool(
        re.search(
            rf"\b{explicit_subject}\b\s+{SPARK_FAILURE_STATE_PATTERN}{SPARK_UNAVAILABLE_PATTERN}\b",
            text,
        )
        or re.search(
            rf"\b{SPARK_UNAVAILABLE_PATTERN}\b(?:\s*[:=-]\s*|\s+)(?:the\s+)?{explicit_subject}\b",
            text,
        )
        or re.search(
            rf"\b{SPARK_MODEL_PATTERN}\b(?:\s+(?:model|capability|dispatch|route|workerbee|worker|tooling|tool))?"
            rf"\s+{SPARK_FAILURE_STATE_PATTERN}{SPARK_UNAVAILABLE_PATTERN}\b.{{0,40}}"
            r"\b(?:local\s+(?:codex\s+)?cli|local\s+tool(?:\s+surface|-surface)|spark\s+tool(?:\s+surface|-surface))\b",
            text,
        )
    )


def prompt_coach_clause_has_explicit_native_tool_absence(text: str) -> bool:
    explicit_tool_subject = (
        rf"(?:(?:native|local)\s+{SPARK_MODEL_PATTERN}\s+"
        r"(?:tooling|tool(?:\s+surface|-surface)?|spawn(?:\s+|-)tool|registry)"
        rf"|{SPARK_MODEL_PATTERN}\s+(?:tool\s+surface|tool-surface))"
    )
    return bool(
        re.search(
            rf"\b{explicit_tool_subject}\b\s+{SPARK_FAILURE_STATE_PATTERN}{SPARK_UNAVAILABLE_PATTERN}\b",
            text,
        )
        or re.search(
            rf"\b{SPARK_UNAVAILABLE_PATTERN}\b(?:\s*[:=-]\s*|\s+)(?:the\s+)?{explicit_tool_subject}\b",
            text,
        )
    )


def prompt_coach_has_workerbee_availability_constraint(text: str) -> bool:
    return any(
        prompt_coach_is_native_spark_failure_clause(clause)
        and (
            (
                prompt_coach_clause_has_explicit_native_spark_absence(clause)
                if prompt_coach_has_browser_provider_context(clause)
                else prompt_coach_clause_has_direct_spark_absence(clause)
            )
            or (
                prompt_coach_clause_has_explicit_native_tool_absence(clause)
                if prompt_coach_has_browser_provider_context(clause)
                else prompt_coach_clause_has_native_tool_absence(clause)
            )
        )
        for clause in prompt_coach_spark_failure_clauses(text)
    )


def prompt_coach_has_spark_native_tool_absence_signal(text: str) -> bool:
    return any(
        prompt_coach_is_native_spark_failure_clause(clause)
        and (
            prompt_coach_clause_has_explicit_native_tool_absence(clause)
            if prompt_coach_has_browser_provider_context(clause)
            else prompt_coach_clause_has_native_tool_absence(clause)
        )
        for clause in prompt_coach_spark_failure_clauses(text)
    )


def prompt_coach_clause_has_spark_rejection(text: str) -> bool:
    spark_subject = (
        rf"(?:native\s+)?{SPARK_MODEL_PATTERN}"
        r"(?:\s+(?:model(?:\s+(?:override|selection))?|dispatch|route|routing))?"
    )
    rejected = r"reject(?:ed|s|ing)"
    state = r"(?:(?:is|are|was|were|has\s+been|have\s+been)\s+)?"
    emphasis = r"(?:explicitly\s+)?"
    native_subject = r"native\s+(?:spark\s+)?(?:model(?:\s+(?:override|selection))?|dispatch|route|routing)"
    return bool(
        re.search(rf"\b{spark_subject}\b\s+{state}{emphasis}{rejected}\b", text)
        or re.search(rf"\b{rejected}\b\s+(?:the\s+)?{spark_subject}\b", text)
        or re.search(rf"\b{native_subject}\b\s+{state}{emphasis}{rejected}\b", text)
        or re.search(
            rf"\b(?:native\s+)?(?:dispatch|route|routing)\b\s+{state}{emphasis}{rejected}\b.{{0,40}}"
            rf"\b(?:for|of)\s+(?:the\s+)?(?:native\s+)?{SPARK_MODEL_PATTERN}\b",
            text,
        )
    )


def prompt_coach_clause_has_explicit_native_spark_rejection(text: str) -> bool:
    explicit_subject = (
        rf"(?:(?:native|local)\s+{SPARK_MODEL_PATTERN}"
        r"(?:\s+(?:model(?:\s+(?:override|selection))?|dispatch|route|routing))?"
        rf"|{SPARK_MODEL_PATTERN}\s+(?:tool\s+surface|tool-surface))"
    )
    predicate = r"(?:(?:is|are|was|were|has\s+been|have\s+been)\s+)?(?:explicitly\s+)?reject(?:ed|s|ing)"
    return bool(
        re.search(rf"\b{explicit_subject}\b\s+{predicate}\b", text)
        or re.search(rf"\breject(?:ed|s|ing)\b\s+(?:the\s+)?{explicit_subject}\b", text)
        or re.search(
            rf"\b(?:native|local)\s+(?:dispatch|route|routing)\b\s+{predicate}\b.{{0,40}}"
            rf"\b(?:for|of)\s+(?:the\s+)?{SPARK_MODEL_PATTERN}\b",
            text,
        )
    )


def prompt_coach_has_spark_override_rejection_signal(text: str) -> bool:
    return any(
        prompt_coach_is_native_spark_failure_clause(clause)
        and (
            prompt_coach_clause_has_explicit_native_spark_rejection(clause)
            if prompt_coach_has_browser_provider_context(clause)
            else prompt_coach_clause_has_spark_rejection(clause)
        )
        for clause in prompt_coach_spark_failure_clauses(text)
    )


def prompt_coach_has_review_only_workerbee_signal(text: str) -> bool:
    return bool(
        re.search(r"\breview(?:ing)?\s*[-_\s]*\s*only\b", text)
        or re.search(r"\bread(?:\s*[-_\s]*\s*only)\b", text)
    )


def prompt_coach_clause_has_spark_registry_tool_mismatch(text: str) -> bool:
    spark_subject = rf"(?:native\s+)?{SPARK_MODEL_PATTERN}"
    mismatch = (
        r"(?:registry_tool_mismatch|registry\s*/\s*tool\s+mismatch|registry-tool\s+mismatch|"
        r"registry\s+tool\s+mismatch|registry\s+and\s+tool\s+mismatch)"
    )
    return bool(
        re.search(rf"\b{spark_subject}\b\s+{mismatch}\b", text)
        or re.search(
            rf"\b{spark_subject}\b(?:\s+evidence)?\s+(?:has|reports?|reported)\s+(?:a\s+)?{mismatch}\b",
            text,
        )
        or re.search(
            rf"\b{mismatch}\b.{{0,40}}\b(?:for|of|on)\s+(?:the\s+)?{spark_subject}\b",
            text,
        )
        or re.search(
            r"\bmismatch\b.{0,40}\bbetween\s+(?:the\s+)?registry\s+and\s+(?:the\s+)?tool\b"
            rf".{{0,40}}\bfor\s+(?:the\s+)?{spark_subject}\b",
            text,
        )
        or re.search(
            rf"\bmismatch\b.{{0,40}}\bbetween\s+(?:the\s+)?{spark_subject}\s+registry\b"
            r".{0,40}\b(?:native\s+)?tool\b",
            text,
        )
        or re.search(
            rf"\bmismatch\b.{{0,40}}\bbetween\s+(?:the\s+)?(?:native\s+)?tool\b"
            rf".{{0,40}}\b{spark_subject}\s+registry\b",
            text,
        )
        or re.search(
            rf"\b{spark_subject}\s+registry\b.{{0,40}}\bdoes\s+not\s+match\b"
            r".{0,40}\b(?:the\s+)?(?:native\s+)?tool\b",
            text,
        )
        or re.search(
            rf"\b{spark_subject}\s+tool\b.{{0,40}}\bdoes\s+not\s+match\b"
            r".{0,40}\b(?:the\s+)?(?:native\s+)?registry\b",
            text,
        )
    )


def prompt_coach_clause_has_explicit_native_spark_registry_tool_mismatch(text: str) -> bool:
    explicit_subject = (
        rf"(?:(?:native|local)\s+{SPARK_MODEL_PATTERN}|"
        rf"{SPARK_MODEL_PATTERN}\s+(?:tool\s+surface|tool-surface))"
    )
    mismatch = (
        r"(?:registry_tool_mismatch|registry\s*/\s*tool\s+mismatch|registry-tool\s+mismatch|"
        r"registry\s+tool\s+mismatch|registry\s+and\s+tool\s+mismatch)"
    )
    return bool(
        re.search(rf"\b{explicit_subject}\b.{{0,40}}\b{mismatch}\b", text)
        or re.search(rf"\b{mismatch}\b.{{0,40}}\b(?:for|of|on)\s+(?:the\s+)?{explicit_subject}\b", text)
    )


def prompt_coach_clause_has_explicit_native_spark_failure(text: str) -> bool:
    return bool(
        prompt_coach_clause_has_explicit_native_spark_absence(text)
        or prompt_coach_clause_has_explicit_native_spark_rejection(text)
        or prompt_coach_clause_has_explicit_native_spark_registry_tool_mismatch(text)
    )


def prompt_coach_has_spark_registry_tool_mismatch_signal(text: str) -> bool:
    return any(
        prompt_coach_is_native_spark_failure_clause(clause)
        and (
            prompt_coach_clause_has_explicit_native_spark_registry_tool_mismatch(clause)
            if prompt_coach_has_browser_provider_context(clause)
            else prompt_coach_clause_has_spark_registry_tool_mismatch(clause)
        )
        for clause in prompt_coach_spark_failure_clauses(text)
    )


def prompt_coach_has_provider_scoped_spark_failure(text: str) -> bool:
    return any(
        "spark" in clause
        and prompt_coach_has_browser_provider_context(clause)
        and not prompt_coach_clause_has_explicit_native_spark_failure(clause)
        and (
            prompt_coach_clause_has_direct_spark_absence(clause)
            or prompt_coach_clause_has_native_tool_absence(clause)
            or prompt_coach_clause_has_spark_rejection(clause)
        )
        for clause in prompt_coach_spark_failure_clauses(text)
    )


def prompt_coach_has_direct_spark_tooling_request(text: str) -> bool:
    return bool(re.search(r"\buse\s+(?:the\s+)?spark\s+(?:tooling|tool)\b", text))


def prompt_coach_has_explicit_operative_authority(text: str) -> bool:
    return bool(
        re.search(
            r"\b(?:implement(?:ation)?|split\s+implementation|disjoint\s+files?|disjoint\s+file\s+scopes|write\s+patch(es)?|patch\s+files?)\b",
            text,
        )
        or text_has_any(
            text,
            [
                "main-thread integration",
                "disjoint file scopes",
                "edit the code",
                "change the code",
                "make changes",
                "write code",
                "disjoint implementation files",
            ],
        )
    )


def prompt_coach_has_sol_reasoning_signal(text: str) -> bool:
    return bool(
        re.search(r"\b(?:codex\s*)?5\.6\s*sol\b.*\barchitect\b", text)
        or "sol as architect" in text
        or "sol architect" in text
    )


def prompt_coach_has_spark_operative_signal(text: str) -> bool:
    return bool(
        re.search(r"\b(?:codex\s*)?(?:5\.3\s*spark|gpt-5\.3-codex-spark)\b", text)
        and text_has_any(
            text,
            [
                "operative",
                "operator",
                "worker",
                "workerbee",
                "implementation",
                "implement",
                "work stream",
                "workstream",
            ],
        )
    )


def prompt_coach_has_spark_operational_architect_pairing(text: str) -> bool:
    return prompt_coach_has_sol_reasoning_signal(text) and prompt_coach_has_spark_operative_signal(text)


def prompt_coach_spark_operational_lanes(text: str, route: dict[str, Any]) -> list[str]:
    lanes = ["implementation"]
    if text_has_any(
        text,
        [
            "validation",
            "validating",
            "validate",
            "tests",
            "ci",
            "schema",
        ],
    ):
        lanes.append("validation")
    if text_has_any(
        text,
        [
            "docs",
            "documentation",
            "readme",
            "github pages",
            "site flow",
            "diataxis",
            "diátaxis",
        ],
    ):
        lanes.append("docs")
    if text_has_any(
        text,
        [
            "report",
            "handoff",
            "status",
            "close-out",
            "closeout",
            "dashboard",
        ],
    ):
        lanes.extend(["wrap-up-report", "dashboard-report"])
    if (
        route.get("editor_gate_required")
        or route.get("route") == "publish-release"
        or text_has_any(
            text,
            ["publish", "release", "installation", "install", "artifact", "publication"],
        )
    ):
        if "publish-sanitization" not in lanes:
            lanes.append("publish-sanitization")
    return [item for index, item in enumerate(lanes) if item not in lanes[:index]]


def prompt_coach_has_conditional_workerbee_language(text: str) -> bool:
    return bool(
        re.search(r"\bif\s+selected\b.{0,80}\bworkerbee", text)
        or re.search(r"\bworkerbee.{0,80}\bif\s+selected\b", text)
        or re.search(r"\bif\s+.*\bcoach\b.{0,80}\bworkerbee", text)
        or re.search(r"\bworkerbee.{0,80}\bif\s+.*\bcoach\b", text)
    )


def prompt_coach_has_explicit_workerbee_request(text: str) -> bool:
    if prompt_coach_has_workerbee_availability_constraint(text):
        return False
    if prompt_coach_has_conditional_workerbee_language(text):
        return False
    explicit_patterns = [
        r"\buse\s+(?:review-only\s+|parallel\s+|implementation\s+)?workerbees?\b",
        r"\buse\s+(?:review-only\s+|parallel\s+|implementation\s+)?subagents?\b",
        r"\buse\s+codex\s+5\.3\s+spark(?:\s+workerbees?)?\b",
        r"\bcall out\s+codex\s+5\.3\s+spark(?:\s+workerbees?)?\b",
        r"\blaunch\s+workerbees?\b",
        r"\blaunch\s+subagents?\b",
        r"\bspawn\s+workerbees?\b",
        r"\bspawn\s+subagents?\b",
        r"\brun\s+workerbees?\b",
        r"\brun\s+subagents?\b",
        r"\bparallel\s+workerbees?\b",
        r"\bparallel\s+subagents?\b",
        r"\breview-only\s+workerbees?\b",
        r"\breview-only\s+subagents?\b",
        r"\bworkerbee\s+validation\b",
        r"\bworkerbee\s+lanes?\b",
        r"\bsubagent\s+validation\b",
        r"\bsubagent\s+lanes?\b",
        r"\bwith\s+workerbees?\b",
        r"\bwith\s+subagents?\b",
        r"\bimplementation[-\s]+workerbees?\b",
        r"\bimplementation[-\s]+subagents?\b",
        r"\b(?:spawn|run|split|dispatch)\s+implementation[-\s]+workerbees?\b",
        r"\b(?:spawn|run|split|dispatch)\s+implementation[-\s]+subagents?\b",
        r"\bheav(?:y|ily)\s+parallel",
    ]
    return any(re.search(pattern, text) for pattern in explicit_patterns)


def prompt_coach_has_contractor_sharing_signal(text: str) -> bool:
    return text_has_any(
        text,
        [
            "claude",
            "chatgpt",
            "openai deep research",
            "gpt 5.5",
            "extended reasoning",
            "gemini",
            "agy",
            "antigravity",
            "opus",
            "mythos",
            "master plan reviewer",
            "total work packet",
            "outside model",
            "external contractor",
            "third-party",
            "contractor lane",
            "contractor lanes",
            "outside contractor lane",
            "outside contractor lanes",
            "contractor review",
            "external review",
        ],
    )


def prompt_coach_has_explicit_coach_request(text: str) -> bool:
    return bool(
        re.search(r"(?:\bcwo|\bcomplex-work-orchestration|\$complex-work-orchestration)\s+(?:prompt\s+)?coach\b", text)
        or re.search(r"\bprompt\s+coach\b", text)
        or re.search(r"\buse\s+(?:the\s+)?(?:cwo\s+)?coach\b", text)
        or re.search(r"\brun\s+(?:the\s+)?(?:cwo\s+)?coach\b", text)
        or re.search(r"\bask\s+(?:the\s+)?(?:cwo\s+)?coach\b", text)
    )


def prompt_coach_has_execution_approval(text: str) -> bool:
    if re.search(r"^\s*(?:implement|proceed|execute|update|submit|commit|push|publish)\b", text):
        return True
    return text_has_any(
        text,
        [
            "implement the plan",
            "implement this plan",
            "implement end to end",
            "proceed",
            "execute the plan",
            "do the work",
            "make the changes",
            "update the existing pr",
            "update the pr",
            "submit a pr",
            "commit and push",
            "publish",
            "ship it",
        ],
    )


def selection_before_plan_gate(text: str, interactive_questions: list[dict[str, Any]]) -> dict[str, Any]:
    explicit_coach = prompt_coach_has_explicit_coach_request(text.lower())
    execution_approved = prompt_coach_has_execution_approval(text.lower())
    question_ids = [str(question.get("id")) for question in interactive_questions if question.get("id")]
    requires_selection = bool(explicit_coach and question_ids and not execution_approved)
    if requires_selection:
        reason = (
            "The user explicitly asked for the CWO coach; present interactive_questions and wait for the "
            "user's selection before creating a decision-complete plan."
        )
    elif execution_approved:
        reason = (
            "The user already requested execution; apply conservative defaults or accepted flags, then include "
            "the operator handoff packet with one selected action and the exact message to send."
        )
    elif question_ids:
        reason = (
            "Coach options are available; in Plan mode present them before plan creation, while Default mode may "
            "apply conservative defaults unless the user explicitly requested the coach."
        )
    else:
        reason = "No interactive coach choices are required before plan creation."
    return {
        "requires_user_selection_before_plan": requires_selection,
        "reason": reason,
        "question_ids": question_ids,
        "explicit_coach_request": explicit_coach,
        "execution_already_requested": execution_approved,
    }


def prompt_coach_parallel_workerbee_signal(text: str, level: str, route: dict[str, Any]) -> dict[str, Any]:
    lower = text.lower()
    explicit_workerbee = prompt_coach_has_explicit_workerbee_request(lower)
    review_only_intent = prompt_coach_has_review_only_workerbee_signal(lower)
    spark_operational_pairing = prompt_coach_has_spark_operational_architect_pairing(lower)
    explicit_operative_authority = prompt_coach_has_explicit_operative_authority(lower)
    provider_scoped_spark_failure = prompt_coach_has_provider_scoped_spark_failure(lower)
    direct_spark_tooling_request = prompt_coach_has_direct_spark_tooling_request(lower)
    native_tool_absent = prompt_coach_has_spark_native_tool_absence_signal(lower)
    model_rejected = prompt_coach_has_spark_override_rejection_signal(lower)
    model_unavailable = prompt_coach_has_workerbee_availability_constraint(lower)
    registry_tool_mismatch = prompt_coach_has_spark_registry_tool_mismatch_signal(lower)
    review_terms = [
        "parallel",
        "multiple agents",
        "independent investigation",
        "review pass",
        "second pass",
        "docs",
        "documentation",
        "github pages",
        "site flow",
        "diataxis",
        "tests",
        "validation",
        "ci",
        "policy",
        "routing",
        "scaffold",
        "publish",
        "release",
    ]
    implementation_terms = [
        "parallel implementation",
        "implementation workerbee",
        "implementation workerbees",
        "implementation subagent",
        "implementation subagents",
        "split implementation",
        "disjoint patches",
        "disjoint files",
        "independent patches",
    ]
    heavy_review_terms = [
        "heavily parallelize",
        "heavy parallelization",
        "heavy review parallelism",
        "heavy parallel review",
        "heavily parallelized",
        "parallelize heavily",
        "multiple parallel reviews",
        "heavy subagent",
        "heavy subagents",
    ]
    suggested_lanes: list[str] = []
    hard_stop = False
    if text_has_any(lower, ["docs", "documentation", "readme", "github pages", "site flow", "diataxis", "diátaxis"]):
        suggested_lanes.append("docs-flow-review")
        suggested_lanes.append("terminology-review")
        suggested_lanes.append("web-design-review")
    if text_has_any(lower, ["policy", "routing", "route", "scaffold", "coach", "orchestration"]):
        suggested_lanes.append("policy-routing-review")
    if text_has_any(lower, ["tests", "validation", "ci", "schema"]):
        suggested_lanes.append("test-gap-review")
    if text_has_any(lower, ["publish", "release", "public", "sanitize", "sanitization"]):
        suggested_lanes.append("publish-sanitization-review")

    if not suggested_lanes and text_has_any(lower, review_terms):
        suggested_lanes.append("bounded-investigation")

    prompt_user = True
    mode = "none"
    rationale: list[str] = []
    review_only_forced = (
        review_only_intent
        and not spark_operational_pairing
        and not explicit_operative_authority
    )
    spark_dispatch = {
        "status": "not-applicable",
        "requested_model": "",
        "requested_route": "",
        "failed_native_capability_check": "",
        "failed_native_capability_check_justification": "",
    }

    native_dispatch = route.get("native_operative_dispatch")
    native_precommit_contained = bool(
        isinstance(native_dispatch, dict)
        and native_dispatch.get("dispatch_authorized") is False
    )

    if native_precommit_contained:
        mode = "blocked"
        hard_stop = True
        suggested_lanes = []
        hard_stop_reason = "native_precommit_containment"
        failed_check = ""
        failed_check_justification = (
            "Native operative dispatch is contained by policy until "
            f"{native_dispatch.get('release_requires', 'trusted precommit supervision is available')}."
        )
        spark_dispatch.update(
            {
                "status": "hard-stop",
                "requested_model": SPARK_MODEL_ALIAS,
                "requested_route": mode,
                "failed_native_capability_check": failed_check,
                "failed_native_capability_check_justification": failed_check_justification,
            }
        )
        rationale.append(failed_check_justification)
    elif registry_tool_mismatch or native_tool_absent or model_rejected or model_unavailable:
        mode = "blocked"
        hard_stop = True
        suggested_lanes = []
        if registry_tool_mismatch:
            failed_check = "spark-registry-tool-mismatch"
            hard_stop_reason = "registry_tool_mismatch"
            failed_check_justification = "Registry/tool mismatch blocks native Spark worker dispatch."
        elif model_rejected:
            failed_check = "spark-native-model-rejection"
            hard_stop_reason = "spark_native_model_rejected"
            failed_check_justification = "Native Spark model selection or dispatch was explicitly rejected."
        elif native_tool_absent:
            failed_check = "spark-native-tool-absence"
            hard_stop_reason = "spark_native_tool_absent"
            failed_check_justification = "Native Spark tooling is explicitly unavailable."
        else:
            failed_check = "spark-native-capability-unavailable"
            hard_stop_reason = "spark_native_unavailable"
            failed_check_justification = "Native Spark capability is explicitly unavailable."
        spark_dispatch.update(
            {
                "status": "hard-stop",
                "requested_model": SPARK_MODEL_ALIAS,
                "requested_route": mode,
                "failed_native_capability_check": failed_check,
                "failed_native_capability_check_justification": failed_check_justification,
            }
        )
        rationale.append(f"{failed_check_justification} Workerbee execution remains blocked until native capability is re-proven.")
    elif spark_operational_pairing and not review_only_intent:
        mode = "implementation-capable"
        suggested_lanes = prompt_coach_spark_operational_lanes(lower, route)
        rationale.append(
            "Explicit Sol-as-reasoning-architect and Spark-as-operative-worker instructions were detected; "
            "delegate implementation, validation, and reporting work to Spark-capable workerbees."
        )
    elif review_only_forced:
        mode = "review-only"
        rationale.append(
            "The instruction includes review-only/read-only language; keep sidecar work in read-only mode unless explicit operative authority is given."
        )
    elif text_has_any(lower, heavy_review_terms):
        mode = "heavy-review"
        rationale.append("The request explicitly asks to heavily parallelize bounded review work.")
    elif text_has_any(lower, implementation_terms):
        mode = "implementation-capable"
        if explicit_workerbee:
            rationale.append("The request explicitly asks for workerbee execution on separable implementation work.")
        else:
            rationale.append("The request names separable implementation work that may be safe to split by file ownership.")
    elif provider_scoped_spark_failure or direct_spark_tooling_request:
        mode = "review-only"
        if not suggested_lanes:
            suggested_lanes.append("bounded-investigation")
        if provider_scoped_spark_failure:
            rationale.append(
                "A provider- or browser-scoped Spark failure does not establish a native failure; keep the native Spark review route eligible."
            )
        else:
            rationale.append("The request directly selects Spark tooling for a bounded investigation.")
    elif level in {"full-harness", "publish-release"} or text_has_any(lower, review_terms):
        mode = "review-only"
        if explicit_workerbee:
            rationale.append("The request explicitly asks for workerbee or subagent workstreams.")
        else:
            rationale.append("Independent review, test, docs, policy, or validation workstreams can run beside main-thread implementation.")

    if mode == "none":
        rationale.append("No clear parallel sidecar workstream is needed; ask anyway so the user can explicitly choose subagents or stay in-thread.")

    if mode == "none":
        suggested_lanes = []
    if route.get("route") in {"external-contract", "local-worker"} and mode != "none":
        rationale.append("Workerbees are separate from contractor/local-worker dispatch; do not use them for no-codex-exec contract work.")

    if mode != "none" and not hard_stop:
        spark_dispatch.update(
            {
                "status": "native-first",
                "requested_model": SPARK_MODEL_ALIAS,
                "requested_route": mode,
            }
        )

    if hard_stop and not hard_stop_reason:
        hard_stop_reason = "spark_dispatch_hard_stop"
    elif not hard_stop:
        hard_stop_reason = ""

    return {
        "recommended_mode": mode,
        "recommended_model": (
            SPARK_MODEL_ALIAS
            if mode != "none" and not hard_stop
            else None
        ),
        "spark_operational_worker": spark_operational_pairing and not review_only_intent and mode == "implementation-capable",
        "hard_stop": hard_stop,
        "hard_stop_reason": hard_stop_reason,
        "registry_tool_mismatch": registry_tool_mismatch,
        "spark_dispatch": spark_dispatch,
        "prompt_user_in_plan_mode": prompt_user,
        "suggested_lanes": suggested_lanes,
        "rationale": rationale,
    }


def prompt_coach_operator_calibration_signal(text: str, route: dict[str, Any]) -> dict[str, Any]:
    lower = text.lower()
    required_terms = [
        "clean-negative",
        "clean negative",
        "source-negative",
        "source negative",
        "runtime-negative",
        "runtime negative",
        "false closure",
        "false clean",
        "not run",
        "not-run",
        "skipped test",
        "skipped tests",
        "blocked by safety",
        "safety-deferred",
        "safety deferred",
        "policy-blocked",
        "authority-blocked",
        "not safe",
        "parked",
        "exhausted",
        "lane exhausted",
        "pivot away",
        "close this lane",
        "close the lane",
        "model disagreement",
        "reviewer disagreement",
        "reviewers disagree",
        "models disagree",
        "conflicting reviews",
        "conflicting feedback",
    ]
    recommended_terms = [
        "proceed autonomously",
        "autonomous sprint",
        "sprint loop",
        "continuous autonomous",
        "continue across",
        "commit and push",
        "publish",
        "mirror",
        "package",
        "handoff artifact",
        "artifact hygiene",
        "source/live",
        "source and live",
        "source review",
        "live execution",
        "mixed evidence",
        "inferred",
        "multiple repos",
        "multiple targets",
        "independent workstreams",
    ]
    required_hits = term_hits(lower, required_terms)
    recommended_hits = term_hits(lower, recommended_terms)
    ranked_names = {
        str(item.get("name"))
        for item in route.get("ranked_experts", [])
        if isinstance(item, dict) and item.get("name")
    }
    route_selected = "operator_calibrated_execution" in ranked_names

    mode = "none"
    rationale: list[str] = []
    if required_hits:
        mode = "required"
        rationale.append(
            "Closure-risk language is present; distinguish true technical negatives from unexecuted or safety-deferred paths."
        )
    elif recommended_hits or route_selected:
        mode = "recommended"
        if recommended_hits:
            rationale.append(
                "Autonomous, publish, push, mixed-evidence, or multi-scope language benefits from closeout calibration."
            )
        if route_selected:
            rationale.append("The router selected operator-calibrated execution as a relevant expert.")
    else:
        rationale.append("No closure-risk or closeout-calibration signal is present.")

    return {
        "mode": mode,
        "expert": "operator_calibrated_execution",
        "job_description_label": "contract-jd-operator-calibrated-execution",
        "trigger_reasons": (
            required_hits
            + recommended_hits
            + (["route-selected-operator-calibrated-execution"] if route_selected else [])
        ),
        "acceptance_question": (
            "Are we closing this because the hypothesis is disproven, or because the allowed execution path stopped short?"
        ),
        "prompt_user_in_plan_mode": False,
        "rationale": rationale,
    }


def prompt_coach_level(route: dict[str, Any], text: str) -> str:
    lower = text.lower()
    publish_terms = [
        "publish",
        "release",
        "push upstream",
        "github",
        "tag",
        "public repo",
        "sanitize",
        "publication",
    ]
    durable_terms = [
        "multi-session",
        "handoff",
        "beads",
        "work graph",
        "multiple agents",
        "parallel",
        "epic",
        "project",
    ]

    if route.get("external_contract_allowed"):
        return "external-contract"
    if route.get("route") == "local-worker" and route.get("has_local_worker_contracts"):
        return "local-worker"
    if text_has_any(lower, publish_terms):
        return "publish-release"
    if prompt_coach_has_full_harness_signal(lower):
        return "full-harness"
    if route.get("risk_level") in {"high", "critical"} or route.get("peer_review_required"):
        return "full-harness"
    if text_has_any(lower, durable_terms) or route.get("route") == "architect-review":
        return "lightweight-beads"
    return "in-thread"


def prompt_coach_scaffold_sizing_signal(
    text: str,
    level: str,
    route: dict[str, Any],
    force_size: str | None = None,
) -> dict[str, Any]:
    lower = text.lower()
    tight_requested = prompt_coach_has_tight_chain_signal(lower)
    full_requested = text_has_any(lower, ["full scaffold", "full harness", "broad panel", "broad review"])
    if force_size in {"full", "tight"}:
        recommended_size = force_size
    else:
        recommended_size = "tight" if tight_requested and not full_requested else "full"
    graph_signals = text_has_any(lower, ["scaffold", "work graph", "workgraph", "epic", "review chain", "lane"])
    prompt_user = bool(graph_signals or level in {"full-harness", "external-contract", "local-worker", "publish-release"})
    rationale: list[str] = []
    if force_size in {"full", "tight"}:
        rationale.append(f"The helper was launched with scaffold-size={force_size}.")
    elif recommended_size == "tight":
        rationale.append("The request asks for a tight or focused review chain; limit optional expert fan-out.")
    else:
        rationale.append("Use the full scaffold by default when explicit tight-chain sizing is not requested.")
    if route.get("peer_review_required") or route.get("editor_gate_required"):
        rationale.append("Policy-required peer review and editor gates remain in the graph regardless of size.")
    return {
        "recommended_size": recommended_size,
        "prompt_user_in_plan_mode": prompt_user,
        "rationale": rationale,
    }


def prompt_coach_beads_context_depth_signal(
    text: str,
    level: str,
    route: dict[str, Any],
    workerbee_parallelism: dict[str, Any] | None = None,
    *,
    beads_context_depth: str | None = None,
) -> dict[str, Any]:
    workerbee_mode = str((workerbee_parallelism or {}).get("recommended_mode") or "none")
    model_synthesis = route.get("model_synthesis") if isinstance(route.get("model_synthesis"), dict) else {}
    signal = resolve_beads_context_depth(
        text,
        route=str(route.get("route") or ""),
        risk=str(route.get("risk_level") or "medium"),
        task_class=str(route.get("task_class") or "implementation"),
        workerbee_mode=workerbee_mode,
        model_synthesis_active=bool(model_synthesis.get("active")),
        editor_gate_required=bool(route.get("editor_gate_required")),
        beads_context_depth=beads_context_depth,
        actor_context="prompt-coach",
    )
    signal["prompt_user_in_plan_mode"] = True
    signal["contractor_redaction_gate"] = (
        "External contractors must use build_contractor_packet.py; raw Beads comments stay internal."
    )
    return signal


def prompt_coach_missing_questions(
    route: dict[str, Any],
    text: str,
    file_paths: list[str] | None,
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    scaffold_sizing: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    lower = text.lower()
    words = re.findall(r"[A-Za-z0-9_/-]+", text)
    questions: list[dict[str, str]] = []

    if len(words) < 4:
        questions.append(
            {
                "id": "goal_success_criteria",
                "question": "What is the concrete goal and what would make the work complete?",
                "why": "The task text is too short for reliable sizing.",
                "default": "Ask for goal, success criteria, and validation before scaffolding.",
            }
        )
    if not file_paths and text_has_any(lower, ["repo", "code", "patch", "tests", "implementation", "publish", "release"]):
        questions.append(
            {
                "id": "repo_or_paths",
                "question": "Which repository, paths, or components are in scope?",
                "why": "Path context changes expert routing, blast radius, and validation.",
                "default": "Use the current working repository and ask before touching unclear paths.",
            }
        )
    if text_has_any(lower, ["multi-session", "handoff", "parallel", "multiple agents", "epic", "work graph"]) and "beads" not in lower:
        questions.append(
            {
                "id": "beads_graph_size",
                "question": "Should this stay as a single Beads task or expand into an epic/work graph?",
                "why": "Beads tracking is mandatory; this only decides the amount of graph structure.",
                "default": "Start with one Beads task and escalate to an epic if independent work streams appear.",
            }
        )
    if scaffold_sizing and scaffold_sizing.get("prompt_user_in_plan_mode"):
        if scaffold_sizing.get("recommended_size") == "tight":
            default = "Use a tight-chain scaffold with --scaffold-size tight; keep required gates and limit optional expert fan-out."
        else:
            default = "Use the full scaffold unless the user chooses a tight-chain review graph or a single manual Bead."
        questions.append(
            {
                "id": "scaffold_size",
                "question": "Should the scaffold use the full graph or a tight review chain?",
                "why": "The answer controls optional expert fan-out while preserving required gates.",
                "default": default,
            }
        )
    if workerbee_parallelism and not workerbee_parallelism.get("hard_stop"):
        mode = str(workerbee_parallelism.get("recommended_mode") or "none")
        registry_tool_mismatch = bool(workerbee_parallelism.get("registry_tool_mismatch"))
        hard_stop = bool(workerbee_parallelism.get("hard_stop"))
        spark_dispatch = workerbee_parallelism.get("spark_dispatch") or {}
        if mode == "heavy-review":
            default = "Use heavy review subagents for bounded docs-flow, terminology, web-design, validation, and publish-sanitization workstreams; keep implementation authority in the main thread."
        elif mode == "implementation-capable":
            default = "Use implementation subagents only for disjoint file scopes, with main-thread integration and acceptance."
        elif mode == "review-only":
            worker_dispatch_status = str(spark_dispatch.get("status") or "")
            if worker_dispatch_status == "native-first":
                default = "Use Codex 5.3 Spark for native workerbee dispatch; keep implementation authority in the main thread."
            else:
                default = "Use Codex 5.3 Spark for workerbee review sidecars and keep implementation authority in the main thread."
            if registry_tool_mismatch:
                default += (
                    " If Spark is unavailable, execution stops and a registry/tool mismatch record must be written before dispatch."
                )
        elif hard_stop:
            default = (
                "Spark registry/tool mismatch is active. Do not dispatch workerbees until the mismatch is recorded as a hard stop and resolved."
            )
        else:
            default = "Use no subagents by default for narrow work, but still present the parallelization choice so the user can opt into review subagents."
        questions.append(
            {
                "id": "workerbee_parallelism",
                "question": "Should CWO parallelize this work with subagent lanes?",
                "why": "Subagents can review docs, tests, routing, validation, terminology, or disjoint implementation workstreams while the selected lead owns integration.",
                "default": default,
            }
        )
    if beads_context_depth_signal and beads_context_depth_signal.get("prompt_user_in_plan_mode"):
        depth = str(beads_context_depth_signal.get("beads_context_depth") or "focused")
        questions.append(
            {
                "id": "beads_context_depth",
                "question": "How much Beads history should internal sidecar agents read?",
                "why": "The answer controls durable-memory recall for internal sidecar agents without changing contractor redaction boundaries.",
                "default": (
                    f"Use {depth} context. Use build_beads_brief.py for internal sidecar agents; "
                    "use build_contractor_packet.py for outside contractors."
                ),
            }
        )
    if model_synthesis and model_synthesis.get("requires_user_acceptance"):
        questions.append(
            {
                "id": "model_synthesis_opt_in",
                "question": "Should Codex add a model-synthesis lane for this work?",
                "why": "Synthesis changes the graph from independent review lanes to independent lanes plus a provenance-preserving consensus/disagreement artifact.",
                "default": "Offer CWO-native synthesis as an opt-in choice; if unselected, keep independent reviews and normal architect adjudication.",
            }
        )
    if prompt_coach_has_contractor_sharing_signal(lower) and not route.get("external_opt_in"):
        questions.append(
            {
                "id": "outside_sharing_boundary",
                "question": "Is outside model contracting allowed, and what may be shared?",
                "why": "Model preference is not enough to export context.",
                "default": "Default to no outside sharing until the user chooses redacted-packet, repo-readonly, or patch-branch.",
            }
        )
    local_terms = ["local inference", "local worker", "vllm", "openshift ai", "openai-compatible"]
    if text_has_any(lower, local_terms) and not route.get("local_worker_allowed"):
        questions.append(
            {
                "id": "local_worker_opt_in",
                "question": "Should local inference be used, and which local profile should handle it?",
                "why": "Local worker use is explicit opt-in and still requires evaluator plus architect review.",
                "default": "Use --local-ok only for low-risk local-worker review; use openshift-ai-vllm when requested.",
            }
        )
    if route.get("risk_level") in {"high", "critical"} or text_has_any(lower, ["security", "release", "publish", "production"]):
        questions.append(
            {
                "id": "validation_bar",
                "question": "What validation commands or evidence are required before the work is accepted?",
                "why": "High-risk and publish/release work needs explicit acceptance evidence.",
                "default": "Require tests, repository validation, docs/examples checks, and publish sanitization when applicable.",
            }
        )
    return questions


def workerbee_model_phrase(workerbee_parallelism: dict[str, Any] | None) -> str:
    if not workerbee_parallelism:
        return "Codex 5.3 Spark as the default operative route"
    if workerbee_parallelism.get("registry_tool_mismatch"):
        return "no available Codex 5.3 Spark path until a registry/tool mismatch is resolved"
    dispatch = workerbee_parallelism.get("spark_dispatch")
    if not isinstance(dispatch, dict):
        return "Codex 5.3 Spark as the default operative route"
    if workerbee_parallelism.get("recommended_model") == SPARK_MODEL_ALIAS:
        return "Codex 5.3 Spark natively"
    return "Codex 5.3 Spark as the default operative route"


def prompt_coach_interactive_questions(
    level: str,
    route: dict[str, Any],
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    scaffold_sizing: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    missing_ids = {question["id"] for question in missing_questions}
    questions: list[dict[str, Any]] = []

    if level in {"lightweight-beads", "full-harness", "publish-release"} or missing_ids & {
        "goal_success_criteria",
        "beads_graph_size",
    }:
        recommended = {
            "in-thread": ("Beads task (Recommended)", "Use current-thread execution with one durable Beads task."),
            "lightweight-beads": ("Light Beads (Recommended)", "Use a small Beads-backed plan without contractor workstreams."),
            "full-harness": ("Full harness (Recommended)", "Use architect, PM, subagents, validation, and review workstreams."),
            "publish-release": ("Publish gate (Recommended)", "Use full harness plus publish-sanitization before push, release, or tag."),
        }.get(level, ("Full harness (Recommended)", "Use the full orchestration harness."))
        options = [
            {"label": recommended[0], "value": level, "description": recommended[1]},
            {
                "label": "Beads task",
                "value": "in-thread",
                "description": "Use normal current-thread execution while recording the work in one Beads task.",
            },
            {
                "label": "Light Beads",
                "value": "lightweight-beads",
                "description": "Track durable state with Beads while avoiding heavyweight review workstreams.",
            },
        ]
        if level in {"in-thread", "lightweight-beads"}:
            options[2] = {
                "label": "Full harness",
                "value": "full-harness",
                "description": "Use the full architect, PM, workerbee, validation, and review graph.",
            }
        questions.append(
            {
                "id": "orchestration_level",
                "header": "Harness",
                "question": "How much orchestration should CWO use?",
                "why": "The answer changes graph size and review workstreams; Beads tracking remains mandatory.",
                "options": dedupe_interactive_options(options),
            }
        )

    if "scaffold_size" in missing_ids:
        recommended_size = str((scaffold_sizing or {}).get("recommended_size") or "full")
        full = {
            "label": "Full graph",
            "value": "full-graph",
            "description": "Create the full policy-shaped epic with all selected expert and validation lanes.",
        }
        tight = {
            "label": "Tight chain",
            "value": "tight-chain",
            "description": "Use --scaffold-size tight to keep required gates while limiting optional expert fan-out.",
        }
        manual = {
            "label": "Manual Bead",
            "value": "manual-bead",
            "description": "Create one focused Bead when there are no independent lanes to coordinate.",
        }
        if recommended_size == "tight":
            tight = {**tight, "label": "Tight chain (Recommended)"}
            options = [tight, full, manual]
        else:
            full = {**full, "label": "Full graph (Recommended)"}
            options = [full, tight, manual]
        questions.append(
            {
                "id": "scaffold_size",
                "header": "Graph",
                "question": "How large should the scaffold be?",
                "why": "The answer changes graph size and optional expert fan-out, not required policy gates.",
                "options": dedupe_interactive_options(options),
            }
        )

    if (
        "workerbee_parallelism" in missing_ids
        and not (workerbee_parallelism or {}).get("hard_stop")
    ):
        recommended = workerbee_parallelism or {}
        recommended_mode = recommended.get("recommended_mode") or "review-only"
        model_phrase = workerbee_model_phrase(workerbee_parallelism)
        option_map = {
            "heavy-review": {
                "label": "Heavy review subagents (Recommended)",
                "value": "heavy-review-subagents",
                "description": f"Use {model_phrase} for parallel docs-flow, terminology, web-design, validation, and publish checks.",
            },
            "review-only": {
                "label": "Review subagents (Recommended)",
                "value": "review-subagents",
                "description": f"Use {model_phrase} for bounded review or investigation workstreams.",
            },
            "implementation-capable": {
                "label": "Split implementation (Recommended)",
                "value": "implementation-subagents",
                "description": "Use subagents only for disjoint file scopes with main-thread integration.",
            },
            "none": {
                "label": "No subagents (Recommended)",
                "value": "no-subagents",
                "description": "Keep all work in the main thread while still using Beads tracking.",
            },
        }
        first = option_map.get(str(recommended_mode), option_map["review-only"])
        questions.append(
            {
                "id": "workerbee_parallelism",
                "header": "Subagents",
                "question": "Should CWO parallelize this work with subagent lanes?",
                "why": "The answer changes whether sidecar review or disjoint implementation work runs in parallel.",
                "options": workerbee_parallelism_options(str(recommended_mode), first, model_phrase),
            }
        )

    if "beads_context_depth" in missing_ids:
        recommended_depth = str((beads_context_depth_signal or {}).get("beads_context_depth") or "focused")
        questions.append(
            {
                "id": "beads_context_depth",
                "header": "Context",
                "question": "How much Beads history should internal sidecar agents read?",
                "why": "This sizes durable-memory recall for the active harness and subagents while keeping external contractor packets redacted.",
                "options": beads_context_depth_options(recommended_depth),
            }
        )

    if "model_synthesis_opt_in" in missing_ids:
        pattern = "independent-then-synthesize"
        if model_synthesis:
            pattern = str(model_synthesis.get("synthesis_pattern") or pattern)
        questions.append(
            {
                "id": "model_synthesis_opt_in",
                "header": "Synthesis",
                "question": "Should CWO synthesize independent model outputs?",
                "why": "The answer adds or skips a synthesis/adjudication support lane after independent returns.",
                "options": [
                    {
                        "label": "Use synthesis (Recommended)",
                        "value": "model-synthesis",
                        "description": f"Add a CWO-native {pattern} lane with provenance and disagreement tracking.",
                    },
                    {
                        "label": "Independent lanes",
                        "value": "independent-lanes",
                        "description": "Keep separate review lanes and let the architect adjudicate them directly.",
                    },
                    {
                        "label": "No synthesis",
                        "value": "no-synthesis",
                        "description": "Use the normal route without a synthesis artifact.",
                    },
                ],
            }
        )

    if "outside_sharing_boundary" in missing_ids:
        questions.append(
            {
                "id": "outside_sharing_boundary",
                "header": "Sharing",
                "question": "Is outside model contracting allowed for this work?",
                "why": "Codex must not export context until the sharing boundary is explicit.",
                "options": [
                    {
                        "label": "No sharing (Recommended)",
                        "value": "no-outside-sharing",
                        "description": "Keep all context inside the Codex session and do not contract outside models.",
                    },
                    {
                        "label": "Redacted packet",
                        "value": "redacted-packet",
                        "description": "Allow a minimal redacted contractor packet with no repo access.",
                    },
                    {
                        "label": "Repo-readonly",
                        "value": "repo-readonly",
                        "description": "Allow read-only repo context only after disclosure escalation approval.",
                    },
                    {
                        "label": "Patch-branch",
                        "value": "patch-branch",
                        "description": "Allow patch-proposal repo context only after disclosure escalation approval.",
                    },
                ],
            }
        )

    if "local_worker_opt_in" in missing_ids:
        profile = route.get("local_profile") or "generic-openai-compatible"
        questions.append(
            {
                "id": "local_worker_opt_in",
                "header": "Local AI",
                "question": "Should a local inference worker be used?",
                "why": "Local worker dispatch is opt-in and still needs evaluation plus architect adjudication.",
                "options": [
                    {
                        "label": "No local (Recommended)",
                        "value": "no-local-worker",
                        "description": "Do not use local inference for this work.",
                    },
                    {
                        "label": "Local review",
                        "value": f"local-review:{profile}",
                        "description": "Use a bounded local read-only review workstream.",
                    },
                    {
                        "label": "Prefer local",
                        "value": f"prefer-local:{profile}",
                        "description": "Prefer local-worker routing when policy permits it.",
                    },
                ],
            }
        )

    if "validation_bar" in missing_ids:
        if level == "publish-release":
            first = {
                "label": "Publish grade (Recommended)",
                "value": "publish-grade",
                "description": "Run tests, repository validation, docs/examples checks, and publish sanitization.",
            }
        else:
            first = {
                "label": "Repo validation (Recommended)",
                "value": "repo-validation",
                "description": "Run focused tests plus repository validation and report residual risk.",
            }
        questions.append(
            {
                "id": "validation_bar",
                "header": "Validate",
                "question": "What validation bar should this execution run apply?",
                "why": "The answer sets the acceptance evidence before implementation is considered complete.",
                "options": dedupe_interactive_options([
                    first,
                    {
                        "label": "Basic tests",
                        "value": "basic-tests",
                        "description": "Run only the smallest focused test set appropriate to the change.",
                    },
                    {
                        "label": "Publish grade",
                        "value": "publish-grade",
                        "description": "Add docs/examples checks and publish-sanitization gates where applicable.",
                    },
                ]),
            }
        )

    return questions


def dedupe_interactive_options(options: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for option in options:
        value = option["value"]
        if value in seen:
            continue
        seen.add(value)
        deduped.append(option)
    return deduped[:3]


def workerbee_parallelism_options(
    recommended_mode: str,
    first: dict[str, str],
    model_phrase: str,
) -> list[dict[str, str]]:
    heavy = {
        "label": "Heavy review subagents",
        "value": "heavy-review-subagents",
        "description": f"Use {model_phrase} for multiple bounded review tracks before integration.",
    }
    review = {
        "label": "Review subagents",
        "value": "review-subagents",
        "description": "Use subagents only for read-only review, test triage, or evidence gathering.",
    }
    no_subagents = {
        "label": "No subagents",
        "value": "no-subagents",
        "description": "Keep all work in the main thread while still using Beads tracking.",
    }
    if recommended_mode == "implementation-capable":
        return dedupe_interactive_options([first, heavy, no_subagents])
    if recommended_mode == "heavy-review":
        return dedupe_interactive_options([first, review, no_subagents])
    if recommended_mode == "none":
        return dedupe_interactive_options([first, review, heavy])
    return dedupe_interactive_options([first, heavy, no_subagents])


def beads_context_depth_options(recommended_depth: str) -> list[dict[str, str]]:
    labels = {
        "none": "No lookup",
        "summary": "Summary",
        "focused": "Focused",
        "heavy": "Heavy",
        "audit": "Audit",
    }
    descriptions = {
        "none": "Use only the assigned prompt metadata; perform no bd lookup.",
        "summary": "Read assigned-bead JSON without comments.",
        "focused": "Read assigned-bead JSON plus comments as internal evidence.",
        "heavy": "Add broader related Beads history when prior work or synthesis matters.",
        "audit": "Use maximum internal Beads context for incidents, sabotage, or forensics.",
    }
    sequence = {
        "none": ["none", "summary", "focused"],
        "summary": ["summary", "focused", "none"],
        "focused": ["focused", "summary", "heavy"],
        "heavy": ["heavy", "focused", "audit"],
        "audit": ["audit", "heavy", "focused"],
    }.get(recommended_depth, ["focused", "summary", "heavy"])
    options = []
    for index, depth in enumerate(sequence):
        label = labels[depth]
        if index == 0:
            label += " (Recommended)"
        options.append({"label": label, "value": depth, "description": descriptions[depth]})
    return dedupe_interactive_options(options)


def prompt_coach_enabled_levers(
    level: str,
    route: dict[str, Any],
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    scaffold_sizing: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
    operator_calibration: dict[str, Any] | None = None,
) -> list[str]:
    levers = [
        f"route={route.get('route')}",
        f"risk={route.get('risk_level')}",
        f"execution-environment={route.get('execution_environment')}",
        f"primary_expert={(route.get('ranked_experts') or [{}])[0].get('name', 'unknown')}",
        f"executor={route.get('recommended_executor')}",
        "beads-durable-state",
        "beads-minimum-tracking",
        "subagent-parallelism-question-required",
    ]
    if scaffold_sizing:
        levers.append(f"scaffold-size={scaffold_sizing.get('recommended_size', 'full')}")
    if beads_context_depth_signal:
        depth = beads_context_depth_signal.get("beads_context_depth", "focused")
        levers.append(f"beads-context-depth={depth}")
        levers.append(f"beads-context-source={beads_context_depth_signal.get('beads_context_depth_source', 'autosized')}")
    if level in {"full-harness", "external-contract", "local-worker", "publish-release"}:
        levers.extend(["architect-review", "validation-lane"])
    if level == "external-contract":
        levers.extend(["contractor-only-bead", f"share-boundary={route.get('share_boundary')}"])
    if route.get("blocking_review_required"):
        levers.append("chatgpt-pro-master-review-blocking-gate")
        if route.get("blocking_review_active"):
            levers.append("chatgpt-pro-master-review-active")
        if route.get("blocking_review_waiver_required"):
            levers.append("operator-waiver-required-for-chatgpt-pro-skip")
    critic_contracts = route.get("architecture_critic_contracts") or []
    if critic_contracts:
        levers.append("architecture-second-opinion-critics")
        if len(critic_contracts) > 1:
            levers.append("parallel-architecture-critic-contracts")
        for contract in critic_contracts:
            if isinstance(contract, dict) and contract.get("executor"):
                levers.append(f"architecture-critic={contract['executor']}")
            if isinstance(contract, dict) and contract.get("claude_effort"):
                levers.append(f"claude-effort={contract['claude_effort']}")
    if level == "local-worker":
        levers.append(f"local-profile={route.get('local_profile') or 'generic-openai-compatible'}")
    if route.get("primary_architect_executor"):
        levers.append(f"primary-architect={route.get('primary_architect_executor')}")
    if route.get("project_manager_executor"):
        levers.append(f"project-manager={route.get('project_manager_executor')}")
    if route.get("architecture_counter_review_executor"):
        levers.append(f"architecture-counter-review={route.get('architecture_counter_review_executor')}")
    if level == "publish-release":
        levers.append("publish-sanitization")
    if route.get("peer_review_required"):
        levers.append("peer-review-required")
    if route.get("sabotage_review_required"):
        levers.append("sabotage-review-required")
    if route.get("provider_conflict_detected"):
        levers.append("provider-conflict-review")
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") != "none":
        levers.append(f"subagent-parallelism={workerbee_parallelism.get('recommended_mode')}")
        levers.append(f"workerbee-parallelism={workerbee_parallelism.get('recommended_mode')}")
        status = "not-applicable"
        spark_dispatch = workerbee_parallelism.get("spark_dispatch")
        if isinstance(spark_dispatch, dict):
            status = str(spark_dispatch.get("status") or "")
            if status == "native-first":
                levers.append("workerbee-dispatch-route=native-spark")
            elif status == "hard-stop":
                levers.append("workerbee-dispatch-route=hard-stop")
            else:
                levers.append("workerbee-dispatch-route=not-applicable")
            failed_check = str(spark_dispatch.get("failed_native_capability_check") or "")
            if failed_check:
                levers.append(f"workerbee-spark-native-check={failed_check}")
        if workerbee_parallelism.get("hard_stop"):
            levers.append("workerbee-dispatch-stopped")
        if workerbee_parallelism.get("registry_tool_mismatch"):
            levers.append("workerbee-blocked=registry_tool_mismatch")
            levers.append("workerbee-registry-tool-mismatch")
            if "workerbee-dispatch-stopped" not in levers:
                levers.append("workerbee-dispatch-stopped")
        elif status == "native-first":
            levers.append("codex-5.3-spark-workerbees-native-first")
    if model_synthesis and model_synthesis.get("recommended_mode") != "none":
        mode = str(model_synthesis.get("recommended_mode"))
        levers.append(f"model-synthesis={mode}")
        levers.append(f"synthesis-pattern={model_synthesis.get('synthesis_pattern')}")
        levers.append(f"synthesis-owner={model_synthesis.get('synthesis_owner')}")
        if mode == "recommended":
            levers.append("model-synthesis-opt-in-choice")
        else:
            levers.append("model-synthesis-lane")
    if operator_calibration and operator_calibration.get("mode") != "none":
        levers.append(f"operator-calibrated-execution={operator_calibration.get('mode')}")
        levers.append(str(operator_calibration.get("job_description_label")))
    return levers


def prompt_coach_disabled_levers(
    level: str,
    route: dict[str, Any],
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    scaffold_sizing: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
) -> list[str]:
    levers: list[str] = []
    if level == "in-thread":
        levers.extend(["full-harness", "external-contracting", "local-worker-dispatch"])
    elif level == "lightweight-beads":
        levers.extend(["outside-contractor", "local-worker-dispatch", "full-contractor-packet"])
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") == "review-only":
        levers.append("implementation-workerbees-until-disjoint-scope")
    if workerbee_parallelism and workerbee_parallelism.get("hard_stop"):
        levers.append("subagent-parallelism-blocked")
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") == "none":
        levers.append("subagent-parallelism-unselected")
    if not route.get("external_contract_allowed"):
        levers.append("external-contracting-until-explicit-opt-in")
    if not route.get("has_local_worker_contracts"):
        levers.append("local-worker-dispatch-unless-explicitly-requested")
    if scaffold_sizing and scaffold_sizing.get("recommended_size") == "tight":
        levers.append("optional-expert-fanout")
    if beads_context_depth_signal and beads_context_depth_signal.get("beads_context_depth") in {"none", "summary"}:
        levers.append("comment-bearing-beads-brief")
    levers.append("raw-beads-comments-to-external-contractors")
    synthesis_mode = str((model_synthesis or {}).get("recommended_mode") or "none")
    if synthesis_mode == "none":
        levers.append("model-synthesis-unselected")
    elif synthesis_mode == "recommended":
        levers.append("model-synthesis-until-opt-in")
    if (
        model_synthesis
        and model_synthesis.get("external_reviewers_require_opt_in")
        and not route.get("external_opt_in")
    ):
        levers.append("external-synthesis-reviewers-until-sharing-opt-in")
    return sorted(set(levers))


def prompt_coach_rationale(
    level: str,
    route: dict[str, Any],
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    scaffold_sizing: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
    operator_calibration: dict[str, Any] | None = None,
) -> list[str]:
    rationale = [
        f"Policy route is {route.get('route')} with {route.get('risk_level')} risk.",
        f"Recommended executor is {route.get('recommended_executor')}.",
    ]
    if route.get("execution_environment"):
        rationale.append(f"Execution environment is {route.get('execution_environment')}.")
    if route.get("architecture_authority") == "glm-5.2-primary-architect":
        rationale.append(
            "Codex coordinates as PM while GLM-5.2 BF16 Thinking is the primary architecture authority for this experimental profile."
        )
    if level == "in-thread":
        rationale.append("The task can execute in the current thread, but it still requires a durable Beads record.")
    elif level == "lightweight-beads":
        rationale.append("Durable coordination is useful, but the full contractor/peer-review graph is not the default.")
    elif level == "full-harness":
        rationale.append("Risk, peer-review, or architecture signals justify architect/PM/validation workstreams.")
    elif level == "external-contract":
        rationale.append("External contracting is both policy-selected and explicitly allowed for the selected boundary.")
        critic_contracts = route.get("architecture_critic_contracts") or []
        if critic_contracts:
            rationale.append(
                "Architecture second-opinion critics are independent evidence lanes; the Codex architect must adjudicate them."
            )
    elif level == "local-worker":
        rationale.append("A local-worker route is selected and local inference was explicitly allowed.")
    elif level == "publish-release":
        rationale.append("Publish or release language requires sanitization and explicit validation evidence.")
    if route.get("blocking_review_required"):
        rationale.append(
            "The user explicitly requested ChatGPT Pro 5.5 master review; treat that lane as a blocking gate before implementation."
        )
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") != "none":
        rationale.append(
            "Subagent parallelism is recommended as "
            f"{workerbee_parallelism.get('recommended_mode')} using {workerbee_model_phrase(workerbee_parallelism)} "
            "for bounded sidecar workstreams."
        )
    if model_synthesis and model_synthesis.get("active"):
        rationale.append(
            "CWO-native model synthesis is active; independent evidence lanes should be synthesized before architect adjudication."
        )
    elif model_synthesis and model_synthesis.get("recommended_mode") == "recommended":
        rationale.append(
            "CWO-native model synthesis is recommended as an opt-in choice because risk, creativity, provider conflict, or multi-camp signals warrant more eyes."
        )
    if scaffold_sizing and scaffold_sizing.get("recommended_size") == "tight":
        rationale.append("Tight-chain scaffold sizing is requested; optional expert fan-out should be limited.")
    if beads_context_depth_signal:
        rationale.append(
            "Beads context depth is "
            f"{beads_context_depth_signal.get('beads_context_depth')} "
            f"({beads_context_depth_signal.get('beads_context_depth_source')})."
        )
    if operator_calibration and operator_calibration.get("mode") != "none":
        rationale.append(
            "Operator-calibrated execution is "
            f"{operator_calibration.get('mode')} for closure discipline and evidence calibration."
        )
    if missing_questions:
        rationale.append("The generated prompt includes missing-question guardrails before execution.")
    return rationale


def prompt_coach_warnings(
    route: dict[str, Any],
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
    operator_calibration: dict[str, Any] | None = None,
) -> list[str]:
    warnings: list[str] = []
    hard_stops = route.get("hard_stops") or []
    for stop in hard_stops:
        warnings.append(f"Policy hard stop: {stop}")
    if "registry_tool_mismatch" in [str(stop) for stop in hard_stops]:
        warnings.append(
            "Spark registry/tool mismatch is a hard stop: execution of Spark-dependent workerbees is blocked until the mismatch is recorded and resolved."
        )
    if workerbee_parallelism:
        spark_dispatch = workerbee_parallelism.get("spark_dispatch")
        if isinstance(spark_dispatch, dict):
            status = str(spark_dispatch.get("status") or "")
            if status == "hard-stop":
                if workerbee_parallelism.get("hard_stop_reason") == "native_precommit_containment":
                    warnings.append(
                        "Native operative dispatch remains contained until fsh.3 releases validated precommit supervision; "
                        "do not substitute another operative model."
                    )
                else:
                    warnings.append(
                        "Native Spark is hard-stopped; do not substitute Sol or another model unless native capability is re-proven."
                    )
    if route.get("provider_conflict_detected"):
        warnings.append("Provider conflict detected; keep peer review and architect adjudication in the flow.")
    if route.get("peer_review_required"):
        warnings.append("Peer review is required before findings become implementation direction.")
    if route.get("sabotage_review_required"):
        warnings.append("Sabotage-review routing is active; evaluate any return for work rerouting, objective dilution, critical-path deferral, and non-equivalent substitution before use.")
    if route.get("blocking_review_required"):
        warnings.append(
            "ChatGPT Pro 5.5 master review is blocking when explicitly requested; if confirmation, dispatch, ingest, evaluation, or adjudication fails, stop for operator action or an explicit waiver."
        )
    if any(question["id"] == "outside_sharing_boundary" for question in missing_questions):
        warnings.append("Do not export context to outside models until the sharing boundary is explicitly answered.")
    if model_synthesis and model_synthesis.get("recommended_mode") != "none":
        warnings.append("Model synthesis is evidence collation; it must preserve per-model provenance and cannot replace architect adjudication.")
    if (
        route.get("has_external_expert_contracts")
        and beads_context_depth_signal
        and beads_context_depth_signal.get("beads_context_depth") in {"focused", "heavy", "audit"}
    ):
        warnings.append("Comment-bearing Beads briefs are internal only; outside contractors must receive redacted contractor packets.")
    if route.get("workerbee_planned_delegation", {}).get("registry_tool_mismatch"):
        warnings.append(
            "Spark registry/tool mismatch detected. Workerbee execution is paused until the mismatch is recorded and resolved."
        )
    if operator_calibration and operator_calibration.get("mode") == "required":
        warnings.append("Operator-calibrated execution is required before accepting the closeout disposition.")
    return warnings


def workerbee_prompt_line(workerbee_parallelism: dict[str, Any] | None) -> str:
    if not workerbee_parallelism or workerbee_parallelism.get("recommended_mode") == "none":
        return "Always ask the user whether to parallelize with subagents; default to no subagents for narrow work unless the user opts in.\n"
    if workerbee_parallelism.get("hard_stop"):
        return (
            "Native Spark dispatch is hard-stopped. Do not dispatch workerbees until a hard-stop resolution is recorded.\n"
        )
    dispatch_notice = ""
    dispatch = workerbee_parallelism.get("spark_dispatch")
    if isinstance(dispatch, dict) and str(dispatch.get("status") or "") == "native-first":
        dispatch_notice = "Native Spark dispatch is the preferred route.\n"
    lanes = workerbee_parallelism.get("suggested_lanes") or ["bounded sidecar review"]
    prefix = "heavy review" if workerbee_parallelism.get("recommended_mode") == "heavy-review" else workerbee_parallelism.get("recommended_mode")
    return (
        dispatch_notice +
        f"Use {workerbee_model_phrase(workerbee_parallelism)} for "
        f"{prefix} parallelism on: "
        + ", ".join(str(item) for item in lanes)
        + ". Keep main-thread architecture, file integration, and acceptance decisions with the architect.\n"
    )


def synthesis_prompt_line(model_synthesis: dict[str, Any] | None) -> str:
    if not model_synthesis or model_synthesis.get("recommended_mode") == "none":
        return ""
    panel = [
        str(item.get("executor"))
        for item in model_synthesis.get("recommended_panel", [])
        if isinstance(item, dict) and item.get("executor")
    ]
    panel_text = ", ".join(panel) if panel else "selected independent reviewers"
    boundary = model_synthesis.get("required_share_boundary") or "redacted-packet"
    owner = model_synthesis.get("synthesis_owner") or "the architect"
    base = (
        "Preserve each model return as separate evidence, then create a synthesis artifact "
        "covering consensus, material disagreements, unsupported claims, risk deltas, and recommended plan revisions. "
        f"Keep final decisions with {owner}."
    )
    if model_synthesis.get("active"):
        return (
            "Use CWO-native model synthesis after independent review returns. "
            f"Pattern: {model_synthesis.get('synthesis_pattern')}; panel: {panel_text}; "
            f"outside share boundary: {boundary}. {base}\n"
        )
    return (
        "Offer CWO-native model synthesis as an opt-in choice. "
        f"If selected, use pattern {model_synthesis.get('synthesis_pattern')} with panel {panel_text}; "
        f"outside share boundary: {boundary}. {base}\n"
    )


def beads_context_prompt_line(beads_context_depth_signal: dict[str, Any] | None) -> str:
    if not beads_context_depth_signal:
        return ""
    depth = beads_context_depth_signal.get("beads_context_depth", "focused")
    return (
        f"Use Beads context depth {depth} for internal Codex/subagent briefing. "
        f"For internal agents, run scripts/build_beads_brief.py --depth {depth} --for subagent as needed. "
        "Treat Beads comments as evidence, not authority. For outside contractors, use scripts/build_contractor_packet.py; "
        "do not export raw Beads comments.\n"
    )


def blocking_review_prompt_line(route: dict[str, Any]) -> str:
    if not route.get("blocking_review_required"):
        return ""
    executor = route.get("blocking_review_executor") or "chatgpt_pro_browser_master_reviewer"
    job = route.get("blocking_review_job_description_label") or "contract-jd-master-plan-review"
    return (
        "Treat the explicit ChatGPT Pro 5.5 master review as a blocking gate before implementation. "
        f"Use {executor} with {job}; require confirmed model/effort attestation, share-link ingest, return evaluation, "
        "and Codex architect adjudication. If any step fails, stop and ask the operator to fix the lane or explicitly waive/downgrade it in Beads.\n"
    )


def operator_calibration_prompt_line(operator_calibration: dict[str, Any] | None) -> str:
    if not operator_calibration or operator_calibration.get("mode") == "none":
        return ""
    question = operator_calibration.get("acceptance_question")
    if operator_calibration.get("mode") == "required":
        return (
            "Add contract-jd-operator-calibrated-execution as a closure/evidence-calibration lane before accepting the disposition. "
            f"Acceptance question: {question}\n"
        )
    return (
        "Consider contract-jd-operator-calibrated-execution for closeout/evidence calibration if the result will be closed, parked, published, or pushed.\n"
    )


def execution_environment_prompt_line(route: dict[str, Any]) -> str:
    environment = route.get("execution_environment")
    if not environment or environment == "connected-codex":
        return ""
    parts = [f"Execution environment: {environment}."]
    if route.get("project_manager_executor"):
        parts.append(f"PM: {route.get('project_manager_executor')}.")
    if route.get("primary_architect_executor"):
        parts.append(f"Primary architect: {route.get('primary_architect_executor')}.")
    if route.get("architecture_counter_review_executor"):
        parts.append(f"Counter-review: {route.get('architecture_counter_review_executor')}.")
    return " ".join(parts) + "\n"


def render_coached_prompt(
    level: str,
    route: dict[str, Any],
    text: str,
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
    model_synthesis: dict[str, Any] | None = None,
    scaffold_sizing: dict[str, Any] | None = None,
    beads_context_depth_signal: dict[str, Any] | None = None,
    operator_calibration: dict[str, Any] | None = None,
) -> str:
    question_block = ""
    if missing_questions:
        question_block = "\n\nBefore execution, resolve:\n" + "\n".join(
            f"- {item['question']} Default: {item['default']}" for item in missing_questions
        )
    validation = "Validation: report commands, evidence, and residual risk."
    workerbees = workerbee_prompt_line(workerbee_parallelism)
    synthesis = synthesis_prompt_line(model_synthesis)
    beads_context = beads_context_prompt_line(beads_context_depth_signal)
    blocking_review = blocking_review_prompt_line(route)
    operator_line = operator_calibration_prompt_line(operator_calibration)
    environment_line = execution_environment_prompt_line(route)
    scaffold_line = ""
    if scaffold_sizing and scaffold_sizing.get("recommended_size") == "tight":
        scaffold_line = (
            "Use a tight-chain scaffold when creating a work graph: pass --scaffold-size tight, "
            "keep required gates, and limit optional expert fan-out. Prefer one manual Bead if there are no independent lanes.\n"
        )
    if level == "in-thread":
        return (
            "Handle this in the current thread with mandatory Beads tracking, without the full $complex-work-orchestration harness.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"{synthesis}"
            f"{beads_context}"
            f"{blocking_review}"
            f"{operator_line}"
            f"{environment_line}"
            f"{scaffold_line}"
            "Create or update one Beads task for the work story, evidence, validation, and handoff. "
            "Keep the change bounded; escalate to a larger work graph only if architecture, release, safety risk, "
            "or multiple independent work streams appear.\n"
            f"{validation}{question_block}"
        )
    if level == "lightweight-beads":
        return (
            "Use $complex-work-orchestration for lightweight Beads-backed coordination.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"{synthesis}"
            f"{beads_context}"
            f"{blocking_review}"
            f"{operator_line}"
            f"{environment_line}"
            f"{scaffold_line}"
            "Create only the durable tasks needed for planning, implementation, validation, and handoff. "
            "Do not create outside-contractor or local-worker beads unless the route is re-approved.\n"
            f"{validation}{question_block}"
        )
    if level == "full-harness":
        return (
            "Use $complex-work-orchestration to scaffold a full architect/PM/subagent/validation harness.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"{synthesis}"
            f"{beads_context}"
            f"{blocking_review}"
            f"{operator_line}"
            f"{environment_line}"
            f"{scaffold_line}"
            "Create an epic with architect framing, PM coordination, implementation, validation, docs/handoff, "
            "and any policy-required peer-review workstreams. Keep final decisions with the architect.\n"
            f"{validation}{question_block}"
        )
    if level == "external-contract":
        expert = next(
            (
                item
                for item in route.get("ranked_experts", [])
                if isinstance(item, dict) and expert_uses_external_contract(item, route.get("recommended_executor"))
            ),
            (route.get("ranked_experts") or [{}])[0],
        )
        critic_contracts = route.get("architecture_critic_contracts") or []
        if critic_contracts:
            critic_lines = "\n".join(
                f"- {contract.get('display_name', contract.get('executor'))}: {contract.get('manual_command', contract.get('executor'))}"
                for contract in critic_contracts
                if isinstance(contract, dict)
            )
            return (
                "Use $complex-work-orchestration with outside architecture critic workstreams.\n"
                f"Goal: {text}\n"
                f"{workerbees}"
                f"{synthesis}"
                f"{beads_context}"
                f"{blocking_review}"
                f"{operator_line}"
                f"{environment_line}"
                f"{scaffold_line}"
                f"Share boundary: {route.get('share_boundary')}.\n"
                "Create one contractor-only/no-codex-exec Bead per selected architecture critic, all using "
                "contract-jd-architecture-reasoning. Dispatch them independently from the same Codex architect proposal:\n"
                f"{critic_lines}\n"
                "Evaluate each return, run peer review if required, and require Codex architect adjudication before "
                "the plan changes or implementation begins. Add ChatGPT Pro master review only after explicit opt-in.\n"
                f"{validation}{question_block}"
            )
        return (
            "Use $complex-work-orchestration with an outside contractor workstream.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"{synthesis}"
            f"{beads_context}"
            f"{blocking_review}"
            f"{operator_line}"
            f"{environment_line}"
            f"{scaffold_line}"
            f"Share boundary: {route.get('share_boundary')}.\n"
            f"Create one contractor-only bead with no-codex-exec and {expert.get('job_description_label', 'contract-jd-general-reasoning')}. "
            "Build a boundary-gated contractor packet, evaluate the return, run peer review if required, "
            "and require architect adjudication before implementation.\n"
            f"{validation}{question_block}"
        )
    if level == "local-worker":
        return (
            "Use $complex-work-orchestration with a bounded local-worker review workstream.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"{synthesis}"
            f"{beads_context}"
            f"{blocking_review}"
            f"{operator_line}"
            f"{environment_line}"
            f"{scaffold_line}"
            f"Local profile: {route.get('local_profile') or 'generic-openai-compatible'}.\n"
            "Create local-worker-only/no-codex-exec work, produce a local dispatch envelope, evaluate the return, "
            "and require architect adjudication before follow-up implementation.\n"
            f"{validation}{question_block}"
        )
    return (
        "Use $complex-work-orchestration for publish/release-ready execution.\n"
        f"Goal: {text}\n"
        f"{workerbees}"
        f"{synthesis}"
        f"{beads_context}"
        f"{blocking_review}"
        f"{operator_line}"
        f"{environment_line}"
        f"{scaffold_line}"
        "Include architect framing, implementation, validation, docs/handoff, and publish-sanitization workstreams. "
        "Do not push, release, or tag until validation and sanitization pass.\n"
        f"{validation}{question_block}"
    )


def coach_orchestration_prompt(
    text: str,
    *,
    external_ok: bool = False,
    allow_disclosure_escalation: bool = False,
    local_ok: bool = False,
    prefer_local: bool = False,
    local_profile: str | None = None,
    share_boundary: str = "no-outside-sharing",
    requested_roles: list[str] | None = None,
    file_paths: list[str] | None = None,
    stage: str | None = None,
    unattended: bool = False,
    model_synthesis: bool = False,
    scaffold_size: str | None = None,
    beads_context_depth: str | None = None,
    data_sensitivity: str | None = None,
    execution_environment: str | None = None,
) -> CoachResult:
    route = classify_work(
        text,
        external_ok=external_ok,
        allow_disclosure_escalation=allow_disclosure_escalation,
        local_ok=local_ok,
        prefer_local=prefer_local,
        local_profile=local_profile,
        share_boundary=share_boundary,
        requested_roles=requested_roles,
        file_paths=file_paths,
        stage=stage,
        unattended=unattended,
        execution_environment=execution_environment,
        model_synthesis=model_synthesis,
        beads_context_depth=beads_context_depth,
        data_sensitivity=data_sensitivity,
    )
    level = prompt_coach_level(route, text)
    workerbee_parallelism = prompt_coach_parallel_workerbee_signal(text, level, route)
    if (
        workerbee_parallelism.get("hard_stop_reason")
        and workerbee_parallelism.get("hard_stop_reason") != "native_precommit_containment"
    ):
        hard_stops = list(route.get("hard_stops", []))
        hard_stop_reason = str(workerbee_parallelism.get("hard_stop_reason"))
        if hard_stop_reason and hard_stop_reason not in hard_stops:
            hard_stops.append(hard_stop_reason)
        route = {**route, "hard_stops": hard_stops}
    workerbee_planned_delegation = _normalize_workerbee_planned_delegation(workerbee_parallelism)
    scaffold_sizing = prompt_coach_scaffold_sizing_signal(text, level, route, force_size=scaffold_size)
    model_synthesis_config = route.get("model_synthesis") if isinstance(route.get("model_synthesis"), dict) else None
    if model_synthesis_config is None:
        model_synthesis_config = recommend_model_synthesis(text, route)
        route = {**route, "model_synthesis": model_synthesis_config}
    beads_context_depth_signal = prompt_coach_beads_context_depth_signal(
        text,
        level,
        route,
        workerbee_parallelism,
        beads_context_depth=beads_context_depth,
    )
    route = {**route, **{key: beads_context_depth_signal[key] for key in [
        "beads_context_depth",
        "beads_context_depth_source",
        "beads_context_depth_rationale",
        "beads_context_depth_provenance",
    ]}}
    route = {**route, "workerbee_planned_delegation": workerbee_planned_delegation}
    operator_calibration = prompt_coach_operator_calibration_signal(text, route)
    questions = prompt_coach_missing_questions(
        route,
        text,
        file_paths,
        workerbee_parallelism,
        model_synthesis_config,
        scaffold_sizing,
        beads_context_depth_signal,
    )
    interactive_questions = prompt_coach_interactive_questions(
        level,
        route,
        questions,
        workerbee_parallelism,
        model_synthesis_config,
        scaffold_sizing,
        beads_context_depth_signal,
    )
    selection_gate = selection_before_plan_gate(text, interactive_questions)
    return {
        "coach_result_type": "complex-work-orchestration-prompt-coach",
        "version": 8,
        "beads_tracking_required": True,
        "recommended_orchestration_level": level,
        "scaffold_sizing": scaffold_sizing,
        "beads_context_depth": beads_context_depth_signal["beads_context_depth"],
        "beads_context_depth_provenance": beads_context_depth_signal["beads_context_depth_provenance"],
        "rationale": prompt_coach_rationale(
            level,
            route,
            questions,
            workerbee_parallelism,
            model_synthesis_config,
            scaffold_sizing,
            beads_context_depth_signal,
            operator_calibration,
        ),
        "missing_questions": questions,
        "interactive_questions": interactive_questions,
        "requires_user_selection_before_plan": selection_gate["requires_user_selection_before_plan"],
        "selection_before_plan_reason": selection_gate["reason"],
        "selection_before_plan_question_ids": selection_gate["question_ids"],
        "enabled_levers": prompt_coach_enabled_levers(
            level,
            route,
            workerbee_parallelism,
            model_synthesis_config,
            scaffold_sizing,
            beads_context_depth_signal,
            operator_calibration,
        ),
        "disabled_levers": prompt_coach_disabled_levers(
            level,
            route,
            workerbee_parallelism,
            model_synthesis_config,
            scaffold_sizing,
            beads_context_depth_signal,
        ),
        "workerbee_parallelism": workerbee_parallelism,
        "workerbee_planned_delegation": workerbee_planned_delegation,
        "model_synthesis": model_synthesis_config,
        "operator_calibration": operator_calibration,
        "route": route,
        "paste_ready_prompt": render_coached_prompt(
            level,
            route,
            text,
            questions,
            workerbee_parallelism,
            model_synthesis_config,
            scaffold_sizing,
            beads_context_depth_signal,
            operator_calibration,
        ),
        "warnings": prompt_coach_warnings(
            route,
            questions,
            workerbee_parallelism,
            model_synthesis_config,
            beads_context_depth_signal,
            operator_calibration,
        ),
    }
