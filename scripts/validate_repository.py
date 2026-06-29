#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import ast
from pathlib import Path
from typing import Any

from cwo_core.packets import (
    CONTRACTOR_PACKET_REQUIRED_FIELDS,
    LOCAL_DISPATCH_REQUIRED_FIELDS,
)
from cwo_core.paths import (
    POLICY_DIR,
    REPO_ROOT,
)
from cwo_core.coach import PROMPT_COACH_RESULT_REQUIRED_FIELDS
from cwo_core.harness import (
    HARNESS_DISPATCH_REQUIRED_FIELDS,
    MODEL_PROFILE_REQUIRED_FIELDS,
    validate_execution_environment_registry,
)
from cwo_core.policy import load_policy
from validate_run_readiness_plan import validate_plan as validate_run_readiness_plan

EMITTED_PACKET_ARTIFACT_TYPES = {
    "assignment_summary",
    "selected_file_snippet",
    "inline_snippet",
    "expert_profile",
}
CI_REQUIRED_COMMANDS = [
    "python scripts/validate_repository.py",
    "python scripts/validate_site.py",
    "python -m unittest discover -s tests",
    "bash examples/sample-prompt-coach-command.sh",
    "python scripts/validate_run_readiness_plan.py examples/sample-run-readiness-plan.json",
    "python scripts/render_run_projection.py examples/sample-run-readiness-plan.json --projection run-sheet",
    "python scripts/render_run_projection.py examples/sample-run-readiness-plan.json --projection wrap-up-status",
    "python scripts/render_run_projection.py examples/sample-run-readiness-plan.json --projection next-version",
    "python scripts/close_bead_with_summary.py --bead example-1 --disposition completed --why \"validated\" --follow-up none --dry-run --json",
    "python scripts/cleanup_stale_agents.py --dry-run --json",
]
CWO_CORE_ALLOWED_IMPORTS = {
    "paths": set(),
    "util": set(),
    "chatgpt_urls": set(),
    "policy": {"paths", "util"},
    "routing": {"policy", "routing_signals", "synthesis", "util"},
    "routing_signals": {"util"},
    "synthesis": {"policy", "util"},
    "coach": {"routing", "synthesis", "util"},
    "packets": {"paths", "policy", "util"},
    "returns": {"policy", "util"},
    "workspace": {"paths", "util"},
    "audit": {"paths", "policy", "util"},
    "beads": {"paths", "util"},
    "harness": {"policy", "util"},
}
PUBLIC_DOC_FORBIDDEN_HARDWARE_TERMS = ["H200", "CerIO", "airgapped-rhoai-h200"]


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.relative_to(REPO_ROOT)} is not valid JSON: {exc}") from exc


def validate_repository() -> list[str]:
    errors: list[str] = []
    validate_cwo_core_contract(errors)

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
        providers = load_policy("provider-registry").get("providers", {})
        peer_review = load_policy("peer-review-policy")
    except SystemExit as exc:
        return [str(exc)]

    errors.extend(validate_execution_environment_registry())

    for key, executor in executors.items():
        alias_for = executor.get("alias_for")
        if alias_for and alias_for not in executors:
            errors.append(f"executor {key!r} aliases unknown executor {alias_for!r}")
        if executor.get("external") and executor.get("codex_pickup") != "forbidden":
            errors.append(f"external executor {key!r} must set codex_pickup=forbidden")
        if executor.get("dispatch_mode") in {"local_openai_compatible", "local_secure_review"} and executor.get("codex_pickup") != "forbidden":
            errors.append(f"local worker executor {key!r} must set codex_pickup=forbidden")
        provider_key = executor.get("provider_key")
        if not provider_key or provider_key not in providers:
            errors.append(f"executor {key!r} references unknown provider_key {provider_key!r}")
        elif bool(executor.get("external")) != bool(providers[provider_key].get("external")):
            errors.append(f"executor {key!r} external flag does not match provider {provider_key!r}")
        if executor.get("dispatch_mode") in {"local_openai_compatible", "local_secure_review"}:
            if not executor.get("local_profile"):
                errors.append(f"local executor {key!r} is missing local_profile")
            transport = executor.get("transport") or {}
            for field in [
                "kind",
                "base_url_env",
                "api_key_env",
                "model_env",
                "endpoint_path",
                "timeout_seconds",
                "max_input_chars",
            ]:
                if field not in transport:
                    errors.append(f"local executor {key!r} transport is missing {field!r}")
            if executor.get("supports_web") or executor.get("supports_shell") or executor.get("supports_repo_write"):
                errors.append(f"local executor {key!r} must not support web, shell, or repo write")
        if executor.get("dispatch_mode") == "local_secure_review":
            if executor.get("supports_web"):
                errors.append(f"local secure reviewer {key!r} must not support web")
            if executor.get("supports_shell"):
                errors.append(f"local secure reviewer {key!r} must not support shell")
            if executor.get("supports_repo_write"):
                errors.append(f"local secure reviewer {key!r} must not support repo write")
            if not executor.get("supports_repo_read"):
                errors.append(f"local secure reviewer {key!r} must support repo read")

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
        if boundary.get("allows_repo_access") and not boundary.get("requires_disclosure_escalation"):
            errors.append(f"boundary {name!r} allows repo access without disclosure escalation")
        if not boundary.get("disclosure_stage"):
            errors.append(f"boundary {name!r} is missing disclosure_stage")

    local_secure = peer_review.get("defaults", {}).get("local_secure_review_executor")
    if local_secure and local_secure not in executors:
        errors.append(f"peer-review policy references unknown local secure reviewer {local_secure!r}")
    elif local_secure and executors[local_secure].get("dispatch_mode") != "local_secure_review":
        errors.append(f"peer-review local secure reviewer {local_secure!r} must use local_secure_review dispatch mode")

    control_peer_executors = controls.get("peer_review_policy", {}).get("allowed_peer_executors", [])
    for executor in control_peer_executors:
        if executor not in executors:
            errors.append(f"contracting controls peer review allows unknown executor {executor!r}")
    if not controls.get("sabotage_policy", {}).get("signal_weights"):
        errors.append("contracting controls must define sabotage_policy.signal_weights")
    if not controls.get("malpractice_policy", {}).get("signal_weights"):
        errors.append("contracting controls must define malpractice_policy.signal_weights")
    acceptance_sabotage_signals = load_policy("acceptance-policy").get("sabotage", {}).get("signals", [])
    for required_signal in [
        "provider_policy_opaque_intervention",
        "provider_conflict_disposition_missing",
        "provider_conflict_disposition_inadequate",
        "work_rerouting_or_subversion",
    ]:
        if required_signal not in controls.get("sabotage_policy", {}).get("signal_weights", {}):
            errors.append(f"contracting controls sabotage_policy.signal_weights missing {required_signal!r}")
    if "work_rerouting_or_subversion" not in acceptance_sabotage_signals:
        errors.append("acceptance-policy sabotage.signals missing 'work_rerouting_or_subversion'")
    work_rerouting_note = load_policy("acceptance-policy").get("sabotage", {}).get("signal_notes", {}).get("work_rerouting_or_subversion", {})
    if work_rerouting_note.get("authority") != "evidence-quality gate and architect-escalation trigger":
        errors.append("acceptance-policy work_rerouting_or_subversion must remain an evidence-quality architect-escalation gate")
    if work_rerouting_note.get("intent_finding") != "not required and not asserted":
        errors.append("acceptance-policy work_rerouting_or_subversion must not assert intent or misconduct")
    for required_signal in [
        "provider_policy_misrepresentation",
        "provider_conflict_disposition_noncompliant",
    ]:
        if required_signal not in controls.get("malpractice_policy", {}).get("signal_weights", {}):
            errors.append(f"contracting controls malpractice_policy.signal_weights missing {required_signal!r}")
    conflict_terms = load_policy("provider-registry").get("conflict_risk_terms", {})
    for required_term in ["distributed training infrastructure", "accelerator design", "pretraining pipeline"]:
        if required_term not in conflict_terms.get("frontier-ai-development", []):
            errors.append(f"provider-registry frontier-ai-development terms missing {required_term!r}")
    if "provider-policy-intervention" not in conflict_terms:
        errors.append("provider-registry conflict_risk_terms missing 'provider-policy-intervention'")
    for provider_key in ["openai_manual", "anthropic_manual", "google_gemini_manual"]:
        domains = providers.get(provider_key, {}).get("conflict_risk_domains", [])
        if "provider-policy-intervention" not in domains:
            errors.append(f"provider {provider_key!r} conflict_risk_domains missing 'provider-policy-intervention'")
    for required_expert in ["peer_review", "sabotage_review", "editor"]:
        if required_expert not in experts:
            errors.append(f"expert registry is missing required {required_expert!r} gate")
    sabotage_triggers = experts.get("sabotage_review", {}).get("trigger_terms", [])
    for required_term in ["work_rerouting_or_subversion", "objective dilution", "critical path deferral"]:
        if required_term not in sabotage_triggers:
            errors.append(f"sabotage_review trigger_terms missing {required_term!r}")

    packet_schema = load_json(REPO_ROOT / "schemas" / "contractor-packet.schema.json")
    packet_required = set(packet_schema.get("required", []))
    missing_packet_required = sorted(set(CONTRACTOR_PACKET_REQUIRED_FIELDS) - packet_required)
    if missing_packet_required:
        errors.append(
            "contractor packet schema is missing runtime required fields: " + ", ".join(missing_packet_required)
        )
    opt_in_schema = load_json(REPO_ROOT / "schemas" / "opt-in-record.schema.json")
    require_schema_properties(
        errors,
        schema_name="opt-in-record.schema.json",
        schema=opt_in_schema,
        properties=["allowed_providers"],
    )
    acceptance_schema = load_json(REPO_ROOT / "schemas" / "acceptance-decision.schema.json")
    require_schema_properties(
        errors,
        schema_name="acceptance-decision.schema.json",
        schema=acceptance_schema,
        properties=[
            "malpractice_score",
            "malpractice_signals",
            "evidence_quality_score",
            "evidence_quality_signals",
            "evidence_quality_signal_categories",
            "research_evidence_score",
            "research_evidence_signals",
            "research_evidence_signal_categories",
            "research_evidence_items",
            "research_contradictions",
            "research_reflection",
            "signal_categories",
            "peer_review_required",
            "peer_review_status",
            "boundary_taint_status",
            "boundary_taint_findings",
            "provider_key",
            "provider_trust_tier",
            "provider_external",
            "provenance_class",
            "human_adjudication_required",
            "recommended_disposition",
            "recommended_synthesis_use",
        ],
    )
    contractor_return_bundle_schema = load_json(REPO_ROOT / "schemas" / "contractor-return-bundle.schema.json")
    require_schema_properties(
        errors,
        schema_name="contractor-return-bundle.schema.json",
        schema=contractor_return_bundle_schema,
        properties=[
            "provider_key",
            "provider_trust_tier",
            "provider_external",
            "dispatch_mode",
            "local_profile",
            "provenance_class",
            "evidence_quality_score",
            "evidence_quality_signals",
            "evidence_quality_signal_categories",
            "research_evidence_score",
            "research_evidence_signals",
            "research_evidence_signal_categories",
            "research_evidence_items",
            "research_contradictions",
            "research_reflection",
        ],
    )
    local_envelope_schema = load_json(REPO_ROOT / "schemas" / "local-dispatch-envelope.schema.json")
    local_required = set(local_envelope_schema.get("required", []))
    missing_local_required = sorted(set(LOCAL_DISPATCH_REQUIRED_FIELDS) - local_required)
    if missing_local_required:
        errors.append(
            "local dispatch envelope schema is missing runtime required fields: " + ", ".join(missing_local_required)
        )
    prompt_coach_schema = load_json(REPO_ROOT / "schemas" / "prompt-coach-result.schema.json")
    prompt_coach_required = set(prompt_coach_schema.get("required", []))
    missing_prompt_coach_required = sorted(set(PROMPT_COACH_RESULT_REQUIRED_FIELDS) - prompt_coach_required)
    if missing_prompt_coach_required:
        errors.append(
            "prompt coach result schema is missing runtime required fields: "
            + ", ".join(missing_prompt_coach_required)
        )
    require_schema_properties(
        errors,
        schema_name="prompt-coach-result.schema.json",
        schema=prompt_coach_schema,
        properties=["scaffold_sizing"],
    )
    harness_dispatch_schema = load_json(REPO_ROOT / "schemas" / "harness-dispatch-envelope.schema.json")
    harness_dispatch_required = set(harness_dispatch_schema.get("required", []))
    missing_harness_dispatch_required = sorted(set(HARNESS_DISPATCH_REQUIRED_FIELDS) - harness_dispatch_required)
    if missing_harness_dispatch_required:
        errors.append(
            "harness dispatch envelope schema is missing runtime required fields: "
            + ", ".join(missing_harness_dispatch_required)
        )
    require_schema_properties(
        errors,
        schema_name="harness-dispatch-envelope.schema.json",
        schema=harness_dispatch_schema,
        properties=["model_profile", "model_profile_details"],
    )
    model_profile_schema = load_json(REPO_ROOT / "schemas" / "model-profile.schema.json")
    profile_properties = (
        model_profile_schema.get("properties", {})
        .get("profiles", {})
        .get("additionalProperties", {})
        .get("properties", {})
    )
    for field in MODEL_PROFILE_REQUIRED_FIELDS:
        if field not in profile_properties:
            errors.append(f"model-profile.schema.json profile is missing property {field!r}")
    require_schema_properties(
        errors,
        schema_name="execution-environment.schema.json",
        schema=load_json(REPO_ROOT / "schemas" / "execution-environment.schema.json"),
        properties=["profiles"],
    )
    require_schema_properties(
        errors,
        schema_name="run-readiness-plan.schema.json",
        schema=load_json(REPO_ROOT / "schemas" / "run-readiness-plan.schema.json"),
        properties=[
            "workstreams",
            "rubric",
            "criterion_evidence_matrix",
            "provider_provenance",
            "quarantine_rules",
            "boundary_negative_tests",
            "next_version_rail",
            "patrol_stopping_rule",
            "handoff_evidence_requirements",
            "adjudication_record",
        ],
    )
    for error in validate_run_readiness_plan(load_json(REPO_ROOT / "examples" / "sample-run-readiness-plan.json")):
        errors.append(f"sample-run-readiness-plan.json: {error}")

    require_doc_terms(
        errors,
        "README.md",
        [
            "https://gprocunier.github.io/complex-work-orchestration/",
            "/plan Use $complex-work-orchestration prompt coach",
            "Connected single-operator quick path",
            "The normal interface is the Codex conversation",
            "Codex may run the helper behind the scenes",
            "Use direct script execution only",
            "scripts/coach_prompt.py",
            "scripts/cleanup_stale_agents.py",
            "scripts/close_bead_with_summary.py",
            "scripts/configure_codex_beads_hooks.py",
            "scripts/workspace_mutation_guard.py",
            "--terminate-unowned-codex",
            "--workspace-root",
            "Advanced helper scripts",
            "references/prompt-coach.md",
            "prompt-coach results",
            "interactive_questions",
            "workerbee_parallelism",
            "beads_context_depth",
            "beads_briefing_depth",
            "beads_context_depth_provenance",
            "scripts/build_beads_brief.py",
            "Beads context-depth choice",
            "autosized depth as the recommended default",
            "review-subagents",
            "heavy-review-subagents",
            "Codex 5.3 Spark",
            "smallest available capable review model",
            "beads_tracking_required",
            "Beads tracking is mandatory",
            "closure-memory comment",
            "What changed",
            "How validated",
            "When closed",
            "Where executed",
            "Complex Multi-Expert Review Pattern",
            "blocking ChatGPT Pro gate",
            "explicitly records a waiver/downgrade in Beads",
            "bd dolt remote list",
            "sudo dnf copr enable greg-at-redhat/beads",
            "Main-Thread PM Dispatch Flow",
            "claude -p",
            "agy -p",
            "native Beads fields",
            "Hello-World Contractor Demo",
            "hello-world-contractor-demo",
            "in-Codex `/plan Use $complex-work-orchestration prompt coach",
            "Codex runtime account must be able to run the approved contractor CLIs",
            "operator-approved privilege escalation",
            "contractor packet",
            "dispatch_work.py renders manual prompts",
            "CONTRACTOR RETURN TEMPLATE - COPY EXACTLY",
            "workspace mutation reports",
            "Codex repairs public-doc issues",
            "`skills`",
            "`acceptance`",
            "`design`",
            "`notes`",
            "full-harness request",
            "workstream language asks",
            "Where CWO Fits",
            "does not replace OpenRouter Fusion",
            "BYOS",
            "BYOK",
            "OpenRouter keys",
            "additional editorial review",
            "reader-facing acceptance check",
            "contract-jd-editorial-reasoning",
            "chatgpt_pro_5_5_extended_reasoning_browser",
            "contract-jd-master-plan-review",
            "scripts/chatgpt_browser_review.py",
            "scripts/ingest_chatgpt_share_return.py",
            "CWO_CHATGPT_BROWSER_CONFIG",
            "Claude Opus and Gemini critique the architect plan",
            "SHARE_URL=\"$(jq -r '.share_url' master-plan-review-dispatch.json)\"",
            "DISPATCH_ID=\"$(jq -r '.dispatch_id' master-plan-review-dispatch.json)\"",
            "PACKET_SHA256=\"$(jq -r '.packet_sha256' master-plan-review-dispatch.json)\"",
            "Browser helper prerequisites",
            "Last verified: June 18, 2026",
            "degraded manual return",
            "hidden",
            "step-by-step planning",
            "OpenShift AI vLLM",
            "execution environment",
            "OpenCode",
            "RHOAI/vLLM model profiles",
            "airgapped",
            "--local-ok",
            "--prefer-local",
            "--local-profile openshift-ai-vllm",
            "references/local-inference.md",
            "references/run-readiness.md",
            "malpractice_score",
            "peer_review_required",
            "schemas/local-dispatch-envelope.schema.json",
            "schemas/harness-dispatch-envelope.schema.json",
            "schemas/run-readiness-plan.schema.json",
            "scripts/validate_run_readiness_plan.py",
            "scripts/render_run_projection.py",
            "wrap-up-status",
            "criterion-to-evidence matrix",
            "run readiness plan",
            "policy/harness-registry.yaml",
            "policy/execution-environments.yaml",
            "policy/model-profiles.yaml",
            "schemas/model-profile.schema.json",
            "Airgapped Model Matrix",
            "Enterprise evaluation targets",
            "benchmark gate",
            "larger disconnected clusters",
            "Nemotron 3 Ultra",
            "GLM-5.2",
            "Llama 4 Maverick",
            "model-profile matrix",
            "--model-profile",
            "references/redhat-expert-catalog.md",
            "contract-jd-redhat-<name>",
            "Codex Beads Hook Output",
            "full-context",
            "visibilityHint",
            "blocking gate",
            "waiver/downgrade in Beads",
            "compact-degraded",
            "hookSpecificOutput.additionalContext",
            "references/codex-beads-hooks.md",
        ],
    )
    require_doc_terms(
        errors,
        "docs/index.html",
        [
            "Complex Work Orchestration",
            "For work that has outgrown web chat",
            "Turn AI coding sessions into work you can resume, review, test, and trust",
            "Why a shell changes the game",
            "Power needs a work story",
            "Crawl",
            "Walk",
            "Run",
            "Fly",
            "A web chat can explain code",
            "A coding shell can do the project work with you",
            "Context gets lost",
            "Validation must be visible",
            "Open the guardrails deep dive",
            "See outside review boundaries",
            "Start the 5-minute path",
            "I already know agent shells",
            "/plan Use $complex-work-orchestration prompt coach",
            "does not replace",
            "OpenRouter Fusion",
            "LangGraph",
            "AutoGen",
            "CrewAI",
            "Claude Code",
            "Gemini CLI",
            "Codex CLI",
            "./get-started.html",
            "./explanation.html",
            "./prompt-coach.html",
            "./workflows.html",
            "./use-cases.html",
            "./beads-memory.html",
            "./model-synthesis.html",
            "./malpractice-sabotage.html",
            "./contractor-demo.html",
            "./reference.html",
            "https://github.com/gprocunier/complex-work-orchestration",
        ],
    )
    require_doc_terms(
        errors,
        "docs/explanation.html",
        [
            "Why The Workflow Is Structured This Way",
            "Role Separation",
            "Durable Memory",
            "Evidence Boundaries",
            "Publication Quality",
            "Failure Modes The Harness Avoids",
            "OpenRouter Fusion",
            "LangGraph",
            "AutoGen",
            "CrewAI",
            "Claude Code",
            "Gemini CLI",
            "Codex CLI",
            "no transcript",
            "compacted",
            "evidence until it is evaluated and adjudicated",
            "redacted review accidentally uses local",
            "./beads-memory.html",
            "./model-synthesis.html",
            "./malpractice-sabotage.html",
            "Guardrails deep dive",
            "./workflows.html",
            "./reference.html",
        ],
    )
    require_doc_terms(
        errors,
        "docs/get-started.html",
        [
            "Get Started",
            "CODEX_SKILLS_DIR",
            "Choose Your Profile",
            "Connected Single Operator",
            "Connected With Contractors",
            "Restricted OpenCode",
            "Airgapped Or RHOAI",
            "Core Terms",
            "Closure Memory",
            "Dolt Remote",
            "Epic",
            "/plan Use $complex-work-orchestration prompt coach",
            "Codex may run this helper behind the scenes",
            "Use direct script execution only",
            "scripts/coach_prompt.py",
            "bd ready",
            "greg-at-redhat/beads",
            "github.com/steveyegge/beads",
            "no-codex-exec",
            "./workflows.html",
            "skills",
            "acceptance",
            "design",
            "notes",
            "simple use case",
            "what changed",
            "how it was validated",
        ],
    )
    require_doc_terms(
        errors,
        "docs/beads-memory.html",
        [
            "Beads Memory",
            "durable task graph",
            "closure-memory comments",
            "context-depth",
            "spawned agents",
            "compacted sessions",
            "local-only",
            "Dolt-backed",
            "outside reviewers receive packets",
            "./workflows.html#beads-graph",
            "./reference.html#durable-memory",
        ],
    )
    require_doc_terms(
        errors,
        "docs/model-synthesis.html",
        [
            "Model Synthesis And Adjudication",
            "Synthesis reports",
            "architect decides",
            "advisory evidence",
            "accepted-with-modification",
            "salvage-only",
            "boundary-tainted",
            "minimum usable primary inputs",
            "provider provenance",
            "architect adjudication",
            "./external-contracting.html#multi-expert-review",
            "./reference.html#experts",
        ],
    )
    require_doc_terms(
        errors,
        "docs/malpractice-sabotage.html",
        [
            "Malpractice And Sabotage Guardrails",
            "untrusted evidence",
            "malpractice",
            "sabotage",
            "boundary-tainted",
            "quarantine",
            "mutation-guard",
            "incident-response",
            "architect adjudication",
            "No guarantee language",
            "Why This Matters Now",
            "Source Facts And Risk Interpretation",
            "Provider-Policy Limitations",
            "Provider conflict disposition",
            "opaque intervention",
            "classifier-triggered",
            "source-bound and time-bound",
            "boundary-risk categories",
            "sensitive-data requests",
            "frontier LLM development",
            "pretraining pipelines",
            "distributed training infrastructure",
            "ML accelerator design",
            "Handlers For Model Work",
            "./workflows.html#validate-handoff",
            "./model-synthesis.html",
        ],
    )
    require_doc_terms(
        errors,
        "docs/prompt-coach.html",
        [
            "Prompt Coach",
            "/plan Use $complex-work-orchestration prompt coach",
            "Codex may run this helper behind the scenes",
            "Use direct script execution only",
            "interactive_questions",
            "scaffold_sizing",
            "beads_context_depth",
            "beads_briefing_depth",
            "build_beads_brief.py",
            "Context option is always present",
            "autosized depth as the recommended default",
            "--scaffold-size tight",
            "workerbee_parallelism",
            "Subagents",
            "The coach always asks",
            "Codex 5.3 Spark when available",
            "smallest available capable review model",
            "curl",
            "Publish Release",
            "editorial review before publish",
            "reader-facing language",
            "outside-sharing boundary",
            "local-worker opt-in",
            "Master review",
            "ChatGPT Pro 5.5 Extended Reasoning",
            "./workflows.html",
        ],
    )
    require_doc_terms(
        errors,
        "docs/workflows.html",
        [
            "Workflows",
            "Invoke From Codex",
            "Coach And Decide",
            "Beads Task Graph",
            "./beads-memory.html",
            "./model-synthesis.html",
            "./malpractice-sabotage.html",
            "Run Readiness",
            "Return-safety deep dive",
            "Optional Workstreams",
            "Validate And Handoff",
            "Profile gate",
            "connected single-operator task",
            "./use-cases.html",
            "./use-cases.html#simple-use-cases",
            "./use-cases.html#complex-use-cases",
            "handoff packet",
            "packet validation checkpoint",
            "Publication review",
            "final editorial pass",
            "repeated or draft-like wording",
            "/plan Use $complex-work-orchestration prompt coach",
            "scripts/coach_prompt.py",
            "--scaffold-size tight",
            "scripts/cleanup_stale_agents.py",
            "scripts/close_bead_with_summary.py",
            "scripts/workspace_mutation_guard.py",
            "--workspace-root",
            "helper execution only for advanced automation",
            "scripts/scaffold_workgraph.py",
            "scripts/validate_run_readiness_plan.py",
            "scripts/render_run_projection.py",
            "wrap-up-status",
            "schemas/run-readiness-plan.schema.json",
            "templates/run-readiness-plan.md",
            "references/run-readiness.md",
            "boundary negative test",
            "scripts/build_beads_brief.py",
            "scripts/build_contractor_packet.py",
            "scripts/dispatch_work.py",
            "scripts/chatgpt_browser_review.py",
            "scripts/ingest_chatgpt_share_return.py",
            "--local-ok",
            "--prefer-local",
            "--local-profile openshift-ai-vllm",
            "--execute-local",
            "./external-contracting.html#master-review",
            "claude -p",
            "agy -p",
            "contractor-dispatch-prompt.md",
            "normalize_contractor_return.py",
            "evaluate_return.py",
            "workspace_mutation_guard.py",
            "build_beads_brief.py",
            "beads_context_depth",
            "Contractor Demo",
            "closure-memory comment",
            "./contractor-demo.html",
            "./explanation.html",
            "incident-response playbook",
            "inventory the existing page URLs",
            "Model Profile Substitution",
            "Airgapped Model Matrix",
            "Enterprise evaluation targets",
            "matrix-list",
            "benchmark gate",
            "disconnected deployments",
            "Nemotron 3 Ultra",
            "GLM-5.2",
            "exact governance files",
            "--model-profile",
        ],
    )
    require_doc_terms(
        errors,
        "docs/use-cases.html",
        [
            "Use Cases",
            "Simple Use Cases",
            "Complex Use Cases",
            "Durable Work Log",
            "Where CWO Fits",
            "Execution Profile Fit",
            "Restricted shell",
            "Airgapped local models",
            "peer-review disposition",
            "Acceptance Gates",
            "does not replace OpenRouter Fusion",
            "LangGraph",
            "AutoGen",
            "CrewAI",
            "Claude Code",
            "Gemini CLI",
            "Codex CLI",
            "BYOS",
            "BYOK",
            "OpenShift AI vLLM",
            "Beads provides the durable task graph",
            "./beads-memory.html",
            "./model-synthesis.html",
            "./malpractice-sabotage.html",
            "/plan Use $complex-work-orchestration prompt coach",
            "closure-memory comment",
            "./reference.html#durable-memory",
            "Gemini",
            "Claude Opus",
            "ChatGPT Pro 5.5 Extended Reasoning",
            "dispatch ID",
            "packet hash",
            "model/share-link evidence",
            "./external-contracting.html#multi-expert-review",
            "./external-contracting.html#master-review",
            "./reference.html#experts",
        ],
    )
    require_doc_terms(
        errors,
        "docs/external-contracting.html",
        [
            "External Contracting",
            "guided workflow",
            "third-party model contractor",
            "contractor handoff packet",
            "Packet Validation",
            "Multi-Expert Review",
            "contractor-only",
            "contract-jd-security-reasoning",
            "skills",
            "acceptance",
            "design",
            "notes",
            "./workflows.html#optional-lanes",
            "./contractor-demo.html",
            "Demo Lessons",
            "claude -p",
            "agy -p",
            "Executor access",
            "Codex runtime account must be able to invoke",
            "operator-approved privilege escalation",
            "External CLIs receive only the rendered prompt",
            "Beads authority",
            "merge permission",
            "blocking ChatGPT Pro gate",
            "waiver/downgrade",
            "Master Review",
            "./model-synthesis.html",
            "./malpractice-sabotage.html",
            "./use-cases.html#complex-use-cases",
            "chatgpt_pro_5_5_extended_reasoning_browser",
            "CWO_CHATGPT_BROWSER_CONFIG",
            "Setup Checklist",
            "ChatGPT does not operate Beads directly",
            "Playwright",
            "jq",
            "Last verified:",
            "SHARE_URL",
            "DISPATCH_ID",
            "PACKET_SHA256",
            "Degraded return",
            "Not doing",
            "ingest_chatgpt_share_return.py",
            "in-Codex prompt coach should ask about outside sharing",
            "normalize_contractor_return.py",
            "workspace_mutation_guard.py",
            "closure-memory comment",
            "Unexpected tracked-file",
        ],
    )
    require_doc_terms(
        errors,
        "docs/local-workers.html",
        [
            "Local Workers",
            "Guided Workflow",
            "Invoke From Codex",
            "Coach Local Opt-In",
            "OpenShift AI vLLM Profile",
            "Large-cluster enterprise architecture",
            "enterprise-scale OpenShift AI clusters",
            "benchmark gate",
            "Dispatch Envelope",
            "Execute Explicitly",
            "Evaluate Returns",
            "/plan Use $complex-work-orchestration prompt coach",
            "--local-ok",
            "--prefer-local",
            "--local-profile openshift-ai-vllm",
            "--execute-local",
            "local-worker-only",
            "no-codex-exec",
            "architect adjudication",
            "OpenAI-compatible",
            "frontier model",
            "curl",
            "codex_pickup=forbidden",
            "evaluate_return.py",
            "./workflows.html#optional-lanes",
        ],
    )
    require_doc_terms(
        errors,
        "docs/reference.html",
        [
            "Control Plane",
            "Start with the guided workflow",
            "Flow References",
            "Connected single operator",
            "Contractor-assisted",
            "Restricted OpenCode",
            "Airgapped RHOAI",
            "Operator Controls",
            "policy/routing-policy.yaml",
            "schemas",
            "OpenShift AI",
            "OpenCode",
            "execution environment",
            "./workflows.html",
            "./explanation.html",
            "./external-contracting.html",
            "./local-workers.html",
            "./beads-memory.html",
            "./model-synthesis.html",
            "./malpractice-sabotage.html",
            "./codex-beads-hooks.html",
            "--local-ok",
            "--local-profile openshift-ai-vllm",
            "architect adjudication",
            "Add <code>--peer-review-required</code> only when route policy",
            "reference label for public docs",
            "draft-like wording",
            "chatgpt_pro_5_5_extended_reasoning_browser",
            "contract-jd-master-plan-review",
            "scripts/chatgpt_browser_review.py",
            "scripts/ingest_chatgpt_share_return.py",
            "claude -p",
            "agy -p",
            "skills",
            "acceptance",
            "design",
            "notes",
            "scripts/validate_site.py",
            "scripts/render_harness_dispatch.py",
            "policy/model-profiles.yaml",
            "schemas/model-profile.schema.json",
            "model-profile registries",
            "deployment_tier",
            "benchmark_gate",
            "promotion_status",
            "scripts/validate_run_readiness_plan.py",
            "scripts/render_run_projection.py",
            "wrap-up-status",
            "schemas/run-readiness-plan.schema.json",
            "workspace_mutation_guard.py",
            "scripts/close_bead_with_summary.py",
            "scripts/configure_codex_beads_hooks.py",
            "--what",
            "--how",
            "--when",
            "--where",
            "closure-memory comments",
            "Run Readiness",
            "Codex Beads Hooks",
            "full-context",
            "visibilityHint",
            "references/codex-beads-hooks.md",
            "--allow-degraded-context",
            "criterion-to-evidence matrix",
            "Durable Memory",
            "what changed",
            "how validated",
            "when closed",
            "where executed",
            "incident-response playbook",
            "./contractor-demo.html",
        ],
    )
    require_doc_terms(
        errors,
        "docs/codex-beads-hooks.html",
        [
            "Codex Beads Hooks",
            "SessionStart",
            "bd codex-hook SessionStart",
            "full-context",
            "visibilityHint",
            "hookSpecificOutput.additionalContext",
            "scripts/configure_codex_beads_hooks.py",
            "--allow-degraded-context",
            "compact-degraded",
            "SubagentStart",
            "Beads 1.0.5",
        ],
    )
    require_doc_terms(
        errors,
        "docs/contractor-demo.html",
        [
            "Contractor Demo",
            "hello-world contractor demo",
            "gprocunier/hello-world-contractor-demo",
            "https://gprocunier.github.io/hello-world-contractor-demo/",
            "Codex PM",
            "Antigravity",
            "Claude Code",
            "In-Codex Invocation",
            "/plan Use $complex-work-orchestration prompt coach",
            "Ask before external sharing",
            "Executor Access",
            "Codex runtime account must be able to invoke",
            "operator-approved privilege escalation",
            "A contractor packet does not grant shell access",
            "External CLIs receive only the rendered",
            "not Beads authority",
            "closure-memory comment",
            "agy -p",
            "claude -p",
            "Packet generation is not dispatch",
            "--allow-disclosure-escalation",
            "contractor-return.md",
            "normalize_contractor_return.py",
            "evaluate_return.py",
            "workspace_mutation_guard.py",
            "unexpected tracked-file mutation",
            "file://",
            "Beads has no Dolt remote",
            "architect responsibilities",
        ],
    )
    require_doc_terms(
        errors,
        "docs/styles.css",
        [
            ":focus-visible",
            "@media",
            "--red",
            "system-map",
            "matrix-list",
            "doc-layout",
            "page-nav",
            "callout",
        ],
    )
    require_doc_terms(
        errors,
        "SKILL.md",
        [
            "scripts/coach_prompt.py",
            "scripts/cleanup_stale_agents.py",
            "scripts/workspace_mutation_guard.py",
            "scripts/configure_codex_beads_hooks.py",
            "--terminate-unowned-codex",
            "--workspace-root",
            "direct script execution only for advanced automation",
            "references/prompt-coach.md",
            "interactive_questions",
            "Beads tracking is mandatory",
            "beads_tracking_required",
            "scaffold_sizing",
            "--scaffold-size tight",
            "workerbee_parallelism",
            "Codex 5.3 Spark when available",
            "smallest available capable review model",
            "bd dolt remote list",
            "--skills",
            "--acceptance",
            "--design",
            "--notes",
            "--what",
            "--how",
            "--when",
            "--where",
            "docs/workflows.html",
            "docs/local-workers.html",
            "explicit reference/operator",
            "/plan",
            "claude -p",
            "agy -p",
            "OpenShift AI vLLM",
            "local-profile",
            "peer_review_required",
            "malpractice_score",
            "CONTRACTOR RETURN TEMPLATE - COPY EXACTLY",
            "references/redhat-expert-catalog.md",
            "references/run-readiness.md",
            "references/codex-beads-hooks.md",
            "scripts/close_bead_with_summary.py",
            "full-context",
            "visibilityHint",
        ],
    )
    require_doc_terms(
        errors,
        "references/redhat-expert-catalog.md",
        [
            "contract-jd-redhat-openshift-platform",
            "contract-jd-redhat-openshift-app-dev",
            "contract-jd-redhat-openshift-ai",
            "contract-jd-redhat-rhoso",
            "contract-jd-redhat-rhacm",
            "contract-jd-redhat-rhacs",
            "contract-jd-redhat-rhel",
            "Identity Management",
            "Satellite",
        ],
    )
    require_doc_terms(
        errors,
        "references/prompt-coach.md",
        [
            "interactive_questions",
            "Use direct script execution only",
            "beads_tracking_required",
            "workerbee_parallelism",
            "review-only",
            "Subagent Parallelism",
            "heavy review subagents",
            "in-thread",
            "lightweight-beads",
            "full-harness",
            "external-contract",
            "local-worker",
            "publish-release",
            "Scaffold Size",
            "Exact contract labels belong",
        ],
    )
    require_doc_terms(
        errors,
        "references/run-readiness.md",
        [
            "Run Readiness Gate",
            "Beads remain canonical",
            "criterion maps to an artifact, validator, or review gate",
            "Rubrics have a version",
            "typed projections",
            "Unsupported or boundary-breaking returns are quarantined",
            "Next-version items have a typed reason",
            "Patrol or recurring work remains research-only",
            "scripts/render_run_projection.py",
            "wrap-up-status",
            "criterion_ids",
            "provider_neutral_execution",
            "out-of-scope",
            "needs-credential",
            "needs-research",
            "hardening",
            "later-version",
            "blocked",
            "schemas/run-readiness-plan.schema.json",
            "examples/sample-run-readiness-plan.json",
            "scripts/validate_run_readiness_plan.py",
            "templates/run-readiness-plan.md",
            "Architect adjudication is the handoff decision",
        ],
    )
    require_doc_terms(
        errors,
        "references/codex-beads-hooks.md",
        [
            "Codex Beads Hooks",
            "bd codex-hook SessionStart",
            "full-context",
            "visibilityHint",
            "hookSpecificOutput.additionalContext",
            "compact-degraded",
            "--allow-degraded-context",
            "SubagentStart",
            "Beads 1.0.5",
            "scripts/build_beads_brief.py",
            "scripts/build_contractor_packet.py",
        ],
    )
    require_doc_terms(
        errors,
        "examples/prompt-coach-examples.md",
        [
            "interactive_questions",
            "advanced helper equivalent",
            "beads_tracking_required",
            "Parallel Subagent Review",
            "workerbee_parallelism.recommended_mode=review-only",
            "review-subagents",
            "Heavy Subagent Review",
            "workerbee_parallelism.recommended_mode=heavy-review",
            "heavy-review-subagents",
            "Explicit Scaffold",
            "Contractor Workstream Scaffold",
            "Narrow In-Thread Work",
            "Lightweight Beads Plan",
            "Full Harness",
            "External Security Contractor",
            "OpenShift AI vLLM Local Worker",
            "/plan Use $complex-work-orchestration prompt coach",
            "local-worker-only",
            "no-codex-exec",
            "architect adjudication",
            "Local Worker Mention Without Opt-In",
            "Publish Release Gate",
            "Publication Editorial Review",
            "editor review before publish sanitization",
            "contract labels belong in",
        ],
    )
    require_doc_terms(
        errors,
        "references/external-contracting.md",
        [
            "Peer-review disposition",
            "malpractice_score",
            "contract-jd-sabotage-review",
            "contract-jd-editorial-reasoning",
            "Hello-World Contractor Demo Lessons",
            "gprocunier/hello-world-contractor-demo",
            "in-Codex `/plan Use $complex-work-orchestration prompt coach",
            "Executor access prerequisite",
            "Codex runtime account must be able to",
            "operator-approved privilege escalation",
            "The contractor packet does not grant shell access",
            "prompt-file or stdin-safe mode",
            "command arguments may be visible",
            "Beads authority",
            "merge permission",
            "blocking ChatGPT Pro gate",
            "waiver/downgrade",
            "agy -p",
            "claude -p",
            "dispatch prompt",
            "file://",
            "chatgpt_pro_5_5_extended_reasoning_browser",
            "contract-jd-master-plan-review",
            "scripts/chatgpt_browser_review.py",
            "scripts/ingest_chatgpt_share_return.py",
            "CWO_CHATGPT_BROWSER_CONFIG",
            "closure-memory comment",
        ],
    )
    for template_path in [
        "templates/work-task.md",
        "templates/review-task.md",
        "templates/external-contract.md",
        "templates/contractor-evaluation.md",
        "templates/acceptance-decision.md",
        "templates/followup-task.md",
        "templates/local-worker-task.md",
        "templates/epic.md",
    ]:
        require_doc_terms(
            errors,
            template_path,
            [
                "closure-memory",
                "who was involved",
                "what changed",
                "how validated",
                "when closed",
                "where executed",
                "evidence",
                "residual risk",
                "follow-up",
            ],
        )
    require_doc_terms(errors, "templates/followup-task.md", ["closure summary"])
    require_doc_terms(
        errors,
        "experts/editor.md",
        [
            "Editor Distinguished Engineer",
            "contract-jd-editorial-reasoning",
            "Diataxis",
            "docs/pages flow",
            "AI-slop",
            "internal process leakage",
            "Design-source or design-corpus",
            "private vocabulary",
            "reference/operator lookup",
            "Required prerequisites",
            "Acceptance criteria",
        ],
    )
    require_doc_terms(
        errors,
        "references/incident-response-playbook.md",
        ["malpractice_score", "peer_review_status", "recommended_disposition"],
    )
    require_doc_terms(
        errors,
        "references/local-inference.md",
        [
            "/plan Use $complex-work-orchestration prompt coach",
            "OpenShift AI vLLM",
            "CWO_OPENSHIFT_AI_VLLM_BASE_URL",
            "--local-ok",
            "--prefer-local",
            "--local-profile openshift-ai-vllm",
            "--execute-local",
            "scripts/dispatch_work.py",
            "architect adjudication",
        ],
    )
    validate_local_inference_peer_review_guidance(errors)
    validate_public_docs_do_not_expose_hardware_categories(errors)

    validate_ci_workflow(errors)

    return errors


def validate_cwo_core_contract(errors: list[str]) -> None:
    core_dir = REPO_ROOT / "scripts" / "cwo_core"
    legacy_name = "orchestration" + "_lib"
    old_module = REPO_ROOT / "scripts" / f"{legacy_name}.py"
    if old_module.exists():
        errors.append("legacy monolith file remains under scripts/")

    for directory in [REPO_ROOT / "scripts", REPO_ROOT / "tests"]:
        for path in sorted(directory.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if legacy_name in text:
                errors.append(f"legacy monolith reference remains in {path.relative_to(REPO_ROOT)}")

    for module_name in CWO_CORE_ALLOWED_IMPORTS:
        module_path = core_dir / f"{module_name}.py"
        if not module_path.is_file():
            errors.append(f"missing cwo_core module: {module_path.relative_to(REPO_ROOT)}")

    for path in sorted(core_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        module_name = path.stem
        allowed = CWO_CORE_ALLOWED_IMPORTS.get(module_name)
        if allowed is None:
            errors.append(f"unexpected cwo_core module: {path.relative_to(REPO_ROOT)}")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            errors.append(f"{path.relative_to(REPO_ROOT)} has invalid Python syntax: {exc}")
            continue
        for node in ast.walk(tree):
            imported: str | None = None
            if isinstance(node, ast.ImportFrom):
                if node.level == 1 and node.module:
                    imported = node.module.split(".", 1)[0]
                elif node.module and node.module.startswith("cwo_core."):
                    imported = node.module.split(".", 1)[1].split(".", 1)[0]
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("cwo_core."):
                        imported = alias.name.split(".", 1)[1].split(".", 1)[0]
            if imported and imported != module_name and imported not in allowed:
                errors.append(f"cwo_core dependency violation: {module_name} imports {imported}")


def validate_ci_workflow(errors: list[str], ci_path: Path | None = None) -> None:
    path = ci_path or REPO_ROOT / ".github" / "workflows" / "ci.yml"
    if not path.is_file():
        return
    ci = path.read_text(encoding="utf-8")
    for term in CI_REQUIRED_COMMANDS:
        if term not in ci:
            errors.append(f"CI workflow is missing required command: {term}")


def require_schema_properties(
    errors: list[str],
    *,
    schema_name: str,
    schema: dict[str, Any],
    properties: list[str],
) -> None:
    available = set(schema.get("properties", {}))
    missing = sorted(set(properties) - available)
    if missing:
        errors.append(f"schema {schema_name} is missing properties: {', '.join(missing)}")


def require_doc_terms(errors: list[str], relative_path: str, terms: list[str]) -> None:
    path = REPO_ROOT / relative_path
    if not path.is_file():
        errors.append(f"required documentation file is missing: {relative_path}")
        return
    content = path.read_text(encoding="utf-8")
    normalized_content = " ".join(content.split())
    missing = [
        term
        for term in terms
        if term not in content and " ".join(term.split()) not in normalized_content
    ]
    if missing:
        errors.append(f"{relative_path} is missing required terms: {', '.join(missing)}")


def validate_public_docs_do_not_expose_hardware_categories(
    errors: list[str], public_docs: list[Path] | None = None
) -> None:
    if public_docs is None:
        public_docs = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.html"))]
    for path in public_docs:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        lowered = content.lower()
        forbidden = [
            term
            for term in PUBLIC_DOC_FORBIDDEN_HARDWARE_TERMS
            if term.lower() in lowered
        ]
        if forbidden:
            try:
                relative = path.relative_to(REPO_ROOT)
            except ValueError:
                relative = path
            errors.append(
                f"{relative} exposes hardware-specific public category terms: {', '.join(forbidden)}"
            )


def validate_local_inference_peer_review_guidance(
    errors: list[str], content: str | None = None, relative_path: str = "references/local-inference.md"
) -> None:
    if content is None:
        path = REPO_ROOT / relative_path
        if not path.is_file():
            return
        content = path.read_text(encoding="utf-8")
    unconditional_command = "python3 scripts/evaluate_return.py --file local-return.md --peer-review-required"
    baseline_section = content.split("Add `--peer-review-required` only when", 1)[0]
    if unconditional_command in baseline_section:
        errors.append(
            f"{relative_path} must show local-worker evaluation without unconditional --peer-review-required"
        )
    required_terms = [
        "python3 scripts/evaluate_return.py --file local-return.md",
        "--executor openshift_ai_vllm_worker",
        "provider_trust_tier",
        "provenance_class",
        "Add `--peer-review-required` only when",
        "route_work.py",
        "evaluator policy",
    ]
    missing = [term for term in required_terms if term not in content]
    if missing:
        errors.append(f"{relative_path} is missing route-derived peer-review guidance: {', '.join(missing)}")


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
