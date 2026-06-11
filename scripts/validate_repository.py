#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from orchestration_lib import (
    CONTRACTOR_PACKET_REQUIRED_FIELDS,
    LOCAL_DISPATCH_REQUIRED_FIELDS,
    POLICY_DIR,
    PROMPT_COACH_RESULT_REQUIRED_FIELDS,
    REPO_ROOT,
    load_policy,
)

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
]


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
        providers = load_policy("provider-registry").get("providers", {})
        peer_review = load_policy("peer-review-policy")
    except SystemExit as exc:
        return [str(exc)]

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
    for required_expert in ["peer_review", "sabotage_review"]:
        if required_expert not in experts:
            errors.append(f"expert registry is missing required {required_expert!r} gate")

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
            "signal_categories",
            "peer_review_required",
            "peer_review_status",
            "human_adjudication_required",
            "recommended_disposition",
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

    require_doc_terms(
        errors,
        "README.md",
        [
            "https://gprocunier.github.io/complex-work-orchestration/",
            "/plan Use $complex-work-orchestration prompt coach",
            "The normal interface is the Codex conversation",
            "scripts/coach_prompt.py",
            "Advanced helper scripts",
            "references/prompt-coach.md",
            "prompt-coach results",
            "interactive_questions",
            "beads_tracking_required",
            "Beads tracking is mandatory",
            "Main-Thread PM Dispatch Flow",
            "claude -p",
            "agy -p",
            "native Beads fields",
            "`skills`",
            "`acceptance`",
            "`design`",
            "`notes`",
            "full-harness request",
            "contractor lanes",
            "OpenShift AI vLLM",
            "--local-ok",
            "--prefer-local",
            "--local-profile openshift-ai-vllm",
            "references/local-inference.md",
            "malpractice_score",
            "peer_review_required",
            "schemas/local-dispatch-envelope.schema.json",
            "references/redhat-expert-catalog.md",
            "contract-jd-redhat-<name>",
        ],
    )
    require_doc_terms(
        errors,
        "docs/index.html",
        [
            "Complex Work Orchestration",
            "Diátaxis documentation map",
            "Two-minute version",
            "The first-class interface is the Codex conversation",
            "/plan Use $complex-work-orchestration prompt coach",
            "Beads graph",
            "./get-started.html",
            "./prompt-coach.html",
            "./workflows.html",
            "./workflows.html#optional-lanes",
            "./reference.html",
            "Red Hat UX reference",
            "https://github.com/gprocunier/complex-work-orchestration",
        ],
    )
    require_doc_terms(
        errors,
        "docs/get-started.html",
        [
            "Get Started",
            "CODEX_SKILLS_DIR",
            "/plan Use $complex-work-orchestration prompt coach",
            "Advanced operator-shell equivalent",
            "scripts/coach_prompt.py",
            "bd ready",
            "no-codex-exec",
            "./workflows.html",
            "skills",
            "acceptance",
            "design",
            "notes",
        ],
    )
    require_doc_terms(
        errors,
        "docs/prompt-coach.html",
        [
            "Prompt Coach",
            "/plan Use $complex-work-orchestration prompt coach",
            "Advanced operator-shell equivalent",
            "interactive_questions",
            "Publish Release",
            "outside-sharing boundary",
            "local-worker opt-in",
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
            "Beads Work Graph",
            "Optional Lanes",
            "Validate And Handoff",
            "/plan Use $complex-work-orchestration prompt coach",
            "scripts/coach_prompt.py",
            "scripts/scaffold_workgraph.py",
            "scripts/build_contractor_packet.py",
            "scripts/dispatch_work.py",
            "--local-ok",
            "--prefer-local",
            "--local-profile openshift-ai-vllm",
            "--execute-local",
            "claude -p",
            "agy -p",
            "contractor-dispatch-prompt.md",
            "normalize_contractor_return.py",
            "evaluate_return.py",
        ],
    )
    require_doc_terms(
        errors,
        "docs/external-contracting.html",
        [
            "External Contracting",
            "guided workflow",
            "third-party model contractor",
            "contractor-only",
            "contract-jd-security-reasoning",
            "skills",
            "acceptance",
            "design",
            "notes",
            "./workflows.html#optional-lanes",
            "claude -p",
            "agy -p",
            "normalize_contractor_return.py",
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
            "policy/routing-policy.yaml",
            "schemas",
            "OpenShift AI",
            "./workflows.html",
            "./external-contracting.html",
            "./local-workers.html",
            "--local-ok",
            "--local-profile openshift-ai-vllm",
            "architect adjudication",
            "claude -p",
            "agy -p",
            "skills",
            "acceptance",
            "design",
            "notes",
            "scripts/validate_site.py",
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
            "references/prompt-coach.md",
            "interactive_questions",
            "Beads tracking is mandatory",
            "beads_tracking_required",
            "--skills",
            "--acceptance",
            "--design",
            "--notes",
            "docs/workflows.html",
            "docs/local-workers.html",
            "/plan",
            "claude -p",
            "agy -p",
            "OpenShift AI vLLM",
            "local-profile",
            "peer_review_required",
            "malpractice_score",
            "references/redhat-expert-catalog.md",
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
            "beads_tracking_required",
            "contractor lanes",
            "in-thread",
            "lightweight-beads",
            "full-harness",
            "external-contract",
            "local-worker",
            "publish-release",
        ],
    )
    require_doc_terms(
        errors,
        "examples/prompt-coach-examples.md",
        [
            "interactive_questions",
            "beads_tracking_required",
            "Explicit Scaffold",
            "Contractor Lane Scaffold",
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
        ],
    )
    require_doc_terms(
        errors,
        "references/external-contracting.md",
        ["Peer-review disposition", "malpractice_score", "contract-jd-sabotage-review"],
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

    validate_ci_workflow(errors)

    return errors


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
    missing = [term for term in terms if term not in content]
    if missing:
        errors.append(f"{relative_path} is missing required terms: {', '.join(missing)}")


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
