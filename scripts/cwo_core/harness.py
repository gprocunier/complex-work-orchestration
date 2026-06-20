from __future__ import annotations

from typing import Any

from .policy import load_policy
from .util import artifact_hash


HARNESS_DISPATCH_REQUIRED_FIELDS = [
    "envelope_type",
    "version",
    "envelope_version",
    "dispatch_id",
    "environment",
    "mode",
    "harness",
    "role",
    "lifecycle_state",
    "prompt",
    "prompt_sha256",
    "suggested_command",
    "capability_requirements",
    "execution_enabled",
    "timeout_seconds",
    "constraints",
]

SUPPORTED_HARNESS_ENVELOPE_VERSIONS = {"1.0"}
SUPPORTED_LIFECYCLE_STATES = {"rendered", "accepted", "running", "completed", "failed", "rejected"}


def harness_registry() -> dict[str, Any]:
    return load_policy("harness-registry")


def execution_environment_registry() -> dict[str, Any]:
    return load_policy("execution-environments")


def validate_execution_environment_registry() -> list[str]:
    errors: list[str] = []
    harnesses = harness_registry().get("harnesses", {})
    environments = execution_environment_registry().get("profiles", {})
    providers = load_policy("provider-registry").get("providers", {})
    executors = load_policy("executor-registry").get("executors", {})

    if not isinstance(harnesses, dict) or not harnesses:
        return ["harness registry must define at least one harness"]
    if not isinstance(environments, dict) or not environments:
        return ["execution environment registry must define at least one profile"]

    for key, harness in harnesses.items():
        if not isinstance(harness, dict):
            errors.append(f"harness {key!r} must be an object")
            continue
        if not harness.get("primary_command"):
            errors.append(f"harness {key!r} is missing primary_command")
        if "supports_repo_write" not in harness:
            errors.append(f"harness {key!r} is missing supports_repo_write")
        if not isinstance(harness.get("default_timeout_seconds"), int):
            errors.append(f"harness {key!r} is missing integer default_timeout_seconds")
        if key == "opencode":
            if not harness.get("noninteractive"):
                errors.append("OpenCode exemplar must support noninteractive dispatch")
            if not harness.get("structured_output"):
                errors.append("OpenCode exemplar must support structured output")
            if not harness.get("supports_local_openai_compatible"):
                errors.append("OpenCode exemplar must support OpenAI-compatible local endpoints")
            safe_tools = set(harness.get("safe_default_tools", []))
            if not {"read", "glob", "grep"}.issubset(safe_tools):
                errors.append("OpenCode exemplar must define read/glob/grep as safe default tools")

    for env_key, profile in environments.items():
        if not isinstance(profile, dict):
            errors.append(f"execution environment {env_key!r} must be an object")
            continue
        default_harness = profile.get("default_harness")
        allowed_harnesses = profile.get("allowed_harnesses", [])
        allowed_providers = profile.get("allowed_providers", [])
        if default_harness not in harnesses:
            errors.append(f"execution environment {env_key!r} references unknown default_harness {default_harness!r}")
        for harness_key in allowed_harnesses:
            if harness_key not in harnesses:
                errors.append(f"execution environment {env_key!r} allows unknown harness {harness_key!r}")
        if default_harness and default_harness not in allowed_harnesses:
            errors.append(f"execution environment {env_key!r} default_harness must be in allowed_harnesses")
        for provider_key in allowed_providers:
            if provider_key not in providers:
                errors.append(f"execution environment {env_key!r} allows unknown provider {provider_key!r}")

        constraints = profile.get("constraints", {})
        if constraints.get("beads_required") is not True:
            errors.append(f"execution environment {env_key!r} must require Beads")
        if constraints.get("execution_lifecycle_owner") != "CWO":
            errors.append(f"execution environment {env_key!r} must set execution_lifecycle_owner=CWO")
        if constraints.get("concurrent_bead_execution") != "disabled-by-default":
            errors.append(f"execution environment {env_key!r} must disable concurrent Bead execution by default")
        if profile.get("mode") == "airgapped" and constraints.get("external_contracting") != "disabled":
            errors.append(f"airgapped execution environment {env_key!r} must disable external contracting")

        for role, binding in (profile.get("role_bindings") or {}).items():
            if not isinstance(binding, dict):
                errors.append(f"execution environment {env_key!r} role {role!r} binding must be an object")
                continue
            harness_key = binding.get("harness")
            if harness_key not in harnesses:
                errors.append(f"execution environment {env_key!r} role {role!r} references unknown harness {harness_key!r}")
            executor_key = binding.get("executor")
            if executor_key and executor_key not in executors:
                errors.append(f"execution environment {env_key!r} role {role!r} references unknown executor {executor_key!r}")
    return errors


def validate_harness_dispatch_envelope(envelope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(envelope, dict):
        return ["harness dispatch envelope must be an object"]
    for field in HARNESS_DISPATCH_REQUIRED_FIELDS:
        if field not in envelope:
            errors.append(f"harness dispatch envelope is missing {field!r}")
    if errors:
        return errors
    if envelope.get("envelope_type") != "harness-dispatch":
        errors.append("harness dispatch envelope has invalid envelope_type")
    if envelope.get("envelope_version") not in SUPPORTED_HARNESS_ENVELOPE_VERSIONS:
        errors.append(f"unsupported harness dispatch envelope_version {envelope.get('envelope_version')!r}")
    if envelope.get("lifecycle_state") not in SUPPORTED_LIFECYCLE_STATES:
        errors.append(f"unsupported harness dispatch lifecycle_state {envelope.get('lifecycle_state')!r}")
    if envelope.get("execution_enabled") is not False:
        errors.append("rendered harness dispatch envelopes must not enable execution")
    requirements = envelope.get("capability_requirements")
    if not isinstance(requirements, dict):
        errors.append("harness dispatch envelope capability_requirements must be an object")
    return errors


def build_harness_prompt(
    *,
    task: str,
    role: str,
    environment_key: str,
    bead_id: str | None,
    epic_id: str | None,
) -> str:
    return (
        "You are executing a bounded Complex Work Orchestration assignment.\n"
        "Return evidence only. Do not claim authority to accept, merge, publish, "
        "close Beads, or expand scope.\n\n"
        f"Execution environment: {environment_key}\n"
        f"Role: {role}\n"
        f"Bead: {bead_id or 'unassigned'}\n"
        f"Epic: {epic_id or 'none'}\n\n"
        "CWO rules:\n"
        "- Keep Beads and validation evidence authoritative.\n"
        "- Do not include secrets or local credentials in output.\n"
        "- State files inspected, commands you recommend, risks, and confidence.\n"
        "- If repo mutation is requested, stop and ask for an explicit mutable harness lane.\n\n"
        f"Task:\n{task}\n"
    )


def build_harness_dispatch(
    *,
    task: str,
    dispatch_id: str,
    environment_key: str,
    role: str,
    harness_key: str | None = None,
    bead_id: str | None = None,
    epic_id: str | None = None,
    agent: str | None = None,
    model: str | None = None,
    variant: str | None = None,
    capability_requirements: dict[str, bool] | None = None,
) -> dict[str, Any]:
    environments = execution_environment_registry().get("profiles", {})
    if environment_key not in environments:
        raise SystemExit(f"unknown execution environment: {environment_key}")
    environment = environments[environment_key]
    selected_harness = harness_key or str(environment.get("default_harness"))
    harnesses = harness_registry().get("harnesses", {})
    if selected_harness not in harnesses:
        raise SystemExit(f"unknown harness: {selected_harness}")
    if selected_harness not in set(environment.get("allowed_harnesses", [])):
        raise SystemExit(f"harness {selected_harness!r} is not allowed in environment {environment_key!r}")
    requirements = {
        "supports_repo_read": True,
        "supports_repo_write": False,
        "supports_shell": False,
        "supports_web": False,
        "supports_local_openai_compatible": False,
        **(capability_requirements or {}),
    }
    harness = harnesses[selected_harness]
    for capability, required in requirements.items():
        if required and harness.get(capability) is not True:
            raise SystemExit(f"harness {selected_harness!r} does not satisfy required capability {capability!r}")

    prompt = build_harness_prompt(
        task=task,
        role=role,
        environment_key=environment_key,
        bead_id=bead_id,
        epic_id=epic_id,
    )
    command = _suggested_command(
        harness_key=selected_harness,
        agent=agent,
        model=model,
        variant=variant,
    )
    return {
        "envelope_type": "harness-dispatch",
        "version": 1,
        "envelope_version": "1.0",
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "epic_id": epic_id,
        "environment": environment_key,
        "mode": environment.get("mode"),
        "harness": selected_harness,
        "role": role,
        "lifecycle_state": "rendered",
        "agent": agent,
        "model": model,
        "variant": variant,
        "prompt": prompt,
        "prompt_sha256": artifact_hash(prompt),
        "suggested_command": command,
        "capability_requirements": requirements,
        "execution_enabled": False,
        "timeout_seconds": int(harness.get("default_timeout_seconds", 1800)),
        "constraints": environment.get("constraints", {}),
        "harness_capabilities": {
            "noninteractive": harness.get("noninteractive"),
            "structured_output": harness.get("structured_output"),
            "supports_local_openai_compatible": harness.get("supports_local_openai_compatible"),
            "supports_repo_write": harness.get("supports_repo_write"),
            "permission_model": harness.get("permission_model"),
        },
    }


def _suggested_command(
    *,
    harness_key: str,
    agent: str | None,
    model: str | None,
    variant: str | None,
) -> str:
    if harness_key == "opencode":
        parts = ["opencode", "run", "--dir", "<repo>", "--format", "json"]
        if agent:
            parts.extend(["--agent", agent])
        if model:
            parts.extend(["--model", model])
        if variant:
            parts.extend(["--variant", variant])
        parts.append('"$(cat <prompt-file>)"')
        return " ".join(parts)
    if harness_key == "manual_operator":
        return "Review <prompt-file> and execute under local operator controls."
    if harness_key == "codex_cli":
        return "Use the Codex conversation with the installed $complex-work-orchestration skill."
    return f"{harness_key} <prompt-file>"
