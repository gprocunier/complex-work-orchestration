from __future__ import annotations

import shlex
from typing import Any

from .access_profiles import (
    access_profile_for_binding,
    access_profile_runtime_status,
    access_profiles,
    sanitized_access_profile,
    validate_access_profile_registry,
)
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
    "agent",
    "model",
    "variant",
    "model_profile",
    "model_profile_details",
    "prompt",
    "prompt_sha256",
    "suggested_command",
    "capability_requirements",
    "execution_enabled",
    "timeout_seconds",
    "constraints",
]
MODEL_PROFILE_REQUIRED_FIELDS = [
    "display_name",
    "provider_key",
    "local_profile",
    "huggingface_model_id",
    "model_alias",
    "publisher",
    "source_url",
    "license",
    "artifact",
    "quantization",
    "vllm_compatible",
    "endpoint_path",
    "recommended_roles",
    "substitute_confidence",
    "deployment_class",
    "deployment_tier",
    "hardware_profile",
    "recommended_enterprise_scale",
    "benchmark_gate",
    "promotion_status",
    "context_window",
    "strengths",
    "limits",
]

SUPPORTED_HARNESS_ENVELOPE_VERSIONS = {"1.0"}
SUPPORTED_LIFECYCLE_STATES = {"rendered", "accepted", "running", "completed", "failed", "rejected"}


def harness_registry() -> dict[str, Any]:
    return load_policy("harness-registry")


def execution_environment_registry() -> dict[str, Any]:
    return load_policy("execution-environments")


def model_profile_registry() -> dict[str, Any]:
    return load_policy("model-profiles")


def model_profiles() -> dict[str, Any]:
    profiles = model_profile_registry().get("profiles", {})
    return profiles if isinstance(profiles, dict) else {}


def model_profile(profile_key: str | None) -> dict[str, Any]:
    if not profile_key:
        return {}
    profile = model_profiles().get(profile_key)
    if not isinstance(profile, dict):
        return {}
    value = dict(profile)
    value.setdefault("key", profile_key)
    return value


def validate_model_profile_registry() -> list[str]:
    errors: list[str] = []
    registry = model_profile_registry()
    profiles = registry.get("profiles", {})
    providers = load_policy("provider-registry").get("providers", {})

    if registry.get("schema") != "json-compatible-yaml":
        errors.append("model profile registry must use schema=json-compatible-yaml")
    if not isinstance(profiles, dict) or not profiles:
        errors.append("model profile registry must define profiles")
        return errors

    for key, profile in profiles.items():
        if not isinstance(profile, dict):
            errors.append(f"model profile {key!r} must be an object")
            continue
        for field in MODEL_PROFILE_REQUIRED_FIELDS:
            if field not in profile:
                errors.append(f"model profile {key!r} is missing {field!r}")
        provider_key = profile.get("provider_key")
        if provider_key not in providers:
            errors.append(f"model profile {key!r} references unknown provider_key {provider_key!r}")
        if profile.get("endpoint_path") != "/v1/chat/completions":
            errors.append(f"model profile {key!r} must use /v1/chat/completions")
        if profile.get("substitute_confidence") not in {"high", "medium", "low"}:
            errors.append(f"model profile {key!r} has invalid substitute_confidence")
        if not isinstance(profile.get("recommended_roles"), list) or not profile.get("recommended_roles"):
            errors.append(f"model profile {key!r} must list recommended_roles")
        if profile.get("vllm_compatible") is not True:
            errors.append(f"model profile {key!r} must be vLLM compatible")
        source_url = str(profile.get("source_url", ""))
        if not source_url.startswith("https://huggingface.co/"):
            errors.append(f"model profile {key!r} source_url must be a Hugging Face URL")
        if not isinstance(profile.get("benchmark_gate"), list) or not profile.get("benchmark_gate"):
            errors.append(f"model profile {key!r} must define benchmark_gate")
        if not profile.get("deployment_tier"):
            errors.append(f"model profile {key!r} must define deployment_tier")
        if not profile.get("hardware_profile"):
            errors.append(f"model profile {key!r} must define hardware_profile")
        if not profile.get("recommended_enterprise_scale"):
            errors.append(f"model profile {key!r} must define recommended_enterprise_scale")
        if profile.get("promotion_status") not in {"practical-default", "candidate", "validated", "fallback"}:
            errors.append(f"model profile {key!r} has invalid promotion_status")

    matrix = registry.get("role_substitution_matrix", [])
    if not isinstance(matrix, list) or not matrix:
        errors.append("model profile registry must define role_substitution_matrix")
    else:
        seen_roles: set[str] = set()
        for index, row in enumerate(matrix):
            if not isinstance(row, dict):
                errors.append(f"role_substitution_matrix[{index}] must be an object")
                continue
            role = str(row.get("cwo_role") or "")
            if role:
                seen_roles.add(role)
            for field in ["cwo_role", "connected_default", "airgapped_profile", "substitute_confidence", "boundary"]:
                if not row.get(field):
                    errors.append(f"role_substitution_matrix[{index}] is missing {field!r}")
            profile_key = row.get("airgapped_profile")
            if profile_key not in profiles:
                errors.append(f"role_substitution_matrix[{index}] references unknown profile {profile_key!r}")
            enterprise_profiles = row.get("enterprise_profiles", [])
            if enterprise_profiles and not isinstance(enterprise_profiles, list):
                errors.append(f"role_substitution_matrix[{index}] enterprise_profiles must be a list")
            for enterprise_profile in enterprise_profiles if isinstance(enterprise_profiles, list) else []:
                if enterprise_profile not in profiles:
                    errors.append(
                        f"role_substitution_matrix[{index}] references unknown enterprise profile {enterprise_profile!r}"
                    )
        for required_role in ["architect", "project_manager", "workerbee", "review_worker", "local_secure_reviewer", "synthesis_input"]:
            if required_role not in seen_roles:
                errors.append(f"role_substitution_matrix missing role {required_role!r}")
    return errors


def sanitized_model_profile(profile_key: str | None) -> dict[str, Any] | None:
    profile = model_profile(profile_key)
    if not profile:
        return None
    return {
        "key": profile.get("key"),
        "display_name": profile.get("display_name"),
        "provider_key": profile.get("provider_key"),
        "local_profile": profile.get("local_profile"),
        "huggingface_model_id": profile.get("huggingface_model_id"),
        "model_alias": profile.get("model_alias"),
        "source_url": profile.get("source_url"),
        "license": profile.get("license"),
        "precision": profile.get("precision"),
        "thinking_enabled": profile.get("thinking_enabled"),
        "reasoning_mode": profile.get("reasoning_mode"),
        "request_options": profile.get("request_options", {}),
        "required_vllm_flags": profile.get("required_vllm_flags", []),
        "vllm_compatible": profile.get("vllm_compatible"),
        "endpoint_path": profile.get("endpoint_path"),
        "recommended_roles": profile.get("recommended_roles", []),
        "substitute_confidence": profile.get("substitute_confidence"),
        "deployment_class": profile.get("deployment_class"),
        "deployment_tier": profile.get("deployment_tier"),
        "hardware_profile": profile.get("hardware_profile"),
        "recommended_enterprise_scale": profile.get("recommended_enterprise_scale"),
        "benchmark_gate": profile.get("benchmark_gate", []),
        "promotion_status": profile.get("promotion_status"),
        "context_window": profile.get("context_window"),
        "strengths": profile.get("strengths", []),
        "limits": profile.get("limits", []),
    }


def validate_execution_environment_registry() -> list[str]:
    errors: list[str] = []
    errors.extend(validate_model_profile_registry())
    errors.extend(validate_access_profile_registry())
    harnesses = harness_registry().get("harnesses", {})
    environments = execution_environment_registry().get("profiles", {})
    providers = load_policy("provider-registry").get("providers", {})
    executors = load_policy("executor-registry").get("executors", {})
    profiles = model_profiles()
    access_profile_configs = access_profiles()

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
            executor = {}
            if executor_key and executor_key not in executors:
                errors.append(f"execution environment {env_key!r} role {role!r} references unknown executor {executor_key!r}")
            elif executor_key:
                executor = dict(executors[executor_key])
                executor.setdefault("key", executor_key)
            profile_key = binding.get("model_profile")
            profile_config = {}
            if profile_key:
                profile_config = profiles.get(profile_key)
                if not isinstance(profile_config, dict):
                    errors.append(f"execution environment {env_key!r} role {role!r} references unknown model_profile {profile_key!r}")
                    profile_config = {}
                else:
                    provider_key = profile_config.get("provider_key")
                    if provider_key not in allowed_providers:
                        errors.append(
                            f"execution environment {env_key!r} role {role!r} model_profile {profile_key!r} "
                            f"uses provider {provider_key!r} not allowed by environment"
                        )
                    if profile_config.get("provider_key") in {"openshift_ai_vllm", "local_inference"}:
                        if harnesses.get(harness_key, {}).get("supports_local_openai_compatible") is not True:
                            errors.append(
                                f"execution environment {env_key!r} role {role!r} model_profile {profile_key!r} "
                                f"requires a local OpenAI-compatible harness"
                            )
            access_profile_key = access_profile_for_binding(
                binding,
                executor=executor,
                model_profile_key=str(profile_key) if profile_key else None,
                model_profile=profile_config if isinstance(profile_config, dict) else {},
            )
            if not access_profile_key:
                errors.append(f"execution environment {env_key!r} role {role!r} does not resolve to an access profile")
            elif access_profile_key not in access_profile_configs:
                errors.append(
                    f"execution environment {env_key!r} role {role!r} references unknown access profile {access_profile_key!r}"
                )
            else:
                access_profile = access_profile_configs[access_profile_key]
                if harness_key not in access_profile.get("harnesses", []):
                    errors.append(
                        f"execution environment {env_key!r} role {role!r} harness {harness_key!r} "
                        f"is not allowed by access profile {access_profile_key!r}"
                    )
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
    prompt = envelope.get("prompt")
    if not isinstance(prompt, str):
        errors.append("harness dispatch envelope prompt must be a string")
    elif envelope.get("prompt_sha256") != artifact_hash(prompt):
        errors.append("harness dispatch envelope prompt_sha256 does not match prompt")
    return errors


def build_harness_prompt(
    *,
    task: str,
    role: str,
    environment_key: str,
    bead_id: str | None,
    epic_id: str | None,
    model_profile_key: str | None = None,
    access_profile_key: str | None = None,
) -> str:
    profile_line = f"Model profile: {model_profile_key}\n" if model_profile_key else ""
    access_profile_line = f"Access profile: {access_profile_key}\n" if access_profile_key else ""
    return (
        "You are executing a bounded Complex Work Orchestration assignment.\n"
        "Return evidence only. Do not claim authority to accept, merge, publish, "
        "close Beads, or expand scope.\n\n"
        f"Execution environment: {environment_key}\n"
        f"Role: {role}\n"
        f"{profile_line}"
        f"{access_profile_line}"
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
    model_profile_key: str | None = None,
    capability_requirements: dict[str, bool] | None = None,
) -> dict[str, Any]:
    environments = execution_environment_registry().get("profiles", {})
    if environment_key not in environments:
        raise SystemExit(f"unknown execution environment: {environment_key}")
    environment = environments[environment_key]
    binding = (environment.get("role_bindings") or {}).get(role)
    if not isinstance(binding, dict):
        raise SystemExit(f"role {role!r} is not bound in execution environment {environment_key!r}")
    selected_harness = harness_key or str(binding.get("harness") or environment.get("default_harness"))
    harnesses = harness_registry().get("harnesses", {})
    if selected_harness not in harnesses:
        raise SystemExit(f"unknown harness: {selected_harness}")
    if selected_harness not in set(environment.get("allowed_harnesses", [])):
        raise SystemExit(f"harness {selected_harness!r} is not allowed in environment {environment_key!r}")
    bound_harness = binding.get("harness")
    if bound_harness and selected_harness != bound_harness:
        raise SystemExit(
            f"role {role!r} in environment {environment_key!r} is bound to harness {bound_harness!r}, "
            f"not {selected_harness!r}"
        )
    resolved_agent = agent or binding.get("agent")
    if model and model_profile_key:
        raise SystemExit("--model and --model-profile are mutually exclusive")
    resolved_profile_key = model_profile_key or (None if model else binding.get("model_profile"))
    resolved_profile = model_profile(str(resolved_profile_key) if resolved_profile_key else None)
    if resolved_profile_key and not resolved_profile:
        raise SystemExit(f"unknown model profile: {resolved_profile_key}")
    bound_executor_key = binding.get("executor")
    executor_details: dict[str, Any] = {}
    if bound_executor_key:
        executors = load_policy("executor-registry").get("executors", {})
        executor = executors.get(bound_executor_key)
        if not isinstance(executor, dict):
            raise SystemExit(f"unknown executor: {bound_executor_key}")
        executor_details = dict(executor)
        executor_details.setdefault("key", bound_executor_key)
    access_profile_model_key = resolved_profile_key or binding.get("model_profile")
    access_profile_model = resolved_profile
    if not access_profile_model and access_profile_model_key:
        access_profile_model = model_profile(str(access_profile_model_key))
    access_profile_key = access_profile_for_binding(
        binding,
        executor=executor_details,
        model_profile_key=str(access_profile_model_key) if access_profile_model_key else None,
        model_profile=access_profile_model,
    )
    access_profile_details = sanitized_access_profile(access_profile_key)
    if access_profile_key and not access_profile_details:
        raise SystemExit(f"unknown access profile: {access_profile_key}")
    if access_profile_details and selected_harness not in set(access_profile_details.get("harnesses", [])):
        raise SystemExit(
            f"harness {selected_harness!r} is not allowed by access profile {access_profile_key!r}"
        )
    requirements = {
        "supports_repo_read": True,
        "supports_repo_write": False,
        "supports_shell": False,
        "supports_web": False,
        "supports_local_openai_compatible": bool(resolved_profile),
        **(capability_requirements or {}),
    }
    harness = harnesses[selected_harness]
    for capability, required in requirements.items():
        if required and harness.get(capability) is not True:
            raise SystemExit(f"harness {selected_harness!r} does not satisfy required capability {capability!r}")
    if resolved_profile:
        provider_key = resolved_profile.get("provider_key")
        if provider_key not in set(environment.get("allowed_providers", [])):
            raise SystemExit(
                f"model profile {resolved_profile_key!r} uses provider {provider_key!r}, "
                f"which is not allowed in environment {environment_key!r}"
            )
    resolved_model = model or resolved_profile.get("model_alias") or resolved_profile.get("huggingface_model_id")
    resolved_variant = variant or resolved_profile.get("default_variant")

    prompt = build_harness_prompt(
        task=task,
        role=role,
        environment_key=environment_key,
        bead_id=bead_id,
        epic_id=epic_id,
        model_profile_key=str(resolved_profile_key) if resolved_profile_key else None,
        access_profile_key=access_profile_key,
    )
    command = _suggested_command(
        harness_key=selected_harness,
        agent=resolved_agent,
        model=resolved_model,
        variant=resolved_variant,
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
        "agent": resolved_agent,
        "model": resolved_model,
        "variant": resolved_variant,
        "model_profile": str(resolved_profile_key) if resolved_profile_key else None,
        "model_profile_details": sanitized_model_profile(str(resolved_profile_key) if resolved_profile_key else None),
        "access_profile": access_profile_key,
        "access_profile_details": access_profile_details,
        "access_profile_readiness": access_profile_runtime_status(access_profile_key),
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
            parts.extend(["--agent", shlex.quote(agent)])
        if model:
            parts.extend(["--model", shlex.quote(model)])
        if variant:
            parts.extend(["--variant", shlex.quote(variant)])
        parts.append('"$(cat <prompt-file>)"')
        return " ".join(parts)
    if harness_key == "manual_operator":
        return "Review <prompt-file> and execute under local operator controls."
    if harness_key == "codex_cli":
        return "Use the Codex conversation with the installed $complex-work-orchestration skill."
    return f"{harness_key} <prompt-file>"
