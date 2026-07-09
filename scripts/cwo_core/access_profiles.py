from __future__ import annotations

import os
from typing import Any, Mapping

from .policy import load_policy


ACCESS_PROFILE_ENV_FIELDS = (
    "base_url_env",
    "api_key_env",
    "config_env",
    "model_env",
    "tls_ca_bundle_env",
    "tls_verify_env",
)


def access_profile_registry() -> dict[str, Any]:
    return load_policy("access-profiles")


def access_profiles() -> dict[str, Any]:
    profiles = access_profile_registry().get("profiles", {})
    return profiles if isinstance(profiles, dict) else {}


def access_profile(profile_key: str | None) -> dict[str, Any]:
    if not profile_key:
        return {}
    profile = access_profiles().get(profile_key)
    if not isinstance(profile, dict):
        return {}
    value = dict(profile)
    value.setdefault("key", profile_key)
    return value


def access_profile_for_model_profile(model_profile_key: str | None, model_profile: Mapping[str, Any] | None) -> str | None:
    if not model_profile_key and not model_profile:
        return None
    profile_key = str(model_profile_key or "").lower()
    provider_key = str((model_profile or {}).get("provider_key") or "").lower()
    if "glm-5-2-bf16" in profile_key:
        return "rhoai-glm-bf16"
    if provider_key == "openshift_ai_vllm":
        return "rhoai-vllm"
    if provider_key == "local_inference":
        return "local-openai-compatible"
    return None


def access_profile_for_executor(executor: Mapping[str, Any] | None) -> str | None:
    if not executor:
        return None
    explicit = executor.get("access_profile")
    if explicit:
        return str(explicit)
    dispatch_mode = str(executor.get("dispatch_mode") or "").lower()
    provider_key = str(executor.get("provider_key") or "").lower()
    role = str(executor.get("role") or "").lower()
    if provider_key == "internal_codex" and dispatch_mode == "main_thread_review":
        return "codex-review-lane"
    if provider_key == "internal_codex":
        return "codex-connected-shell"
    if provider_key == "local_inference":
        return "local-openai-compatible"
    if provider_key == "openshift_ai_vllm":
        model_profile_key = str(executor.get("model_profile") or "").lower()
        if "glm-5-2-bf16" in model_profile_key:
            return "rhoai-glm-bf16"
        return "rhoai-vllm"
    if provider_key in {"anthropic_manual", "google_gemini_manual"}:
        return "manual-external-cli"
    if provider_key == "openai_manual":
        return "browser-external-review"
    if provider_key == "human_specialist" or role == "outside-contractor-human":
        return "human-specialist-contractor"
    return None


def access_profile_for_binding(
    binding: Mapping[str, Any] | None,
    *,
    executor: Mapping[str, Any] | None = None,
    model_profile_key: str | None = None,
    model_profile: Mapping[str, Any] | None = None,
) -> str | None:
    if binding and binding.get("access_profile"):
        return str(binding["access_profile"])
    executor_profile = access_profile_for_executor(executor)
    if executor_profile:
        return executor_profile
    return access_profile_for_model_profile(model_profile_key, model_profile)


def sanitized_access_profile(profile_key: str | None) -> dict[str, Any] | None:
    profile = access_profile(profile_key)
    if not profile:
        return None
    return {
        "key": profile.get("key"),
        "display_name": profile.get("display_name"),
        "status": profile.get("status"),
        "provider_keys": profile.get("provider_keys", []),
        "harnesses": profile.get("harnesses", []),
        "dispatch_modes": profile.get("dispatch_modes", []),
        "external": profile.get("external"),
        "repo_access": profile.get("repo_access"),
        "tool_access": profile.get("tool_access", {}),
        "disclosure": profile.get("disclosure", {}),
        "credential_sources": profile.get("credential_sources", {}),
        "runtime_readiness": profile.get("runtime_readiness", {}),
        "authority": profile.get("authority", {}),
    }


def _env_status(names: list[str], environ: Mapping[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "name": str(name),
            "configured": bool(environ.get(str(name))),
        }
        for name in names
    ]


def access_profile_runtime_status(
    profile_key: str | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any] | None:
    profile = access_profile(profile_key)
    if not profile:
        return None
    env = environ if environ is not None else os.environ
    credentials = profile.get("credential_sources", {})
    required = [str(name) for name in credentials.get("required_env", [])]
    optional = [str(name) for name in credentials.get("optional_env", [])]
    required_status = _env_status(required, env)
    optional_status = _env_status(optional, env)
    missing_required = [item["name"] for item in required_status if not item["configured"]]
    return {
        "access_profile": profile.get("key", profile_key),
        "display_name": profile.get("display_name"),
        "status": profile.get("status"),
        "ready": not missing_required,
        "missing_required_env": missing_required,
        "required_env": required_status,
        "optional_env": optional_status,
    }


def executor_transport_env_names(executor: Mapping[str, Any]) -> set[str]:
    transport = executor.get("transport") if isinstance(executor.get("transport"), dict) else {}
    names: set[str] = set()
    for field in ACCESS_PROFILE_ENV_FIELDS:
        value = transport.get(field)
        if value:
            names.add(str(value))
    return names


def validate_access_profile_registry() -> list[str]:
    errors: list[str] = []
    registry = access_profile_registry()
    profiles = registry.get("profiles", {})
    providers = load_policy("provider-registry").get("providers", {})
    harnesses = load_policy("harness-registry").get("harnesses", {})
    executors = load_policy("executor-registry").get("executors", {})

    if registry.get("schema") != "json-compatible-yaml":
        errors.append("access profile registry must use schema=json-compatible-yaml")
    if not isinstance(profiles, dict) or not profiles:
        errors.append("access profile registry must define profiles")
        return errors

    for key, profile in profiles.items():
        if not isinstance(profile, dict):
            errors.append(f"access profile {key!r} must be an object")
            continue
        for field in [
            "display_name",
            "status",
            "provider_keys",
            "harnesses",
            "dispatch_modes",
            "external",
            "repo_access",
            "tool_access",
            "disclosure",
            "credential_sources",
            "runtime_readiness",
            "authority",
        ]:
            if field not in profile:
                errors.append(f"access profile {key!r} is missing {field!r}")
        if profile.get("status") not in {"available", "offline", "experimental", "deprecated"}:
            errors.append(f"access profile {key!r} has invalid status")
        if profile.get("repo_access") not in {"none", "read-only", "read-write", "bounded"}:
            errors.append(f"access profile {key!r} has invalid repo_access")
        provider_keys = profile.get("provider_keys", [])
        if not isinstance(provider_keys, list) or not provider_keys:
            errors.append(f"access profile {key!r} must list provider_keys")
        for provider_key in provider_keys if isinstance(provider_keys, list) else []:
            if provider_key not in providers:
                errors.append(f"access profile {key!r} references unknown provider {provider_key!r}")
        for harness_key in profile.get("harnesses", []) if isinstance(profile.get("harnesses"), list) else []:
            if harness_key not in harnesses:
                errors.append(f"access profile {key!r} references unknown harness {harness_key!r}")
        tool_access = profile.get("tool_access", {})
        if not isinstance(tool_access, dict):
            errors.append(f"access profile {key!r} tool_access must be an object")
        else:
            for field in ["shell", "web", "repo_read", "repo_write", "local_openai_compatible"]:
                if not isinstance(tool_access.get(field), bool):
                    errors.append(f"access profile {key!r} tool_access.{field} must be boolean")
        credentials = profile.get("credential_sources", {})
        if not isinstance(credentials, dict):
            errors.append(f"access profile {key!r} credential_sources must be an object")
        else:
            for field in ["required_env", "optional_env"]:
                if not isinstance(credentials.get(field), list):
                    errors.append(f"access profile {key!r} credential_sources.{field} must be a list")
        readiness = profile.get("runtime_readiness", {})
        if not isinstance(readiness, dict) or not isinstance(readiness.get("missing_required_env_is_error"), bool):
            errors.append(f"access profile {key!r} runtime_readiness.missing_required_env_is_error must be boolean")
        authority = profile.get("authority", {})
        if not isinstance(authority, dict):
            errors.append(f"access profile {key!r} authority must be an object")
        else:
            for field in ["evidence_only", "may_execute", "may_write_repo"]:
                if not isinstance(authority.get(field), bool):
                    errors.append(f"access profile {key!r} authority.{field} must be boolean")

    for executor_key, executor in executors.items():
        if not isinstance(executor, dict):
            continue
        profile_key = access_profile_for_executor(executor)
        if not profile_key:
            errors.append(f"executor {executor_key!r} does not resolve to an access profile")
            continue
        profile = profiles.get(profile_key)
        if not isinstance(profile, dict):
            errors.append(f"executor {executor_key!r} references unknown access profile {profile_key!r}")
            continue
        provider_key = executor.get("provider_key")
        if provider_key not in profile.get("provider_keys", []):
            errors.append(
                f"executor {executor_key!r} provider {provider_key!r} is not allowed by access profile {profile_key!r}"
            )
        dispatch_mode = executor.get("dispatch_mode")
        if dispatch_mode not in profile.get("dispatch_modes", []):
            errors.append(
                f"executor {executor_key!r} dispatch mode {dispatch_mode!r} is not allowed by access profile {profile_key!r}"
            )
        if bool(executor.get("external")) != bool(profile.get("external")):
            errors.append(f"executor {executor_key!r} external flag does not match access profile {profile_key!r}")
        env_names = executor_transport_env_names(executor)
        if env_names:
            credentials = profile.get("credential_sources", {})
            listed = set(credentials.get("required_env", [])) | set(credentials.get("optional_env", []))
            missing = sorted(env_names - listed)
            if missing:
                errors.append(
                    f"executor {executor_key!r} transport env vars are missing from access profile {profile_key!r}: "
                    + ", ".join(missing)
                )
    return errors
