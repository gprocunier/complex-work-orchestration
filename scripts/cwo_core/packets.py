from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .paths import REPO_ROOT, assert_repo_safe_path, repo_relative_path
from .policy import boundary_config, load_contracting_controls, load_policy, provider_profile
from .util import artifact_hash, packet_payload_hash, parse_iso_datetime


MANDATORY_EXCLUDED_ARTIFACTS = {"full_bead_json", "secrets", "production_access"}
SECRET_LIKE_FIELD_RE = re.compile(r"(?i)(api[_-]?key|token|password|secret|credential|private[_-]?key)")
DEFAULT_REDACTION_PATTERNS = [
    r"(?i)([\"']?(?:api[_-]?key|token|password|secret|credential)[\"']?\s*[:=]\s*)[\"']?[^\"'\s,}\]]+",
    r"(?i)(\b_?(?:api[_-]?key|token|password|secret|credential)\b\s+)[\"']?[^\"'\s,}\]]+",
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----",
]


CONTRACTOR_PACKET_REQUIRED_FIELDS = [
    "dispatch_id",
    "generated_at",
    "bead_id",
    "executor",
    "provider_key",
    "provider_trust_tier",
    "share_boundary",
    "disclosure_stage",
    "disclosure_escalation_approved",
    "job_description_label",
    "expert_profile_included",
    "degraded_context_justification",
    "external_opt_in",
    "opt_in_basis",
    "boundary_description",
    "bead_summary",
    "selected_snippets",
    "included_artifacts",
    "excluded_artifacts",
    "required_return_sections",
    "acceptance_rule",
    "quota_checked",
    "packet_sha256",
]


LOCAL_DISPATCH_REQUIRED_FIELDS = [
    "envelope_type",
    "version",
    "dispatch_id",
    "executor_key",
    "provider_key",
    "transport_kind",
    "messages",
    "constraints",
    "execution_enabled",
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in [*DEFAULT_REDACTION_PATTERNS, *load_policy("share-boundaries").get("redaction_patterns", [])]:
        redacted = re.sub(pattern, lambda match: (match.group(1) if match.groups() else "") + "[REDACTED]", redacted)
    return redacted


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def sanitize_boundary_value(value: Any, forbidden: set[str]) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in forbidden:
                continue
            if SECRET_LIKE_FIELD_RE.search(key_text):
                sanitized[key_text] = "[REDACTED]"
                continue
            sanitized[key_text] = sanitize_boundary_value(item, forbidden)
        return sanitized
    if isinstance(value, list):
        return [sanitize_boundary_value(item, forbidden) for item in value]
    return redact_value(value)


def sanitize_bead(bead_json: Any, share_boundary: str) -> dict[str, Any]:
    boundary = boundary_config(share_boundary)
    whitelist = set(boundary.get("field_whitelist", []))
    forbidden = set(boundary.get("forbidden_fields", []))
    if isinstance(bead_json, list) and len(bead_json) == 1 and isinstance(bead_json[0], dict):
        bead_json = bead_json[0]
    elif isinstance(bead_json, list):
        return {
            "raw_type": "list",
            "item_count": len(bead_json),
            "reason": "multi-item bead list requires explicit selection before sharing",
        }
    if not isinstance(bead_json, dict):
        return {"raw_type": type(bead_json).__name__}
    source = bead_json.get("issue") if isinstance(bead_json.get("issue"), dict) else bead_json
    sanitized: dict[str, Any] = {}
    for key, value in source.items():
        if key in forbidden:
            continue
        if whitelist and key not in whitelist:
            continue
        if SECRET_LIKE_FIELD_RE.search(str(key)):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = sanitize_boundary_value(value, forbidden)
    return sanitized


def artifact_whitelist_for_boundary(share_boundary: str) -> set[str]:
    return set(boundary_config(share_boundary).get("artifact_whitelist", []))


def validate_opt_in_record(
    path: str | Path,
    *,
    executor: str,
    share_boundary: str,
    bead_id: str | None = None,
    epic_id: str | None = None,
) -> dict[str, Any]:
    record_path = Path(path)
    if not record_path.is_file():
        raise SystemExit(f"opt-in record does not exist: {record_path}")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"opt-in record is not valid JSON: {record_path}: {exc}") from exc
    if not isinstance(record, dict):
        raise SystemExit("opt-in record must contain a top-level object")

    if record.get("allowed") is not True and record.get("external_contracting_allowed") is not True:
        raise SystemExit("opt-in record must set allowed=true or external_contracting_allowed=true")

    boundaries = record.get("share_boundaries", record.get("share_boundary"))
    if isinstance(boundaries, str):
        boundary_allowed = boundaries in [share_boundary, "*"]
    elif isinstance(boundaries, list):
        boundary_allowed = share_boundary in boundaries or "*" in boundaries
    else:
        boundary_allowed = False
    if not boundary_allowed:
        raise SystemExit(f"opt-in record does not allow share boundary {share_boundary!r}")

    executors = record.get(
        "allowed_external_executors",
        record.get("allowed_executors", record.get("executors", record.get("executor"))),
    )
    if isinstance(executors, str):
        executor_allowed = executors in [executor, "*"]
    elif isinstance(executors, list):
        executor_allowed = executor in executors or "*" in executors
    else:
        executor_allowed = False
    if not executor_allowed:
        raise SystemExit(f"opt-in record does not allow executor {executor!r}")
    allowed_providers = record.get("allowed_providers")
    if allowed_providers is not None:
        executor_config = load_policy("executor-registry").get("executors", {}).get(executor, {})
        provider_key = executor_config.get("provider_key")
        if isinstance(allowed_providers, str):
            provider_allowed = allowed_providers in [provider_key, "*"]
        elif isinstance(allowed_providers, list):
            provider_allowed = provider_key in allowed_providers or "*" in allowed_providers
        else:
            provider_allowed = False
        if not provider_allowed:
            raise SystemExit(f"opt-in record does not allow provider {provider_key!r}")

    if not record.get("decision_source"):
        raise SystemExit("opt-in record must include decision_source")
    if not record.get("recorded_at"):
        raise SystemExit("opt-in record must include recorded_at")
    parse_iso_datetime(str(record["recorded_at"]), "recorded_at")
    expires_at = record.get("expires_at")
    if expires_at:
        expiry = parse_iso_datetime(str(expires_at), "expires_at")
        if expiry <= dt.datetime.now(dt.timezone.utc):
            raise SystemExit("opt-in record has expired")
    if not record.get("scope"):
        raise SystemExit("opt-in record must include scope")
    record_bead = record.get("bead_id")
    if record_bead and bead_id and record_bead != bead_id:
        raise SystemExit(f"opt-in record bead_id {record_bead!r} does not match assigned bead {bead_id!r}")
    record_epic = record.get("epic_id")
    if record_epic and epic_id and record_epic != epic_id:
        raise SystemExit(f"opt-in record epic_id {record_epic!r} does not match assigned epic {epic_id!r}")
    return record


def find_forbidden_fields(value: Any, forbidden_fields: set[str], prefix: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if key in forbidden_fields:
                hits.append(path)
            hits.extend(find_forbidden_fields(item, forbidden_fields, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            hits.extend(find_forbidden_fields(item, forbidden_fields, path))
    return hits


def validate_contractor_packet(packet: dict[str, Any], *, allow_degraded_packet: bool = False) -> list[str]:
    errors: list[str] = []
    if not isinstance(packet, dict):
        return ["packet must contain a top-level object"]

    for field in CONTRACTOR_PACKET_REQUIRED_FIELDS:
        if field not in packet:
            errors.append(f"packet is missing required field {field!r}")
    if errors:
        return errors

    executor_key = str(packet.get("executor", ""))
    executors = load_policy("executor-registry").get("executors", {})
    executor = executors.get(executor_key)
    if not isinstance(executor, dict):
        errors.append(f"packet executor {executor_key!r} is unknown")
    elif not executor.get("external"):
        errors.append(f"packet executor {executor_key!r} is not an outside contractor executor")
    elif packet.get("provider_key") != executor.get("provider_key"):
        errors.append(f"packet provider_key {packet.get('provider_key')!r} does not match executor provider")
    elif packet.get("provider_trust_tier") != provider_profile(executor.get("provider_key")).get("trust_tier"):
        errors.append(f"packet provider_trust_tier {packet.get('provider_trust_tier')!r} does not match provider registry")

    controls = load_contracting_controls()
    allowed_external = set(controls.get("allowed_external_executors", []))
    if allowed_external and executor_key not in allowed_external:
        errors.append(f"packet executor {executor_key!r} is not allowed by contracting controls")

    share_boundary = str(packet.get("share_boundary", ""))
    try:
        boundary = boundary_config(share_boundary)
    except SystemExit as exc:
        errors.append(str(exc))
        boundary = {}
    if boundary and not boundary.get("allows_external"):
        errors.append(f"packet share boundary {share_boundary!r} does not allow external contracting")
    if boundary:
        expected_stage = str(boundary.get("disclosure_stage", share_boundary))
        if packet.get("disclosure_stage") != expected_stage:
            errors.append(
                f"packet disclosure_stage {packet.get('disclosure_stage')!r} does not match boundary stage {expected_stage!r}"
            )
        if boundary.get("requires_disclosure_escalation") and packet.get("disclosure_escalation_approved") is not True:
            errors.append(f"packet share boundary {share_boundary!r} requires disclosure escalation approval")

    if packet.get("external_opt_in") is not True:
        errors.append("packet external_opt_in must be true")
    if packet.get("opt_in_basis") in [None, "", "not-recorded"]:
        errors.append("packet opt_in_basis must record explicit user opt-in")
    job_label = str(packet.get("job_description_label", ""))
    if not job_label.startswith("contract-jd-"):
        errors.append("packet job_description_label must be a contract-jd label")
    registry_job_labels = {
        str(profile.get("job_description_label"))
        for profile in load_policy("expert-registry").get("experts", {}).values()
        if isinstance(profile, dict) and profile.get("job_description_label")
    }
    if registry_job_labels and job_label not in registry_job_labels:
        errors.append(f"packet job_description_label {job_label!r} is not registered")
    bead_labels = packet.get("bead_summary", {}).get("labels", []) if isinstance(packet.get("bead_summary"), dict) else []
    if isinstance(bead_labels, list):
        job_labels = [str(label) for label in bead_labels if str(label).startswith("contract-jd-")]
        if len(job_labels) > 1:
            errors.append("packet bead_summary contains multiple primary job-description labels: " + ", ".join(job_labels))
        if job_labels and job_label not in job_labels:
            errors.append("packet job_description_label does not match bead_summary job-description label")
    if packet.get("expert_profile_included") is not True and not allow_degraded_packet:
        errors.append("packet is missing the expert profile; pass --allow-degraded-packet to dispatch anyway")
    if packet.get("expert_profile_included") is not True and not str(packet.get("degraded_context_justification", "")).strip():
        errors.append("degraded packet is missing degraded_context_justification")

    expected_hash = packet_payload_hash(packet)
    if packet.get("packet_sha256") != expected_hash:
        errors.append("packet_sha256 does not match packet payload")

    forbidden_fields = set(boundary.get("forbidden_fields", [])) if boundary else set()
    forbidden_hits = find_forbidden_fields(packet, forbidden_fields)
    if forbidden_hits:
        errors.append("packet contains forbidden boundary fields: " + ", ".join(sorted(forbidden_hits)))

    excluded_types = {
        artifact.get("type")
        for artifact in packet.get("excluded_artifacts", [])
        if isinstance(artifact, dict)
    }
    missing_exclusions = sorted(MANDATORY_EXCLUDED_ARTIFACTS - excluded_types)
    if missing_exclusions:
        errors.append("excluded_artifacts is missing mandatory exclusions: " + ", ".join(missing_exclusions))

    whitelist = set(boundary.get("artifact_whitelist", [])) if boundary else set()
    included_artifacts = [item for item in packet.get("included_artifacts", []) if isinstance(item, dict)]
    selected_snippets = [item for item in packet.get("selected_snippets", []) if isinstance(item, dict)]
    snippet_limit = int(boundary.get("snippet_line_limit", 0)) if boundary else 0
    for artifact in packet.get("included_artifacts", []):
        artifact_type = artifact.get("type") if isinstance(artifact, dict) else None
        if not artifact_type:
            errors.append("included_artifacts contains an artifact without a type")
        elif artifact_type not in whitelist:
            errors.append(f"artifact type {artifact_type!r} is not allowed by share boundary {share_boundary!r}")

    for snippet in packet.get("selected_snippets", []):
        if not isinstance(snippet, dict):
            errors.append("selected_snippets contains a non-object entry")
            continue
        required_snippet_fields = {"type", "path", "line_count", "truncated", "sha256", "content"}
        missing = sorted(required_snippet_fields - set(snippet))
        if missing:
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} is missing fields: {', '.join(missing)}")
        snippet_type = snippet.get("type") if isinstance(snippet, dict) else None
        if snippet_type and snippet_type not in whitelist:
            errors.append(f"snippet artifact type {snippet_type!r} is not allowed by share boundary {share_boundary!r}")
        line_count = snippet.get("line_count")
        if not isinstance(line_count, int):
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} has non-integer line_count")
        elif snippet_limit and line_count > snippet_limit:
            errors.append(
                f"selected snippet {snippet.get('path', '<unknown>')} exceeds boundary line limit {snippet_limit}"
            )
        content = snippet.get("content")
        sha256 = snippet.get("sha256")
        if isinstance(content, str) and isinstance(sha256, str) and artifact_hash(content) != sha256:
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} sha256 does not match content")

    assignment = next((item for item in included_artifacts if item.get("type") == "assignment_summary"), None)
    if not assignment:
        errors.append("included_artifacts is missing assignment_summary")
    elif assignment.get("sha256") != artifact_hash(json.dumps(packet.get("bead_summary", {}), sort_keys=True)):
        errors.append("assignment_summary sha256 does not match bead_summary")

    if packet.get("expert_profile_included"):
        profile = packet.get("expert_profile") or {}
        profile_artifact = next((item for item in included_artifacts if item.get("type") == "expert_profile"), None)
        if not profile_artifact:
            errors.append("included_artifacts is missing expert_profile")
        elif isinstance(profile, dict):
            if profile_artifact.get("path") != profile.get("path") or profile_artifact.get("sha256") != profile.get("sha256"):
                errors.append("expert_profile artifact does not match expert_profile payload")

    for artifact in included_artifacts:
        artifact_type = artifact.get("type")
        if artifact_type in {"selected_file_snippet", "inline_snippet"}:
            match = next(
                (
                    snippet
                    for snippet in selected_snippets
                    if snippet.get("type") == artifact_type
                    and snippet.get("path") == artifact.get("path")
                    and snippet.get("sha256") == artifact.get("sha256")
                ),
                None,
            )
            if not match:
                errors.append(f"included artifact {artifact_type}:{artifact.get('path')} has no matching selected snippet")

    if not packet.get("required_return_sections"):
        errors.append("packet required_return_sections must not be empty")
    return errors


def require_valid_contractor_packet(packet: dict[str, Any], *, allow_degraded_packet: bool = False) -> None:
    errors = validate_contractor_packet(packet, allow_degraded_packet=allow_degraded_packet)
    if errors:
        raise SystemExit("invalid contractor packet:\n- " + "\n- ".join(errors))


def load_expert_profile(persona_file: str | None) -> dict[str, str]:
    if not persona_file:
        return {}
    safe_path = assert_repo_safe_path(REPO_ROOT / persona_file)
    relative = Path(repo_relative_path(safe_path))
    if not relative.parts or relative.parts[0] != "experts" or safe_path.suffix != ".md":
        raise SystemExit("expert profile must be a Markdown file under experts/")
    content = redact_text(safe_path.read_text(encoding="utf-8"))
    line_count = len(content.splitlines())
    if line_count > 220:
        raise SystemExit(f"expert profile exceeds line limit 220: {relative.as_posix()}")
    return {
        "path": relative.as_posix(),
        "sha256": artifact_hash(content),
        "content": content,
    }


def file_snippet(path: Path, *, max_lines: int) -> dict[str, Any]:
    repo_path = assert_repo_safe_path(path)
    relative = repo_relative_path(repo_path)
    lines = repo_path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = "\n".join(lines[:max_lines])
    redacted = redact_text(selected)
    return {
        "type": "selected_file_snippet",
        "path": relative,
        "line_count": min(len(lines), max_lines),
        "truncated": len(lines) > max_lines,
        "sha256": artifact_hash(redacted),
        "content": redacted,
    }


def attestation_payload_hash(attestation: dict[str, Any]) -> str:
    payload = dict(attestation)
    payload.pop("attestation_sha256", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def make_attestation(
    *,
    subject_type: str,
    subject_sha256: str,
    subject_id: str | None = None,
    issuer: str = "complex-work-orchestration",
    predicate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attestation: dict[str, Any] = {
        "attestation_type": "sha256-subject-attestation",
        "version": 1,
        "issued_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": issuer,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_sha256": subject_sha256,
        "predicate": predicate or {},
    }
    attestation["attestation_sha256"] = attestation_payload_hash(attestation)
    return attestation


def verify_attestation(
    subject: str | bytes,
    attestation: dict[str, Any],
    *,
    expected_subject_type: str | None = None,
    expected_subject_id: str | None = None,
    expected_predicate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    subject_bytes = subject if isinstance(subject, bytes) else subject.encode("utf-8")
    actual_subject_hash = hashlib.sha256(subject_bytes).hexdigest()
    errors: list[str] = []
    if not isinstance(attestation, dict):
        errors.append("attestation must be an object")
        return {
            "valid": False,
            "errors": errors,
            "subject_sha256": actual_subject_hash,
            "attestation_sha256": None,
        }
    expected_attestation_hash = attestation_payload_hash(attestation)
    if attestation.get("attestation_type") != "sha256-subject-attestation":
        errors.append("attestation_type must be sha256-subject-attestation")
    if attestation.get("version") != 1:
        errors.append("attestation version must be 1")
    if not isinstance(attestation.get("predicate"), dict):
        errors.append("attestation predicate must be an object")
    if expected_subject_type and attestation.get("subject_type") != expected_subject_type:
        errors.append("subject_type does not match expected context")
    if expected_subject_id and attestation.get("subject_id") != expected_subject_id:
        errors.append("subject_id does not match expected context")
    if expected_predicate:
        predicate = attestation.get("predicate") if isinstance(attestation.get("predicate"), dict) else {}
        for key, expected in expected_predicate.items():
            if predicate.get(key) != expected:
                errors.append(f"predicate {key!r} does not match expected context")
    if attestation.get("subject_sha256") != actual_subject_hash:
        errors.append("subject_sha256 does not match subject bytes")
    if not re.fullmatch(r"[0-9a-f]{64}", str(attestation.get("subject_sha256", ""))):
        errors.append("subject_sha256 is not a lowercase SHA-256 hex digest")
    if attestation.get("attestation_sha256") != expected_attestation_hash:
        errors.append("attestation_sha256 does not match attestation payload")
    return {
        "valid": not errors,
        "errors": errors,
        "subject_sha256": actual_subject_hash,
        "attestation_sha256": expected_attestation_hash,
    }


def fenced_block(content: Any, info: str = "text") -> str:
    text = str(content if content is not None else "")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    suffix = info.strip()
    opener = f"{fence}{suffix}" if suffix else fence
    return f"{opener}\n{text}\n{fence}"


def markdown_table_cell(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>").replace("`", "\\`")
