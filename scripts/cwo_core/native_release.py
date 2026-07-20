from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator, Mapping

from .native_precommit import (
    REQUIRED_MODEL,
    canonical_sha256,
    render_fit_prompt,
    validate_precommit_receipt,
)
from .paths import is_cwo_temp_path
from .policy import load_policy
from .util import atomic_write_text


EVIDENCE_TYPE = "cwo-native-release-evidence"
EVIDENCE_SCHEMA = "schemas/native-release-evidence.schema.json"
AUTHORITY = "cwo-native-release-supervisor"
AUTHORITY_BEAD = "complex-work-orchestration-fsh.3"
ADJUDICATION_BEAD = "complex-work-orchestration-fsh.3.5"
RELEASE_STATES = (
    "precommit-validated",
    "canary-authorized",
    "operative-authorized",
)
EVIDENCE_RELEASE_STATES = RELEASE_STATES[1:]
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_FIELDS = {
    "evidence_type",
    "version",
    "schema",
    "evidence_id",
    "release_state",
    "authority",
    "authority_bead",
    "adjudication_bead",
    "packet_id",
    "attempt_nonce",
    "requested_model",
    "work_plan_sha256",
    "fit_prompt_sha256",
    "precommit_receipt_sha256",
    "canary_receipt_sha256",
    "adjudication_sha256",
    "operation_class",
    "authorized_operations",
    "workdir",
    "repository_work_authorized",
    "source_mutation_authorized",
    "issued_at",
    "expires_at",
    "release_requires",
    "evidence_sha256",
}
POLICY_FIELDS = {
    "version",
    "schema",
    "authority",
    "required_model",
    "canary_bead",
    "operative_adjudication_bead",
    "max_ttl_seconds",
    "canary_operation_class",
    "canary_authorized_operations",
    "operative_authorized_operations",
    "canary_repository_work_authorized",
    "canary_source_mutation_authorized",
    "canary_workspace_scope",
    "operative_release_enabled",
    "operative_release_requires",
}


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _require_hash(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    text = _require_string(value, field)
    if HASH_RE.fullmatch(text) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _require_exact_fields(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    result = dict(value)
    missing = sorted(fields - set(result))
    unknown = sorted(set(result) - fields)
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise ValueError(f"{field} fields are invalid: " + "; ".join(details))
    return result


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty string list")
    result: list[str] = []
    for item in value:
        text = _require_string(item, f"{field} item")
        if text in result:
            raise ValueError(f"{field} contains duplicate {text!r}")
        result.append(text)
    return result


def _parse_time(value: Any, field: str) -> dt.datetime:
    text = _require_string(value, field)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is invalid: {exc}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _policy(source: Mapping[str, Any] | None = None) -> dict[str, Any]:
    policy = dict(source) if source is not None else load_policy("native-worker-execution")
    value = _require_exact_fields(policy.get("native_release_evidence"), POLICY_FIELDS, "native_release_evidence policy")
    expected = {
        "version": 1,
        "schema": EVIDENCE_SCHEMA,
        "authority": AUTHORITY,
        "required_model": REQUIRED_MODEL,
        "canary_bead": ADJUDICATION_BEAD,
        "operative_adjudication_bead": ADJUDICATION_BEAD,
        "canary_operation_class": "supervised-zero-tool-fit-canary",
        "canary_repository_work_authorized": False,
        "canary_source_mutation_authorized": False,
        "canary_workspace_scope": "cwo-temp-only",
        "operative_release_requires": ADJUDICATION_BEAD,
        "operative_release_enabled": True,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise ValueError(f"native_release_evidence.{field} must equal {expected_value!r}")
    maximum = value.get("max_ttl_seconds")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 60:
        raise ValueError("native_release_evidence.max_ttl_seconds must be an integer >= 60")
    value["canary_authorized_operations"] = _string_list(
        value.get("canary_authorized_operations"),
        "native_release_evidence.canary_authorized_operations",
    )
    value["operative_authorized_operations"] = _string_list(
        value.get("operative_authorized_operations"),
        "native_release_evidence.operative_authorized_operations",
    )
    if not isinstance(value.get("operative_release_enabled"), bool):
        raise ValueError("native_release_evidence.operative_release_enabled must be boolean")
    return value


def _evidence_hash(value: Mapping[str, Any]) -> str:
    return canonical_sha256({key: item for key, item in value.items() if key != "evidence_sha256"})


def _require_candidate_packet_version_2(candidate_packet: Mapping[str, Any]) -> None:
    version = candidate_packet.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 2:
        raise ValueError("candidate packet version must be integer 2")


def _registry_root() -> Path:
    configured = os.environ.get("CWO_NATIVE_RELEASE_REGISTRY_ROOT")
    path = Path(configured).expanduser() if configured else Path("/tmp/cwo-native-release-v1")
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("native release registry root must be an absolute non-symlink path")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise ValueError("native release registry root must be owned by the current user")
    path.chmod(0o700)
    return path.resolve()


@contextmanager
def _registry_lock() -> Iterator[Path]:
    root = _registry_root()
    lock_path = root / "registry.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise ValueError(f"native release registry lock is unavailable: {exc}") from exc
    with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("native release registry lock must be a current-user regular file")
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield root
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _register_canary(evidence: Mapping[str, Any]) -> None:
    with _registry_lock() as root:
        path = root / "issued-canaries.json"
        if path.exists():
            try:
                registry = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"native release registry is unreadable: {exc}") from exc
        else:
            registry = {"packet_ids": [], "attempt_nonces": [], "evidence_ids": []}
        expected = {"packet_ids", "attempt_nonces", "evidence_ids"}
        if not isinstance(registry, dict) or set(registry) != expected:
            raise ValueError("native release registry shape is invalid")
        bindings = {
            "packet_ids": evidence["packet_id"],
            "attempt_nonces": evidence["attempt_nonce"],
            "evidence_ids": evidence["evidence_id"],
        }
        for field, binding in bindings.items():
            values = registry.get(field)
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise ValueError("native release registry shape is invalid")
            if binding in values:
                raise ValueError(f"duplicate native release {field[:-1]}")
            values.append(str(binding))
            values.sort()
        atomic_write_text(path, json.dumps(registry, sort_keys=True, separators=(",", ":")) + "\n")
        path.chmod(0o600)


def build_canary_release_evidence(
    *,
    packet_id: str,
    attempt_nonce: str,
    work_plan: Mapping[str, Any],
    workdir: str | Path,
    ttl_seconds: int = 900,
    now: str | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    release_policy = _policy(policy)
    packet = _require_string(packet_id, "packet_id")
    nonce = _require_string(attempt_nonce, "attempt_nonce")
    plan = dict(work_plan)
    if plan.get("bead_id") != release_policy["canary_bead"]:
        raise ValueError("canary work plan must belong to the configured canary Bead")
    if plan.get("requested_model") != release_policy["required_model"]:
        raise ValueError("canary work plan must request the exact configured model")
    prompt = render_fit_prompt(plan)
    workspace = Path(workdir).expanduser().resolve()
    if not workspace.is_dir() or workspace.is_symlink() or not is_cwo_temp_path(workspace):
        raise ValueError("canary workdir must be a disposable CWO-owned temp directory")
    if workspace.stat().st_uid != os.getuid():
        raise ValueError("canary workdir must be owned by the current user")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 60:
        raise ValueError("ttl_seconds must be an integer >= 60")
    if ttl_seconds > int(release_policy["max_ttl_seconds"]):
        raise ValueError("ttl_seconds exceeds the native release policy maximum")
    issued = _parse_time(now, "now") if now else dt.datetime.now(dt.timezone.utc)
    evidence: dict[str, Any] = {
        "evidence_type": EVIDENCE_TYPE,
        "version": 1,
        "schema": EVIDENCE_SCHEMA,
        "evidence_id": f"native-release-{uuid.uuid4().hex}",
        "release_state": "canary-authorized",
        "authority": AUTHORITY,
        "authority_bead": AUTHORITY_BEAD,
        "adjudication_bead": ADJUDICATION_BEAD,
        "packet_id": packet,
        "attempt_nonce": nonce,
        "requested_model": REQUIRED_MODEL,
        "work_plan_sha256": canonical_sha256(plan),
        "fit_prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "precommit_receipt_sha256": None,
        "canary_receipt_sha256": None,
        "adjudication_sha256": None,
        "operation_class": release_policy["canary_operation_class"],
        "authorized_operations": list(release_policy["canary_authorized_operations"]),
        "workdir": str(workspace),
        "repository_work_authorized": False,
        "source_mutation_authorized": False,
        "issued_at": _iso(issued),
        "expires_at": _iso(issued + dt.timedelta(seconds=ttl_seconds)),
        "release_requires": release_policy["operative_release_requires"],
        "evidence_sha256": "",
    }
    evidence["evidence_sha256"] = _evidence_hash(evidence)
    errors = validate_native_release_evidence(evidence, policy=policy, now=issued)
    if errors:
        raise ValueError("invalid canary release evidence: " + "; ".join(errors))
    _register_canary(evidence)
    return evidence


def build_operative_release_evidence(
    *,
    candidate_packet: Mapping[str, Any],
    adjudication: Mapping[str, Any],
    canary_receipt: Mapping[str, Any],
    ttl_seconds: int = 900,
    now: str | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    release_policy = _policy(policy)
    if release_policy["operative_release_enabled"] is not True:
        raise ValueError("operative release evidence is disabled by policy")
    packet = dict(candidate_packet)
    _require_candidate_packet_version_2(packet)
    if packet.get("stage") != "precommit-validated" or packet.get("operative_dispatch_authorized") is not False:
        raise ValueError("operative release requires a precommit-validated candidate packet")
    work_plan = packet.get("work_plan")
    receipt = packet.get("precommit_receipt")
    if not isinstance(work_plan, Mapping) or not isinstance(receipt, Mapping):
        raise ValueError("operative release candidate is missing its work plan or precommit receipt")
    receipt_hash = _require_hash(packet.get("precommit_receipt_sha256"), "precommit_receipt_sha256")
    if receipt.get("receipt_sha256") != receipt_hash:
        raise ValueError("operative release candidate precommit receipt hash is inconsistent")
    canary = dict(canary_receipt)
    canary_errors = validate_precommit_receipt(canary, require_accepting=True)
    if canary_errors:
        raise ValueError("canary receipt is invalid: " + "; ".join(canary_errors))
    if canary.get("bead_id") != ADJUDICATION_BEAD:
        raise ValueError("canary receipt must belong to the operative adjudication Bead")
    canary_hash = _require_hash(canary.get("receipt_sha256"), "canary_receipt_sha256")
    decision = _require_exact_fields(
        adjudication,
        {
            "adjudication_type",
            "version",
            "bead_id",
            "decision",
            "accepted_high_severity_findings",
            "validation_sha256",
            "critic_evidence_sha256",
            "canary_receipt_sha256",
        },
        "operative adjudication",
    )
    expected_decision = {
        "adjudication_type": "cwo-native-operative-release-adjudication",
        "version": 1,
        "bead_id": ADJUDICATION_BEAD,
        "decision": "GO",
        "accepted_high_severity_findings": 0,
        "canary_receipt_sha256": canary_hash,
    }
    for field, expected in expected_decision.items():
        if decision.get(field) != expected:
            raise ValueError(f"operative adjudication {field} must equal {expected!r}")
    _require_hash(decision.get("validation_sha256"), "operative adjudication validation_sha256")
    _require_hash(decision.get("critic_evidence_sha256"), "operative adjudication critic_evidence_sha256")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= int(release_policy["max_ttl_seconds"]):
        raise ValueError("ttl_seconds is outside the native release policy range")
    issued = _parse_time(now, "now") if now else dt.datetime.now(dt.timezone.utc)
    evidence: dict[str, Any] = {
        "evidence_type": EVIDENCE_TYPE,
        "version": 1,
        "schema": EVIDENCE_SCHEMA,
        "evidence_id": f"native-release-{uuid.uuid4().hex}",
        "release_state": "operative-authorized",
        "authority": AUTHORITY,
        "authority_bead": AUTHORITY_BEAD,
        "adjudication_bead": ADJUDICATION_BEAD,
        "packet_id": _require_string(packet.get("packet_id"), "packet_id"),
        "attempt_nonce": _require_string(receipt.get("attempt_nonce"), "attempt_nonce"),
        "requested_model": REQUIRED_MODEL,
        "work_plan_sha256": canonical_sha256(dict(work_plan)),
        "fit_prompt_sha256": _require_hash(receipt.get("fit_prompt_sha256"), "fit_prompt_sha256"),
        "precommit_receipt_sha256": receipt_hash,
        "canary_receipt_sha256": canary_hash,
        "adjudication_sha256": canonical_sha256(decision),
        "operation_class": "native-operative-release",
        "authorized_operations": list(release_policy["operative_authorized_operations"]),
        "workdir": _require_string(packet.get("scope", {}).get("workdir"), "scope.workdir"),
        "repository_work_authorized": True,
        "source_mutation_authorized": True,
        "issued_at": _iso(issued),
        "expires_at": _iso(issued + dt.timedelta(seconds=ttl_seconds)),
        "release_requires": release_policy["operative_release_requires"],
        "evidence_sha256": "",
    }
    evidence["evidence_sha256"] = _evidence_hash(evidence)
    errors = validate_native_release_evidence(evidence, policy=policy, now=issued)
    if errors:
        raise ValueError("invalid operative release evidence: " + "; ".join(errors))
    return evidence


def authorize_operative_packet(
    *,
    candidate_packet: Mapping[str, Any],
    adjudication: Mapping[str, Any],
    canary_receipt: Mapping[str, Any],
    ttl_seconds: int = 900,
    now: str | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach short-lived adjudicated evidence to one precommit candidate."""

    _require_candidate_packet_version_2(dict(candidate_packet))
    evidence = build_operative_release_evidence(
        candidate_packet=candidate_packet,
        adjudication=adjudication,
        canary_receipt=canary_receipt,
        ttl_seconds=ttl_seconds,
        now=now,
        policy=policy,
    )
    authorized = deepcopy(dict(candidate_packet))
    authorized.update(
        {
            "stage": "operative-authorized",
            "operative_dispatch_authorized": True,
            "release_requires": ADJUDICATION_BEAD,
            "release_evidence": evidence,
            "release_evidence_sha256": evidence["evidence_sha256"],
        }
    )
    return authorized


def validate_native_release_evidence(
    value: Any,
    *,
    policy: Mapping[str, Any] | None = None,
    operation: str | None = None,
    expected_packet_id: str | None = None,
    expected_work_plan_sha256: str | None = None,
    expected_precommit_receipt_sha256: str | None = None,
    now: dt.datetime | None = None,
    live: bool = True,
) -> list[str]:
    errors: list[str] = []
    try:
        release_policy = _policy(policy)
        evidence = _require_exact_fields(value, EVIDENCE_FIELDS, "native release evidence")
        expected_constants = {
            "evidence_type": EVIDENCE_TYPE,
            "version": 1,
            "schema": EVIDENCE_SCHEMA,
            "authority": AUTHORITY,
            "authority_bead": AUTHORITY_BEAD,
            "adjudication_bead": ADJUDICATION_BEAD,
            "requested_model": REQUIRED_MODEL,
            "release_requires": ADJUDICATION_BEAD,
        }
        for field, expected in expected_constants.items():
            if evidence.get(field) != expected:
                raise ValueError(f"native release evidence {field} must equal {expected!r}")
        for field in ("evidence_id", "packet_id", "attempt_nonce", "operation_class", "workdir"):
            _require_string(evidence.get(field), field)
        for field in ("work_plan_sha256", "fit_prompt_sha256", "evidence_sha256"):
            _require_hash(evidence.get(field), field)
        for field in ("precommit_receipt_sha256", "canary_receipt_sha256", "adjudication_sha256"):
            _require_hash(evidence.get(field), field, nullable=True)
        if evidence["evidence_sha256"] != _evidence_hash(evidence):
            raise ValueError("native release evidence canonical hash mismatch")
        release_state = evidence.get("release_state")
        if release_state not in EVIDENCE_RELEASE_STATES:
            raise ValueError("native release evidence release_state is invalid")
        operations = _string_list(evidence.get("authorized_operations"), "authorized_operations")
        if operation is not None and operation not in operations:
            raise ValueError(f"native release evidence does not authorize {operation}")
        for field in ("repository_work_authorized", "source_mutation_authorized"):
            if not isinstance(evidence.get(field), bool):
                raise ValueError(f"{field} must be boolean")
        issued = _parse_time(evidence.get("issued_at"), "issued_at")
        expires = _parse_time(evidence.get("expires_at"), "expires_at")
        if expires <= issued:
            raise ValueError("native release evidence expiry must follow issuance")
        if (expires - issued).total_seconds() > int(release_policy["max_ttl_seconds"]):
            raise ValueError("native release evidence exceeds maximum TTL")
        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
        if live and not (issued <= current <= expires):
            raise ValueError("native release evidence is not live")
        if expected_packet_id is not None and evidence["packet_id"] != expected_packet_id:
            raise ValueError("native release evidence packet_id binding mismatch")
        if expected_work_plan_sha256 is not None and evidence["work_plan_sha256"] != expected_work_plan_sha256:
            raise ValueError("native release evidence work plan binding mismatch")
        if (
            expected_precommit_receipt_sha256 is not None
            and evidence["precommit_receipt_sha256"] != expected_precommit_receipt_sha256
        ):
            raise ValueError("native release evidence precommit receipt binding mismatch")
        if release_state == "canary-authorized":
            if evidence["operation_class"] != release_policy["canary_operation_class"]:
                raise ValueError("canary release evidence operation_class is invalid")
            if operations != release_policy["canary_authorized_operations"]:
                raise ValueError("canary release evidence operations are invalid")
            if evidence["repository_work_authorized"] is not False or evidence["source_mutation_authorized"] is not False:
                raise ValueError("canary release evidence cannot authorize repository work or source mutation")
            if any(evidence[field] is not None for field in ("precommit_receipt_sha256", "canary_receipt_sha256", "adjudication_sha256")):
                raise ValueError("canary release evidence cannot claim post-canary or adjudication receipts")
            workspace = Path(evidence["workdir"]).expanduser().resolve()
            if not is_cwo_temp_path(workspace):
                raise ValueError("canary release evidence requires a disposable CWO temp workdir")
            if live and (not workspace.is_dir() or workspace.is_symlink()):
                raise ValueError("canary release evidence requires a live disposable CWO temp workdir")
        else:
            if evidence["operation_class"] != "native-operative-release":
                raise ValueError("operative release evidence operation_class is invalid")
            if operations != release_policy["operative_authorized_operations"]:
                raise ValueError("operative release evidence operations are invalid")
            if any(evidence[field] is None for field in ("precommit_receipt_sha256", "canary_receipt_sha256", "adjudication_sha256")):
                raise ValueError("operative release evidence requires precommit, canary, and adjudication hashes")
            if release_policy["operative_release_enabled"] is not True:
                raise ValueError("operative release evidence is disabled by policy")
    except (OSError, SystemExit, ValueError) as exc:
        errors.append(str(exc))
    return errors


def write_release_evidence(path_value: str | Path, evidence: Mapping[str, Any]) -> Path:
    errors = validate_native_release_evidence(evidence)
    if errors:
        raise ValueError("invalid native release evidence: " + "; ".join(errors))
    path = Path(path_value).expanduser().resolve()
    if path.is_symlink() or not is_cwo_temp_path(path):
        raise ValueError("native release evidence artifact must be under a CWO-owned temp directory")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_uid != os.getuid():
        raise ValueError("native release evidence directory must be owned by the current user")
    atomic_write_text(path, json.dumps(dict(evidence), indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    return path
