"""Fixed-plan control artifacts for the one-shot native activation preview."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from typing import Any
import uuid

from .beads_ready_set import (
    LEASE_SCOPE_TYPE,
    LEASE_SCOPE_VERSION,
    build_ready_set_evidence,
    canonical_json_sha256,
)
from .native_activation_ledger import (
    NativeActivationLedgerError,
    activation_iso,
    canonical_activation_sha256,
    ensure_private_directory,
    fsync_private_directory,
    locked_private_file,
    read_private_bytes,
    read_private_json,
    write_exclusive_private_bytes,
    write_exclusive_private_json,
)
from .native_authority import (
    AuthorityProvenanceError,
    OperatorApprovalVerifier,
    sign_operator_approval_receipt,
    trusted_actor_authority,
    validate_operator_approval_receipt,
)
from .native_capability import (
    build_native_capability_receipt,
    canonical_capability_evidence_sha256,
)
from .native_pool_admission import (
    AdmissionCandidate,
    BeadsClaimAdapter,
    reserve_pool_cohort,
)
from .native_pool_contracts import default_completion_evidence_policy
from .native_pool_preflight import effective_child_packet_sha256
from .native_pool_proportionality import pool_proportionality_check
from .native_pool_workspace import capture_workspace_snapshot
from .native_tool_activation import (
    tool_enforcement_activation_artifacts,
    tool_enforcement_activation_assessment,
)
from .native_tool_isolation import (
    TOOL_ENFORCEMENT_OVERRIDE_RISK,
    build_tool_surface_snapshot,
    default_tool_policy,
    prompt_preflight,
    seal_tool_enforcement_override,
)
from .policy import load_policy
from .work_sizing import (
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
)


PLAN_TYPE = "cwo-native-tool-activation-plan"
PLAN_VERSION = 1
PLAN_SCHEMA = "schemas/native-tool-activation-plan.schema.json"
CLAIM_TYPE = "cwo-native-tool-activation-claim"
CLAIM_VERSION = 1
CLAIM_SCHEMA = "schemas/native-tool-activation-claim.schema.json"
RESULT_TYPE = "cwo-native-tool-activation-result"
RESULT_VERSION = 2
RESULT_SCHEMA = "schemas/native-tool-activation-result-v2.schema.json"
KEY_NAME = "activation-preview.key"
MODEL = "gpt-5.3-codex-spark"
MUTABLE_PATCH_INPUT = (
    "*** Begin Patch\n"
    "*** Update File: targets/activation.txt\n"
    "@@\n"
    "+activation-preview-mutated\n"
    "*** End of File\n"
    "*** End Patch\n"
)
PLAN_TTL_SECONDS = 3600
APPROVAL_TTL_MAX_SECONDS = 600
APPROVAL_TTL_MIN_SECONDS = 60
PROFILE = {
    "n1-read-only": {"workers": 1, "mutating_workers": 0},
    "n2-read-only": {"workers": 2, "mutating_workers": 0},
    "n1-mutable": {"workers": 1, "mutating_workers": 1},
}
PATH_FIELDS = frozenset(
    {
        "records",
        "integration",
        "beads_directory",
        "beads_database",
        "claims",
        "ledger",
        "leases",
        "pool_state",
        "pool_decision",
        "approval",
        "approval_replay",
        "result",
    }
)
TASK_FIELDS = frozenset(
    {
        "ordinal",
        "role",
        "child_id",
        "bead_id",
        "work_unit_id",
        "packet_id",
        "attempt_nonce",
        "lease_id",
        "worktree",
        "isolation_class",
        "declared_write_paths",
        "integration_target_paths",
        "prompt",
        "expected_token",
        "hard_budget",
        "completion_evidence_policy",
        "tool_policy",
        "prompt_preflight",
        "tool_surface",
        "packet_sha256",
        "worktree_identity_sha256",
    }
)
PLAN_FIELDS = frozenset(
    {
        "plan_type",
        "version",
        "schema",
        "activation_id",
        "profile",
        "prepared_at",
        "expires_at",
        "source_repository",
        "candidate_commit",
        "candidate_tree",
        "control_root",
        "run_root",
        "launch_id",
        "pool_id",
        "pool_epoch",
        "campaign_nonce",
        "requested_workers",
        "mutating_workers",
        "risk_acknowledgement",
        "paths",
        "override",
        "epic_id",
        "tasks",
        "readiness_evidence",
        "work_estimates",
        "proportionality_assessment",
        "child_bindings",
        "activation_request",
        "activation_artifacts",
        "plan_sha256",
    }
)
CLAIM_FIELDS = frozenset(
    {
        "claim_type",
        "version",
        "schema",
        "claim_id",
        "activation_id",
        "profile",
        "plan_sha256",
        "approval_sha256",
        "approval_id",
        "approval_nonce",
        "action_sha256",
        "override_sha256",
        "launch_id",
        "pool_id",
        "pool_epoch",
        "campaign_nonce",
        "candidate_commit",
        "candidate_tree",
        "requested_workers",
        "mutating_workers",
        "fixed_cohort_sha256",
        "child_bindings_sha256",
        "output_paths",
        "controller_identity",
        "claimed_at",
        "claim_sha256",
    }
)


class NativeActivationPreviewError(ValueError):
    """Fail-closed activation preview error with stable messages."""


def _sha256(value: Any) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _git_object(value: Any) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[0-9a-f]{40}", value) is not None
    )


def _uuid(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _parse_time(value: Any, *, label: str) -> dt.datetime:
    if type(value) is not str:
        raise NativeActivationPreviewError(f"{label}-invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NativeActivationPreviewError(f"{label}-invalid") from exc
    if parsed.tzinfo is None:
        raise NativeActivationPreviewError(f"{label}-timezone-required")
    return parsed.astimezone(dt.timezone.utc)


def _run(
    args: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    label: str,
) -> str:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeActivationPreviewError(f"{label}-failed") from exc
    if completed.returncode != 0:
        raise NativeActivationPreviewError(
            f"{label}-failed:{completed.returncode}:"
            + hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest()
        )
    return completed.stdout.strip()


def _git(cwd: Path, *args: str) -> str:
    return _run(["git", *args], cwd=cwd, label="activation-git")


def _bd_environment(directory: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["BEADS_DIR"] = str(directory / ".beads")
    environment["BEADS_ACTOR"] = "native-activation-preview-controller"
    return environment


def _bd(directory: Path, *args: str) -> str:
    return _run(
        ["bd", *args],
        cwd=directory,
        env=_bd_environment(directory),
        label="activation-beads",
    )


def _json_output(raw: str, *, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NativeActivationPreviewError(f"{label}-json-invalid") from exc


def _source_identity(source_repository: Path) -> tuple[Path, str, str]:
    source = Path(source_repository)
    if not source.is_absolute():
        raise NativeActivationPreviewError(
            "activation-source-repository-not-absolute"
        )
    try:
        source = source.resolve(strict=True)
    except OSError as exc:
        raise NativeActivationPreviewError(
            "activation-source-repository-unavailable"
        ) from exc
    if not source.is_dir():
        raise NativeActivationPreviewError(
            "activation-source-repository-invalid"
        )
    commit = _git(source, "rev-parse", "HEAD^{commit}")
    tree = _git(source, "rev-parse", "HEAD^{tree}")
    if not _git_object(commit) or not _git_object(tree):
        raise NativeActivationPreviewError(
            "activation-source-git-identity-invalid"
        )
    if _git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise NativeActivationPreviewError(
            "activation-source-repository-dirty"
        )
    return source, commit, tree


def generate_activation_key(control_root: Path) -> dict[str, Any]:
    root = ensure_private_directory(Path(control_root), create=True)
    key = secrets.token_bytes(32)
    path = root / KEY_NAME
    write_exclusive_private_bytes(
        path,
        key.hex().encode("ascii") + b"\n",
        label="activation-key",
    )
    return {
        "status": "created",
        "key_file": str(path),
        "fingerprint_sha256": hashlib.sha256(key).hexdigest(),
    }


def read_activation_key(control_root: Path) -> bytes:
    root = ensure_private_directory(Path(control_root), create=False)
    raw = read_private_bytes(root / KEY_NAME, label="activation-key")
    if re.fullmatch(rb"[0-9a-f]{64}\n", raw) is None:
        raise NativeActivationPreviewError("activation-key-format-invalid")
    return bytes.fromhex(raw[:-1].decode("ascii"))


def _fixed_prompt(profile: str, ordinal: int) -> tuple[str, str]:
    if profile in {"n1-read-only", "n2-read-only"}:
        token = f"ACTIVATION_READ_ONLY_{ordinal}_OK"
        return (
            "Use exec_command exactly twice: first run `git rev-parse HEAD`, "
            "then run `sha256sum data/shared.txt`. Do not mutate any file. "
            f"Return exactly {token}.",
            token,
        )
    token = "ACTIVATION_MUTABLE_0_OK"
    return (
        "Use apply_patch exactly once with exactly this payload:\n"
        f"{MUTABLE_PATCH_INPUT}"
        "Do not modify any other file. Then use exec_command exactly once "
        "to run `git diff --check`. "
        f"Return exactly {token}.",
        token,
    )


def _activation_argument_hash(arguments: Any) -> str:
    """Match the trusted transport's canonical argument digest."""

    encoded = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fixed_activation_tool_trace(
    profile: str,
    ordinal: int,
    *,
    worktree: Path | str,
) -> list[dict[str, Any]]:
    """Compile the exact trusted trace required by a fixed activation profile."""

    worktree_value = str(Path(worktree))

    def exec_hashes(command: str) -> list[str]:
        return sorted(
            {
                _activation_argument_hash({"cmd": command}),
                _activation_argument_hash(
                    {"cmd": command, "workdir": worktree_value}
                ),
                _activation_argument_hash(
                    {
                        "cmd": command,
                        "workdir": worktree_value,
                        "login": False,
                    }
                ),
            }
        )

    if profile in {"n1-read-only", "n2-read-only"}:
        calls = (
            (
                "exec_command",
                exec_hashes("git rev-parse HEAD"),
                "read",
                [],
            ),
            (
                "exec_command",
                exec_hashes("sha256sum data/shared.txt"),
                "read",
                ["data/shared.txt"],
            ),
        )
    elif profile == "n1-mutable" and ordinal == 0:
        calls = (
            (
                "apply_patch",
                [_activation_argument_hash(MUTABLE_PATCH_INPUT)],
                "write",
                ["targets/activation.txt"],
            ),
            (
                "exec_command",
                exec_hashes("git diff --check"),
                "test",
                [],
            ),
        )
    else:
        raise NativeActivationPreviewError(
            "activation-tool-trace-profile-invalid"
        )
    return [
        {
            "sequence": sequence,
            "tool": tool,
            "canonical_argument_hashes": argument_hashes,
            "action_class": action_class,
            "determinable_target_paths": target_paths,
            "pairing_status": "paired",
            "result_kind": "paired-success",
            "exit_code": 0,
        }
        for sequence, (
            tool,
            argument_hashes,
            action_class,
            target_paths,
        ) in enumerate(calls)
    ]


def _create_git_layout(run_root: Path, activation_id: str, profile: str) -> dict[str, Any]:
    integration = run_root / "integration"
    integration.mkdir(mode=0o700)
    _git(integration, "init", "-q")
    _git(integration, "config", "user.name", "CWO Activation Preview")
    _git(
        integration,
        "config",
        "user.email",
        "cwo-activation-preview@example.invalid",
    )
    (integration / "data").mkdir(mode=0o700)
    (integration / "targets").mkdir(mode=0o700)
    (integration / "data" / "shared.txt").write_text(
        "activation-preview-read-only-baseline\n",
        encoding="utf-8",
    )
    (integration / "targets" / "activation.txt").write_text(
        "activation-preview-mutable-baseline\n",
        encoding="utf-8",
    )
    _git(integration, "add", ".")
    _git(integration, "commit", "-qm", "activation preview baseline")
    worktrees: list[Path] = []
    if profile == "n1-mutable":
        mutable = run_root / "mutable-0"
        _git(
            integration,
            "worktree",
            "add",
            "-q",
            "-b",
            f"activation-preview-{activation_id}",
            str(mutable),
            "HEAD",
        )
        worktrees.append(mutable)
    else:
        read_shared = run_root / "read-shared"
        _git(
            integration,
            "worktree",
            "add",
            "-q",
            "--detach",
            str(read_shared),
            "HEAD",
        )
        worktrees.extend(
            read_shared for _ in range(PROFILE[profile]["workers"])
        )
    return {"integration": integration, "worktrees": worktrees}


def _work_plan(
    bead_id: str,
    *,
    ordinal: int,
    write_paths: list[str],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    return evaluate_work_estimate(
        {
            "estimate_type": "cwo-native-work-estimate",
            "version": 1,
            "work_unit_id": f"activation-preview-{ordinal}-{bead_id}",
            "bead_id": bead_id,
            "requested_model": MODEL,
            "primary_outcome": "complete one fixed activation preview task",
            "expected_artifacts": ["trusted terminal evidence"],
            "expert_profiles": ["operative-certification"],
            "frozen_decisions": [
                "fixed prompt",
                "fixed tool policy",
                "no retry or resume",
            ],
            "unresolved_decisions": [],
            "subsystems": ["native activation preview"],
            "write_paths": write_paths,
            "context_manifest": [],
            "acceptance_checks": ["fixed expected token observed"],
            "estimates": {
                "tool_calls_p50": 2,
                "tool_calls_p90": 4,
                "runtime_seconds_p50": 480,
                "runtime_seconds_p90": 600,
                "context_tokens_p90": 4000,
            },
            "scores": {
                "reasoning_uncertainty": 0,
                "subsystem_coupling": 1,
                "contract_risk": 1,
                "diagnostic_uncertainty": 0,
                "context_breadth": 1,
                "validation_breadth": 1,
            },
        },
        policy=policy,
    )


def _worker_commitment(plan: Mapping[str, Any], bead_id: str) -> dict[str, Any]:
    return {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": plan["work_unit_id"],
        "bead_id": bead_id,
        "requested_model": MODEL,
        "session_id": f"activation-preview-plan-{bead_id}",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": MODEL,
        "work_estimate_sha256": canonical_work_estimate_sha256(plan),
        "decision": "accept",
        "confidence": 1.0,
        "estimates": {
            "tool_calls_p50": 2,
            "tool_calls_p90": 4,
            "runtime_seconds_p50": 480,
            "runtime_seconds_p90": 600,
        },
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "fixed activation-preview controller plan",
    }


def _admission_metadata(
    *,
    bead_id: str,
    ordinal: int,
    cohort_workers: int,
    write_paths: list[str],
    override: Mapping[str, Any],
    integration: Path,
    policy: Mapping[str, Any],
    issued_at: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = _work_plan(
        bead_id,
        ordinal=ordinal,
        write_paths=write_paths,
        policy=policy,
    )
    mutable = bool(write_paths)
    tool_policy = default_tool_policy(
        mutable=mutable,
        enforcement_override=override,
    )
    tool_surface = build_tool_surface_snapshot(
        tool_policy,
        source="activation-preview-prospective-app-server-surface",
        server_allowlist_supported=False,
        allowlist_parameter=None,
        effective_allowlist=None,
    )
    session_id = f"activation-preview-capability-{bead_id}"
    capability_evidence = {
        "requested_model": MODEL,
        "configured_model": MODEL,
        "advertised": True,
        "advertised_models": [MODEL],
        "spawn_accepted": True,
        "canary_session_id": session_id,
        "attestation_source": "trusted-session-jsonl",
        "attested_model": MODEL,
        "tool_calls": 0,
        "context_compactions": 0,
        "runtime_seconds": 0.001,
        "closure_receipt": True,
        "tool_surface_id": tool_surface["surface_sha256"],
    }
    capability_authority = trusted_actor_authority(
        source_type="worker-discovery",
        source_id=session_id,
        source_sha256=canonical_capability_evidence_sha256(
            capability_evidence
        ),
        actor_id=f"activation-preview-controller-{ordinal}",
        actor_role="operative-worker",
        identity_source="trusted-session-jsonl",
    )
    expires = issued_at + dt.timedelta(minutes=30)
    capability_receipt = build_native_capability_receipt(
        capability_evidence,
        [MODEL],
        activation_iso(issued_at),
        activation_iso(expires),
        session_authority=capability_authority,
    )
    lease_scope = {
        "lease_scope_type": LEASE_SCOPE_TYPE,
        "version": LEASE_SCOPE_VERSION,
        "issue_id": bead_id,
        "integration_root_identity_sha256": canonical_json_sha256(
            {"integration_root": str(integration)}
        ),
        "workspace_scope_sha256": canonical_json_sha256(
            {"activation_preview_bead": bead_id}
        ),
        "target_paths": write_paths,
    }
    lease_scope["lease_scope_sha256"] = canonical_json_sha256(lease_scope)
    allowance = plan["aggregate_allowance"]
    hard_budget = {
        "tool_calls": int(allowance["tool_calls_hard"]),
        "runtime_seconds": int(allowance["runtime_seconds_hard"]),
        "compactions": int(allowance["max_compactions"]),
        "full_suite_runs": 0,
        "mutations": 1 if mutable else 0,
    }
    metadata = {
        "version": 2,
        "work_plan": plan,
        "worker_commitment": _worker_commitment(plan, bead_id),
        "declared_read_paths": ["data/shared.txt"] if not mutable else [],
        "declared_write_paths": write_paths,
        "integration_target_paths": write_paths,
        "topology": "single-host-process-v1",
        "isolation_class": (
            "mutable-isolated" if mutable else "read-only-shared"
        ),
        "architecture_authority": "architect",
        "execution_authority": "workerbee",
        "share_boundary": "no-outside-sharing",
        "required_tools": list(tool_policy["permitted_tools"]),
        "tool_surface_id": tool_surface["surface_sha256"],
        "tool_policy": tool_policy,
        "tool_surface": tool_surface,
        "capability_receipt": capability_receipt,
        "capability_assessed_at": activation_iso(
            issued_at + dt.timedelta(seconds=1)
        ),
        "lease_scope": lease_scope,
        "hard_budget": hard_budget,
        "aggregate_hard_budget": {
            field: hard_budget[field] * cohort_workers
            for field in (
                "tool_calls",
                "runtime_seconds",
                "compactions",
                "full_suite_runs",
                "mutations",
            )
        },
    }
    return metadata, plan


def _normalize_issue(
    raw: Mapping[str, Any],
    *,
    ready_rank: int | None,
    executable_leaf: bool,
) -> dict[str, Any]:
    value = deepcopy(dict(raw))
    value["_cwo_canonical_ready"] = ready_rank is not None
    value["_cwo_canonical_ready_rank"] = ready_rank
    value["_cwo_executable_leaf"] = executable_leaf
    issue_type = value.get("issue_type") or value.get("type") or "issue"
    labels = value.get("labels")
    return {
        "id": str(value.get("id") or ""),
        "title": str(value.get("title") or ""),
        "type": str(issue_type),
        "status": str(value.get("status") or "open"),
        "priority": int(value.get("priority") or 50),
        "labels": (
            list(labels)
            if isinstance(labels, list)
            else [item.strip() for item in str(labels or "").split(",") if item.strip()]
        ),
        "dependencies": [],
        "raw": value,
    }


def _create_beads_graph(
    run_root: Path,
    *,
    profile: str,
    integration: Path,
    override: Mapping[str, Any],
    now: dt.datetime,
) -> tuple[Path, Path, str, list[str], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    if shutil.which("bd") is None:
        raise NativeActivationPreviewError("activation-beads-cli-unavailable")
    beads_directory = run_root / "private-beads"
    beads_directory.mkdir(mode=0o700)
    _git(beads_directory, "init", "-q")
    _bd(
        beads_directory,
        "init",
        "--non-interactive",
        "--skip-agents",
        "--skip-hooks",
        "-p",
        "nap",
    )
    epic_id = _bd(
        beads_directory,
        "create",
        "Native activation preview fixed cohort",
        "--type",
        "epic",
        "--priority",
        "0",
        "--labels",
        "activation-preview",
        "--silent",
    )
    issue_ids: list[str] = []
    estimates: dict[str, dict[str, Any]] = {}
    for ordinal in range(PROFILE[profile]["workers"]):
        issue_id = _bd(
            beads_directory,
            "create",
            f"Fixed activation preview child {ordinal}",
            "--type",
            "task",
            "--parent",
            epic_id,
            "--priority",
            str(ordinal),
            "--labels",
            "activation-preview,fixed-synthetic",
            "--silent",
        )
        write_paths = (
            ["targets/activation.txt"] if profile == "n1-mutable" else []
        )
        metadata, estimate = _admission_metadata(
            bead_id=issue_id,
            ordinal=ordinal,
            cohort_workers=PROFILE[profile]["workers"],
            write_paths=write_paths,
            override=override,
            integration=integration,
            policy=load_policy("native-worker-execution"),
            issued_at=now,
        )
        _bd(
            beads_directory,
            "update",
            issue_id,
            "--metadata",
            json.dumps(
                {"cwo_ready_set_admission": metadata},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "--json",
        )
        issue_ids.append(issue_id)
        estimates[issue_id] = estimate
    raw_ready = _json_output(
        _bd(
            beads_directory,
            "ready",
            "--json",
            "--parent",
            epic_id,
            "--unassigned",
            "--limit",
            "0",
        ),
        label="activation-beads-ready",
    )
    if type(raw_ready) is dict:
        raw_ready = raw_ready.get("issues") or raw_ready.get("data") or []
    if type(raw_ready) is not list:
        raise NativeActivationPreviewError(
            "activation-beads-ready-shape-invalid"
        )
    ready_order = [
        str(item.get("id"))
        for item in raw_ready
        if isinstance(item, Mapping) and item.get("id")
    ]
    if ready_order != issue_ids:
        raise NativeActivationPreviewError(
            "activation-beads-ready-order-invalid"
        )
    exact = _json_output(
        _bd(
            beads_directory,
            "show",
            epic_id,
            *issue_ids,
            "--json",
        ),
        label="activation-beads-show",
    )
    if type(exact) is dict:
        exact = exact.get("issues") or exact.get("data") or [exact]
    if type(exact) is not list:
        raise NativeActivationPreviewError(
            "activation-beads-show-shape-invalid"
        )
    by_id = {
        str(item.get("id")): item
        for item in exact
        if isinstance(item, Mapping) and item.get("id")
    }
    if set(by_id) != {epic_id, *issue_ids}:
        raise NativeActivationPreviewError(
            "activation-beads-show-set-invalid"
        )
    scope_items = [
        _normalize_issue(
            by_id[epic_id],
            ready_rank=None,
            executable_leaf=False,
        ),
        *[
            _normalize_issue(
                by_id[issue_id],
                ready_rank=ordinal,
                executable_leaf=True,
            )
            for ordinal, issue_id in enumerate(issue_ids)
        ],
    ]
    database = beads_directory / ".beads" / "embeddeddolt"
    if not database.is_dir():
        raise NativeActivationPreviewError(
            "activation-beads-database-missing"
        )
    return (
        beads_directory,
        database,
        epic_id,
        issue_ids,
        estimates,
        scope_items,
    )


def _prospective_task(
    *,
    profile: str,
    ordinal: int,
    bead_id: str,
    estimate: Mapping[str, Any],
    worktree: Path,
    override: Mapping[str, Any],
) -> dict[str, Any]:
    mutable = profile == "n1-mutable"
    isolation = "mutable-isolated" if mutable else "read-only-shared"
    role = f"mutable-{ordinal}" if mutable else f"read-only-{ordinal}"
    prompt, expected_token = _fixed_prompt(profile, ordinal)
    tool_policy = default_tool_policy(
        mutable=mutable,
        enforcement_override=override,
    )
    completion = default_completion_evidence_policy(
        isolation,
        minimum_tool_calls=2,
    )
    tool_surface = build_tool_surface_snapshot(
        tool_policy,
        source="codex-app-server-v2-thread-start-schema",
        server_allowlist_supported=False,
        allowlist_parameter=None,
        effective_allowlist=None,
    )
    allowance = estimate["aggregate_allowance"]
    hard_budget = {
        "tool_calls": int(allowance["tool_calls_hard"]),
        "runtime_seconds": int(allowance["runtime_seconds_hard"]),
        "compactions": int(allowance["max_compactions"]),
        "full_suite_runs": 0,
        "mutations": 1 if mutable else 0,
    }
    declared = ["targets/activation.txt"] if mutable else []
    task: dict[str, Any] = {
        "ordinal": ordinal,
        "role": role,
        "child_id": f"activation-preview-child-{ordinal}",
        "bead_id": bead_id,
        "work_unit_id": estimate["work_unit_id"],
        "packet_id": str(uuid.uuid4()),
        "attempt_nonce": str(uuid.uuid4()),
        "lease_id": str(uuid.uuid4()),
        "worktree": str(worktree),
        "isolation_class": isolation,
        "declared_write_paths": declared,
        "integration_target_paths": declared,
        "prompt": prompt,
        "expected_token": expected_token,
        "hard_budget": hard_budget,
        "completion_evidence_policy": completion,
        "tool_policy": tool_policy,
        "prompt_preflight": prompt_preflight(prompt, tool_policy),
        "tool_surface": tool_surface,
        "packet_sha256": "0" * 64,
        "worktree_identity_sha256": canonical_activation_sha256(
            capture_workspace_snapshot(
                worktree,
                allowed_paths=declared,
            )["identity"]
        ),
    }
    task["packet_sha256"] = effective_child_packet_sha256(
        {
            "child_id": task["child_id"],
            "packet_id": task["packet_id"],
            "attempt_nonce": task["attempt_nonce"],
            "lease_id": task["lease_id"],
            "worktree": task["worktree"],
            "isolation_class": task["isolation_class"],
            "completion_evidence_policy": task[
                "completion_evidence_policy"
            ],
            "tool_policy": task["tool_policy"],
            "prompt": task["prompt"],
            "prompt_preflight": task["prompt_preflight"],
            "tool_surface": task["tool_surface"],
            "hard_budget": task["hard_budget"],
            "declared_write_paths": task["declared_write_paths"],
            "integration_target_paths": task[
                "integration_target_paths"
            ],
        }
    )
    return task


def _activation_child(
    task: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "child_id": task["child_id"],
        "packet_id": task["packet_id"],
        "packet_sha256": task["packet_sha256"],
        "attempt_nonce": task["attempt_nonce"],
        "lease_id": task["lease_id"],
        "worktree": task["worktree"],
        "isolation_class": task["isolation_class"],
        "declared_write_paths": list(task["declared_write_paths"]),
        "integration_target_paths": list(
            task["integration_target_paths"]
        ),
        "tool_policy": deepcopy(task["tool_policy"]),
        "hard_budget": deepcopy(task["hard_budget"]),
        **{
            field: deepcopy(binding[field])
            for field in (
                "bead_id",
                "work_unit_id",
                "candidate_sha256",
                "work_estimate_sha256",
                "worker_commitment_sha256",
                "lease_scope_sha256",
                "worktree_identity_sha256",
                "requested_model",
                "admitted_child_sha256",
            )
        },
    }


def _seal_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(plan))
    result.pop("plan_sha256", None)
    result["plan_sha256"] = canonical_activation_sha256(result)
    errors = validate_activation_plan(result, check_live_source=False)
    if errors:
        raise NativeActivationPreviewError(
            "activation-plan-invalid:" + ";".join(errors)
        )
    return result


def validate_activation_plan(
    value: Any,
    *,
    check_live_source: bool = True,
    now: dt.datetime | None = None,
) -> list[str]:
    try:
        if type(value) is not dict or set(value) != PLAN_FIELDS:
            raise NativeActivationPreviewError(
                "activation-plan-fields-invalid"
            )
        if (
            value.get("plan_type") != PLAN_TYPE
            or value.get("version") != PLAN_VERSION
            or value.get("schema") != PLAN_SCHEMA
        ):
            raise NativeActivationPreviewError(
                "activation-plan-header-invalid"
            )
        profile = value.get("profile")
        if profile not in PROFILE:
            raise NativeActivationPreviewError(
                "activation-plan-profile-invalid"
            )
        if not _uuid(value.get("activation_id")):
            raise NativeActivationPreviewError(
                "activation-plan-id-invalid"
            )
        for field in (
            "launch_id",
            "pool_id",
            "pool_epoch",
            "campaign_nonce",
        ):
            if not _uuid(value.get(field)):
                raise NativeActivationPreviewError(
                    f"activation-plan-{field.replace('_', '-')}-invalid"
                )
        if (
            value.get("requested_workers") != PROFILE[str(profile)]["workers"]
            or value.get("mutating_workers")
            != PROFILE[str(profile)]["mutating_workers"]
            or value.get("risk_acknowledgement")
            != TOOL_ENFORCEMENT_OVERRIDE_RISK
        ):
            raise NativeActivationPreviewError(
                "activation-plan-profile-binding-invalid"
            )
        if not _git_object(value.get("candidate_commit")) or not _git_object(
            value.get("candidate_tree")
        ):
            raise NativeActivationPreviewError(
                "activation-plan-candidate-invalid"
            )
        source = Path(str(value.get("source_repository")))
        control_root = Path(str(value.get("control_root")))
        run_root = Path(str(value.get("run_root")))
        if not all(path.is_absolute() for path in (source, control_root, run_root)):
            raise NativeActivationPreviewError(
                "activation-plan-path-not-absolute"
            )
        if run_root.parent.parent != control_root or run_root.name != value.get(
            "activation_id"
        ):
            raise NativeActivationPreviewError(
                "activation-plan-run-root-invalid"
            )
        paths = value.get("paths")
        if type(paths) is not dict or set(paths) != PATH_FIELDS:
            raise NativeActivationPreviewError(
                "activation-plan-paths-invalid"
            )
        if any(not Path(str(item)).is_absolute() for item in paths.values()):
            raise NativeActivationPreviewError(
                "activation-plan-artifact-path-not-absolute"
            )
        tasks = value.get("tasks")
        if type(tasks) is not list or len(tasks) != PROFILE[str(profile)][
            "workers"
        ]:
            raise NativeActivationPreviewError(
                "activation-plan-tasks-invalid"
            )
        expected_roles = (
            [f"read-only-{index}" for index in range(len(tasks))]
            if profile != "n1-mutable"
            else ["mutable-0"]
        )
        for ordinal, task in enumerate(tasks):
            if type(task) is not dict or set(task) != TASK_FIELDS:
                raise NativeActivationPreviewError(
                    "activation-plan-task-fields-invalid"
                )
            if (
                task.get("ordinal") != ordinal
                or task.get("role") != expected_roles[ordinal]
            ):
                raise NativeActivationPreviewError(
                    "activation-plan-task-order-invalid"
                )
            fixed_prompt, token = _fixed_prompt(str(profile), ordinal)
            if (
                task.get("prompt") != fixed_prompt
                or task.get("expected_token") != token
            ):
                raise NativeActivationPreviewError(
                    "activation-plan-task-not-fixed"
                )
            if effective_child_packet_sha256(task) != task.get(
                "packet_sha256"
            ):
                raise NativeActivationPreviewError(
                    "activation-plan-task-packet-invalid"
                )
        artifacts = tool_enforcement_activation_artifacts(
            value["activation_request"]
        )
        if artifacts != value.get("activation_artifacts"):
            raise NativeActivationPreviewError(
                "activation-plan-artifacts-mismatch"
            )
        child_bindings = value.get("child_bindings")
        if (
            type(child_bindings) is not list
            or len(child_bindings) != len(tasks)
        ):
            raise NativeActivationPreviewError(
                "activation-plan-child-bindings-invalid"
            )
        expected_activation_children = [
            _activation_child(task, binding)
            for task, binding in zip(tasks, child_bindings)
        ]
        request = value.get("activation_request")
        if (
            type(request) is not dict
            or request.get("children") != expected_activation_children
            or request.get("launch_id") != value.get("launch_id")
            or request.get("pool_id") != value.get("pool_id")
            or request.get("pool_epoch") != value.get("pool_epoch")
            or request.get("campaign_nonce") != value.get("campaign_nonce")
            or request.get("requested_workers")
            != value.get("requested_workers")
        ):
            raise NativeActivationPreviewError(
                "activation-plan-request-binding-invalid"
            )
        unsigned = dict(value)
        observed = unsigned.pop("plan_sha256")
        if not _sha256(observed) or observed != canonical_activation_sha256(
            unsigned
        ):
            raise NativeActivationPreviewError(
                "activation-plan-sha256-mismatch"
            )
        prepared_at = _parse_time(
            value.get("prepared_at"),
            label="activation-plan-prepared-at",
        )
        expires_at = _parse_time(
            value.get("expires_at"),
            label="activation-plan-expires-at",
        )
        if expires_at <= prepared_at or (
            now is not None
            and now.astimezone(dt.timezone.utc) >= expires_at
        ):
            raise NativeActivationPreviewError(
                "activation-plan-expired"
            )
        if check_live_source:
            observed_source, commit, tree = _source_identity(source)
            if (
                str(observed_source) != str(source)
                or commit != value.get("candidate_commit")
                or tree != value.get("candidate_tree")
            ):
                raise NativeActivationPreviewError(
                    "activation-plan-candidate-drift"
                )
        return []
    except (
        AuthorityProvenanceError,
        NativeActivationLedgerError,
        NativeActivationPreviewError,
        TypeError,
        ValueError,
    ) as exc:
        return [str(exc)]


def load_activation_plan(
    path: Path,
    *,
    check_live_source: bool = True,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    value = read_private_json(path, label="activation-plan")
    errors = validate_activation_plan(
        value,
        check_live_source=check_live_source,
        now=now,
    )
    if errors:
        raise NativeActivationPreviewError(
            "activation-plan-invalid:" + ";".join(errors)
        )
    return value


def prepare_activation_plan(
    control_root: Path,
    *,
    profile: str,
    source_repository: Path,
    now: dt.datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    if profile not in PROFILE:
        raise NativeActivationPreviewError(
            "activation-plan-profile-invalid"
        )
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise NativeActivationPreviewError("activation-time-invalid")
    source, commit, tree = _source_identity(source_repository)
    root = ensure_private_directory(Path(control_root), create=True)
    if root == source or root.is_relative_to(source):
        raise NativeActivationPreviewError(
            "activation-control-root-inside-source-forbidden"
        )
    runs = ensure_private_directory(root / "runs", create=True)
    activation_id = str(uuid.uuid4())
    run_root = ensure_private_directory(runs / activation_id, create=True)
    records = ensure_private_directory(run_root / "records", create=True)
    claims = ensure_private_directory(root / "claims", create=True)
    ledger = run_root / "allocation-ledger"
    layout = _create_git_layout(run_root, activation_id, profile)
    integration = layout["integration"]
    authorization_id = str(uuid.uuid4())
    campaign_nonce = str(uuid.uuid4())
    override = seal_tool_enforcement_override(
        {
            "override_type": "cwo-native-tool-enforcement-override",
            "version": 1,
            "schema": "schemas/native-tool-enforcement-override.schema.json",
            "authorization_id": authorization_id,
            "authorization_canonical_sha256": canonical_activation_sha256(
                {
                    "activation_id": activation_id,
                    "profile": profile,
                    "candidate_commit": commit,
                    "candidate_tree": tree,
                }
            ),
            "outer_authority_id": str(uuid.uuid4()),
            "outer_authority_file_sha256": canonical_activation_sha256(
                {"control_root": str(root)}
            ),
            "outer_authority_canonical_sha256": canonical_activation_sha256(
                {
                    "risk_acknowledgement": TOOL_ENFORCEMENT_OVERRIDE_RISK,
                    "default": "server-allowlist-required",
                }
            ),
            "campaign_nonce": campaign_nonce,
            "candidate_commit": commit,
            "candidate_tree": tree,
            "max_workers": 2,
            "max_mutating_workers": 1,
            "single_use": True,
            "risk_acknowledgement": TOOL_ENFORCEMENT_OVERRIDE_RISK,
        }
    )
    (
        beads_directory,
        beads_database,
        epic_id,
        _issue_ids,
        estimates,
        scope_items,
    ) = _create_beads_graph(
        run_root,
        profile=profile,
        integration=integration,
        override=override,
        now=current,
    )
    ready_items = [
        item for item in scope_items if item["raw"]["_cwo_canonical_ready"]
    ]
    policy = load_policy("native-worker-execution")
    readiness = build_ready_set_evidence(
        ready_items,
        epic_id=epic_id,
        requested_workers=PROFILE[profile]["workers"],
        policy_document=policy,
        scope_items=scope_items,
    )
    assessment = pool_proportionality_check(
        readiness,
        estimates,
        requested_workers=PROFILE[profile]["workers"],
        policy_document=policy,
    )
    selected = assessment.get("selected_cohort")
    issue_ids = (
        list(selected["issue_ids"])
        if isinstance(selected, Mapping)
        else [str(assessment["fallback_issue_id"])]
    )
    tasks = [
        _prospective_task(
            profile=profile,
            ordinal=ordinal,
            bead_id=bead_id,
            estimate=estimates[bead_id],
            worktree=layout["worktrees"][ordinal],
            override=override,
        )
        for ordinal, bead_id in enumerate(issue_ids)
    ]
    from .native_pool_admission import build_admission_child_binding

    bindings = [
        build_admission_child_binding(
            readiness,
            estimates[task["bead_id"]],
            bead_id=task["bead_id"],
            child_id=task["child_id"],
            packet_id=task["packet_id"],
            packet_sha256=task["packet_sha256"],
            worktree_identity_sha256=task["worktree_identity_sha256"],
        )
        for task in tasks
    ]
    candidate = AdmissionCandidate(
        readiness,
        estimates,
        assessment,
        {binding["bead_id"]: binding for binding in bindings},
    )
    offline_adapter = BeadsClaimAdapter(
        directory=beads_directory,
        database=beads_database,
        actor="native-activation-preview-offline",
        timeout=20,
    )
    reserve_pool_cohort(
        candidate,
        claim_adapter=offline_adapter,
        admission_nonce=f"offline-{activation_id}",
        live_revalidate=lambda binding: dict(binding),
        policy_document=policy,
        productive=False,
        now=current,
    )
    launch_id = str(uuid.uuid4())
    pool_id = str(uuid.uuid4())
    pool_epoch = str(uuid.uuid4())
    activation_request = {
        "launch_id": launch_id,
        "pool_id": pool_id,
        "pool_epoch": pool_epoch,
        "campaign_nonce": campaign_nonce,
        "requested_workers": PROFILE[profile]["workers"],
        "children": [
            _activation_child(task, binding)
            for task, binding in zip(tasks, bindings)
        ],
    }
    aggregate_budget = {
        field: sum(int(task["hard_budget"][field]) for task in tasks)
        for field in (
            "tool_calls",
            "runtime_seconds",
            "compactions",
            "full_suite_runs",
            "mutations",
        )
    }
    for task in tasks:
        task["hard_budget"] = deepcopy(task["hard_budget"])
    paths = {
        "records": str(records),
        "integration": str(integration),
        "beads_directory": str(beads_directory),
        "beads_database": str(beads_database),
        "claims": str(claims),
        "ledger": str(ledger),
        "leases": str(run_root / "leases.json"),
        "pool_state": str(run_root / "pool-state.json"),
        "pool_decision": str(run_root / "pool-decision.json"),
        "approval": str(run_root / "approval.json"),
        "approval_replay": str(root / "operator-approval-replay.json"),
        "result": str(run_root / "result.json"),
    }
    plan = _seal_plan(
        {
            "plan_type": PLAN_TYPE,
            "version": PLAN_VERSION,
            "schema": PLAN_SCHEMA,
            "activation_id": activation_id,
            "profile": profile,
            "prepared_at": activation_iso(current),
            "expires_at": activation_iso(
                current + dt.timedelta(seconds=PLAN_TTL_SECONDS)
            ),
            "source_repository": str(source),
            "candidate_commit": commit,
            "candidate_tree": tree,
            "control_root": str(root),
            "run_root": str(run_root),
            "launch_id": launch_id,
            "pool_id": pool_id,
            "pool_epoch": pool_epoch,
            "campaign_nonce": campaign_nonce,
            "requested_workers": PROFILE[profile]["workers"],
            "mutating_workers": PROFILE[profile]["mutating_workers"],
            "risk_acknowledgement": TOOL_ENFORCEMENT_OVERRIDE_RISK,
            "paths": paths,
            "override": override,
            "epic_id": epic_id,
            "tasks": tasks,
            "readiness_evidence": readiness,
            "work_estimates": estimates,
            "proportionality_assessment": assessment,
            "child_bindings": bindings,
            "activation_request": activation_request,
            "activation_artifacts": (
                tool_enforcement_activation_artifacts(activation_request)
            ),
        }
    )
    if aggregate_budget["mutations"] != PROFILE[profile]["mutating_workers"]:
        raise NativeActivationPreviewError(
            "activation-plan-mutation-budget-invalid"
        )
    plan_path = run_root / "prepared.json"
    write_exclusive_private_json(
        plan_path,
        plan,
        label="activation-plan",
    )
    fsync_private_directory(run_root)
    return plan_path, plan


def approve_activation_plan(
    plan_path: Path,
    *,
    control_root: Path,
    actor_id: str,
    identity_source: str,
    ttl_seconds: int,
    risk_acknowledgement: str,
    now: dt.datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    if risk_acknowledgement != TOOL_ENFORCEMENT_OVERRIDE_RISK:
        raise NativeActivationPreviewError(
            "activation-risk-acknowledgement-required"
        )
    if (
        type(ttl_seconds) is not int
        or not APPROVAL_TTL_MIN_SECONDS
        <= ttl_seconds
        <= APPROVAL_TTL_MAX_SECONDS
    ):
        raise NativeActivationPreviewError(
            "activation-approval-ttl-invalid"
        )
    current = now or dt.datetime.now(dt.timezone.utc)
    plan = load_activation_plan(
        Path(plan_path),
        check_live_source=True,
        now=current,
    )
    root = ensure_private_directory(Path(control_root), create=False)
    if str(root) != plan["control_root"]:
        raise NativeActivationPreviewError(
            "activation-control-root-mismatch"
        )
    key = read_activation_key(root)
    assessment = tool_enforcement_activation_assessment(
        plan["activation_request"],
        plan["activation_artifacts"],
    )
    try:
        receipt = sign_operator_approval_receipt(
            assessment,
            change_type="security-or-authority-change",
            signing_key=key,
            actor_id=actor_id,
            identity_source=identity_source,
            authorized_scope="complete-task",
            issued_at=current,
            expires_at=current + dt.timedelta(seconds=ttl_seconds),
        )
    except AuthorityProvenanceError as exc:
        raise NativeActivationPreviewError(str(exc)) from exc
    approval_path = Path(plan["paths"]["approval"])
    write_exclusive_private_json(
        approval_path,
        receipt,
        label="activation-approval",
    )
    return approval_path, receipt


def validate_activation_approval(
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    *,
    key: bytes,
    actor_id: str,
    identity_source: str,
    now: dt.datetime | None = None,
) -> list[str]:
    assessment = tool_enforcement_activation_assessment(
        plan["activation_request"],
        plan["activation_artifacts"],
    )
    return validate_operator_approval_receipt(
        approval,
        verification_key=key,
        expected_actor_id=actor_id,
        expected_identity_source=identity_source,
        expected_change_type="security-or-authority-change",
        before_artifact=assessment.before_subject,
        after_artifact=assessment.after_subject,
        now=now,
    )


def activation_dry_run(
    plan_path: Path,
    approval_path: Path,
    *,
    control_root: Path,
    actor_id: str,
    identity_source: str,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    current = now or dt.datetime.now(dt.timezone.utc)
    plan = load_activation_plan(
        Path(plan_path),
        check_live_source=True,
        now=current,
    )
    root = ensure_private_directory(Path(control_root), create=False)
    if str(root) != plan["control_root"]:
        raise NativeActivationPreviewError(
            "activation-control-root-mismatch"
        )
    approval = read_private_json(
        Path(approval_path),
        label="activation-approval",
    )
    errors = validate_activation_approval(
        plan,
        approval,
        key=read_activation_key(root),
        actor_id=actor_id,
        identity_source=identity_source,
        now=current,
    )
    if errors:
        raise NativeActivationPreviewError(
            "activation-approval-invalid:" + ";".join(errors)
        )
    candidate = AdmissionCandidate(
        plan["readiness_evidence"],
        plan["work_estimates"],
        plan["proportionality_assessment"],
        {
            binding["bead_id"]: binding
            for binding in plan["child_bindings"]
        },
    )
    adapter = BeadsClaimAdapter(
        directory=Path(plan["paths"]["beads_directory"]),
        database=Path(plan["paths"]["beads_database"]),
        actor="native-activation-preview-dry-run",
        timeout=20,
    )
    offline = reserve_pool_cohort(
        candidate,
        claim_adapter=adapter,
        admission_nonce=f"dry-run-{plan['activation_id']}",
        live_revalidate=lambda binding: dict(binding),
        policy_document=load_policy("native-worker-execution"),
        productive=False,
        now=current,
    )
    return {
        "status": "dry-run-accepted",
        "live": False,
        "consumed": False,
        "activation_id": plan["activation_id"],
        "profile": plan["profile"],
        "plan_sha256": plan["plan_sha256"],
        "action_sha256": plan["activation_artifacts"]["action_sha256"],
        "approval_sha256": canonical_activation_sha256(approval),
        "fixed_cohort_sha256": offline.receipt["fixed_cohort_sha256"],
        "requested_workers": plan["requested_workers"],
        "mutating_workers": plan["mutating_workers"],
        "risk_acknowledgement": TOOL_ENFORCEMENT_OVERRIDE_RISK,
    }


def _claim_marker_path(root: Path, kind: str, identifier: str) -> Path:
    digest = canonical_activation_sha256(
        {"kind": kind, "identifier": identifier}
    )
    return root / f"marker-{kind}-{digest}.json"


def _claim_path(root: Path, activation_id: str, campaign_nonce: str) -> Path:
    digest = canonical_activation_sha256(
        {
            "activation_id": activation_id,
            "campaign_nonce": campaign_nonce,
        }
    )
    return root / f"claim-{digest}.json"


def _validate_claim(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != CLAIM_FIELDS:
        raise NativeActivationPreviewError(
            "activation-claim-fields-invalid"
        )
    if (
        value.get("claim_type") != CLAIM_TYPE
        or value.get("version") != CLAIM_VERSION
        or value.get("schema") != CLAIM_SCHEMA
    ):
        raise NativeActivationPreviewError(
            "activation-claim-header-invalid"
        )
    for field in (
        "claim_id",
        "activation_id",
        "launch_id",
        "pool_id",
        "pool_epoch",
        "campaign_nonce",
    ):
        if not _uuid(value.get(field)):
            raise NativeActivationPreviewError(
                f"activation-claim-{field.replace('_', '-')}-invalid"
            )
    for field in ("approval_id", "approval_nonce"):
        if type(value.get(field)) is not str or not value[field].strip():
            raise NativeActivationPreviewError(
                f"activation-claim-{field.replace('_', '-')}-invalid"
            )
    for field in (
        "plan_sha256",
        "approval_sha256",
        "action_sha256",
        "override_sha256",
        "fixed_cohort_sha256",
        "child_bindings_sha256",
        "claim_sha256",
    ):
        if not _sha256(value.get(field)):
            raise NativeActivationPreviewError(
                f"activation-claim-{field.replace('_', '-')}-invalid"
            )
    unsigned = dict(value)
    observed = unsigned.pop("claim_sha256")
    if observed != canonical_activation_sha256(unsigned):
        raise NativeActivationPreviewError(
            "activation-claim-sha256-mismatch"
        )
    return dict(value)


def _migrate_claim_markers(root: Path) -> None:
    for path in sorted(root.glob("claim-*.json")):
        claim = _validate_claim(
            read_private_json(path, label="activation-claim")
        )
        for kind, identifier in (
            ("activation", str(claim["activation_id"])),
            ("nonce", str(claim["campaign_nonce"])),
        ):
            marker_path = _claim_marker_path(root, kind, identifier)
            marker = {
                "marker_type": "cwo-native-tool-activation-claim-marker",
                "version": 1,
                "kind": kind,
                "identifier": identifier,
                "claim_sha256": claim["claim_sha256"],
            }
            marker["marker_sha256"] = canonical_activation_sha256(marker)
            if marker_path.exists():
                observed = read_private_json(
                    marker_path,
                    label="activation-claim-marker",
                )
                if observed != marker:
                    raise NativeActivationPreviewError(
                        "activation-claim-marker-conflict"
                    )
            else:
                write_exclusive_private_json(
                    marker_path,
                    marker,
                    label="activation-claim-marker",
                )


def acquire_activation_claim(
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    *,
    controller_identity: Mapping[str, Any],
    claimed_at: str | None = None,
) -> dict[str, Any]:
    errors = validate_activation_plan(
        plan,
        check_live_source=True,
        now=dt.datetime.now(dt.timezone.utc),
    )
    if errors:
        raise NativeActivationPreviewError(
            "activation-plan-invalid:" + ";".join(errors)
        )
    root = ensure_private_directory(
        Path(plan["paths"]["claims"]),
        create=False,
    )
    with locked_private_file(
        root / ".claims.lock",
        label="activation-claims",
    ):
        _migrate_claim_markers(root)
        for kind, identifier in (
            ("activation", str(plan["activation_id"])),
            ("nonce", str(plan["campaign_nonce"])),
        ):
            if _claim_marker_path(root, kind, identifier).exists():
                raise NativeActivationPreviewError(
                    f"activation-claim-{kind}-reused"
                )
        artifacts = plan["activation_artifacts"]["action"]
        output_paths = {
            field: plan["paths"][field]
            for field in (
                "ledger",
                "leases",
                "pool_state",
                "pool_decision",
                "result",
            )
        }
        claim: dict[str, Any] = {
            "claim_type": CLAIM_TYPE,
            "version": CLAIM_VERSION,
            "schema": CLAIM_SCHEMA,
            "claim_id": str(uuid.uuid4()),
            "activation_id": plan["activation_id"],
            "profile": plan["profile"],
            "plan_sha256": plan["plan_sha256"],
            "approval_sha256": canonical_activation_sha256(approval),
            "approval_id": (
                str(approval["approval_id"])
                if isinstance(approval.get("approval_id"), str)
                and approval["approval_id"].strip()
                else "invalid-" + canonical_activation_sha256(approval)[:32]
            ),
            "approval_nonce": (
                str(approval["nonce"])
                if isinstance(approval.get("nonce"), str)
                and approval["nonce"].strip()
                else "invalid-" + canonical_activation_sha256(approval)[32:]
            ),
            "action_sha256": plan["activation_artifacts"]["action_sha256"],
            "override_sha256": artifacts["override_sha256"],
            "launch_id": plan["launch_id"],
            "pool_id": plan["pool_id"],
            "pool_epoch": plan["pool_epoch"],
            "campaign_nonce": plan["campaign_nonce"],
            "candidate_commit": plan["candidate_commit"],
            "candidate_tree": plan["candidate_tree"],
            "requested_workers": plan["requested_workers"],
            "mutating_workers": plan["mutating_workers"],
            "fixed_cohort_sha256": artifacts["fixed_cohort_sha256"],
            "child_bindings_sha256": artifacts["child_bindings_sha256"],
            "output_paths": output_paths,
            "controller_identity": deepcopy(dict(controller_identity)),
            "claimed_at": claimed_at or activation_iso(),
        }
        claim["claim_sha256"] = canonical_activation_sha256(claim)
        _validate_claim(claim)
        path = _claim_path(
            root,
            str(plan["activation_id"]),
            str(plan["campaign_nonce"]),
        )
        # Persist the pair-bearing claim first. Marker migration can recreate
        # either tombstone after a crash, so the attempt remains burned.
        write_exclusive_private_json(
            path,
            claim,
            label="activation-claim",
        )
        _migrate_claim_markers(root)
        fsync_private_directory(root)
        return claim


def operator_approval_verifier(
    plan: Mapping[str, Any],
    *,
    key: bytes,
    actor_id: str,
    identity_source: str,
    now: dt.datetime | None = None,
) -> OperatorApprovalVerifier:
    replay_path = Path(plan["paths"]["approval_replay"])
    ensure_private_directory(replay_path.parent, create=False)
    try:
        return OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id=actor_id,
            expected_identity_source=identity_source,
            replay_store_path=replay_path,
            now=now,
        )
    except AuthorityProvenanceError as exc:
        raise NativeActivationPreviewError(str(exc)) from exc
