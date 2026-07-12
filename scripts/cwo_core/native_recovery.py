"""Pure recovery, lineage, and semantic verification foundations.

Nothing in this module performs replay or reads the workspace.  The caller
supplies trusted observations and receives a fail-closed verification result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class RecoveryLineage:
    root_packet_id: str
    parent_packet_id: str | None
    attempt: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_packet_id": self.root_packet_id,
            "parent_packet_id": self.parent_packet_id,
            "attempt": self.attempt,
        }


@dataclass(frozen=True)
class RecoveryContract:
    enabled: bool = False
    autonomous_replay: bool = False
    max_retries: int = 0
    requires_fresh_session: bool = True
    incomplete_baseline_disables_replay: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "autonomous_replay": self.autonomous_replay,
            "max_retries": self.max_retries,
            "requires_fresh_session": self.requires_fresh_session,
            "incomplete_baseline_disables_replay": self.incomplete_baseline_disables_replay,
        }


def build_recovery_contract(*, version: int = 2) -> dict[str, Any]:
    """Build the inert recovery contract for a packet version."""
    if version not in {2, 3}:
        raise ValueError("recovery contract supports packet versions 2 and 3")
    return RecoveryContract().as_dict()


def build_recovery_lineage(packet_id: str, *, root_packet_id: str | None = None, parent_packet_id: str | None = None, attempt: int = 0) -> dict[str, Any]:
    if not isinstance(packet_id, str) or not packet_id.strip():
        raise ValueError("packet_id is required")
    if attempt not in {0, 1}:
        raise ValueError("attempt must be 0 or 1")
    root = root_packet_id or packet_id
    if attempt == 0 and parent_packet_id is not None:
        raise ValueError("attempt 0 cannot have a parent packet")
    if attempt == 1 and (not parent_packet_id or parent_packet_id == packet_id):
        raise ValueError("attempt 1 requires a distinct parent packet")
    return RecoveryLineage(root, parent_packet_id, attempt).as_dict()


def replay_is_allowed(*, recovery_contract: Mapping[str, Any] | None, workspace_evidence: Mapping[str, Any] | None = None) -> bool:
    """Return whether a future caller may consider replay; never performs it."""
    contract = recovery_contract or {}
    if contract.get("enabled") is not True or contract.get("autonomous_replay") is not True:
        return False
    if workspace_evidence and workspace_evidence.get("incomplete"):
        return False
    return False


def _claim(packet: Mapping[str, Any], claims: Mapping[str, Any], key: str, errors: list[str]) -> None:
    expected = packet.get(key)
    actual = claims.get(key)
    if actual is not None and expected is not None and actual != expected:
        errors.append(f"{key} claim contradicts packet")


def _paths_from_evidence(evidence: Mapping[str, Any]) -> set[str]:
    paths: set[str] = set()
    for key in ("changed_paths", "scoped_paths", "observed_paths"):
        value = evidence.get(key)
        if isinstance(value, list):
            paths.update(str(item) for item in value)
    for key in ("changes", "allowed_mutations", "scoped_mutations"):
        value = evidence.get(key)
        if isinstance(value, list):
            paths.update(str(item.get("path")) for item in value if isinstance(item, Mapping) and item.get("path"))
    return paths


def verify_native_worker_semantics(
    packet: Mapping[str, Any],
    worker_claims: Mapping[str, Any],
    trusted_usage: Mapping[str, Any],
    action_receipts: list[Mapping[str, Any]],
    workspace_evidence: Mapping[str, Any],
    validation_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare claims with trusted observations without granting claim authority."""
    errors: list[str] = []
    warnings: list[str] = []
    for key in ("packet_id", "bead_id", "session_id", "segment_id", "requested_model"):
        _claim(packet, worker_claims, key, errors)
    for key in ("session_id", "segment_id", "model", "actual_model", "attestation_status", "attestation_source"):
        if key in trusted_usage and key in worker_claims and trusted_usage[key] != worker_claims[key]:
            errors.append(f"{key} claim contradicts trusted attestation evidence")
    trusted_model = trusted_usage.get("model") or trusted_usage.get("actual_model")
    if trusted_model and trusted_model != packet.get("requested_model"):
        errors.append("trusted model evidence contradicts packet requested_model")
    if worker_claims.get("actual_model") is not None and worker_claims.get("attestation_status") == "trusted":
        if worker_claims.get("actual_model") != packet.get("requested_model"):
            errors.append("trusted model claim contradicts packet requested_model")
    claimed_usage = worker_claims.get("usage")
    if isinstance(claimed_usage, Mapping):
        for key, observed in trusted_usage.items():
            if key in claimed_usage and claimed_usage[key] != observed:
                errors.append(f"usage.{key} claim contradicts trusted observed usage")

    observed_receipts = [receipt for receipt in action_receipts if isinstance(receipt, Mapping)]
    if any(receipt.get("pairing_status") != "paired" or receipt.get("action_class") == "unknown" for receipt in observed_receipts):
        errors.append("action receipts contain unknown or unpaired evidence")
    claimed_commands = worker_claims.get("commands_run", [])
    if isinstance(claimed_commands, list):
        rendered = [str(receipt.get("redacted_command") or "") for receipt in observed_receipts]
        for command in claimed_commands:
            if isinstance(command, str) and command.strip() and not any(command.strip() in item for item in rendered):
                errors.append("commands_run claim has no matching trusted action receipt")
    claimed_results = worker_claims.get("command_results") or worker_claims.get("results")
    if isinstance(claimed_results, list):
        trusted_exit_codes = [receipt.get("exit_code") for receipt in observed_receipts]
        for result in claimed_results:
            if isinstance(result, Mapping) and result.get("exit_code") not in trusted_exit_codes:
                errors.append("command result claim has no matching trusted action receipt")
    claimed_files = worker_claims.get("files_touched", [])
    evidence_paths = _paths_from_evidence(workspace_evidence)
    if isinstance(claimed_files, list):
        for path in claimed_files:
            if str(path) not in evidence_paths:
                errors.append(f"files_touched claim has no matching workspace evidence: {path}")
    if workspace_evidence.get("out_of_scope") or workspace_evidence.get("unexpected_mutation_detected"):
        errors.append("workspace evidence reports out-of-scope mutation")
    if workspace_evidence.get("attribution_ambiguous") or workspace_evidence.get("incomplete"):
        errors.append("workspace evidence is incomplete or attribution-ambiguous")

    phase_contract = packet.get("phase_contract")
    status = worker_claims.get("status")
    expected_artifact = phase_contract.get("expected_artifact_class") if isinstance(phase_contract, Mapping) else None
    artifact = worker_claims.get("artifact_class") or worker_claims.get("phase_artifact")
    if artifact is None and isinstance(worker_claims.get("artifact"), Mapping):
        artifact = worker_claims["artifact"].get("class")
    if status == "completed" and expected_artifact and artifact != expected_artifact:
        errors.append("completed return is missing its required phase artifact")
    if status == "completed" and validation_evidence.get("status") not in {"pass", "passed", "valid"}:
        errors.append("completed return lacks passing validation evidence")
    if validation_evidence.get("contradiction") or validation_evidence.get("contradictions"):
        errors.append("validation evidence contradicts worker claims")

    return {
        "verifier": "cwo-native-semantic-verifier",
        "version": 1,
        "eligible": not errors,
        "fail_closed": bool(errors),
        "errors": errors,
        "warnings": warnings,
        "trusted_observation_counts": {
            "action_receipts": len(observed_receipts),
            "workspace_paths": len(evidence_paths),
        },
    }


semantic_verify = verify_native_worker_semantics
verify_semantics = verify_native_worker_semantics
verify_semantic_contract = verify_native_worker_semantics
