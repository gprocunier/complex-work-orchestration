#!/usr/bin/env python3
"""Run disposable exact-Spark app-server canaries for supervisor concurrency.

This ignored work-packet harness persists only sanitized, hash-bound evidence.
Raw model messages and reasoning remain in Codex-owned session telemetry and are
never copied into the result artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import pwd
import re
from pathlib import Path
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_live_campaign_contracts import (  # noqa: E402
    HistoricalV4V1ProofInputs,
    JsonArtifactSnapshot,
    VALIDATOR_CONTRACT_PATHS,
    Version5PredecessorProofInputs,
    active_outer_authority_scope_key,
    validate_campaign_manifest,
    validate_full_auto_authorization as validate_full_auto_authorization_contract,
    validate_release_patch_result,
    validator_contract_sha256,
)
from cwo_core.native_canary_contracts import (  # noqa: E402
    CanaryAuthorizationStore,
    CONTROL_OBSERVATION_MAX,
    MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError,
    canonical_sha256 as domain_sha256,
    consume_steering_receipt,
    materialization_execution_correlation,
    new_authorization_state,
    seal_materialization_evidence,
    validate_capability_rendered_command,
    validate_materialization_evidence,
)
from cwo_core.native_pool import NativePoolCoordinator  # noqa: E402
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    EXPECTED_ROLES,
    NativeLiveAllocationLedgerError,
    NativeLiveAllocationLedgerStore,
)
from cwo_core.native_pool_config import build_live_canary_pool_contract  # noqa: E402
from cwo_core.native_pool_contracts import (  # noqa: E402
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    canonical_sha256,
    callback_certification_policy_sha256,
    seal_artifact,
    validate_capability_receipt,
    validate_pool_receipt,
    write_private_artifact,
    zero_token_usage,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry, capture_owner_identity  # noqa: E402
from cwo_core.native_pool_scheduler import select_earliest_deadline  # noqa: E402
from cwo_core.native_pool_workspace import PoolWorkspaceMonitor  # noqa: E402
from cwo_core.native_session_boundary import (  # noqa: E402
    NativeSessionBoundaryError,
    capture_boundary,
    capture_unique_boundary,
    telemetry_markers,
    trusted_terminal_event,
    trusted_turn_context,
)


EXACT_MODEL = "gpt-5.3-codex-spark"
CONTROL_TURN_ID = "complex-work-orchestration-18w.6-live-canary-control-turn"
POST_SUBMISSION_MATERIALIZATION_GRACE_MS = POOL_POLL_LAG_TOLERANCE_MS
PROVISIONAL_TERMINAL_GRACE_SECONDS = 5.0
OPERATIVE_ITEM_TYPES = {
    "commandExecution",
    "fileChange",
    "mcpToolCall",
    "dynamicToolCall",
    "collabAgentToolCall",
    "webSearch",
    "imageView",
    "sleep",
    "imageGeneration",
}
INDEPENDENT_VALIDATION_RECORD_TYPES = {
    "session_meta",
    "event_msg",
    "response_item",
    "world_state",
    "turn_context",
}
INDEPENDENT_VALIDATION_EVENT_TYPES = {
    "task_started",
    "user_message",
    "agent_message",
    "token_count",
    "task_complete",
}
INDEPENDENT_VALIDATION_RESPONSE_TYPES = {"message", "reasoning"}
INDEPENDENT_VALIDATION_MESSAGE_ROLES = {"developer", "user", "assistant"}


class CampaignLaunchInputs:
    """One read-once snapshot set for a live-campaign launch decision."""

    __slots__ = (
        "authorization",
        "manifest",
        "outer_authority",
        "release_patch_bytes",
        "pre_mutation_receipt",
        "pre_mutation_adjudication",
        "pre_live_receipt",
        "pre_live_adjudication",
        "opus_review_evidence",
        "opus_adjudication",
        "spark_validation_receipt",
        "spark_validation_session_path",
        "spark_validation_session_bytes",
        "legacy_predecessor",
        "predecessor_proof",
        "recovery_cause_evidence",
        "recovery_cause_source_analysis_bytes",
        "source_identities",
    )

    def __init__(
        self,
        *,
        authorization: JsonArtifactSnapshot,
        manifest: JsonArtifactSnapshot,
        outer_authority: JsonArtifactSnapshot,
        release_patch_bytes: bytes,
        pre_mutation_receipt: JsonArtifactSnapshot,
        pre_mutation_adjudication: JsonArtifactSnapshot,
        pre_live_receipt: JsonArtifactSnapshot,
        pre_live_adjudication: JsonArtifactSnapshot,
        opus_review_evidence: JsonArtifactSnapshot,
        opus_adjudication: JsonArtifactSnapshot,
        spark_validation_receipt: JsonArtifactSnapshot,
        spark_validation_session_path: Path,
        spark_validation_session_bytes: bytes,
        legacy_predecessor: HistoricalV4V1ProofInputs | None = None,
        predecessor_proof: Version5PredecessorProofInputs | None = None,
        recovery_cause_evidence: JsonArtifactSnapshot | None = None,
        recovery_cause_source_analysis_bytes: bytes | None = None,
        source_identities: Mapping[str, tuple[int, int, int, int]] | None = None,
    ) -> None:
        self.authorization = authorization
        self.manifest = manifest
        self.outer_authority = outer_authority
        self.release_patch_bytes = release_patch_bytes
        self.pre_mutation_receipt = pre_mutation_receipt
        self.pre_mutation_adjudication = pre_mutation_adjudication
        self.pre_live_receipt = pre_live_receipt
        self.pre_live_adjudication = pre_live_adjudication
        self.opus_review_evidence = opus_review_evidence
        self.opus_adjudication = opus_adjudication
        self.spark_validation_receipt = spark_validation_receipt
        self.spark_validation_session_path = spark_validation_session_path
        self.spark_validation_session_bytes = spark_validation_session_bytes
        self.legacy_predecessor = legacy_predecessor
        self.predecessor_proof = predecessor_proof
        self.recovery_cause_evidence = recovery_cause_evidence
        self.recovery_cause_source_analysis_bytes = (
            recovery_cause_source_analysis_bytes
        )
        self.source_identities = dict(source_identities or {})


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def run_git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def require_repository_checkpoint(repo_root: Path, expected_head: str) -> None:
    if run_git(repo_root, "rev-parse", "HEAD") != expected_head:
        raise AppServerError("full-auto-repository-head-changed")
    if run_git(repo_root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise AppServerError("full-auto-repository-not-clean")


def percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("capability-stat-samples-missing")
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * ratio) - 1))
    return ordered[index]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.50), 3),
        "p90_ms": round(percentile(values, 0.90), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def callback_certification_policy() -> dict[str, Any]:
    try:
        document = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("callback-certification-policy-unreadable") from exc
    pool = document.get("native_supervision_pool") if isinstance(document, Mapping) else None
    certification = pool.get("callback_certification") if isinstance(pool, Mapping) else None
    expected = {
        "version": CAPABILITY_CERTIFICATION_VERSION,
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": CAPABILITY_SCHEDULER_MODEL,
        "response_time_equation": CAPABILITY_RESPONSE_TIME_EQUATION,
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_callback_max_ms": CERTIFIED_CALLBACK_MAX_MS,
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
    }
    if not isinstance(certification, Mapping) or dict(certification) != expected:
        raise AppServerError("callback-certification-policy-invalid")
    return dict(certification)


def capability_certification() -> dict[str, Any]:
    policy = callback_certification_policy()
    return {
        **policy,
        "policy_sha256": callback_certification_policy_sha256(policy),
        "adapter_implementation_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }


def validate_full_auto_authorization(
    authorization: Mapping[str, Any],
    campaign_nonce: str,
    *,
    predecessor_authorization: Mapping[str, Any] | None = None,
    predecessor_authorization_raw_sha256: str | None = None,
    predecessor_manifest: Mapping[str, Any] | None = None,
    predecessor_manifest_raw_sha256: str | None = None,
    predecessor_authorization_state: Mapping[str, Any] | None = None,
    predecessor_authorization_state_raw_sha256: str | None = None,
    predecessor_failure_evidence: Mapping[str, Any] | None = None,
    predecessor_failure_evidence_raw_sha256: str | None = None,
    predecessor_original_containment: Mapping[str, Any] | None = None,
    predecessor_original_containment_raw_sha256: str | None = None,
    predecessor_containment: Mapping[str, Any] | None = None,
    predecessor_containment_raw_sha256: str | None = None,
    predecessor_allocation_ledger: Mapping[str, Any] | None = None,
    predecessor_allocation_ledger_raw_sha256: str | None = None,
    predecessor_allocation_audit_path: Path | None = None,
    predecessor_allocation_audit_raw_sha256: str | None = None,
    predecessor_allocation_audit_bytes: bytes | None = None,
    cause_evidence: bytes | None = None,
    predecessor_proof: Version5PredecessorProofInputs | None = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path,
) -> tuple[str, str]:
    if authorization.get("version") == 6:
        errors = validate_full_auto_authorization_contract(
            authorization,
            expected_campaign_nonce=campaign_nonce,
            predecessor_proof=predecessor_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=repo_root,
        )
    else:
        errors = validate_full_auto_authorization_contract(
            authorization,
            expected_campaign_nonce=campaign_nonce,
            predecessor_authorization=predecessor_authorization,
            predecessor_authorization_raw_sha256=predecessor_authorization_raw_sha256,
            predecessor_manifest=predecessor_manifest,
            predecessor_manifest_raw_sha256=predecessor_manifest_raw_sha256,
            predecessor_authorization_state=predecessor_authorization_state,
            predecessor_authorization_state_raw_sha256=predecessor_authorization_state_raw_sha256,
            predecessor_failure_evidence=predecessor_failure_evidence,
            predecessor_failure_evidence_raw_sha256=predecessor_failure_evidence_raw_sha256,
            predecessor_original_containment=predecessor_original_containment,
            predecessor_original_containment_raw_sha256=predecessor_original_containment_raw_sha256,
            predecessor_containment=predecessor_containment,
            predecessor_containment_raw_sha256=predecessor_containment_raw_sha256,
            predecessor_allocation_ledger=predecessor_allocation_ledger,
            predecessor_allocation_ledger_raw_sha256=predecessor_allocation_ledger_raw_sha256,
            predecessor_allocation_audit_path=predecessor_allocation_audit_path,
            predecessor_allocation_audit_raw_sha256=predecessor_allocation_audit_raw_sha256,
            predecessor_allocation_audit_bytes=predecessor_allocation_audit_bytes,
            cause_evidence=cause_evidence,
            repo_root=repo_root,
        )
    if errors:
        raise AppServerError("full-auto-authorization-invalid:" + ";".join(errors))
    return str(authorization["authorization_id"]), run_git(repo_root, "rev-parse", "HEAD")


def plan_steering_receipt_consumptions(
    campaign_nonce: str,
    authorization_id: str,
    authorization_sha256: str,
    *,
    registry_file: Path,
    repo_head: str,
    pre_mutation_receipt: Mapping[str, Any],
    pre_mutation_adjudication: Mapping[str, Any],
    pre_mutation_adjudication_sha256: str,
    pre_live_receipt: Mapping[str, Any],
    pre_live_adjudication: Mapping[str, Any],
    pre_live_adjudication_sha256: str,
) -> dict[str, tuple[str, dict[str, Any]]]:
    bundles = (
        (
            "pre-mutation",
            pre_mutation_receipt,
            pre_mutation_adjudication,
            pre_mutation_adjudication_sha256,
        ),
        (
            "pre-live",
            pre_live_receipt,
            pre_live_adjudication,
            pre_live_adjudication_sha256,
        ),
    )
    for label, receipt, adjudication, adjudication_sha256 in bundles:
        if (
            receipt.get("gate") != label
            or receipt.get("authorization_id") != authorization_id
            or receipt.get("authorization_sha256") != authorization_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", adjudication_sha256)
        ):
            raise AppServerError(f"{label}-steering-binding-invalid")
        if adjudication.get("main_architect_decision") != "go":
            raise AppServerError(f"{label}-adjudication-decision-invalid")

    steering_prepared: dict[str, tuple[str, dict[str, Any]]] = {}
    for label, receipt, adjudication, adjudication_sha256 in bundles:
        phase_nonce = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{campaign_nonce}:{label}:{receipt.get('canonical_receipt_sha256')}",
            )
        )
        kwargs: dict[str, Any] = {
            "phase_nonce": phase_nonce,
            "architect_adjudication_sha256": adjudication_sha256,
            "architect_decision": "go",
        }
        if label == "pre-mutation" and receipt.get("opinion", {}).get("recommendation") == "stop":
            kwargs.update(
                {
                    "allow_resolved_stop": True,
                    "resolved_stop_adjudication": adjudication.get("resolved_stop"),
                    "resolved_stop_post_resolution_commit": repo_head,
                }
            )
        try:
            consume_steering_receipt(
                receipt,
                registry_file,
                dry_run=True,
                **kwargs,
            )
        except NativeCanaryContractError as exc:
            raise AppServerError(f"{label}-steering-not-accepting") from exc
        steering_prepared[label] = (receipt["canonical_receipt_sha256"], kwargs)
    return steering_prepared


class AppServerError(RuntimeError):
    pass


class LivePoolProtectedFault(AppServerError):
    def __init__(self, first_protected_fault: Mapping[str, Any] | None) -> None:
        self.first_protected_fault = (
            dict(first_protected_fault)
            if isinstance(first_protected_fault, Mapping)
            else {
                "code": "unknown",
                "operation": None,
                "observed_callback_latency_ms": None,
                "certified_callback_max_ms": None,
                "latched_state_sequence": 0,
            }
        )
        super().__init__(f"live-pool-protected-fault:{self.first_protected_fault['code']}")


class AppServer:
    """Minimal stdlib JSON-RPC client for one trusted Codex app-server."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            ["codex", "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise AppServerError("app-server-pipes-unavailable")
        self._condition = threading.Condition()
        self._responses: dict[int, dict[str, Any]] = {}
        self._notifications: list[tuple[int, dict[str, Any]]] = []
        self._request_id = 0
        self._reader_error: str | None = None
        self._stderr_line_count = 0
        self.connection_epoch_sha256 = domain_sha256(
            {"epoch": str(uuid.uuid4())}, domain="app-server-stdio-connection-epoch"
        )
        self.rpc_latencies: dict[str, list[float]] = {}
        self.started_threads: dict[str, str | None] = {}
        self.allocation_ledger: NativeLiveAllocationLedgerStore | None = None
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        result, _ = self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "cwo-supervisor-concurrency-canary",
                    "title": "CWO supervisor concurrency canary",
                    "version": "1.0.0",
                },
                "capabilities": {"experimentalApi": True},
            },
            timeout=10,
        )
        if not isinstance(result, Mapping) or not result.get("codexHome"):
            raise AppServerError("app-server-initialize-invalid")
        self.codex_home = Path(str(result["codexHome"])).resolve()
        self.notify("initialized", {})

    def attach_allocation_ledger(self, ledger: NativeLiveAllocationLedgerStore) -> None:
        if self.started_threads or self.allocation_ledger is not None:
            raise AppServerError("allocation-ledger-attach-state-invalid")
        ledger.load()
        self.allocation_ledger = ledger

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for raw in self.process.stdout:
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    with self._condition:
                        self._reader_error = "app-server-non-json-output"
                        self._condition.notify_all()
                    continue
                with self._condition:
                    if isinstance(message.get("id"), int) and (
                        "result" in message or "error" in message
                    ):
                        self._responses[int(message["id"])] = message
                    elif isinstance(message.get("method"), str):
                        self._notifications.append((time.monotonic_ns(), message))
                    self._condition.notify_all()
        finally:
            with self._condition:
                if self.process.poll() is None:
                    self._reader_error = "app-server-output-closed"
                self._condition.notify_all()

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for _line in self.process.stderr:
            self._stderr_line_count += 1

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        payload = {"method": method, "params": dict(params)}
        assert self.process.stdin is not None
        with self._condition:
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()

    def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout: float = 30,
    ) -> tuple[dict[str, Any], float]:
        assert self.process.stdin is not None
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": dict(params)}
            started = time.monotonic_ns()
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            while request_id not in self._responses:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AppServerError(f"app-server-request-timeout:{method}")
                if self.process.poll() is not None:
                    raise AppServerError(f"app-server-exited:{method}:{self.process.returncode}")
                if self._reader_error:
                    raise AppServerError(self._reader_error)
                self._condition.wait(timeout=remaining)
            message = self._responses.pop(request_id)
        latency_ms = (time.monotonic_ns() - started) / 1_000_000
        self.rpc_latencies.setdefault(method, []).append(latency_ms)
        if "error" in message:
            error = message.get("error") if isinstance(message.get("error"), Mapping) else {}
            code = error.get("code", "unknown")
            raise AppServerError(f"app-server-request-failed:{method}:{code}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise AppServerError(f"app-server-result-invalid:{method}")
        return result, latency_ms

    def model_discovery(self) -> dict[str, Any]:
        result, latency = self.request("model/list", {"includeHidden": True})
        models = result.get("data")
        if not isinstance(models, list):
            raise AppServerError("model-list-data-invalid")
        matches = [item for item in models if isinstance(item, Mapping) and item.get("id") == EXACT_MODEL]
        if len(matches) != 1 or matches[0].get("model") != EXACT_MODEL:
            raise AppServerError("exact-spark-model-unavailable")
        return {
            "id": matches[0]["id"],
            "model": matches[0]["model"],
            "display_name": matches[0].get("displayName"),
            "latency_ms": round(latency, 3),
        }

    def start_thread(
        self,
        cwd: Path,
        *,
        mutable: bool,
        role: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        allocation_intent_id: str | None = None
        if self.allocation_ledger is not None:
            if role not in EXPECTED_ROLES:
                raise AppServerError("allocation-ledger-role-required")
            allocation_intent_id = self.allocation_ledger.allocation_intent(str(role))
        result, latency = self.request(
            "thread/start",
            {
                "model": EXACT_MODEL,
                "allowProviderModelFallback": False,
                "cwd": str(cwd.resolve()),
                "runtimeWorkspaceRoots": [str(cwd.resolve())],
                "approvalPolicy": "never",
                "sandbox": "workspace-write" if mutable else "read-only",
                "ephemeral": False,
                "historyMode": "legacy",
                "developerInstructions": (
                    "This is a bounded CWO live canary. Do not spawn subagents, use network access, "
                    "or access paths outside the supplied workspace. Follow the user task exactly."
                ),
            },
            timeout=30,
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or not thread.get("id"):
            raise AppServerError("thread-start-response-invalid")
        thread_id = str(thread["id"])
        self.started_threads[thread_id] = None
        if self.allocation_ledger is not None and allocation_intent_id is not None:
            self.allocation_ledger.bind_thread(allocation_intent_id, thread_id)
        if result.get("model") != EXACT_MODEL:
            raise AppServerError("thread-start-model-mismatch")
        return dict(result), latency

    def read_thread(self, thread_id: str) -> tuple[dict[str, Any], float]:
        result, latency = self.request(
            "thread/read", {"threadId": thread_id, "includeTurns": True}, timeout=15
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or thread.get("id") != thread_id:
            raise AppServerError("thread-read-response-invalid")
        return dict(thread), latency

    def start_turn(self, thread_id: str, prompt: str) -> tuple[dict[str, Any], float]:
        turn_intent_id: str | None = None
        if self.allocation_ledger is not None:
            turn_intent_id = self.allocation_ledger.turn_intent(thread_id)
        result, latency = self.request(
            "turn/start",
            {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt, "text_elements": []}],
                "model": EXACT_MODEL,
                "effort": "low",
                "clientUserMessageId": str(uuid.uuid4()),
                "responsesapiClientMetadata": {
                    "cwo_bead": "complex-work-orchestration-18w.6",
                    "cwo_control_turn": CONTROL_TURN_ID,
                },
            },
            timeout=30,
        )
        turn = result.get("turn")
        if not isinstance(turn, Mapping) or not turn.get("id"):
            raise AppServerError("turn-start-response-invalid")
        turn_id = str(turn["id"])
        self.started_threads[thread_id] = turn_id
        if self.allocation_ledger is not None and turn_intent_id is not None:
            self.allocation_ledger.bind_turn(thread_id, turn_intent_id, turn_id)
        return dict(turn), latency

    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        _result, latency = self.request(
            "turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15
        )
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "interrupt-observed", "interrupt-request-accepted"
            )
        return latency

    def archive_thread(self, thread_id: str) -> float:
        _result, latency = self.request("thread/archive", {"threadId": thread_id}, timeout=15)
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "archive-observed", "archive-request-accepted"
            )
        return latency

    def notifications(self, thread_id: str, method: str | None = None) -> list[dict[str, Any]]:
        with self._condition:
            values = []
            for _timestamp, message in self._notifications:
                params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                if params.get("threadId") != thread_id:
                    continue
                if method is not None and message.get("method") != method:
                    continue
                values.append(message)
            return values

    def notification_cursor(self) -> int:
        """Return the current connection-local receive sequence."""

        with self._condition:
            return len(self._notifications)

    def notification_events(
        self,
        thread_id: str,
        turn_id: str,
        *,
        after_sequence: int,
    ) -> list[dict[str, Any]]:
        """Snapshot trusted stdio notifications with connection-local provenance."""

        with self._condition:
            values: list[dict[str, Any]] = []
            for sequence, (received_ns, message) in enumerate(self._notifications, 1):
                if sequence <= after_sequence:
                    continue
                params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
                    continue
                values.append(
                    {
                        "connection_epoch_sha256": self.connection_epoch_sha256,
                        "sequence": sequence,
                        "received_monotonic_ns": received_ns,
                        "method": message.get("method"),
                        "params": dict(params),
                    }
                )
            return values

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def turn_from_thread(thread: Mapping[str, Any], turn_id: str | None) -> Mapping[str, Any] | None:
    turns = thread.get("turns")
    if not isinstance(turns, list):
        return None
    for item in turns:
        if isinstance(item, Mapping) and item.get("id") == turn_id:
            return item
    return None


def turn_status(thread: Mapping[str, Any], turn_id: str | None) -> str | None:
    turn = turn_from_thread(thread, turn_id)
    return str(turn.get("status")) if isinstance(turn, Mapping) and turn.get("status") else None


def turn_items(thread: Mapping[str, Any], turn_id: str | None) -> list[Mapping[str, Any]]:
    turn = turn_from_thread(thread, turn_id)
    items = turn.get("items") if isinstance(turn, Mapping) else None
    return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []


def final_message_hash_and_match(
    thread: Mapping[str, Any], turn_id: str | None, expected_token: str
) -> tuple[str | None, bool]:
    messages = [
        str(item.get("text", ""))
        for item in turn_items(thread, turn_id)
        if item.get("type") == "agentMessage" and item.get("phase") in {"finalAnswer", "final_answer", None}
    ]
    if not messages:
        return None, False
    final = messages[-1]
    return sha256_text(final), final.strip() == expected_token


def session_boundary_summary(
    codex_home: Path,
    thread_id: str,
    _reported: str | None,
    *,
    turn_id: str | None = None,
    baseline: Mapping[str, Any] | None = None,
    allow_unmaterialized: bool = False,
    expected_source_identity_sha256: str | None = None,
) -> dict[str, Any]:
    try:
        located, boundary, records = capture_unique_boundary(
            codex_home,
            thread_id,
            baseline=baseline,
        )
        if (
            expected_source_identity_sha256 is not None
            and located.source_identity_sha256 != expected_source_identity_sha256
        ):
            raise NativeSessionBoundaryError(
                "trusted session source identity changed after materialization"
            )
    except NativeSessionBoundaryError as exc:
        boundary_error = str(exc)
        if not allow_unmaterialized or boundary_error not in {
            "trusted session file is missing",
            "session file has no complete records",
        }:
            raise AppServerError(f"session-boundary-invalid:{exc}") from exc
        return {
            "available": False,
            "record_count": 0,
            "byte_offset": 0,
            "boundary_sha256": None,
            "token_snapshot": None,
            "source_identity_sha256": None,
            "trailing_partial": False,
            "attested_models": [],
            "attested_efforts": [],
            "compactions": 0,
            "reroutes": 0,
            "observation_type": "unmaterialized-nonattesting",
            "terminal_event": None,
        }
    models: list[str] = []
    efforts: list[str] = []
    compactions = 0
    reroutes = 0
    terminal_event = None
    if turn_id is not None:
        try:
            terminal_event = trusted_terminal_event(records, turn_id=turn_id)
        except NativeSessionBoundaryError as exc:
            raise AppServerError(f"session-terminal-grammar-invalid:{exc}") from exc
    for record in records:
        record_type = record.get("type")
        payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
        if record_type == "turn_context":
            if isinstance(payload.get("model"), str):
                models.append(str(payload["model"]))
            effort = payload.get("effort") or payload.get("reasoning_effort")
            if isinstance(effort, str):
                efforts.append(effort)
        payload_type = str(payload.get("type", ""))
        marker = f"{record_type}:{payload_type}".lower()
        if "compact" in marker:
            compactions += 1
        if "rerout" in marker:
            reroutes += 1
    return {
        "available": True,
        "record_count": boundary["record_count"],
        "byte_offset": boundary["byte_offset"],
        "boundary_sha256": boundary["boundary_sha256"],
        "token_snapshot": boundary.get("token_snapshot"),
        "source_identity_sha256": located.source_identity_sha256,
        "trailing_partial": False,
        "attested_models": sorted(set(models)),
        "attested_efforts": sorted(set(efforts)),
        "compactions": compactions,
        "reroutes": reroutes,
        "observation_type": "trusted-complete-boundary",
        "terminal_event": terminal_event,
    }


class LiveThreadAdapter:
    def __init__(
        self,
        server: AppServer,
        thread_response: Mapping[str, Any],
        *,
        prompt: str,
        expected_token: str,
        worktree: Path,
        mutable: bool,
        expected_mutation: str | None,
        force_interrupt_after_checks: int | None = None,
        record_dir: Path,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.server = server
        self.thread_response = dict(thread_response)
        self.thread = dict(thread_response["thread"])
        self.thread_id = str(self.thread["id"])
        self.reported_session_path = self.thread.get("path")
        self.prompt = prompt
        self.expected_token = expected_token
        self.worktree = worktree
        self.mutable = mutable
        self.expected_mutation = expected_mutation
        self.force_interrupt_after_checks = force_interrupt_after_checks
        self.record_dir = record_dir
        self.turn_id: str | None = None
        self.send_started_ns: int | None = None
        self.last_thread: dict[str, Any] = dict(self.thread)
        self.check_count = 0
        self.interrupted = False
        self.archived = False
        self._boundary_phase = "pre-dispatch"
        self._boundary_lock = threading.RLock()
        self._monotonic_ns = monotonic_ns
        self._materialization_deadline_ns: int | None = None
        self._projection_started_ns: int | None = None
        self._session_boundary_baseline: dict[str, Any] | None = None
        self._session_source_identity_sha256: str | None = None
        self.callback_latencies: dict[str, list[float]] = {}
        self._evidence_sequence = 0

    def _timed(self, name: str, action: Callable[[], Any]) -> Any:
        started = time.monotonic_ns()
        try:
            return action()
        finally:
            elapsed = (time.monotonic_ns() - started) / 1_000_000
            self.callback_latencies.setdefault(name, []).append(elapsed)

    def arm(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if self.thread_response.get("model") != EXACT_MODEL:
                raise AppServerError("prearmed-thread-model-mismatch")
            if self.thread.get("id") != self.thread_id or self.thread.get("turns"):
                raise AppServerError("prearmed-thread-is-not-fresh")
            return {"ack": "armed"}

        return self._timed("arm", action)

    def send_input(self, *, message: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if message != self.prompt:
                raise AppServerError("turn-prompt-binding-mismatch")
            with self._boundary_lock:
                # Revoke the pre-dispatch allowance before the RPC. Failed or
                # ambiguous submission can never recover it from a missing id.
                self._boundary_phase = "dispatch-attempted"
                turn, _latency = self.server.start_turn(self.thread_id, message)
                returned_ns = self._monotonic_ns()
                turn_id = turn.get("id") if isinstance(turn, Mapping) else None
                if not isinstance(turn_id, str) or not turn_id:
                    raise AppServerError("turn-start-response-invalid")
                if self.server.started_threads.get(self.thread_id) != turn_id:
                    raise AppServerError("trusted-turn-start-binding-mismatch")
                self.turn_id = turn_id
                self.send_started_ns = returned_ns
                self._materialization_deadline_ns = returned_ns + (
                    POST_SUBMISSION_MATERIALIZATION_GRACE_MS * 1_000_000
                )
                self._boundary_phase = "submission-acknowledged-awaiting-materialization"
                return {"submission_id": self.turn_id}

        return self._timed("send_input", action)

    def mark_dispatched(self, *, submission_id: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if submission_id != self.turn_id:
                raise AppServerError("submission-id-binding-mismatch")
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-dispatch.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "prompt_sha256": sha256_text(self.prompt),
                    "control_turn_id": CONTROL_TURN_ID,
                },
            )
            return {"ack": "dispatched"}

        return self._timed("mark_dispatched", action)

    def check(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self.check_count += 1
            thread, _latency = self.server.read_thread(self.thread_id)
            self.last_thread = thread
            self.reported_session_path = thread.get("path") or self.reported_session_path
            boundary = self._capture_trusted_boundary(allow_pending=True)
            status = turn_status(self.last_thread, self.turn_id)
            terminal_event = boundary.get("terminal_event")
            durable_status = (
                terminal_event.get("status")
                if isinstance(terminal_event, Mapping)
                else None
            )
            if durable_status == "completed":
                _message_hash, matches = final_message_hash_and_match(
                    self.last_thread, self.turn_id, self.expected_token
                )
                return {"decision": "complete" if matches else "control-lost"}
            if durable_status == "interrupted":
                return {"decision": "interrupt"}
            if durable_status == "failed":
                return {"decision": "control-lost"}
            now_ns = self._monotonic_ns()
            if status in {"completed", "failed", "interrupted"}:
                if self._projection_started_ns is None:
                    self._projection_started_ns = now_ns
                elif (
                    now_ns - self._projection_started_ns
                    > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
                ):
                    return {"decision": "control-lost"}
            elif status in {"inProgress", "in_progress", "running"}:
                if boundary.get("available") is True:
                    self._projection_started_ns = None
            if (
                self.force_interrupt_after_checks is not None
                and self.check_count >= self.force_interrupt_after_checks
            ):
                return {"decision": "interrupt"}
            if status in {
                "inProgress",
                "in_progress",
                "running",
                "completed",
                "failed",
                "interrupted",
                None,
            }:
                return {"decision": "continue"}
            return {"decision": "control-lost"}

        return self._timed("check", action)

    def interrupt(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if self.turn_id is None:
                    raise AppServerError("interrupt-turn-id-missing")
                # Interrupt wins locally before the control RPC is attempted;
                # unavailable telemetry can never be accepted after this point.
                self._boundary_phase = "interrupt-requested"
                self.server.interrupt_turn(self.thread_id, self.turn_id)
                self.interrupted = True
                return {"ack": "interrupt-requested"}

        return self._timed("interrupt", action)

    def finalize(self, *, control_action: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-finalize-{control_action}.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "control_action": control_action,
                    "control_turn_id": CONTROL_TURN_ID,
                },
            )
            return {"ack": control_action}

        return self._timed("finalize", action)

    def close(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                self._boundary_phase = "closing"
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = thread.get("path") or self.reported_session_path
                boundary = self._capture_trusted_boundary(allow_pending=True)
                terminal_event = boundary.get("terminal_event")
                durable_status = (
                    terminal_event.get("status")
                    if isinstance(terminal_event, Mapping)
                    else None
                )
                if boundary.get("available") is True and durable_status not in {
                    "completed",
                    "interrupted",
                    "failed",
                }:
                    raise AppServerError(
                        f"close-before-durable-terminal:{durable_status}"
                    )
                if boundary.get("available") is not True and not self.interrupted:
                    raise AppServerError("close-before-durable-terminal:unavailable")
                self.server.archive_thread(self.thread_id)
                self.archived = True
                return {"ack": "closed"}

        return self._timed("close", action)

    @staticmethod
    def sleep(*, seconds: float) -> None:
        time.sleep(seconds)

    def callbacks(self) -> dict[str, Callable[..., Any]]:
        return {
            "arm": self.arm,
            "send_input": self.send_input,
            "mark_dispatched": self.mark_dispatched,
            "check": self.check,
            "interrupt": self.interrupt,
            "close": self.close,
            "finalize": self.finalize,
            "sleep": self.sleep,
        }

    def _workspace_mutations(self) -> list[str]:
        output = run_git(self.worktree, "status", "--porcelain=v1", "--untracked-files=all")
        values = []
        for line in output.splitlines():
            if len(line) >= 4:
                values.append(line[3:].strip())
        return sorted(set(values))

    def _pending_window_is_open_locked(self) -> None:
        if self._boundary_phase != "submission-acknowledged-awaiting-materialization":
            raise AppServerError("post-submission-materialization-phase-invalid")
        if not self.turn_id or self.server.started_threads.get(self.thread_id) != self.turn_id:
            raise AppServerError("trusted-turn-start-binding-mismatch")
        if self._materialization_deadline_ns is None:
            raise AppServerError("post-submission-materialization-deadline-missing")
        if self._monotonic_ns() >= self._materialization_deadline_ns:
            raise AppServerError("post-submission-materialization-deadline-exceeded")

    def _record_complete_boundary_locked(self, boundary: Mapping[str, Any]) -> dict[str, Any]:
        if self._boundary_phase == "submission-acknowledged-awaiting-materialization":
            self._pending_window_is_open_locked()
            self._boundary_phase = "materialized"
        self._session_boundary_baseline = {
            "record_count": boundary.get("record_count"),
            "byte_offset": boundary.get("byte_offset"),
            "boundary_sha256": boundary.get("boundary_sha256"),
            "token_snapshot": boundary.get("token_snapshot"),
        }
        source_identity = boundary.get("source_identity_sha256")
        if not isinstance(source_identity, str) or not source_identity:
            raise AppServerError("trusted-session-source-identity-missing")
        if (
            self._session_source_identity_sha256 is not None
            and source_identity != self._session_source_identity_sha256
        ):
            raise AppServerError("trusted-session-source-identity-changed")
        self._session_source_identity_sha256 = source_identity
        return dict(boundary)

    def _fresh_nonterminal_thread_locked(self) -> None:
        self._pending_window_is_open_locked()
        thread, _latency = self.server.read_thread(self.thread_id)
        if thread.get("id") != self.thread_id:
            raise AppServerError("post-submission-thread-read-identity-mismatch")
        self.last_thread = thread
        self.reported_session_path = thread.get("path") or self.reported_session_path
        self._pending_window_is_open_locked()

    def _capture_trusted_boundary(self, *, allow_pending: bool) -> dict[str, Any]:
        with self._boundary_lock:
            pending_phase = self._boundary_phase in {
                "pre-dispatch",
                "submission-acknowledged-awaiting-materialization",
            }
            containment_phase = self._boundary_phase in {
                "interrupt-requested",
                "closing",
            }
            allow_unmaterialized = (
                (allow_pending and pending_phase or containment_phase)
                and self._session_boundary_baseline is None
            )
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                None,
                turn_id=self.turn_id,
                baseline=self._session_boundary_baseline,
                allow_unmaterialized=allow_unmaterialized,
                expected_source_identity_sha256=self._session_source_identity_sha256,
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            if self._boundary_phase == "pre-dispatch":
                boundary["observation_type"] = (
                    "pre-dispatch-unmaterialized-nonattesting-nonaccepting"
                )
                return boundary
            if containment_phase:
                boundary["observation_type"] = (
                    "containment-unmaterialized-nonattesting-rejected"
                )
                return boundary

            # The trusted file was absent or exactly zero bytes. Re-read the
            # control plane after that observation, retry the boundary once,
            # then re-read status immediately before emitting a pending marker.
            self._fresh_nonterminal_thread_locked()
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                None,
                turn_id=self.turn_id,
                baseline=None,
                allow_unmaterialized=True,
                expected_source_identity_sha256=None,
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            self._fresh_nonterminal_thread_locked()
            boundary["observation_type"] = (
                "post-submission-unmaterialized-nonattesting-nonaccepting"
            )
            return boundary

    def _trusted_summary(self, *, allow_pending: bool = True) -> dict[str, Any]:
        boundary = self._capture_trusted_boundary(allow_pending=allow_pending)
        items = turn_items(self.last_thread, self.turn_id)
        item_types = [str(item.get("type")) for item in items if item.get("type")]
        tool_calls = sum(item_type in OPERATIVE_ITEM_TYPES for item_type in item_types)
        compactions = item_types.count("contextCompaction") + len(
            self.server.notifications(self.thread_id, "thread/compacted")
        )
        final_hash, final_matches = final_message_hash_and_match(
            self.last_thread, self.turn_id, self.expected_token
        )
        reroutes = self.server.notifications(self.thread_id, "model/rerouted")
        token_events = self.server.notifications(self.thread_id, "thread/tokenUsage/updated")
        token_total = None
        if token_events:
            params = token_events[-1].get("params", {})
            token_usage = params.get("tokenUsage", {}) if isinstance(params, Mapping) else {}
            total = token_usage.get("total", {}) if isinstance(token_usage, Mapping) else {}
            if isinstance(total, Mapping):
                token_total = {
                    "input": total.get("inputTokens"),
                    "cached_input": total.get("cachedInputTokens"),
                    "output": total.get("outputTokens"),
                    "reasoning": total.get("reasoningOutputTokens"),
                    "total": total.get("totalTokens"),
                }
        models = boundary.get("attested_models", [])
        efforts = boundary.get("attested_efforts", [])
        model_exact = (
            boundary.get("available") is True
            and models == [EXACT_MODEL]
            and efforts == ["low"]
        )
        projected_status = turn_status(self.last_thread, self.turn_id)
        terminal_event = boundary.get("terminal_event")
        durable_status = (
            terminal_event.get("status")
            if isinstance(terminal_event, Mapping)
            else None
        )
        return {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "thread_start_model": self.thread_response.get("model"),
            "thread_start_model_provider": self.thread_response.get("modelProvider"),
            "turn_status": durable_status or projected_status,
            "projected_turn_status": projected_status,
            "durable_terminal_event": terminal_event,
            "session_boundary": boundary,
            "model_exact": model_exact,
            "reroute_count": len(reroutes),
            "compactions": compactions,
            "tool_calls": tool_calls,
            "item_types": sorted(set(item_types)),
            "token_telemetry": {
                "availability": "available" if token_total is not None else "unavailable",
                "total": token_total,
            },
            "final_response_sha256": final_hash,
            "expected_final_token_observed": final_matches,
            "workspace_mutations": self._workspace_mutations(),
            "interrupted": self.interrupted,
            "archived": self.archived,
        }

    def evidence(self) -> dict[str, Any]:
        self._evidence_sequence += 1
        summary = self._trusted_summary()
        status = summary["turn_status"]
        terminal = status in {"completed", "interrupted", "failed"}
        reasons: list[str] = []
        if terminal and not summary["model_exact"]:
            reasons.append("trusted-model-attestation-mismatch")
        if (
            summary["session_boundary"].get("observation_type")
            == "containment-unmaterialized-nonattesting-rejected"
        ):
            reasons.append("containment-unmaterialized-nonattesting-rejected")
        if summary["reroute_count"]:
            reasons.append("model-reroute-observed")
        if summary["compactions"]:
            reasons.append("compaction-observed")
        if terminal and summary["session_boundary"].get("trailing_partial"):
            reasons.append("terminal-session-boundary-partial")
        if status == "completed" and not summary["expected_final_token_observed"]:
            reasons.append("invalid-final-response")
        mutations = summary["workspace_mutations"]
        if self.mutable:
            if any(path != self.expected_mutation for path in mutations):
                reasons.append("mutable-workspace-attribution-mismatch")
        elif mutations:
            reasons.append("read-only-workspace-mutation")
        runtime = 0
        if self.send_started_ns is not None:
            runtime = int(max(0, time.monotonic_ns() - self.send_started_ns) / 1_000_000_000)
        usage = {
            "tool_calls": int(summary["tool_calls"]),
            "runtime_seconds": runtime,
            "compactions": int(summary["compactions"]),
            "full_suite_runs": 0,
            "mutations": len(mutations),
            "tokens": zero_token_usage("pool-v1-token-ingest-not-bound"),
        }
        state_payload = {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "status": status,
            "boundary_sha256": summary["session_boundary"].get("boundary_sha256"),
            "boundary_observation": summary["session_boundary"].get("observation_type"),
            "tool_calls": usage["tool_calls"],
            "runtime_seconds": usage["runtime_seconds"],
            "mutations": usage["mutations"],
            "compactions": usage["compactions"],
            "evidence_sequence": self._evidence_sequence,
        }
        if (
            summary["session_boundary"].get("observation_type")
            == "containment-unmaterialized-nonattesting-rejected"
        ):
            session_disposition = "quarantined"
            artifact_disposition = "rejected"
        elif summary["session_boundary"].get("available") is not True:
            session_disposition = "accepted-with-warning"
            artifact_disposition = "independent-validation-required"
        elif self.interrupted:
            session_disposition = "accepted-with-warning" if not reasons else "quarantined"
            artifact_disposition = "rejected"
        elif status == "completed" and not reasons:
            session_disposition = "accepted"
            artifact_disposition = "accepted"
        elif terminal:
            session_disposition = "quarantined"
            artifact_disposition = "rejected"
        else:
            session_disposition = "accepted"
            artifact_disposition = "accepted"
        return {
            "state_sha256": canonical_sha256(state_payload),
            "usage": usage,
            "protected_fault": bool(reasons),
            "control_loss": status == "failed" or "trusted-model-attestation-mismatch" in reasons,
            "reasons": reasons,
            "session_disposition": session_disposition,
            "artifact_disposition": artifact_disposition,
        }

    def final_summary(self) -> dict[str, Any]:
        summary = self._trusted_summary(allow_pending=False)
        summary["callback_stats"] = {
            name: stats(values) for name, values in sorted(self.callback_latencies.items())
        }
        summary["prompt_sha256"] = sha256_text(self.prompt)
        return summary


def guarded_measure(
    samples: dict[str, list[float]],
    name: str,
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.20,
) -> Any:
    started = time.monotonic_ns()
    result = action()
    time.sleep(guard_seconds)
    samples.setdefault(name, []).append((time.monotonic_ns() - started) / 1_000_000)
    return result


def pool_sleep(*, seconds: float) -> None:
    """Adapt the coordinator's keyword callback to positional-only time.sleep."""

    time.sleep(seconds)


def calibration(
    server: AppServer,
    cwd: Path,
    record_dir: Path,
    owner: Mapping[str, Any],
    *,
    run_nonce: str,
    phase_nonce: str,
    materialization_timeout_seconds: float = 10.0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    samples: dict[str, list[float]] = {}
    result, preallocation_latency = server.start_thread(
        cwd, mutable=False, role="capability-calibration"
    )
    thread_id = str(result["thread"]["id"])
    reported_path = result["thread"].get("path")
    guarded_measure(
        samples,
        "arm",
        lambda: (
            result.get("model") == EXACT_MODEL
            and result.get("thread", {}).get("id") == thread_id
            and not result.get("thread", {}).get("turns")
        )
        or (_ for _ in ()).throw(AppServerError("prearmed-thread-binding-invalid")),
        guard_seconds=0.0,
    )
    prompt = (
        "Use the exec_command tool exactly once to run `sleep 20`. After it finishes, return "
        "exactly CAPABILITY_LONG_DONE. Do not use any other tool."
    )
    notification_floor = server.notification_cursor()
    turn = guarded_measure(
        samples,
        "send_input",
        lambda: server.start_turn(thread_id, prompt),
        guard_seconds=0.0,
    )[0]
    turn_id = str(turn["id"])
    attempt_nonce = str(uuid.uuid4())
    guarded_measure(
        samples,
        "mark_dispatched",
        lambda: write_private_artifact(
            record_dir / "calibration-mark.json",
            {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "control_turn_id": CONTROL_TURN_ID,
                "attempt_nonce": attempt_nonce,
                "phase_nonce": phase_nonce,
            },
        ),
        guard_seconds=0.0,
    )

    strict_baseline = {
        "record_count": 0,
        "byte_offset": 0,
        "boundary_sha256": sha256_bytes(b""),
        "token_snapshot": None,
    }
    trusted_source_identity: str | None = None
    observed_prefix: dict[str, Any] = dict(strict_baseline)
    control_started_ns = time.monotonic_ns()
    control_observations: list[dict[str, Any]] = []
    projection_started_ns: int | None = None

    def public_boundary(value: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "record_count": int(value["record_count"]),
            "byte_offset": int(value["byte_offset"]),
            "boundary_sha256": str(value["boundary_sha256"]),
            "invalid_record_count": 0,
            "trailing_partial": False,
        }

    def normalize_projected_status(value: str | None) -> str:
        if value in {"inProgress", "in_progress", "running"}:
            return "active"
        if value in {"completed", "failed", "interrupted"}:
            return str(value)
        if value is None:
            return "missing"
        return "unknown"

    def append_control_observation(
        *,
        phase: str,
        projected_status: str,
        durable_status: str | None,
        source_identity_sha256: str | None,
        previous_boundary: Mapping[str, Any],
        boundary: Mapping[str, Any],
        decision: str,
    ) -> None:
        if len(control_observations) >= CONTROL_OBSERVATION_MAX:
            raise AppServerError("capability-control-observation-limit-exceeded")
        control_observations.append(
            {
                "ordinal": len(control_observations),
                "elapsed_monotonic_ms": round(
                    (time.monotonic_ns() - control_started_ns) / 1_000_000, 3
                ),
                "phase": phase,
                "projected_status": projected_status,
                "durable_status": durable_status,
                "source_identity_sha256": source_identity_sha256,
                "previous_boundary_sha256": str(
                    previous_boundary["boundary_sha256"]
                ),
                "boundary": public_boundary(boundary),
                "decision": decision,
            }
        )

    def record_nonterminal_projection(
        *,
        phase: str,
        projected_status: str,
        boundary_available: bool,
        ready: bool,
        source_identity_sha256: str | None,
        previous_boundary: Mapping[str, Any],
        boundary: Mapping[str, Any],
    ) -> bool:
        nonlocal projection_started_ns
        now_ns = time.monotonic_ns()
        if projected_status in {"completed", "failed", "interrupted"}:
            if projection_started_ns is None:
                projection_started_ns = now_ns
            append_control_observation(
                phase=phase,
                projected_status=projected_status,
                durable_status=None,
                source_identity_sha256=source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=boundary,
                decision="continue-provisional",
            )
            if (
                now_ns - projection_started_ns
                > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
            ):
                raise AppServerError(
                    f"capability-uncorroborated-terminal-projection:{projected_status}"
                )
            return False
        if boundary_available and projected_status == "active":
            projection_started_ns = None
        elif (
            projection_started_ns is not None
            and now_ns - projection_started_ns
            > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
        ):
            raise AppServerError("capability-uncorroborated-terminal-projection:unresolved")
        decision = (
            "ready"
            if ready and projected_status == "active"
            else "continue-active"
            if projected_status == "active"
            else "continue-pending"
        )
        append_control_observation(
            phase=phase,
            projected_status=projected_status,
            durable_status=None,
            source_identity_sha256=source_identity_sha256,
            previous_boundary=previous_boundary,
            boundary=boundary,
            decision=decision,
        )
        return ready and projected_status == "active"

    def observe(
        phase: str = "materialization",
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        thread, _latency = server.read_thread(thread_id)
        nonlocal trusted_source_identity, observed_prefix
        projected_status = normalize_projected_status(turn_status(thread, turn_id))
        previous_boundary = dict(observed_prefix)
        try:
            located, boundary, records = capture_unique_boundary(
                server.codex_home,
                thread_id,
                baseline=observed_prefix,
            )
        except NativeSessionBoundaryError as exc:
            if str(exc) == "trusted session file is missing":
                if trusted_source_identity is not None:
                    raise AppServerError("capability-pinned-session-source-missing") from exc
                record_nonterminal_projection(
                    phase=phase,
                    projected_status=projected_status,
                    boundary_available=False,
                    ready=False,
                    source_identity_sha256=None,
                    previous_boundary=previous_boundary,
                    boundary=observed_prefix,
                )
                return thread, None
            raise AppServerError(f"capability-session-boundary-invalid:{exc}") from exc
        if trusted_source_identity is None:
            trusted_source_identity = located.source_identity_sha256
        elif trusted_source_identity != located.source_identity_sha256:
            raise AppServerError("capability-session-source-identity-changed")
        observed_prefix = dict(boundary)
        try:
            terminal_event = trusted_terminal_event(records, turn_id=turn_id)
        except NativeSessionBoundaryError as exc:
            raise AppServerError(f"capability-terminal-grammar-invalid:{exc}") from exc
        contexts = [
            (index, record["payload"])
            for index, record in enumerate(records)
            if record.get("type") == "turn_context"
            and isinstance(record.get("payload"), Mapping)
            and (record["payload"].get("turn_id") or record["payload"].get("turnId")) == turn_id
        ]
        if contexts and any(
            context.get("model") != EXACT_MODEL
            or (context.get("effort") or context.get("reasoning_effort")) != "low"
            for _index, context in contexts
        ):
            raise AppServerError("capability-trusted-model-effort-mismatch")
        if len(contexts) > 1:
            raise AppServerError("capability-current-turn-context-not-singular")
        markers = telemetry_markers(records, turn_id=turn_id)
        if markers["compaction_indices"] or markers["reroute_indices"]:
            raise AppServerError("capability-session-containment-failed")
        if terminal_event is not None:
            raise AppServerError(
                "capability-terminal-event-before-deliberate-interrupt:"
                + str(terminal_event["status"])
            )

        def finish(
            observation: dict[str, Any] | None,
        ) -> tuple[dict[str, Any], dict[str, Any] | None]:
            usable = record_nonterminal_projection(
                phase=phase,
                projected_status=projected_status,
                boundary_available=True,
                ready=observation is not None,
                source_identity_sha256=located.source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=boundary,
            )
            return thread, observation if usable else None
        events = server.notification_events(
            thread_id,
            turn_id,
            after_sequence=notification_floor,
        )
        started_commands = []
        completed_commands = []
        for event in events:
            params = event["params"]
            item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
            if item.get("type") != "commandExecution":
                continue
            if event.get("method") == "item/started":
                started_commands.append((event, item))
            elif event.get("method") == "item/completed":
                completed_commands.append((event, item))
        if len(started_commands) > 1:
            raise AppServerError("capability-command-start-not-singular")
        if completed_commands:
            raise AppServerError("capability-command-completed-before-interrupt")
        if not contexts or not started_commands:
            return finish(None)
        context_index, _context = trusted_turn_context(
            records,
            turn_id=turn_id,
            model=EXACT_MODEL,
            effort="low",
        )
        start_event, command = started_commands[0]
        if start_event.get("connection_epoch_sha256") != server.connection_epoch_sha256:
            raise AppServerError("capability-notification-connection-epoch-mismatch")
        started_at_ms = start_event["params"].get("startedAtMs")
        if (
            isinstance(started_at_ms, bool)
            or not isinstance(started_at_ms, int)
            or started_at_ms < 0
        ):
            raise AppServerError("capability-command-start-time-invalid")
        item_id = command.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise AppServerError("capability-command-item-identity-invalid")
        if "source" not in command:
            raise AppServerError("capability-command-source-missing")
        if command.get("source") != "unifiedExecStartup":
            raise AppServerError("capability-command-source-invalid")
        if command.get("status") in {"completed", "failed", "declined"}:
            raise AppServerError(
                f"capability-command-terminal-before-interrupt:{command.get('status')}"
            )
        if command.get("status") != "inProgress":
            return finish(None)
        function_calls: list[tuple[int, Mapping[str, Any]]] = []
        function_outputs: list[tuple[int, Mapping[str, Any]]] = []
        competing_calls: list[int] = []
        for index, record in enumerate(records[context_index + 1 :], context_index + 1):
            if record.get("type") != "response_item" or not isinstance(
                record.get("payload"), Mapping
            ):
                continue
            payload = record["payload"]
            if payload.get("type") in {"function_call", "functionCall"}:
                if payload.get("name") == "exec_command":
                    function_calls.append((index, payload))
                else:
                    competing_calls.append(index)
            elif payload.get("type") in {"function_call_output", "functionCallOutput"}:
                function_outputs.append((index, payload))
        if competing_calls or len(function_calls) > 1:
            raise AppServerError("capability-function-call-not-singular")
        if function_outputs:
            raise AppServerError("capability-function-output-before-interrupt")
        if not function_calls:
            return finish(None)
        function_call_index, function_call = function_calls[0]
        call_id = function_call.get("call_id") or function_call.get("callId")
        if not isinstance(call_id, str) or not call_id:
            raise AppServerError("capability-function-call-identity-invalid")
        arguments = function_call.get("arguments")
        if not isinstance(arguments, str):
            raise AppServerError("capability-function-call-arguments-invalid")
        try:
            parsed_arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise AppServerError("capability-function-call-arguments-invalid") from exc
        if not isinstance(parsed_arguments, Mapping) or not isinstance(
            parsed_arguments.get("cmd"), str
        ):
            raise AppServerError("capability-function-call-command-missing")
        if sha256_text(str(parsed_arguments["cmd"])) != sha256_text("sleep 20"):
            raise AppServerError("capability-function-call-command-digest-mismatch")
        try:
            rendered_command_sha256 = validate_capability_rendered_command(
                command.get("command"), raw_command=str(parsed_arguments["cmd"])
            )
        except NativeCanaryContractError as exc:
            raise AppServerError(f"capability-{exc}") from exc
        command_cwd = command.get("cwd")
        if not isinstance(command_cwd, str) or not command_cwd:
            raise AppServerError("capability-notification-workspace-missing")
        try:
            notification_workspace = Path(command_cwd).resolve(strict=True)
            expected_workspace = cwd.resolve(strict=True)
        except OSError as exc:
            raise AppServerError("capability-notification-workspace-unresolvable") from exc
        if notification_workspace != expected_workspace:
            raise AppServerError("capability-notification-workspace-mismatch")
        command_item_id_sha256 = domain_sha256(
            {"item_id": item_id}, domain="app-server-command-item-id"
        )
        function_call_id_sha256 = domain_sha256(
            {"call_id": call_id}, domain="session-exec-command-call-id"
        )
        raw_command_sha256 = sha256_text(str(parsed_arguments["cmd"]))
        execution_correlation_sha256 = materialization_execution_correlation(
            connection_epoch_sha256=str(start_event["connection_epoch_sha256"]),
            session_id=thread_id,
            thread_id=thread_id,
            turn_id=turn_id,
            command_item_id_sha256=command_item_id_sha256,
            function_call_id_sha256=function_call_id_sha256,
            notification_sequence=int(start_event["sequence"]),
            notification_received_monotonic_ns=int(
                start_event["received_monotonic_ns"]
            ),
            notification_started_at_ms=started_at_ms,
            turn_context_record_index=context_index,
            function_call_record_index=function_call_index,
            rendered_command_sha256=rendered_command_sha256,
            raw_command_sha256=raw_command_sha256,
        )
        return finish({
            "observed_at": iso(),
            "boundary": public_boundary(boundary),
            "session_source_identity_sha256": located.source_identity_sha256,
            "connection_epoch_sha256": str(start_event["connection_epoch_sha256"]),
            "notification_sequence": int(start_event["sequence"]),
            "notification_received_monotonic_ns": int(
                start_event["received_monotonic_ns"]
            ),
            "notification_started_at_ms": started_at_ms,
            "turn_context_record_index": context_index,
            "function_call_record_index": function_call_index,
            "command_item_id_sha256": command_item_id_sha256,
            "function_call_id_sha256": function_call_id_sha256,
            "rendered_command_sha256": rendered_command_sha256,
            "execution_correlation_sha256": execution_correlation_sha256,
            "notification_command_semantic_match": True,
            "notification_workspace_match": True,
            "command_source": "unifiedExecStartup",
            "command_status": "inProgress",
            "started_event_count": 1,
            "function_call_count": 1,
            "completed_event_count": 0,
            "paired_result_count": 0,
            "competing_call_count": 0,
            "terminal_event_count": 0,
            "failed_event_count": 0,
            "declined_event_count": 0,
            "ambiguous_event_count": 0,
        })

    observations: list[dict[str, Any]] = []
    last_threads: dict[str, dict[str, Any]] = {}
    poll_started: list[float] = []
    if materialization_timeout_seconds < 1.0:
        raise AppServerError("capability-materialization-timeout-invalid")
    deadline = time.monotonic() + materialization_timeout_seconds
    while time.monotonic() < deadline and len(observations) < 2:
        poll_start = time.monotonic()
        poll_started.append(poll_start)
        thread, observation = guarded_measure(
            samples,
            "check",
            observe,
            guard_seconds=0.0,
        )
        last_threads[thread_id] = thread
        if observation is not None:
            if not observations:
                observations.append(observation)
            else:
                first_time = dt.datetime.fromisoformat(
                    observations[0]["observed_at"].replace("Z", "+00:00")
                )
                current_time = dt.datetime.fromisoformat(
                    observation["observed_at"].replace("Z", "+00:00")
                )
                if (current_time - first_time).total_seconds() >= 1.0:
                    if any(
                        observations[0][field] != observation[field]
                        for field in (
                            "session_source_identity_sha256",
                            "connection_epoch_sha256",
                            "notification_sequence",
                            "notification_received_monotonic_ns",
                            "notification_started_at_ms",
                            "turn_context_record_index",
                            "function_call_record_index",
                            "command_item_id_sha256",
                            "function_call_id_sha256",
                            "rendered_command_sha256",
                            "execution_correlation_sha256",
                        )
                    ):
                        raise AppServerError("capability-observation-identity-changed")
                    observations.append(observation)
        elapsed = time.monotonic() - poll_start
        if len(observations) < 2:
            time.sleep(max(0.0, 0.20 - elapsed))
    if len(observations) != 2:
        raise AppServerError("capability-materialization-deadline-exceeded")
    pre_interrupt: dict[str, Any] | None = None
    pre_thread: dict[str, Any] | None = None
    while time.monotonic() < deadline and pre_interrupt is None:
        poll_start = time.monotonic()
        poll_started.append(poll_start)
        pre_thread, pre_interrupt = guarded_measure(
            samples,
            "check",
            lambda: observe("pre-interrupt"),
            guard_seconds=0.0,
        )
        last_threads[thread_id] = pre_thread
        if pre_interrupt is None:
            time.sleep(max(0.0, 0.20 - (time.monotonic() - poll_start)))
    if any(
        later - earlier > 0.250
        for earlier, later in zip(poll_started, poll_started[1:])
    ):
        raise AppServerError("capability-poll-interval-exceeded")
    if pre_interrupt is None or any(
        pre_interrupt[field] != observations[-1][field]
        for field in (
            "session_source_identity_sha256",
            "connection_epoch_sha256",
            "notification_sequence",
            "notification_received_monotonic_ns",
            "notification_started_at_ms",
            "turn_context_record_index",
            "function_call_record_index",
            "command_item_id_sha256",
            "function_call_id_sha256",
            "rendered_command_sha256",
            "execution_correlation_sha256",
        )
    ):
        raise AppServerError("capability-immediate-revalidation-failed")
    interrupt_requested_at = iso()
    guarded_measure(
        samples,
        "interrupt",
        lambda: server.interrupt_turn(thread_id, turn_id),
        guard_seconds=0.0,
    )
    interrupt_request_accepted_at = iso()
    interrupt_deadline = time.monotonic() + 5.0
    interrupt_confirmed_at: str | None = None
    confirmed_terminal_event: dict[str, Any] | None = None
    while time.monotonic() < interrupt_deadline:
        thread, _latency = server.read_thread(thread_id)
        last_threads[thread_id] = thread
        previous_boundary = dict(observed_prefix)
        try:
            interrupt_location, interrupt_boundary, interrupt_records = (
                capture_unique_boundary(
                    server.codex_home,
                    thread_id,
                    baseline=observed_prefix,
                )
            )
            interrupt_terminal_event = trusted_terminal_event(
                interrupt_records, turn_id=turn_id
            )
        except NativeSessionBoundaryError as exc:
            raise AppServerError(
                f"capability-interrupt-boundary-invalid:{exc}"
            ) from exc
        if interrupt_location.source_identity_sha256 != trusted_source_identity:
            raise AppServerError("capability-interrupt-session-source-identity-changed")
        interrupt_markers = telemetry_markers(interrupt_records, turn_id=turn_id)
        if (
            interrupt_markers["compaction_indices"]
            or interrupt_markers["reroute_indices"]
        ):
            raise AppServerError("capability-interrupt-containment-failed")
        observed_prefix = dict(interrupt_boundary)
        durable_status = (
            str(interrupt_terminal_event["status"])
            if interrupt_terminal_event is not None
            else None
        )
        if durable_status in {"completed", "failed"}:
            raise AppServerError(
                f"capability-interrupt-race-lost:{durable_status}"
            )
        if durable_status == "interrupted":
            append_control_observation(
                phase="interrupt-confirmation",
                projected_status=normalize_projected_status(
                    turn_status(thread, turn_id)
                ),
                durable_status="interrupted",
                source_identity_sha256=interrupt_location.source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=interrupt_boundary,
                decision="interrupt-confirmed",
            )
            confirmed_terminal_event = dict(interrupt_terminal_event)
            interrupt_confirmed_at = iso()
            break
        append_control_observation(
            phase="interrupt-confirmation",
            projected_status=normalize_projected_status(turn_status(thread, turn_id)),
            durable_status=None,
            source_identity_sha256=interrupt_location.source_identity_sha256,
            previous_boundary=previous_boundary,
            boundary=interrupt_boundary,
            decision="interrupt-pending",
        )
        time.sleep(0.05)
    if interrupt_confirmed_at is None or confirmed_terminal_event is None:
        raise AppServerError("capability-interrupt-not-confirmed")

    guarded_measure(
        samples,
        "finalize",
        lambda: write_private_artifact(
            record_dir / "calibration-finalize.json",
            {"thread_id": thread_id, "turn_id": turn_id, "control_turn_id": CONTROL_TURN_ID},
        ),
        guard_seconds=0.0,
    )
    guarded_measure(
        samples,
        "close",
        lambda: server.archive_thread(thread_id),
        guard_seconds=0.0,
    )
    previous_boundary = dict(observed_prefix)
    try:
        terminal_location, terminal_boundary, terminal_records = capture_unique_boundary(
            server.codex_home,
            thread_id,
            baseline=observed_prefix,
        )
        terminal_event = trusted_terminal_event(terminal_records, turn_id=turn_id)
    except NativeSessionBoundaryError as exc:
        raise AppServerError(f"capability-terminal-boundary-invalid:{exc}") from exc
    terminal_markers = telemetry_markers(terminal_records, turn_id=turn_id)
    if terminal_location.source_identity_sha256 != trusted_source_identity:
        raise AppServerError("capability-terminal-session-source-identity-changed")
    if terminal_markers["compaction_indices"] or terminal_markers["reroute_indices"]:
        raise AppServerError("capability-terminal-containment-failed")
    if terminal_event != confirmed_terminal_event or terminal_event is None:
        raise AppServerError("capability-terminal-interrupt-proof-changed")
    if terminal_event.get("status") != "interrupted":
        raise AppServerError("capability-terminal-interrupt-proof-invalid")
    observed_prefix = dict(terminal_boundary)
    append_control_observation(
        phase="terminal",
        projected_status=normalize_projected_status(
            turn_status(last_threads[thread_id], turn_id)
        ),
        durable_status="interrupted",
        source_identity_sha256=terminal_location.source_identity_sha256,
        previous_boundary=previous_boundary,
        boundary=terminal_boundary,
        decision="terminal-accepted",
    )
    if trusted_source_identity is None:
        raise AppServerError("capability-session-source-identity-not-pinned")
    materialization = seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 4,
            "schema": MATERIALIZATION_EVIDENCE_SCHEMA,
            "evidence_id": f"materialization-{uuid.uuid4()}",
            "run_nonce": run_nonce,
            "attempt_nonce": attempt_nonce,
            "phase_nonce": phase_nonce,
            "session_id": thread_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "requested_model": EXACT_MODEL,
            "attested_model": EXACT_MODEL,
            "attested_effort": "low",
            "attestation_source": (
                "initialized-codex-home-session-jsonl-and-local-app-server-stdio-notifications"
            ),
            "connection_epoch_sha256": server.connection_epoch_sha256,
            "command_sha256": sha256_text("sleep 20"),
            "session_source_identity_sha256": trusted_source_identity,
            "baseline": public_boundary(strict_baseline),
            "control_observations": control_observations,
            "liveness_observations": observations,
            "pre_interrupt_observation": pre_interrupt,
            "interrupt": {
                "requested_at": interrupt_requested_at,
                "request_accepted_at": interrupt_request_accepted_at,
                "confirmed_at": interrupt_confirmed_at,
                "session_id": thread_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "request_outcome": "accepted",
                "outcome": "interrupt-confirmed",
            },
            "terminal": public_boundary(terminal_boundary),
            "terminal_event": terminal_event,
            "status": "interrupt-confirmed",
            "disposition": "accepted",
        }
    )
    materialization_errors = validate_materialization_evidence(
        materialization, require_accepting=True
    )
    if materialization_errors:
        raise AppServerError(
            "capability-materialization-evidence-invalid:" + ";".join(materialization_errors)
        )

    scheduler_samples: list[float] = []
    children = [
        {"child_id": "a", "next_deadline_ns": 1_000_000_000},
        {"child_id": "b", "next_deadline_ns": 1_000_000_000},
    ]
    cursor = 0
    for _index in range(4):
        started = time.monotonic_ns()
        selected = select_earliest_deadline(children, cursor=cursor)
        if selected is None:
            raise AppServerError("scheduler-calibration-selection-missing")
        cursor = selected.next_cursor
        time.sleep(0.05)
        scheduler_samples.append((time.monotonic_ns() - started) / 1_000_000)

    measured_at = utc_now()
    receipt = seal_artifact(
        {
            "receipt_type": CAPABILITY_RECEIPT_TYPE,
            "version": 1,
            "schema": CAPABILITY_RECEIPT_SCHEMA,
            "adapter_id": "native-multi-agent-v1",
            "adapter_version": "codex-app-server-0.144.5",
            "execution_surface": "connected-codex",
            "host_identity": dict(owner),
            "control_turn_id": CONTROL_TURN_ID,
            "measured_at": iso(measured_at),
            "expires_at": iso(measured_at + dt.timedelta(minutes=55)),
            "sample_count": min(len(values) for values in samples.values()),
            "requested_cap": 2,
            "clock": "monotonic_ns",
            "callbacks": {name: stats(samples[name]) for name in sorted(samples)},
            "scheduler_overhead": stats(scheduler_samples),
            "certification": capability_certification(),
            "capabilities": {
                "interrupt": True,
                "close": True,
                "wait": True,
                "trusted_telemetry": True,
            },
            "attestation_source": "trusted-control-plane-session-metadata",
            "validation_outcome": "accepted",
        },
        "receipt_sha256",
    )
    errors = validate_capability_receipt(receipt, now=utc_now())
    if errors:
        raise AppServerError("capability-receipt-invalid:" + ";".join(errors))
    ceilings = receipt["certification"]["certified_callback_max_ms"]
    check_max = ceilings["check"]
    lifecycle_max = max(ceilings.values())
    overhead_max = receipt["certification"]["certified_scheduler_overhead_ms"]
    if lifecycle_max + 2 * check_max + overhead_max > 1000:
        raise AppServerError("capability-response-time-bound-failed")

    thread = last_threads[thread_id]
    boundary = session_boundary_summary(
        server.codex_home,
        thread_id,
        None,
        turn_id=turn_id,
        baseline=strict_baseline,
    )
    summary = {
        "thread_id": thread_id,
        "turn_id": turn_id,
        "thread_start_model": result.get("model"),
        "thread_start_model_provider": result.get("modelProvider"),
        "turn_status": turn_status(thread, turn_id),
        "session_boundary": boundary,
        "final_response_sha256": None,
        "expected_final_token_observed": False,
        "reroute_count": len(server.notifications(thread_id, "model/rerouted")),
        "compactions": len(server.notifications(thread_id, "thread/compacted"))
        + int(boundary.get("compactions", 0)),
    }
    if summary["thread_start_model"] != EXACT_MODEL:
        raise AppServerError("capability-thread-start-model-mismatch")
    if summary["session_boundary"].get("attested_models") != [EXACT_MODEL]:
        raise AppServerError("capability-session-model-mismatch")
    if summary["session_boundary"].get("attested_efforts") != ["low"]:
        raise AppServerError("capability-session-effort-mismatch")
    if summary["compactions"] or summary["reroute_count"]:
        raise AppServerError("capability-session-containment-failed")

    evidence = {
        "thread_preallocation_stats": stats([preallocation_latency]),
        "guard_band_ms": {"callbacks": 0, "scheduler_overhead": 50},
        "sessions": [summary],
        "materialization_evidence": materialization,
        "materialization_evidence_sha256": materialization["evidence_sha256"],
        "poll_interval_max_ms": round(
            max(
                (later - earlier) * 1000
                for earlier, later in zip(poll_started, poll_started[1:])
            ),
            3,
        ) if len(poll_started) > 1 else 0.0,
        "interrupt_confirmed": True,
        "peer_completion_deferred_to_coordinator_interrupt_canary": True,
        "scheduler_inequality_lhs_ms": round(
            lifecycle_max + 2 * check_max + overhead_max, 3
        ),
        "scheduler_inequality_rhs_ms": 1000,
    }
    return receipt, evidence


def make_git_layout(root: Path) -> dict[str, Path]:
    integration = root / "integration"
    integration.mkdir()
    run_git(integration, "init", "-q")
    run_git(integration, "config", "user.name", "CWO Live Canary")
    run_git(integration, "config", "user.email", "cwo-canary@example.invalid")
    (integration / "data").mkdir()
    (integration / "targets").mkdir()
    (integration / "data" / "shared.txt").write_text("trusted-read-only-baseline\n", encoding="utf-8")
    (integration / "targets" / "child_0.txt").write_text("baseline-0\n", encoding="utf-8")
    (integration / "targets" / "child_1.txt").write_text("baseline-1\n", encoding="utf-8")
    run_git(integration, "add", ".")
    run_git(integration, "commit", "-qm", "canary baseline")
    paths: dict[str, Path] = {"integration": integration}
    for name in ("read-shared", "mutable-0", "mutable-1", "interrupt-shared"):
        target = root / name
        run_git(
            integration,
            "worktree",
            "add",
            "-q",
            "-b",
            f"cwo-18w6-{name}",
            str(target),
            "HEAD",
        )
        paths[name] = target
    return paths


def build_pool_inputs(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    campaign_manifest: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    interrupt_after: list[int | None] | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, LiveThreadAdapter],
    PoolWorkspaceMonitor,
]:
    manifest_errors = validate_campaign_manifest(campaign_manifest)
    if manifest_errors:
        raise AppServerError(
            "campaign-manifest-invalid-before-thread-start:"
            + ";".join(manifest_errors)
        )
    if campaign_manifest.get("control_turn_id") != CONTROL_TURN_ID:
        raise AppServerError("campaign-control-turn-invalid-before-thread-start")
    record_dir = root / f"{pool_name}-records"
    record_dir.mkdir(mode=0o700)
    thread_results = []
    for index, worktree in enumerate(worktrees):
        role = f"{pool_name}-{index}"
        result, _latency = server.start_thread(worktree, mutable=mutable, role=role)
        thread_results.append(result)
    children = []
    child_contracts: dict[str, dict[str, Any]] = {}
    adapters: dict[str, LiveThreadAdapter] = {}
    for index, (result, worktree, prompt, expected_token) in enumerate(
        zip(thread_results, worktrees, prompts, expected_tokens)
    ):
        child_id = f"{pool_name}-child-{index}"
        thread_id = str(result["thread"]["id"])
        state_file = record_dir / f"{child_id}-worker-state.json"
        control_file = record_dir / f"{child_id}-control-contract.json"
        control_turn_id = f"{CONTROL_TURN_ID}:{pool_name}:{index}"
        packet_sha256 = sha256_text(
            json.dumps(
                {
                    "pool": pool_name,
                    "child": index,
                    "prompt_sha256": sha256_text(prompt),
                    "thread_id": thread_id,
                },
                sort_keys=True,
            )
        )
        control = build_control_turn_contract(
            state_file=str(state_file),
            agent_id=thread_id,
            control_turn_id=control_turn_id,
            task_sha256=sha256_text(prompt),
            poll_interval_ms=1000,
        )
        state = {
            "result_type": "cwo-native-supervision-state",
            "version": 1,
            "schema": "schemas/native-supervision-state.schema.json",
            "packet_id": f"{pool_name}-packet-{uuid.uuid4()}",
            "packet_sha256": packet_sha256,
            "agent_id": thread_id,
            "session_id": thread_id,
            "status": "created",
            "control_turn_id": None,
            "poll_interval_ms": 1000,
            "control_adapter": "native-multi-agent-v1",
            "required_capabilities": ["interrupt", "close", "wait"],
        }
        write_private_artifact(control_file, control)
        write_private_artifact(state_file, state)
        target = f"targets/child_{index}.txt" if mutable else None
        child = {
            "child_id": child_id,
            "packet_id": state["packet_id"],
            "attempt_nonce": f"{pool_name}-attempt-{uuid.uuid4()}",
            "session_id": thread_id,
            "agent_id": thread_id,
            "control_turn_id": control_turn_id,
            "packet_sha256": packet_sha256,
            "control_contract_file": str(control_file),
            "state_file": str(state_file),
            "worktree": str(worktree),
            "isolation_class": "mutable-isolated" if mutable else "read-only-shared",
            "declared_write_paths": [target] if target else [],
            "integration_target_paths": [target] if target else [],
            "lease_id": f"{pool_name}-lease-{uuid.uuid4()}",
        }
        children.append(child)
        child_contracts[child_id] = control
        adapters[child_id] = LiveThreadAdapter(
            server,
            result,
            prompt=prompt,
            expected_token=expected_token,
            worktree=worktree,
            mutable=mutable,
            expected_mutation=target,
            force_interrupt_after_checks=(interrupt_after or [None, None])[index],
            record_dir=record_dir,
        )
    request = {
        "request_type": "cwo-native-supervision-pool-render-request",
        "version": 1,
        "schema": "schemas/native-supervision-pool-render-request.schema.json",
        "pool_id": f"18w6-{pool_name}-{uuid.uuid4()}",
        "pool_epoch": f"18w6-{pool_name}-epoch-{uuid.uuid4()}",
        "control_turn_id": CONTROL_TURN_ID,
        "created_at": iso(),
        "max_active_workers": 2,
        "aggregate_hard_budget": {
            "tool_calls": 20,
            "runtime_seconds": 300,
            "compactions": 0,
            "full_suite_runs": 0,
            "mutations": 2 if mutable else 0,
        },
        "integration_root": str(integration),
        "children": children,
    }
    contract = build_live_canary_pool_contract(
        request,
        campaign_manifest=campaign_manifest,
        capability_receipt=capability_receipt,
        owner_pid=os.getpid(),
        now=utc_now(),
    )
    monitor = PoolWorkspaceMonitor(
        contract,
        integration_root=integration,
        child_worktrees={child_id: adapter.worktree for child_id, adapter in adapters.items()},
    )
    return contract, child_contracts, adapters, monitor


def run_pool_canary(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    campaign_manifest: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    interrupt_after: list[int | None] | None = None,
) -> dict[str, Any]:
    contract, child_contracts, adapters, monitor = build_pool_inputs(
        server,
        capability_receipt,
        campaign_manifest,
        root=root,
        integration=integration,
        pool_name=pool_name,
        worktrees=worktrees,
        mutable=mutable,
        prompts=prompts,
        expected_tokens=expected_tokens,
        interrupt_after=interrupt_after,
    )
    child_ids = list(adapters)

    def read_child_evidence(*, child_id: str, state_file: str) -> dict[str, Any]:
        if state_file != next(
            child["state_file"] for child in contract["children"] if child["child_id"] == child_id
        ):
            raise AppServerError("child-evidence-state-file-mismatch")
        return adapters[child_id].evidence()

    coordinator = NativePoolCoordinator(
        contract,
        child_contracts,
        {child_id: adapters[child_id].prompt for child_id in child_ids},
        {child_id: adapters[child_id].callbacks() for child_id in child_ids},
        pool_callbacks={
            "monotonic_ns": time.monotonic_ns,
            "sleep": pool_sleep,
            "now_utc": iso,
            "read_child_evidence": read_child_evidence,
            "compare_workspaces": monitor.compare,
        },
        lease_registry=PoolLeaseRegistry(root / f"{pool_name}-leases.json"),
        capability_receipt=capability_receipt,
        state_file=root / f"{pool_name}-pool-state.json",
        decision_file=root / f"{pool_name}-pool-decision.json",
    )
    started = time.monotonic_ns()
    receipt = coordinator.run()
    elapsed = (time.monotonic_ns() - started) / 1_000_000_000
    terminal_state = coordinator.progress()["state"]
    receipt_errors = validate_pool_receipt(
        receipt, contract=contract, terminal_state=terminal_state
    )
    if receipt_errors:
        raise AppServerError("live-pool-receipt-invalid:" + ";".join(receipt_errors))
    if interrupt_after is None and receipt.get("accepting") is not True:
        first_fault = receipt.get("first_protected_fault")
        raise LivePoolProtectedFault(first_fault)
    summaries = [adapters[child_id].final_summary() for child_id in child_ids]
    worker_seconds = float(receipt["worker_seconds"])
    improvement = (
        (worker_seconds - float(receipt["pool_wall_seconds"])) / worker_seconds
        if worker_seconds > 0
        else 0.0
    )
    return {
        "pool_name": pool_name,
        "pool_id": contract["pool_id"],
        "pool_epoch": contract["pool_epoch"],
        "contract_sha256": contract["contract_sha256"],
        "receipt": receipt,
        "receipt_validation_errors": receipt_errors,
        "terminal_state_sha256": terminal_state["state_sha256"],
        "elapsed_seconds": round(elapsed, 3),
        "elapsed_improvement_ratio": round(improvement, 6),
        "sessions": summaries,
        "workspace": {
            "evidence": monitor.last_report["evidence"] if monitor.last_report else None,
            "phase": monitor.last_report["phase"] if monitor.last_report else None,
        },
    }


def validate_campaign(
    capability: Mapping[str, Any],
    calibration_evidence: Mapping[str, Any],
    canaries: list[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    capability_errors = validate_capability_receipt(capability, now=utc_now())
    errors.extend(f"capability:{item}" for item in capability_errors)
    certification = capability["certification"]
    ceilings = certification["certified_callback_max_ms"]
    check_max = ceilings["check"]
    overhead = certification["certified_scheduler_overhead_ms"]
    lifecycle_max = max(ceilings.values())
    if check_max > 200:
        errors.append("capability-check-max-exceeded")
    if lifecycle_max + 2 * check_max + overhead > 1000:
        errors.append("capability-response-time-bound-failed")
    all_sessions = list(calibration_evidence.get("sessions", []))
    for canary in canaries:
        all_sessions.extend(canary.get("sessions", []))
    thread_ids = [session.get("thread_id") for session in all_sessions]
    if len(thread_ids) != 7 or len(thread_ids) != len(set(thread_ids)):
        errors.append("fresh-session-cardinality-or-uniqueness-failed")
    for session in all_sessions:
        boundary = session.get("session_boundary", {})
        if session.get("thread_start_model") != EXACT_MODEL:
            errors.append("session-thread-start-model-mismatch")
        if boundary.get("attested_models") != [EXACT_MODEL]:
            errors.append("session-trusted-model-mismatch")
        if boundary.get("attested_efforts") != ["low"]:
            errors.append("session-trusted-effort-mismatch")
        if boundary.get("trailing_partial"):
            errors.append("session-terminal-boundary-partial")
        if session.get("compactions"):
            errors.append("session-compaction-observed")
        if session.get("reroute_count"):
            errors.append("session-model-reroute-observed")
    by_name = {str(item.get("pool_name")): item for item in canaries}
    for name in ("read-only", "mutable"):
        canary = by_name.get(name, {})
        receipt = canary.get("receipt", {})
        if receipt.get("accepting") is not True or receipt.get("pool_disposition") != "accepted":
            errors.append(f"{name}-pool-not-accepting")
        if receipt.get("reasons"):
            errors.append(f"{name}-protected-reasons-observed")
        if canary.get("elapsed_improvement_ratio", 0) <= 0:
            errors.append(f"{name}-elapsed-improvement-not-positive")
        for session in canary.get("sessions", []):
            if not session.get("expected_final_token_observed"):
                errors.append(f"{name}-invalid-final-response")
    mutable = by_name.get("mutable", {})
    expected_mutations = [["targets/child_0.txt"], ["targets/child_1.txt"]]
    if [session.get("workspace_mutations") for session in mutable.get("sessions", [])] != expected_mutations:
        errors.append("mutable-workspace-attribution-failed")
    read_only = by_name.get("read-only", {})
    if any(session.get("workspace_mutations") for session in read_only.get("sessions", [])):
        errors.append("read-only-workspace-mutation-observed")
    interrupted = by_name.get("interrupt", {})
    receipt = interrupted.get("receipt", {})
    if receipt.get("accepting") is not False or receipt.get("pool_disposition") != "partial":
        errors.append("interrupt-pool-disposition-invalid")
    if receipt.get("reasons"):
        errors.append("interrupt-protected-reasons-observed")
    sessions = interrupted.get("sessions", [])
    if len(sessions) != 2:
        errors.append("interrupt-session-count-invalid")
    else:
        if sessions[0].get("turn_status") != "interrupted" or not sessions[0].get("interrupted"):
            errors.append("independent-interrupt-not-confirmed")
        if sessions[1].get("turn_status") != "completed" or not sessions[1].get(
            "expected_final_token_observed"
        ):
            errors.append("interrupt-peer-did-not-complete")
    if interrupted.get("elapsed_improvement_ratio", 0) <= 0:
        errors.append("interrupt-elapsed-improvement-not-positive")
    for canary in canaries:
        evidence = canary.get("workspace", {}).get("evidence")
        if evidence != {
            "integration_root_clean": True,
            "shared_read_only_clean": True,
            "child_worktrees_clean": True,
        }:
            errors.append(f"{canary.get('pool_name')}-workspace-evidence-not-clean")
        if canary.get("receipt_validation_errors"):
            errors.append(f"{canary.get('pool_name')}-receipt-validation-failed")
    return sorted(set(errors))


def contain_started_threads(server: AppServer) -> dict[str, Any]:
    """Idempotently interrupt, archive, and audit every allocated thread."""

    interrupted: list[str] = []
    archived: list[str] = []
    already_contained: list[str] = []
    ambiguous: list[str] = []
    ledger_errors: list[str] = []
    ledger = getattr(server, "allocation_ledger", None)

    def audit_containment(thread_id: str, outcome: str, status: str | None) -> None:
        if ledger is None:
            return
        try:
            ledger.record_containment_audit(
                thread_id,
                outcome=outcome,
                evidence={
                    "thread_id_sha256": sha256_text(thread_id),
                    "turn_status": status,
                    "outcome": outcome,
                },
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))

    for thread_id, turn_id in list(server.started_threads.items()):
        try:
            thread, _latency = server.read_thread(thread_id)
            status = turn_status(thread, turn_id) if turn_id else None
            if turn_id and status == "inProgress":
                server.interrupt_turn(thread_id, turn_id)
                interrupted.append(thread_id)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    thread, _latency = server.read_thread(thread_id)
                    status = turn_status(thread, turn_id)
                    if status in {"interrupted", "completed", "failed"}:
                        break
                    time.sleep(0.05)
            if turn_id is None or status in {"interrupted", "completed", "failed"}:
                server.archive_thread(thread_id)
                archived.append(thread_id)
                audit_containment(thread_id, "contained", status)
            else:
                ambiguous.append(thread_id)
        except Exception:
            try:
                archived_in_ledger = bool(
                    ledger is not None
                    and ledger.has_lifecycle(thread_id, "archive-observed")
                )
            except Exception as exc:
                archived_in_ledger = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            if archived_in_ledger:
                already_contained.append(thread_id)
                audit_containment(thread_id, "already-contained", None)
            else:
                ambiguous.append(thread_id)
    unresolved_allocations = 0
    unresolved_turns = 0
    ledger_allocation_count = len(server.started_threads)
    if ledger is not None:
        try:
            ledger_summary = ledger.summary()
            unresolved_allocations = int(
                ledger_summary["unresolved_allocation_intent_count"]
            )
            unresolved_turns = int(ledger_summary["unresolved_turn_intent_count"])
            ledger_allocation_count = int(ledger_summary["allocation_intent_count"])
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
    ambiguous_count = len(set(ambiguous)) + unresolved_allocations
    return {
        "allocated_count": ledger_allocation_count,
        "identified_thread_count": len(server.started_threads),
        "interrupted_count": len(set(interrupted)),
        "archived_count": len(set(archived)),
        "already_contained_count": len(set(already_contained)),
        "unresolved_allocation_intent_count": unresolved_allocations,
        "unresolved_turn_intent_count": unresolved_turns,
        "ambiguous_count": ambiguous_count,
        "all_contained": ambiguous_count == 0,
        "ledger_consistent": not ledger_errors and not unresolved_allocations and not unresolved_turns,
        "ledger_error_sha256": sorted(set(ledger_errors)),
    }


def _load_owned_regular_bytes(
    path: Path,
    label: str,
    *,
    require_private: bool,
) -> bytes:
    """Capture one owner-bound file exactly once through a stable descriptor."""

    supplied = Path(path)
    lexical = supplied.absolute()
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"{label}-file-invalid") from exc
    if lexical != resolved:
        raise AppServerError(f"{label}-path-invalid")
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise AppServerError(f"{label}-file-invalid") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or (
                before.st_mode & 0o077
                if require_private
                else before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
        ):
            raise AppServerError(f"{label}-permissions-invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or len(
        value
    ) != before.st_size:
        raise AppServerError(f"{label}-source-changed")
    if not value:
        raise AppServerError(f"{label}-file-empty")
    return value


def load_private_bytes(path: Path, label: str) -> bytes:
    """Read one private regular file through a no-follow descriptor snapshot."""

    return _load_owned_regular_bytes(path, label, require_private=True)


def load_trusted_session_bytes(path: Path, label: str) -> bytes:
    """Snapshot owner-bound session telemetry that may be world-readable."""

    return _load_owned_regular_bytes(path, label, require_private=False)


def load_private_json_snapshot(path: Path, label: str) -> JsonArtifactSnapshot:
    raw = load_private_bytes(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    if not isinstance(value, dict):
        raise AppServerError(f"{label}-not-object")
    return JsonArtifactSnapshot(raw=raw, value=value)


def load_private_json(path: Path, label: str) -> dict[str, Any]:
    return dict(load_private_json_snapshot(path, label).value)


def _private_control_directory(path: Path, label: str) -> Path:
    supplied = Path(path).absolute()
    try:
        if supplied.is_symlink():
            raise AppServerError(f"{label}-directory-permissions-invalid")
        supplied.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = supplied.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if directory != supplied:
        raise AppServerError(f"{label}-directory-permissions-invalid")
    try:
        info = directory.lstat()
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppServerError(f"{label}-directory-permissions-invalid")
    return directory


def _stable_codex_control_root() -> Path:
    """Resolve the control root from the effective account, never mutable HOME."""

    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).absolute()
        root = (account_home / ".codex").resolve(strict=True)
        info = root.lstat()
    except (KeyError, OSError) as exc:
        raise AppServerError("stable-codex-control-root-unavailable") from exc
    if (
        root != account_home / ".codex"
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise AppServerError("stable-codex-control-root-invalid")
    return root


def _open_private_control_lock(path: Path, label: str) -> int:
    """Open one owner-private regular lock file without following aliases."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise AppServerError(f"{label}-lock-invalid") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AppServerError(f"{label}-lock-invalid")
    return descriptor


def _write_exclusive_private_bytes(path: Path, raw: bytes, label: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise AppServerError(f"{label}-already-exists") from exc
    except OSError as exc:
        raise AppServerError(f"{label}-create-failed") from exc
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-write-failed") from exc
    finally:
        os.close(descriptor)


def _fsync_private_control_directory(path: Path, label: str) -> None:
    """Durably persist a newly created private control-plane directory entry."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise AppServerError(f"{label}-directory-permissions-invalid")
        os.fsync(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-directory-fsync-failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _active_authority_registry_root(override: Path | None = None) -> Path:
    return _private_control_directory(
        override
        if override is not None
        else _stable_codex_control_root() / "cwo-native-live-authorities-v1",
        "active-outer-authority-registry",
    )


def _active_authority_registry_path(
    outer_authority: Mapping[str, Any], registry_root: Path | None = None
) -> tuple[Path, Path, str]:
    scope = outer_authority.get("scope")
    if not isinstance(scope, Mapping):
        raise AppServerError("active-outer-authority-scope-invalid")
    try:
        scope_key = active_outer_authority_scope_key(
            scope.get("epic_id"), scope.get("parent_work_unit_id")
        )
    except ValueError as exc:
        raise AppServerError("active-outer-authority-scope-invalid") from exc
    declared = outer_authority.get("active_registry")
    if declared != {
        "contract": "cwo-active-outer-authority-registry:v1",
        "scope_key": scope_key,
    }:
        raise AppServerError("active-outer-authority-registry-declaration-invalid")
    root = _active_authority_registry_root(registry_root)
    return root / f"{scope_key}.json", root / f"{scope_key}.lock", scope_key


def register_active_outer_authority(
    outer_authority: JsonArtifactSnapshot,
    *,
    candidate_commit: str,
    candidate_tree: str,
    registry_root: Path | None = None,
) -> JsonArtifactSnapshot:
    """Atomically supersede the active outer authority for one work-graph scope."""

    value = dict(outer_authority.value)
    outer_bindings = value.get("bindings")
    if (
        json.loads(outer_authority.raw) != value
        or value.get("status") != "active"
        or not isinstance(outer_bindings, Mapping)
        or outer_bindings.get("candidate_commit") != candidate_commit
        or outer_bindings.get("candidate_tree") != candidate_tree
        or not re.fullmatch(r"[0-9a-f]{40}", candidate_commit)
        or not re.fullmatch(r"[0-9a-f]{40}", candidate_tree)
        or value.get("canonical_outer_authority_sha256")
        != sha256_bytes(
            json.dumps(
                {
                    key: item
                    for key, item in value.items()
                    if key != "canonical_outer_authority_sha256"
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
    ):
        raise AppServerError("active-outer-authority-artifact-invalid")
    path, lock_path, scope_key = _active_authority_registry_path(
        value, registry_root
    )
    scope = value["scope"]
    record: dict[str, Any] = {
        "registry_type": "cwo-active-outer-authority-registry",
        "version": 1,
        "scope_key": scope_key,
        "epic_id": scope["epic_id"],
        "parent_work_unit_id": scope["parent_work_unit_id"],
        "authority_id": value["authority_id"],
        "authority_file_sha256": outer_authority.raw_sha256,
        "authority_canonical_sha256": value[
            "canonical_outer_authority_sha256"
        ],
        "candidate_commit": candidate_commit,
        "candidate_tree": candidate_tree,
        "status": "active",
        "updated_at": iso(),
    }
    record["canonical_registry_sha256"] = sha256_bytes(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    )
    raw = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    lock_descriptor = _open_private_control_lock(
        lock_path, "active-outer-authority"
    )
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if path.exists():
            current = load_private_json(path, "active-outer-authority-registry")
            if current.get("authority_id") != value["authority_id"]:
                supersession = value.get("supersession")
                if (
                    not isinstance(supersession, Mapping)
                    or supersession.get("prior_outer_authority_id")
                    != current.get("authority_id")
                ):
                    raise AppServerError(
                        "active-outer-authority-supersession-invalid"
                    )
        temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
        _write_exclusive_private_bytes(
            temporary, raw, "active-outer-authority-registry-temporary"
        )
        os.replace(temporary, path)
        _fsync_private_control_directory(
            path.parent, "active-outer-authority-registry"
        )
    finally:
        os.close(lock_descriptor)
    return JsonArtifactSnapshot(raw=raw, value=record)


def _validate_active_outer_authority_unlocked(
    outer_authority: JsonArtifactSnapshot,
    *,
    candidate_commit: str,
    candidate_tree: str,
    path: Path,
    scope_key: str,
) -> str:
    registry = load_private_json(path, "active-outer-authority-registry")
    expected_fields = {
        "registry_type",
        "version",
        "scope_key",
        "epic_id",
        "parent_work_unit_id",
        "authority_id",
        "authority_file_sha256",
        "authority_canonical_sha256",
        "candidate_commit",
        "candidate_tree",
        "status",
        "updated_at",
        "canonical_registry_sha256",
    }
    unsigned = dict(registry)
    recorded = unsigned.pop("canonical_registry_sha256", None)
    scope = outer_authority.value.get("scope", {})
    if (
        set(registry) != expected_fields
        or registry.get("registry_type")
        != "cwo-active-outer-authority-registry"
        or registry.get("version") != 1
        or registry.get("scope_key") != scope_key
        or registry.get("epic_id") != scope.get("epic_id")
        or registry.get("parent_work_unit_id")
        != scope.get("parent_work_unit_id")
        or registry.get("authority_id")
        != outer_authority.value.get("authority_id")
        or registry.get("authority_file_sha256") != outer_authority.raw_sha256
        or registry.get("authority_canonical_sha256")
        != outer_authority.value.get("canonical_outer_authority_sha256")
        or registry.get("candidate_commit") != candidate_commit
        or registry.get("candidate_tree") != candidate_tree
        or registry.get("status") != "active"
        or recorded
        != sha256_bytes(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        )
    ):
        raise AppServerError("active-outer-authority-registry-mismatch")
    return str(recorded)


def validate_active_outer_authority(
    outer_authority: JsonArtifactSnapshot,
    *,
    candidate_commit: str,
    candidate_tree: str,
    registry_root: Path | None = None,
) -> str:
    """Require the supplied outer artifact to remain the canonical active one."""

    path, lock_path, scope_key = _active_authority_registry_path(
        outer_authority.value, registry_root
    )
    lock_descriptor = _open_private_control_lock(
        lock_path, "active-outer-authority"
    )
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_SH)
        return _validate_active_outer_authority_unlocked(
            outer_authority,
            candidate_commit=candidate_commit,
            candidate_tree=candidate_tree,
            path=path,
            scope_key=scope_key,
        )
    finally:
        os.close(lock_descriptor)


def acquire_global_campaign_claim(
    inputs: CampaignLaunchInputs,
    *,
    launch_claim_sha256: str,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
    claim_root: Path | None = None,
    registry_root: Path | None = None,
) -> Path:
    """Acquire the permanent machine-global claim for one inner authorization.

    A claim is an intentional one-shot tombstone, not a recoverable lock.  A
    contained or aborted campaign must mint a fresh authorization ID and nonce;
    deleting a prior claim would turn a forbidden resume into a replay path.
    """

    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-global-claim-authorization-invalid")
    identity = {
        "authorization_id": authorization.get("authorization_id"),
        "run_generation": authorization.get("run_generation"),
        "live_generation": authorization.get("live_generation"),
        "campaign_nonce": bindings.get("campaign_nonce"),
    }
    identity_sha256 = domain_sha256(identity, domain="native-live-global-claim")
    root = _private_control_directory(
        claim_root
        if claim_root is not None
        else _stable_codex_control_root()
        / "cwo-native-live-campaign-claims-v1",
        "campaign-global-claim",
    )
    path = root / f"{identity_sha256}.json"
    claim: dict[str, Any] = {
        "claim_type": "cwo-native-live-campaign-global-claim",
        "version": 1,
        "identity": identity,
        "identity_sha256": identity_sha256,
        "launch_claim_sha256": launch_claim_sha256,
        "outer_authority_id": inputs.outer_authority.value.get("authority_id"),
        "candidate_commit": manifest.get("candidate", {}).get("commit"),
        "candidate_tree": manifest.get("candidate", {}).get("tree"),
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "claimed_at": iso(),
    }
    claim["canonical_claim_sha256"] = domain_sha256(
        claim, domain="native-live-global-claim-artifact"
    )
    authority_path, authority_lock_path, scope_key = (
        _active_authority_registry_path(
            inputs.outer_authority.value, registry_root
        )
    )
    authority_lock_descriptor = _open_private_control_lock(
        authority_lock_path, "active-outer-authority"
    )
    try:
        # The shared authority lock makes the active-authority check and the
        # exclusive one-shot claim one indivisible launch decision. A successor
        # authority cannot supersede this authority between those two events.
        fcntl.flock(authority_lock_descriptor, fcntl.LOCK_SH)
        _validate_active_outer_authority_unlocked(
            inputs.outer_authority,
            candidate_commit=str(manifest.get("candidate", {}).get("commit")),
            candidate_tree=str(manifest.get("candidate", {}).get("tree")),
            path=authority_path,
            scope_key=scope_key,
        )
        _write_exclusive_private_bytes(
            path,
            (json.dumps(claim, indent=2, sort_keys=True) + "\n").encode(),
            "campaign-global-claim",
        )
        _fsync_private_control_directory(root, "campaign-global-claim")
    finally:
        os.close(authority_lock_descriptor)
    return path


def require_unique_input_paths(paths: Mapping[str, Path]) -> dict[str, Path]:
    """Resolve a complete input set once and reject path or inode aliases."""

    resolved: dict[str, Path] = {}
    reverse: dict[Path, str] = {}
    identities: dict[tuple[int, int], str] = {}
    for label, supplied in paths.items():
        lexical = Path(supplied).absolute()
        try:
            current = Path(supplied).resolve(strict=True)
            info = current.stat()
        except OSError as exc:
            raise AppServerError(f"{label}-path-invalid") from exc
        identity = (info.st_dev, info.st_ino)
        if (
            lexical != current
            or current in reverse
            or identity in identities
            or not stat.S_ISREG(info.st_mode)
        ):
            raise AppServerError("campaign-input-path-alias")
        resolved[label] = current
        reverse[current] = label
        identities[identity] = label
    return resolved


def capture_input_source_identities(
    paths: Mapping[str, Path],
) -> dict[str, tuple[int, int, int, int]]:
    """Capture stable source identities after alias rejection."""

    identities: dict[str, tuple[int, int, int, int]] = {}
    for label, path in paths.items():
        try:
            info = path.stat()
        except OSError as exc:
            raise AppServerError(f"{label}-source-identity-unavailable") from exc
        identities[label] = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
    return identities


def require_private_parent(path: Path, label: str) -> None:
    try:
        info = path.parent.lstat()
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppServerError(f"{label}-directory-permissions-invalid")


def campaign_input_requires_private_parent(label: str) -> bool:
    """Session telemetry is owner-bound but may live below a shared directory."""

    return "session" not in label


def require_trusted_session_snapshots_unchanged(
    paths: Mapping[str, Path], inputs: CampaignLaunchInputs
) -> None:
    """Re-read every trusted JSONL immediately before the first allocation."""

    expected: dict[str, bytes] = {
        "spark-validation-session": inputs.spark_validation_session_bytes,
    }
    proof = inputs.predecessor_proof
    if proof is not None:
        expected["predecessor-independent-validation-session"] = (
            proof.independent_validation_session_bytes
        )
        expected.update(
            {
                f"predecessor-contained-session-{index}": raw
                for index, raw in enumerate(proof.contained_session_bytes)
            }
        )
        expected.update(
            {
                f"ancestor-contained-session-{index}": raw
                for index, raw in enumerate(
                    proof.ancestor.contained_session_bytes
                )
            }
        )
    for label, snapshot in expected.items():
        path = paths.get(label)
        if path is None:
            raise AppServerError(f"{label}-path-missing")
        if load_trusted_session_bytes(path, label) != snapshot:
            raise AppServerError(f"{label}-changed-before-allocation")


def require_launch_source_snapshots_unchanged(
    paths: Mapping[str, Path], inputs: CampaignLaunchInputs
) -> None:
    """Recheck every mutable source against the read-once launch snapshots."""

    expected: dict[str, bytes] = {
        "authorization": inputs.authorization.raw,
        "campaign-manifest": inputs.manifest.raw,
        "outer-authority": inputs.outer_authority.raw,
        "release-patch": inputs.release_patch_bytes,
        "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
        "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
        "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
        "pre-live-adjudication": inputs.pre_live_adjudication.raw,
        "opus-review-evidence": inputs.opus_review_evidence.raw,
        "opus-adjudication": inputs.opus_adjudication.raw,
        "spark-validation-receipt": inputs.spark_validation_receipt.raw,
    }
    proof = inputs.predecessor_proof
    legacy = inputs.legacy_predecessor
    if proof is not None:
        expected.update(
            {
                "predecessor-authorization": proof.authorization.raw,
                "predecessor-manifest": proof.manifest.raw,
                "predecessor-authorization-state": proof.authorization_state.raw,
                "predecessor-failure-evidence": proof.failure_evidence.raw,
                "predecessor-containment": proof.containment.raw,
                "predecessor-allocation-ledger": proof.allocation_ledger.raw,
                "predecessor-allocation-audit": proof.allocation_audit_bytes,
                "predecessor-outer-authority": proof.outer_authority.raw,
                "predecessor-independent-validation-receipt": (
                    proof.independent_validation_receipt.raw
                ),
                "predecessor-authorization-cause-evidence": (
                    proof.authorization_cause_evidence
                ),
                "ancestor-authorization": proof.ancestor.authorization.raw,
                "ancestor-manifest": proof.ancestor.manifest.raw,
                "ancestor-authorization-state": proof.ancestor.authorization_state.raw,
                "ancestor-failure-evidence": proof.ancestor.failure_evidence.raw,
                "ancestor-original-containment": proof.ancestor.original_containment.raw,
                "ancestor-containment": proof.ancestor.containment.raw,
                "ancestor-allocation-ledger": proof.ancestor.allocation_ledger.raw,
                "ancestor-allocation-audit": proof.ancestor.allocation_audit_bytes,
            }
        )
        if inputs.recovery_cause_evidence is not None:
            expected["cause-evidence"] = inputs.recovery_cause_evidence.raw
        if inputs.recovery_cause_source_analysis_bytes is not None:
            expected["cause-source-analysis"] = (
                inputs.recovery_cause_source_analysis_bytes
            )
    elif legacy is not None:
        expected.update(
            {
                "predecessor-authorization": legacy.authorization.raw,
                "predecessor-manifest": legacy.manifest.raw,
                "predecessor-authorization-state": legacy.authorization_state.raw,
                "predecessor-failure-evidence": legacy.failure_evidence.raw,
                "predecessor-original-containment": legacy.original_containment.raw,
                "predecessor-containment": legacy.containment.raw,
                "predecessor-allocation-ledger": legacy.allocation_ledger.raw,
                "predecessor-allocation-audit": legacy.allocation_audit_bytes,
                "cause-evidence": legacy.cause_evidence,
            }
        )
    for label, snapshot in expected.items():
        path = paths.get(label)
        if path is None or load_private_bytes(path, label) != snapshot:
            raise AppServerError(f"{label}-changed-before-allocation")
    require_trusted_session_snapshots_unchanged(paths, inputs)
    for label, expected_identity in inputs.source_identities.items():
        path = paths.get(label)
        if path is None:
            raise AppServerError(f"{label}-path-missing")
        try:
            info = path.stat()
        except OSError as exc:
            raise AppServerError(f"{label}-source-identity-unavailable") from exc
        if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != tuple(
            expected_identity
        ):
            raise AppServerError(f"{label}-source-identity-changed")


def _capture_session_snapshot(
    raw: bytes,
    session_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not raw or not raw.endswith(b"\n"):
        raise AppServerError("spark-validation-session-telemetry-invalid")
    records: list[dict[str, Any]] = []
    try:
        for line in raw.splitlines(keepends=True):
            if not line.strip():
                continue
            value = json.loads(line.decode("utf-8"))
            if not isinstance(value, dict):
                raise AppServerError("spark-validation-session-telemetry-invalid")
            explicit = value.get("session_id")
            if isinstance(explicit, str) and explicit and explicit != session_id:
                raise AppServerError("spark-validation-session-telemetry-invalid")
            records.append(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppServerError("spark-validation-session-telemetry-invalid") from exc
    identities = {
        str(payload[field])
        for record in records
        if record.get("type") == "session_meta"
        and isinstance((payload := record.get("payload")), Mapping)
        for field in ("id", "session_id")
        if isinstance(payload.get(field), str) and payload.get(field)
    }
    identities.update(
        str(record["session_id"])
        for record in records
        if isinstance(record.get("session_id"), str) and record.get("session_id")
    )
    if not records or identities != {session_id}:
        raise AppServerError("spark-validation-session-telemetry-invalid")
    return (
        {
            "record_count": len(records),
            "byte_offset": len(raw),
            "boundary_sha256": sha256_bytes(raw),
        },
        records,
    )


def validate_independent_validation_session(
    receipt: Mapping[str, Any],
    session_path: Path,
    *,
    codex_home: Path | None = None,
) -> str:
    raw = load_trusted_session_bytes(
        Path(session_path), "spark-validation-session"
    )
    return validate_independent_validation_session_snapshot(
        receipt,
        session_path,
        raw,
        codex_home=codex_home,
    )


def validate_independent_validation_session_snapshot(
    receipt: Mapping[str, Any],
    session_path: Path,
    session_raw: bytes,
    *,
    codex_home: Path | None = None,
) -> str:
    session_id = receipt.get("session_id")
    turn_id = receipt.get("submission_id")
    if not isinstance(session_id, str) or not isinstance(turn_id, str):
        raise AppServerError("spark-validation-session-identity-invalid")
    supplied_path = Path(session_path)
    lexical_path = supplied_path.absolute()
    try:
        resolved_path = supplied_path.resolve(strict=True)
    except OSError as exc:
        raise AppServerError("spark-validation-session-path-invalid") from exc
    if supplied_path.is_symlink() or lexical_path != resolved_path:
        raise AppServerError("spark-validation-session-path-invalid")
    path = resolved_path
    trusted_home = (
        codex_home
        if codex_home is not None
        else Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    ).resolve()
    try:
        relative = path.relative_to(trusted_home)
    except ValueError as exc:
        raise AppServerError("spark-validation-session-path-invalid") from exc
    if (
        len(relative.parts) != 2
        or relative.parts[0] != "archived_sessions"
        or session_id not in relative.name
    ):
        raise AppServerError("spark-validation-session-path-invalid")
    if not session_raw:
        raise AppServerError("spark-validation-session-file-empty")
    boundary_value = receipt.get("boundary")
    expected_terminal = (
        boundary_value.get("terminal") if isinstance(boundary_value, Mapping) else None
    )
    if not isinstance(expected_terminal, Mapping):
        raise AppServerError("spark-validation-session-boundary-invalid")
    try:
        observed_boundary, records = _capture_session_snapshot(session_raw, session_id)
        context_index, _context = trusted_turn_context(
            records,
            turn_id=turn_id,
            model=EXACT_MODEL,
            effort="low",
        )
        markers = telemetry_markers(records, turn_id=turn_id)
        terminal = trusted_terminal_event(records, turn_id=turn_id)
    except (OSError, NativeSessionBoundaryError) as exc:
        raise AppServerError("spark-validation-session-telemetry-invalid") from exc
    if (
        sha256_text(str(path)) != expected_terminal.get("path_sha256")
        or any(
            observed_boundary.get(field) != expected_terminal.get(field)
            for field in ("record_count", "byte_offset", "boundary_sha256")
        )
        or expected_terminal.get("invalid_record_count") != 0
        or expected_terminal.get("trailing_partial") is not False
        or sha256_bytes(session_raw) != observed_boundary.get("boundary_sha256")
        or markers.get("compaction_indices")
        or markers.get("reroute_indices")
        or not isinstance(terminal, Mapping)
        or terminal.get("status") != "completed"
    ):
        raise AppServerError("spark-validation-session-boundary-mismatch")
    session_meta_indices: list[int] = []
    turn_context_indices: list[int] = []
    start_indices: list[int] = []
    terminal_indices: list[int] = []
    agent_messages: list[tuple[int, str]] = []
    assistant_messages: list[tuple[int, str]] = []
    for index, record in enumerate(records):
        record_type = record.get("type")
        payload = record.get("payload")
        if record_type not in INDEPENDENT_VALIDATION_RECORD_TYPES or not isinstance(
            payload, Mapping
        ):
            raise AppServerError("spark-validation-session-activity-invalid")
        payload_type = payload.get("type")
        if record_type in {"session_meta", "world_state", "turn_context"}:
            if payload_type is not None:
                raise AppServerError("spark-validation-session-activity-invalid")
            if record_type == "session_meta":
                session_meta_indices.append(index)
            elif record_type == "turn_context":
                turn_context_indices.append(index)
            continue
        if record_type == "event_msg":
            if payload_type not in INDEPENDENT_VALIDATION_EVENT_TYPES:
                raise AppServerError("spark-validation-session-activity-invalid")
            lifecycle_turn_id = payload.get("turn_id")
            if payload_type in {"task_started", "task_complete"}:
                if lifecycle_turn_id != turn_id:
                    raise AppServerError("spark-validation-session-activity-invalid")
                target = start_indices if payload_type == "task_started" else terminal_indices
                target.append(index)
            if payload_type == "agent_message":
                message = payload.get("message")
                if payload.get("phase") != "final_answer" or not isinstance(message, str):
                    raise AppServerError("spark-validation-session-activity-invalid")
                agent_messages.append((index, message))
            continue
        if payload_type not in INDEPENDENT_VALIDATION_RESPONSE_TYPES:
            raise AppServerError("spark-validation-session-activity-invalid")
        if payload_type == "reasoning":
            continue
        role = payload.get("role")
        if role not in INDEPENDENT_VALIDATION_MESSAGE_ROLES:
            raise AppServerError("spark-validation-session-activity-invalid")
        if role != "assistant":
            continue
        content = payload.get("content")
        if payload.get("phase") != "final_answer" or not isinstance(content, list):
            raise AppServerError("spark-validation-session-activity-invalid")
        output_texts = [
            str(item["text"])
            for item in content
            if isinstance(item, Mapping)
            and item.get("type") == "output_text"
            and isinstance(item.get("text"), str)
        ]
        if len(output_texts) != 1 or len(content) != 1:
            raise AppServerError("spark-validation-session-activity-invalid")
        assistant_messages.append((index, output_texts[0]))
    if (
        len(session_meta_indices) != 1
        or len(turn_context_indices) != 1
        or turn_context_indices[0] != context_index
        or len(start_indices) != 1
        or len(terminal_indices) != 1
        or len(agent_messages) != 1
        or len(assistant_messages) != 1
    ):
        raise AppServerError("spark-validation-session-activity-invalid")
    start_index = start_indices[0]
    terminal_index = terminal_indices[0]
    agent_index, agent_text = agent_messages[0]
    assistant_index, final_text = assistant_messages[0]
    if not (
        session_meta_indices[0] == 0
        and start_index == 1
        and terminal_index == len(records) - 1
        and start_index < context_index < agent_index < assistant_index < terminal_index
    ) or agent_text != final_text:
        raise AppServerError("spark-validation-session-activity-invalid")
    try:
        final_opinion = json.loads(final_text)
    except json.JSONDecodeError as exc:
        raise AppServerError("spark-validation-session-final-json-invalid") from exc
    if (
        sha256_text(final_text) != receipt.get("final_response_sha256")
        or final_opinion != receipt.get("opinion")
    ):
        raise AppServerError("spark-validation-session-final-binding-mismatch")
    return str(observed_boundary["boundary_sha256"])


def guarded_diff_sha256(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "diff", "--binary"],
            cwd=repo_root,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise AppServerError("guarded-primary-diff-unavailable") from exc
    return sha256_bytes(completed.stdout)


def campaign_output_paths(
    output: Path,
    manifest: Mapping[str, Any],
    *,
    authorization_state: Path | None,
    steering_registry: Path | None,
) -> tuple[Path, Path, Path]:
    outputs = manifest.get("outputs")
    if not isinstance(outputs, Mapping):
        raise AppServerError("campaign-manifest-outputs-invalid")
    if output.name != outputs.get("evidence_basename"):
        raise AppServerError("campaign-output-basename-mismatch")
    state_path = (
        authorization_state.absolute()
        if authorization_state is not None
        else output.parent / str(outputs.get("authorization_state_basename"))
    )
    registry_path = (
        steering_registry.absolute()
        if steering_registry is not None
        else output.parent / str(outputs.get("steering_registry_basename"))
    )
    ledger_path = output.parent / str(outputs.get("allocation_ledger_basename"))
    expected = {
        state_path.name: outputs.get("authorization_state_basename"),
        registry_path.name: outputs.get("steering_registry_basename"),
        ledger_path.name: outputs.get("allocation_ledger_basename"),
    }
    if any(actual != declared for actual, declared in expected.items()):
        raise AppServerError("campaign-output-path-mismatch")
    if len({output, state_path, registry_path, ledger_path}) != 4:
        raise AppServerError("campaign-output-path-collision")
    return state_path, registry_path, ledger_path


def validate_campaign_launch_bindings(
    *,
    inputs: CampaignLaunchInputs,
    guarded_primary: Path,
) -> dict[str, Any]:
    authorization = dict(inputs.authorization.value)
    manifest = dict(inputs.manifest.value)
    outer_authority = dict(inputs.outer_authority.value)
    pre_mutation_receipt = dict(inputs.pre_mutation_receipt.value)
    pre_live_receipt = dict(inputs.pre_live_receipt.value)
    opus_review_evidence = dict(inputs.opus_review_evidence.value)
    opus_adjudication = dict(inputs.opus_adjudication.value)
    spark_validation_receipt = dict(inputs.spark_validation_receipt.value)
    spark_validation_session_file_sha256 = validate_independent_validation_session_snapshot(
        spark_validation_receipt,
        inputs.spark_validation_session_path,
        inputs.spark_validation_session_bytes,
    )
    primary_diff_sha256 = guarded_diff_sha256(guarded_primary)
    validator_sha256 = validator_contract_sha256(
        ROOT, manifest.get("candidate", {}).get("tree")
    )
    common_manifest_kwargs = {
        "authorization": authorization,
        "authorization_raw_sha256": inputs.authorization.raw_sha256,
        "outer_authority": outer_authority,
        "outer_authority_raw_sha256": inputs.outer_authority.raw_sha256,
        "independent_validation_receipt": spark_validation_receipt,
        "independent_validation_receipt_raw_sha256": (
            inputs.spark_validation_receipt.raw_sha256
        ),
        "repo_root": ROOT,
        "expected_primary_diff_sha256": primary_diff_sha256,
    }
    predecessor_bindings: dict[str, Any]
    if manifest.get("version") == 3:
        errors = validate_campaign_manifest(
            manifest,
            predecessor_proof=inputs.predecessor_proof,
            recovery_cause_evidence=inputs.recovery_cause_evidence,
            recovery_cause_source_analysis=(
                inputs.recovery_cause_source_analysis_bytes
            ),
            expected_validator_contract_sha256=validator_sha256,
            **common_manifest_kwargs,
        )
        proof = inputs.predecessor_proof
        cause = inputs.recovery_cause_evidence
        if (
            proof is None
            or cause is None
            or inputs.legacy_predecessor is not None
        ):
            raise AppServerError("campaign-modern-proof-input-invalid")
        predecessor_bindings = {
            "predecessor_authorization_file_sha256": proof.authorization.raw_sha256,
            "predecessor_manifest_file_sha256": proof.manifest.raw_sha256,
            "predecessor_authorization_state_file_sha256": (
                proof.authorization_state.raw_sha256
            ),
            "predecessor_failure_evidence_file_sha256": proof.failure_evidence.raw_sha256,
            "predecessor_containment_file_sha256": proof.containment.raw_sha256,
            "predecessor_allocation_ledger_file_sha256": proof.allocation_ledger.raw_sha256,
            "predecessor_allocation_audit_file_sha256": sha256_bytes(
                proof.allocation_audit_bytes
            ),
            "predecessor_outer_authority_file_sha256": proof.outer_authority.raw_sha256,
            "predecessor_independent_validation_receipt_file_sha256": (
                proof.independent_validation_receipt.raw_sha256
            ),
            "predecessor_independent_validation_session_file_sha256": sha256_bytes(
                proof.independent_validation_session_bytes
            ),
            "predecessor_authorization_cause_evidence_file_sha256": sha256_bytes(
                proof.authorization_cause_evidence
            ),
            "predecessor_contained_session_file_sha256s": [
                sha256_bytes(raw) for raw in proof.contained_session_bytes
            ],
            "recovery_cause_evidence_file_sha256": cause.raw_sha256,
            "recovery_cause_source_analysis_file_sha256": sha256_bytes(
                inputs.recovery_cause_source_analysis_bytes or b""
            ),
            "cause_evidence_file_sha256": cause.raw_sha256,
            "ancestor_authorization_file_sha256": proof.ancestor.authorization.raw_sha256,
            "ancestor_manifest_file_sha256": proof.ancestor.manifest.raw_sha256,
            "ancestor_authorization_state_file_sha256": (
                proof.ancestor.authorization_state.raw_sha256
            ),
            "ancestor_failure_evidence_file_sha256": proof.ancestor.failure_evidence.raw_sha256,
            "ancestor_original_containment_file_sha256": (
                proof.ancestor.original_containment.raw_sha256
            ),
            "ancestor_containment_file_sha256": proof.ancestor.containment.raw_sha256,
            "ancestor_allocation_ledger_file_sha256": (
                proof.ancestor.allocation_ledger.raw_sha256
            ),
            "ancestor_allocation_audit_file_sha256": sha256_bytes(
                proof.ancestor.allocation_audit_bytes
            ),
            "ancestor_contained_session_file_sha256s": [
                sha256_bytes(raw)
                for raw in proof.ancestor.contained_session_bytes
            ],
            "ancestor_cause_evidence_file_sha256": sha256_bytes(
                proof.ancestor.cause_evidence
            ),
            "validator_contract_sha256": validator_sha256,
        }
    else:
        proof = inputs.legacy_predecessor
        if (
            proof is None
            or inputs.predecessor_proof is not None
            or inputs.recovery_cause_evidence is not None
        ):
            raise AppServerError("campaign-legacy-proof-input-invalid")
        errors = validate_campaign_manifest(
            manifest,
            predecessor_authorization=proof.authorization.value,
            predecessor_authorization_raw_sha256=proof.authorization.raw_sha256,
            predecessor_manifest=proof.manifest.value,
            predecessor_manifest_raw_sha256=proof.manifest.raw_sha256,
            predecessor_authorization_state=proof.authorization_state.value,
            predecessor_authorization_state_raw_sha256=(
                proof.authorization_state.raw_sha256
            ),
            predecessor_failure_evidence=proof.failure_evidence.value,
            predecessor_failure_evidence_raw_sha256=proof.failure_evidence.raw_sha256,
            predecessor_original_containment=proof.original_containment.value,
            predecessor_original_containment_raw_sha256=(
                proof.original_containment.raw_sha256
            ),
            predecessor_containment=proof.containment.value,
            predecessor_containment_raw_sha256=proof.containment.raw_sha256,
            predecessor_allocation_ledger=proof.allocation_ledger.value,
            predecessor_allocation_ledger_raw_sha256=proof.allocation_ledger.raw_sha256,
            predecessor_allocation_audit_raw_sha256=sha256_bytes(
                proof.allocation_audit_bytes
            ),
            predecessor_allocation_audit_bytes=proof.allocation_audit_bytes,
            cause_evidence=proof.cause_evidence,
            **common_manifest_kwargs,
        )
        predecessor_bindings = {
            "predecessor_authorization_file_sha256": proof.authorization.raw_sha256,
            "predecessor_manifest_file_sha256": proof.manifest.raw_sha256,
            "predecessor_authorization_state_file_sha256": (
                proof.authorization_state.raw_sha256
            ),
            "predecessor_failure_evidence_file_sha256": proof.failure_evidence.raw_sha256,
            "predecessor_original_containment_file_sha256": (
                proof.original_containment.raw_sha256
            ),
            "predecessor_containment_file_sha256": proof.containment.raw_sha256,
            "predecessor_allocation_ledger_file_sha256": proof.allocation_ledger.raw_sha256,
            "predecessor_allocation_audit_file_sha256": sha256_bytes(
                proof.allocation_audit_bytes
            ),
            "cause_evidence_file_sha256": sha256_bytes(proof.cause_evidence),
        }
    if errors:
        raise AppServerError("campaign-manifest-invalid:" + ";".join(errors))
    if manifest.get("control_turn_id") != CONTROL_TURN_ID:
        raise AppServerError("campaign-manifest-control-turn-mismatch")
    reviews = manifest["reviews"]
    observed_reviews = {
        "pre_mutation_receipt_canonical_sha256": pre_mutation_receipt.get(
            "canonical_receipt_sha256"
        ),
        "pre_mutation_receipt_file_sha256": inputs.pre_mutation_receipt.raw_sha256,
        "pre_mutation_adjudication_file_sha256": (
            inputs.pre_mutation_adjudication.raw_sha256
        ),
        "opus_evidence_file_sha256": inputs.opus_review_evidence.raw_sha256,
        "opus_adjudication_file_sha256": inputs.opus_adjudication.raw_sha256,
        "spark_validation_receipt_canonical_sha256": spark_validation_receipt.get(
            "canonical_receipt_sha256"
        ),
        "spark_validation_receipt_file_sha256": (
            inputs.spark_validation_receipt.raw_sha256
        ),
        "pre_live_receipt_canonical_sha256": pre_live_receipt.get(
            "canonical_receipt_sha256"
        ),
        "pre_live_receipt_file_sha256": inputs.pre_live_receipt.raw_sha256,
        "pre_live_adjudication_file_sha256": inputs.pre_live_adjudication.raw_sha256,
    }
    if dict(reviews) != observed_reviews:
        raise AppServerError("campaign-manifest-review-binding-mismatch")
    candidate = manifest["candidate"]
    if (
        opus_review_evidence.get("exact_model") != "claude-opus-4-6"
        or opus_review_evidence.get("candidate_commit") != candidate["commit"]
        or opus_review_evidence.get("glm_5_2_used") is not False
        or opus_review_evidence.get("model_synthesis_used") is not False
        or opus_adjudication.get("main_architect_decision") != "go"
        or opus_adjudication.get("candidate_commit") != candidate["commit"]
        or opus_adjudication.get("opus_evidence_file_sha256")
        != observed_reviews["opus_evidence_file_sha256"]
    ):
        raise AppServerError("campaign-opus-review-binding-invalid")
    release_errors = validate_release_patch_result(
        ROOT,
        None,
        manifest,
        patch_bytes=inputs.release_patch_bytes,
    )
    if release_errors:
        raise AppServerError("campaign-release-patch-invalid:" + ";".join(release_errors))
    try:
        policy_document = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("campaign-policy-unreadable") from exc
    pool_policy = (
        policy_document.get("native_supervision_pool")
        if isinstance(policy_document, Mapping)
        else None
    )
    current_policy = {
        "status": pool_policy.get("status") if isinstance(pool_policy, Mapping) else None,
        "cap_two_operative_release": (
            pool_policy.get("cap_two_operative_release")
            if isinstance(pool_policy, Mapping)
            else None
        ),
    }
    if current_policy != manifest["release"]["policy_before"]:
        raise AppServerError("campaign-policy-before-mismatch")
    return {
        "authorization_raw_sha256": inputs.authorization.raw_sha256,
        "manifest_file_sha256": inputs.manifest.raw_sha256,
        "manifest_sha256": manifest["manifest_sha256"],
        "candidate_commit": candidate["commit"],
        "candidate_tree": candidate["tree"],
        "origin_main_commit": candidate["origin_main_commit"],
        "guarded_primary_diff_sha256": primary_diff_sha256,
        "release_patch_sha256": manifest["release"]["patch_file_sha256"],
        "release_prospective_tree": manifest["release"]["prospective_tree"],
        "outer_authority_file_sha256": inputs.outer_authority.raw_sha256,
        **predecessor_bindings,
        "spark_validation_session_file_sha256": spark_validation_session_file_sha256,
        "spark_validation_receipt_file_sha256": observed_reviews[
            "spark_validation_receipt_file_sha256"
        ],
        "opus_evidence_file_sha256": observed_reviews["opus_evidence_file_sha256"],
        "opus_adjudication_file_sha256": observed_reviews[
            "opus_adjudication_file_sha256"
        ],
    }


def campaign_launch_claim_sha256(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> str:
    """Bind one authorization and all immutable launch inputs to one claim."""

    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    outer = inputs.outer_authority.value
    spark = inputs.spark_validation_receipt.value
    declared_outputs = manifest.get("outputs")
    if not isinstance(declared_outputs, Mapping):
        raise AppServerError("campaign-launch-claim-outputs-invalid")
    output_basenames = {
        "evidence_basename": output.name,
        "authorization_state_basename": authorization_state.name,
        "steering_registry_basename": steering_registry.name,
        "allocation_ledger_basename": allocation_ledger.name,
    }
    if output_basenames != dict(declared_outputs):
        raise AppServerError("campaign-launch-claim-outputs-mismatch")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-launch-claim-authorization-invalid")
    claim = {
        "claim_type": "cwo-native-live-campaign-launch-claim",
        "version": 1,
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "raw_sha256": inputs.authorization.raw_sha256,
            "canonical_sha256": authorization.get(
                "canonical_authorization_sha256"
            ),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get(
                "predecessor_live_generation"
            ),
            "campaign_nonce": bindings.get("campaign_nonce"),
        },
        "manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "raw_sha256": inputs.manifest.raw_sha256,
            "canonical_sha256": manifest.get("manifest_sha256"),
        },
        "outer_authority": {
            "authority_id": outer.get("authority_id"),
            "raw_sha256": inputs.outer_authority.raw_sha256,
            "canonical_sha256": outer.get("canonical_outer_authority_sha256"),
        },
        "spark_validation": {
            "receipt_raw_sha256": inputs.spark_validation_receipt.raw_sha256,
            "receipt_canonical_sha256": spark.get("canonical_receipt_sha256"),
            "session_id": spark.get("session_id"),
            "session_file_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
        },
        "successor_proof": {
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
                if inputs.recovery_cause_evidence is not None
                else None
            ),
            "recovery_cause_source_analysis_sha256": (
                sha256_bytes(inputs.recovery_cause_source_analysis_bytes)
                if isinstance(inputs.recovery_cause_source_analysis_bytes, bytes)
                else None
            ),
            "predecessor_contained_session_sha256s": (
                [
                    sha256_bytes(raw)
                    for raw in inputs.predecessor_proof.contained_session_bytes
                ]
                if inputs.predecessor_proof is not None
                else []
            ),
            "ancestor_contained_session_sha256s": (
                [
                    sha256_bytes(raw)
                    for raw in inputs.predecessor_proof.ancestor.contained_session_bytes
                ]
                if inputs.predecessor_proof is not None
                else []
            ),
        },
        "steering": {
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_mutation_receipt_canonical_sha256": (
                inputs.pre_mutation_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "pre_live_receipt_canonical_sha256": inputs.pre_live_receipt.value.get(
                "canonical_receipt_sha256"
            ),
        },
        "output_basenames": output_basenames,
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }
    return domain_sha256(claim, domain="native-live-campaign-launch-claim")


def safe_allocation_ledger_summary(
    ledger: NativeLiveAllocationLedgerStore | None,
) -> dict[str, Any] | None:
    if ledger is None:
        return None
    try:
        return {"available": True, **ledger.summary()}
    except Exception as exc:
        return {
            "available": False,
            "summary_error_sha256": sha256_text(f"{type(exc).__name__}:{exc}"),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--campaign-manifest", type=Path, required=True)
    parser.add_argument("--outer-authority", type=Path, required=True)
    parser.add_argument("--predecessor-authorization", type=Path, required=True)
    parser.add_argument("--predecessor-manifest", type=Path, required=True)
    parser.add_argument("--predecessor-authorization-state", type=Path, required=True)
    parser.add_argument("--predecessor-failure-evidence", type=Path, required=True)
    parser.add_argument("--predecessor-original-containment", type=Path)
    parser.add_argument("--predecessor-containment", type=Path, required=True)
    parser.add_argument("--predecessor-allocation-ledger", type=Path, required=True)
    parser.add_argument("--predecessor-allocation-audit", type=Path, required=True)
    parser.add_argument("--predecessor-outer-authority", type=Path)
    parser.add_argument("--predecessor-independent-validation-receipt", type=Path)
    parser.add_argument("--predecessor-independent-validation-session", type=Path)
    parser.add_argument("--predecessor-authorization-cause-evidence", type=Path)
    parser.add_argument(
        "--predecessor-contained-session", type=Path, action="append"
    )
    parser.add_argument("--ancestor-authorization", type=Path)
    parser.add_argument("--ancestor-manifest", type=Path)
    parser.add_argument("--ancestor-authorization-state", type=Path)
    parser.add_argument("--ancestor-failure-evidence", type=Path)
    parser.add_argument("--ancestor-original-containment", type=Path)
    parser.add_argument("--ancestor-containment", type=Path)
    parser.add_argument("--ancestor-allocation-ledger", type=Path)
    parser.add_argument("--ancestor-allocation-audit", type=Path)
    parser.add_argument("--ancestor-contained-session", type=Path, action="append")
    parser.add_argument("--cause-evidence", type=Path, required=True)
    parser.add_argument("--cause-source-analysis", type=Path)
    parser.add_argument("--guarded-primary", type=Path, required=True)
    parser.add_argument("--release-patch", type=Path, required=True)
    parser.add_argument("--pre-mutation-steering-receipt", type=Path, required=True)
    parser.add_argument("--pre-mutation-adjudication", type=Path, required=True)
    parser.add_argument("--opus-review-evidence", type=Path, required=True)
    parser.add_argument("--opus-adjudication", type=Path, required=True)
    parser.add_argument("--spark-validation-receipt", type=Path, required=True)
    parser.add_argument("--spark-validation-session", type=Path, required=True)
    parser.add_argument("--pre-live-steering-receipt", type=Path, required=True)
    parser.add_argument("--pre-live-adjudication", type=Path, required=True)
    parser.add_argument("--campaign-nonce", required=True)
    parser.add_argument("--authorization-state", type=Path)
    parser.add_argument("--steering-registry", type=Path)
    args = parser.parse_args()
    output = Path(args.output).absolute()
    started_at = utc_now()
    server: AppServer | None = None
    authorization_store: CanaryAuthorizationStore | None = None
    authorization_state: dict[str, Any] | None = None
    steering_consumptions: dict[str, str] = {}
    allocation_ledger: NativeLiveAllocationLedgerStore | None = None
    artifact_bindings: dict[str, Any] = {}
    manifest: dict[str, Any] | None = None
    try:
        try:
            uuid.UUID(args.campaign_nonce)
        except ValueError as exc:
            raise AppServerError("campaign-nonce-invalid") from exc
        path_arguments: dict[str, Path] = {
            "authorization": args.authorization,
            "campaign-manifest": args.campaign_manifest,
            "outer-authority": args.outer_authority,
            "predecessor-authorization": args.predecessor_authorization,
            "predecessor-manifest": args.predecessor_manifest,
            "predecessor-authorization-state": args.predecessor_authorization_state,
            "predecessor-failure-evidence": args.predecessor_failure_evidence,
            "predecessor-containment": args.predecessor_containment,
            "predecessor-allocation-ledger": args.predecessor_allocation_ledger,
            "predecessor-allocation-audit": args.predecessor_allocation_audit,
            "cause-evidence": args.cause_evidence,
            "release-patch": args.release_patch,
            "pre-mutation-steering-receipt": args.pre_mutation_steering_receipt,
            "pre-mutation-adjudication": args.pre_mutation_adjudication,
            "opus-review-evidence": args.opus_review_evidence,
            "opus-adjudication": args.opus_adjudication,
            "spark-validation-receipt": args.spark_validation_receipt,
            "spark-validation-session": args.spark_validation_session,
            "pre-live-steering-receipt": args.pre_live_steering_receipt,
            "pre-live-adjudication": args.pre_live_adjudication,
        }
        optional_arguments = {
            "predecessor-original-containment": args.predecessor_original_containment,
            "predecessor-outer-authority": args.predecessor_outer_authority,
            "predecessor-independent-validation-receipt": (
                args.predecessor_independent_validation_receipt
            ),
            "predecessor-independent-validation-session": (
                args.predecessor_independent_validation_session
            ),
            "predecessor-authorization-cause-evidence": (
                args.predecessor_authorization_cause_evidence
            ),
            "ancestor-authorization": args.ancestor_authorization,
            "ancestor-manifest": args.ancestor_manifest,
            "ancestor-authorization-state": args.ancestor_authorization_state,
            "ancestor-failure-evidence": args.ancestor_failure_evidence,
            "ancestor-original-containment": args.ancestor_original_containment,
            "ancestor-containment": args.ancestor_containment,
            "ancestor-allocation-ledger": args.ancestor_allocation_ledger,
            "ancestor-allocation-audit": args.ancestor_allocation_audit,
            "cause-source-analysis": args.cause_source_analysis,
        }
        path_arguments.update(
            {
                label: path
                for label, path in optional_arguments.items()
                if path is not None
            }
        )
        path_arguments.update(
            {
                f"predecessor-contained-session-{index}": path
                for index, path in enumerate(
                    args.predecessor_contained_session or []
                )
            }
        )
        path_arguments.update(
            {
                f"ancestor-contained-session-{index}": path
                for index, path in enumerate(args.ancestor_contained_session or [])
            }
        )
        paths = require_unique_input_paths(path_arguments)
        source_identities = capture_input_source_identities(paths)
        for label, path in paths.items():
            if campaign_input_requires_private_parent(label):
                require_private_parent(path, label)

        authorization_snapshot = load_private_json_snapshot(
            paths["authorization"], "authorization"
        )
        manifest_snapshot = load_private_json_snapshot(
            paths["campaign-manifest"], "campaign-manifest"
        )
        authorization = dict(authorization_snapshot.value)
        manifest = dict(manifest_snapshot.value)
        version = authorization.get("version")
        if version not in {5, 6}:
            raise AppServerError("authorization-contract-version-invalid")
        if manifest.get("version") != (3 if version == 6 else 2):
            raise AppServerError("campaign-contract-version-mismatch")
        modern_labels = {
            "predecessor-outer-authority",
            "predecessor-independent-validation-receipt",
            "predecessor-independent-validation-session",
            "predecessor-authorization-cause-evidence",
            "ancestor-authorization",
            "ancestor-manifest",
            "ancestor-authorization-state",
            "ancestor-failure-evidence",
            "ancestor-original-containment",
            "ancestor-containment",
            "ancestor-allocation-ledger",
            "ancestor-allocation-audit",
            "cause-source-analysis",
        }
        if version == 6:
            if (
                "predecessor-original-containment" in paths
                or not modern_labels.issubset(paths)
                or not args.predecessor_contained_session
                or not args.ancestor_contained_session
            ):
                raise AppServerError("campaign-modern-proof-path-set-invalid")
        elif (
            "predecessor-original-containment" not in paths
            or modern_labels.intersection(paths)
            or args.predecessor_contained_session
            or args.ancestor_contained_session
        ):
            raise AppServerError("campaign-legacy-proof-path-set-invalid")

        predecessor_common = {
            label: load_private_json_snapshot(paths[label], label)
            for label in (
                "predecessor-authorization",
                "predecessor-manifest",
                "predecessor-authorization-state",
                "predecessor-failure-evidence",
                "predecessor-containment",
                "predecessor-allocation-ledger",
            )
        }
        predecessor_audit_bytes = load_private_bytes(
            paths["predecessor-allocation-audit"],
            "predecessor-allocation-audit",
        )
        legacy_predecessor: HistoricalV4V1ProofInputs | None = None
        predecessor_proof: Version5PredecessorProofInputs | None = None
        recovery_cause_evidence: JsonArtifactSnapshot | None = None
        recovery_cause_source_analysis_bytes: bytes | None = None
        if version == 6:
            authorization_cause_evidence = load_private_bytes(
                paths["predecessor-authorization-cause-evidence"],
                "predecessor-authorization-cause-evidence",
            )
            ancestor = HistoricalV4V1ProofInputs(
                authorization=load_private_json_snapshot(
                    paths["ancestor-authorization"], "ancestor-authorization"
                ),
                manifest=load_private_json_snapshot(
                    paths["ancestor-manifest"], "ancestor-manifest"
                ),
                authorization_state=load_private_json_snapshot(
                    paths["ancestor-authorization-state"],
                    "ancestor-authorization-state",
                ),
                failure_evidence=load_private_json_snapshot(
                    paths["ancestor-failure-evidence"],
                    "ancestor-failure-evidence",
                ),
                original_containment=load_private_json_snapshot(
                    paths["ancestor-original-containment"],
                    "ancestor-original-containment",
                ),
                containment=load_private_json_snapshot(
                    paths["ancestor-containment"], "ancestor-containment"
                ),
                allocation_ledger=load_private_json_snapshot(
                    paths["ancestor-allocation-ledger"],
                    "ancestor-allocation-ledger",
                ),
                allocation_audit_bytes=load_private_bytes(
                    paths["ancestor-allocation-audit"],
                    "ancestor-allocation-audit",
                ),
                cause_evidence=authorization_cause_evidence,
                contained_session_bytes=tuple(
                    load_trusted_session_bytes(
                        paths[f"ancestor-contained-session-{index}"],
                        f"ancestor-contained-session-{index}",
                    )
                    for index in range(len(args.ancestor_contained_session or []))
                ),
            )
            predecessor_proof = Version5PredecessorProofInputs(
                authorization=predecessor_common["predecessor-authorization"],
                manifest=predecessor_common["predecessor-manifest"],
                authorization_state=predecessor_common[
                    "predecessor-authorization-state"
                ],
                failure_evidence=predecessor_common[
                    "predecessor-failure-evidence"
                ],
                containment=predecessor_common["predecessor-containment"],
                allocation_ledger=predecessor_common[
                    "predecessor-allocation-ledger"
                ],
                allocation_audit_bytes=predecessor_audit_bytes,
                authorization_cause_evidence=authorization_cause_evidence,
                outer_authority=load_private_json_snapshot(
                    paths["predecessor-outer-authority"],
                    "predecessor-outer-authority",
                ),
                independent_validation_receipt=load_private_json_snapshot(
                    paths["predecessor-independent-validation-receipt"],
                    "predecessor-independent-validation-receipt",
                ),
                independent_validation_session_bytes=load_trusted_session_bytes(
                    paths["predecessor-independent-validation-session"],
                    "predecessor-independent-validation-session",
                ),
                ancestor=ancestor,
                contained_session_bytes=tuple(
                    load_trusted_session_bytes(
                        paths[f"predecessor-contained-session-{index}"],
                        f"predecessor-contained-session-{index}",
                    )
                    for index in range(
                        len(args.predecessor_contained_session or [])
                    )
                ),
            )
            recovery_cause_evidence = load_private_json_snapshot(
                paths["cause-evidence"], "cause-evidence"
            )
            recovery_cause_source_analysis_bytes = load_private_bytes(
                paths["cause-source-analysis"], "cause-source-analysis"
            )
        else:
            legacy_predecessor = HistoricalV4V1ProofInputs(
                authorization=predecessor_common["predecessor-authorization"],
                manifest=predecessor_common["predecessor-manifest"],
                authorization_state=predecessor_common[
                    "predecessor-authorization-state"
                ],
                failure_evidence=predecessor_common[
                    "predecessor-failure-evidence"
                ],
                original_containment=load_private_json_snapshot(
                    paths["predecessor-original-containment"],
                    "predecessor-original-containment",
                ),
                containment=predecessor_common["predecessor-containment"],
                allocation_ledger=predecessor_common[
                    "predecessor-allocation-ledger"
                ],
                allocation_audit_bytes=predecessor_audit_bytes,
                cause_evidence=load_private_bytes(
                    paths["cause-evidence"], "cause-evidence"
                ),
            )

        launch_inputs = CampaignLaunchInputs(
            authorization=authorization_snapshot,
            manifest=manifest_snapshot,
            outer_authority=load_private_json_snapshot(
                paths["outer-authority"], "outer-authority"
            ),
            release_patch_bytes=load_private_bytes(
                paths["release-patch"], "release-patch"
            ),
            pre_mutation_receipt=load_private_json_snapshot(
                paths["pre-mutation-steering-receipt"],
                "pre-mutation-steering-receipt",
            ),
            pre_mutation_adjudication=load_private_json_snapshot(
                paths["pre-mutation-adjudication"], "pre-mutation-adjudication"
            ),
            pre_live_receipt=load_private_json_snapshot(
                paths["pre-live-steering-receipt"],
                "pre-live-steering-receipt",
            ),
            pre_live_adjudication=load_private_json_snapshot(
                paths["pre-live-adjudication"], "pre-live-adjudication"
            ),
            opus_review_evidence=load_private_json_snapshot(
                paths["opus-review-evidence"], "opus-review-evidence"
            ),
            opus_adjudication=load_private_json_snapshot(
                paths["opus-adjudication"], "opus-adjudication"
            ),
            spark_validation_receipt=load_private_json_snapshot(
                paths["spark-validation-receipt"], "spark-validation-receipt"
            ),
            spark_validation_session_path=paths["spark-validation-session"],
            spark_validation_session_bytes=load_trusted_session_bytes(
                paths["spark-validation-session"], "spark-validation-session"
            ),
            legacy_predecessor=legacy_predecessor,
            predecessor_proof=predecessor_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis_bytes=(
                recovery_cause_source_analysis_bytes
            ),
            source_identities=source_identities,
        )
        authorization_sha256 = launch_inputs.authorization.raw_sha256
        if version == 6:
            authorization_id, repo_head = validate_full_auto_authorization(
                authorization,
                args.campaign_nonce,
                predecessor_proof=predecessor_proof,
                recovery_cause_evidence=recovery_cause_evidence,
                recovery_cause_source_analysis=(
                    recovery_cause_source_analysis_bytes
                ),
                expected_validator_contract_sha256=validator_contract_sha256(
                    ROOT, authorization.get("bindings", {}).get("checkpoint_tree")
                ),
                repo_root=ROOT,
            )
        else:
            if legacy_predecessor is None:
                raise AppServerError("campaign-legacy-proof-input-invalid")
            authorization_id, repo_head = validate_full_auto_authorization(
                authorization,
                args.campaign_nonce,
                predecessor_authorization=legacy_predecessor.authorization.value,
                predecessor_authorization_raw_sha256=(
                    legacy_predecessor.authorization.raw_sha256
                ),
                predecessor_manifest=legacy_predecessor.manifest.value,
                predecessor_manifest_raw_sha256=legacy_predecessor.manifest.raw_sha256,
                predecessor_authorization_state=legacy_predecessor.authorization_state.value,
                predecessor_authorization_state_raw_sha256=(
                    legacy_predecessor.authorization_state.raw_sha256
                ),
                predecessor_failure_evidence=legacy_predecessor.failure_evidence.value,
                predecessor_failure_evidence_raw_sha256=(
                    legacy_predecessor.failure_evidence.raw_sha256
                ),
                predecessor_original_containment=legacy_predecessor.original_containment.value,
                predecessor_original_containment_raw_sha256=(
                    legacy_predecessor.original_containment.raw_sha256
                ),
                predecessor_containment=legacy_predecessor.containment.value,
                predecessor_containment_raw_sha256=(
                    legacy_predecessor.containment.raw_sha256
                ),
                predecessor_allocation_ledger=legacy_predecessor.allocation_ledger.value,
                predecessor_allocation_ledger_raw_sha256=(
                    legacy_predecessor.allocation_ledger.raw_sha256
                ),
                predecessor_allocation_audit_raw_sha256=sha256_bytes(
                    legacy_predecessor.allocation_audit_bytes
                ),
                predecessor_allocation_audit_bytes=(
                    legacy_predecessor.allocation_audit_bytes
                ),
                cause_evidence=legacy_predecessor.cause_evidence,
                repo_root=ROOT,
            )

        outer_authority = dict(launch_inputs.outer_authority.value)
        pre_mutation_receipt = dict(launch_inputs.pre_mutation_receipt.value)
        pre_live_receipt = dict(launch_inputs.pre_live_receipt.value)
        pre_mutation_adjudication = dict(
            launch_inputs.pre_mutation_adjudication.value
        )
        pre_live_adjudication = dict(launch_inputs.pre_live_adjudication.value)
        opus_review_evidence = dict(launch_inputs.opus_review_evidence.value)
        opus_adjudication = dict(launch_inputs.opus_adjudication.value)
        spark_validation_receipt = dict(
            launch_inputs.spark_validation_receipt.value
        )
        artifact_bindings = validate_campaign_launch_bindings(
            inputs=launch_inputs,
            guarded_primary=args.guarded_primary.absolute(),
        )
        state_path, registry_path, ledger_path = campaign_output_paths(
            output,
            manifest,
            authorization_state=args.authorization_state,
            steering_registry=args.steering_registry,
        )
        if any(path.exists() or path.is_symlink() for path in (output, state_path, registry_path, ledger_path)):
            raise AppServerError("campaign-output-already-exists")
        for label, path in (
            ("campaign-output", output),
            ("authorization-state", state_path),
            ("steering-registry", registry_path),
            ("allocation-ledger", ledger_path),
        ):
            require_private_parent(path, label)
            if path in set(paths.values()):
                raise AppServerError("campaign-output-input-path-collision")
        launch_claim_sha256 = (
            campaign_launch_claim_sha256(
                launch_inputs,
                output=output,
                authorization_state=state_path,
                steering_registry=registry_path,
                allocation_ledger=ledger_path,
            )
            if version == 6
            else None
        )
        if launch_claim_sha256 is not None:
            artifact_bindings["launch_claim_sha256"] = launch_claim_sha256
            acquire_global_campaign_claim(
                launch_inputs,
                launch_claim_sha256=launch_claim_sha256,
                output=output,
                authorization_state=state_path,
                steering_registry=registry_path,
                allocation_ledger=ledger_path,
            )
        authorization_store = CanaryAuthorizationStore(state_path)
        authorization_state = authorization_store.initialize(
            new_authorization_state(
                authorization_id=authorization_id,
                run_nonce=args.campaign_nonce,
                now=iso(),
                launch_claim_sha256=launch_claim_sha256,
            )
        )
        pre_mutation_adjudication_sha256 = (
            launch_inputs.pre_mutation_adjudication.raw_sha256
        )
        pre_live_adjudication_sha256 = (
            launch_inputs.pre_live_adjudication.raw_sha256
        )
        prepared = plan_steering_receipt_consumptions(
            args.campaign_nonce,
            authorization_id,
            authorization_sha256,
            registry_file=registry_path,
            repo_head=repo_head,
            pre_mutation_receipt=pre_mutation_receipt,
            pre_mutation_adjudication=pre_mutation_adjudication,
            pre_mutation_adjudication_sha256=pre_mutation_adjudication_sha256,
            pre_live_receipt=pre_live_receipt,
            pre_live_adjudication=pre_live_adjudication,
            pre_live_adjudication_sha256=pre_live_adjudication_sha256,
        )
        require_repository_checkpoint(ROOT, repo_head)
        for label in ("pre-mutation", "pre-live"):
            _, params = prepared[label]
            if label == "pre-mutation":
                receipt = pre_mutation_receipt
            else:
                receipt = pre_live_receipt
            steering_consumptions[label] = consume_steering_receipt(receipt, registry_path, **params)
        require_repository_checkpoint(ROOT, repo_head)
        active_state = authorization_store.require_action("tracked-mutation")
        if (
            launch_claim_sha256 is not None
            and active_state.get("launch_claim_sha256") != launch_claim_sha256
        ):
            raise AppServerError("campaign-launch-claim-state-mismatch")
        require_launch_source_snapshots_unchanged(paths, launch_inputs)
        refreshed_bindings = validate_campaign_launch_bindings(
            inputs=launch_inputs,
            guarded_primary=args.guarded_primary.absolute(),
        )
        if launch_claim_sha256 is not None:
            refreshed_bindings["launch_claim_sha256"] = (
                campaign_launch_claim_sha256(
                    launch_inputs,
                    output=output,
                    authorization_state=state_path,
                    steering_registry=registry_path,
                    allocation_ledger=ledger_path,
                )
            )
        if refreshed_bindings != artifact_bindings:
            raise AppServerError("campaign-artifact-binding-changed-before-allocation")
        with tempfile.TemporaryDirectory(prefix="cwo-18w6-live-") as temporary:
            temp_root = Path(temporary)
            temp_root.chmod(0o700)
            layout = make_git_layout(temp_root)
            record_dir = temp_root / "capability-records"
            record_dir.mkdir(mode=0o700)
            server = AppServer()
            if (
                server.codex_home.resolve()
                != launch_inputs.spark_validation_session_path.parents[1].resolve()
                or validate_independent_validation_session_snapshot(
                    spark_validation_receipt,
                    launch_inputs.spark_validation_session_path,
                    launch_inputs.spark_validation_session_bytes,
                    codex_home=server.codex_home,
                )
                != artifact_bindings["spark_validation_session_file_sha256"]
            ):
                raise AppServerError(
                    "spark-validation-session-changed-before-allocation"
                )
            discovery = server.model_discovery()
            owner = capture_owner_identity(os.getpid())
            authorization_bindings = authorization.get("bindings")
            if not isinstance(authorization_bindings, Mapping):
                raise AppServerError("allocation-ledger-authorization-bindings-invalid")
            if (
                run_git(ROOT, "rev-parse", "HEAD") != manifest["candidate"]["commit"]
                or run_git(ROOT, "rev-parse", "HEAD^{tree}")
                != manifest["candidate"]["tree"]
                or guarded_diff_sha256(args.guarded_primary.absolute())
                != artifact_bindings["guarded_primary_diff_sha256"]
                or (
                    version == 6
                    and validator_contract_sha256(
                        ROOT, manifest["candidate"]["tree"]
                    )
                    != artifact_bindings["validator_contract_sha256"]
                )
            ):
                raise AppServerError("campaign-watermark-changed-before-allocation")
            require_repository_checkpoint(ROOT, manifest["candidate"]["commit"])
            certification_policy = callback_certification_policy()
            work_units = manifest["work_units"]
            allocation_ledger = NativeLiveAllocationLedgerStore(ledger_path)
            allocation_ledger.initialize(
                {
                    "bead_id": work_units["epic_id"],
                    "work_unit_id": work_units["live_work_unit_id"],
                    "authorization_id": authorization_id,
                    "authorization_raw_sha256": authorization_sha256,
                    "authorization_canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "campaign_manifest_sha256": manifest["manifest_sha256"],
                    "campaign_nonce": args.campaign_nonce,
                    "live_generation": manifest["live_generation"],
                    "predecessor_generation": manifest["predecessor_live_generation"],
                    "candidate_commit": manifest["candidate"]["commit"],
                    "candidate_tree": manifest["candidate"]["tree"],
                    "origin_main_commit": manifest["candidate"]["origin_main_commit"],
                    "guarded_primary_diff_sha256": authorization_bindings[
                        "guarded_primary_diff_sha256"
                    ],
                    "predecessor_containment_sha256": authorization_bindings[
                        "predecessor_containment_canonical_sha256"
                    ],
                    "frozen_release_patch_sha256": artifact_bindings[
                        "release_patch_sha256"
                    ],
                    "pre_mutation_steering_receipt_sha256": pre_mutation_receipt[
                        "canonical_receipt_sha256"
                    ],
                    "pre_live_steering_receipt_sha256": pre_live_receipt[
                        "canonical_receipt_sha256"
                    ],
                    "opus_review_sha256": artifact_bindings[
                        "opus_evidence_file_sha256"
                    ],
                    "certification_policy_sha256": callback_certification_policy_sha256(
                        certification_policy
                    ),
                    "controller_identity": owner,
                    "connection_epoch_sha256": server.connection_epoch_sha256,
                    "retention_class": "private-local-until-bead-closure",
                    "expected_roles": list(EXPECTED_ROLES),
                },
                version=2,
            )
            server.attach_allocation_ledger(allocation_ledger)
            require_launch_source_snapshots_unchanged(paths, launch_inputs)
            if version == 6:
                validate_active_outer_authority(
                    launch_inputs.outer_authority,
                    candidate_commit=manifest["candidate"]["commit"],
                    candidate_tree=manifest["candidate"]["tree"],
                )
            capability, calibration_evidence = calibration(
                server,
                layout["read-shared"],
                record_dir,
                owner,
                run_nonce=authorization_id,
                phase_nonce=args.campaign_nonce,
            )
            allocation_ledger.bind_certification(capability["receipt_sha256"])

            read_prompts = [
                (
                    f"Use exec_command to run `sleep 2`, then use exec_command to run "
                    f"`sha256sum data/shared.txt`. Do not mutate any file. Return exactly "
                    f"READ_ONLY_CHILD_{index}_OK."
                )
                for index in range(2)
            ]
            read_canary = run_pool_canary(
                server,
                capability,
                manifest,
                root=temp_root,
                integration=layout["integration"],
                pool_name="read-only",
                worktrees=[layout["read-shared"], layout["read-shared"]],
                mutable=False,
                prompts=read_prompts,
                expected_tokens=["READ_ONLY_CHILD_0_OK", "READ_ONLY_CHILD_1_OK"],
            )

            mutable_prompts = [
                (
                    f"Use apply_patch to append the exact line `spark-canary-{index}` to "
                    f"targets/child_{index}.txt and do not modify any other file. Then use "
                    f"exec_command to run `sleep 2`. Return exactly MUTABLE_CHILD_{index}_OK."
                )
                for index in range(2)
            ]
            mutable_canary = run_pool_canary(
                server,
                capability,
                manifest,
                root=temp_root,
                integration=layout["integration"],
                pool_name="mutable",
                worktrees=[layout["mutable-0"], layout["mutable-1"]],
                mutable=True,
                prompts=mutable_prompts,
                expected_tokens=["MUTABLE_CHILD_0_OK", "MUTABLE_CHILD_1_OK"],
            )

            interrupt_prompts = [
                (
                    "Use exec_command to run `sleep 20`. After it finishes, return exactly "
                    "INTERRUPT_LONG_UNEXPECTED_COMPLETION. Do not use any other tool."
                ),
                (
                    "Use exec_command to run `sleep 3`. After it finishes, return exactly "
                    "INTERRUPT_PEER_OK. Do not use any other tool."
                ),
            ]
            interrupt_canary = run_pool_canary(
                server,
                capability,
                manifest,
                root=temp_root,
                integration=layout["integration"],
                pool_name="interrupt",
                worktrees=[layout["interrupt-shared"], layout["interrupt-shared"]],
                mutable=False,
                prompts=interrupt_prompts,
                expected_tokens=["INTERRUPT_LONG_UNEXPECTED_COMPLETION", "INTERRUPT_PEER_OK"],
                interrupt_after=[2, None],
            )
            canaries = [read_canary, mutable_canary, interrupt_canary]
            campaign_errors = validate_campaign(capability, calibration_evidence, canaries)
            if campaign_errors:
                raise AppServerError("campaign-validation-failed:" + ";".join(campaign_errors))
            authorization_state = authorization_store.transition(
                "complete", reason="seven-turn-campaign-accepted", now=iso()
            )
            value = seal_artifact(
                {
                    "result_type": "cwo-native-supervision-pool-live-canary-evidence",
                    "version": 1,
                    "bead_id": manifest["work_units"]["epic_id"],
                    "work_unit_id": manifest["work_units"]["live_work_unit_id"],
                    "control_turn_id": manifest["control_turn_id"],
                    "exact_model": EXACT_MODEL,
                    "attestation_source": "trusted-control-plane-session-metadata",
                    "execution_surface": "connected-codex",
                    "app_server_transport": "stdio",
                    "model_discovery": discovery,
                    "started_at": iso(started_at),
                    "completed_at": iso(),
                    "capability_receipt": capability,
                    "capability_calibration": calibration_evidence,
                    "materialization_evidence_sha256": calibration_evidence[
                        "materialization_evidence_sha256"
                    ],
                    "authorization_sha256": authorization_sha256,
                    "authorization_id": authorization_id,
                    "authorization_canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "campaign_manifest_sha256": manifest["manifest_sha256"],
                    "campaign_bindings": artifact_bindings,
                    "run_generation": manifest["run_generation"],
                    "live_generation": manifest["live_generation"],
                    "predecessor_live_generation": manifest[
                        "predecessor_live_generation"
                    ],
                    "authorization_state_sha256": authorization_state["state_sha256"],
                    "steering_consumptions": steering_consumptions,
                    "allocation_ledger": allocation_ledger.summary(),
                    "canaries": canaries,
                    "fresh_session_count": 7,
                    "no_resume_or_salvage": True,
                    "campaign_errors": campaign_errors,
                    "validation_outcome": "accepted",
                    "release_gate_passed": True,
                    "temporary_workspace_disposition": "deleted-after-evidence-capture",
                    "glm_5_2_used": False,
                    "model_synthesis_used": False,
                },
                "evidence_sha256",
            )
            write_private_artifact(output, value)
            print(
                json.dumps(
                    {
                        "release_gate_passed": value["release_gate_passed"],
                        "evidence_sha256": value["evidence_sha256"],
                        "fresh_session_count": value["fresh_session_count"],
                        "campaign_errors": value["campaign_errors"],
                        "observed_check_max_ms": capability["callbacks"]["check"]["max_ms"],
                        "certified_check_max_ms": capability["certification"][
                            "certified_callback_max_ms"
                        ]["check"],
                        "scheduler_inequality_lhs_ms": calibration_evidence[
                            "scheduler_inequality_lhs_ms"
                        ],
                        "canaries": [
                            {
                                "name": item["pool_name"],
                                "accepting": item["receipt"]["accepting"],
                                "disposition": item["receipt"]["pool_disposition"],
                                "elapsed_improvement_ratio": item[
                                    "elapsed_improvement_ratio"
                                ],
                            }
                            for item in canaries
                        ],
                    },
                    sort_keys=True,
                )
            )
            return 0
    except Exception as exc:
        manifest_work_units = (
            manifest.get("work_units")
            if isinstance(manifest, Mapping)
            and isinstance(manifest.get("work_units"), Mapping)
            else {}
        )
        containment = (
            contain_started_threads(server)
            if server is not None
            else {
                "allocated_count": 0,
                "identified_thread_count": 0,
                "interrupted_count": 0,
                "archived_count": 0,
                "already_contained_count": 0,
                "unresolved_allocation_intent_count": 0,
                "unresolved_turn_intent_count": 0,
                "ambiguous_count": 0,
                "all_contained": True,
                "ledger_consistent": True,
                "ledger_error_sha256": [],
            }
        )
        if authorization_store is not None and authorization_state is not None:
            try:
                current = authorization_store.load()
                if current["state"] == "active":
                    authorization_state = authorization_store.transition(
                        "containment-only", reason="evidence-bearing-protected-fault", now=iso()
                    )
                else:
                    authorization_state = current
            except Exception:
                containment["authorization_transition_failed"] = True
        raw_failure = str(exc)
        safe_failure_code = (
            raw_failure
            if raw_failure
            and len(raw_failure) <= 240
            and all(character.isalnum() or character in "-_:;." for character in raw_failure)
            else type(exc).__name__
        )
        failure = seal_artifact(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": (
                    manifest_work_units.get("epic_id")
                ),
                "work_unit_id": (
                    manifest_work_units.get("live_work_unit_id")
                ),
                "control_turn_id": (
                    manifest.get("control_turn_id")
                    if isinstance(manifest, Mapping)
                    else CONTROL_TURN_ID
                ),
                "exact_model": EXACT_MODEL,
                "started_at": iso(started_at),
                "failed_at": iso(),
                "failure_class": type(exc).__name__,
                "failure_code": safe_failure_code,
                "failure_message_sha256": sha256_text(str(exc)),
                "validation_outcome": "rejected",
                "release_gate_passed": False,
                "no_resume_or_salvage": True,
                "containment": containment,
                "authorization_state_sha256": (
                    authorization_state.get("state_sha256")
                    if isinstance(authorization_state, Mapping)
                    else None
                ),
                "steering_consumptions": steering_consumptions,
                "campaign_bindings": artifact_bindings,
                "first_protected_fault": getattr(exc, "first_protected_fault", None),
                "allocation_ledger": safe_allocation_ledger_summary(allocation_ledger),
                "glm_5_2_used": False,
                "model_synthesis_used": False,
            },
            "evidence_sha256",
        )
        failure_persisted = not output.exists() and not output.is_symlink()
        if failure_persisted:
            write_private_artifact(output, failure)
        print(
            json.dumps(
                {
                    "release_gate_passed": False,
                    "failure_class": type(exc).__name__,
                    "failure_code": safe_failure_code,
                    "failure_message_sha256": failure["failure_message_sha256"],
                    "evidence_sha256": failure["evidence_sha256"],
                    "failure_evidence_persisted": failure_persisted,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        if server is not None:
            server.close()


if __name__ == "__main__":
    raise SystemExit(main())
