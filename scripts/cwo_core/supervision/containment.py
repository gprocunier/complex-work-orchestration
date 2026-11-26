"""Staged thread archive and fail-closed native containment."""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Callable, Mapping

from cwo_core.native_turn_dispatch import validate_turn_dispatch_record
from cwo_core.supervision.transport.app_server import (
    AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS,
    AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS,
    AppServer,
    sha256_text,
)
from cwo_core.supervision.transport.errors import (
    AppServerError,
    AppServerRpcError,
)


STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS = 0.05
STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS = 5.0
STAGED_ARCHIVE_TERMINAL_POLL_SECONDS = 0.05


class StagedThreadArchive:
    """Issue one archive RPC off-callback and expose a bounded close check."""

    def __init__(
        self,
        server: AppServer,
        thread_id: str,
        *,
        prepare: Callable[[], None] | None = None,
        after_archive: Callable[[float], None] | None = None,
    ) -> None:
        self.server = server
        self.thread_id = thread_id
        self.prepare = prepare
        self.after_archive = after_archive
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._started = False
        self._error: BaseException | None = None
        self._rpc_latency_ms: float | None = None

    def _run(self) -> None:
        try:
            if self.prepare is not None:
                self.prepare()
            latency = self.server.archive_thread(self.thread_id)
            if (
                not isinstance(latency, (int, float))
                or isinstance(latency, bool)
                or not math.isfinite(float(latency))
                or float(latency) < 0
            ):
                raise AppServerError("staged-archive-latency-invalid")
            proof_reader = getattr(self.server, "archive_acceptance_proof", None)
            if callable(proof_reader) and proof_reader(self.thread_id) is None:
                raise AppServerError("staged-archive-acceptance-proof-missing")
            self._rpc_latency_ms = float(latency)
            if self.after_archive is not None:
                self.after_archive(self._rpc_latency_ms)
        except BaseException as exc:
            self._error = exc
        finally:
            self._done.set()

    def start(self) -> None:
        with self._lock:
            if self._started:
                raise AppServerError("staged-archive-already-started")
            register = getattr(self.server, "register_staged_archive", None)
            if callable(register):
                register(self.thread_id, self)
            self._started = True
            threading.Thread(
                target=self._run,
                name=f"cwo-archive-{sha256_text(self.thread_id)[:12]}",
                daemon=True,
            ).start()

    def require_complete(
        self,
        *,
        timeout_seconds: float = STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS,
    ) -> float:
        if not self._started:
            raise AppServerError("staged-archive-not-started")
        if not self._done.wait(timeout=max(0.0, timeout_seconds)):
            raise AppServerError("staged-archive-not-complete-after-cooperative-wait")
        if self._error is not None:
            if isinstance(self._error, Exception):
                raise self._error
            raise AppServerError(
                f"staged-archive-failed:{type(self._error).__name__}"
            )
        if self._rpc_latency_ms is None:
            raise AppServerError("staged-archive-latency-missing")
        return self._rpc_latency_ms

    def completion_ready(self) -> bool:
        """Return whether the single staged request has reached a terminal result."""

        if not self._started:
            raise AppServerError("staged-archive-not-started")
        return self._done.is_set()

    def telemetry(self) -> dict[str, Any]:
        return {
            "mode": "cooperative-staged-single-request",
            "started": self._started,
            "completed": self._done.is_set() and self._error is None,
            "rpc_latency_ms": (
                round(self._rpc_latency_ms, 3)
                if self._rpc_latency_ms is not None
                else None
            ),
            "error_type": (
                type(self._error).__name__ if self._error is not None else None
            ),
        }


def contain_started_threads(
    server: AppServer,
    *,
    allow_same_process_proofs: bool = False,
    delete_proven_never_turned: bool = False,
    failure_diagnostics: list[dict[str, Any]] | None = None,
    containment_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Idempotently prove terminal absence, then contain allocated threads."""

    interrupted: list[str] = []
    archived: list[str] = []
    already_contained: list[str] = []
    ambiguous: list[str] = []
    ledger_errors: list[str] = []
    ledger = getattr(server, "allocation_ledger", None)
    no_pending_turn_intent = allow_same_process_proofs and ledger is None
    if allow_same_process_proofs and ledger is not None:
        try:
            no_pending_turn_intent = (
                int(ledger.summary()["unresolved_turn_intent_count"]) == 0
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))

    def record_failure(
        thread_id: str,
        substep: str,
        exc: Exception,
    ) -> None:
        if failure_diagnostics is None:
            return
        diagnostic: dict[str, Any] = {
            "thread_id_sha256": sha256_text(thread_id),
            "substep": substep,
            "failure_class": type(exc).__name__,
            "failure_message_sha256": sha256_text(str(exc)),
        }
        if isinstance(exc, AppServerRpcError):
            diagnostic.update(
                {
                    "rpc_method": exc.method,
                    "rpc_code": exc.code,
                }
            )
        failure_diagnostics.append(diagnostic)

    for thread_id, record in list(
        getattr(server, "_turn_dispatch_records", {}).items()
    ):
        if not isinstance(record, Mapping):
            ambiguous.append(str(thread_id))
            continue
        errors = validate_turn_dispatch_record(record)
        if errors:
            ambiguous.append(str(thread_id))
            continue
        if record.get("status") in {"dispatching", "failed-ambiguous"}:
            try:
                record = server.contain_ambiguous_turn_dispatch(str(thread_id))
            except Exception:
                ambiguous.append(str(thread_id))
                continue
        if record.get("status") == "failed-ambiguous":
            ambiguous.append(str(thread_id))

    def audit_containment(
        thread_id: str,
        outcome: str,
        status: str | None,
        *,
        local_proof_sha256: str | None = None,
    ) -> bool:
        if ledger is None:
            return True
        try:
            evidence = {
                "thread_id_sha256": sha256_text(thread_id),
                "turn_status": status,
                "outcome": outcome,
            }
            if local_proof_sha256 is not None:
                evidence["same_process_proof_sha256"] = (
                    local_proof_sha256
                )
            ledger.record_containment_audit(
                thread_id,
                outcome=outcome,
                evidence=evidence,
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            return False
        return True

    for thread_id, turn_id in list(server.started_threads.items()):
        dispatch_record = (
            server.turn_dispatch_record(thread_id)
            if hasattr(server, "turn_dispatch_record")
            else None
        )
        if (
            isinstance(dispatch_record, Mapping)
            and dispatch_record.get("status") == "failed-ambiguous"
        ):
            ambiguous.append(thread_id)
            continue
        if (
            isinstance(dispatch_record, Mapping)
            and dispatch_record.get("status") == "failed-contained"
            and dispatch_record.get("archived") is True
        ):
            try:
                success_audited = bool(
                    ledger is None or ledger.has_successful_containment(thread_id)
                )
            except Exception as exc:
                success_audited = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            if success_audited:
                already_contained.append(thread_id)
            else:
                ambiguous.append(thread_id)
            continue
        staged_archive = (
            server.staged_archive(thread_id)
            if hasattr(server, "staged_archive")
            else None
        )
        if staged_archive is not None:
            try:
                staged_archive.require_complete(timeout_seconds=15.0)
            except Exception as exc:
                record_failure(thread_id, "staged-archive-settlement", exc)
                ambiguous.append(thread_id)
                continue
        local_proof = (
            server.same_process_containment_proof(thread_id)
            if allow_same_process_proofs
            and hasattr(server, "same_process_containment_proof")
            else None
        )
        if local_proof is not None:
            try:
                success_audited = bool(
                    ledger is not None
                    and ledger.has_successful_containment(thread_id)
                )
            except Exception as exc:
                success_audited = False
                ledger_errors.append(
                    sha256_text(f"{type(exc).__name__}:{exc}")
                )
            if success_audited or audit_containment(
                thread_id,
                "already-contained",
                None,
                local_proof_sha256=local_proof["proof_sha256"],
            ):
                already_contained.append(thread_id)
            else:
                ambiguous.append(thread_id)
            continue
        if (
            staged_archive is not None
            and hasattr(server, "archive_acceptance_proof")
            and server.archive_acceptance_proof(thread_id) is not None
        ):
            # The exact archive request was accepted, but no terminal-bound
            # containment proof survived. Never issue a second archive RPC.
            ambiguous.append(thread_id)
            continue
        fresh_proof = (
            server.fresh_never_turned_thread_proof(thread_id)
            if allow_same_process_proofs
            and hasattr(server, "fresh_never_turned_thread_proof")
            else None
        )
        if (
            turn_id is None
            and dispatch_record is None
            and no_pending_turn_intent
            and fresh_proof is not None
        ):
            delete_fresh_thread = (
                delete_proven_never_turned and ledger is None
            )
            substep = (
                "never-turned-delete"
                if delete_fresh_thread
                else "never-turned-archive"
            )
            try:
                if delete_fresh_thread:
                    # Archive requires a materialized rollout. The activation
                    # delete opt-in is limited to a proven fresh, loaded,
                    # non-ephemeral thread that has never received a turn.
                    server.delete_thread(thread_id)
                    substep = "never-turned-delete-proof"
                    local_proof = (
                        server.record_never_turned_delete_containment(
                            thread_id
                        )
                    )
                else:
                    server.archive_thread(thread_id)
                    substep = "never-turned-archive-proof"
                    local_proof = (
                        server.record_never_turned_archive_containment(
                            thread_id
                        )
                    )
                substep = "never-turned-containment-audit"
                if not audit_containment(
                    thread_id,
                    "contained",
                    None,
                    local_proof_sha256=local_proof[
                        "proof_sha256"
                    ],
                ):
                    raise AppServerError(
                        "never-turned-containment-audit-failed"
                    )
                if delete_fresh_thread:
                    if containment_actions is not None:
                        containment_actions.append(
                            {
                                "action": "never-turned-delete",
                                "thread_id_sha256": sha256_text(
                                    thread_id
                                ),
                                "proof_sha256": local_proof[
                                    "proof_sha256"
                                ],
                            }
                        )
                else:
                    archived.append(thread_id)
            except Exception as exc:
                record_failure(thread_id, substep, exc)
                ambiguous.append(thread_id)
            continue
        try:
            thread, _latency = server.read_thread(thread_id)
            projected = AppServer._projected_turns(thread)
            expected_turns = {turn_id} if turn_id is not None else set()
            active = {
                candidate
                for candidate, status in projected.items()
                if AppServer._normalized_terminal_status(status) is None
            }
            interrupt_failed = False
            for candidate in sorted(active):
                try:
                    server.interrupt_turn(thread_id, candidate)
                    interrupted.append(thread_id)
                except Exception:
                    interrupt_failed = True
            deadline = time.monotonic() + AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS
            terminal: dict[str, str] = {
                candidate: normalized
                for candidate, status in projected.items()
                if (normalized := AppServer._normalized_terminal_status(status))
                is not None
            }
            while active and time.monotonic() < deadline and not interrupt_failed:
                try:
                    thread, _latency = server.read_thread(
                        thread_id,
                        timeout=max(0.001, deadline - time.monotonic()),
                    )
                except TypeError as exc:
                    if "timeout" not in str(exc):
                        raise
                    thread, _latency = server.read_thread(thread_id)
                projected = AppServer._projected_turns(thread)
                terminal.update(
                    {
                        candidate: normalized
                        for candidate, status in projected.items()
                        if (normalized := AppServer._normalized_terminal_status(status))
                        is not None
                    }
                )
                active = {
                    candidate
                    for candidate, status in projected.items()
                    if AppServer._normalized_terminal_status(status) is None
                }
                if active:
                    time.sleep(AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS)
            terminal_proven = expected_turns.issubset(terminal)
            absence_proven = not active
            if not interrupt_failed and terminal_proven and absence_proven:
                server.archive_thread(thread_id)
                archived.append(thread_id)
                audit_containment(
                    thread_id,
                    "contained",
                    terminal.get(turn_id) if turn_id is not None else None,
                )
            else:
                ambiguous.append(thread_id)
        except Exception:
            try:
                containment_audited = bool(
                    ledger is not None
                    and ledger.has_successful_containment(thread_id)
                )
            except Exception as exc:
                containment_audited = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            record_proves_containment = bool(
                isinstance(dispatch_record, Mapping)
                and not validate_turn_dispatch_record(dispatch_record)
                and dispatch_record.get("status") == "failed-contained"
                and dispatch_record.get("absence_verified") is True
            )
            if containment_audited or (ledger is None and record_proves_containment):
                already_contained.append(thread_id)
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
    ambiguous_count = len(set(ambiguous)) + unresolved_allocations + unresolved_turns
    return {
        "allocated_count": ledger_allocation_count,
        "identified_thread_count": len(server.started_threads),
        "interrupted_count": len(set(interrupted)),
        "archived_count": len(set(archived)),
        "already_contained_count": len(set(already_contained)),
        "unresolved_allocation_intent_count": unresolved_allocations,
        "unresolved_turn_intent_count": unresolved_turns,
        "ambiguous_count": ambiguous_count,
        "all_contained": ambiguous_count == 0 and not ledger_errors,
        "ledger_consistent": not ledger_errors
        and not unresolved_allocations
        and not unresolved_turns,
        "ledger_error_sha256": sorted(set(ledger_errors)),
    }
