"""Host control for one supervised native-worker segment.

``NativeControlTurn`` exposes a cooperative, one-callback ``step`` interface
for pool scheduling while retaining the exact blocking ``run`` receipt
contract.  Only ``run`` invokes the policy sleep callback.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping


CONTRACT_TYPE = "cwo-native-control-turn-contract"
RECEIPT_TYPE = "cwo-native-control-turn-receipt"
VERSION = 1
ALLOWED_ACTIONS = (
    "arm",
    "send-input",
    "mark-dispatched",
    "check",
    "interrupt",
    "close",
    "finalize",
)
REQUIRED_CALLBACKS = (
    "arm",
    "send_input",
    "mark_dispatched",
    "check",
    "interrupt",
    "close",
    "finalize",
    "sleep",
)
REQUIRED_CONTRACT_FIELDS = {
    "contract_type",
    "version",
    "state_file",
    "agent_id",
    "control_turn_id",
    "task_sha256",
    "poll_interval_ms",
    "allowed_actions",
    "contract_sha256",
}
RECEIPT_FIELDS = {
    "receipt_type",
    "version",
    "contract_sha256",
    "task_sha256",
    "submission_id",
    "actions",
    "decisions",
    "poll_count",
    "terminal_state",
    "errors",
}
VALID_DECISIONS = {"continue", "warn", "complete", "interrupt", "control-lost"}
_DECISION_ALIASES = {
    "completed": "complete",
    "worker-completed": "complete",
    "task_complete": "complete",
    "task-complete": "complete",
}


def normalize_terminal_state(value: Any) -> str:
    if value is None:
        raise ValueError("terminal state is required")
    if isinstance(value, str):
        state = value.strip().lower().replace("_", "-")
        if state in {"complete", "completed", "worker-completed", "task-complete"}:
            return "completed"
        if state in {"closed", "control-failed"}:
            return state
    raise ValueError("terminal state is invalid")


def normalize_control_acknowledgement(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized if normalized else None
    if isinstance(value, Mapping):
        for field in ("ack", "acknowledgement", "status", "state", "control_action"):
            candidate = value.get(field)
            if isinstance(candidate, str):
                normalized = candidate.strip()
                if normalized:
                    return normalized
        if "decision" in value and isinstance(value["decision"], str):
            normalized = value["decision"].strip()
            return normalized if normalized else None
    raise ValueError("control callback acknowledgement must be text, mapping, or null")


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _contract_payload(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in contract.items() if key != "contract_sha256"}


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def build_control_turn_contract(
    *,
    state_file: str,
    agent_id: str,
    control_turn_id: str,
    task_sha256: str,
    poll_interval_ms: int,
) -> dict[str, Any]:
    """Build a hash-bound, JSON-safe control-turn contract."""
    contract: dict[str, Any] = {
        "contract_type": CONTRACT_TYPE,
        "version": VERSION,
        "state_file": state_file,
        "agent_id": agent_id,
        "control_turn_id": control_turn_id,
        "task_sha256": task_sha256,
        "poll_interval_ms": poll_interval_ms,
        "allowed_actions": list(ALLOWED_ACTIONS),
    }
    contract["contract_sha256"] = _canonical_sha256(contract)
    errors = validate_control_turn_contract(contract)
    if errors:
        raise ValueError("invalid control-turn contract: " + "; ".join(errors))
    return contract


def validate_control_turn_contract(contract: Any) -> list[str]:
    """Return deterministic contract errors without performing native actions."""
    if not isinstance(contract, Mapping):
        return ["contract-must-be-object"]
    errors: list[str] = []
    fields = set(contract)
    missing = sorted(REQUIRED_CONTRACT_FIELDS - fields)
    unknown = sorted(fields - REQUIRED_CONTRACT_FIELDS)
    if missing:
        errors.append("missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("unknown-fields:" + ",".join(unknown))
    if contract.get("contract_type") != CONTRACT_TYPE:
        errors.append("invalid-contract-type")
    version = contract.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        errors.append("invalid-version")
    state_file = contract.get("state_file")
    if not _nonempty(state_file) or not Path(str(state_file)).is_absolute():
        errors.append("invalid-state-file")
    for field in ("agent_id", "control_turn_id"):
        if not _nonempty(contract.get(field)):
            errors.append(f"invalid-{field.replace('_', '-')}")
    if not _is_sha256(contract.get("task_sha256")):
        errors.append("invalid-task-sha256")
    interval = contract.get("poll_interval_ms")
    if not isinstance(interval, int) or isinstance(interval, bool) or interval <= 0:
        errors.append("invalid-poll-interval-ms")
    actions = contract.get("allowed_actions")
    if not isinstance(actions, list) or actions != list(ALLOWED_ACTIONS):
        errors.append("invalid-allowed-actions")
    elif any("wait" in action for action in actions):
        errors.append("wait-action-forbidden")
    contract_sha256 = contract.get("contract_sha256")
    if not _is_sha256(contract_sha256):
        errors.append("invalid-contract-sha256")
    elif not missing and not unknown and contract_sha256 != _canonical_sha256(_contract_payload(contract)):
        errors.append("contract-sha256-mismatch")
    return errors


def validate_control_callbacks(callbacks: Any) -> list[str]:
    if not isinstance(callbacks, Mapping):
        return ["callbacks-must-be-object"]
    errors: list[str] = []
    forbidden = sorted(key for key in callbacks if "wait" in str(key).lower())
    if forbidden:
        errors.append("wait-callback-forbidden:" + ",".join(forbidden))
    unknown = sorted(set(callbacks) - set(REQUIRED_CALLBACKS))
    if unknown:
        errors.append("unknown-callbacks:" + ",".join(unknown))
    missing = [name for name in REQUIRED_CALLBACKS if name not in callbacks]
    if missing:
        errors.append("missing-callbacks:" + ",".join(missing))
    invalid = [name for name in REQUIRED_CALLBACKS if name in callbacks and not callable(callbacks[name])]
    if invalid:
        errors.append("noncallable-callbacks:" + ",".join(invalid))
    return errors


def validate_control_turn_receipt(
    receipt: Any,
    *,
    contract: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate one complete terminal control receipt and its contract binding."""

    if not isinstance(receipt, Mapping):
        return ["control-receipt-must-be-object"]
    errors: list[str] = []
    missing = sorted(RECEIPT_FIELDS - set(receipt))
    unknown = sorted(set(receipt) - RECEIPT_FIELDS)
    if missing:
        errors.append("control-receipt-missing-fields:" + ",".join(missing))
    if unknown:
        errors.append("control-receipt-unknown-fields:" + ",".join(unknown))
    if receipt.get("receipt_type") != RECEIPT_TYPE:
        errors.append("control-receipt-type-invalid")
    if type(receipt.get("version")) is not int or receipt.get("version") != VERSION:
        errors.append("control-receipt-version-invalid")
    for field in ("contract_sha256", "task_sha256"):
        if not _is_sha256(receipt.get(field)):
            errors.append(f"control-receipt-{field.replace('_', '-')}-invalid")
    submission_id = receipt.get("submission_id")
    if submission_id is not None and not _nonempty(submission_id):
        errors.append("control-receipt-submission-id-invalid")
    actions = receipt.get("actions")
    if not isinstance(actions, list) or any(not _nonempty(item) for item in actions):
        errors.append("control-receipt-actions-invalid")
    decisions = receipt.get("decisions")
    if not isinstance(decisions, list) or any(
        item not in VALID_DECISIONS for item in decisions
    ):
        errors.append("control-receipt-decisions-invalid")
    poll_count = receipt.get("poll_count")
    if type(poll_count) is not int or poll_count < 0:
        errors.append("control-receipt-poll-count-invalid")
    if receipt.get("terminal_state") not in {
        "completed",
        "closed",
        "control-failed",
    }:
        errors.append("control-receipt-terminal-state-invalid")
    receipt_errors = receipt.get("errors")
    if not isinstance(receipt_errors, list) or any(
        not _nonempty(item) for item in receipt_errors
    ):
        errors.append("control-receipt-errors-invalid")
    if contract is not None:
        errors.extend(
            "control-receipt-contract:" + item
            for item in validate_control_turn_contract(contract)
        )
        if receipt.get("contract_sha256") != contract.get("contract_sha256"):
            errors.append("control-receipt-contract-sha256-mismatch")
        if receipt.get("task_sha256") != contract.get("task_sha256"):
            errors.append("control-receipt-task-sha256-mismatch")
    return sorted(set(errors))


def _submission_id(value: Any) -> str:
    if isinstance(value, Mapping):
        value = value.get("submission_id")
    if not _nonempty(value):
        raise ValueError("send_input did not return a submission_id")
    return str(value).strip()


def _decision(value: Any) -> str:
    if value is None:
        raise ValueError("check returned missing decision evidence")
    if isinstance(value, Mapping):
        if "decision" in value:
            value = value.get("decision")
        elif "control_action" in value:
            value = value.get("control_action")
        elif "ack" in value:
            value = value.get("ack")
        elif "acknowledgement" in value:
            value = value.get("acknowledgement")
        elif "state" in value:
            value = value.get("state")
        else:
            raise ValueError("check returned an invalid decision")
    if isinstance(value, Mapping):
        raise ValueError("check returned an invalid decision")
    if isinstance(value, str):
        normalized = value.strip().lower().replace("_", "-")
        normalized = _DECISION_ALIASES.get(normalized, normalized)
        if normalized in VALID_DECISIONS:
            return normalized
    raise ValueError("check returned an invalid decision")


class NativeControlTurn:
    """Execute one immutable native control contract at most once."""

    def __init__(self, contract: Mapping[str, Any], callbacks: Mapping[str, Callable[..., Any]]) -> None:
        self.contract = dict(contract) if isinstance(contract, Mapping) else contract
        self.callbacks = dict(callbacks) if isinstance(callbacks, Mapping) else callbacks
        self._started = False
        self._terminal = False
        self._phase = "start"
        self._waiting = False
        self._task_input: str | None = None
        self._submission_id: str | None = None
        self._actions: list[str] = []
        self._decisions: list[str] = []
        self._errors: list[str] = []
        self._poll_count = 0
        self._terminal_receipt: dict[str, Any] | None = None

    def _receipt(
        self,
        *,
        submission_id: str | None,
        actions: list[str],
        decisions: list[str],
        poll_count: int,
        terminal_state: str,
        errors: list[str],
    ) -> dict[str, Any]:
        contract = self.contract if isinstance(self.contract, Mapping) else {}
        return {
            "receipt_type": RECEIPT_TYPE,
            "version": VERSION,
            "contract_sha256": contract.get("contract_sha256"),
            "task_sha256": contract.get("task_sha256"),
            "submission_id": submission_id,
            "actions": list(actions),
            "decisions": list(decisions),
            "poll_count": poll_count,
            "terminal_state": terminal_state,
            "errors": list(errors),
        }

    def _progress(self) -> dict[str, Any]:
        """Return JSON-safe cooperative state without widening legacy receipts."""
        return {
            "status": "terminal" if self._terminal else ("waiting" if self._waiting else "running"),
            "phase": self._phase,
            "wait_required": self._waiting,
            "wait_seconds": (
                self.contract.get("poll_interval_ms", 0) / 1000
                if self._waiting and isinstance(self.contract, Mapping)
                else None
            ),
            "receipt": dict(self._terminal_receipt) if self._terminal_receipt is not None else None,
        }

    def _finish(self, terminal_state: str) -> dict[str, Any]:
        self._terminal = True
        self._waiting = False
        self._phase = "terminal"
        self._terminal_receipt = self._receipt(
            submission_id=self._submission_id,
            actions=self._actions,
            decisions=self._decisions,
            poll_count=self._poll_count,
            terminal_state=terminal_state,
            errors=self._errors,
        )
        return self._progress()

    def _invoke(self, name: str, label: str | None = None, **kwargs: Any) -> Any:
        self._actions.append(label or name.replace("_", "-"))
        result = self.callbacks[name](**kwargs)
        if name in {"arm", "mark_dispatched", "finalize", "close", "interrupt"}:
            normalize_control_acknowledgement(result)
        return result

    def _record_callback_failure(self, exc: Exception) -> None:
        self._errors.append(f"callback-failed:{type(exc).__name__}:{exc}")
        self._waiting = False
        self._phase = "finalize-control-failed"

    def _start(self, task_input: Any) -> bool:
        contract_errors = validate_control_turn_contract(self.contract)
        callback_errors = validate_control_callbacks(self.callbacks)
        if not isinstance(task_input, str):
            self._errors.append("task-input-must-be-string")
        elif isinstance(self.contract, Mapping):
            actual_task_sha256 = hashlib.sha256(task_input.encode("utf-8")).hexdigest()
            if actual_task_sha256 != self.contract.get("task_sha256"):
                self._errors.append("task-sha256-mismatch")
        self._errors.extend(contract_errors)
        self._errors.extend(callback_errors)
        if self._errors:
            self._finish("control-failed")
            return False
        self._started = True
        self._task_input = task_input
        self._phase = "arm"
        return True

    def step(self, task_input: str | None = None) -> dict[str, Any]:
        """Advance by at most one adapter callback and never sleep."""
        if self._terminal:
            return self._progress()
        if not self._started:
            if not self._start(task_input):
                return self._progress()
        elif task_input is not None:
            raise ValueError("task input is already bound to this control turn")
        if self._waiting:
            return self._progress()

        state_file = self.contract["state_file"]
        control_turn_id = self.contract["control_turn_id"]
        agent_id = self.contract["agent_id"]

        try:
            if self._phase == "arm":
                self._invoke("arm", state_file=state_file, control_turn_id=control_turn_id)
                self._phase = "send-input"
            elif self._phase == "send-input":
                self._submission_id = _submission_id(
                    self._invoke("send_input", agent_id=agent_id, message=self._task_input)
                )
                self._phase = "mark-dispatched"
            elif self._phase == "mark-dispatched":
                self._invoke(
                    "mark_dispatched",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    submission_id=self._submission_id,
                )
                self._phase = "check"
            elif self._phase == "check":
                decision = _decision(
                    self._invoke("check", state_file=state_file, control_turn_id=control_turn_id)
                )
                self._poll_count += 1
                self._decisions.append(decision)
                if decision in {"continue", "warn"}:
                    self._phase = "waiting"
                    self._waiting = True
                elif decision == "complete":
                    self._phase = "finalize-complete"
                else:
                    self._phase = "interrupt"
            elif self._phase == "finalize-complete":
                self._invoke(
                    "finalize",
                    label="finalize:worker-completed",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    control_action="worker-completed",
                )
                self._phase = "close-complete"
            elif self._phase == "close-complete":
                self._invoke("close", agent_id=agent_id)
                return self._finish("completed")
            elif self._phase == "interrupt":
                decision = self._decisions[-1]
                self._invoke(
                    "interrupt",
                    agent_id=agent_id,
                    message=f"STOP: native supervisor decision {decision}",
                )
                self._phase = "finalize-interrupt"
            elif self._phase == "finalize-interrupt":
                self._invoke(
                    "finalize",
                    label="finalize:interrupt-confirmed",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    control_action="interrupt-confirmed",
                )
                self._phase = "close-interrupt"
            elif self._phase == "close-interrupt":
                self._invoke("close", agent_id=agent_id)
                self._phase = "finalize-close"
            elif self._phase == "finalize-close":
                self._invoke(
                    "finalize",
                    label="finalize:close-confirmed",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    control_action="close-confirmed",
                )
                return self._finish("closed")
            elif self._phase == "finalize-control-failed":
                try:
                    self._invoke(
                        "finalize",
                        label="finalize:control-failed",
                        state_file=state_file,
                        control_turn_id=control_turn_id,
                        control_action="control-failed",
                    )
                except Exception as finalize_exc:
                    self._errors.append(
                        "control-failed-receipt-failed:"
                        f"{type(finalize_exc).__name__}:{finalize_exc}"
                    )
                return self._finish("control-failed")
            else:
                raise RuntimeError(f"unknown cooperative phase: {self._phase}")
        except Exception as exc:  # The control boundary converts adapter failures into evidence.
            self._record_callback_failure(exc)
        return self._progress()

    def resume_after_wait(self) -> dict[str, Any]:
        """Clear a cooperative wait without invoking an adapter callback."""
        if self._terminal:
            return self._progress()
        if not self._waiting:
            raise ValueError("control turn is not waiting")
        self._waiting = False
        self._phase = "check"
        return self._progress()

    def request_interrupt(self, reason: str = "pool-interrupt") -> dict[str, Any]:
        """Give a trusted outer supervisor interrupt precedence without a callback."""
        if self._terminal:
            return self._progress()
        if not self._started:
            raise ValueError("control turn has not started")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("interrupt reason must be a nonempty string")
        decision = f"interrupt:{reason.strip()}"
        if not self._decisions or self._decisions[-1] != decision:
            self._decisions.append(decision)
        self._waiting = False
        self._phase = "interrupt"
        return self._progress()

    def run(self, task_input: str) -> dict[str, Any]:
        """Drive the cooperative machine with exact legacy blocking behavior."""
        if self._started or self._terminal:
            return self._receipt(
                submission_id=None,
                actions=[],
                decisions=[],
                poll_count=0,
                terminal_state="control-failed",
                errors=["control-turn-already-dispatched"],
            )

        progress = self.step(task_input)
        while not self._terminal:
            if progress["wait_required"]:
                self._actions.append("sleep")
                try:
                    self.callbacks["sleep"](seconds=self.contract["poll_interval_ms"] / 1000)
                except Exception as exc:
                    self._record_callback_failure(exc)
                else:
                    self.resume_after_wait()
            progress = self.step()
        assert self._terminal_receipt is not None
        return dict(self._terminal_receipt)


def run_control_turn(
    contract: Mapping[str, Any],
    task_input: str,
    callbacks: Mapping[str, Callable[..., Any]],
) -> dict[str, Any]:
    """Convenience entry point for a single-use control turn."""
    return NativeControlTurn(contract, callbacks).run(task_input)
