"""Synchronous host control for one supervised native-worker segment."""

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

    def run(self, task_input: str) -> dict[str, Any]:
        actions: list[str] = []
        decisions: list[str] = []
        errors: list[str] = []
        submission_id: str | None = None
        poll_count = 0
        if self._started or self._terminal:
            return self._receipt(
                submission_id=None,
                actions=[],
                decisions=[],
                poll_count=0,
                terminal_state="control-failed",
                errors=["control-turn-already-dispatched"],
            )

        contract_errors = validate_control_turn_contract(self.contract)
        callback_errors = validate_control_callbacks(self.callbacks)
        if not isinstance(task_input, str):
            errors.append("task-input-must-be-string")
        elif isinstance(self.contract, Mapping):
            actual_task_sha256 = hashlib.sha256(task_input.encode("utf-8")).hexdigest()
            if actual_task_sha256 != self.contract.get("task_sha256"):
                errors.append("task-sha256-mismatch")
        errors.extend(contract_errors)
        errors.extend(callback_errors)
        if errors:
            self._terminal = True
            return self._receipt(
                submission_id=None,
                actions=actions,
                decisions=decisions,
                poll_count=0,
                terminal_state="control-failed",
                errors=errors,
            )

        self._started = True
        state_file = self.contract["state_file"]
        control_turn_id = self.contract["control_turn_id"]
        agent_id = self.contract["agent_id"]

        def invoke(name: str, label: str | None = None, **kwargs: Any) -> Any:
            actions.append(label or name.replace("_", "-"))
            result = self.callbacks[name](**kwargs)
            if name in {"arm", "mark_dispatched", "finalize", "close", "interrupt"}:
                normalize_control_acknowledgement(result)
            return result

        try:
            invoke("arm", state_file=state_file, control_turn_id=control_turn_id)
            submission_id = _submission_id(
                invoke("send_input", agent_id=agent_id, message=task_input)
            )
            invoke(
                "mark_dispatched",
                state_file=state_file,
                control_turn_id=control_turn_id,
                submission_id=submission_id,
            )
            while True:
                decision = _decision(
                    invoke("check", state_file=state_file, control_turn_id=control_turn_id)
                )
                poll_count += 1
                decisions.append(decision)
                if decision in {"continue", "warn"}:
                    invoke("sleep", seconds=self.contract["poll_interval_ms"] / 1000)
                    continue
                if decision == "complete":
                    invoke(
                        "finalize",
                        label="finalize:worker-completed",
                        state_file=state_file,
                        control_turn_id=control_turn_id,
                        control_action="worker-completed",
                    )
                    invoke("close", agent_id=agent_id)
                    self._terminal = True
                    return self._receipt(
                        submission_id=submission_id,
                        actions=actions,
                        decisions=decisions,
                        poll_count=poll_count,
                        terminal_state="completed",
                        errors=[],
                    )
                invoke(
                    "interrupt",
                    agent_id=agent_id,
                    message=f"STOP: native supervisor decision {decision}",
                )
                invoke(
                    "finalize",
                    label="finalize:interrupt-confirmed",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    control_action="interrupt-confirmed",
                )
                invoke("close", agent_id=agent_id)
                invoke(
                    "finalize",
                    label="finalize:close-confirmed",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    control_action="close-confirmed",
                )
                self._terminal = True
                return self._receipt(
                    submission_id=submission_id,
                    actions=actions,
                    decisions=decisions,
                    poll_count=poll_count,
                    terminal_state="closed",
                    errors=[],
                )
        except Exception as exc:  # The control boundary must convert adapter failures into evidence.
            errors.append(f"callback-failed:{type(exc).__name__}:{exc}")
            try:
                invoke(
                    "finalize",
                    label="finalize:control-failed",
                    state_file=state_file,
                    control_turn_id=control_turn_id,
                    control_action="control-failed",
                )
            except Exception as finalize_exc:
                errors.append(f"control-failed-receipt-failed:{type(finalize_exc).__name__}:{finalize_exc}")
            self._terminal = True
            return self._receipt(
                submission_id=submission_id,
                actions=actions,
                decisions=decisions,
                poll_count=poll_count,
                terminal_state="control-failed",
                errors=errors,
            )


def run_control_turn(
    contract: Mapping[str, Any],
    task_input: str,
    callbacks: Mapping[str, Callable[..., Any]],
) -> dict[str, Any]:
    """Convenience entry point for a single-use control turn."""
    return NativeControlTurn(contract, callbacks).run(task_input)
