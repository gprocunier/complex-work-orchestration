"""Finite cooperative EXAMPLE effects for the original offline fake host.

This is a fake effect adapter, not an isolation launcher or a permission source.
Only EXAMPLE_RENDER_RESULT writes a file; all other effects are memory fixtures.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


PROFILE = {
    "name": "EXAMPLE_OFFLINE_EFFECT_PROFILE",
    "evidence_kind": "cooperative-declaration",
    "allowed": ["EXAMPLE_RENDER_RESULT", "EXAMPLE_ORDINARY_FAILURE"],
    "denied": ["EXAMPLE_WRITE", "EXAMPLE_NETWORK", "EXAMPLE_PROCESS", "EXAMPLE_READ"],
    "escalation": "EXAMPLE_EXPLICIT_ESCALATION",
    "max_requests": 12,
}
FALSE_FIELDS = (
    "production_ready", "effect_authority", "operative", "qualified", "accepted_for_use",
)
BINDING_KEYS = {
    "candidate", "context", "factory", "limits", "request_sha256",
    "scope_sha256", "configuration_pins", "control_contract", "max_steps",
}
COMMAND = "EXAMPLE_RENDER_RESULT"
ACK = "EXAMPLE_RESULT_FILE_WRITTEN\n"
OUTPUT = b"EXAMPLE_RESULT: useful offline fixture output\n"


def _snapshot(value):
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


class ExampleEffects:
    """Harmless disposable backend with observable actual effect counters."""

    def __init__(self, worker):
        self.worker = Path(worker)
        self.calls = dict.fromkeys((COMMAND, "EXAMPLE_WRITE", "EXAMPLE_NETWORK",
                                   "EXAMPLE_PROCESS", "EXAMPLE_READ", "EXAMPLE_ORDINARY_FAILURE"), 0)
        self.memory = {"EXAMPLE_PRIVATE": "EXAMPLE private fixture"}

    def apply(self, command):
        self.calls[command] += 1
        if command == COMMAND:
            # Exclusive creation makes a duplicate productive invocation observable.
            with (self.worker / "result.txt").open("xb") as stream:
                stream.write(OUTPUT)
            return ACK
        if command == "EXAMPLE_ORDINARY_FAILURE":
            raise OSError("EXAMPLE ordinary operation failed")
        if command == "EXAMPLE_READ":
            return self.memory["EXAMPLE_PRIVATE"]
        self.memory[command] = "EXAMPLE effect occurred"
        return "EXAMPLE effect occurred"


class ExampleEffectRunner:
    """One finite runner and one backend; denials never invoke an effect or retry.

    The supplied binding is retained as data. The original host/admission gates
    remain mandatory and independently validate their own inputs.
    """

    def __init__(self, worker, *, binding):
        if type(binding) is not dict or set(binding) != BINDING_KEYS:
            raise ValueError("Complete EXAMPLE effect bindings are required.")
        self._binding = _snapshot(binding)
        self._profile = _snapshot(PROFILE)
        self._effects = ExampleEffects(worker)
        self._records = []

    def check_binding(self, binding):
        if _snapshot(binding) != self._binding:
            raise ValueError("EXAMPLE effect binding changed; no substitute runner is selected.")

    def request(self, command):
        if len(self._records) >= self._profile["max_requests"]:
            raise ValueError("EXAMPLE finite runner request bound exhausted.")
        record = {"sequence": len(self._records) + 1, "command": None,
                  "status": "unknown", "output": None, "error": None,
                  "ordinary_retry": False, "fallback": False, "unsandboxed": False}
        self._records.append(record)
        if type(command) is not str or len(command) > 80:
            record["error"] = "EXAMPLE unknown command shape"
            return copy.deepcopy(record)
        record["command"] = command
        if command in self._profile["denied"]:
            record.update(status="denied", error="EXAMPLE declared profile denied effect")
        elif command == self._profile["escalation"]:
            record.update(status="escalation-required", error="EXAMPLE additional grant refused")
        elif command in self._profile["allowed"]:
            self._apply(command, record)
        else:
            record["error"] = "EXAMPLE required effect metadata unknown"
        return copy.deepcopy(record)

    def _apply(self, command, record):
        try:
            record["output"] = self._effects.apply(command)
            record["status"] = "completed"
        except OSError as failure:
            record.update(status="failed", error=str(failure))

    def observations(self):
        binding = _snapshot(self._binding)
        digest = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
        return {
            "profile": _snapshot(self._profile), "binding": binding, "binding_sha256": digest,
            "requests": copy.deepcopy(self._records), "effect_calls": dict(self._effects.calls),
            "effective_backend_metadata": None, "effective_backend_metadata_supported": False,
            "observed_usage": None, "actual_confinement_qualified": False,
            **dict.fromkeys(FALSE_FIELDS, False),
        }
