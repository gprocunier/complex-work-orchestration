"""Aggregate invocation ledger: one-use reservations, durable intent and conservative accounting.

This is the reservation and accounting layer of controlled local invocation (issue #41). ``cwo_core.local_invocation`` wires it in
front of the local HTTP effect, but controlled local invocation stays unavailable
(``dispatch_work.LOCAL_INVOCATION_AVAILABLE`` is False) until an admission record binds workload-derived sizing to
the exact request and a separately reviewed patch restores the route.

States follow 04 section 6::

    prepared -> reserved -> invocation-intent -> terminal | reconciliation-required

``prepared`` is an admitted request that has not touched the ledger. The ledger stores the rest:

- ``reserved``: a one-use reservation against one aggregate budget, taken under an exclusive lock after
  checking that every budget dimension still has room. It records the owner process, the request digest,
  the admission digest (one use across the whole ledger) and the attempt lineage.
- ``invocation-intent``: a compare-and-swap from ``reserved`` by the owner, before expiry and only when the
  frozen request bytes still hash to the reserved digest. Intent and the observer names are written and
  fsynced before the effect runs, so a synchronous callback reads valid persisted state.
- ``terminal``: the final record. Outcomes ``released``, ``expired`` and ``drift-refused`` come only from
  ``reserved``: intent was never persisted, so the effect cannot have run through this ledger and the
  reservation charges nothing. Every other outcome comes after intent and charges at least the full
  reserved amount. Observed usage above the reservation is charged as observed; observed usage below it
  does not release anything in this version.
- ``reconciliation-required``: the owner exited after persisting intent, or ``invoke`` was left by any
  exception or interrupt (for example ``KeyboardInterrupt``) at a point after intent where no terminal outcome
  had been recorded: observer notification, the effect, or recording its result. Remote execution is unknown.
  It charges in full, cannot be invoked again, and blocks a retry, fallback or successor until ``reconcile``
  records it terminal (still charged in full). A terminal record written before the interruption is kept.

The states, the transitions between them and the outcomes each transition permits are listed once, in
``_ALLOWED_TRANSITIONS``; ``transition_error`` is the only reader, used both to move an attempt and to validate a
stored history, so an unknown state or a transition outside the table is refused everywhere.

Every attempt, including retries, fallbacks, successors and siblings, charges the one budget it was reserved
against. Budget limits are immutable once opened, and nothing lowers a charge except releasing a reservation
whose intent was never persisted. At most one invocation per reservation is enforced locally; that is not
exactly-once remote execution, and unknown remote usage stays unknown.

Durability: every write goes through a temporary file, ``fsync``, ``os.replace`` and an ``fsync`` of the ledger
directory. Directories are provisioned durably on first use: until the ledger file has been written once, every
operation fsyncs the parent of each directory from the top of the current user's owned chain down to the ledger
root. That covers every directory this module can have created, including directories left by an earlier
process that was killed between ``mkdir`` and the fsync, and it happens before the first budget can be opened,
so before any reservation or effect.

Concurrency: every operation holds an exclusive ``flock`` on the lock file. Before each write the ledger checks
that the lock file it holds is still the one at the lock path and that the ledger file is byte-for-byte what it
loaded (or last wrote) under that lock; anything else is a concurrent update outside the lock, and the operation is
refused without overwriting it.

Enforcement is cooperative (04 section 8): a same-user process can bypass this module or rewrite the ledger
file. The ledger refuses a file that fails validation, but validation is a consistency check, not custody.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ContextDecorator, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import AUDIT_DIR
from .process_identity import parse_proc_stat

LEDGER_TYPE = "cwo-invocation-ledger"
LEDGER_VERSION = 1
LEDGER_FILE = "ledger.json"
LOCK_FILE = "ledger.lock"
ROOT_ENV = "CWO_INVOCATION_LEDGER_ROOT"

STATES = ("reserved", "invocation-intent", "terminal", "reconciliation-required")
# Terminal outcomes reachable only from ``reserved``: intent was never persisted, so nothing is charged.
RELEASING_OUTCOMES = ("released", "expired", "drift-refused")
# Terminal outcomes after intent: charged at least the full reservation.
CHARGED_OUTCOMES = ("completed", "failed", "timeout", "cancelled", "unknown", "aborted-before-effect", "reconciled")
OUTCOMES = RELEASING_OUTCOMES + CHARGED_OUTCOMES
EFFECT_OUTCOMES = ("completed", "failed", "timeout", "cancelled", "unknown", "aborted-before-effect")
USAGE_OUTCOMES = ("completed", "failed")
LINEAGE_KINDS = ("initial", "retry", "fallback", "successor", "sibling")
# These kinds follow a finished parent; a sibling runs alongside its parent.
FOLLOWING_KINDS = ("retry", "fallback", "successor")

LEDGER_FIELDS = ("ledger_type", "version", "budgets", "attempts")
BUDGET_FIELDS = ("budget_id", "scope_sha256", "limits", "created_at")
ATTEMPT_FIELDS = (
    "attempt_id",
    "reservation_id",
    "budget_id",
    "request_id",
    "request_sha256",
    "admission_sha256",
    "lineage",
    "amount",
    "owner",
    "sequence",
    "created_at",
    "expires_at",
    "state",
    "outcome",
    "observers",
    "observed_usage",
    "charge",
    "history",
)
LINEAGE_FIELDS = ("kind", "parent_attempt_id")
OWNER_FIELDS = ("pid", "start_ticks", "boot_id_sha256")
HISTORY_FIELDS = ("state", "outcome", "at", "reason")

MAX_UNITS = 2**53 - 1
# Times are POSIX seconds. The bound keeps every conversion to float exact and finite, so an oversized integer is
# a validation diagnostic, never an OverflowError.
MAX_TIME = 2**53 - 1
MAX_REASON_CHARS = 500
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIMENSION_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

_ALLOWED_TRANSITIONS: dict[str, dict[str, tuple[str, ...]]] = {
    # state -> next state -> permitted terminal outcomes (empty for non-terminal next states)
    "reserved": {"invocation-intent": (), "terminal": RELEASING_OUTCOMES},
    "invocation-intent": {"terminal": EFFECT_OUTCOMES, "reconciliation-required": ()},
    "reconciliation-required": {"terminal": ("reconciled",)},
    "terminal": {},
}


def transition_error(state: Any, next_state: Any, outcome: Any) -> str | None:
    """Why ``state -> next_state`` (with ``outcome``) is not permitted, or None when the table permits it.

    The single reader of ``_ALLOWED_TRANSITIONS``. An unknown or unhashable state is refused, never looked up.
    """
    if not isinstance(state, str) or state not in _ALLOWED_TRANSITIONS:
        return f"{state!r} is not a ledger state"
    permitted = _ALLOWED_TRANSITIONS[state]
    if not isinstance(next_state, str) or next_state not in permitted:
        return f"moves from {state} to {next_state!r}, which is not a permitted transition"
    if next_state == "terminal" and outcome not in permitted[next_state]:
        return f"ends {state} with outcome {outcome!r}, which is not permitted"
    if next_state != "terminal" and outcome is not None:
        return "records an outcome before the attempt is terminal"
    return None


def _failure_detail(failure: BaseException) -> str:
    try:
        return repr(failure)
    except BaseException:
        return "unrenderable secondary failure"


def add_failure_note(failure: BaseException, note: str) -> None:
    """Diagnostics are best effort; even broken __notes__ cannot replace a primary.

    Normal exceptions retain the original secondary-error note. For an unusable
    or raising notes attribute, primary identity/accounting take precedence.
    """
    try:
        BaseException.add_note(failure, note)
    except BaseException:
        pass


class InvocationLedgerError(ValueError):
    """A refused ledger operation. The message names what was refused and why."""


class InvocationTimeout(Exception):
    """Raised by an effect when its admitted time limit expired. Charged in full."""


class InvocationCancelled(Exception):
    """Raised by an effect that was cancelled locally; remote cancellation is unknown. Charged in full."""


@dataclass(frozen=True)
class EffectResult:
    """What an effect reports when it returns: ``completed`` or ``failed`` and any observed usage."""

    status: str
    usage: Mapping[str, int] | None = None


class ProcOwnerProbe:
    """Owner identity from /proc: PID, start time in clock ticks and a boot ID digest. Tests substitute a fake."""

    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        self.proc_root = proc_root

    def _boot_sha256(self) -> str:
        boot = (self.proc_root / "sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        if not boot:
            raise OSError("boot identity is empty")
        return hashlib.sha256(boot.encode("utf-8")).hexdigest()

    def current(self) -> dict[str, Any]:
        pid = os.getpid()
        try:
            proc = parse_proc_stat((self.proc_root / f"{pid}/stat").read_text(encoding="utf-8", errors="surrogateescape"))
            boot = self._boot_sha256()
        except (OSError, ValueError) as exc:
            raise InvocationLedgerError(f"owner identity is unavailable: {exc}") from exc
        return {"pid": pid, "start_ticks": proc.start_ticks, "boot_id_sha256": boot}

    def status(self, owner: Mapping[str, Any]) -> str:
        """``alive``, ``gone`` or ``unknown``. Only ``gone`` lets recovery act on another owner's attempt."""
        try:
            boot = self._boot_sha256()
        except OSError:
            return "unknown"
        if boot != owner["boot_id_sha256"]:
            return "gone"
        try:
            text = (self.proc_root / f"{owner['pid']}/stat").read_text(encoding="utf-8", errors="surrogateescape")
        except (FileNotFoundError, ProcessLookupError):
            return "gone"
        except OSError:
            return "unknown"
        try:
            proc = parse_proc_stat(text)
        except ValueError:
            return "unknown"
        if proc.start_ticks != owner["start_ticks"] or proc.state in {"Z", "X", "x"}:
            return "gone"
        return "alive"


_LOCAL = threading.local()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and _ID_RE.fullmatch(value) is not None


def _is_units(value: Any, *, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= MAX_UNITS


def _is_time(value: Any) -> bool:
    """A non-negative time no larger than ``MAX_TIME``. Integers are compared before any float conversion."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return 0 <= value <= MAX_TIME


def _exact_fields(value: Any, fields: Sequence[str]) -> bool:
    return isinstance(value, dict) and set(value) == set(fields)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvocationLedgerError(f"invocation ledger repeats key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InvocationLedgerError(f"invocation ledger contains non-finite number {value}")


def request_sha256(request_bytes: bytes) -> str:
    """Digest of the exact serialized request bytes."""
    return hashlib.sha256(bytes(request_bytes)).hexdigest()


def _frozen_bytes(request_bytes: Any) -> bytes:
    """An immutable copy of the request bytes; text or any other type is refused."""
    if not isinstance(request_bytes, (bytes, bytearray, memoryview)):
        raise InvocationLedgerError(
            f"request bytes must be bytes, not {type(request_bytes).__name__}; nothing was invoked"
        )
    return bytes(request_bytes)


def empty_ledger() -> dict[str, Any]:
    return {"ledger_type": LEDGER_TYPE, "version": LEDGER_VERSION, "budgets": {}, "attempts": {}}


def derived_charge(attempt: Mapping[str, Any]) -> dict[str, int]:
    """The charge an attempt's state and outcome require."""
    amount = attempt["amount"]
    if attempt["state"] == "terminal" and attempt["outcome"] in RELEASING_OUTCOMES:
        return {dimension: 0 for dimension in amount}
    observed = attempt.get("observed_usage")
    if isinstance(observed, Mapping):
        return {dimension: max(units, int(observed.get(dimension, 0))) for dimension, units in amount.items()}
    return dict(amount)


def _limits_errors(limits: Any, where: str) -> list[str]:
    if not isinstance(limits, dict) or not limits:
        return [f"{where} must be a non-empty mapping of dimension to positive integer units"]
    errors = []
    for dimension, units in limits.items():
        if not isinstance(dimension, str) or _DIMENSION_RE.fullmatch(dimension) is None:
            errors.append(f"{where} has an invalid dimension name {dimension!r}")
        elif not _is_units(units, minimum=1):
            errors.append(f"{where}.{dimension} must be a positive integer, not {units!r}")
    return errors


def _amount_errors(amount: Any, limits: Mapping[str, int], where: str) -> list[str]:
    if not isinstance(amount, dict):
        return [f"{where} must be a mapping with one positive integer per budget dimension; a bare number is refused"]
    errors = _limits_errors(amount, where)
    if not errors and set(amount) != set(limits):
        errors.append(
            f"{where} must name exactly the budget dimensions {sorted(limits)}, not {sorted(amount)}"
        )
    return errors


def _usage_errors(usage: Any, limits: Mapping[str, int], where: str) -> list[str]:
    if not isinstance(usage, dict):
        return [f"{where} must be a mapping of budget dimension to non-negative integer units"]
    errors = []
    for dimension, units in usage.items():
        if dimension not in limits:
            errors.append(f"{where} names {dimension!r}, which is not a budget dimension")
        elif not _is_units(units, minimum=0):
            errors.append(f"{where}.{dimension} must be a non-negative integer, not {units!r}")
    return errors


def _charge_errors(charge: Any, amount: Mapping[str, int], where: str) -> list[str]:
    """A stored charge names exactly the amount's dimensions with exact non-negative integers (no bool or float)."""
    if not isinstance(charge, dict) or set(charge) != set(amount):
        return [f"{where} must name exactly the dimensions {sorted(amount)}"]
    return [
        f"{where}.{dimension} must be a non-negative integer, not {units!r}"
        for dimension, units in charge.items()
        if not _is_units(units, minimum=0)
    ]


def _owner_errors(owner: Any, where: str) -> list[str]:
    if not _exact_fields(owner, OWNER_FIELDS):
        return [f"{where} must have exactly {list(OWNER_FIELDS)}"]
    errors = []
    if not _is_units(owner["pid"], minimum=1):
        errors.append(f"{where}.pid must be a positive integer")
    if not _is_units(owner["start_ticks"], minimum=0):
        errors.append(f"{where}.start_ticks must be a non-negative integer")
    if not _is_sha256(owner["boot_id_sha256"]):
        errors.append(f"{where}.boot_id_sha256 must be a SHA-256 hex digest")
    return errors


def _history_errors(attempt: Mapping[str, Any], where: str) -> list[str]:
    history = attempt["history"]
    if not isinstance(history, list) or not history:
        return [f"{where}.history must be a non-empty list"]
    errors: list[str] = []
    previous_state: str | None = None
    previous_at = attempt["created_at"] if _is_time(attempt["created_at"]) else 0
    for index, entry in enumerate(history):
        at = f"{where}.history[{index}]"
        if not _exact_fields(entry, HISTORY_FIELDS):
            errors.append(f"{at} must have exactly {list(HISTORY_FIELDS)}")
            return errors
        state, outcome = entry["state"], entry["outcome"]
        if state not in STATES:
            errors.append(f"{at}.state {state!r} is not a ledger state")
            return errors
        if not isinstance(entry["reason"], str) or not entry["reason"] or len(entry["reason"]) > MAX_REASON_CHARS:
            errors.append(f"{at}.reason must be a non-empty string of at most {MAX_REASON_CHARS} characters")
        if not _is_time(entry["at"]) or entry["at"] < previous_at:
            errors.append(f"{at}.at must be a time no earlier than the previous entry")
        else:
            previous_at = entry["at"]
        if previous_state is None:
            if state != "reserved" or outcome is not None:
                errors.append(f"{at} must record the reservation first")
        else:
            problem = transition_error(previous_state, state, outcome)
            if problem is not None:
                errors.append(f"{at} {problem}")
        previous_state = state
    last = history[-1]
    if isinstance(last, dict) and (last.get("state"), last.get("outcome")) != (attempt["state"], attempt["outcome"]):
        errors.append(f"{where} state and outcome do not match its last history entry")
    return errors


def validate_ledger(document: Any) -> list[str]:
    """Every consistency error in a ledger document; empty when it is valid."""
    if not _exact_fields(document, LEDGER_FIELDS):
        return [f"invocation ledger must have exactly {list(LEDGER_FIELDS)}"]
    if document["ledger_type"] != LEDGER_TYPE:
        return [f"invocation ledger type must be {LEDGER_TYPE!r}"]
    if type(document["version"]) is not int or document["version"] != LEDGER_VERSION:
        return [f"unsupported invocation ledger version {document['version']!r}; no migration is defined"]
    budgets, attempts = document["budgets"], document["attempts"]
    if not isinstance(budgets, dict) or not isinstance(attempts, dict):
        return ["invocation ledger budgets and attempts must be mappings"]
    errors: list[str] = []
    for key, budget in budgets.items():
        where = f"budgets[{key!r}]"
        if not _exact_fields(budget, BUDGET_FIELDS):
            errors.append(f"{where} must have exactly {list(BUDGET_FIELDS)}")
            continue
        if budget["budget_id"] != key or not _is_id(key):
            errors.append(f"{where}.budget_id must be a valid identifier equal to its key")
        if not _is_sha256(budget["scope_sha256"]):
            errors.append(f"{where}.scope_sha256 must be a SHA-256 hex digest")
        if not _is_time(budget["created_at"]):
            errors.append(f"{where}.created_at must be a finite non-negative time")
        errors.extend(_limits_errors(budget["limits"], f"{where}.limits"))
    if errors:
        return errors
    seen_reservations: set[str] = set()
    seen_admissions: set[str] = set()
    seen_sequences: set[int] = set()
    for key, attempt in attempts.items():
        where = f"attempts[{key!r}]"
        if not _exact_fields(attempt, ATTEMPT_FIELDS):
            errors.append(f"{where} must have exactly {list(ATTEMPT_FIELDS)}")
            continue
        if attempt["attempt_id"] != key or not _is_id(key):
            errors.append(f"{where}.attempt_id must be a valid identifier equal to its key")
        for field in ("reservation_id", "request_id"):
            if not _is_id(attempt[field]):
                errors.append(f"{where}.{field} must be a valid identifier")
        for field in ("request_sha256", "admission_sha256"):
            if not _is_sha256(attempt[field]):
                errors.append(f"{where}.{field} must be a SHA-256 hex digest")
        # Only values that passed the type checks above are hashed or used as keys.
        if _is_id(attempt["reservation_id"]):
            if attempt["reservation_id"] in seen_reservations:
                errors.append(f"{where}.reservation_id is used by another attempt")
            seen_reservations.add(attempt["reservation_id"])
        if _is_sha256(attempt["admission_sha256"]):
            if attempt["admission_sha256"] in seen_admissions:
                errors.append(f"{where}.admission_sha256 is used by another attempt; an admission is one use")
            seen_admissions.add(attempt["admission_sha256"])
        if not _is_units(attempt["sequence"], minimum=1) or attempt["sequence"] in seen_sequences:
            errors.append(f"{where}.sequence must be a unique positive integer")
        else:
            seen_sequences.add(attempt["sequence"])
        budget = budgets.get(attempt["budget_id"]) if _is_id(attempt["budget_id"]) else None
        if budget is None:
            errors.append(f"{where}.budget_id must name an open budget")
            continue
        amount_errors = _amount_errors(attempt["amount"], budget["limits"], f"{where}.amount")
        errors.extend(amount_errors)
        errors.extend(_owner_errors(attempt["owner"], f"{where}.owner"))
        if not _is_time(attempt["created_at"]) or not _is_time(attempt["expires_at"]):
            errors.append(f"{where} times must be finite and non-negative")
        elif attempt["expires_at"] <= attempt["created_at"]:
            errors.append(f"{where}.expires_at must be after created_at")
        if attempt["state"] not in STATES:
            errors.append(f"{where}.state {attempt['state']!r} is not a ledger state")
            continue
        if attempt["state"] == "terminal":
            if attempt["outcome"] not in OUTCOMES:
                errors.append(f"{where}.outcome {attempt['outcome']!r} is not a terminal outcome")
        elif attempt["outcome"] is not None:
            errors.append(f"{where}.outcome must be null until the attempt is terminal")
        observers = attempt["observers"]
        if not isinstance(observers, list) or not all(isinstance(name, str) and name for name in observers):
            errors.append(f"{where}.observers must be a list of non-empty names")
        usage = attempt["observed_usage"]
        if usage is not None:
            if attempt["state"] != "terminal" or attempt["outcome"] not in USAGE_OUTCOMES:
                errors.append(f"{where}.observed_usage is recorded only for a completed or failed effect")
            else:
                errors.extend(_usage_errors(usage, budget["limits"], f"{where}.observed_usage"))
        lineage = attempt["lineage"]
        if not _exact_fields(lineage, LINEAGE_FIELDS) or lineage["kind"] not in LINEAGE_KINDS:
            errors.append(f"{where}.lineage must have a kind in {list(LINEAGE_KINDS)} and a parent_attempt_id")
        elif lineage["kind"] == "initial":
            if lineage["parent_attempt_id"] is not None:
                errors.append(f"{where}.lineage of an initial attempt has no parent")
        else:
            parent_id = lineage["parent_attempt_id"]
            parent = attempts.get(parent_id) if _is_id(parent_id) else None
            if not isinstance(parent, dict):
                errors.append(f"{where}.lineage names no recorded parent attempt")
            elif parent.get("budget_id") != attempt["budget_id"]:
                errors.append(f"{where}.lineage parent belongs to another budget")
            elif (
                not _is_units(parent.get("sequence"), minimum=1)
                or not _is_units(attempt["sequence"], minimum=1)
                or parent["sequence"] >= attempt["sequence"]
            ):
                errors.append(f"{where}.lineage parent must precede the attempt")
        errors.extend(_history_errors(attempt, where))
        if amount_errors:
            continue
        charge_errors = _charge_errors(attempt["charge"], attempt["amount"], f"{where}.charge")
        errors.extend(charge_errors)
        usage_valid = usage is None or (isinstance(usage, dict) and not _usage_errors(usage, budget["limits"], ""))
        if not charge_errors and usage_valid and attempt["charge"] != derived_charge(attempt):
            errors.append(f"{where}.charge does not match the charge its state and outcome require")
    return errors


def _reservation_inputs(
    budget_id: Any, request_id: Any, request_sha256: Any, admission_sha256: Any, lineage: Any
) -> dict[str, Any]:
    """Check a reservation's caller inputs before anything is read or locked; return the lineage record."""
    if not _is_id(budget_id):
        raise InvocationLedgerError(f"budget_id {budget_id!r} is not a valid identifier; nothing was reserved")
    if not _is_id(request_id):
        raise InvocationLedgerError(f"request_id {request_id!r} is not a valid identifier")
    for name, value in (("request_sha256", request_sha256), ("admission_sha256", admission_sha256)):
        if not _is_sha256(value):
            raise InvocationLedgerError(f"{name} must be a SHA-256 hex digest")
    if lineage is None:
        return {"kind": "initial", "parent_attempt_id": None}
    # A mapping is required before anything converts it, so a number or a string is a refusal, not a TypeError.
    if not isinstance(lineage, Mapping):
        raise InvocationLedgerError(
            f"lineage must be a mapping with a kind in {list(LINEAGE_KINDS)} and a parent_attempt_id, "
            f"not {type(lineage).__name__}; nothing was reserved"
        )
    record = dict(lineage)
    if not _exact_fields(record, LINEAGE_FIELDS) or record["kind"] not in LINEAGE_KINDS:
        raise InvocationLedgerError(f"lineage must have a kind in {list(LINEAGE_KINDS)} and a parent_attempt_id")
    return record


def _check_lineage_parent(document: Mapping[str, Any], lineage: Mapping[str, Any], budget_id: str) -> None:
    parent_id = lineage["parent_attempt_id"]
    if lineage["kind"] == "initial":
        if parent_id is not None:
            raise InvocationLedgerError("an initial attempt has no parent")
        return
    parent = document["attempts"].get(parent_id) if _is_id(parent_id) else None
    if parent is None:
        raise InvocationLedgerError(f"lineage parent {parent_id!r} is not recorded")
    if parent["budget_id"] != budget_id:
        raise InvocationLedgerError(
            f"a {lineage['kind']} charges its parent's budget {parent['budget_id']}; a child cannot move to a fresh budget"
        )


def _check_follower_parent(document: Mapping[str, Any], lineage: Mapping[str, Any]) -> None:
    if lineage["kind"] not in FOLLOWING_KINDS:
        return
    parent_id = lineage["parent_attempt_id"]
    parent = document["attempts"][parent_id]
    if parent["state"] == "reconciliation-required":
        raise InvocationLedgerError(f"parent {parent_id} requires reconciliation; it is never retried silently")
    if parent["state"] != "terminal":
        raise InvocationLedgerError(f"a {lineage['kind']} needs a terminal parent; {parent_id} is {parent['state']}")


def _charged_totals(document: Mapping[str, Any], budget_id: str) -> dict[str, int]:
    limits = document["budgets"][budget_id]["limits"]
    totals = {dimension: 0 for dimension in limits}
    for attempt in document["attempts"].values():
        if attempt["budget_id"] == budget_id:
            for dimension, units in attempt["charge"].items():
                totals[dimension] += units
    return totals


def _check_aggregate(document: Mapping[str, Any], budget_id: str, amount: Mapping[str, int]) -> None:
    charged = _charged_totals(document, budget_id)
    for dimension, limit in document["budgets"][budget_id]["limits"].items():
        if charged[dimension] + amount[dimension] > limit:
            raise InvocationLedgerError(
                f"aggregate allowance exhausted for budget {budget_id}: {dimension} has {charged[dimension]} "
                f"charged of {limit}, so {amount[dimension]} more is refused; nothing was reserved"
            )


def _is_released(attempt: Mapping[str, Any]) -> bool:
    return attempt["state"] == "terminal" and attempt["outcome"] in RELEASING_OUTCOMES


def _new_attempt(
    document: Mapping[str, Any], budget_id: str, request_id: str, request_digest: str, admission_digest: str,
    lineage: dict[str, Any], amount: dict[str, int], owner: dict[str, Any], now: float, expires_at: float,
) -> dict[str, Any]:
    sequence = 1 + max((attempt["sequence"] for attempt in document["attempts"].values()), default=0)
    token = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    return {
        "attempt_id": f"inv-attempt-{token}",
        "reservation_id": f"inv-reservation-{token}",
        "budget_id": budget_id,
        "request_id": request_id,
        "request_sha256": request_digest,
        "admission_sha256": admission_digest,
        "lineage": lineage,
        "amount": amount,
        "owner": owner,
        "sequence": sequence,
        "created_at": now,
        "expires_at": float(expires_at),
        "state": "reserved",
        "outcome": None,
        "observers": [],
        "observed_usage": None,
        "charge": dict(amount),
        "history": [{"state": "reserved", "outcome": None, "at": now, "reason": "reserved within the aggregate budget"}],
    }


class InvocationLedger:
    """A file-backed aggregate ledger under one private directory, serialized by an exclusive lock."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        clock: Callable[[], float] = time.time,
        owner_probe: Any = None,
        fsync: Callable[[int], None] = os.fsync,
    ) -> None:
        configured = root if root is not None else os.environ.get(ROOT_ENV) or AUDIT_DIR / "invocation-ledger"
        self.root = Path(configured).expanduser()
        if not self.root.is_absolute():
            raise InvocationLedgerError(f"invocation ledger root must be an absolute path: {self.root}")
        self.clock = clock
        self.owner_probe = owner_probe if owner_probe is not None else ProcOwnerProbe()
        self._fsync = fsync

    # Storage -------------------------------------------------------------------------------------------

    def _prepare_root(self) -> Path:
        if self.root.is_symlink():
            raise InvocationLedgerError("invocation ledger root must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = os.lstat(self.root)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise InvocationLedgerError("invocation ledger root must be a directory owned by the current user")
        os.chmod(self.root, 0o700)
        if not os.path.lexists(self.root / LEDGER_FILE):
            self._provision_durably()
        return self.root

    def _fsync_directory(self, path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            self._fsync(descriptor)
        finally:
            os.close(descriptor)

    def _provision_durably(self) -> None:
        """Make the directory entries of the root and of every ancestor this module can have created durable.

        Runs until the ledger file has been written once, so before any budget, reservation or effect. Walking up
        from the resolved root while a directory is owned by the current user covers every directory created here,
        including one left by a process killed between ``mkdir`` and this fsync. Parents are fsynced from the top
        down. A parent that cannot be fsynced refuses the operation.
        """
        uid = os.getuid()
        parents: list[str] = []
        directory = os.path.realpath(self.root)
        while True:
            parent = os.path.dirname(directory)
            if parent == directory or os.lstat(directory).st_uid != uid:
                break
            parents.append(parent)
            directory = parent
        try:
            for parent in reversed(parents):
                self._fsync_directory(Path(parent))
        except OSError as exc:
            raise InvocationLedgerError(f"cannot durably provision the invocation ledger directory: {exc}") from exc

    def _open_private(self, path: Path, flags: int) -> int:
        try:
            descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as exc:
            raise InvocationLedgerError(f"{path.name} must be a current-user regular non-symlink file: {exc}") from exc
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            os.close(descriptor)
            raise InvocationLedgerError(f"{path.name} must be a current-user regular file")
        return descriptor

    def _read_ledger_bytes(self, root: Path) -> bytes | None:
        path = root / LEDGER_FILE
        if not os.path.lexists(path):
            return None
        descriptor = self._open_private(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as handle:
            return handle.read()

    def _load(self, root: Path) -> dict[str, Any]:
        raw = self._read_ledger_bytes(root)
        self._guard()["expected"] = None if raw is None else hashlib.sha256(raw).hexdigest()
        if raw is None:
            return empty_ledger()
        try:
            text = raw.decode("utf-8")
            document = json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
        except InvocationLedgerError:
            raise
        except ValueError as exc:
            # JSONDecodeError, invalid UTF-8, and integers longer than the interpreter converts all land here.
            raise InvocationLedgerError(f"invocation ledger is not valid JSON: {exc}") from exc
        errors = validate_ledger(document)
        if errors:
            raise InvocationLedgerError("invocation ledger is invalid; every operation is refused: " + "; ".join(errors))
        return document

    def _save(self, root: Path, document: dict[str, Any]) -> None:
        errors = validate_ledger(document)
        if errors:
            raise InvocationLedgerError("refusing to write an invalid invocation ledger: " + "; ".join(errors))
        self._refuse_concurrent_update(root)
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        temporary = root / f".{LEDGER_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
        if os.path.lexists(temporary):
            os.unlink(temporary)  # left by an earlier crash; the lock is held, so nobody else is writing it
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                self._fsync(handle.fileno())
            os.replace(temporary, root / LEDGER_FILE)
        except BaseException:
            if os.path.lexists(temporary):
                os.unlink(temporary)
            raise
        self._guard()["expected"] = hashlib.sha256(payload).hexdigest()
        self._fsync_directory(root)

    def _refuse_concurrent_update(self, root: Path) -> None:
        """Refuse to write unless this thread still holds the lock at the lock path and the ledger file is exactly what
        it loaded or last wrote under that lock."""
        guard = self._guard()
        try:
            info = os.lstat(root / LOCK_FILE)
            current_lock = (info.st_dev, info.st_ino)
        except FileNotFoundError:
            current_lock = None
        if guard.get("lock") is None or current_lock != guard["lock"]:
            raise InvocationLedgerError(
                "invocation ledger lock file was replaced during the operation; refusing a concurrent update"
            )
        raw = self._read_ledger_bytes(root)
        current = None if raw is None else hashlib.sha256(raw).hexdigest()
        if current != guard.get("expected"):
            raise InvocationLedgerError(
                "invocation ledger changed outside the lock during the operation; refusing to overwrite a concurrent "
                "update"
            )

    @contextmanager
    def _locked(self) -> Iterator[tuple[Path, dict[str, Any]]]:
        held: set[str] = getattr(_LOCAL, "held", set())
        key = str(self.root)
        if key in held:
            raise InvocationLedgerError("reentrant invocation ledger operation")
        root = self._prepare_root()
        descriptor = self._open_private(root / LOCK_FILE, os.O_RDWR | os.O_CREAT)
        held.add(key)
        _LOCAL.held = held
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                info = os.fstat(descriptor)
                self._guards()[key] = {"lock": (info.st_dev, info.st_ino), "expected": None}
                yield root, self._load(root)
            finally:
                self._guards().pop(key, None)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            held.discard(key)
            os.close(descriptor)

    # Helpers -------------------------------------------------------------------------------------------

    @staticmethod
    def _guards() -> dict[str, dict[str, Any]]:
        """Per-thread state of the locks this thread holds, keyed by ledger root."""
        guards = getattr(_LOCAL, "guards", None)
        if guards is None:
            guards = _LOCAL.guards = {}
        return guards

    def _guard(self) -> dict[str, Any]:
        guard = self._guards().get(str(self.root))
        if guard is None:
            raise InvocationLedgerError("invocation ledger state is read or written only under its lock")
        return guard

    def _now(self) -> float:
        now = self.clock()
        if not _is_time(now):
            raise InvocationLedgerError("ledger clock returned an invalid time")
        return float(now)

    def current_time(self) -> float:
        """The ledger clock, validated: callers derive expiries from it, never from a clock of their own."""
        return self._now()

    def _current_owner(self) -> dict[str, Any]:
        owner = dict(self.owner_probe.current())
        errors = _owner_errors(owner, "owner")
        if errors:
            raise InvocationLedgerError("; ".join(errors))
        return owner

    @staticmethod
    def _transition(attempt: dict[str, Any], state: str, outcome: str | None, at: float, reason: str) -> None:
        problem = transition_error(attempt["state"], state, outcome)
        if problem is not None:
            raise InvocationLedgerError(
                f"attempt {attempt['attempt_id']} cannot move from {attempt['state']!r} to {state!r}"
                + (f" ({outcome})" if outcome else "") + f": {problem}"
            )
        # A clock that steps backwards never makes the history unorderable.
        at = max(at, attempt["history"][-1]["at"])
        attempt["state"] = state
        attempt["outcome"] = outcome
        attempt["history"].append({"state": state, "outcome": outcome, "at": at, "reason": reason[:MAX_REASON_CHARS]})
        attempt["charge"] = derived_charge(attempt)

    @staticmethod
    def _by_reservation(document: Mapping[str, Any], reservation_id: str) -> dict[str, Any]:
        for attempt in document["attempts"].values():
            if attempt["reservation_id"] == reservation_id:
                return attempt
        raise InvocationLedgerError(f"no reservation {reservation_id!r} is recorded; nothing was invoked")

    def _require_owner(self, attempt: Mapping[str, Any]) -> None:
        if attempt["owner"] != self._current_owner():
            raise InvocationLedgerError(
                f"reservation {attempt['reservation_id']} belongs to another process; nothing was invoked"
            )

    @staticmethod
    def _charged(document: Mapping[str, Any], budget_id: str) -> dict[str, int]:
        return _charged_totals(document, budget_id)

    def _sweep(self, document: dict[str, Any], budget_id: str | None) -> list[dict[str, Any]]:
        """Expire stale reservations and act on attempts whose owner is gone. Unknown owners are left alone."""
        now = self._now()
        changes = []
        for attempt in document["attempts"].values():
            if budget_id is not None and attempt["budget_id"] != budget_id:
                continue
            before = attempt["state"]
            if before == "reserved":
                if now >= attempt["expires_at"]:
                    self._transition(attempt, "terminal", "expired", now, "reservation expired before intent; nothing was charged")
                elif self.owner_probe.status(attempt["owner"]) == "gone":
                    self._transition(
                        attempt, "terminal", "released", now,
                        "owner exited before persisting intent; the effect cannot have run through this ledger",
                    )
            elif before == "invocation-intent" and self.owner_probe.status(attempt["owner"]) == "gone":
                self._transition(
                    attempt, "reconciliation-required", None, now,
                    "owner exited after persisting intent; remote execution is unknown and the attempt stays charged",
                )
            if attempt["state"] != before:
                changes.append({"attempt_id": attempt["attempt_id"], "from": before, "to": attempt["state"],
                                "outcome": attempt["outcome"]})
        return changes

    # Operations ----------------------------------------------------------------------------------------

    def open_budget(self, budget_id: str, limits: Mapping[str, int], *, scope_sha256: str) -> dict[str, Any]:
        """Open an aggregate budget, or return it unchanged when the same limits and scope are already recorded."""
        if not _is_id(budget_id):
            raise InvocationLedgerError(f"budget_id {budget_id!r} is not a valid identifier")
        if not _is_sha256(scope_sha256):
            raise InvocationLedgerError("scope_sha256 must be a SHA-256 hex digest")
        limits = dict(limits) if isinstance(limits, Mapping) else limits
        errors = _limits_errors(limits, "limits")
        if errors:
            raise InvocationLedgerError("; ".join(errors))
        with self._locked() as (root, document):
            existing = document["budgets"].get(budget_id)
            if existing is not None:
                if existing["limits"] != limits or existing["scope_sha256"] != scope_sha256:
                    raise InvocationLedgerError(
                        f"budget {budget_id} is already open with different limits or scope; limits never change "
                        "or reset, and a larger allowance needs new authority"
                    )
                return copy.deepcopy(existing)
            budget = {"budget_id": budget_id, "scope_sha256": scope_sha256, "limits": limits, "created_at": self._now()}
            document["budgets"][budget_id] = budget
            self._save(root, document)
            return copy.deepcopy(budget)

    def reserve(
        self,
        *,
        budget_id: str,
        request_id: str,
        request_sha256: str,
        admission_sha256: str,
        amount: Mapping[str, int],
        expires_at: float,
        lineage: Mapping[str, Any] | None = None,
        refuse_while_unresolved: bool = False,
    ) -> dict[str, Any]:
        """Take a one-use reservation of ``amount`` against ``budget_id``, or refuse without recording anything.

        With ``refuse_while_unresolved`` (the controlled invocation route always sets it), an attempt whose outcome is
        unknown counts as consumed and blocks a blind retry: the reservation is refused while any attempt in the budget
        requires reconciliation or holds intent under an owner not known to be alive, and while any attempt for the
        same ``request_id`` anywhere in the ledger is not a terminal release. These checks run after the sweep, under
        the same lock as the reservation.
        """
        lineage_record = _reservation_inputs(budget_id, request_id, request_sha256, admission_sha256, lineage)
        owner = self._current_owner()
        with self._locked() as (root, document):
            budget = document["budgets"].get(budget_id)
            if budget is None:
                raise InvocationLedgerError(f"no budget {budget_id!r} is open; nothing was reserved")
            amount_record = dict(amount) if isinstance(amount, Mapping) else amount
            errors = _amount_errors(amount_record, budget["limits"], "amount")
            if errors:
                raise InvocationLedgerError("; ".join(errors))
            now = self._now()
            if not _is_time(expires_at) or expires_at <= now:
                raise InvocationLedgerError("expires_at must be a time after now; a stale admission is not reserved")
            if any(attempt["admission_sha256"] == admission_sha256 for attempt in document["attempts"].values()):
                raise InvocationLedgerError("admission replay: this admission already has a reservation; it is one use")
            _check_lineage_parent(document, lineage_record, budget_id)
            if self._sweep(document, budget_id):
                # Recovery is persisted before any refusal below, so a refused reservation never discards it.
                self._save(root, document)
            _check_follower_parent(document, lineage_record)
            if refuse_while_unresolved:
                self._refuse_unresolved(document, budget_id, request_id)
            _check_aggregate(document, budget_id, amount_record)
            attempt = _new_attempt(document, budget_id, request_id, request_sha256, admission_sha256,
                                   lineage_record, amount_record, owner, now, expires_at)
            document["attempts"][attempt["attempt_id"]] = attempt
            self._save(root, document)
            return copy.deepcopy(attempt)

    def _refuse_unresolved(self, document: Mapping[str, Any], budget_id: str, request_id: str) -> None:
        """Refuse while an attempt's outcome is unknown in this budget, or while this request already has an attempt."""
        for attempt in document["attempts"].values():
            if attempt["budget_id"] == budget_id:
                problem = self._unresolved_problem(attempt)
                if problem is not None:
                    raise InvocationLedgerError(
                        f"attempt {attempt['attempt_id']} in budget {budget_id} {problem}; an unknown outcome counts as "
                        "consumed and blocks a blind retry until it is reconciled; nothing was reserved"
                    )
            if attempt["request_id"] == request_id and not _is_released(attempt):
                raise InvocationLedgerError(
                    f"request {request_id} already has attempt {attempt['attempt_id']} ({attempt['state']}"
                    + (f", {attempt['outcome']}" if attempt["outcome"] else "")
                    + "); one request is invoked at most once and is never retried blindly; nothing was reserved"
                )

    def _unresolved_problem(self, attempt: Mapping[str, Any]) -> str | None:
        if attempt["state"] == "reconciliation-required":
            return "requires reconciliation"
        if attempt["state"] == "invocation-intent" and self.owner_probe.status(attempt["owner"]) != "alive":
            return "holds intent under an owner whose status is unknown"
        return None

    def begin_invocation(
        self, reservation_id: str, request_bytes: bytes, *, observers: Sequence[str] = ()
    ) -> dict[str, Any]:
        """Persist invocation intent (compare-and-swap from ``reserved``) and the observer names before any effect."""
        return self._persist_intent(reservation_id, _frozen_bytes(request_bytes), observers, [])

    def _persist_intent(
        self, reservation_id: str, frozen: bytes, observers: Sequence[str], intent_written: list[bool]
    ) -> dict[str, Any]:
        """``intent_written`` gains an entry just before intent is saved, so ``invoke`` knows the attempt is its own
        to settle if anything interrupts it from there on."""
        names = list(observers)
        if not all(isinstance(name, str) and name for name in names):
            raise InvocationLedgerError("observer names must be non-empty strings")
        digest = request_sha256(frozen)
        with self._locked() as (root, document):
            attempt = self._by_reservation(document, reservation_id)
            if attempt["state"] != "reserved":
                raise InvocationLedgerError(
                    f"reservation {reservation_id} was already used (state {attempt['state']}"
                    + (f", outcome {attempt['outcome']}" if attempt["outcome"] else "")
                    + "); a replay never invokes"
                )
            self._require_owner(attempt)
            now = self._now()
            if now >= attempt["expires_at"]:
                self._transition(attempt, "terminal", "expired", now, "reservation expired before intent; nothing was charged")
                self._save(root, document)
                raise InvocationLedgerError(f"reservation {reservation_id} expired; nothing was invoked")
            if digest != attempt["request_sha256"]:
                self._transition(
                    attempt, "terminal", "drift-refused", now,
                    "prepared request bytes changed after reservation; the admission is invalid",
                )
                self._save(root, document)
                raise InvocationLedgerError(
                    f"prepared request changed since reservation {reservation_id}; nothing was invoked and the "
                    "reservation cannot be reused"
                )
            attempt["observers"] = names
            self._transition(attempt, "invocation-intent", None, now, "intent persisted before the effect")
            intent_written.append(True)
            self._save(root, document)
            return copy.deepcopy(attempt)

    def finish(
        self,
        reservation_id: str,
        outcome: str,
        *,
        reason: str,
        observed_usage: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        """Record the terminal outcome of an attempt in ``invocation-intent``. Charges at least the full reservation."""
        if outcome not in EFFECT_OUTCOMES:
            raise InvocationLedgerError(f"outcome {outcome!r} is not an effect outcome")
        with self._locked() as (root, document):
            attempt = self._by_reservation(document, reservation_id)
            if attempt["state"] != "invocation-intent":
                raise InvocationLedgerError(f"reservation {reservation_id} is {attempt['state']}, not invocation-intent")
            self._require_owner(attempt)
            if observed_usage is not None:
                if outcome not in USAGE_OUTCOMES:
                    raise InvocationLedgerError("observed usage is recorded only for a completed or failed effect")
                usage = dict(observed_usage) if isinstance(observed_usage, Mapping) else observed_usage
                errors = _usage_errors(usage, document["budgets"][attempt["budget_id"]]["limits"], "observed_usage")
                if errors:
                    raise InvocationLedgerError("; ".join(errors))
                attempt["observed_usage"] = usage
            self._transition(attempt, "terminal", outcome, self._now(), reason)
            self._save(root, document)
            return copy.deepcopy(attempt)

    def mark_reconciliation_required(self, reservation_id: str, *, reason: str) -> dict[str, Any]:
        with self._locked() as (root, document):
            attempt = self._by_reservation(document, reservation_id)
            if attempt["state"] != "invocation-intent":
                raise InvocationLedgerError(f"reservation {reservation_id} is {attempt['state']}, not invocation-intent")
            self._require_owner(attempt)
            self._transition(attempt, "reconciliation-required", None, self._now(), reason)
            self._save(root, document)
            return copy.deepcopy(attempt)

    def release(self, reservation_id: str, *, reason: str = "cancelled before intent") -> dict[str, Any]:
        """Cancel a reservation whose intent was never persisted. After intent nothing is released."""
        with self._locked() as (root, document):
            attempt = self._by_reservation(document, reservation_id)
            if attempt["state"] != "reserved":
                raise InvocationLedgerError(
                    f"reservation {reservation_id} is {attempt['state']}; cancellation after intent cannot show the "
                    "allowance was unused, so the attempt stays charged"
                )
            self._require_owner(attempt)
            self._transition(attempt, "terminal", "released", self._now(), reason)
            self._save(root, document)
            return copy.deepcopy(attempt)

    def recover(self, budget_id: str | None = None) -> list[dict[str, Any]]:
        """Apply crash recovery: expire stale reservations, release dead owners' reservations that never reached
        intent, and mark dead owners' intents reconciliation-required. Never retries anything."""
        with self._locked() as (root, document):
            changes = self._sweep(document, budget_id)
            if changes:
                self._save(root, document)
            return changes

    def reconcile(self, attempt_id: str, *, reason: str) -> dict[str, Any]:
        """Close an attempt that required reconciliation. It stays charged in full; nothing is invoked again."""
        if not isinstance(reason, str) or not reason.strip():
            raise InvocationLedgerError("reconciliation needs a reason")
        if not _is_id(attempt_id):
            raise InvocationLedgerError(f"attempt_id {attempt_id!r} is not a valid identifier")
        with self._locked() as (root, document):
            attempt = document["attempts"].get(attempt_id)
            if attempt is None:
                raise InvocationLedgerError(f"no attempt {attempt_id!r} is recorded")
            if attempt["state"] != "reconciliation-required":
                raise InvocationLedgerError(f"attempt {attempt_id} is {attempt['state']}, not reconciliation-required")
            self._transition(attempt, "terminal", "reconciled", self._now(), reason)
            self._save(root, document)
            return copy.deepcopy(attempt)

    def attempt(self, reservation_id: str) -> dict[str, Any]:
        with self._locked() as (_root, document):
            return copy.deepcopy(self._by_reservation(document, reservation_id))

    def summary(self, budget_id: str) -> dict[str, Any]:
        if not _is_id(budget_id):
            raise InvocationLedgerError(f"budget_id {budget_id!r} is not a valid identifier")
        with self._locked() as (_root, document):
            budget = document["budgets"].get(budget_id)
            if budget is None:
                raise InvocationLedgerError(f"no budget {budget_id!r} is open")
            charged = self._charged(document, budget_id)
            attempts = [attempt for attempt in document["attempts"].values() if attempt["budget_id"] == budget_id]
            by_state = {state: 0 for state in STATES}
            for attempt in attempts:
                by_state[attempt["state"]] += 1
            return {
                "budget_id": budget_id,
                "limits": dict(budget["limits"]),
                "charged": charged,
                "remaining": {dimension: budget["limits"][dimension] - units for dimension, units in charged.items()},
                "attempts_by_state": by_state,
                "usage_unknown": sum(
                    1 for attempt in attempts
                    if attempt["observed_usage"] is None
                    and (attempt["state"] in {"invocation-intent", "reconciliation-required"}
                         or attempt["outcome"] in CHARGED_OUTCOMES)
                ),
                "reconciliation_required": sorted(
                    attempt["attempt_id"] for attempt in attempts if attempt["state"] == "reconciliation-required"
                ),
            }

    def invoke(
        self,
        reservation_id: str,
        request_bytes: bytes,
        effect: Callable[[bytes, Callable[..., None]], EffectResult],
        *,
        observers: Sequence[Callable[[dict[str, Any]], None]] = (),
    ) -> dict[str, Any]:
        """Run ``effect`` at most once for a reservation, with intent and observers persisted first.

        ``effect`` receives the frozen request bytes whose digest was checked when intent was persisted, and a
        ``report(kind, detail)`` callback that forwards to the observers with the persisted attempt.

        From the moment intent is written, the whole lifecycle (observer notification, the effect, recording the
        result and the final notification) is guarded: if anything escapes while the attempt is still in
        ``invocation-intent``, it is marked ``reconciliation-required`` durably before the exception propagates.
        A terminal record already written is kept unchanged.
        """
        frozen = _frozen_bytes(request_bytes)
        names = [getattr(observer, "__qualname__", type(observer).__name__) for observer in observers]
        intent_written: list[bool] = []
        try:
            intent = self._persist_intent(reservation_id, frozen, names, intent_written)
            return self._run_after_intent(reservation_id, frozen, intent, effect, observers)
        except BaseException as interruption:
            if intent_written:
                self._settle_pending_intent(reservation_id, interruption)
            raise

    def _settle_pending_intent(self, reservation_id: str, interruption: BaseException) -> None:
        """Mark the attempt reconciliation-required if it is still in invocation-intent; leave a terminal one alone.

        If marking fails too (for example a second interrupt or a storage error), the original exception still
        propagates with a note, and ``recover()`` marks the attempt once this process has exited.
        """
        try:
            with self._locked() as (root, document):
                attempt = self._by_reservation(document, reservation_id)
                if attempt["state"] != "invocation-intent":
                    return
                self._transition(
                    attempt, "reconciliation-required", None, self._now(),
                    f"interrupted after intent was persisted ({type(interruption).__name__}); remote execution is "
                    "unknown and the attempt stays charged",
                )
                self._save(root, document)
        except BaseException as failure:
            add_failure_note(interruption,
                f"invocation ledger: marking reservation {reservation_id} reconciliation-required failed "
                f"({_failure_detail(failure)}); recover() marks it once this process has exited"
            )

    def _run_after_intent(
        self,
        reservation_id: str,
        frozen: bytes,
        intent: dict[str, Any],
        effect: Callable[[bytes, Callable[..., None]], EffectResult],
        observers: Sequence[Callable[[dict[str, Any]], None]],
    ) -> dict[str, Any]:
        notify = _notifier(observers)

        def report(kind: str, detail: Mapping[str, Any] | None = None) -> None:
            current = self.attempt(reservation_id)
            if current["state"] != "invocation-intent":
                raise InvocationLedgerError(f"callback after reservation {reservation_id} left invocation-intent")
            notify(str(kind), current, detail)

        self._notify_intent(reservation_id, notify, intent)
        try:
            result = effect(frozen, report)
        except Exception as failure:
            self._settle_failure(reservation_id, failure, notify=notify)
            raise
        if not isinstance(result, EffectResult) or result.status not in USAGE_OUTCOMES:
            final = self.finish(reservation_id, "unknown",
                                reason="the effect returned no recognizable result; charged in full")
            notify("terminal", final)
            raise InvocationLedgerError("effect returned no recognizable result; the attempt is charged in full")
        return self._finish_with_result(reservation_id, result.status, result.usage, notify)

    def invocation(
        self, reservation_id: str, request_bytes: bytes, *,
        observers: Sequence[Callable[[dict[str, Any]], None]] = (),
    ) -> _LedgerInvocation:
        """Persist/notify before the inline body, then settle without a generator boundary.

        Ordinary context methods preserve even an observer's StopIteration.
        Exceptions charge in full; interruptions retain reconciliation semantics.
        """
        return _LedgerInvocation(self, reservation_id, request_bytes, observers)

    def _notify_intent(self, reservation_id: str, notify: Callable[..., None], intent: dict[str, Any]) -> None:
        try:
            notify("invocation-intent", intent)
        except Exception as failure:
            self._settle_failure(reservation_id, failure, before_effect=True)
            raise

    def _settle_failure(
        self, reservation_id: str, failure: Exception, *, notify: Callable[..., None] | None = None,
        before_effect: bool = False,
    ) -> None:
        """Keep an existing terminal record and the primary failure, including when settlement/observers fail."""
        try:
            current = self.attempt(reservation_id)
            if current["state"] == "terminal":
                final = current
            elif before_effect:
                final = self.finish(reservation_id, "aborted-before-effect",
                    reason="an observer failed before the effect; the attempt stays charged in full")
            else:
                final = self._finish_after_exception(reservation_id, failure)
            if notify is not None:
                notify("terminal", final)
        except BaseException as secondary:
            add_failure_note(failure,
                f"invocation ledger: settlement or terminal observer failed ({_failure_detail(secondary)}); "
                "the original failure is retained")

    def _finish_after_exception(self, reservation_id: str, failure: Exception) -> dict[str, Any]:
        if issubclass(type(failure), InvocationTimeout):
            return self.finish(reservation_id, "timeout", reason="the effect timed out; charged in full")
        if issubclass(type(failure), InvocationCancelled):
            return self.finish(reservation_id, "cancelled",
                               reason="cancelled locally; remote cancellation is unknown, charged in full")
        return self.finish(reservation_id, "unknown", reason="the effect raised; remote outcome unknown, charged in full")

    def _finish_with_result(
        self, reservation_id: str, status: str, usage: Mapping[str, int] | None, notify: Callable[..., None]
    ) -> dict[str, Any]:
        try:
            final = self.finish(
                reservation_id, status, observed_usage=usage,
                reason=f"the effect reported {status}" + ("" if usage is not None else "; usage unknown, charged in full"),
            )
        except InvocationLedgerError as exc:
            final = self.finish(reservation_id, "unknown",
                                reason="the effect reported unusable usage; not recorded, charged in full")
            notify("terminal", final)
            raise InvocationLedgerError(f"effect usage was refused and the attempt is charged in full: {exc}") from exc
        notify("terminal", final)
        return final


class _LedgerInvocation(ContextDecorator):
    """One-shot lifecycle context; callbacks never run under its entry lock."""

    def __init__(self, ledger: InvocationLedger, reservation_id: str, request_bytes: bytes,
                 observers: Sequence[Callable[[dict[str, Any]], None]]) -> None:
        self._ledger = ledger
        self._reservation_id = reservation_id
        self._request_bytes = request_bytes
        self._observers = observers
        self._entry_lock = threading.Lock()
        self._entered = False
        self._intent_written: list[bool] = []
        self._handle: InvocationHandle | None = None
        self._notify: Callable[..., None] | None = None

    def _recreate_cm(self) -> _LedgerInvocation:
        return type(self)(self._ledger, self._reservation_id, self._request_bytes, self._observers)

    def __enter__(self) -> InvocationHandle:
        with self._entry_lock:
            if self._entered:
                raise InvocationLedgerError("invocation context is one-shot and already entered")
            self._entered = True
        frozen = _frozen_bytes(self._request_bytes)
        names = [getattr(observer, "__qualname__", type(observer).__name__) for observer in self._observers]
        try:
            intent = self._ledger._persist_intent(self._reservation_id, frozen, names, self._intent_written)
            self._notify = _notifier(self._observers)
            self._handle = InvocationHandle(self._ledger, self._reservation_id, frozen, self._notify)
            self._ledger._notify_intent(self._reservation_id, self._notify, intent)
            return self._handle
        except BaseException as interruption:
            if self._intent_written:
                self._ledger._settle_pending_intent(self._reservation_id, interruption)
            raise

    def __exit__(self, kind: Any, failure: BaseException | None, traceback: Any) -> bool:
        del kind, traceback
        if self._handle is None or self._notify is None:
            raise InvocationLedgerError("invocation context did not enter successfully")
        if failure is not None:
            if issubclass(type(failure), Exception):
                self._ledger._settle_failure(self._reservation_id, failure, notify=self._notify)
            if self._intent_written:
                self._ledger._settle_pending_intent(self._reservation_id, failure)
            return False
        try:
            self._handle.final = self._ledger._finish_with_result(
                self._reservation_id, self._handle.status, self._handle.usage, self._notify)
        except BaseException as interruption:
            if self._intent_written:
                self._ledger._settle_pending_intent(self._reservation_id, interruption)
            raise
        return False


def _notifier(observers: Sequence[Callable[[dict[str, Any]], None]]) -> Callable[..., None]:
    def notify(event: str, attempt: dict[str, Any], detail: Mapping[str, Any] | None = None) -> None:
        for observer in observers:
            observer({"event": event, "detail": dict(detail or {}), "attempt": copy.deepcopy(attempt)})
    return notify


class InvocationHandle:
    """The live side of one invocation opened by ``InvocationLedger.invocation``."""

    def __init__(self, ledger: InvocationLedger, reservation_id: str, request_bytes: bytes,
                 notify: Callable[..., None]) -> None:
        self.ledger = ledger
        self.reservation_id = reservation_id
        self.request_bytes = request_bytes
        self.status = "completed"
        self.usage: Mapping[str, int] | None = None
        self.final: dict[str, Any] | None = None
        self._notify = notify

    def require_intent(self) -> dict[str, Any]:
        """Re-read the persisted attempt: still in invocation-intent, owned by this process, for these exact bytes."""
        current = self.ledger.attempt(self.reservation_id)
        if current["state"] != "invocation-intent":
            raise InvocationLedgerError(
                f"reservation {self.reservation_id} is {current['state']}, not invocation-intent; nothing more is sent"
            )
        if current["request_sha256"] != request_sha256(self.request_bytes):
            raise InvocationLedgerError(f"reservation {self.reservation_id} is for other request bytes")
        self.ledger._require_owner(current)
        return current

    def report(self, kind: str, detail: Mapping[str, Any] | None = None) -> None:
        """Forward an event to the observers with the persisted attempt, after checking it is still in intent."""
        self._notify(str(kind), self.require_intent(), detail)

    def record(self, status: str, usage: Mapping[str, int] | None = None) -> None:
        """What the effect observed: ``completed`` or ``failed`` and any usage, recorded when the body ends."""
        if status not in USAGE_OUTCOMES:
            raise InvocationLedgerError(f"status {status!r} is not completed or failed")
        self.status, self.usage = status, usage
