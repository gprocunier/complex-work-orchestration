"""Immutable start allowances for the contained pool campaign."""

from .invocation_ledger import RELEASING_OUTCOMES, STATES
from .native_pool_contracts import canonical_sha256
from .native_pool_transaction import NativePoolTransactionError

CAMPAIGN_START_CAP = 20
CAMPAIGN_MAX_START_INCREMENT = CAMPAIGN_START_CAP // 2
CAMPAIGN_MAX_START_CAP = 3 * CAMPAIGN_START_CAP
CAMPAIGN_BUDGET_ID = "native-pool-contained-qualification"
CAMPAIGN_SCOPE_SHA256 = canonical_sha256({"campaign": CAMPAIGN_BUDGET_ID, "start_cap": CAMPAIGN_START_CAP})
_INCREMENT_PREFIX = CAMPAIGN_BUDGET_ID + ":increment:"


def valid_start_limit(value):
    return type(value) is int and CAMPAIGN_START_CAP <= value <= CAMPAIGN_MAX_START_CAP


def _require(condition, reason):
    if not condition:
        raise NativePoolTransactionError(reason)


def _increment_scope(previous, budget_id, previous_limit, start_limit):
    return canonical_sha256({"campaign": CAMPAIGN_BUDGET_ID, "budget_id": budget_id,
                             "previous_budget_id": previous["budget_id"],
                             "previous_scope_sha256": previous["scope_sha256"],
                             "previous_start_limit": previous_limit, "start_limit": start_limit})


def next_allowance(document, status, start_limit):
    """Derive the linked budget to append to an already verified campaign."""
    budget_ids = status["budget_ids"]
    budget_id = _INCREMENT_PREFIX + str(len(budget_ids))
    previous = document["budgets"][budget_ids[-1]]
    scope = _increment_scope(previous, budget_id, status["cap"], start_limit)
    return budget_id, {"starts": start_limit - status["cap"]}, scope


def _prior_allowances(budgets):
    original = budgets.get(CAMPAIGN_BUDGET_ID)
    _require(original is not None, "campaign-ledger-enrollment-required")
    _require(original["limits"] == {"starts": CAMPAIGN_START_CAP}
             and original["scope_sha256"] == CAMPAIGN_SCOPE_SHA256, "campaign-original-budget-drift")
    allowed = {CAMPAIGN_BUDGET_ID: CAMPAIGN_START_CAP}
    previous, cap = original, CAMPAIGN_START_CAP
    increments = {key: value for key, value in budgets.items() if key.startswith(_INCREMENT_PREFIX)}
    for ordinal in range(1, len(increments) + 1):
        budget_id = _INCREMENT_PREFIX + str(ordinal)
        allowance = increments.get(budget_id)
        starts = _increment_size(allowance, previous, budget_id, cap)
        allowed[budget_id] = starts
        previous, cap = allowance, cap + starts
    return allowed


def _increment_size(allowance, previous, budget_id, cap):
    _require(allowance is not None and allowance["limits"].keys() == {"starts"}, "campaign-allowance-link-invalid")
    starts = allowance["limits"]["starts"]
    _require(starts <= CAMPAIGN_MAX_START_INCREMENT and valid_start_limit(cap + starts)
             and allowance["scope_sha256"] == _increment_scope(previous, budget_id, cap, cap + starts),
             "campaign-allowance-link-invalid")
    return starts


def _start_charge(attempt):
    released = attempt["state"] == "terminal" and attempt["outcome"] in RELEASING_OUTCOMES
    charge = 0 if released else 1
    _require(attempt["amount"] == {"starts": 1} and attempt["charge"] == {"starts": charge},
             "campaign-start-charge-drift")
    return charge


def campaign_start_snapshot(document):
    """Derive campaign capacity and charges from one validated ledger snapshot."""
    limits = _prior_allowances(document["budgets"])
    remaining = dict(limits)
    by_state = dict.fromkeys(STATES, 0)
    for attempt in document["attempts"].values():
        budget_id = attempt["budget_id"]
        if budget_id in limits:
            remaining[budget_id] -= _start_charge(attempt)
            by_state[attempt["state"]] += 1
    _require(min(remaining.values()) >= 0, "campaign-allowance-overdrawn")
    cap, available = sum(limits.values()), sum(remaining.values())
    return {"cap": cap, "charged": cap - available, "remaining": available, "attempts_by_state": by_state,
            "budget_ids": tuple(limits), "remaining_by_budget": remaining}
