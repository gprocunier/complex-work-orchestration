from __future__ import annotations

from typing import Any


SESSION_DISPOSITIONS = {"accepted", "accepted-with-warning", "quarantined"}
ARTIFACT_DISPOSITIONS = {
    "accepted",
    "independent-validation-required",
    "architect-adjudication-required",
    "rejected",
}
VALIDATION_OUTCOMES = {"not-run", "passed", "failed"}
DISPOSITION_FIELDS = {
    "session_disposition",
    "artifact_disposition",
    "artifact_validation",
}


def _validation(*, eligible: bool, attempts: int, outcome: str, reason: str) -> dict[str, Any]:
    return {
        "eligible": eligible,
        "max_attempts": 1,
        "attempts_used": attempts,
        "outcome": outcome,
        "reason": reason,
    }


def _result(session: str, artifact: str, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_disposition": session,
        "artifact_disposition": artifact,
        "artifact_validation": validation,
    }


def derive_disposition(
    *,
    status: str,
    requested_model: str,
    actual_model: str | None,
    usage: dict[str, Any],
    budget: dict[str, Any],
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mismatch = actual_model is None or actual_model != requested_model or status == "model-mismatch"
    if mismatch:
        return _result(
            "quarantined",
            "rejected",
            _validation(eligible=False, attempts=0, outcome="not-run", reason="missing or mismatched model"),
        )

    compactions = usage.get("context_compactions", 0)
    if isinstance(compactions, int) and compactions > int(budget.get("max_compactions", 0)):
        return _result(
            "quarantined",
            "architect-adjudication-required",
            _validation(eligible=False, attempts=0, outcome="not-run", reason="context compaction requires architect adjudication"),
        )

    hard_dimensions = 0
    soft_dimensions = 0
    for field, soft_key, hard_key in (
        ("tool_calls", "tool_calls_soft", "tool_calls_hard"),
        ("elapsed_seconds", "runtime_seconds_soft", "runtime_seconds_hard"),
    ):
        value = usage.get(field)
        if isinstance(value, (int, float)):
            if value > budget.get(hard_key, float("inf")):
                hard_dimensions += 1
            elif value > budget.get(soft_key, float("inf")):
                soft_dimensions += 1
    suites = usage.get("full_suite_runs")
    if isinstance(suites, int) and suites > int(budget.get("max_full_suite_runs", 0)):
        hard_dimensions += 1

    budget_validation_eligible = bool(hard_dimensions or soft_dimensions >= 2)
    if budget_validation_eligible and isinstance(validation, dict) and validation.get("attempts_used") == 1:
        outcome = validation.get("outcome")
        if outcome == "passed":
            return _result(
                "quarantined",
                "accepted",
                _validation(eligible=False, attempts=1, outcome="passed", reason="independent validation passed"),
            )
        if outcome == "failed":
            return _result(
                "quarantined",
                "rejected",
                _validation(eligible=False, attempts=1, outcome="failed", reason="independent validation failed"),
            )

    if hard_dimensions:
        return _result(
            "quarantined",
            "independent-validation-required",
            _validation(eligible=True, attempts=0, outcome="not-run", reason="budget-only hard overrun"),
        )
    if soft_dimensions >= 2:
        return _result(
            "quarantined",
            "independent-validation-required",
            _validation(eligible=True, attempts=0, outcome="not-run", reason="multiple soft budget overruns"),
        )
    if status in {"needs-architect-realignment", "budget-exhausted", "blocked"}:
        return _result(
            "quarantined",
            "architect-adjudication-required",
            _validation(eligible=False, attempts=0, outcome="not-run", reason="non-budget realignment requires architect adjudication"),
        )
    if status == "soft-limit" or soft_dimensions == 1:
        return _result(
            "accepted-with-warning",
            "accepted",
            _validation(eligible=False, attempts=0, outcome="not-run", reason="one soft budget limit exceeded"),
        )
    return _result(
        "accepted",
        "accepted",
        _validation(eligible=False, attempts=0, outcome="not-run", reason="completed within policy"),
    )


def validate_disposition(
    *,
    packet: dict[str, Any],
    result: dict[str, Any],
    required: bool,
) -> list[str]:
    present = DISPOSITION_FIELDS.intersection(result)
    if not present:
        return ["current packet requires disposition fields"] if required else []
    if present != DISPOSITION_FIELDS:
        return ["session_disposition, artifact_disposition, and artifact_validation must be provided together"]

    errors: list[str] = []
    if result.get("session_disposition") not in SESSION_DISPOSITIONS:
        errors.append("session_disposition is invalid")
    if result.get("artifact_disposition") not in ARTIFACT_DISPOSITIONS:
        errors.append("artifact_disposition is invalid")
    validation = result.get("artifact_validation")
    if not isinstance(validation, dict):
        return [*errors, "artifact_validation must be an object"]
    expected_keys = {"eligible", "max_attempts", "attempts_used", "outcome", "reason"}
    if set(validation) != expected_keys:
        errors.append("artifact_validation must contain exactly eligible, max_attempts, attempts_used, outcome, and reason")
    if not isinstance(validation.get("eligible"), bool):
        errors.append("artifact_validation.eligible must be boolean")
    if validation.get("max_attempts") != 1:
        errors.append("artifact_validation.max_attempts must be 1")
    attempts = validation.get("attempts_used")
    outcome = validation.get("outcome")
    if attempts not in {0, 1}:
        errors.append("artifact_validation.attempts_used must be 0 or 1")
    if outcome not in VALIDATION_OUTCOMES:
        errors.append("artifact_validation.outcome is invalid")
    if attempts == 0 and outcome != "not-run":
        errors.append("attempts_used 0 requires outcome not-run")
    if attempts == 1 and outcome not in {"passed", "failed"}:
        errors.append("attempts_used 1 requires outcome passed or failed")
    if attempts == 1 and validation.get("eligible") is not False:
        errors.append("a completed validation attempt cannot remain eligible")
    if not isinstance(validation.get("reason"), str) or not validation.get("reason", "").strip():
        errors.append("artifact_validation.reason must be non-empty")

    expected = derive_disposition(
        status=str(result.get("status") or ""),
        requested_model=str(packet.get("requested_model") or ""),
        actual_model=result.get("actual_model") if isinstance(result.get("actual_model"), str) else None,
        usage=result.get("usage") if isinstance(result.get("usage"), dict) else {},
        budget=packet.get("budget") if isinstance(packet.get("budget"), dict) else {},
        validation=validation,
    )
    for field in ("session_disposition", "artifact_disposition"):
        if result.get(field) != expected[field]:
            errors.append(f"{field} must be {expected[field]!r} for this return")
    for field in ("eligible", "max_attempts", "attempts_used", "outcome"):
        if validation.get(field) != expected["artifact_validation"][field]:
            errors.append(f"artifact_validation.{field} is inconsistent with this return")
    return errors
