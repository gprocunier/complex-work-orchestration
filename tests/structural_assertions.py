"""Counted assertion support for explicit arrange/act family tables in tests.

These projections inspect a real action's result. They do not arrange fixtures,
run cases, generate selectors, or change unittest's lifecycle.
"""

from __future__ import annotations

from typing import Any, Callable, Literal, NamedTuple
from unittest import TestCase


class Check(NamedTuple):
    value: Callable[[Any], Any]
    expected: Any = None
    operation: Literal[
        "equal", "not-equal", "true", "false", "contains", "not-contains",
        "in", "not-in", "none", "greater", "less", "is-instance",
    ] = "equal"
    message: Callable[[Any], Any] | None = None


def assert_checks(case: TestCase, result: Any, checks: tuple[Check, ...]) -> None:
    assertions = {
        "equal": case.assertEqual,
        "not-equal": case.assertNotEqual,
        "true": lambda value, _, message: case.assertTrue(value, message),
        "false": lambda value, _, message: case.assertFalse(value, message),
        "contains": lambda value, expected, message: case.assertIn(expected, value, message),
        "not-contains": lambda value, expected, message: case.assertNotIn(expected, value, message),
        "in": case.assertIn,
        "not-in": case.assertNotIn,
        "none": lambda value, _, message: case.assertIsNone(value, message),
        "greater": case.assertGreater,
        "less": case.assertLess,
        "is-instance": case.assertIsInstance,
    }
    for check in checks:
        message = check.message(result) if check.message is not None else None
        assertions[check.operation](check.value(result), check.expected, message)
