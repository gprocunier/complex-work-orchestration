from __future__ import annotations

import argparse
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_temp  # noqa: E402


class TempDurationValidationTests(unittest.TestCase):
    def test_valid_durations_preserve_existing_conversion(self) -> None:
        cases = (
            ("48h", 172800),
            ("2d", 172800),
            ("15m", 900),
            ("30", 30),
            (" 1.5 H ", 5400),
            (" 2D ", 172800),
            ("0.5m", 30),
            ("1.9s", 1),
            ("0.999s", 0),
            ("0", 0),
            ("-0.0", 0),
            ("-0.0d", 0),
            ("1e200", int(1e200)),
            ("1e200d", int(1e200 * 86400)),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(cwo_temp.parse_duration_seconds(value), expected)

    def test_negative_durations_are_rejected_before_truncation(self) -> None:
        values = (
            "-0.1s",
            "-0.999s",
            "-1s",
            "-1e-300",
            "-5e-324",
            "-0.01m",
            "-0.0001h",
            "-0.000001d",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    cwo_temp.parse_duration_seconds(value)

    def test_nonfinite_amounts_and_scaled_overflow_are_argument_errors(self) -> None:
        for value in (
            "nan",
            "NaNs",
            "inf",
            "+inf",
            "-inf",
            "Infinity",
            "1e309",
            "-1e309",
            "1e308m",
            "1e308h",
            "1e308d",
        ):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    cwo_temp.parse_duration_seconds(value)

    def test_invalid_duration_text_remains_an_argument_error(self) -> None:
        for value in ("", "  ", "invalid-duration", "1w", "1ss"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    cwo_temp.parse_duration_seconds(value)

    def test_cli_rejects_invalid_duration_before_cleanup(self) -> None:
        for value in (
            "",
            "invalid-duration",
            "nan",
            "inf",
            "-inf",
            "1e309",
            "1e308d",
            "-0.1s",
            "-1e-300",
            "-0.01m",
        ):
            with self.subTest(value=value):
                output = io.StringIO()
                errors = io.StringIO()
                with patch.object(
                    cwo_temp, "cleanup_cwo_temp", return_value={"dry_run": True, "actions": []}
                ) as cleanup:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                        with self.assertRaises(SystemExit) as raised:
                            cwo_temp.main(["cleanup", f"--older-than={value}", "--json"])
                    cleanup.assert_not_called()
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("usage:", errors.getvalue())
                self.assertIn("error:", errors.getvalue())
                self.assertIn("--older-than", errors.getvalue())

    def test_valid_cli_keeps_duration_and_dry_run_defaults(self) -> None:
        for argv, expected_seconds in (
            (["cleanup", "--older-than", "0.5m", "--json"], 30),
            (["cleanup", "--json"], 48 * 3600),
        ):
            with self.subTest(argv=argv):
                with patch.object(
                    cwo_temp, "cleanup_cwo_temp", return_value={"dry_run": True, "actions": []}
                ) as cleanup:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(cwo_temp.main(argv), 0)
                    cleanup.assert_called_once_with(
                        scope="all",
                        older_than_seconds=expected_seconds,
                        force=False,
                        include_current_session=False,
                    )
                    self.assertIs(cleanup.call_args.kwargs["force"], False)


if __name__ == "__main__":
    unittest.main()
