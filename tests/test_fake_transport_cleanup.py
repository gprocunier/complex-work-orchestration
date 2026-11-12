"""The fake app-server harness accepts a transcript only after a clean close.

``FakeAppServerTransportTests.exercise`` in ``tests/test_supervision_transport.py``
records what the client wrote and what the child received. That transcript shows
that observation has finished only if cleanup succeeded: ``close()`` returned,
``resources_closed`` and ``all_contained`` are true and no cleanup error was
reported. Each case here runs the real fake server and the real ``close()``, then
reports a cleanup outcome through a wrapper, and checks the harness refuses the
transcript. The control passes the real cleanup through and is accepted.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

from tests import test_supervision_transport as TRANSPORT_TESTS  # noqa: E402


def _echo(server, defining) -> None:
    server.request("fake/echo", {"value": 1}, timeout=10)


class CleanupReportCase(NamedTuple):
    original: str
    report: dict
    replace: bool = False


class HarnessCleanupAcceptanceTests(unittest.TestCase):
    def run_harness(self, outcome):
        """Run the harness once; ``outcome(real_cleanup, error_type)`` decides what close() reports."""

        harness = TRANSPORT_TESTS.FakeAppServerTransportTests("test_request_returns_the_correlated_result")
        harness.setUp()
        server_class = TRANSPORT_TESTS.transport("app_server").AppServer
        error_type = TRANSPORT_TESTS.transport("errors").AppServerError
        real_close = server_class.close
        real_cleanups: list[dict] = []

        def close(server):
            real = real_close(server)  # the child and reader really are cleaned up
            real_cleanups.append(dict(real))
            return outcome(dict(real), error_type)

        with mock.patch.object(server_class, "close", close):
            try:
                harness.exercise("core", server_class, "ok", _echo)
            except AssertionError as exc:
                accepted, failure = False, str(exc)
            else:
                accepted, failure = True, None
        self.assertEqual(len(real_cleanups), 1)
        self.assertTrue(real_cleanups[0]["all_contained"] and real_cleanups[0]["resources_closed"])
        return accepted, failure, harness.transcripts

    def assert_refused(self, outcome) -> None:
        accepted, _failure, transcripts = self.run_harness(outcome)
        self.assertFalse(accepted, "the harness accepted a transcript after a failed cleanup")
        self.assertNotIn("core", transcripts)

    def test_control_clean_cleanup_is_accepted(self) -> None:
        accepted, failure, transcripts = self.run_harness(lambda real, _error: real)
        self.assertTrue(accepted, failure)
        self.assertEqual(transcripts["core"]["written"], [{"id": 2, "method": "fake/echo", "params": {"value": 1}}])

    def test_cleanup_error_with_reader_still_running_is_refused(self) -> None:
        # The reviewer's probe: contained, but a resource is still open and an error is reported.
        def outcome(real, error_type):
            error = error_type("app-server-cleanup-incomplete")
            error.app_server_cleanup = {"all_contained": True, "resources_closed": False,
                                        "errors": ["reader-still-running"]}
            raise error

        self.assert_refused(outcome)

    def test_cleanup_error_with_a_clean_report_is_refused(self) -> None:
        def outcome(real, error_type):
            error = error_type("app-server-cleanup-incomplete")
            error.app_server_cleanup = real
            raise error

        self.assert_refused(outcome)

    def test_cleanup_error_without_a_report_is_refused(self) -> None:
        def outcome(real, error_type):
            raise error_type("app-server-cleanup-incomplete")

        self.assert_refused(outcome)

    def test_returned_cleanup_report_rows_are_refused(self) -> None:
        rows = (
            CleanupReportCase("test_returned_cleanup_with_resources_open_is_refused", {"resources_closed": False}),
            CleanupReportCase("test_returned_cleanup_with_errors_is_refused", {"errors": ["reader-still-running"]}),
            CleanupReportCase("test_returned_cleanup_not_contained_is_refused", {"all_contained": False}),
            CleanupReportCase("test_returned_cleanup_missing_fields_is_refused", {"all_contained": True}, True),
        )
        for row in rows:
            with self.subTest(original=row.original):
                self.assert_refused(lambda real, _error, row=row: row.report if row.replace else {**real, **row.report})


if __name__ == "__main__":
    unittest.main()
