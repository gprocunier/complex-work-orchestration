"""S4 finite checks of captured host authority and its final audit binding."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_qualified_closure as fixtures
import production_closure_authority as authority


class ProductionAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"database_id": "EXAMPLE-database", "device": 1,
                         "inode": 2, "owner": 3, "mode": 0o600}
        self.decision = {"adjudication_result": "accepted", "_record_sha256": "1" * 64}
        self.store = SimpleNamespace(require_outside_worker_roots=Mock(),
                                     require_database_identity=Mock(return_value=self.identity),
                                     record_audit_event=Mock())
        self.captured = authority.Authority(
            self.store, "1" * 64, "EXAMPLE-bead", "2" * 64, "3" * 64,
            authority._snapshot(self.identity), authority._snapshot(self.decision))

    def test_capture_requires_setup_identity_then_exact_verified_decision(self):
        """S4 capture checks: no missing identity or refused acceptance can register."""
        with patch.object(authority.host_records, "configured_store", return_value=self.store), \
                patch.object(authority.host_acceptance, "require_acceptance", return_value=self.decision) as verify:
            captured = authority.capture(database="/EXAMPLE/database", bead_id="EXAMPLE-bead",
                                         acceptance_record="1" * 64, return_sha256="2" * 64,
                                         evaluation_sha256="3" * 64)
            self.assertEqual(captured, self.captured)
            self.store.require_outside_worker_roots.assert_called_once_with(())
            self.store.require_database_identity.assert_called_once_with(Path("/EXAMPLE/database"))
            verify.assert_called_once_with(self.store, "1" * 64, bead_id="EXAMPLE-bead",
                return_sha256="2" * 64, evaluation_sha256="3" * 64, database_identity=self.identity)
            verify.side_effect = ValueError("EXAMPLE refused acceptance")
            with self.assertRaisesRegex(ValueError, "refused acceptance"):
                authority.capture(database="/EXAMPLE/database", bead_id="EXAMPLE-bead",
                                  acceptance_record="1" * 64, return_sha256="2" * 64,
                                  evaluation_sha256="3" * 64)
            self.store.require_database_identity.side_effect = ValueError("EXAMPLE missing setup identity")
            verify.reset_mock()
            with self.assertRaisesRegex(ValueError, "missing setup identity"):
                authority.capture(database="/EXAMPLE/database", bead_id="EXAMPLE-bead",
                                  acceptance_record="1" * 64, return_sha256="2" * 64,
                                  evaluation_sha256="3" * 64)
            verify.assert_not_called()

    def test_capture_checks_private_source_and_worker_roots_independently(self):
        """S4 root separation: custody and candidate exclusions precede database I/O."""
        roots = (Path("/EXAMPLE/candidate"), Path("/EXAMPLE/custody"))
        with patch.object(authority.host_records, "configured_store", return_value=self.store), \
                patch.object(authority.host_acceptance, "require_acceptance", return_value=self.decision) as verify:
            authority.capture(database="/EXAMPLE/database", bead_id="EXAMPLE-bead",
                              acceptance_record="1" * 64, return_sha256="2" * 64,
                              evaluation_sha256="3" * 64, worker_writable_roots=roots)
            self.store.require_outside_worker_roots.assert_called_once_with(roots)
            self.store.require_outside_worker_roots.side_effect = ValueError("EXAMPLE overlapping host state")
            self.store.require_database_identity.reset_mock()
            verify.reset_mock()
            with self.assertRaisesRegex(ValueError, "overlapping host state"):
                authority.capture(database="/EXAMPLE/database", bead_id="EXAMPLE-bead",
                                  acceptance_record="1" * 64, return_sha256="2" * 64,
                                  evaluation_sha256="3" * 64, worker_writable_roots=roots)
            self.store.require_database_identity.assert_not_called()
            verify.assert_not_called()

    def test_rechecks_reject_changed_identity_or_verified_decision(self):
        """S4 captured binding: revalidation cannot silently select another authority."""
        with patch.object(authority.host_acceptance, "require_acceptance", return_value=self.decision) as verify:
            self.assertEqual(self.captured.check("/EXAMPLE/database"), self.identity)
            self.store.require_database_identity.return_value = {**self.identity, "database_id": "EXAMPLE-other"}
            verify.reset_mock()
            with self.assertRaisesRegex(ValueError, "identity changed"):
                self.captured.check("/EXAMPLE/database")
            verify.assert_not_called()
            self.store.require_database_identity.return_value = self.identity
            verify.return_value = {**self.decision, "adjudication_result": "rejected"}
            with self.assertRaisesRegex(ValueError, "decision changed"):
                self.captured.check("/EXAMPLE/database")
            self.store.record_audit_event.assert_not_called()

    def test_closure_audit_contains_exact_acceptance_and_database_identity(self):
        """S4 audit binding: successful consumption names its full setup identity."""
        self.captured.record_closure()
        self.store.record_audit_event.assert_called_once_with({
            "event_type": "production_closure_consumed", "bead_id": "EXAMPLE-bead",
            "acceptance_record_sha256": "1" * 64, "return_sha256": "2" * 64,
            "evaluation_sha256": "3" * 64,
            "database_identity": json.loads(self.captured.database_identity)})

    def test_production_guard_requires_registered_authority_with_positive_control(self):
        """S4 issued state: no production bridge can operate without host authority."""
        qualified = fixtures.qualified
        state = SimpleNamespace(bridge=qualified._ProductionBeadsBridge(Path("/EXAMPLE/database"), "EXAMPLE"),
                                authority=None)
        with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True):
            with self.assertRaisesRegex(fixtures.original.ClosureError, "host acceptance authority"):
                qualified._production_guard(state)
            state.authority = Mock()
            qualified._production_guard(state)
            state.authority.check.assert_called_once_with("/EXAMPLE/database")
        with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", False):
            state.authority.reset_mock()
            with self.assertRaisesRegex(fixtures.original.ClosureError, "unavailable"):
                qualified._production_guard(state)
            state.authority.check.assert_not_called()

    def test_every_bd_call_rechecks_authority_before_original_adapter(self):
        """S4 adapter boundary: a late provenance refusal reaches zero Beads calls."""
        qualified = fixtures.qualified
        with patch.object(qualified, "_BEADS_CALL", Mock()) as original_adapter, \
                patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True):
            bridge = qualified._ProductionBeadsBridge(Path("/EXAMPLE/database"), "EXAMPLE")
            state = SimpleNamespace(bridge=bridge, retired=False, authority=Mock())
            state.authority.check.side_effect = ValueError("EXAMPLE late acceptance refusal")
            with self.assertRaisesRegex(fixtures.original.ClosureError, "late acceptance refusal"):
                qualified._bd(state, ["show", "--", "EXAMPLE-bead"])
            original_adapter.assert_not_called()
            state.authority.check.side_effect = None
            qualified._bd(state, ["show", "--", "EXAMPLE-bead"])
            original_adapter.assert_called_once_with([
                "--db", "/EXAMPLE/database", "--actor", "EXAMPLE", "show", "--", "EXAMPLE-bead"])


if __name__ == "__main__":
    unittest.main()
