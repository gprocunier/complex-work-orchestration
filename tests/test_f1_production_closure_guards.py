"""Refusal paths at the production adapter, using only the fake bd process."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_production_closure as production

closure, original, qualified = production.closure, production.original, production.qualified


class F1ProductionClosureGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = production.ProductionClosureTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.builders = self.fixture.builders

    def test_r4_C01_F1_default_gate_refuses_before_setup_and_reads_with_patched_positive_control(self):
        self.assertIs(qualified.PRODUCTION_CLOSURE_AVAILABLE, False)
        case = self.builders.compact()
        with self.fixture.provisioned(case) as (process, custody, db), \
                patch.object(qualified, "_directory", wraps=qualified._directory) as directory, \
                patch.object(qualified, "_read_at", wraps=qualified._read_at) as read, \
                patch.object(qualified, "_BEADS_CALL", wraps=qualified._BEADS_CALL) as run_bd:
            with self.assertRaisesRegex(original.ClosureError, "production closure is unavailable"), \
                    qualified.production_custody(str(custody), database=str(db), actor="EXAMPLE-supervisor",
                                                 **process.authority):
                self.fail("Production registration ignored its default-off gate")
            run_bd.assert_not_called()
            directory.assert_not_called()
            read.assert_not_called()
            self.assertEqual(process.calls, [])
            with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True), \
                    qualified.production_custody(str(custody), database=str(db), actor="EXAMPLE-supervisor",
                                                 **process.authority) as host:
                self.fixture.reviewed(case, host, custody)
                result = closure.execute_qualified_completed(host)
                self.assertEqual(result["state"], "COMPLETED")
                self.assertGreater(directory.call_count, 0)
                self.assertGreater(read.call_count, 0)
                self.assertGreater(run_bd.call_count, 0)
                self.assertEqual([command[0] for command in process.effects], ["comment", "close"])
        self.assertIs(qualified.PRODUCTION_CLOSURE_AVAILABLE, False)

    def test_F1_M029_M030_bd_gate_refuses_each_action_after_registration_with_positive_control(self):
        case = self.builders.compact()
        with patch.object(qualified, "_BEADS_CALL", wraps=qualified._BEADS_CALL) as run_bd, \
                self.fixture.registered(case) as (host, process, custody):
            self.fixture.reviewed(case, host, custody)
            state = qualified._state(host)
            before = run_bd.call_count
            commands = (["show", "--json", "--include-comments", "--", case.bead["id"]],
                        ["comment", "--", case.bead["id"], "EXAMPLE held summary"],
                        ["close", "--reason", "Bound delivery accepted", "--", case.bead["id"]])
            with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", False):
                for command in commands:
                    with self.subTest(action=command[0]), \
                            self.assertRaisesRegex(original.ClosureError, "production closure is unavailable"):
                        qualified._bd(state, command)
            self.assertEqual(run_bd.call_count, before)
            self.assertEqual(process.effects, [])
            self.assertTrue(closure.execute_qualified_completed(host)["completed"])
            self.assertEqual([command[0] for command in process.effects], ["comment", "close"])

    def test_F1_M024_example_scope_is_required_independently_of_example_task_id(self):
        case = self.builders.compact()
        for scope in ("EXAMPLE-only", "production"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory(prefix="EXAMPLE-F1-scope-") as temporary:
                custody = Path(temporary)
                bridge = self.builders.provision(case, custody)
                value = json.loads((custody / "contract.json").read_bytes())
                value["scope"] = scope
                self.builders.write(custody, "contract.json", original._freeze(value))
                with patch.object(closure, "run_bd", bridge):
                    if scope == "EXAMPLE-only":
                        with qualified.example_custody(str(custody)) as host:
                            self.builders.reviewed(case, host, custody)
                            self.assertTrue(closure.execute_qualified_completed(host)["fake_completed"])
                        self.assertEqual([command[0] for command in bridge.effects], ["comment", "close"])
                    else:
                        with self.assertRaisesRegex(original.ClosureError, "only explicit EXAMPLE tasks"), \
                                qualified.example_custody(str(custody)):
                            self.fail("Closure accepted a non-EXAMPLE scope")
                        self.assertEqual(bridge.effects, [])

    def test_F1_M025_actor_guard_requires_type_nonempty_and_exact_trim(self):
        case = self.builders.compact()
        with self.fixture.provisioned(case) as (process, custody, db), \
                patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True), \
                patch.object(qualified, "_BEADS_CALL", wraps=qualified._BEADS_CALL) as run_bd:
            for actor in ("", " ", " EXAMPLE-supervisor ", 7):
                with self.subTest(actor=actor), \
                        self.assertRaisesRegex(original.ClosureError, "explicit Beads actor"), \
                        qualified.production_custody(str(custody), database=str(db), actor=actor,
                                                     **process.authority):
                    self.fail("Production closure accepted an invalid actor")
                run_bd.assert_not_called()
            with qualified.production_custody(str(custody), database=str(db), actor="EXAMPLE-supervisor",
                                                 **process.authority) as host:
                self.fixture.reviewed(case, host, custody)
                self.assertTrue(closure.execute_qualified_completed(host)["completed"])
            self.assertEqual([command[0] for command in process.effects], ["comment", "close"])

    def test_F1_M026_database_guard_refuses_relative_noncanonical_missing_and_symlink_paths(self):
        case = self.builders.compact()
        with self.fixture.provisioned(case) as (process, custody, db), \
                patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True), \
                patch.object(qualified, "_BEADS_CALL", wraps=qualified._BEADS_CALL) as run_bd:
            link = db.parent / "EXAMPLE-alias.db"
            link.symlink_to(db)
            paths = (os.path.relpath(db), str(db.parent / ".." / db.parent.name / db.name),
                     str(db.parent / "EXAMPLE-missing.db"), str(link))
            for database in paths:
                with self.subTest(database=database), \
                        self.assertRaisesRegex(original.ClosureError, "existing canonical Beads database"), \
                        qualified.production_custody(str(custody), database=database, actor="EXAMPLE-supervisor",
                                                     **process.authority):
                    self.fail("Production closure accepted an invalid database path")
                run_bd.assert_not_called()
            with qualified.production_custody(str(custody), database=str(db), actor="EXAMPLE-supervisor",
                                                 **process.authority) as host:
                self.fixture.reviewed(case, host, custody)
                self.assertTrue(closure.execute_qualified_completed(host)["completed"])
            self.assertEqual([command[0] for command in process.effects], ["comment", "close"])


    def test_F1_M036_bind_rechecks_review_custody_before_another_bd_read(self):
        """The retired review-file drift case now targets verified host acceptance."""
        case = self.builders.compact()
        for drift in (False, True):
            with self.subTest(drift=drift), self.fixture.registered(case) as (host, process, custody):
                qualified.observe(host)
                current = original._current

                def current_and_drift(*args, current=current, drift=drift, process=process, **kwargs):
                    result = current(*args, **kwargs)
                    if drift:
                        path = process.store.root / (process.authority["acceptance_record"] + ".json")
                        path.write_bytes(path.read_bytes() + b" ")
                    return result

                before = len(process.calls)
                with patch.object(original, "_current", side_effect=current_and_drift):
                    if drift:
                        with self.assertRaisesRegex(original.ClosureError, "digest mismatch"):
                            qualified.bind(host)
                        self.assertEqual(len(process.calls), before)
                    else:
                        qualified.bind(host)
                        self.assertGreater(len(process.calls), before)
                        self.assertEqual(closure.execute_qualified_completed(host, dry_run=True)["state"], "VALIDATED")
                self.assertEqual(process.effects, [])

    def test_F1_M038_non_boolean_dry_run_refuses_without_reads_or_effects_then_boolean_control(self):
        case = self.builders.compact()
        with self.fixture.registered(case) as (host, process, custody):
            self.fixture.reviewed(case, host, custody)
            before = len(process.calls)
            for dry_run in ("false", 0, 1, None, []):
                with self.subTest(dry_run=dry_run), \
                        self.assertRaisesRegex(original.ClosureError, "dry_run must be an exact Boolean"):
                    closure.execute_qualified_completed(host, dry_run=dry_run)
                self.assertEqual(len(process.calls), before)
                self.assertEqual(process.effects, [])
            self.assertEqual(closure.execute_qualified_completed(host, dry_run=True)["state"], "VALIDATED")
            self.assertEqual(process.effects, [])
            self.assertTrue(closure.execute_qualified_completed(host, dry_run=False)["completed"])
            self.assertEqual([command[0] for command in process.effects], ["comment", "close"])

    def test_F1_M033_task_mapping_guard_precedes_production_projection(self):
        case = self.builders.compact()
        with self.fixture.registered(case) as (host, process, _custody):
            state = qualified._state(host)
            with patch.object(qualified, "_production_projection", wraps=qualified._production_projection) as project:
                qualified._task(state, process.bead)
                project.assert_called_once()
                for projection in ([None], [True], ["EXAMPLE-invalid"], [3]):
                    with self.subTest(projection=projection):
                        project.reset_mock()
                        process.show_projection = lambda projection=projection: projection
                        with self.assertRaisesRegex(original.ClosureError, "authoritative task mapping"):
                            qualified._task(state, process.bead)
                        project.assert_not_called()
            self.assertEqual(process.effects, [])


if __name__ == "__main__":
    unittest.main()
