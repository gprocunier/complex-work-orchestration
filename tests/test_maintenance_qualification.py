"""Current maintenance reader and opaque checks with a providerless record."""
from __future__ import annotations
from copy import deepcopy, copy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from tests import test_maintenance_authority as authority_fixture
from tests.historical_campaign_launcher import HELD_QUALIFICATION_PRODUCERS, run_archived_cases
from tests.maintenance_qualification_fixture import THREAD_ID, TURN_ID, write_fixture_observation
from cwo_core import maintenance_qualification as q
from codex_tool_surface import canonical_sha256 as surface_hash, PROOF_VERSION


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = authority_fixture.MaintenanceAuthorityTests("test_review_positive_no_write_authority")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.plan, self.operation, _ = f.operation(role="review")
        self.plan["children"][0]["bead_id"] = "synthetic-qualification-only"
        directive = f.reseal(self.plan, self.operation)
        self.cap = f.verifier.verify_operation(self.plan, self.operation, directive)
        self.cap.claim()
        self.verifier = f.verifier
        self.output = f.controller / "observed"
        self.home = f.root / "synthetic-codex-home"
        self.home.mkdir()
        binding = {"codex_home": str(self.home), "codex_binary": str(Path(sys.executable).resolve()),
            "codex_binary_sha256": "b" * 64, "requested_model": "test-model",
            "requested_tools": ["exec_command", "write_stdin"], "lockdown_config": {"test": "synthetic-provider-fixture"},
            "lockdown_config_sha256": "c" * 64, "startup_config": {}, "catalog_projection_sha256": None,
            "tool_profile": "read-only-v1", "effect_policy": {"sandbox": "readOnly", "network_access": False,
                "approval_policy": "never", "dynamic_tools": [], "mcp_endpoints": "none"}}
        binding["binding_sha256"] = surface_hash(binding)
        self.proof = {**{k: v for k, v in binding.items() if k != "binding_sha256"},
            "version": PROOF_VERSION, "verified": True, "observed_model": "test-model",
            "observed_tools": ["exec_command", "write_stdin"], "tool_profile": "read-only-v1",
            "capture_binding": binding}
        self.proof["proof_sha256"] = surface_hash(self.proof)

    def observe(self, *, metadata_rows=()):
        observed, self.session_source = write_fixture_observation(
            output=self.output, proof=self.proof, operation=self.cap, verifier=self.verifier,
            plan=self.plan, metadata_rows=metadata_rows)
        return observed

    def check(self, observation):
        return q.check_qualification(observation, operation=self.cap, verifier=self.verifier)

    def adjudicate(self, observation, checked, **kwargs):
        return q.adjudicate_qualification(observation=observation, checked_execution=checked,
            operation=self.cap, verifier=self.verifier, **kwargs)

    def reseal_file(self, name, transform):
        path = self.output / name
        value = json.loads(path.read_text())
        transform(value)
        path.write_text(json.dumps(value))
        report_path = self.output / "observation.json"
        report = json.loads(report_path.read_text())
        report["pins"][name] = q.digest(path.read_bytes())
        report_path.write_text(json.dumps(report))
        return q.digest(report_path.read_bytes())

    def test_observed_checked_qualification_and_consumed_replay_contracts(self):
        observation = self.observe()
        with self.subTest(original_id="test_record_property_is_detached_not_mutable_authority"):
            record = observation.record
            record["model"] = "forged-model"
            record["pins"].clear()
            self.assertEqual(observation.record["model"], "test-model")
        with self.subTest(original_id="test_real_reader_cli_and_opaque_adjudication_positive_fixture"):
            self.assertFalse(observation.record["qualified"])
        checked = self.check(observation)
        with self.subTest(original_id="test_real_reader_cli_and_opaque_adjudication_positive_fixture"):
            receipt = json.loads((self.output / "checker-receipt.json").read_text())
            spec = json.loads((self.output / "checker-intent.json").read_text())["spec"]
            self.assertEqual(spec["argv"][3], str(ROOT / "scripts/check_maintenance_qualification.py"))
            self.assertEqual(receipt["exit_code"], 0)
            self.assertIs(receipt["execution_started"], True)
            self.assertIs(json.loads(receipt["diagnostics"]["stdout"])["authority"], False)
        qualification = self.adjudicate(observation, checked)
        with self.subTest(original_id="test_real_reader_cli_and_opaque_adjudication_positive_fixture"):
            self.assertIs(q.require_maintenance_qualification(qualification, operation=self.cap, verifier=self.verifier), qualification)
            self.assertEqual(qualification.record["origin_expires_at"], observation.record["origin_expires_at"])
            self.assertEqual(qualification.record["execution_sha256"], q.canonical_sha256(receipt))
        with self.subTest(original_id="test_checker_and_adjudicator_replays_are_denied"):
            with self.assertRaisesRegex(q.QualificationError, "already-consumed"):
                self.adjudicate(observation, checked)
            with self.assertRaisesRegex(q.QualificationError, "already-consumed"):
                self.check(observation)

    def test_retired_observer_refuses_a_real_claimed_operation(self):
        with mock.patch.object(q.live_availability, "N1_LIVE_AVAILABLE", True), \
             mock.patch.object(q, "private_write") as write, \
             self.assertRaisesRegex(q.live_availability.NativeLiveUnavailable, "^native-n1-live-unavailable$"):
            q.observe_qualification(operation=self.cap, verifier=self.verifier, plan=self.plan,
                workspace=self.fixture.workspace, output=self.output, session_ledger=None,
                tool_surface_proof=self.proof, control_image_sha256="0" * 64, fit_prompt="fixture")
        self.assertFalse(self.output.exists())
        write.assert_not_called()

    def test_old_true_command_receipt_and_free_json_api_are_rejected(self):
        observation = self.observe()
        with self.assertRaises(TypeError):
            q.adjudicate_qualification(root=self.output, observation_sha256="a" * 64,
                checked_cli_receipt={}, checked_spec={}, runner_sha256="not-a-hash", operation=self.cap, verifier=self.verifier)
        execute = q.checked_command.execute_checked_command
        def wrong_command(spec):
            spec = deepcopy(spec)
            spec["argv"] = ["/usr/bin/true"]
            return execute(spec)
        with mock.patch.object(q.checked_command, "execute_checked_command", side_effect=wrong_command), \
             self.assertRaisesRegex(q.QualificationError, "checked-cli-receipt-invalid"):
            self.check(observation)
        with self.assertRaisesRegex(q.QualificationError, "opaque-checked-execution"):
            self.adjudicate(observation, {"accepted": True})

    def test_serialized_copied_cross_issuer_and_cross_operation_denied(self):
        observation = self.observe()
        for bad in (observation.record, copy(observation), None):
            with self.subTest(type=type(bad).__name__), self.assertRaises(q.QualificationError):
                self.check(bad)
        with self.assertRaisesRegex(q.QualificationError, "foreign-issuer"):
            q._observation_current(observation, operation=self.cap, verifier=self.fixture.make_verifier())
        plan, operation, directive = self.fixture.operation(operation_id="new-operation", role="review")
        cap = self.verifier.verify_operation(plan, operation, directive)
        cap.claim()
        with self.assertRaisesRegex(q.QualificationError, "foreign-operation"):
            q._observation_current(observation, operation=cap, verifier=self.verifier)


    def test_qualification_reuse_new_owner_operation_retains_original_expiry(self):
        observation = self.observe()
        qualification = self.adjudicate(observation, self.check(observation))
        self.fixture.store.settle(self.operation["operation_id"], self.cap.operation_sha256, outcome="contained")
        plan, operation, directive = self.fixture.operation(operation_id="continuation", role="review")
        cap = self.verifier.verify_operation(plan, operation, directive)
        cap.claim()
        self.assertIs(q.require_maintenance_qualification(qualification, operation=cap, verifier=self.verifier), qualification)
        expired = dt.datetime.fromisoformat(qualification.record["origin_expires_at"])
        with self.assertRaisesRegex(q.QualificationError, "not-current"):
            q.require_maintenance_qualification(qualification, operation=cap, verifier=self.verifier, now=expired)


    def test_source_inode_replacement_and_byte_drift_denied(self):
        observation = self.observe()
        source = self.session_source
        saved = source.read_bytes()
        source.unlink()
        source.write_bytes(saved)
        with self.assertRaisesRegex(q.QualificationError, "original-source-drift"):
            self.check(observation)

    def test_original_byte_mutation_after_cli_before_adjudication_denied(self):
        observation = self.observe()
        checked = self.check(observation)
        with self.session_source.open("ab") as stream:
            stream.write(b"{}\n")
        with self.assertRaisesRegex(q.QualificationError, "original-source-drift"):
            self.adjudicate(observation, checked)

    def test_durable_checked_receipt_drift_after_cli_denied(self):
        observation = self.observe()
        checked = self.check(observation)
        (self.output / "checker-receipt.json").write_text("{}")
        with self.assertRaisesRegex(q.QualificationError, "pin-drift"):
            self.adjudicate(observation, checked)

    def test_checker_source_drift_denied(self):
        observation = self.observe()
        pins = q._code_pins()
        with mock.patch.object(q, "_code_pins", side_effect=[pins, {**pins, "other": "d" * 64}]), \
             self.assertRaisesRegex(q.QualificationError, "checker-source-drift"):
            self.check(observation)

    def test_current_checker_refuses_a_resealed_different_control_image(self):
        self.observe()
        image = json.loads((self.output / "control-image.json").read_bytes())
        image["files"]["README.md"]["sha256"] = "0" * 64
        del image["image_sha256"]
        image["image_sha256"] = q.canonical_sha256(image)
        self.reseal_file("control-image.json", lambda value: value.update(image))
        self.reseal_file("intent.json", lambda value: value.update(control_image_sha256=image["image_sha256"]))
        report_path = self.output / "observation.json"
        report = json.loads(report_path.read_bytes())
        report["control_image_sha256"] = image["image_sha256"]
        report_path.write_text(json.dumps(report))
        checker = ROOT / "scripts/check_maintenance_qualification.py"
        result = subprocess.run([sys.executable, "-I", "-B", str(checker), "--root", str(self.output),
            "--observation-sha256", q.digest(report_path.read_bytes()), "--nonce", "a" * 32],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("maintenance-control-image-drift", result.stderr)

    def test_reentrant_checked_executor_invalidates_outer_result(self):
        observation = self.observe()
        execute = q.checked_command.execute_checked_command
        def nested(spec):
            with self.assertRaisesRegex(q.QualificationError, "reentrant"):
                self.check(observation)
            return execute(spec)
        with mock.patch.object(q.checked_command, "execute_checked_command", side_effect=nested), \
             self.assertRaisesRegex(q.QualificationError, "capability-invalidated"):
            self.check(observation)

    def test_revocation_between_cli_and_adjudication_denies(self):
        observation = self.observe()
        checked = self.check(observation)
        self.fixture.store.revoke()
        with self.assertRaisesRegex(ValueError, "authority-not-current"):
            self.adjudicate(observation, checked)

    def test_missing_raw_pin_and_boolean_version_are_rejected_by_reader(self):
        self.observe()
        path = self.output / "observation.json"
        original = json.loads(path.read_text())
        for mutation in (lambda r: r["pins"].pop("session-source.json"), lambda r: r.update(version=True)):
            report = deepcopy(original)
            mutation(report)
            path.write_text(json.dumps(report))
            with self.assertRaises(q.QualificationError):
                q.inspect_observation(root=self.output, observation_sha256=q.digest(path.read_bytes()))

    def test_boolean_closure_counts_and_wrong_thread_and_prompt_rejected_by_reader(self):
        self.observe()
        originals = {p.name: p.read_bytes() for p in self.output.iterdir() if p.is_file()}
        mutations = [
            ("thread-closure.json", lambda r: r.update(allocated_count=True), "thread-closure-invalid"),
            ("terminal.json", lambda r: r.update(id="wrong-thread"), "terminal-thread-invalid"),
            ("thread-config.json", lambda r: r["request"].update(allowProviderModelFallback=True), "effective-config-invalid"),
            ("turn-intent.json", lambda r: r.update(prompt_sha256="f" * 64), "turn-intent-mismatch"),
            ("process-start.json", lambda r: r.update(codex_home=str(self.fixture.root)), "process-host-mismatch"),
        ]
        for name, mutation, reason in mutations:
            with self.subTest(name=name):
                for filename, raw in originals.items():
                    (self.output / filename).write_bytes(raw)
                hashed = self.reseal_file(name, mutation)
                with self.assertRaisesRegex(q.QualificationError, reason):
                    q.inspect_observation(root=self.output, observation_sha256=hashed)

    def test_tool_use_in_terminal_is_not_a_no_tools_qualification(self):
        self.observe()
        hashed = self.reseal_file("terminal.json", lambda r: r["turns"][0]["items"].append({"type": "commandExecution"}))
        with self.assertRaisesRegex(q.QualificationError, "tools-forbidden"):
            q.inspect_observation(root=self.output, observation_sha256=hashed)

    def test_current_metadata_rows_through_actual_checked_reader(self):
        model = self.proof["requested_model"]
        workspace = str(self.fixture.workspace)
        world = {"type": "world_state", "payload": {"full": True, "state": {
            "model": model, "environments": {"environments": {"local": {"cwd": workspace}}},
            "host_skills": {"body": "non-operative fixture text"}}}}
        counters = {"input_tokens": 100, "cached_input_tokens": 20, "cache_write_input_tokens": 0,
                    "output_tokens": 10, "reasoning_output_tokens": 5, "total_tokens": 110}
        usage = {"type": "token_usage_record", "payload": {"thread_id": THREAD_ID, "session_id": THREAD_ID,
            "turn_id": TURN_ID, "root_turn_id": TURN_ID, "response_id": "response-fixture", "usage": counters,
            "turn_token_usage": counters, "thread_token_usage": counters}}
        observation = self.observe(metadata_rows=[world, usage])
        self.assertEqual(self.adjudicate(observation, self.check(observation)).record["model"], model)

    def test_boolean_numeric_checked_output_is_not_equal(self):
        observed=self.observe();original=q.checked_command.execute_checked_command
        def altered(spec):
            receipt=original(spec);body=json.loads(receipt['diagnostics']['stdout'])
            body.update(accepted_evidence=1,authority=0);receipt['diagnostics']['stdout']=json.dumps(body)
            return receipt
        with mock.patch.object(q.checked_command,'execute_checked_command',side_effect=altered),self.assertRaisesRegex(q.QualificationError,'checked-cli-output-mismatch'):
            self.check(observed)

    def test_pid_scope_and_copied_qualification_are_denied(self):
        observation = self.observe()
        qualification = self.adjudicate(observation, self.check(observation))
        with mock.patch.object(q.os, "getpid", return_value=os.getpid() + 1), self.assertRaisesRegex(q.QualificationError, "foreign-copied"):
            _ = qualification.record
        with self.assertRaisesRegex(q.QualificationError, "foreign-copied"):
            q.require_maintenance_qualification(copy(qualification), operation=self.cap, verifier=self.verifier)

    def test_observation_directory_replacement_cannot_keep_capability(self):
        observation = self.observe()
        archived = self.output.with_name("replaced-original-output")
        self.output.rename(archived)
        self.output.mkdir(mode=0o700)
        for path in archived.iterdir():
            target = self.output / path.name
            target.write_bytes(path.read_bytes())
            target.chmod(0o600)
        with self.assertRaisesRegex(q.QualificationError, "directory-replaced"):
            self.check(observation)

    def test_boolean_source_identity_and_process_pid_rejected(self):
        self.observe()
        originals = {p.name: p.read_bytes() for p in self.output.iterdir() if p.is_file()}
        for name, mutation, reason in [
            ("session-source.json", lambda r: r["identity"].update(links=True), "source-identity-type-invalid"),
            ("process-start.json", lambda r: r.update(pid=True), "process-host-mismatch"),
            ("process-closure.json", lambda r: r.update(pid=True), "owned-process-closure-invalid"),
        ]:
            with self.subTest(name=name):
                for filename, raw in originals.items():
                    (self.output / filename).write_bytes(raw)
                hashed = self.reseal_file(name, mutation)
                with self.assertRaisesRegex(q.QualificationError, reason):
                    q.inspect_observation(root=self.output, observation_sha256=hashed)

    def test_cli_nonzero_exit_and_stdout_wrong_nonce_are_rejected(self):
        for failure in ("exit", "nonce"):
            with self.subTest(failure=failure):
                # Separate fresh owner fixture: a failed check cannot reset its old right.
                other = QualificationTests("test_observed_checked_qualification_and_consumed_replay_contracts")
                other.setUp()
                try:
                    observation = other.observe()
                    execute = q.checked_command.execute_checked_command
                    def corrupt(spec):
                        receipt = execute(spec)
                        if failure == "exit":
                            receipt["exit_code"] = 1
                        else:
                            summary = json.loads(receipt["diagnostics"]["stdout"])
                            summary["nonce"] = "0" * 32
                            receipt["diagnostics"]["stdout"] = json.dumps(summary)
                        return receipt
                    with mock.patch.object(q.checked_command, "execute_checked_command", side_effect=corrupt), self.assertRaises(q.QualificationError):
                        other.check(observation)
                finally:
                    other.doCleanups()

    def test_direct_checker_output_cannot_be_passed_as_authority(self):
        observation = self.observe()
        summary = q.inspect_observation(root=self.output, observation_sha256=q.digest((self.output / "observation.json").read_bytes()))
        self.assertIs(summary["authority"], False)
        for value in (summary, observation.record, {"qualified": True}):
            with self.assertRaisesRegex(q.QualificationError, "verified-qualification-required"):
                q.require_maintenance_qualification(value, operation=self.cap, verifier=self.verifier)


class QualificationCapabilityDerivativeTests(unittest.TestCase):
    setUp = QualificationTests.setUp
    observe = QualificationTests.observe
    check = QualificationTests.check
    adjudicate = QualificationTests.adjudicate
    reseal_file = QualificationTests.reseal_file
    def test_derivative_original_session_duration_and_checked_surface(self):
        from cwo_core.native_tool_isolation import default_tool_policy, build_tool_surface_snapshot
        observation = self.observe()
        qualification = self.adjudicate(observation, self.check(observation))
        surface = build_tool_surface_snapshot(default_tool_policy(mutable=False),
            source="codex-app-server-v2-thread-config-proof:" + self.proof["proof_sha256"],
            server_allowlist_supported=True, allowlist_parameter="config",
            effective_allowlist=self.proof["observed_tools"])
        evidence = q.qualification_capability_evidence(qualification, operation=self.cap,
            verifier=self.verifier, tool_surface_id=surface["surface_sha256"])
        self.assertEqual(evidence["canary_session_id"], THREAD_ID)
        self.assertEqual(evidence["attested_model"], self.proof["requested_model"])
        self.assertEqual(evidence["tool_calls"], 0)
        self.assertEqual(evidence["context_compactions"], 0)
        times = json.loads((self.output / "observation-times.json").read_text())
        self.assertEqual(evidence["runtime_seconds"], (times["terminal_monotonic_ns"] - times["started_monotonic_ns"]) / 1e9)
        self.assertIs(evidence["closure_receipt"], True)
        evidence["canary_session_id"] = "not-the-original"
        self.assertEqual(q.qualification_capability_evidence(qualification, operation=self.cap,
            verifier=self.verifier, tool_surface_id=surface["surface_sha256"])["canary_session_id"], THREAD_ID)
        with self.assertRaisesRegex(q.QualificationError, "capability-tool-surface-mismatch"):
            q.qualification_capability_evidence(qualification, operation=self.cap,
                verifier=self.verifier, tool_surface_id="a" * 64)
        with self.assertRaises(q.QualificationError):
            q.qualification_capability_evidence(qualification.record, operation=self.cap,
                verifier=self.verifier, tool_surface_id=surface["surface_sha256"])

    def test_added_raw_fields_are_strict_and_original(self):
        self.observe()
        originals = {p.name: p.read_bytes() for p in self.output.iterdir() if p.is_file()}
        cases = [("control-image.json", lambda d: d.update(version=True)),
            ("control-image.json", lambda d: d["files"][next(iter(d["files"]))].update(executable=0)),
            ("endpoint-inventory-after.json", lambda d: d.update(thread_id="other-thread")),
            ("endpoint-inventory-before.json", lambda d: d.update(notification_generation=True)),
            ("model-discovery.json", lambda d: d.update(model="unobserved")),
            ("observation-times.json", lambda d: d.update(terminal_monotonic_ns=True))]
        for name, edit in cases:
            with self.subTest(name=name):
                for file, raw in originals.items():
                    (self.output / file).write_bytes(raw)
                digest = self.reseal_file(name, edit)
                with self.assertRaises(q.QualificationError):
                    q.inspect_observation(root=self.output, observation_sha256=digest)


class ArchivedMaintenanceObservationTests(unittest.TestCase):
    def test_pinned_observation_producer_and_issuing_image_reader(self):
        tests = (
            "test_observed_checked_qualification_and_consumed_replay_contracts",
            "test_owned_early_read_rpc_failure_then_real_terminal_qualifies",
            "test_other_rpc_errors_do_not_enter_startup_retry",
            "test_startup_retry_exhaustion_remains_nonqualified",
            "test_failed_turn_and_cleanup_are_preserved_separately_never_issued",
            "test_ambiguous_start_counts_before_rpc_and_never_qualifies",
            "test_constructor_cleanup_failure_is_preserved_not_inferred_from_missing_server",
        )
        run_archived_cases(self, HELD_QUALIFICATION_PRODUCERS,
            *("tests.test_maintenance_qualification.QualificationTests." + test for test in tests), all_paths=True)


class TypedHostMetadataTests(unittest.TestCase):
    """Pure non-operative fixtures: no provider, observer capability or grant."""
    def setUp(self):
        self.world={'type':'world_state','payload':{'full':True,'state':{'model':'model','environments':{'environments':{'local':{'cwd':'/fixture/workspace'}}}}}}
        counts={'input_tokens':100,'cached_input_tokens':20,'cache_write_input_tokens':0,'output_tokens':10,'reasoning_output_tokens':0,'total_tokens':110}
        self.usage={'type':'token_usage_record','payload':{'thread_id':'thread','session_id':'thread','turn_id':'turn','root_turn_id':'turn','response_id':'response','usage':counts,'turn_token_usage':deepcopy(counts),'thread_token_usage':deepcopy(counts)}}
    def validate(self,rows):
        return q._validate_session_metadata(rows,model='model',tid='thread',turn_id='turn',workspace='/fixture/workspace')
    def test_known_host_metadata_and_non_authority_preferences(self):
        preferred_world = deepcopy(self.world)
        preferred_world['payload']['state'].update(host_skills={'body':'changed'}, model_catalog='changed-cache', timezone='different')
        rows = (
            ('test_known_metadata_positive', [self.world, self.usage]),
            ('test_locale_skill_and_catalog_preferences_are_not_authority_gates', [preferred_world]),
        )
        for original_id, events in rows:
            with self.subTest(original_id=original_id):
                self.validate(events)
    def test_host_metadata_rejection_matrix(self):
        rows: list[tuple[str, dict, dict]] = []
        original_id = 'test_world_state_types_identity_and_scope_negatives'
        for change in [lambda p:p.update(full=1),lambda p:p.update(state=[]),lambda p:p['state'].update(model='wrong'),lambda p:p['state']['environments']['environments']['local'].update(cwd='/wrong'),lambda p:p.update(extra='unknown')]:
            row = deepcopy(self.world)
            change(row['payload'])
            rows.append((original_id, {'row': row}, row))
        original_id = 'test_token_counter_types_and_arithmetic_negatives'
        for value in (True, False, 1.0, '1', None, [], {}, -1):
            row = deepcopy(self.usage)
            row['payload']['usage']['input_tokens'] = value
            rows.append((original_id, {'value': value}, row))
        row = deepcopy(self.usage)
        row['payload']['usage']['total_tokens'] = 999
        rows.append((original_id, {'arithmetic': 'total'}, row))
        original_id = 'test_token_identity_and_extra_fields_negatives'
        for key in ('thread_id', 'session_id', 'turn_id', 'root_turn_id'):
            row = deepcopy(self.usage)
            row['payload'][key] = 'wrong'
            rows.append((original_id, {'key': key}, row))
        row = deepcopy(self.usage)
        row['payload']['usage']['extra'] = 0
        rows.append((original_id, {'extra': 'usage'}, row))
        original_id = 'test_unknown_events_and_permission_escalation_rejected'
        rows.append((original_id, {'event': 'unknown'}, {'type':'event_msg','payload':{'type':'future_execution'}}))
        row = {'type':'turn_context','payload':{'permission_profile':{'type':'managed','network':'restricted','file_system':{'type':'restricted','entries':[{'access':'write','path':{}}]}}}}
        rows.append((original_id, {'event': 'permission-escalation'}, row))
        for original_id, labels, row in rows:
            with self.subTest(original_id=original_id, **labels), self.assertRaises(q.QualificationError):
                self.validate([row])
    def test_nested_json_type_preservation(self):
        for bad in (0,0.0,None,[],{}):self.assertFalse(q._same_json({'config':{'fallback':False}},{'config':{'fallback':bad}}))
        self.assertTrue(q._same_json({'x':[False,1,1.0,None]},{'x':[False,1,1.0,None]}))


if __name__ == "__main__":
    unittest.main()
