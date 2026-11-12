"""EXAMPLE selected input through original admission, native host and artifact validation."""
from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import subprocess
import sys
import threading
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import prepare_delivery_closure as closure  # noqa: E402
import test_offline_admitted_n1 as admitted  # noqa: E402
import test_offline_n1_host as hosts  # noqa: E402
from cwo_core import server_request_preparation as prep  # noqa: E402

OUTPUT = b"EXAMPLE cooperative input output\n"
FINITE = "EXAMPLE_FINITE"
SUPPORTING = "EXAMPLE_STDIN"


class ProfileInputTests(unittest.TestCase):
    def setUp(self):
        # declare the fixed child's runner marker instead of inheriting it.
        self.enterContext(patch.dict("os.environ", CWO_PY=f"{sys.version_info.major}{sys.version_info.minor}"))
        self.api = importlib.import_module("offline_profile_input")
        self.helper = admitted.OfflineAdmittedN1Tests(methodName="runTest")
        self.addCleanup(self.helper.doCleanups)
        self.helper.setUp()

    def case(self, name="EXAMPLE", profile=SUPPORTING, *, legacy=False):
        case = self.helper.case(name=name) if legacy else self.profile_case(name, profile)
        specification = {"version": 1, "outputs": [{"path": "result.txt", "validator": "bytes",
            "size": len(OUTPUT), "sha256": hashlib.sha256(OUTPUT).hexdigest()}]}
        case.declaration = closure.freeze_native_policy(case.host, specification)
        case.process = self.api.ExampleInputProcess(case.host.worker)
        case.preparation = self.preparation(case.host.worker, profile)
        case.server.offline_profile_observation = {
            "profile": profile, "policy_id": "EXAMPLE_POLICY", "thread_id": case.adapter.thread_id,
            "cwd": str(case.host.worker), "input_capability": "finite" if profile == FINITE else "authorized-stdin",
            "network": False, "grants": [], "rules": [], "hooks": []}
        case.server.offline_input_context = prep.FakeItemContext(
            "EXAMPLE_EPOCH", case.adapter.thread_id, case.server.turn_result_id,
            "EXAMPLE_ITEM", prep.COMMAND, "EXAMPLE_APPROVAL", "writeStdin",
            "EXAMPLE_INPUT_PROCESS", str(case.host.worker))
        case.server.offline_input_started_at = 0
        return case

    def preparation(self, worker, profile):
        return {"fake": True, "schema_version": "0.164.0", "bundle": "experimental",
            "experimental_api": True, "inventory": {"available_profiles": [FINITE, SUPPORTING],
                "managed_allowed_profiles": [FINITE, SUPPORTING],
                "expected_policy_id": "EXAMPLE_POLICY", "observed_policy_id": "EXAMPLE_POLICY"},
            "thread_start": {"permissions": profile, "approvalPolicy": "untrusted",
                "approvalsReviewer": "user", "cwd": str(worker), "ephemeral": True}}

    def profile_case(self, name, profile):
        repositories = self.helper.repositories
        target, worker = repositories.clone("target-" + name), repositories.clone("worker-" + name)
        state = repositories.root / ("state-" + name)
        state.mkdir()
        records = state / "records"
        records.mkdir()
        clock, owners = admitted.ledger_fixtures.FakeClock(), admitted.ledger_fixtures.FakeOwners()
        store = admitted.ledger_api.InvocationLedger(repositories.root / ("ledger-" + name), clock=clock, owner_probe=owners)
        route = admitted.example_route(alternatives=True)
        receipt = admitted.admission.prepare(route, "plan", now=clock.now, expires_at=clock.now + 60)
        task = receipt.request_bytes.decode("utf-8")
        server = self.api.ExampleProfileServer(state / "fake-server", worker, task, self.preparation(worker, profile))
        server.ledger, server.admission = store, receipt
        server.expected_observers, server.ledger_intent = [], None
        policy = {"minimum_tool_calls": 1, "required_evidence": {
            "predicates": ["trusted-terminal-boundary", "trusted-tool-call", "expected-workspace-mutation"], "sha256": []},
            "allow_zero_tool_completion": False, "expected_mutation_mode": "mutable-isolated"}
        adapter = self.api.OfflineProfileAdapter(server, server.thread_response(mutable=True),
            prompt=task, expected_token=hosts.TOKEN, worktree=worker, mutable=True,
            expected_mutation="result.txt", completion_evidence_policy=policy, record_dir=records,
            campaign_live_route=False)
        bound = admitted.live_fixtures.LiveThreadBoundaryPhaseTests.controller_bind_and_arm(
            object(), adapter, arm=False)
        host = admitted.native.OfflineN1Host(state, target, worker)
        return SimpleNamespace(host=host, adapter=adapter, server=server, control=bound["control_contract"],
            receipt=receipt, route=route, ledger=store, clock=clock, owners=owners,
            pins=dict(admitted.PINS), outputs=["result.txt"], node_id="plan")

    def select(self, case, **changes):
        values = dict(admission=case.receipt, route_input=case.route, node_id=case.node_id,
            ledger=case.ledger, host=case.host, adapter=case.adapter, contract=case.control,
            configuration_pins=case.pins, preparation=case.preparation, process=case.process)
        values.update(changes)
        return self.api.select_input(case.declaration, **values)

    def frame(self, case, **changes):
        context = case.server.offline_input_context
        params = {"threadId": context.thread_id, "turnId": context.turn_id, "itemId": context.item_id,
            "approvalId": context.approval_id, "kind": "writeStdin", "command": context.command,
            "cwd": context.cwd, "startedAtMs": 0, "availableDecisions": ["accept", "decline", "cancel"]}
        params.update(changes)
        return json.dumps({"id": "EXAMPLE_REQUEST", "method": prep.COMMAND, "params": params}).encode() + b"\n"

    def authorize(self, case, selection, chars=b"EXAMPLE authorized input\n", **changes):
        return self.api.authorize_input(selection, self.frame(case, **changes), chars, decision="accept")

    def execute(self, case, selection, grant, chars):
        deliveries = []

        def input_at_original_send():
            deliveries.append(self.api.deliver_input(selection, grant, chars,
                context=case.server.offline_input_context))
            # The existing fake result writer consumes actual child stdout.
            hosts.OUTPUT = deliveries[-1]["output"]

        case.server.on_send = input_at_original_send
        with patch.object(hosts, "OUTPUT", b"EXAMPLE missing child output\n"):
            result = self.helper.run_case(case)
        return result, deliveries

    def no_effect(self, case):
        self.assertEqual(case.process.exchanges, [])
        self.assertEqual(case.server.sends, 0)
        self.assertFalse(case.ledger.root.exists())
        self.assertIsNone(case.host._load())
        self.assertFalse((case.host.worker / "result.txt").exists())

    def fake_process_count(self, spy):
        return sum(call.args[0][:4] == [sys.executable, "-I", "-S", "-c"]
                   for call in spy.call_args_list)

    def test_predecessor_missing_selected_input_consumer(self):
        self.assertTrue(callable(self.api.select_input))

    def test_finite_nonempty_refuses_before_process_and_empty_poll_uses_same_selection(self):
        """The finite child fixture declares its required runner environment."""
        case = self.case(profile=FINITE)
        selection = self.select(case)
        with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as process:
            with self.assertRaisesRegex(ValueError, "finite"):
                self.authorize(case, selection)
            self.no_effect(case)
            self.assertEqual(self.fake_process_count(process), 0)
        # A new approval identity is required after a denied input, with no retry/fallback.
        case.server.offline_input_context = dataclasses.replace(
            case.server.offline_input_context, approval_id="EXAMPLE_POLL")
        # Selection pins context, so declare a fresh selection for that new item observation.
        selection = self.select(case)
        grant = self.authorize(case, selection, b"")
        result, deliveries = self.execute(case, selection, grant, b"")
        self.assertEqual(deliveries[0]["output"], OUTPUT)
        self.assertEqual(case.process.exchanges[0]["chars"], b"")
        self.assertEqual(grant.report["profile"], FINITE)
        self.assertEqual(result["native_report"]["binding"]["configuration_pins"], case.pins)

    def test_supporting_input_reaches_actual_fake_process_once_with_original_bindings(self):
        """Supporting input works without an inherited runner marker."""
        case = self.case()
        selection = self.select(case)
        chars = b"EXAMPLE authorized input\n"
        grant = self.authorize(case, selection, chars)
        start = case.adapter._effective_boundary["thread_start"]
        self.assertEqual(start["request"]["permissions"], SUPPORTING)
        self.assertNotIn("sandbox", start["request"])
        self.assertEqual(start["request"]["approvalPolicy"], "untrusted")
        self.assertEqual(start["response"]["activePermissionProfile"]["id"], SUPPORTING)
        with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as process:
            result, deliveries = self.execute(case, selection, grant, chars)
        self.assertEqual(self.fake_process_count(process), 1)
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(len(case.process.exchanges), 1)
        sent = case.process.exchanges[0]
        self.assertEqual(sent["chars"], chars)
        self.assertEqual(sent["context"], deliveries[0]["context"])
        self.assertEqual(sent["context"]["admission_sha256"], result["admission_sha256"])
        self.assertEqual(sent["context"]["owner"], result["attempt"]["owner"])
        self.assertEqual(sent["context"]["control"], case.control)
        self.assertEqual(sent["context"]["candidate"], case.host._initial["target"])
        self.assertEqual(sent["context"]["profile"], SUPPORTING)
        self.assertEqual(sent["context"]["input_capability"], "authorized-stdin")
        self.assertEqual(sent["context"]["configuration_pins"], case.pins)
        self.assertEqual(result["request_bytes"], case.receipt.request_bytes)
        self.assertEqual(result["native_receipt"]["contract_sha256"], case.control["contract_sha256"])
        native_policy = closure._declared(case.declaration).policy
        target = case.host._initial["target"]
        observed = closure.validation.validate_artifact(case.host, result["native_report"], target, native_policy)
        outputs = closure.validation.consume_validated(case.host, observed, result["native_report"], target, native_policy)
        self.assertEqual(outputs, (("result.txt", OUTPUT),))
        self.assertEqual(deliveries[0]["output"], OUTPUT)
        for flag in ("production_ready", "effect_authority", "accepted_for_use", "qualified"):
            self.assertIs(grant.report[flag], False)
        with self.assertRaises(ValueError):
            self.api.deliver_input(selection, grant, chars, context=case.server.offline_input_context)
        self.assertEqual(len(case.process.exchanges), 1)

    def test_configuration_matrix_refuses_before_original_caller_or_process(self):
        changes = (
            ("mixed-selector", lambda c: c.preparation["thread_start"].update(sandbox="read-only")),
            ("missing-capability", lambda c: c.preparation.pop("experimental_api")),
            ("policy-drift", lambda c: c.preparation["inventory"].update(observed_policy_id="EXAMPLE_OTHER")),
            ("fallback", lambda c: c.server.offline_profile_observation.update(profile=FINITE)),
            ("unknown-capability", lambda c: c.server.offline_profile_observation.update(input_capability="unknown")),
            ("missing-metadata", lambda c: c.server.offline_profile_observation.pop("policy_id")),
            ("network-widening", lambda c: c.server.offline_profile_observation.update(network=True)),
            ("grant-widening", lambda c: c.server.offline_profile_observation.update(grants=["EXAMPLE_GRANT"])),
            ("rule-widening", lambda c: c.server.offline_profile_observation.update(rules=["EXAMPLE_ALLOW"])),
            ("hooks", lambda c: c.server.offline_profile_observation.update(hooks=["EXAMPLE_HOOK"])),
            ("reviewer", lambda c: c.preparation["thread_start"].update(approvalsReviewer="auto_review")),
        )
        for name, change in changes:
            with self.subTest(name=name):
                case = self.case(name)
                change(case)
                with self.assertRaises(ValueError):
                    self.select(case)
                self.no_effect(case)

    def test_actual_approval_consumer_denies_widening_and_unknown_evidence_despite_reason(self):
        changes = (
            {"additionalPermissions": {"network": {"enabled": True}}},
            {"additionalPermissions": {}}, {"environmentId": "EXAMPLE_ENV"},
            {"networkApprovalContext": {"host": "example.invalid", "protocol": "https"}},
            {"proposedExecpolicyAmendment": ["EXAMPLE_ALLOW"]},
            {"proposedNetworkPolicyAmendments": [{"action": "allow", "host": "example.invalid"}]},
            {"availableDecisions": ["acceptForSession"]}, {"cwd": None}, {"command": None},
            {"kind": "command"}, {"startedAtMs": 1}, {"approvalId": None},
            {"threadId": "EXAMPLE_OTHER"}, {"turnId": "EXAMPLE_OLD"}, {"itemId": "EXAMPLE_OTHER"},
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                case = self.case("approval-" + str(index))
                selection = self.select(case)
                with self.assertRaises(ValueError):
                    self.authorize(case, selection, reason="EXAMPLE safe ordinary retry, approved", **change)
                self.no_effect(case)

    def test_forged_declaration_selection_and_grant_refuse_before_process(self):
        case = self.case()
        with self.assertRaises(ValueError):
            self.api.select_input(case.declaration.report)
        selection = self.select(case)
        for forged in ({}, object.__new__(self.api.InputSelection)):
            with self.assertRaises(ValueError):
                self.authorize(case, forged)
        with self.assertRaises(ValueError):
            self.api.deliver_input(selection, {}, b"", context=case.server.offline_input_context)
        self.no_effect(case)

    def test_reused_approval_identity_refuses_across_fresh_selection_and_request(self):
        case = self.case()
        selection = self.select(case)
        self.authorize(case, selection)
        second = self.select(case)
        frame = json.loads(self.frame(case))
        frame["id"] = "EXAMPLE_SECOND_REQUEST"
        with self.assertRaisesRegex(ValueError, "reused"):
            self.api.authorize_input(second, json.dumps(frame).encode() + b"\n", b"EXAMPLE authorized input\n", decision="accept")
        self.no_effect(case)

    def test_denied_approval_cannot_be_edited_into_an_ordinary_retry(self):
        case = self.case()
        selection = self.select(case)
        with self.assertRaises(ValueError):
            self.authorize(case, selection, additionalPermissions={})
        with self.assertRaisesRegex(ValueError, "reused"):
            self.authorize(case, selection, reason="EXAMPLE reassuring ordinary retry")
        self.no_effect(case)

    def test_approval_history_survives_recreating_original_ledger_handle(self):
        case = self.case()
        selection = self.select(case)
        self.authorize(case, selection)
        replacement = admitted.ledger_api.InvocationLedger(
            case.ledger.root, clock=case.clock, owner_probe=case.owners)
        selection = self.select(case, ledger=replacement)
        with self.assertRaisesRegex(ValueError, "reused"):
            self.authorize(case, selection)
        self.no_effect(case)

    def test_selected_receipt_owner_metadata_and_candidate_drift_refuse_before_delivery(self):
        changes = (
            ("owner", lambda c: c.owners.me.update(start_ticks=8)),
            ("metadata", lambda c: c.server.offline_profile_observation.update(input_capability="unknown")),
            ("pins", lambda c: c.pins.update(w15="EXAMPLE_DRIFT")),
            ("candidate", lambda c: (c.host.target / "seed.txt").write_text("EXAMPLE changed\n")),
            ("context", lambda c: setattr(c.server, "offline_input_context", dataclasses.replace(
                c.server.offline_input_context, approval_id="EXAMPLE_OTHER"))),
        )
        for name, change in changes:
            with self.subTest(name=name):
                case = self.case("drift-" + name)
                selection = self.select(case)
                self.authorize(case, selection)
                change(case)
                with self.assertRaises(ValueError):
                    self.authorize(case, selection)
                self.no_effect(case)

    def test_input_bytes_and_direct_delivery_without_original_intent_refuse(self):
        case = self.case()
        selection = self.select(case)
        grant = self.authorize(case, selection)
        for chars in (b"EXAMPLE widened", b"", "EXAMPLE wrong type"):
            with self.assertRaises(ValueError):
                self.api.deliver_input(selection, grant, chars, context=case.server.offline_input_context)
        with self.assertRaises(ValueError):
            self.api.deliver_input(selection, grant, b"EXAMPLE authorized input\n", context=case.server.offline_input_context)
        self.no_effect(case)

    def test_cross_host_declaration_and_process_refuse(self):
        left, right = self.case("left"), self.case("right")
        changed = dataclasses.replace(left.receipt, budget_id="EXAMPLE_OTHER")
        for values in ({"host": right.host}, {"process": right.process}, {"admission": changed}):
            with self.assertRaises(ValueError):
                self.select(left, **values)
        self.no_effect(left)
        self.no_effect(right)

    def test_original_final_caller_revalidates_grant_before_fake_process_without_retry(self):
        for name in ("changed-bytes", "widened-metadata", "forged-grant", "changed-context"):
            with self.subTest(name=name):
                case = self.case("final-" + name)
                selection = self.select(case)
                chars = b"EXAMPLE authorized input\n"
                grant = self.authorize(case, selection, chars)
                if name == "changed-bytes":
                    chars = b"EXAMPLE changed input\n"
                elif name == "forged-grant":
                    grant = grant.report
                elif name == "widened-metadata":
                    case.server.offline_profile_observation["network"] = True
                else:
                    case.server.offline_input_context = dataclasses.replace(
                        case.server.offline_input_context, turn_id="EXAMPLE_OTHER_TURN")
                with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as process:
                    with self.assertRaises(admitted.client.OfflineAdmittedN1Error):
                        self.execute(case, selection, grant, chars)
                self.assertEqual(self.fake_process_count(process), 0)
                expected_sends = 0 if name in ("widened-metadata", "changed-context") else 1
                self.assertEqual(case.server.sends, expected_sends)
                self.assertEqual(case.process.exchanges, [])
                self.assertFalse((case.host.worker / "result.txt").exists())
                self.assertEqual(case.host.status("FAKE_OPERATION")["status"], "reconciliation-required")

    def test_review_actual_legacy_start_cannot_be_replaced_by_profile_side_metadata(self):
        case = self.case("actual-legacy", legacy=True)
        with self.assertRaises(ValueError):
            self.select(case)
        self.no_effect(case)

    def test_actual_thread_start_drift_refuses_with_unchanged_profile_side_metadata(self):
        for name, change in (
            ("legacy-selector", lambda start: start["request"].update(sandbox="workspace-write")),
            ("approval", lambda start: start["request"].update(approvalPolicy="never")),
            ("ephemeral-type", lambda start: start["request"].update(ephemeral=1)),
            ("readback", lambda start: start["response"].update(activePermissionProfile={"id": FINITE})),
        ):
            with self.subTest(name=name):
                case = self.case("issued-" + name)
                change(case.server._effective_thread_start_evidence[case.adapter.thread_id])
                with self.assertRaises(ValueError):
                    self.select(case)
                self.no_effect(case)

    def test_review_reentrant_pre_dispatch_refusal_never_delivers_input(self):
        case = self.case("reentrant-surface")
        selection = self.select(case)
        chars = b"EXAMPLE authorized input\n"
        grant = self.authorize(case, selection, chars)
        original = case.adapter._tool_surface_reader

        def surface():
            if case.adapter._effective_boundary_send_reserved:
                try:
                    self.api.deliver_input(selection, grant, chars, context=case.server.offline_input_context)
                except ValueError:
                    pass
                return {}
            return original()

        case.adapter._tool_surface_reader = surface
        with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as process:
            with self.assertRaises(admitted.client.OfflineAdmittedN1Error):
                self.execute(case, selection, grant, chars)
        self.assertEqual(case.server.sends, 0)
        self.assertEqual(self.fake_process_count(process), 0)
        self.assertEqual(case.process.exchanges, [])

    def test_review_authorization_overlapping_native_delivery_has_one_lock_order(self):
        """Concurrent delivery uses an explicit fixed-child environment."""
        case = self.case("overlapping-input")
        selection = self.select(case)
        chars = b"EXAMPLE authorized input\n"
        grant = self.authorize(case, selection, chars)
        waiting, timeouts, errors = threading.Event(), [], []
        case.adapter._boundary_lock = BoundedBoundaryLock(case.adapter._boundary_lock, waiting, timeouts)

        def authorize_again():
            try:
                self.authorize(case, selection, chars)
            except ValueError as error:
                errors.append(str(error))

        thread = threading.Thread(target=authorize_again, name="EXAMPLE_AUTHORIZE")

        def send():
            thread.start()
            if not waiting.wait(2):
                raise AssertionError("EXAMPLE authorization never reached the native lock")
            delivered = self.api.deliver_input(selection, grant, chars, context=case.server.offline_input_context)
            hosts.OUTPUT = delivered["output"]

        case.server.on_send = send
        try:
            with patch.object(hosts, "OUTPUT", b"EXAMPLE missing child output\n"):
                result = self.helper.run_case(case)
        finally:
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(result["offline_completed"])
        self.assertEqual(timeouts, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(case.process.exchanges), 1)

    def test_review_denied_approval_cannot_move_to_another_ledger_path(self):
        case = self.case("another-ledger")
        selection = self.select(case)
        with self.assertRaises(ValueError):
            self.authorize(case, selection, additionalPermissions={})
        other = admitted.ledger_api.InvocationLedger(case.ledger.root.parent / "EXAMPLE_OTHER_LEDGER",
            clock=case.clock, owner_probe=case.owners)
        selection = self.select(case, ledger=other)
        with self.assertRaisesRegex(ValueError, "reused"):
            self.authorize(case, selection, reason="EXAMPLE ordinary retry")
        self.no_effect(case)
        self.assertFalse(other.root.exists())

    def test_review_inconsistent_initial_adapter_readback_is_not_normalized_away(self):
        for value in (None, "never"):
            with self.subTest(approval=value):
                case = self.case("initial-" + str(value))
                response = json.loads(json.dumps(case.adapter.thread_response))
                if value is None:
                    response.pop("approvalPolicy")
                else:
                    response["approvalPolicy"] = value
                adapter = self.api.OfflineProfileAdapter(case.server, response,
                    prompt=case.adapter.prompt, expected_token=hosts.TOKEN, worktree=case.host.worker,
                    mutable=True, expected_mutation="result.txt",
                    completion_evidence_policy=case.adapter.completion_evidence_policy,
                    record_dir=case.adapter.record_dir, campaign_live_route=False)
                with self.assertRaises(ValueError):
                    admitted.live_fixtures.LiveThreadBoundaryPhaseTests.controller_bind_and_arm(object(), adapter, arm=False)
                self.no_effect(case)

    def test_review_installed_scripts_without_tests_preserve_unsupported_adapter_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "EXAMPLE-installed-projection"
            stage.mkdir()
            projection = json.loads((ROOT / "policy/install-projection.yaml").read_text())
            for entry in projection["entries"]:
                source, destination = ROOT / entry["path"], stage / entry["path"]
                if entry["kind"] == "directory":
                    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", ".ruff_cache"))
                else:
                    shutil.copy2(source, destination)
            self.assertFalse((stage / "tests").exists())
            code = (
                "import sys;sys.path.insert(0,sys.argv[1]);import offline_n1_host as host\n"
                "try:host._methods(object())\n"
                "except host.OfflineHostError:print('EXAMPLE unsupported adapter refused')\n"
                "else:raise AssertionError('EXAMPLE unsupported adapter accepted')\n")
            result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(stage / "scripts")],
                cwd=stage, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"EXAMPLE unsupported adapter refused\n")

    def test_review_delivery_owner_callouts_cannot_widen_scope_before_process(self):
        for point in ("status", "intent-owner"):
            for changed in ("metadata", "workspace", "expiry"):
                with self.subTest(point=point, changed=changed):
                    self.owner_callback_case(point, changed)

    def owner_callback_case(self, point, changed):
        case = self.case("owner-" + point + "-" + changed)
        selection = self.select(case)
        chars = b"EXAMPLE authorized input\n"
        grant = self.authorize(case, selection, chars)
        original_current, original_status = case.owners.current, case.owners.status
        phase = {"delivery": False, "current_calls": 0, "mutations": []}

        def mutate():
            if changed == "metadata":
                case.server.offline_profile_observation["network"] = True
            elif changed == "expiry":
                case.clock.now = case.receipt.expires_at
            else:
                case.process.worker = case.host.target
            phase["mutations"].append(changed)

        def current():
            if phase["delivery"]:
                phase["current_calls"] += 1
                if point == "intent-owner" and phase["current_calls"] == 2:
                    mutate()
            return original_current()

        def status(owner):
            if phase["delivery"] and point == "status" and not phase["mutations"]:
                mutate()
            return original_status(owner)

        def send():
            phase["delivery"] = True
            delivered = self.api.deliver_input(selection, grant, chars, context=case.server.offline_input_context)
            hosts.OUTPUT = delivered["output"]

        case.owners.current, case.owners.status = current, status
        case.server.on_send = send
        failure = None
        with patch.object(hosts, "OUTPUT", b"EXAMPLE missing child output\n"):
            with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as process:
                try:
                    self.helper.run_case(case)
                except admitted.client.OfflineAdmittedN1Error as error:
                    failure = error
        self.assertEqual(phase["mutations"], [changed])
        self.assertEqual(self.fake_process_count(process), 0)
        self.assertEqual(case.process.exchanges, [])
        self.assertIsNotNone(failure)
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(case.host.status("FAKE_OPERATION")["status"], "reconciliation-required")
        self.helper.assert_charged(case)

    def test_review_final_clock_owner_drift_refuses_before_process(self):
        for changed in ("owner", "expiry", "gone", "unknown", "reconciliation"):
            with self.subTest(changed=changed):
                self.final_clock_case(changed)

    def final_clock_case(self, changed):
        case = self.case("final-clock-" + changed)
        selection = self.select(case)
        chars = b"EXAMPLE authorized input\n"
        grant = self.authorize(case, selection, chars)
        original_clock = type(case.clock).__call__
        phase = {"delivery": False, "calls": 0, "mutated": False}

        def clock_read(clock):
            observed = original_clock(clock)
            if clock is case.clock and phase["delivery"]:
                phase["calls"] += 1
                if phase["calls"] == 2:
                    if changed == "owner":
                        case.owners.me["start_ticks"] += 1
                    elif changed == "expiry":
                        case.clock.now = case.receipt.expires_at
                    elif changed == "reconciliation":
                        case.ledger.mark_reconciliation_required(case.server.ledger_intent["reservation_id"],
                            reason="EXAMPLE final clock requires reconciliation")
                    else:
                        key = (case.owners.me["pid"], case.owners.me["start_ticks"])
                        getattr(case.owners, changed).add(key)
                    phase["mutated"] = True
            return observed

        def send():
            phase["delivery"] = True
            delivered = self.api.deliver_input(selection, grant, chars, context=case.server.offline_input_context)
            hosts.OUTPUT = delivered["output"]

        case.server.on_send = send
        failure = None
        with patch.object(type(case.clock), "__call__", clock_read):
            with patch.object(hosts, "OUTPUT", b"EXAMPLE missing child output\n"):
                with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as process:
                    try:
                        self.helper.run_case(case)
                    except (admitted.client.OfflineAdmittedN1Error, admitted.ledger_api.InvocationLedgerError) as error:
                        failure = error
        self.assertTrue(phase["mutated"])
        self.assertEqual(self.fake_process_count(process), 0)
        self.assertEqual(case.process.exchanges, [])
        self.assertIsNotNone(failure)
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(case.host.status("FAKE_OPERATION")["status"], "reconciliation-required")
        self.helper.assert_charged(case)

    def test_missing_callback_free_state_capability_refuses_before_callouts(self):
        case = self.case("unknown-state-provider")
        calls = []

        def unsupported(*_args):
            calls.append("EXAMPLE unsupported provider called")
            raise AssertionError("Unknown state provider must refuse before callouts")

        unknown_owner = SimpleNamespace(current=unsupported, status=unsupported)
        for name, clock, owners in (("clock", unsupported, case.owners),
                                    ("owner", case.clock, unknown_owner)):
            store = admitted.ledger_api.InvocationLedger(case.ledger.root.parent / ("EXAMPLE-unknown-" + name),
                clock=clock, owner_probe=owners)
            with self.assertRaisesRegex(ValueError, "readback"):
                self.select(case, ledger=store)
            self.assertFalse(store.root.exists())
        self.assertEqual(calls, [])
        self.no_effect(case)


class BoundedBoundaryLock:
    """Reproduce lock inversion without leaving an unbounded deadlocked test."""

    def __init__(self, original, waiting, timeouts):
        self.original, self.waiting, self.timeouts = original, waiting, timeouts

    def __enter__(self):
        if threading.current_thread().name == "EXAMPLE_AUTHORIZE":
            self.waiting.set()
        if not self.original.acquire(timeout=2):
            self.timeouts.append("EXAMPLE native/input lock inversion")
            raise ValueError("EXAMPLE native lock wait exceeded the test budget")
        return self

    def __exit__(self, *_error):
        self.original.release()
        return False


if __name__ == "__main__":
    unittest.main()
