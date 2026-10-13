"""Providerless mechanics fixtures, NEVER live qualification/acceptance evidence."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import datetime as dt
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.maintenance_native_runtime as module
from cwo_core.maintenance_image import capture_control_image
from cwo_core.native_tool_isolation import default_tool_policy
from cwo_core.maintenance_authority import (
    MaintenanceAuthorityError, MaintenanceAuthorityVerifier, MaintenanceStateStore,
    mission_sha256, sign_controller_directive,
)
from cwo_core.maintenance_runtime_support import (
    MaintenanceControllerContext, MaintenanceRelease, MaintenanceRuntimeError,
    MaintenanceSessionLedger, MaintenanceTask, ValidationCommand,
)
from cwo_core.native_authority import canonical_authority_sha256
from cwo_core.native_pool_admission import AdmissionCandidate, BeadsClaimAdapter, build_admission_child_binding
from cwo_core.native_pool_contracts import canonical_sha256, validate_pool_contract
from cwo_core.native_pool_preflight import effective_child_packet_sha256
from cwo_core.native_pool_proportionality import pool_proportionality_check
from cwo_core.native_pool_transaction import (
    MAINTENANCE_PLAN_SCHEMA, PLAN_TYPE, TRANSACTION_CALL_GRAPH_SHA256,
    AdmittedPoolLaunch, TransactionRuntime, execution_authoritative_bead_sha256, seal_transaction_plan,
)
from cwo_core.native_pool_workspace import capture_workspace_snapshot
from cwo_core.native_tool_isolation import default_tool_policy
from cwo_core.paths import cwo_temp_dir
from tests.test_native_pool_admission import MemoryBdRunner
from tests.test_native_pool_proportionality import _fixture


class FakeServer:
    """No provider processes or model RPCs; only allocation acknowledgement shape."""
    def __init__(self, *, requested_model, reasoning_effort, tool_surface_proof, operation_metadata):
        self.requested_model, self.reasoning_effort = requested_model, reasoning_effort
        self.started_threads, self._effective_thread_start_evidence = {}, {}
        self.connection_epoch_sha256 = "e" * 64
        self.process = SimpleNamespace(poll=lambda: None)
        self._reader_error = None
        self.events = []
        self.before_start = None
        self.failure = None
        self.sandbox_override = None
        self.allowlist_supported = True

    def model_discovery(self):
        self.events.append("discovery")
        return {"id": self.requested_model, "model": self.requested_model}

    def tool_surface_capability(self, *, permitted_tools):
        return {"source": "PROVIDERLESS-FIXTURE", "server_allowlist_supported": self.allowlist_supported,
                "allowlist_parameter": "allowedTools" if self.allowlist_supported else None,
                "effective_allowlist": permitted_tools if self.allowlist_supported else None}

    def start_thread(self, cwd, *, mutable, role, permitted_tools, allowlist_parameter, **kwargs):
        if self.before_start:
            self.before_start()
        self.events.append("thread/start")
        if self.failure:
            raise self.failure
        identity = str(uuid.uuid4())
        response = {"thread": {"id": identity, "turns": [], "path": str(cwd.parent / (identity + ".jsonl"))},
            "model": self.requested_model, "modelProvider": "fixture-only", "cwd": str(cwd),
            "runtimeWorkspaceRoots": [str(cwd)], "approvalPolicy": "never",
            "sandbox": self.sandbox_override or {"type": "workspaceWrite" if mutable else "readOnly", "networkAccess": False}}
        request = {"model": self.requested_model, "allowProviderModelFallback": False,
                   "cwd": str(cwd), "runtimeWorkspaceRoots": [str(cwd)], "approvalPolicy": "never",
                   "sandbox": "workspace-write" if mutable else "read-only"}
        self.started_threads[identity] = None
        self._effective_thread_start_evidence[identity] = {"request": request, "response": deepcopy(response)}
        return response, 0.1

    def start_turn(self, *_args, **_kwargs):
        raise AssertionError("fixture must not dispatch a real or pretend model turn")

    def interrupt_turn(self, *_args):
        return None

    def archive_thread(self, *_args):
        return None

    def read_thread(self, *_args):
        return {}, 0.1

    def close(self):
        self.events.append("close")
        return {"all_contained": True, "resources_closed": True, "errors": []}


class RuntimeFixture:
    def __init__(self, root, *, role="review", commands=None):
        self.root = root
        self.controller = root / "controller"
        self.controller.mkdir(mode=0o700)
        self.worker, self.integration = root / "worker", root / "integration"
        for path in (self.worker, self.integration):
            path.mkdir(mode=0o700)
            (path / "seed.txt").write_text("original\n")
            subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(path), "add", "seed.txt"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(path), "-c", "user.name=Fixture", "-c", "user.email=fixture.invalid",
                            "commit", "-qm", "fixture"], check=True, capture_output=True)
        self.readiness, self.estimates, self.items, self.policy = _fixture([600], writes=role == "product")
        self.bead_id = self.items[0]["id"]
        self.work_plan = self.estimates[self.bead_id]
        self.model = self.work_plan["requested_model"]
        writes = tuple(self.items[0]["raw"]["metadata"]["cwo_ready_set_admission"]["declared_write_paths"])
        allowance = self.work_plan["aggregate_allowance"]
        self.task = MaintenanceTask(child_id="child-0", packet_id=str(uuid.uuid4()), attempt_nonce=str(uuid.uuid4()),
            role=role, worktree=self.worker, write_paths=writes, work_plan=self.work_plan, operative_routing={},
            instruction="Inspect seed.txt and complete the bounded task.", hard_budget={
                "tool_calls": allowance["tool_calls_hard"], "runtime_seconds": allowance["runtime_seconds_hard"],
                "compactions": 0, "full_suite_runs": 0, "mutations": 1 if writes else 0},
            validation_commands=commands or (ValidationCommand((sys.executable, "-c", "print('checked')"), 5,
                                                               hashlib.sha256(b"checked\n").hexdigest()),),
            expected_artifacts={path: hashlib.sha256(b"product\n").hexdigest() for path in writes})
        self.image = capture_control_image()
        self.qualification_record = {"model": self.model, "canary_sha256": "f" * 64,
            "control_image_sha256": self.image["image_sha256"],
            "tool_profile_sha256": canonical_sha256(default_tool_policy(mutable=role == "product")["permitted_tools"]),
            "origin_issued_at": (dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=1)).isoformat(),
            "origin_expires_at": (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=30)).isoformat()}
        self.qualification = SimpleNamespace(record=self.qualification_record, fixture_only=True)
        self.ledger = MaintenanceSessionLedger(self.controller / "sessions.jsonl", mission_id="fixture-mission")
        self.ledger.initialize()
        self.mission = {"mission_type": "cwo-maintenance-mission", "version": 1, "mission_id": "fixture-mission",
            "objective": "Providerless mechanics fixture only", "provenance": {"adoption_id": "fixture", "user_request_sha256": "f" * 64},
            "scope": {"effect_scope": "cwo-maintenance", "workspace_roots": [str(self.worker)], "models": [self.model],
                      "roles": ["product", "review"], "factory_ids": ["installed-maintenance"]},
            "budget": {"mode": "unbounded"}, "lifetime": {"mode": "until-revoked"}}
        self.mission_hash = mission_sha256(self.mission)
        self.key = b"fixture-only-controller-key-never-a-real-user-grant"
        self.directive = self.sign(self.mission_hash, "mission")
        adapter_path = ROOT / "scripts/cwo_core/maintenance_native_runtime.py"
        adapter_hash = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
        self.store = MaintenanceStateStore(self.controller, mission_id="fixture-mission", mission_sha256=self.mission_hash)
        self.store.initialize()
        self.verifier = MaintenanceAuthorityVerifier(mission=self.mission, operator_directive=self.directive,
            verification_key=self.key, expected_actor_id="fixture-owner", expected_identity_source="fixture-parent",
            factory_registry={"installed-maintenance": {"adapter_path": str(adapter_path), "adapter_sha256": adapter_hash}},
            state_reader=self.store.read_state, claim_operation=self.store.claim_operation)
        self.runner = MemoryBdRunner(self.items)
        self.claim_adapter = BeadsClaimAdapter(directory=self.controller, database=self.controller / "fixture.db",
                                              actor="fixture-controller", runner=self.runner)
        self.plan = seal_transaction_plan({"plan_type": PLAN_TYPE, "version": 8, "schema": MAINTENANCE_PLAN_SCHEMA,
            "transaction_id": "fixture-operation", "phase_id": "fixture-phase", "candidate_manifest_sha256": "a" * 64,
            "controller_overlay_sha256": self.image["image_sha256"], "authority_sha256": self.mission_hash,
            "call_graph_sha256": TRANSACTION_CALL_GRAPH_SHA256, "runtime_adapter_path": str(adapter_path),
            "runtime_adapter_sha256": adapter_hash, "created_at": "2026-10-13T00:00:00Z", "selected_model": self.model,
            "prelude_session_count": 1, "required_session_count": 2,
            "budget": {"mode": "maintenance-unbounded", "cumulative_before": 0, "reserved_sessions": 2},
            "startup_bounds_ms": {"pre_allocation_ms": 1, "per_allocation_ms": 1, "runtime_binding_ms": 1,
                                  "admission_ms": 1, "dispatch_and_first_observation_ms": 1, "safety_margin_ms": 1},
            "children": [{"child_id": "child-0", "bead_id": self.bead_id, "segment_id": "segment-0",
                "work_unit_id": self.work_plan["work_unit_id"], "requested_model": self.model,
                "bead_projection_sha256": execution_authoritative_bead_sha256(self.runner.issues[self.bead_id]),
                "worktree_identity_sha256": canonical_sha256(capture_workspace_snapshot(self.worker, allowed_paths=list(writes))["identity"]),
                "work_plan_sha256": canonical_sha256(self.work_plan), "packet_blueprint_sha256": canonical_sha256(self.task.blueprint()),
                "write_paths": list(writes), "read_only": role == "review"}], "plan_sha256": ""})
        self.operation = {"operation_id": "fixture-operation", "mission_id": "fixture-mission", "mission_sha256": self.mission_hash,
            "revocation_generation": 0, "plan_sha256": self.plan["plan_sha256"], "factory_id": "installed-maintenance",
            "workspace": str(self.worker), "model": self.model, "role": role, "write_paths": list(writes),
            "reservation": {"mode": "finite-operation", "sessions": 2, "tool_calls": allowance["tool_calls_hard"],
                            "runtime_seconds": allowance["runtime_seconds_hard"] + 30, "cleanup_seconds": 30, "max_concurrency": 1}}
        grant = self.sign(canonical_authority_sha256(self.operation), "operation", parent=canonical_authority_sha256(self.directive))
        self.cap = self.verifier.verify_operation(self.plan, self.operation, grant)
        self.cap.claim()
        self.context = MaintenanceControllerContext(self.task, self.integration, cwo_temp_dir(scope="session") / "fresh-run",
            self.claim_adapter, self.ledger, "max", {"fixture_only": True}, {"qualifications": {self.model:self.qualification_record}}, self.release, self.candidate,
            qualification=self.qualification, control_image=self.image)
        self.context.bind_operation(self.cap, self.verifier, self.plan)

    def sign(self, digest, identity, parent=None):
        return sign_controller_directive(verification_key=self.key, actor_id="fixture-owner", identity_source="fixture-parent",
            action_sha256=digest, directive_id=identity, parent_receipt_sha256=parent)

    def release(self, **kwargs):
        evidence = {"version": 2, "evidence_sha256": "d" * 64, "issued_at": "2026-10-13T00:00:00Z", "expires_at": self.qualification_record["origin_expires_at"],
                    "issued_at": self.qualification_record["origin_issued_at"], "canary_receipt_sha256": self.qualification_record["canary_sha256"]}
        packet = {"packet_id": self.task.packet_id, "bead_id": self.bead_id, "requested_model": self.model,
            "work_plan": deepcopy(self.work_plan), "precommit_receipt_sha256": kwargs["precommit_receipt"]["receipt_sha256"],
            "tool_policy": default_tool_policy(mutable=self.task.role == "product"), "release_evidence": evidence,
            "scope": {"workdir": str(self.worker), "allowed_paths": list(self.task.write_paths),
                      "prohibited_actions": ["source-mutation"] if self.task.role == "review" else []}}
        return MaintenanceRelease(packet, ({"child_id": "child-0", "kind": "operative-release",
            **{key: evidence[key] for key in ("evidence_sha256", "issued_at", "expires_at")}},))

    def candidate(self, *, effective_child, **kwargs):
        assessment = pool_proportionality_check(self.readiness, self.estimates, requested_workers=1, policy_document=self.policy)
        binding = build_admission_child_binding(self.readiness, self.work_plan, bead_id=self.bead_id, child_id="child-0",
            packet_id=effective_child["packet_id"], packet_sha256=effective_child["packet_sha256"],
            worktree_identity_sha256=self.plan["children"][0]["worktree_identity_sha256"])
        return AdmissionCandidate(self.readiness, self.estimates, assessment, {self.bead_id: binding})

    def call_context(self, ordinal, *, prelude):
        identity = {"transaction_id": self.plan["transaction_id"], "allocation_class": "prelude" if prelude else "worker",
                    "ordinal": ordinal, "child_id": None if prelude else "child-0"}
        allocation = {key: value for key, value in identity.items() if key != "transaction_id"}
        allocation["allocation_id"] = canonical_sha256(identity)
        return {"transaction_allocation": allocation}


class MaintenanceRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cwo-maintenance-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {"CWO_TEMP_ROOT": str(self.root / "temp"), "CWO_SESSION_ID": "runtime-fixture"})
        self.env.start()
        self.addCleanup(self.env.stop)
        # Explicitly synthetic capability only at the provider qualification
        # boundary. Real opaque qualifier behavior is independently tested.
        def fixture_qualification(value, **kwargs):
            if type(value) is not SimpleNamespace or value.fixture_only is not True:
                raise ValueError("fixture requires separately supplied qualification")
            return value
        qualification_patch=mock.patch.object(module,"require_maintenance_qualification",side_effect=fixture_qualification)
        qualification_patch.start();self.addCleanup(qualification_patch.stop)

    def fixture(self, role="review"):
        return RuntimeFixture(self.root, role=role)

    def prepared(self, fixture):
        runtime = module.build_transaction_runtime(fixture.plan, fixture.context)
        with mock.patch.object(module, "AppServer", FakeServer):
            context = runtime.prepare(fixture.plan)
        return runtime, fixture.context.runtime_state, context

    def released(self, fixture):
        runtime, state, context = self.prepared(fixture)
        state._start(fixture.call_context(0, prelude=True), prelude=True)
        state.precommit = {"receipt_sha256": "c" * 64}
        # Only release/native-fit are synthetic in this providerless mechanics
        # fixture. Real admission, contract, preflight and boundary binding run.
        with mock.patch.object(module, "validate_native_worker_packet", return_value=[]), \
             mock.patch.object(module, "_render_prompt", return_value="Inspect the bounded task; no outside work."):
            runtime.release_artifacts(fixture.plan, context, None)
        allocation = runtime.start_worker_session(fixture.plan["children"][0], fixture.call_context(1, prelude=False))
        return runtime, state, context, allocation

    def test_factory_is_exact_runtime_and_does_not_start_server(self):
        fixture = self.fixture()
        with mock.patch.object(module, "AppServer", side_effect=AssertionError("unexpected process")):
            runtime = module.build_transaction_runtime(fixture.plan, fixture.context)
        self.assertIs(type(runtime), TransactionRuntime)
        self.assertEqual(runtime.trusted_session_count(), 0)
        self.assertFalse(fixture.context.run_dir.exists())
        self.assertIs(runtime.maintenance_operation, fixture.cap)

    def test_worker_json_context_and_unbound_context_are_denied(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(MaintenanceRuntimeError, "trusted-context-required"):
            module.build_transaction_runtime(fixture.plan, {"operation": fixture.cap.evidence()})
        unbound = replace(fixture.context)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "context-plan-mismatch"):
            module.build_transaction_runtime(fixture.plan, unbound)

    def test_context_binding_cannot_be_reused(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(MaintenanceRuntimeError, "context-already-bound"):
            fixture.context.bind_operation(fixture.cap, fixture.verifier, fixture.plan)

    def test_revocation_denies_before_process_creation(self):
        fixture = self.fixture()
        runtime = module.build_transaction_runtime(fixture.plan, fixture.context)
        fixture.store.revoke()
        with mock.patch.object(module, "AppServer") as server, self.assertRaises(MaintenanceAuthorityError):
            runtime.prepare(fixture.plan)
        server.assert_not_called()

    def test_task_mutation_denies_before_process_creation(self):
        fixture = self.fixture()
        runtime = module.build_transaction_runtime(fixture.plan, fixture.context)
        fixture.task.hard_budget["tool_calls"] += 1
        with mock.patch.object(module, "AppServer") as server, self.assertRaisesRegex(MaintenanceRuntimeError, "blueprint-drift"):
            runtime.prepare(fixture.plan)
        server.assert_not_called()

    def test_run_directory_is_one_shot(self):
        fixture = self.fixture()
        runtime, _, _ = self.prepared(fixture)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "prepare-reused"):
            runtime.prepare(fixture.plan)

    def test_constructor_failure_does_not_erase_unproved_cleanup(self):
        fixture = self.fixture()
        runtime = module.build_transaction_runtime(fixture.plan, fixture.context)
        failure = RuntimeError("constructor transport failure")
        failure.app_server_cleanup = {"all_contained": False, "resources_closed": False, "errors": ["unreaped"]}
        with mock.patch.object(module, "AppServer", side_effect=failure), self.assertRaises(RuntimeError):
            runtime.prepare(fixture.plan)
        result = runtime.contain([], "constructor-failed", {})
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["construction_cleanup"], failure.app_server_cleanup)

    def test_unaccounted_prelude_allocation_rejected(self):
        fixture = self.fixture()
        runtime, state, context = self.prepared(fixture)
        def dishonest_runner(**kwargs):
            state.server.started_threads["unaccounted"] = None
            return {"receipt_sha256": "a" * 64}
        fixture.context.precommit_runner = dishonest_runner
        with self.assertRaisesRegex(MaintenanceRuntimeError, "precommit-unaccounted-allocation"):
            runtime.start_prelude_session(0, fixture.call_context(0, prelude=True))
        self.assertEqual(fixture.ledger.count(), 1)

    def test_allocation_intent_is_fsynced_before_rpc(self):
        fixture = self.fixture()
        _, state, _ = self.prepared(fixture)
        state.server.before_start = lambda: self.assertEqual(fixture.ledger.count(), 1)
        result = state._start(fixture.call_context(0, prelude=True), prelude=True)
        self.assertEqual(result["attestation_source"], "trusted-app-server-thread-start")
        self.assertEqual(fixture.ledger.count(), 1)

    def test_lost_rpc_counts_and_cannot_claim_containment(self):
        fixture = self.fixture()
        runtime, state, context = self.prepared(fixture)
        state.server.failure = TimeoutError("acknowledgement lost")
        with self.assertRaises(TimeoutError):
            state._start(fixture.call_context(0, prelude=True), prelude=True)
        self.assertEqual(fixture.ledger.count(), 1)
        with mock.patch.object(module, "contain_started_threads", return_value={"all_contained": True}):
            result = runtime.contain([], "failure", context)
        self.assertFalse(result["all_contained"])
        self.assertEqual(result["unidentified_allocations"], 1)

    def test_sandbox_expansion_rejected_after_counting_allocation(self):
        fixture = self.fixture()
        _, state, _ = self.prepared(fixture)
        state.server.sandbox_override = {"type": "workspaceWrite", "networkAccess": True}
        with self.assertRaisesRegex(MaintenanceRuntimeError, "sandbox-mismatch"):
            state._start(fixture.call_context(0, prelude=True), prelude=True)
        self.assertEqual(fixture.ledger.count(), 1)

    def test_missing_enforced_tool_surface_denies_before_rpc(self):
        fixture = self.fixture()
        _, state, _ = self.prepared(fixture)
        state.server.allowlist_supported = False
        with self.assertRaisesRegex(module.AppServerError, "operative-tool-restriction-unsupported"):
            state._start(fixture.call_context(0, prelude=True), prelude=True)
        self.assertEqual(fixture.ledger.count(), 0)
        self.assertNotIn("thread/start", state.server.events)

    def test_revocation_in_surface_callback_stops_before_allocation(self):
        fixture = self.fixture()
        _, state, _ = self.prepared(fixture)
        original = state.server.tool_surface_capability
        def revoke(**kwargs):
            result = original(**kwargs)
            fixture.store.revoke()
            return result
        state.server.tool_surface_capability = revoke
        with self.assertRaises(MaintenanceAuthorityError):
            state._start(fixture.call_context(0, prelude=True), prelude=True)
        self.assertEqual(fixture.ledger.count(), 0)

    def test_injected_invalid_release_is_not_authority(self):
        required = {"maintenance_operation", "maintenance_verifier"}
        if not required <= set(inspect.signature(module.validate_native_worker_packet).parameters):
            self.skipTest("pending shared maintenance-v2 dispatchable packet consumer API")
        fixture = self.fixture()
        runtime, state, context = self.prepared(fixture)
        state.precommit = {"receipt_sha256": "c" * 64}
        with self.assertRaisesRegex(MaintenanceRuntimeError, "operative-packet-invalid"):
            runtime.release_artifacts(fixture.plan, context, None)
        self.assertEqual(fixture.ledger.count(), 0)

    def test_release_hooks_receive_same_opaque_authority_not_serialized_evidence(self):
        fixture = self.fixture()
        hook = mock.Mock(side_effect=fixture.release)
        fixture.context.release_packet = hook
        runtime, state, context = self.prepared(fixture)
        state.precommit = {"receipt_sha256": "c" * 64}
        with mock.patch.object(module, "validate_native_worker_packet", return_value=[]) as validator, \
             mock.patch.object(module, "_render_prompt", return_value="Inspect only the bounded task."):
            runtime.release_artifacts(fixture.plan, context, None)
        for observer in (hook, validator):
            kwargs = observer.call_args.kwargs
            self.assertIs(kwargs["maintenance_operation"], fixture.cap)
            self.assertIs(kwargs["maintenance_verifier"], fixture.verifier)
        self.assertTrue(validator.call_args.kwargs["dispatchable"])
        self.assertEqual(fixture.ledger.count(), 0)

    def test_maintenance_runtime_rejects_historical_release_before_validator(self):
        fixture = self.fixture()
        def historical(**kwargs):
            release = fixture.release(**kwargs)
            release.packet["release_evidence"]["version"] = 1
            return release
        fixture.context.release_packet = historical
        runtime, state, context = self.prepared(fixture)
        state.precommit = {"receipt_sha256": "c" * 64}
        with mock.patch.object(module, "validate_native_worker_packet") as validator, \
             self.assertRaisesRegex(MaintenanceRuntimeError, "maintenance-release-v2-required"):
            runtime.release_artifacts(fixture.plan, context, None)
        validator.assert_not_called()

    def test_resealed_release_canary_cannot_name_other_qualification(self):
        fixture = self.fixture()
        runtime, state, context = self.prepared(fixture)
        state.precommit = {"receipt_sha256": "c" * 64}
        original = fixture.context.release_packet
        def changed(**kwargs):
            release = original(**kwargs)
            packet = deepcopy(dict(release.packet))
            packet["release_evidence"]["canary_receipt_sha256"] = "a" * 64
            return MaintenanceRelease(packet, release.dependencies)
        fixture.context.release_packet = changed
        with mock.patch.object(module,"validate_native_worker_packet",return_value=[]), \
             self.assertRaisesRegex(MaintenanceRuntimeError,"release-qualification-canary"):
            runtime.release_artifacts(fixture.plan,context,None)

    def test_missing_qualification_denies_before_process_start(self):
        fixture = self.fixture();fixture.context.qualification = None
        runtime = module.build_transaction_runtime(fixture.plan,fixture.context)
        with mock.patch.object(module,"AppServer") as server, self.assertRaises(ValueError):
            runtime.prepare(fixture.plan)
        server.assert_not_called()

    def test_dispatch_and_finalize_writers_use_current_sealed_control_identity(self):
        fixture = self.fixture()
        runtime, state, context, allocation = self.released(fixture)
        runtime.bind_admitted_launch(fixture.plan, [allocation], context)
        adapter = state.adapters["child-0"]
        expected = "maintenance-control:" + fixture.operation["operation_id"]
        self.assertEqual(adapter.control_turn_identity(), expected)
        adapter.turn_id = "fixture-observation-only"
        adapter.mark_dispatched(submission_id=adapter.turn_id)
        # This nonterminal callback tests artifact identity only; it must not
        # fabricate completed work or exercise the live archive path.
        adapter.finalize(control_action="fixture-observation-only")
        for suffix in ("dispatch", "finalize-fixture-observation-only"):
            receipt = json.loads((fixture.context.run_dir / f"{adapter.thread_id}-{suffix}.json").read_text())
            self.assertEqual(receipt["control_turn_id"], expected)
        self.assertNotIn("turn/start", state.server.events)

    def test_readonly_real_admission_contract_and_effective_boundary(self):
        fixture = self.fixture()
        runtime, state, context, allocation = self.released(fixture)
        launch = runtime.bind_admitted_launch(fixture.plan, [allocation], context)
        self.assertIs(type(launch), AdmittedPoolLaunch)
        self.assertEqual(validate_pool_contract(launch.contract), [])
        self.assertTrue(launch.preflight_result["accepted"], launch.preflight_result)
        self.assertEqual(json.loads((fixture.context.run_dir / "pool-contract.json").read_text()), launch.contract)
        self.assertEqual(json.loads((fixture.context.run_dir / "admission-reservation.json").read_text()), launch.reservation_receipt)
        self.assertEqual(launch.contract["children"][0]["isolation_class"], "read-only-shared")
        self.assertEqual(launch.preflight_request["children"][0]["packet_sha256"],
                         effective_child_packet_sha256(launch.preflight_request["children"][0]))
        adapter = state.adapters["child-0"]
        self.assertIsNotNone(adapter._workspace_baseline)
        self.assertIsNotNone(adapter._effective_boundary)
        self.assertEqual(fixture.ledger.count(), 2)
        self.assertEqual(state.server.events.count("thread/start"), 2)

    def test_product_real_admission_contract_and_effective_boundary(self):
        fixture = self.fixture(role="product")
        runtime, state, context, allocation = self.released(fixture)
        launch = runtime.bind_admitted_launch(fixture.plan, [allocation], context)
        self.assertTrue(launch.preflight_result["accepted"], launch.preflight_result)
        self.assertEqual(launch.contract["children"][0]["declared_write_paths"], list(fixture.task.write_paths))
        self.assertEqual(state.adapters["child-0"]._effective_boundary["adapter"]["writable_roots"], [str(fixture.worker)])

    def test_same_adapter_cannot_be_used_as_second_runtime(self):
        fixture = self.fixture()
        module.build_transaction_runtime(fixture.plan, fixture.context)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "context-runtime-reused"):
            module.build_transaction_runtime(fixture.plan, fixture.context)

    def final_validation_fixture(self, fixture, *, completed=True, cleanup=True, terminal_states=None):
        runtime, state, context, allocation = self.released(fixture)
        runtime.bind_admitted_launch(fixture.plan, [allocation], context)
        files = list(fixture.task.write_paths) if completed else []
        summary = {"native_worker_return": {"status": "completed" if completed else "blocked",
                   "remaining_scope": {} if completed else {"remaining": "work"}, "decision_required": [],
                   "artifact_disposition": "accepted" if completed else "architect-adjudication-required",
                   "session_disposition": "accepted", "files_touched": files},
                   "native_worker_return_errors": [], "workspace_mutations": files}
        state.adapters["child-0"].final_summary = lambda: deepcopy(summary)
        for target in fixture.task.write_paths:
            path = fixture.worker / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("product\n")
        # These mocks isolate the post-pool reducer; they are not pool receipts
        # and cannot demonstrate model execution or acceptance outside this test.
        with mock.patch.object(module, "validate_dispatch_receipt", return_value=[]), \
             mock.patch.object(module, "validate_pool_receipt", return_value=[]) as receipt_validator, \
             mock.patch.object(module, "read_pool_terminal_state", return_value={"state_sha256": "f" * 64}, side_effect=terminal_states), \
             mock.patch.object(module, "contain_started_threads", return_value={"all_contained": cleanup}):
            result = runtime.validate({"dispatch_receipt": {}, "pool_receipt": {"pool_disposition": "accepted"}}, context)
        self.assertIn("terminal_state", receipt_validator.call_args.kwargs)
        return result

    def test_terminal_state_drift_after_independent_observers_is_not_accepted(self):
        result = self.final_validation_fixture(self.fixture(), terminal_states=[{"state_sha256":"f"*64}, {"state_sha256":"e"*64}])
        self.assertFalse(result["accepted"])
        self.assertIn("pool-terminal-state-drift", result["errors"])

    def test_missing_terminal_observation_preserves_cleanup_and_denies_acceptance(self):
        result = self.final_validation_fixture(self.fixture(), terminal_states=FileNotFoundError("owned state missing"))
        self.assertFalse(result["accepted"])
        self.assertTrue(result["containment"]["all_contained"])
        self.assertTrue(any(e.startswith("pool-terminal-state-unobserved") for e in result["errors"]))

    def test_independent_product_validation_observes_real_artifact_without_closing_bead(self):
        fixture = self.fixture(role="product")
        result = self.final_validation_fixture(fixture)
        self.assertTrue(result["accepted"], result)
        self.assertTrue(result["independent_checks"][0]["accepted"])
        self.assertFalse(result["bead_closed"])
        self.assertEqual(fixture.runner.close_order, [])
        self.assertEqual(fixture.runner.issues[fixture.bead_id]["status"], "in_progress")

    def test_realignment_never_becomes_product_acceptance(self):
        result = self.final_validation_fixture(self.fixture(), completed=False)
        self.assertFalse(result["accepted"])
        self.assertIn("native-return-not-accepted", result["errors"])
        self.assertEqual(result["independent_checks"], [])

    def test_unproved_cleanup_never_becomes_acceptance(self):
        result = self.final_validation_fixture(self.fixture(), cleanup=False)
        self.assertFalse(result["accepted"])
        self.assertIn("containment-unproven", result["errors"])

    def test_independent_readonly_validator_mutation_is_observed(self):
        commands = (ValidationCommand((sys.executable, "-c", "from pathlib import Path; Path('seed.txt').write_text('bad')"), 5),)
        fixture = RuntimeFixture(self.root, commands=commands)
        result = self.final_validation_fixture(fixture)
        self.assertFalse(result["accepted"])
        self.assertIn("validation-mutated-workspace", result["errors"])
        self.assertIn("workspace-final-observation-rejected", result["errors"])

    def test_independent_command_wrong_output_is_not_a_success(self):
        commands = (ValidationCommand((sys.executable, "-c", "print('wrong')"), 5, hashlib.sha256(b"expected\n").hexdigest()),)
        fixture = RuntimeFixture(self.root, commands=commands)
        result = self.final_validation_fixture(fixture)
        self.assertFalse(result["accepted"])
        self.assertIn("independent-validation-failed", result["errors"])

    def test_task_exact_budget_and_scope_types(self):
        fixture = self.fixture()
        for field, value in (("tool_calls", True), ("runtime_seconds", float("inf")), ("mutations", 1)):
            budget = dict(fixture.task.hard_budget, **{field: value})
            with self.subTest(field=field), self.assertRaises(MaintenanceRuntimeError):
                replace(fixture.task, hard_budget=budget).blueprint()
        with self.assertRaisesRegex(MaintenanceRuntimeError, "single-product-path"):
            replace(fixture.task, write_paths=("one", "two"), role="product").blueprint()

    def test_live_precommit_producer_uses_real_state_machine_with_providerless_records(self):
        from tests.test_native_precommit import work_plan, fit_records, session_record
        fixture = self.fixture()
        run_dir = cwo_temp_dir(scope="session") / "precommit-mechanics"
        run_dir.mkdir(mode=0o700)
        session_id = str(uuid.uuid4())
        source = run_dir / "raw-session.jsonl"
        source.write_text(json.dumps(session_record(session_id)) + "\n")
        task = SimpleNamespace(packet_id=str(uuid.uuid4()), attempt_nonce=str(uuid.uuid4()),
            worktree=fixture.worker, work_plan=work_plan(), operative_routing=None)
        events = []
        class FitServer:
            requested_model = task.work_plan["requested_model"]
            reasoning_effort = "max"
            connection_epoch_sha256 = "e" * 64
            _reader_error = None
            process = SimpleNamespace(poll=lambda: None)
            def start_turn(self, identity, prompt):
                persisted = json.loads((run_dir / "precommit-state.json").read_text())
                self_test.assertEqual(persisted["status"], "armed")
                self_test.assertEqual(identity, session_id)
                events.append("turn-after-armed")
                with source.open("a") as handle:
                    for record in fit_records(session_id):
                        handle.write(json.dumps(record) + "\n")
                return {"id": "fit-turn"}, 0.1
            def archive_thread(self, identity):
                self_test.assertIn("live-terminal-inventory-observed", events)
                state = json.loads((run_dir / "precommit-state.json").read_text())
                self_test.assertEqual(state["status"], "completed")
                events.append("archive-after-terminal")
            def record_terminal_archive_containment(self, *args, **kwargs):
                events.append("containment-observed")
            def read_thread(self, identity):
                events.append("archived-path-observed" if "archive-after-terminal" in events else "live-terminal-inventory-observed")
                return {"id": identity, "path": str(source), "turns": [{"id":"fit-turn","status":"completed","error":None}]}, 0.1
        self_test = self
        with mock.patch.dict(os.environ, {"CWO_PRECOMMIT_REGISTRY_ROOT": str(run_dir / "registry")}):
            result = module.run_app_server_precommit(server=FitServer(),
                thread_response={"thread": {"id": session_id, "path": str(source), "turns": []},
                                 "model": task.work_plan["requested_model"]},
                task=task, run_dir=run_dir, current_authority=None, authority_guard=lambda: None, timeout_seconds=10)
            self.assertEqual(module.validate_precommit_receipt(result, task.work_plan,
                operative_routing=None, current_authority=None, live=True, require_accepting=True), [])
        self.assertEqual(events, ["turn-after-armed", "live-terminal-inventory-observed", "archive-after-terminal", "containment-observed", "archived-path-observed"])
        self.assertEqual(result["session_id"], session_id)


class MaintenanceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = MaintenanceSessionLedger(self.root / "ledger.jsonl", mission_id="fixture")
        self.ledger.initialize()
        self.intent = {"allocation_id": "a", "allocation_class": "prelude", "ordinal": 0, "child_id": None}

    def test_fresh_operations_accumulate_without_ceiling_or_reset(self):
        self.assertEqual(self.ledger.count(), 0)
        self.assertEqual(self.ledger.record_intent("op-1", self.intent), 1)
        self.assertEqual(self.ledger.record_intent("op-2", dict(self.intent, allocation_id="b")), 2)
        reopened = MaintenanceSessionLedger(self.ledger.path, mission_id="fixture")
        self.assertEqual(reopened.count(), 2)
        with self.assertRaises((MaintenanceRuntimeError, FileExistsError)):
            reopened.initialize()

    def test_duplicate_wrong_mission_partial_and_tamper_fail_closed(self):
        self.ledger.record_intent("op", self.intent)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "replayed"):
            self.ledger.record_intent("op", self.intent)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "chain-invalid"):
            MaintenanceSessionLedger(self.ledger.path, mission_id="wrong").count()
        content = self.ledger.path.read_text()
        self.ledger.path.write_text(content.rstrip())
        with self.assertRaisesRegex(MaintenanceRuntimeError, "partial"):
            self.ledger.count()
        self.ledger.path.write_text(content.replace('"sequence":1', '"sequence":2'))
        with self.assertRaisesRegex(MaintenanceRuntimeError, "chain-invalid"):
            self.ledger.count()

    def test_boolean_ordinal_and_worker_readable_mode_rejected(self):
        with self.assertRaisesRegex(MaintenanceRuntimeError, "intent-invalid"):
            self.ledger.record_intent("op", dict(self.intent, ordinal=True))
        self.ledger.path.chmod(0o644)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "not-private"):
            self.ledger.count()


class NativeReturnObservationTests(unittest.TestCase):
    def make(self):
        adapter = object.__new__(module.OperationalThreadAdapter)
        adapter.packet = {"packet_id": "packet", "bead_id": "bead", "requested_model": "test-model",
                          "scope": {"workdir": str(ROOT), "allowed_paths": []},
                          "budget": {"tool_calls_soft": 2, "tool_calls_hard": 4, "runtime_seconds_soft": 10,
                                     "runtime_seconds_hard": 20, "max_compactions": 0, "max_full_suite_runs": 0}}
        adapter.packet_hash = canonical_sha256(adapter.packet)
        adapter.segment_id, adapter.thread_id, adapter.turn_id = "segment", "session", "turn"
        adapter.thread_response = {"model": "test-model"}
        adapter.native_return, adapter.return_errors = None, []
        adapter._observing_return = adapter._return_invalidated = False
        result = {"return_type": "cwo-native-worker-return", "version": 1, "packet_id": "packet", "bead_id": "bead",
                  "requested_model": "test-model", "status": "completed", "completed_evidence": "read seed",
                  "files_touched": [], "mutation_state": "clean", "commands_run": ["cat seed.txt"],
                  "validation": {"status": "pass"}, "decision_required": [], "bounded_options": [], "recommendation": "",
                  "remaining_scope": {}, "usage": {"tool_calls": 1, "elapsed_seconds": 1, "context_compactions": 0,
                  "full_suite_runs": 0}, "residual_risks": []}
        for key in ("session_id", "segment_id", "actual_model", "attestation_source", "attestation_status"):
            result[key] = "__CWO_CONTROLLER_BOUND__"
        self.set_message(adapter, result)
        return adapter, result

    def set_message(self, adapter, value):
        text = json.dumps(value) if not isinstance(value, str) else value
        adapter.last_thread = {"turns": [{"id": "turn", "status": "completed", "items": [
            {"type": "agentMessage", "phase": "finalAnswer", "text": text}]}]}

    def test_strict_native_return_binds_only_controller_identity(self):
        adapter, _ = self.make()
        digest, matched = adapter.final_message_observation()
        self.assertTrue(matched, adapter.return_errors)
        self.assertEqual(len(digest), 64)
        self.assertEqual(adapter.native_return["session_id"], "session")
        self.assertEqual(adapter.native_return["actual_model"], "test-model")

    def test_malformed_types_duplicates_and_wrong_identity_fail_closed(self):
        for change in ({"version": True}, {"version": 1.0}, {"session_id": "other"}, {"remaining_scope": {"still": "work"}}):
            adapter, value = self.make()
            value.update(change)
            self.set_message(adapter, value)
            with self.subTest(change=change):
                self.assertFalse(adapter.final_message_observation()[1])
                self.assertIsNone(adapter.native_return)
        adapter, value = self.make()
        self.set_message(adapter, json.dumps(value)[:-1] + ',"version":1}')
        self.assertFalse(adapter.final_message_observation()[1])

    def test_reentrant_parser_permanently_invalidates_return(self):
        adapter, _ = self.make()
        original = module.validate_native_worker_return
        def reentrant(packet, value):
            self.assertFalse(adapter.final_message_observation()[1])
            return original(packet, value)
        with mock.patch.object(module, "validate_native_worker_return", side_effect=reentrant):
            self.assertFalse(adapter.final_message_observation()[1])
        self.assertFalse(adapter.final_message_observation()[1])
        self.assertEqual(adapter.return_errors, ["worker-return-reentrant-observation"])

    def test_missing_return_and_packet_mutation_cannot_inherit_prior_success(self):
        adapter, value = self.make()
        self.assertTrue(adapter.final_message_observation()[1])
        adapter.last_thread = {"turns": []}
        self.assertFalse(adapter.final_message_observation()[1])
        self.set_message(adapter, value)
        adapter.packet["bead_id"] = "different"
        self.assertFalse(adapter.final_message_observation()[1])


class ProjectionTests(unittest.TestCase):
    def test_real_source_prefix_identity_and_exact_model_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source.jsonl", root / "projection.jsonl"
            source.write_text(json.dumps({"type": "session_meta", "payload": {"id": "session", "cwd": str(root)}}) + "\n")
            server = SimpleNamespace(requested_model="test-model", reasoning_effort="max", connection_epoch_sha256="c" * 64)
            projection = module._SessionProjection(server=server,
                response={"thread": {"id": "session", "path": str(source)}, "model": "test-model"}, target=target, worktree=root)
            projection.sync()
            with source.open("a") as handle:
                handle.write(json.dumps({"type": "turn_context", "payload": {"model": "other"}}) + "\n")
            with self.assertRaisesRegex(MaintenanceRuntimeError, "model-mismatch"):
                projection.sync()
            source.write_text("{}\n")
            with self.assertRaisesRegex(MaintenanceRuntimeError, "prefix-drift"):
                projection.sync()


class TerminalPoolStateConsumerTests(unittest.TestCase):
    """Real coordinator/state/receipt validators; providerless, not qualification."""
    def setUp(self):
        from tests import test_native_pool as pool_fixture
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.harness = pool_fixture.PoolHarness(self.temp.name, cap=1, decisions=[["continue", "complete"]])
        self.receipt = self.harness.coordinator.run()
        self.path = self.root / "pool-state.json"

    def test_closed_state_is_required_and_consumed_by_actual_receipt_validator(self):
        self.assertIn("accepting-requires-closed-state", module.validate_pool_receipt(self.receipt, contract=self.harness.contract))
        state = module.read_pool_terminal_state(self.path, contract=self.harness.contract)
        self.assertEqual(state["status"], "closed")
        self.assertEqual(module.validate_pool_receipt(self.receipt, contract=self.harness.contract, terminal_state=state), [])

    def test_tampered_terminal_state_hash_cannot_be_replaced_by_success_boolean(self):
        state = json.loads(self.path.read_text())
        state["worker_seconds"] += 1
        self.path.write_text(json.dumps(state))
        with self.assertRaisesRegex(MaintenanceRuntimeError, "pool-state-invalid"):
            module.read_pool_terminal_state(self.path, contract=self.harness.contract)

    def test_missing_malformed_and_symlink_state_are_controlled_failures(self):
        data = self.path.read_bytes()
        self.path.unlink()
        with self.assertRaises(MaintenanceRuntimeError):
            module.read_pool_terminal_state(self.path, contract=self.harness.contract)
        self.path.write_text('{"state_type":')
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            module.read_pool_terminal_state(self.path, contract=self.harness.contract)
        target = self.root / "state-source.json"
        target.write_bytes(data)
        self.path.unlink(); self.path.symlink_to(target)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "symlink"):
            module.read_pool_terminal_state(self.path, contract=self.harness.contract)

    def test_wrong_contract_and_untrusted_file_mode_reject(self):
        contract = deepcopy(self.harness.contract); contract["contract_sha256"] = "a"*64
        with self.assertRaisesRegex(MaintenanceRuntimeError, "pool-state-invalid"):
            module.read_pool_terminal_state(self.path, contract=contract)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(MaintenanceRuntimeError, "pool-state-private-file"):
            module.read_pool_terminal_state(self.path, contract=self.harness.contract)

    def test_real_fifo_rejects_before_blocking_and_resource_cleanup(self):
        fifo = self.root / "not-state.fifo"
        os.mkfifo(fifo, 0o600)
        script = ("import sys; from pathlib import Path; "
                  "sys.path.insert(0,sys.argv[1]); "
                  "from cwo_core.maintenance_native_runtime import read_pool_terminal_state; "
                  "read_pool_terminal_state(Path(sys.argv[2]),contract={})")
        result = subprocess.run([sys.executable,"-B","-c",script,str(ROOT / "scripts"),str(fifo)],
                                capture_output=True,timeout=3,check=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b"pool-state-private-file-required",result.stderr)

    def test_malformed_status_types_reject_before_unhashable_enum_checks(self):
        original = json.loads(self.path.read_text())
        for target in ("pool", "child"):
            for bad in ([], {}, None, 0, True):
                state = deepcopy(original)
                group = state if target == "pool" else state["children"][0]
                group["status"] = bad
                self.path.write_text(json.dumps(state))
                with self.subTest(target=target,bad=bad), self.assertRaisesRegex(MaintenanceRuntimeError,"status-type-invalid"):
                    module.read_pool_terminal_state(self.path,contract=self.harness.contract)


if __name__ == "__main__":
    unittest.main()
