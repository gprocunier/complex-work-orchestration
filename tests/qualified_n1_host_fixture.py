"""One finite cooperative EXAMPLE lifecycle; no qualified execution authority.

The existing offline fake server calls the existing effect runner. Only its useful
EXAMPLE effect is backed by a retained-owner fixed child. Archive cannot return until
that child has been independently terminated and reaped. All publication is FAKE.
"""
from __future__ import annotations

import copy
import hashlib
import os
import sys
import threading
import time
from pathlib import Path

import linux_owned_children as ownership
import offline_admitted_n1 as admitted
import offline_artifact_validation as validation
import offline_effect_profile as effects
import offline_fake_artifact_promotion as promotion

# Independently selected validator expectation, separate from the child program.
EXPECTED = b"EXAMPLE_RESULT: useful offline fixture output\n"
CHILD_PROGRAM = (
    "import os,pathlib,time; "
    "p=pathlib.Path('result.txt'); staged=pathlib.Path('EXAMPLE-result.tmp'); "
    "f=staged.open('xb'); f.write(b'EXAMPLE_RESULT: useful offline fixture output\\n'); "
    "f.close(); os.link(staged,p); staged.unlink(); time.sleep(5)"
)
LIMITS = {"max_files": 4, "max_file_bytes": 1048576,
          "max_total_bytes": 4194304, "max_entries": 64}
_FALSE = dict.fromkeys(admitted.FALSE_FIELDS, False)
_SPAWN = ownership.LinuxOwnedChildController.spawn_owned
_TERMINATE = ownership.LinuxOwnedChildController.terminate


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _binding(receipt, host, adapter, contract, pins, max_steps):
    decode = admitted.reconciliation._decode
    return {"candidate": host._initial, "context": adapter._effective_boundary,
            "factory": decode(receipt.execution_bytes),
            "limits": {"allowance": decode(receipt.amounts_bytes),
                       "aggregate": decode(receipt.limits_bytes)},
            "request_sha256": admitted.admission_api.request_sha256(receipt.request_bytes),
            "scope_sha256": receipt.scope_sha256, "configuration_pins": pins,
            "control_contract": contract, "max_steps": max_steps}


class _OwnedEffect(effects.ExampleEffects):
    """The original runner invokes this fixed useful process, with no input pipe."""

    def __init__(self, lifecycle):
        super().__init__(lifecycle.host.worker)
        self.lifecycle = lifecycle

    def apply(self, command):
        if command != effects.COMMAND:
            return super().apply(command)
        self.calls[command] += 1
        self.lifecycle._spawn()
        deadline = time.monotonic() + 1.0
        while (not (self.worker / "result.txt").exists()
               or os.path.lexists(self.worker / "EXAMPLE-result.tmp")):
            _need(time.monotonic() < deadline, "EXAMPLE child output was not observed within the finite wait.")
            time.sleep(0.002)
        raw = admitted.native._read(self.worker, "result.txt", len(EXPECTED))
        _need(raw == EXPECTED, "EXAMPLE child output differs from the independent expectation.")
        return effects.ACK


class FiniteN1Lifecycle:
    """One offline operation and recoverable fake publication, never a route factory.

    Requires the existing JA EffectServer, original runner, original native adapter,
    actual PreparedAdmission/InvocationLedger and original retained-child controller.
    The server remains a cooperative test transport, not a custody provider.
    """

    def __init__(self, receipt, route, node_id, *, ledger, host, adapter, controller,
                 contract, operation_id, configuration_pins, fake_state, fake_target,
                 initial_files, max_steps=128):
        # This module is intentionally an offline harness of existing fixtures.
        from test_offline_effect_profile import EffectServer
        _need(type(adapter) is admitted.native.LiveThreadAdapter,
              "The original native adapter is required.")
        _need(type(adapter.server) is EffectServer,
              "Select the existing cooperative EXAMPLE fake server explicitly.")
        _need(type(controller) is ownership.LinuxOwnedChildController,
              "The original retained-child controller is required.")
        _need(type(adapter.server.runner) is effects.ExampleEffectRunner,
              "The original finite effect runner is required.")
        _need(type(adapter.server.runner._effects) is effects.ExampleEffects,
              "A fresh original EXAMPLE backend is required.")
        admitted.native._methods(adapter)
        self.receipt, self.route, self.node_id = receipt, copy.deepcopy(route), node_id
        self.ledger, self.host, self.adapter, self.controller = ledger, host, adapter, controller
        self.contract, self.pins = copy.deepcopy(contract), copy.deepcopy(configuration_pins)
        self.operation_id, self.max_steps = operation_id, max_steps
        self.runner, self.server = adapter.server.runner, adapter.server
        self._expected_binding = copy.deepcopy(self._current_binding())
        self.runner.check_binding(self._expected_binding)
        self._expected_target = copy.deepcopy(host._initial["target"])
        self.policy = validation.freeze_policy({"version": 1, "outputs": [{
            "path": "result.txt", "validator": "bytes", "size": len(EXPECTED),
            "sha256": hashlib.sha256(EXPECTED).hexdigest()}]})
        self._selected_policy = self.policy
        self._policy_report = self.policy.report
        self.target = promotion.FakeArtifactTarget(
            fake_state, fake_target, host, self._expected_target, initial_files, limits=dict(LIMITS))
        self._archive = self.server.archive_thread
        self._child = None
        self.spawn_report = self.termination_report = None
        self.spawn_error = self.termination_error = None
        self._termination_lock = threading.Lock()
        self._termination_state = "not-attempted"
        self.execution = self.token = None
        self._started = False
        self._lock = threading.Lock()
        self.runner._effects = _OwnedEffect(self)
        self.server.archive_thread = self._archive_owned

    def _current_binding(self):
        return _binding(self.receipt, self.host, self.adapter, self.contract, self.pins, self.max_steps)

    def _check(self):
        _need(self.policy is self._selected_policy and self.policy.report == self._policy_report,
              "The independently selected fixed validation policy changed.")
        archive = self.server.archive_thread
        _need(getattr(archive, "__self__", None) is self
              and getattr(archive, "__func__", None) is FiniteN1Lifecycle._archive_owned,
              "The registered pre-capture lifetime boundary changed.")
        _need(self._current_binding() == self._expected_binding,
              "The finite lifecycle binding changed.")
        self.runner.check_binding(self._expected_binding)

    def _retain_spawn(self, report):
        self.spawn_report = report
        if type(report) is dict and report.get("receipt_available") is True:
            receipt = report.get("receipt")
            if type(receipt) is ownership.OwnedChildReceipt:
                self._child = receipt

    def _spawn(self):
        self._check()
        _need(self._child is None and self.spawn_report is None, "EXAMPLE child dispatch is one-shot.")
        _need(not any(os.path.lexists(self.host.worker / name)
                      for name in ("result.txt", "EXAMPLE-result.tmp")),
              "EXAMPLE output and staging paths must not preexist child dispatch.")
        executable = str(Path(sys.executable).resolve())
        _need(self.controller._executable == executable, "The fixed current interpreter must be selected.")
        try:
            report = _SPAWN(self.controller,
                self.operation_id, [executable, "-I", "-S", "-c", CHILD_PROGRAM], str(self.host.worker))
        except BaseException as failure:
            self.spawn_error = failure
            self._retain_spawn(getattr(failure, "ownership_report", None))
            raise
        self._retain_spawn(report)
        _need(report["outcome"] == "registered" and self._child is not None,
              "Actual retained-child registration is required.")

    def _terminate(self):
        with self._termination_lock:
            _need(self._child is not None, "No owned useful child was registered.")
            perform = self._termination_state == "not-attempted"
            if perform:
                self._termination_state = "in-progress"
            else:
                _need(self._termination_state != "in-progress",
                      "The existing child termination is in-progress; no repeat is permitted.")
                if self.termination_error is not None:
                    raise self.termination_error
            report = self.termination_report
        if perform:
            try:
                report = _TERMINATE(self.controller, self._child, 0.1, allow_kill=True)
            except BaseException as failure:
                with self._termination_lock:
                    self.termination_error = failure
                    self.termination_report = getattr(failure, "ownership_report", None)
                    self._termination_state = "failed"
                raise
            with self._termination_lock:
                self.termination_report = report
                self._termination_state = "returned"
        _need(type(report) is dict
              and report.get("outcome") in {"terminated", "killed", "already-exited", "exited-before-signal"}
              and report.get("child_exit_confirmed") is True
              and report.get("child_reaped") is True,
              "Controlled useful-child exit and retained-handle reaping are required before capture.")

    def _cleanup_failure(self, primary):
        with self._termination_lock:
            state = self._termination_state
        if self._child is not None and state == "not-attempted":
            try:
                self._terminate()
            except BaseException as secondary:
                admitted.admission_api.ledger_api.add_failure_note(
                    primary, "Finite child cleanup failed (" + type(secondary).__name__ + ").")
        elif state == "in-progress":
            admitted.admission_api.ledger_api.add_failure_note(
                primary, "Finite child termination was in-progress at failure cleanup; no repeat was attempted.")

    def _archive_owned(self, thread_id):
        self._check()
        self._terminate()
        return self._archive(thread_id)

    def run_offline(self):
        """Execute once; the original ledger retains unknown usage and all charges."""
        with self._lock:
            _need(not self._started, "Native redispatch and lifecycle replay are refused; use publish_offline only.")
            self._started = True
        try:
            self._check()
            self.execution = admitted.run_offline_admitted_n1(
                self.receipt, self.route, self.node_id, ledger=self.ledger, host=self.host,
                adapter=self.adapter, contract=self.contract, operation_id=self.operation_id,
                outputs=("result.txt",), max_steps=self.max_steps, configuration_pins=self.pins)
            self._check()
            self._terminate()
            self.token = validation.validate_artifact(
                self.host, self.execution["native_report"], self._expected_target, self.policy)
            self.target.initialize()
            return self.publish_offline()
        except BaseException as primary:
            self._cleanup_failure(primary)
            raise

    def publish_offline(self):
        """Only original guarded fake transaction replay; never repeat native work."""
        self._check()
        _need(self.execution is not None and self.token is not None,
              "Original execution and independent issued validation are required.")
        report = self.target.promote(
            self.operation_id, self.token, self.execution["native_report"], self.policy, expected_revision=0)
        return {"offline_completed": self.execution["offline_completed"],
                "offline_validation_complete": self.token.report["offline_validation_complete"],
                "fake_publication": report, "execution": self.execution,
                "ownership": self.termination_report, "purpose": "EXAMPLE-fixed-output-only",
                "evidence_acceptance_is_execution_authority": False, **_FALSE}
