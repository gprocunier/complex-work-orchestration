"""Wire real offline admission to one original native host and its fake server."""

from __future__ import annotations

import os
import stat
import threading
from dataclasses import fields
from pathlib import Path

import offline_n1_host as native
import prepare_local_admission as admission_api
from cwo_core.invocation_ledger import EffectResult, InvocationLedger

reconciliation = admission_api.reconciliation
FALSE_FIELDS = (
    "production_ready", "effect_authority", "operative", "qualified", "accepted_for_use",
)
_PATH_TYPE = type(Path())
_INVOKE = admission_api.invoke_offline
_RUN = native.OfflineN1Host.run
_STATUS = native.OfflineN1Host.status
_VERIFY = native.OfflineN1Host.verify_artifact
_CLIENT_LOCK = threading.Lock()
_CLIENT_CLAIMS = {}


class OfflineAdmittedN1Error(native.OfflineHostError):
    """A refused bridge operation; attached observations confer no authority."""

    def __init__(self, message, *, native_report=None, verification=None):
        super().__init__(message)
        self.native_report = native_report
        self.verification = verification


def _require(condition, reason):
    if not condition:
        raise OfflineAdmittedN1Error(reason)


def _method_table(cls):
    return {
        name: (getattr(cls, name), isinstance(descriptor, staticmethod))
        for name, descriptor in vars(cls).items()
        if callable(getattr(cls, name))
    }


_HOST_METHODS = _method_table(native.OfflineN1Host)
_LEDGER_METHODS = _method_table(InvocationLedger)


def _claim_keys(host, adapter):
    _require(type(host) is native.OfflineN1Host,
             "Exact original host and adapter objects are required for a client claim.")
    native._methods(adapter)
    _require(type(host.state) is _PATH_TYPE,
             "The client claim requires the original host state path type.")
    server = adapter.server
    device, inode = native._identity(host.state)[:2]
    return (
        ("host", id(host)), ("adapter", id(adapter)),
        ("server", id(server)), ("state-path", str(host.state)),
        ("state-identity", device, inode),
    ), server


def _take_client_claim(keys, token):
    with _CLIENT_LOCK:
        _require(not any(key in _CLIENT_CLAIMS for key in keys),
                 "An overlapping offline client claim is busy.")
        _CLIENT_CLAIMS.update(dict.fromkeys(keys, token))


def _release_client_claim(keys, token):
    with _CLIENT_LOCK:
        for key in keys:
            if _CLIENT_CLAIMS.get(key) is token:
                del _CLIENT_CLAIMS[key]


class _ClientClaim:
    """Serialize overlapping library calls in memory without granting authority."""

    def __init__(self, host, adapter):
        self.host, self.adapter = host, adapter
        self.server = None
        self._keys, self._token = (), object()
        self._used = False

    def __enter__(self):
        with _CLIENT_LOCK:
            _require(not self._used, "An offline client claim is one-shot.")
            self._used = True
        self._keys, self.server = _claim_keys(self.host, self.adapter)
        try:
            _take_client_claim(self._keys, self._token)
            return self
        except BaseException as failure:
            self._release(failure)
            raise

    def _release(self, failure):
        try:
            _release_client_claim(self._keys, self._token)
        except BaseException as secondary:
            if failure is None:
                raise
            admission_api.ledger_api.add_failure_note(
                failure, "Offline client claim cleanup failed (" + type(secondary).__name__
                + "); the original failure is retained.")

    def __exit__(self, _kind, failure, _traceback):
        self._release(failure)
        return False


def _original_methods(value, cls, methods):
    _require(type(value) is cls, "The exact original library object is required.")
    for name, (original, static) in methods.items():
        bound = getattr(value, name)
        observed = bound if static else getattr(bound, "__func__", None)
        _require(observed is original and (static or getattr(bound, "__self__", None) is value),
                 "Original bound library methods are required.")


def _admission_snapshot(value):
    if type(value) is not admission_api.PreparedAdmission:
        raise admission_api.AdmissionError("A complete immutable offline admission is required.")
    values = {}
    for item in fields(admission_api.PreparedAdmission):
        admission_api._require(hasattr(value, item.name), "Offline admission record is incomplete.")
        current = getattr(value, item.name)
        if not item.init:
            admission_api._require(current is False, "Offline admission cannot carry authority.")
        elif item.name in ("issued_at", "expires_at"):
            values[item.name] = current
        else:
            expected = bytes if item.name.endswith("_bytes") else str
            admission_api._require(type(current) is expected and len(current) <= reconciliation.MAX_BYTES,
                                   "Offline admission fields require bounded exact immutable types.")
            values[item.name] = current
    admission_api._times(values["issued_at"], values["expires_at"])
    return admission_api.PreparedAdmission(**values)


def _require_primary(admission):
    selected = reconciliation._decode(admission.selected_node_bytes)
    _require(selected["kind"] == "primary" and selected["lineage_parent"] is None
             and selected["depends_on"] == [],
             "The offline native client supports only a primary node without prior attempts.")


def _graph_attempts(fresh, node_attempts):
    """Retain legacy refusals or copy explicit bindings through original validation."""
    if node_attempts is None:
        _require_primary(fresh)
        return {}, {}
    prior = admission_api._prior_attempts(fresh, node_attempts)
    return prior, {"node_attempts": prior}


def _host_snapshot(host):
    _original_methods(host, native.OfflineN1Host, _HOST_METHODS)
    _require(all(type(getattr(host, name, None)) is _PATH_TYPE for name in ("state", "target", "worker")),
             "Original host paths must retain their exact path type.")
    return reconciliation._snapshot({
        "state": str(host.state), "target": str(host.target), "worker": str(host.worker),
        "identity": host._state_identity, "initial": host._initial,
    })[1]


def _adapter_snapshot(adapter):
    native._methods(adapter)
    _require(all(type(value) is _PATH_TYPE for value in
                 (adapter.worktree, adapter.record_dir, adapter.server.codex_home)),
             "Original adapter paths must retain their exact path type.")
    return reconciliation._snapshot({
        "worker": str(adapter.worktree), "records": str(adapter.record_dir),
        "server_home": str(adapter.server.codex_home), "prompt": adapter.prompt,
        "thread_id": adapter.thread_id, "boundary": adapter._effective_boundary,
        "turn_id": adapter.turn_id, "armed": adapter._effective_boundary_armed,
        "send_reserved": adapter._effective_boundary_send_reserved,
    })[1]


def _ledger_handles(ledger):
    _original_methods(ledger, InvocationLedger, _LEDGER_METHODS)
    _require(type(ledger.root) is _PATH_TYPE, "The ledger requires its original absolute path type.")
    return ledger.root, ledger.clock, ledger.owner_probe, ledger._fsync


def _check_ledger(ledger, handles, host):
    current = _ledger_handles(ledger)
    _require(current[0] == handles[0] and all(left is right for left, right in zip(current[1:], handles[1:])),
             "The ledger path, clock, owner probe or persistence binding changed.")
    root = native._path(current[0])
    for protected in (host.state, host.target, host.worker):
        _require(not native._within(root, protected) and not native._within(protected, root),
                 "Ledger storage must stay separate from host state and both repositories.")


def _read_host_claim(host):
    if not os.path.lexists(host.state / "host.lock"):
        return host._load()
    with host._locked():
        return host._load()


def _refuse_host_claim(host, inputs):
    existing = _read_host_claim(host)
    if existing is None:
        return
    if any(existing["binding"][name] != value for name, value in inputs.items()):
        raise OfflineAdmittedN1Error(
            "Mutated replay or a competing operation ID is refused.",
            native_report=existing,
        )
    raise OfflineAdmittedN1Error(
        "The existing host claim is retained; offline replay is refused.",
        native_report=existing,
    )


def _native_gate(host, adapter, ledger, inputs, host_bytes, adapter_bytes, server, handles):
    _require(_host_snapshot(host) == host_bytes and adapter.server is server,
             "Original host or server bindings changed before execution.")
    _check_ledger(ledger, handles, host)
    _refuse_host_claim(host, inputs)
    _require(_adapter_snapshot(adapter) == adapter_bytes,
             "Original adapter bindings changed before execution.")
    current = host._observe()
    if current != host._initial:
        raise native.OfflineHostError("Worker identity or expected target state drifted.")
    native._adapter_binding(adapter, inputs["contract"], inputs["task"], host.worker, host.state)
    if adapter.turn_id is not None or adapter._effective_boundary_armed or adapter._effective_boundary_send_reserved:
        raise native.OfflineHostError("A fresh unarmed original adapter is required for a new claim.")


def _intent(ledger, admission):
    digest = admission_api._receipt_sha256(admission)
    with ledger._locked() as (_root, document):
        matches = [value for value in document["attempts"].values() if value["admission_sha256"] == digest]
        _require(len(matches) == 1, "The bridge requires its actual persisted admission attempt.")
        current = matches[0]
        _require(current["state"] == "invocation-intent" and current["budget_id"] == admission.budget_id
                 and current["request_id"] == admission.node_id
                 and current["request_sha256"] == admission_api.request_sha256(admission.request_bytes)
                 and reconciliation._same(current["amount"], reconciliation._decode(admission.amounts_bytes)),
                 "The persisted invocation intent differs from the admitted request or allowance.")
        ledger._require_owner(current)
        return current["attempt_id"]


def _verified(host, report, expected_target, host_bytes):
    _require(_host_snapshot(host) == host_bytes, "Original host bindings changed around artifact verification.")
    verification = _VERIFY(host, report, expected_target)
    if verification["valid"] is not True:
        raise OfflineAdmittedN1Error(
            "The original immutable artifact verification failed.",
            native_report=report, verification=verification,
        )
    return verification


def _diagnostic_bindings(ledger, handles, host, host_bytes):
    """Check original handles and current disjoint roots before diagnostic reads."""
    _require(_host_snapshot(host) == host_bytes,
             "Original host bindings changed before failure diagnostics.")
    _check_ledger(ledger, handles, host)
    roots = tuple(native._path(path) for path in
                  (host.state, host.target, host.worker, handles[0]))
    identities = tuple(native._identity(root) for root in roots)
    expected = (host._state_identity, host._initial["target_identity"]["root"],
                host._initial["worker_identity"]["root"])
    _require(identities[:3] == expected,
             "Original host directory identities changed before failure diagnostics.")
    _require(len({tuple(identity[:2]) for identity in identities}) == len(roots),
             "Failure diagnostics require distinct directory identities.")
    for index, root in enumerate(roots):
        _require(all(not native._within(root, other)
                     and not native._within(other, root)
                     for other in roots[index + 1:]),
                 "Failure diagnostics require separate host, target, worker and ledger roots.")
    return identities[-1]


def _diagnostic_mark(info):
    return native._file_mark(info) + (info.st_uid,)


def _read_diagnostic_ledger(ledger, handles, host, host_bytes):
    """Read a stable regular file without creating storage or waiting for a writer."""
    identity = _diagnostic_bindings(ledger, handles, host, host_bytes)
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    root = os.open(handles[0], flags | os.O_DIRECTORY)
    try:
        info = os.fstat(root)
        _require([info.st_dev, info.st_ino, info.st_mode] == identity
                 and info.st_uid == os.getuid(),
                 "The diagnostic ledger directory changed identity or ownership.")
        try:
            before = os.stat(admission_api.ledger_api.LEDGER_FILE, dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            _require(_diagnostic_bindings(ledger, handles, host, host_bytes) == identity,
                     "The diagnostic ledger directory changed while checking for a file.")
            return None
        descriptor = os.open(admission_api.ledger_api.LEDGER_FILE, flags, dir_fd=root)
        try:
            opened = os.fstat(descriptor)
            _require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.getuid()
                     and 0 <= opened.st_size <= reconciliation.MAX_BYTES
                     and _diagnostic_mark(before) == _diagnostic_mark(opened),
                     "Diagnostic ledger data requires the original owned regular file within the byte bound.")
            _require(_diagnostic_bindings(ledger, handles, host, host_bytes) == identity,
                     "The diagnostic ledger binding changed before the bounded read.")
            raw = os.read(descriptor, reconciliation.MAX_BYTES + 1)
            _require(type(raw) is bytes and len(raw) <= reconciliation.MAX_BYTES,
                     "Diagnostic ledger data exceeds the byte bound.")
            after = os.fstat(descriptor)
            current = os.stat(admission_api.ledger_api.LEDGER_FILE, dir_fd=root, follow_symlinks=False)
            _require(_diagnostic_mark(opened) == _diagnostic_mark(after) == _diagnostic_mark(current)
                     and len(raw) == after.st_size,
                     "The diagnostic ledger file changed or the bounded read was incomplete.")
            _require(_diagnostic_bindings(ledger, handles, host, host_bytes) == identity,
                     "The diagnostic ledger binding changed during the bounded read.")
            return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(root)


def _diagnostics(failure, ledger, admission, host, inputs, handles, host_bytes):
    """Read retained observations without provisioning storage or replacing a failure."""
    _diagnostic_bindings(ledger, handles, host, host_bytes)
    try:
        if inputs is not None and getattr(failure, "native_report", None) is None:
            report = _STATUS(host, inputs["operation_id"])
            if all(report["binding"][name] == value for name, value in inputs.items()):
                failure.native_report = report
    except BaseException:
        pass
    identity = _diagnostic_bindings(ledger, handles, host, host_bytes)
    raw = _read_diagnostic_ledger(ledger, handles, host, host_bytes)
    if raw is None:
        return
    document = reconciliation._decode(raw)
    _require(not admission_api.ledger_api.validate_ledger(document),
             "Stored diagnostic ledger data failed the original consistency checks.")
    matches = [value for value in document["attempts"].values()
               if value["admission_sha256"] == admission_api._receipt_sha256(admission)
               and value["request_id"] == admission.node_id and value["budget_id"] == admission.budget_id]
    _require(_diagnostic_bindings(ledger, handles, host, host_bytes) == identity,
             "The diagnostic ledger binding changed before retaining observations.")
    failure.ledger_attempts = reconciliation._snapshot(matches)[0]


def _observe_failure(failure, ledger, admission, host, inputs, handles, host_bytes,
                     invocation_started, native_reports):
    """Retain known reports and keep every diagnostic failure secondary."""
    try:
        if native_reports and getattr(failure, "native_report", None) is None:
            failure.native_report = native_reports[-1]
        if invocation_started:
            _diagnostics(failure, ledger, admission, host, inputs, handles, host_bytes)
    except BaseException:
        pass


def _run_claimed(admission, expected_route_input, node_id, *, ledger, host, adapter, server,
                 contract, operation_id, outputs, max_steps, configuration_pins,
                 observer=None, node_attempts=None):
    """Run one admitted fake native operation; no task, effect or usage override is supported."""
    fresh = _admission_snapshot(admission)
    route, _route_bytes = reconciliation._snapshot(expected_route_input)
    _require(type(node_id) is str, "The independently selected node requires an exact string identity.")
    control, _control_bytes = reconciliation._snapshot(contract)
    pins, _pins_bytes = reconciliation._snapshot(configuration_pins)
    _require(type(outputs) in (list, tuple) and 1 <= len(outputs) <= native.MAX_OUTPUTS,
             "Declared outputs require a bounded nonempty exact list or tuple.")
    paths, _paths_bytes = reconciliation._snapshot(list(outputs))
    host_bytes = _host_snapshot(host)
    handles = _ledger_handles(ledger)
    expected_target = reconciliation._decode(host_bytes)["initial"]["target"]
    observed = []
    native_reports = []
    native_started = []
    invocation_started = False

    def bridge(request, execution, allowance, _report):
        _require(type(request) is bytes and request == fresh.request_bytes
                 and reconciliation._same(execution, reconciliation._decode(fresh.execution_bytes))
                 and reconciliation._same(allowance, reconciliation._decode(fresh.amounts_bytes)),
                 "The library bridge requires the exact admitted request, execution and allowance.")
        _native_gate(host, adapter, ledger, inputs, host_bytes, adapter_bytes, server, handles)
        attempt_id = _intent(ledger, fresh)
        admission_api._graph_state(fresh, prior, ledger, attempt_id)
        native_started.append(True)
        report = _RUN(
            host, inputs["operation_id"], inputs["task"], inputs["contract"], adapter,
            outputs=tuple(inputs["outputs"]), max_steps=inputs["max_steps"],
            configuration_pins=inputs["configuration_pins"],
        )
        native_reports.append(report)
        if report["status"] != "artifact-ready":
            raise OfflineAdmittedN1Error(
                report["error"] or "The native operation requires reconciliation.",
                native_report=report,
            )
        _require(all(report["binding"][name] == value for name, value in inputs.items())
                 and adapter.turn_id == report["receipt"]["submission_id"],
                 "The native report must match this admitted dispatch and original adapter turn.")
        verification = _verified(host, report, expected_target, host_bytes)
        observed.append((report, verification))
        return EffectResult("completed")

    try:
        fresh = admission_api._validated(fresh, route, node_id, ledger, bridge, observer)
        prior, invocation_options = _graph_attempts(fresh, node_attempts)
        task = fresh.request_bytes.decode("utf-8", errors="strict")
        inputs = native._inputs(operation_id, task, control, paths, max_steps, pins)
        _refuse_host_claim(host, inputs)
        _require(adapter.server is server,
                 "The claimed server binding changed before validation.")
        adapter_bytes = _adapter_snapshot(adapter)
        _native_gate(host, adapter, ledger, inputs, host_bytes, adapter_bytes, server, handles)
        invocation_started = True
        admitted = _INVOKE(
            fresh, route, node_id, ledger=ledger, effect=bridge, observer=observer, **invocation_options)
        _check_ledger(ledger, handles, host)
        attempt = ledger.attempt(admitted["attempt"]["reservation_id"])
        _require(attempt == admitted["attempt"] and attempt["state"] == "terminal"
                 and attempt["outcome"] == "completed" and len(observed) == 1,
                 "Offline completion requires the actual completed ledger invocation.")
        report, _first_verification = observed[0]
        verification = _verified(host, report, expected_target, host_bytes)
    except BaseException as failure:
        _observe_failure(
            failure, ledger, fresh, host, inputs if native_started else None,
            handles, host_bytes, invocation_started, native_reports,
        )
        raise
    return {
        "api": "offline-admitted-n1-v1", "offline_completed": True,
        "prepared_admission": fresh, "admission_result": admitted, "attempt": attempt,
        "admission_sha256": admission_api._receipt_sha256(fresh),
        "budget_id": fresh.budget_id, "scope_sha256": fresh.scope_sha256, "node_id": fresh.node_id,
        "request_bytes": fresh.request_bytes, "request_sha256": admission_api.request_sha256(fresh.request_bytes),
        "declared_execution": reconciliation._decode(fresh.execution_bytes),
        "declared_allowance": reconciliation._decode(fresh.amounts_bytes),
        "declared_aggregate_limits": reconciliation._decode(fresh.limits_bytes),
        "native_report": report, "native_receipt": report["receipt"], "artifact": report["artifact"],
        "artifact_verification": verification,
        "effective_backend_metadata": None, "effective_backend_metadata_supported": False,
        "actual_quota_known": False, "actual_provider_billing_known": False,
        **dict.fromkeys(FALSE_FIELDS, False),
    }


def run_offline_admitted_n1(admission, expected_route_input, node_id, *, ledger, host, adapter,
                            contract, operation_id, outputs, max_steps, configuration_pins,
                            observer=None, node_attempts=None):
    """Hold one client claim through admission, native execution and final verification."""
    with _ClientClaim(host, adapter) as claim:
        return _run_claimed(
            admission, expected_route_input, node_id, ledger=ledger, host=host,
            adapter=adapter, server=claim.server, contract=contract, operation_id=operation_id,
            outputs=outputs, max_steps=max_steps, configuration_pins=configuration_pins,
            observer=observer, node_attempts=node_attempts,
        )
