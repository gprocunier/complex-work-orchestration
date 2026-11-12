"""Custody adapters for the original closure client.

Production closure remains disabled. Its authority is the host acceptance
pipeline and verified database identity; the EXAMPLE path stays a simulation.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import threading
import uuid
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import close_bead_with_summary as closure
import prepare_delivery_closure as original
from cwo_core import beads
from cwo_core.errors import CWOPolicyError
import production_closure_authority as production_authority

PUBLIC_ACTIVATION = False
PRODUCTION_CLOSURE_AVAILABLE = False
MAX_CONTROL = original.combined.MAX_DOCUMENT


def _need(value: bool, reason: str) -> None:
    if not value:
        raise original.ClosureError(reason)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def _directory(path: Path) -> int:
    _need(path.is_absolute() and path.resolve() == path, "custody paths must be canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        _need(info.st_uid == os.getuid() and not info.st_mode & 0o077,
              "EXAMPLE custody must be supervisor-owned and private")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_at(descriptor: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=descriptor)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and before.st_uid == os.getuid() and not before.st_mode & 0o077
              and 0 < before.st_size <= MAX_CONTROL, "control source must be a bounded private regular file")
        data = os.read(fd, MAX_CONTROL + 1)
        after = os.fstat(fd)
        _need(len(data) == before.st_size and _identity(after) == _identity(before)
              and (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
              == (before.st_size, before.st_mtime_ns, before.st_ctime_ns),
              "control source changed while reading")
        return data
    finally:
        os.close(fd)


def _sources() -> tuple[tuple[str, bytes], ...]:
    modules = (closure, original, original.combined, original.producer, original.artifacts,
               original.validation, original.ci, original.rb,
               original.combined.validators, original.combined.final_review,
               original.combined.validators.cc, original.validation.HOST, beads,
               production_authority, production_authority.host_records, production_authority.host_acceptance)
    paths = sorted({str(Path(module.__file__).resolve()) for module in modules} | {str(Path(__file__).resolve())})
    return tuple((name, hashlib.sha256(Path(name).read_bytes()).digest()) for name in paths)


class ExampleBeadsBridge:
    """Fixed inert simulation of the original Beads boundary, never an authority source."""

    def __init__(self, bead: Any, custody: Path) -> None:
        self.bead = original._read(original._freeze(bead))
        self.database = str(custody / "EXAMPLE.db")
        self.effects: list[tuple[str, ...]] = []
        self.lock = threading.RLock()

    def _show(self) -> str:
        return original._freeze([self.bead]).decode()

    def _comment(self, command: list[str]) -> str:
        self.effects.append(tuple(command))
        self.bead["comments"].append({"text": command[3]})
        return ""

    def _close(self, command: list[str]) -> str:
        self.effects.append(tuple(command))
        self.bead["status"] = "closed"
        return ""

    def __call__(self, args: list[str]) -> str:
        with self.lock:
            _need(args[:4] == ["--db", self.database, "--actor", "EXAMPLE-qualified-closure"],
                  "the fixed EXAMPLE database and actor are required")
            command = args[4:]
            if command == ["show", "--json", "--include-comments", "--", self.bead["id"]]:
                return self._show()
            if len(command) == 4 and command[:3] == ["comment", "--", self.bead["id"]]:
                return self._comment(command)
            _need(command == ["close", "--reason", "EXAMPLE bound delivery accepted", "--", self.bead["id"]],
                  "the EXAMPLE bridge refuses unsupported commands or task IDs")
            return self._close(command)


_EXAMPLE_CALL = ExampleBeadsBridge.__call__
_BEADS_CALL = beads.run_bd


class _ProductionBeadsBridge:
    """The original real adapter, selected by supervisor registration, never worker data."""

    def __init__(self, database: Path, actor: str) -> None:
        self.database = str(database)
        self.actor = actor
        self.lock = threading.RLock()
        self.call = _BEADS_CALL

    def __call__(self, args: list[str]) -> str:
        return self.call(["--db", self.database, "--actor", self.actor, *args])


_PRODUCTION_CALL = _ProductionBeadsBridge.__call__


@dataclass
class _State:
    custody: Path
    descriptor: int
    identity: tuple[int, int, int, int]
    contract: bytes
    root_descriptor: int
    root_identity: tuple[int, int, int, int]
    sources: tuple[tuple[str, bytes], ...]
    bridge: Any
    resources: contextlib.ExitStack
    registration_id: str = field(default_factory=lambda: "EXAMPLE-registration-" + uuid.uuid4().hex)
    lock: Any = field(default_factory=threading.RLock)
    active: bool = False
    retired: bool = False
    observation: Any = None
    bound: Any = None
    review: tuple[bytes, bytes] | None = None
    failure: BaseException | None = None
    report: dict[str, Any] = field(default_factory=dict)
    attempted: bool = False
    native_roots: tuple[tuple[str, int, tuple[int, int, int, int]], ...] = ()
    database_root: tuple[tuple[str, int, tuple[int, int, int, int]], ...] = ()
    database_identity: tuple[int, int, int, int] | None = None
    authority: Any = None


_registry: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_final_reports: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_registry_lock = threading.RLock()


class Host:
    """Opaque process-local EXAMPLE host identity, issued only while custody is held."""

    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise original.ClosureError("use example_custody; records and constructors cannot issue hosts")

    @property
    def report(self) -> dict[str, Any]:
        with _registry_lock:
            state = _registry.get(self)
            saved = _final_reports.get(self)
        if state is None:
            _need(saved is not None, "an issued EXAMPLE host report is required")
            return original._read(saved)
        with state.lock:
            return original._read(original._freeze(state.report))

    @property
    def review_context(self) -> dict[str, str]:
        """Return EXAMPLE review bindings; production authorization is host-recorded."""
        state = _state(self)
        context = {"registration_id": state.registration_id, "database": state.bridge.database,
                   "bead_id": original._read(state.contract)["bead"]["id"]}
        if type(state.bridge) is _ProductionBeadsBridge:
            context["actor"] = state.bridge.actor
        return context


def _state(host: Host) -> _State:
    with _registry_lock:
        _need(type(host) is Host and host in _registry, "an active registered EXAMPLE host is required")
        return _registry[host]


def _contract(raw: bytes) -> dict[str, Any]:
    value = original._read(raw)
    original.combined._shape(value, "cwo-EXAMPLE-closure-custody", (
        "scope", "root", "initial", "amendments", "candidate", "bead", "commands"))
    _need(value["scope"] == "EXAMPLE-only" and value["bead"]["id"].startswith("EXAMPLE-"),
          "only explicit EXAMPLE tasks may use this registration")
    original._observation_input(value["root"], value["initial"], value["candidate"],
                                value["bead"], value["commands"], value["amendments"])
    original._candidate({"root": value["root"], "baseline": value["initial"],
                         "amendments": value["amendments"], "candidate": value["candidate"]}, value["bead"])
    _need(value["bead"].get("status") == "open", "the authorized task must start open")
    return value


def _production_contract(raw: bytes) -> dict[str, Any]:
    value = original._read(raw)
    original.combined._shape(value, "cwo-production-closure-custody", (
        "root", "initial", "amendments", "candidate", "bead", "commands"))
    original._observation_input(value["root"], value["initial"], value["candidate"],
                                value["bead"], value["commands"], value["amendments"])
    original._candidate({"root": value["root"], "baseline": value["initial"],
                         "amendments": value["amendments"], "candidate": value["candidate"]}, value["bead"])
    _need(value["bead"].get("status") in ("open", "in_progress"), "the authorized task must be open or in progress")
    return value


def _report() -> dict[str, Any]:
    return {"record_type": "cwo-qualified-EXAMPLE-closure", "version": 1,
            **dict.fromkeys(original.AUTHORITY_FIELDS, False),
            "scope": "EXAMPLE-only", "custody_registered": True,
            "registration_active": True,
            "retirement_interrupted": False,
            "state": "REFUSED", "fake_completed": False, "completion_unconfirmed": True,
            "comment_posted": False, "closed": False, "partial_persistence": False,
            "comment_attempted": False, "close_attempted": False,
            "persistence_known": True,
            "last_call_state": "REFUSED", "current_applicability": "REFUSED",
            "failure_type": None, "summary": None}


@contextlib.contextmanager
def example_custody(directory: str) -> Iterator[Host]:
    """Hold a private out-of-worker supervisor directory and cooperative candidate ownership.

    The supervisor provisions contract.json before result production and later
    deposits review.json and expectation.json through its separate review source.
    These files are never accepted from consume() or a worker return. This finite
    registration qualifies EXAMPLE custody only; it cannot register a live issuer.
    """
    custody = Path(directory)
    with contextlib.ExitStack() as stack:
        descriptor = _directory(custody)
        stack.callback(os.close, descriptor)
        raw = _read_at(descriptor, "contract.json")
        contract = _contract(raw)
        root = Path(contract["root"])
        _need(not custody.is_relative_to(root) and not root.is_relative_to(custody),
              "supervisor custody and worker root must be disjoint")
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root_fd)
        fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        bridge = closure.run_bd
        _need(type(bridge) is ExampleBeadsBridge and bridge.database == str(custody / "EXAMPLE.db"),
              "a fixed EXAMPLE bridge for this custody is required; live Beads effects are disabled")
        state = _State(custody, descriptor, _identity(os.fstat(descriptor)), raw,
                       root_fd, _identity(os.fstat(root_fd)), _sources(), bridge, stack, report=_report())
        host = object.__new__(Host)
        with _registry_lock:
            _registry[host] = state
        active_error = None
        try:
            _guard(state)
            _task(state, contract["bead"])
            yield host
        except BaseException as error:
            active_error = error
            raise
        finally:
            _retire(host, state, active_error)


@contextlib.contextmanager
def production_custody(directory: str, *, database: str, actor: str,
                       acceptance_record: str | None = None,
                       return_sha256: str | None = None,
                       evaluation_sha256: str | None = None) -> Iterator[Host]:
    """Register an exact autonomous host acceptance, never an approval file.

    The code gate is checked before validation or I/O. Database identity must
    already have been established by explicit workspace setup. Every Beads call
    rechecks that identity and the verified acceptance and its hold evidence.
    """
    _need(PRODUCTION_CLOSURE_AVAILABLE is True,
          "production closure is unavailable pending the production closure restoration decision")
    custody, db = Path(directory), Path(database)
    _need(type(actor) is str and bool(actor.strip()) and actor == actor.strip(),
          "a supervisor-selected explicit Beads actor is required")
    _need(db.is_absolute() and db.resolve() == db and (db.is_file() or db.is_dir()) and not db.is_symlink(),
          "a supervisor-selected existing canonical Beads database is required")
    database_root = db if db.is_dir() else db.parent
    with contextlib.ExitStack() as stack:
        descriptor = _directory(custody)
        stack.callback(os.close, descriptor)
        raw = _read_at(descriptor, "contract.json")
        contract = _production_contract(raw)
        root = Path(contract["root"])
        authority = _authority_call(production_authority.capture, database=str(db),
                                    bead_id=contract["bead"]["id"],
                                    acceptance_record=acceptance_record,
                                    return_sha256=return_sha256,
                                    evaluation_sha256=evaluation_sha256,
                                    worker_writable_roots=(root, custody))
        _need(not custody.is_relative_to(root) and not root.is_relative_to(custody)
              and not database_root.is_relative_to(root) and not root.is_relative_to(database_root)
              and not database_root.is_relative_to(custody) and not custody.is_relative_to(database_root),
              "supervisor, database and worker ownership must be separate")
        db_fd = _directory(database_root)
        stack.callback(os.close, db_fd)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root_fd)
        fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        bridge = _ProductionBeadsBridge(db, actor)
        report = _report()
        report.update(record_type="cwo-production-closure", scope="registered-task-only", completed=False)
        state = _State(custody, descriptor, _identity(os.fstat(descriptor)), raw,
                       root_fd, _identity(os.fstat(root_fd)), _sources(), bridge, stack,
                       registration_id="closure-registration-" + uuid.uuid4().hex, report=report)
        state.database_root = ((str(database_root), db_fd, _identity(os.fstat(db_fd))),)
        state.database_identity = _identity(os.stat(db, follow_symlinks=False))
        state.authority = authority
        host = object.__new__(Host)
        with _registry_lock:
            _registry[host] = state
        active_error = None
        try:
            _guard(state)
            _task(state, contract["bead"])
            yield host
        except BaseException as error:
            active_error = error
            raise
        finally:
            _retire(host, state, active_error)


def _retire(host: Host, state: _State, active_error: BaseException | None) -> None:
    interrupted = None
    while True:
        try:
            with state.lock:
                state.retired = True
                state.report.update(registration_active=False, current_applicability="EXPIRED",
                                    retirement_interrupted=interrupted is not None or state.report["retirement_interrupted"])
                with _registry_lock:
                    _final_reports[host] = original._freeze(state.report)
                    _registry.pop(host, None)
            break
        except (KeyboardInterrupt, SystemExit, InterruptedError) as error:
            if interrupted is None:
                interrupted = error
    if interrupted is not None:
        if active_error is None:
            raise interrupted
        active_error.add_note("EXAMPLE custody retirement was interrupted; ownership was retained until active work finished.")


@contextlib.contextmanager
def _operation(host: Host) -> Iterator[_State]:
    state = _state(host)
    with state.lock, state.bridge.lock:
        _need(not state.retired and _state(host) is state,
              "the EXAMPLE host retired while this operation was queued")
        _need(not state.active, "a closure operation is already active")
        if state.failure is not None:
            raise state.failure
        state.active = True
        try:
            yield state
        except BaseException as error:
            state.failure = error
            state.report.update(last_call_state="REFUSED", current_applicability="REFUSED",
                                failure_type=type(error).__name__)
            if not state.report["closed"]:
                state.report.update(state="PARTIAL_PERSISTENCE" if state.report["comment_posted"] else "REFUSED",
                                    completion_unconfirmed=True,
                                    partial_persistence=state.report["comment_posted"])
            raise
        finally:
            state.active = False


def _authority_call(call: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return call(*args, **kwargs)
    except (CWOPolicyError, ValueError, OSError) as error:
        raise original.ClosureError(str(error)) from error


def _production_guard(state: _State) -> None:
    if type(state.bridge) is _ProductionBeadsBridge:
        _need(PRODUCTION_CLOSURE_AVAILABLE is True,
              "production closure is unavailable pending the production closure restoration decision")
        _need(state.authority is not None, "verified host acceptance authority is required")
        _authority_call(state.authority.check, state.bridge.database)


def _guard(state: _State) -> dict[str, Any]:
    _production_guard(state)
    _need(_identity(os.stat(state.custody, follow_symlinks=False)) == state.identity
          == _identity(os.fstat(state.descriptor)), "supervisor custody identity changed")
    _need(_read_at(state.descriptor, "contract.json") == state.contract,
          "authoritative baseline, task or candidate changed")
    value = original._read(state.contract)
    _need(_identity(os.stat(value["root"], follow_symlinks=False)) == state.root_identity
          == _identity(os.fstat(state.root_descriptor)), "owned candidate root identity changed")
    _need(_sources() == state.sources, "current closure source changed after registration")
    for path, descriptor, identity in state.native_roots + state.database_root:
        _need(_identity(os.stat(path, follow_symlinks=False)) == identity
              == _identity(os.fstat(descriptor)), "owned native prerequisite root identity changed")
    if state.database_identity is not None:
        _need(_identity(os.stat(state.bridge.database, follow_symlinks=False)) == state.database_identity,
              "registered Beads database identity changed")
    if state.review is not None:
        _need((_read_at(state.descriptor, "review.json"), _read_at(state.descriptor, "expectation.json"))
              == state.review, "qualified review source changed after binding")
    return value


def _native_selection(native: dict[str, Any]) -> dict[str, Any]:
    _need(type(native) is dict, "native selection must be an explicit mapping")
    selected = native.copy()
    _need(set(selected) == {"host", "policy", "report", "expected_target"},
          "native selection has missing or unsupported fields")
    for field_name in ("report", "expected_target"):
        selected[field_name] = json.loads(original.validation._snapshot(selected[field_name]))
    return selected


def _hold_native(state: _State, native: dict[str, Any]) -> None:
    declared = original._declared(native["policy"])
    _need(native["host"] is declared.host
          and original.validation._host(declared.host) == declared.roots,
          "native ownership requires the original declared host and roots")
    _need(original._read(state.contract)["root"] == declared.roots[2][0],
          "native worker must be the already owned candidate root")
    for path, _binding in sorted(declared.roots[:2]):
        _need(Path(path).resolve() == Path(path), "native ownership roots must remain canonical")
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        state.resources.callback(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state.native_roots += ((path, descriptor, _identity(os.fstat(descriptor))),)
    _guard(state)


def _native_join(state: _State, result: Any, selected: dict[str, Any]) -> None:
    produced = original._observed(result).native
    _need(produced is not None and produced.policy is selected["policy"],
          "issued native observation must use the captured policy")
    declared = original._declared(produced.policy)
    _need(declared.host is selected["host"]
          and tuple(path for path, _descriptor, _identity in state.native_roots)
          == tuple(path for path, _binding in sorted(declared.roots[:2]))
          and produced.report == original.validation._snapshot(selected["report"])
          and produced.target == original.validation._snapshot(selected["expected_target"]),
          "issued native observation must match the captured host, data and held ownership")


def _bd(state: _State, args: list[str]) -> str:
    # Fixed original adapter boundary. There is no caller-selected callback or route.
    if type(state.bridge) is _ProductionBeadsBridge:
        _need(PRODUCTION_CLOSURE_AVAILABLE is True,
              "production closure is unavailable pending the production closure restoration decision")
        _need(not state.retired and type(state.bridge).__call__ is _PRODUCTION_CALL
              and state.bridge.call is _BEADS_CALL,
              "the captured original production Beads adapter is required")
        _production_guard(state)
        return state.bridge(args)
    bridge = closure.run_bd
    _need(not state.retired, "the EXAMPLE host registration has expired")
    _need(bridge is state.bridge
          and type(state.bridge) is ExampleBeadsBridge
          and type(state.bridge).__call__ is _EXAMPLE_CALL,
          "live Beads effects are disabled; the EXAMPLE effect bridge is required")
    return bridge(["--db", str(state.custody / "EXAMPLE.db"),
                   "--actor", "EXAMPLE-qualified-closure", *args])


def _production_projection(result: dict[str, Any], expected: dict[str, Any], state: _State) -> dict[str, Any]:
    """Account only for Beads-generated metadata of our own comment/close effects."""
    current = original._read(original._freeze(result))
    if state.report["comment_posted"]:
        comments = current.get("comments", [])
        _need(len(comments) == len(expected["comments"]) and bool(comments),
              "the exact original comments and one closure summary are required")
        added = comments[-1]
        _need(type(added) is dict and added.get("text") == state.report["summary"]
              and set(added) <= {"text", "id", "issue_id", "author", "created_at"}
              and added.get("author") == state.bridge.actor
              and added.get("issue_id", expected["id"]) == expected["id"],
              "the posted summary must belong to the registered actor")
        comments[-1] = {"text": added["text"]}
        _generated_task_metadata(current, expected)
    if expected["status"] == "closed":
        _need(current.get("close_reason", "Bound delivery accepted") == "Bound delivery accepted",
              "the exact closure reason is required")
        for name in ("closed_at", "close_reason"):
            if name in expected:
                current[name] = expected[name]
            else:
                current.pop(name, None)
    return current


def _generated_task_metadata(current: dict[str, Any], expected: dict[str, Any]) -> None:
    # bd show's count/revision are generated projections, not contract content.
    # Before our first write _task still requires exact equality, including these.
    if "comment_count" in expected:
        _need(current.get("comment_count") == len(current["comments"]),
              "the Beads comment count must match the complete observed comments")
    for name in ("updated_at", "revision", "comment_count"):
        if name in expected:
            _need(name in current and type(current[name]) is type(expected[name]),
                  "Beads generated metadata must retain its original shape")
            current[name] = expected[name]


def _task(state: _State, expected: dict[str, Any]) -> None:
    raw = _bd(state, ["show", "--json", "--include-comments", "--", expected["id"]]).encode()
    _need(len(raw) <= MAX_CONTROL, "task projection exceeds the control bound")
    result = original._read(b'{"projection":' + raw + b'}')["projection"]
    if type(result) is list:
        _need(len(result) == 1, "exactly one authoritative task is required")
        result = result[0]
    if type(state.bridge) is _ProductionBeadsBridge:
        _need(type(result) is dict, "an authoritative task mapping is required")
        result = _production_projection(result, expected, state)
    _need(original._freeze(result) == original._freeze(expected),
          "authoritative task projection changed or belongs to another task")


def observe(host: Host, *, native: dict[str, Any] | None = None) -> Any:
    """Run the original result producer against the custodied independent contract."""
    with _operation(host) as state:
        _need(state.observation is None, "result production is single use")
        value = _guard(state)
        _task(state, value["bead"])
        arguments = {key: value[key] for key in ("root", "initial", "candidate", "bead", "commands", "amendments")}
        if native is None:
            chain = original.rb.resolve_chain(value["initial"], value["amendments"])
            mixed = any(item["evidence_kind"] == "artifact" and item["applicability"] == "required"
                        for item in chain["baseline"]["criteria"])
            result = (original.observe_mixed if mixed else original.observe)(**arguments)
        else:
            selected = _native_selection(native)
            _hold_native(state, selected)
            result = original.observe_native_mixed(**arguments, **selected)
            _native_join(state, result, selected)
        original._current(original._observed(result))
        _guard(state)
        _task(state, value["bead"])
        state.observation = result
        return result


def bind(host: Host) -> None:
    """Bind EXAMPLE review files or the production host acceptance decision."""
    with _operation(host) as state:
        value = _guard(state)
        _need(state.observation is not None and state.bound is None, "one original observation and no prior binding are required")
        if type(state.bridge) is _ProductionBeadsBridge:
            original._current(original._observed(state.observation))
            state.bound = state.authority
            _guard(state)
            _task(state, value["bead"])
            return
        state.review = (_read_at(state.descriptor, "review.json"), _read_at(state.descriptor, "expectation.json"))
        envelope = original._read(state.review[1])
        kind = "cwo-EXAMPLE-qualified-review-source"
        original.combined._shape(envelope, kind, ("context", "expected"))
        _need(envelope["context"] == host.review_context,
              "final review source must bind this fresh registration, database and task")
        state.bound = original.bind_review(state.observation, state.review[0], envelope["expected"])
        _guard(state)
        _task(state, value["bead"])


def _validate(state: _State, expected: dict[str, Any]) -> dict[str, Any]:
    value = _guard(state)
    _need(state.bound is not None, "a qualified final review binding is required")
    if type(state.bridge) is _ProductionBeadsBridge:
        _need(state.bound is state.authority, "the registered host acceptance binding is required")
        observed = original._observed(state.observation)
        original._current(observed)
        context = original._read(observed.context)
    else:
        context = original._consume(original._bound(state.bound))
    _need(context == state.observation.context, "the original bound observation context changed")
    original._candidate(context, expected)
    _task(state, expected)
    _guard(state)
    original._candidate(context, expected)
    _task(state, expected)
    _guard(state)
    return value


def _summary(state: _State) -> str:
    if type(state.bridge) is _ProductionBeadsBridge:
        return _production_summary(state)
    context = state.observation.context
    return ("Qualified EXAMPLE closure summary:\n"
            "Scope: EXAMPLE-only; no live issuer, production acceptance or dispatch authority.\n"
            "Bead: " + context["bead"]["id"] + "\n"
            "Baseline: " + original.rb.resolve_chain(context["baseline"], context["amendments"])["digest"] + "\n"
            "Candidate: " + original.ci.candidate_digest(context["candidate"]) + "\n"
            "Registration: " + state.registration_id + "\n"
            "Qualified review source: " + original._digest(state.review[1]) + "\n"
            "Combined final review: " + original._digest(original._freeze(state.bound.prepared)) + "\n"
            "All applicable original observations pass; final APPROVE has no unresolved blockers.\n")


def _production_summary(state: _State) -> str:
    context = state.observation.context
    return closure.render_closure_summary(
        bead=context["bead"]["id"], disposition="completed", why="Bound delivery accepted",
        who_involved=[state.bridge.actor], what_changed=["The registered candidate satisfies its recorded contract."],
        how_validated=["Original observations pass; the verified autonomous acceptance clears every required hold."],
        when_closed=["Registration " + state.registration_id], where_executed=[context["root"]],
        decisions=["Complete only the selected task; public activation and parent acceptance remain held."],
        evidence=["Baseline " + original.rb.resolve_chain(context["baseline"], context["amendments"])["digest"],
                  "Candidate " + original.ci.candidate_digest(context["candidate"]),
                  "Host acceptance " + state.authority.acceptance_record,
                  "Return " + state.authority.return_sha256,
                  "Evaluation " + state.authority.evaluation_sha256,
                  "Database identity " + state.authority.database_identity.decode()],
        residual_risk=["Integrity-only host records; no hostile same-user protection."],
        follow_up=["Integration and parent acceptance remain independently adjudicated."])


def consume(host: Host, *, dry_run: bool = False) -> dict[str, Any]:
    """Revalidate under held ownership, then comment and close through the original adapter.

    Refusals and effect failures are sticky for this registration. Original
    exceptions, including interruptions, propagate with persistence facts retained
    in host.report. No replay or automatic retry is permitted.
    """
    # Inspect only process-local state before the production gate, even for bad input.
    with _registry_lock:
        registered = _registry.get(host) if type(host) is Host else None
    if registered is not None and type(registered.bridge) is _ProductionBeadsBridge:
        _need(PRODUCTION_CLOSURE_AVAILABLE is True,
              "production closure is unavailable pending the production closure restoration decision")
    _need(type(dry_run) is bool, "dry_run must be an exact Boolean")
    with _operation(host) as state:
        _need(not state.attempted, "this bound approval has already been consumed")
        value = _guard(state)
        bead = value["bead"]
        _validate(state, bead)
        summary = _summary(state)
        state.report["summary"] = summary
        if dry_run:
            validated = "VALIDATED" if type(state.bridge) is _ProductionBeadsBridge else "VALIDATED_EXAMPLE"
            state.report.update(state=validated, last_call_state=validated,
                                current_applicability="CURRENT")
            return host.report
        state.attempted = True
        _validate(state, bead)
        state.report["comment_attempted"] = True
        state.report["persistence_known"] = False
        _bd(state, ["comment", "--", bead["id"], summary])
        state.report["comment_posted"] = True
        commented = original._read(original._commented(original._freeze(bead), summary))
        _validate(state, commented)
        state.report["close_attempted"] = True
        state.report["persistence_known"] = False
        reason = ("Bound delivery accepted" if type(state.bridge) is _ProductionBeadsBridge
                  else "EXAMPLE bound delivery accepted")
        _bd(state, ["close", "--reason", reason, "--", bead["id"]])
        closed = original._read(original._closed_projection(original._freeze(commented)))
        _task(state, closed)
        # Persistence was independently read back, even if acceptance now drifts.
        state.report.update(state="CLOSED_UNCONFIRMED", closed=True, persistence_known=True,
                            completion_unconfirmed=True, partial_persistence=False)
        _guard(state)
        production = type(state.bridge) is _ProductionBeadsBridge
        if production:
            _production_guard(state)
            _authority_call(state.authority.record_closure)
            state.report["database_identity"] = json.loads(state.authority.database_identity)
            state.report["acceptance_record_sha256"] = state.authority.acceptance_record
        completed = "COMPLETED" if production else "FAKE_COMPLETED"
        state.report.update(state=completed, fake_completed=not production,
                            completion_unconfirmed=False, closed=True, persistence_known=True,
                            last_call_state=completed, current_applicability="CURRENT")
        if production:
            state.report["completed"] = True
        return host.report
