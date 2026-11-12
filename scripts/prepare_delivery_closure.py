"""Offline delivery closure with a cooperative memory target and held production authority."""
from __future__ import annotations

import contextlib
import hashlib
import json
import threading
import weakref
from dataclasses import dataclass
from typing import Any, Iterator

import offline_artifact_validation as validation
import prepare_artifact_acceptance as artifacts
import prepare_combined_review_binding as combined
import produce_validator_evidence as producer
from cwo_core import candidate_identity as ci
from cwo_core import requirement_baseline as rb

AUTHORITY_FIELDS = tuple(dict.fromkeys((
    *combined.FALSE_FIELDS, "production_available", "accepted_for_use",
    "trusted_host_authority",
)))


class ClosureError(ValueError):
    """A required offline reliability condition was refused."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ClosureError(reason)


def _freeze(value: Any) -> bytes:
    return combined._encode(value)


def _read(value: bytes) -> dict[str, Any]:
    return combined._decode(value)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class _NativePolicy:
    host: Any
    policy: validation.ValidationPolicy
    specification: bytes
    roots: tuple[Any, ...]
    initial: bytes


@dataclass(frozen=True)
class _Native:
    policy: FrozenPolicy
    token: validation.ValidatedObservation
    document: bytes
    report: bytes
    target: bytes
    validated: bytes
    outputs: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class _Observed:
    context: bytes
    production: bytes
    combined: bytes
    production_mode: str
    native: _Native | None = None


@dataclass(frozen=True)
class _Bound:
    observation: Observation
    raw: bytes
    expected: bytes
    prepared: bytes


_states_lock = threading.RLock()
_observations: weakref.WeakKeyDictionary[Observation, _Observed] = weakref.WeakKeyDictionary()
_bindings: weakref.WeakKeyDictionary[BoundReview, _Bound] = weakref.WeakKeyDictionary()
_policies: weakref.WeakKeyDictionary[FrozenPolicy, _NativePolicy] = weakref.WeakKeyDictionary()


def _observed(value: Any) -> _Observed:
    with _states_lock:
        _need(type(value) is Observation and value in _observations,
              "an issued immutable observation is required for reliable closure")
        return _observations[value]


def _bound(value: Any) -> _Bound:
    with _states_lock:
        _need(type(value) is BoundReview and value in _bindings,
              "an issued immutable review binding is required for reliable closure")
        return _bindings[value]


class FrozenPolicy:
    """An issued immutable reliability declaration made before original native execution."""

    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise ClosureError("native reliability policies must be issued by freeze_native_policy")

    @property
    def report(self) -> dict[str, Any]:
        return json.loads(_declared(self).specification)

    def __reduce_ex__(self, protocol):
        raise ClosureError("native reliability policy identities cannot be copied or serialized")


def _declared(value: Any) -> _NativePolicy:
    with _states_lock:
        _need(type(value) is FrozenPolicy and value in _policies,
              "an original issued native reliability policy is required")
        return _policies[value]


@contextlib.contextmanager
def _native_errors() -> Iterator[None]:
    try:
        yield
    except ClosureError:
        raise
    except (Exception, SystemExit) as exc:
        arguments = BaseException.args.__get__(exc)
        message = arguments[0] if arguments and type(arguments[0]) is str else type(exc).__name__
        raise ClosureError(message) from exc


def freeze_native_policy(host: Any, specification: Any) -> FrozenPolicy:
    """Declare independent reliability expectations before the original host invocation."""
    with _native_errors():
        policy = validation.freeze_policy(specification)
        roots = validation._host(host)
        initial = validation._snapshot(host._initial)
        with host._locked(create=True):
            _need(host._load() is None,
                  "native reliability expectations must precede the original invocation")
            _need(validation._snapshot(host._observe()) == initial,
                  "original reliability host roots and repository bindings must remain unchanged")
            state = object.__new__(FrozenPolicy)
            with _states_lock:
                _policies[state] = _NativePolicy(
                    host, policy, validation._snapshot(policy.report), roots, initial)
            return state


class Observation:
    """An issued observation whose reliability records are returned as private copies."""

    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise ClosureError("reliability observations must be issued by observe or observe_mixed")

    @property
    def production_mode(self) -> str:
        return _observed(self).production_mode

    @property
    def context(self) -> dict[str, Any]:
        return _read(_observed(self).context)

    @property
    def production(self) -> dict[str, Any]:
        return _read(_observed(self).production)

    @property
    def combined(self) -> dict[str, Any]:
        return _read(_observed(self).combined)

    @property
    def report(self) -> dict[str, Any]:
        return {"record_type": "cwo-offline-delivery-observation", "version": 1,
                **dict.fromkeys(AUTHORITY_FIELDS, False),
                "production_mode": self.production_mode,
                "production": self.production, "combined": self.combined}


class BoundReview:
    """An issued immutable review binding for one complete reliability observation."""

    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise ClosureError("reliability review bindings must be issued by bind_review")

    @property
    def observation(self) -> Observation:
        return _bound(self).observation

    @property
    def prepared(self) -> dict[str, Any]:
        return _read(_bound(self).prepared)

    @property
    def report(self) -> dict[str, Any]:
        return {"record_type": "cwo-offline-delivery-review-binding", "version": 1,
                **dict.fromkeys(AUTHORITY_FIELDS, False),
                "prepared": self.prepared}


def _observation_input(root: str, initial: Any, candidate: Any, bead: Any, commands: Any,
                       amendments: Any) -> dict[str, Any]:
    _need(type(amendments) in (list, tuple), "reliability amendments must be an ordered list or tuple")
    return _read(_freeze({
        "root": root, "baseline": initial, "candidate": candidate, "bead": bead,
        "commands": commands, "amendments": list(amendments),
    }))


def _issue(document: dict[str, Any], result: dict[str, Any], mode: str,
           native: _Native | None = None) -> Observation:
    production = _freeze(result)
    context = _freeze({
        "record_type": combined.INPUT_TYPE, "version": 1,
        "root": document["root"], "baseline": document["baseline"],
        "amendments": document["amendments"], "candidate": document["candidate"],
        "bead": document["bead"], "validator_evidence": _read(production)["validator_evidence"],
    })
    observed = _freeze(combined.observe(_read(context)))
    state = object.__new__(Observation)
    with _states_lock:
        _observations[state] = _Observed(context, production, observed, mode, native)
    return state


def observe(root: str, initial: Any, candidate: Any, bead: Any, commands: Any, *,
            amendments: list[Any] | tuple[Any, ...] = ()) -> Observation:
    """Produce actual validator evidence and observe the complete original reliability context."""
    document = _observation_input(root, initial, candidate, bead, commands, amendments)
    result = producer.produce(
        document["root"], document["baseline"], document["candidate"], document["bead"],
        document["commands"], amendments=document["amendments"])
    return _issue(document, result, "validator-only")


def observe_mixed(root: str, initial: Any, candidate: Any, bead: Any, commands: Any, *,
                  amendments: list[Any] | tuple[Any, ...] = ()) -> Observation:
    """Observe actual artifact and validator reliability evidence without changing original requirements."""
    document = _observation_input(root, initial, candidate, bead, commands, amendments)
    result = producer.produce_mixed(
        document["root"], document["baseline"], document["candidate"], document["bead"],
        document["commands"], amendments=document["amendments"])
    return _issue(document, result, "mixed")


def _native_predicates(document: dict[str, Any], entries: dict[str, Any]) -> None:
    chain = rb.resolve_chain(document["baseline"], document["amendments"])
    required = [item for item in chain["baseline"]["criteria"] if item["applicability"] == "required"]
    _need(all(item["evidence_kind"] in ("artifact", "validator") for item in required),
          "unsupported native reliability evidence kind remains UNASSESSABLE")
    _need(any(item["evidence_kind"] == "validator" for item in required),
          "native mixed reliability requires an original required validator criterion")
    paths = set()
    for item in required:
        if item["evidence_kind"] == "artifact":
            predicate = artifacts._predicate(item, document["candidate"])
            path = predicate["path"]
            _need(predicate["op"] == "regular-file-sha256" and path in entries
                  and predicate["sha256"] == entries[path]["sha256"],
                  "each original artifact reliability predicate must check its independently expected output")
            paths.add(path)
    _need(paths == set(entries),
          "every declared native reliability output needs an original required artifact criterion")


def _native_binding(declared: _NativePolicy, report: dict[str, Any]) -> None:
    """Compare complete recorded reliability bindings with the original declaration."""
    for name, original in json.loads(declared.initial).items():
        _need(validation._snapshot(report["binding"][name]) == validation._snapshot(original),
              "native reliability report repository and target bindings must match "
              "the complete original declaration")


def _native_joins(document: dict[str, Any], declared: _NativePolicy,
                  report: dict[str, Any], outputs: tuple[tuple[str, bytes], ...]) -> None:
    binding = report["binding"]
    candidate = document["candidate"]
    _need(document["root"] == str(declared.host.worker) == binding["worker_identity"]["path"]
          and candidate["commit"] == binding["worker_identity"]["head_commit"],
          "native reliability evidence must join the exact original worker repository and root")
    entries = {entry["path"]: entry for entry in json.loads(declared.specification)["outputs"]}
    _need([path for path, _data in outputs] == list(entries) == binding["outputs"],
          "native reliability names must exactly cover the independently declared outputs")
    for path, data in outputs:
        _need(type(data) is bytes and len(data) == entries[path]["size"]
              and hashlib.sha256(data).hexdigest() == entries[path]["sha256"],
              "native reliability bytes must match every independent output expectation")
    _native_predicates(document, entries)
    _candidate(document, document["bead"])


def _native_record(native: _Native, declared: _NativePolicy) -> None:
    checked = native.token.report
    _need(validation._encode(checked) == native.validated
          and checked["offline_validation_complete"] is True and not checked["errors"],
          "the complete original native reliability validation must remain unchanged")
    _need(validation._snapshot(checked["host_report"]) == native.report
          and validation._snapshot(checked["expected_target"]) == native.target
          and validation._snapshot(checked["policy"]) == declared.specification,
          "native reliability validation must retain the full original report, receipt, target and policy")
    _need(validation._host(declared.host) == declared.roots
          and validation._snapshot(declared.policy.report) == declared.specification
          and validation._snapshot(declared.host._initial) == declared.initial
          and validation._snapshot(declared.host._observe()) == declared.initial,
          "original native reliability host identities, repository bindings and target must remain current")


def _native_integrity(native: _Native) -> None:
    declared = _declared(native.policy)
    report, target = json.loads(native.report), json.loads(native.target)
    _native_binding(declared, report)
    outputs = validation.consume_validated(
        declared.host, native.token, report, target, declared.policy)
    _need(outputs == native.outputs,
          "native reliability consumption must retain the exact original returned names and bytes")
    _native_record(native, declared)
    _native_joins(_read(native.document), declared, report, outputs)


def observe_native_mixed(root: str, initial: Any, candidate: Any, bead: Any, commands: Any, *,
                         host: Any, report: Any, expected_target: Any, policy: FrozenPolicy,
                         amendments: list[Any] | tuple[Any, ...] = ()) -> Observation:
    """Join original native reliability bytes to actual mixed production and complete observations."""
    document = _observation_input(root, initial, candidate, bead, commands, amendments)
    with _native_errors():
        declared = _declared(policy)
        _need(host is declared.host, "native reliability production requires the originally declared host")
        original, target = validation._snapshot(report), validation._snapshot(expected_target)
        _native_binding(declared, json.loads(original))
        token = validation.validate_artifact(
            host, json.loads(original), json.loads(target), declared.policy)
        outputs = validation.consume_validated(
            host, token, json.loads(original), json.loads(target), declared.policy)
        native = _Native(policy, token, _freeze(document), original, target,
                         validation._encode(token.report), outputs)
        _native_integrity(native)
        result = producer.produce_mixed(
            document["root"], document["baseline"], document["candidate"], document["bead"],
            document["commands"], amendments=document["amendments"])
        observation = _issue(document, result, "mixed", native)
        _native_integrity(native)
        return observation


def _check_native(data: _Observed) -> None:
    if data.native is not None:
        with _native_errors():
            _native_integrity(data.native)


def _native_parts(native: _Native) -> tuple[bytes, ...]:
    declared = _declared(native.policy)
    return (
        native.document, native.report, native.target, native.validated,
        declared.specification, declared.initial,
        str(id(declared.host)).encode("ascii"), str(id(native.policy)).encode("ascii"),
        str(id(native.token)).encode("ascii"),
        *(part for path, data in native.outputs for part in (path.encode("utf-8"), data)),
    )


def _production_complete(data: _Observed, produced: dict[str, Any]) -> bool:
    modes = {
        "validator-only": ("cwo-validator-evidence-production", "observations_complete"),
        "mixed": ("cwo-mixed-evidence-production", "validator_observations_complete"),
    }
    _need(data.production_mode in modes, "the issued reliability production mode is unsupported")
    kind, field = modes[data.production_mode]
    _need(produced["record_type"] == kind
          and produced.get("production_mode", "validator-only") == data.production_mode,
          "production evidence must match the immutable issued reliability mode")
    return produced[field] is True


def _complete(data: _Observed) -> None:
    produced, observed = _read(data.production), _read(data.combined)
    _need(_production_complete(data, produced) and not produced["errors"],
          "all independently required validator observations must pass")
    _need(observed["combined_observations_complete"] is True and not observed["errors"],
          "the original complete combined observation is required")
    _need(observed["snapshot"] is not None
          and _freeze(observed["snapshot"]["input_context"]) == data.context,
          "the complete observation must retain the original closure context")


def _current(data: _Observed) -> None:
    _check_native(data)
    _complete(data)
    if data.production_mode == "mixed":
        current = _freeze(combined.observe(_read(data.context)))
        _need(current == data.combined,
              "the same original combined reliability observation must remain current")
    _check_native(data)


def _approved(report: dict[str, Any]) -> None:
    _need(report["binding_consistent"] is True and not report["errors"]
          and report["combined_observations_complete"] is True
          and report["review_verdict"] == "APPROVE"
          and report["unresolved_blocking_finding_ids"] == [],
          "current complete observations and a bound final APPROVE without blockers are required")


def bind_review(observation: Observation, raw: bytes, expected: Any) -> BoundReview:
    """Bind exact final review bytes to the original complete reliability observation."""
    data = _observed(observation)
    _current(data)
    _need(type(raw) is bytes, "reliable review binding requires immutable raw bytes")
    expectation = _freeze(expected)
    prepared = _freeze(combined.prepare(_read(data.context), raw, _read(expectation)))
    report = _read(prepared)
    _approved(report)
    _need(_freeze(report["snapshot"]) == _freeze(_read(data.combined)["snapshot"]),
          "final review must bind the exact original complete observation")
    _current(data)
    state = object.__new__(BoundReview)
    with _states_lock:
        _bindings[state] = _Bound(observation, raw, expectation, prepared)
    return state


def _consume(data: _Bound) -> dict[str, Any]:
    observed = _observed(data.observation)
    _current(observed)
    current = combined.consume(
        _read(data.prepared), _read(observed.context), data.raw, _read(data.expected))
    _approved(current)
    _need(_freeze(current) == data.prepared, "the same complete bound state must remain current")
    _current(observed)
    return _read(observed.context)


def _candidate(context: dict[str, Any], bead: dict[str, Any]) -> None:
    chain = rb.resolve_chain(context["baseline"], context["amendments"])
    checked = ci.check_candidate(
        context["candidate"], root=context["root"], chain=chain, bead=bead)
    _need(checked["valid"] is True and checked["errors"] == [],
          "current candidate, dirty content and task references must remain consistent")


def _commented(projection: bytes, summary: str) -> bytes:
    bead = _read(projection)
    bead["comments"].append({"text": summary})
    return _freeze(bead)


def _closed_projection(projection: bytes) -> bytes:
    bead = _read(projection)
    bead["status"] = "closed"
    return _freeze(bead)


@dataclass(frozen=True)
class _Operation:
    fingerprint: str
    report: bytes
    revision: int
    projection: bytes
    closed: bool


class MemoryClosureTarget:
    """A cooperative memory fake with local exclusion and revision checks only."""

    def __init__(self, bead: Any) -> None:
        projection = _freeze(bead)
        value = _read(projection)
        _need(type(value.get("id")) is str and type(value.get("comments")) is list,
              "a memory task needs its original identity and comment list")
        _need(value.get("status", "open") != "closed", "a memory task must start open")
        self._lock = threading.RLock()
        self._active = False
        self._projection = projection
        self._revision = 0
        self._closed = False
        self._comment_writes = 0
        self._close_writes = 0
        self._operations: dict[str, _Operation] = {}

    def snapshot(self) -> dict[str, Any]:
        """Return a private copy of the memory task and its reliability counters."""
        with self._lock:
            return {"bead": _read(self._projection), "revision": self._revision,
                    "closed": self._closed, "comment_writes": self._comment_writes,
                    "close_writes": self._close_writes, **dict.fromkeys(AUTHORITY_FIELDS, False)}

    def compare_and_swap(self, expected_revision: int, bead: Any) -> int:
        """Simulate a cooperative task edit using a reliable memory revision check."""
        projection = _freeze(bead)
        with self._lock:
            self._match(expected_revision, self._projection)
            _need(_read(projection).get("status", "open") != "closed" or self._closed,
                  "only the checked closure operation may close a memory task")
            self._projection = projection
            self._revision += 1
            return self._revision

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._lock:
            _need(not self._active, "a memory closure operation is already active")
            self._active = True
            try:
                yield
            finally:
                self._active = False

    def _match(self, revision: int, projection: bytes) -> None:
        _need(type(revision) is int and self._revision == revision
              and self._projection == projection, "memory task projection or revision changed")

    def _append_comment(self, revision: int, projection: bytes, summary: str) -> None:
        self._match(revision, projection)
        _need(not self._closed, "the memory task is already closed")
        update = _commented(projection, summary)
        self._projection = update
        self._revision += 1
        self._comment_writes += 1

    def _mark_closed(self, revision: int, projection: bytes) -> None:
        self._match(revision, projection)
        _need(not self._closed, "the memory task is already closed")
        update = _closed_projection(projection)
        self._projection = update
        self._revision += 1
        self._closed = True
        self._close_writes += 1


def _fingerprint(data: _Bound, revision: int) -> str:
    _need(type(revision) is int and revision >= 0, "the expected memory revision must be a nonnegative integer")
    observed = _observed(data.observation)
    parts = (observed.context, observed.production, observed.combined,
             data.raw, data.expected, data.prepared, observed.production_mode.encode("ascii"),
             str(revision).encode("ascii"))
    if observed.native is not None:
        parts += _native_parts(observed.native)
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


def _summary(data: _Bound, operation: str, revision: int) -> str:
    observed = _observed(data.observation)
    context, production = _read(observed.context), _read(observed.production)
    snapshot = _read(data.prepared)["snapshot"]
    lines = [
        "Offline memory closure summary:",
        "This summary records checked offline evidence for a memory task.",
        "Production closure and all external effects remain unavailable.",
        "Reliability production mode: " + observed.production_mode,
        "Operation digest: " + operation,
        "Original memory revision: " + str(revision),
        "Baseline digest: " + snapshot["resolved_baseline"]["digest"],
        "Candidate digest: " + ci.candidate_digest(context["candidate"]),
        "Original task projection digest: " + rb.record_digest(context["bead"]),
        "Complete context digest: " + _digest(observed.context),
        "Producer report digest: " + _digest(observed.production),
        "Combined review binding digest: " + _digest(data.prepared),
        "Raw final review digest: " + _digest(data.raw),
        "Final review verdict: APPROVE; unresolved blocking findings: 0.",
    ]
    for wrapper in production["validator_evidence"]:
        lines.append("Checked criterion " + wrapper["criterion_id"] + ": " + rb.record_digest(wrapper))
    return "\n".join(lines) + "\n"


def _report() -> dict[str, Any]:
    return {
        "record_type": "cwo-offline-delivery-closure", "version": 1,
        **dict.fromkeys(AUTHORITY_FIELDS, False),
        "state": "REFUSED", "fake_completed": False, "completion_unconfirmed": True,
        "current_applicability": "REFUSED", "persistence_known": False,
        "operation_id_digest": None, "operation_binding_digest": None,
        "operation_expected_revision": None, "operation_target_revision": None,
        "comment_posted": False, "closed": False, "partial_persistence": False,
        "comment_writes": 0, "close_writes": 0, "target_revision": None,
        "new_comment_writes": 0, "new_close_writes": 0,
        "summary": None, "errors": [],
    }


def _failure(result: dict[str, Any], error: BaseException) -> dict[str, Any]:
    message = type(error).__name__ + ": " + str(error)
    result["errors"] = [message.encode("utf-8", errors="replace").decode("utf-8")[:512]]
    return result


def _persist(data: _Bound, target: MemoryClosureTarget, revision: int,
             projection: bytes, summary: str) -> None:
    expected = _commented(projection, summary)
    _current(_observed(data.observation))
    target._match(revision, projection)
    target._append_comment(revision, projection, summary)
    target._match(revision + 1, expected)
    context = _consume(data)
    _candidate(context, _read(target._projection))
    _current(_observed(data.observation))
    target._match(revision + 1, expected)
    target._mark_closed(revision + 1, expected)
    target._match(revision + 2, _closed_projection(expected))
    _need(target._closed, "memory closure completion is unconfirmed")


def _attempt(data: _Bound, target: MemoryClosureTarget, operation: str, revision: int) -> dict[str, Any]:
    result = _report()
    comments, closes = target._comment_writes, target._close_writes
    try:
        context = _consume(data)
        projection = _freeze(context["bead"])
        target._match(revision, projection)
        _need(not target._closed, "the memory task is already closed")
        _candidate(context, _read(target._projection))
        target._match(revision, projection)
        result["summary"] = _summary(data, operation, revision)
        _persist(data, target, revision, projection, result["summary"])
        result.update(state="FAKE_COMPLETED", fake_completed=True,
                      completion_unconfirmed=False, closed=True, current_applicability="CURRENT")
    except (Exception, SystemExit) as exc:
        _failure(result, exc)
    result["comment_writes"] = target._comment_writes - comments
    result["close_writes"] = target._close_writes - closes
    result["new_comment_writes"] = result["comment_writes"]
    result["new_close_writes"] = result["close_writes"]
    result["comment_posted"] = result["comment_writes"] > 0
    result["partial_persistence"] = result["comment_posted"] and not result["fake_completed"]
    if result["partial_persistence"]:
        result["state"] = "PARTIAL_PERSISTENCE"
    result["target_revision"] = target._revision
    return result


def _replay_checks(saved: _Operation, bound: BoundReview, target: MemoryClosureTarget,
                   revision: int) -> None:
    data = _bound(bound)
    fingerprint = _fingerprint(data, revision)
    _need(saved.fingerprint == fingerprint, "the operation ID was reused with changed bound inputs")
    target._match(saved.revision, saved.projection)
    _need(target._closed is saved.closed, "the memory task close state changed")
    context = _consume(data)
    _candidate(context, _read(target._projection))
    target._match(saved.revision, saved.projection)
    _need(target._closed is saved.closed, "the memory task close state changed")


def _replay(saved: _Operation, bound: BoundReview, target: MemoryClosureTarget,
            revision: int) -> dict[str, Any]:
    result = _read(saved.report)
    result.update(new_comment_writes=0, new_close_writes=0)
    try:
        _replay_checks(saved, bound, target, revision)
    except (Exception, SystemExit) as exc:
        result.update(state="REFUSED", fake_completed=False, completion_unconfirmed=True,
                      current_applicability="REFUSED")
        _failure(result, exc)
    result["target_revision"] = target._revision
    return result


def _close_exclusive(bound: BoundReview, target: MemoryClosureTarget, operation_id: str,
                     revision: int) -> dict[str, Any]:
    saved = target._operations.get(operation_id)
    if saved is not None:
        return _replay(saved, bound, target, revision)
    data = _bound(bound)
    fingerprint = _fingerprint(data, revision)
    result = _attempt(data, target, fingerprint, revision)
    result.update(persistence_known=True,
                  operation_id_digest=_digest(operation_id.encode("utf-8")),
                  operation_binding_digest=fingerprint, operation_expected_revision=revision,
                  operation_target_revision=target._revision)
    target._operations[operation_id] = _Operation(
        fingerprint, _freeze(result), target._revision, target._projection, target._closed)
    return result


def close_offline(bound: BoundReview, target: MemoryClosureTarget, *, operation_id: str,
                  expected_revision: int) -> dict[str, Any]:
    """Consume the same current reliability binding before closing only the explicit memory fake."""
    result = _report()
    try:
        _need(type(target) is MemoryClosureTarget, "only the explicit memory closure fake is supported")
        combined._text(operation_id, 64)
        with target._exclusive():
            return _close_exclusive(bound, target, operation_id, expected_revision)
    except (Exception, SystemExit) as exc:
        return _failure(result, exc)
