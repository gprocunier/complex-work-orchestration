"""Original native artifact reliability observations with held production use."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FunctionType

import offline_artifact_validation as validation
import offline_n1_host as host_source
import prepare_hold_clearance as clearance
from cwo_core import adjudication, adjudication_binding as binding
from cwo_core import adjudication_source as source
from cwo_core import returns

_FALSE = {"effect_authority": False, "production_ready": False,
          "accepted_for_use": False, "trusted_host_authority": False}
_CONTEXT_FIELDS = ("task", "scope", "candidate", "dispatch_id", "packet_sha256", "executor")
_POLICY_NAMES = binding.POLICIES
_MODULES = (host_source, validation, binding, source, clearance,
            binding.policy, adjudication, returns)
_FUNCTIONS = tuple((module, name, value) for module in _MODULES
                   for name, value in vars(module).items() if type(value) is FunctionType)
_CLASS_NAMES = (
    (host_source, "OfflineN1Host"), (validation, "ValidationPolicy"),
    (validation, "ValidatedObservation"), (binding, "ExpectedContext"),
    (binding, "EvaluationObservation"), (binding, "SupportObservation"),
    (binding, "PreparedAdjudication"), (source, "SourceObservation"),
    (source, "SourceReceipt"), (clearance, "PreparedAffectedUse"),
)
_CLASSES = tuple((module, name, getattr(module, name)) for module, name in _CLASS_NAMES)
_PROPERTIES = tuple((kind, name, value) for _module, _name, kind in _CLASSES
                    for name, value in vars(kind).items() if type(value) is property)
_lock = threading.RLock()
_declarations = weakref.WeakKeyDictionary()
_observations = weakref.WeakKeyDictionary()
_preparations = weakref.WeakKeyDictionary()


class NativeError(ValueError):
    """An explicit native reliability refusal, with known evidence when available."""


def _need(condition, message):
    if not condition:
        raise NativeError(message)


def _originals():
    _need(all(getattr(module, name, None) is value for module, name, value in _FUNCTIONS),
          "Original reliability producer, evaluator and consumer functions are required.")
    _need(all(getattr(module, name, None) is value for module, name, value in _CLASSES),
          "Original reliability record and token types are required.")
    _need(all(vars(kind).get(name) is value for kind, name, value in _PROPERTIES),
          "Original reliability record properties are required.")
    _need(binding.POLICIES is _POLICY_NAMES,
          "The original applicable reliability policy collection is required.")


def _snapshot(value, limit=host_source.MAX_RECORD_BYTES):
    return validation._snapshot(value, limit)


def _context(expected):
    _need(type(expected) is binding.ExpectedContext,
          "An independent exact reliability context is required.")
    values = {name: getattr(expected, name) for name in _CONTEXT_FIELDS}
    _need(all(type(value) is str and len(value) <= 4096 and value.strip()
              for value in values.values()), "Reliability context text must be bounded.")
    _need(len(values["packet_sha256"]) == 64
          and all(char in "0123456789abcdef" for char in values["packet_sha256"]),
          "The reliability packet digest must retain its exact supported form.")
    return _snapshot(values, validation.MAX_POLICY_BYTES)


def _root(path):
    _need(type(path) is type(Path()), "A canonical reliability root Path is required.")
    selected = host_source._path(path)
    return str(selected), tuple(host_source._identity(selected))


def _policy_files(root):
    files, total = [], 0
    for name in _POLICY_NAMES:
        raw = host_source._read(root, name + ".yaml", host_source.MAX_FILE_BYTES)
        total += len(raw)
        _need(total <= host_source.MAX_RECORD_BYTES, "Reliability policy bytes exceed the bound.")
        files.append((name, raw))
    return tuple(files)


def _policies():
    root = binding.policy.POLICY_DIR
    identity = _root(root)
    files = _policy_files(root)
    raw = binding._policies()
    _need(type(raw) is bytes and len(raw) <= host_source.MAX_RECORD_BYTES,
          "The applicable reliability policy snapshot exceeds the bound.")
    _need(_root(root) == identity and _policy_files(root) == files,
          "Applicable reliability policies changed during their observation.")
    return identity, files, raw


@dataclass(frozen=True)
class _Declaration:
    host: object
    policy: validation.ValidationPolicy
    expected: binding.ExpectedContext
    root: Path
    roots: tuple
    initial: bytes
    state_identity: bytes
    specification: bytes
    context: bytes
    policies: tuple
    root_identity: tuple
    dispatch_path: str
    dispatch_bytes: bytes
    return_path: str


@dataclass(frozen=True)
class _Observed:
    declaration: NativeDeclaration
    token: validation.ValidatedObservation
    report: bytes
    target: bytes
    validated: bytes
    outputs: tuple
    source: source.SourceObservation
    source_key: tuple


@dataclass(frozen=True)
class _Prepared:
    observation: NativeObservation
    record: bytes
    support: tuple
    support_key: tuple
    receipt: source.SourceReceipt
    receipt_key: tuple


def _issued(registry, kind, token):
    with _lock:
        _need(type(token) is kind and token in registry,
              "An original same process reliability token is required.")
        return registry[token]


def _issue(registry, kind, data):
    token = object.__new__(kind)
    with _lock:
        registry[token] = data
    return token


class _Token:
    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise NativeError("Reliability tokens must be issued by the native adapter.")

    def __reduce_ex__(self, protocol):
        raise NativeError("Reliability tokens cannot be copied or serialized.")


class NativeDeclaration(_Token):
    """An independent cooperative reliability declaration made before invocation."""
    __slots__ = ()

    @property
    def report(self):
        data = _issued(_declarations, NativeDeclaration, self)
        return {"policy": json.loads(data.specification), "context": json.loads(data.context),
                "root": str(data.root), "dispatch_path": data.dispatch_path,
                "return_path": data.return_path, **_FALSE, "implementation_blocked": True}


class NativeObservation(_Token):
    """A private native reliability binding to the original immutable source record."""
    __slots__ = ()

    @property
    def source(self):
        return _issued(_observations, NativeObservation, self).source

    @property
    def report(self):
        data = _issued(_observations, NativeObservation, self)
        return {"host_report": json.loads(data.report), "validation": json.loads(data.validated),
                "evaluation": json.loads(data.source_key[4]),
                "provenance": json.loads(data.source_key[6]),
                **_FALSE, "implementation_blocked": True}


class NativePreparation(_Token):
    """An issued reliability preparation retaining the original adjudication receipt."""
    __slots__ = ()

    @property
    def receipt(self):
        return _issued(_preparations, NativePreparation, self).receipt

    @property
    def report(self):
        return consume_native(self)


def _diagnostic_report(facts):
    return {"native_valid": False, "offline_affected_use_ready": False, **_FALSE,
            "implementation_blocked": True,
            "host_report": json.loads(facts["host_report_bytes"]) if facts.get("host_report_bytes") else None,
            "evaluation": json.loads(facts["evaluation_bytes"]) if facts.get("evaluation_bytes") else None,
            "source_projection": json.loads(facts["source_projection_bytes"]) if facts.get("source_projection_bytes") else None,
            "callback_entered": facts.get("callback_entered", False)}


def _attach(error, facts):
    for name, value in facts.items():
        try:
            setattr(error, "native_" + name, value)
        except BaseException:
            pass
    try:
        error.native_report = _diagnostic_report(facts)
    except BaseException:
        pass


@contextmanager
def _evidence(facts):
    try:
        yield facts
    except BaseException as error:
        try:
            _attach(error, facts)
        except BaseException:
            pass
        raise


def freeze_native(host, policy, expected, root, *, dispatch_path, return_path):
    """Freeze independent reliability expectations before the original fake invocation."""
    _originals()
    _need(type(policy) is validation.ValidationPolicy, "An original reliability validation policy is required.")
    specification = _snapshot(policy.report, validation.MAX_POLICY_BYTES)
    context, root_identity = _context(expected), _root(root)
    dispatch_path, return_path = validation._relative(dispatch_path), validation._relative(return_path)
    _need(return_path in [item["path"] for item in json.loads(specification)["outputs"]],
          "The reliability return path must be an independently declared output.")
    roots = validation._host(host)
    initial, state_identity = _snapshot(host._initial), _snapshot(host._state_identity)
    policies = _policies()
    dispatch_bytes = binding.read_support(root, dispatch_path)
    with host._locked(create=True):
        _need(host._load() is None and not os.path.lexists(host.state / "artifact"),
              "The reliability declaration must precede every operation and artifact.")
        _need(_snapshot(host._observe()) == initial,
              "The complete original reliability observation must remain unchanged.")
        data = _Declaration(host, policy, expected, root, roots, initial, state_identity,
                            specification, context, policies, root_identity,
                            dispatch_path, dispatch_bytes, return_path)
    _declared_current(data)
    return _issue(_declarations, NativeDeclaration, data)


def _declared_current(data):
    _originals()
    _need(validation._host(data.host) == data.roots
          and _snapshot(data.host._state_identity) == data.state_identity
          and _snapshot(data.host._initial) == data.initial
          and _snapshot(data.host._observe()) == data.initial,
          "Original reliability host identities and the complete initial observation changed.")
    _need(_snapshot(data.policy.report, validation.MAX_POLICY_BYTES) == data.specification
          and _context(data.expected) == data.context and _policies() == data.policies,
          "Independent reliability expectations or applicable policies changed.")
    _need(_root(data.root) == data.root_identity
          and binding.read_support(data.root, data.dispatch_path) == data.dispatch_bytes,
          "The selected reliability dispatch root or exact file changed.")


def _report_binding(data, report):
    for name, original in json.loads(data.initial).items():
        _need(_snapshot(report["binding"][name]) == _snapshot(original),
              "Native reliability bindings must match the complete original declaration.")


def _output_entry(entry, item):
    _need(type(item) is tuple and len(item) == 2,
          "A declared reliability output requires an exact name and byte pair.")
    name, raw = item
    _need(type(name) is str and name == entry["path"] and type(raw) is bytes,
          "Declared reliability output names and byte types must remain exact.")
    _need(len(raw) == entry["size"] and hashlib.sha256(raw).hexdigest() == entry["sha256"],
          "Consumed reliability bytes must match their independent expectation.")


def _output_bytes(data, outputs):
    entries = json.loads(data.specification)["outputs"]
    _need(type(outputs) is tuple and len(outputs) == len(entries),
          "Every declared reliability output must be consumed.")
    for entry, item in zip(entries, outputs):
        _output_entry(entry, item)
        _need(host_source._read(data.host.worker, item[0], host_source.MAX_FILE_BYTES) == item[1],
              "The original reliability worker output changed.")
    return next(raw for name, raw in outputs if name == data.return_path)


def _native_current(observed):
    data = _issued(_declarations, NativeDeclaration, observed.declaration)
    _declared_current(data)
    report, target = json.loads(observed.report), json.loads(observed.target)
    _report_binding(data, report)
    outputs = validation.consume_validated(data.host, observed.token, report, target, data.policy)
    _need(outputs == observed.outputs, "The exact consumed reliability outputs changed.")
    checked = observed.token.report
    _need(_snapshot(checked) == observed.validated
          and checked["offline_validation_complete"] is True and checked["errors"] == [],
          "The complete original reliability validation changed.")
    _need(_snapshot(checked["host_report"]) == observed.report
          and _snapshot(checked["expected_target"]) == observed.target
          and _snapshot(checked["policy"]) == data.specification,
          "Original reliability report, target and policy bindings must remain exact.")
    raw = _output_bytes(data, outputs)
    _declared_current(data)
    return data, raw


def _source_key(value, expected):
    _need(type(value) is source.SourceObservation
          and type(value.evaluation) is binding.EvaluationObservation
          and value.context is expected, "The original immutable reliability source is required.")
    values = (value.dispatch_bytes, value.evaluation.raw_return, value.evaluation.result_bytes,
              value.evaluation.policy_bytes, value.provenance_bytes)
    _need(type(value.dispatch_path) is str and len(value.dispatch_path) <= 240 and all(type(raw) is bytes
          and len(raw) <= host_source.MAX_RECORD_BYTES for raw in values),
          "Original reliability source fields must remain bounded immutable bytes.")
    return (value.dispatch_path, values[0], _context(expected), *values[1:])


def _observed_current(observed):
    data, raw = _native_current(observed)
    _need(_source_key(observed.source, data.expected) == observed.source_key
          and observed.source.evaluation.raw_return == raw
          and observed.source.evaluation.policy_bytes == data.policies[2]
          and observed.source.dispatch_bytes == data.dispatch_bytes
          and observed.source.dispatch_path == data.dispatch_path,
          "The original reliability source, context, policy and consumed return must remain exact.")
    source._revalidate(observed.source, data.expected, data.root)
    return data


def observe_native(declaration, host, report):
    """Observe only genuine validated native reliability bytes through the original adjudication source."""
    facts = {"callback_entered": False}
    with _evidence(facts):
        data = _issued(_declarations, NativeDeclaration, declaration)
        _need(host is data.host, "The originally declared reliability host is required.")
        _originals()
        validation._host(host)
        with host._locked():
            stored = host._load()
            _need(stored is not None, "An original stored reliability operation is required.")
            original = _snapshot(stored)
        facts["host_report_bytes"] = original
        _declared_current(data)
        supplied = _snapshot(report)
        _need(supplied == original, "The supplied reliability report must be the exact stored report.")
        _report_binding(data, stored)
        target = _snapshot(json.loads(data.initial)["target"])
        token = validation.validate_artifact(host, json.loads(original), json.loads(target), data.policy)
        outputs = validation.consume_validated(host, token, json.loads(original), json.loads(target), data.policy)
        checked = _snapshot(token.report)
        pending = _Observed(declaration, token, original, target, checked, outputs, None, ())
        _data, raw = _native_current(pending)
        observed_source = source.observe_source(data.root, data.dispatch_path, raw, data.expected)
        key = _source_key(observed_source, data.expected)
        facts.update(source=observed_source, evaluation_bytes=key[4])
        observed = _Observed(declaration, token, original, target, checked, outputs, observed_source, key)
        _observed_current(observed)
        return _issue(_observations, NativeObservation, observed)


def _facts(observed):
    return {"host_report_bytes": observed.report, "source": observed.source,
            "evaluation_bytes": observed.source_key[4], "callback_entered": False}


def _support_key(values):
    _need(type(values) is tuple and len(values) <= binding.MAX_SUPPORT_FILES,
          "Reliability support requires a bounded tuple of original observations.")
    result, total = [], 0
    for item in values:
        _need(type(item) is binding.SupportObservation, "Original reliability support records are required.")
        path = validation._relative(item.artifact)
        _need(type(item.finding_id) is str and len(item.finding_id) <= clearance.MAX_FINDING_LENGTH
              and item.finding_id.strip()
              and type(item.raw) is bytes and len(item.raw) <= binding.MAX_SUPPORT_BYTES,
              "Reliability support fields must be bounded exact text and immutable bytes.")
        total += len(item.raw)
        _need(total <= host_source.MAX_ARTIFACT_BYTES, "Reliability support exceeds the total byte bound.")
        result.append((path, item.finding_id, item.raw))
    return tuple(result)


def _support_current(data, prepared):
    _need(_support_key(prepared.support) == prepared.support_key,
          "Original reliability support observations changed.")
    for path, _finding, raw in prepared.support_key:
        _need(binding.read_support(data.root, path) == raw,
              "Selected reliability support bytes changed or are missing.")


def _receipt_limits(receipt):
    _need(type(receipt) is source.SourceReceipt
          and type(receipt.prepared) is binding.PreparedAdjudication,
          "Bounded original reliability receipt records are required.")
    _need(type(receipt.binding_bytes) is bytes
          and len(receipt.binding_bytes) <= host_source.MAX_RECORD_BYTES,
          "Original reliability receipt bytes must remain bounded.")
    prepared = receipt.prepared
    _need(type(prepared.return_sha256) is str and len(prepared.return_sha256) == 64
          and all(char in "0123456789abcdef" for char in prepared.return_sha256),
          "Prepared reliability return digests require exactly 64 lowercase hexadecimal characters.")
    for name in ("errors", "resolved_findings", "remaining_holds", "adjudication_restrictions"):
        values = getattr(prepared, name)
        _need(type(values) is tuple and len(values) <= validation.MAX_NODES,
              "Prepared reliability sequences must remain bounded tuples.")
        _snapshot(list(values))
    _need(type(prepared.support_bytes) is tuple and len(prepared.support_bytes) <= binding.MAX_SUPPORT_FILES,
          "Prepared reliability support must remain a bounded tuple.")
    for raw in (*prepared.support_bytes, prepared.evaluation_bytes, prepared.policy_bytes):
        _need(type(raw) is bytes and len(raw) <= host_source.MAX_RECORD_BYTES,
              "Prepared reliability evidence must remain bounded immutable bytes.")
    _need(prepared.decision is None or (type(prepared.decision) is str
          and len(prepared.decision) <= 512), "Prepared reliability decisions must remain bounded.")


def _receipt_key(receipt, expected):
    _receipt_limits(receipt)
    key = _source_key(receipt.source, expected)
    _need(receipt.prepared.return_sha256 == receipt.source.evaluation.return_sha256,
          "Prepared reliability return digests must match the original evaluated return.")
    clearance._checked_receipt(receipt)
    _need(receipt.prepared.context is expected, "Original reliability preparation context is required.")
    _need(sum(len(raw) for raw in receipt.prepared.support_bytes) <= host_source.MAX_ARTIFACT_BYTES,
          "Prepared reliability support exceeds the byte bound.")
    computed = source._receipt_bytes(receipt.source, receipt.prepared)
    _need(computed == receipt.binding_bytes, "The original reliability source receipt binding changed.")
    return key, receipt.binding_bytes


def prepare_native(observation, record, *, observed_support=()):
    """Prepare the original reliability adjudication receipt using independently observed real support."""
    observed = _issued(_observations, NativeObservation, observation)
    facts = _facts(observed)
    with _evidence(facts):
        data = _observed_current(observed)
        validation._plain_record(record, 32)
        record_bytes, support_key = _snapshot(record, binding.MAX_SUPPORT_BYTES), _support_key(observed_support)
        support = tuple(binding.SupportObservation(*item) for item in support_key)
        receipt = source.prepare_source(observed.source, data.expected, json.loads(record_bytes),
                                        data.root, observed_support=support)
        facts.update(receipt=receipt, receipt_binding_bytes=receipt.binding_bytes)
        prepared = _Prepared(observation, record_bytes, support, support_key, receipt,
                             _receipt_key(receipt, data.expected))
        _observed_current(observed)
        _support_current(data, prepared)
        return _issue(_preparations, NativePreparation, prepared)


def _current_preparation(prepared, facts):
    observed = _issued(_observations, NativeObservation, prepared.observation)
    data = _observed_current(observed)
    _need(prepared.receipt.source is observed.source
          and _receipt_key(prepared.receipt, data.expected) == prepared.receipt_key,
          "The original immutable reliability preparation changed.")
    _support_current(data, prepared)
    current = source.prepare_source(observed.source, data.expected, json.loads(prepared.record),
                                    data.root, observed_support=prepared.support)
    _need(_receipt_key(current, data.expected) == prepared.receipt_key,
          "The current original reliability source preparation changed.")
    result = source.consume_source(prepared.receipt, data.expected, data.root)
    result_bytes = _snapshot(result)
    if result.get("source_valid") is not True or result.get("inert_valid") is not True:
        facts.setdefault("source_projection_bytes", result_bytes)
    _support_current(data, prepared)
    _observed_current(observed)
    facts.update(receipt=prepared.receipt, receipt_binding_bytes=prepared.receipt_key[1])
    return data, json.loads(result_bytes)


def _prepared_facts(prepared):
    facts = _facts(_issued(_observations, NativeObservation, prepared.observation))
    facts.update(receipt=prepared.receipt, receipt_binding_bytes=prepared.receipt_key[1])
    return facts


def consume_native(preparation):
    """Reprepare and consume original reliability state; returned dictionaries grant no use."""
    prepared = _issued(_preparations, NativePreparation, preparation)
    with _evidence(_prepared_facts(prepared)) as facts:
        _data, result = _current_preparation(prepared, facts)
        return {**result, "native_valid": True, **_FALSE, "implementation_blocked": True}


def _affected_input(values):
    _need(type(values) is list and 1 <= len(values) <= clearance.MAX_AFFECTED_FINDINGS,
          "Affected reliability findings require a bounded nonempty list.")
    _need(all(type(value) is str and len(value) <= clearance.MAX_FINDING_LENGTH and value.strip()
              for value in values), "Affected reliability IDs must be bounded exact text.")
    return list(values)


def _current_use(prepared, facts):
    data, result = _current_preparation(prepared, facts)
    _need(result.get("source_valid") is True and result.get("inert_valid") is True,
          "The current original reliability source refused offline affected use.")
    return data


def _enter_effect(prepared, ids, affected, effect, facts):
    _need(type(ids) is tuple and ids == tuple(affected),
          "Only the original scoped reliability finding IDs may reach the fake callback.")
    _current_use(prepared, facts)
    observed = _issued(_observations, NativeObservation, prepared.observation)
    _native_current(observed)
    facts["callback_entered"] = True
    return effect(ids)


def use_offline_native(preparation, *, affected_findings, effect):
    """Call original reliability evidence use with a final native check before the fake callback."""
    prepared = _issued(_preparations, NativePreparation, preparation)
    with _evidence(_prepared_facts(prepared)) as facts:
        data = _current_use(prepared, facts)
        affected = _affected_input(affected_findings)

        def guarded(ids):
            return _enter_effect(prepared, ids, affected, effect, facts)

        callback = guarded if callable(effect) else effect
        result = clearance.use_offline(prepared.receipt, data.expected, data.root,
                                       affected_findings=affected, effect=callback)
        _current_use(prepared, facts)
        return result
