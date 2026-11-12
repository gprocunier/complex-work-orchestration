"""Deterministic offline validation of immutable host bytes; no effect authority."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import weakref
from contextlib import contextmanager
from types import FunctionType

import offline_n1_host as HOST

MAX_POLICY_BYTES = 64 * 1024
MAX_TEXT_BYTES = 4096
MAX_DEPTH = 16
MAX_INPUT_DEPTH = 64
MAX_NODES = 100_000
MAX_ERROR_CHARACTERS = 1024
MAX_STAGE_ENTRIES = HOST.MAX_OUTPUTS * (MAX_DEPTH + 1)
_FALSE = {**HOST._FLAGS_FALSE, "operative": False}
_HOST_TYPE = HOST.OfflineN1Host
_VERIFY = _HOST_TYPE.verify_artifact
_CAPTURE = HOST._capture
_HOST_FUNCTIONS = {
    name: value for name, value in vars(HOST).items()
    if type(value) is FunctionType and value.__module__ == HOST.__name__
}
_HOST_METHODS = {
    name: value for name, value in vars(_HOST_TYPE).items()
    if type(value) is FunctionType
}
_POLICIES = weakref.WeakKeyDictionary()
_TOKENS = weakref.WeakKeyDictionary()


class ValidationError(ValueError):
    """A bounded validation refusal with a copied diagnostic report."""

    def __init__(self, message, report=None):
        message = _bounded_text(message)
        super().__init__(message)
        self._report = _encode(report or {"offline_validation_complete": False,
                                         "errors": [message], **_FALSE})

    @property
    def report(self):
        return json.loads(self._report)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _bounded_text(value):
    if type(value) is not str:
        return "The diagnostic is not plain text."
    return value[:MAX_ERROR_CHARACTERS]


def _exception_text(exc):
    name = type(exc).__name__[:128]
    arguments = BaseException.args.__get__(exc)
    if arguments and type(arguments[0]) is str:
        return name + ": " + _bounded_text(arguments[0])
    return name


def _diagnostics(messages):
    parts, remaining = [], MAX_ERROR_CHARACTERS
    for value in messages:
        if remaining <= 0:
            break
        part = _bounded_text(value)[:remaining]
        parts.append(part)
        remaining -= len(part) + 2
    return "; ".join(parts)


def _plain_record(value, maximum):
    if type(value) is not dict or len(value) > maximum:
        raise ValidationError("An input record has an unsupported type or field count.")
    if any(type(key) is not str for key in value):
        raise ValidationError("Input field names must be plain text.")


def _children(item, remaining):
    record = type(item) is dict
    if len(item) * (2 if record else 1) > remaining:
        raise ValidationError("The input exceeds the pending inspection bound.")
    if record:
        _plain_record(item, MAX_NODES)
        for key, value in item.items():
            yield key
            yield value
    else:
        yield from item


def _utf8(text):
    return text.encode("utf-8", errors="strict")


def _text_size(text, remaining):
    bound = min(remaining, HOST.MAX_RECORD_BYTES)
    if len(text) > bound:
        raise ValidationError("The input text exceeds the byte bound.")
    size = len(_utf8(text))
    if size > bound:
        raise ValidationError("The input text exceeds the byte bound.")
    return size


def _scalar_size(item, remaining=HOST.MAX_RECORD_BYTES):
    kind = type(item)
    if kind is str:
        return _text_size(item, remaining)
    if kind is int:
        if item.bit_length() > 64:
            raise ValidationError("An input integer exceeds the inspection bound.")
        return 0
    if kind is float:
        if not math.isfinite(item):
            raise ValidationError("Input numbers must be finite.")
        return 0
    if item is not None and kind is not bool:
        raise ValidationError("The input has an unsupported value type.")
    return 0


def _snapshot(value, limit=HOST.MAX_RECORD_BYTES):
    pending, nodes, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_INPUT_DEPTH:
            raise ValidationError("The input exceeds the inspection bound.")
        kind = type(item)
        if kind is dict or kind is list:
            remaining = MAX_NODES - nodes - len(pending)
            pending.extend((child, depth + 1) for child in _children(item, remaining))
        else:
            size += _scalar_size(item, limit - size)
    data = _encode(value)
    if len(data) > limit:
        raise ValidationError("The input exceeds the serialized byte bound.")
    return data


def _relative(value):
    path = HOST._relative(value)
    parts = path.split("/")
    if len(parts) > MAX_DEPTH or any(len(part) > 64 or part.casefold() == ".git" for part in parts):
        raise ValidationError("An output path exceeds the supported path bound.")
    return path


def _expected_bytes(value):
    if type(value["size"]) is not int or not 0 <= value["size"] <= HOST.MAX_FILE_BYTES:
        raise ValidationError("Expected output size must be a bounded integer.")
    if type(value["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None:
        raise ValidationError("Expected output digest must be lowercase SHA256 text.")


def _required_text(text):
    if type(text) is not str or not text or len(text) > MAX_TEXT_BYTES:
        raise ValidationError("Required text must be bounded nonempty UTF8 text.")
    if len(text.encode("utf-8", errors="strict")) > MAX_TEXT_BYTES:
        raise ValidationError("Required text exceeds the UTF8 byte bound.")


def _policy_entry(value):
    _plain_record(value, 5)
    validator = value.get("validator")
    if type(validator) is not str or validator not in {"bytes", "utf8-required-text"}:
        raise ValidationError("The validation policy names an unsupported validator.")
    fields = {"path", "validator", "size", "sha256"}
    if validator == "utf8-required-text":
        fields.add("required_text")
    if set(value) != fields:
        raise ValidationError("A policy output has unknown or missing fields.")
    _relative(value["path"])
    _expected_bytes(value)
    if validator == "utf8-required-text":
        _required_text(value["required_text"])
    return dict(value)


def _policy_preflight(specification):
    _plain_record(specification, 2)
    _snapshot(specification, MAX_POLICY_BYTES)
    outputs = specification.get("outputs")
    if type(outputs) is not list or not 1 <= len(outputs) <= HOST.MAX_OUTPUTS:
        raise ValidationError("The policy needs a bounded nonempty output list.")
    for entry in outputs:
        _plain_record(entry, 5)


def _check_paths(paths):
    declared = set(paths)
    if len(declared) != len(paths) or any(
            path[:index] in declared
            for path in paths for index, char in enumerate(path) if char == "/"):
        raise ValidationError("Policy output paths must be distinct and cannot overlap.")


def _policy_outputs(outputs):
    if type(outputs) is not list or not 1 <= len(outputs) <= HOST.MAX_OUTPUTS:
        raise ValidationError("The policy needs a bounded nonempty output list.")
    outputs = [_policy_entry(entry) for entry in outputs]
    _check_paths([entry["path"] for entry in outputs])
    if sum(entry["size"] for entry in outputs) > HOST.MAX_ARTIFACT_BYTES:
        raise ValidationError("Expected output sizes exceed the artifact byte bound.")
    return sorted(outputs, key=lambda entry: entry["path"])


def freeze_policy(specification):
    """Freeze independent expectations before observing any artifact output."""
    _policy_preflight(specification)
    if set(specification) != {"version", "outputs"}:
        raise ValidationError("The policy has unknown or missing fields.")
    if type(specification["version"]) is not int or specification["version"] != 1:
        raise ValidationError("The policy version is unsupported.")
    outputs = _policy_outputs(specification["outputs"])
    payload = _snapshot({"version": 1, "outputs": outputs}, MAX_POLICY_BYTES)
    issued = object.__new__(ValidationPolicy)
    _POLICIES[issued] = payload
    return issued


def _issued(registry, kind, value):
    if type(value) is not kind or value not in registry:
        raise ValidationError("An original module issued object is required.")
    return registry[value]


class ValidationPolicy:
    """An immutable same process declaration; its report is a deep copy."""

    __slots__ = ("__weakref__",)

    def __new__(cls, issued=None):
        _issued(_POLICIES, cls, issued)
        return issued

    def __init__(self, issued=None):
        _issued(_POLICIES, ValidationPolicy, self)

    @property
    def report(self):
        return json.loads(_issued(_POLICIES, ValidationPolicy, self))

    def __reduce_ex__(self, protocol):
        raise ValidationError("Policies require a new declaration in each process.")


class ValidatedObservation:
    """An immutable local observation with no promotion or acceptance authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls, issued=None):
        _issued(_TOKENS, cls, issued)
        return issued

    def __init__(self, issued=None):
        _issued(_TOKENS, ValidatedObservation, self)

    @property
    def report(self):
        return json.loads(_issued(_TOKENS, ValidatedObservation, self)[3])

    def __reduce_ex__(self, protocol):
        raise ValidationError("Observations cannot be replayed as serialized authority.")


def _host(host):
    if type(host) is not _HOST_TYPE or HOST.OfflineN1Host is not _HOST_TYPE:
        raise ValidationError("The original OfflineN1Host object is required.")
    if any(getattr(HOST, name, None) is not value for name, value in _HOST_FUNCTIONS.items()):
        raise ValidationError("The original host source functions changed.")
    for name, original in _HOST_METHODS.items():
        method = getattr(host, name, None)
        if getattr(method, "__func__", None) is not original or getattr(method, "__self__", None) is not host:
            raise ValidationError("The original bound host methods changed.")
    return tuple((str(path), tuple(HOST._identity(HOST._path(path))))
                 for path in (host.state, host.target, host.worker))


def _inputs(host, report, expected_target, policy):
    policy_bytes = _issued(_POLICIES, ValidationPolicy, policy)
    roots = _host(host)
    report_bytes, target_bytes = _snapshot(report), _snapshot(expected_target)
    supplied = json.loads(report_bytes)
    HOST._validate_record(supplied)
    if supplied["status"] != "artifact-ready":
        raise ValidationError("Only the stored ready host report can be validated.")
    paths = [entry["path"] for entry in json.loads(policy_bytes)["outputs"]]
    files = supplied["artifact"]["files"]
    if type(files) is not list or len(files) != len(paths) or supplied["binding"]["outputs"] != paths:
        raise ValidationError("The policy must declare every artifact output exactly once.")
    for index, (entry, path) in enumerate(zip(files, paths)):
        if type(entry) is not dict or set(entry) != {"path", "blob", "size", "sha256"}:
            raise ValidationError("An artifact output has an unsupported shape.")
        if entry["path"] != path or entry["blob"] != f"file-{index:04d}":
            raise ValidationError("Artifact paths do not match the declared policy.")
        _policy_entry({"validator": "bytes", "path": entry["path"],
                       "size": entry["size"], "sha256": entry["sha256"]})
    if _snapshot(supplied["binding"]["target"]) != target_bytes:
        raise ValidationError("The full expected target differs from the original invocation.")
    return policy_bytes, report_bytes, target_bytes, roots


def _safe_scratch(host):
    roots = (host.target, host.worker, host.state)
    HOST._validate_scratch((host.target, host.worker))
    usable = False
    for candidate in HOST.workspace_capture._scratch_candidates():
        path = HOST._path(candidate)
        if str(path) == "/" or any(HOST._within(path, HOST.Path(root)) for root in ("/dev", "/proc", "/sys")):
            raise ValidationError("A scratch candidate names a special root.")
        HOST._scratch_parent(str(path), roots)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ValidationError("A scratch candidate is not a directory.")
        pinned = HOST.workspace_capture._pin_directory(str(path))
        if pinned is None:
            raise ValidationError("A scratch candidate is not a safe directory.")
        descriptor, _chain = pinned
        usable = True
        try:
            protected = {tuple(HOST._identity(root)[:2]) for root in roots}
            if protected.intersection((info.st_dev, info.st_ino) for info in HOST.workspace_capture._ancestry(descriptor)):
                raise ValidationError("Scratch ancestry overlaps a bound root.")
        finally:
            os.close(descriptor)
    if not usable:
        raise ValidationError("No usable safe scratch directory is available.")


def _names(descriptor, limit):
    # A fresh open also sees entries added after the pinned descriptor was opened.
    listing = os.open(".", HOST._FLAGS, dir_fd=descriptor)
    names = []
    try:
        with os.scandir(listing) as entries:
            for entry in entries:
                if len(names) >= limit:
                    raise ValidationError("A directory exceeds its entry bound.")
                names.append(entry.name)
    finally:
        os.close(listing)
    return names


def _inventory(host, report):
    names = {"manifest.json", *(entry["blob"] for entry in report["artifact"]["files"])}
    with HOST._directory(host.state / "artifact") as descriptor:
        if set(_names(descriptor, HOST.MAX_OUTPUTS + 1)) != names:
            raise ValidationError("The artifact has missing or extra entries.")
        for name in names:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400:
                raise ValidationError("Artifact entries must remain single read only regular files.")


def _check(host, binding):
    _policy_bytes, report_bytes, target_bytes, roots = binding
    if _host(host) != roots:
        raise ValidationError("A bound host directory changed.")
    _safe_scratch(host)
    report, target = json.loads(report_bytes), json.loads(target_bytes)
    _inventory(host, report)
    result = _VERIFY(host, report, target)
    if result != {"valid": True, "errors": [], **HOST._FLAGS_FALSE}:
        raise ValidationError("Original host verification refused: " + _diagnostics(result["errors"]))
    with host._locked():
        if _snapshot(host._load()) != report_bytes:
            raise ValidationError("The exact stored host report changed.")
    if _snapshot(_CAPTURE(host.target, (host.target, host.worker))) != target_bytes:
        raise ValidationError("The full expected target changed.")
    return result


def _blobs(host, report):
    outputs = []
    for entry in report["artifact"]["files"]:
        data = HOST._immutable_read(host.state / "artifact", entry["blob"], HOST.MAX_FILE_BYTES)
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValidationError("Immutable artifact bytes changed after host verification.")
        outputs.append((entry["path"], data))
    if sum(len(data) for _path, data in outputs) > HOST.MAX_ARTIFACT_BYTES:
        raise ValidationError("Immutable artifact bytes exceed the total byte bound.")
    return tuple(outputs)


def _stage_kind(path, info, files, directories):
    if path in directories and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700:
        return "directory"
    if (path in files and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o400):
        return "file"
    raise ValidationError("The stage contains an unexpected or unsafe entry.")


class _Stage:
    def __init__(self, host):
        _safe_scratch(host)
        self.scratch = HOST.workspace_capture._Snapshot(tuple(str(path) for path in (host.state, host.target, host.worker)))

    def check(self, directory=None):
        self.scratch.checkpoint()
        self.scratch.verify()
        HOST._path(self.scratch.root)
        info = os.fstat(self.scratch.fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValidationError("The staging directory lost its private mode.")
        if directory is not None:
            ancestry = HOST.workspace_capture._ancestry(directory)
            if self.scratch.identity not in {(item.st_dev, item.st_ino) for item in ancestry}:
                raise ValidationError("A staged directory moved outside the private scratch.")

    def put(self, relative, data):
        current = os.dup(self.scratch.fd)
        try:
            parts = _relative(relative).split("/")
            for part in parts[:-1]:
                self.check(current)
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                following = os.open(part, HOST._FLAGS, dir_fd=current)
                os.close(current)
                current = following
            self.check(current)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(parts[-1], flags, 0o600, dir_fd=current)
            try:
                remaining = memoryview(data)
                while remaining:
                    self.check(current)
                    count = os.write(descriptor, remaining)
                    if count <= 0:
                        raise ValidationError("A staged write made no progress.")
                    remaining = remaining[count:]
                os.fchmod(descriptor, 0o400)
            finally:
                os.close(descriptor)
        finally:
            os.close(current)

    def read(self, relative):
        self.check()
        return HOST._immutable_read(HOST.Path(self.scratch.root), relative, HOST.MAX_FILE_BYTES)

    def inventory(self, paths):
        self.check()
        expected = set(paths)
        directories = {path[:index] for path in paths for index, char in enumerate(path) if char == "/"}
        pending, files, seen, count = [(os.dup(self.scratch.fd), "")], set(), set(), 0
        try:
            while pending:
                descriptor, prefix = pending.pop()
                try:
                    for name in _names(descriptor, MAX_STAGE_ENTRIES - count):
                        count += 1
                        if count > MAX_STAGE_ENTRIES:
                            raise ValidationError("The stage exceeds the entry bound.")
                        path = prefix + name
                        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        if _stage_kind(path, info, expected, directories) == "directory":
                            seen.add(path)
                            pending.append((os.open(name, HOST._FLAGS, dir_fd=descriptor), path + "/"))
                        else:
                            files.add(path)
                finally:
                    os.close(descriptor)
            if files != expected or seen != directories:
                raise ValidationError("The stage does not contain the exact declared outputs.")
        finally:
            for descriptor, _prefix in pending:
                os.close(descriptor)

    def close(self):
        self.scratch.close(deadline=time.monotonic() + 5.0)
        if self.scratch.problems:
            raise ValidationError("Scratch cleanup refused: " + _diagnostics(self.scratch.problems))


@contextmanager
def _cleanup_stage(stage, errors):
    try:
        yield stage
    except BaseException:
        try:
            stage.close()
        except BaseException as exc:
            try:
                errors.append(_bounded_text(f"Scratch cleanup refused ({_exception_text(exc)})."))
            except BaseException:
                pass
        raise
    else:
        stage.close()


@contextmanager
def _staging(host, errors):
    with _cleanup_stage(_Stage(host), errors) as stage:
        yield stage


def _compare(entry, data):
    observation = {
        "path": entry["path"], "validator": entry["validator"],
        "expected_size": entry["size"], "observed_size": len(data),
        "expected_sha256": entry["sha256"], "observed_sha256": hashlib.sha256(data).hexdigest(),
        "size_matches": len(data) == entry["size"],
        "sha256_matches": hashlib.sha256(data).hexdigest() == entry["sha256"],
        "required_text": entry.get("required_text"), "utf8_decoded": None,
        "text_matches": None, "text_error": None,
    }
    if entry["validator"] == "utf8-required-text":
        try:
            text = data.decode("utf-8", errors="strict")
            observation.update(utf8_decoded=True, text_matches=entry["required_text"] in text)
        except UnicodeDecodeError as exc:
            observation.update(utf8_decoded=False, text_matches=False, text_error=str(exc))
    observation["passed"] = (
        observation["size_matches"] and observation["sha256_matches"] and observation["text_matches"] is not False
    )
    return observation


def _read_stage(stage, paths):
    stage.inventory(paths)
    return tuple((path, stage.read(path)) for path in paths)


def _observe(host, binding):
    policy_bytes, report_bytes, target_bytes, _roots = binding
    policy, original = json.loads(policy_bytes), json.loads(report_bytes)
    report = {"version": 1, "offline_validation_complete": False, **_FALSE,
              "host_report": original, "expected_target": json.loads(target_bytes),
              "policy": policy, "files": [], "host_checks": [], "errors": []}
    try:
        report["host_checks"].append(_check(host, binding))
        outputs = _blobs(host, original)
        with _staging(host, report["errors"]) as stage:
            for path, data in outputs:
                stage.put(path, data)
            paths = [entry["path"] for entry in policy["outputs"]]
            staged = _read_stage(stage, paths)
            report["files"] = [_compare(entry, data) for entry, (_path, data) in zip(policy["outputs"], staged)]
            report["host_checks"].append(_check(host, binding))
            if _blobs(host, original) != outputs or staged != outputs:
                raise ValidationError("The stage differs from the reverified immutable bytes.")
            if _read_stage(stage, paths) != staged:
                raise ValidationError("Staged bytes changed during validation.")
            if not all(entry["passed"] for entry in report["files"]):
                raise ValidationError("Independent expected output comparisons failed.")
        report["host_checks"].append(_check(host, binding))
        report["offline_validation_complete"] = True
        return _encode(report), staged
    except Exception as exc:
        message = _bounded_text(f"Offline validation refused ({_exception_text(exc)}).")
        report["errors"].insert(0, message)
        raise ValidationError(message, report) from exc


def validate_artifact(host, report, expected_target, policy):
    """Validate inert staged bytes and issue only a same process observation."""
    try:
        binding = _inputs(host, report, expected_target, policy)
        observation, _outputs = _observe(host, binding)
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(f"Validation input refused ({_exception_text(exc)}).") from exc
    issued = object.__new__(ValidatedObservation)
    _TOKENS[issued] = (host, policy, binding, observation)
    return issued


def consume_validated(host, token, report, expected_target, policy):
    """Revalidate and return declared names with immutable bytes for future offline work."""
    try:
        original_host, original_policy, binding, observation = _issued(_TOKENS, ValidatedObservation, token)
        if host is not original_host or policy is not original_policy:
            raise ValidationError("The issued host and policy identities must match.")
        if _inputs(host, report, expected_target, policy) != binding:
            raise ValidationError("The issued report, target, policy or host binding changed.")
        current, outputs = _observe(host, binding)
        if current != observation:
            raise ValidationError("The original validated observation changed during revalidation.")
        return outputs
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(f"Validation consumption refused ({_exception_text(exc)}).") from exc


def publication_custody(host, report, expected_target, policy, observation, operation):
    """Exact inert retention action; only original controller signing grants custody."""
    binding = _inputs(host, report, expected_target, policy)
    return {"purpose": "registered-publication-custody-v1", "operation": operation.operation_sha256,
            "policy": json.loads(binding[0]), "report": json.loads(binding[1]),
            "expected_target": json.loads(binding[2]),
            "roots": [[path, list(identity)] for path, identity in binding[3]],
            "observation": json.loads(_snapshot(observation))}


def _publication_comparison(host, report, policy, observation):
    _inventory(host, report)
    with host._locked():
        if _snapshot(host._load()) != _snapshot(report):
            raise ValidationError("The retained original host report changed.")
        host._verify_files(report["artifact"], report["binding"])
    outputs = _blobs(host, report)
    errors = []
    with _staging(host, errors) as stage:
        for path, data in outputs:
            stage.put(path, data)
        staged = _read_stage(stage, [entry['path'] for entry in policy.report['outputs']])
        comparisons = [_compare(entry, data) for entry, (_path, data) in zip(policy.report['outputs'], staged)]
        if staged != outputs or not all(entry['passed'] for entry in comparisons):
            raise ValidationError("Independent retained output comparison refused.")
        if comparisons != observation['files']:
            raise ValidationError("Original independent validation comparison changed.")
    if _blobs(host, report) != outputs:
        raise ValidationError("Immutable output changed during recovery comparison.")


def reissue_publication_observation(host, report, expected_target, policy, observation, *,
                                    operation, verifier, custody_directive):
    """Reissue only authenticated original validation for guarded publication.

    Target freshness is intentionally the original publisher's authenticated
    checkpoint responsibility. This cannot authorize native work or turn an
    unsigned serialized report into an issued observation.
    """
    from cwo_core import maintenance_authority as authority
    authority.require_maintenance_operation(operation, verifier=verifier)
    expected_adapter = HOST.Path(__file__).resolve().with_name('guarded_artifact_target.py')
    if operation.adapter_path != expected_adapter:
        raise ValidationError("Only original registered publication authority may recover validation.")
    body = publication_custody(host, report, expected_target, policy, observation, operation)
    authority._directive(custody_directive, key=verifier._key, actor=verifier._actor,
        identity=verifier._identity, action=authority.canonical_authority_sha256(body),
        parent=operation.operation_sha256)
    _retained_observation(body)
    _publication_comparison(host, report, policy, observation)
    authority.require_maintenance_operation(operation, verifier=verifier)
    binding = _inputs(host, report, expected_target, policy)
    issued = object.__new__(ValidatedObservation)
    _TOKENS[issued] = (host, policy, binding, _encode(observation))
    return issued


def _retained_observation(body):
    observation = body['observation']
    expected = {"host_report": body['report'], "expected_target": body['expected_target'],
                "policy": body['policy'], "offline_validation_complete": True, "errors": [], **_FALSE}
    if any(observation.get(key) != value for key, value in expected.items()):
        raise ValidationError("Original retained validation observation binding changed.")
