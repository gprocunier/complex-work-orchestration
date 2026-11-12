"""Installed fake frame reliability evidence from disposable images."""
from __future__ import annotations

import ast
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch

from tests.installed_consumer_fixtures import RestoredInstalledRows, prepare_replacement
from tests import test_install_projection as fixture
from tests import test_installed_numeric_rollback as rollback_fixture
from tests import test_server_request_frame_preparation as source_fixture


ROOT = fixture.ROOT.resolve()
RECORD = ".cwo-install-manifest.json"
SCHEMA = "cwo-installed-server-frame-consumer-evidence-v1"
PREFIX = "CWO_INSTALLED_SERVER_FRAME_EVIDENCE "
INPUT_IDENTITY = ("b5bb9b2763590e9cb3275513d536c9103b3ba259", "addafeaa98d5b581f08c2f385fc93605f781ca13")
EPOCH = source_fixture.EPOCH
COMMAND = source_fixture.prep.COMMAND
FILE = source_fixture.prep.FILE
PERMISSIONS = source_fixture.prep.PERMISSIONS
FLAGS = (
    "operative", "qualified", "effect_authority",
    "production_ready", "current_transport_wired",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def identity(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def typed(name, **values):
    return {"type": name, "value": values}


def status(received=0, completed=0, delivered=0, buffered=0, closed=False, epoch=EPOCH):
    return typed("FrameStatus", epoch=epoch, received_bytes=received,
                 completed_frames=completed, delivered_frames=delivered,
                 buffered_bytes=buffered, closed=closed, delivering=False,
                 **dict.fromkeys(FLAGS, False))


def batch(state, delivered=()):
    return typed("FrameBatch", delivered=list(delivered), status=state,
                 **dict.fromkeys(FLAGS, False))


def frame_error(code, state, delivered=(), *, fatal=True):
    return typed("FramePreparationError", code=code, status=state,
                 delivered=list(delivered), delivered_count=len(delivered),
                 delivered_total=state["value"]["delivered_frames"], fatal=fatal,
                 **dict.fromkeys(FLAGS, False))


def prep_error(code):
    return typed("PreparationError", code=code)


def step(target, method, want=None, *, args=(), now=None, epoch=None, **extra):
    kwargs = {}
    if now is not None:
        kwargs["now"] = now
    if epoch is not None:
        kwargs["epoch"] = epoch
    return ({"target": target, "method": method, "args": list(args),
             "kwargs": kwargs, **extra}, want)


def feed(raw, want, *, now=0, epoch=EPOCH, target="reader"):
    return step(target, "feed", want, now=now,
                epoch=epoch, raw=raw)


def context_values(method=COMMAND, **changes):
    values = asdict(source_fixture.context(method, **changes))
    values.pop("provenance")
    return values


def register(method=COMMAND, *, epoch=EPOCH, now=0):
    values = context_values(method, epoch=epoch)
    return [
        step("consumer", "open_turn", args=(values["thread_id"], values["turn_id"]), now=now),
        step("consumer", "observe_item", context=values, now=now),
    ]


def message(value):
    if "method" not in value:
        return typed("Response", request_id=value["id"], frame_json=canonical(value))
    if "id" not in value:
        return typed("Notification", method=value["method"], frame_json=canonical(value))
    return typed("ServerRequest", request_id=value["id"], method=value["method"],
                 params_json=canonical(value["params"]))


def correlation(value, epoch=EPOCH):
    params = value["params"]
    return typed("Correlation", epoch=epoch, request_id=value["id"],
                 thread_id=params["threadId"], turn_id=params["turnId"],
                 item_id=params["itemId"], approval_id=params.get("approvalId"))


def work(value, epoch=EPOCH):
    values = context_values(value["method"], epoch=epoch)
    return typed("DecisionWork", correlation=correlation(value, epoch),
                 method=value["method"], params_json=canonical(value["params"]),
                 context=typed("FakeItemContext", **values,
                               provenance="caller-supplied fake pre-effect context; not authenticated production provenance"))


def reply(value, result, *, interrupt=False, epoch=EPOCH, error=False):
    return typed("PreparedReply", epoch=epoch,
                 correlation=None if error else correlation(value, epoch),
                 frame_json=canonical({"id": value["id"], "error" if error else "result": result}),
                 interruption_required=interrupt, captured_version="0.164.0",
                 evidence_qualifier="captured-provisional-schema-only; experimental; unqualified",
                 experimental=True, qualified=False,
                 context_provenance="caller-supplied fake pre-effect context; not authenticated production provenance")


def consumer_state(values=(), *, now=0, closed=True, entry_state="revoked"):
    callbacks = [
        [EPOCH, v["params"]["threadId"], v["params"]["turnId"], v["params"]["itemId"],
         v["method"], v["params"].get("approvalId")]
        for v in values if v["method"] in {COMMAND, FILE, PERMISSIONS}
    ]
    return {"epoch": EPOCH, "now": now, "closed": closed,
            "entries": [[type(v["id"]).__name__, v["id"], entry_state] for v in values],
            "callbacks": sorted(callbacks, key=canonical), "queued": 0, "replies": 0,
            "active": {} if closed else {"EXAMPLE-thread": "EXAMPLE-turn"},
            "items": 0 if closed else 1}


def nested(depth):
    value = []
    for _ in range(depth - 1):
        value = [value]
    return value


def positive_cases(add):
    for method, label in ((COMMAND, "command"), (FILE, "file"), (PERMISSIONS, "permissions")):
        value = source_fixture.request(method)
        raw = source_fixture.line(value)
        wanted = {"permissions": {}} if method == PERMISSIONS else {"decision": "accept"}
        decision = "decline" if method == PERMISSIONS else "accept"
        steps = register(method) + [
            feed(raw, batch(status(len(raw), 1, 1), [message(value)])),
            step("consumer", "drain_replies", [], now=0),
            step("consumer", "next_decision", work(value), now=0, save="EXAMPLE-work"),
            step("consumer", "prepare", prep_error("one-action-decision-required"), now=0,
                 work="EXAMPLE-work", decision="acceptForSession"),
        ]
        if method == PERMISSIONS:
            steps.append(step("consumer", "prepare", prep_error("permission-grants-and-universal-cancel-forbidden"), now=0,
                              work="EXAMPLE-work", decision="accept"))
        steps += [
            step("consumer", "prepare", now=0, work="EXAMPLE-work", decision=decision),
            step("consumer", "drain_replies", [reply(value, wanted)], now=0),
            step("consumer", "next_decision", now=0),
            step("reader", "eof", batch(status(len(raw), 1, 1, closed=True)), epoch=EPOCH, now=1),
            step("reader", "snapshot", status(len(raw), 1, 1, closed=True)),
            step("state", "snapshot", consumer_state([value], now=1)),
        ]
        add("EXAMPLE-" + label, steps)
    notice = {"method": "EXAMPLE/notice", "params": {"text": "EXAMPLE café"}}
    response = {"id": "EXAMPLE-response", "result": 'EXAMPLE "quoted {[]}" \\'}
    value = source_fixture.request(reason='EXAMPLE café 🧪 "quoted {[]}" \\')
    values = [notice, response, value]
    raw = b"".join(source_fixture.line(v, b"\r\n") for v in values)
    split = raw.index("é".encode("utf-8")) + 1
    add("EXAMPLE-split-multiframe", register() + [
        feed(raw[:split], batch(status(split, buffered=split))),
        feed(raw[split:], batch(status(len(raw), 3, 3), [message(v) for v in values]), now=1),
        step("consumer", "drain_replies", [], now=1),
        step("consumer", "next_decision", work(value), now=1, save="EXAMPLE-work"),
        step("consumer", "next_decision", now=1),
        step("consumer", "prepare", now=1, work="EXAMPLE-work", decision="decline"),
        step("consumer", "drain_replies", [reply(value, {"decision": "decline"})], now=1),
    ])
    value = {"id": "EXAMPLE-unsupported", "method": "EXAMPLE/unsupported", "params": {}}
    unsupported = {"code": -32601, "message": "Unsupported server request"}
    raw = source_fixture.line(value)
    add("EXAMPLE-unsupported", register() + [
        feed(raw, batch(status(len(raw), 1, 1), [message(value)])),
        step("consumer", "next_decision", now=0),
        step("consumer", "drain_replies", [reply(value, unsupported, interrupt=True, error=True)], now=0),
    ])
    response = {"id": "EXAMPLE-boundary", "result": "EXAMPLE"}
    raw = source_fixture.line(response)
    add("EXAMPLE-exact-chunk", register() + [
        feed(raw, batch(status(len(raw), 1, 1), [message(response)])),
        step("consumer", "next_decision", now=0),
        step("consumer", "drain_replies", [], now=0),
    ], reader_limits={"max_chunk_bytes": len(raw)})
    payload = raw[:-1]
    add("EXAMPLE-crlf-boundaries", register() + [
        feed(payload + b"\r", batch(status(len(payload) + 1, buffered=len(payload) + 1))),
        feed(b"\n", batch(status(len(payload) + 2, 1, 1), [message(response)]), now=1),
        step("reader", "eof", batch(status(len(payload) + 2, 1, 1, closed=True)), epoch=EPOCH, now=2),
    ], reader_limits={"max_frame_bytes": len(payload), "max_chunk_bytes": len(payload) + 1,
                      "max_total_bytes": len(payload) + 2, "max_frames": 1})
    for label, result in (("depth", nested(16)), ("escaped", '"' * 8192)):
        value = {"id": "EXAMPLE-" + label, "result": result}
        raw = source_fixture.line(value)
        add("EXAMPLE-legal-" + label, register() + [
            feed(raw, batch(status(len(raw), 1, 1), [message(value)])),
            step("consumer", "next_decision", now=0),
            step("consumer", "drain_replies", [], now=0),
        ])


def negative_cases(add):
    cases = (
        ("duplicate", b'{"id":1,"id":2,"result":{}}\n', "duplicate-textual-key"),
        ("escaped-alias", b'{"id":1,"result":{"EXAMPLE-a":1,"EXAMPLE-\\u0061":2}}\n', "duplicate-textual-key"),
        ("json", b"{\n", "invalid-json-or-native-limit"),
        ("utf8", b"\xff\n", "invalid-utf8"),
        ("boolean-id", source_fixture.line({"id": True, "result": {}}), "request-id"),
        ("container", source_fixture.line([]), "message-not-object"),
        ("params", source_fixture.line({"id": 1, "method": "EXAMPLE/unknown", "params": []}), "method-or-params"),
        ("scalar", source_fixture.line(source_fixture.request(startedAtMs=True)), "approval-params"),
        ("depth", source_fixture.line({"id": 1, "result": nested(17)}), "message-size-or-depth"),
    )
    for label, raw, code in cases:
        state = status(len(raw), 1, 0, closed=True)
        add("EXAMPLE-refuse-" + label, register() + [
            feed(raw, frame_error(code, state)),
            step("reader", "snapshot", state),
            step("state", "snapshot", consumer_state()),
        ])
    value = {"id": "EXAMPLE-limit", "result": "EXAMPLE"}
    raw = source_fixture.line(value)
    for label, limits, received, code in (
        ("frame", {"max_frame_bytes": len(raw) - 2}, len(raw) - 2, "frame-byte-bound"),
        ("chunk", {"max_chunk_bytes": len(raw) - 1}, 0, "chunk-byte-bound"),
    ):
        state = status(received, closed=True)
        add("EXAMPLE-refuse-" + label, register() + [
            feed(raw, frame_error(code, state)),
            step("state", "snapshot", consumer_state()),
        ], reader_limits=limits)
    notice = {"method": "EXAMPLE/notice", "params": {}}
    raw = source_fixture.line(notice)
    for label, limits, tail, code in (
        ("total", {"max_total_bytes": len(raw)}, b"E", "total-byte-bound"),
        ("count", {"max_frames": 1}, raw, "message-count-bound"),
    ):
        state = status(len(raw), 1, 1, closed=True)
        add("EXAMPLE-refuse-" + label, register() + [
            feed(raw + tail, frame_error(code, state, [message(notice)])),
            step("state", "snapshot", consumer_state()),
        ], reader_limits=limits)
    value = source_fixture.request()
    raw = source_fixture.line(value)
    for label, tail, code in (
        ("prefix", b"{\n", "invalid-json-or-native-limit"),
        ("duplicate-id", raw, "duplicate-request-id"),
    ):
        state = status(len(raw) + len(tail), 2, 1, closed=True)
        add("EXAMPLE-refuse-" + label, register() + [
            feed(raw + tail, frame_error(code, state, [message(value)])),
            step("state", "snapshot", consumer_state([value])),
        ])
    second = source_fixture.request(request_id=2, itemId="EXAMPLE-second-item")
    tail = source_fixture.line(second)
    ctx = context_values(item_id="EXAMPLE-second-item")
    add("EXAMPLE-pending-bound", register() + [
        step("consumer", "observe_item", context=ctx, now=0),
        feed(raw + tail, frame_error("pending-and-reply-bound",
                                    status(len(raw) + len(tail), 2, 1, closed=True), [message(value)])),
        step("state", "snapshot", consumer_state([value])),
    ], consumer_limits={"max_pending": 1, "max_requests": 2})
    add("EXAMPLE-stale-context", register() + [
        step("consumer", "terminal", args=("EXAMPLE-thread", "EXAMPLE-turn"), now=1),
        feed(raw, frame_error("inactive-or-cross-thread-turn", status(len(raw), 1, 0, closed=True)), now=2),
        step("state", "snapshot", consumer_state([value], now=2)),
    ])


def lifecycle_cases(add):
    value = source_fixture.request()
    raw = source_fixture.line(value)
    unfinished = source_fixture.line({"id": "EXAMPLE-unfinished", "result": {}})[:-1]
    state = status(len(raw) + len(unfinished), 1, 1, closed=True)
    add("EXAMPLE-required-lf-eof", register() + [
        feed(raw + unfinished, batch(status(len(raw) + len(unfinished), 1, 1, buffered=len(unfinished)), [message(value)])),
        step("consumer", "next_decision", work(value), now=0, save="EXAMPLE-old"),
        step("reader", "eof", frame_error("partial-eof-frame", state), epoch=EPOCH, now=1),
        step("reader", "snapshot", state),
        step("state", "snapshot", consumer_state([value], now=1)),
        step("reader", "eof", frame_error("reader-closed", state, fatal=False), epoch=EPOCH, now=2),
        feed(b"", frame_error("reader-closed", state, fatal=False), now=2),
        step("consumer", "prepare", prep_error("closed-or-stale-epoch"), now=2, work="EXAMPLE-old", decision="accept"),
    ])
    add("EXAMPLE-deadline", register() + [
        feed(raw, batch(status(len(raw), 1, 1), [message(value)])),
        step("consumer", "next_decision", work(value), now=1, save="EXAMPLE-work"),
        step("consumer", "drain_replies", [reply(value, {"decision": "decline"}, interrupt=True)], now=10),
        step("consumer", "prepare", prep_error("decision-stale-or-duplicate"), now=10, work="EXAMPLE-work", decision="accept"),
        step("consumer", "drain_replies", [], now=10),
    ])
    add("EXAMPLE-terminal", register() + [
        feed(raw, batch(status(len(raw), 1, 1), [message(value)])),
        step("consumer", "next_decision", work(value), now=0, save="EXAMPLE-work"),
        step("consumer", "prepare", now=0, work="EXAMPLE-work", decision="accept"),
        step("consumer", "terminal", args=("EXAMPLE-thread", "EXAMPLE-turn"), now=1),
        step("consumer", "drain_replies", [reply(value, {"decision": "cancel"}, interrupt=True)], now=1),
        step("consumer", "prepare", prep_error("decision-stale-or-duplicate"), now=1, work="EXAMPLE-work", decision="accept"),
    ])
    new_epoch = "EXAMPLE-next-epoch"
    add("EXAMPLE-reconnect", register() + [
        feed(raw + b"{", batch(status(len(raw) + 1, 1, 1, buffered=1), [message(value)])),
        step("consumer", "next_decision", work(value), now=0, save="EXAMPLE-old"),
        step("consumer", "reconnect", args=(new_epoch,), now=1),
        *register(epoch=new_epoch, now=1),
        step("new-reader", "new", key="EXAMPLE-new"),
        feed(raw, frame_error("closed-or-stale-epoch", status(epoch=new_epoch), fatal=False),
             epoch=EPOCH, now=1, target="EXAMPLE-new"),
        feed(raw, batch(status(len(raw), 1, 1, epoch=new_epoch), [message(value)]),
             epoch=new_epoch, now=1, target="EXAMPLE-new"),
        step("reader", "eof", frame_error("reader-closed",
                                        status(len(raw) + 1, 1, 1, closed=True), fatal=False), epoch=EPOCH, now=1),
        step("consumer", "prepare", prep_error("closed-or-stale-epoch"), now=1, work="EXAMPLE-old", decision="accept"),
        step("consumer", "next_decision", work(value, new_epoch), now=1, save="EXAMPLE-new"),
        step("consumer", "prepare", now=1, work="EXAMPLE-new", decision="decline"),
        step("consumer", "drain_replies", [reply(value, {"decision": "decline"}, epoch=new_epoch)], now=1),
        step("EXAMPLE-new", "eof", batch(status(len(raw), 1, 1, closed=True, epoch=new_epoch)), epoch=new_epoch, now=2),
        step("consumer", "reconnect", prep_error("epoch-reused-or-bound"), args=(EPOCH,), now=2),
    ], consumer_limits={"max_epochs": 2})


def build_matrix():
    recipes, expected = [], []
    def add(name, steps, **limits):
        commands, wanted = zip(*steps)
        recipes.append({"name": name, "steps": list(commands), **limits})
        refused = any(isinstance(value, dict) and value.get("type") in {"PreparationError", "FramePreparationError"} for value in wanted)
        expected.append({"name": name, "status": "refused" if refused else "completed",
                         "result_sha256": digest(list(wanted))})
    for group in (positive_cases, negative_cases, lifecycle_cases):
        group(add)
    assert len({case["name"] for case in recipes}) == len(recipes)
    return recipes, expected


class PhaseDeadline(AssertionError):
    def __init__(self, report):
        self.report = report
        super().__init__(canonical(report))


def bounded_run(phase, argv, **kwargs):
    try:
        return subprocess.run(argv, check=False, **kwargs)
    except subprocess.TimeoutExpired as error:
        captured = []
        for value in (error.output, error.stderr):
            data = value.encode("utf-8") if isinstance(value, str) else value or b""
            captured.append({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        report = {"ok": False, "phase": phase, "type": "TimeoutExpired", "count": 1,
                  "argument_count": len(argv), "invocation_sha256": digest(argv), "captured": captured}
        raise PhaseDeadline(report) from None


def retain_record(record, stream):
    line = canonical(record)
    if len(line.encode("utf-8")) > 1048576:
        raise AssertionError("EXAMPLE reliability evidence exceeds its retained bound")
    stream.write(PREFIX + line + "\n")
    stream.flush()
    return json.loads(line)


CHECKER_BOOTSTRAP = (
    "import runpy, sys\n"
    "sys.path.insert(0, sys.argv.pop(1))\n"
    "runpy.run_module('check_installed_skill', run_name='__main__')\n"
)


PROBE = r'''
import ast
import dataclasses
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import random
import socket
import subprocess
import sys
from unittest.mock import patch

root, checkout, source, area, packet_path = (Path(v).resolve() for v in sys.argv[1:6])
packet_sha = sys.argv[6]
scripts = root / "scripts"
library = Path(os.__file__).resolve().parent
flags = ("operative", "qualified", "effect_authority", "production_ready", "current_transport_wired")
effects = dict.fromkeys(("read", "write", "mutation", "process", "socket", "beads", "current-dispatch", "model"), 0)
reads, descriptors, opening = set(), {}, []
allowed = {packet_path}

class EffectRefused(RuntimeError):
    pass

class CorrespondenceRefused(AssertionError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

def sha(value):
    return hashlib.sha256(value).hexdigest()

def digest(value):
    return sha(canonical(value).encode("utf-8"))

def file_identity(path):
    return {"path": str(path), "sha256": sha(path.read_bytes())}

def block(name):
    effects[name] += 1
    raise EffectRefused(name)

def path_for(value, directory=None):
    if isinstance(value, int):
        if value not in descriptors:
            block("read")
        return descriptors[value]
    path = Path(os.fsdecode(value))
    if directory not in (None, -1) and not path.is_absolute():
        path = path_for(directory) / path
    return path.resolve()

def observe_path(path, mode):
    if mode & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        block("write")
    if path in allowed or path.is_relative_to(root):
        reads.add(str(path))
        return
    if path.is_relative_to(library) and not ({"site-packages", "dist-packages"} & set(path.parts)):
        return
    block("read")

def audit(event, args):
    if event == "open":
        observe_path(opening[-1] if opening else path_for(args[0]), args[2] or 0)
    elif event in {"os.listdir", "os.scandir"}:
        observe_path(path_for(args[0]), 0)
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink", "os.chmod", "os.chown", "os.truncate", "os.utime"}:
        block("mutation")
    elif event in {"subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.forkpty"}:
        block("process")
    elif event.startswith("socket."):
        block("socket")

real_open = os.open
def open_path(path, mode, *args, **kwargs):
    resolved = path_for(path, kwargs.get("dir_fd"))
    opening.append(resolved)
    try:
        descriptor = real_open(path, mode, *args, **kwargs)
    finally:
        opening.pop()
    descriptors[descriptor] = resolved
    return descriptor

# Standard library reliability startup ends before the measured CWO observation phase.
sys.addaudithook(audit)
assert sys.flags.isolated and sys.dont_write_bytecode
assert root == area / "skills/complex-work-orchestration"
assert source == area / "source" and not source.exists()
assert Path.cwd() == area / "home" == Path(os.environ["HOME"]).resolve()
assert not area.is_relative_to(checkout)
assert all(not Path(v).resolve().is_relative_to(checkout) and not Path(v).resolve().is_relative_to(source) for v in sys.path)
assert not any(name == "tests" or name.startswith("tests.") or name == "cwo_core" or name.startswith("cwo_core.") for name in sys.modules)
sys.path.insert(0, str(scripts))
raw_packet = packet_path.read_bytes()
assert sha(raw_packet) == packet_sha
packet = json.loads(raw_packet)
allowed.update(Path(entry["path"]) for entry in packet["inputs"])
allowed.add(Path(packet["interpreter"]["path"]))
inputs = {}
identities = [file_identity(packet_path)]
for entry in packet["inputs"]:
    path = Path(entry["path"])
    data = path.read_bytes()
    actual = {"path": str(path), "sha256": sha(data)}
    assert actual == entry
    identities.append(actual)
    inputs[str(path)] = data
interpreter = file_identity(Path(sys.executable).resolve())
assert interpreter == packet["interpreter"]
dispatch_file = scripts / "cwo_core/native_turn_dispatch.py"
dispatch_names = {node.name for node in ast.parse(dispatch_file.read_text(encoding="utf-8")).body
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
guarded_names = dispatch_names | {"__init__", "create_bead", "add_dependency", "run_bd", "run_bd_structured"}

def profile(frame, event, _argument):
    if event != "call" or frame.f_code.co_name not in guarded_names:
        return
    module = frame.f_globals.get("__name__")
    if module == "cwo_core.native_turn_dispatch" and frame.f_code.co_name in dispatch_names:
        block("current-dispatch")
    if module == "cwo_core.beads" and frame.f_code.co_name in {"create_bead", "add_dependency", "run_bd", "run_bd_structured"}:
        block("beads")
    if module == "cwo_core.supervision.transport.app_server" and frame.f_code.co_qualname == "AppServer.__init__":
        block("model")

def normalize(value):
    if isinstance(value, (frames.FrameBatch, frames.FrameStatus, frames.FramePreparationError)):
        assert all(getattr(value, name) is False for name in flags)
    if isinstance(value, frames.FramePreparationError):
        return {"type": "FramePreparationError",
                "value": {"code": value.code, "fatal": value.fatal, "status": normalize(value.status),
                          "delivered": normalize(value.delivered), "delivered_count": value.delivered_count,
                          "delivered_total": value.delivered_total, **dict.fromkeys(flags, False)}}
    if isinstance(value, prep.PreparationError):
        return {"type": "PreparationError", "value": {"code": str(value)}}
    if dataclasses.is_dataclass(value):
        return {"type": type(value).__name__,
                "value": {field.name: normalize(getattr(value, field.name)) for field in dataclasses.fields(value)}}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return value

def state(consumer):
    return {"epoch": consumer._epoch, "now": consumer._last_now, "closed": consumer._closed,
            "entries": [[token[0].__name__, token[1], entry.state] for token, entry in consumer._entries.items()],
            "callbacks": sorted([list(token) for token in consumer._callbacks], key=canonical),
            "queued": len(consumer._queue), "replies": len(consumer._replies),
            "active": dict(consumer._active), "items": len(consumer._items)}

def invoke(command, consumer, readers, works):
    target, method = command["target"], command["method"]
    if target == "new-reader":
        readers[command["key"]] = frames.FakeFrameReader(consumer)
        return None
    if target == "state":
        return state(consumer)
    owner = consumer if target == "consumer" else readers[target]
    args = command.get("args", [])
    if method == "feed":
        args = [inputs[command["input"]]]
    elif method == "observe_item":
        context = command["context"]
        if type(context) is not dict:
            raise ValueError("EXAMPLE reliability context must be an object")
        paths = context.get("paths")
        if type(paths) is not list or any(type(path) is not str for path in paths):
            raise ValueError("EXAMPLE reliability context paths must be a list of strings")
        args = [prep.FakeItemContext(**{**context, "paths": tuple(paths)})]
    elif method == "prepare":
        args = [works[command["work"]].correlation, command["decision"]]
    result = getattr(owner, method)(*args, **command["kwargs"])
    if "save" in command:
        works[command["save"]] = result
    return result

def exercise():
    outcomes = []
    for case in packet["cases"]:
        consumer = prep.FakeRequestPreparer("EXAMPLE-epoch", allowed_paths=("/EXAMPLE/file",),
                                           timeout_ms=10, **case.get("consumer_limits", {}))
        readers = {"reader": frames.FakeFrameReader(consumer, **case.get("reader_limits", {}))}
        results, works, rejected = [], {}, False
        for command in case["steps"]:
            try:
                result = invoke(command, consumer, readers, works)
            except prep.PreparationError as error:
                result, rejected = error, True
            results.append(normalize(result))
        outcomes.append({"name": case["name"], "status": "refused" if rejected else "completed",
                         "result_sha256": digest(results)})
    return outcomes

def origins():
    result = []
    for name, module in sorted(sys.modules.copy().items()):
        filename = getattr(module, "__file__", None)
        if not filename:
            continue
        path = Path(filename).resolve()
        is_core = name == "cwo_core" or name.startswith("cwo_core.")
        if not (is_core or path.is_relative_to(scripts)):
            assert not path.is_relative_to(checkout) and not path.is_relative_to(source)
            continue
        assert path.is_relative_to(scripts)
        spec = Path(module.__spec__.origin).resolve()
        assert path == spec
        packages = [str(Path(v).resolve()) for v in getattr(module, "__path__", ())]
        spec_packages = [str(Path(v).resolve()) for v in (module.__spec__.submodule_search_locations or ())]
        assert packages == spec_packages
        expected = scripts.joinpath(*name.split("."))
        assert path == (expected / "__init__.py" if packages else expected.with_suffix(".py"))
        assert not packages or packages == [str(path.parent)]
        result.append({"name": name, "file": str(path), "spec": str(spec),
                       "sha256": sha(path.read_bytes()), "package_paths": packages, "spec_package_paths": spec_packages})
    assert not any(name == "tests" or name.startswith("tests.") for name in sys.modules)
    return result

def complete_call(function):
    signature = inspect.signature(function)
    args, kwargs = [], {}
    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        value = parameter.default if parameter.default is not parameter.empty else "EXAMPLE reliability control"
        if parameter.kind == parameter.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[parameter.name] = value
    bound = signature.bind(*args, **kwargs)
    result = function(*bound.args, **bound.kwargs)
    if inspect.iscoroutine(result) or inspect.isgenerator(result):
        result.send(None)
    return result

failure, phase, outcomes, manifest = None, "imports", [], None
beads = dispatch = model = None
record_identity = file_identity(root / ".cwo-install-manifest.json")
security_identity = file_identity(root / "SECURITY.md")
sys.setprofile(profile)
with patch("os.open", open_path):
    try:
        beads = importlib.import_module("cwo_core.beads")
        dispatch = importlib.import_module("cwo_core.native_turn_dispatch")
        model = importlib.import_module("cwo_core.supervision.transport.app_server")
        checker = importlib.import_module("check_installed_skill")
        phase = "manifest"
        manifest = checker.build_manifest(root)
        record = json.loads((root / ".cwo-install-manifest.json").read_text(encoding="utf-8"))
        assert record["source_dir"] == str(source)
        assert record["projection"] == packet["expected"]["projection"]
        for key in ("source_content_sha256", "installed_content_sha256"):
            assert record[key] == packet["expected"]["content_sha256"]
        for key in ("source_file_count", "installed_file_count"):
            assert record[key] == packet["expected"]["file_count"]
        phase = "imports"
        frames = importlib.import_module("prepare_server_request_frames")
        prep = importlib.import_module("cwo_core.server_request_preparation")
        phase = "correspondence"
        if manifest != packet["expected"]:
            raise CorrespondenceRefused("EXAMPLE reliability manifest differs")
        phase = "cases"
        outcomes = exercise()
    except BaseException as error:
        failure = {"phase": phase, "type": type(error).__name__, "name": getattr(error, "name", None)}
    measured = dict(effects)
    controls = dict.fromkeys(effects, 0)
    bindings = []
    try:
        probes = [
            ("read", lambda: open(checkout / "EXAMPLE_BLOCKED", "rb")),
            ("read", lambda: open(source / "EXAMPLE_BLOCKED", "rb")),
            ("read", lambda: open("/dev/urandom", "rb")),
            ("write", lambda: open(root / "EXAMPLE_BLOCKED", "wb")),
            ("mutation", lambda: os.mkdir(area / "EXAMPLE_BLOCKED")),
            ("process", lambda: subprocess.Popen([sys.executable, "-V"])),
            ("socket", lambda: socket.socket()),
        ]
        if beads is not None:
            probes += [
                ("beads", lambda: beads.create_bead("EXAMPLE reliability task")),
                ("beads", lambda: beads.add_dependency("EXAMPLE-first", "EXAMPLE-last")),
                ("beads", lambda: beads.run_bd(["EXAMPLE-never-run"])),
                ("beads", lambda: beads.run_bd_structured(["EXAMPLE-never-run"],
                                                        directory=area, database="EXAMPLE-unused", actor="EXAMPLE-actor")),
            ]
        if model is not None:
            probes.append(("model", lambda: complete_call(model.AppServer)))
        if dispatch is not None:
            assert dispatch_names
            for name in sorted(dispatch_names):
                function = getattr(dispatch, name)
                assert inspect.isfunction(function) and function.__module__ == dispatch.__name__
                probes.append(("current-dispatch", lambda function=function: complete_call(function)))
        for name, call in probes:
            sys.setprofile(profile)
            before = dict(effects)
            try:
                call()
            except EffectRefused as error:
                assert error.args == (name,)
            else:
                raise AssertionError("EXAMPLE reliability guard control was missed")
            controls[name] += 1
            before[name] += 1
            assert effects == before
        sys.setprofile(profile)
        bindings = origins()
    except BaseException as error:
        if failure is None:
            failure = {"phase": "positive-controls", "type": type(error).__name__, "name": getattr(error, "name", None)}
    print(json.dumps({
        "ok": failure is None and not any(measured.values()), "failure": failure,
        "inputs": identities, "interpreter": interpreter, "version": list(sys.version_info[:3]),
        "expected_manifest_sha256": digest(packet["expected"]),
        "installed_manifest_sha256": digest(manifest),
        "record": record_identity, "security": security_identity, "origins": bindings,
        "outcomes": outcomes, "effects": measured, "controls": controls, "final_effects": effects,
        "installed_reads": sorted(path for path in reads if Path(path).is_relative_to(root)),
    }, sort_keys=True))
    raise SystemExit(0 if failure is None and not any(measured.values()) else 1)
'''


class InstalledServerFrameConsumerTests(unittest.TestCase):
    def setUp(self):
        self.install = fixture.InstallerProjectionTests("test_fresh_install_is_the_projection_and_its_resources_are_usable")
        self.addCleanup(self.cleanup_install)
        self.install.setUp()
        self.area = self.install.tmp
        self.source = self.install.copy_source()
        self.assertFalse(self.area.resolve().is_relative_to(ROOT))
        self.env = {**os.environ, "HOME": str(self.area / "home"),
                    "SKILL_VALIDATOR": str(self.area / "EXAMPLE-no-validator.py"), "PYTHONDONTWRITEBYTECODE": "1",
                    "PATH": str(self.install.shims) + os.pathsep + os.environ.get("PATH", os.defpath)}
        for key in ("CODEX_HOME", "CODEX_SKILLS_DIR", "PYTHONPATH", "PYTHONHOME",
                    "PYTHONSTARTUP", "BASH_ENV", "ENV"):
            self.env.pop(key, None)
        self.expected = fixture.checker.build_manifest(self.source)
        self.source_bindings = self.bind_source()
        self.assertEqual(identity(ROOT / "scripts/prepare_server_request_frames.py")["sha256"],
                         "b2a31e4d03b9c838299c790c86e6c070972b52ee7b82c98f33ed822ef53f5c40")
        self.dispatch_names = {node.name for node in ast.parse(
            (ROOT / "scripts/cwo_core/native_turn_dispatch.py").read_text(encoding="utf-8")).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.install_events = []
        self.install_image()
        prepare_replacement(self)

    def cleanup_install(self):
        temporary = getattr(self.install, "_tmp", None)
        try:
            self.install.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def bind_source(self):
        paths = {ROOT / "scripts/install.sh", ROOT / "policy/install-projection.yaml", ROOT / "SECURITY.md"}
        for module in list(sys.modules.values()):
            filename = getattr(module, "__file__", None)
            if filename and Path(filename).resolve().is_relative_to(ROOT):
                paths.add(Path(filename).resolve())
        return [identity(path) for path in sorted(paths)]

    def call_phase(self, phase, argv, **kwargs):
        try:
            return bounded_run(phase, argv, **kwargs)
        except PhaseDeadline as error:
            print("CWO_INSTALLED_SERVER_FRAME_FAILURE " + canonical(error.report), flush=True)
            raise

    def summary(self, result):
        return {"returncode": result.returncode,
                "stdout_bytes": len(result.stdout.encode("utf-8")), "stdout_sha256": digest(result.stdout),
                "stderr_bytes": len(result.stderr.encode("utf-8")), "stderr_sha256": digest(result.stderr)}

    def run_install(self, **extra):
        before = fixture.snapshot(self.source)
        result = self.call_phase("install", ["bash", str(self.source / "scripts/install.sh"),
                                "--skills-dir", str(self.install.skills), "--yes"], cwd=self.area, env={**self.env, **extra},
                                capture_output=True, text=True, timeout=180)
        self.assertTrue(fixture.snapshot(self.source) == before, "EXAMPLE reliability source changed during installation")
        self.install_events.append(self.summary(result))
        return result

    def assert_image(self, path, expected):
        self.assertTrue(fixture.checker.build_manifest(path) == expected, "EXAMPLE complete reliability manifest differs")
        record = json.loads((path / RECORD).read_text(encoding="utf-8"))
        self.assertEqual((record["version"], record["status"], record["source_dir"]),
                         (2, "current", str(self.source.resolve())))
        self.assertTrue(record["projection"] == expected["projection"], "EXAMPLE reliability projection differs")
        for key in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[key], expected["content_sha256"])
        for key in ("source_file_count", "installed_file_count"):
            self.assertEqual(record[key], expected["file_count"])
        self.assertFalse((path / "tests").exists())

    def install_image(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, self.summary(result))
        self.assert_image(self.install.target, self.expected)

    def prepare_replacement(self):
        before = fixture.snapshot(self.source)
        path = self.source / "SECURITY.md"
        path.write_bytes(path.read_bytes() + b"\nEXAMPLE disposable reliability replacement marker.\n")
        after = fixture.snapshot(self.source)
        self.assertEqual(before.keys(), after.keys())
        self.assertEqual({name for name in before if before[name] != after[name]}, {"SECURITY.md"})
        expected = fixture.checker.build_manifest(self.source)
        self.assertEqual(fixture.checker.compare_manifests(self.expected, expected)["changed_files"], ["SECURITY.md"])
        return expected

    def inputs(self):
        recipes, wanted = build_matrix()
        directory = self.area / "inputs"
        directory.mkdir()
        paths = []
        for case in recipes:
            for command in case["steps"]:
                if "raw" not in command:
                    continue
                path = directory / f"EXAMPLE-frame-{len(paths):03d}.bin"
                path.write_bytes(command.pop("raw"))
                command["input"] = str(path)
                paths.append(identity(path))
        packet = {"cases": recipes, "inputs": paths, "expected": self.expected,
                  "interpreter": identity(Path(sys.executable).resolve())}
        path = directory / "EXAMPLE-packet.json"
        path.write_text(canonical(packet), encoding="utf-8")
        return path, packet, wanted

    def check_report(self, report, packet_path, packet, wanted, failure):
        self.assertEqual(report["failure"], failure)
        self.assertIs(report["ok"], failure is None)
        self.assertEqual(report["inputs"], [identity(packet_path), *packet["inputs"]])
        self.assertEqual(report["interpreter"], packet["interpreter"])
        self.assertEqual(report["version"], list(sys.version_info[:3]))
        self.assertEqual(report["expected_manifest_sha256"], digest(self.expected))
        actual = fixture.checker.build_manifest(self.install.target)
        self.assertEqual(report["installed_manifest_sha256"], digest(actual))
        self.assertEqual(report["record"], identity(self.install.target / RECORD))
        self.assertEqual(report["security"], identity(self.install.target / "SECURITY.md"))
        self.assertEqual(report["outcomes"], wanted)
        controls = {"read": 3, "write": 1, "mutation": 1, "process": 1, "socket": 1,
                    "beads": 4, "current-dispatch": len(self.dispatch_names), "model": 1}
        self.assertEqual(report["controls"], controls)
        self.assertEqual(report["effects"], dict.fromkeys(controls, 0))
        self.assertEqual(report["final_effects"], controls)
        files = {str(self.install.target / item["path"]): item["sha256"]
                 for item in actual["files"]}
        names = set()
        for origin in report["origins"]:
            name = origin["name"]
            self.assertNotIn(name, names)
            names.add(name)
            path = self.install.target / "scripts" / Path(*name.split("."))
            packages = origin["package_paths"]
            path = path / "__init__.py" if packages else path.with_suffix(".py")
            self.assertEqual(origin["file"], str(path))
            self.assertEqual(origin["spec"], str(path))
            self.assertEqual(origin["sha256"], files[str(path)])
            self.assertEqual(packages, [str(path.parent)] if packages else [])
            self.assertEqual(origin["spec_package_paths"], packages)
        required = {"check_installed_skill", "cwo_core", "cwo_core.beads", "cwo_core.native_turn_dispatch",
                    "cwo_core.supervision.transport.app_server"}
        if failure is None or failure["phase"] == "correspondence":
            required |= {"prepare_server_request_frames", "cwo_core.server_request_preparation"}
        self.assertTrue(required <= names, "EXAMPLE installed reliability dependency origins are missing")
        self.assertTrue(report["installed_reads"], "EXAMPLE installed reliability reads were not observed")

    def probe(self, phase, packet_path, packet, wanted, failure=None):
        before = fixture.snapshot(self.area)
        result = self.call_phase(phase, [sys.executable, "-I", "-B", "-c", PROBE,
                                str(self.install.target), str(ROOT), str(self.source), str(self.area), str(packet_path), identity(packet_path)["sha256"]],
                                cwd=self.area / "home", env=self.env, capture_output=True, text=True, timeout=60)
        self.assertTrue(fixture.snapshot(self.area) == before, "EXAMPLE reliability reader changed the disposable image")
        self.assertEqual(result.returncode, 0 if failure is None else 1, self.summary(result))
        self.assertTrue(len(result.stdout.encode("utf-8")) <= 1048576, "EXAMPLE reliability child report exceeds its bound")
        report = json.loads(result.stdout)
        self.check_report(report, packet_path, packet, wanted, failure)
        return report

    def _lifecycle_metadata(self):
        return {"retention": getattr(self, "retention", {}),
                "source_snapshot_sha256": digest(fixture.snapshot(self.source)),
                "install_outcomes": self.install_events}

    def finish_scenario(self, scenario, retention=None, rows=None):
        packet_path, packet, wanted = self.inputs()
        source_snapshot = digest(fixture.snapshot(self.source)) if rows is None else None
        self.assertEqual(self.source, self.area / "source")
        shutil.rmtree(self.source)
        check = self.call_phase("installed-check", [sys.executable, "-I", "-B", "-c", CHECKER_BOOTSTRAP,
                               str(self.install.target / "scripts"),
                               "--record-check", "--installed-dir", str(self.install.target), "--json"],
                               cwd=self.area / "home", env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(check.returncode, 0, self.summary(check))
        self.assertEqual(json.loads(check.stdout)["status"], "record-consistent")
        reports = [self.probe("reader-main", packet_path, packet, wanted)]
        dependencies = []
        for label, relative, modified, failure in (
            ("missing-frame", "scripts/prepare_server_request_frames.py", False,
             {"phase": "imports", "type": "ModuleNotFoundError", "name": "prepare_server_request_frames"}),
            ("missing-consumer", "scripts/cwo_core/server_request_preparation.py", False,
             {"phase": "imports", "type": "ImportError", "name": "cwo_core"}),
            ("modified-frame", "scripts/prepare_server_request_frames.py", True,
             {"phase": "correspondence", "type": "CorrespondenceRefused", "name": None}),
        ):
            path = self.install.target / relative
            original, mode = path.read_bytes(), path.stat().st_mode
            before = fixture.snapshot(self.area)
            try:
                if modified:
                    path.write_bytes(original + b"\n# EXAMPLE reliability correspondence control.\n")
                else:
                    path.unlink()
                report = self.probe("reader-" + label, packet_path, packet, [], failure)
                reports.append(report)
                dependencies.append({"name": "EXAMPLE-" + label, "status": "refused",
                                     "result_sha256": digest(report["failure"])})
            finally:
                path.write_bytes(original)
                path.chmod(mode)
            self.assertTrue(fixture.snapshot(self.area) == before, "EXAMPLE reliability dependency control did not restore the image")
        self.assertEqual([identity(Path(item["path"])) for item in self.source_bindings], self.source_bindings)
        for row in rows or [None]:
            metadata = ({"retention": retention or {}, "source_snapshot_sha256": source_snapshot,
                         "install_outcomes": self.install_events} if row is None else row["metadata"])
            self.retained = retain_record({
                "schema": SCHEMA, "scenario": scenario if row is None else row["row_id"],
                "shared_product_flow_sha256": digest(reports), "source_dependencies": self.source_bindings,
                "accepted_input_identity": list(INPUT_IDENTITY),
                "source_snapshot_sha256": metadata["source_snapshot_sha256"],
                "source_removed": not self.source.exists(),
                "expected_manifest_sha256": digest(self.expected), "reports": reports,
                "dependency_outcomes": dependencies, "install_outcomes": metadata["install_outcomes"],
                "checker_outcome": self.summary(check), "retained_artifacts": metadata["retention"],
            }, sys.stdout)

    def test_installed_reader_lifecycle_without_source(self):
        self.assertEqual(self.install.leftovers(), [])
        shared = RestoredInstalledRows(self, self._lifecycle_metadata)
        shared.exercise_rollbacks()
        shared.retain()
        with self.subTest(rows=("fresh", "activation-rollback", "term-rollback")):
            self.finish_scenario("fresh", rows=shared.rows)
        with self.subTest(row="replacement"):
            self.replacement_case.replacement_row()

    def replacement_row(self):
        previous = fixture.snapshot(self.install.target)
        self.expected = self.prepare_replacement()
        self.install_image()
        backups = sorted(self.install.backups.glob(f"{fixture.SKILL}.prev.*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(fixture.snapshot(backups[0]) == previous, "EXAMPLE reliability replacement backup differs")
        self.assertEqual(list(self.install.skills.glob(f".{fixture.SKILL}.stage.*")), [])
        self.finish_scenario("replacement", {"backup": {"path": str(backups[0]), "snapshot_sha256": digest(fixture.snapshot(backups[0])),
                                                       "record": identity(backups[0] / RECORD), "security": identity(backups[0] / "SECURITY.md")}})

    def rollback(self, mode):
        previous = fixture.snapshot(self.install.target)
        replacement = self.prepare_replacement()
        source_before = fixture.snapshot(self.source)
        witness, event = self.area / ("EXAMPLE-witness-" + mode), self.area / ("EXAMPLE-event-" + mode)
        shim = self.install.shims / "mv"
        self.addCleanup(shim.unlink, missing_ok=True)
        self.install.write_shim("mv", rollback_fixture.MV_SHIM)
        try:
            result = self.run_install(CWO_TEST_INTERRUPT=mode, CWO_TEST_TARGET=str(self.install.target),
                                      CWO_TEST_SKILLS=str(self.install.skills), CWO_TEST_BACKUPS=str(self.install.backups),
                                      CWO_TEST_SKILL=fixture.SKILL, CWO_TEST_WITNESS=str(witness), CWO_TEST_EVENT=str(event))
        finally:
            shim.unlink(missing_ok=True)
        if mode == "term":
            self.assertEqual(result.returncode, 143, self.summary(result))
        else:
            self.assertNotEqual(result.returncode, 0, self.summary(result))
            self.assertTrue("could not activate staged install" in result.stderr, "EXAMPLE reliability activation refusal is missing")
        self.assertTrue(f"Restored the previous install at {self.install.target}" in result.stderr.splitlines(), "EXAMPLE reliability restoration message is missing")
        self.assertTrue(fixture.snapshot(self.install.target) == previous, "EXAMPLE reliability restored bytes or modes differ")
        self.assertTrue(fixture.snapshot(self.source) == source_before, "EXAMPLE reliability source image differs")
        self.assertEqual(self.install.leftovers(), [])
        stage, backup = (Path(line) for line in event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assertFalse(stage.exists() or backup.exists())
        self.assert_image(witness, replacement)
        self.assert_image(self.install.target, self.expected)
        self.retention = {
            "outcome": self.summary(result), "restored_snapshot_sha256": digest(previous),
            "source_snapshot_sha256": digest(source_before), "stage_path": str(stage), "backup_path": str(backup),
            "stage_retained": stage.exists(), "backup_retained": backup.exists(), "event": identity(event),
            "witness": {"path": str(witness), "snapshot_sha256": digest(fixture.snapshot(witness)),
                        "manifest_sha256": digest(fixture.checker.build_manifest(witness)),
                        "record": identity(witness / RECORD), "security": identity(witness / "SECURITY.md")},
        }


class InstalledServerFrameEvidenceControls(unittest.TestCase):
    def child_invoke(self):
        tree = ast.parse(PROBE)
        declarations = [
            node for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
        ]
        namespace = {"prep": source_fixture.prep, "frames": source_fixture.frames,
                     "inputs": {}, "flags": FLAGS}
        exec(compile(ast.Module(body=declarations, type_ignores=[]),
                     "EXAMPLE installed reliability declarations", "exec"), namespace)
        return namespace["invoke"]

    def context_consumer(self):
        consumer = source_fixture.prep.FakeRequestPreparer(
            EPOCH, allowed_paths=("/EXAMPLE/file",), timeout_ms=10)
        consumer.open_turn("EXAMPLE-thread", "EXAMPLE-turn", now=0)
        return consumer

    def test_installed_checker_bootstrap_preserves_arguments_and_exit(self):
        import runpy

        scripts = "/EXAMPLE/installed/scripts"
        arguments = ["--record-check", "--installed-dir", "/EXAMPLE/installed", "--json"]
        for code in (0, 1, 2):
            with self.subTest(returncode=code):
                error = SystemExit(code)
                with patch.object(sys, "argv", ["-c", scripts, *arguments]), \
                        patch.object(sys, "path", ["/EXAMPLE/stdlib"]), \
                        patch.object(runpy, "run_module", side_effect=error) as run:
                    with self.assertRaises(SystemExit) as caught:
                        exec(CHECKER_BOOTSTRAP, {})
                    self.assertIs(caught.exception, error)
                    self.assertEqual(sys.argv, ["-c", *arguments])
                    self.assertEqual(sys.path, [scripts, "/EXAMPLE/stdlib"])
                    run.assert_called_once_with("check_installed_skill", run_name="__main__")

    def test_literal_child_context_round_trip_uses_real_native_consumer(self):
        invoke = self.child_invoke()
        for method in (COMMAND, FILE, PERMISSIONS):
            with self.subTest(method=method):
                native = source_fixture.context(method, approval_id="EXAMPLE-approval")
                self.assertIs(type(native.paths), tuple)
                genuine = self.context_consumer()
                genuine.observe_item(native, now=0)
                values = asdict(native)
                values.pop("provenance")
                command = json.loads(canonical(
                    step("consumer", "observe_item", context=values, now=0)[0]))
                self.assertIs(type(command["context"]["paths"]), list)
                before = canonical(command)
                consumer = self.context_consumer()
                self.assertIsNone(invoke(command, consumer, {}, {}))
                self.assertEqual(consumer._items, genuine._items)
                restored, = consumer._items.values()
                self.assertIs(type(restored.paths), tuple)
                self.assertEqual(restored, native)
                self.assertEqual(canonical(command), before)

    def test_literal_child_rejects_malformed_context_paths(self):
        invoke = self.child_invoke()
        cases = (
            ("string", "/EXAMPLE/file"),
            ("mapping", {"/EXAMPLE/file": True}),
            ("boolean", True),
            ("null", None),
            ("native-tuple", ("/EXAMPLE/file",)),
            ("boolean-member", [True]),
            ("mixed-member", ["/EXAMPLE/file", 1]),
            ("nested-member", [["/EXAMPLE/file"]]),
        )
        for label, paths in cases:
            with self.subTest(case=label):
                command = json.loads(canonical(register(FILE)[1][0]))
                command["context"]["paths"] = paths
                consumer = self.context_consumer()
                with self.assertRaisesRegex(
                        ValueError, "^EXAMPLE reliability context paths must be a list of strings$"):
                    invoke(command, consumer, {}, {})
                self.assertEqual(consumer._items, {})
        command = json.loads(canonical(register(FILE)[1][0]))
        command["context"]["paths"] = ["EXAMPLE-relative"]
        consumer = self.context_consumer()
        with self.assertRaisesRegex(source_fixture.prep.PreparationError, "^item-paths-or-kind$"):
            invoke(command, consumer, {}, {})
        self.assertEqual(consumer._items, {})

    def test_literal_child_rejects_malformed_context_objects(self):
        invoke = self.child_invoke()
        for label, context in (("string", "EXAMPLE invalid context"), ("list", []),
                               ("boolean", True), ("null", None)):
            with self.subTest(case=label):
                command = json.loads(canonical(register()[1][0]))
                command["context"] = context
                consumer = self.context_consumer()
                with self.assertRaisesRegex(
                        ValueError, "^EXAMPLE reliability context must be an object$"):
                    invoke(command, consumer, {}, {})
                self.assertEqual(consumer._items, {})

    def test_literal_child_keeps_context_fields_closed(self):
        invoke = self.child_invoke()
        for field, error in (("paths", ValueError), ("epoch", TypeError), ("EXAMPLE-extra", TypeError)):
            with self.subTest(field=field):
                command = json.loads(canonical(register()[1][0]))
                context = command["context"]
                if field == "EXAMPLE-extra":
                    context[field] = "EXAMPLE invalid field"
                else:
                    context.pop(field)
                consumer = self.context_consumer()
                with self.assertRaises(error):
                    invoke(command, consumer, {}, {})
                self.assertEqual(consumer._items, {})

    def test_parent_timeouts_are_bounded_and_keep_failure_phase(self):
        secret = "EXAMPLE private command and captured reliability text"
        for phase in ("install", "installed-check", "reader-main"):
            with self.subTest(phase=phase):
                error = subprocess.TimeoutExpired(secret, 1, output=secret, stderr=secret)
                with patch.object(subprocess, "run", side_effect=error):
                    with self.assertRaises(PhaseDeadline) as caught:
                        bounded_run(phase, [secret], timeout=1)
                report = caught.exception.report
                self.assertIs(report["ok"], False)
                self.assertEqual((report["phase"], report["type"], report["count"]), (phase, "TimeoutExpired", 1))
                rendered = "".join(traceback.format_exception(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertTrue(secret not in rendered, "EXAMPLE reliability timeout report disclosed captured text")
                self.assertTrue(PREFIX not in rendered, "EXAMPLE reliability timeout emitted a completion marker")
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(bounded_run("EXAMPLE-nonzero", [], timeout=1).returncode, 7)
            run.assert_called_once()
        original = OSError("EXAMPLE unrelated reliability failure")
        with patch.object(subprocess, "run", side_effect=original):
            with self.assertRaises(OSError) as caught:
                bounded_run("EXAMPLE-unrelated", [], timeout=1)
        self.assertIs(caught.exception, original)

    def test_normalized_evidence_survives_private_cleanup(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "EXAMPLE-input.txt"
        path.write_text("EXAMPLE reliability fixture.\n", encoding="utf-8")
        record = {"schema": SCHEMA, "scenario": "EXAMPLE-retention-control", "inputs": [identity(path)],
                  "outcomes": [{"name": "EXAMPLE-retained", "status": "completed", "result_sha256": digest(None)}]}
        stream = io.StringIO()
        retained = retain_record(record, stream)
        temporary.cleanup()
        record["inputs"].clear()
        self.assertFalse(path.exists())
        line = stream.getvalue()
        self.assertEqual(len(line.splitlines()), 1)
        self.assertTrue(line.startswith(PREFIX))
        self.assertEqual(json.loads(line[len(PREFIX):]), retained)
        self.assertEqual(retained["inputs"][0]["path"], str(path))
        self.assertTrue("EXAMPLE reliability fixture." not in line, "EXAMPLE reliability evidence disclosed fixture data")


if __name__ == "__main__":
    unittest.main()
