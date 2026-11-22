"""Transport extraction: old and new import paths, and unchanged wire behavior.

The Codex app-server transport moved from ``scripts/run_native_pool_live_canaries.py``
to ``cwo_core.supervision.transport`` and ``scripts/codex_tool_surface.py`` moved to
``cwo_core.codex_tool_surface``. These tests hold both paths to one set of objects
and drive the moved client against a fake app server over real pipes. No Codex
executable or model is used: the fake is a short Python program, and ``PATH`` is
emptied so a missed patch cannot find a real ``codex``.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import inspect
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import textwrap
import threading
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_native_pool_live_canaries as runner  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture


TRANSPORT_MODULES = {
    "errors": ("AppServerError", "AppServerRpcError", "AmbiguousTurnStartError"),
    "private_io": (
        "_load_owned_regular_bytes",
        "load_private_bytes",
        "load_private_json_snapshot",
        "load_private_json",
        "_private_control_directory",
        "_open_private_control_lock",
        "_fsync_private_control_directory",
        "_fsync_owned_control_directory",
    ),
    "app_server": (
        "AppServer",
        "sha256_bytes",
        "sha256_text",
        "_seal_same_process_proof",
        "_validated_same_process_proof",
        "_canonical_controller_workdir",
    ),
}
TRANSPORT_CONSTANTS = (
    "EXACT_MODEL",
    "THREAD_PHASE_LIVE_CANARY",
    "THREAD_PHASE_PRECOMMIT_FIT",
    "THREAD_START_PHASES",
    "CONTROL_TURN_ID",
    "THREAD_READ_TIMEOUT_SECONDS",
    "AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS",
    "AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS",
)
MOVED_NAMES = frozenset(
    {name for names in TRANSPORT_MODULES.values() for name in names} | set(TRANSPORT_CONSTANTS)
)


def transport(name: str):
    return importlib.import_module(f"cwo_core.supervision.transport.{name}")


def defining_module(name: str):
    """The new module that owns a moved name."""

    for module, names in TRANSPORT_MODULES.items():
        if name in names:
            return transport(module)
    return transport("app_server")


class TransportImportPathTests(unittest.TestCase):
    def test_moved_code_is_defined_in_core(self) -> None:
        for module, names in TRANSPORT_MODULES.items():
            implementation = transport(module)
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(
                        getattr(implementation, name).__module__,
                        f"cwo_core.supervision.transport.{module}",
                    )

    def test_runner_reexports_the_same_objects(self) -> None:
        for name in sorted(MOVED_NAMES):
            with self.subTest(name=name):
                self.assertIs(getattr(runner, name), getattr(defining_module(name), name))

    def test_runner_loaded_from_its_file_shares_the_core_objects(self) -> None:
        # Several suites load the runner by path under their own module name.
        spec = importlib.util.spec_from_file_location(
            "transport_compat_runner_copy", ROOT / "scripts" / "run_native_pool_live_canaries.py"
        )
        assert spec and spec.loader
        copy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(copy)
        for name in sorted(MOVED_NAMES):
            with self.subTest(name=name):
                self.assertIs(getattr(copy, name), getattr(runner, name))
        self.assertTrue(issubclass(copy.LivePoolProtectedFault, transport("errors").AppServerError))

    def test_script_and_core_importers_bind_the_core_objects(self) -> None:
        app_server = transport("app_server")
        errors = transport("errors")
        import check_codex_worker_surface
        import run_native_pool_activation_preview
        from cwo_core import maintenance_native_runtime

        for module in (check_codex_worker_surface, run_native_pool_activation_preview, maintenance_native_runtime):
            with self.subTest(module=module.__name__):
                self.assertIs(module.AppServer, app_server.AppServer)
                self.assertIs(module.AppServerError, errors.AppServerError)
        self.assertIs(maintenance_native_runtime.THREAD_PHASE_PRECOMMIT_FIT, app_server.THREAD_PHASE_PRECOMMIT_FIT)

    def test_codex_tool_surface_old_name_is_the_core_module(self) -> None:
        core = importlib.import_module("cwo_core.codex_tool_surface")
        old = importlib.import_module("codex_tool_surface")
        self.assertIs(old, core)
        self.assertEqual(core.__file__, str(ROOT / "scripts" / "cwo_core" / "codex_tool_surface.py"))
        # A patch through the old name reaches the implementation's globals.
        with mock.patch("codex_tool_surface._codex_binary", return_value=Path("/fixture/codex")):
            self.assertEqual(core._codex_binary(), Path("/fixture/codex"))
        self.assertIs(transport("app_server").require_surface_proof, core.require_surface_proof)

    def test_core_does_not_import_moved_names_from_scripts(self) -> None:
        core = ROOT / "scripts" / "cwo_core"
        offenders: list[str] = []
        for path in sorted(core.rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom) and node.level == 0:
                    if node.module == "run_native_pool_live_canaries":
                        moved = sorted(alias.name for alias in node.names if alias.name in MOVED_NAMES)
                        if moved:
                            offenders.append(f"{relative}: {','.join(moved)} from the runner")
                    if node.module == "codex_tool_surface":
                        offenders.append(f"{relative}: script codex_tool_surface")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in {"run_native_pool_live_canaries", "codex_tool_surface"}:
                            offenders.append(f"{relative}: import {alias.name}")
        self.assertEqual(offenders, [])

    def test_transport_modules_import_only_stdlib_and_core(self) -> None:
        package = ROOT / "scripts" / "cwo_core" / "supervision"
        paths = sorted(package.rglob("*.py")) + [ROOT / "scripts" / "cwo_core" / "codex_tool_surface.py"]
        offenders: list[str] = []
        for path in paths:
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".", 1)[0]
                    if top != "cwo_core" and top != "__future__" and top not in sys.stdlib_module_names:
                        offenders.append(f"{path.relative_to(ROOT).as_posix()}: {name}")
        self.assertEqual(offenders, [])

    def test_f5_held_route_maintenance_code_pins_cover_transport_and_availability(self) -> None:
        from cwo_core import maintenance_qualification

        pinned = set(maintenance_qualification._code_pins())
        for relative in (
            "scripts/codex_tool_surface.py",
            "scripts/run_native_pool_live_canaries.py",
            "scripts/cwo_core/native_live_availability.py",
            "scripts/cwo_core/codex_tool_surface.py",
            "scripts/cwo_core/supervision/__init__.py",
            "scripts/cwo_core/supervision/transport/__init__.py",
            "scripts/cwo_core/supervision/transport/app_server.py",
            "scripts/cwo_core/supervision/transport/errors.py",
            "scripts/cwo_core/supervision/transport/private_io.py",
        ):
            with self.subTest(path=relative):
                self.assertIn(str(ROOT / relative), pinned)

    def test_capacity_source_scan_covers_the_transport(self) -> None:
        import validate_repository

        self.assertIn("scripts/cwo_core/supervision/transport/*.py", validate_repository._CAPACITY_SOURCE_GLOBS)


class AdapterImplementationDigestTests(unittest.TestCase):
    def test_f5_held_route_digest_covers_runner_transport_and_availability(self) -> None:
        self.assertEqual(
            runner.ADAPTER_IMPLEMENTATION_PATHS,
            (
                "scripts/run_native_pool_live_canaries.py",
                "scripts/cwo_core/native_live_availability.py",
                "scripts/cwo_core/supervision/transport/app_server.py",
                "scripts/cwo_core/supervision/transport/errors.py",
                "scripts/cwo_core/supervision/transport/private_io.py",
            ),
        )
        expected = runner.domain_sha256(
            {
                relative: runner.sha256_bytes((ROOT / relative).read_bytes())
                for relative in runner.ADAPTER_IMPLEMENTATION_PATHS
            },
            domain="native-adapter-implementation-sources",
        )
        self.assertEqual(runner.adapter_implementation_sha256(), expected)
        self.assertEqual(runner.capability_certification()["adapter_implementation_sha256"], expected)

    def test_changing_any_adapter_source_changes_the_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copy_root = Path(temporary)
            for relative in runner.ADAPTER_IMPLEMENTATION_PATHS:
                target = copy_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            with mock.patch.object(runner, "ROOT", copy_root):
                baseline = runner.adapter_implementation_sha256()
                self.assertEqual(baseline, runner.adapter_implementation_sha256())
                for relative in runner.ADAPTER_IMPLEMENTATION_PATHS:
                    with self.subTest(path=relative):
                        target = copy_root / relative
                        original = target.read_bytes()
                        target.write_bytes(original + b"\n# changed\n")
                        try:
                            self.assertNotEqual(runner.adapter_implementation_sha256(), baseline)
                        finally:
                            target.write_bytes(original)
                self.assertEqual(runner.adapter_implementation_sha256(), baseline)


MOVED_SOURCE_PATHS = (
    "scripts/codex_tool_surface.py",
    "scripts/cwo_core/codex_tool_surface.py",
    "scripts/cwo_core/supervision/__init__.py",
    "scripts/cwo_core/supervision/transport/__init__.py",
    "scripts/cwo_core/supervision/transport/app_server.py",
    "scripts/cwo_core/supervision/transport/errors.py",
    "scripts/cwo_core/supervision/transport/private_io.py",
)


def git(root: Path, *args: str) -> str:
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    completed = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True, env=environment
    )
    return completed.stdout.strip()


class ValidatorContractV7Tests(unittest.TestCase):
    """Future frozen-contract digests bind the moved transport through V7.

    V1 to V6 are unchanged; their digests over historical trees are pinned by
    ``tests/test_w20_affected_contract_w13.py``.
    """

    def setUp(self) -> None:
        self.contracts = importlib.import_module("cwo_core.native_live_campaign_contracts")

    def frozen_lists(self) -> dict[str, tuple[str, ...]]:
        return {
            f"v{n}": getattr(self.contracts, f"VALIDATOR_CONTRACT_PATHS_V{n}") for n in range(1, 7)
        }

    def test_v7_is_v6_plus_the_moved_sources(self) -> None:
        v6 = self.contracts.VALIDATOR_CONTRACT_PATHS_V6
        v7 = self.contracts.VALIDATOR_CONTRACT_PATHS_V7
        self.assertEqual(v7[: len(v6)], v6)
        self.assertEqual(v7[len(v6):], MOVED_SOURCE_PATHS)
        self.assertEqual(len(set(v7)), len(v7))
        self.assertIn("scripts/run_native_pool_live_canaries.py", v7)
        for version, paths in self.frozen_lists().items():
            with self.subTest(frozen=version):
                self.assertEqual(set(paths) & set(MOVED_SOURCE_PATHS), set())

    def test_v7_binds_every_file_that_defines_moved_code(self) -> None:
        v7 = set(self.contracts.VALIDATOR_CONTRACT_PATHS_V7)
        core_tool_surface = importlib.import_module("cwo_core.codex_tool_surface")
        defining_files = {
            Path(inspect.getsourcefile(transport("app_server").AppServer)),
            Path(inspect.getsourcefile(transport("errors").AppServerError)),
            Path(inspect.getsourcefile(transport("private_io").load_private_bytes)),
            Path(core_tool_surface.__file__),
            ROOT / "scripts" / "codex_tool_surface.py",
            ROOT / "scripts" / "run_native_pool_live_canaries.py",
        }
        supervision = ROOT / "scripts" / "cwo_core" / "supervision"
        # V7 freezes the transport extraction, not every future sibling module.
        defining_files.add(supervision / "__init__.py")
        defining_files |= set((supervision / "transport").rglob("*.py"))
        for path in sorted(defining_files):
            relative = path.resolve().relative_to(ROOT).as_posix()
            with self.subTest(path=relative):
                self.assertIn(relative, v7)

    def payload(self, digest, root: Path, tree: str) -> tuple[str, dict]:
        """The digest and the canonical payload it was computed over."""

        with mock.patch.object(
            self.contracts, "canonical_sha256", wraps=self.contracts.canonical_sha256
        ) as spy:
            value = digest(root, tree)
        self.assertEqual(spy.call_count, 1)
        return value, spy.call_args.args[0]

    def test_new_sibling_is_bound_by_tree_without_rewriting_historical_paths(self) -> None:
        digest = self.contracts.validator_contract_sha256_v7
        paths = self.contracts.VALIDATOR_CONTRACT_PATHS_V7
        sibling = "scripts/cwo_core/supervision/turn_observations.py"
        self.assertNotIn(sibling, paths)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, "init", "-q")
            configure_git_fixture(root)
            for relative in paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            git(root, "add", "--", *paths)
            original_tree = git(root, "write-tree")
            original_digest, original_payload = self.payload(digest, root, original_tree)
            target = root / sibling
            target.write_bytes((ROOT / sibling).read_bytes())
            git(root, "add", "--", sibling)
            added_tree = git(root, "write-tree")
            added_digest, added_payload = self.payload(digest, root, added_tree)
            self.assertNotEqual(added_tree, original_tree)
            self.assertNotEqual(added_digest, original_digest)
            self.assertEqual(added_payload["files"], original_payload["files"])
            self.assertEqual(self.contracts.VALIDATOR_CONTRACT_PATHS_V7, paths)
            target.write_bytes(target.read_bytes() + b"\n# changed sibling\n")
            git(root, "add", "--", sibling)
            changed_tree = git(root, "write-tree")
            changed_digest, changed_payload = self.payload(digest, root, changed_tree)
            self.assertNotEqual(changed_tree, added_tree)
            self.assertNotEqual(changed_digest, added_digest)
            self.assertEqual(changed_payload["files"], original_payload["files"])
            # Reading an old checkpoint remains deterministic after later edits.
            self.assertEqual(digest(root, original_tree), original_digest)

    def test_changing_a_moved_source_changes_the_v7_digest(self) -> None:
        # Every Vn payload carries the checkpoint tree id, so any change to the
        # tree changes every digest. What V7 adds is each moved file's own blob
        # sha256 in its file list, and a refusal when one is missing.
        v6_digest = self.contracts.validator_contract_sha256_v6
        v7_digest = self.contracts.validator_contract_sha256_v7
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, "init", "-q")
            configure_git_fixture(root)
            for relative in self.contracts.VALIDATOR_CONTRACT_PATHS_V7:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            git(root, "add", "--", *self.contracts.VALIDATOR_CONTRACT_PATHS_V7)
            tree = git(root, "write-tree")
            baseline_v7, payload_v7 = self.payload(v7_digest, root, tree)
            baseline_v6, payload_v6 = self.payload(v6_digest, root, tree)
            self.assertNotEqual(baseline_v7, baseline_v6)
            self.assertEqual(payload_v7["contract"], "cwo-live-successor-validator:v7")
            self.assertEqual(
                [entry["path"] for entry in payload_v7["files"]],
                list(self.contracts.VALIDATOR_CONTRACT_PATHS_V7),
            )
            self.assertEqual(
                {k: v for k, v in payload_v7.items() if k not in {"contract", "files"}},
                {k: v for k, v in payload_v6.items() if k not in {"contract", "files"}},
            )
            for relative in (*MOVED_SOURCE_PATHS, "scripts/run_native_pool_live_canaries.py"):
                with self.subTest(path=relative):
                    target = root / relative
                    original = target.read_bytes()
                    changed_bytes = original + b"\n# changed\n"
                    target.write_bytes(changed_bytes)
                    git(root, "add", "--", relative)
                    changed = git(root, "write-tree")
                    try:
                        value_v7, changed_v7 = self.payload(v7_digest, root, changed)
                        self.assertNotEqual(value_v7, baseline_v7)
                        bound = {entry["path"]: entry["sha256"] for entry in changed_v7["files"]}
                        self.assertEqual(bound[relative], hashlib.sha256(changed_bytes).hexdigest())
                        _value_v6, changed_v6 = self.payload(v6_digest, root, changed)
                        bound_v6 = {entry["path"]: entry["sha256"] for entry in changed_v6["files"]}
                        if relative in MOVED_SOURCE_PATHS:
                            # V6's file list cannot see the move; this is why V7 exists.
                            self.assertNotIn(relative, bound_v6)
                        else:
                            self.assertEqual(bound_v6[relative], hashlib.sha256(changed_bytes).hexdigest())
                    finally:
                        target.write_bytes(original)
                        git(root, "add", "--", relative)
            self.assertEqual(git(root, "write-tree"), tree)
            self.assertEqual(v7_digest(root, tree), baseline_v7)
            for relative in MOVED_SOURCE_PATHS:
                with self.subTest(missing=relative):
                    git(root, "rm", "-q", "--cached", "--", relative)
                    missing = git(root, "write-tree")
                    try:
                        with self.assertRaisesRegex(
                            ValueError, "^validator-contract-path-invalid:" + re.escape(relative) + "$"
                        ):
                            v7_digest(root, missing)
                        self.assertRegex(v6_digest(root, missing), r"^[0-9a-f]{64}$")
                    finally:
                        git(root, "add", "--", relative)
            self.assertEqual(git(root, "write-tree"), tree)

    def test_v7_reproduces_on_the_candidate_tree_and_refuses_pre_move_trees(self) -> None:
        tree = git(ROOT, "rev-parse", "HEAD^{tree}")
        digest = self.contracts.validator_contract_sha256_v7(ROOT, tree)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(self.contracts.validator_contract_sha256_v7(ROOT, tree), digest)
        from tests.historical_policy_fixtures import portable_repository
        fixture = portable_repository()
        with self.assertRaisesRegex(
            ValueError, r"^validator-contract-path-invalid:scripts/cwo_core/codex_tool_surface\.py$"
        ):
            self.contracts.validator_contract_sha256_v7(fixture.root, fixture.trees["baseline"])


class CoreContractCoversSubpackagesTests(unittest.TestCase):
    def run_contract(self, files: dict[str, str]) -> list[str]:
        import validate_repository

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tests").mkdir()
            for relative, text in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            errors: list[str] = []
            with mock.patch.object(validate_repository, "REPO_ROOT", root):
                validate_repository.validate_cwo_core_contract(errors)
        return [error for error in errors if not error.startswith("missing cwo_core module:")]

    def tree(self, app_server: str, **extra: str) -> dict[str, str]:
        files = {
            "scripts/cwo_core/__init__.py": "",
            "scripts/cwo_core/supervision/__init__.py": "",
            "scripts/cwo_core/supervision/transport/__init__.py": "",
            "scripts/cwo_core/supervision/transport/errors.py": "",
            "scripts/cwo_core/supervision/transport/app_server.py": app_server,
        }
        files.update(extra)
        return files

    def test_allowed_subpackage_imports_pass(self) -> None:
        source = (
            "from cwo_core.native_turn_dispatch import validate_turn_dispatch_record\n"
            "from cwo_core.supervision.transport.errors import AppServerError\n"
        )
        self.assertEqual(self.run_contract(self.tree(source)), [])

    def test_disallowed_import_from_a_subpackage_module_is_reported(self) -> None:
        for source in (
            "from cwo_core.routing import classify_work\n",
            "from ...routing import classify_work\n",
            "import cwo_core.routing\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    self.run_contract(self.tree(source)),
                    ["cwo_core dependency violation: supervision.transport.app_server imports routing"],
                )

    def test_unlisted_subpackage_module_is_reported(self) -> None:
        errors = self.run_contract(self.tree("", **{"scripts/cwo_core/supervision/rogue.py": ""}))
        self.assertEqual(errors, ["unexpected cwo_core module: scripts/cwo_core/supervision/rogue.py"])

    def test_relative_import_above_core_is_reported(self) -> None:
        errors = self.run_contract(self.tree("from .... import paths\n"))
        self.assertEqual(
            errors,
            ["cwo_core dependency violation: supervision.transport.app_server imports <outside cwo_core>"],
        )


FAKE_APP_SERVER = textwrap.dedent(
    """
    import json, os, sys, time

    mode = os.environ["CWO_FAKE_APP_SERVER_MODE"]
    log = open(os.environ["CWO_FAKE_APP_SERVER_LOG"], "a", encoding="utf-8")

    def send(message):
        sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\\n")
        sys.stdout.flush()

    for raw in sys.stdin:
        log.write(raw)
        log.flush()
        message = json.loads(raw)
        if message.get("method") == "initialized":
            with open(log.name + ".initialized-consumed", "x"):
                pass
        if message.get("method") == "initialized" and mode in {"unread-stdin", "request-during-write"}:
            time.sleep(0.05)
            if mode == "request-during-write":
                send({"id": "900", "method": "item/commandExecution/requestApproval", "params": {}})
            else:
                send({"method": "progress", "params": {"threadId": "thread-1", "value": 1}})
            time.sleep(30)
        if "id" not in message or "method" not in message:
            continue  # notifications and client responses get no answer
        request_id = message["id"]
        if message.get("method") == "initialize":
            send({"id": request_id, "result": {"codexHome": os.environ["CODEX_HOME"]}})
            if os.environ["CWO_FAKE_APP_SERVER_DELAY_INITIALIZED"] == "1":
                with open(log.name + ".initialized-waiting", "x"):
                    pass
                deadline = time.monotonic() + 5
                while not os.path.exists(log.name + ".release-initialized"):
                    if time.monotonic() >= deadline:
                        sys.exit(4)
                    time.sleep(0.005)
        elif mode.startswith("oversized"):
            text = "é" * 600 if mode == "oversized-multibyte" else "x" * 1100
            raw = json.dumps({"method": "progress", "params": {"text": text}}, ensure_ascii=False)
            sys.stdout.write(raw + ("" if mode == "oversized-unterminated" else "\\n"))
            sys.stdout.flush()
            if mode == "oversized-unterminated":
                time.sleep(30)
            send({"id": request_id, "result": {"echo": message["method"]}})
        elif mode in {"response-count", "response-bytes", "notification-count", "notification-bytes", "ordinary-events"}:
            count = 40 if mode.endswith("count") else 5
            for index in range(count):
                params = {"threadId": "thread-1", "turnId": "turn-1", "value": index}
                if mode.endswith("bytes"):
                    params["text"] = "é" * 440
                if mode.startswith("response"):
                    send({"id": 900 + index, "result": params})
                else:
                    send({"method": "progress", "params": params})
            send({"id": request_id, "result": {"echo": message["method"]}})
        elif mode.startswith("required-"):
            methods = {
                "command": "item/commandExecution/requestApproval",
                "file": "item/fileChange/requestApproval",
                "permissions": "item/permissions/requestApproval",
                "unknown": "future/required",
            }
            kind = mode.removeprefix("required-")
            send({"id": "900" if kind in {"file", "unknown"} else 900,
                  "method": methods[kind],
                  "params": {"threadId": "thread-1", "turnId": "turn-1", "itemId": "item-1"}})
            send({"id": request_id, "result": {"echo": message["method"]}})
        elif mode == "partial-eof":
            sys.stdout.write('{"method":"progress"')
            sys.stdout.flush()
            # Isolate stream EOF from process exit; the original reader refusal
            # and close() still own termination and reaping of this child.
            os.close(sys.stdout.fileno())
            sys.stderr.write("partial-eof-stdout-closed\\n")
            sys.stderr.flush()
            sys.stdin.read()
        elif mode == "timeout":
            continue
        elif mode == "duplicate-key":
            sys.stdout.write('{"id":900,"id":"900","method":"future/required","params":{}}\\n')
            sys.stdout.flush()
            send({"id": request_id, "result": {"echo": message["method"]}})
        elif mode == "ok":
            send({"id": request_id, "result": {"echo": message["method"], "params": message["params"]}})
        elif mode == "server-request":
            send({
                "id": 900,
                "method": "item/commandExecution/requestApproval",
                "params": {"threadId": "thread-1", "turnId": "turn-1", "itemId": "item-1"},
            })
            send({"id": request_id, "result": {"echo": message["method"]}})
        elif mode == "rpc-error":
            send({"id": request_id, "error": {"code": -32603, "message": "internal"}})
        elif mode == "error-code-string":
            send({"id": request_id, "error": {"code": "-32603", "message": "internal"}})
        elif mode == "error-message-missing":
            send({"id": request_id, "error": {"code": -32603}})
        elif mode == "error-not-object":
            send({"id": request_id, "error": "internal"})
        elif mode == "result-and-error":
            send({"id": request_id, "result": {}, "error": {"code": -32603, "message": "internal"}})
        elif mode == "result-not-object":
            send({"id": request_id, "result": ["not", "an", "object"]})
        elif mode == "non-json":
            sys.stdout.write("this is not json\\n")
            sys.stdout.flush()
        elif mode == "non-object":
            send(["not", "an", "object"])
        elif mode == "exit":
            sys.exit(3)
    """
)


class RecordingPipe:
    """Controller side of the child's stdin: records each line the client writes."""

    def __init__(self, stream) -> None:
        self._stream = stream
        self.written: list[str] = []

    def write(self, data: str) -> int:
        self.written.append(data)
        return self._stream.write(data)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


class FakeAppServerTransportTests(unittest.TestCase):
    """The moved client behaves as before, through the old and the new import path."""

    def setUp(self) -> None:
        # One transcript per import path, so each path is asserted on its own.
        self.enterContext(mock.patch.object(transport('app_server').live_availability, 'N1_LIVE_AVAILABLE', True))
        self.transcripts: dict[str, dict[str, list]] = {}

    def import_paths(self) -> list[tuple[str, type]]:
        paths: list[tuple[str, type]] = [("runner", runner.AppServer)]
        try:
            paths.append(("core", transport("app_server").AppServer))
        except ModuleNotFoundError as exc:
            paths.append(("core", exc))  # type: ignore[arg-type]
        return paths

    def run_mode(self, mode: str, check, *, delay_initialized: bool = False) -> None:
        for label, server_class in self.import_paths():
            with self.subTest(import_path=label, mode=mode):
                if isinstance(server_class, Exception):
                    raise server_class
                self.exercise(label, server_class, mode, check, delay_initialized=delay_initialized)

    def _wait_for_child_marker(self, server, path: Path) -> None:
        deadline = time.monotonic() + 5
        while not path.exists():
            self.assertIsNone(server.process.poll(), "fake child exited before initialized consumption")
            self.assertLess(time.monotonic(), deadline, "fake child initialization barrier timed out")
            time.sleep(0.005)

    def _await_initialized_consumption(self, server, log: Path, delayed: bool) -> None:
        if delayed:
            self._wait_for_child_marker(server, Path(str(log) + ".initialized-waiting"))
            received = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([message["method"] for message in received], ["initialize"])
            Path(str(log) + ".release-initialized").touch()
        self._wait_for_child_marker(server, Path(str(log) + ".initialized-consumed"))
        received = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(received[1], {"method": "initialized", "params": {}})

    def exercise(self, label: str, server_class: type, mode: str, check, *, delay_initialized: bool = False) -> None:
        """Bind both launch paths to this disposable fake executable and home."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "codex-home"
            home.mkdir()
            empty_path = root / "empty-path"
            empty_path.mkdir()
            fake = root / "fake-app-server"
            fake.write_text(f"#!{sys.executable}\n{FAKE_APP_SERVER}", encoding="utf-8")
            fake.chmod(0o700)
            log = root / "received.jsonl"
            environment = {
                "CODEX_HOME": str(home),
                "CWO_FAKE_APP_SERVER_MODE": mode,
                "CWO_FAKE_APP_SERVER_LOG": str(log),
                "CWO_FAKE_APP_SERVER_DELAY_INITIALIZED": "1" if delay_initialized else "0",
                "PATH": str(empty_path),
            }
            defining = sys.modules[server_class.__module__]
            with mock.patch.dict(os.environ, environment), mock.patch.object(
                defining, "_codex_binary", return_value=fake
            ), mock.patch.object(defining, "check_codex_capabilities") as capability_check:
                server = server_class(requested_model="gpt-5.6-luna", executable=fake, codex_home=home)
                capability_check.assert_called_once_with(str(fake))
                # Every write after the handshake goes through this pipe, so a reply
                # the client sent is recorded even if the child never reads it.
                pipe = RecordingPipe(server.process.stdin)
                server.process.stdin = pipe
                cleanup_error = None
                raw_write = os.write
                def record_write(fd, data):
                    count = raw_write(fd, data)
                    if fd == pipe.fileno():
                        pipe.written.append(data[:count].decode("utf-8"))
                    return count
                recorder = mock.patch.object(defining.os, "write", side_effect=record_write)
                recorder.start()
                try:
                    self._await_initialized_consumption(server, log, delay_initialized)
                    self.assertEqual(server.launched_executable, str(fake))
                    self.assertEqual(server.codex_home, home)
                    check(server, defining)
                finally:
                    try:
                        cleanup = server.close()
                    except defining.AppServerError as exc:
                        cleanup_error = exc
                        cleanup = getattr(exc, "app_server_cleanup", None)
                    recorder.stop()
                    transcript = {
                        "received": [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()],
                        "written": [json.loads(line) for line in "".join(pipe.written).splitlines(keepends=True) if line.endswith("\n")],
                    }
            # Observation has finished only after a clean close: close() returned,
            # every resource is closed and contained, and cleanup reported no error.
            # A transcript taken after a failed cleanup is not accepted.
            self.assertIsNone(cleanup_error, cleanup)
            self.assertIsInstance(cleanup, dict)
            self.assertIs(cleanup.get("all_contained"), True, cleanup)
            self.assertIs(cleanup.get("resources_closed"), True, cleanup)
            self.assertEqual(cleanup.get("errors"), [], cleanup)
            self.transcripts[label] = transcript
            received = transcript["received"]
            self.assertEqual(received[0]["method"], "initialize")
            self.assertEqual(received[0]["params"]["clientInfo"]["name"], "cwo-supervisor-concurrency-canary")
            self.assertEqual(received[1], {"method": "initialized", "params": {}})

    def test_request_returns_the_correlated_result(self) -> None:
        def check(server, defining) -> None:
            result, latency_ms = server.request("fake/echo", {"value": 1}, timeout=10)
            self.assertEqual(result, {"echo": "fake/echo", "params": {"value": 1}})
            self.assertGreaterEqual(latency_ms, 0)
            self.assertEqual(len(server.rpc_latencies["fake/echo"]), 1)

        self.run_mode("ok", check)
        for label, transcript in self.transcripts.items():
            with self.subTest(import_path=label):
                self.assertEqual(transcript["received"][2], {"id": 2, "method": "fake/echo", "params": {"value": 1}})
                self.assertEqual(transcript["written"], [{"id": 2, "method": "fake/echo", "params": {"value": 1}}])

    def test_error_response_is_a_correlated_rpc_error(self) -> None:
        def check(server, defining) -> None:
            with self.assertRaises(defining.AppServerRpcError) as caught:
                server.request("fake/echo", {}, timeout=10)
            self.assertEqual((caught.exception.method, caught.exception.code, caught.exception.request_id),
                             ("fake/echo", -32603, 2))

        self.run_mode("rpc-error", check)

    def test_malformed_responses_are_refused(self) -> None:
        expected = {
            "error-code-string": "app-server-error-response-invalid:fake/echo",
            "error-message-missing": "app-server-error-response-invalid:fake/echo",
            "error-not-object": "app-server-error-response-invalid:fake/echo",
            "result-and-error": "app-server-error-response-invalid:fake/echo",
            "result-not-object": "app-server-result-invalid:fake/echo",
            "non-json": "app-server-non-json-output",
            "non-object": "app-server-non-object-output",
        }
        for mode, message in expected.items():
            def check(server, defining, message=message) -> None:
                with self.assertRaises(defining.AppServerError) as caught:
                    server.request("fake/echo", {}, timeout=10)
                self.assertNotIsInstance(caught.exception, defining.AppServerRpcError)
                self.assertEqual(str(caught.exception), message)

            self.run_mode(mode, check)

    def test_server_exit_is_refused(self) -> None:
        def check(server, defining) -> None:
            with self.assertRaisesRegex(
                defining.AppServerError, r"^app-server-(exited:fake/echo:3|output-closed)$"
            ):
                server.request("fake/echo", {}, timeout=10)

        self.run_mode("exit", check)

    def assert_bounded_refusal(self, server, defining, reason: str) -> None:
        epoch = server.connection_epoch_sha256
        started = time.monotonic()
        with self.assertRaisesRegex(defining.AppServerError, "^" + reason + "$"):
            server.request("fake/echo", {}, timeout=2)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(server.connection_epoch_sha256, epoch)
        with self.assertRaisesRegex(defining.AppServerError, "^" + reason + "$"):
            server.request("fake/after-fault", {}, timeout=2)
        cleanup = server.close()
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(cleanup["all_contained"])
        self.assertFalse(any(reader.is_alive() for reader in server._reader_threads))

    def bounded_modes(self, modes, reason: str) -> None:
        defining = transport("app_server")
        with mock.patch.multiple(defining, create=True, MAX_FRAME_BYTES=1024,
                                 MAX_RESPONSES=32, MAX_RESPONSE_BYTES=4096,
                                 MAX_NOTIFICATIONS=32, MAX_NOTIFICATION_BYTES=4096):
            for mode in modes:
                self.run_mode(mode, lambda server, module: self.assert_bounded_refusal(server, module, reason))

    def test_raw_frame_byte_limit_refuses_newline_and_unterminated_input(self) -> None:
        self.bounded_modes(["oversized", "oversized-unterminated", "oversized-multibyte"],
                           "app-server-frame-size-limit")

    def test_response_storage_count_and_byte_limits(self) -> None:
        self.bounded_modes(["response-count", "response-bytes"], "app-server-response-storage-limit")
        for transcript in self.transcripts.values():
            self.assertFalse(any(message.get("method") == "fake/after-fault" for message in transcript["written"]))

    def test_notification_storage_count_and_byte_limits(self) -> None:
        self.bounded_modes(["notification-count", "notification-bytes"], "app-server-notification-storage-limit")

    def test_ordinary_notifications_preserve_sequence_epoch_and_correlated_result(self) -> None:
        def check(server, defining) -> None:
            epoch = server.connection_epoch_sha256
            result, _latency = server.request("fake/echo", {}, timeout=2)
            self.assertEqual(result, {"echo": "fake/echo"})
            self.assertEqual(server.notification_cursor(), 5)
            self.assertEqual(len(server.notifications("thread-1", "progress")), 5)
            events = server.notification_events("thread-1", "turn-1", after_sequence=2)
            self.assertEqual([event["sequence"] for event in events], [3, 4, 5])
            self.assertEqual({event["connection_epoch_sha256"] for event in events}, {epoch})
            self.assertEqual([event["params"]["value"] for event in events], [2, 3, 4])

        self.run_mode("ordinary-events", check)

    def test_unexpected_required_requests_reply_without_grants_then_refuse(self) -> None:
        expectations = {
            "command": {"id": 900, "result": {"decision": "decline"}},
            "file": {"id": "900", "result": {"decision": "decline"}},
            "permissions": {"id": 900, "result": {"permissions": {}}},
            "unknown": {"id": "900", "error": {"code": -32601, "message": "Unsupported server request"}},
        }
        for kind, expected in expectations.items():
            with self.subTest(kind=kind):
                writes = []
                real_write = os.write
                def record_write(fd, data):
                    count = real_write(fd, data)
                    writes.append(data[:count])
                    return count
                with mock.patch.object(transport("app_server").os, "write", side_effect=record_write):
                    self.run_mode("required-" + kind, lambda server, module: self.assert_bounded_refusal(
                        server, module, "app-server-unexpected-server-request"))
                replies = [json.loads(raw) for raw in writes if raw.startswith(b'{"id":') and "method" not in json.loads(raw)]
                self.assertEqual(replies, [expected, expected])

    def test_partial_eof_and_duplicate_keys_are_latched(self) -> None:
        self.bounded_modes(["partial-eof"], "app-server-partial-frame")
        self.bounded_modes(["duplicate-key"], "app-server-duplicate-json-key")

    def test_partial_eof_fixture_keeps_child_until_reader_refusal(self) -> None:
        defining = transport("app_server")
        read_lines, drain_stderr = defining.AppServer._bounded_protocol_lines, defining.AppServer._drain_stderr
        epochs = []
        for label, server_class in self.import_paths():
            with self.subTest(import_path=label):
                partial_seen, stderr_seen, release_reader = (threading.Event() for _ in range(3))
                stderr_chunks = []

                def paused_lines(server):
                    try:
                        yield from read_lines(server)
                    except defining.AppServerError as exc:
                        if str(exc) == "app-server-partial-frame":
                            partial_seen.set()
                            self.assertTrue(release_reader.wait(2), "partial-frame reader was not released")
                        raise

                def observed_stderr(server):
                    stream = server.process.stderr.buffer
                    read = stream.read1
                    def observe(size):
                        data = read(size)
                        stderr_chunks.append(data)
                        if b"\n" in data or not data:
                            stderr_seen.set()
                        return data
                    with mock.patch.object(stream, "read1", side_effect=observe):
                        drain_stderr(server)

                def check(server, module):
                    write, wait = server._write_payload, server._condition.wait
                    epochs.append(server.connection_epoch_sha256)
                    def write_before_reader(*args, **kwargs):
                        deadline = write(*args, **kwargs)
                        self.assertTrue(partial_seen.wait(2), "real partial EOF was not observed")
                        self.assertTrue(stderr_seen.wait(2), "child stdout-close acknowledgment or exit was not observed")
                        if not b"".join(stderr_chunks):
                            # Old fixture: observe its real exit before allowing
                            # request() to poll, while the parser has not latched.
                            server.process.wait(timeout=2)
                        return deadline
                    def wait_after_poll(*args, **kwargs):
                        # request() has polled the retained child alive and is
                        # entering its original condition wait. Let EOF latch.
                        release_reader.set()
                        return wait(*args, **kwargs)
                    try:
                        with mock.patch.object(server, "_write_payload", side_effect=write_before_reader), mock.patch.object(
                            server._condition, "wait", side_effect=wait_after_poll
                        ):
                            self.assert_bounded_refusal(server, module, "app-server-partial-frame")
                        self.assertEqual(b"".join(stderr_chunks), b"partial-eof-stdout-closed\n")
                        self.assertEqual(server._stderr_line_count, 1)
                        self.assertEqual(server._reader_error, "app-server-partial-frame")
                        self.assertFalse(any("fake/after-fault" in line for line in server.process.stdin.written))
                    finally:
                        release_reader.set()

                with mock.patch.object(defining.AppServer, "_bounded_protocol_lines", paused_lines), mock.patch.object(
                    defining.AppServer, "_drain_stderr", observed_stderr
                ):
                    self.exercise(label, server_class, "partial-eof", check)

        def fresh(server, module):
            self.assertNotIn(server.connection_epoch_sha256, epochs)
            self.assertIsNone(server._reader_error)
            self.assertEqual(server.request("fake/echo", {}, timeout=2)[0], {"echo": "fake/echo", "params": {}})
        self.run_mode("ok", fresh)

    def test_stderr_drain_bounds_unterminated_bytes_and_counts_lines(self) -> None:
        class ChunkedStderr:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)
            def __iter__(self):
                raise AssertionError("unbounded stderr iteration")
        for data, count in ((b"ordinary\nsecond\n", 2), (b"x" * 100000, 1),
                            (b"x" * 100000 + b"\nlast", 2)):
            with self.subTest(bytes=len(data)):
                server = object.__new__(runner.AppServer)
                server.process = SimpleNamespace(stderr=ChunkedStderr(data))
                server._stderr_line_count = 0
                server._drain_stderr()
                self.assertEqual(server._stderr_line_count, count)

    def test_unread_outbound_pipe_keeps_reader_responsive_and_refuses(self) -> None:
        def check(server, defining) -> None:
            failures = []
            def call():
                try:
                    server.request("fake/echo", {"text": "x" * 512000}, timeout=0.2)
                except BaseException as exc:
                    failures.append(exc)
            sender = threading.Thread(target=call, daemon=True)
            sender.start()
            sender.join(timeout=0.6)
            self.assertFalse(sender.is_alive(), "outbound write held the request past its deadline")
            self.assertEqual([str(exc) for exc in failures], ["app-server-request-write-timeout:fake/echo"])
            self.assertEqual(len(server._notifications), 1, "reader was held behind the outbound pipe")
            self.assertEqual(server._reader_error, "app-server-request-write-timeout:fake/echo")
        self.run_mode("unread-stdin", check)

    def test_required_request_cannot_insert_reply_into_partial_outbound_frame(self) -> None:
        def check(server, defining) -> None:
            started = time.monotonic()
            with self.assertRaisesRegex(defining.AppServerError, "^app-server-server-request-reply-blocked$"):
                server.request("fake/echo", {"text": "x" * 512000}, timeout=1)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertNotIn("decline", "".join(server.process.stdin.written))
            self.assertEqual(server._reader_error, "app-server-server-request-reply-blocked")
            self.assertFalse(server._wire_writing)
        self.run_mode("request-during-write", check)

    def test_concurrent_multichunk_requests_keep_frames_ids_and_storage_accounting(self) -> None:
        def check(server, defining) -> None:
            results, failures = {}, []
            ready = threading.Barrier(3)
            def call(name):
                ready.wait(timeout=2)
                try:
                    results[name] = server.request("fake/" + name, {"text": name * 16000}, timeout=2)[0]
                except BaseException as exc:
                    failures.append(exc)
            senders = [threading.Thread(target=call, args=(name,), daemon=True) for name in ("one", "two")]
            for sender in senders:
                sender.start()
            ready.wait(timeout=2)
            for sender in senders:
                sender.join(timeout=3)
                self.assertFalse(sender.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(results, {name: {"echo": "fake/" + name, "params": {"text": name * 16000}}
                                       for name in ("one", "two")})
            self.assertEqual(server._responses, {})
            self.assertEqual(server._response_sizes, {})
        self.run_mode("ok", check)
        for transcript in self.transcripts.values():
            self.assertEqual({message["id"] for message in transcript["written"]}, {2, 3})

    def test_hold_recheck_after_partial_notify_refuses_without_completed_frame(self) -> None:
        def check(server, defining) -> None:
            write = os.write
            def revoke(fd, data):
                count = write(fd, data)
                defining.live_availability.N1_LIVE_AVAILABLE = False
                return count
            with mock.patch.object(defining.live_availability, "N1_LIVE_AVAILABLE", True), mock.patch.object(
                defining.os, "write", side_effect=revoke
            ):
                with self.assertRaisesRegex(defining.AppServerError, "^native-n1-live-unavailable$"):
                    server.notify("fake/launch", {"text": "x" * 512000})
            self.assertEqual(server._reader_error, "native-n1-live-unavailable")
            self.assertNotIn("\n", "".join(server.process.stdin.written))
            self.assertFalse(server._wire_writing)
        self.run_mode("unread-stdin", check)

    def test_partial_notify_waits_for_delayed_initialized_consumption(self) -> None:
        run = self.run_mode
        def delayed(mode, check):
            run(mode, check, delay_initialized=True)
        with mock.patch.object(self, "run_mode", side_effect=delayed):
            self.test_hold_recheck_after_partial_notify_refuses_without_completed_frame()

    def test_hold_recheck_after_partial_turn_write_retains_ambiguous_intent(self) -> None:
        from tests.test_run_native_pool_live_canaries import AmbiguousTurnDispatchTests
        fixture = AmbiguousTurnDispatchTests()
        self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, _state, _writer, thread_id, _turns = fixture.server(Path(temporary), "absent")
            read_fd, write_fd = os.pipe()
            self.addCleanup(os.close, read_fd)
            stream = os.fdopen(write_fd, "w")
            self.addCleanup(stream.close)
            server.process.stdin = stream
            write, prefixes = os.write, []
            def revoke(fd, data):
                count = write(fd, data[:7])
                if fd == write_fd:
                    prefixes.append(data[:count])
                    transport("app_server").live_availability.N1_LIVE_AVAILABLE = False
                return count
            with mock.patch.object(transport("app_server").live_availability, "N1_LIVE_AVAILABLE", True), mock.patch.object(
                os, "write", side_effect=revoke
            ):
                with self.assertRaises(runner.AmbiguousTurnStartError) as caught:
                    server.start_turn(thread_id, "Explain the local function.", timeout=0.03, ambiguity_timeout=0)
            self.assertEqual(server._reader_error, "native-n1-live-unavailable")
            record = caught.exception.record
            self.assertEqual((record["status"], record["ledger_resolution"], record["wire_write_attempt_count"]),
                             ("failed-ambiguous", "pending", 1))
            self.assertEqual(ledger.summary()["unresolved_turn_intent_count"], 1)
            self.assertEqual(len(prefixes), 1)
            self.assertNotIn(b"\n", prefixes[0])
            server.process.terminate.assert_called_once()

    def test_faulted_turn_keeps_charge_without_waiting_for_dead_reader(self) -> None:
        from tests.test_run_native_pool_live_canaries import AmbiguousTurnDispatchTests
        fixture = AmbiguousTurnDispatchTests()
        self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory() as temporary:
            server, ledger, _state, writer, thread_id, _turns = fixture.server(Path(temporary), "absent")
            write = writer.write
            def fault(raw):
                result = write(raw)
                server._reader_error = "app-server-frame-size-limit"
                return result
            writer.write = fault

            # The real read preflight refuses before a wire request on this
            # faulted connection. Recovery can still inspect local evidence.
            read_thread = runner.AppServer.read_thread.__get__(server)
            with (
                mock.patch.object(server, "read_thread", read_thread),
                mock.patch.object(server, "contain_ambiguous_turn_dispatch",
                                  wraps=server.contain_ambiguous_turn_dispatch) as contain,
                mock.patch.object(server._condition, "wait",
                                  side_effect=AssertionError("waited for faulted reader")) as response_wait,
                mock.patch.object(time, "sleep",
                                  side_effect=AssertionError("polled faulted reader")) as poll_sleep,
                self.assertRaises(runner.AmbiguousTurnStartError) as caught,
            ):
                server.start_turn(thread_id, "bounded", timeout=1, ambiguity_timeout=0.4)
            contain.assert_called_once_with(thread_id, timeout=0)
            response_wait.assert_not_called()
            poll_sleep.assert_not_called()
            record = caught.exception.record
            self.assertEqual(record["status"], "failed-ambiguous")
            self.assertEqual(record["ledger_resolution"], "pending")
            self.assertEqual(record["query_count"], 0)
            summary = ledger.summary()
            self.assertEqual(summary["turn_intent_count"], 1)
            self.assertEqual(summary["unresolved_turn_intent_count"], 1)
            self.assertEqual([payload["method"] for payload in writer.payloads], ["turn/start"])

    def test_required_request_reply_refuses_pipe_backpressure_without_blocking(self) -> None:
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        stream = os.fdopen(write_fd, "w")
        self.addCleanup(stream.close)
        os.set_blocking(write_fd, False)
        try:
            while True:
                os.write(write_fd, b"x" * 4096)
        except BlockingIOError:
            pass
        os.set_blocking(write_fd, True)
        server = object.__new__(runner.AppServer)
        server.process = SimpleNamespace(stdin=stream)
        started = time.monotonic()
        with self.assertRaisesRegex(runner.AppServerError, "^app-server-server-request-reply-blocked$"):
            server._refuse_server_request({"id": "900", "method": "future/required"})
        self.assertLess(time.monotonic() - started, 0.1)
        self.assertTrue(os.get_blocking(write_fd))

    def test_timeout_still_terminates_cleanly(self) -> None:
        def check(server, defining) -> None:
            started = time.monotonic()
            with self.assertRaisesRegex(defining.AppServerError, "^app-server-request-timeout:fake/echo$"):
                server.request("fake/echo", {}, timeout=0.05)
            self.assertLess(time.monotonic() - started, 1)
        self.run_mode("timeout", check)


if __name__ == "__main__":
    unittest.main()
