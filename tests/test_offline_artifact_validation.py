from __future__ import annotations

import builtins
import copy
import hashlib
import os
import pickle
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import offline_artifact_validation as VALIDATION  # noqa: E402
import offline_n1_host as HOST  # noqa: E402
import test_offline_n1_host as FIXTURE  # noqa: E402
from cwo_core.native_control import NativeControlTurn  # noqa: E402


EXAMPLE_BYTES = b"EXAMPLE_RESULT: independently declared offline bytes\n"
EXAMPLE_PINS = {"w14": "EXAMPLE_CONFIGURATION", "w15": "EXAMPLE_PROFILE"}


def specification(outputs=None, *, text="EXAMPLE_RESULT"):
    outputs = {"result.txt": EXAMPLE_BYTES} if outputs is None else outputs
    entries = []
    for path, data in outputs.items():
        entry = {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "validator": "bytes" if text is None else "utf8-required-text"}
        if text is not None:
            entry["required_text"] = text
        entries.append(entry)
    return {"version": 1, "outputs": entries}


class HostFixture:
    """Compose the existing useful fake producer without inheriting its tests."""

    @staticmethod
    def repository_seed(test):
        owner = type(test)
        if "_artifact_repository_seed" not in owner.__dict__:
            seed = FIXTURE.OfflineN1HostTests(methodName="runTest")
            owner.addClassCleanup(seed.doCleanups)
            seed.setUp()
            owner._artifact_repository_seed = seed
            owner.addClassCleanup(delattr, owner, "_artifact_repository_seed")
        return owner._artifact_repository_seed

    def __init__(self, test):
        self.seed = self.repository_seed(test)
        self.helper = FIXTURE.OfflineN1HostTests(methodName="runTest")
        test.addCleanup(self.helper.doCleanups)
        temporary = tempfile.TemporaryDirectory()
        self.helper.addCleanup(temporary.cleanup)
        self.helper.root = Path(temporary.name).resolve()
        self.helper.source = self.helper.root / "source"
        shutil.copytree(self.seed.source, self.helper.source)

    def ready(self, outputs=None, *, mode="complete", name="host"):
        outputs = {"result.txt": EXAMPLE_BYTES} if outputs is None else outputs
        # The original mutable profile permits one changed file only. Additional
        # inert artifacts start in a genuine common committed baseline.
        extra_paths = [path for path in outputs if path != "result.txt"]
        if extra_paths:
            for path in extra_paths:
                destination = self.helper.source / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(outputs[path])
            self.helper.git(self.helper.source, "add", "--", *extra_paths)
            self.helper.git(self.helper.source, "commit", "--quiet", "-m", "EXAMPLE independently declared inert artifacts")
            self.helper.target = self.helper.clone(name + "-seeded-target")
            self.helper.worker = self.helper.clone(name + "-seeded-worker")
        else:
            # Copy bytes, never hardlink mutable Git objects, indexes or files.
            self.helper.target = Path(shutil.copytree(self.seed.target, self.helper.root / "target"))
            self.helper.worker = Path(shutil.copytree(self.seed.worker, self.helper.root / "worker"))
        case = self.helper.case(name=name, mode=mode)
        host, adapter, server, _control = case
        original = server.record_completed_write

        def write():
            original()
            if "result.txt" in outputs:
                (self.helper.worker / "result.txt").write_bytes(outputs["result.txt"])

        server.record_completed_write = write
        with patch.object(FIXTURE, "OUTPUT", EXAMPLE_BYTES), patch.object(FIXTURE, "PINS", EXAMPLE_PINS):
            report = self.helper.run_case(case, outputs=tuple(outputs))
        return host, report, adapter, server


@contextmanager
def token_registrations():
    """Observe actual issue events without depending on weak-key collection."""
    observed = []
    registry_type = type(VALIDATION._TOKENS)
    original = registry_type.__setitem__

    def registered(registry, token, state):
        if registry is VALIDATION._TOKENS:
            observed.append(token)
        return original(registry, token, state)

    with patch.object(registry_type, "__setitem__", new=registered):
        yield observed


@contextmanager
def stages():
    locations = []
    original = VALIDATION._Stage.__init__

    def observe(stage, host):
        original(stage, host)
        locations.append(Path(stage.scratch.root))

    with patch.object(VALIDATION._Stage, "__init__", observe):
        yield locations


@contextmanager
def effect_guard():
    original_popen, original_import = subprocess.Popen, builtins.__import__
    calls = []
    tails = (
        ["ls-files", "--stage", "-v", "--sparse", "--full-name", "-z"],
        ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--full-name"],
    )

    def capture_only(command, *args, **kwargs):
        executable = HOST.workspace_capture.trusted_git()
        fixed = list(HOST.workspace_capture.INERT_GIT_CONFIG)
        if (not isinstance(command, list) or command[:2] != [executable.path, "-C"]
                or command[3:3 + len(fixed)] != fixed or command[3 + len(fixed):] not in tails):
            raise AssertionError("Only the original capture Git observations are allowed.")
        calls.append(tuple(command))
        return original_popen(command, *args, **kwargs)

    def import_only(name, *args, **kwargs):
        if any(part.lower() in {"beads", "bead"} for part in name.split(".")):
            raise AssertionError("Beads calls are forbidden during offline validation.")
        return original_import(name, *args, **kwargs)

    with ExitStack() as stack:
        stack.enter_context(patch.object(subprocess, "Popen", side_effect=capture_only))
        stack.enter_context(patch.object(subprocess, "run", side_effect=AssertionError("No new command runner is allowed.")))
        stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("Network calls are forbidden.")))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=AssertionError("Network calls are forbidden.")))
        stack.enter_context(patch.object(urllib.request, "urlopen", side_effect=AssertionError("Network calls are forbidden.")))
        stack.enter_context(patch.object(builtins, "__import__", side_effect=import_only))
        yield calls


@contextmanager
def refuse_stage_removal(locations, failure):
    original_rmdir = os.rmdir
    failures = []

    def refuse(path, *, dir_fd=None):
        raw = os.fsdecode(path)
        parent = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) if dir_fd is not None else Path.cwd()
        candidate = Path(raw) if os.path.isabs(raw) else parent / raw
        if candidate in locations:
            failures.append(candidate)
            raise failure
        return original_rmdir(path, dir_fd=dir_fd)

    with patch.object(os, "rmdir", side_effect=refuse):
        yield failures


class DirectoryInventoryTests(unittest.TestCase):
    def test_F6_D1_reused_descriptor_refreshes_names_and_enforces_entry_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with HOST._directory(root) as descriptor:
                self.assertEqual(VALIDATION._names(descriptor, 0), [])
                (root / "first").write_bytes(b"EXAMPLE first")
                self.assertEqual(VALIDATION._names(descriptor, 1), ["first"])
                (root / "second").write_bytes(b"EXAMPLE second")
                duplicate = os.dup(descriptor)
                try:
                    self.assertEqual(set(VALIDATION._names(duplicate, 2)), {"first", "second"})
                    self.assertEqual(set(VALIDATION._names(descriptor, 2)), {"first", "second"})
                    with self.assertRaisesRegex(VALIDATION.ValidationError, "entry bound"):
                        VALIDATION._names(duplicate, 1)
                finally:
                    os.close(duplicate)


class CleanupStageInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = HostFixture(self)
        self.host, self.report, _adapter, _server = self.fixture.ready()
        self.assertEqual(self.report["status"], "artifact-ready", self.report["error"])
        self.data = HOST._immutable_read(self.host.state / "artifact", "file-0000", HOST.MAX_FILE_BYTES)
        self.assertEqual(self.data, EXAMPLE_BYTES)

    def test_primary_identity_survives_every_secondary_failure(self):
        original_close = VALIDATION._Stage.close
        kinds = (RuntimeError, KeyboardInterrupt, SystemExit)
        for primary_kind in kinds:
            for secondary_kind in kinds:
                primary = primary_kind("EXAMPLE original failure.")
                cause = LookupError("EXAMPLE original cause.")
                primary.__cause__ = cause
                secondary = secondary_kind("EXAMPLE cleanup failure. " + "X" * VALIDATION.MAX_ERROR_CHARACTERS)
                errors = []

                def close(stage):
                    original_close(stage)
                    raise secondary

                with self.subTest(primary=primary_kind.__name__, secondary=secondary_kind.__name__):
                    with FIXTURE.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
                        with effect_guard(), stages() as locations, patch.object(VALIDATION._Stage, "close", new=close):
                            with self.assertRaises(primary_kind) as caught:
                                with VALIDATION._cleanup_stage(VALIDATION._Stage(self.host), errors) as stage:
                                    stage.put("result.txt", self.data)
                                    self.assertEqual(stage.read("result.txt"), EXAMPLE_BYTES)
                                    raise primary
                    self.assertIs(caught.exception, primary)
                    self.assertIs(caught.exception.__cause__, cause)
                    self.assertEqual(writes, [])
                    self.assertEqual(len(locations), 1)
                    self.assertFalse(locations[0].exists())
                    self.assertEqual(len(errors), 1)
                    self.assertIn(secondary_kind.__name__, errors[0])
                    self.assertIn("EXAMPLE cleanup failure.", errors[0])
                    self.assertLessEqual(len(errors[0]), VALIDATION.MAX_ERROR_CHARACTERS)

    def test_primary_only_failures_keep_identity_and_successful_cleanup(self):
        for primary_kind in (RuntimeError, KeyboardInterrupt, SystemExit):
            primary = primary_kind("EXAMPLE original failure.")
            errors = []
            with self.subTest(primary=primary_kind.__name__):
                with FIXTURE.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
                    with effect_guard(), stages() as locations:
                        with self.assertRaises(primary_kind) as caught:
                            with VALIDATION._cleanup_stage(VALIDATION._Stage(self.host), errors) as stage:
                                stage.put("result.txt", self.data)
                                self.assertEqual(stage.read("result.txt"), EXAMPLE_BYTES)
                                raise primary
                self.assertIs(caught.exception, primary)
                self.assertEqual(errors, [])
                self.assertEqual(writes, [])
                self.assertEqual(len(locations), 1)
                self.assertFalse(locations[0].exists())

    def test_cleanup_only_failures_propagate_unchanged(self):
        original_close = VALIDATION._Stage.close
        for secondary_kind in (RuntimeError, KeyboardInterrupt, SystemExit):
            secondary = secondary_kind("EXAMPLE cleanup failure.")
            errors = []

            def close(stage):
                original_close(stage)
                raise secondary

            with self.subTest(secondary=secondary_kind.__name__):
                with FIXTURE.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
                    with effect_guard(), stages() as locations, patch.object(VALIDATION._Stage, "close", new=close):
                        with self.assertRaises(secondary_kind) as caught:
                            with VALIDATION._cleanup_stage(VALIDATION._Stage(self.host), errors) as stage:
                                stage.put("result.txt", self.data)
                                self.assertEqual(stage.read("result.txt"), EXAMPLE_BYTES)
                self.assertIs(caught.exception, secondary)
                self.assertEqual(errors, [])
                self.assertEqual(writes, [])
                self.assertEqual(len(locations), 1)
                self.assertFalse(locations[0].exists())

    def test_secondary_diagnostic_failures_cannot_replace_primary(self):
        original_close = VALIDATION._Stage.close
        kinds = (RuntimeError, KeyboardInterrupt, SystemExit)
        for primary_kind in kinds:
            for diagnostic_kind in kinds:
                for failure_point in ("format", "append"):
                    primary = primary_kind("EXAMPLE original failure.")
                    diagnostic = diagnostic_kind("EXAMPLE diagnostic failure.")

                    class RefusingErrors(list):
                        def append(self, value):
                            raise diagnostic

                    def close(stage):
                        original_close(stage)
                        raise RuntimeError("EXAMPLE cleanup failure.")

                    errors = [] if failure_point == "format" else RefusingErrors()
                    with self.subTest(primary=primary_kind.__name__,
                                      diagnostic=diagnostic_kind.__name__, failure_point=failure_point):
                        with ExitStack() as stack:
                            stack.enter_context(patch.object(VALIDATION._Stage, "close", new=close))
                            if failure_point == "format":
                                stack.enter_context(patch.object(VALIDATION, "_exception_text", side_effect=diagnostic))
                            with FIXTURE.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
                                with effect_guard(), stages() as locations:
                                    with self.assertRaises(primary_kind) as caught:
                                        with VALIDATION._cleanup_stage(VALIDATION._Stage(self.host), errors) as stage:
                                            stage.put("result.txt", self.data)
                                            self.assertEqual(stage.read("result.txt"), EXAMPLE_BYTES)
                                            raise primary
                        self.assertIs(caught.exception, primary)
                        self.assertEqual(errors, [])
                        self.assertEqual(writes, [])
                        self.assertEqual(len(locations), 1)
                        self.assertFalse(locations[0].exists())

    def test_actual_removal_interruptions_preserve_comparison_evidence_and_refuse_tokens(self):
        original_close = VALIDATION._Stage.close
        for secondary_kind in (KeyboardInterrupt, SystemExit):
            for comparison_fails in (False, True):
                required_text = "EXAMPLE_MISSING" if comparison_fails else "EXAMPLE_RESULT"
                policy = VALIDATION.freeze_policy(specification(text=required_text))
                secondary = secondary_kind("EXAMPLE scratch cleanup interruption.")
                primaries = []

                def observe_close(stage):
                    primaries.append(sys.exc_info()[1])
                    return original_close(stage)

                expected = VALIDATION.ValidationError if comparison_fails else secondary_kind
                with self.subTest(secondary=secondary_kind.__name__, comparison_fails=comparison_fails):
                    with stages() as locations:
                        with FIXTURE.repository_write_boundaries((self.host.target, self.host.worker)) as writes:
                            with effect_guard(), token_registrations() as registered:
                                with refuse_stage_removal(locations, secondary) as failures:
                                    with patch.object(VALIDATION._Stage, "close", new=observe_close):
                                        with self.assertRaises(expected) as caught:
                                            VALIDATION.validate_artifact(
                                                self.host, self.report, self.report["binding"]["target"], policy)
                    self.assertEqual(writes, [])
                    self.assertEqual(len(locations), 1)
                    location = locations[0]
                    self.addCleanup(lambda path=location: path.rmdir() if path.exists() else None)
                    self.assertEqual(failures, [location])
                    self.assertTrue(location.is_dir())
                    self.assertFalse(any(location.iterdir()))
                    self.assertEqual(registered, [])
                    if not comparison_fails:
                        self.assertIs(caught.exception, secondary)
                        self.assertEqual(primaries, [None])
                        continue
                    primary = primaries[0]
                    self.assertIs(type(primary), VALIDATION.ValidationError)
                    self.assertIs(caught.exception.__cause__, primary)
                    message = "Independent expected output comparisons failed."
                    self.assertEqual(str(primary), message)
                    refusal = caught.exception.report
                    self.assertFalse(refusal["offline_validation_complete"])
                    self.assertEqual(refusal["host_report"], self.report)
                    self.assertEqual(refusal["expected_target"], self.report["binding"]["target"])
                    self.assertEqual(refusal["policy"], policy.report)
                    self.assertEqual(len(refusal["host_checks"]), 2)
                    self.assertEqual(refusal["files"], [{
                        "path": "result.txt", "validator": "utf8-required-text",
                        "expected_size": len(EXAMPLE_BYTES), "observed_size": len(EXAMPLE_BYTES),
                        "expected_sha256": hashlib.sha256(EXAMPLE_BYTES).hexdigest(),
                        "observed_sha256": hashlib.sha256(EXAMPLE_BYTES).hexdigest(),
                        "size_matches": True, "sha256_matches": True,
                        "required_text": required_text, "utf8_decoded": True,
                        "text_matches": False, "text_error": None, "passed": False,
                    }])
                    self.assertEqual(len(refusal["errors"]), 2)
                    self.assertIn(message, refusal["errors"][0])
                    self.assertIn(secondary_kind.__name__, refusal["errors"][1])
                    self.assertIn("EXAMPLE scratch cleanup interruption.", refusal["errors"][1])
                    self.assertLessEqual(len(refusal["errors"][1]), VALIDATION.MAX_ERROR_CHARACTERS)
                    for flag in VALIDATION._FALSE:
                        self.assertIs(refusal[flag], False)


class PolicyPreflightTests(unittest.TestCase):
    def test_component_prefixes_refuse_before_normalization_or_observation(self):
        cases = (
            ("a", "a-b", "a/b"),
            ("EXAMPLE", "EXAMPLE-near", "EXAMPLE/deep/result.txt"),
            ("EXAMPLE/root", "EXAMPLE/root-near", "EXAMPLE/root/child", "EXAMPLE/root.txt"),
        )
        with ExitStack() as stack:
            sort = stack.enter_context(patch.object(VALIDATION, "sorted", wraps=sorted, create=True))
            host = stack.enter_context(patch.object(VALIDATION, "_host", side_effect=AssertionError("No host observation is allowed.")))
            scratch = stack.enter_context(patch.object(VALIDATION, "_safe_scratch", side_effect=AssertionError("No scratch allocation is allowed.")))
            for paths in cases:
                for order in (paths, tuple(reversed(paths))):
                    with self.subTest(paths=order), self.assertRaises(VALIDATION.ValidationError):
                        VALIDATION.freeze_policy(specification(dict.fromkeys(order, b"EXAMPLE"), text=None))
            duplicate = specification(text=None)
            duplicate["outputs"] *= 2
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION.freeze_policy(duplicate)
        sort.assert_not_called()
        host.assert_not_called()
        scratch.assert_not_called()

    def test_nearby_names_remain_valid(self):
        outputs = {"a": b"EXAMPLE", "a-b/result.txt": b"EXAMPLE", "aa/result.txt": b"EXAMPLE", "a.b": b"EXAMPLE"}
        policy = VALIDATION.freeze_policy(specification(outputs, text=None))
        self.assertEqual([entry["path"] for entry in policy.report["outputs"]], sorted(outputs))

    def test_nonplain_mapping_keys_never_run_equality(self):
        calls = []

        class Key(str):
            __hash__ = str.__hash__

            def __eq__(self, other):
                calls.append(True)
                raise AssertionError("EXAMPLE key equality must not run.")

        for field in ("version", "outputs", "validator", "path", "size", "sha256", "required_text"):
            spec = specification()
            record = spec if field in ("version", "outputs") else spec["outputs"][0]
            value = record.pop(field)
            record[Key(field)] = value
            self.assertIs(type(record), dict)
            with self.subTest(field=field):
                with patch.object(VALIDATION, "set", wraps=set, create=True) as schema_sets:
                    with self.assertRaises(VALIDATION.ValidationError):
                        VALIDATION.freeze_policy(spec)
                schema_sets.assert_not_called()
            self.assertEqual(calls, [])

    def test_large_plain_mappings_refuse_before_schema_sets(self):
        for scope in ("top", "entry"):
            spec = specification()
            record = spec if scope == "top" else spec["outputs"][0]
            record.update({f"EXAMPLE_extra_{index}": 0 for index in range(1024)})
            self.assertIs(type(record), dict)
            with self.subTest(scope=scope):
                with patch.object(VALIDATION, "set", wraps=set, create=True) as schema_sets:
                    with self.assertRaises(VALIDATION.ValidationError):
                        VALIDATION.freeze_policy(spec)
                schema_sets.assert_not_called()

    def test_plain_strings_are_bounded_before_utf8_allocation(self):
        oversized = "X" * (HOST.MAX_RECORD_BYTES + 1)
        with patch.object(VALIDATION, "_utf8", wraps=VALIDATION._utf8) as utf8:
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION._scalar_size(oversized)
            utf8.assert_not_called()
        oversized = "X" * (VALIDATION.MAX_POLICY_BYTES + 1)
        spec = specification(text=oversized)
        original = VALIDATION._utf8

        def bounded_encode(text):
            if text is oversized:
                raise AssertionError("EXAMPLE oversized text reached UTF8 allocation.")
            return original(text)

        with patch.object(VALIDATION, "_utf8", side_effect=bounded_encode):
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION.freeze_policy(spec)
        with patch.object(VALIDATION, "_utf8", wraps=original) as utf8:
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION._snapshot(["EXAMPLE", "EXAMPLE_2"], limit=15)
            utf8.assert_called_once_with("EXAMPLE_2")

    def test_multibyte_and_complete_serialized_boundaries(self):
        for character in ("é", "😀"):
            width = len(character.encode("utf-8"))
            text = character * (VALIDATION.MAX_TEXT_BYTES // width)
            with self.subTest(width=width):
                policy = VALIDATION.freeze_policy(specification(text=text))
                self.assertEqual(policy.report["outputs"][0]["required_text"], text)
                with self.assertRaises(VALIDATION.ValidationError):
                    VALIDATION.freeze_policy(specification(text=text + character))
        self.assertEqual(VALIDATION._scalar_size("é" * 8, 16), 16)
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION._scalar_size("é" * 8, 15)
        self.assertEqual(len(VALIDATION._snapshot("é", limit=8)), 8)
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION._snapshot("é", limit=7)

    def test_collection_expansion_and_depth_keep_finite_limits(self):
        values = ([None] * 8, {f"EXAMPLE_{index}": None for index in range(4)})
        with patch.object(VALIDATION, "MAX_NODES", 8):
            with patch.object(VALIDATION, "_scalar_size", side_effect=AssertionError("No child inspection is allowed.")):
                for value in values:
                    with self.assertRaises(VALIDATION.ValidationError):
                        VALIDATION._snapshot(value)
        value = None
        for _ in range(VALIDATION.MAX_INPUT_DEPTH + 1):
            value = [value]
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION._snapshot(value)

    def test_nonplain_containers_refuse_before_custom_methods(self):
        class Mapping(dict):
            def __len__(self):
                raise AssertionError("EXAMPLE custom mapping inspection must not run.")

        class Sequence(list):
            def __len__(self):
                raise AssertionError("EXAMPLE custom list inspection must not run.")

        spec = specification()
        values = (Mapping(spec), {**spec, "outputs": Sequence(spec["outputs"])},
                  {**spec, "outputs": [Mapping(spec["outputs"][0])]})
        for value in values:
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION.freeze_policy(value)

    def test_unsupported_values_do_not_format_caller_objects(self):
        class Unsupported:
            def __str__(self):
                raise AssertionError("EXAMPLE caller text must not run.")

            def __repr__(self):
                raise AssertionError("EXAMPLE caller representation must not run.")

        for value in (Unsupported(), float("nan"), float("inf"), float("-inf"), 1 << 65):
            spec = specification()
            spec["outputs"][0]["required_text"] = value
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION.freeze_policy(spec)
        error = VALIDATION.ValidationError("EXAMPLE " + "X" * HOST.MAX_RECORD_BYTES)
        self.assertLessEqual(len(str(error)), VALIDATION.MAX_ERROR_CHARACTERS)
        self.assertLessEqual(len(error.report["errors"][0]), VALIDATION.MAX_ERROR_CHARACTERS)


class OfflineArtifactValidationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = HostFixture(self)
        self.spec = specification()
        self.policy = VALIDATION.freeze_policy(self.spec)

    def validate(self, host, report, policy=None):
        return VALIDATION.validate_artifact(host, report, report["binding"]["target"],
                                            self.policy if policy is None else policy)

    def consume(self, host, token, report, policy=None):
        return VALIDATION.consume_validated(host, token, report, report["binding"]["target"],
                                            self.policy if policy is None else policy)

    def test_real_producer_staging_and_exact_consumer_without_repository_writes(self):
        host, report, adapter, server = self.fixture.ready()
        self.assertEqual(report["status"], "artifact-ready", report["error"])
        self.assertIs(HOST.NativeControlTurn, NativeControlTurn)
        self.assertIs(type(adapter), HOST.LiveThreadAdapter)
        self.assertTrue(server.archived)
        self.assertIn("close", report["receipt"]["actions"])
        self.assertEqual(report["binding"]["configuration_pins"], EXAMPLE_PINS)
        callbacks = copy.deepcopy(adapter.callback_latencies)
        with FIXTURE.repository_write_boundaries((host.target, host.worker)) as writes:
            with stages() as locations, effect_guard() as capture_calls:
                token = self.validate(host, report)
                consumed = self.consume(host, token, report)
        self.assertEqual(writes, [])
        self.assertTrue(capture_calls)
        self.assertEqual(consumed, (("result.txt", EXAMPLE_BYTES),))
        self.assertEqual(adapter.callback_latencies, callbacks)
        self.assertEqual(server.sends, 1)
        self.assertEqual(len(locations), 2)
        self.assertTrue(all(not path.exists() for path in locations))
        observation = token.report
        self.assertTrue(observation["offline_validation_complete"])
        self.assertTrue(all(entry["passed"] for entry in observation["files"]))
        self.assertTrue(observation["files"][0]["text_matches"])
        self.assertEqual(observation["host_report"], report)
        self.assertEqual(observation["policy"], self.policy.report)
        for flag in ("effect_authority", "production_ready", "accepted_for_use", "operative"):
            self.assertIs(observation[flag], False)
        self.assertEqual(len(observation["host_checks"]), 3)
        self.assertEqual(VALIDATION.ValidatedObservation(token), token)
        self.assertIs(VALIDATION.ValidationPolicy(self.policy), self.policy)

    def test_later_worker_edits_cannot_substitute_immutable_bytes(self):
        host, report, _adapter, _server = self.fixture.ready()
        (host.worker / "result.txt").write_bytes(b"EXAMPLE worker substitution\n")
        with FIXTURE.repository_write_boundaries((host.target, host.worker)) as writes:
            token = self.validate(host, report)
            self.assertEqual(self.consume(host, token, report), (("result.txt", EXAMPLE_BYTES),))
        self.assertEqual(writes, [])

    def test_each_independent_comparison_fails_with_exact_observations_and_cleanup(self):
        host, report, _adapter, _server = self.fixture.ready()
        changes = (("size", len(EXAMPLE_BYTES) + 1, "size_matches"),
                   ("sha256", hashlib.sha256(b"EXAMPLE different expectation\n").hexdigest(), "sha256_matches"),
                   ("required_text", "EXAMPLE_MISSING_TEXT", "text_matches"))
        for field, value, predicate in changes:
            spec = specification()
            spec["outputs"][0][field] = value
            policy = VALIDATION.freeze_policy(spec)
            with self.subTest(predicate=predicate), stages() as locations:
                with self.assertRaises(VALIDATION.ValidationError) as caught:
                    self.validate(host, report, policy)
                self.assertFalse(caught.exception.report["offline_validation_complete"])
                entry = caught.exception.report["files"][0]
                self.assertIs(entry[predicate], False)
                self.assertEqual(entry["observed_size"], len(EXAMPLE_BYTES))
                self.assertEqual(entry["observed_sha256"], hashlib.sha256(EXAMPLE_BYTES).hexdigest())
                self.assertTrue(caught.exception.report["errors"])
            self.assertEqual(len(locations), 1)
            self.assertFalse(locations[0].exists())

    def test_invalid_utf8_fails_the_declared_text_validator(self):
        outputs = {"result.txt": b"\xffEXAMPLE_RESULT"}
        policy = VALIDATION.freeze_policy(specification(outputs))
        host, report, _adapter, _server = self.fixture.ready(outputs)
        with self.assertRaises(VALIDATION.ValidationError) as caught:
            self.validate(host, report, policy)
        self.assertIs(caught.exception.report["files"][0]["utf8_decoded"], False)
        self.assertTrue(caught.exception.report["files"][0]["text_error"])

    def test_closed_policy_types_fields_paths_and_byte_bounds(self):
        changes = (
            ("size", True), ("size", 1.0), ("size", -1), ("size", HOST.MAX_FILE_BYTES + 1),
            ("sha256", True), ("sha256", "EXAMPLE_INVALID_DIGEST"), ("required_text", 1),
            ("required_text", ""), ("required_text", "X" * (VALIDATION.MAX_TEXT_BYTES + 1)),
            ("validator", "EXAMPLE_EXECUTABLE"), ("unknown", False), ("path", True),
            ("path", "../escape"), ("path", "/absolute"), ("path", ".git/HEAD"),
            ("path", ".GIT/HEAD"), ("path", "a" * 241), ("path", "a" * 65),
            ("path", "/".join(["a"] * (VALIDATION.MAX_DEPTH + 1))),
        )
        with patch.object(VALIDATION, "_check", side_effect=AssertionError("No artifact observation is allowed.")) as check:
            for field, value in changes:
                spec = specification()
                spec["outputs"][0][field] = value
                with self.subTest(field=field, value=repr(value)[:40]), self.assertRaises(ValueError):
                    VALIDATION.freeze_policy(spec)
            for value in (True, 1.0, "1"):
                with self.assertRaises(ValueError):
                    VALIDATION.freeze_policy({"version": value, "outputs": specification()["outputs"]})
            for outputs in ([], [specification()["outputs"][0]] * 2):
                with self.assertRaises(ValueError):
                    VALIDATION.freeze_policy({"version": 1, "outputs": outputs})
            with self.assertRaises(ValueError):
                VALIDATION.freeze_policy({**specification(), "unknown": False})
            with self.assertRaises(ValueError):
                VALIDATION.freeze_policy(specification({"a": b"", "a/b": b""}, text=None))
            oversized = specification({f"EXAMPLE-{index}": b"" for index in range(5)}, text=None)
            for entry in oversized["outputs"]:
                entry["size"] = HOST.MAX_FILE_BYTES
            with self.assertRaises(ValueError):
                VALIDATION.freeze_policy(oversized)
            large = specification({f"EXAMPLE-{index}": b"" for index in range(HOST.MAX_OUTPUTS)},
                                  text="X" * VALIDATION.MAX_TEXT_BYTES)
            with self.assertRaises(ValueError):
                VALIDATION.freeze_policy(large)
        check.assert_not_called()

    def test_missing_extra_or_forged_reports_refuse_before_blob_validation(self):
        host, report, _adapter, _server = self.fixture.ready()
        policies = (specification({"other.txt": EXAMPLE_BYTES}),
                    specification({"result.txt": EXAMPLE_BYTES, "extra.txt": EXAMPLE_BYTES}))
        with patch.object(VALIDATION, "_check", side_effect=AssertionError("No blob validation is allowed.")) as check:
            for spec in policies:
                with self.assertRaises(VALIDATION.ValidationError):
                    self.validate(host, report, VALIDATION.freeze_policy(spec))
            for change in ("duplicate", "missing", "extra", "flag", "numeric"):
                forged = copy.deepcopy(report)
                if change == "duplicate":
                    forged["artifact"]["files"] *= 2
                elif change == "missing":
                    forged["artifact"]["files"].clear()
                elif change == "extra":
                    forged["artifact"]["files"].append({"path": "EXAMPLE_EXTRA"})
                elif change == "flag":
                    forged["effect_authority"] = True
                else:
                    forged["version"] = True
                with self.subTest(change=change), self.assertRaises(VALIDATION.ValidationError):
                    self.validate(host, forged)
        check.assert_not_called()
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION.validate_artifact({}, report, report["binding"]["target"], self.policy)
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION.validate_artifact(host, None, report["binding"]["target"], self.policy)
        expected = copy.deepcopy(report["binding"]["target"])
        expected["complete"] = 1
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION.validate_artifact(host, report, expected, self.policy)

    def test_missing_or_failed_original_host_cannot_issue_observations(self):
        host, report, _adapter, _server = self.fixture.ready(mode="failure")
        self.assertEqual(report["status"], "reconciliation-required")
        with self.assertRaises(VALIDATION.ValidationError):
            self.validate(host, report)
        other = HostFixture(self)
        host, report, _adapter, _server = other.ready()
        missing = other.helper.case(name="EXAMPLE_MISSING_HOST")[0]
        with self.assertRaises(VALIDATION.ValidationError):
            self.validate(missing, report)
        with patch.object(host, "verify_artifact", return_value={"valid": True}):
            with self.assertRaises(VALIDATION.ValidationError):
                self.validate(host, report)

    def test_blob_symlink_special_link_missing_extra_mode_and_size_refuse(self):
        host, report, _adapter, _server = self.fixture.ready()
        directory = host.state / "artifact"
        blob = directory / "file-0000"
        for kind in ("symlink", "fifo", "hardlink", "missing", "extra", "mode", "oversize"):
            directory.chmod(0o700)
            blob.unlink()
            if kind == "symlink":
                blob.symlink_to(host.worker / "result.txt")
            elif kind == "fifo":
                os.mkfifo(blob, 0o400)
            elif kind == "hardlink":
                os.link(host.worker / "result.txt", blob)
            elif kind != "missing":
                blob.write_bytes(b"X" * (HOST.MAX_FILE_BYTES + 1) if kind == "oversize" else EXAMPLE_BYTES)
                blob.chmod(0o600 if kind == "mode" else 0o400)
            if kind == "extra":
                (directory / "EXAMPLE_EXTRA").write_bytes(b"EXAMPLE")
            directory.chmod(0o500)
            try:
                with self.subTest(kind=kind), stages() as locations, self.assertRaises(VALIDATION.ValidationError):
                    self.validate(host, report)
                self.assertEqual(locations, [])
            finally:
                directory.chmod(0o700)
                if os.path.lexists(blob):
                    blob.unlink()
                (directory / "EXAMPLE_EXTRA").unlink(missing_ok=True)
                blob.write_bytes(EXAMPLE_BYTES)
                blob.chmod(0o400)
                directory.chmod(0o500)

    def test_stage_symlinks_and_special_files_are_inert_and_removed(self):
        host, report, _adapter, _server = self.fixture.ready()
        original = VALIDATION._Stage.put
        for kind in ("symlink", "fifo"):
            def replace(stage, path, data):
                original(stage, path, data)
                destination = Path(stage.scratch.root) / path
                destination.unlink()
                if kind == "symlink":
                    destination.symlink_to(host.worker / "result.txt")
                else:
                    os.mkfifo(destination, 0o400)
            with self.subTest(kind=kind), stages() as locations:
                with patch.object(VALIDATION._Stage, "put", replace), self.assertRaises(VALIDATION.ValidationError):
                    self.validate(host, report)
            self.assertEqual(len(locations), 1)
            self.assertFalse(locations[0].exists())
        self.assertEqual((host.worker / "result.txt").read_bytes(), EXAMPLE_BYTES)

    def test_missing_fallback_is_skipped_without_creation_and_valid_stage_completes(self):
        host, report, _adapter, _server = self.fixture.ready()
        missing = self.fixture.helper.root / "EXAMPLE_MISSING_FALLBACK"
        self.assertFalse(missing.exists())
        with patch.object(HOST.workspace_capture, "SCRATCH_PARENTS", (str(missing), "/tmp")):
            with FIXTURE.repository_write_boundaries((host.target, host.worker)) as writes:
                token = self.validate(host, report)
                consumed = self.consume(host, token, report)
        self.assertTrue(token.report["offline_validation_complete"])
        self.assertEqual(consumed, (("result.txt", EXAMPLE_BYTES),))
        self.assertEqual(writes, [])
        self.assertFalse(missing.exists())

    def test_only_missing_scratch_candidates_refuse_before_stage_allocation(self):
        host, report, _adapter, _server = self.fixture.ready()
        missing = self.fixture.helper.root / "EXAMPLE_ONLY_MISSING_FALLBACK"
        with patch.object(HOST.workspace_capture, "_scratch_candidates", return_value=[str(missing)]):
            with patch.object(HOST.workspace_capture, "_Snapshot", side_effect=AssertionError("No stage allocation.")) as allocation:
                with self.assertRaisesRegex(VALIDATION.ValidationError, "No usable safe scratch"):
                    self.validate(host, report)
                allocation.assert_not_called()
        self.assertFalse(missing.exists())

    def test_unsafe_actual_scratch_candidates_refuse_before_allocation_and_writes(self):
        host, report, _adapter, _server = self.fixture.ready()
        alias = self.fixture.helper.root / "EXAMPLE_ALIAS"
        alias.symlink_to(host.target, target_is_directory=True)
        special = self.fixture.helper.root / "EXAMPLE_FIFO"
        os.mkfifo(special)
        candidates = (host.target, host.worker, host.state, host.target / "nested", alias, str(alias) + "/..", special, "/proc", "/")
        for candidate in candidates:
            with self.subTest(candidate=str(candidate)), FIXTURE.repository_write_boundaries((host.target, host.worker)) as writes:
                with patch.object(tempfile, "tempdir", str(candidate)):
                    with patch.object(HOST.workspace_capture, "_Snapshot", side_effect=AssertionError("No allocation is allowed.")) as allocation:
                        with self.assertRaises(VALIDATION.ValidationError):
                            self.validate(host, report)
                        allocation.assert_not_called()
            self.assertEqual(writes, [])

    def test_target_drift_before_during_after_and_cleanup_refuses(self):
        host, report, _adapter, _server = self.fixture.ready()
        seed = host.target / "seed.txt"
        original_seed = seed.read_bytes()
        seed.write_bytes(b"EXAMPLE drift before validation\n")
        with self.assertRaises(VALIDATION.ValidationError):
            self.validate(host, report)
        seed.write_bytes(original_seed)
        original_compare = VALIDATION._compare

        def drift(entry, data):
            result = original_compare(entry, data)
            seed.write_bytes(b"EXAMPLE drift during validation\n")
            return result

        with stages() as locations:
            with patch.object(VALIDATION, "_compare", side_effect=drift), self.assertRaises(VALIDATION.ValidationError):
                self.validate(host, report)
        self.assertTrue(all(not path.exists() for path in locations))
        seed.write_bytes(original_seed)
        original_close = VALIDATION._Stage.close

        def cleanup_drift(stage):
            original_close(stage)
            seed.write_bytes(b"EXAMPLE drift after staging cleanup\n")

        with stages() as locations:
            with patch.object(VALIDATION._Stage, "close", cleanup_drift), self.assertRaises(VALIDATION.ValidationError):
                self.validate(host, report)
        self.assertTrue(all(not path.exists() for path in locations))
        seed.write_bytes(original_seed)
        token = self.validate(host, report)
        seed.write_bytes(b"EXAMPLE drift after issued validation\n")
        with self.assertRaises(VALIDATION.ValidationError):
            self.consume(host, token, report)

    def test_artifact_mutation_between_staging_and_host_recheck_refuses_and_cleans(self):
        host, report, _adapter, _server = self.fixture.ready()
        original = VALIDATION._compare

        def mutate(entry, data):
            blob = host.state / "artifact" / "file-0000"
            blob.chmod(0o600)
            blob.write_bytes(b"EXAMPLE artifact drift\n")
            blob.chmod(0o400)
            return original(entry, data)

        with stages() as locations:
            with patch.object(VALIDATION, "_compare", side_effect=mutate), self.assertRaises(VALIDATION.ValidationError):
                self.validate(host, report)
        self.assertEqual(len(locations), 1)
        self.assertFalse(locations[0].exists())

    def test_issued_identity_deep_copies_and_revalidation_bindings(self):
        host, report, _adapter, _server = self.fixture.ready()
        token = self.validate(host, report)
        view = token.report
        view["files"][0]["passed"] = False
        view["host_report"]["binding"]["configuration_pins"]["w14"] = "EXAMPLE_CHANGED"
        self.assertTrue(token.report["files"][0]["passed"])
        policy_view = self.policy.report
        policy_view["outputs"][0]["size"] = 0
        self.spec["outputs"][0]["required_text"] = "EXAMPLE_CHANGED"
        self.assertEqual(self.consume(host, token, report), (("result.txt", EXAMPLE_BYTES),))
        for value in (view, {}, object.__new__(VALIDATION.ValidatedObservation)):
            with self.assertRaises(VALIDATION.ValidationError):
                self.consume(host, value, report)
            with self.assertRaises(VALIDATION.ValidationError):
                VALIDATION.ValidatedObservation(value)
        with self.assertRaises(VALIDATION.ValidationError):
            VALIDATION.ValidationPolicy(specification())
        forged_policy = object.__new__(VALIDATION.ValidationPolicy)
        with self.assertRaises(VALIDATION.ValidationError):
            self.validate(host, report, forged_policy)
        with self.assertRaises(VALIDATION.ValidationError):
            self.consume(host, token, report, VALIDATION.freeze_policy(specification()))
        with self.assertRaises(AttributeError):
            token.offline_validation_complete = True
        with self.assertRaises(VALIDATION.ValidationError):
            pickle.dumps(token)
        changed = copy.deepcopy(report)
        changed["summary"]["EXAMPLE_CHANGED"] = True
        with self.assertRaises(VALIDATION.ValidationError):
            self.consume(host, token, changed)
        report_path = host.state / "operation.json"
        original_record = report_path.read_bytes()
        report_path.write_bytes(b"{}")
        with self.assertRaises(VALIDATION.ValidationError):
            self.consume(host, token, report)
        report_path.write_bytes(original_record)
        with patch.object(host, "_verify_files", return_value=None), self.assertRaises(VALIDATION.ValidationError):
            self.consume(host, token, report)

    def test_nested_python_and_configuration_artifacts_are_never_evaluated(self):
        outputs = {
            "nested/EXAMPLE_artifact.py": b"raise RuntimeError('EXAMPLE artifact must stay inert')\n",
            "nested/EXAMPLE_config.ini": b"[EXAMPLE]\ncommand = EXAMPLE_NEVER_RUN\n",
        }
        policy = VALIDATION.freeze_policy(specification(outputs, text=None))
        host, report, _adapter, _server = self.fixture.ready(outputs)
        self.assertEqual(report["status"], "artifact-ready", report["error"])
        with effect_guard(), FIXTURE.repository_write_boundaries((host.target, host.worker)) as writes:
            token = self.validate(host, report, policy)
            result = self.consume(host, token, report, policy)
        self.assertEqual(result, tuple(sorted(outputs.items())))
        self.assertTrue(all(item["text_matches"] is None for item in token.report["files"]))
        self.assertEqual(writes, [])

    def test_registration_observer_sees_actual_successful_issuance(self):
        host, report, _adapter, _server = self.fixture.ready()
        with token_registrations() as registered:
            token = self.validate(host, report)
        self.assertEqual(registered, [token])
        self.assertEqual(self.consume(host, token, report), (("result.txt", EXAMPLE_BYTES),))

    def test_actual_scratch_cleanup_failure_preserves_success_and_comparison_evidence(self):
        host, report, _adapter, _server = self.fixture.ready()
        for comparison_fails in (False, True):
            spec = specification(text="EXAMPLE_MISSING" if comparison_fails else "EXAMPLE_RESULT")
            policy = VALIDATION.freeze_policy(spec)
            with self.subTest(comparison_fails=comparison_fails), stages() as locations:
                failure = OSError("EXAMPLE scratch cleanup failure.")
                with FIXTURE.repository_write_boundaries((host.target, host.worker)) as writes:
                    with effect_guard(), token_registrations() as registered, refuse_stage_removal(locations, failure) as failures:
                        with self.assertRaises(VALIDATION.ValidationError) as caught:
                            self.validate(host, report, policy)
                self.assertEqual(writes, [])
                self.assertEqual(len(locations), 1)
                location = locations[0]
                self.addCleanup(lambda path=location: path.rmdir() if path.exists() else None)
                self.assertEqual(failures, [location])
                self.assertTrue(location.is_dir())
                self.assertFalse(any(location.iterdir()))
                self.assertEqual(registered, [])
                refusal = caught.exception.report
                self.assertFalse(refusal["offline_validation_complete"])
                self.assertTrue(any("EXAMPLE scratch cleanup failure." in error for error in refusal["errors"]))
                for flag in VALIDATION._FALSE:
                    self.assertIs(refusal[flag], False)
                if comparison_fails:
                    self.assertFalse(refusal["files"][0]["text_matches"])
                    self.assertIn("Independent expected output comparisons failed.", str(caught.exception))
                    self.assertEqual(str(caught.exception.__cause__), "Independent expected output comparisons failed.")
                    self.assertEqual(len(refusal["errors"]), 2)
                else:
                    self.assertTrue(all(entry["passed"] for entry in refusal["files"]))
                    self.assertIn("Scratch cleanup refused", str(caught.exception))

    def test_consumption_retains_the_original_host_refusal_cause(self):
        host, report, _adapter, _server = self.fixture.ready()
        token = self.validate(host, report)
        changed = copy.deepcopy(report)
        changed["summary"]["EXAMPLE_CHANGED"] = True
        with self.assertRaises(VALIDATION.ValidationError) as caught:
            self.consume(host, token, changed)
        self.assertIsInstance(caught.exception.__cause__, HOST.OfflineHostError)
        self.assertLessEqual(len(str(caught.exception)), VALIDATION.MAX_ERROR_CHARACTERS)


if __name__ == "__main__":
    unittest.main()
