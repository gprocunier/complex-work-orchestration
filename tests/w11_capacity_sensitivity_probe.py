#!/usr/bin/env python3
"""Reproduce raw-reference capacity-test sensitivity; this is not a discovered test.

Run only inside the integration root's qualified offline bwrap boundary.
This probe neither qualifies that boundary nor grants review/approval.
Commit the probe first: all measured sources must match HEAD, and the
producer and strong tests must also match the selected public prerequisite.
Output includes actual identities, compiled mutant sources and hashes,
unittest results and raw assertion traces. No results are embedded here.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import linecache
import subprocess
import sys
import traceback
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

PRODUCER = "scripts/validate_public_copy.py"
STRONG = "tests/test_raw_reference_scan.py"
COMPONENTS = (PRODUCER, "scripts/cwo_core/public_copy.py", STRONG)
PROBE = "tests/w11_capacity_sensitivity_probe.py"
CASES = (
    ("TokenCapacityTests", "test_max_safe_token_count_works",
     'self.assertTrue(any("retired claim" in error for error in errors), errors)'),
    ("TokenCapacityTests", "test_next_allocation_after_max_fails",
     "self.assertEqual(tuple(protected.values), stored_values)"),
    ("AlternateReadingOverflowTests", "test_markdown_image_alt_overflow",
     'self.assertTrue(len(errors) > 0, f"Expected rewording diagnostic, got empty list: {errors}")'),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def emit(kind: str, **fields: object) -> None:
    print(json.dumps({"event": kind, **fields}, sort_keys=True), flush=True)


def sha(source: bytes) -> str:
    return hashlib.sha256(source).hexdigest()


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(ROOT), *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def identity() -> tuple[str, str]:
    return (git("rev-parse", "HEAD").decode().strip(),
            git("rev-parse", "HEAD^{tree}").decode().strip())


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.assertion_sites: list[dict[str, object]] = []

    def addFailure(self, test: unittest.TestCase, err: tuple) -> None:
        self.assertion_sites.append({
            "test": test.id(),
            "assertion_error": issubclass(err[0], AssertionError),
            "frames": [
                {"file": frame.filename, "line": frame.lineno, "function": frame.name}
                for frame in traceback.extract_tb(err[2])
            ],
        })
        super().addFailure(test, err)


def assertion_line(source: str, case: tuple[str, str, str]) -> int:
    class_name, method_name, assertion = case
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method_name)
    lines = source.splitlines()
    matches = [number for number in range(method.lineno, method.end_lineno + 1)
               if lines[number - 1].strip() == assertion]
    require(len(matches) == 1, f"Cannot identify intended assertion: {class_name}.{method_name}")
    return matches[0]


def run_phase(label: str, tests: object, source: str, selected: tuple,
              expected: tuple[str, str, str] | None = None) -> None:
    suite = unittest.TestSuite(getattr(tests, cls)(method) for cls, method, _ in selected)
    emit("phase_start", phase=label, selected=[test.id() for test in suite])
    result = unittest.TextTestRunner(
        stream=sys.stdout, verbosity=2, resultclass=EvidenceResult,
    ).run(suite)
    emit(
        "unittest_result", phase=label, tests_run=result.testsRun,
        failure_count=len(result.failures), error_count=len(result.errors),
        failures=[{"test": test.id(), "raw_trace": trace} for test, trace in result.failures],
        errors=[{"test": test.id(), "raw_trace": trace} for test, trace in result.errors],
        assertion_sites=result.assertion_sites,
        skipped=result.skipped, expected_failures=len(result.expectedFailures),
        unexpected_successes=len(result.unexpectedSuccesses),
    )
    require(result.testsRun == len(selected), f"{label}: wrong test count")
    require(not result.errors, f"{label}: errors are not mutation evidence")
    require(not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses,
            f"{label}: skipped/expected/unexpected outcomes are not evidence")
    if expected is None:
        require(result.wasSuccessful(), f"{label}: unmutated strong tests failed")
        return
    cls, method, _ = expected
    test_id = f"{tests.__name__}.{cls}.{method}"
    line = assertion_line(source, expected)
    require(len(result.failures) > 0, f"{label}: mutant survived")
    require(len(result.failures) == 1 and result.failures[0][0].id() == test_id,
            f"{label}: failure outside the expected method")
    require(len(result.assertion_sites) == 1, f"{label}: unexpected failure accounting")
    site = result.assertion_sites[0]
    require(site["assertion_error"] and site["test"] == test_id,
            f"{label}: failure was not the intended AssertionError")
    require(any(frame["file"] == str(ROOT / STRONG) and frame["line"] == line
                and frame["function"] == method for frame in site["frames"]),
            f"{label}: failure did not reach the intended semantic assertion")
    emit("intended_failure_observed", phase=label, test=test_id,
         assertion_line=line, assertion=expected[2])


def mutant_functions(source: str, producer: object) -> list[tuple[str, str, str, str, object]]:
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_Protected")
    hold = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "hold")
    retired = next(node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == "retired_claim_errors")
    require(ast.unparse(hold.body[0].test) == "len(self.values) >= 65534",
            "Allocator guard no longer has the supplied shape")
    require(ast.unparse(hold.body[1]) == "self.values.append(text)",
            "Allocator append no longer has the supplied shape")
    reduced = copy.deepcopy(hold)
    reduced.body[0].test.comparators[0].value = 65533
    appended = copy.deepcopy(hold)
    appended.body[0].test.ops = [ast.Gt()]
    appended.body[:2] = [appended.body[1], appended.body[0]]

    class DiscardAlternate(ast.NodeTransformer):
        removed = 0

        def visit_Expr(self, node: ast.Expr) -> ast.Expr | None:
            if ast.unparse(node) == "unreadable.extend(reading_unreadable)":
                self.removed += 1
                return None
            return self.generic_visit(node)

    discard = DiscardAlternate()
    alternate = discard.visit(copy.deepcopy(retired))
    require(discard.removed == 2, "Expected exactly two alternate-diagnostic accumulation sites")
    require("unreadable.extend(measured_unreadable)" in ast.unparse(alternate),
            "Measuring diagnostics must remain intact")
    definitions = (
        ("reduced_capacity", "hold", reduced,
         "Refuse at 65533 stored values instead of 65534."),
        ("append_before_refusal", "hold", appended,
         "Append first, then refuse when length exceeds 65534; allocation 65535 mutates values."),
        ("discard_alternate_diagnostics", "retired_claim_errors", alternate,
         "Keep initial/measured diagnostics and all readings; discard only alternate diagnostics."),
    )
    compiled = []
    for label, name, node, description in definitions:
        original = hold if name == "hold" else retired
        original_source = ast.unparse(original) + "\n"
        mutated_source = ast.unparse(ast.fix_missing_locations(node)) + "\n"
        filename = f"<w11-mutant:{label}>"
        namespace = dict(vars(producer))
        exec(compile(mutated_source, filename, "exec"), namespace)
        function = namespace[name]
        require(function.__globals__["_Protected"] is producer._Protected
                and function.__globals__["_reading"] is producer._reading,
                f"{label}: compiled helper aliases changed")
        linecache.cache[filename] = (len(mutated_source), None, mutated_source.splitlines(True), filename)
        emit(
            "mutant_source", mutation=label, description=description,
            source_normalization="ast.unparse plus trailing newline",
            original_function_source_sha256=sha(original_source.encode()),
            mutated_function_source_sha256=sha(mutated_source.encode()),
            mutated_function_source=mutated_source,
        )
        compiled.append((label, name, description, mutated_source, function))
    return compiled


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="HEAD", help="public prerequisite commit (default: HEAD)")
    args = parser.parse_args()
    base = git("rev-parse", "--verify", args.baseline + "^{commit}").decode().strip()
    base_tree = git("rev-parse", base + "^{tree}").decode().strip()
    head, tree = identity()
    snapshots = {path: (ROOT / path).read_bytes() for path in (*COMPONENTS, PROBE)}
    components = {}
    for path, data in snapshots.items():
        require(data == git("show", f"{head}:{path}"), f"Measured file differs from committed HEAD: {path}")
        if path in COMPONENTS:
            require(data == git("show", f"{base}:{path}"), f"Prerequisite component changed: {path}")
        components[path] = {
            "sha256": sha(data),
            "head_blob": git("rev-parse", f"{head}:{path}").decode().strip(),
        }
    emit(
        "measurement_identity", head=head, tree=tree,
        prerequisite_commit=base, prerequisite_tree=base_tree,
        components=components, python=sys.version, executable=sys.executable,
        boundary="External qualified offline bwrap is required; not attested by this probe.",
    )
    sys.path.insert(0, str(ROOT / "scripts"))
    import validate_public_copy as producer

    require(Path(producer.__file__).resolve() == ROOT / PRODUCER, "Wrong producer module imported")
    spec = importlib.util.spec_from_file_location("w11_strong_reference_tests", ROOT / STRONG)
    require(spec is not None and spec.loader is not None, "Cannot load strong tests")
    tests = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = tests
    spec.loader.exec_module(tests)
    source = snapshots[STRONG].decode("utf-8")
    originals = (producer._Protected, producer._Protected.hold,
                 producer._reading, producer.retired_claim_errors)

    def unchanged() -> None:
        protected, hold, reading, retired = originals
        require(producer._Protected is protected and producer._Protected.hold is hold
                and producer._reading is reading and producer.retired_claim_errors is retired,
                "Producer helpers were not restored")
        require(tests._Protected is protected and tests._reading is reading
                and tests.retired_claim_errors is retired, "Strong-test import aliases were not restored")
        require(reading.__globals__ is vars(producer), "Reading globals are not the producer namespace")
        for path, data in snapshots.items():
            require((ROOT / path).read_bytes() == data, f"Measured source changed during execution: {path}")
        require(identity() == (head, tree), "HEAD/tree changed during execution")

    for case in CASES:
        assertion_line(source, case)
    unchanged()
    try:
        run_phase("untouched_positive", tests, source, CASES)
        unchanged()
        mutants = mutant_functions(snapshots[PRODUCER].decode("utf-8"), producer)
        require(len(mutants) == len(CASES), "Incomplete mutation matrix")
        for (label, name, _description, _source, function), case in zip(mutants, CASES):
            unchanged()
            with ExitStack() as stack:
                if name == "hold":
                    stack.enter_context(mock.patch.object(producer._Protected, "hold", function))
                    require(tests._Protected.hold is function, f"{label}: allocator alias not patched")
                else:
                    stack.enter_context(mock.patch.object(producer, name, function))
                    stack.enter_context(mock.patch.object(tests, name, function))
                    require(tests.retired_claim_errors is producer.retired_claim_errors,
                            f"{label}: public function alias not patched")
                run_phase(label, tests, source, (case,), expected=case)
            unchanged()
        run_phase("restored_positive", tests, source, CASES)
    finally:
        unchanged()
    emit("probe_complete", selected_methods=3, positive_runs=2, intended_mutants=3,
         source_integrity="unchanged", review_status="Independent review remains required.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("probe_error", error_type=type(exc).__name__, message=str(exc))
        traceback.print_exc()
        raise SystemExit(1)
