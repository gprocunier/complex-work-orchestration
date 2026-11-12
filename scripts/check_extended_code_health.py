#!/usr/bin/env python3
"""Staged development gates; no runtime or current CI gate imports this module.

Real Ruff annotation diagnostics, exact AST duplicate bodies, and executed line
coverage of a fixed EXAMPLE family; these checks are development-only.
"""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from types import CodeType

import check_code_health as initial

ROOT = Path(__file__).resolve().parents[1]
RULES = "ANN001,ANN201,ANN202"
RUFF = "0.17.1"
SUBJECT = "tests/fixtures/extended_code_health/EXAMPLE_subject.py"
DRIVER = "tests/fixtures/extended_code_health/EXAMPLE_test.py"
CONTRACT = {"version": 1, "ruff": RUFF, "rules": RULES,
            "duplicates": "DUP001-exact-args-body-ast-v1", "metric": "line coverage",
            "measurement": [SUBJECT, DRIVER], "interpreters": ["3.12", "3.14"]}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def interpreter() -> str:
    lane = f"{sys.version_info.major}.{sys.version_info.minor}"
    if lane not in CONTRACT["interpreters"]:
        raise SystemExit(f"unsupported interpreter {lane}; need an executed 3.12 or 3.14 measurement")
    return lane


def annotation_diagnostics(root: Path, inventory: list[str]) -> dict[str, int]:
    """Invoke the pinned real tool; there is intentionally no supplied-report adapter."""
    if initial.ruff_version() != RUFF:
        raise SystemExit(f"need pinned Ruff {RUFF}")
    command = ["ruff", "check", "--no-cache", "--isolated", "--ignore-noqa",
               "--no-respect-gitignore", "--select", RULES, "--output-format", "json", "--exit-zero"]
    env = {key: value for key, value in os.environ.items() if not key.startswith("RUFF_")}
    result = subprocess.run([*command, *inventory], cwd=root, env=env,
                            capture_output=True, text=True, check=False)
    if result.returncode or not result.stdout.strip():
        raise SystemExit(f"Ruff failed or lost its report: {result.stderr[:300]}")
    records = json.loads(result.stdout)
    if not isinstance(records, list):
        raise SystemExit("Ruff report is not an array")
    if any(record.get("code") not in RULES.split(",") for record in records):
        raise SystemExit("unexpected Ruff diagnostic")
    identities = initial.diagnostic_identities(root, records)
    # Ruff's return rules quote the def name, already represented by enclosing scope.
    # A reviewed rename must not turn that redundant display name into new debt.
    normalized = {}
    for identity, count in identities.items():
        file, scope, rule, subject = identity.split("::", 3)
        subject = "<return>" if rule in ("ANN201", "ANN202") else subject
        normalized[f"{file}::{scope}::{rule}::{subject}"] = count
    return normalized


def body_fingerprint(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Exact parameter/body AST, including literals and names, excluding docstring and def name."""
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    return digest(initial._canonical([type(node).__name__, node.args, body]).encode())


def duplicate_bodies(root: Path, inventory: list[str]) -> dict[str, int]:
    groups: dict[str, list[str]] = defaultdict(list)
    for relative in inventory:
        if not relative.endswith(".py"):
            continue  # Stubs describe contracts, not executable bodies.
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for _, _, name, node in initial._definitions(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # One-statement bodies are common trivial adapters and are deliberately out of scope.
            body = [entry for entry in node.body if not (
                isinstance(entry, ast.Expr) and isinstance(entry.value, ast.Constant)
                and isinstance(entry.value.value, str))]
            if len(body) < 2:
                continue
            groups[body_fingerprint(node)].append(f"{relative}::{name}")
    return {f"{name}::DUP001::{fingerprint}": 1
            for fingerprint, names in sorted(groups.items()) if len(names) > 1 for name in names}


def coverage_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    definitions = initial._definitions(tree)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if len(definitions) != len(functions) or len({node.name for node in functions}) != len(functions):
        raise SystemExit("measurement supports unique top-level functions only")
    excluded = (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    if any(isinstance(node, excluded) for node in ast.walk(tree)):
        raise SystemExit("measurement does not support lambdas or comprehensions")
    if any(node.decorator_list for node in functions):
        raise SystemExit("measurement does not support decorators")
    if not functions:
        raise SystemExit("measurement needs at least one function")
    return functions


def executable_line_groups(node: ast.FunctionDef, lines: list[int]) -> list[list[int]]:
    """AST node memberships of each compiler line; independent of absolute positions.

    The canonical body binds the nodes. Their deterministic traversal indexes bind
    which of those same nodes share each measured physical line. Equal line counts
    alone cannot establish that relation (semicolons and inline suites can regroup it).
    """
    nodes = [child for child in ast.walk(node) if hasattr(child, "lineno")]
    return [[index for index, child in enumerate(nodes)
             if child.lineno <= line <= child.end_lineno] for line in lines]


def function_layout(node: ast.FunctionDef, function: CodeType) -> dict:
    if any(isinstance(entry, CodeType) for entry in function.co_consts):
        raise SystemExit("measurement does not support nested code, lambdas or comprehensions")
    lines = sorted({line for _, _, line in function.co_lines()
                    if line is not None and line > node.lineno})
    if not lines:
        raise SystemExit("measurement function has no executable body lines")
    return {"fingerprint": body_fingerprint(node), "lines": lines,
            "line_groups": executable_line_groups(node, lines)}


def coverage_layout(source: str, filename: str) -> dict[str, dict]:
    """Finite coverage domain: unique undecorated top-level synchronous functions only."""
    functions = coverage_functions(ast.parse(source))
    code = compile(source, filename, "exec")
    codes = {entry.co_name: entry for entry in code.co_consts if isinstance(entry, CodeType)}
    return {f"{SUBJECT}::{node.name}": function_layout(node, codes[node.name]) for node in functions}


def measure(root: Path) -> dict:
    """Run only the fixed, explicitly approved fixture test, never paths from a report."""
    lane = interpreter()
    paths = [root / SUBJECT, root / DRIVER]
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
            raise SystemExit("missing or indirect approved measurement source")
    before = {str(path.relative_to(root)): digest(path.read_bytes()) for path in paths}
    filename = str(paths[0])
    layout = coverage_layout(paths[0].read_text(encoding="utf-8"), filename)
    executed: set[int] = set()
    called: set[str] = set()

    def tracer(frame, event, arg):
        if frame.f_code.co_filename == filename:
            if event == "line":
                executed.add(frame.f_lineno)
            elif event == "call":
                called.add(frame.f_code.co_name)
        return tracer

    previous = sys.gettrace()
    try:
        sys.settrace(tracer)
        try:
            runpy.run_path(str(paths[1]), run_name="__w21_measurement__")
        except SystemExit as error:
            raise SystemExit(f"measurement driver exited before completion: {error.code}") from None
    finally:
        sys.settrace(previous)
    if before != {str(path.relative_to(root)): digest(path.read_bytes()) for path in paths}:
        raise SystemExit("measurement source changed during execution")
    for scope, entry in layout.items():
        entry["executed"] = sorted(executed.intersection(entry["lines"]))
        entry["called"] = scope.split("::")[1] in called
    if not any(entry["executed"] for entry in layout.values()):
        raise SystemExit("missing executed measurement")
    return {"lane": lane, "interpreter": sys.version, "sources": before,
            "metric": "line coverage", "functions": layout, "executed_lines": sorted(executed)}


def observe(root: Path) -> dict:
    interpreter()
    inventory = initial._python_files_in_tree(root, initial.LINT_PATHS)
    if not inventory:
        raise SystemExit("missing source inventory")
    sources = {name: digest((root / name).read_bytes()) for name in inventory}
    annotations = annotation_diagnostics(root, inventory)
    duplicates = duplicate_bodies(root, inventory)
    definitions, repeated = initial.definition_inventory(root, inventory)
    measurement = measure(root)
    if sources != {name: digest((root / name).read_bytes()) for name in inventory}:
        raise SystemExit("source changed during observation")
    return {"contract": CONTRACT, "sources": sources, "annotations": annotations,
            "duplicates": duplicates, "definitions": sorted(definitions), "repeated": repeated,
            "coverage": {measurement["lane"]: measurement}}


def move_projection(state: dict) -> dict:
    """Adapt to the existing reviewed-move validator without duplicating its rules."""
    coverage = {scope: 1 for measurement in state["coverage"].values()
                for scope in measurement["functions"]}
    return {"complexity": coverage, "f_e9": {**state["annotations"], **state["duplicates"]},
            "definitions": set(state["definitions"])}


def compare_coverage(old: dict, new: dict, moves: list[dict]) -> list[str]:
    failures = []
    known = {initial._moved(scope, moves): entry for scope, entry in old["functions"].items()}
    if not known:
        return ["missing baseline measurement"]
    for scope, entry in known.items():
        current = new["functions"].get(scope)
        if current is None:
            failures.append(f"missing measured function: {scope}")
        elif (entry["fingerprint"] != current["fingerprint"]
              or entry.get("line_groups") != current["line_groups"]):
            failures.append(f"stale measured source or line layout: {scope}; review actual remeasurement")
        else:
            covered = {entry["lines"].index(line) for line in entry["executed"]}
            now = {current["lines"].index(line) for line in current["executed"]}
            if covered - now or (entry["called"] and not current["called"]):
                failures.append(f"line coverage regressed: {scope}")
    for scope in new["functions"].keys() - known.keys():
        failures.append(f"new measured function needs reviewed floor: {scope}")
    return failures


def compare_debt(baseline: dict, state: dict, moves: list[dict]) -> tuple[list[str], list[str]]:
    failures, notes = [], []
    for kind in ("annotations", "duplicates"):
        known = {initial._moved(key, moves): count for key, count in baseline[kind].items()}
        current = state[kind]
        failures.extend(f"new {kind}: {key}" for key, count in current.items() if count > known.get(key, 0))
        notes.extend(f"reduced {kind}: {key}" for key, count in known.items() if current.get(key, 0) < count)
    return failures, notes


def compare_repeated(baseline: dict, state: dict, moves: list[dict]) -> list[str]:
    """Preserve conservative repeated-definition identity semantics for new debt."""
    old = {initial._moved(key, moves): value for key, value in baseline["repeated"].items()}
    debt = move_projection(baseline)
    debt = {kind: {initial._moved(key, moves): value for key, value in debt[kind].items()}
            for kind in ("complexity", "f_e9")}
    failures = []
    for name in old.keys() | state["repeated"].keys():
        scoped = initial._debt_under(name, debt["complexity"], debt["f_e9"])
        if (scoped[0] or scoped[1]) and old.get(name) != state["repeated"].get(name):
            failures.append(f"repeated definitions changed: {name}")
    return failures


def compare(baseline: dict, state: dict, document: dict) -> tuple[list[str], list[str], list[dict], str | None]:
    if baseline.get("contract") != CONTRACT or state.get("contract") != CONTRACT:
        raise SystemExit("unsupported or missing staged contract")
    batch, moves, problems = initial.pending_batch(document, baseline)
    if problems:
        raise SystemExit("invalid move batch: " + "; ".join(problems))
    problems = initial.validate_moves(moves, move_projection(baseline), move_projection(state))
    if problems:
        raise SystemExit("invalid reviewed move: " + "; ".join(problems))
    failures, notes = compare_debt(baseline, state, moves)
    failures.extend(compare_repeated(baseline, state, moves))
    lane = next(iter(state["coverage"]))
    if lane not in baseline["coverage"]:
        failures.append(f"missing executed baseline interpreter measurement: {lane}")
    else:
        failures.extend(compare_coverage(baseline["coverage"][lane], state["coverage"][lane], moves))
    return failures, notes, moves, batch


def comparison_for_refresh(baseline: dict | None, state: dict, document: dict) -> tuple:
    _, pending, problems = initial.pending_batch(document, baseline or {})
    if problems:
        raise SystemExit("invalid move batch: " + "; ".join(problems))
    if baseline is not None:
        return compare(baseline, state, document)
    if pending:
        raise SystemExit("cannot move debt without a baseline")
    return [], [], [], None


def refresh(baseline: dict | None, state: dict, document: dict, reason: str | None,
            admit: str | None = None) -> dict:
    if not reason or not reason.strip():
        raise SystemExit("staging/enabling/refresh needs an explicit recorded --reason")
    failures, notes, moves, batch = comparison_for_refresh(baseline, state, document)
    if failures and not (admit or "").strip():
        raise SystemExit("refresh would admit changes; need --admit REASON: " + "; ".join(failures))
    history = baseline.get("history", []) if baseline else []
    consumed = dict(baseline.get("consumed_batches", {})) if baseline else {}
    if moves:
        consumed[batch] = initial.moves_digest(moves)
    coverage = dict(baseline["coverage"]) if baseline else {}
    # Move other interpreter records too; their old measured source stays bound and is checked on that lane.
    for lane, measurement in coverage.items():
        coverage[lane] = {**measurement, "functions": {
            initial._moved(key, moves): entry for key, entry in measurement["functions"].items()}}
    coverage.update(state["coverage"])
    return {**state, "coverage": coverage, "consumed_batches": consumed,
            "history": [*history, {"reason": reason, "admit": admit, "failures": failures,
                                   "reductions": notes, "moves": moves, "sources": state["sources"]}]}


def main(argv: list[str] | None = None, *, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("observe", "check", "refresh"))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--moves", type=Path)
    parser.add_argument("--reason")
    parser.add_argument("--admit")
    args = parser.parse_args(argv)
    if args.command != "observe" and args.baseline is None:
        parser.error("check/refresh require an explicit staged --baseline")
    state = observe(root)
    if args.command == "observe":
        print(json.dumps({"stage": "observation only; no ratchet enabled", "contract": CONTRACT,
                          "annotation_count": sum(state["annotations"].values()),
                          "duplicate_members": len(state["duplicates"]), "coverage": state["coverage"]}, indent=2))
        return 0
    baseline = initial.load_json(args.baseline, {})
    document = initial.load_json(args.moves, {"moves": []}) if args.moves else {"moves": []}
    if args.command == "refresh":
        updated = refresh(baseline or None, state, document, args.reason, args.admit)
        initial._replace(args.baseline, updated)
        print("Staged measured baseline written; current gates unchanged")
        return 0
    if not baseline:
        raise SystemExit("missing staged baseline")
    failures, notes, _, _ = compare(baseline, state, document)
    for text in [*notes, *failures]:
        print(text)
    return int(bool(failures))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"staged gate refused: {error}") from None
