#!/usr/bin/env python3
"""Ratchet diagnostics, module boundaries and definition structure against reviewed allowances.

``check`` reports new, increased and reduced debt by stable identity.
``refresh`` lowers allowances and requires ``--admit REASON`` to raise them.
``init`` records existing debt once. Reviewed definition moves carry scoped
allowances across names and files, and each batch can be consumed only once.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path("policy/code-health-baseline.json")
MOVES = Path("policy/code-health-moves.json")
LINT_PATHS = ("scripts", "tests")
COMPLEXITY_PATHS = ("scripts",)
CORE = Path("scripts/cwo_core")
RUFF_RULES = "F,E9"
ANNOTATION_RULES = "ANN001,ANN201,ANN202"
ANNOTATION_PREFIXES = {"scripts": ("registered_", "offline_"),
                       "scripts/cwo_core": ("native_pool_qualification",)}
SIZE_LIMITS = {"definition_length": 100, "suite_nesting": 5}
COUNT_LABELS = {"f_e9": "F/E9 diagnostic", "annotations": "annotation diagnostic",
                "broad_catches": "broad catch", "private_imports": "private import"}
SCOPED_TABLES = ("complexity", *SIZE_LIMITS, "f_e9", "annotations", "broad_catches")
# --ignore-noqa: an inline suppression must not admit debt without a recorded reason.
RUFF_COMMAND = ["ruff", "check", "--no-cache", "--isolated", "--ignore-noqa", "--select", f"{RUFF_RULES},{ANNOTATION_RULES}",
                "--output-format", "json", "--exit-zero"]

Diagnostics = Callable[[Path, tuple[str, ...], list[str] | None], list[dict]]


# Identities ---------------------------------------------------------------


Definitions = list[tuple[int, int, str, ast.AST]]
Scopes = list[tuple[int, int, str]]


def _definitions(tree: ast.AST, source: str | None = None) -> Definitions:
    """``(first line, last line, identity, node)`` for every function and class.

    A repeated qualified name gets ``#2``, ``#3`` in definition order, and
    nested names extend the disambiguated parent, so two conditional
    definitions of ``f`` never share an identity. A definition's span starts
    at its first decorator.
    """
    found: Definitions = []
    seen: Counter[str] = Counter()
    lines = source.split("\n") if source is not None else None

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                base = f"{prefix}{child.name}"
                seen[base] += 1
                name = base + (f"#{seen[base]}" if seen[base] > 1 else "")
                start = child.decorator_list[0].lineno if child.decorator_list else child.lineno
                # A parenthesized decorator expression can start after its @ line.
                if lines is not None and child.decorator_list:
                    while start > 1 and not lines[start - 1].lstrip().startswith("@"):
                        start -= 1
                found.append((start, child.end_lineno or child.lineno, name, child))
                visit(child, name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _scopes(definitions: Definitions) -> Scopes:
    return [(start, end, name) for start, end, name, _ in definitions]


def _scope_at(scopes: Scopes, line: int) -> str:
    inside = [scope for scope in scopes if scope[0] <= line <= scope[1]]
    return max(inside, key=lambda scope: scope[0])[2] if inside else "<module>"


def _subject(message: str) -> str:
    """The name a diagnostic is about (its first backticked token), else its message without numbers."""
    quoted = re.search(r"`([^`]+)`", message)
    return quoted.group(1) if quoted else re.sub(r"\d+", "#", message)


_FILENAME_COMPONENT = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]*")


def _python_files_in_tree(root: Path, paths: tuple[str, ...]) -> list[str]:
    """Python source files under ``paths``: a filesystem walk that includes ``.py`` and ``.pyi`` files, independent
    of git state and of Ruff's default excludes and gitignore. Fails closed on symlinks, unsupported file types,
    unreadable entries, and unsafe filenames. Returns paths from root."""
    found: list[str] = []

    def scan_directory(dir_path: Path) -> None:
        """Recursively scan a directory with fail-closed entry inspection."""
        try:
            with os.scandir(dir_path) as entries:
                for entry in entries:
                    # Inspect every entry before any filtering. Let all OSErrors propagate as refusals.
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except OSError as e:
                        raise SystemExit(f"cannot inspect {Path(entry.path).relative_to(root)}: {e.strerror}")

                    # Classify only by lstat mode.
                    mode = entry_stat.st_mode
                    if stat.S_ISLNK(mode):
                        raise SystemExit(f"symlink not supported: {Path(entry.path).relative_to(root)}")
                    elif stat.S_ISDIR(mode):
                        # Recurse into directories.
                        scan_directory(Path(entry.path))
                    elif stat.S_ISREG(mode):
                        # Regular files: check extension and filename pattern.
                        if entry.name.endswith((".py", ".pyi")):
                            rel_path = Path(entry.path).relative_to(root)
                            # Validate every path component against the conservative pattern.
                            for component in rel_path.parts:
                                if not _FILENAME_COMPONENT.fullmatch(component):
                                    raise SystemExit(
                                        f"filename contains unsupported characters: {rel_path} "
                                        f"(component {component!r} does not match pattern)"
                                    )
                            # Refuse Python source inside __pycache__ at any depth.
                            if "__pycache__" in rel_path.parts:
                                raise SystemExit(
                                    f"Python source inside __pycache__ is not supported "
                                    f"(__pycache__ should only contain compiled files): {rel_path}"
                                )
                            # Refuse __init__.py or __init__.pyi directly inside the scripts/ CLI lint root.
                            # scripts/ is a directory of CLI modules, not a package, so scripts/__init__.py
                            # would be inventoried as CLI module "__init__" but imports like "from scripts import helper"
                            # would fail to produce the required import edge. Genuine packages below scripts/ are allowed.
                            if rel_path.parts == ("scripts", "__init__.py") or rel_path.parts == ("scripts", "__init__.pyi"):
                                raise SystemExit(
                                    f"__init__.py directly inside CLI lint root is not supported "
                                    f"(scripts/ is a directory of CLI modules, not a package): {rel_path}"
                                )
                            found.append(str(rel_path))
                        # Regular files with other suffixes are skipped silently.
                    elif stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
                        raise SystemExit(f"unsupported file type: {Path(entry.path).relative_to(root)}")
                    else:
                        # Refuse any unrecognized file mode.
                        raise SystemExit(f"unsupported file type: {Path(entry.path).relative_to(root)}")
        except OSError as e:
            raise SystemExit(f"cannot read directory {dir_path.relative_to(root)}: {e.strerror}")

    for base in paths:
        base_dir = root / base
        # Inspect each configured lint root with lstat before any walk.
        try:
            root_stat = base_dir.lstat()
        except OSError as e:
            raise SystemExit(f"cannot inspect configured lint root {base}: {e.strerror}")

        # Refuse if the root is missing, a symlink, not a directory, or unsupported.
        if stat.S_ISLNK(root_stat.st_mode):
            raise SystemExit(f"configured lint root is a symlink: {base}")
        elif not stat.S_ISDIR(root_stat.st_mode):
            if stat.S_ISREG(root_stat.st_mode):
                raise SystemExit(f"configured lint root is a regular file, not a directory: {base}")
            else:
                raise SystemExit(f"configured lint root is not a directory: {base}")

        # Walk the validated root.
        scan_directory(base_dir)

    return sorted(found)


def ruff_diagnostics(root: Path, paths: tuple[str, ...], inventory: list[str] | None = None) -> list[dict]:
    """Run Ruff over every inventoried source and require a JSON report."""
    if inventory is None:
        inventory = _python_files_in_tree(root, paths)
    if not inventory:
        raise SystemExit(f"no Python sources found under {', '.join(paths)}; the ratchet cannot verify the tree")
    env = {key: value for key, value in os.environ.items() if not key.startswith("RUFF_")}
    result = subprocess.run(
        [*RUFF_COMMAND, "--no-respect-gitignore", *inventory],
        cwd=root, capture_output=True, text=True, check=False, env=env,
    )
    if result.returncode != 0:
        raise SystemExit(f"ruff failed: {result.stderr.strip()[:400]}")
    if not result.stdout:
        raise SystemExit("ruff produced no output; the diagnostic ratchet cannot verify the tree is clean")
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"ruff output is not valid JSON: {error}")
    if not isinstance(records, list):
        raise SystemExit("ruff output must be a JSON array")
    return records


def ruff_version() -> str:
    result = subprocess.run(["ruff", "--version"], capture_output=True, text=True, check=False)
    match = re.fullmatch(r"ruff (\S+)\s*", result.stdout)
    if result.returncode != 0 or not match:
        raise SystemExit("ruff is not available; install the pinned version from requirements-test.txt")
    return match.group(1)


def diagnostic_identities(root: Path, records: Iterable[dict],
                          definitions: dict[str, Scopes] | None = None) -> Counter[str]:
    counts: Counter[str] = Counter()
    scopes = {} if definitions is None else definitions
    for record in records:
        path = Path(record["filename"])
        relative = (path.relative_to(root) if path.is_absolute() else path).as_posix()
        if relative not in scopes:
            try:
                source = (root / relative).read_text(encoding="utf-8")
                scopes[relative] = _scopes(_definitions(ast.parse(source), source))
            except (FileNotFoundError, SyntaxError, ValueError):
                scopes[relative] = []
        scope = _scope_at(scopes[relative], int(record["location"]["row"]))
        rule = record["code"]
        # For return findings the quoted function name is already represented by scope.
        subject = "<return>" if rule in ("ANN201", "ANN202") else _subject(record["message"])
        counts[f"{relative}::{scope}::{rule}::{subject}"] += 1
    return counts


def _plain_import_cli(node: ast.Import, cli: set[str]) -> set[str]:
    found = set()
    for alias in node.names:
        parts = alias.name.split(".")
        if parts[0] in cli:
            found.add(parts[0])
        elif parts[0] == "scripts" and len(parts) > 1 and parts[1] in cli:
            found.add(parts[1])
    return found


def _module_path(relative: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    parts = tuple(relative.removeprefix("scripts/").rsplit(".", 1)[0].split("/"))
    package = parts[:-1]
    return (package if parts[-1] == "__init__" else parts), package


def _module_index(inventory: list[str]) -> set[tuple[str, ...]]:
    modules = {()}
    for relative in inventory:
        if relative.startswith("scripts/"):
            parts, _ = _module_path(relative)
            modules.update(parts[:index] for index in range(1, len(parts) + 1))
    return modules


def _from_module(node: ast.ImportFrom, package: tuple[str, ...]) -> tuple[str, ...] | None:
    parts = tuple(node.module.split(".")) if node.module else ()
    if not node.level:
        return parts[1:] if parts[:1] == ("scripts",) else parts
    parents = node.level - 1
    return package[:len(package) - parents] + parts if parents <= len(package) else None


def _from_import_cli(node: ast.ImportFrom, module: tuple[str, ...], cli: set[str]) -> set[str]:
    targets = module[:1] if module else (alias.name for alias in node.names)
    return {target for target in targets if target in cli}


def _private_symbols(node: ast.ImportFrom) -> list[str]:
    return [alias.name for alias in node.names if alias.name.startswith("_") and not alias.name.startswith("__")]


def _module_imports(relative: str, tree: ast.Module, modules: set[tuple[str, ...]],
                    cli: set[str]) -> tuple[set[str], set[str]]:
    consumer, package = _module_path(relative)
    core = relative.startswith("scripts/cwo_core/") and relative.endswith(".py")
    name = ".".join(consumer)
    edges, private = set(), set()
    for node in ast.walk(tree):
        if core and isinstance(node, ast.Import):
            edges.update(f"{name} -> {target}" for target in _plain_import_cli(node, cli))
        if not isinstance(node, ast.ImportFrom):
            continue
        module = _from_module(node, package)
        if module is None:
            continue
        if core:
            edges.update(f"{name} -> {target}" for target in _from_import_cli(node, module, cli))
        if module in modules and module != consumer:
            exporter = ".".join(module) or "scripts"
            private.update(f"{name} -> {exporter}::{symbol}" for symbol in _private_symbols(node))
    return edges, private


def import_edges(root: Path, inventory: list[str] | None = None) -> set[str]:
    """Core-to-CLI edges in the scripts inventory."""
    if inventory is None:
        inventory = _python_files_in_tree(root, LINT_PATHS)
    modules = _module_index(inventory)
    cli = _cli_modules(modules)
    edges: set[str] = set()
    for relative in inventory:
        if relative.startswith("scripts/cwo_core/") and relative.endswith(".py"):
            tree = ast.parse((root / relative).read_text(encoding="utf-8"))
            edges.update(_module_imports(relative, tree, modules, cli)[0])
    return edges


def _cli_modules(modules: set[tuple[str, ...]]) -> set[str]:
    return {parts[0] for parts in modules if len(parts) == 1} - {"cwo_core"}


_BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.match_case)
_SUITES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.TryStar, ast.Match)


def _broad_families(exception: ast.expr | None) -> set[str]:
    if exception is None:
        return {"bare"}
    if isinstance(exception, ast.Tuple):
        return set().union(*(_broad_families(item) for item in exception.elts))
    if isinstance(exception, ast.Name) and exception.id in ("Exception", "BaseException"):
        return {exception.id}
    if (isinstance(exception, ast.Attribute) and exception.attr in ("Exception", "BaseException")
            and isinstance(exception.value, ast.Name) and exception.value.id == "builtins"):
        return {exception.attr}
    return set()


def _body_metrics(definition: ast.AST) -> tuple[int, int, Counter[str]]:
    complexity, nesting = 1, 0
    catches: Counter[str] = Counter()
    stack = [(node, 0) for node in ast.iter_child_nodes(definition)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, _BRANCHES):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
        if isinstance(node, ast.ExceptHandler):
            catches.update(_broad_families(node.type))
        if isinstance(node, _SUITES):
            depth += 1
            nesting = max(nesting, depth)
        elif_arm = None
        # A true elif shares the if header's indentation in the AST.
        if isinstance(node, ast.If) and node.orelse:
            child = node.orelse[0]
            if isinstance(child, ast.If) and child.col_offset == node.col_offset:
                elif_arm = child
        stack.extend((child, depth - (child is elif_arm)) for child in ast.iter_child_nodes(node))
    return complexity, nesting, catches


def function_complexity(root: Path, inventory: list[str] | None = None, paths: tuple[str, ...] = COMPLEXITY_PATHS) -> dict[str, int]:
    """Complexity of executable functions under the configured paths."""
    if inventory is None:
        inventory = _python_files_in_tree(root, paths)
    scores: dict[str, int] = {}
    for relative in inventory:
        if not relative.endswith(".py") or not any(relative.startswith(base + "/") for base in paths):
            continue
        path = root / relative
        for _, _, name, node in _definitions(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scores[f"{relative}::{name}"] = _body_metrics(node)[0]
    return scores


# Baseline -----------------------------------------------------------------


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    new_debt: list[str] = field(default_factory=list)  # the identities behind the failures


def _json_integer(text: str) -> int:
    """Parse exact integers without imposing the interpreter's decimal-string digit limit."""
    return int(Decimal(text))


def _integer_text(value: int) -> str:
    """Render an integer exactly, including integers beyond the decimal-string digit limit."""
    return str(Decimal(value))


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(text: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {text}")


def _json_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"nonfinite JSON number: {text}")
    return value


def load_json(path: Path, default: dict) -> dict:
    """Read a UTF-8 JSON object, refusing ambiguous or nonfinite input before consumers run."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default
    except (OSError, UnicodeError) as error:
        raise SystemExit(f"cannot read JSON {path}: {error}") from None
    try:
        document = json.loads(
            text, object_pairs_hook=_json_object, parse_constant=_reject_json_constant,
            parse_int=_json_integer, parse_float=_json_float,
        )
    except (ValueError, OverflowError, RecursionError) as error:
        raise SystemExit(f"cannot read JSON {path}: {error}") from None
    if not isinstance(document, dict):
        raise SystemExit(f"{path} must be a JSON object")
    return document


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _baseline_header_problems(baseline: dict, require_header: bool) -> list[str]:
    """Bind file headers; allow headerless programmatic comparison projections."""
    problems = []
    if require_header or "version" in baseline:
        version = baseline.get("version")
        if type(version) is not int or version != 1:
            problems.append("version must be the supported integer 1 (not bool)")
    if require_header or "tool" in baseline:
        tool = baseline.get("tool")
        if not isinstance(tool, dict):
            problems.append("tool must be an object containing a string ruff pin")
        elif not isinstance(tool.get("ruff"), str):
            problems.append("tool.ruff must be a string")
    return problems


def _object_list_problems(value: object, label: str) -> list[str]:
    """Require JSON object arrays before consumers access fields or expand history."""
    if not isinstance(value, list):
        return [f"{label} must be an array of objects"]
    return [f"{label} entry {index + 1} must be an object"
            for index, entry in enumerate(value) if not isinstance(entry, dict)]


def _baseline_history_problems(baseline: dict) -> list[str]:
    """Check optional history containers without revalidating historical move identities."""
    problems = []
    if "consumed_batches" in baseline:
        consumed = baseline["consumed_batches"]
        if not isinstance(consumed, dict):
            problems.append("consumed_batches must be an object mapping string batches to string digests")
        elif any(not isinstance(batch, str) or not isinstance(digest, str)
                 for batch, digest in consumed.items()):
            problems.append("consumed_batches batches and digests must be strings")
    if "moved" in baseline:
        problems.extend(_object_list_problems(baseline["moved"], "moved"))
    return problems


def _baseline_envelope_problems(baseline: dict, require_header: bool) -> list[str]:
    """Validate consumed envelope fields without imposing a general metadata schema."""
    problems = _baseline_header_problems(baseline, require_header)
    imports = baseline.get("imports")
    if not isinstance(imports, list):
        problems.append("imports must be an array of strings")
    elif any(not isinstance(edge, str) for edge in imports):
        problems.append("imports elements must be strings")
    if "admitted" in baseline:
        admitted = baseline["admitted"]
        if not isinstance(admitted, dict):
            problems.append("admitted must be an object mapping string identities to string reasons")
        elif any(not isinstance(identity, str) or not isinstance(reason, str)
                 for identity, reason in admitted.items()):
            problems.append("admitted identities and reasons must be strings")
    return problems


def _baseline_problems(baseline: object, *, require_header: bool = False) -> list[str]:
    """Validate consumed numeric and envelope fields, retaining optional metadata contracts."""
    if not isinstance(baseline, dict):
        return ["baseline must be an object"]
    problems = _baseline_envelope_problems(baseline, require_header)
    problems.extend(_baseline_history_problems(baseline))
    if not _nonnegative_integer(baseline.get("complexity_threshold")):
        problems.append("complexity_threshold must be a nonnegative integer (not bool)")
    for name in (*COUNT_LABELS, "complexity", *SIZE_LIMITS):
        table = baseline.get(name) if name in ("f_e9", "complexity") else baseline.get(name, {})
        if not isinstance(table, dict):
            problems.append(f"{name} must be an object mapping string identities to nonnegative integers")
            continue
        for identity, value in table.items():
            if not isinstance(identity, str):
                problems.append(f"{name} identities must be strings")
            if not _nonnegative_integer(value):
                problems.append(f"{name} allowances must be nonnegative integers (not bool)")
    return problems


def _require_baseline(baseline: object, *, require_header: bool = False) -> None:
    problems = _baseline_problems(baseline, require_header=require_header)
    if problems:
        raise SystemExit("invalid baseline:\n" + "\n".join(problems))


_FUNCTION_ID = re.compile(r"[^\s:]+\.pyi?::[A-Za-z_][\w]*(?:#\d+)?(?:\.[A-Za-z_][\w]*(?:#\d+)?)*")


def _scope_of(identity: str) -> str:
    """``file::scope`` of a diagnostic identity (``file::scope::rule::subject``)."""
    return "::".join(identity.split("::")[:2])


def _has_entries(scope: str, known: set[str]) -> bool:
    """Whether ``scope`` or a definition nested in it has baseline entries."""
    return any(entry == scope or entry.startswith(scope + ".") for entry in known)


def _move_problems(label: str, move: dict, known: set[str], seen: tuple[set[str], set[str]], state: dict,
                   vacated: set[str]) -> list[str]:
    source, target, reason = move.get("from"), move.get("to"), move.get("reason")
    problems = [] if isinstance(reason, str) and reason.strip() else [f"{label} has no reason"]
    if not (isinstance(source, str) and _FUNCTION_ID.fullmatch(source) and isinstance(target, str) and _FUNCTION_ID.fullmatch(target)):
        return [*problems, f"{label} must name functions as file::qualified.name"]
    sources, targets = seen
    if source == target or source in sources or target in targets:
        problems.append(f"{label} repeats or maps onto itself: {source} -> {target}")
    sources.add(source)
    targets.add(target)
    if not _has_entries(source, known):
        problems.append(f"{label} source has no baseline entry, itself or below it: {source}")
    if target in known and target not in vacated:
        problems.append(f"{label} target already has baseline entries (a merge needs refresh --admit): {target}")
    if target not in state["definitions"]:
        problems.append(f"{label} target is not a definition in the tree: {target}")
    return problems


def validate_moves(moves: list[dict], baseline: dict, state: dict) -> list[str]:
    """Problems with reviewed moves; any problem makes check and refresh refuse."""
    problems = _object_list_problems(moves, "moves")
    if problems or not moves:
        return problems
    known = {_scope_of(identity) for table in SCOPED_TABLES for identity in baseline.get(table, {})}
    seen: tuple[set[str], set[str]] = (set(), set())
    # A target whose own entries move elsewhere is free; the merge check below covers what remains.
    vacated = {move.get("from") for move in moves if isinstance(move.get("from"), str)}
    problems = [problem for index, move in enumerate(moves)
                for problem in _move_problems(f"move {index + 1}", move, known, seen, state, vacated)]
    return problems or _merge_problems(moves, baseline) or _unapplied_moves(moves, baseline)


def _merge_problems(moves: list[dict], baseline: dict) -> list[str]:
    """Baseline entries, descendants included, that the moves would map onto one another."""
    problems = []
    for table in SCOPED_TABLES:
        label = "diagnostics" if table == "f_e9" else f"{table.replace('_', ' ')} entries"
        mapped = Counter(_moved(identity, moves) for identity in baseline.get(table, {}))
        problems.extend(f"moves would merge {label} into {identity}"
                        for identity, count in sorted(mapped.items()) if count > 1)
    return problems


def _chosen(identity: str, moves: list[dict]) -> dict | None:
    """The most specific move whose source is the identity's scope or encloses it (``a.inner -> c`` over
    ``a -> b``), so the order of the moves file is irrelevant."""
    chosen = None
    for move in moves:
        source = move["from"]
        if identity == source or identity.startswith(source + "::") or identity.startswith(source + "."):
            if chosen is None or len(source) > len(chosen["from"]):
                chosen = move
    return chosen


def _moved(identity: str, moves: list[dict]) -> str:
    """Apply validated moves to a baseline identity: only its ``file::scope`` part changes."""
    chosen = _chosen(identity, moves)
    return identity if chosen is None else chosen["to"] + identity[len(chosen["from"]):]


def _unapplied_moves(moves: list[dict], baseline: dict) -> list[str]:
    """Moves that carry no baseline entry, because more specific moves take all of them."""
    applied = {id(_chosen(identity, moves)) for table in SCOPED_TABLES for identity in baseline.get(table, {})}
    return [f"move {index + 1} carries no baseline entry (more specific moves take them all): {move['from']}"
            for index, move in enumerate(moves) if id(move) not in applied]


def _canonical(value: object) -> str:
    """A serialization of a syntax tree that is the same on every supported interpreter: node types and
    fields, leaving out positions and empty fields (which ``ast.dump`` shows on some versions only)."""
    if isinstance(value, ast.AST):
        fields = [f"{name}={_canonical(child)}" for name, child in ast.iter_fields(value) if child is not None and child != []]
        return f"{type(value).__name__}({','.join(fields)})"
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    return repr(value)


def _fingerprint(node: ast.AST, module: str) -> str:
    """A line-independent fingerprint of a repeated definition: its code and the code of the whole file it is in,
    without positions or comments. Same-named definitions are told apart only by their order and by the code
    around them that selects one (a guard, an exception handler, an early exit), and none of that can be
    modelled completely, so any change to the file changes the fingerprint and asks for review."""
    return hashlib.sha256(f"{module}|{_canonical(node)}".encode("utf-8")).hexdigest()[:16]


def definition_inventory(root: Path, inventory: list[str] | None = None, paths: tuple[str, ...] = LINT_PATHS) -> tuple[set[str], dict[str, list[str]]]:
    """Definition identities and ordered fingerprints for repeated names."""
    if inventory is None:
        inventory = _python_files_in_tree(root, paths)
    identities: set[str] = set()
    repeated: dict[str, list[str]] = {}
    for relative in sorted(inventory):
        if not any(relative.startswith(base + "/") for base in paths):
            continue
        path = root / relative
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, ValueError):
            continue
        definitions = _definitions(tree)
        identities.update(f"{relative}::{name}" for _, _, name, _ in definitions)
        repeated.update(_repeated_fingerprints(relative, tree, definitions))
    return identities, repeated


def _repeated_fingerprints(relative: str, tree: ast.Module, definitions: Definitions) -> dict[str, list[str]]:
    grouped: dict[str, list[ast.AST]] = {}
    for _, _, name, node in definitions:
        grouped.setdefault(_unnumbered(name), []).append(node)
    repeated = {name: nodes for name, nodes in grouped.items() if len(nodes) > 1}
    if not repeated:
        return {}
    module = hashlib.sha256(_canonical(tree).encode("utf-8")).hexdigest()
    return {f"{relative}::{name}": [_fingerprint(node, module) for node in nodes]
            for name, nodes in repeated.items()}


def _unnumbered(identity: str) -> str:
    """``identity`` without definition numbers, removed from its scope only: a file name may contain ``#2``."""
    file, separator, scope = identity.partition("::")
    return file + separator + re.sub(r"#\d+", "", scope) if separator else re.sub(r"#\d+", "", identity)


def current_state(root: Path, diagnostics: Diagnostics) -> dict:
    """Measure one inventory, sharing each parsed file across the ratchets."""
    inventory = _python_files_in_tree(root, LINT_PATHS)
    records = diagnostics(root, LINT_PATHS, inventory)
    modules = _module_index(inventory)
    cli = _cli_modules(modules)
    state: dict = {key: {} for key in (*SCOPED_TABLES, "private_imports", "repeated")}
    state["definitions"] = set()
    edges: set[str] = set()
    scopes: dict[str, Scopes] = {}
    for relative in inventory:
        script = relative.startswith("scripts/")
        executable = script and relative.endswith(".py")
        try:
            source = (root / relative).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            if executable:
                raise
            scopes[relative] = []
            continue
        definitions = _definitions(tree, source)
        scopes[relative] = _scopes(definitions)
        state["definitions"].update(f"{relative}::{name}" for _, _, name, _ in definitions)
        state["repeated"].update(_repeated_fingerprints(relative, tree, definitions))
        if script:
            core_edges, private = _module_imports(relative, tree, modules, cli)
            edges.update(core_edges)
            state["private_imports"].update(dict.fromkeys(private, 1))
        if executable:
            _record_structure(state, relative, tree, definitions)
    state["imports"] = sorted(edges)
    annotation_codes = set(ANNOTATION_RULES.split(","))
    for identity, count in diagnostic_identities(root, records, scopes).items():
        relative, _, rule, _ = identity.split("::", 3)
        if rule not in annotation_codes:
            state["f_e9"][identity] = count
        elif _in_annotation_scope(relative):
            state["annotations"][identity] = count
    return state


def _in_annotation_scope(relative: str) -> bool:
    directory, _, filename = relative.rpartition("/")
    return filename.endswith(".py") and filename.startswith(ANNOTATION_PREFIXES.get(directory, ()))


def _record_structure(state: dict, relative: str, tree: ast.Module, definitions: Definitions) -> None:
    for start, end, name, node in [(0, 0, "<module>", tree), *definitions]:
        identity = f"{relative}::{name}"
        complexity, nesting, catches = _body_metrics(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            state["complexity"][identity] = complexity
            state["definition_length"][identity] = end - start + 1
            state["suite_nesting"][identity] = nesting
        state["broad_catches"].update({f"{identity}::{family}": count for family, count in catches.items()})


def _compare_counts(label: str, known: dict, current: dict, report: Report) -> None:
    for identity in sorted(known.keys() | current.keys()):
        count, allowance = current.get(identity, 0), known.get(identity, 0)
        if count > allowance:
            report.failures.append(f"new {label}: {identity} ({_integer_text(count)} now, {_integer_text(allowance)} in baseline)")
            report.new_debt.append(identity)
        elif count < allowance:
            report.notes.append(f"{label} reduced: {identity} ({_integer_text(count)} now, {_integer_text(allowance)} in baseline)")


def _compare_imports(baseline: dict, state: dict, report: Report) -> None:
    for edge in sorted(set(state["imports"]) - set(baseline["imports"])):
        report.failures.append(f"new core-to-CLI import: {edge}")
        report.new_debt.append(edge)
    for edge in sorted(set(baseline["imports"]) - set(state["imports"])):
        report.notes.append(f"core-to-CLI import removed: {edge}")


def _compare_sizes(table: str, threshold: int, known: dict, current: dict, report: Report) -> None:
    label = table.replace("_", " ")
    subject = "function" if table == "complexity" else "definition"
    for identity, value in sorted(current.items()):
        if identity not in known:
            if value > threshold:
                report.failures.append(f"new {subject} over the {label} threshold {_integer_text(threshold)}: {identity} ({_integer_text(value)})")
                report.new_debt.append(identity)
        elif value > known[identity]:
            report.failures.append(f"{label} grew: {identity} ({_integer_text(value)}, baseline {_integer_text(known[identity])})")
            report.new_debt.append(identity)
        elif value < known[identity]:
            report.notes.append(f"{label} reduced: {identity} ({_integer_text(value)}, baseline {_integer_text(known[identity])})")
    for identity in sorted(known.keys() - current.keys()):
        report.notes.append(f"baseline {subject} gone: {identity}")


def _under(identity: str, name: str) -> bool:
    plain = _unnumbered(identity)
    return plain == name or plain.startswith(name + ".")


def _debt_under(name: str, *tables: dict[str, int]) -> tuple[dict, ...]:
    """Entries for repeated definitions and their descendants."""
    return tuple({identity: value for identity, value in table.items() if _under(_scope_of(identity), name)}
                 for table in tables)


def _repeated_change(old_prints: object, new_prints: list[str] | None, old_debt: tuple, new_debt: tuple) -> str | None:
    old_count = len(old_prints) if isinstance(old_prints, list) else int(old_prints or 1)  # type: ignore[arg-type]
    new_count = len(new_prints) if new_prints else 1
    if old_count != new_count:
        return f"{old_count} -> {new_count}"
    if old_prints != new_prints or old_debt != new_debt:
        return "their code, order or debt changed, and only their order tells them apart"
    return None


def _compare_repeated(baseline: dict, moves: list[dict], state: dict, report: Report,
                      known: dict, limits: dict[str, int]) -> None:
    """Same-named definitions are told apart only by their order, so for a repeated name that carries debt, any
    change to its definitions' number, code (line-independent fingerprints), order or debt needs review."""
    before = {_moved(name, moves): prints for name, prints in baseline.get("repeated", {}).items()}
    after = state["repeated"]
    for name in sorted(set(before) | set(after)):
        old = _debt_under(name, *(known[table] for table in SCOPED_TABLES))
        if not any(old):
            continue
        current = _debt_under(name, *(state.get(table, {}) for table in SCOPED_TABLES))
        new = tuple({identity: value for identity, value in values.items()
                     if value > limits.get(table, 0) or identity in previous}
                    for table, values, previous in zip(SCOPED_TABLES, current, old))
        change = _repeated_change(before.get(name), after.get(name), old, new)
        if change:
            report.failures.append(f"repeated definitions changed: {name} ({change}); review and refresh --admit")
            report.new_debt.append(name)


def compare(baseline: dict, moves: list[dict], state: dict) -> Report:
    report = Report()
    problems = _baseline_problems(baseline)
    if problems:
        report.failures.extend(f"invalid baseline: {problem}" for problem in problems)
        report.new_debt.extend(problems)
        return report
    problems = validate_moves(moves, baseline, state)
    if problems:
        report.failures.extend(f"invalid move: {problem}" for problem in problems)
        report.new_debt.extend(problems)
        return report
    known = {table: {_moved(identity, moves): value for identity, value in baseline.get(table, {}).items()}
             for table in SCOPED_TABLES}
    for table, label in COUNT_LABELS.items():
        _compare_counts(label, known.get(table, baseline.get(table, {})), state.get(table, {}), report)
    _compare_imports(baseline, state, report)
    limits = {"complexity": baseline["complexity_threshold"], **SIZE_LIMITS}
    for table, threshold in limits.items():
        _compare_sizes(table, threshold, known[table], state.get(table, {}), report)
    _compare_repeated(baseline, moves, state, report, known, limits)
    return report


def _recorded_tables(baseline: dict, state: dict) -> dict[str, dict[str, int]]:
    limits = {"complexity": baseline["complexity_threshold"], **SIZE_LIMITS}
    return {table: {identity: value for identity, value in sorted(state.get(table, {}).items())
                    if table not in limits or value > limits[table]}
            for table in (*COUNT_LABELS, *limits)}


def refresh(baseline: dict, moves: list[dict], state: dict, admit: str | None,
            batch: str | None = None) -> tuple[dict, list[str]]:
    """The baseline rewritten to the current state; raises SystemExit if that would admit debt without ``admit``.
    Applied moves are recorded with their reasons, and their batch identifier is recorded as consumed."""
    _require_baseline(baseline)
    problems = _object_list_problems(moves, "moves")
    if problems:
        raise SystemExit("fix the moves file before refreshing:\n" + "\n".join(f"invalid move: {p}" for p in problems))
    if moves and not batch:
        raise ValueError("applied moves need their batch identifier")
    report = compare(baseline, moves, state)
    if any(failure.startswith("invalid move:") for failure in report.failures):
        raise SystemExit("fix the moves file before refreshing:\n" + "\n".join(report.failures))
    if report.failures and not admit:
        raise SystemExit("refresh would admit new debt; review it and pass --admit REASON:\n" + "\n".join(report.failures))
    admitted = dict(baseline.get("admitted", {}))
    if admit:
        for identity in report.new_debt:
            admitted[identity] = admit
    consumed = dict(baseline.get("consumed_batches", {}))
    if moves:
        consumed[batch] = moves_digest(moves)
    updated = {
        **baseline,
        **_recorded_tables(baseline, state),
        "imports": sorted(state["imports"]),
        "admitted": admitted,
        "repeated": dict(sorted(state["repeated"].items())),
        "moved": [*baseline.get("moved", []), *moves],
        "consumed_batches": consumed,
    }
    return updated, report.notes


def _json_key(key: object) -> str:
    if isinstance(key, str):
        return json.dumps(key)
    if key is None or isinstance(key, (bool, float)):
        return json.dumps(json.dumps(key))
    if isinstance(key, int):
        return json.dumps(_integer_text(key))
    raise TypeError("keys must be str, int, float, bool or None")


def _json_container(value: dict | list | tuple, level: int, indent: int | None, sort_keys: bool) -> list[tuple]:
    """Prepare formatting and child events without recursively encoding children."""
    opening, closing = ("{", "}") if isinstance(value, dict) else ("[", "]")
    if not value:
        return [("text", opening + closing, 0)]
    if isinstance(value, dict):
        items = sorted(value.items()) if sort_keys else value.items()
    else:
        items = ((None, child) for child in value)
    newline = "\n" if indent is not None else ""
    prefix = " " * (indent * (level + 1)) if indent is not None else ""
    separator = "," + newline if indent is not None else ", "
    parts = [("text", opening + newline, 0)]
    for index, (key, child) in enumerate(items):
        if index:
            parts.append(("text", separator, 0))
        lead = prefix + (_json_key(key) + ": " if isinstance(value, dict) else "")
        parts.append(("text", lead, 0))
        parts.append(("value", child, level + 1))
    suffix = newline + (" " * (indent * level) if indent is not None else "") + closing
    parts.append(("text", suffix, 0))
    return parts


def _json_text(value: object, level: int = 0, seen: set[int] | None = None, *,
               indent: int | None = 2, sort_keys: bool = False) -> str:
    """Encode JSON iteratively, preserving stdlib formatting and exact integer digits."""
    active = set(seen or ())
    stack = [("value", value, level)]
    chunks = []
    while stack:
        action, value, level = stack.pop()
        if action == "text":
            chunks.append(value)
        elif action == "leave":
            active.remove(value)
        elif isinstance(value, (dict, list, tuple)):
            if id(value) in active:
                raise ValueError("Circular reference detected")
            active.add(id(value))
            stack.append(("leave", id(value), 0))
            stack.extend(reversed(_json_container(value, level, indent, sort_keys)))
        elif isinstance(value, int) and not isinstance(value, bool):
            chunks.append(_integer_text(value))
        else:
            chunks.append(json.dumps(value))
    return "".join(chunks)


def _replace(path: Path, data: dict) -> None:
    """Write ``data`` to ``path`` as JSON so that a reader sees the old file or the new one, never part of one."""
    temporary = path.with_name(f".{path.name}.tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(_json_text(data) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write(root: Path, baseline: dict) -> None:
    _replace(root / BASELINE, baseline)


def _check(baseline: dict, moves: list[dict], state: dict) -> int:
    report = compare(baseline, moves, state)
    for note in report.notes:
        print(f"note: {note} (run refresh to lower the baseline)")
    for failure in report.failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if report.failures:
        return 1
    print(f"Code-health ratchets passed: {_integer_text(sum(state['f_e9'].values()))} recorded F/E9 diagnostics, "
          f"{len(state['imports'])} core-to-CLI imports, {len(state['private_imports'])} private imports, "
          f"{sum(state['broad_catches'].values())} broad catches, and {sum(state['annotations'].values())} annotation findings. "
          f"Thresholds: complexity {_integer_text(baseline['complexity_threshold'])}, "
          f"definition length {SIZE_LIMITS['definition_length']}, suite nesting {SIZE_LIMITS['suite_nesting']}.")
    return 0


def _load(root: Path, command: str, reason: str | None) -> tuple[dict, dict]:
    baseline = load_json(root / BASELINE, {})
    if not baseline:
        raise SystemExit(f"missing baseline {BASELINE}")
    _require_baseline(baseline, require_header=True)
    debt_tables = (*COUNT_LABELS, "imports", "complexity", *SIZE_LIMITS)
    if command == "init" and (baseline.get("created") or any(baseline.get(table) for table in debt_tables)):
        raise SystemExit("init records existing debt only once, into an empty baseline; use refresh")
    if command == "init" and not (reason or "").strip():
        raise SystemExit("init needs --reason")
    return baseline, load_json(root / MOVES, {"moves": []})


_BATCH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")


def moves_digest(moves: list[dict]) -> str:
    """The exact content of one batch, order included, as ``refresh`` records it against the batch identifier."""
    return hashlib.sha256(_json_text(moves, indent=None, sort_keys=True).encode("utf-8")).hexdigest()


def pending_batch(document: dict, baseline: dict) -> tuple[str | None, list[dict], list[str]]:
    """The moves file's batch identifier, the moves still to apply, and problems that make check and refresh refuse.

    Content cannot identify a review: an equal batch may be a fresh review, and a reordered one may be a stale
    batch. So each reviewed batch names itself, and ``refresh`` records the identifier as consumed together with
    the baseline, in one write. A consumed batch still listed unchanged means the refresh was interrupted before
    clearing it, so nothing is pending. A consumed identifier with any other content (reordered, extended, mixed)
    is refused; a new batch needs a new identifier, whatever its content."""
    if not isinstance(document, dict):
        return None, [], ["the moves file must be an object"]
    if not isinstance(baseline, dict):
        return None, [], ["baseline must be an object"]
    problems = _baseline_history_problems(baseline)
    if problems:
        return None, [], [f"invalid baseline: {problem}" for problem in problems]
    moves, batch = document.get("moves", []), document.get("batch")
    problems = _object_list_problems(moves, "moves")
    if problems:
        return None, [], problems
    if not moves:
        return None, [], []
    if not (isinstance(batch, str) and _BATCH_ID.fullmatch(batch)):
        return None, [], ["a batch of moves needs a batch identifier (letters, digits, '.', '_', ':' or '-'), "
                          "fresh for each review"]
    consumed = baseline.get("consumed_batches", {})
    if batch not in consumed:
        return batch, moves, []
    if consumed[batch] == moves_digest(moves):
        return batch, [], []
    return batch, [], [f"batch {batch} was already applied, and its moves have changed since; "
                       "a newly reviewed batch needs a new identifier"]


def _clear_moves(root: Path) -> None:
    _replace(root / MOVES, {"version": 2, "batch": None, "moves": []})


def _refuse_batch(command: str, problems: list[str]) -> int:
    if command != "check":
        raise SystemExit("fix the moves file before refreshing:\n" + "\n".join(f"invalid move: {p}" for p in problems))
    for problem in problems:
        print(f"FAIL: invalid move: {problem}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None, *, diagnostics: Diagnostics | None = None, root: Path = ROOT) -> int:
    cli = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    cli.add_argument("command", nargs="?", choices=("check", "refresh", "init"), default="check")
    cli.add_argument("--admit", help="Reason for admitting new or larger debt during refresh.")
    cli.add_argument("--reason", help="Why the baseline is created from the current tree (init only).")
    args = cli.parse_args(argv)
    baseline, document = _load(root, args.command, args.reason)
    if args.admit is not None and not args.admit.strip():
        raise SystemExit("--admit needs a reason")
    batch, pending, problems = pending_batch(document, baseline)
    if problems:
        return _refuse_batch(args.command, problems)
    if diagnostics is None:
        version = ruff_version()
        if version != baseline["tool"]["ruff"]:
            raise SystemExit(f"ruff {version} is not the pinned {baseline['tool']['ruff']}")
        diagnostics = ruff_diagnostics
    state = current_state(root, diagnostics)
    listed = bool(document.get("moves"))
    if args.command == "check":
        if listed and not pending:
            print("note: the moves file still lists moves an earlier refresh applied; refresh clears them")
        return _check(baseline, pending, state)
    updated, notes = refresh(baseline, pending, state, admit="initial" if args.command == "init" else args.admit,
                             batch=batch)
    if args.command == "init":
        updated["admitted"] = {}
        updated["created"] = args.reason
    _write(root, updated)
    if listed:
        # Applied moves are consumed: recorded with their reasons in the baseline, then removed from the file.
        _clear_moves(root)
    for note in notes:
        print(f"refreshed: {note}")
    print(f"Baseline written: {BASELINE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
