"""Bounded release evidence joins; semantic decisions are external review trust.

No inventoried module is imported. Resolution covers explicit bounded families only.
The installed inventory is small; generated data is only written to evidence/.
"""
from __future__ import annotations

import ast
from functools import lru_cache
import hashlib
import json
import os
import re
from pathlib import Path
import stat


INVENTORY = "policy/release-effect-routes.json"
IGNORED = {".git", "__pycache__", ".ruff_cache"}
# Complete script bindings and individual primitive dispositions need more than
# the old 200,000 bytes. Keep authored installed data finite; traces stay external.
MAX_INVENTORY = 512 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 12000
WITNESS_SEMANTICS = {
    "zero-effect-refusal": "zero-effect-and-matched-positive",
    "operator-contract": "operator-selection-and-limits",
    "inspection-only": "inspection-selection-and-limits",
    "matched-positive": "matched-positive-for-specified-refusal",
}


class Refused(ValueError):
    """Release evidence is missing, stale or unrelated."""


def need(condition, message):
    if not condition:
        raise Refused(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def mark(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read_file(root, relative, limit=MAX_FILE):
    """Bound every read, refuse symlink parents/leaves, special files and drift."""
    parts = Path(relative).parts
    need(parts and not Path(relative).is_absolute() and not ({"..", "."} & set(parts)), "unsafe relative path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "regular bounded file required")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            linked = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            need(mark(before) == mark(after) == mark(linked) and len(data) == before.st_size,
                 "file changed during read")
            return data, {"sha256": digest(data), "mode": stat.S_IMODE(before.st_mode), "size": len(data)}
    finally:
        os.close(directory)


def _walk(root, prefix="", budget=None):
    if budget is None:
        budget = [MAX_FILES * 2]
    need(len(Path(prefix).parts) <= 32, "source directory depth exceeded")
    entries = []
    with os.scandir(root / prefix) as scan:
        for entry in scan:
            budget[0] -= 1
            need(budget[0] >= 0, "source entry budget exceeded")
            entries.append(entry)
    for entry in sorted(entries, key=lambda entry: entry.name):
        if entry.name in IGNORED:
            continue
        relative = f"{prefix}/{entry.name}".lstrip("/")
        info = entry.stat(follow_symlinks=False)
        need(not stat.S_ISLNK(info.st_mode), f"source link refused: {relative}")
        if stat.S_ISDIR(info.st_mode):
            yield from _walk(root, relative, budget)
        else:
            need(stat.S_ISREG(info.st_mode), f"source special file refused: {relative}")
            yield relative


def source(root):
    files, contents, total = {}, {}, 0
    for relative in _walk(root):
        data, identity = read_file(root, relative)
        total += len(data)
        need(len(files) < MAX_FILES and total <= MAX_TOTAL, "source budget exceeded")
        files[relative], contents[relative] = identity, data
    need("scripts" in {Path(name).parts[0] for name in files}, "scripts source required")
    return files, contents


@lru_cache(maxsize=4)
def _symbols(data):
    tree = ast.parse(data)
    result = {}

    def visit(body, prefix=""):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}.{node.name}".lstrip(".")
                need(name not in result, f"ambiguous declaration: {name}")
                result[name] = node
                visit(node.body, name)
    visit(tree.body)
    return tree, result


def body(contents, point):
    path, symbol = point["path"], point["symbol"]
    need(path.endswith(".py") and path in contents, "declaration source missing")
    _tree, symbols = _symbols(contents[path])
    need(symbol in symbols, f"declaration missing: {path}:{symbol}")
    node = symbols[symbol]
    lines = contents[path].splitlines(keepends=True)
    first = min([node.lineno] + [item.lineno for item in node.decorator_list])
    data = b"".join(lines[first - 1:node.end_lineno])
    return {"path": path, "symbol": symbol, "line": first, "sha256": digest(data)}, data.decode()


def _point(contents, point):
    path, line, text = point["path"], point["line"], point["text"]
    need(type(line) is int and line > 0 and path in contents and bool(text.strip()), "invalid source point")
    if "col" in point:
        col, end_line, end_col = point["col"], point["end_line"], point["end_col"]
        need(all(type(item) is int for item in (col, end_line, end_col)) and
             0 <= col and line <= end_line and 0 <= end_col, "invalid source span")
        lines = contents[path].splitlines(keepends=True)
        need(end_line <= len(lines) and col <= len(lines[line - 1]) and
             end_col <= len(lines[end_line - 1]) and (line < end_line or col < end_col), "invalid source span")
        selected = lines[line - 1:end_line]
        selected[-1] = selected[-1][:end_col]
        selected[0] = selected[0][col:]
        need(b"".join(selected).decode().strip() == text.strip(), f"stale source span: {path}:{line}:{col}")
        return {"path": path, "line": line, "text": text.strip(),
                "col": col, "end_line": end_line, "end_col": end_col}
    lines = contents[path].decode().splitlines()
    span = len(text.splitlines())
    need(line <= len(lines) and "\n".join(lines[line - 1:line - 1 + span]).strip() == text.strip(),
         f"stale source point: {path}:{line}")
    return {"path": path, "line": line, "text": text.strip()}



GUARD_CALLS = frozenset(['R.live_availability.require_n1_live', 'R.live_availability.require_pool_live', '_need', '_require_live_activation', '_require_native_rpc', 'checked.require_intent', 'checked_narrative', 'handle.require_intent', 'live_availability.require_campaign_live', 'live_availability.require_n1_live', 'live_availability.require_pool_live', 'need', 'normalize_command_spec', 'pre_allocation_check', 'require_audited_local_execution', 'require_clean', 'require_maintenance_operation', 'require_n1_live', 'require_recovery_authority', 'require_v8_live_routes', 'require_waiver_reason', 'revalidate_reservation_live', 'self._guard', 'self._handle.require_intent', 'self._preflight_tool_launch', 'self._require_campaign_live_route', 'self.factory.require_effect', 'validate_advisory_hook_configuration', 'validate_workgraph_plan'])
SHELL_GUARDS = frozenset(['entries="$(projection_list --list-entries)" || die "source does not satisfy the installed projection ($PROJECTION); nothing was installed"', 'if ! python3 -B "$CHECKER" --source-dir "$SOURCE_DIR" --installed-dir "$INSTALL_STAGE_DIR" --write-manifest --check; then', 'if [ "$DRY_RUN" -eq 1 ]; then', 'if [[ "$DRY_RUN" -eq 0 ]]; then', 'if [[ "$DRY_RUN" -eq 1 ]]; then', 'if [[ "$REPLACE" -eq 1 && "$DRY_RUN" -eq 0 ]]; then', 'if [[ "$WRITE_CONFIG" -eq 1 && "$DRY_RUN" -eq 0 ]]; then'])
DURABLE_CALLS = {"capability.claim"}
GUARD_CALLS = GUARD_CALLS | {"self.handle.require_intent"}


@lru_cache(maxsize=4)
def _gate_tree(data):
    return ast.parse(data)


@lru_cache(maxsize=4)
def _line_offsets(data):
    result = [0]
    for line in data.splitlines(keepends=True):
        result.append(result[-1] + len(line))
    return tuple(result)


def _byte_offset(data, line, column):
    return _line_offsets(data)[line - 1] + column


def _node_interval(data, node):
    return (_byte_offset(data, node.lineno, node.col_offset),
            _byte_offset(data, node.end_lineno, node.end_col_offset))


def _selected_interval(data, point):
    lines = data.splitlines(keepends=True)
    line = point["line"]
    if "col" in point:
        return (_byte_offset(data, line, point["col"]),
                _byte_offset(data, point["end_line"], point["end_col"]))
    end = line + len(point["text"].splitlines()) - 1
    col = len(lines[line - 1]) - len(lines[line - 1].lstrip())
    return _byte_offset(data, line, col), _byte_offset(data, end, len(lines[end - 1].rstrip()))


def _callee(node):
    return ast.unparse(node.func) if isinstance(node.func, (ast.Name, ast.Attribute)) else ""


def _call_guard(data, node, selected):
    value = node.value
    if not isinstance(value, ast.Call) or _callee(value) not in GUARD_CALLS:
        return None
    start, end = _node_interval(data, value)
    anchor = _node_interval(data, node)[0]
    if selected[0] in {anchor, start} and selected[1] <= end:
        return start, end
    return None


def _conditional_guard(data, node, point, selected):
    if isinstance(node.test, ast.Constant):
        return None
    start = _node_interval(data, node)[0]
    predicate = _node_interval(data, node.test)
    body_start = _node_interval(data, node.body[0])[0]
    if selected[0] == start and selected[1] <= body_start:
        return start, predicate[1]
    if "col" in point and selected == predicate:
        return predicate
    return None


def _python_guard(data, point, selected):
    return _python_guard_span(data, selected, "col" in point)


@lru_cache(maxsize=256)
def _python_guard_span(data, selected, columns):
    for node in ast.walk(_gate_tree(data)):
        result = None
        if isinstance(node, ast.If):
            result = _conditional_guard(data, node, {"col": 0} if columns else {}, selected)
        elif isinstance(node, ast.Raise):
            span = _node_interval(data, node)
            if selected[0] == span[0] and selected[1] <= span[1]:
                result = span
        elif isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign)):
            result = _call_guard(data, node, selected)
        if result is not None:
            return result
    raise Refused("unsupported gate form")



def _shell_heredoc(text, position, previous):
    match = re.match(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2", text[position:])
    need(match is not None and previous is None, "unsupported shell context")
    return match.end(), (match[3], bool(match[1]))

def _shell_line(text, quote):
    position, delimiter, continued = 0, None, False
    while position < len(text):
        char = text[position]
        if char == "\\" and quote != "'":
            continued = text[position + 1:] in {"\n", "\r\n"}
            position += 2
            continue
        if quote:
            if char == quote[-1]:
                quote = ""
        elif text.startswith("$'", position):
            quote = "$'"
            position += 2
            continue
        elif char in {"'", '\"'}:
            quote = char
        elif char == "#":
            break
        elif text.startswith("<<", position):
            consumed, delimiter = _shell_heredoc(text, position, delimiter)
            position += consumed
            continue
        position += 1
    return quote, delimiter, continued


def _shell_context(data, line):
    quote, pending, continued = "", None, False
    for text in data.decode().splitlines(keepends=True)[:line - 1]:
        if pending:
            selected = text.rstrip("\r\n")
            if pending[1]:
                selected = selected.lstrip("\t")
            if selected == pending[0]:
                pending = None
            continue
        quote, pending, continued = _shell_line(text, quote)
    return not quote and pending is None and not continued


def gate_span(contents, point):
    """Selected guard syntax, not proof of execution order or refusal causality."""
    observed = _point(contents, point)
    path = observed["path"]
    data = contents[path]
    selected = _selected_interval(data, observed)
    if path.endswith(".py"):
        span = _python_guard(data, observed, selected)
    else:
        text = data.decode().splitlines()[observed["line"] - 1].strip()
        need(path.endswith(".sh") and text == observed["text"] and text in SHELL_GUARDS
             and _shell_context(data, observed["line"]), "unsupported gate form")
        span = selected
    return path, *span


def _effect_interval(data, point):
    selected = _selected_interval(data, point)
    if "col" in point or not point["path"].endswith(".py"):
        return selected
    return _call_intersection(data, selected)


@lru_cache(maxsize=256)
def _call_intersection(data, selected):
    candidates = [_node_interval(data, node) for node in ast.walk(_gate_tree(data))
                  if isinstance(node, ast.Call)]
    intersecting = [span for span in candidates if max(span[0], selected[0]) < min(span[1], selected[1])]
    return min(intersecting, key=lambda span: (span[0], -span[1])) if intersecting else selected


def _gate_effects(contents, routes, hits):
    effects = set()
    for route in routes:
        for point in route.get("effect_points", []):
            observed = _point(contents, point)
            effects.add((point["path"], *_effect_interval(contents[point["path"]], observed)))
    for path, line, col, end, end_col, _family, _sha in hits:
        effects.add((path, _byte_offset(contents[path], line, col), _byte_offset(contents[path], end, end_col)))
    for path, data in contents.items():
        if path.startswith("scripts/") and path.endswith(".py"):
            effects.update((path, *_node_interval(data, node)) for node in ast.walk(_gate_tree(data))
                           if isinstance(node, ast.Call) and _callee(node) in DURABLE_CALLS)
    return effects


def _check_gate_effects(contents, routes, hits):
    effects = _gate_effects(contents, routes, hits)
    for route in routes:
        for point in route["gates"] + route.get("review_gates", []):
            path, start, end = gate_span(contents, point)
            need(not any(path == other and max(start, first) < min(end, last)
                         for other, first, last in effects), "gate overlaps effect")
        _check_route_order(contents, route)


@lru_cache(maxsize=4)
def _structure(data):
    tree = _gate_tree(data)
    parents = {child: (node, field, index) for node in ast.walk(tree)
            for field, value in ast.iter_fields(node) if isinstance(value, list)
            for index, child in enumerate(value) if isinstance(child, ast.AST)} | {
                value: (node, field, None) for node in ast.walk(tree)
                for field, value in ast.iter_fields(node) if isinstance(value, ast.AST)}
    return tree, parents, {}


def _parents(data):
    return _structure(data)[1]


def _ancestors(data, node):
    parents, result = _parents(data), []
    while node in parents:
        node, field, index = parents[node]
        result.append((node, field, index))
    return result


def _owner(data, node):
    return next((parent for parent, _field, _index in _ancestors(data, node)
                 if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))), _structure(data)[0])


def _point_node(data, point, *, guard=False):
    span = gate_span({point["path"]: data}, point)[1:] if guard else _effect_interval(data, point)
    return _interval_node(data, *span)


def _interval_node(data, start, end):
    span = start, end
    _tree, parents, selections = _structure(data)
    if span in selections:
        return selections[span]
    candidates = [node for node in parents if hasattr(node, "lineno")
                  and _node_interval(data, node)[0] <= span[0] and span[1] <= _node_interval(data, node)[1]]
    need(candidates, "source point has no structural node")
    result = min(candidates, key=lambda node: (_node_interval(data, node)[1] - _node_interval(data, node)[0],
                                              not isinstance(node, ast.Call)))
    if len(selections) < 256:
        selections[span] = result
    return result


def _statement(data, node):
    if isinstance(node, ast.stmt):
        return node
    return next(parent for parent, _field, _index in _ancestors(data, node) if isinstance(parent, ast.stmt))


def _stops(body, *, raising=False):
    if not body:
        return False
    node = body[-1]
    if isinstance(node, ast.Raise):
        return True
    if isinstance(node, ast.Return):
        return not raising
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and _callee(node.value) == "parser.error":
        return True
    return isinstance(node, ast.If) and _stops(node.body, raising=raising) and _stops(node.orelse, raising=raising)


def _has_refusal(data, node):
    owner = _owner(data, node)
    return any(_owner(data, child) is owner and
               (isinstance(child, (ast.Raise, ast.Return)) or
                isinstance(child, ast.Call) and _callee(child) in GUARD_CALLS | {"parser.error"}) and
               _refusal_path(data, child, node)
               for child in ast.walk(node))


def _refusal_path(data, child, container):
    for parent, field, _index in _ancestors(data, child):
        if parent is container:
            return True
        if isinstance(parent, (ast.With, ast.AsyncWith, ast.GeneratorExp, ast.TryStar)):
            return False
        if isinstance(parent, ast.Try):
            if parent.finalbody:
                return False
            if field == "body" and not isinstance(child, ast.Return):
                if not all(_stops(handler.body) for handler in parent.handlers):
                    return False
    return False


def _guard_statement(data, node):
    statement = _statement(data, node)
    # A selected call in a boolean expression or deferred expression is not
    # unconditionally evaluated just because its statement is reached.
    if isinstance(node, ast.Call):
        if isinstance(statement, ast.If) and statement.test is node:
            return statement
        value = statement.value if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)) else None
        return statement if value is node else None
    return statement if isinstance(statement, ast.If) else None


def _suite_order(data, before, after):
    """One suite, with no jump from a nested/sibling suite to its parent."""
    parent, field, index = _parents(data)[before]
    return any(node is parent and branch == field and position is not None and position > index
               for node, branch, position in _ancestors(data, after))


def _uncaught_suite_order(data, before, after):
    if _suite_order(data, before, after):
        return True
    parent, field, _index = _parents(data)[before]
    if isinstance(parent, ast.Try) and field == "body" and not parent.finalbody:
        if all(_stops(handler.body) for handler in parent.handlers):
            return _uncaught_suite_order(data, parent, after)
    return False


def _python_dominates(data, gate, effect):
    if _owner(data, gate) is not _owner(data, effect):
        return False
    statement = _guard_statement(data, gate)
    if statement is None:
        return False
    if isinstance(statement, ast.If):
        branches = [(node, field) for node, field, _index in _ancestors(data, effect)]
        if (statement, "body") in branches or (statement, "orelse") in branches:
            return True
        if not (_stops(statement.body) or _stops(statement.orelse) or _has_refusal(data, statement)):
            return False
    return _uncaught_suite_order(data, statement, effect)


def _direct_order(contents, gate, effect, *, guard=True):
    if gate["path"] != effect["path"]:
        return False
    data = contents[gate["path"]]
    if gate["path"].endswith(".py"):
        return _python_dominates(data, _point_node(data, gate, guard=guard), _point_node(data, effect))
    return _shell_order(data, gate["line"], effect["line"])


def _shell_open(text, line):
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*\(\)\s*\{", text):
        return ("function", line, "body")
    if text.startswith("if ") and text.endswith("; then"):
        return ("if", line, "body")
    if text.startswith("case "):
        return ("case", line, "body")
    if re.match(r"(?:while|for|until)\s", text):
        return ("loop", line, "body")
    return None


@lru_cache(maxsize=4)
def _shell_blocks(data):
    stack, contexts, ends = [], {}, {}
    for line, raw in enumerate(data.decode().splitlines(), 1):
        if not _shell_context(data, line):
            continue
        text = raw.strip()
        if re.match(r"(?:fi|done|esac|\})(?:\s|$)", text) and stack:
            block = stack.pop()
            ends[block[1]] = line
        elif text == "else" or text.startswith("elif "):
            need(stack and stack[-1][0] == "if", "unsupported shell branch context")
            stack[-1] = ("if", stack[-1][1], f"branch-{line}")
        contexts[line] = tuple(stack)
        block = _shell_open(text, line)
        if block:
            stack.append(block)
    return contexts, ends


def _shell_order(data, gate, effect):
    contexts, ends = _shell_blocks(data)
    before, after = contexts.get(gate), contexts.get(effect)
    if before is None or after is None or gate >= effect:
        return False
    if any(kind == "case" for kind, _line, _branch in before + after):
        return False
    if before != after[:len(before)]:
        return False
    if any(kind == "function" for kind, _line, _branch in after[len(before):]):
        return False
    return _shell_gate_order(data, gate, effect, before, after, contexts, ends)


def _shell_gate_order(data, gate, effect, before, after, contexts, ends):
    text = data.decode().splitlines()[gate - 1].strip()
    if not text.startswith("if "):
        return True  # the finite projection command has an explicit || die
    if any(kind == "if" and start == gate for kind, start, _branch in after):
        return True
    if gate not in ends or ends[gate] >= effect:
        return False
    lines = data.decode().splitlines()
    return any(contexts.get(line) == before + (("if", gate, "body"),) and
               re.match(r"(?:return|exit|die)(?:\s|$)", lines[line - 1].strip())
               for line in range(gate + 1, ends[gate]))


def _chain_target(contents, edge):
    call, target = edge["call"], edge["target"]
    data = contents[call["path"]]
    _point(contents, call)
    node = _point_node(data, call)
    need(isinstance(node, ast.Call) and _selected_interval(data, call) == _node_interval(data, node),
         "chain must name an exact actual call")
    observed, _text = body(contents, target)
    need(observed == target and _target_reference(data, call, node, target),
         f"chain call target mismatch: {call['path']}:{call['line']} -> {target['symbol']}")
    selected = _symbols(contents[target["path"]])[1][target["symbol"]]
    declaration = _interval_node(contents[target["path"]], *_node_interval(contents[target["path"]], selected))
    need(isinstance(declaration, ast.FunctionDef) and not declaration.decorator_list and
         not any(isinstance(n, (ast.Yield, ast.YieldFrom))
                                                           for n in ast.walk(declaration)),
         "deferred chain target unsupported")
    return declaration


def _target_reference(data, point, node, target):
    func, symbol = node.func, target["symbol"]
    if isinstance(func, ast.Name):
        if point["path"] == target["path"] and func.id == symbol:
            return not _local_name(data, node, func.id)
        module = ".".join(Path(target["path"]).relative_to("scripts").with_suffix("").parts)
        return not _local_name(data, node, func.id) and _imported_target(data, func.id, module, symbol)
    if not isinstance(func, ast.Attribute) or "." not in symbol:
        return False
    class_name, method = symbol.rsplit(".", 1)
    return (point["path"] == target["path"] and func.attr == method and
            _method_receiver(data, node, func.value, class_name))


def _local_name(data, node, name):
    owner = _owner(data, node)
    return any(n is not owner and _binds_name(n, name) for n in ast.walk(owner))


def _binds_name(node, name):
    if isinstance(node, ast.Name):
        return isinstance(node.ctx, ast.Store) and node.id == name
    if isinstance(node, ast.arg):
        return node.arg == name
    if isinstance(node, ast.alias):
        return (node.asname or node.name.split(".")[0]) == name
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name


def _imported_target(data, name, module, symbol):
    return any(isinstance(node, ast.ImportFrom) and not node.level and node.module == module and
               any(alias.name == symbol and (alias.asname or alias.name) == name for alias in node.names)
               for node in _gate_tree(data).body)


def _method_receiver(data, node, receiver, class_name):
    if isinstance(receiver, ast.Call):
        return isinstance(receiver.func, ast.Name) and receiver.func.id == class_name
    if not isinstance(receiver, ast.Name):
        return False
    owner = _owner(data, node)
    if receiver.id == "self":
        return any(name.rsplit(".", 1)[0] == class_name and hasattr(owner, "lineno") and
                   _node_interval(data, declaration) == _node_interval(data, owner)
                   for name, declaration in _symbols(data)[1].items())
    stores = [n for n in ast.walk(owner) if isinstance(n, ast.Name) and
              isinstance(n.ctx, ast.Store) and n.id == receiver.id]
    assignments = [_parents(data)[store][0] for store in stores]
    return _receiver_binding(data, assignments, node, class_name)


def _receiver_binding(data, assignments, node, class_name):
    constructors = [assignment for assignment in assignments if _constructor_binding(data, assignment, node, class_name)]
    if len(constructors) != 1:
        return False
    selected = constructors[0]
    return all(assignment is selected or _none_binding(assignment) and _suite_order(data, assignment, selected)
               for assignment in assignments)


def _none_binding(assignment):
    return (isinstance(assignment, (ast.Assign, ast.AnnAssign)) and
            isinstance(assignment.value, ast.Constant) and assignment.value.value is None)


def _constructor_binding(data, assignment, node, class_name):
    return (isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Call) and
            isinstance(assignment.value.func, ast.Name) and assignment.value.func.id == class_name and
            _suite_order(data, assignment, node))


def _return_order(contents, gate, target, declaration):
    if gate["path"] != target["path"]:
        return False
    data = contents[gate["path"]]
    node = _point_node(data, gate, guard=True)
    if _owner(data, node) is not declaration:
        return False
    statement = _guard_statement(data, node)
    if isinstance(statement, ast.If) and not (_stops(statement.body, raising=True) or
                                             _stops(statement.orelse, raising=True)):
        return False
    returns = [n for n in ast.walk(declaration) if isinstance(n, ast.Return) and _owner(data, n) is declaration]
    return (_parents(data).get(statement, ())[:2] == (declaration, "body") and
            all(_python_dominates(data, node, end) for end in returns))


def _chain_order(contents, binding):
    boundary, entry, guard = binding["gate"], None, True
    calls = binding["calls"]
    need(0 < len(calls) <= 12, "bounded explicit call chain required")
    for edge in calls:
        declaration = _chain_target(contents, edge)
        call, target = edge["call"], edge["target"]
        if edge["direction"] == "return":
            need(entry is None and _return_order(contents, boundary, target, declaration),
                 "chain validator refusal/order not established")
            boundary = call
            guard = False
        else:
            need(edge["direction"] == "into", "unknown chain direction")
            need(_entry_order(contents, entry, call) if entry else _direct_order(contents, boundary, call, guard=guard),
                 "chain call is not dominated by gate")
            entry = target
    return (_entry_order(contents, entry, binding["effect"]) if entry else
            _direct_order(contents, boundary, binding["effect"], guard=guard))


def _entry_order(contents, entry, point):
    if entry["path"] != point["path"]:
        return False
    data = contents[point["path"]]
    owner = _owner(data, _point_node(data, point))
    declaration = _symbols(data)[1][entry["symbol"]]
    return hasattr(owner, "lineno") and _node_interval(data, owner) == _node_interval(data, declaration)


def _check_route_order(contents, route):
    gates, effects = route["gates"], route.get("effect_points", [])
    bindings = route.get("gate_chains", [])
    pairs = []
    for binding in bindings:
        need(binding["gate"] in gates and binding["effect"] in effects, "unrelated chain binding")
        need(_chain_order(contents, binding), "chain does not reach guarded effect")
        pairs.append((binding["gate"], _effect_key(contents, binding["effect"])))
    for gate in gates:
        need(any(_ordered_effect(contents, gate, effect, pairs) for effect in effects),
             f"gate does not dominate route effect: {route['id']} {gate['path']}:{gate['line']}")
    if gates:
        for effect in effects:
            need(any(_ordered_effect(contents, gate, effect, pairs) for gate in gates),
                 f"effect has no dominating gate: {route['id']} {effect['path']}:{effect['line']}")


def _effect_key(contents, point):
    return point["path"], *_effect_interval(contents[point["path"]], point)


def _ordered_effect(contents, gate, effect, pairs):
    return bool(pairs) and (gate, _effect_key(contents, effect)) in pairs or _direct_order(contents, gate, effect)


def route_points(route):
    points = [route["entrypoint"], *route["gates"], *route.get("review_gates", []), *route.get("effect_points", [])]
    for binding in route.get("gate_chains", []):
        points.extend([binding["gate"], binding["effect"]])
        for edge in binding["calls"]:
            points.extend([edge["call"], edge["target"]])
    return points

def route_binding(contents, route):
    need(route["id"] and route["effect"] and route["authority"] and route["earlier_effects"], "route contract missing")
    entry = route["entrypoint"]
    need(entry["path"].startswith("scripts/"), "script entrypoint required")
    if entry.get("symbol"):
        declaration, _text = body(contents, entry)
        need(declaration == entry, "stale entrypoint body or location")
    else:
        _point(contents, entry)
    _admission(route)
    gates = [_point(contents, point) for point in route["gates"]]
    need(not route.get("review_gates") or bool(route.get("gate_limits", "").strip()),
         "contextual checks require explicit manual limits")
    witnesses = [_witness_binding(contents, witness) for witness in route["witnesses"]]
    manual = route["manual_review"]
    need(manual["status"] == "external-review-required" and manual["conclusion"] and manual["limits"],
         "explicit manual decision required")
    need(route["trace_files"] and all(path.startswith("scripts/") and path in contents for path in route["trace_files"]),
         "manual trace scope missing")
    return {"id": route["id"], "entrypoint": entry, "gates": gates, "witnesses": witnesses,
            "decision_sha256": digest(encoded(route))}


def _admission(route):
    admission = route.get("admission", "guarded-effect")
    need(admission in {"guarded-effect", "manual-program", "inspection-only"}, "unknown admission contract")
    need(route["witnesses"] and (route["gates"] or admission != "guarded-effect"), "gate and named witness required")
    if admission == "guarded-effect":
        need(any(item.get("kind", "zero-effect-refusal") == "zero-effect-refusal" for item in route["witnesses"]),
             "guarded effect requires a specified zero-effect refusal witness")


def _witness_binding(contents, witness):
    need(witness.get("kind", "zero-effect-refusal") in WITNESS_SEMANTICS, "unknown witness semantics")
    binding, text = body(contents, witness["body"])
    need(binding == witness["body"], "stale witness body or location")
    module = ".".join(Path(binding["path"]).with_suffix("").parts)
    need(witness["test_id"] == f"{module}.{binding['symbol']}" and module.startswith("tests."), "unrelated named test")
    for support in witness.get("support", []):
        observed, additional = body(contents, support)
        need(observed == support, "stale supporting helper body")
        text += "\n" + additional
    need(witness["assertion"].strip() in text and witness["positive"].strip() in text,
         "refusal assertion or matched positive absent from selected bodies")
    need(bool(witness["assertion"].strip()) and bool(witness["positive"].strip()), "empty witness evidence")
    _tree, symbols = _symbols(contents[binding["path"]])
    doc = ast.get_docstring(symbols[binding["symbol"]], clean=False) or ""
    return {**witness, "description": doc.split("\n", 1)[0].strip()}


def _sites(contents):
    """Retain lexical calls/imports and shell lines; deliberately no dispatch guesses."""
    sites = []
    for path, data in contents.items():
        if not path.startswith("scripts/"):
            continue
        if path.endswith(".py"):
            tree = ast.parse(data)
            lines = data.splitlines(keepends=True)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Call, ast.Import, ast.ImportFrom)):
                    target = node.func if isinstance(node, ast.Call) else node
                    selected = lines[target.lineno - 1:target.end_lineno]
                    selected[-1] = selected[-1][:target.end_col_offset]
                    selected[0] = selected[0][target.col_offset:]
                    sites.append([path, node.lineno, node.col_offset, type(node).__name__, digest(b"".join(selected))])
        else:
            sites.extend([path, line, 0, "manual-shell", digest(text)]
                         for line, text in enumerate(data.splitlines(), 1) if text.strip())
    return sorted(sites)



# These are candidate families, not permission or whole-program effect proofs.
PROCESS_CALLS = {"run", "Popen", "check_call", "check_output", "call", "getoutput", "getstatusoutput"}
NETWORK_CALLS = {"request", "get", "post", "put", "patch", "delete", "head", "options",
                 "Session", "Client", "AsyncClient"}
BROWSER_METHODS = {"launch", "launch_persistent_context", "connect", "connect_over_cdp",
                   "new_context", "new_page", "goto", "evaluate", "click", "fill", "press"}
APPSERVER_METHODS = {"rpc", "request", "notify", "send_request", "_rpc", "send_notification"}
BEADS_CALLS = {"run_bd", "run_bd_structured", "create_bead", "add_dependency"}
LOCAL_BEADS_HELPERS = {
    "scripts/qualified_closure.py": ("_bd",),
    "scripts/cwo_core/native_activation_preview.py": ("_bd",),
    "scripts/continue_sprint.py": ("bd_json",),
    "scripts/summarize_resume_state.py": ("bd_json",),
}
SHELL_PRIMITIVES = {b"bd": "beads", b"systemctl": "process", b"curl": "network"}
SHELL_CANDIDATE = re.compile(rb"(?<![A-Za-z0-9_-])(bd|systemctl|curl)(?![A-Za-z0-9_-])")
COPY_CALLS = {"copytree", "copy", "copy2", "copyfile", "move"}
KNOWN_PRIMITIVE_MODULES = {"subprocess", "os", "socket", "urllib.request", "http.client", "http.server",
                           "socketserver", "requests", "httpx", "shutil", "playwright.sync_api", "playwright.async_api"}
RECEIVER_NAMESPACES = KNOWN_PRIMITIVE_MODULES | {"@network", "@appserver", "@playwright"}
PRIMITIVE_FAMILIES = {"process", "network", "browser", "appserver", "beads", "install-copy", "dynamic"}


def _literal(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _receiver(name):
    tail = name.rsplit(".", 1)[-1]
    if tail in {"AppServer", "RegisteredAppServer"}:
        return {"@appserver"}
    if "playwright" in name:
        return {"@playwright"}
    if name in {"socket.socket", "socket.create_connection", "http.client.HTTPConnection",
                "http.client.HTTPSConnection", "requests.Session", "httpx.Client", "httpx.AsyncClient"}:
        return {"@network"}
    return set()



def _call_namespace(name):
    """Keep possible declared namespaces across calls, not inferred return types."""
    for namespace in RECEIVER_NAMESPACES:
        if name == namespace or name.startswith(namespace + "."):
            return {namespace}
    return set()


def _attribute_names(bases, attribute):
    # Unknown constructed receivers still carry expressly declared method tails.
    return {f"{base}.{attribute}" for base in bases or {"@receiver"}}


def _container_names(node, aliases, depth):
    # A literal subscript may select any element. No index/key execution or
    # arbitrary container/wrapper implementation is resolved here.
    values = node.values if isinstance(node, ast.Dict) else node.elts
    return set().union(*(_resolved(value, aliases, depth + 1) for value in values))

def _call_result(node, names, aliases, depth):
    if names & {"importlib.import_module", "__import__"}:
        module = _literal(node.args[0]) if node.args else None
        return {module} if module else {"?dynamic"}
    if "getattr" in names:
        attribute = _literal(node.args[1]) if len(node.args) >= 2 else None
        if attribute:
            return _attribute_names(_resolved(node.args[0], aliases, depth + 1), attribute)
        return {"?dynamic"}
    return set().union(*(_receiver(name) | _call_namespace(name) for name in names))


def _resolved(node, aliases, depth=0):
    """Conservative file-local name unions, at most twelve expression levels."""
    if node is None or depth >= 12:
        return {"?dynamic"}
    if isinstance(node, ast.Name):
        return {node.id} | aliases.get(node.id, set())
    if isinstance(node, ast.Attribute):
        return _attribute_names(_resolved(node.value, aliases, depth + 1), node.attr)
    if isinstance(node, ast.Call):
        names = _resolved(node.func, aliases, depth + 1)
        return _call_result(node, names, aliases, depth)
    if isinstance(node, ast.Subscript):
        return _resolved(node.value, aliases, depth + 1)
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        return _container_names(node, aliases, depth)
    return set()


def _alias_inputs(tree):
    aliases, assignments = {}, []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases.setdefault(item.asname or item.name.split(".")[0], set()).add(
                    item.name if item.asname else item.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases.setdefault(item.asname or item.name, set()).add(f"{node.module}.{item.name}")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assignments.extend((target.id, node.value) for target in targets if isinstance(target, ast.Name))
    return aliases, assignments


def _alias_candidate(candidate):
    return (candidate.split(".", 1)[0] in {
        "subprocess", "os", "socket", "urllib", "http", "requests", "httpx",
        "shutil", "socketserver", "playwright", "importlib", "getattr", "__import__"} or
        candidate.startswith(("@network", "@appserver", "@playwright", "?")) or bool(_family(candidate)))


def _aliases(tree, path=""):
    aliases, assignments = _alias_inputs(tree)
    # These reviewed module-local adapters share the public Beads family. Seed
    # the union before assignment propagation so their aliases stay candidates.
    for helper in LOCAL_BEADS_HELPERS.get(path, ()):
        aliases.setdefault(helper, set()).add("run_bd")
    # A chain beyond this finite budget must be reviewed as unresolved, not dropped.
    for _round in range(8):
        changed = False
        for name, value in assignments:
            before = aliases.setdefault(name, set()).copy()
            candidates = _resolved(value, aliases)
            aliases[name].update(candidate for candidate in candidates if _alias_candidate(candidate))
            changed |= before != aliases[name]
        if not changed:
            return aliases
    need(False, "primitive alias resolution budget exceeded")


def _process_name(name, tail):
    return (name.startswith("subprocess.") and tail in PROCESS_CALLS or
            name.startswith("os.") and (tail in {"system", "popen"} or
                                       tail.startswith(("exec", "spawn", "posix_spawn"))))


def _network_name(name, tail):
    return (name in {"socket.socket", "socket.socketpair", "socket.create_connection",
                    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.build_opener",
                    "urllib.request.install_opener", "http.client.HTTPConnection", "http.client.HTTPSConnection",
                    "http.server.HTTPServer", "http.server.ThreadingHTTPServer", "socketserver.TCPServer",
                    "socketserver.ThreadingTCPServer", "socketserver.UnixStreamServer"} or
            name.startswith(("requests.", "httpx.", "@network.")) and tail in NETWORK_CALLS)


def _family(name):
    tail = name.rsplit(".", 1)[-1]
    if _process_name(name, tail):
        return "process"
    if _network_name(name, tail):
        return "network"
    if tail in BROWSER_METHODS or "playwright" in name and tail in {"sync_playwright", "async_playwright", "start"}:
        return "browser"
    if tail in {"AppServer", "RegisteredAppServer"} or tail in APPSERVER_METHODS:
        return "appserver"
    if tail in BEADS_CALLS:
        return "beads"
    if name.startswith("shutil.") and tail in COPY_CALLS:
        return "install-copy"
    if name == "?dynamic":
        return "dynamic"
    return None


def _call_families(node, aliases):
    names = _resolved(node.func, aliases)
    families = {_family(name) for name in names} - {None}
    if names & {"importlib.import_module", "__import__", "getattr"}:
        resolved = _resolved(node, aliases)
        if (names & {"importlib.import_module", "__import__"} and
                not resolved <= KNOWN_PRIMITIVE_MODULES) or not resolved or "?dynamic" in resolved or (
                "getattr" in names and not any(_family(name) for name in resolved)):
            families.add("dynamic")
    return families


def _span(data, node):
    lines = data.splitlines(keepends=True)
    selected = lines[node.lineno - 1:node.end_lineno]
    selected[-1] = selected[-1][:node.end_col_offset]
    selected[0] = selected[0][node.col_offset:]
    return b"".join(selected)


def _python_primitive_hits(path, data):
    hits = []
    tree = ast.parse(data)
    aliases = _aliases(tree, path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for family in sorted(_call_families(node, aliases)):
            hits.append([path, node.lineno, node.col_offset, node.end_lineno,
                         node.end_col_offset, family, digest(_span(data, node))])
    return hits


def _shell_primitive_hits(path, data):
    """Whole-line lexical candidates, including quoted/help/comment occurrences."""
    hits = []
    for line, text in enumerate(data.splitlines(), 1):
        families = {SHELL_PRIMITIVES[match[1]] for match in SHELL_CANDIDATE.finditer(text)}
        for family in sorted(families):
            hits.append([path, line, 0, line, len(text), family, digest(text)])
    return hits


def primitive_hits(contents):
    """Exact Python call spans and shell candidate lines; no shell execution guesses."""
    hits = []
    for path, data in sorted(contents.items()):
        if not path.startswith("scripts/"):
            continue
        if path.endswith(".py"):
            hits.extend(_python_primitive_hits(path, data))
        elif path.endswith(".sh") or path == "scripts/cwo-codex":
            hits.extend(_shell_primitive_hits(path, data))
    return sorted(hits)


def _excluded_primitive(disposition, exclusions, by_id, used):
    need(len(disposition) == 2 and isinstance(disposition[1], str), "unknown primitive exclusion")
    key = disposition[1]
    need(key in exclusions, "unknown primitive exclusion")
    need(key.strip() and key not in used, "duplicate primitive exclusion")
    used.add(key)
    exclusion = exclusions[key]
    need(isinstance(exclusion, dict), "named primitive exclusion decision required")
    need(isinstance(exclusion.get("reason"), str) and exclusion["reason"].strip() and
         isinstance(exclusion.get("conclusion"), str) and exclusion["conclusion"].strip(),
         "named primitive exclusion decision required")
    need("route" not in exclusion or isinstance(exclusion["route"], str) and exclusion["route"] in by_id,
         "unknown exclusion route")


def _mapped_primitive(row, value, contents, by_id):
    path, line, col, end_line, end_col, _family, sha, disposition = row
    need(disposition[0] == "route" and len(disposition) == 3 and isinstance(disposition[1], str),
         "unknown primitive route disposition")
    need(disposition[1] in by_id, "unknown primitive route disposition")
    route, selected_point = by_id[disposition[1]], disposition[2]
    if isinstance(selected_point, str):
        need(selected_point in value.get("points", {}), "unknown primitive effect point")
        point = _table_point(value, selected_point)
    else:
        point = selected_point
    need(point in route.get("effect_points", []), "unrelated primitive effect point")
    observed = _point(contents, point)
    raw = contents[path].splitlines(keepends=True)[line - 1:end_line]
    raw[-1] = raw[-1][:end_col]
    raw[0] = raw[0][col:]
    text = b"".join(raw)
    expected = {"path": path, "line": line, "text": text.decode().strip()}
    if "col" in point:
        expected.update(col=col, end_line=end_line, end_col=end_col)
    need(observed == expected and digest(text) == sha, "primitive effect point must equal exact hit")


def _primitive_path_table(coverage, contents):
    paths = coverage.get("paths")
    need(isinstance(paths, list) and len(paths) <= MAX_FILES, "primitive path table required within source bound")
    need(all(isinstance(path, str) and path.startswith("scripts/") and path in contents for path in paths),
         "primitive path entry must name current script source")
    need(len(set(paths)) == len(paths), "duplicate primitive path entry")
    return paths


def _expanded_primitive_coverage(coverage, contents):
    """Decode explicit path indices only; keep evidence and dispositions expanded."""
    need(isinstance(coverage, dict) and coverage.get("schema") in ("bounded-primitives-v1", "bounded-primitives-v2"),
         "primitive coverage schema required")
    rows = coverage.get("hits", [])
    need(isinstance(rows, list), "primitive hit rows required")
    need(all(isinstance(row, list) and len(row) == 8 for row in rows), "primitive hit row required")
    if coverage["schema"] == "bounded-primitives-v1":
        need("paths" not in coverage, "unexpected primitive path table")
        return coverage
    paths = _primitive_path_table(coverage, contents)
    expanded, used = [], set()
    for row in rows:
        index = row[0]
        need(type(index) is int and 0 <= index < len(paths), "primitive path index outside table")
        expanded.append([paths[index], *row[1:]])
        used.add(index)
    need(used == set(range(len(paths))), "unused primitive path table entry")
    result = {**coverage, "schema": "bounded-primitives-v1", "hits": expanded}
    del result["paths"]
    return result


def _primitive_hit_key(row):
    need(isinstance(row[0], str) and all(type(number) is int for number in row[1:5]),
         "primitive hit path and integer span required")
    need(row[1] > 0 and row[2] >= 0 and row[3] >= row[1] and row[4] >= 0, "invalid primitive hit span")
    need(isinstance(row[5], str) and row[5] in PRIMITIVE_FAMILIES and isinstance(row[6], str)
         and re.fullmatch(r"[0-9a-f]{64}", row[6]), "primitive hit family and full SHA256 required")
    return row[:7]


def _check_primitive_coverage(value, contents, routes):
    coverage = _expanded_primitive_coverage(value.get("primitive_coverage", {}), contents)
    rows, exclusions = coverage.get("hits", []), coverage.get("exclusions", {})
    need(isinstance(exclusions, dict), "primitive exclusions mapping required")
    hits = primitive_hits(contents)
    selected = [_primitive_hit_key(row) for row in rows]
    need(sorted(selected) == hits and len({tuple(row) for row in selected}) == len(selected),
         "primitive hit coverage mismatch")
    by_id = {route["id"]: route for route in routes}
    used = set()
    for row in rows:
        family, disposition = row[5], row[7]
        need(family in PRIMITIVE_FAMILIES and isinstance(disposition, list) and disposition,
             "primitive disposition required")
        need(family != "dynamic" or disposition[0] == "exclude", "unresolved dynamic candidate requires exclusion")
        if disposition[0] == "exclude":
            _excluded_primitive(disposition, exclusions, by_id, used)
        else:
            _mapped_primitive(row, value, contents, by_id)
    need(set(exclusions) == used, "orphan primitive exclusion")
    return hits, coverage


def _check_script_bindings(value, files):
    need({path for path in files if path.startswith("scripts/")} ==
         {path for path in value["source_bindings"] if path.startswith("scripts/")},
         "complete scripts binding set required")


def inventory(root):
    data, _identity = read_file(root, INVENTORY, MAX_INVENTORY)
    value = json.loads(data)
    need(value["schema"] == "compact-release-routes-v1", "inventory schema refused")
    ids = [route["id"] for route in value["routes"]]
    need(ids and len(ids) == len(set(ids)), "missing or duplicate routes")
    return value, digest(data)


def _table_point(value, key):
    point = value["points"][key]
    path = value["point_files"][point[0]]
    if isinstance(point[1], str):
        return dict(path=path, symbol=point[1], line=point[2], sha256=point[3])
    result = dict(path=path, line=point[1], text=point[2])
    if len(point) == 6:
        result.update(col=point[3], end_line=point[4], end_col=point[5])
    return result


def _table_witness(value, key):
    witness = dict(value["witnesses"][key])
    witness["body"] = _table_point(value, witness["body"])
    witness["support"] = [_table_point(value, key) for key in witness.get("support", [])]
    return witness


def _routes(value):
    """Expand only explicit shared inventory references; no inferred edges."""
    if "contracts" not in value:
        return value["routes"]
    rows = []
    for entry in value["routes"]:
        route = {**value["contracts"][entry["contract"]], **entry}
        route.setdefault("earlier_effects", route["limits"])
        _expand_route_points(value, route)
        route["witnesses"] = [_table_witness(value, key) for key in route["witnesses"]]
        decisions = {key: value["manual_decisions"][key] for key in route["manual_decisions"]}
        route["manual_review"] = {"status": "external-review-required", "conclusion": route["ordering"],
                                  "limits": route["limits"], "decisions": decisions}
        rows.append(route)
    return rows


def _expand_route_points(value, route):
    route["entrypoint"] = _table_point(value, route["entrypoint"])
    for field in ("gates", "effect_points", "review_gates"):
        route[field] = [_table_point(value, key) for key in route.get(field, [])]
    route["gate_chains"] = [{"gate": _table_point(value, binding["gate"]),
                             "effect": _table_point(value, binding["effect"]),
                             "calls": [{**edge, "call": _table_point(value, edge["call"]),
                                        "target": _table_point(value, edge["target"])} for edge in binding["calls"]]}
                            for binding in route.get("gate_chains", [])]


def trace(root):
    root = Path(root)
    value, inventory_hash = inventory(root)
    files, contents = source(root)
    need(files[INVENTORY]["sha256"] == inventory_hash, "inventory changed before source capture")
    routes = _routes(value)
    bindings = [route_binding(contents, route) for route in routes]
    _check_script_bindings(value, files)
    need(value["source_bindings"] == {path: files[path] for path in value["source_bindings"]}, "stale route source binding")
    required = {point["path"] for route in routes for point in route_points(route)}
    required.update(witness["body"]["path"] for route in routes for witness in route["witnesses"])
    required.update(support["path"] for route in routes for witness in route["witnesses"]
                    for support in witness.get("support", []))
    required.update(path for route in routes for path in route["trace_files"])
    required.update(_inventory_points(value, contents))
    need(required <= set(value["source_bindings"]), "unbound route source")
    hits, coverage = _check_primitive_coverage(value, contents, routes)
    _check_gate_effects(contents, routes, hits)
    sites = _sites(contents)
    after, _contents = source(root)
    need(files == after, "source changed during evidence step")
    return {"schema": "release-lexical-trace-v1", "source_sha256": digest(encoded(files)),
            "inventory_sha256": inventory_hash, "files": files, "routes": bindings, "sites": sites,
            "primitive_hits": hits, "primitive_coverage": coverage,
            "resolution": "bounded primitive families and file-local alias unions; dispatch and route semantics require external review"}


def _inventory_points(value, contents):
    paths = set()
    for key in value.get("points", {}):
        point = _table_point(value, key)
        paths.add(point["path"])
        if "symbol" in point:
            observed, _text = body(contents, point)
            need(observed == point, "stale inventory declaration point")
        else:
            _point(contents, point)
    return paths


def evidence_directory(root, destination):
    root, destination = Path(root).resolve(), Path(destination).resolve()
    need(not destination.is_relative_to(root), "generated evidence cannot enter product tree")
    need("evidence" in destination.parts, "generated data requires an explicit evidence/ destination")
    return destination


def write_trace(root, destination):
    destination = evidence_directory(root, destination)
    value = trace(root)
    destination.mkdir(parents=True, exist_ok=True)
    raw = encoded(value) + b"\n"
    need(not (destination / "trace.json").exists() and not (destination / "index.json").exists(), "fresh evidence paths required")
    (destination / "trace.json").write_bytes(raw)
    index = _index(value, raw)
    (destination / "index.json").write_bytes(encoded(index) + b"\n")
    return index


def _index(value, raw):
    result = {key: value[key] for key in ("schema", "source_sha256", "inventory_sha256")}
    result.update(trace_sha256=digest(raw), routes=len(value["routes"]), sites=len(value["sites"]))
    return result


def _artifact(directory, selected, limit=MAX_TOTAL):
    raw, _identity = read_file(directory, selected["path"], limit)
    need(digest(raw) == selected["sha256"], "selected artifact changed")
    return raw


def _passed_test(raw, test_id, description=""):
    header = f"{test_id.rsplit('.', 1)[-1]} ({test_id})".encode()
    framed = b"\n" + raw + b"\n"
    ordinary = b"\n" + header + b" ... ok\n"
    described = b"\n" + header + b"\n" + description.encode() + b" ... ok\n"
    return ordinary in framed or bool(description) and described in framed


def _review(directory, review, current, trace_hash):
    need(review["schema"] == "release-route-review-v1" and review["role"] == "independent-reviewer"
         and review["verdict"] == "ACCEPT" and review["reviewer"], "independent acceptance not selected")
    for key in ("source_sha256", "inventory_sha256"):
        need(review[key] == current[key], f"unrelated review {key}")
    need(review["trace_sha256"] == trace_hash, "unrelated review trace")
    decisions = review["decisions"]
    need(set(decisions) == {route["id"] for route in current["routes"]}, "review route set mismatch")
    custody = []
    for route in current["routes"]:
        decision = decisions[route["id"]]
        need(decision["decision_sha256"] == route["decision_sha256"] and decision["verdict"] == "ACCEPT"
             and decision["conclusion"], "manual decision missing or mismapped")
        observations = decision["observations"]
        need(set(observations) == {item["test_id"] for item in route["witnesses"]}, "test selection mismatch")
        for witness in route["witnesses"]:
            row = observations[witness["test_id"]]
            custody.extend([row["receipt"], row["log"]])
            need(row["body_sha256"] == witness["body"]["sha256"], "unrelated observed test body")
            receipt = json.loads(_artifact(directory, row["receipt"], MAX_FILE))
            raw = _artifact(directory, row["log"])
            need(receipt["returncode"] == 0 and receipt["status"] == "complete"
                 and receipt["log_sha256"] == digest(raw), "failed or unrelated test receipt")
            need(_passed_test(raw, witness["test_id"], witness["description"]), "named passing test absent")
            semantic = WITNESS_SEMANTICS[witness.get("kind", "zero-effect-refusal")]
            need(row["source_sha256"] == current["source_sha256"] and row["semantic_review"] == semantic,
                 "observation source or semantic selection mismatch")
    return custody


def check(root, directory, review_path=None, review_sha256=None):
    directory = evidence_directory(root, directory)
    raw, _identity = read_file(directory, "trace.json", MAX_TOTAL)
    current = trace(root)
    need(raw == encoded(current) + b"\n", "stale or mismapped trace; generate a fresh evidence step")
    index_raw, _identity = read_file(directory, "index.json", MAX_FILE)
    need(index_raw == encoded(_index(current, raw)) + b"\n", "trace index mismatch")
    need(review_path is not None and review_sha256 is not None, "explicit independent review path and digest required")
    selected = {"path": review_path, "sha256": review_sha256}
    review_raw = _artifact(directory, selected, MAX_FILE)
    custody = _review(directory, json.loads(review_raw), current, digest(raw))
    # Re-read all custody inputs after the last review/observation read.
    need(trace(root) == current and _artifact(directory, selected, MAX_FILE) == review_raw,
         "source or selected review changed during check")
    for artifact in custody + [{"path": "trace.json", "sha256": digest(raw)},
                               {"path": "index.json", "sha256": digest(index_raw)}]:
        _artifact(directory, artifact)
    return {"contract_valid": True, "complete_effect_trace": True, "f8_complete": False,
            "routes": len(current["routes"]), "source_sha256": current["source_sha256"],
            "trust": "operator-selected external semantic review; JSON does not authenticate people"}
