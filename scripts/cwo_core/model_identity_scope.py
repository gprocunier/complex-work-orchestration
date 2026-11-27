"""Scoped lint for model-identity literals in current runtime code and current policy.

Scope. The lint reads every file under ``scripts/`` (current runtime code) and
every ``policy/*.yaml`` document (current policy) except the register itself
and ``policy/model-roles.yaml``, the authority for configured model identities.
The latter is checked by its closed schema and role validator. The exact native
preferred-model field can mirror the configured Luna model. The lint does not read archived or historical
records: ``schemas/`` (versioned record contracts, including frozen const
identities), ``tests/`` and their fixtures, ``calibration/``, ``docs/``,
``references/``, ``examples/`` and ``CHANGELOG.md``. A historical record is
never rewritten to satisfy this lint.

Classification. Every literal the lint finds must be classified by the register:
policy literals by file and JSON pointer (the longest registered pointer that
contains the finding), source literals by path and literal. Each entry pins the
exact count of each literal, so a new literal, a removed literal and an edited
frozen literal all fail until the register is changed in review. Classes:

- ``historical``: a record contract or section the code or policy itself marks
  historical, or a file whose blob is bound by historical evidence; frozen;
- ``unadjudicated``: a pre-existing literal whose current or historical role
  this lint does not decide; frozen until a later change adjudicates it;
- ``detection-term``: text-classification vocabulary, not an identity;
- ``nonoperative``: a binding that names a model archived task-selected
  routing marks historical-nonoperative. The binding is kept as
  recorded and its consumers resolve it through the model refusal rule
  (``operative_routing.nonoperative_model_refusal``), which refuses it without
  substituting another model. May name only such models.
- ``qualification-pin``: an exact source literal used by a separately
  authorized, bounded qualification run. The classification is scoped to
  the declared source path and occurrence count.

The register grants nothing. No runtime consumer reads it, and classifying a
literal never makes a model selectable, dispatchable, qualified or cleared.
The lint matches ``gpt-`` identities only (case-insensitive); other model
families and spellings without the hyphen are outside it.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from .model_identities import validate_model_role_config
from .policy import load_json_compatible_yaml
from .policy_schema import policy_document_errors


IDENTITY_PATTERN = re.compile(r"(?<![a-z0-9])gpt-[0-9]+(?:\.[0-9]+)*(?:-[a-z0-9]+)*", re.IGNORECASE)
REGISTER_FILE = "model-identity-scope.yaml"
ROLE_POLICY_FILE = "model-roles.yaml"
NATIVE_POLICY_FILE = "native-worker-execution.yaml"
SOURCE_ROOT = "scripts"
POLICY_ROOT = "policy"
OUT_OF_SCOPE = ("schemas", "tests", "calibration", "docs", "references", "examples", "CHANGELOG.md")


def find_identities(text: str) -> list[str]:
    return [match.lower() for match in IDENTITY_PATTERN.findall(text)]


def _escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _policy_findings(value: Any, pointer: str, out: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{pointer}/{_escape(str(key))}"
            out.extend((child, literal) for literal in find_identities(str(key)))
            _policy_findings(item, child, out)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _policy_findings(item, f"{pointer}/{index}", out)
    elif isinstance(value, str):
        out.extend((pointer, literal) for literal in find_identities(value))


def _registered_policy_findings(document: Any, filename: str, luna_model: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    _policy_findings(document, "", findings)
    if filename != NATIVE_POLICY_FILE or not isinstance(document, dict):
        return findings
    governance = document.get("governance")
    worker = governance.get("native_operative_worker") if isinstance(governance, dict) else None
    if isinstance(worker, dict) and worker.get("preferred_model") == luna_model:
        findings.remove(("/governance/native_operative_worker/preferred_model", luna_model))
    return findings


def _contains(location: str, pointer: str) -> bool:
    return location == "" or pointer == location or pointer.startswith(location + "/")


def _source_files(root: Path, errors: list[str]) -> list[Path]:
    """Every file under the source root; symlinks and unreadable entries fail closed."""
    files: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(f"model identity lint cannot list {directory}: {exc}")
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                errors.append(f"model identity lint cannot inspect {path}: {exc}")
                continue
            if stat.S_ISLNK(mode):
                errors.append(f"model identity lint does not follow symlinks: {path}")
            elif stat.S_ISDIR(mode):
                if entry.name != "__pycache__":
                    pending.append(path)
            elif stat.S_ISREG(mode):
                files.append(path)
            else:
                errors.append(f"model identity lint found an unsupported file type: {path}")
    return sorted(files)


def _lint_policy_errors(register: dict[str, Any], roles: dict[str, Any]) -> list[str]:
    errors = [
        f"policy/{filename}: {error}"
        for filename, document in ((REGISTER_FILE, register), (ROLE_POLICY_FILE, roles))
        for error in policy_document_errors(filename, document)
    ]
    if errors:
        return errors
    try:
        validate_model_role_config(roles)
    except ValueError as exc:
        return [f"policy/{ROLE_POLICY_FILE}: {exc}"]
    return []


def lint_model_identities(repo_root: Path) -> list[str]:
    """Errors for unclassified, miscounted or misclassified model identities in scope."""
    root = Path(repo_root)
    policy_dir = root / POLICY_ROOT
    errors: list[str] = []
    try:
        register = load_json_compatible_yaml(policy_dir / REGISTER_FILE)
        roles = load_json_compatible_yaml(policy_dir / ROLE_POLICY_FILE)
        native = load_json_compatible_yaml(policy_dir / NATIVE_POLICY_FILE)
        schema_errors = _lint_policy_errors(register, roles)
    except SystemExit as exc:
        return [f"model identity lint cannot load policy: {exc}"]
    if schema_errors:
        return schema_errors
    nonoperative = _nonoperative_models(native)

    locations: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in register["policy_locations"]:
        key = (entry["file"], entry["pointer"])
        if key in locations:
            errors.append(f"model identity register repeats policy location {entry['file']}{entry['pointer']}")
        locations[key] = entry
    found: dict[tuple[str, str], dict[str, int]] = {key: {} for key in locations}
    for path in sorted(policy_dir.glob("*.yaml")):
        if path.name in (REGISTER_FILE, ROLE_POLICY_FILE):
            continue
        try:
            document = load_json_compatible_yaml(path)
        except SystemExit as exc:
            errors.append(str(exc))
            continue
        findings = _registered_policy_findings(document, path.name, roles["roles"]["luna"]["current"])
        for pointer, literal in findings:
            owners = [key for key in locations if key[0] == path.name and _contains(key[1], pointer)]
            if not owners:
                errors.append(f"unclassified model identity {literal!r} at policy/{path.name}#{pointer}")
                continue
            owner = max(owners, key=lambda key: len(key[1]))
            counts = found[owner]
            counts[literal] = counts.get(literal, 0) + 1
    for key, entry in locations.items():
        label = f"policy/{key[0]}#{key[1]}"
        if not (policy_dir / key[0]).is_file() or key[0] in (REGISTER_FILE, ROLE_POLICY_FILE):
            errors.append(f"model identity register names a policy file that is not scanned: {label}")
            continue
        errors.extend(_count_errors(label, entry, found[key], nonoperative))

    sources: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in register["source_literals"]:
        key = (entry["path"], entry["literal"])
        if key in sources:
            errors.append(f"model identity register repeats source literal {entry['literal']!r} in {entry['path']}")
        sources[key] = entry
    observed: dict[tuple[str, str], int] = {}
    for path in _source_files(root / SOURCE_ROOT, errors):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"model identity lint cannot read {relative} as UTF-8: {exc}")
            continue
        for literal in find_identities(text):
            observed[(relative, literal)] = observed.get((relative, literal), 0) + 1
    for (relative, literal), count in sorted(observed.items()):
        if (relative, literal) not in sources:
            errors.append(f"unclassified model identity {literal!r} in {relative} ({count} occurrence{'s' if count != 1 else ''})")
    for (relative, literal), entry in sorted(sources.items()):
        label = f"{relative} {literal!r}"
        if not relative.startswith(SOURCE_ROOT + "/"):
            errors.append(f"model identity register names a source outside {SOURCE_ROOT}/: {label}")
            continue
        errors.extend(_count_errors(label, {**entry, "literals": {literal: entry["count"]}}, {literal: observed.get((relative, literal), 0)}, nonoperative))
    return errors


def _nonoperative_models(native: dict[str, Any]) -> set[str]:
    routing = native.get("historical_task_selected_routing_v3")
    roles = routing.get("operative_roles") if isinstance(routing, dict) else None
    if not isinstance(roles, dict):
        return set()
    return {model for model, role in roles.items() if role == "historical-nonoperative"}


def _count_errors(label: str, entry: dict[str, Any], counts: dict[str, int], nonoperative: set[str]) -> list[str]:
    errors: list[str] = []
    declared: dict[str, int] = entry["literals"]
    for literal in sorted(set(declared) | set(counts)):
        if not IDENTITY_PATTERN.fullmatch(literal) or literal != literal.lower():
            errors.append(f"{label}: register literal {literal!r} is not a normalized identity")
            continue
        expected, actual = declared.get(literal, 0), counts.get(literal, 0)
        if expected != actual:
            errors.append(f"{label}: {literal!r} found {actual} time(s), register pins {expected}")
        if entry["class"] == "nonoperative" and (actual or expected) and literal not in nonoperative:
            errors.append(
                f"{label}: nonoperative location names {literal!r}, which archived v3 routing does not mark "
                "historical-nonoperative"
            )
    return errors
