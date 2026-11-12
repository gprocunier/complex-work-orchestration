#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from cwo_core.codex_hook_enforcement import validate_advisory_hook_configuration
from cwo_core.errors import CWOValidationError
from cwo_core.util import atomic_write_text
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason


MANAGED_EVENTS = {
    "SessionStart": {
        "matcher": "startup|resume|clear",
        "command": "bd codex-hook SessionStart",
        "statusMessage": "Loading Beads context",
    },
    "UserPromptSubmit": {
        "command": "bd codex-hook UserPromptSubmit",
        "statusMessage": "Refreshing Beads context",
    },
    "PreCompact": {
        "matcher": "manual|auto",
        "command": "bd codex-hook PreCompact",
        "statusMessage": "Checking Beads context",
    },
    "PostCompact": {
        "matcher": "manual|auto",
        "command": "bd codex-hook PostCompact",
        "statusMessage": "Scheduling Beads context refresh",
    },
}
VISIBILITY_MODES = {"quiet", "verbose"}
VISIBILITY_NEEDLES = (b"visibilityHint", b"HookVisibilityHint")
MAX_VISIBILITY_PROBE_BYTES = 4 * 1024 * 1024


class ConfigurationError(RuntimeError):
    pass


def run_codex_version(codex_bin: str) -> str | None:
    try:
        result = subprocess.run(
            [codex_bin, "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip()
    return output or None


def codex_binary_candidates(codex_bin: str) -> list[Path]:
    candidates: list[Path] = []
    resolved = shutil.which(codex_bin) if os.path.sep not in codex_bin else codex_bin
    if not resolved:
        return candidates
    start = Path(resolved).expanduser()
    for candidate in {start, start.resolve()}:
        if candidate not in candidates:
            candidates.append(candidate)
    for parent in [start.resolve().parent, *start.resolve().parents]:
        vendor_root = parent / "node_modules" / "@openai"
        if vendor_root.exists():
            for path in vendor_root.glob("codex-*/vendor/*/bin/codex"):
                if path not in candidates:
                    candidates.append(path)
        sibling_vendor = parent / "node_modules" / "@openai" / "codex-linux-x64" / "vendor"
        if sibling_vendor.exists():
            for path in sibling_vendor.glob("*/bin/codex"):
                if path not in candidates:
                    candidates.append(path)
    return candidates


def file_has_visibility_hint(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_VISIBILITY_PROBE_BYTES)
    except OSError:
        return False
    return all(needle in data for needle in VISIBILITY_NEEDLES)


def detect_visibility_hint_support(codex_bin: str) -> dict[str, Any]:
    candidates = codex_binary_candidates(codex_bin)
    matching = [str(path) for path in candidates if path.is_file() and file_has_visibility_hint(path)]
    return {
        "codex_bin": codex_bin,
        "codex_version": run_codex_version(codex_bin),
        "visibility_hint_supported": bool(matching),
        "candidate_paths": [str(path) for path in candidates],
        "matching_paths": matching,
        "support_signal": "binary contains visibilityHint and HookVisibilityHint" if matching else "not detected",
    }


def unprobed_support_info(codex_bin: str) -> dict[str, Any]:
    return {
        "codex_bin": codex_bin,
        "codex_version": None,
        "visibility_hint_supported": False,
        "candidate_paths": [],
        "matching_paths": [],
        "support_signal": "not probed",
    }


def managed_hook_entry(event: str, *, visibility_hint: str | None = None) -> dict[str, Any]:
    spec = MANAGED_EVENTS[event]
    hook: dict[str, Any] = {
        "type": "command",
        "command": spec["command"],
        "statusMessage": spec["statusMessage"],
    }
    if visibility_hint:
        hook["visibilityHint"] = visibility_hint
    group: dict[str, Any] = {"hooks": [hook]}
    if "matcher" in spec:
        group["matcher"] = spec["matcher"]
    return group


def degraded_session_entry() -> dict[str, Any]:
    return {
        "matcher": "startup|resume|clear",
        "hooks": [
            {
                "type": "command",
                "command": "bd prime --memories-only --hook-json",
                "statusMessage": "Loading reduced Beads memories",
            }
        ],
    }


def build_managed_hooks(
    *,
    mode: str,
    visibility_hint_supported: bool,
    force_visibility_hint: bool = False,
    allow_degraded_context: bool = False,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    warnings: list[str] = []
    # Support-dependent refusal: quiet/verbose modes require visibility hint support.
    if mode in VISIBILITY_MODES and not (visibility_hint_supported or force_visibility_hint):
        raise ConfigurationError(
            "Codex visibilityHint support was not detected; refusing to render quiet/verbose hooks "
            "because the only safe mitigation is display-layer suppression that preserves additionalContext."
        )
    # Probe-independent refusal: compact-degraded requires acknowledgement.
    # This check is also performed in main() before detection to avoid probing configurations
    # that will be refused. Keeping it here provides defense in depth for direct callers.
    if mode == "compact-degraded" and not allow_degraded_context:
        raise ConfigurationError(
            "compact-degraded reduces automatic Beads context. Re-run with --allow-degraded-context "
            "only for a deliberate operator fallback."
        )
    if mode == "compact-degraded":
        warnings.append(
            "compact-degraded replaces full SessionStart context with bd prime --memories-only; "
            "this is not equivalent to bd codex-hook SessionStart."
        )
        return {"SessionStart": [degraded_session_entry()]}, warnings

    visibility_hint = mode if mode in VISIBILITY_MODES else None
    if force_visibility_hint and mode in VISIBILITY_MODES and not visibility_hint_supported:
        warnings.append("visibilityHint was forced without installed-Codex support detection.")
    hooks = {event: [managed_hook_entry(event, visibility_hint=visibility_hint)] for event in MANAGED_EVENTS}
    if mode == "full-context":
        warnings.append(
            "full-context preserves automatic Beads context injection; Codex may still display the SessionStart context."
        )
    return hooks, warnings


def hook_group_is_managed(event: str, group: dict[str, Any]) -> bool:
    expected = MANAGED_EVENTS.get(event, {}).get("command")
    if not expected:
        return False
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return False
    for hook in hooks:
        if isinstance(hook, dict) and hook.get("command") == expected:
            return True
    return False


def hook_group_is_mixed(event: str, group: dict[str, Any]) -> bool:
    """True when a managed group also holds entries that replacement would remove."""
    if not hook_group_is_managed(event, group):
        return False
    expected = MANAGED_EVENTS[event]["command"]
    return any(not (isinstance(hook, dict) and hook.get("command") == expected) for hook in group["hooks"])


def merge_hooks(existing: dict[str, Any], managed: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    if not isinstance(existing, dict):
        raise ConfigurationError("existing hooks configuration must be a JSON object; refusing to replace it")
    current = existing.get("hooks", {})
    if not isinstance(current, dict):
        raise ConfigurationError("existing hooks configuration 'hooks' must be an object; refusing to replace it")
    merged: dict[str, Any] = dict(existing)
    hooks = dict(current)
    for event, groups in managed.items():
        existing_groups = hooks.get(event, [])
        if not isinstance(existing_groups, list):
            raise ConfigurationError(f"existing {event} hooks must be a list of groups; refusing to replace them")
        for index, group in enumerate(existing_groups):
            if isinstance(group, dict) and hook_group_is_mixed(event, group):
                raise ConfigurationError(
                    f"existing {event} hook group {index} mixes the managed Beads command "
                    f"{MANAGED_EVENTS[event]['command']!r} with other hook entries; replacing it would remove "
                    "those entries, so it is refused. Split the group or remove the other entries first."
                )
        preserved = [group for group in existing_groups if not (isinstance(group, dict) and hook_group_is_managed(event, group))]
        hooks[event] = preserved + groups
    merged["hooks"] = hooks
    return merged


def load_existing_hooks(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"hooks": {}}

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConfigurationError(f"{path} contains duplicate JSON key {key!r}; refusing ambiguous hooks configuration")
            result[key] = value
        return result

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError(f"{path} contains invalid UTF-8 encoding") from exc

    try:
        return json.loads(content, object_pairs_hook=unique_keys)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"{path} is not valid JSON: {exc}") from exc


def path_has_existing_symlink_component(path: Path) -> bool:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            return True
    return False


def assert_safe_hooks_file_path(path: Path, *, project_dir: Path) -> Path:
    raw = Path(path).expanduser()
    if raw.name != "hooks.json":
        raise ConfigurationError("hooks file override must target a hooks.json file")
    if raw.exists():
        if raw.is_dir():
            raise ConfigurationError(f"refusing to overwrite directory hooks path: {raw}")
        if raw.is_symlink():
            raise ConfigurationError(f"refusing symlink hooks path: {raw}")
    parent = raw.parent
    if parent.name != ".codex":
        raise ConfigurationError("hooks file must live in a .codex directory")
    if parent.exists() and not parent.is_dir():
        raise ConfigurationError(f"hooks file parent is not a directory: {parent}")
    if path_has_existing_symlink_component(raw):
        raise ConfigurationError(f"refusing hooks path with symlink component: {raw}")
    nearest = parent
    while not nearest.exists() and nearest != nearest.parent:
        nearest = nearest.parent
    if not nearest.exists() or not nearest.is_dir():
        raise ConfigurationError(f"hooks file parent base does not exist: {parent}")
    resolved = raw.resolve(strict=False)
    allowed_roots = [project_dir.resolve(), Path.home().resolve()]
    if not any(_path_is_relative_to(resolved, root) for root in allowed_roots):
        raise ConfigurationError("hooks file must be inside the project directory or the operator home directory")
    return resolved


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def write_hooks(path: Path, payload: dict[str, Any]) -> None:
    validate_advisory_hook_configuration(payload, context=f"hooks file {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def build_result(
    *,
    args: argparse.Namespace,
    hooks_file: Path,
    support: dict[str, Any],
    rendered: dict[str, Any] | None,
    warnings: list[str],
    applied: bool,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "mode": args.mode,
        "project_dir": str(Path(args.project_dir).resolve()),
        "hooks_file": str(hooks_file),
        "applied": applied,
        "visibility_hint_supported": support["visibility_hint_supported"],
        "codex_version": support["codex_version"],
        "support_signal": support["support_signal"],
        "candidate_paths": support["candidate_paths"],
        "matching_paths": support["matching_paths"],
        "warnings": warnings,
        "error": error,
        "rendered_hooks": rendered,
    }


def render_human(result: dict[str, Any]) -> None:
    print(f"Mode: {result['mode']}")
    print(f"Hooks file: {result['hooks_file']}")
    print(f"Applied: {str(result['applied']).lower()}")
    print(f"Codex: {result['codex_version'] or 'not detected'}")
    print(f"visibilityHint support: {str(result['visibility_hint_supported']).lower()} ({result['support_signal']})")
    for warning in result["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    if result["error"]:
        print(f"error: {result['error']}", file=sys.stderr)
        return
    if not result["applied"]:
        print()
        print(json.dumps(result["rendered_hooks"], indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render or apply Codex Beads lifecycle hooks without weakening automatic Beads context injection."
        )
    )
    parser.add_argument("--project-dir", default=".", help="Project root containing .codex/hooks.json.")
    parser.add_argument("--hooks-file", help="Override the hooks JSON path.")
    parser.add_argument("--codex-bin", default="codex", help="Codex executable to inspect for visibilityHint support.")
    parser.add_argument(
        "--mode",
        choices=["full-context", "quiet", "verbose", "compact-degraded"],
        default="full-context",
        help="Hook profile to render. quiet/verbose require Codex visibilityHint support unless forced.",
    )
    parser.add_argument("--apply", action="store_true", help="Write the rendered profile to the hooks file.")
    parser.add_argument(
        "--force-visibility-hint",
        action="store_true",
        help="Render visibilityHint fields even when the installed Codex support signal is not detected.",
    )
    parser.add_argument(
        "--allow-degraded-context",
        action="store_true",
        help="Permit the compact-degraded fallback that intentionally reduces Beads context.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a JSON result.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    require_waiver_reason(args, ["force_visibility_hint", "allow_degraded_context"])
    return args


def main() -> int:
    args = parse_args()
    project_dir = Path(args.project_dir).resolve()
    hooks_file = assert_safe_hooks_file_path(
        Path(args.hooks_file).expanduser() if args.hooks_file else project_dir / ".codex" / "hooks.json",
        project_dir=project_dir,
    )
    warnings: list[str] = []
    support: dict[str, Any] = unprobed_support_info(args.codex_bin)
    try:
        # Validate existing hooks before running the probe to ensure existing-file validation
        # failures do not invoke the configured executable.
        existing = load_existing_hooks(hooks_file)
        validate_advisory_hook_configuration(existing, context=f"existing hooks file {hooks_file}")

        # Refuse probe-independent mode constraints before detection.
        if args.mode == "compact-degraded" and not args.allow_degraded_context:
            raise ConfigurationError(
                "compact-degraded reduces automatic Beads context. Re-run with --allow-degraded-context "
                "only for a deliberate operator fallback."
            )

        # Run the probe only after existing-file validation and probe-independent refusals.
        support = detect_visibility_hint_support(args.codex_bin)

        managed, build_warnings = build_managed_hooks(
            mode=args.mode,
            visibility_hint_supported=support["visibility_hint_supported"],
            force_visibility_hint=args.force_visibility_hint,
            allow_degraded_context=args.allow_degraded_context,
        )
        warnings.extend(build_warnings)
        rendered = merge_hooks(existing, managed)
        validate_advisory_hook_configuration(rendered, context=f"rendered hooks for {hooks_file}")
        if args.apply:
            write_hooks(hooks_file, rendered)
    except (ConfigurationError, CWOValidationError) as exc:
        result = build_result(
            args=args,
            hooks_file=hooks_file,
            support=support,
            rendered=None,
            warnings=warnings,
            applied=False,
            error=str(exc),
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            render_human(result)
        return 2

    result = build_result(
        args=args,
        hooks_file=hooks_file,
        support=support,
        rendered=rendered,
        warnings=warnings,
        applied=args.apply,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        render_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
