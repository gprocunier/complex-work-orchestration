#!/usr/bin/env python3
"""Refresh mechanical release bindings; span and primitive changes need review."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core import release_effect_routes as R

MANIFEST = "tests/fixtures/affected_contract_compatibility/EXAMPLE-manifest.json"


def render(value, original):
    """Retain the inventory's compact layout and the checkpoint's indented layout."""
    if value == json.loads(original):
        return original
    if b"\n" in original.rstrip(b"\n"):
        text = json.dumps(value, ensure_ascii=True, indent=2)
    else:
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return text.encode() + b"\n"


def changes(label, before, after):
    fields = []
    for key in after:
        if before[key] != after[key]:
            fields.append(f"{key} {before[key]} -> {after[key]}")
    return f"{label}: {', '.join(fields)}"


def refresh_points(value, contents, messages):
    for key, row in value["points"].items():
        point = R._table_point(value, key)
        location = f"{point['path']}:{point['line']}"
        if "col" in point:
            location += f":{point['col']}-{point['end_line']}:{point['end_col']}"
        try:
            if "symbol" not in point:
                R._point(contents, point)
                continue
            observed, _text = R.body(contents, point)
        except (R.Refused, SyntaxError, UnicodeError) as exc:
            raise R.Refused(f"point {key} {location}: {exc}") from exc
        if observed != point:
            messages.append(changes(f"declaration {key} {point['path']}:{point['symbol']}", point, observed))
            row[2:] = [observed["line"], observed["sha256"]]


def refresh_checkpoint(manifest, files, messages):
    R.need(set(manifest["files"]) == set(manifest["current_file_modes"]),
           "checkpoint dependency/mode roster mismatch")
    for path, previous in manifest["files"].items():
        R.need(path in files, f"checkpoint source missing: {path}")
        identity = files[path]
        if previous != identity["sha256"]:
            messages.append(f"checkpoint files {path}: sha256 {previous} -> {identity['sha256']}")
            manifest["files"][path] = identity["sha256"]
        mode = manifest["current_file_modes"][path]
        if mode != identity["mode"]:
            messages.append(f"checkpoint current_file_modes {path}: mode {mode} -> {identity['mode']}")
            manifest["current_file_modes"][path] = identity["mode"]


def route_paths(route):
    points = R.route_points(route)
    for witness in route["witnesses"]:
        points.extend([witness["body"], *witness.get("support", [])])
    return set(route["trace_files"]) | {point["path"] for point in points}


def check_proposal(value, files, contents):
    """Use the installed checker's contracts without writing a proposed inventory."""
    routes = R._routes(value)
    R._check_script_bindings(value, files)
    required = R._inventory_points(value, contents)
    for route in routes:
        R.route_binding(contents, route)
        required.update(route_paths(route))
    R.need(required <= set(value["source_bindings"]), "unbound route source")
    # Never rewrite hits, exclusions or dispositions. Even a changed candidate's
    # bytes or location needs an explicit decision before a mechanical refresh.
    hits, _coverage = R._check_primitive_coverage(value, contents, routes)
    R._check_gate_effects(contents, routes, hits)
    return routes


def rebind(root):
    root = Path(root).resolve()
    original, inventory_hash = R.inventory(root)
    value = copy.deepcopy(original)
    files, contents = R.source(root)
    captured_files = files.copy()
    R.need(files[R.INVENTORY]["sha256"] == inventory_hash, "inventory changed before source capture")
    R.need(R.INVENTORY not in value["source_bindings"], "inventory cannot bind itself")
    R.need(MANIFEST in value["source_bindings"], "checkpoint manifest binding required")
    manifest_raw = contents[MANIFEST]
    manifest = json.loads(manifest_raw)
    messages = []
    refresh_checkpoint(manifest, files, messages)
    proposed_manifest = render(manifest, manifest_raw)
    # Bind the proposed checkpoint bytes, not the old on-disk checkpoint.
    files[MANIFEST] = {**files[MANIFEST], "sha256": R.digest(proposed_manifest), "size": len(proposed_manifest)}
    contents[MANIFEST] = proposed_manifest
    refresh_points(value, contents, messages)
    changed_files = set()
    for path, previous in value["source_bindings"].items():
        R.need(path in files, f"bound source missing: {path}")
        if previous != files[path]:
            messages.append(changes(f"source_bindings {path}", previous, files[path]))
            changed_files.add(path)
            previous.update(files[path])
    routes = check_proposal(value, files, contents)
    for route in sorted(routes, key=lambda row: row["id"]):
        affected = sorted(changed_files & route_paths(route))
        if affected:
            messages.append(f"affected route {route['id']}: {', '.join(affected)}")
    proposed_inventory = render(value, contents[R.INVENTORY])
    # All refusal checks, rendering and source-drift checks precede either write.
    after, _contents = R.source(root)
    R.need(captured_files == after, "source changed before write")
    for path, raw in ((MANIFEST, proposed_manifest), (R.INVENTORY, proposed_inventory)):
        if raw != (manifest_raw if path == MANIFEST else contents[R.INVENTORY]):
            (root / path).write_bytes(raw)
    return messages


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="source checkout (default: this command's checkout)")
    args = parser.parse_args(argv)
    try:
        messages = rebind(args.root)
    except (R.Refused, OSError, ValueError, KeyError, IndexError, TypeError, SyntaxError) as exc:
        print(f"Rebind refused: {exc}", file=sys.stderr)
        return 1
    print("\n".join(messages) if messages else "No bindings changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
