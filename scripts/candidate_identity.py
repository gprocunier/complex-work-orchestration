#!/usr/bin/env python3
"""Record and verify the exact candidate a Bead's delivery claims (issue #37).

``record`` identifies the working tree (commit, tree and a manifest of content that differs from the commit) for the current
version of a requirement baseline and writes the candidate identity record to a new file. It prints the reference
line to post on the Bead; it does not post it. ``verify`` checks a recorded candidate against the working tree, the
baseline chain and the Bead, and refuses on any mismatch, drift or absence. Both read the working tree and the
repository inertly, with no Git command run against either; the only Beads command either runs is ``bd show``
(``verify --read-beads``). Neither makes successful closure available.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cwo_core.candidate_identity import (
    CandidateIdentityError,
    candidate_digest,
    candidate_reference_line,
    capture_candidate,
    check_candidate,
)
from cwo_core.requirement_baseline import RequirementBaselineError, load_record, resolve_chain


def _read_record(path: str) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise RequirementBaselineError([f"cannot read input {path}: {exc}"]) from exc
    return load_record(text)


def _chain(baseline: str, amendments: list[str]) -> dict[str, Any]:
    initial = _read_record(baseline)
    return resolve_chain(initial, [_read_record(path) for path in amendments])


def _output_errors(output: Path, repo: Path, excluded: list[str]) -> list[str]:
    """A record written inside the working tree would change the candidate it describes, unless it is excluded."""
    target = output.resolve()
    root = repo.resolve()
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError:
        return []
    if any(relative == path or relative.startswith(path + "/") for path in excluded):
        return []
    return [f"--output {output} is inside the working tree and not under an --exclude path, so writing it would "
            "change the candidate it records"]


def _bead_projection(args: argparse.Namespace, bead_id: str) -> Any:
    if args.bead_json:
        value: Any = json.loads(Path(args.bead_json).read_text(encoding="utf-8"))
    else:
        from cwo_core.beads import show_bead_json

        value = show_bead_json(bead_id, include_comments=True)
    if type(value) is list and len(value) == 1:
        value = value[0]
    return value


def _record(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    repo = Path(args.repo)
    errors = _output_errors(Path(args.output), repo, args.exclude)
    if errors:
        return 1, {"recorded": False, "errors": errors}
    chain = _chain(args.baseline, args.amendment)
    record = capture_candidate(repo, chain=chain, base_commit=args.base_commit, scope_paths=args.scope,
                               excluded_paths=args.exclude)
    digest = candidate_digest(record)
    with Path(args.output).open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return 0, {
        "recorded": True,
        "errors": [],
        "output": args.output,
        "digest": digest,
        "bead_id": record["bead_id"],
        "baseline": record["baseline"],
        "commit": record["commit"],
        "tree": record["tree"],
        "manifest_entries": len(record["worktree_manifest"]),
        "reference_line": candidate_reference_line(record["bead_id"], digest),
    }


def _verify(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    chain = _chain(args.baseline, args.amendment)
    record = _read_record(args.candidate)
    try:
        bead = _bead_projection(args, chain["bead_id"])
    except (OSError, ValueError, SystemExit) as exc:
        return 1, {"valid": False, "errors": [f"the Bead could not be read: {exc}"]}
    result = check_candidate(record, root=args.repo, chain=chain, bead=bead)
    result["bead_id"] = chain["bead_id"]
    result["baseline"] = {"version": chain["version"], "digest": chain["digest"], "amendment_ids": chain["amendment_ids"]}
    return (0 if result["valid"] else 1), result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record or verify the exact candidate a Bead's delivery claims.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("record", "Identify the working tree and write a candidate identity record."),
                       ("verify", "Check a candidate identity against the working tree, baseline chain and Bead.")):
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("--repo", default=".", help="Top of the Git working tree (default: current directory).")
        command.add_argument("--baseline", required=True, help="Requirement baseline record, version 1.")
        command.add_argument("--amendment", action="append", default=[],
                             help="Requirement amendment applied to the baseline, in order. Repeatable.")
        command.add_argument("--json", action="store_true", help="Emit the JSON result.")
        if name == "record":
            command.add_argument("--base-commit", required=True, help="The commit the work started from, by its full object ID.")
            command.add_argument("--scope", action="append", required=True,
                                 help="Repository path the delivery claims ('.' for the whole repository). Repeatable.")
            command.add_argument("--exclude", action="append", default=[],
                                 help="Untracked path left out of the candidate, such as an evidence directory. "
                                 "Repeatable; it cannot contain tracked files or delivery scope paths.")
            command.add_argument("--output", required=True, help="New file for the record; an existing file is refused.")
        else:
            command.add_argument("--candidate", required=True, help="Candidate identity record to verify.")
            source = command.add_mutually_exclusive_group(required=True)
            source.add_argument("--bead-json", help="Saved projection from `bd show <id> --json --include-comments`.")
            source.add_argument("--read-beads", action="store_true",
                                help="Read the Bead with `bd show --json --include-comments` (read-only).")
    args = parser.parse_args(argv)
    try:
        code, result = _record(args) if args.command == "record" else _verify(args)
    except (CandidateIdentityError, RequirementBaselineError) as exc:
        code, result = 1, {"valid": False, "recorded": False, "errors": exc.errors}
    except FileExistsError:
        code, result = 1, {"recorded": False, "errors": [f"--output {args.output} already exists; nothing was written"]}
    except OSError as exc:
        code, result = 1, {"valid": False, "recorded": False, "errors": [f"cannot read input: {exc}"]}
    if args.command == "verify":
        result.pop("recorded", None)
    else:
        result.pop("valid", None)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0 and args.command == "record":
        print(f"candidate {result['digest']} recorded in {result['output']}")
        print(f"post this exact line as a comment on {result['bead_id']}:")
        print(result["reference_line"])
    elif code == 0:
        print(f"candidate {result['digest']} verified: it is the current candidate for {result['bead_id']}")
    else:
        print("candidate refused:", file=sys.stderr)
        for error in result["errors"]:
            print(f"- {error}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
