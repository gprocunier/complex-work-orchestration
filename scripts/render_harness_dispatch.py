#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from cwo_core.harness import build_harness_dispatch
from cwo_core.util import make_dispatch_id, read_text_arg


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a CWO harness dispatch envelope without executing it.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--environment", default="connected-opencode-exemplar")
    parser.add_argument("--harness")
    parser.add_argument("--role", default="worker")
    parser.add_argument("--bead")
    parser.add_argument("--epic")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--agent")
    parser.add_argument("--model")
    parser.add_argument("--model-profile")
    parser.add_argument("--variant")
    parser.add_argument("--requires-repo-write", action="store_true")
    parser.add_argument("--requires-shell", action="store_true")
    parser.add_argument("--requires-web", action="store_true")
    parser.add_argument("--requires-local-openai-compatible", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    dispatch_id = args.dispatch_id or make_dispatch_id(args.bead or "harness")
    capability_requirements = {
        key: True
        for key, enabled in {
            "supports_repo_write": args.requires_repo_write,
            "supports_shell": args.requires_shell,
            "supports_web": args.requires_web,
            "supports_local_openai_compatible": args.requires_local_openai_compatible,
        }.items()
        if enabled
    }
    envelope = build_harness_dispatch(
        task=task,
        dispatch_id=dispatch_id,
        environment_key=args.environment,
        role=args.role,
        harness_key=args.harness,
        bead_id=args.bead,
        epic_id=args.epic,
        agent=args.agent,
        model=args.model,
        model_profile_key=args.model_profile,
        variant=args.variant,
        capability_requirements=capability_requirements,
    )
    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
        return

    print("# Harness Dispatch")
    print()
    print(f"Dispatch ID: {envelope['dispatch_id']}")
    print(f"Environment: {envelope['environment']}")
    print(f"Harness: {envelope['harness']}")
    print(f"Role: {envelope['role']}")
    print(f"Prompt SHA-256: {envelope['prompt_sha256']}")
    print()
    print("Suggested command:")
    print()
    print(envelope["suggested_command"])
    print()
    print("Prompt:")
    print()
    print(envelope["prompt"])


if __name__ == "__main__":
    main()
