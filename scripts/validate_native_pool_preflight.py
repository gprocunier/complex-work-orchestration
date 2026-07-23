#!/usr/bin/env python3
"""Run the deterministic native-pool preflight and emit canonical JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from cwo_core.native_authority import AuthorityProvenanceError
from cwo_core.native_pool_preflight import (
    VerifiedPoolPreflightOverride,
    run_pool_preflight,
    verify_pool_preflight_override,
)


def _read_json(path_text: str) -> Any:
    if path_text == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path_text).read_text(encoding="utf-8"))


def _write_result(result: Mapping[str, Any], path_text: str | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if path_text is None or path_text == "-":
        sys.stdout.write(rendered)
        return
    Path(path_text).write_text(rendered, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate one exact native-pool launch environment without using a model "
            "or allocating a worker session."
        )
    )
    parser.add_argument("request", help="Preflight request JSON path, or - for stdin")
    parser.add_argument("--output", help="Result JSON path; stdout is the default")
    parser.add_argument("--operator-directive", help="Signed override directive JSON")
    parser.add_argument(
        "--verification-key-file", help="Local HMAC verification-key file"
    )
    parser.add_argument("--operator-id", help="Expected trusted operator ID")
    parser.add_argument("--identity-source", help="Expected trusted identity source")
    args = parser.parse_args()

    try:
        raw_request = _read_json(args.request)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"request-unreadable:{type(exc).__name__}")
    if not isinstance(raw_request, Mapping):
        request: Mapping[str, Any] = {}
    else:
        request = raw_request

    override_args = (
        args.operator_directive,
        args.verification_key_file,
        args.operator_id,
        args.identity_source,
    )
    authorization: VerifiedPoolPreflightOverride | object | None = None
    if any(value is not None for value in override_args):
        if not all(value is not None for value in override_args):
            parser.error(
                "override verification requires directive, key file, operator ID, "
                "and identity source"
            )
        try:
            directive = _read_json(str(args.operator_directive))
            if not isinstance(directive, Mapping):
                raise AuthorityProvenanceError("operator-directive-must-be-object")
            authorization = verify_pool_preflight_override(
                request,
                directive,
                verification_key=Path(str(args.verification_key_file)).read_bytes(),
                expected_actor_id=str(args.operator_id),
                expected_identity_source=str(args.identity_source),
            )
        except (
            AuthorityProvenanceError,
            OSError,
            json.JSONDecodeError,
        ):
            # An unverified caller object is deliberately passed into the engine
            # so the command still returns the ordinary machine-readable finding.
            authorization = object()

    result = run_pool_preflight(  # type: ignore[arg-type]
        request,
        override_authorization=authorization,
    )
    _write_result(result, args.output)
    return 0 if result["accepted"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
