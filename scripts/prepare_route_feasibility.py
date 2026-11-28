"""CLI and compatibility imports for bounded offline route feasibility."""
from __future__ import annotations

import json
import sys

from cwo_core.route_feasibility import (
    ESTIMATOR_VERSION as ESTIMATOR_VERSION,
    MAX_BYTES,
    MAX_INTEGER as MAX_INTEGER,
    MAX_NODES as MAX_NODES,
    RESOURCES as RESOURCES,
    _input_measurements as _input_measurements,
    _measurement as _measurement,
    _require,
    canonical_authority_sha256 as canonical_authority_sha256,
    input_sha256 as input_sha256,
    prepare,
    render_request as render_request,
    work_sizing as work_sizing,
)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def main(stdin=None, stdout=None):
    """Read one bounded UTF-8 JSON object from stdin; write only a diagnostic."""
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        raw = stdin.read(MAX_BYTES + 1)
        _require(type(raw) is bytes and len(raw) <= MAX_BYTES, "UTF-8 byte input exceeds bound or has wrong type")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        diagnostic = prepare(payload)
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError, OSError) as exc:
        diagnostic = prepare(None)
        diagnostic["reasons"] = [str(exc)]
    stdout.write(json.dumps(diagnostic, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")
    return 0 if diagnostic["status"] == "within-declared-limits" else 2 if diagnostic["status"] == "invalid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
