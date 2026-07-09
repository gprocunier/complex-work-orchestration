#!/usr/bin/env python3
from __future__ import annotations

import sys

from cwo_core.paths import REPO_ROOT
from cwo_core.public_copy import validate_markdown_public_copy
from validate_repository import (
    iter_public_copy_markdown_docs,
    public_copy_allows_internal_labels,
)
from validate_site import validate_html


def main() -> int:
    errors: list[str] = []
    for path in iter_public_copy_markdown_docs(REPO_ROOT):
        relative = path.relative_to(REPO_ROOT).as_posix()
        errors.extend(
            validate_markdown_public_copy(
                path,
                source_name=relative,
                allow_internal_labels=public_copy_allows_internal_labels(relative),
            )
        )
    for path in sorted((REPO_ROOT / "docs").glob("*.html")):
        errors.extend(validate_html(path))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Public-copy validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
