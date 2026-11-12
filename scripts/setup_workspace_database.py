#!/usr/bin/env python3
"""Bind the existing workspace database physically, without invoking Beads."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwo_core.host_records import configured_store


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True,
                        help='Absolute existing owner-private Beads database file or directory.')
    args = parser.parse_args()
    identity = configured_store().setup_database_identity(Path(args.database))
    print(json.dumps({'database_identity': identity, 'beads_state_changed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
