"""Bounded referenced-record enumeration; unrelated bytes convey no authority."""
from __future__ import annotations

import os

from . import host_records as records


def referenced_inventory(directory, anchors, limits):
    expected = {record_id for record_id, kind, event in anchors if kind in records._TYPES
                and event == ('dispatch_prepared' if kind == 'dispatch' else 'host_record_written')}
    names = {records._sha(record_id) + '.json': record_id for record_id in expected}
    values, strays, present = [], [], set()
    count = scan_bytes = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            count += 1
            records._need(count <= limits.max_records, 'host record count bound exceeded')
            info = entry.stat(follow_symlinks=False)
            scan_bytes += info.st_size
            records._need(scan_bytes <= limits.max_scan_bytes, 'host record scan byte bound exceeded')
            if entry.name not in names:
                strays.append((entry.name, info))
                continue
            record_id = names[entry.name]
            values.append(records._verified_record_at(record_id, None, anchors, directory, limits))
            # DirEntry.stat caches metadata; recheck the name through the held directory.
            current = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
            records._need(records._identity(current) == records._identity(info),
                          'host record changed around inventory verification')
            present.add(record_id)
    records._require_record_inventory(anchors, present)
    return values, strays
