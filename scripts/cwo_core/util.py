from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


def read_text_arg(text: str | None, file_path: str | None) -> str:
    parts: list[str] = []
    if text:
        parts.append(text)
    if file_path:
        parts.append(Path(file_path).read_text(encoding="utf-8"))
    if not parts:
        raise SystemExit("provide task text or --file")
    return "\n\n".join(parts)


def term_hits(text: str, terms: list[str]) -> list[str]:
    haystack = text.lower()
    hits: list[str] = []
    for term in terms:
        needle = term.lower()
        if not needle:
            continue
        prefix = r"(?<![a-z0-9])" if needle[0].isalnum() else ""
        suffix = r"(?![a-z0-9])" if needle[-1].isalnum() else ""
        pattern = f"{prefix}{re.escape(needle)}{suffix}"
        if re.search(pattern, haystack):
            hits.append(term)
    return hits


def rank_max(values: list[str], order: list[str], default: str) -> str:
    current = default
    for value in values:
        if value in order and order.index(value) > order.index(current):
            current = value
    return current


def rank_allows(value: str, limit: str, order: list[str]) -> bool:
    if value not in order or limit not in order:
        return False
    return order.index(value) <= order.index(limit)


def metadata_json(metadata: dict[str, Any]) -> str:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":"))


def artifact_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write text via a same-directory temp file and atomic replace."""
    target = Path(path)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding=encoding,
            dir=parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
        temp_name = None
    finally:
        if temp_name:
            try:
                Path(temp_name).unlink()
            except FileNotFoundError:
                pass


def make_dispatch_id(bead_id: str, generated_at: str | None = None) -> str:
    timestamp = generated_at or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_bead = re.sub(r"[^A-Za-z0-9_.-]+", "-", bead_id).strip("-") or "unassigned"
    return f"dispatch-{safe_bead}-{timestamp}"


def packet_payload_hash(packet: dict[str, Any]) -> str:
    payload = dict(packet)
    payload.pop("packet_sha256", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def parse_iso_datetime(value: str, field_name: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise SystemExit(f"{field_name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)
