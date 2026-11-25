"""Date parsing helpers."""

from datetime import date


def parse_iso_date(text):
    """Parse a YYYY-MM-DD date."""
    year, month, day = (int(part) for part in text.split("-"))
    return date(year, month, day)
