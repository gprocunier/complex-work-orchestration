from core.dates import parse_iso_date


def month_of(text):
    return parse_iso_date(text).month
