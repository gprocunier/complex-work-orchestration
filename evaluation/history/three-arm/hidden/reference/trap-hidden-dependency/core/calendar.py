from core.dates import parse_iso_date


def day_of_week(text):
    return parse_iso_date(text).strftime("%A")
