from core.dates import parse_date


def month_of(text):
    return parse_date(text).month
