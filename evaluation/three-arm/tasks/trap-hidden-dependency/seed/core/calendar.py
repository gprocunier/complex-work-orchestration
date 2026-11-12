from core.dates import parse_date


def day_of_week(text):
    return parse_date(text).strftime("%A")
