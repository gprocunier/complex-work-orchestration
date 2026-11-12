"""Slug helpers."""


def slugify(title):
    words = title.lower().split()
    first = words[0]
    rest = words[1:]
    return "-".join([first, *rest])
