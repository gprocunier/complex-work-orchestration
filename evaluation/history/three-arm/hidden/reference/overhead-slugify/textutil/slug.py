"""Slug helpers."""


def slugify(title):
    return "-".join(title.lower().split())
