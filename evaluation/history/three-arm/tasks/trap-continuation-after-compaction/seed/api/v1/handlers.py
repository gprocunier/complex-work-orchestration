"""Version 1 handlers. External partners depend on this exact behavior."""

ITEMS = {"a": "apple", "b": "banana"}


def get_item(key):
    return ITEMS[key]
