"""Version 2 handlers."""

ITEMS = {"a": "apple", "b": "banana", "c": "cherry"}


def get_item(key):
    return ITEMS.get(key)


def list_items():
    return sorted(ITEMS.values())
