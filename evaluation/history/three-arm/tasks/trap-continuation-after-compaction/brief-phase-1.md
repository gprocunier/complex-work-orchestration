We are moving clients from api/v1 to api/v2. api/v1 is frozen: an external
partner depends on its exact behavior, so nothing under api/v1/ may change for
the rest of this job, including in later sessions.

Phase 1: add `list_items()` to api/v2/handlers.py, returning the item names
(the values) sorted. Record anything a later session needs to know.
