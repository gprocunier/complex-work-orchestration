"""Exact model identities named by current runtime code, each written once.

Current runtime modules import these names instead of repeating the literal. Each value is an
exact model identity, recorded as resolved; nothing here selects, substitutes, qualifies or
authorizes a model, and no alias resolves to a different model. What each identity is allowed to
do is decided by current policy (``policy/native-worker-execution.yaml`` task_selected_routing,
through ``operative_routing``), not by this module.

- ``SPARK_MODEL``: historical-nonoperative under the active task_selected_routing v3. Current
  runtime defaults and requirements that still name it (native worker preparation and session
  checks, precommit, work sizing, activation preview, coach and scaffold text) are recorded as
  unadjudicated in the model-identity register; replacing them is a model choice for the
  operator, not part of this centralization.
- ``GPT55_MODEL``: v2 fallback identity, prohibited for v3 dispatch.
- ``TERRA_MODEL`` and ``LUNA_MODEL``: current v3 operative models (escalation-only and primary).

Frozen validator-contract files, whose blobs are bound into historical evidence, keep their own
literals and do not import this module.
"""

from __future__ import annotations

SPARK_MODEL = "gpt-5.3-codex-spark"
GPT55_MODEL = "gpt-5.5"
TERRA_MODEL = "gpt-5.6-terra"
LUNA_MODEL = "gpt-5.6-luna"
