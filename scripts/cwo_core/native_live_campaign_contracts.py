"""Campaign compatibility imports and the private JSON snapshot type."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping

from .native_campaign_history import (
    COMMIT_RE as COMMIT_RE,
    TRANSPORT_MOVED_SOURCE_PATHS as TRANSPORT_MOVED_SOURCE_PATHS,
    VALIDATOR_CONTRACT_PATHS as VALIDATOR_CONTRACT_PATHS,
    VALIDATOR_CONTRACT_PATHS_V1 as VALIDATOR_CONTRACT_PATHS_V1,
    VALIDATOR_CONTRACT_PATHS_V2 as VALIDATOR_CONTRACT_PATHS_V2,
    VALIDATOR_CONTRACT_PATHS_V3 as VALIDATOR_CONTRACT_PATHS_V3,
    VALIDATOR_CONTRACT_PATHS_V4 as VALIDATOR_CONTRACT_PATHS_V4,
    VALIDATOR_CONTRACT_PATHS_V5 as VALIDATOR_CONTRACT_PATHS_V5,
    VALIDATOR_CONTRACT_PATHS_V6 as VALIDATOR_CONTRACT_PATHS_V6,
    VALIDATOR_CONTRACT_PATHS_V7 as VALIDATOR_CONTRACT_PATHS_V7,
    VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES as VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES,
    canonical_sha256 as canonical_sha256,
    validator_contract_sha256 as validator_contract_sha256,
    validator_contract_sha256_v2 as validator_contract_sha256_v2,
    validator_contract_sha256_v3 as validator_contract_sha256_v3,
    validator_contract_sha256_v4 as validator_contract_sha256_v4,
    validator_contract_sha256_v5 as validator_contract_sha256_v5,
    validator_contract_sha256_v6 as validator_contract_sha256_v6,
    validator_contract_sha256_v7 as validator_contract_sha256_v7,
    validator_contract_v6_tree_errors as validator_contract_v6_tree_errors,
    _REGULAR_BLOB_MODES as _REGULAR_BLOB_MODES,
    _TOOL_SURFACE_PATH as _TOOL_SURFACE_PATH,
    _TRANSPORT_MOVED_SOURCE_ROOTS as _TRANSPORT_MOVED_SOURCE_ROOTS,
    _TRANSPORT_RUNNER_PATH as _TRANSPORT_RUNNER_PATH,
    _V6_PRE_MOVE_IDENTITY_PAIRS as _V6_PRE_MOVE_IDENTITY_PAIRS,
    _is_commit as _is_commit,
    _run_git as _run_git,
    _v6_blob_sha256 as _v6_blob_sha256,
    _v6_tree_entries as _v6_tree_entries,
    _validator_contract_sha256 as _validator_contract_sha256,
)


@dataclass(frozen=True)
class JsonArtifactSnapshot:
    """One immutable byte read and its parsed JSON object."""

    raw: bytes
    value: Mapping[str, Any]

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()
