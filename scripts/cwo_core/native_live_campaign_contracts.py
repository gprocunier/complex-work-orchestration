"""Read-only Git digests and JSON snapshots retained after campaign retirement.

The original authorization and proof validators are available in v1.37.0.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from .workspace_capture import trusted_git_completed


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class JsonArtifactSnapshot:
    """One immutable byte read and its parsed JSON object."""

    raw: bytes
    value: Mapping[str, Any]

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and bool(COMMIT_RE.fullmatch(value))


def _run_git(repo: Path, *args: str) -> str:
    """Read-only Git through the trusted executable; raises CalledProcessError on failure."""
    completed = trusted_git_completed(repo, list(args), text=True)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, completed.args, completed.stdout, completed.stderr)
    return completed.stdout.strip()


VALIDATOR_CONTRACT_PATHS_V1 = (
    "scripts/cwo_core/audit.py",
    "scripts/cwo_core/native_canary_contracts.py",
    "scripts/cwo_core/native_live_allocation_ledger.py",
    "scripts/cwo_core/native_live_campaign_contracts.py",
    "scripts/run_native_pool_live_canaries.py",
    "schemas/full-auto-run-authorization.schema.json",
    "schemas/full-auto-run-authorization-v6.schema.json",
    "schemas/native-live-campaign-manifest.schema.json",
    "schemas/native-live-campaign-manifest-v3.schema.json",
    "schemas/native-live-campaign-cause-evidence.schema.json",
    "schemas/native-canary-authorization-state.schema.json",
    "schemas/native-canary-authorization-state-v2.schema.json",
    "schemas/native-live-allocation-ledger-v2.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V2 = VALIDATOR_CONTRACT_PATHS_V1 + (
    "schemas/full-auto-run-authorization-v7.schema.json",
    "schemas/native-live-campaign-manifest-v4.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V3 = VALIDATOR_CONTRACT_PATHS_V2 + (
    "schemas/full-auto-run-authorization-v8.schema.json",
    "schemas/native-live-campaign-manifest-v5.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V4 = VALIDATOR_CONTRACT_PATHS_V3 + (
    "schemas/full-auto-run-authorization-v9.schema.json",
    "schemas/native-live-campaign-manifest-v6.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V5 = VALIDATOR_CONTRACT_PATHS_V4 + (
    "schemas/full-auto-run-authorization-v10.schema.json",
    "schemas/native-live-campaign-manifest-v7.schema.json",
)
VALIDATOR_CONTRACT_PATHS_V6 = VALIDATOR_CONTRACT_PATHS_V5 + (
    "scripts/cwo_core/native_pool_config.py",
    "schemas/full-auto-run-authorization-v11.schema.json",
    "schemas/native-live-campaign-manifest-v8.schema.json",
    "schemas/generation11-terminal-facts.schema.json",
)
# V7 is V6 plus the code that moved out of the runner into cwo_core: the
# app-server transport, the tool-surface implementation, their packages and the
# compatibility shim that resolves the old tool-surface import name. V1 to V6
# stay byte-for-byte as recorded, so digests over historical trees reproduce;
# from the move onward only V7 binds the transport bytes.
VALIDATOR_CONTRACT_PATHS_V7 = VALIDATOR_CONTRACT_PATHS_V6 + (
    "scripts/codex_tool_surface.py",
    "scripts/cwo_core/codex_tool_surface.py",
    "scripts/cwo_core/supervision/__init__.py",
    "scripts/cwo_core/supervision/transport/__init__.py",
    "scripts/cwo_core/supervision/transport/app_server.py",
    "scripts/cwo_core/supervision/transport/errors.py",
    "scripts/cwo_core/supervision/transport/private_io.py",
)
# Historical callers imported this name when v1 was the only contract. Keep the
# alias immutable; Generation 8 must opt in to the explicitly versioned v2 API.
VALIDATOR_CONTRACT_PATHS = VALIDATOR_CONTRACT_PATHS_V1


def _validator_contract_sha256(
    repo_root: Path,
    checkpoint_tree: str | None,
    *,
    paths: tuple[str, ...],
    contract: str,
    proof_dag: tuple[str, ...],
    ancestor_depth_exact: int,
) -> str:
    """Bind validator blobs from one immutable checkpoint tree.

    Reading the working tree one pathname at a time leaves the digest vulnerable
    to a concurrent rewrite-and-restore race. Git tree objects provide one stable,
    candidate-bound snapshot for the complete validator contract.
    """

    root = Path(repo_root).resolve()
    if checkpoint_tree is None:
        completed = trusted_git_completed(
            root,
            ["rev-parse", "HEAD^{tree}"],
            text=True,
        )
        checkpoint_tree = completed.stdout.strip()
    if not _is_commit(checkpoint_tree):
        raise ValueError("validator-contract-tree-invalid")
    files: list[dict[str, str]] = []
    for relative in paths:
        entry = trusted_git_completed(
            root,
            ["ls-tree", checkpoint_tree, "--", relative],
            text=True,
        )
        fields = entry.stdout.strip().split(None, 3)
        if (
            entry.returncode != 0
            or len(fields) != 4
            or fields[0] not in {"100644", "100755"}
            or fields[1] != "blob"
            or fields[3] != relative
        ):
            raise ValueError(f"validator-contract-path-invalid:{relative}")
        blob = trusted_git_completed(
            root,
            ["show", f"{checkpoint_tree}:{relative}"],
            text=False,
        )
        if blob.returncode != 0:
            raise ValueError(f"validator-contract-blob-invalid:{relative}")
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(blob.stdout).hexdigest(),
            }
        )
    return canonical_sha256(
        {
            "contract": contract,
            "proof_dag": list(proof_dag),
            "ancestor_depth_exact": ancestor_depth_exact,
            "checkpoint_tree": checkpoint_tree,
            "files": files,
        }
    )


def validator_contract_sha256(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Reproduce the frozen Generation-7 validator-contract v1 digest."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V1,
        contract="cwo-live-successor-validator:v1",
        proof_dag=("v6/v3", "v5/v2", "v4/v1"),
        ancestor_depth_exact=1,
    )


def validator_contract_sha256_v2(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the fixed Generation-8 v7/v4 finite predecessor proof DAG."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V2,
        contract="cwo-live-successor-validator:v2",
        proof_dag=("v7/v4", "v6/v3", "v5/v2", "v4/v1"),
        ancestor_depth_exact=2,
    )


def validator_contract_sha256_v3(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v8/v5 DAG and its dedicated nonattesting quarantine leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V3,
        contract="cwo-live-successor-validator:v3",
        proof_dag=("v8/v5", "v7/v4", "v6/v3", "v5/v2", "v4/v1"),
        ancestor_depth_exact=3,
    )


def validator_contract_sha256_v4(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v9/v6 DAG and its terminal protected-fault predecessor leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V4,
        contract="cwo-live-successor-validator:v4",
        proof_dag=(
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=4,
    )


def validator_contract_sha256_v5(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v10/v7 DAG and its zero-allocation preflight-fault leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V5,
        contract="cwo-live-successor-validator:v5",
        proof_dag=(
            "v10/v7",
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=5,
    )


def validator_contract_sha256_v6(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v11/v8 DAG and terminal interrupted-empty-boundary leaf."""

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V6,
        contract="cwo-live-successor-validator:v6",
        proof_dag=(
            "v11/v8",
            "v10/v7",
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=6,
    )


def validator_contract_sha256_v7(
    repo_root: Path, checkpoint_tree: str | None = None
) -> str:
    """Bind the v6 proof DAG over the runner and the moved transport sources.

    The predecessor proof DAG and ancestor depth are v6's: only the bound path
    list grows. The retired launcher never selected v7 for execution.
    """

    return _validator_contract_sha256(
        repo_root,
        checkpoint_tree,
        paths=VALIDATOR_CONTRACT_PATHS_V7,
        contract="cwo-live-successor-validator:v7",
        proof_dag=(
            "v11/v8",
            "v10/v7",
            "v9/v6",
            "v8/v5",
            "v7/v4",
            "v6/v3",
            "v5/v2",
            "v4/v1",
        ),
        ancestor_depth_exact=6,
    )


# The files V7 adds to V6 that exist only after the move. The old tool-surface
# shim is left out: its path also exists, as the real module, before the move.
TRANSPORT_MOVED_SOURCE_PATHS = (
    "scripts/cwo_core/codex_tool_surface.py",
    "scripts/cwo_core/supervision/__init__.py",
    "scripts/cwo_core/supervision/transport/__init__.py",
    "scripts/cwo_core/supervision/transport/app_server.py",
    "scripts/cwo_core/supervision/transport/errors.py",
    "scripts/cwo_core/supervision/transport/private_io.py",
)
_TRANSPORT_RUNNER_PATH = "scripts/run_native_pool_live_canaries.py"
_TOOL_SURFACE_PATH = "scripts/codex_tool_surface.py"
_TRANSPORT_MOVED_SOURCE_ROOTS = (
    "scripts/cwo_core/codex_tool_surface.py",
    "scripts/cwo_core/supervision",
)
# The reviewed pre-move identities: (sha256 of the runner blob, sha256 of the
# tool-surface blob or None where that path is absent, provenance). Derived from
# Git history alone, not from source shape. The scope is every commit with
# 0aafd2f (which introduced validator contract v6) as ancestor-or-self and
# b8f6251 (the last commit in the pre-move range) as descendant-or-self: 182
# commits, each carrying every v6 path and no moved source. Their runner and
# tool-surface blobs form exactly these 31 pairs, one per commit that changed
# the runner, in history order. Each runner holds the transport itself; the
# tool surface first appears with the runner from 71b31b8. A test re-derives
# the original list from history. One explicit continuation pair is additionally
# admitted below: introduced by 281d102 and retained at accepted pre-move head
# 3ac550f. Intervening pairs are not automatically eligible. No arbitrary HEAD,
# mixed pairing, source-shape match or post-move tree gains acceptance.
VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES = (
    (
        "17b3f67b0da6af739faae837aaf4aa0bd7a342fa84994f517ff36ce7d07f1ebc",
        None,
        "runner blob 2d2d147b21f2 from 0aafd2f",
    ),
    (
        "94368496846c1217dc00f4d64a871ca8583d49ee2eff430cc60d026c2e013f13",
        None,
        "runner blob 857e3af01b7c from 1f0806c",
    ),
    (
        "d6e7654db1e616e5d5141c82e3a3c7317f240ba00cc45e11cfdb387385fd11c7",
        None,
        "runner blob 88c7e865c4d2 from 82e0a81",
    ),
    (
        "113e7a78e943714aeb4adbb894d61bb1b2cf5ddee9b430be28233d831d47f096",
        None,
        "runner blob d7d2867edef3 from 37ffa82",
    ),
    (
        "461df4e6a50ef578b4f41433224ba3a93b5c4724dbb96aad9fd3fee56a12767c",
        None,
        "runner blob b64a6b71e4e9 from a2e5b2f",
    ),
    (
        "4bdfa55a0d1d6a60c5097b20643a73da4a161717687d1f1b0b0aefc048475e4f",
        None,
        "runner blob c23b55ae9682 from 7ed3110",
    ),
    (
        "4405c023738a9ed09ea4a0d79b32b861107fafc00db4be676f4023bb45c3c9d1",
        None,
        "runner blob d012f6068456 from 9e24e81",
    ),
    (
        "457776f8d4a0221986bcaea0ebf0ee597759c1f75011d4179856ac50d3ba3975",
        None,
        "runner blob 2518ba9c05ab from 1de94dc",
    ),
    (
        "dc69edeb6bdf056589d4978242595d55772fbdc9b407a53be0454eab91019f36",
        None,
        "runner blob 0d9517f4220c from 683e722",
    ),
    (
        "4a8b36aa7ca5608e01107fd383f638025b2887ef1a607c9a990816574a884991",
        None,
        "runner blob 2b4201ab6537 from e605348",
    ),
    (
        "a00923506220a9ea2357250bcca5142d098251dbe480060ad8ff7c1c43b63d77",
        None,
        "runner blob c7a2618a1a97 from a8bc0fa",
    ),
    (
        "8317c7daaaac6b2e21407cf9c9c9f47de4dabb89ae0253eb7263602d8087a429",
        None,
        "runner blob 55f09ee9926b from 69e9c09",
    ),
    (
        "656a413e1029d7a03d51636c25ba44fa46307331efee27ec3c641ce34b397593",
        None,
        "runner blob 60b7e51b343a from 198df7a",
    ),
    (
        "cb8a19f3efbc178d4f4da04575b325fd324453365f819e9dd8498a2c0acc8605",
        None,
        "runner blob e22be4c51d75 from c7448a5",
    ),
    (
        "176fdd9cf376169ec5273f928cc426d77972170331ae2fdc49d529d88d76c01e",
        None,
        "runner blob db710e2a847b from a2e5b10",
    ),
    (
        "648e97b93cb9b26479f5dd84ae93959581852572531c7c8ef890ee3558e59211",
        None,
        "runner blob 7cf19f7460c3 from a860b17",
    ),
    (
        "dde4525c86abe362ec01db805107f6ebabd7bf265f139c39912c9dd46ae5b373",
        None,
        "runner blob 9781cd73b7ea from 5dcbbca",
    ),
    (
        "2250b09b8d5c44d139e48c719e0ec1902245b9c4b7ac0c230501217f7c6f71de",
        None,
        "runner blob 0275b562a470 from 158aee7",
    ),
    (
        "f2403f89ac86db738a0f2f1121a0bcb628b35f10244b806f7adaad0d4240e608",
        None,
        "runner blob 2ad3ea6bb760 from 5db631a",
    ),
    (
        "a9f1e78a4133a3a457ee5446811c3588b2d974e3a018535ff44b4293ab650af4",
        None,
        "runner blob cae04db62963 from 6651579",
    ),
    (
        "38db147e0f6d524a37f0bd21e3a0e8291a7372fac1fe21c3b4ad651003deaccb",
        None,
        "runner blob 46729721d4a1 from 7af85ea",
    ),
    (
        "63ef2dfbb121af0a459ca1983e938c6ff812f9f5b33ad53ba066c3b8d63f4f89",
        None,
        "runner blob a4b852da5c09 from 1a91ee2",
    ),
    (
        "52ec8fbdd6e242f3590a89e9b5454969c68871827de21ca536b0bc5a1706e5c0",
        None,
        "runner blob e1c6523d6ba4 from 5267fa6",
    ),
    (
        "a94e6c2c773ba02e36a7a7f7ba316ac16e1a757d7f75c95e4388c1c3a399d8b5",
        None,
        "runner blob 50e602b53397 from 3b240c6",
    ),
    (
        "41e12c6e4f372a90ded327cf32f0295260aa0c0f510af05695d0ccff16dff7ea",
        None,
        "runner blob e6873c2dd87f from 6e50fdc",
    ),
    (
        "84cef627cfba1c1144a257c96c6077eed4651fe96dfa5d11cf0c73fdafc3baf3",
        None,
        "runner blob 984c939efa7c from f58ae3d",
    ),
    (
        "412baa9059393daa2d2ee3b2d7e90e03f687afcde4069aca1daa7485753aa9e6",
        None,
        "runner blob 0dd208dd93cc from eda1ce6",
    ),
    (
        "43adf0374c9f1597b9e402e487230ec14cacec104525c950401522bef39edd45",
        None,
        "runner blob 7c03ab241f8a from a858fcc",
    ),
    (
        "951ee785cfac693c97b69ca913643a2fa0ad5136ac42ca4f7cca9aa09e9bd5e9",
        None,
        "runner blob 05b76a631f66 from 9bf0b77",
    ),
    (
        "3e076c3349a2763fe838d116f50cc598a48ed9922752fa169428518c8a6db554",
        None,
        "runner blob d340b26771a5 from 83f3e4a",
    ),
    (
        "a089fca5b58ee1e5e11a075a4592c5b43e665aabce80c969a07c225480daefca",
        "dffcb33b96074d861f4e5b0866ed58a69888fa42e730433c81058e8e0d07569c",
        "runner blob 31e449c2261b from 71b31b8, tool surface blob ecfe0fe4f712",
    ),
    (
        "c25b348b02285129208b69c8aedac1301bdff135e90f1028815d18fd49119c38",
        "dffcb33b96074d861f4e5b0866ed58a69888fa42e730433c81058e8e0d07569c",
        "accepted continuation pair from 281d102759c4d298d5f018d6b7db43c989bed182 at 3ac550f225028c2a5eda8ad4f4465e772e6ed085",
    ),
)
_V6_PRE_MOVE_IDENTITY_PAIRS = frozenset(
    (runner, tool_surface)
    for runner, tool_surface, _provenance in VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES
)
_REGULAR_BLOB_MODES = frozenset({"100644", "100755"})


def _v6_tree_entries(root: Path, tree: str) -> dict[str, tuple[str, str]] | None:
    """List the identity paths and moved roots of ``tree``: path to (mode, oid)."""

    listing = trusted_git_completed(root, [
        "ls-tree", "-r", "-z", tree, "--", _TRANSPORT_RUNNER_PATH,
        _TOOL_SURFACE_PATH, *_TRANSPORT_MOVED_SOURCE_ROOTS,
    ])
    if listing.returncode != 0:
        return None
    entries: dict[str, tuple[str, str]] = {}
    for record in listing.stdout.split(b"\0"):
        if record:
            meta, _, path = record.decode("utf-8", "surrogateescape").partition("\t")
            mode, kind, oid = meta.split(" ")
            entries[path] = (mode if kind == "blob" else kind, oid)
    return entries


def _v6_blob_sha256(
    root: Path, entries: Mapping[str, tuple[str, str]], path: str
) -> str | None:
    """Hash one regular blob; None when absent, "" when not a readable regular blob."""

    if path not in entries:
        return None
    mode, oid = entries[path]
    if mode not in _REGULAR_BLOB_MODES:
        return ""
    blob = trusted_git_completed(root, ["cat-file", "blob", oid])
    return hashlib.sha256(blob.stdout).hexdigest() if blob.returncode == 0 else ""


def validator_contract_v6_tree_errors(
    repo_root: Path, checkpoint_tree: Any
) -> list[str]:
    """Refuse a tree validator contract v6 cannot bind; ``[]`` means pre-move.

    V6 binds the runner but none of the files the transport moved into. A tree
    is accepted only when its runner and tool-surface blobs are a reviewed
    pre-move identity (``VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES``) and no
    moved source exists under ``scripts/cwo_core``. Source shape is never
    evidence: any blob not on the list is refused, as is a tree with any moved
    source, and each missing moved source is named. Reads Git objects only.
    """

    if not _is_commit(checkpoint_tree):
        return ["validator-contract-tree-invalid"]
    root = Path(repo_root).resolve()
    entries = _v6_tree_entries(root, checkpoint_tree)
    if entries is None:
        return ["validator-contract-tree-unreadable"]
    runner = _v6_blob_sha256(root, entries, _TRANSPORT_RUNNER_PATH)
    if not runner:
        return ["validator-contract-runner-unreadable"]
    tool_surface = _v6_blob_sha256(root, entries, _TOOL_SURFACE_PATH)
    # Every listed path under scripts/cwo_core is inside a moved-source root.
    present = [path for path in entries if path.startswith("scripts/cwo_core/")]
    errors: list[str] = []
    if (runner, tool_surface) not in _V6_PRE_MOVE_IDENTITY_PAIRS:
        errors.append("validator-contract-v6-pre-move-identity-unknown")
    if present:
        errors.append("validator-contract-v6-post-move-tree")
    if errors:
        errors.extend(
            f"validator-contract-v6-moved-source-missing:{path}"
            for path in TRANSPORT_MOVED_SOURCE_PATHS
            if path not in entries
        )
    return errors
