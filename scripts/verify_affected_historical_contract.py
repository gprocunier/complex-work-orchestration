"""Finite, test-only affected-contract compatibility evidence; never selects executable history.

Run under the caller's offline isolation boundary. This module is not a sandbox,
production admission path, or a generic replay engine. The manifest is reviewed
code of record, not an untrusted record or permission to execute a revision.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "tests/fixtures/affected_contract_compatibility/EXAMPLE-manifest.json"
SOURCE = "2432501363fdc60e6c56c4b4e4c9e108301244b5"
BASE = "66dfb6bcb01e18bbd8e8911ffd211e51cacf1cbe"
FIXTURE_PATH = "tests/fixtures/w20_affected_contract_w13/source-pins-2026-10-23.json"
FIXTURE_SHA256 = "8828c94c7041e4750f6f895e87828ce95e824e938d9cc54bc4c8404c26c13d28"
FIXTURE_SCHEMA = "cwo-portable-contract-inputs-v1"
FIXTURE_SCOPE = "bounded-neutral-fixture-only"
ARTIFACT_CAP = 1024 * 1024
HISTORY = {
    "b8f62514fb673d130b2054d3b4f6e307f5168d50": "149662af110fd1dbe71d371ec41cf810e45d9dbd",
    "298d21b8a430cc3c85d9bb72c7f2b877f9dac1e4": "fed494dd635e919f04ab8f9c1ac1b8ef8db688fa",
    "7473e3fe8d66528823478ce3c1cac6a2d481b844": "4f2fc2f70523c9182f7b422f3c0586af2e2ff4fe",
    "bf36658b5b76845ac662daebb842a80eb8923947": "2308918e032d101f3f660b67677a4655e7ddccc6",
    "d77dd2f824a75bf7c85b6dff9fb83333089d6ad0": "5dbec726d10e3ad77a3b71251fff2f70befdc8a1",
    "238ddfb22c52f5e753bc5b24ba1e24b30df7b347": "652646a2a09cfdd37e9bb24e166ebd2da61c3149",
    "ce3a13cafc4cdf5ce5e9bb203e3bb7ef6a858221": "e96dab5c1ebf8c101523e11225f7946f2ead61e6",
    "b335b9a884b2717f265825427d5d5fdfa1b825ce": "ff91d10f4e46cb48e8edc3f5564470ceaf17f049",
    "27d7eff047e4622b9a5640a7e9625802c95664ef": "6a94fdcbd1a26ff7fb01c8e6f836cda7792a9831",
    "a182076154f04c68bed7f66886c3a00fe408ab00": "9e8ebfbff0dc7a686799c572009ddabdf6e591db",
    "b5b3b3fea2ab466d6d35b7f30bab2a53cfeba87f": "4213c99ad65141f311bf9f0ceb11102c07fbf5f4",
    "87f0fc2cd191c8dd052eefe4df7783cea921c42b": "b95a937c8b3d36e62648aa6611cdf2f11de9a8d6",
    "9bd7e18659590c62ee42e0c8827558d46f6812d7": "1d5005ae7952693c6d0ab87316536bc2c30f32b6",
    "5194d81ac64500b1d47583369e47eabdb2e6fbec": "9e051866b3426f8f0e47a6d5dd9bf226f52e5279",
    "1cc6b5f7b2280bb10a44e139b69699be833be19b": "6cb5995622befb50fc27dec771757019170c41a6",
    "c63b431de37c273f1e8d654ddcf592ab4477b703": "5ec66f1c6f5311f5e2d4f02b63016c6a20f916a2",
    "9ff44b78c0655da5c3aae1280ca2679e0f5c4eff": "e3566f47a0830d7828a40842348302b48e3fd66a",
    "0143913b64b664dab06d4c03fe3176d74936be6b": "d45838f6193355ff342a81b99fc01179785588ce",
    "400ee2f83df6a315c44ec5107bf57355c167794c": "959937bbdabb8a4fdef99d09a9814cf6a14db55c",
    "eba853c99a13d1ee8629ac4dbb57db105ccd6d48": "017e76163cded728435cd5a88424db4ed145340f",
    "3d989d007204a8ff79983e254d941b73c145ec62": "3bb032011277e3912e89fdfa494a4029b5e268d8",
    "e861e03f6997cf8028947290e08ec693675b0041": "cbb678266b2571cd11517741c098254f20ca83b3",
    "1a09bd749cbb1a9d6186fc129a373bcf76acc8d3": "b796d4636dad9f8e52e689d1e294034a7c7bebae",
    "fd30c1f7bfc2513932f43f863201650a122df8e9": "6a764ab7dfccc51448687c571d2c02156d86606d",
    "14e4a7ab8221c8a71a148b5a6536c3bf3104d20a": "7aebb6b167d69b1d1e552a7c4aca11b012225c38",
    BASE: "37c62617e4ceb3c1631e703db5455070574ac322",
    SOURCE: "e38657afdd242b13eaf226b1bc3c6012d0c144f5",
}


class CompatibilityRefusal(ValueError):
    """Missing or drifted evidence cannot establish this checkpoint."""

    def __init__(self, message, *, evidence_scope=None):
        self.evidence_scope = evidence_scope
        prefix = evidence_scope + ": " if evidence_scope else ""
        super().__init__(prefix + message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(condition, message):
    if not condition:
        raise CompatibilityRefusal(message)


def git_bytes(root, spec, *, tree=False):
    from cwo_core.workspace_capture import trusted_git_completed

    result = trusted_git_completed(
        root, ["show", *(["--no-patch", "--format=%T"] if tree else []), spec], timeout=10)
    require(result.returncode == 0, "required approved history/artifact unavailable: " + spec)
    return result.stdout


def _regular_artifact(root, name, missing):
    """Use the existing bounded reader; refuse symlinks at every relative component."""
    from cwo_core.workspace_capture import BudgetExhausted, read_beneath

    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        kind, raw, info = read_beneath(descriptor, name, ARTIFACT_CAP)
    except BudgetExhausted as failure:
        raise CompatibilityRefusal("artifact byte limit exceeded: " + name) from failure
    finally:
        os.close(descriptor)
    require(kind == "file", missing)
    return raw, info


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def _json_float(value):
    number = float(value)
    require(math.isfinite(number), "nonfinite JSON number")
    return number


def _json_constant(value):
    raise CompatibilityRefusal("nonfinite JSON constant: " + value)


def _json_document(raw):
    # The byte cap bounds input size; this fixed depth cap also bounds canonicalization.
    document = json.loads(raw, object_pairs_hook=_json_object,
                          parse_float=_json_float, parse_constant=_json_constant)
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 32, "JSON depth limit exceeded")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
    require(type(document) is dict, "JSON object required")
    return document


def verify_files(root, files):
    for name, expected in files.items():
        raw, _ = _regular_artifact(root, name, "required dependency/artifact missing: " + name)
        require(digest(raw) == expected, "checkpoint dependency drift: " + name)


def verify_modes(root, modes):
    """Bind the current producer and original caller modes as well as bytes."""
    for name, expected in modes.items():
        _, info = _regular_artifact(root, name, "required mode-bound artifact missing: " + name)
        require(type(expected) is int and stat.S_IMODE(info.st_mode) == expected,
                "checkpoint dependency mode drift: " + name)


def verify_history(root, manifest):
    for revision, tree in HISTORY.items():
        observed = git_bytes(root, revision, tree=True)
        require(observed.strip() == tree.encode(),
                "approved source tree mismatch: " + revision)
    for revision, files in manifest["historical_files"].items():
        require(revision in HISTORY, "unapproved manifest history")
        for name, expected in files.items():
            require(digest(git_bytes(root, revision + ":" + name)) == expected,
                    "historical source artifact mismatch: " + name)


def verify_checkpoint(*, root=ROOT, source_revision=SOURCE, interpreter=None):
    """Strict original Git revision/tree/blob verification. Never falls back to fixtures."""
    require(source_revision == SOURCE, "unsupported evidence source revision; record selection forbidden")
    manifest, identity = _checkpoint_bindings(root, interpreter)
    verify_history(root, manifest)
    return dict(identity, source_revision=SOURCE)


def _checkpoint_bindings(root, interpreter):
    """The complete current byte/mode/policy envelope shared by both explicit APIs."""
    version = tuple(sys.version_info[:2]) if interpreter is None else interpreter
    require(version in ((3, 12), (3, 14)), "unsupported interpreter; expected Python 3.12 or 3.14")
    raw, _ = _regular_artifact(root, MANIFEST, "required scoped manifest missing")
    manifest = _json_document(raw)
    require(manifest["schema"] == "EXAMPLE-batch3e-affected-checkpoint-v1", "checkpoint schema mismatch")
    require(manifest["source_revision"] == SOURCE, "checkpoint source identity mismatch")
    require((manifest["source_tree"], manifest["source_base"], manifest["source_base_tree"])
            == (HISTORY[SOURCE], BASE, HISTORY[BASE]), "checkpoint source/base tree identity mismatch")
    policies = [*(root / "policy").glob("*.yaml")]
    host_config = root / "policy/workspace-host-state.json"
    if host_config.is_file():
        policies.append(host_config)
    require(sorted(str(p.relative_to(root)) for p in policies)
            == sorted(n for n in manifest["registered_current_resources"] if n.startswith("policy/")),
            "current policy roster drift")
    _current_rosters(manifest)
    verify_files(root, manifest["files"])
    verify_modes(root, manifest["current_file_modes"])
    return manifest, {"manifest_sha256": digest(raw),
            "dependency_count": len(manifest["files"]), "interpreter": sys.version,
            "executable_sha256": digest(Path(sys.executable).read_bytes())}


def _current_rosters(manifest):
    files = set(manifest["files"])
    require(files == set(manifest["current_file_modes"]), "current dependency/mode roster mismatch")
    required = {"tests/fixtures/affected_contract_compatibility/EXAMPLE-admission-v1.json",
                FIXTURE_PATH, "tests/historical_policy_fixtures.py",
                "scripts/verify_affected_historical_contract.py"}
    for key in ("roots", "registered_current_roots", "registered_current_consumers", "registered_current_resources"):
        required.update(manifest[key])
    require(required <= files, "required current dependency roster mismatch")


def _fixture_shape(evidence):
    fields = {"schema", "version", "effect_authority", "scope", "provider_v1_schema",
              "production_pre_move_identities", "production_pre_move_metadata_sha256",
              "production_generation11_sources", "sources", "archived_source_projection_sha256"}
    require(type(evidence) is dict and set(evidence) == fields, "public contract fixture fields mismatch")
    require(evidence["schema"] == FIXTURE_SCHEMA and type(evidence["version"]) is int
            and evidence["version"] == 1 and evidence["effect_authority"] is False,
            "public contract fixture header mismatch")
    require(evidence["scope"] == "Neutral offline inputs and public contract digests; no archived source or execution authority.",
            "public contract fixture scope mismatch")
    require(type(evidence["provider_v1_schema"]) is dict, "public contract provider schema type mismatch")
    sources = evidence["sources"]
    require(type(sources) is dict and set(sources) == {
        "runner_template", "surface", "generation11_runner", "generation11_boundary"},
        "public contract source roster mismatch")
    require(all(type(source) is str and source for source in sources.values()),
            "public contract source type mismatch")


def _sha256_string(value):
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _fixture_provenance(evidence):
    for field in ("production_pre_move_metadata_sha256", "archived_source_projection_sha256"):
        require(_sha256_string(evidence[field]), "public contract digest type mismatch: " + field)
    generation = evidence["production_generation11_sources"]
    require(type(generation) is dict and set(generation) == {"runner", "boundary"}
            and all(_sha256_string(value) for value in generation.values()),
            "public contract generation source mismatch")
    pairs = evidence["production_pre_move_identities"]
    require(type(pairs) is list and len(pairs) == 32, "public contract identity roster mismatch")
    for pair in pairs:
        require(type(pair) is list and len(pair) == 2 and _sha256_string(pair[0])
                and (pair[1] is None or _sha256_string(pair[1])), "public contract identity type mismatch")


def _fixture_evidence(root, manifest):
    binding = manifest["portable_contract_evidence"]
    expected = {"path": FIXTURE_PATH, "canonical_sha256": FIXTURE_SHA256,
                "schema": FIXTURE_SCHEMA, "version": 1, "effect_authority": False}
    require(type(binding) is dict and binding == expected and type(binding["version"]) is int
            and binding["effect_authority"] is False, "public contract evidence binding mismatch")
    raw, info = _regular_artifact(root, FIXTURE_PATH, "public contract fixture missing")
    require(stat.S_IMODE(info.st_mode) == 0o644, "public contract fixture mode mismatch")
    evidence = _json_document(raw)["portable_contract_evidence"]
    _fixture_shape(evidence)
    _fixture_provenance(evidence)
    require(digest(canonical(evidence)) == FIXTURE_SHA256, "public contract fixture digest mismatch")
    projection = digest(canonical(manifest["historical_files"]))
    require(projection == evidence["archived_source_projection_sha256"], "archived source projection mismatch")
    return {"schema": "cwo-fixture-contract-verification-v1", "evidence_scope": FIXTURE_SCOPE,
            "fixture_evidence_verified": True, "historical_artifacts_verified": False,
            "historical_verification": "not-performed-fixture-only",
            "historical_semantic_acceptance": False, "effect_authority": False, "current_authority": False,
            "fixture_evidence_sha256": FIXTURE_SHA256, "fixture_artifact_sha256": digest(raw),
            "archived_metadata": {"reverified": False, "historical_files_sha256": projection}}


def verify_fixture_evidence(root, manifest):
    """Verify only the independently pinned neutral object and archived table integrity."""
    try:
        return _fixture_evidence(root, manifest)
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as failure:
        raise CompatibilityRefusal(str(failure), evidence_scope=FIXTURE_SCOPE) from failure


def verify_fixture_checkpoint(*, root=ROOT, interpreter=None):
    """Tests-only fixture selection plus full current bindings and real offline observations.

    The process entry remains strict. This API never reads original Git artifacts
    or accepts a revision selector, and supplies no historical semantic acceptance.
    """
    try:
        manifest, identity = _checkpoint_bindings(root, interpreter)
        report = _fixture_evidence(root, manifest)
        observations = {"surface": surface_observations(), "admission": admission_observations(),
                        "registered_consumers": registered_consumer_observations()}
        require(observations["registered_consumers"]["current_roots"] == manifest["registered_current_roots"],
                "current consumer root roster drift")
        return dict(report, **identity, current_dependency_bindings_verified=True,
                    behavior_observations=observations, loaded_python_files=runtime_identity(manifest=manifest))
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as failure:
        raise CompatibilityRefusal(str(failure), evidence_scope=FIXTURE_SCOPE) from failure


def surface_observations():
    # Reuse the genuine versioned fixtures and original preserved verifiers.
    from tests import test_w20_affected_contract_w13 as original

    observed = original.tool_surface_section()
    expected = original.load_golden()["sections"]["tool_surface"]
    require(observed == expected, "preserved surface golden/rejection outcome drift")
    return observed


def admission_observations():
    from tests import test_local_admission_preparation as original

    world = original.LocalAdmissionTest()
    world.setUp()
    try:
        cases = _admission_cases(world, original)
        stored = json.loads((ROOT / "tests/fixtures/affected_contract_compatibility/EXAMPLE-admission-v1.json").read_bytes())
        observed = original.reconciliation.prepare(stored["input"])
        require(observed == stored["outcome"], "retained adapter snapshot outcome drift")
        cases["retained-adapter-v1-replay"] = _case(stored["input"], observed)
        return cases
    finally:
        world.doCleanups()


def _admission_cases(world, original):
    adapter, consumer = original.adapter, original.reconciliation
    attempt = world.consume_node("plan")
    payload = world.reconciliation_input({"plan": attempt["attempt_id"]})
    result = consumer.prepare(payload)
    require(result["status"] == "within-declared-limits", "adapter reconciliation control failed")
    cases = {"adapter-produced-v1": _case(payload, result)}
    from copy import deepcopy

    for label in ("malformed", "tampered-charge", "mismatched-scope", "unsupported-ledger-version"):
        changed = deepcopy(payload)
        _mutate_snapshot(changed, label)
        outcome = consumer.prepare(changed)
        require(outcome["status"] == "invalid", "reconciliation must refuse " + label)
        cases[label] = _case(changed, outcome)
    # The real admission consumer must refuse a planner diagnostic as a receipt.
    calls = []
    before = world.disk_bytes()
    try:
        adapter.invoke_offline(world.plan, world.route, "plan", ledger=world.store,
                               effect=lambda *args: calls.append(args))
    except adapter.AdmissionError as failure:
        refusal = str(failure)
    else:
        raise CompatibilityRefusal("planner diagnostic became admission authority")
    require(not calls and world.disk_bytes() == before, "refused diagnostic caused an effect/write")
    cases["diagnostic-as-admission"] = {"input_sha256": digest(canonical(world.plan)),
        "outcome": refusal, "selected_effects": len(calls), "ledger_bytes_unchanged": True}
    return cases


def _case(payload, result):
    return {"input_sha256": digest(canonical(payload)), "status": result["status"],
            "outcome_sha256": digest(canonical(result)),
            "availability": {name: result[name] for name in (
                "operative", "qualified", "effect_authority")}}


def _mutate_snapshot(payload, label):
    snapshot = payload["ledger_snapshot"]
    if label == "malformed":
        payload.pop("node_attempts")
    elif label == "tampered-charge":
        next(iter(snapshot["attempts"].values()))["charge"]["tokens"] += 1
    elif label == "mismatched-scope":
        payload["expected"]["scope_sha256"] = "0" * 64
    else:
        snapshot["version"] = 2  # Unsupported input, never a claim of a retired v2 ledger.


def runtime_identity(*, manifest=None):
    """Check actual loaded local sources against the scoped dependency inventory."""
    files = {}
    for module in tuple(sys.modules.values()):
        raw = getattr(module, "__file__", None)
        if not raw:
            continue
        path = Path(raw)
        if path.is_relative_to(ROOT) and path.suffix == ".py" and path.is_file():
            name = str(path.relative_to(ROOT))
            raw, _ = _regular_artifact(ROOT, name, "loaded dependency missing: " + name)
            files[name] = digest(raw)
    if manifest is None:
        raw, _ = _regular_artifact(ROOT, MANIFEST, "required scoped manifest missing")
        manifest = _json_document(raw)
    expected = manifest["files"]
    own_path = "scripts/verify_affected_historical_contract.py"
    for name, observed in files.items():
        require(expected.get(name) == observed, "loaded dependency missing/drifted: " + name)
    return {"loaded_local_paths": sorted(files), "local_bindings_sha256": digest(canonical(files)),
            "runner_sha256": files[own_path]}


def registered_consumer_observations():
    """Observe fixed current imports and hostless refusals; never issue a host."""
    import inspect
    import registered_app_server_transport as transport
    import registered_finite_input as finite_input
    import registered_finite_tool_calls as finite_tools
    import registered_n1_factory as factory
    import registered_n1_workflow as workflow
    import registered_native_pool_host as pool
    import registered_native_pool_retry as retry
    import registered_native_pool_client as client
    import run_admitted_native_pool_transaction as launcher

    require(factory.RegisteredAppServer is transport.RegisteredAppServer,
            "registered factory transport identity drift")
    require(pool.W is workflow and retry.P is pool,
            "registered workflow/pool/retry identity drift")
    require(inspect.signature(pool.PoolConfiguration).parameters["enabled"].default is False,
            "registered pool must remain disabled by default")
    request = {"version": 1, "mode": "validate-only", "pool_id": "EXAMPLE-pool",
               "workers": ["EXAMPLE-worker"]}
    observed = client.submit(request)
    require(observed == {"structurally_valid": True, "authority_validated": False,
                         "model_calls": 0, "dispatch_authorized": False},
            "hostless structural validation became authority")
    try:
        client.submit(dict(request, mode="execute"))
    except ValueError as failure:
        refusal = str(failure)
    else:
        raise CompatibilityRefusal("hostless execution accepted")
    require(refusal == "registered-pool-host-required", "hostless refusal drift")
    modules = (finite_input, finite_tools, factory, workflow, pool, retry, client, launcher)
    return {"current_roots": sorted(str(Path(module.__file__).relative_to(ROOT)) for module in modules),
            "hostless_validation": observed, "hostless_execution_refusal": refusal,
            "current_authority": False}


def main():
    if sys.argv[1:]:
        print(json.dumps({"status": "refused", "evidence_scope": "strict-historical-artifacts",
                          "reason": "no execution selectors are accepted"}))
        return 2
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        identity = verify_checkpoint()
        report = {"identity": identity, "surface": surface_observations(),
                  "admission": admission_observations(), "current_authority": False,
                  "registered_consumers": registered_consumer_observations(),
                  "loaded_python_files": runtime_identity()}
    except (CompatibilityRefusal, OSError, ValueError) as failure:
        print(json.dumps({"status": "refused", "evidence_scope": "strict-historical-artifacts",
                          "reason": str(failure)}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
