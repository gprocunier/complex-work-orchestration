from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from codex_tool_surface import (
    DIRECT_TOOL_TRANSPORT,
    EXACT_OPERATIVE_TOOLS,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
    build_lockdown_config,
    build_surface_proof,
    _model_catalog,
    thread_start_enforcement_params,
    validate_surface_proof,
)


def synthetic_empty_endpoint_inventory(thread_id="synthetic-only", pid=123, epoch="e" * 64):
    """Test-only status-RPC transcript, explicitly not a host observation."""
    return {"source": "app-server-thread-mcp-inventory-v1", "version": 1,
        "thread_id": thread_id, "pid": pid, "connection_epoch_sha256": epoch,
        "notification_generation": 0, "pages": [{
            "request": {"threadId": thread_id, "detail": "full", "limit": 100, "cursor": None},
            "response": {"data": [], "nextCursor": None}}]}


def bound_fixture_proof(captured, **kwargs):
    """Synthetic controller observation; never live qualification evidence."""
    import codex_tool_surface as surface
    binding = surface.prepare_capture_binding(**kwargs)
    tools = binding['requested_tools']
    observed = {'model': binding['requested_model'], 'modelProvider': 'cwo-loopback-probe',
        'approvalPolicy': 'never', 'networkAccess': False,
        'sandbox': 'readOnly' if not surface.tools_are_mutable(tools) else 'workspaceWrite',
        'allowProviderModelFallback': False, 'dynamicTools': [],
        'lockdown_config_sha256': binding['lockdown_config_sha256']}
    process = surface.bind_capture_process(binding, captured, executable=binding['codex_binary'],
        codex_home=binding['codex_home'], pid=123, thread_id='synthetic-only', effective_thread=observed,
        endpoint_inventory={"before": synthetic_empty_endpoint_inventory(), "after": synthetic_empty_endpoint_inventory()})
    return surface.build_surface_proof(captured, **kwargs, capture_binding=binding, process_binding=process)


class CodexToolSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        (self.home / "config.toml").write_text(
            "[mcp_servers.alpha]\ncommand = 'false'\n",
            encoding="utf-8",
        )
        (self.home / "models_cache.json").write_text(
            json.dumps(
                {
                    "models": [
                        {
                            "slug": "gpt-5.3-codex-spark",
                            "shell_type": "unified_exec",
                            "apply_patch_tool_type": "freeform",
                            "experimental_supported_tools": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.binary = self.home / "codex"
        self.binary.write_bytes(b"codex-test-binary")
        self.captured = {
            "model": "gpt-5.3-codex-spark",
            "tools": [{"name": name} for name in EXACT_OPERATIVE_TOOLS],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _proof(self) -> dict:
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            return bound_fixture_proof(
                self.captured,
                codex_home=self.home,
                requested_model="gpt-5.3-codex-spark",
            )

    def test_lockdown_disables_optional_tool_sources_and_all_mcp_servers(self) -> None:
        config = build_lockdown_config(
            self.home,
            requested_model="gpt-5.3-codex-spark",
        )
        self.assertEqual(config["web_search"], "disabled")
        self.assertEqual(config["agents"], {"enabled": False})
        self.assertTrue(config["features"])
        self.assertTrue(all(value is False for value in config["features"].values()))
        self.assertEqual(config["mcp_servers"], {"alpha": {"enabled": False}})

    def test_exact_probe_proof_revalidates_and_builds_thread_inputs(self) -> None:
        proof = self._proof()
        self.assertEqual(proof["tool_transport"], DIRECT_TOOL_TRANSPORT)
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            self.assertEqual(
                validate_surface_proof(
                    proof,
                    requested_model="gpt-5.3-codex-spark",
                    permitted_tools=list(EXACT_OPERATIVE_TOOLS),
                ),
                [],
            )
            params = thread_start_enforcement_params(
                proof,
                requested_model="gpt-5.3-codex-spark",
                permitted_tools=list(EXACT_OPERATIVE_TOOLS),
            )
        self.assertEqual(params["dynamicTools"], [])
        self.assertEqual(params["config"], proof["lockdown_config"])

    def test_model_catalog_read_retries_transient_atomic_refresh_window(self) -> None:
        valid = (self.home / "models_cache.json").read_bytes()
        with (
            mock.patch.object(Path, "read_bytes", side_effect=[b"{", valid]),
            mock.patch("codex_tool_surface.time.sleep") as sleep,
        ):
            path, _catalog_sha256, entry_sha256 = _model_catalog(
                self.home,
                "gpt-5.3-codex-spark",
            )
        self.assertEqual(path, (self.home / "models_cache.json").resolve())
        self.assertEqual(len(entry_sha256), 64)
        sleep.assert_called_once_with(0.05)

    def test_extra_captured_tool_is_rejected(self) -> None:
        captured = deepcopy(self.captured)
        captured["tools"].append({"name": "spawn_agent"})
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "tool-surface-mismatch"):
                build_surface_proof(
                    captured,
                    codex_home=self.home,
                    requested_model="gpt-5.3-codex-spark",
                )

    def test_namespaced_exec_surface_projects_only_declared_nested_tools(self) -> None:
        captured = {
            "model": "gpt-5.3-codex-spark",
            "input": [
                {
                    "type": "additional_tools",
                    "role": "developer",
                    "tools": [
                        {
                            "type": "namespace",
                            "name": "functions",
                            "tools": [
                                {
                                    "type": "custom",
                                    "name": "exec",
                                    "description": "\n".join(
                                        f"### `{name}`\ndeclare const tools: {{ {name}: unknown }};"
                                        for name in EXACT_OPERATIVE_TOOLS
                                    ),
                                },
                                {
                                    "type": "function",
                                    "name": "wait",
                                    "description": "Wait for a yielded exec cell.",
                                },
                            ],
                        }
                    ],
                }
            ],
        }
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            proof = bound_fixture_proof(
                captured,
                codex_home=self.home,
                requested_model="gpt-5.3-codex-spark",
            )
        self.assertEqual(
            proof["observed_tools"],
            sorted(EXACT_OPERATIVE_TOOLS),
        )
        self.assertEqual(
            proof["tool_transport"],
            NAMESPACED_EXEC_TOOL_TRANSPORT,
        )

        expanded = deepcopy(captured)
        expanded["input"][0]["tools"][0]["tools"][0]["description"] += (
            "\n### `spawn_agent`\ndeclare const tools: { spawn_agent: unknown };"
        )
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "tool-surface-mismatch"):
                build_surface_proof(
                    expanded,
                    codex_home=self.home,
                    requested_model="gpt-5.3-codex-spark",
                )

    def test_user_config_drift_invalidates_proof(self) -> None:
        proof = self._proof()
        (self.home / "config.toml").write_text(
            "[mcp_servers.beta]\ncommand = 'false'\n",
            encoding="utf-8",
        )
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            errors = validate_surface_proof(
                proof,
                requested_model="gpt-5.3-codex-spark",
                permitted_tools=list(EXACT_OPERATIVE_TOOLS),
            )
        self.assertIn("codex-tool-surface-lockdown-config-drift", errors)

    def test_unrelated_derived_model_cache_refresh_does_not_invalidate_proof(self) -> None:
        proof = self._proof()
        catalog = json.loads((self.home / "models_cache.json").read_text())
        catalog["fetched_at"] = "later"
        (self.home / "models_cache.json").write_text(json.dumps(catalog))
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            errors = validate_surface_proof(
                proof,
                requested_model="gpt-5.3-codex-spark",
                permitted_tools=list(EXACT_OPERATIVE_TOOLS),
            )
        self.assertEqual(errors, [])

    def test_selected_model_entry_drift_invalidates_proof(self) -> None:
        proof = self._proof()
        catalog = json.loads((self.home / "models_cache.json").read_text())
        catalog["models"][0]["new_metadata"] = True
        (self.home / "models_cache.json").write_text(json.dumps(catalog))
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            errors = validate_surface_proof(
                proof,
                requested_model="gpt-5.3-codex-spark",
                permitted_tools=list(EXACT_OPERATIVE_TOOLS),
            )
        self.assertIn("codex-tool-surface-model-entry-drift", errors)

    def test_hash_tampering_is_rejected(self) -> None:
        proof = self._proof()
        proof["captured_request_sha256"] = hashlib.sha256(b"tampered").hexdigest()
        with (
            mock.patch(
                "codex_tool_surface._codex_binary",
                return_value=self.binary,
            ),
            mock.patch(
                "codex_tool_surface._codex_version",
                return_value="test-version",
            ),
        ):
            errors = validate_surface_proof(
                proof,
                requested_model="gpt-5.3-codex-spark",
                permitted_tools=list(EXACT_OPERATIVE_TOOLS),
            )
        self.assertIn("codex-tool-surface-proof-hash-mismatch", errors)

# Synthetic host fixtures; never live qualification evidence.
class ToolProfileProofTests(unittest.TestCase):
    setUp = CodexToolSurfaceTests.setUp
    tearDown = CodexToolSurfaceTests.tearDown

    def proof(self, tools=None, namespaced=False):
        import codex_tool_surface as surface
        tools = list(EXACT_OPERATIVE_TOOLS) if tools is None else tools
        capture = {"model": self.captured["model"], "tools": [{"name": x} for x in tools]}
        if namespaced:
            capture.pop("tools")
            capture["input"] = [{"type": "additional_tools", "tools": [{"type": "namespace", "name": "functions", "tools": [
                {"type": "custom", "name": "exec", "description": "\n".join(f"### `{x}`" for x in tools)},
                {"type": "function", "name": "wait"}]}]}]
        projection = None
        if not surface.tools_are_mutable(tools):
            projection = self.home / 'private-projection.json'
            if not projection.exists():
                surface.prepare_read_only_catalog(self.home, requested_model=self.captured['model'], output=projection)
        with mock.patch.object(surface, '_codex_binary', return_value=self.binary), mock.patch.object(surface, '_codex_version', return_value='test-version'):
            return bound_fixture_proof(capture, codex_home=self.home, requested_model=self.captured['model'], permitted_tools=tools, catalog_projection=projection)

    def validate(self, proof, tools=None):
        import codex_tool_surface as surface
        with mock.patch.object(surface, '_codex_binary', return_value=self.binary), mock.patch.object(surface, '_codex_version', return_value='test-version'):
            return surface.validate_surface_proof(proof, requested_model=self.captured['model'], permitted_tools=list(EXACT_OPERATIVE_TOOLS) if tools is None else tools)

    def test_exact_profiles_both_transports_and_legacy(self):
        import codex_tool_surface as surface
        for tools in [list(EXACT_OPERATIVE_TOOLS), list(surface.EXACT_READ_ONLY_TOOLS)]:
            for namespaced in [False, True]:
                with self.subTest(tools=tools,namespaced=namespaced):
                    proof=self.proof(tools,namespaced)
                    self.assertEqual(self.validate(proof,tools), [])
                    self.assertEqual(proof['observed_tools'],tools)
        legacy=self.proof();legacy['version']=2
        for key in surface.PROFILE_PROOF_FIELDS | surface.CAPTURE_PROOF_FIELDS | surface.CURRENT_EFFECT_FIELDS:legacy.pop(key)
        legacy['proof_sha256']=surface.canonical_sha256({k:v for k,v in legacy.items() if k!='proof_sha256'})
        self.assertEqual(self.validate(legacy),[])
        self.assertTrue(self.validate(legacy,list(surface.EXACT_READ_ONLY_TOOLS)))

    def test_malformed_permitted_tools_are_controlled(self):
        import codex_tool_surface as surface
        proof=self.proof()
        for bad in [None,{},[],[{}],['exec_command',{}],[[],{}],['exec_command',False],'exec_command',17]:
            with self.subTest(bad=bad):
                errors=surface.validate_surface_proof(proof,requested_model=self.captured['model'],permitted_tools=bad)
                self.assertTrue(errors)
                with self.assertRaises(surface.CodexToolSurfaceError):surface.normalized_tools(bad)

    def test_malformed_fields_do_not_escape(self):
        proof=self.proof()
        for field in ['tool_transport','startup_config','requested_tools','observed_tools','requested_model','codex_home','lockdown_config','version']:
            for bad in [None,{},[],[{}],True,17]:
                if field == 'startup_config' and bad == {}:
                    continue  # Empty startup overrides are valid for the mutating profile.
                with self.subTest(field=field,bad=bad):
                    value=deepcopy(proof);value[field]=bad
                    self.assertTrue(self.validate(value))
        value=deepcopy(proof);value[4]='unknown';self.assertTrue(self.validate(value))

    def test_three_tool_capture_cannot_mint_two_tool_proof(self):
        import codex_tool_surface as surface
        for names in [list(EXACT_OPERATIVE_TOOLS),['exec_command'],['exec_command','write_stdin','spawn_agent']]:
            with self.subTest(names=names),self.assertRaisesRegex(ValueError,'tool-surface-mismatch'):
                surface.build_surface_proof({'model':self.captured['model'],'tools':[{'name':n} for n in names]},codex_home=self.home,requested_model=self.captured['model'],permitted_tools=list(surface.EXACT_READ_ONLY_TOOLS))
        with self.assertRaisesRegex(ValueError,'model-mismatch'):
            surface.build_surface_proof(dict(self.captured,model='wrong'),codex_home=self.home,requested_model=self.captured['model'])

    def test_projection_selected_metadata_hash_and_binary_drift(self):
        import codex_tool_surface as surface
        proof=self.proof(list(surface.EXACT_READ_ONLY_TOOLS));path=Path(proof['startup_config']['model_catalog_json'])
        data=path.read_bytes();path.write_bytes(data+b' ')
        self.assertIn('codex-tool-surface-catalog-projection-drift',self.validate(proof,list(surface.EXACT_READ_ONLY_TOOLS)))
        path.write_bytes(data);value=json.loads(data);value['models'][0]['shell_type']='wrong';path.write_text(json.dumps(value))
        self.assertTrue(self.validate(proof,list(surface.EXACT_READ_ONLY_TOOLS)))
        path.write_bytes(data);self.binary.write_bytes(b'changed')
        self.assertIn('codex-tool-surface-binary-drift',self.validate(proof,list(surface.EXACT_READ_ONLY_TOOLS)))

    def test_projection_no_overwrite_and_no_real_catalog_mutation(self):
        import codex_tool_surface as surface
        cache=self.home/'models_cache.json';before=cache.read_bytes()
        with self.assertRaises(surface.CodexToolSurfaceError):
            surface.prepare_read_only_catalog(self.home,requested_model=self.captured['model'],output=cache)
        self.assertEqual(cache.read_bytes(),before)
        self.proof(list(surface.EXACT_READ_ONLY_TOOLS))
        with self.assertRaises(FileExistsError):surface.prepare_read_only_catalog(self.home,requested_model=self.captured['model'],output=self.home/'private-projection.json')
        self.assertEqual(cache.read_bytes(),before)

    def test_tool_instructions_only_advertise_validated_profile(self):
        import codex_tool_surface as surface
        for transport in [DIRECT_TOOL_TRANSPORT,NAMESPACED_EXEC_TOOL_TRANSPORT]:
            text=surface.tool_transport_instructions(list(surface.EXACT_READ_ONLY_TOOLS),transport)
            self.assertNotIn('apply_patch',text)
            self.assertIn('exec_command',text);self.assertIn('write_stdin',text)
        for bad in [None,{},[],17]:
            with self.assertRaises(surface.CodexToolSurfaceError):surface.tool_transport_instructions(['exec_command'],bad)


class CaptureProvenanceTests(ToolProfileProofTests):
    def test_fresh_proof_requires_precapture_and_process_bindings(self):
        import codex_tool_surface as surface
        with self.assertRaisesRegex(ValueError, 'capture-binding-invalid'):
            surface.build_surface_proof(self.captured, codex_home=self.home, requested_model=self.captured['model'])
        proof=self.proof()
        for version in [2,3]:
            historical=deepcopy(proof);historical['version']=version
            for key in surface.CAPTURE_PROOF_FIELDS | surface.CURRENT_EFFECT_FIELDS:historical.pop(key)
            if version==2:
                for key in surface.PROFILE_PROOF_FIELDS:historical.pop(key)
            historical['proof_sha256']=surface.canonical_sha256({k:v for k,v in historical.items() if k!='proof_sha256'})
            with mock.patch.object(surface,'_codex_binary',return_value=self.binary),mock.patch.object(surface,'_codex_version',return_value='test-version'):
                self.assertEqual(surface.validate_surface_proof(historical,requested_model=self.captured['model'],permitted_tools=list(EXACT_OPERATIVE_TOOLS)),[])
                with self.assertRaisesRegex(ValueError,'historical-proof-not-dispatch-authority'):
                    surface.require_surface_proof(historical,requested_model=self.captured['model'],permitted_tools=list(EXACT_OPERATIVE_TOOLS))

    def test_prepost_drift_cannot_be_stamped_onto_old_capture(self):
        import codex_tool_surface as surface
        for change in ['binary','config','selected','projection','wrong-home','tampered-process']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as td:
                home=Path(td);binary=home/'codex';binary.write_bytes(b'binary')
                (home/'config.toml').write_text('')
                catalog=json.loads((self.home/'models_cache.json').read_text());(home/'models_cache.json').write_text(json.dumps(catalog))
                projection=home/'projection.json';surface.prepare_read_only_catalog(home,requested_model=self.captured['model'],output=projection)
                capture={'model':self.captured['model'],'tools':[{'name':n} for n in surface.EXACT_READ_ONLY_TOOLS]}
                with mock.patch.object(surface,'_codex_binary',return_value=binary),mock.patch.object(surface,'_codex_version',return_value='test-version'):
                    proof=bound_fixture_proof(capture,codex_home=home,requested_model=self.captured['model'],permitted_tools=list(surface.EXACT_READ_ONLY_TOOLS),catalog_projection=projection)
                    if change=='binary':binary.write_bytes(b'new')
                    elif change=='config':(home/'config.toml').write_text('[mcp_servers.new]\ncommand="false"\n')
                    elif change=='selected':
                        catalog['models'][0]['new-field']=True;(home/'models_cache.json').write_text(json.dumps(catalog))
                    elif change=='projection':projection.write_bytes(projection.read_bytes()+b' ')
                    elif change=='wrong-home':proof['process_binding']['codex_home']=str(home/'other')
                    else:proof['process_binding']['captured_request_sha256']='0'*64
                    with self.assertRaises(surface.CodexToolSurfaceError):
                        surface.build_surface_proof(capture,codex_home=home,requested_model=self.captured['model'],permitted_tools=list(surface.EXACT_READ_ONLY_TOOLS),catalog_projection=projection,capture_binding=proof['capture_binding'],process_binding=proof['process_binding'])

    def test_projection_uses_one_valid_snapshot(self):
        import codex_tool_surface as surface
        path=self.home/'models_cache.json';raw=path.read_bytes();original=Path.read_bytes;count=0
        def read(p):
            nonlocal count
            if p==path:
                count+=1
                return raw if count==1 else b'{'
            return original(p)
        with mock.patch.object(Path,'read_bytes',read):
            target=surface.prepare_read_only_catalog(self.home,requested_model=self.captured['model'],output=self.home/'single.json')
        self.assertEqual(count,1);self.assertIsNone(json.loads(target.read_text())['models'][0]['apply_patch_tool_type'])

    def test_catalog_wrong_types_duplicates_and_invalid_json_controlled(self):
        import codex_tool_surface as surface
        good=json.loads((self.home/'models_cache.json').read_text())['models'][0]
        values=[None,[],{}, {'models':{}},{'models':[None,good]}, {'models':['bad',good]}, {'models':[good,good]}, {'models':[{'slug':[]},good]}]
        for i,value in enumerate(values):
            (self.home/'models_cache.json').write_text(json.dumps(value))
            with self.subTest(value=value),self.assertRaises(surface.CodexToolSurfaceError):
                surface.prepare_read_only_catalog(self.home,requested_model=self.captured['model'],output=self.home/f'bad{i}.json')
        (self.home/'models_cache.json').write_text('{')
        with mock.patch.object(surface.time,'sleep'),self.assertRaises(surface.CodexToolSurfaceError):
            surface.prepare_read_only_catalog(self.home,requested_model=self.captured['model'],output=self.home/'bad-json.json')

    def test_capture_binding_malformed_and_unrelated_refresh(self):
        import codex_tool_surface as surface
        proof=self.proof()
        with mock.patch.object(surface,'_codex_binary',return_value=self.binary),mock.patch.object(surface,'_codex_version',return_value='test-version'):
            binding=proof['capture_binding'];before=deepcopy(binding)
            cache=json.loads((self.home/'models_cache.json').read_text());cache['fetched_at']='later';(self.home/'models_cache.json').write_text(json.dumps(cache))
            (self.home/'config.toml').write_text((self.home/'config.toml').read_text()+'\nmodel_reasoning_effort="high"\n')
            self.assertEqual(surface.require_capture_binding(binding),before)
            for bad in [None,[],{}, {'startup_config':[]}]:
                with self.subTest(bad=bad),self.assertRaises(surface.CodexToolSurfaceError):surface.require_capture_binding(bad)


class StrictJsonProofTests(unittest.TestCase):
    """Synthetic typed tampering; outer resealing is deliberately not trusted."""

    setUp = CodexToolSurfaceTests.setUp
    tearDown = CodexToolSurfaceTests.tearDown
    proof = ToolProfileProofTests.proof
    validate = ToolProfileProofTests.validate

    def reseal(self, proof, *, binding=False, inner=False):
        import codex_tool_surface as surface
        if inner:
            for payload in (proof, proof['capture_binding']):
                payload['lockdown_config_sha256'] = surface.canonical_sha256(payload['lockdown_config'])
            proof['process_binding']['effective_thread']['lockdown_config_sha256'] = proof['lockdown_config_sha256']
        if binding:
            value = proof['capture_binding']
            value['binding_sha256'] = surface.canonical_sha256({k: v for k, v in value.items() if k != 'binding_sha256'})
            proof['process_binding']['capture_binding_sha256'] = value['binding_sha256']
        proof['proof_sha256'] = surface.canonical_sha256({k: v for k, v in proof.items() if k != 'proof_sha256'})
        return proof

    def test_effective_thread_exact_types_and_closed_shape(self):
        baseline = self.proof()
        for field in ('networkAccess', 'allowProviderModelFallback'):
            for bad in (0, 1, 0.0, 1.0, 'false', None, [], {}, True):
                with self.subTest(field=field, bad=bad):
                    proof = deepcopy(baseline)
                    proof['process_binding']['effective_thread'][field] = bad
                    self.assertTrue(self.validate(self.reseal(proof)))
        for change in ('missing', 'extra', 'list', 'null'):
            proof = deepcopy(baseline)
            thread = proof['process_binding']['effective_thread']
            if change == 'missing': del thread['networkAccess']
            elif change == 'extra': thread['unbound'] = False
            else: proof['process_binding']['effective_thread'] = [] if change == 'list' else None
            with self.subTest(change=change): self.assertTrue(self.validate(self.reseal(proof)))

    def test_nested_config_types_rejected_even_with_consistent_resealed_hashes(self):
        baseline = self.proof()
        paths = [('features', 'apps'), ('agents', 'enabled'),
                 ('tools', 'update_plan', 'enabled'), ('mcp_servers', 'alpha', 'enabled')]
        for path in paths:
            for bad in (0, 1, 0.0, 'false', None, [], {}, True):
                proof = deepcopy(baseline)
                for owner in (proof, proof['capture_binding']):
                    value = owner['lockdown_config']
                    for key in path[:-1]: value = value[key]
                    value[path[-1]] = bad
                with self.subTest(path=path, bad=bad):
                    self.assertTrue(self.validate(self.reseal(proof, binding=True, inner=True)))
        for field in ('features', 'agents', 'tools', 'mcp_servers'):
            for action in ('missing', 'extra', 'array'):
                proof = deepcopy(baseline)
                for owner in (proof, proof['capture_binding']):
                    if action == 'missing': del owner['lockdown_config'][field]
                    elif action == 'extra': owner['lockdown_config'][field]['extra'] = False
                    else: owner['lockdown_config'][field] = []
                with self.subTest(field=field, action=action):
                    self.assertTrue(self.validate(self.reseal(proof, binding=True, inner=True)))

    def test_embedded_hash_must_match_payload_before_environment_lookup(self):
        import codex_tool_surface as surface
        proof = self.proof()
        for owner in (proof, proof['capture_binding']):
            owner['lockdown_config']['features']['apps'] = 0
        self.reseal(proof, binding=True)
        with mock.patch.object(surface, '_codex_binary') as binary:
            self.assertIn('codex-tool-surface-lockdown-payload-hash-mismatch',
                          surface.validate_surface_proof(proof, requested_model=self.captured['model'],
                                                         permitted_tools=list(EXACT_OPERATIVE_TOOLS)))
            binary.assert_not_called()
        with mock.patch.object(surface, 'prepare_capture_binding') as prepare:
            with self.assertRaises(surface.CodexToolSurfaceError):
                surface.require_capture_binding(proof['capture_binding'])
            prepare.assert_not_called()

    def test_tampered_binding_cannot_reach_worker_process_or_thread_consumers(self):
        import codex_tool_surface as surface
        import run_native_pool_live_canaries as live
        proof = self.proof()
        proof['process_binding']['effective_thread']['networkAccess'] = 0
        self.reseal(proof)
        with mock.patch.object(surface, '_codex_binary', return_value=self.binary), \
                mock.patch.object(surface, '_codex_version', return_value='test-version'), \
                mock.patch.object(live.subprocess, 'Popen') as popen:
            with self.assertRaises(live.AppServerError):
                live.AppServer(requested_model=self.captured['model'], tool_surface_proof=proof)
            popen.assert_not_called()
            server = object.__new__(live.AppServer)
            server._tool_surface_proof = proof
            server.requested_model = self.captured['model']
            for consumer in (server.capability_adapter_version, server.operative_tool_transport):
                with self.assertRaises(live.AppServerError): consumer()
            with self.assertRaises(surface.CodexToolSurfaceError):
                surface.thread_start_enforcement_params(proof, requested_model=self.captured['model'],
                                                        permitted_tools=list(EXACT_OPERATIVE_TOOLS))

    def test_strict_json_comparison_never_coerces_scalar_types(self):
        import codex_tool_surface as surface
        for left, right in [(0, False), (1, True), (0.0, 0), (1.0, 1), ([], {}), (None, False)]:
            self.assertFalse(surface._same_json({'x': [left]}, {'x': [right]}))
        self.assertTrue(surface._same_json({'x': [False, 0, 0.0, None]}, {'x': [False, 0, 0.0, None]}))
