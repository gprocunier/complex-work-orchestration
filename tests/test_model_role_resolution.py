from __future__ import annotations

import unittest

from cwo_core import model_identities as identities


CYBER_MODEL = "gpt-6-sol"
CYBER_ROLE = {
    "model": CYBER_MODEL,
    "required_access_program": "daybreakBlue",
    "codex_config": {"daybreak": True},
}


def catalog(*models: str, cyber_access: tuple[str, ...] = ()) -> dict:
    rows = [{"id": model, "model": model, "hidden": False} for model in models]
    for row in rows:
        if row["id"] == CYBER_MODEL:
            row["availableAccessPrograms"] = {"cyber": list(cyber_access)}
    return {"data": rows,
            "nextCursor": None}


class ModelRoleResolutionTests(unittest.TestCase):
    def config(self):
        from cwo_core.policy import load_policy

        return load_policy("model-roles")

    def test_explicit_default_and_exact_membership(self):
        config = self.config()
        for role, role_config in config["roles"].items():
            with self.subTest(role=role):
                model = role_config["current"]
                self.assertEqual(identities.current_model(role), model)
                self.assertEqual(identities.resolve_model(role), model)
                self.assertEqual(identities.role_for_model(model), role)
                self.assertEqual(identities.previous_model(role), role_config["previous"])
                for invalid in (f" {model}", model.upper(), "gpt-reserve", "codex-auto-review"):
                    self.assertIsNone(identities.role_for_model(invalid))
        self.assertGreater(identities.reviewer_rank("astra"), identities.reviewer_rank("sol"))

    def test_legacy_sol_role_can_still_resolve_its_model(self):
        config = self.config()
        sol = config["roles"]["sol"]
        del sol["reasoning_effort"]
        del sol["service_tier"]
        self.assertEqual(identities.resolve_model("sol", config=config), sol["current"])

    def test_latest_uses_numeric_order_from_public_catalog(self):
        config = self.config()
        config["roles"]["luna"]["selection"] = "latest-in-family"
        models = catalog("gpt-9.9-luna", "gpt-9.10-luna", "gpt-9.11-luna", "gpt-100-terra")
        models["data"][2]["hidden"] = True
        self.assertEqual(identities.resolve_model("luna", config=config, catalog=models), "gpt-9.10-luna")
        self.assertEqual(identities.role_for_model("gpt-9.10-luna", config=config, catalog=models), "luna")
        self.assertIsNone(identities.role_for_model("gpt-9.11-luna", config=config, catalog=models))
        with self.assertRaisesRegex(ValueError, "catalog"):
            identities.resolve_model("luna", config=config)

    def test_latest_refuses_aliases_and_incomplete_catalogs(self):
        config = self.config()
        config["roles"]["terra"]["selection"] = "latest-in-family"
        for changes in ({"id": "gpt-9.9-terra", "model": "gpt-reserve"}, {"hidden": True},
                        {"hidden": None}, {"id": "gpt-9.9-terra-extra", "model": "gpt-9.9-terra-extra"}):
            with self.subTest(changes=changes):
                models = catalog("gpt-9.9-terra")
                models["data"][0].update(changes)
                with self.assertRaises(ValueError):
                    identities.resolve_model("terra", config=config, catalog=models)
        models = catalog("gpt-9.9-terra")
        models["nextCursor"] = "remaining-page"
        with self.assertRaisesRegex(ValueError, "catalog"):
            identities.resolve_model("terra", config=config, catalog=models)

    def test_explicit_pin_overrides_latest_and_requires_the_right_family(self):
        config = self.config()
        config["roles"]["terra"].update(selection="latest-in-family", pin="gpt-9.9-terra")
        self.assertEqual(identities.resolve_model("terra", config=config), "gpt-9.9-terra")
        self.assertEqual(identities.resolve_model("terra", config=config, catalog=catalog("gpt-10-terra")),
                         "gpt-9.9-terra")
        models = catalog("gpt-9.9-terra")
        models["data"][0]["hidden"] = True
        with self.assertRaisesRegex(ValueError, "hidden"):
            identities.resolve_model("terra", config=config, catalog=models)
        for invalid in ("gpt-9-luna", "gpt-reserve", "codex-auto-review", "gpt-09-terra"):
            with self.subTest(invalid=invalid):
                config["roles"]["terra"]["pin"] = invalid
                with self.assertRaisesRegex(ValueError, "terra"):
                    identities.resolve_model("terra", config=config)

    def test_startup_catalog_is_an_exact_snapshot(self):
        config = self.config()
        config["roles"]["luna"]["selection"] = "latest-in-family"
        models = catalog("gpt-9.9-luna", "gpt-10-luna")
        self.addCleanup(identities.configure_model_catalog, None)
        identities.configure_model_catalog(models)
        models["data"][1]["hidden"] = True
        self.assertTrue(identities.requires_model_catalog(("luna",), config=config))
        self.assertFalse(identities.requires_model_catalog(("terra",), config=config))
        self.assertEqual(identities.resolve_model("luna", config=config), "gpt-10-luna")

    def test_optional_cyber_fallback_is_absent_by_default(self):
        config = self.config()

        self.assertNotIn("cyber_fallback", config["roles"])
        self.assertFalse(identities.requires_model_catalog(("cyber_fallback",), config=config))
        self.assertEqual(
            identities.cyber_fallback_availability(config=config),
            {
                "role": "cyber_fallback",
                "status": "unconfigured",
                "reason": "role-absent",
                "model": None,
                "required_access_program": None,
                "codex_config": None,
            },
        )

    def test_configured_cyber_fallback_uses_access_program_metadata(self):
        config = self.config()
        config["roles"]["cyber_fallback"] = dict(CYBER_ROLE)
        available = catalog(CYBER_MODEL, cyber_access=("standard", "daybreakBlue"))

        self.assertTrue(identities.requires_model_catalog(("cyber_fallback",), config=config))
        self.assertEqual(
            identities.cyber_fallback_availability(config=config, catalog=available),
            {
                "role": "cyber_fallback",
                "status": "available",
                "reason": "required-access-program-advertised",
                **CYBER_ROLE,
            },
        )

        for unavailable, reason in (
            (catalog(), "model-not-advertised"),
            (catalog(CYBER_MODEL), "access-program-not-advertised"),
            (catalog(CYBER_MODEL, cyber_access=("standard",)), "access-program-not-advertised"),
        ):
            with self.subTest(reason=reason):
                status = identities.cyber_fallback_availability(config=config, catalog=unavailable)
                self.assertEqual((status["status"], status["reason"]), ("unavailable", reason))

    def test_cyber_fallback_configuration_is_closed_and_exact(self):
        base = self.config()
        invalid = (
            {**CYBER_ROLE, "model": "gpt-6.2-sol"},
            {**CYBER_ROLE, "required_access_program": "standard"},
            {**CYBER_ROLE, "codex_config": {"daybreak": False}},
            {**CYBER_ROLE, "codex_config": {"daybreak": True, "other": True}},
            {**CYBER_ROLE, "extra": True},
            {**CYBER_ROLE, "model": "gpt-daybreak-blue-latest"},
            {**CYBER_ROLE, "previous": "not-a-model"},
            {**CYBER_ROLE, "model": "gpt-6.2-astra"},
            {**CYBER_ROLE, "model": "gpt-6-luna"},
        )
        for entry in invalid:
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, "cyber_fallback"):
                config = {"version": base["version"], "roles": {**base["roles"], "cyber_fallback": entry}}
                identities.validate_model_role_config(config)


class CyberFallbackConfigurationTests(unittest.TestCase):
    def test_configured_model_and_previous_are_accepted(self):
        from cwo_core.policy import load_policy

        base = load_policy("model-roles")
        for entry in (
            dict(CYBER_ROLE),
            {**CYBER_ROLE, "model": "gpt-7-sol", "previous": CYBER_MODEL},
            {**CYBER_ROLE, "previous": None, "purpose": "Daybreak Blue retry after a cyber-policy refusal"},
        ):
            with self.subTest(entry=entry):
                identities.validate_model_role_config(
                    {"version": base["version"], "roles": {**base["roles"], "cyber_fallback": entry}}
                )

    def test_no_daybreak_model_id_is_hard_coded_in_scripts(self):
        from pathlib import Path

        scripts = Path(__file__).resolve().parents[1] / "scripts"
        offenders = [
            str(path.relative_to(scripts))
            for path in scripts.rglob("*.py")
            if "gpt-daybreak-blue-latest" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
