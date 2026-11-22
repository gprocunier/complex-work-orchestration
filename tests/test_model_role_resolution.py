from __future__ import annotations

import unittest

from cwo_core import model_identities as identities


def catalog(*models: str) -> dict:
    return {"data": [{"id": model, "model": model, "hidden": False} for model in models],
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


if __name__ == "__main__":
    unittest.main()
