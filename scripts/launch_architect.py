"""Launch an interactive Codex session using CWO's architect profile."""

import json
import os
import sys

from cwo_core.model_identities import resolve_model
from cwo_core.policy import load_policy
from manage_instruction_profile import PROFILE_NAME
from model_catalog_startup import configure_cli_model_catalog


def main() -> None:
    try:
        config = load_policy("model-roles")
        sol = config["roles"]["sol"]
        for key in ("reasoning_effort", "service_tier"):
            if not sol.get(key, "").strip():
                raise ValueError(f"model-roles sol {key} must be set in the routing configuration")
        configure_cli_model_catalog(("sol",))
        settings = {
            "model": resolve_model("sol", config=config),
            "model_reasoning_effort": sol["reasoning_effort"],
            "service_tier": sol["service_tier"],
        }
        command = ["codex", "--profile", PROFILE_NAME]
        for key, value in settings.items():
            command.extend(("-c", f"{key}={json.dumps(value)}"))
        os.execvp("codex", command + sys.argv[1:])
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cwo-codex: {exc}") from exc


if __name__ == "__main__":
    main()
