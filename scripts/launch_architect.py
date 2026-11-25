"""Launch an interactive Codex session using CWO's architect profile."""

import json
import os
from pathlib import Path
import shutil
import sys

from cwo_core.model_identities import resolve_model
from cwo_core.policy import load_policy
from manage_instruction_profile import PROFILE_NAME
from model_catalog_startup import configure_cli_model_catalog


def _launch_directory(arguments):
    directory = Path.cwd()
    remaining = iter(arguments)
    for argument in remaining:
        if argument == '--':
            break
        if argument in ('-C', '--cd'):
            directory = Path(next(remaining, '.'))
        elif argument.startswith('--cd='):
            directory = Path(argument.removeprefix('--cd='))
        elif argument.startswith('-C'):
            directory = Path(argument.removeprefix('-C'))
    return str(directory.resolve())


def _delegation_settings(arguments):
    excluded = {'--remote', '--remote-auth-token-env', '--worktree', 'agents'}
    if not (sys.stdin.isatty() and sys.stdout.isatty()) or any(arg.split('=', 1)[0] in excluded for arg in arguments):
        return {}
    prefix = 'mcp_servers.cwo-delegation.'
    script = Path(__file__).resolve().with_name('registered_delegation_foreground.py')
    binary = shutil.which('codex')
    if binary is None:
        raise ValueError('Codex CLI is required.')
    parent = [str(os.getpid()), str(Path(binary).resolve())]
    settings = {'command': sys.executable, 'args': ['-B', '-E', '-s', str(script), *parent],
                'cwd': _launch_directory(arguments), 'env_vars': ['BEADS_DIR'],
                'default_tools_approval_mode': 'approve'}
    return {prefix + key: value for key, value in settings.items()}


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
        arguments = sys.argv[1:]
        delegation = _delegation_settings(arguments)
        settings.update(delegation)
        command = ["codex", "--profile", PROFILE_NAME]
        if delegation and '--no-daemon' not in arguments:
            command.append('--no-daemon')
        for key, value in settings.items():
            command.extend(("-c", f"{key}={json.dumps(value)}"))
        os.execvp("codex", command + arguments)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cwo-codex: {exc}") from exc


if __name__ == "__main__":
    main()
