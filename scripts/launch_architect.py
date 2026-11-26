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


_DIRECTORY_OPTIONS = {'-C', '--cd'}


def _launch_directory(arguments):
    directory = Path.cwd()
    remaining = iter(arguments)
    for argument in remaining:
        if argument == '--':
            break
        if argument in _DIRECTORY_OPTIONS:
            directory = Path(next(remaining, '.'))
        elif argument.startswith('--cd='):
            directory = Path(argument.removeprefix('--cd='))
        elif argument.startswith('-C'):
            directory = Path(argument.removeprefix('-C'))
    return str(directory.resolve())


def _has_excluded_launch_argument(arguments):
    excluded = {'--remote', '--remote-auth-token-env', '--worktree', 'agents'}
    directory_value = False
    parse_options = True
    for argument in arguments:
        name = argument.partition('=')[0]
        if name in excluded and not (name == 'agents' and directory_value):
            return True
        if argument == '--':
            parse_options = False
        directory_value = parse_options and not directory_value and argument in _DIRECTORY_OPTIONS
    return False


def _delegation_settings(arguments):
    if not (sys.stdin.isatty() and sys.stdout.isatty()) or _has_excluded_launch_argument(arguments):
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
