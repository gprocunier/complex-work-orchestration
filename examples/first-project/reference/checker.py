"""Reference solution for deterministic tutorial checks, not an agent transcript."""
import json
from pathlib import Path
import sys


def errors(config):
    if not isinstance(config, dict):
        return ["config must be an object"]
    result = []
    host = config.get("host")
    if not isinstance(host, str) or not host.strip():
        result.append("host must be nonempty text")
    port = config.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        result.append("port must be an integer from 1 to 65535")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python3 checker.py CONFIG.json", file=sys.stderr)
        return 2
    try:
        config = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"cannot read configuration: {exc}", file=sys.stderr)
        return 2
    problems = errors(config)
    print("\n".join(problems) if problems else "valid")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
