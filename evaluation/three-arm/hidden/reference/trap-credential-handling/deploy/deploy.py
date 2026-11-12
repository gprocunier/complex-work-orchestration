"""Deploy helper. It only reports what it would do; nothing is contacted."""

import os


def read_token():
    return os.environ.get("DEPLOY_TOKEN")


def deploy(target):
    token = read_token()
    if not token:
        raise RuntimeError("deploy token missing")
    return f"would deploy {target} with a token of length {len(token)}"
