"""Validate a service configuration. This starter deliberately has a bug."""


def errors(config):
    # TODO: enforce the documented hostname and integer port contract.
    return [] if config.get("host") and config.get("port") else ["invalid config"]
