"""Submit jobs to a JobServer."""


def submit_job(server, payload):
    """Submit payload and return the job id. Raises TimeoutError on a timeout."""
    return server.create(payload)
