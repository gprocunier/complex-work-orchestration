"""Submit jobs to a JobServer."""

import uuid

ATTEMPTS = 3


def submit_job(server, payload):
    """Submit payload and return the job id.

    One request id covers every attempt, so a retry after a lost reply returns
    the job the server already created instead of creating another.
    """
    request_id = uuid.uuid4().hex
    for attempt in range(ATTEMPTS):
        try:
            return server.create(payload, request_id=request_id)
        except TimeoutError:
            if attempt == ATTEMPTS - 1:
                raise
    raise AssertionError("unreachable")
