"""In-memory job server used by the client. It never contacts a network."""

import itertools


class JobServer:
    def __init__(self):
        self.jobs = {}
        self.by_request = {}
        self._ids = itertools.count(1)

    def create(self, payload, request_id=None):
        """Create a job and return its id.

        A request_id that was already used returns the job created for it.
        """
        if request_id is not None and request_id in self.by_request:
            return self.by_request[request_id]
        job_id = f"job-{next(self._ids)}"
        self.jobs[job_id] = payload
        if request_id is not None:
            self.by_request[request_id] = job_id
        return job_id
