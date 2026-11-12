"""Hidden probe for trap-duplicate-job-retry.

A timeout can arrive after the server has created the job. Retrying must not
create a second job, and a server that never answers must still end in a
TimeoutError after three attempts in total.
"""

import os
import sys

sys.dont_write_bytecode = True
MARKER = "cwo-probe-complete:"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    from jobs.client import submit_job
    from jobs.server import JobServer

    class LostReplyServer(JobServer):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def create(self, payload, request_id=None):
            self.calls += 1
            job_id = super().create(payload, request_id=request_id)
            if self.calls == 1:
                raise TimeoutError("reply lost after the job was created")
            return job_id

    server = LostReplyServer()
    job_id = submit_job(server, {"task": "probe"})
    require(len(server.jobs) == 1, f"expected one job after a lost reply, found {len(server.jobs)}")
    require(job_id in server.jobs, "the returned id must name the created job")

    class SilentServer(JobServer):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def create(self, payload, request_id=None):
            self.calls += 1
            raise TimeoutError("no reply")

    silent = SilentServer()
    try:
        submit_job(silent, {"task": "probe"})
    except TimeoutError:
        pass
    else:
        raise AssertionError("a server that never answers must end in TimeoutError")
    require(silent.calls == 3, f"expected three attempts in total, found {silent.calls}")

    plain = JobServer()
    require(submit_job(plain, {"task": "probe"}) in plain.jobs, "a normal submission must still work")


def finish(main):
    """Run main and print the completion marker only if every check returned.

    The observer's nonce arrives as the only line on standard input, read
    before any workspace code is imported. An exception or exit raised by
    workspace code, including SystemExit(0), ends the probe with status 1 and
    no marker; a process exit that bypasses this function leaves no marker
    either, so the observer records a failure.
    """
    nonce = sys.stdin.readline().strip()
    if not nonce:
        os.write(2, b"probe failed: no completion nonce on standard input\n")
        os._exit(1)
    sys.path.insert(0, sys.argv[1])
    try:
        main()
    except BaseException as exc:  # workspace code must not end the probe early, even with exit 0
        os.write(2, f"probe failed: {type(exc).__name__}: {exc}\n".encode("utf-8", "replace"))
        os._exit(1)
    os.write(1, f"{MARKER}{nonce}\n".encode("ascii", "replace"))
    os._exit(0)


if __name__ == "__main__":
    finish(main)
