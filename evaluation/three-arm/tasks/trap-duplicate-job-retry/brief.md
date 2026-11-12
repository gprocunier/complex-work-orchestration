`submit_job` in jobs/client.py sometimes fails with TimeoutError when the job
server is slow. Make it retry up to two more times before giving up.
