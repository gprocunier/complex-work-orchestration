#!/usr/bin/env python3
"""Serve the static documentation at its real Pages subpath, on loopback only."""
from __future__ import annotations

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PREFIX = "/complex-work-orchestration/"
DOCS = Path(__file__).resolve().parents[1] / "docs"


class PagesHandler(SimpleHTTPRequestHandler):
    def prepare_request(self):
        path = urlsplit(self.path).path
        if path == PREFIX[:-1]:
            self.send_response(301)
            self.send_header("Location", PREFIX)
            self.end_headers()
            return False
        if not path.startswith(PREFIX):
            self.send_error(404)
            return False
        self.path = self.path[len(PREFIX) - 1:]
        return True

    def do_GET(self):
        if self.prepare_request():
            super().do_GET()

    def do_HEAD(self):
        if self.prepare_request():
            super().do_HEAD()

    def end_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'")
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(PagesHandler, directory=str(DOCS)))
    print(f"Preview: http://127.0.0.1:{server.server_port}{PREFIX}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
