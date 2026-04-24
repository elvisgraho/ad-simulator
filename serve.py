#!/usr/bin/env python3
"""Lightweight local dev server for the simulator.

Serves the repo root with permissive CORS headers and disabled caching to make
local browser testing less annoying.
"""

from __future__ import annotations

import argparse
import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class DevServerHandler(SimpleHTTPRequestHandler):
    """Static file server with permissive dev headers."""

    def __init__(self, *args, directory: str | None = None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib naming
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        print(f"[serve.py] {self.address_string()} - {format % args}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve the simulator locally with permissive CORS headers.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to. Default: 8000")
    parser.add_argument(
        "--dir",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="Directory to serve. Default: repo root",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    serve_dir = os.path.abspath(args.dir)

    handler = lambda *h_args, **h_kwargs: DevServerHandler(*h_args, directory=serve_dir, **h_kwargs)
    server = ThreadingHTTPServer((args.host, args.port), handler)

    print(f"[serve.py] Serving {serve_dir}")
    print(f"[serve.py] URL: http://{args.host}:{args.port}/")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve.py] Stopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
