#!/usr/bin/env python3
"""CASE FILE VP-26-001 · local preview server.

Serves the site exactly as Netlify would, as far as a local server can:
  - every security header from netlify.toml is applied (same source of truth)
  - /integrity.json is computed live, so the integrity panel has something to compare
  - clean URLs (/security/ → security/index.html), /404.html for unknown paths
  - nothing is cached, so edits show up on reload

Usage:  python3 scripts/serve.py [port]      (default 4174, binds 127.0.0.1 only)
"""
import hashlib
import json
import os
import sys
import tomllib
from datetime import datetime, timezone
from fnmatch import fnmatch
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4174

with open(os.path.join(ROOT, "netlify.toml"), "rb") as fh:
    CONFIG = tomllib.load(fh)
HEADER_RULES = [(h["for"], h.get("values", {})) for h in CONFIG.get("headers", [])]


def headers_for(path: str):
    out = {}
    for pattern, values in HEADER_RULES:
        # Netlify's "/*" matches everything; "/fonts/*" matches below that prefix.
        if pattern == "/*" or fnmatch(path, pattern):
            out.update(values)
    return out


def digest(relpath: str) -> str:
    with open(os.path.join(ROOT, relpath), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".asc": "text/plain; charset=utf-8",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
        ".woff2": "font/woff2",
        ".webmanifest": "application/manifest+json",
        ".xml": "application/xml; charset=utf-8",
    }

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def end_headers(self):
        for name, value in headers_for(self.path.split("?")[0]).items():
            self.send_header(name, value)
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        if self.path.split("?")[0] == "/integrity.json":
            body = json.dumps(
                {
                    "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "algorithm": "sha256",
                    "note": "computed live by scripts/serve.py; Netlify writes this file at build time",
                    "files": {f: digest(f) for f in ("index.html", "styles.css", "main.js")},
                },
                indent=2,
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def send_error(self, code, message=None, explain=None):
        if code == 404 and self.command in ("GET", "HEAD"):
            page = os.path.join(ROOT, "404.html")
            if os.path.exists(page):
                with open(page, "rb") as fh:
                    body = fh.read()
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command == "GET":
                    self.wfile.write(body)
                return
        super().send_error(code, message, explain)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"case file served at http://127.0.0.1:{PORT}/  (headers from netlify.toml)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
