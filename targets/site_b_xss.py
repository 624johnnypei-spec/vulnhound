#!/usr/bin/env python3
"""Target B — "QuickSearch"  ·  ISSUES: XSS (x2) + open redirect + missing headers

  1. Reflected XSS in search    GET /search?q=<script>...            [high]
  2. Reflected XSS in greeting  GET /hello?name=<script>...          [high]
  3. Open redirect              GET /go?url=http://evil.example      [medium]
  4. Missing security headers   (no CSP / X-Frame-Options anywhere)  [low]
Run:  python targets/site_b_xss.py [port]   (default 8101)
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = """<!doctype html><title>QuickSearch</title><h2>QuickSearch</h2>
<form action=/search><input name=q placeholder="Search..."><button>Go</button></form>
<p><a href="/hello?name=friend">say hello</a></p>%s"""

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, headers=None):
        self.send_response(code); self.send_header("Content-Type","text/html")
        # NOTE: deliberately no Content-Security-Policy / X-Frame-Options (missing headers).
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(body.encode())
    def log_message(self, *a): pass
    def do_GET(self):
        parts = urlsplit(self.path); qs = parse_qs(parts.query)
        if parts.path == "/search":
            q = qs.get("q", [""])[0]
            return self._send(200, PAGE % ("<p>You searched for: %s</p>" % q))  # reflected XSS
        if parts.path == "/hello":
            name = qs.get("name", ["there"])[0]
            return self._send(200, "<h3>Hello, %s!</h3>" % name)  # reflected XSS
        if parts.path == "/go":
            url = qs.get("url", ["/"])[0]
            return self._send(302, "redirecting...", {"Location": url})  # open redirect
        return self._send(200, PAGE % "")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8101
    print("Target B (XSS + open redirect) on http://0.0.0.0:%d" % port)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
