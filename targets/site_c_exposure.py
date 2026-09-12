#!/usr/bin/env python3
"""Target C — "DevPortal"  ·  ISSUES: file exposure + default creds + version leak + IDOR

  1. Sensitive file exposure   /.env /backup.zip /config.php.bak      [medium]
  2. Directory listing          GET /                                  [low]
  3. Default admin credentials  POST /admin  (admin/admin)             [high]
  4. IDOR on invoices           GET /invoice?id=2  (any id readable)   [high]
  5. Server version disclosure  Server: DevPortal/1.0 (Debug)          [low]
Run:  python targets/site_c_exposure.py [port]   (default 8102)
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

SECRET_FILES = {
    "/.env": ("text/plain", "DB_HOST=prod-db.internal\nDB_USER=root\nDB_PASSWORD=Pr0d-P@ssw0rd!\n"
              "STRIPE_SECRET_KEY=sk_live_51H8xQffFakeKeyForDemo\nJWT_SIGNING_KEY=supersecret\n"),
    "/backup.zip": ("application/zip", "PK\x03\x04 (fake db backup) customers,emails,password_hashes"),
    "/config.php.bak": ("text/plain", "<?php $db_pass='Pr0d-P@ssw0rd!'; // backup ?>"),
}
INVOICES = {"1": "Invoice #1 — jane@example.com — $42.00",
            "2": "Invoice #2 — ceo@bigcorp.com — $9,900.00 (CONFIDENTIAL)"}
INDEX = ("<!doctype html><title>DevPortal</title><h2>Index of /</h2><ul>"
         + "".join('<li><a href="%s">%s</a></li>' % (p, p) for p in SECRET_FILES)
         + '<li><a href="/invoice?id=1">/invoice?id=1</a></li>'
         + '<li><a href="/admin">/admin</a></li></ul>')

class H(BaseHTTPRequestHandler):
    server_version = "DevPortal/1.0"; sys_version = "(Debug build)"  # version disclosure
    def _send(self, code, ctype, content):
        body = content.encode("utf-8", "replace")
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
    def do_GET(self):
        parts = urlsplit(self.path); path = parts.path
        if path in ("/", "/index.html"): return self._send(200, "text/html", INDEX)
        if path in SECRET_FILES:
            ctype, content = SECRET_FILES[path]; return self._send(200, ctype, content)
        if path == "/invoice":
            iid = parse_qs(parts.query).get("id", ["1"])[0]
            # VULNERABLE: no ownership check -> IDOR.
            return self._send(200, "text/plain", INVOICES.get(iid, "no such invoice"))
        if path == "/admin":
            return self._send(200, "text/html",
                "<form method=POST action=/admin>admin login: "
                "<input name=u><input name=p type=password><button>go</button></form>")
        self._send(404, "text/plain", "not found")
    def do_POST(self):
        if urlsplit(self.path).path != "/admin": return self._send(404, "text/plain", "nf")
        n = int(self.headers.get("Content-Length", 0))
        f = parse_qs(self.rfile.read(n).decode())
        u = f.get("u", [""])[0]; p = f.get("p", [""])[0]
        if u == "admin" and p == "admin":  # VULNERABLE: default credentials.
            return self._send(200, "text/html", "<h3>Admin access granted (default creds).</h3>")
        self._send(401, "text/html", "denied")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8102
    print("Target C (exposure + default creds + IDOR) on http://0.0.0.0:%d" % port)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
