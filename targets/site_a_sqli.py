#!/usr/bin/env python3
"""Target A — "CoolStore"  ·  ISSUES: SQL injection + broken access control + info leak

A deliberately vulnerable shop. Multiple distinct weaknesses so a scan runs longer:
  1. SQL injection in login       POST /login   ( ' OR '1'='1' -- )      [critical]
  2. SQL injection in product id  GET  /product?id=1 (UNION-based)       [critical]
  3. Broken access control        GET  /admin    (no auth required)      [high]
  4. Verbose SQL error disclosure (leaks the query on malformed input)   [medium]
Run:  python targets/site_a_sqli.py [port]   (default 8100)
"""
import sqlite3, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

def _db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users(id INTEGER, username TEXT, password TEXT, role TEXT)")
    db.execute("CREATE TABLE products(id INTEGER, name TEXT, price TEXT, secret TEXT)")
    db.executemany("INSERT INTO users VALUES (?,?,?,?)",
                   [(1,'admin','s3cr3t-admin-pw','admin'), (2,'jane','hunter2','user')])
    db.executemany("INSERT INTO products VALUES (?,?,?,?)",
                   [(1,'Widget','9.99','none'), (2,'Gadget','19.99','none')])
    db.commit(); return db
DB = _db()

LOGIN = """<!doctype html><title>CoolStore</title><h2>CoolStore — Sign in</h2>
<form method=POST action=/login><p>User <input name=username></p>
<p>Pass <input name=password type=password></p><button>Sign in</button></form>
<p><a href="/product?id=1">Browse a product</a></p>"""

class H(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self, *a): pass
    def do_GET(self):
        parts = urlsplit(self.path); path = parts.path
        if path == "/product":
            pid = parse_qs(parts.query).get("id", ["1"])[0]
            # VULNERABLE: id concatenated -> UNION SQL injection.
            q = "SELECT name, price FROM products WHERE id = %s" % pid
            try:
                rows = DB.execute(q).fetchall()
            except Exception as e:
                return self._send(500, "SQL error: %s<br>query: %s" % (e, q))  # verbose leak
            body = "".join("<li>%s — $%s</li>" % (r[0], r[1]) for r in rows)
            return self._send(200, "<h3>Products</h3><ul>%s</ul>" % body)
        if path == "/admin":
            # VULNERABLE: admin area with no authentication.
            users = DB.execute("SELECT username, role, password FROM users").fetchall()
            rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % u for u in users)
            return self._send(200, "<h2>Admin — all users</h2><table>%s</table>" % rows)
        return self._send(200, LOGIN)
    def do_POST(self):
        if urlsplit(self.path).path != "/login":
            return self._send(404, "not found")
        n = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(n).decode())
        user = form.get("username", [""])[0]; pw = form.get("password", [""])[0]
        q = "SELECT username, role FROM users WHERE username='%s' AND password='%s'" % (user, pw)
        try:
            row = DB.execute(q).fetchone()
        except Exception as e:
            return self._send(500, "SQL error: %s<br>query: %s" % (e, q))  # verbose leak
        if row:
            return self._send(200, "<h3>Welcome, %s (%s)!</h3>" % (row[0], row[1]))
        return self._send(401, "<h3>Invalid credentials.</h3>")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8100
    print("Target A (SQLi + access control) on http://0.0.0.0:%d" % port)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
