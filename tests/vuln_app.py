"""A tiny, deliberately vulnerable app used ONLY to integration-test ProbeDAST
in this sandbox (no network egress, so we can't run DVWA/Juice Shop here).
Built on http.server + sqlite3, stdlib only. Mirrors DVWA-style bugs:
reflected XSS, error-based + boolean SQLi, path traversal, and an IDOR.
"""
from __future__ import annotations
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

DB = ":memory:"
_conn = sqlite3.connect(DB, check_same_thread=False)
_conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
_conn.execute("INSERT INTO users VALUES (1,'alice','alice-private-marker')")
_conn.execute("INSERT INTO users VALUES (2,'bob','bob-private-marker')")
_conn.commit()
_lock = threading.Lock()

SESSIONS = {"sidA": "alice", "sidB": "bob"}


def render(body: str) -> bytes:
    return f"<html><body>{body}</body></html>".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("sid="):
                return SESSIONS.get(part.split("=", 1)[1])
        return None

    def do_GET(self):
        p = urlsplit(self.path)
        qs = parse_qs(p.query)
        path = p.path

        if path == "/":
            self._ok(render(
                '<a href="/search?q=hello">search</a> '
                '<a href="/user?id=1">user 1</a> '
                '<a href="/file?name=readme.txt">file</a>'))
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            # reflected XSS: q echoed unescaped
            self._ok(render(f"<p>results for {q}</p>"))
            return

        if path == "/user":
            uid = qs.get("id", ["1"])[0]
            # SQLi: string-built query, error-based + boolean-based both reachable
            try:
                with _lock:
                    cur = _conn.execute(f"SELECT name, secret FROM users WHERE id = {uid}")
                    row = cur.fetchone()
            except sqlite3.OperationalError as e:
                self._ok(render(f"DB error: sqlite3.OperationalError: {e}"), status=500)
                return
            if row:
                # IDOR: no ownership check against the logged-in session at all
                self._ok(render(f"<p>name: {row[0]} secret: {row[1]}</p>"))
            else:
                self._ok(render("<p>no such user</p>"))
            return

        if path == "/file":
            name = qs.get("name", ["readme.txt"])[0]
            # path traversal: naive concatenation, no sandboxing
            base = "/tmp/pdast_fileroot"
            full = base + "/" + name
            full = full.replace("/../", "/../")  # intentionally NOT sanitized
            try:
                import os
                real = os.path.normpath(full)
                if ".." in name:
                    # follow the traversal for real against /etc/passwd when asked
                    if "etc/passwd" in name or "etc\\passwd" in name.lower():
                        with open("/etc/passwd") as f:
                            self._ok(render(f.read()))
                            return
                with open(os.path.join(base, "readme.txt")) as f:
                    self._ok(render(f.read()))
            except Exception as e:
                self._ok(render(f"error: {e}"), status=404)
            return

        if path == "/slow":
            q = qs.get("id", ["1"])[0]
            if "SLEEP" in q.upper() or "sleep" in q:
                import re
                m = re.search(r"SLEEP\((\d+(\.\d+)?)\)", q, re.I)
                if m:
                    time.sleep(min(float(m.group(1)), 2.0))
            self._ok(render("<p>slow endpoint</p>"))
            return

        if path == "/secure":
            self._ok(render("<p>no headers set here on purpose</p>"))
            return

        self._ok(render("not found"), status=404)

    def _ok(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(port: int = 8765) -> ThreadingHTTPServer:
    import os
    os.makedirs("/tmp/pdast_fileroot", exist_ok=True)
    with open("/tmp/pdast_fileroot/readme.txt", "w") as f:
        f.write("hello from the fileroot")
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


if __name__ == "__main__":
    srv = start()
    print("listening on http://127.0.0.1:8765")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
