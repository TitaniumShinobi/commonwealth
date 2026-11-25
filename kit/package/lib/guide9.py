"""Loopback-only browser controls for the installed authority handlers."""
import hashlib
import html
import http.server
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from operator9 import Denied, apply, canonical, issue, load, make_plan, save


def serve(directory, ready, seconds=45):
    if not 1 <= seconds <= 120:
        raise Denied("invalid_session_duration")
    launch = secrets.token_urlsafe(32)
    session = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    expires = 0
    launched = False
    plan = None
    approval = None

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def show(self, decision, status=200, cookie=False):
            result = html.escape(canonical(decision).decode())
            title = html.escape(canonical(plan).decode()) if plan else ""
            page = (
                '<!doctype html><meta charset="utf-8"><title>Commonwealth operator</title>'
                '<h1>Commonwealth operator</h1><pre id="result">' + result + '</pre>'
                '<pre id="plan">' + title + '</pre>'
                '<form action="/plan" method="post">'
                f'<input name="csrf" type="hidden" value="{csrf}">'
                '<label>Action <select name="action">'
                + "".join(f'<option>{op}</option>' for op in
                          ("configure", "enroll", "exit", "upgrade", "rollback", "restore"))
                + '</select></label><label>Target <input name="target" id="target"></label>'
                  '<label>Typed payload <textarea name="payload" id="payload"></textarea></label>'
                  '<button id="plan-button">Review plan</button></form>'
                + "".join(
                    f'<form action="/{step}" method="post">'
                    f'<input name="csrf" type="hidden" value="{csrf}">'
                    f'<button id="{step}-button" name="confirmed" value="yes">{label}</button></form>'
                    for step, label in (("approve", "Approve reviewed plan"), ("apply", "Apply approved plan")))
            ).encode()
            if status == 403:
                page = ("<!doctype html><title>Access denied</title><pre>" + result + "</pre>").encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
            if cookie:
                self.send_header("Set-Cookie", f"cw={session}; HttpOnly; SameSite=Strict; Path=/")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def eligible(self):
            return (self.headers.get("Host") == host and
                    self.headers.get("Cookie") == f"cw={session}" and time.monotonic() < expires)

        def do_GET(self):
            nonlocal launched, expires
            if self.headers.get("Host") != host:
                return self.show({"decision": "wrong_host"}, 403)
            path = urlsplit(self.path)
            if path.path == "/launch":
                if launched or parse_qs(path.query).get("token") != [launch]:
                    return self.show({"decision": "launch_denied"}, 403)
                launched = True
                expires = time.monotonic() + seconds
                return self.show({"decision": "session_ready"}, cookie=True)
            if not self.eligible():
                return self.show({"decision": "session_denied"}, 403)
            return self.show({"decision": "ready"})

        def do_POST(self):
            nonlocal plan, approval
            if not self.eligible() or self.headers.get("Origin") != f"http://{host}":
                return self.show({"decision": "request_denied"}, 403)
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 8192:
                    raise Denied("request_size")
                payload = parse_qs(self.rfile.read(size).decode())
                if payload.get("csrf") != [csrf]:
                    raise Denied("request_denied")
                if self.path == "/plan":
                    plan = make_plan(directory, payload["action"][0], payload["target"][0],
                                     json.loads(payload["payload"][0]))
                    approval = None
                    return self.show({"decision": "planned", "plan_sha256": hashlib.sha256(canonical(plan)).hexdigest()})
                if not plan or payload.get("confirmed") != ["yes"]:
                    raise Denied("explicit_confirmation_required")
                if self.path == "/approve":
                    approval = issue(directory, plan, 30)
                    return self.show({"decision": "approved", "action": approval["action"]})
                if self.path == "/apply":
                    result = apply(directory, plan, approval, plan["target"])
                    return self.show({k: v for k, v in result.items() if k != "operation_id"})
                raise Denied("unrecognized_action")
            except (Denied, ValueError, KeyError) as exc:
                return self.show({"decision": "denied", "reason": str(exc)}, 422)

    with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
        host = f"127.0.0.1:{server.server_port}"
        path = Path(ready)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
            out.write(json.dumps({"url": f"http://{host}/launch?token={launch}"}))
        server.serve_forever()
