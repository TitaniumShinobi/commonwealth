"""Isolated browser/DNS/TLS/origin fixture; no public network route."""
import hashlib
import http.client
import http.server
import json
import os
import secrets
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
from pathlib import Path

from bell import STATES, trial

ROOT = Path(sys.argv[1])
RUN = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
HOST = "lab.example"
TOKEN = secrets.token_urlsafe(32)
RECEIPTS = []
lock = threading.Lock()
PAGE = b"""<!doctype html><html><title>Commonwealth simulation</title>
<h1>Simulation</h1><button id="run">Run simulation</button><output id="result"></output>
<script src="/app.js"></script></html>"""
ASSET = b"""document.querySelector('#run').onclick = async () => {
const trial = new URL(location.href).searchParams.get('trial');
const response = await fetch('/experiment', {method:'POST', headers:{'Content-Type':'application/json',
},body:JSON.stringify({trial})});
document.querySelector('#result').textContent = JSON.stringify({status:response.status, ...await response.json()});
};"""
CASES = {f"ideal-{i}": (label, "ideal") for i, label in enumerate(STATES)}
CASES.update(dephasing=("+i", "dephasing"), missing=("+", "missing"), cancelled=("+", "cancelled"),
             unavailable=("0", "unavailable"))
WRONG_NAME = "wrong.lab.example"


def note(layer, **data):
    row = {"run_id": RUN, "layer": layer, **data}
    with lock:
        RECEIPTS.append(row)
        with (ROOT / "trace.ndjson").open("a") as stream:
            print(json.dumps(row, separators=(",", ":")), file=stream)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        offset = 12
        labels = []
        try:
            while query[offset]:
                width = query[offset]
                if width > 63:
                    return
                offset += 1
                labels.append(query[offset:offset + width].decode("ascii"))
                offset += width
            end = offset + 5
            kind, domain_class = struct.unpack("!HH", query[offset + 1:end])
        except (IndexError, ValueError, struct.error):
            return
        name = ".".join(labels).lower()
        found = name in (HOST, WRONG_NAME) and kind == 1 and domain_class == 1
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton("127.0.0.1")
        status = 0x8180 if name in (HOST, WRONG_NAME) else 0x8183
        response = query[:2] + struct.pack("!HHHHH", status, 1, int(found), 0, 0) + query[12:end]
        sock.sendto(response + (answer if found else b""), self.client_address)
        note("dns", name=name, query_type=kind, query_id=int.from_bytes(query[:2], "big"),
             answer="127.0.0.1" if found else None, transport="udp", port=53)


class HTTP(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, content, media):
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Fixture-Run", RUN)
        self.end_headers()
        self.wfile.write(content)


class Origin(HTTP):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if self.path != "/experiment" or not 0 < length <= 512:
            return self.respond(400, b"{}", "application/json")
        data = json.loads(self.rfile.read(length))
        identifier = data.get("trial")
        granted = secrets.compare_digest(self.headers.get("Cookie", ""), f"lab_session={TOKEN}") and identifier in CASES
        note("authorization", trial_id=identifier, decision="allowed" if granted else "denied")
        if not granted:
            return self.respond(403, b'{"terminal":"denied"}', "application/json")
        label, mode = CASES[identifier]
        receipt = trial(RUN, identifier, label, mode)
        note("simulation", **{k: v for k, v in receipt.items() if k != "run_id"})
        self.respond(200, json.dumps(receipt).encode(), "application/json")


class Gateway(HTTP):
    def proxy(self):
        if self.headers.get("Host") != HOST:
            return self.respond(421, b"", "text/plain")
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 512:
            return self.respond(400, b"", "text/plain")
        headers = {"Host": "origin.example"}
        for field in ("Cookie", "Content-Type"):
            if self.headers.get(field):
                headers[field] = self.headers[field]
        is_asset = self.command == "GET" and self.path.split("?", 1)[0] in ("/", "/app.js")
        is_api = self.command == "POST" and self.path == "/experiment"
        if not (is_asset or is_api):
            return self.respond(404, b"", "text/plain")
        port = 8443 if is_asset else origin.server_port
        route = "stock-https" if is_asset else "quantum-api"
        path = self.path.split("?", 1)[0] if is_asset else self.path
        if path == "/":
            path = "/index.html"
        request = http.client.HTTPSConnection("localhost", port, context=origin_trust, timeout=10)
        try:
            request.connect()
            peer = hashlib.sha256(request.sock.getpeercert(binary_form=True)).hexdigest()
            body = self.rfile.read(length) if length else None
            identifier = json.loads(body).get("trial") if body and self.path == "/experiment" else None
            request.request(self.command, path, body=body, headers=headers)
            upstream = request.getresponse()
            data = upstream.read()
            note("gateway", ingress=self.headers["Host"], origin="origin.example", origin_port=port, route=route,
                 origin_certificate_sha256=peer, method=self.command, path=self.path, status=upstream.status,
                 trial_id=identifier, client_port=self.client_address[1], body_sha256=hashlib.sha256(data).hexdigest())
            self.respond(upstream.status, data, upstream.getheader("Content-Type", "application/json"))
        finally:
            request.close()

    do_GET = proxy
    do_POST = proxy


def tls(server, role, certificate):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT / (certificate + ".pem"), ROOT / (certificate + ".key"))
    def sni(channel, name, _):
        note("tls", role=role, sni=name, port=server.server_port, client_port=channel.getpeername()[1])
        if name not in ((HOST, WRONG_NAME) if role == "gateway" else ("localhost",)):
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    context.set_servername_callback(sni)
    server.socket = context.wrap_socket(server.socket, server_side=True)


def require(condition, criterion):
    note("check", criterion=criterion, passed=bool(condition))
    if not condition:
        raise RuntimeError(criterion)


origin_trust = ssl.create_default_context(cafile=str(ROOT / "ca.pem"))
with socketserver.ThreadingUDPServer(("127.0.0.1", 53), DNS) as dns, \
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin, \
        http.server.ThreadingHTTPServer(("127.0.0.1", 443), Gateway) as gateway:
    tls(origin, "quantum-api", "origin")
    tls(gateway, "gateway", "gateway")
    for server in (dns, origin, gateway):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    static = ROOT / "stock-origin"
    static.mkdir()
    (static / "index.html").write_bytes(PAGE)
    (static / "app.js").write_bytes(ASSET)
    stock = subprocess.Popen(["openssl", "s_server", "-quiet", "-WWW", "-accept", "127.0.0.1:8443",
                              "-cert", str(ROOT / "origin.pem"), "-key", str(ROOT / "origin.key")],
                             cwd=static, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        subprocess.run([sys.argv[2], str(Path(__file__).with_name("browser.mjs")), sys.argv[3], str(ROOT), RUN],
                       check=True, timeout=95, env={**os.environ, "CW11_BROWSER_SESSION": TOKEN})
        browser = json.loads((ROOT / "browser.json").read_text())
        require(browser["typed"] == "https://lab.example", "typed address")
        require(browser["denied"] == 403 and len(browser["trials"]) == len(CASES), "authorization and all trials")
        require(any(r["layer"] == "dns" and r["answer"] == "127.0.0.1" for r in RECEIPTS), "real DNS query and answer")
        require(any(r["layer"] == "tls" and r["role"] == "gateway" and r["sni"] == HOST and r["port"] == 443
                    for r in RECEIPTS), "gateway SNI over TCP 443")
        require(any(r["layer"] == "tls" and r["role"] == "quantum-api" for r in RECEIPTS), "separate API TLS")
        require(any(r["layer"] == "gateway" and r.get("route") == "stock-https" and r["path"] == "/app.js"
                    and r["body_sha256"] == hashlib.sha256(ASSET).hexdigest() for r in RECEIPTS), "stock origin asset bytes")
        require(browser["wrong_name"]["error"] == "net::ERR_CERT_COMMON_NAME_INVALID" and
                any(r["layer"] == "dns" and r["name"] == WRONG_NAME and r["answer"] for r in RECEIPTS) and
                any(r["layer"] == "tls" and r["sni"] == WRONG_NAME for r in RECEIPTS), "wrong-name DNS and certificate rejection")
        require(not any(r["layer"] == "gateway" and r["path"] == "/wrong-name-probe" for r in RECEIPTS),
                "wrong-name browser emitted zero origin requests")
        operations = [(r["layer"], r.get("decision")) for r in RECEIPTS
                      if r.get("trial_id") == "ideal-0" and r["layer"] in ("authorization", "simulation")]
        require(operations == [("authorization", "denied"), ("authorization", "allowed"), ("simulation", None)],
                "same valid trial rejected before authorization without dispatch")
        for identifier, evidence in browser["trials"].items():
            label, mode = CASES[identifier]
            observed = evidence["result"]
            require(evidence["page"] == "Simulation" and evidence["status"] == 200, f"{identifier}: loaded and posted")
            require(evidence["security"]["protocol"].startswith("TLS") and evidence["security"]["subjectName"] == HOST
                    and evidence["security"]["issuer"] == "Commonwealth Step 11 Fixture CA", f"{identifier}: trusted certificate")
            ingress = [r for r in RECEIPTS if r["layer"] == "gateway" and r.get("trial_id") == identifier
                       and r["method"] == "POST" and r["status"] == 200]
            require(len(ingress) == 1 and any(r["layer"] == "tls" and r["role"] == "gateway" and
                    r["client_port"] == ingress[0]["client_port"] for r in RECEIPTS), f"{identifier}: POST and ingress TLS")
            require(any(r["layer"] == "authorization" and r["trial_id"] == identifier and
                        r["decision"] == "allowed" for r in RECEIPTS), f"{identifier}: authorized origin")
            require(observed["run_id"] == RUN and observed["trial_id"] == identifier, f"{identifier}: correlation")

            require(observed["terminal"] == {"missing": "classical_bits_expired", "cancelled": "cancelled", "unavailable": "quantum_link_unavailable"}
                    .get(mode, "measured"), f"{identifier}: expected terminal")
        note("browser_gate", revision=os.environ["GITHUB_SHA"], verdict="PASS",
             scope=["browser_network_fixture", "simulated_quantum_workflow"], trials=len(CASES))
    finally:
        stock.terminate()
        stock.wait(timeout=3)
        for server in (dns, origin, gateway):
            server.shutdown()
