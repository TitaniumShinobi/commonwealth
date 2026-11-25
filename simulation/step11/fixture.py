"""Isolated browser/DNS/TLS/origin fixture; no public network route."""
import hashlib
import http.client
import http.server
import json
import os
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
TOKEN = "fixture-lab-operator"
RECEIPTS = []
lock = threading.Lock()
PAGE = b"""<!doctype html><html><title>Commonwealth simulation</title>
<h1>Simulation</h1><button id="run">Run simulation</button><output id="result"></output>
<script src="/app.js"></script></html>"""
ASSET = b"""document.querySelector('#run').onclick = async () => {
const trial = new URL(location.href).searchParams.get('trial');
const response = await fetch('/experiment', {method:'POST', headers:{'Content-Type':'application/json',
'Authorization':'Bearer fixture-lab-operator'},body:JSON.stringify({trial})});
document.querySelector('#result').textContent = JSON.stringify({status:response.status, ...await response.json()});
};"""
CASES = {f"ideal-{i}": (label, "ideal") for i, label in enumerate(STATES)}
CASES.update(dephasing=("+i", "dephasing"), missing=("+", "missing"), unavailable=("0", "unavailable"))


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
        found = name == HOST and kind == 1 and domain_class == 1
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton("127.0.0.1")
        status = 0x8180 if name == HOST else 0x8183
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
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        content, media = {"/": (PAGE, "text/html"), "/app.js": (ASSET, "text/javascript")}.get(path, (b"", "text/plain"))
        status = 200 if content else 404
        note("origin", method="GET", path=self.path, status=status, host=self.headers.get("Host"),
             body_sha256=hashlib.sha256(content).hexdigest())
        self.respond(status, content, media)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if self.path != "/experiment" or not 0 < length <= 512:
            return self.respond(400, b"{}", "application/json")
        data = json.loads(self.rfile.read(length))
        identifier = data.get("trial")
        granted = self.headers.get("Authorization") == f"Bearer {TOKEN}" and identifier in CASES
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
        for field in ("Authorization", "Content-Type"):
            if self.headers.get(field):
                headers[field] = self.headers[field]
        request = http.client.HTTPSConnection("localhost", origin.server_port, context=origin_trust, timeout=10)
        try:
            request.connect()
            peer = hashlib.sha256(request.sock.getpeercert(binary_form=True)).hexdigest()
            request.request(self.command, self.path, body=self.rfile.read(length) if length else None, headers=headers)
            upstream = request.getresponse()
            data = upstream.read()
            note("gateway", ingress=self.headers["Host"], origin="origin.example", origin_port=origin.server_port,
                 origin_certificate_sha256=peer, method=self.command, path=self.path, status=upstream.status)
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
        note("tls", role=role, sni=name, port=server.server_port)
        if name != (HOST if role == "gateway" else "localhost"):
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
    tls(origin, "origin", "origin")
    tls(gateway, "gateway", "gateway")
    for server in (dns, origin, gateway):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        subprocess.run([sys.argv[2], str(Path(__file__).with_name("browser.mjs")), sys.argv[3], str(ROOT), RUN],
                       check=True, timeout=65)
        browser = json.loads((ROOT / "browser.json").read_text())
        require(browser["typed"] == "https://lab.example", "typed address")
        require(browser["denied"] == 403 and len(browser["trials"]) == len(CASES), "authorization and all trials")
        require(any(r["layer"] == "dns" and r["answer"] == "127.0.0.1" for r in RECEIPTS), "real DNS query and answer")
        require(any(r["layer"] == "tls" and r["role"] == "gateway" and r["sni"] == HOST and r["port"] == 443
                    for r in RECEIPTS), "gateway SNI over TCP 443")
        require(any(r["layer"] == "tls" and r["role"] == "origin" for r in RECEIPTS), "separate origin TLS")
        require(any(r["layer"] == "origin" and r["path"] == "/app.js" and r["status"] == 200 for r in RECEIPTS),
                "actual origin asset")
        for identifier, evidence in browser["trials"].items():
            label, mode = CASES[identifier]
            observed = evidence["result"]
            require(evidence["page"] == "Simulation" and evidence["status"] == 200, f"{identifier}: loaded and posted")
            require(evidence["security"]["protocol"].startswith("TLS") and evidence["security"]["subjectName"] == HOST
                    and evidence["security"]["issuer"] == "Commonwealth Step 11 Fixture CA", f"{identifier}: trusted certificate")
            require(observed["run_id"] == RUN and observed["trial_id"] == identifier, f"{identifier}: correlation")
            require(observed == trial(RUN, identifier, label, mode), f"{identifier}: deterministic replay")
            require(observed["terminal"] == {"missing": "classical_bits_expired", "unavailable": "quantum_link_unavailable"}
                    .get(mode, "measured"), f"{identifier}: expected terminal")
        note("gate", revision=os.environ["GITHUB_SHA"], verdict="PASS",
             scope=["browser_network_fixture", "simulated_quantum_workflow"], trials=len(CASES))
    finally:
        for server in (dns, origin, gateway):
            server.shutdown()
