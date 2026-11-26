"""Synthetic contract checks. These fixtures are not vendor or AP evidence."""
import contextlib
import http.server
import json
import ssl
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from readback import Controller, evaluate


def uid(i):
    return str(uuid.UUID(int=i))


groups = [
    {"credential_ref": "shared-ab", "broadcast_id": uid(1), "network_id": uid(11), "ap_id": uid(21),
     "vlan_id": 101, "client_ids": [uid(31), uid(32)], "reviewed_network_type": "STATIC_FIXTURE",
     "reviewed_ap_filter_type": "EXACT_DEVICES_FIXTURE", "reviewed_personal_security_type": "WPA_PERSONAL_FIXTURE"},
    {"credential_ref": "independent-c", "broadcast_id": uid(2), "network_id": uid(12), "ap_id": uid(21),
     "vlan_id": 102, "client_ids": [uid(33)], "reviewed_network_type": "STATIC_FIXTURE",
     "reviewed_ap_filter_type": "EXACT_DEVICES_FIXTURE", "reviewed_personal_security_type": "WPA_PERSONAL_FIXTURE"},
]
config = {"groups": groups, "reviewed_static_network_type": "STATIC_FIXTURE"}
networks = {g["network_id"]: {"vlanId": g["vlan_id"], "enabled": True} for g in groups}
broadcasts = {g["broadcast_id"]: {"enabled": True,
              "network": {"networkId": g["network_id"], "type": g["reviewed_network_type"]},
              "broadcastingDeviceFilter": {"type": g["reviewed_ap_filter_type"], "deviceIds": [g["ap_id"]]},
              "securityConfiguration": {"type": g["reviewed_personal_security_type"]}} for g in groups}
devices = {uid(21): {"state": "ONLINE", "firmwareVersion": "synthetic"}}
clients = {i: {"access": {"authorized": True}, "uplinkDeviceId": uid(21)}
           for group in groups for i in group["client_ids"]}
assert not evaluate(config, networks, broadcasts, devices, clients)[1]
conflicting = {**broadcasts, uid(3): {**broadcasts[uid(1)]}}
assert any("conflicting" in error for error in evaluate(config, networks, conflicting, devices, clients)[1])
unknown = {**broadcasts, uid(3): {"enabled": True, "network": {"type": "RADIUS_FIXTURE"}}}
assert any("unresolved" in error for error in evaluate(config, networks, unknown, devices, clients)[1])
assert any("duplicate" in error for error in evaluate(config,
    {**networks, uid(99): {"enabled": True, "vlanId": 101}}, broadcasts, devices, clients)[1])
moved = {**clients, uid(31): {"access": {"authorized": True}, "uplinkDeviceId": uid(22)}}
assert any("uplink mismatch" in error for error in evaluate(config, networks, broadcasts, devices, moved)[1])


class Endpoint(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.headers["X-API-Key"] != "synthetic-fixture-only":
            self.send_error(401)
            return
        if not self.path.startswith("/proxy/network/integration/v1/sites?"):
            self.send_error(404)
            return
        result = b'{"count":0,"offset":0,"totalCount":0,"data":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


with tempfile.TemporaryDirectory() as path, http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint) as server:
    root = Path(path)
    cert, key = root / "cert", root / "key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", key, "-out", cert], capture_output=True, check=True, timeout=5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        import hashlib
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        target = {"address": "127.0.0.1", "tls_name": "localhost", "port": server.server_port,
                  "prefix": "/proxy/network/integration/v1", "certificate_sha256": pin, "ca_file": str(cert)}
        assert Controller(target, "synthetic-fixture-only").complete("/sites") == {}
        with contextlib.suppress(RuntimeError):
            Controller(target, "wrong").complete("/sites")
            raise AssertionError("incorrect API key accepted")
        with contextlib.suppress(ValueError):
            Controller({**target, "certificate_sha256": "0" * 64}, "synthetic-fixture-only").complete("/sites")
            raise AssertionError("incorrect TLS pin accepted")
    finally:
        server.shutdown()
        thread.join()
print(json.dumps({"scope": "synthetic adapter and local TLS fixture", "verdict": "PASS",
                  "configuration_conflicts": 4, "transport_tests": 3, "physical_readback": "UNVERIFIED"}))
