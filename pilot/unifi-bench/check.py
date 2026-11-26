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

from copy import deepcopy
import time
from signed_readback import issue

with tempfile.TemporaryDirectory() as directory:
    private, public, payload, signature = (Path(directory) / n for n in ("key", "pub", "body", "sig"))
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private], check=True, timeout=5)
    subprocess.run(["openssl", "pkey", "-in", private, "-pubout", "-out", public], check=True, timeout=5)
    target = {"edge": "synthetic-edge", "ap": uid(21), "credential": "shared-ab",
              "generation": 7, "vlan": 101, "interface": "guest101", "subnet": "10.77.101.0/24"}
    fresh = {"nonce": "a" * 48, "epoch": 1, "kind": "admit", "expires_at": int(time.time()) + 30}

    def observe(subject, challenge):
        observations, conflicts = evaluate(config, networks, broadcasts, devices, clients)
        assert observations[0]["ap_id"] == subject["ap"]
        stations = {role: {"mac": f"02:00:00:00:00:0{i}", "ipv4": f"192.0.2.{i}", "vlan": vlan}
                    for i, (role, vlan) in enumerate(zip("ABC", (101, 101, 102)), 1)}
        return {"target": subject, "challenge": challenge, "complete_inventory": True,
                "authenticated_ap": True, "single_personal_psk": True, "conflicts": conflicts,
                "vlan_credentials": ["shared-ab"], "future_admission": "allowed", "stations": stations,
                "tags": {role: {"station": deepcopy(station), "observed_at": time.time()}
                         for role, station in stations.items()}}

    def verified():
        envelope = issue(target, lambda: fresh, observe, private)
        payload.write_text(json.dumps(envelope["body"], sort_keys=True, separators=(",", ":")))
        signature.write_bytes(bytes.fromhex(envelope["signature"]))
        subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                        "-in", payload, "-sigfile", signature], check=True, capture_output=True, timeout=5)
        assert envelope["body"] == {**target, **fresh, "future_admission": "allowed", "vlan_credentials": ["shared-ab"]}
        return envelope["body"]

    admitted = verified()
    fresh.update(nonce="b" * 48, epoch=2, kind="renew")
    renewed = verified()
    assert admitted["nonce"] != renewed["nonce"] and admitted["epoch"] < renewed["epoch"]
    rejected = []
    for field, value in {"complete_inventory": False, "authenticated_ap": False,
                         "single_personal_psk": False, "conflicts": ["another broadcast"],
                         "future_admission": "denied", "target": {**target, "generation": 6},
                         "challenge": {**fresh, "epoch": 1}, "tags": {}}.items():
        try:
            issue(target, lambda: fresh, lambda *args: {**observe(*args), field: value}, private)
        except ValueError:
            rejected.append(field)
        else:
            raise AssertionError("unsafe synthetic proof signed: " + field)
    print(json.dumps({"scope": "synthetic signer, separate from authentic controller receipt",
                      "signed_and_verified": [admitted, renewed], "rejected": rejected,
                      "physical_adapter": "BLOCKED_AP_APPLIED_EVIDENCE"}))


# Exercise the receipt checker with synthetic records. No device access occurs.
from hashlib import sha256
from check_receipts import DATASETS, digest, score

site = uid(40)
pin = "1" * 64
controller_config = {**config, "site_id": site, "certificate_sha256": pin}
bench_config = {"trunk": "eth0", "approval_ref": "synthetic", "stations": []}
tagged_receipt = {"scope": "physical_bench_observation_only", "field_acceptance": "UNVERIFIED",
                  "activation": "HELD", "trunk": {"interface": "eth0", "observed": True},
                  "machine": "aarch64", "model": "Raspberry Pi 4 synthetic", "memory_kib": 8000000,
                  "tagged_dataplane": "CORROBORATED", "received_tags": [],
                  "blockers": ["controller/AP applied membership and field decision require independent review"]}
for index, (role, group) in enumerate(zip("ABC", [groups[0], groups[0], groups[1]]), 1):
    mac, ip, vlan = f"02:00:00:00:00:0{index}", f"192.0.2.{index}", group["vlan_id"]
    client = uid(30 + index)
    clients[client].update(macAddress=mac, ipAddress=ip)
    bench_config["stations"].append({"role": role, "mac": mac, "source_ipv4": ip, "vlan": vlan, "client_id": client})
    packet = (f"12:00:00.123456 {mac} > 02:00:00:00:00:ff, ethertype 802.1Q (0x8100), length 98: "
              f"vlan {vlan}, p 0, ethertype IPv4 (0x0800), {ip} > 192.0.2.254: ICMP echo request")
    tagged_receipt["received_tags"].append(
        {"role": role, "mac": mac, "ipv4": ip, "vlan": vlan, "window_started": 110 + index,
         "observed_at": 110.5 + index, "record": packet, "sha256": sha256(packet.encode()).hexdigest()})
tagged_receipt["bench_config_sha256"] = digest(bench_config)
observations, conflicts = evaluate(controller_config, networks, broadcasts, devices, clients)
assert not conflicts
controller_receipt = {"scope": "read_only_unifi_local_api", "guard_readback_issued": False,
                      "configuration_consistent": True, "failures": [], "config_sha256": digest(controller_config),
                      "started_at": 100, "finished_at": 110, "configuration_observations": observations}
counts = dict(zip(DATASETS, [2, 2, 1, 3]))
controller_receipt["inventory"] = {
    name: {"total": total, "pages": [{"offset": 0, "count": total, "total": total}]}
    for name, total in counts.items()}
paths = [f"/sites/{site}/{name}?offset=0&limit=100" for name in DATASETS]
paths.extend(f"/sites/{site}/clients/{uid(i)}" for i in (31, 32, 33))
controller_receipt["requests"] = [{"path": path, "status": 200, "certificate_sha256": pin} for path in paths]
controller_hash = digest(controller_receipt)
tagged_receipt["controller_receipt_sha256"] = controller_hash

bad_packet = deepcopy(tagged_receipt)
row = bad_packet["received_tags"][0]
row["record"] = row["record"].replace("vlan 101,", "vlan 999,")
row["sha256"] = sha256(row["record"].encode()).hexdigest()

bad_pages = deepcopy(controller_receipt)
bad_pages["inventory"]["networks"]["pages"][0]["count"] = 1

stale = deepcopy(tagged_receipt)
for row in stale["received_tags"]:
    row["window_started"] += 40
    row["observed_at"] += 40

receipt_cases = [
    ("both_consistent", controller_receipt, tagged_receipt, ("PASS", "PASS", "PASS")),
    ("missing_inventory", {}, tagged_receipt, ("UNVERIFIED", "PASS", "UNVERIFIED")),
    ("incomplete_pagination", bad_pages, tagged_receipt, ("UNVERIFIED", "PASS", "UNVERIFIED")),
    ("missing_tags", controller_receipt, {}, ("PASS", "UNVERIFIED", "UNVERIFIED")),
    ("wrong_tag_with_matching_checksum", controller_receipt, bad_packet, ("PASS", "UNVERIFIED", "UNVERIFIED")),
    ("other_controller_receipt", controller_receipt,
     {**tagged_receipt, "controller_receipt_sha256": "0" * 64}, ("PASS", "PASS", "UNVERIFIED")),
    ("outside_controller_window", controller_receipt, stale, ("PASS", "PASS", "UNVERIFIED")),
]
reports = {}
for name, controller_case, bench_case, expected in receipt_cases:
    report = score(controller_config, bench_config, controller_case, controller_hash, bench_case, 200)
    assert tuple(report[key]["verdict"] for key in ("controller_inventory", "tagged_dataplane", "correlation")) == expected, report
    assert report["signed_admission"] == "HELD"
    reports[name] = report
print(json.dumps({"scope": "synthetic offline receipt checks", "receipt_checks": reports}))
