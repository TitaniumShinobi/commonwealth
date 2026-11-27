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
        if self.path.startswith("/proxy/network/integration/v1/sites?"):
            result = b'{"count":0,"offset":0,"totalCount":0,"data":[]}'
        else:
            path = self.path.removeprefix(f"/proxy/network/integration/v1/sites/{site}/")
            name, query = path.split("?", 1) if "?" in path else (path, "")
            datasets = dict(zip(DATASETS, (networks, broadcasts, devices, clients)))
            if name in datasets and query == "offset=0&limit=100":
                rows = [{"id": key, **row} for key, row in datasets[name].items()]
                body = {"offset": 0, "limit": 100, "count": len(rows), "totalCount": len(rows), "data": rows}
            elif name.startswith("clients/") and not query and name[8:] in clients:
                body = {"id": name[8:], **clients[name[8:]]}
            else:
                self.send_error(404)
                return
            result = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


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

def setup_tagged_links():
    for command in (("link", "add", "cwtag-tx", "type", "veth", "peer", "name", "cwtag-rx"),
                    ("link", "set", "cwtag-tx", "up"), ("link", "set", "cwtag-rx", "up")):
        subprocess.run(["ip", *command], check=True, timeout=5)



def exercise_tagged_flow(root, controller_path, secret_path, case, sent_vlans, expected_tags):
    import os
    import socket
    import struct

    config_path = root / f"{case}-bench.json"
    config_path.write_text(json.dumps({**bench_config, "trunk": "cwtag-rx"}))
    secret_path.write_text("synthetic-fixture-only")
    output = root / case
    stop = threading.Event()
    sent = {role: 0 for role in "ABC"}

    def traffic():
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as wire:
            wire.bind(("cwtag-tx", 0))
            while not stop.is_set():
                for row in bench_config["stations"]:
                    role = row["role"]
                    if role not in sent_vlans:
                        continue
                    mac = bytes.fromhex(row["mac"].replace(":", ""))
                    ethernet = b"\xff" * 6 + mac + struct.pack("!HHH", 0x8100, sent_vlans[role], 0x0800)
                    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0,
                                       socket.inet_aton(row["source_ipv4"]), socket.inet_aton("192.0.2.254"))
                    words = struct.unpack("!10H", ipv4)
                    checksum = sum(words)
                    while checksum >> 16:
                        checksum = (checksum & 0xffff) + (checksum >> 16)
                    ipv4 = ipv4[:10] + struct.pack("!H", checksum ^ 0xffff) + ipv4[12:]
                    wire.send(ethernet + ipv4 + struct.pack("!HHHH", 9001, 9002, 8, 0))
                    sent[role] += 1
                stop.wait(0.05)

    sender = threading.Thread(target=traffic)
    sender.start()
    wrong_vlan_frame = None
    try:
        if sent_vlans.get("B") == 999:
            witness = subprocess.run(
                ["tcpdump", "-Q", "in", "-nn", "-e", "-s", "96", "-c", "1", "-i", "cwtag-rx",
                 "ether src 02:00:00:00:00:02 and vlan 999 and ip and src host 192.0.2.2"],
                check=True, capture_output=True, text=True, timeout=5)
            wrong_vlan_frame = witness.stdout.strip()
            assert "vlan 999," in wrong_vlan_frame, wrong_vlan_frame
        execution = subprocess.run(["bash", Path(__file__).with_name("operator.sh"),
                                    controller_path, secret_path, config_path, output],
                                   env={**os.environ, "CW_U7_TAGGED_FIXTURE": "1"},
                                   capture_output=True, text=True, timeout=55)
    finally:
        stop.set()
        sender.join()
    assert execution.returncode == 2, execution.stderr
    result = json.loads((output / "receipt-score.json").read_text())
    complete = len(expected_tags) == 3
    assert result["controller_inventory"]["verdict"] == "PASS", result
    for name in ("tagged_dataplane", "correlation"):
        assert result[name]["verdict"] == ("PASS" if complete else "UNVERIFIED"), (result, execution.stderr)
    assert result["signed_admission"] == "HELD"
    capture = json.loads((output / "tagged-bench.json").read_text())
    tags = capture["received_tags"]
    assert [(row["role"], row["vlan"]) for row in tags] == expected_tags, capture
    assert all(row["record"] for row in tags)
    assert all((count > 0) == (role in sent_vlans) for role, count in sent.items()), sent
    if not complete:
        timed_out_role = "ABC"[len(expected_tags)]
        assert f"Send separately approved IPv4 traffic from station {timed_out_role} now" in execution.stderr
        assert any("timed out after 15 seconds" in blocker for blocker in capture["blockers"]), capture
    print(json.dumps({"scope": "synthetic isolated kernel veth and TLS controller",
                      "case": case, "full_operator_flow": result, "exit": execution.returncode,
                      "sent_frames": sent, "sent_vlans": sent_vlans, "wrong_vlan_witness": wrong_vlan_frame,
                      "capture_blockers": capture["blockers"], "packets": tags}, sort_keys=True))
    return output, config_path


def reject_mixed_sessions(controller_config, first, second, *, case):
    import sys

    first_output, _ = first
    second_output, bench_config_path = second
    first_receipt = first_output / "controller-readback.json"
    second_receipt = second_output / "controller-readback.json"
    second_tags = second_output / "tagged-bench.json"
    first_hash = sha256(first_receipt.read_bytes()).hexdigest()
    second_hash = sha256(second_receipt.read_bytes()).hexdigest()
    tags = json.loads(second_tags.read_text())
    assert first_hash != second_hash and tags["controller_receipt_sha256"] == second_hash
    controller = json.loads(first_receipt.read_text())
    expected_stations = {row["client_id"]: (row["mac"], row["ipv4"], row["vlan"])
                         for group in controller["configuration_observations"] for row in group["stations"]}
    bench = json.loads(bench_config_path.read_text())
    identity_mismatches = [row["role"] for row in bench["stations"]
                           if expected_stations[row["client_id"]] != (row["mac"], row["source_ipv4"], row["vlan"])]
    assert identity_mismatches == (["B"] if case == "mixed_station_identity_matching_hash" else [])
    if case != "mixed_valid_operator_runs":
        # Rebind only the enclosing receipt hash. Preserve the real captures and timestamps.
        tags["controller_receipt_sha256"] = first_hash
        second_tags = second_output / "matching-hash-mixed-tags.json"
        second_tags.write_text(json.dumps(tags))
    first_finished = controller["finished_at"]
    second_capture_start = tags["received_tags"][0]["window_started"]
    age_seconds = second_capture_start - first_finished
    if case == "mixed_capture_outside_window_matching_hash":
        assert age_seconds > 30, "capture must exceed the correlation time bound"
    else:
        assert 0 <= age_seconds <= 30, "keep both runs within the correlation time bound"

    execution = subprocess.run([sys.executable, Path(__file__).with_name("check_receipts.py"),
                                controller_config, bench_config_path, first_receipt, second_tags],
                               capture_output=True, text=True, check=False, timeout=10)
    assert execution.returncode == 2, execution.stderr
    report = json.loads(execution.stdout)
    assert report["controller_inventory"]["verdict"] == "PASS", report
    assert report["tagged_dataplane"]["verdict"] == "PASS", report
    assert report["correlation"]["verdict"] == "UNVERIFIED", report
    assert report["signed_admission"] == "HELD", report
    print(json.dumps({"case": case, "exit": execution.returncode, "score": report,
                      "controller_sha256": first_hash,
                      "capture_original_controller_sha256": second_hash,
                      "capture_bound_controller_sha256": tags["controller_receipt_sha256"],
                      "identity_mismatches": identity_mismatches, "controller_to_capture_seconds": age_seconds,
                      "controller_finished_at": first_finished, "capture_started_at": second_capture_start},
                     sort_keys=True))



import sys
isolated_mode = sys.argv[1:] == ["--isolated-tagged-flow"]
if isolated_mode:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)

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
        controller_path = root / "controller.json"
        controller_path.write_text(json.dumps({**controller_config, **target,
                                               "design": "one-psk-per-ssid-review-alternative"}))
        bench_path = root / "bench.json"
        bench_path.write_text(json.dumps({**bench_config, "trunk": "lo"}))
        secret_path = root / "api-key"
        secret_path.touch(mode=0o600)
        if isolated_mode:
            setup_tagged_links()
            expected_vlans = {"A": 101, "B": 101, "C": 102}
            expected_tags = list(expected_vlans.items())
            first = exercise_tagged_flow(root, controller_path, secret_path,
                                         "all_expected_tags", expected_vlans, expected_tags)
            second = exercise_tagged_flow(root, controller_path, secret_path,
                                          "all_expected_tags_second_run", expected_vlans, expected_tags)
            reject_mixed_sessions(controller_path, first, second, case="mixed_valid_operator_runs")
            station_b = next(row for row in bench_config["stations"] if row["role"] == "B")
            original_mac = station_b["mac"]
            changed_mac = "02:00:00:00:00:12"
            client_b = clients[station_b["client_id"]]
            try:
                station_b["mac"] = client_b["macAddress"] = changed_mac
                changed = exercise_tagged_flow(root, controller_path, secret_path,
                                               "different_b_identity", expected_vlans, expected_tags)
                reject_mixed_sessions(controller_path, first, changed, case="mixed_station_identity_matching_hash")
            finally:
                station_b["mac"] = client_b["macAddress"] = original_mac
            for case, vlans, expected in (
                ("wrong_b_and_missing_c", {"A": 101, "B": 999}, [("A", 101)]),
                ("missing_c", {"A": 101, "B": 101}, [("A", 101), ("B", 101)]),
            ):
                exercise_tagged_flow(root, controller_path, secret_path, case, vlans, expected)
            # The two negative captures each spent 15 seconds waiting for an expected frame.
            # Collect a new valid pair and retain its actual clock readings.
            late = exercise_tagged_flow(root, controller_path, secret_path,
                                        "all_expected_tags_later_run", expected_vlans, expected_tags)
            reject_mixed_sessions(controller_path, first, late, case="mixed_capture_outside_window_matching_hash")
            raise SystemExit(0)
        reports = {}
        for name, credential, configuration, expected_inventory, has_capture in (
            ("capture_incomplete", "synthetic-fixture-only", bench_path, "PASS", True),
            ("controller_denied", "wrong", bench_path, "UNVERIFIED", False),
            ("capture_receipt_absent", "synthetic-fixture-only", root / "missing.json", "PASS", False),
        ):
            secret_path.write_text(credential)
            output = root / name
            execution = subprocess.run(["bash", Path(__file__).with_name("operator.sh"),
                                        controller_path, secret_path, configuration, output],
                                       capture_output=True, text=True, timeout=20)
            assert execution.returncode == 2, execution.stderr
            score_report = json.loads((output / "receipt-score.json").read_text())
            assert score_report["controller_inventory"]["verdict"] == expected_inventory
            assert score_report["tagged_dataplane"]["verdict"] == "UNVERIFIED"
            assert score_report["correlation"]["verdict"] == "UNVERIFIED"
            assert score_report["signed_admission"] == "HELD"
            assert (output / "tagged-bench.json").exists() == has_capture
            if has_capture:
                capture = json.loads((output / "tagged-bench.json").read_text())
                assert capture["received_tags"] == []
                assert "8GB Pi 4 native ARM64 hardware not demonstrated" in capture["blockers"]
            reports[name] = {"exit": execution.returncode, "capture_receipt_written": has_capture,
                             **score_report}
        print(json.dumps({"scope": "operator CLI with isolated TLS fixture and real bench preflight",
                          "operator_flow": reports}))
    finally:
        server.shutdown()
        thread.join()


# RouterOS registration parser fixture derived from the documented detail layout.
from routeros_readback import match as match_routeros, registrations

routeros_stations = [
    {"role": role, "mac": f"02:00:00:00:00:0{index}", "vlan": vlan, "credential_comment": label,
     "interface": "wifi1", "ssid": "Bench"}
    for index, (role, vlan, label) in enumerate(zip("ABC", (101, 101, 102), ("shared", "shared", "control")), 1)
]
routeros_detail = "Flags: A - AUTHORIZED\n" + "\n".join(
    f'{index} A ;;; {row["credential_comment"]}\n'
    f'    interface=wifi1 ssid="Bench" mac-address={row["mac"]}\n'
    f'    auth-type=wpa2-psk vlan-id={row["vlan"]}'
    for index, row in enumerate(routeros_stations))
assert set(match_routeros(routeros_stations, registrations(routeros_detail))) == {"A", "B", "C"}
routeros_rejected = []
for name, detail in (
    ("missing_applied_vlan", routeros_detail.replace(" vlan-id=101", "", 1)),
    ("wrong_vlan", routeros_detail.replace("vlan-id=101", "vlan-id=999", 1)),
    ("wrong_comment", routeros_detail.replace(";;; shared", ";;; different", 1)),
    ("missing_comment", routeros_detail.replace(" ;;; shared", "", 1)),
    ("duplicate_station", routeros_detail.replace("00:03", "00:02", 1)),
    ("unauthorized", routeros_detail.replace("0 A", "0  ", 1)),
):
    try:
        match_routeros(routeros_stations, registrations(detail))
    except ValueError:
        routeros_rejected.append(name)
    else:
        raise AssertionError(name)
print(json.dumps({"scope": "synthetic RouterOS registration transcript", "registration": "PASS",
                  "rejected": routeros_rejected, "signed_admission": "HELD"}))

if not isolated_mode:
    import shutil

    if not shutil.which("tcpdump"):
        subprocess.run(["sudo", "-n", "apt-get", "install", "-y", "-qq", "tcpdump"],
                       check=True, timeout=90)
    subprocess.run(["sudo", "-n", "unshare", "--net", sys.executable, __file__, "--isolated-tagged-flow"],
                   check=True, timeout=75)
