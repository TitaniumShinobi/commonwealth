"""Namespace AP fixture. Signed readback is synthetic; VLAN enforcement is Linux."""
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import tempfile
from pathlib import Path

from commonwealth_sim.namespace_pilot import Fixture
from edge import encode, fingerprint, openssl
from policy import table_name, withdraw_transaction

TARGET = {"ap": "fixture-ap", "edge": "fixture-edge", "credential": "shared-guest", "generation": 7,
          "vlan": 101, "stations": ["A", "B"]}
ADDRESSES = {"a": "10.77.101.20", "b": "10.77.101.21", "c": "10.77.102.20"}
SERVER = """
import socket,sys,threading,json
server=socket.socket()
server.bind(('203.0.113.2',8090))
server.listen()
clients=[]
received={}
lock=threading.Lock()
def loop(client, source):
    with client:
        while item:=client.recv(1):
            with lock: received[source]=received.get(source,0)+len(item)
            client.sendall(item)
def accept():
    while True:
        client,address=server.accept()
        clients.append((client,address[0]))
        threading.Thread(target=loop,args=(client,address[0]),daemon=True).start()
threading.Thread(target=accept,daemon=True).start()
print('ready',flush=True)
for line in sys.stdin:
    if line.strip()=='stats':
        with lock: print(json.dumps(received),flush=True)
        continue
    sent={}
    for client,source in clients:
        try:
            client.sendall(b'p')
            sent[source]=sent.get(source,0)+1
        except OSError: pass
    print(json.dumps(sent),flush=True)
"""
CLIENT = """
import socket,sys
s=socket.create_connection(('203.0.113.2',8090),2)
s.settimeout(0.7)
print('ready',flush=True)
for line in sys.stdin:
    try:
        if line.strip()=='echo': s.sendall(b'x')
        item=s.recv(1)
        print(item.decode() or 'closed',flush=True)
    except OSError:
        print('blocked',flush=True)
"""


CONTINUITY = """
import json,select,socket,sys,time
observations=[]
while len(observations)<200:
    if select.select([sys.stdin],[],[],0.12)[0]:
        break
    start=time.monotonic()
    try:
        with socket.create_connection(('203.0.113.2',8090),0.65) as conn:
            conn.settimeout(0.65)
            conn.sendall(b'c')
            live=conn.recv(1)==b'c'
    except OSError:
        live=False
    observations.append({"started":start,"elapsed":time.monotonic()-start,"fresh_echo":live})
    if len(observations)==1:
        print('sampled',flush=True)
print(json.dumps(observations),flush=True)
"""


def sign(key, body):
    with tempfile.TemporaryDirectory() as work:
        payload = Path(work) / "statement"
        payload.write_bytes(encode(body))
        return {"body": body, "signature": openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", payload).hex()}


def verify(public, envelope, expected):
    if envelope["body"] != expected:
        raise ValueError("scope_or_current_readback_mismatch")
    with tempfile.TemporaryDirectory() as work:
        payload, signature = (Path(work) / part for part in ("statement", "signature"))
        payload.write_bytes(encode(expected))
        signature.write_bytes(bytes.fromhex(envelope["signature"]))
        openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public, "-in", payload, "-sigfile", signature)


def keypair(work, role):
    private, public = (work / f"{role}.{suffix}" for suffix in ("key", "pub"))
    private.touch(mode=0o600)
    private.write_bytes(openssl("genpkey", "-algorithm", "Ed25519"))
    public.write_bytes(openssl("pkey", "-in", private, "-pubout"))
    return private, public


def persist(path, value):
    with path.open("x") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def associate(ap_state):
    state = json.loads(ap_state.read_text())
    return state["future_admission"] == "allowed"


def admit(operator_public, ap_public, request, readback, nonce, withdrawn):
    verify(operator_public, request, {**TARGET, "intent": "admit"})
    if withdrawn.exists():
        verify(operator_public, json.loads(withdrawn.read_text()), {**TARGET, "intent": "withdraw"})
        raise ValueError("credential_withdrawn")
    if readback is None:
        raise ValueError("no_ap_readback")
    verify(ap_public, readback, {**TARGET, "nonce": nonce, "future_admission": "allowed",
                                "vlan_credentials": [TARGET["credential"]]})
    return True


def open_rules():
    return """destroy table inet wifi_policy
table inet wifi_policy {
 chain routed {
   type filter hook forward priority filter; policy drop;
   iifname { "guest101", "guest102" } oifname "wan0" ip daddr 203.0.113.2 tcp dport 8090 ct state new,established accept
   iifname "wan0" oifname { "guest101", "guest102" } ip saddr 203.0.113.2 tcp sport 8090 ct state established accept
 }
}
"""


def guard(block):
    return """destroy table inet wifi_guard
table inet wifi_guard {
 chain ingress {
   type filter hook prerouting priority -310; policy accept;
   %s
 }
 chain routed {
   type filter hook forward priority -100; policy accept;
   %s
 }
}
""" % (('iifname "guest101" counter drop\n'
        'iifname "wan0" ip daddr 10.77.101.0/24 counter drop') if block else '',
       'oifname "guest101" counter drop' if block else '')


def run(out):
    f = Fixture({})
    output = Path(out)
    output.mkdir(parents=True)
    out = output / "receipt.json"
    evidence = {"revision": os.environ["GITHUB_SHA"], "scope": "synthetic AP signed-readback with kernel VLAN data plane",
                "checks": f.checks}
    with tempfile.TemporaryDirectory(prefix="cw-wifi-keys-") as directory:
        work = Path(directory)
        operator, operator_public = keypair(work, "operator")
        ap, ap_public = keypair(work, "ap")
        revoked, ap_state = (work / part for part in ("withdrawn.json", "ap-state.json"))
        evidence["trust_pins"] = {"operator": fingerprint(operator_public), "fixture_ap": fingerprint(ap_public)}
        evidence["target"] = TARGET
        def expect(case, expected, observed):
            f.check(case, expected, observed)
            if not f.checks[-1]["matches"]:
                raise RuntimeError(case)
        def r(ns, *args):
            return f.run(*args, namespace=ns).stdout
        def client_action(process, action):
            process.stdin.write(action + "\n")
            process.stdin.flush()
            return f.line(process)
        edge = "g"
        def tracking():
            return r(edge, "conntrack", "-L", "-p", "tcp", "-d", "203.0.113.2", "--dport", "8090")
        def ap_readback(nonce):
            result = subprocess.check_output([sys.executable, __file__, "--ap-readback", str(ap), str(ap_state), nonce],
                                             text=True, timeout=5)
            return json.loads(result)
        def admission(readback, challenge):
            try:
                return admit(operator_public, ap_public, approval, readback, challenge, revoked)
            except (ValueError, OSError, subprocess.SubprocessError):
                return False
        def reconstruct_guard():
            return subprocess.check_output([sys.executable, __file__, "--recover-guard",
                                            str(operator_public), str(revoked)], text=True, timeout=5)
        def denied_fresh(role):
            code = ("import socket; socket.create_connection(('203.0.113.2',8090),0.6).close()")
            return f.run(sys.executable, "-c", code, namespace=role, check=False).returncode != 0
        try:
            for role in ("a", "b", "c", "ap", "g", "w"):
                f.create(role)
            f.wire("ap", "g", 0, "trunk", "trunk")
            f.wire("g", "w", 1, "wan0", "wan0")
            for index, role in enumerate(("a", "b", "c"), 2):
                f.wire("ap", role, index, "station" + role, "eth0")
            r("ap", "ip", "link", "add", "br0", "type", "bridge", "vlan_filtering", "1", "vlan_default_pvid", "0")
            r("ap", "ip", "link", "set", "br0", "up")
            for port, vlans in (("trunk", (101, 102)), ("stationa", (101,)), ("stationb", (101,)), ("stationc", (102,))):
                r("ap", "ip", "link", "set", port, "master", "br0")
                if port != "trunk":
                    r("ap", "bridge", "link", "set", "dev", port, "isolated", "on")
                for vlan in vlans:
                    tail = [] if port == "trunk" else ["pvid", "untagged"]
                    r("ap", "bridge", "vlan", "add", "dev", port, "vid", str(vlan), *tail)
            vlan_table = json.loads(r("ap", "bridge", "-j", "vlan", "show"))
            evidence["ap_vlan_table"] = vlan_table
            table = {row["ifname"]: [v["vlan"] for v in row["vlans"]] for row in vlan_table}
            expect("exclusive_kernel_station_vlan_membership", {"stationa": [101], "stationb": [101], "stationc": [102]},
                   {port: table.get(port) for port in ("stationa", "stationb", "stationc")})
            for vlan in (101, 102):
                device = f"guest{vlan}"
                r("g", "ip", "link", "add", "link", "trunk", "name", device, "type", "vlan", "id", str(vlan))
                f.address("g", device, f"10.77.{vlan}.1/24")
                r("g", "ip", "link", "set", device, "up")
            for role, ip in ADDRESSES.items():
                f.address(role, "eth0", ip + "/24")
                r(role, "ip", "route", "add", "default", "via", ip.rsplit(".", 1)[0] + ".1")
            f.address("g", "wan0", "203.0.113.1/24")
            f.address("w", "wan0", "203.0.113.2/24")
            r("w", "ip", "route", "add", "10.77.0.0/16", "via", "203.0.113.1")
            r("g", "sysctl", "-qw", "net.ipv4.ip_forward=1")
            rules = open_rules()
            f.program("g", guard(True))
            f.program("g", rules)
            approval = sign(operator, {**TARGET, "intent": "admit"})
            ap_state.write_text(json.dumps({"future_admission": "allowed", "vlan_credentials": [TARGET["credential"]]}))
            nonce = secrets.token_hex(16)
            current = ap_readback(nonce)
            evidence["pre_withdrawal_readback"] = current
            expect("missing_ap_readback_closed", False, admission(None, nonce))
            expect("stale_nonce_closed", False, admission(current, secrets.token_hex(16)))
            expect("mismatched_ap_vlan_closed", False, admission(sign(ap, {**current["body"], "vlan": 102}), nonce))
            expect("nonexclusive_ap_vlan_closed", False, admission(
                sign(ap, {**current["body"], "vlan_credentials": [TARGET["credential"], "other"]}), nonce))
            expect("forged_ap_readback_closed", False, admission(sign(operator, current["body"]), nonce))
            expect("current_ap_readback_admits", True, admission(current, nonce))
            f.program("g", guard(False))
            server = f.launch("w", SERVER)
            expect("origin_ready", "ready", f.line(server))
            guests = {role: f.launch(role, CLIENT) for role in ADDRESSES}
            for role, child in guests.items():
                expect(f"{role}_connected", "ready", f.line(child))
                expect(f"{role}_echo_before_withdrawal", "x", client_action(child, "echo"))
            for source, destination in (("a", "b"), ("b", "a")):
                expect(source + "_local_gateway_reachable", True, f.ping(source, "10.77.101.1"))
                expect(source + "_same_vlan_peer_isolated", False, f.ping(source, ADDRESSES[destination]))
            pushed_before = json.loads(client_action(server, "push"))
            expect("each_existing_socket_received_live_downstream_before_withdrawal", True,
                   all(pushed_before.get(ip, 0) >= 1 for ip in ADDRESSES.values()))
            for role in guests:
                expect(role + "_downstream_before_withdrawal", "p", client_action(guests[role], "read"))
            continuous = f.launch("c", CONTINUITY)
            expect("c_continuous_first_observation", "sampled", f.line(continuous))
            revoked_continuity = {role: f.launch(role, CONTINUITY) for role in ("a", "b")}
            for role, process in revoked_continuity.items():
                expect(role + "_boundary_probe_live", "sampled", f.line(process))
            before = tracking()
            evidence["conntrack_before"] = before.splitlines()
            expect("all_sessions_tracked", True, all(f"src={ip}" in before for ip in ADDRESSES.values()))
            server_before = json.loads(client_action(server, "stats"))
            crash_started = time.monotonic()
            boundary = work / "boundary-time.json"
            crash = subprocess.run([sys.executable, __file__, "--commit-then-crash", str(operator), str(revoked),
                                    f.prefix + "g", str(boundary)],
                                   check=False, timeout=5)
            expect("crash_after_durable_commit", 77, crash.returncode)
            expect("guard_installed_before_durable_commit", True,
                   'iifname "guest101" counter' in r("g", "nft", "list", "table", "inet", "wifi_guard"))
            evidence["signed_withdrawal"] = json.loads(revoked.read_text())
            evidence["withdrawal_boundary"] = json.loads(boundary.read_text())
            pushed_at_crash = json.loads(client_action(server, "push"))
            expect("origin_wrote_to_both_old_sockets_at_crash_boundary", True,
                   all(pushed_at_crash.get(ADDRESSES[role], 0) >= 1 for role in ("a", "b")))
            for role in ("a", "b"):
                expect(role + "_crash_boundary_inbound_blocked", "blocked", client_action(guests[role], "read"))
                expect(role + "_crash_boundary_outbound_blocked", "blocked", client_action(guests[role], "echo"))
            expect("c_crash_boundary_downstream_continues", "p", client_action(guests["c"], "read"))
            expect("origin_no_a_or_b_payload_after_commit_before_recovery",
                   [server_before.get(ADDRESSES[x], 0) for x in ("a", "b")],
                   [json.loads(client_action(server, "stats")).get(ADDRESSES[x], 0) for x in ("a", "b")])
            f.program("g", reconstruct_guard())
            for role in ("a", "b"):
                r("g", "conntrack", "-D", "-p", "tcp", "-s", ADDRESSES[role], "--dport", "8090")
            after = tracking()
            evidence["conntrack_after"] = after.splitlines()
            expect("only_unrelated_conntrack_remains", [False, False, True],
                   [f"src={ip}" in after for ip in ADDRESSES.values()])
            expect("c_conntrack_tuple_preserved", True, any(
                line.split("[ASSURED]")[0].split("src=", 1)[1] in after
                for line in before.splitlines() if f"src={ADDRESSES['c']}" in line))
            pushed_after = json.loads(client_action(server, "push"))
            evidence["downstream_origin_send_counts_after_guard"] = pushed_after
            expect("origin_wrote_to_existing_withdrawn_sockets", True,
                   all(pushed_after.get(ADDRESSES[role], 0) >= 1 for role in ("a", "b")))
            for role in ("a", "b"):
                expect(f"{role}_downstream_denied_with_association_retained", "blocked", client_action(guests[role], "read"))
                expect(f"{role}_upstream_denied_with_association_retained", "blocked", client_action(guests[role], "echo"))
            for role in ("a", "b"):
                expect(f"{role}_fresh_flow_denied", True, denied_fresh(role))
            server_after = json.loads(client_action(server, "stats"))
            expect("origin_received_no_withdrawn_payload", [server_before.get(ADDRESSES[x], 0) for x in ("a", "b")],
                   [server_after.get(ADDRESSES[x], 0) for x in ("a", "b")])
            expect("c_downstream_continues", "p", client_action(guests["c"], "read"))
            expect("c_upstream_continues", "x", client_action(guests["c"], "echo"))
            expect("kernel_ap_assignments_unchanged_eviction_withheld", vlan_table,
                   json.loads(r("ap", "bridge", "-j", "vlan", "show")))
            evidence["restart_and_rollback"] = []
            for action in ("policy_process_restart", "exact_rollback"):
                challenge = secrets.token_hex(16)
                expect(action + "_old_readback_and_admission_denied", False, admission(current, challenge))
                expect(action + "_fresh_readback_cannot_override_tombstone", False, admission(ap_readback(challenge), challenge))
                digest = f.program("g", rules)
                f.program("g", reconstruct_guard())
                evidence["restart_and_rollback"].append({"action": action, "baseline_sha256": digest})
                expect(action + "_a_still_blocked", "blocked", client_action(guests["a"], "echo"))
                expect(action + "_b_still_blocked", "blocked", client_action(guests["b"], "echo"))
                expect(action + "_c_still_live", "x", client_action(guests["c"], "echo"))
            rollback_finished = time.monotonic()
            time.sleep(0.35)
            continuous.stdin.write("stop\n")
            continuous.stdin.flush()
            samples = json.loads(f.line(continuous))
            evidence["c_continuity"] = {"sample_budget_seconds": 0.9, "crash_started": crash_started,
                                        "rollback_finished": rollback_finished, "samples": samples}
            expect("c_fresh_continuity_spans_crash_withdrawal_and_rollback", True,
                   len(samples) >= 5 and samples[0]["started"] <= crash_started
                   and samples[-1]["started"] >= rollback_finished)
            expect("c_no_failed_fresh_connection_or_gap_over_budget", True,
                   all(row["fresh_echo"] and row["elapsed"] <= 0.9 for row in samples)
                   and all(b["started"] - a["started"] <= 0.9 for a, b in zip(samples, samples[1:])))
            reverse = r("g", "conntrack", "-L", "-p", "tcp", "-s", "203.0.113.2", "--sport", "8090")
            expect("withdrawn_reverse_conntrack_not_recreated", False, any(
                f"dst={ADDRESSES[role]}" in reverse for role in ("a", "b")))
            evidence["withdrawn_probe_window"] = {}
            for role, process in revoked_continuity.items():
                process.stdin.write("stop\n")
                process.stdin.flush()
                observations = json.loads(f.line(process))
                committed = evidence["withdrawal_boundary"]["withdrawal_synced_at"]
                after = [entry for entry in observations if entry["started"] >= committed]
                expect(role + "_fresh_duplex_probe_blocked_across_commit_and_rollback", True,
                       observations[0]["fresh_echo"] and len(after) >= 3 and not any(row["fresh_echo"] for row in after))
                evidence["withdrawn_probe_window"][role] = {
                    "before_succeeded": sum(row["fresh_echo"] for row in observations if row["started"] < committed),
                    "after_denied": len(after), "first_after": after[0], "last_after": after[-1]}
            live_tracking = tracking()
            evidence["conntrack_live_after_rollback"] = live_tracking.splitlines()
            expect("withdrawn_conntrack_not_recreated_during_live_rollback", [False, False, True],
                   [f"src={ip}" in live_tracking for ip in ADDRESSES.values()])

            # This deliberately breaks the old routes and is scored separately from C continuity.
            evidence["reboot_recovery"] = {"scope": "fresh gateway namespace and fresh guard process"}
            f.create("g2")
            edge = "g2"
            r(edge, "sysctl", "-qw", "net.ipv4.ip_forward=0")
            r("ap", "ip", "link", "del", "trunk")
            r("w", "ip", "link", "del", "wan0")
            f.wire("ap", edge, 7, "trunk", "trunk")
            f.wire(edge, "w", 8, "wan0", "wan0")
            r("ap", "ip", "link", "set", "trunk", "master", "br0")
            for vlan in (101, 102):
                r("ap", "bridge", "vlan", "add", "dev", "trunk", "vid", str(vlan))
                device = f"guest{vlan}"
                r(edge, "ip", "link", "add", "link", "trunk", "name", device, "type", "vlan", "id", str(vlan))
                f.address(edge, device, f"10.77.{vlan}.1/24")
                r(edge, "ip", "link", "set", device, "up")
            f.address(edge, "wan0", "203.0.113.1/24")
            f.address("w", "wan0", "203.0.113.2/24")
            r("w", "ip", "route", "add", "10.77.0.0/16", "via", "203.0.113.1")
            for role in ADDRESSES:
                r(role, "ip", "neigh", "flush", "dev", "eth0")
            expect("reboot_forwarding_closed_before_policy", "0", r(edge, "sysctl", "-n", "net.ipv4.ip_forward").strip())
            expect("reboot_c_cannot_forward_before_startup", True, denied_fresh("c"))
            evidence["reboot_recovery"]["guard_sha256"] = f.program(edge, reconstruct_guard())
            evidence["reboot_recovery"]["baseline_sha256"] = f.program(edge, rules)
            expect("reboot_exact_original_baseline", evidence["restart_and_rollback"][-1]["baseline_sha256"],
                   evidence["reboot_recovery"]["baseline_sha256"])
            r(edge, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            for role in ("a", "b"):
                expect(f"reboot_{role}_fresh_denied", True, denied_fresh(role))
            recovered_c = f.launch("c", CLIENT)
            expect("reboot_c_new_connection_ready", "ready", f.line(recovered_c))
            expect("reboot_c_new_echo", "x", client_action(recovered_c, "echo"))
            service_target = {"edge": "fixture-edge", "ap": "fixture-ap", "credential": "shared-guest",
                              "generation": 7, "vlan": 101, "interface": "guest101", "subnet": "10.77.101.0/24"}
            configuration = work / "deployed-service.json"
            configuration.write_text(json.dumps({**service_target, "state": str(work / "deployed-state"), "registry": str(work / "guard-registry"),
                "operator_public": str(operator_public), "ap_public": str(ap_public),
                "operator_key_sha256": fingerprint(operator_public), "ap_key_sha256": fingerprint(ap_public)}))
            service = Path(__file__).with_name("policy.py")
            def service_command(operation, *args, check=True):
                return f.run("env", f"PYTHONPATH={service.resolve().parents[1] / 'activation'}",
                             sys.executable, str(service), operation, str(configuration), *map(str, args),
                             namespace=edge, check=check)
            expect("deployed_service_boot_closed", "completed",
                   json.loads(service_command("boot-closed").stdout)["result"])
            admit_envelope = work / "service-admit.json"
            admit_envelope.write_text(json.dumps(sign(operator, {**service_target, "intent": "admit"})))
            readback_envelope = work / "service-readback.json"
            service_challenge = json.loads(service_command("challenge").stdout.splitlines()[0])
            readback_envelope.write_text(json.dumps(sign(ap, {**service_target, **service_challenge,
                "future_admission": "allowed", "vlan_credentials": [service_target["credential"]]})))
            expect("deployed_service_authenticates_current_ap_readback", "completed",
                   json.loads(service_command("admit", "--approval", admit_envelope,
                                              "--readback", readback_envelope).stdout)["result"])
            expect("deployed_service_uses_timed_kernel_vlan_membership", True,
                   'elements = { "guest101" timeout' in r(edge, "nft", "list", "set", "inet", table_name(service_target), "live_vlan"))
            expect("deployed_service_rejects_replayed_challenge", True,
                   service_command("admit", "--approval", admit_envelope, "--readback", readback_envelope,
                                   check=False).returncode != 0)
            signed = work / "service-withdraw.json"
            signed.write_text(json.dumps(sign(operator, {**service_target, "intent": "withdraw"})))
            expect("deployed_service_withdraw", "completed",
                   json.loads(service_command("withdraw", "--approval", signed).stdout)["result"])
            expect("deployed_service_rejects_post_withdrawal_challenge", True,
                   service_command("challenge", check=False).returncode != 0)
            expect("deployed_service_preserves_unrelated_traffic", "x", client_action(recovered_c, "echo"))
            evidence["deployed_service_guard"] = r(edge, "nft", "list", "table", "inet", table_name(service_target))
            r(edge, "nft", "delete", "table", "inet", "wifi_guard")
            for role in ("a", "b"):
                expect(role + "_denied_with_only_deployed_guard", True, denied_fresh(role))
            base_service_config = json.loads(configuration.read_text())
            collision = {**base_service_config, "credential": "other-credential",
                         "state": str(work / "overlap-state")}
            configuration.write_text(json.dumps(collision))
            expect("same_vlan_subnet_interface_overlap_denied", True,
                   service_command("boot-closed", check=False).returncode != 0)
            collision = {**collision, "vlan": 103, "interface": "guest103", "subnet": "10.77.101.128/25"}
            configuration.write_text(json.dumps(collision))
            expect("different_vlan_overlapping_subnet_denied", True,
                   service_command("boot-closed", check=False).returncode != 0)
            configuration.write_text(json.dumps(base_service_config))
            # Qualify renewal on the actual live C VLAN with a separate operator state.
            renewal_target = {**service_target, "credential": "control-guest", "vlan": 102,
                              "interface": "guest102", "subnet": "10.77.102.0/24"}
            renewal_config = {**json.loads(configuration.read_text()), **renewal_target,
                              "state": str(work / "renewal-state"), "lease_seconds": 10}
            configuration.write_text(json.dumps(renewal_config))
            book = work / "renewal-state" / "live-until"
            def renewal_files(kind, issuer):
                operation = "renew-challenge" if kind == "renew" else "challenge"
                fresh = json.loads(service_command(operation).stdout.splitlines()[0])
                admit_envelope.write_text(json.dumps(sign(operator, {**renewal_target, "intent": kind})))
                readback_envelope.write_text(json.dumps(sign(issuer, {**renewal_target, **fresh,
                    "future_admission": "allowed", "vlan_credentials": [renewal_target["credential"]]})))
                return fresh
            def apply_lease(kind, check=True):
                return service_command(kind, "--approval", admit_envelope, "--readback", readback_envelope,
                                       check=check)
            initial = renewal_files("admit", ap)
            apply_lease("admit")
            before_renewal = json.loads(f.run("cat", str(book)).stdout)
            renewal_monitor = f.launch("c", CONTINUITY)
            expect("renewal_live_probe_started", "sampled", f.line(renewal_monitor))
            time.sleep(1.7)
            fresh = renewal_files("renew", ap)
            apply_lease("renew")
            renewed = json.loads(f.run("cat", str(book)).stdout)
            expect("authenticated_renewal_epoch_and_deadline_advance", True,
                   fresh["epoch"] > initial["epoch"] and renewed["monotonic_until"] > before_renewal["monotonic_until"])
            expect("same_renewal_replay_rejected", True, apply_lease("renew", check=False).returncode != 0)
            expect("replay_does_not_extend_validity", renewed, json.loads(f.run("cat", str(book)).stdout))
            for role in ("a", "b"):
                expect(role + "_still_denied_during_other_credential_renewal", True, denied_fresh(role))
            renewal_files("renew", operator)
            expect("invalid_ap_renewal_rejected", True, apply_lease("renew", check=False).returncode != 0)
            expect("invalid_signature_does_not_extend_validity", renewed, json.loads(f.run("cat", str(book)).stdout))
            renewal_files("renew", ap)
            race = f.run("env", f"PYTHONPATH={service.resolve().parent}:{service.resolve().parents[1] / 'activation'}",
                         sys.executable, str(service.with_name("expiry_race.py")), str(configuration),
                         str(admit_envelope), str(readback_envelope), namespace=edge)
            evidence["expiry_race"] = json.loads(race.stdout)
            expect("kernel_atomic_renewal_rejects_expired_member", True, evidence["expiry_race"]["rejected"])
            expect("raced_renewal_does_not_extend_validity", renewed, json.loads(f.run("cat", str(book)).stdout))
            time.sleep(max(0, renewed["monotonic_until"] - time.monotonic()) + 2.3)
            renewal_monitor.stdin.write("stop\n")
            renewal_monitor.stdin.flush()
            renewal_samples = json.loads(f.line(renewal_monitor))
            valid = [row for row in renewal_samples if row["started"] <= renewed["monotonic_until"] - 0.25]
            expired = [row for row in renewal_samples if row["started"] >= renewed["monotonic_until"] + 0.15]
            expect("fresh_traffic_uninterrupted_through_authentication_and_renewal", True,
                   len(valid) >= 5 and all(row["fresh_echo"] for row in valid)
                   and any(row["started"] > before_renewal["monotonic_until"] for row in valid))
            expect("actual_kernel_expiry_blocks_ongoing_traffic_within_bound", True,
                   len(expired) >= 2 and not any(row["fresh_echo"] for row in expired)
                   and expired[0]["started"] - renewed["monotonic_until"] <= 1.0)
            evidence["renewal"] = {"initial": before_renewal, "renewed": renewed, "samples": renewal_samples}
            expect("expired_kernel_lease_cannot_renew", True, service_command("renew-challenge", check=False).returncode != 0)
            signed.write_text(json.dumps(sign(operator, {**renewal_target, "intent": "withdraw"})))
            service_command("withdraw", "--approval", signed)
            expect("revoked_renew_challenge_denied", True, service_command("renew-challenge", check=False).returncode != 0)
            for role in ("a", "b"):
                expect(role + "_still_denied_after_other_credential_expiry", True, denied_fresh(role))
            # Restore only the independent C guard in this isolated test.
            r(edge, "nft", "delete", "table", "inet", table_name(renewal_target))
            configuration.write_text(json.dumps({**renewal_config, **service_target, "state": str(work / "deployed-state")}))
            service_command("boot-closed")
            expect("control_restored_after_expiry_measurement", False, denied_fresh("c"))

            guard_unit = Path(__file__).with_name("commonwealth-wifi-guard.service").read_text()
            forward_unit = Path(__file__).with_name("commonwealth-wifi-forward.service").read_text()
            unit_prefix = f.prefix + "-boot"
            guard_name = unit_prefix + "-guard.service"
            forward_name = unit_prefix + "-forward.service"
            units = []
            try:
                guard_source = work / guard_name
                guard_source.write_text(guard_unit.replace("[Service]", "[Service]\nNetworkNamespacePath=/run/netns/" +
                                      f.prefix + edge).replace(
                                      "ExecStart=/usr/bin/python3 /usr/local/lib/commonwealth/wifi/policy.py boot-closed /etc/commonwealth/wifi.json",
                                      "ExecStart=/usr/bin/false"))
                forward_source = work / forward_name
                forward_source.write_text(forward_unit.replace("commonwealth-wifi-guard.service", guard_name)
                                          .replace("[Service]", "[Service]\nNetworkNamespacePath=/run/netns/" + f.prefix + edge))
                for source in (guard_source, forward_source):
                    path = "/run/systemd/system/" + source.name
                    f.run("install", "-m", "0644", str(source), path)
                    units.append(path)
                f.run("systemctl", "daemon-reload")
                attempt = f.run("systemctl", "start", forward_name, check=False)
                expect("faulted_guard_blocks_systemd_forwarding_dependency", True, attempt.returncode != 0)
                expect("faulted_guard_is_failed", "failed",
                       f.run("systemctl", "is-active", guard_name, check=False).stdout.strip())
                expect("faulted_boot_leaves_kernel_forwarding_off", "0", r(edge, "sysctl", "-n", "net.ipv4.ip_forward").strip())
                expect("faulted_boot_blocks_new_control_forwarding", True, denied_fresh("c"))
                evidence["startup_fault"] = {"scope": "systemd dependency with injected guard failure in fresh namespace",
                                              "start_returncode": attempt.returncode, "detail": attempt.stderr}
            finally:
                f.run("systemctl", "stop", forward_name, guard_name, check=False)
                if units:
                    f.run("rm", "-f", *units)
                f.run("systemctl", "daemon-reload")
            r(edge, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            restored_c = f.launch("c", CLIENT)
            expect("fresh_control_after_fault_recovery", "ready", f.line(restored_c))
            expect("control_echo_after_fault_recovery", "x", client_action(restored_c, "echo"))
            ap_state.write_text(json.dumps({"future_admission": "denied", "vlan_credentials": [TARGET["credential"]]}))
            challenge = secrets.token_hex(16)
            future = ap_readback(challenge)
            verify(ap_public, future, {**TARGET, "nonce": challenge, "future_admission": "denied",
                                       "vlan_credentials": [TARGET["credential"]]})
            evidence["future_admission_readback"] = future
            final = tracking()
            attempt = subprocess.check_output([sys.executable, __file__, "--associate", str(ap_state)], text=True, timeout=5)
            expect("ap_denies_future_association", "denied", json.loads(attempt)["decision"])
            expect("withdrawn_conntrack_not_recreated", [False, False, True],
                   [f"src={ip}" in final for ip in ADDRESSES.values()])
            evidence["verdict"] = "PASS"
        except Exception as exc:
            evidence["error"] = str(exc)
            if any(not check["matches"] for check in f.checks):
                evidence["verdict"] = "FAIL"
            raise
        finally:
            out.write_text(json.dumps({**evidence, "verdict": evidence.get("verdict", "UNVERIFIED")}, indent=2))
            for child in f.children:
                child.terminate()
            for child in f.children:
                child.wait(timeout=4)
            for role in reversed(f.namespaces):
                f.run("ip", "netns", "del", f.prefix + role, check=False)
            f.state.cleanup()
            for directory in ("deployed-state", "renewal-state", "guard-registry", "overlap-state"):
                if (work / directory).exists():
                    f.run("chown", "-R", str(os.getuid()), str(work / directory))


if __name__ == "__main__":
    if sys.argv[1] == "--ap-readback":
        key, state, nonce = sys.argv[2:]
        print(json.dumps(sign(key, {**TARGET, **json.loads(Path(state).read_text()), "nonce": nonce})))
    elif sys.argv[1] == "--commit-then-crash":
        key, target, namespace, boundary = sys.argv[2:]
        def deny():
            subprocess.run(["sudo", "-n", "ip", "netns", "exec", namespace, "nft", "-f", "-"],
                           input=guard(True), text=True, check=True, timeout=5)
        def commit():
            before = time.monotonic()
            persist(Path(target), sign(Path(key), {**TARGET, "intent": "withdraw"}))
            persist(Path(boundary), {"deny_ack_at": before, "withdrawal_synced_at": time.monotonic()})
        withdraw_transaction(deny, commit, lambda: None, lambda: os._exit(77))
    elif sys.argv[1] == "--recover-guard":
        public, target = map(Path, sys.argv[2:])
        verify(public, json.loads(target.read_text()), {**TARGET, "intent": "withdraw"})
        print(guard(True), end="")
    elif sys.argv[1] == "--associate":
        print(json.dumps({"decision": "allowed" if associate(Path(sys.argv[2])) else "denied"}))
    else:
        run(sys.argv[1])
