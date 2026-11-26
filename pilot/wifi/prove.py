"""Namespace AP fixture. Signed readback is synthetic; VLAN enforcement is Linux."""
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from commonwealth_sim.namespace_pilot import Fixture
from edge import encode, fingerprint, openssl

TARGET = {"ap": "fixture-ap", "edge": "fixture-edge", "credential": "shared-guest", "generation": 7,
          "vlan": 101, "stations": ["A", "B"]}
ADDRESSES = {"a": "10.77.101.20", "b": "10.77.101.21", "c": "10.77.102.20"}
SERVER = """
import socket,sys,threading
server=socket.socket()
server.bind(('203.0.113.2',8090))
server.listen()
clients=[]
def loop(client):
    with client:
        while item:=client.recv(1):
            client.sendall(item)
def accept():
    while True:
        client,_=server.accept()
        clients.append(client)
        threading.Thread(target=loop,args=(client,),daemon=True).start()
threading.Thread(target=accept,daemon=True).start()
print('ready',flush=True)
for line in sys.stdin:
    for client in clients:
        try: client.sendall(b'p')
        except OSError: pass
    print('pushed',flush=True)
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
""" % ('iifname "guest101" counter drop' if block else '',
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
        def tracking():
            return r("g", "conntrack", "-L", "-p", "tcp", "-d", "203.0.113.2", "--dport", "8090")
        def ap_readback(nonce):
            result = subprocess.check_output([sys.executable, __file__, "--ap-readback", str(ap), str(ap_state), nonce],
                                             text=True, timeout=5)
            return json.loads(result)
        def admission(readback, challenge):
            try:
                return admit(operator_public, ap_public, approval, readback, challenge, revoked)
            except (ValueError, OSError, subprocess.SubprocessError):
                return False
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
            before = tracking()
            evidence["conntrack_before"] = before.splitlines()
            expect("all_sessions_tracked", True, all(f"src={ip}" in before for ip in ADDRESSES.values()))
            persist(revoked, sign(operator, {**TARGET, "intent": "withdraw"}))
            evidence["signed_withdrawal"] = json.loads(revoked.read_text())
            f.program("g", guard(True))
            for role in ("a", "b"):
                r("g", "conntrack", "-D", "-p", "tcp", "-s", ADDRESSES[role], "--dport", "8090")
            after = tracking()
            evidence["conntrack_after"] = after.splitlines()
            expect("only_unrelated_conntrack_remains", [False, False, True],
                   [f"src={ip}" in after for ip in ADDRESSES.values()])
            expect("c_conntrack_tuple_preserved", True, any(
                line.split("[ASSURED]")[0].split("src=", 1)[1] in after
                for line in before.splitlines() if f"src={ADDRESSES['c']}" in line))
            expect("server_push", "pushed", client_action(server, "push"))
            for role in ("a", "b"):
                expect(f"{role}_downstream_denied_with_association_retained", "blocked", client_action(guests[role], "read"))
                expect(f"{role}_upstream_denied_with_association_retained", "blocked", client_action(guests[role], "echo"))
            expect("c_downstream_continues", "p", client_action(guests["c"], "read"))
            expect("c_upstream_continues", "x", client_action(guests["c"], "echo"))
            expect("kernel_ap_assignments_unchanged_eviction_withheld", vlan_table,
                   json.loads(r("ap", "bridge", "-j", "vlan", "show")))
            evidence["restart_and_rollback"] = []
            for action in ("restart", "exact_rollback"):
                challenge = secrets.token_hex(16)
                expect(action + "_old_readback_and_admission_denied", False, admission(current, challenge))
                expect(action + "_fresh_readback_cannot_override_tombstone", False, admission(ap_readback(challenge), challenge))
                digest = f.program("g", rules)
                f.program("g", guard(True))
                evidence["restart_and_rollback"].append({"action": action, "baseline_sha256": digest})
                expect(action + "_a_still_blocked", "blocked", client_action(guests["a"], "echo"))
                expect(action + "_b_still_blocked", "blocked", client_action(guests["b"], "echo"))
                expect(action + "_c_still_live", "x", client_action(guests["c"], "echo"))
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


if __name__ == "__main__":
    if sys.argv[1] == "--ap-readback":
        key, state, nonce = sys.argv[2:]
        print(json.dumps(sign(key, {**TARGET, **json.loads(Path(state).read_text()), "nonce": nonce})))
    elif sys.argv[1] == "--associate":
        print(json.dumps({"decision": "allowed" if associate(Path(sys.argv[2])) else "denied"}))
    else:
        run(sys.argv[1])
