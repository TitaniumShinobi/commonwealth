"""Disposable, disconnected Linux network namespace fixture."""
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TCP_SERVER = """import socket,threading
s=socket.socket()
s.bind(('203.0.113.2', 8090))
s.listen()
print('ready', flush=True)
def echo(c):
    with c:
        while item:=c.recv(1):
            c.sendall(item)
while True:
    c,_=s.accept()
    threading.Thread(target=echo,args=(c,),daemon=True).start()
"""
TCP_CLIENT = """import socket,sys
s=socket.create_connection(('203.0.113.2',8090),2)
s.settimeout(1)
for line in sys.stdin:
    try:
        s.sendall(b'x')
        print('echo' if s.recv(1)==b'x' else 'closed',flush=True)
    except OSError:
        print('blocked',flush=True)
"""


class Fixture:
    def __init__(self, profile):
        self.profile = profile
        self.prefix = "cw7" + str(os.getpid())
        self.namespaces = []
        self.children = []
        self.commands = []
        self.checks = []
        self.policy_events = []
        self.state = tempfile.TemporaryDirectory(prefix="cw-pilot-policy-")

    def run(self, *cmd, namespace=None, check=True, data=None):
        prefix = ["sudo", "-n"]
        root = [*prefix, "ip", "netns", "exec", self.prefix + namespace] if namespace else prefix
        line = [*root, *cmd]
        self.commands.append(line)
        return subprocess.run(line, text=True, input=data, capture_output=True, timeout=8, check=check)

    def create(self, role):
        self.run("ip", "netns", "add", self.prefix + role)
        self.namespaces.append(role)
        self.run("ip", "link", "set", "lo", "up", namespace=role)
        self.run("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1", namespace=role)

    def wire(self, left, right, index, left_if, right_if):
        # Both ends are moved off the runner before either is brought up.
        src, dst = f"{self.prefix}{index}a", f"{self.prefix}{index}b"
        try:
            self.run("ip", "link", "add", src, "type", "veth", "peer", "name", dst)
            self.run("ip", "link", "set", src, "netns", self.prefix + left)
            self.run("ip", "link", "set", dst, "netns", self.prefix + right)
            for ns, old, new in ((left, src, left_if), (right, dst, right_if)):
                self.run("ip", "link", "set", old, "name", new, namespace=ns)
                self.run("ip", "link", "set", new, "up", namespace=ns)
        finally:
            self.run("ip", "link", "del", src, check=False)
            self.run("ip", "link", "del", dst, check=False)

    def address(self, role, interface, address):
        self.run("ip", "addr", "add", address, "dev", interface, namespace=role)

    def ping(self, role, address):
        return self.run("ping", "-c", "1", "-W", "1", address, namespace=role, check=False).returncode == 0

    def check(self, case, expected, observed):
        self.checks.append({"case": case, "expected": expected, "observed": observed,
                            "matches": expected == observed})

    def program(self, namespace, rules):
        self.run("nft", "--check", "-f", "-", namespace=namespace, data=rules)
        self.run("nft", "-f", "-", namespace=namespace, data=rules)
        return hashlib.sha256(rules.encode()).hexdigest()

    def launch(self, namespace, code):
        cmd = ["sudo", "-n", "ip", "netns", "exec", self.prefix + namespace,
               sys.executable, "-u", "-c", code]
        child = subprocess.Popen(cmd, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
        self.children.append(child)
        return child

    def line(self, child, send=False):
        import select
        if send:
            child.stdin.write("probe\n")
            child.stdin.flush()
        if not select.select([child.stdout], [], [], 4)[0]:
            raise TimeoutError("fixture TCP process did not acknowledge")
        return child.stdout.readline().strip()

    def tracked(self, program, source):
        result = self.run(program, "-L", "-p", "tcp", "-s", source,
                          "-d", "203.0.113.2", "--dport", "8090", namespace="g")
        return result.stdout.strip().splitlines()

    def delete_tracking(self, program, source):
        return self.run(program, "-D", "-p", "tcp", "-s", source,
                        "-d", "203.0.113.2", "--dport", "8090", namespace="g", check=False)

    def host_service(self):
        code = ("import socket; s=socket.create_connection(('198.51.100.18', 8091), 2); "
                "s.settimeout(2); s.sendall(b'h'); print(s.recv(1).decode())")
        result = self.run(sys.executable, "-c", code, namespace="g", check=False)
        return result.returncode == 0 and result.stdout.strip() == "h"

    def cleanup(self):
        errors = []
        for child in reversed(self.children):
            child.terminate()
            try:
                child.wait(2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(2)
        for ns in reversed(self.namespaces):
            processes = self.run("ip", "netns", "pids", self.prefix + ns, check=False).stdout.split()
            for pid in processes:
                self.run("kill", "-KILL", pid, check=False)
            result = self.run("ip", "netns", "del", self.prefix + ns, check=False)
            if result.returncode:
                errors.append(ns)
        self.state.cleanup()
        return errors


def firewall(guest, wan, deny, close=False):
    guard = "".join(f"ip {direction}addr {address} counter drop\n"
                    for direction in ("s", "d") for address in deny)
    rules = "" if close else (f'iifname "{guest}" oifname "{wan}" counter accept\n'
                               f'iifname "{wan}" oifname "{guest}" ct state established,related counter accept\n')
    return (f"table inet cw {{ chain forward {{ type filter hook forward priority filter; policy drop;\n"

            f"{guard}{rules} }}\n"
            'chain input { type filter hook input priority filter; policy drop; ' 
            f'iifname "lo" accept; iifname "cwm0" accept; iifname "{guest}" udp dport {{ 53, 67 }} accept; '
            f'iifname "{guest}" tcp dport 53 accept; }}\n}}\n'
            f'table ip cwnat {{ chain post {{ type nat hook postrouting priority srcnat; policy accept; '
            f'oifname "{wan}" ip saddr 192.0.2.0/24 masquerade; }}\n}}\n')


def bridge(deny=False):
    ports = ('iifname "p1" counter drop\noifname "p1" counter drop\n' if deny else "")
    return ('table bridge cwlan { chain forward { type filter hook forward priority filter; '
            f'policy accept;\n{ports}iifname "p1" oifname "p2" counter drop\n'
            'iifname "p2" oifname "p1" counter drop\n}\n}\n')


def exercise(profile, config):
    tools = ("sudo", "ip", "nft", "ping")
    versions = {name: shutil.which(name) for name in tools}
    unavailable = [name for name, present in versions.items() if not present]
    if unavailable:
        return {"verdict": "UNVERIFIED", "missing_tools": unavailable, "tools": versions}
    conntrack = os.environ.get("PILOT_CONNTRACK") or shutil.which("conntrack")
    if not conntrack:
        return {"verdict": "UNVERIFIED", "missing_tools": ["conntrack"], "tools": versions}
    f = Fixture(profile)
    error = None
    digests = {}
    setup = False
    config_status = "UNVERIFIED"
    custody = {}
    tracked = {}
    try:
        for role in ("g", "l", "a", "b", "w", "h", "m", "s"):
            f.create(role)
        interfaces = profile["interfaces"]
        guest, wan = interfaces["guest"], interfaces["wan"]
        for index, (left, right, left_if, right_if) in enumerate((
            ("g", "l", guest, "uplink0"), ("l", "a", "p1", "eth0"), ("l", "b", "p2", "eth0"),
            ("g", "w", wan, "eth0"), ("g", "h", interfaces["household"], "eth0"),
            ("g", "m", interfaces["management"], "eth0"), ("g", "s", interfaces["service"], "eth0"))):
            f.wire(left, right, index, left_if, right_if)
        f.run("ip", "link", "add", "br0", "type", "bridge", namespace="l")
        for port in ("uplink0", "p1", "p2"):
            f.run("ip", "link", "set", port, "master", "br0", namespace="l")
        f.run("ip", "link", "set", "br0", "up", namespace="l")
        for role, interface, ip in (
            ("g", guest, "192.0.2.1/24"), ("a", "eth0", "192.0.2.10/24"),
            ("b", "eth0", "192.0.2.11/24"), ("g", wan, "203.0.113.1/24"),
            ("w", "eth0", "203.0.113.2/24"), ("g", interfaces["household"], "198.51.100.1/28"),
            ("h", "eth0", "198.51.100.2/28"), ("g", interfaces["management"], "198.51.100.17/28"),
            ("m", "eth0", "198.51.100.18/28"), ("g", interfaces["service"], "198.51.100.33/28"),
            ("s", "eth0", "198.51.100.34/28")):
            f.address(role, interface, ip)
        for role in ("a", "b"):
            f.run("ip", "route", "add", "default", "via", "192.0.2.1", namespace=role)
        f.run("sysctl", "-qw", "net.ipv4.ip_forward=1", namespace="g")
        # No host links or default routes on the gateway and synthetic WAN.
        for role in ("g", "w"):
            routes = f.run("ip", "route", "show", "default", namespace=role).stdout
            f.check(f"{role}_has_no_default_route", "", routes.strip())
            if routes.strip():
                raise RuntimeError("unexpected route in isolated fixture")
        initial = firewall(guest, wan, (), close=True)
        digests["initial_closed"] = f.program("g", initial)
        digests["bridge"] = f.program("l", bridge())
        # Capture the installed baseline and bind its restore to this runtime target.
        baseline = f.run("nft", "-s", "list", "ruleset", namespace="g").stdout
        replace = "delete table inet cw\ndelete table ip cwnat\n"
        captured = hashlib.sha256(baseline.encode()).hexdigest()
        candidate = firewall(guest, wan, ())
        custody = {"target": f.prefix + "g", "baseline_sha256": captured,
                   "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                   "baseline_ruleset": baseline}
        tools_version = f.run(conntrack, "-V", check=False)
        versions["conntrack"] = (tools_version.stdout or tools_version.stderr).strip()
        if tools_version.returncode:
            raise RuntimeError("conntrack binary unavailable")
        host = f.launch("m", TCP_SERVER.replace("203.0.113.2", "198.51.100.18").replace("8090", "8091"))
        f.check("host_service_started", "ready", f.line(host))
        f.check("host_service_on_baseline", True, f.host_service())
        f.check("baseline_guest_closed", False, f.ping("b", "203.0.113.2"))
        f.check("target_bound_baseline_pre_apply", captured, hashlib.sha256(
            f.run("nft", "-s", "list", "ruleset", namespace="g").stdout.encode()).hexdigest())
        digests["candidate_applied"] = f.program("g", replace + candidate)
        f.check("host_service_after_candidate", True, f.host_service())
        setup = True
        for name, cmd in {"ip": ("ip", "-V"), "nft": ("nft", "--version"),
                          "ping": ("ping", "-V")}.items():
            versions[name] = f.run(*cmd, check=False).stdout.strip()
        dnsmasq = os.environ.get("PILOT_DNSMASQ") or shutil.which("dnsmasq")
        if dnsmasq:
            tool = f.run(dnsmasq, "--version", namespace="g", check=False)
            versions["dnsmasq"] = tool.stdout.splitlines()[0] if tool.returncode == 0 else "unavailable"
        if dnsmasq and versions["dnsmasq"] != "unavailable":
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "dnsmasq.conf"
                path.write_text(config)
                syntax = f.run(dnsmasq, "--test", "-C", str(path), namespace="g", check=False)
                config_status = "PASS" if syntax.returncode == 0 else "FAIL"
                f.check("dhcp_resolver_config_syntax", 0, syntax.returncode)
        f.check("synthetic_wan", True, f.ping("a", "203.0.113.2"))
        for label, address in (("guest_bridge", "192.0.2.11"), ("household", "198.51.100.2"),
                               ("management", "198.51.100.18"), ("service", "198.51.100.34")):
            f.check(label + "_isolated", False, f.ping("a", address))
        f.check("guest_cannot_reach_gateway_management_address", False, f.ping("a", "198.51.100.17"))
        f.check("management_can_reach_gateway", True, f.ping("m", "198.51.100.17"))
        server = f.launch("w", TCP_SERVER)
        f.check("tcp_server", "ready", f.line(server))
        client = f.launch("a", TCP_CLIENT)
        f.check("existing_tcp_before_withdrawal", "echo", f.line(client, send=True))
        tracked["active_before_withdrawal"] = f.tracked(conntrack, "192.0.2.10")
        f.check("existing_conntrack_established", True, any("ESTABLISHED" in x for x in tracked["active_before_withdrawal"]))
        ledger = Path(f.state.name) / "revocations.txt"
        with ledger.open("w") as stream:
            stream.write("192.0.2.10\n")
            stream.flush()
            os.fsync(stream.fileno())
        f.policy_events.append("durable_revocation_committed")
        denied = firewall(guest, wan, tuple(ledger.read_text().splitlines()))
        digests["withdrawal"] = f.program("g", replace + denied)
        f.check("existing_tcp_stops_without_eviction", "blocked", f.line(client, send=True))
        f.check("new_flow_stops_without_eviction", False, f.ping("a", "203.0.113.2"))
        f.check("routed_deny_counters", True, bool(re.search(r"ip saddr 192\.0\.2\.10 counter packets [1-9]",
                    f.run("nft", "list", "chain", "inet", "cw", "forward", namespace="g").stdout)))
        f.policy_events.append("routed_deny_verified_before_conntrack_delete")
        tracked["withdrawal_delete_returncode"] = f.delete_tracking(conntrack, "192.0.2.10").returncode
        f.check("withdrawal_conntrack_delete", 0, tracked["withdrawal_delete_returncode"])
        tracked["after_withdrawal"] = f.tracked(conntrack, "192.0.2.10")
        f.check("withdrawal_conntrack_empty", [], tracked["after_withdrawal"])
        f.program("l", "delete table bridge cwlan\n" + bridge(True))
        f.check("withdrawn_bridge_path", False, f.ping("a", "192.0.2.1"))
        f.check("bridge_deny_counter", True, bool(re.search(r'iifname "p1" counter packets [1-9]',
                f.run("nft", "list", "chain", "bridge", "cwlan", "forward", namespace="l").stdout)))
        # Model a policy-process restart: close guest forwarding, read durable
        # revocation, reinstall denial, and verify it before enabling forwarding.
        f.program("g", replace + firewall(guest, wan, (), close=True))
        f.policy_events.append("restart_guest_forwarding_closed")
        f.check("restart_before_reload_control_closed", False, f.ping("b", "203.0.113.2"))
        durable = tuple(ledger.read_text().splitlines())
        f.program("g", replace + firewall(guest, wan, durable, close=True))
        closed_policy = f.run("nft", "-s", "list", "chain", "inet", "cw", "forward", namespace="g").stdout
        denial_verified = (bool(durable) and all(
            f"ip {direction}addr {address} counter drop" in closed_policy
            for direction in ("s", "d") for address in durable) and "oifname" not in closed_policy)
        f.check("denial_read_back_before_forwarding_resume", True, denial_verified)
        if not denial_verified:
            raise RuntimeError("policy restart blocked forwarding because denial readback failed")
        f.policy_events.append("revocation_read_back_while_closed")
        f.program("g", replace + firewall(guest, wan, durable))
        f.policy_events.append("forwarding_resumed_with_revocation")
        f.check("unaffected_control", True, f.ping("b", "203.0.113.2"))
        f.check("revoked_denied_after_restart", False, f.ping("a", "203.0.113.2"))
        f.check("revoked_conntrack_absent_after_restart", [], f.tracked(conntrack, "192.0.2.10"))
        f.check("host_service_after_restart", True, f.host_service())
        f.run("ip", "link", "set", wan, "down", namespace="g")
        f.check("wan_loss", False, f.ping("b", "203.0.113.2"))
        f.check("local_management_during_loss", True, f.ping("m", "198.51.100.17"))
        f.run("ip", "link", "set", wan, "up", namespace="g")
        f.check("unaffected_recovery", True, f.ping("b", "203.0.113.2"))
        f.check("withdrawal_survives_recovery", False, f.ping("a", "203.0.113.2"))
        control = f.launch("b", TCP_CLIENT)
        f.check("unaffected_tcp_before_rollback", "echo", f.line(control, send=True))
        tracked["control_before_rollback"] = f.tracked(conntrack, "192.0.2.11")
        f.check("control_conntrack_exists_before_rollback", True,
                any("ESTABLISHED" in x for x in tracked["control_before_rollback"]))
        restore_digest = hashlib.sha256(baseline.encode()).hexdigest()
        restore_target = f.prefix + "g"
        f.check("baseline_digest_before_restore", captured, restore_digest)
        f.check("baseline_target_before_restore", custody["target"], restore_target)
        if restore_digest != captured or restore_target != custody["target"]:
            raise RuntimeError("captured baseline does not match rollback target and digest")
        digests["rollback_captured_baseline"] = f.program("g", replace + baseline)
        restored = f.run("nft", "-s", "list", "ruleset", namespace="g").stdout
        custody["restored_pre_overlay_sha256"] = hashlib.sha256(restored.encode()).hexdigest()
        f.check("captured_baseline_exact_readback", captured, custody["restored_pre_overlay_sha256"])
        f.check("rollback_guest_closed_before_reconciliation", False, f.ping("b", "203.0.113.2"))
        for direction in ("s", "d"):
            f.run("nft", "insert", "rule", "inet", "cw", "forward", "ip", f"{direction}addr",
                  durable[0], "counter", "drop", namespace="g")
        tracked["rollback_delete_returncode"] = f.delete_tracking(conntrack, "192.0.2.11").returncode
        f.check("rollback_conntrack_delete", 0, tracked["rollback_delete_returncode"])
        tracked["after_rollback_control"] = f.tracked(conntrack, "192.0.2.11")
        tracked["after_rollback_revoked"] = f.tracked(conntrack, "192.0.2.10")
        f.check("rollback_all_exercised_guest_conntrack_empty", [[], []],
                [tracked["after_rollback_control"], tracked["after_rollback_revoked"]])
        f.check("host_service_after_baseline_restore", True, f.host_service())
        f.check("rollback_guest_closed", False, f.ping("b", "203.0.113.2"))
        f.check("rollback_management_retained", True, f.ping("m", "198.51.100.17"))
        f.check("rollback_revocation_retained", True,
                "192.0.2.10" in f.run("nft", "list", "table", "inet", "cw", namespace="g").stdout)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        error = {"type": type(exc).__name__, "message": str(exc)[:500],
                 "stderr": (getattr(exc, "stderr", "") or "")[:1200]}
    cleanup = f.cleanup()
    fail = bool(cleanup) or any(not item["matches"] for item in f.checks)
    packet = "FAIL" if fail else "UNVERIFIED" if error or not setup else "PASS"
    verdict = "FAIL" if fail else "PASS" if packet == config_status == "PASS" else "UNVERIFIED"
    return {"verdict": verdict, "packet_fixture": packet, "dhcp_dns_syntax": config_status,
            "checks": f.checks, "namespace_commands": f.commands, "tools": versions,
            "kernel": platform.release(), "config_sha256": digests, "incomplete": error,
            "capture_and_rollback": custody, "policy_events": f.policy_events,
            "conntrack_readbacks": tracked, "cleanup_errors": cleanup, "wan": "disconnected veth only",
            "limit": "AP identity and radio are modeled; DHCP/DNS configuration check is syntax only"}
