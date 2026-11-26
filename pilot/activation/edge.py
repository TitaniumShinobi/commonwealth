"""Render a target-bound, default-closed Linux guest edge configuration."""
import hashlib
import hmac
import ipaddress
import json
import re
import sys
from pathlib import Path

TARGET_FIELDS = {"node", "inside", "outside", "guest_ip", "guest_mac", "operator", "relay_ips"}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def read(path):
    return json.loads(Path(path).read_text())


def sha(value):
    return hashlib.sha256(encode(value)).hexdigest()


def validate(target):
    if set(target) != TARGET_FIELDS:
        raise ValueError("target schema")
    for field in ("node", "inside", "outside", "operator"):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,14}", target[field]):
            raise ValueError("invalid target field")
    if target["inside"] == target["outside"]:
        raise ValueError("interface collision")
    if ipaddress.IPv4Address(target["guest_ip"]) not in ipaddress.IPv4Network("10.231.56.0/24"):
        raise ValueError("guest outside pilot pool")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", target["guest_mac"]):
        raise ValueError("invalid MAC")
    for ip in target["relay_ips"]:
        ipaddress.IPv4Address(ip)


def proof(target, intent, secret):
    validate(target)
    if intent not in ("admit", "withdraw"):
        raise ValueError("unsupported intent")
    body = {"schema": 1, "target_sha256": sha(target), "intent": intent, "session": "wired-test-guest"}
    return {**body, "mac": hmac.digest(secret, encode(body), "sha256").hex()}


def render(target, mode, approval=None, secret=None):
    validate(target)
    if mode == "open" and (not approval or not hmac.compare_digest(
            encode(approval), encode(proof(target, "admit", secret)))):
        raise ValueError("current target approval required")
    if mode == "withdraw" and (not approval or not hmac.compare_digest(
            encode(approval), encode(proof(target, "withdraw", secret)))):
        raise ValueError("current target withdrawal required")
    if mode not in ("closed", "open", "withdraw"):
        raise ValueError("invalid policy mode")
    inside, outside, guest, mac = (target[key] for key in ("inside", "outside", "guest_ip", "guest_mac"))
    private = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }"
    forward = ""
    if mode == "open":
        forward = f'''
        iifname "{inside}" ip daddr {private} counter drop
        iifname "{inside}" oifname "{outside}" ether saddr {mac} ip saddr {guest} tcp dport 443 ct state new,established counter accept
        iifname "{outside}" oifname "{inside}" ip daddr {guest} ct state established counter accept'''
    return f'''flush ruleset
table inet guest_edge {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        iifname "{outside}" ct state established,related accept
        iifname "{inside}" udp sport 68 udp dport 67 counter accept
        iifname "{inside}" ether saddr {mac} ip saddr {guest} udp dport 53 counter accept
        iifname "{inside}" ether saddr {mac} ip saddr {guest} tcp dport 53 counter accept
    }}
    chain forward {{
        type filter hook forward priority filter; policy drop;{forward}
    }}
}}
table ip guest_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "{outside}" ip saddr 10.231.56.0/24 counter masquerade
    }}
}}
'''


if __name__ == "__main__":
    command, target_path, *args = sys.argv[1:]
    target = read(target_path)
    if command == "approve":
        print(encode(proof(target, args[0], Path(args[1]).read_bytes())).decode())
    elif command == "render":
        approval = read(args[1]) if len(args) > 1 else None
        secret = Path(args[2]).read_bytes() if len(args) > 2 else None
        print(render(target, args[0], approval, secret), end="")
    else:
        raise ValueError("unsupported command")
