"""Render a target-bound, default-closed Linux guest edge configuration."""
import hashlib
import base64
import subprocess
import tempfile
import ipaddress
import json
import re
import sys
from pathlib import Path

TARGET_FIELDS = {"node", "inside", "outside", "guest_ip", "guest_mac", "operator", "relay_ips", "operator_key_sha256"}


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
    if not re.fullmatch(r"[0-9a-f]{64}", target["operator_key_sha256"]):
        raise ValueError("invalid operator key pin")
    for ip in target["relay_ips"]:
        ipaddress.IPv4Address(ip)


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True, timeout=5).stdout


def fingerprint(public):
    return hashlib.sha256(openssl("pkey", "-pubin", "-in", public, "-outform", "DER")).hexdigest()


def statement(target, intent):
    validate(target)
    if intent not in ("admit", "withdraw", "cross-open", "cross-close"):
        raise ValueError("unsupported intent")
    return {"schema": 1, "target_sha256": sha(target), "intent": intent, "session": "wired-test-guest"}


def proof(target, intent, key):
    body = statement(target, intent)
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / "body"
        message.write_bytes(encode(body))
        signed = openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", message)
    return {**body, "signature": base64.b64encode(signed).decode()}


def verify(target, intent, approval, public):
    if fingerprint(public) != target["operator_key_sha256"]:
        raise ValueError("wrong operator")
    expected = statement(target, intent)
    if {key: value for key, value in approval.items() if key != "signature"} != expected:
        raise ValueError("wrong target or intent")
    with tempfile.TemporaryDirectory() as directory:
        message, signature = (Path(directory) / name for name in ("body", "signature"))
        message.write_bytes(encode(expected))
        signature.write_bytes(base64.b64decode(approval["signature"], validate=True))
        try:
            openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public, "-in", message, "-sigfile", signature)
        except subprocess.CalledProcessError as exc:
            raise ValueError("invalid operator signature") from exc


def revocation(target, public, state):
    if state is None:
        raise ValueError("missing operator revocation state")
    tombstone = state / "session-revocation.json"
    row = read(tombstone if tombstone.exists() else state / "session-state.json")
    intent = row.get("intent")
    if intent not in ("admit", "withdraw"):
        raise ValueError("invalid revocation state")
    verify(target, intent, row, public)
    return row


def record_session(target, approval, public, state):
    intent = approval.get("intent")
    verify(target, intent, approval, public)
    destination = state / "session-state.json"
    if intent == "admit":
        if (state / "session-revocation.json").exists():
            raise ValueError("session withdrawn")
        with destination.open("x") as output:
            output.write(encode(approval).decode())
    elif intent == "withdraw":
        revocation(target, public, state)
        tombstone = state / "session-revocation.json"
        replacement = tombstone.with_suffix(".next")
        with replacement.open("x") as output:
            output.write(encode(approval).decode())
        replacement.replace(tombstone)
    else:
        raise ValueError("not a session state transition")


def guard(target, public, state):
    try:
        revoked = revocation(target, public, state)["intent"] != "admit"
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        revoked = True
    inside, guest = target["inside"], target["guest_ip"]
    ingress = f'iifname "{inside}" ip saddr {guest} counter drop' if revoked else ""
    reply = f'oifname "{inside}" ip daddr {guest} counter drop' if revoked else ""
    return f"""destroy table inet guest_revocation
table inet guest_revocation {{
    chain ingress {{
        type filter hook prerouting priority -310; policy accept;
        {ingress}
    }}
    chain replies {{
        type filter hook forward priority -100; policy accept;
        {reply}
    }}
}}
"""


def render(target, mode, approval=None, public=None, state=None):
    validate(target)
    intents = {"open": "admit", "withdraw": "withdraw", "crossing": "cross-open", "post-crossing": "cross-close"}
    if mode in intents:
        verify(target, intents[mode], approval, public)
    elif mode != "closed":
        raise ValueError("invalid policy mode")
    if mode in ("open", "crossing", "post-crossing") and revocation(target, public, state)["intent"] != "admit":
        raise ValueError("session withdrawn")
    if mode == "crossing" and (state is None or (state / "crossing-closed.json").exists()):
        raise ValueError("crossing authorization withdrawn")
    inside, outside, guest, mac = (target[key] for key in ("inside", "outside", "guest_ip", "guest_mac"))
    private = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }"
    forward = ""
    if mode in ("open", "crossing", "post-crossing"):
        forward = f'''
        iifname "lan1" counter drop
        iifname "{inside}" ip daddr {private} counter drop
        iifname "{inside}" oifname "{outside}" ether saddr {mac} ip saddr {guest} tcp dport 443 ct state new,established counter accept
        iifname "{outside}" oifname "{inside}" ip daddr {guest} ct state established counter accept'''
    if mode in ("open", "crossing", "post-crossing", "withdraw"):
        forward = f'''
        iifname "lan2" ip daddr {private} counter drop
        iifname "lan2" oifname "{outside}" ether saddr 02:23:15:61:00:02 ip saddr 10.231.61.2 tcp dport 443 ct state new,established counter accept
        iifname "{outside}" oifname "lan2" ip daddr 10.231.61.2 ct state established counter accept''' + forward
    if mode == "crossing":
        crossing = f'''
        iifname "{inside}" oifname "peer0" ether saddr {mac} ip saddr {guest} ip daddr 10.231.60.2 tcp dport 8443 ct state new,established counter accept
        iifname "peer0" oifname "{inside}" ip saddr 10.231.60.2 ip daddr {guest} ct state established counter accept'''
        # The operator-approved private peer exception precedes the ordinary private-network deny.
        forward = crossing + forward
    return f'''destroy table inet guest_edge
destroy table ip guest_nat
table inet guest_edge {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        iifname "{outside}" ct state established,related accept
        iifname "{outside}" udp sport 67 udp dport 68 counter accept
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
        oifname "{outside}" ip saddr {{ 10.231.56.0/24, 10.231.61.0/24 }} counter masquerade
    }}
}}
'''


if __name__ == "__main__":
    command, target_path, *args = sys.argv[1:]
    if command == "bootstrap":
        directory = Path(target_path)
        directory.mkdir(mode=0o700)
        private = directory / "operator.key"
        key = openssl("genpkey", "-algorithm", "Ed25519")
        private.touch(mode=0o600, exist_ok=False)
        private.write_bytes(key)
        (directory / "operator.pub").write_bytes(openssl("pkey", "-in", private, "-pubout"))
        print(fingerprint(directory / "operator.pub"))
    else:
        target = read(target_path)
        if command == "approve":
            print(encode(proof(target, args[0], args[1])).decode())
        elif command == "render":
            approval = read(args[1]) if len(args) > 1 else None
            public = args[2] if len(args) > 2 else None
            state = Path(args[3]) if len(args) > 3 else None
            print(render(target, args[0], approval, public, state), end="")
        elif command == "record-session":
            record_session(target, read(args[0]), args[1], Path(args[2]))
        elif command == "guard":
            validate(target)
            print(guard(target, args[0], Path(args[1])), end="")
        elif command == "record-cross-close":
            approval, public, state = read(args[0]), args[1], Path(args[2])
            verify(target, "cross-close", approval, public)
            with (state / "crossing-closed.json").open("x") as evidence:
                evidence.write(encode(approval).decode())
        else:
            raise ValueError("unsupported command")
