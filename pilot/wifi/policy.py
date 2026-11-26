"""Wi-Fi admission guard for a dedicated Linux edge; never programs an AP."""
import argparse
import fcntl
import ipaddress
import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path

from edge import encode, fingerprint, openssl


def write_once(path, value):
    with path.open("x") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def withdraw_transaction(deny, commit, clear, after_commit=None):
    """A successful kernel transaction precedes durable publication of withdrawal."""
    deny()
    commit()
    if after_commit is not None:
        after_commit()
    clear()


def read(path):
    return json.loads(Path(path).read_text())


def verify(public, envelope, expected, directory):
    if envelope["body"] != expected:
        raise ValueError("signed statement scope does not match")
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(dir=directory) as work:
        message, signature = (Path(work) / name for name in ("body", "signature"))
        message.write_bytes(encode(expected))
        signature.write_bytes(bytes.fromhex(envelope["signature"]))
        openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                "-in", message, "-sigfile", signature)


def nft_rule(config, block):
    iface = config["interface"]
    prefix = str(ipaddress.IPv4Network(config["subnet"]))
    ingress = f'iifname "{iface}" counter drop\nip daddr {prefix} counter drop' if block else ""
    forwarding = f'oifname "{iface}" counter drop' if block else ""
    return f"""destroy table inet cw_wifi_guard
table inet cw_wifi_guard {{
 chain ingress {{
    type filter hook prerouting priority -310; policy accept;
    {ingress}
 }}
 chain forwarding {{
    type filter hook forward priority -100; policy accept;
    {forwarding}
 }}
}}
"""


def run(*args, text=None, allowed=(0,)):
    result = subprocess.run(args, input=text, capture_output=True, text=True, timeout=8)
    if result.returncode not in allowed:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()}")
    return result


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("operation", choices=("boot-closed", "challenge", "admit", "withdraw"))
    cli.add_argument("configuration", type=Path)
    cli.add_argument("--approval", type=Path)
    cli.add_argument("--readback", type=Path)
    options = cli.parse_args()
    config = read(options.configuration)
    interface = config["interface"]
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        raise ValueError("invalid VLAN interface")
    prefix = str(ipaddress.IPv4Network(config["subnet"]))
    directory = Path(config["state"])
    directory.mkdir(exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_uid != os.geteuid() or directory.stat().st_mode & 0o077:
        raise ValueError("state must be a private directory owned by the service account")
    revoked = directory / "withdrawn.json"
    challenge = directory / "challenge.json"
    operator = config["operator_public"]
    ap = config["ap_public"]
    target = {name: config[name] for name in ("edge", "ap", "credential", "generation", "vlan", "interface", "subnet")}
    def apply(block):
        script = nft_rule(config, block)
        run("nft", "--check", "-f", "-", text=script)
        run("nft", "-f", "-", text=script)
    def clear():
        for selector in ("-s", "-d"):
            run("conntrack", "-D", "-f", "ipv4", selector, prefix, allowed=(0, 1))
            remaining = run("conntrack", "-L", "-f", "ipv4", selector, prefix)
            if remaining.stdout.strip():
                raise RuntimeError("withdrawn conntrack state remains")
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if options.operation == "boot-closed":
            apply(True)
            challenge.unlink(missing_ok=True)
            clear()
        elif options.operation == "challenge":
            apply(True)
            if revoked.exists():
                raise ValueError("credential withdrawn")
            challenge.unlink(missing_ok=True)
            statement = {"nonce": secrets.token_hex(24), "expires_at": int(time.time()) + 20}
            write_once(challenge, statement)
            print(json.dumps(statement))
        elif options.operation == "admit":
            apply(True)
            if revoked.exists():
                raise ValueError("credential withdrawn")
            if fingerprint(operator) != config["operator_key_sha256"] or fingerprint(ap) != config["ap_key_sha256"]:
                raise ValueError("public key pin mismatch")
            fresh = read(challenge)
            challenge.unlink()
            if time.time() >= fresh["expires_at"]:
                raise ValueError("challenge expired")
            verify(operator, read(options.approval), {**target, "intent": "admit"}, directory)
            verify(ap, read(options.readback),
                   {**target, **fresh, "future_admission": "allowed",
                    "vlan_credentials": [config["credential"]]}, directory)
            link = json.loads(run("ip", "-j", "-d", "link", "show", "dev", interface).stdout)[0]
            info = link.get("linkinfo", {})
            if info.get("info_kind") != "vlan" or info["info_data"]["id"] != config["vlan"]:
                raise ValueError("kernel VLAN mapping mismatch")
            apply(False)
        else:
            signed = read(options.approval)
            if fingerprint(operator) != config["operator_key_sha256"]:
                raise ValueError("operator pin mismatch")
            verify(operator, signed, {**target, "intent": "withdraw"}, directory)
            def commit():
                if revoked.exists():
                    verify(operator, read(revoked), {**target, "intent": "withdraw"}, directory)
                else:
                    write_once(revoked, signed)
            withdraw_transaction(lambda: apply(True), commit, clear)
    print(json.dumps({"edge": config["edge"], "vlan": config["vlan"], "operation": options.operation, "result": "completed"}))


if __name__ == "__main__":
    main()
