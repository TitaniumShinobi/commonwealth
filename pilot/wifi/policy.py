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
import tempfile
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


def replace_counter(directory, number):
    with tempfile.NamedTemporaryFile("w", dir=directory, delete=False) as output:
        output.write(str(number))
        output.flush()
        os.fsync(output.fileno())
    Path(output.name).replace(directory / "epoch")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
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


def nft_rule(config, block, lifetime=0):
    iface = config["interface"]
    prefix = str(ipaddress.IPv4Network(config["subnet"]))
    member = "" if block else f'elements = {{ "{iface}" timeout {lifetime}s }}'
    reverse = f"ip daddr {prefix} counter drop" if block else ""
    return f"""destroy table inet cw_wifi_guard
table inet cw_wifi_guard {{
 set live_vlan {{
    type ifname; flags timeout;
    {member}
 }}
 chain ingress {{
    type filter hook prerouting priority -310; policy accept;
    iifname @live_vlan return
    iifname "{iface}" counter drop
    {reverse}
 }}
 chain forwarding {{
    type filter hook forward priority -100; policy accept;
    oifname @live_vlan return
    oifname "{iface}" counter drop
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
    cli.add_argument("operation", choices=("boot-closed", "challenge", "admit", "renew-challenge", "renew", "withdraw"))
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
    lease_seconds = config.get("lease_seconds", 20)
    if type(lease_seconds) is not int or not 6 <= lease_seconds <= 20:
        raise ValueError("lease_seconds outside enforced bound")
    revoked = directory / "withdrawn.json"
    challenge = directory / "challenge.json"
    lifetime = directory / "live-until"
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    operator = config["operator_public"]
    ap = config["ap_public"]
    target = {name: config[name] for name in ("edge", "ap", "credential", "generation", "vlan", "interface", "subnet")}
    def apply(block, lifetime=0):
        script = nft_rule(config, block, lifetime)
        run("nft", "--check", "-f", "-", text=script)
        run("nft", "-f", "-", text=script)
    def clear():
        for selector in ("-s", "-d"):
            run("conntrack", "-D", "-f", "ipv4", selector, prefix, allowed=(0, 1))
            remaining = run("conntrack", "-L", "-f", "ipv4", selector, prefix)
            if remaining.stdout.strip():
                raise RuntimeError("withdrawn conntrack state remains")
    def check_live():
        active = read(lifetime)
        if active["boot_id"] != boot_id or time.monotonic() >= active["monotonic_until"]:
            raise ValueError("prior kernel admission expired")
        live = run("nft", "list", "set", "inet", "cw_wifi_guard", "live_vlan").stdout
        if f'elements = {{ "{interface}" timeout' not in live:
            raise ValueError("no current admission to renew")
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if options.operation == "boot-closed":
            apply(True)
            challenge.unlink(missing_ok=True)
            lifetime.unlink(missing_ok=True)
            clear()
        elif options.operation in ("challenge", "renew-challenge"):
            if options.operation == "challenge":
                apply(True)
            else:
                check_live()
            if revoked.exists():
                raise ValueError("credential withdrawn")
            challenge.unlink(missing_ok=True)
            epoch_path = directory / "epoch"
            epoch = (int(epoch_path.read_text()) if epoch_path.exists() else 0) + 1
            replace_counter(directory, epoch)
            statement = {"nonce": secrets.token_hex(24), "epoch": epoch,
                         "kind": "renew" if options.operation == "renew-challenge" else "admit",
                         "expires_at": int(time.time()) + lease_seconds}
            write_once(challenge, statement)
            print(json.dumps(statement))
        elif options.operation in ("admit", "renew"):
            if options.operation == "admit":
                apply(True)
            if revoked.exists():
                raise ValueError("credential withdrawn")
            if fingerprint(operator) != config["operator_key_sha256"] or fingerprint(ap) != config["ap_key_sha256"]:
                raise ValueError("public key pin mismatch")
            fresh = read(challenge)
            challenge.unlink()
            if fresh["kind"] != options.operation or fresh["epoch"] != int((directory / "epoch").read_text()):
                raise ValueError("stale challenge epoch")
            if time.time() >= fresh["expires_at"]:
                raise ValueError("challenge expired")
            verify(operator, read(options.approval), {**target, "intent": options.operation}, directory)
            verify(ap, read(options.readback),
                   {**target, **fresh, "future_admission": "allowed",
                    "vlan_credentials": [config["credential"]]}, directory)
            link = json.loads(run("ip", "-j", "-d", "link", "show", "dev", interface).stdout)[0]
            info = link.get("linkinfo", {})
            if info.get("info_kind") != "vlan" or info["info_data"]["id"] != config["vlan"]:
                raise ValueError("kernel VLAN mapping mismatch")
            ttl = int(fresh["expires_at"] - time.time()) - 1
            if ttl < 1:
                raise ValueError("challenge expired before activation")
            if options.operation == "renew":
                check_live()
            deadline = time.monotonic() + ttl
            apply(False, ttl)
            with tempfile.NamedTemporaryFile("w", dir=directory, delete=False) as book:
                json.dump({"boot_id": boot_id, "monotonic_until": deadline, "epoch": fresh["epoch"]}, book)
                book.flush()
            Path(book.name).replace(lifetime)
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
            lifetime.unlink(missing_ok=True)
            challenge.unlink(missing_ok=True)
    print(json.dumps({"edge": config["edge"], "vlan": config["vlan"], "operation": options.operation, "result": "completed"}))


if __name__ == "__main__":
    main()
