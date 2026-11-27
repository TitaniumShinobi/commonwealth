"""Read-only RouterOS wifi-qcom registration observation; never signs admission."""
import argparse
import ipaddress
import json
import re
import shlex
import subprocess
import time
from pathlib import Path

from readback import LOCAL

HEADER = re.compile(r"^\s*(\d+)\s+([A-Z ]*?)(?:\s*;;;\s*([a-zA-Z0-9_.-]+))?\s*$")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
COMMAND = "/interface/wifi/registration-table/print detail without-paging"


def registrations(output):
    rows = []
    current = None
    for line in output.splitlines():
        if not line.strip() or line.startswith("Flags:"):
            continue
        header = HEADER.fullmatch(line)
        if header:
            current = (header[2].strip().split(), header[3], [])
            rows.append(current)
        elif current is not None and line.startswith(" "):
            current[2].extend(shlex.split(line))
        else:
            raise ValueError("unexpected RouterOS registration format")
    result = {}
    for flags, comment, tokens in rows:
        fields = {}
        for token in tokens:
            key, separator, value = token.partition("=")
            if not separator or key in fields:
                raise ValueError("ambiguous RouterOS registration field")
            fields[key] = value
        mac = fields.get("mac-address", "").lower()
        if not MAC.fullmatch(mac) or mac in result:
            raise ValueError("missing or duplicate RouterOS station identity")
        vlan = fields.get("vlan-id")
        result[mac] = {"authorized": "A" in flags, "credential_comment": comment,
                       "vlan": int(vlan) if vlan and vlan.isascii() and vlan.isdecimal() else None,
                       "interface": fields.get("interface"), "ssid": fields.get("ssid"),
                       "auth_type": fields.get("auth-type")}
    return result


def match(expected, observed):
    by_role = {row["role"]: row for row in expected}
    if len(expected) != 3 or set(by_role) != {"A", "B", "C"}:
        raise ValueError("exactly three stations required")
    if len({row["mac"].lower() for row in expected}) != 3:
        raise ValueError("distinct station identities required")
    a, b, c = (by_role[role] for role in ("A", "B", "C"))
    if (a["credential_comment"], a["vlan"]) != (b["credential_comment"], b["vlan"]) or (
            c["credential_comment"] == a["credential_comment"] or c["vlan"] == a["vlan"]):
        raise ValueError("expected shared A/B credential and distinct C")
    result = {}
    for role, row in by_role.items():
        mac = row["mac"].lower()
        vlan = row["vlan"]
        if (not MAC.fullmatch(mac) or type(vlan) is not int or not 1 <= vlan <= 4094
                or not re.fullmatch(r"[a-zA-Z0-9_.-]+", row["credential_comment"])
                or not row["interface"] or not row["ssid"]):
            raise ValueError("invalid expected station")
        actual = observed.get(mac)
        if actual != {"authorized": True, "credential_comment": row["credential_comment"], "vlan": vlan,
                      "interface": row["interface"], "ssid": row["ssid"], "auth_type": "wpa2-psk"}:
            raise ValueError(f"station {role}: documented registration evidence missing or mismatched")
        result[role] = {"mac": mac, **actual}
    return result


def collect(config, known_hosts, identity):
    address = ipaddress.ip_address(config["address"])
    user = config["user"]
    if not any(address in network for network in LOCAL) or not re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_.-]*", user):
        raise ValueError("expected a reviewed private management endpoint and SSH user")
    if not known_hosts.is_file() or not identity.is_file():
        raise ValueError("preprovisioned host key and SSH identity are required")
    argv = ["ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts.resolve()}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5", "-i", str(identity.resolve()),
            "-l", user, str(address), COMMAND]
    completed = subprocess.run(argv, capture_output=True, timeout=12, check=False)
    if completed.returncode:
        raise ValueError("pinned SSH registration read failed")
    if len(completed.stdout) > 262144:
        raise ValueError("registration output exceeds size limit")
    return match(config["stations"], registrations(completed.stdout.decode("utf-8")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    args = parser.parse_args()
    report = {"scope": "routeros_registration_only", "signed_admission": "HELD",
              "guard_called": False, "started_at": time.time(),
              "remaining": ["complete effective route and credential inventory",
                            "fresh independent tagged captures bound to gateway challenge"]}
    try:
        report["stations"] = collect(json.loads(args.config.read_text()), args.known_hosts, args.identity)
        report["registration"] = "OBSERVED"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report["registration"] = "UNVERIFIED"
        report["error_type"] = type(exc).__name__
        if type(exc) is ValueError and str(exc).startswith(("station ", "pinned SSH")):
            report["reason"] = str(exc)
    report["finished_at"] = time.time()
    print(json.dumps(report, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
