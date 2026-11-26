"""Read-only Pi bench preflight and bounded tagged witness collector."""
import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("configuration", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--capture-tags", action="store_true")
    p.add_argument("--controller-receipt", type=Path)
    args = p.parse_args()
    result = {"scope": "physical_bench_observation_only", "field_acceptance": "UNVERIFIED",
              "activation": "HELD", "received_tags": [], "blockers": []}
    config = json.loads(args.configuration.read_text())
    model = Path("/proc/device-tree/model")
    result["machine"] = platform.machine()
    result["model"] = model.read_text(errors="replace").rstrip("\x00") if model.exists() else None
    with open("/proc/meminfo") as meminfo:
        result["memory_kib"] = int(next(line for line in meminfo if line.startswith("MemTotal:")).split()[1])
    if (result["machine"] != "aarch64" or not (result["model"] or "").startswith("Raspberry Pi 4")
            or not 7 * 1024 * 1024 <= result["memory_kib"] <= 8 * 1024 * 1024):
        result["blockers"].append("8GB Pi 4 native ARM64 hardware not demonstrated")
    try:
        iface = config["trunk"]
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", iface):
            raise ValueError("invalid trunk interface")
        topology = subprocess.run(["ip", "-j", "-d", "link", "show", "dev", iface], check=True, timeout=4,
                                  capture_output=True, text=True)
        result["trunk"] = {"interface": iface, "observed": bool(json.loads(topology.stdout))}
        if args.capture_tags:
            if result["blockers"]:
                raise ValueError("refusing live capture without qualified Pi bench architecture")
            if not args.controller_receipt:
                raise ValueError("fresh controller receipt required before tagged capture")
            controller = json.loads(args.controller_receipt.read_text())
            if (controller.get("scope") != "read_only_unifi_local_api" or not controller.get("configuration_consistent")
                    or not 0 <= time.time() - controller["finished_at"] <= 30):
                raise ValueError("controller configuration unverified or stale")
            result["controller_receipt_sha256"] = hashlib.sha256(args.controller_receipt.read_bytes()).hexdigest()
            known = {station["client_id"]: station for group in controller["configuration_observations"]
                     for station in group["stations"]}
            for station in config["stations"]:
                source = known.get(station["client_id"]) or {}
                if (source.get("mac"), source.get("ipv4"), source.get("vlan")) != (
                        station["mac"], station["source_ipv4"], station["vlan"]):
                    raise ValueError("controller station and capture target mismatch")
            if config["approval_ref"] in ("", "REQUIRED"):
                raise ValueError("explicit bench authorization reference required")
            if sorted(row["role"] for row in config["stations"]) != ["A", "B", "C"]:
                raise ValueError("A, B and C station records required")
            vlans = {row["role"]: row["vlan"] for row in config["stations"]}
            if vlans["A"] != vlans["B"] or vlans["A"] == vlans["C"]:
                raise ValueError("expected A/B shared tag and separate C tag")
            if len({row["mac"] for row in config["stations"]}) != 3:
                raise ValueError("station MAC addresses must be unique")
            for station in config["stations"]:
                role, mac, vlan = (station[k] for k in ("role", "mac", "vlan"))
                ip = str(ipaddress.IPv4Address(station["source_ipv4"]))
                if not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac) or type(vlan) is not int or not 1 <= vlan <= 4094:
                    raise ValueError("invalid station selector")
                print(f"Send separately approved IPv4 traffic from station {role} now", file=sys.stderr, flush=True)
                command = ["tcpdump", "-Q", "in", "-nn", "-e", "-s", "96", "-c", "1", "-i", iface,
                           f"ether src {mac} and vlan {vlan} and ip and src host {ip}"]
                started = time.time()
                packet = subprocess.run(command, text=True, capture_output=True, timeout=15, check=True).stdout.strip()
                if not packet:
                    raise ValueError("tagged frame missing")
                result["received_tags"].append({"role": role, "mac": mac, "vlan": vlan, "ipv4": ip,
                                                "window_started": started, "observed_at": time.time(),
                                                "record": packet, "sha256": hashlib.sha256(packet.encode()).hexdigest()})
    except (subprocess.SubprocessError, OSError, ValueError, KeyError) as exc:
        result["blockers"].append(str(exc))
    if len(result["received_tags"]) != 3:
        result["blockers"].append("fresh independent tagged A/B/C frames missing")
    result["tagged_dataplane"] = "CORROBORATED" if len(result["received_tags"]) == 3 else "UNVERIFIED"
    result["blockers"].append("controller/AP applied membership and field decision require independent review")
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
