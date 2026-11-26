"""Score bench observations offline. This command cannot authorize signed admission."""
import argparse
import hashlib
import ipaddress
import json
import math
import re
import time
from pathlib import Path

from readback import digest, identifier

DATASETS = ("networks", "wifi/broadcasts", "devices", "clients")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(1048577)
    require(len(raw) <= 1048576, "receipt exceeds size limit")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def station(row, ip_field):
    mac, ip, vlan = row["mac"], row[ip_field], row["vlan"]
    require(re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac) is not None
            and str(ipaddress.IPv4Address(ip)) == ip
            and type(vlan) is int and 1 <= vlan <= 4094, "invalid station identity or VLAN")
    return identifier(row["client_id"]), mac, ip, vlan


def bench_stations(config):
    rows = config["stations"]
    roles = {row["role"]: station(row, "source_ipv4") for row in rows}
    require(len(rows) == 3 and set(roles) == {"A", "B", "C"}
            and all(len({row[i] for row in roles.values()}) == 3 for i in range(3))
            and roles["A"][3] == roles["B"][3] != roles["C"][3],
            "expected distinct A/B/C stations and separate control VLAN")
    return roles


def inventory(config, receipt):
    require(receipt["scope"] == "read_only_unifi_local_api" and not receipt.get("blocker")
            and receipt["guard_readback_issued"] is False
            and receipt["configuration_consistent"] is True and receipt["failures"] == []
            and receipt["config_sha256"] == digest(config), "controller receipt incomplete or inconsistent")
    groups = config["groups"]
    require(len(groups) == 2 and sorted(len(group["client_ids"]) for group in groups) == [1, 2],
            "expected two credential groups")
    site = identifier(config["site_id"])
    pin = config["certificate_sha256"]
    requests = receipt["requests"]
    require(re.fullmatch(r"[0-9a-f]{64}", pin) is not None and requests
            and all(row["status"] == 200 and row["certificate_sha256"] == pin for row in requests),
            "missing or mismatched authenticated request records")
    for dataset in DATASETS:
        summary = receipt["inventory"][dataset]
        pages = summary["pages"]
        rows = [row["path"] for row in requests if row["path"].startswith(f"/sites/{site}/{dataset}?")]
        require(0 <= summary["total"] <= 2000 and 1 <= len(pages) <= 20
                and rows == [f"/sites/{site}/{dataset}?offset={p['offset']}&limit=100" for p in pages],
                "missing or inconsistent inventory pages")
        offset = 0
        for page in pages:
            require(page["offset"] == offset and type(page["count"]) is int
                    and 0 <= page["count"] <= 100 and (page["count"] > 0 or len(pages) == 1)
                    and page["total"] == summary["total"], "inventory page counts do not reconcile")
            offset += page["count"]
        require(offset == summary["total"], "inventory count does not reconcile")
    observations = receipt["configuration_observations"]
    require(len(observations) == 2, "missing controller credential groups")
    result = {}
    for group, row in zip(groups, observations):
        require(all(row[field] == group[field] for field in ("credential_ref", "network_id", "broadcast_id", "ap_id",
                                                               "client_ids"))
                and row["vlan"] == group["vlan_id"]
                and row["network_type"] == group["reviewed_network_type"]
                and row["security_type"] == group["reviewed_personal_security_type"],
                "controller credential group mismatch")
        require([s["client_id"] for s in row["stations"]] == group["client_ids"],
                "controller client membership mismatch")
        for item in row["stations"]:
            client, mac, ip, vlan = station(item, "ipv4")
            require(client not in result and vlan == group["vlan_id"]
                    and sum(r["path"] == f"/sites/{site}/clients/{client}" for r in requests) == 1,
                    "missing or inconsistent client detail")
            result[client] = (client, mac, ip, vlan)
    require(len(result) == 3, "expected three controller clients")
    return result


def tagged(config, receipt, now):
    roles = bench_stations(config)
    trunk = config["trunk"]
    physical = (receipt["scope"] == "physical_bench_observation_only"
                and receipt["machine"] == "aarch64" and (receipt["model"] or "").startswith("Raspberry Pi 4")
                and 7 * 1024 * 1024 <= receipt["memory_kib"] <= 8 * 1024 * 1024)
    synthetic = receipt["scope"] == "synthetic_namespace_bench_observation" and trunk == "cwtag-rx"
    require(trunk != "lo" and (physical or synthetic)
            and receipt["bench_config_sha256"] == digest(config)
            and receipt["field_acceptance"] == "UNVERIFIED" and receipt["activation"] == "HELD"
            and receipt["trunk"] == {"interface": trunk, "observed": True}
            and config["approval_ref"] not in ("", "REQUIRED") and receipt["tagged_dataplane"] == "CORROBORATED"
            and receipt["blockers"] == ["controller/AP applied membership and field decision require independent review"],
            "bench topology, configuration, or capture status unverified")
    rows = receipt["received_tags"]
    require([row["role"] for row in rows] == ["A", "B", "C"], "expected exactly three ordered station captures")
    previous = 0
    for row in rows:
        _, mac, ip, vlan = roles[row["role"]]
        start, observed = row["window_started"], row["observed_at"]
        require(all(type(v) in (int, float) and math.isfinite(v) for v in (start, observed))
                and previous <= start <= observed <= now and observed - start <= 16
                and observed - rows[0]["window_started"] <= 50, "invalid capture window")
        previous = observed
        packet = row["record"]
        require((row["mac"], row["ipv4"], row["vlan"]) == (mac, ip, vlan)
                and len(packet) <= 4096 and "\n" not in packet
                and hashlib.sha256(packet.encode()).hexdigest() == row["sha256"]
                and re.search(rf" {re.escape(mac)} > [^,]+, .*ethertype 802\.1Q .*?\bvlan {vlan},.*?"
                              rf"ethertype IPv4 .*?, {re.escape(ip)}(?:\.\d+)? >", packet),
                "packet digest or observed MAC/IPv4/VLAN mismatch")
    return roles


def score(controller_config, bench_config, controller, controller_sha256, bench, now):
    report = {"scope": "offline receipt consistency only", "signed_admission": "HELD"}
    data = {}
    for gate, operation in (
        ("controller_inventory", lambda: inventory(controller_config, controller)),
        ("tagged_dataplane", lambda: tagged(bench_config, bench, now)),
    ):
        try:
            data[gate] = operation()
            report[gate] = {"verdict": "PASS"}
            if gate == "tagged_dataplane":
                report[gate]["evidence_scope"] = bench["scope"]
        except (KeyError, AttributeError, TypeError, ValueError, IndexError) as exc:
            report[gate] = {"verdict": "UNVERIFIED", "reason": str(exc)}
    try:
        require(len(data) == 2 and bench["controller_receipt_sha256"] == controller_sha256
                and data["controller_inventory"] == {row[0]: row for row in data["tagged_dataplane"].values()}
                and 0 <= controller["started_at"] <= controller["finished_at"]
                <= bench["received_tags"][0]["window_started"]
                <= controller["finished_at"] + 30,
                "controller receipt, station identities, or observation window do not bind")
        report["correlation"] = {"verdict": "PASS"}
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        report["correlation"] = {"verdict": "UNVERIFIED", "reason": str(exc)}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("controller_config", "bench_config", "controller_receipt", "tagged_receipt"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()

    def optional(path):
        try:
            return load(path)
        except (OSError, ValueError):
            return {}, None

    config, _ = optional(args.controller_config)
    bench_config, _ = optional(args.bench_config)
    controller, controller_sha = optional(args.controller_receipt)
    bench, _ = optional(args.tagged_receipt)
    result = score(config, bench_config, controller, controller_sha, bench, time.time())
    print(json.dumps(result, indent=2))
    return 0 if all(result[gate]["verdict"] == "PASS" for gate in
                    ("controller_inventory", "tagged_dataplane", "correlation")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
