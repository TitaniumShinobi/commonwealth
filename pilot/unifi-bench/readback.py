"""Read-only collector for a local, TLS-authenticated UniFi Network API."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

PREFIXES = {"/proxy/network/integration/v1", "/integration/v1"}
LOCAL = tuple(ipaddress.ip_network(p) for p in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                                                 "192.168.0.0/16", "::1/128", "fc00::/7"))


def identifier(value):
    normalized = str(uuid.UUID(value))
    if value != normalized:
        raise ValueError("noncanonical identifier")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Controller:
    def __init__(self, config, key):
        self.config = config
        self.key = key
        self.requests = []
        self.inventory = {}
        host = config["tls_name"]
        address = ipaddress.ip_address(config["address"])
        if not any(address in network for network in LOCAL) or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
            raise ValueError("controller must be a pinned private or loopback address")
        if config["prefix"] not in PREFIXES or type(config["port"]) is not int or not 1 <= config["port"] <= 65535:
            raise ValueError("unsupported pinned API route")
        if not key.strip() or "\n" in key or "\r" in key:
            raise ValueError("expected a local API key")
        self.context = ssl.create_default_context(cafile=config["ca_file"])

    def get(self, path):
        c = self.config
        class PinnedConnection(http.client.HTTPSConnection):
            def connect(inner):
                raw = socket.create_connection((c["address"], c["port"]), timeout=5)
                try:
                    inner.sock = self.context.wrap_socket(raw, server_hostname=c["tls_name"])
                except Exception:
                    raw.close()
                    raise
        connection = PinnedConnection(c["tls_name"], c["port"], timeout=5, context=self.context)
        try:
            connection.connect()
            certificate = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
            if certificate != c["certificate_sha256"]:
                raise ValueError("controller certificate pin mismatch")
            connection.request("GET", c["prefix"] + path, headers={"Accept": "application/json", "X-API-Key": self.key})
            response = connection.getresponse()
            self.requests.append({"path": path, "status": response.status, "certificate_sha256": certificate})
            if response.status != 200:
                raise RuntimeError(f"local API returned HTTP {response.status} for {path}")
            if response.getheader("Content-Type", "").split(";", 1)[0] != "application/json":
                raise RuntimeError("controller did not return JSON")
            raw = response.read(262145)
            if len(raw) > 262144:
                raise ValueError("response exceeds size bound")
            return json.loads(raw)
        finally:
            connection.close()

    def complete(self, path):
        values = []
        total = None
        pages = []
        for _ in range(20):
            page = self.get(f"{path}?offset={len(values)}&limit=100")
            data = page["data"]
            if (not isinstance(data, list) or page["count"] != len(data) or page["offset"] != len(values)
                    or type(page["totalCount"]) is not int or not 0 <= page["totalCount"] <= 2000
                    or total is not None and total != page["totalCount"]):
                raise ValueError("inconsistent pagination")
            total = page["totalCount"]
            pages.append({"offset": len(values), "count": len(data), "total": total})
            values.extend(data)
            if len(values) == total:
                break
            if not data or len(values) > total:
                raise ValueError("incomplete inventory")
        else:
            raise ValueError("inventory pagination exceeded bound")
        ids = [identifier(row["id"]) for row in values]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate inventory identifiers")
        self.inventory[path.rsplit('/sites/', 1)[-1].split('/', 1)[-1]] = {"total": total, "pages": pages}
        return dict(zip(ids, values))


def evaluate(config, networks, broadcasts, devices, clients):
    if sorted(len(group["client_ids"]) for group in config["groups"]) != [1, 2]:
        raise ValueError("expected shared A/B and independent C design")
    observations = []
    failures = []
    reserved = {}
    consumed_clients = set()
    for group in config["groups"]:
        group_name = group["credential_ref"]
        bid, nid, ap = (identifier(group[k]) for k in ("broadcast_id", "network_id", "ap_id"))
        vlan = group["vlan_id"]
        if type(vlan) is not int or not 1 <= vlan <= 4094 or vlan in reserved:
            raise ValueError("duplicate or invalid reserved VLAN")
        reserved[vlan] = bid
        network, broadcast, device = networks[nid], broadcasts[bid], devices[ap]
        if any(other_id != nid and row.get("enabled") is not False and row.get("vlanId") == vlan
               for other_id, row in networks.items()):
            failures.append(group_name + ": duplicate enabled network route")
        route = broadcast.get("network") or {}
        security = broadcast.get("securityConfiguration") or {}
        ap_filter = broadcast.get("broadcastingDeviceFilter") or {}
        projected = {"credential_ref": group_name, "vlan": vlan, "network_id": nid, "broadcast_id": bid,
                     "ap_id": ap, "security_type": security.get("type"), "network_type": route.get("type"),
                     "firmware": device.get("firmwareVersion"), "client_ids": [], "stations": []}
        if (network.get("enabled") is not True or network.get("vlanId") != vlan or broadcast.get("enabled") is not True
                or route.get("networkId") != nid or route.get("type") != group["reviewed_network_type"]
                or device.get("state") != "ONLINE" or ap_filter.get("deviceIds") != [ap]
                or ap_filter.get("type") != group["reviewed_ap_filter_type"]
                or security.get("type") != group["reviewed_personal_security_type"]):
            failures.append(group_name + ": configuration or AP scope mismatch")
        if (not isinstance(security.get("type"), str)
                or "PERSONAL" not in security["type"].upper()
                or any(part in security["type"].upper() for part in ("PPSK", "ENTERPRISE", "OPEN"))):
            failures.append(group_name + ": personal security mode is ambiguous")
        for client_id in group["client_ids"]:
            client_id = identifier(client_id)
            if client_id in consumed_clients:
                raise ValueError("client assigned to more than one credential")
            consumed_clients.add(client_id)
            row = clients.get(client_id) or {}
            projected["client_ids"].append(client_id)
            projected["stations"].append({"client_id": client_id, "mac": row.get("macAddress"),
                                          "ipv4": row.get("ipAddress"), "vlan": vlan})
            if row.get("uplinkDeviceId") is not None and row["uplinkDeviceId"] != ap:
                failures.append(group_name + ": controller-reported client uplink mismatch")
            if row.get("access", {}).get("authorized") is not True:
                failures.append(group_name + ": expected client authorization unavailable")
        observations.append(projected)
    for bid, row in broadcasts.items():
        if row.get("enabled") is False:
            continue
        route = row.get("network") or {}
        target = networks.get(route.get("networkId")) or {}
        if row.get("enabled") is not True or not target or route.get("type") != config["reviewed_static_network_type"]:
            failures.append("unresolved or dynamic enabled broadcast route: " + bid)
            continue
        vlan = target.get("vlanId")
        if vlan in reserved and reserved[vlan] != bid:
            failures.append("conflicting enabled broadcast on reserved VLAN: " + bid)
    return observations, sorted(set(failures))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("configuration", type=Path)
    p.add_argument("--api-key-file", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    receipt = {"scope": "read_only_unifi_local_api", "physical_authorization": "HELD",
               "guard_readback_issued": False, "mapping": "UNVERIFIED", "started_at": int(time.time())}
    controller = None
    try:
        config = json.loads(args.configuration.read_text())
        if config["design"] != "one-psk-per-ssid-review-alternative":
            raise ValueError("explicit one-PSK-per-SSID alternative selection required")
        mode = args.api_key_file.stat().st_mode & 0o777
        if mode & 0o077:
            raise ValueError("API key file permissions must exclude group and other access")
        controller = Controller(config, args.api_key_file.read_text().strip())
        site = identifier(config["site_id"])
        route = f"/sites/{site}"
        datasets = [controller.complete(route + "/" + name) for name in ("networks", "wifi/broadcasts", "devices", "clients")]
        for group in config["groups"]:
            for client_id in group["client_ids"]:
                client_id = identifier(client_id)
                detail = controller.get(route + "/clients/" + client_id)
                if detail.get("id") != client_id:
                    raise ValueError("connected client detail identity mismatch")
                datasets[-1][client_id] = {**datasets[-1][client_id], **detail}
        observations, failures = evaluate(config, *datasets)
        receipt.update(config_sha256=digest(config), configuration_observations=observations,
                       configuration_consistent=not failures, failures=failures)
        receipt["blocking_requirements"] = ["independently authenticated AP-applied credential/VLAN membership",
                                             "fresh station-tagged dataplane proof", "approved bench authority"]
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException) as exc:
        receipt["blocker"] = str(exc)
    finally:
        receipt["requests"] = controller.requests if controller else []
        receipt["inventory"] = controller.inventory if controller else {}
        receipt["finished_at"] = int(time.time())
        args.out.write_text(json.dumps(receipt, indent=2) + "\n")
    # A collector receipt is never an authorization or guard admission envelope.
    return 2 if "blocker" in receipt else 0


if __name__ == "__main__":
    raise SystemExit(main())
