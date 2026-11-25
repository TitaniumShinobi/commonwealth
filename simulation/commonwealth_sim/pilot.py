"""Offline preparation checks and field evidence gates for Commonwealth Step 7."""
import argparse
import hashlib
import ipaddress
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from .namespace_pilot import exercise

TARGET = "2026-11-30"
ROLES = ("handoff", "gateway", "switch", "access_points", "management",
         "dhcp_dns", "power", "participant_device", "control_device")
COSTS = ("equipment", "installation", "uplink", "overage", "power", "staffing",
         "support", "maintenance", "spares", "continuity")
LIMITS = ("join_seconds", "load_participants", "withdrawal_seconds",
          "interruption_seconds", "recovery_seconds", "probe_seconds")
READINESS = {
    "site_audience_and_permission": "site owner",
    "operator_support_and_recovery": "site operator and recovery owner",
    "funding_and_zero_price": "funding owner and site operator",
    "permitted_upstream": "account holder and provider if needed",
    "equipment_power_and_interfaces": "equipment and technical owners",
    "baseline_and_local_recovery": "site operator",
    "test_plan_limits_and_window": "field acceptance authority",
}
FIELD = {
    "attachment": "ordinary device and AP",
    "invalid_credential": "AP admission",
    "ipv4_lease": "ordinary device and DHCP",
    "dhcp_failure_and_recovery": "DHCP and participant path",
    "fresh_dns": "ordinary device and resolver",
    "cache_expiry_and_recovery": "ordinary device and resolver",
    "independent_https": "ordinary device",
    "zero_participant_cost": "participant and funding terms",
    "representative_load": "participant and independent site probe",
    "guest_household_management_isolation": "each forwarding boundary",
    "future_admission_denial": "every applicable AP admission path",
    "existing_forwarding_denial": "each forwarding boundary",
    "new_forwarding_denial": "each forwarding boundary",
    "eviction_withheld_association": "AP and ordinary device",
    "copied_roamed_changed_lease_restart": "controller and each forwarding boundary",
    "unaffected_participant": "independent control device",
    "crossing_cleanup_and_stale_reuse": "deployed crossing enforcement boundary",
    "uplink_loss_local_management_withdrawal": "local operator and participant path",
    "restored_public_access": "ordinary device and resolver",
    "rollback_and_revocation_preserved": "local management and host and guest probes",
}


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validated(profile):
    problems = []
    interfaces = profile["interfaces"]
    zones = profile["zones"]
    ranges = {role: ipaddress.IPv4Network(value) for role, value in zones.items()}
    if set(ranges) != {"guest", "household", "service", "management", "wan"}:
        problems.append("zones")
    for i, network in enumerate(ranges.values()):
        if any(network.overlaps(other) for other in list(ranges.values())[:i]):
            problems.append("overlapping_networks")
            break
    if (set(interfaces) != set(zones) or len(set(interfaces.values())) != len(interfaces)
            or set(interfaces.values()) != {"cwg0", "cwh0", "cws0", "cwm0", "cww0"}):
        problems.append("unknown_or_reused_interface")
    guest = ranges["guest"]
    pool = [ipaddress.IPv4Address(x) for x in profile["dhcp_pool"]]
    gateway = ipaddress.IPv4Address(profile["gateway"])
    if (len(pool) != 2 or pool[0] > pool[1]
            or any(x not in guest or x in (guest.network_address, guest.broadcast_address)
                   for x in [*pool, gateway])
            or int(pool[0]) <= int(gateway) <= int(pool[1]) or profile["resolver"] != str(gateway)):
        problems.append("dhcp_or_resolver")
    for role in ROLES:
        item = profile["equipment"].get(role, {})
        if not all(item.get(key) for key in ("model", "revision", "interface", "owner", "power", "mode")):
            problems.append(f"equipment:{role}")
    if (not profile["authenticated_session_mapping"] or
            set(profile["enforcement_paths"]) != {"ipv4-local", "ipv4-wan", "local-bridge"}):
        problems.append("session_mapping_or_paths")
    if (profile["participant_ipv6"] or profile["participant_router_advertisements"]
            or not profile["local_management"] or profile["wan_handoff"] != "ethernet"):
        problems.append("management_ipv6_or_handoff")
    if set(profile["fixture_funding"]) != set(COSTS) or not all(profile["fixture_funding"].values()):
        problems.append("funded_obligations")
    if profile["participant_price_minor"] != 0:
        problems.append("participant_price")
    if profile["activation"] != "HELD" or profile["environment"] != "synthetic":
        problems.append("activation_or_environment")
    return problems


def config_text(profile):
    interface = profile["interfaces"]["guest"]
    gateway = profile["gateway"]
    low, high = profile["dhcp_pool"]
    return (f"interface={interface}\nbind-interfaces\nlisten-address={gateway}\n"
            f"dhcp-range={low},{high},255.255.255.0,1h\n"
            f"dhcp-option=option:router,{gateway}\ndhcp-option=option:dns-server,{gateway}\n"
            "no-resolv\nno-hosts\nserver=203.0.113.2\n")


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        instant = datetime.fromisoformat(value)
        return instant if instant.utcoffset() is not None else None
    except ValueError:
        return None


def assess(field):
    def evidence(record, scope):
        return (isinstance(record, dict) and record.get("scope") == scope
                and all(record.get(k) for k in ("owner", "reference"))
                and timestamp(record.get("observed_at")) is not None
                and record.get("site_ref") == field.get("site_ref")
                and record.get("configuration_ref") == field.get("configuration_ref")
                and bool(field.get("site_ref") and field.get("configuration_ref")))

    missing = [key for key in READINESS if not evidence(field["readiness"].get(key), "direct")]
    if any(type(field["limits"].get(key)) is not int or field["limits"][key] <= 0 for key in LIMITS):
        missing.append("approved_positive_limits")
    if field["participant_price_minor"] != 0:
        missing.append("documented_zero_price")
    if field.get("target") != TARGET:
        missing.append("target")
    run = field.get("field_run") or {}
    approval = field.get("activation_authority") or {}
    start = timestamp(run.get("starts_at"))
    end = timestamp(run.get("ends_at"))
    approved_at = timestamp(approval.get("observed_at"))
    authorization = (evidence(approval, "direct") and start is not None and end is not None
                     and approved_at <= start < end and bool(run.get("run_ref"))
                     and all(approval.get(k) == run.get(k) for k in ("run_ref", "starts_at", "ends_at"))
                     and run.get("authority_ref") == approval.get("reference"))
    pending, failures, rejected = [], [], {}
    for key in FIELD:
        row = field["observations"].get(key)
        if row is None:
            pending.append(key)
            continue
        if not isinstance(row, dict):
            pending.append(key)
            rejected[key] = "invalid_observation"
            continue
        if not authorization:
            pending.append(key)
            rejected[key] = "run_or_window_not_authorized"
            continue
        observed = timestamp(row.get("observed_at"))
        if (row.get("site_ref"), row.get("configuration_ref")) != (
                field.get("site_ref"), field.get("configuration_ref")):
            rejected[key] = "site_or_configuration_mismatch"
        elif row.get("run_ref") != run["run_ref"]:
            rejected[key] = "mixed_run"
        elif row.get("authority_ref") != run["authority_ref"]:
            rejected[key] = "activation_authority_mismatch"
        elif observed is None:
            rejected[key] = "invalid_observation_timestamp"
        elif not start <= observed < end:
            rejected[key] = "outside_activation_window"
        if key in rejected:
            pending.append(key)
        elif (not evidence(row, "field")
              or not all(row.get(k) for k in ("vantage", "criterion_ref", "enforcement_boundary"))
              or "observed_result" not in row):
            pending.append(key)
        elif row.get("verdict") == "FAIL":
            failures.append(key)
        elif row.get("verdict") != "PASS":
            pending.append(key)
    ready = "UNVERIFIED" if missing else "PASS"
    verdict = "FAIL" if failures else "UNVERIFIED" if pending or missing or not authorization else "PASS"
    return {"target": TARGET, "target_forecast": "UNVERIFIED" if missing else "ELIGIBLE_FOR_FIELD_REVIEW",
            "ready_to_request_activation": ready, "activation": "HELD" if not authorization else "AUTHORITY_RECORDED",
            "field_acceptance": verdict, "missing_readiness": missing,
            "field_run_ref": run.get("run_ref"), "receipt_binding_rejections": rejected,
            "missing_field_observations": pending, "observed_field_failures": failures}


class Site:
    def __init__(self, profile):
        self.profile = profile
        self.sessions = {}
        self.allowed = {"device-1", "device-2"}
        self.withdrawn = set()
        self.flows = {}
        self.leases = {}
        self.events = []
        self.cache = {}
        self.uplink = self.resolver = self.dhcp = self.mapping = self.management = True
        self.issuing = False
        self.candidate = False
        self.crossings = {"affected": {"token": "old", "session": "temporary", "buffer": "queued",
                                       "pending": ["work"], "effects": 0},
                          "unrelated": {"token": "other", "effects": 0}}

    def apply(self, p):
        return getattr(self, p["action"])(**{k: v for k, v in p.items() if k != "action"})

    def status(self, component, online):
        if component not in ("uplink", "resolver", "dhcp"):
            raise ValueError("unknown failure boundary")
        setattr(self, component, online)
        return {"component": component, "online": online}

    def attach(self, credential, session, ap):
        approved = credential in self.allowed and credential not in self.withdrawn and self.mapping
        if approved:
            self.sessions[session] = {"credential": credential, "ap": ap}
        return {"admitted": approved}

    def provision(self, session, address):
        guest = ipaddress.IPv4Network(self.profile["zones"]["guest"])
        candidate = ipaddress.IPv4Address(address)
        allowed = (self.dhcp and self.eligible(session) and candidate in guest
                   and candidate not in (guest.network_address, guest.broadcast_address)
                   and address != self.profile["gateway"]
                   and all(value != address or key == session for key, value in self.leases.items()))
        if allowed:
            self.leases[session] = address
            return {"lease": address, "gateway": self.profile["gateway"], "resolver": self.profile["resolver"]}
        return {"lease": None}

    def eligible(self, session):
        return (self.mapping and session in self.sessions
                and self.sessions[session]["credential"] not in self.withdrawn)

    def roam(self, session, ap, address):
        self.sessions[session]["ap"] = ap
        self.leases[session] = address
        return {"associated": True, "forwarding_eligible": self.eligible(session)}

    def resolve(self, session, name, tick):
        if not self.eligible(session) or session not in self.leases:
            return {"resolved": False}
        if self.cache.get(name, -1) > tick:
            return {"resolved": True, "source": "cache"}
        if not self.resolver or not self.uplink:
            return {"resolved": False}
        self.cache[name] = tick + 3
        return {"resolved": True, "source": "recursion"}

    def forward(self, session, destination, name, direction="outbound"):
        allowed = (self.eligible(session) and session in self.leases and self.uplink
                   and destination == "synthetic-wan"
                   and (direction == "outbound" or self.flows.get(name) == session))
        if allowed:
            self.flows[name] = session
        return {"forwarded": allowed}

    def withdraw(self, credential):
        self.withdrawn.add(credential)
        steps = ["persist_deny_both_directions"]
        affected = sorted(k for k, v in self.sessions.items() if v["credential"] == credential)
        removed = sorted(k for k, v in self.flows.items() if v in affected)
        self.flows = {k: v for k, v in self.flows.items() if k not in removed}
        steps += ["clear_connection_state", "deny_future_admission", "observe_eviction_separately"]
        return {"affected_sessions": affected, "cleared_flows": removed,
                "evicted": False, "ordering": steps}

    def observe(self, session, flow):
        return {"associated": session in self.sessions, "lease": self.leases.get(session),
                "flow_exists": flow in self.flows, "management": self.management}

    def restart(self, mapping_verified):
        self.mapping = False
        self.flows.clear()
        self.mapping = mapping_verified
        return {"mapping_verified": self.mapping, "withdrawn": sorted(self.withdrawn)}

    def stage(self, target, baseline, candidate):
        self.candidate = target == "fixture-site" and baseline == "verified-baseline" and bool(candidate)
        self.issuing = False
        return {"staged": self.candidate, "issuing": self.issuing}

    def apply_site(self, activation):
        return {"applied": False, "reason": "fixture_has_no_activation_authority",
                "issuing": self.issuing}

    def rollback(self, verified):
        self.issuing = False
        self.candidate = False
        return {"guest_path": "closed", "baseline": "verified" if verified else "unverified",
                "incident": not verified, "withdrawn": sorted(self.withdrawn)}

    def close(self, name):
        crossing = self.crossings[name]
        crossing.update(token=None, session=None, buffer=None, pending=[])
        return crossing.copy()

    def crossing(self, name, token):
        crossing = self.crossings.get(name, {})
        allowed = token is not None and crossing.get("token") == token
        if allowed:
            crossing["effects"] += 1
        return {"allowed": allowed, "disclosed": allowed, "effects": crossing.get("effects", 0)}

    def renew(self, name, token, newly_authorized):
        allowed = name not in self.crossings and newly_authorized
        if allowed:
            self.crossings[name] = {"token": token, "effects": 0}
        return {"opened": allowed}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("layer", choices=("model", "gateway"))
    parser.add_argument("profile", type=Path)
    parser.add_argument("field", type=Path)
    parser.add_argument("cases", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    profile, field, fixtures = [json.loads(path.read_text()) for path in
                                (args.profile, args.field, args.cases)]
    smoke = json.loads((args.out.parent.parent / "smoke.json").read_text())
    revision = os.environ["GITHUB_SHA"]
    if smoke["verdict"] != "PASS" or smoke["revision"] != revision:
        raise SystemExit("current revision smoke PASS required")
    config = config_text(profile)
    problems = validated(profile)
    data = {"environment": "synthetic", "layer": args.layer, "revision": revision,
            "workflow_sha": os.getenv("GITHUB_WORKFLOW_SHA"), "run": os.getenv("GITHUB_RUN_ID"),
            "image": os.getenv("ImageVersion", "unavailable"), "command": [sys.executable, *sys.argv],
            "profile_sha256": sha(args.profile.read_bytes()), "field_sha256": sha(args.field.read_bytes()),
            "cases_sha256": sha(args.cases.read_bytes()), "dhcp_dns_config_sha256": sha(config.encode()),
            "readiness": assess(field), "configuration_problems": problems}
    if args.layer == "model":
        checks = []
        for name, steps in fixtures["cases"].items():
            site = Site(profile)
            for step in steps:
                observed = site.apply(step["input"])
                checks.append({"case": name, "input": step["input"], "expected": step["expect"],
                               "observed": observed, "matches": observed == step["expect"]})
        for name, patch, required in fixtures["invalid_profiles"]:
            observed = validated({**profile, **patch})
            checks.append({"case": name, "expected": required, "observed": observed,
                           "matches": required in observed})
        for name, patch, expected in fixtures["readiness"]:
            observed = assess({**field, **patch})
            checks.append({"case": name, "expected": expected, "observed": observed,
                           "matches": all(observed[k] == v for k, v in expected.items())})
        data.update(checks=checks, verdict="FAIL" if problems or not all(x["matches"] for x in checks) else "PASS")
    elif problems:
        data.update(verdict="FAIL", reason="invalid fixture profile")
    else:
        data.update(exercise(profile, config))
    from .__main__ import save
    save(args.out, data)
    print(f"Step 7 {args.layer}: {data['verdict']}")
    return {"PASS": 0, "FAIL": 1, "UNVERIFIED": 2}[data["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
