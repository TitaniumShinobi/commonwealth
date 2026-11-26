"""Validate observed membership and produce the exact Wi-Fi guard envelope.

Cloud tests inject an explicitly synthetic observer and use a disposable signing key.
No command-line path accepts injected observations or signs without an AP witness.
"""
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

TARGET_FIELDS = ("edge", "ap", "credential", "generation", "vlan", "interface", "subnet")
CHALLENGE_FIELDS = {"nonce", "epoch", "kind", "expires_at"}


def issue(target, current_challenge, observe, signing_key):
    if set(target) != set(TARGET_FIELDS) or type(target["generation"]) is not int:
        raise ValueError("invalid guard target")
    target = dict(target)
    challenge = dict(current_challenge())
    if (set(challenge) != CHALLENGE_FIELDS or not re.fullmatch(r"[0-9a-f]{48}", challenge["nonce"])
            or type(challenge["epoch"]) is not int or challenge["epoch"] < 1
            or challenge["kind"] not in ("admit", "renew")
            or type(challenge["expires_at"]) is not int):
        raise ValueError("invalid gateway challenge")
    started = time.time()
    if started >= challenge["expires_at"]:
        raise ValueError("gateway challenge expired")
    proof = observe(dict(target), dict(challenge))
    now = time.time()
    if (now >= challenge["expires_at"] or current_challenge() != challenge
            or proof["target"] != target or proof["challenge"] != challenge):
        raise ValueError("stale or mismatched target/challenge")
    if (proof["complete_inventory"] is not True or proof["authenticated_ap"] is not True
            or proof["single_personal_psk"] is not True or proof["conflicts"]
            or proof["vlan_credentials"] != [target["credential"]]
            or proof["future_admission"] != "allowed"):
        raise ValueError("exclusive AP-applied membership not established")
    stations = proof["stations"]
    tags = proof["tags"]
    if set(stations) != {"A", "B", "C"} or set(tags) != set(stations):
        raise ValueError("missing independent A/B/C witnesses")
    identities = set()
    shared_vlan = stations["A"]["vlan"]
    control_vlan = stations["C"]["vlan"]
    if shared_vlan != stations["B"]["vlan"] or shared_vlan == control_vlan or target["vlan"] not in (shared_vlan, control_vlan):
        raise ValueError("wrong shared or control VLAN")
    for role, station in stations.items():
        tag = tags[role]
        identity = (station["mac"], station["ipv4"])
        if identity in identities or tag["station"] != station or not started <= tag["observed_at"] <= now:
            raise ValueError("stale or mismatched tagged witness")
        identities.add(identity)
    body = {**target, **challenge, "future_admission": "allowed", "vlan_credentials": [target["credential"]]}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "body"
        path.write_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        result = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", signing_key, "-in", path],
                                check=True, capture_output=True, timeout=5)
    if current_challenge() != challenge or time.time() >= challenge["expires_at"]:
        raise ValueError("gateway challenge changed during signing")
    return {"body": body, "signature": result.stdout.hex()}
