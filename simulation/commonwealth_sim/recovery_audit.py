"""Independent reconciliation of the modeled recovery dispatch and effect ledgers."""
from .recovery import digest

# This inventory covers fixture principals and privilege-bearing outputs.
# The controllers and actors share a runner and public fixture keys.
CAPABILITIES = {
    "00-lifecycle": {"loss"}, "00-source": {"source_commit"}, "op-a": {"enroll"},
    "op-b": {"enroll", "read", "read_gate", "cross_queue", "cross_use", "rejoin_candidate"},
    "backup-owner": {"capture", "snapshot"}, "old-host": {
        "backup", "observe_version", "old_read", "disclose", "write", "credential_check"},
    "new-host": {"restore_result", "disclose"}, "restore-owner": {"approve", "restore_commit"},
    "a-steward": {"restore"}, "authz-owner": {"withdraw", "renew"},
    "ingress-owner": {"fence"}, "writer-owner": {"fence"}, "credential-owner": {"issue"},
    "publisher": {"publish", "binding", "rejoin_candidate"},
    "serve-gate": {"read_store", "read_result"}, "recover-authz": {"checkpoint", "reconcile"},
    "recover-pub": {"checkpoint", "reconcile"}, "recover-creds": {"checkpoint", "reconcile"},
    "fixture-observer": {"version_readback", "version_verified", "store_state", "peer_state",
                         "authority_state", "audit_state", "control_commit", "control_read"},
    "founder": set(), "founder-delegate": set(),
}

BOUNDARIES = {"old_read", "read_gate", "disclose", "write", "restore", "restore_commit",
              "binding", "issue", "publish", "cross_use", "credential_check", "renew"}

READ_ONLY = {"capture", "snapshot", "version_readback", "observe_version", "store_state",
             "read", "read_gate", "read_store", "read_result", "disclose", "old_read",
             "peer_state", "control_read", "credential_check", "rejoin_candidate",
             "authority_state", "audit_state"}
ACCEPTANCE = {
    "enroll": {"enrolled"}, "source_commit": {"source_committed"},
    "version_verified": {"version_verified"}, "backup": {"backup_verified"},
    "loss": {"host_lost"}, "fence": {"fenced"}, "withdraw": {"withdrawn"},
    "approve": {"approved"},
    "restore_commit": {"restored"}, "restore_result": {"restore_recorded"},
    "issue": {"credential_issued"}, "publish": {"published"}, "binding": {"binding_accepted"},
    "write": {"committed"}, "checkpoint": {"checkpoint_loaded"}, "reconcile": {"reconciled"},
    "cross_queue": {"queued"}, "cross_use": {"crossing_operated"},
    "renew": {"fresh_authorization"}, "control_commit": {"control_committed"},
    "disclose": {"allowed"}, "read_result": {"allowed"},
}


def summarize(dispatches, records, fixture, lifecycle):
    """Compare original ordered dispatches with readback from append-only actor ledgers."""
    expected_by_id = {}
    for item in dispatches:
        envelope = item["request"]["envelope"]
        operation = envelope["payload"]["op"]
        if operation == "audit_state":
            continue
        key = (envelope["sender"], envelope["id"], item["actor"])
        expected_by_id[key] = (envelope, item["reply"])
    observed_by_id = {(row["principal"], row["id"], row["actor"]): row for row in records}
    compared = set(expected_by_id) == set(observed_by_id) and len(observed_by_id) == len(records)
    unauthorized, founder, unaccounted = 0, 0, 0
    attempts, rejections, effects = 0, 0, 0
    for key, row in observed_by_id.items():
        envelope, reply = expected_by_id.get(key, ({}, {}))
        observation = reply.get("observation", {})
        op = row["operation"]
        complete = (envelope.get("tick") == row["tick"] and envelope.get("payload", {}).get("op") == op
                    and row["request_sha256"] == digest(envelope.get("payload"))
                    and row["reply_sha256"] == digest(reply)
                    and observation.get("decision") == row["decision"])
        compared &= complete
        known = row["decision"] in ACCEPTANCE.get(op, set())
        state_change = row["pre_state_sha256"] != row["post_state_sha256"]
        disclosed = row["disclosed"]
        effect = known or state_change or disclosed
        effects += effect
        if op in BOUNDARIES:
            attempts += 1
            rejections += not effect and row["decision"] not in (
                "duplicate_restore", "read_admitted", "credential_allowed")
        if not effect:
            continue
        if row["principal"] in ("founder", "founder-delegate"):
            founder += 1
        if (not complete or op not in CAPABILITIES.get(row["principal"], set())
                or (state_change and op in READ_ONLY)):
            unaccounted += 1
        if op in BOUNDARIES or disclosed:
            tick = fixture["ticks"].get(str(row["tick"]), {})
            checks = tick.get("expect", {})
            explicit = checks.get(f'{row["actor"]}/{op}', checks.get(op))
            # For the actual disclosure boundary the peer's correlated read result
            # is the reference criterion. An unplanned release is always a violation.
            if op == "disclose":
                explicit = checks.get("read_result")
            if (not explicit or explicit["decision"] != row["decision"]
                    or (disclosed and explicit.get("disclosed") is not True)):
                unauthorized += 1
    lifecycle_ok = [(e["lifecycle"], e["tick"]) for e in lifecycle] == [
        ("old_host_reaped", 10), ("clean_host_started", 12)]
    return {"reconciled": compared and lifecycle_ok, "attempts": attempts,
            "rejections": rejections, "recorded_effects": effects,
            "unauthorized_effects": unauthorized, "founder_or_delegate_effects": founder,
            "unaccounted_effects": unaccounted, "dispatches": len(expected_by_id),
            "journal_entries": len(records), "window": [0, fixture["end"]],
            "inventory_sha256": digest({k: sorted(v) for k, v in CAPABILITIES.items()})}
