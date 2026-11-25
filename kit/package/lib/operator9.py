"""Local Step 9 operation authority. All state effects and receipts commit together."""
import argparse
import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path


class Denied(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha(value):
    return hashlib.sha256(value).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    Path(path).write_bytes(canonical(value))


def init(path):
    directory = Path(path).resolve()
    directory.mkdir(mode=0o700)
    with sqlite3.connect(directory / "authority.sqlite") as db:
        db.executescript("""
            CREATE TABLE state (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE decisions (id TEXT PRIMARY KEY, approval TEXT NOT NULL, result TEXT);
        """)
        db.execute("INSERT INTO state VALUES (1, ?)", (canonical({
            "revision": 1, "approver": "local-operator", "active": True, "settings": {},
            "peers": {}, "withdrawn": [], "binding_floor": 0}).decode(),))
    return {"decision": "authority_initialized", "scope": "local-fixture"}


def release():
    proof = Path(__file__).resolve().parent.parent / ".release-proof.json"
    return load(proof)["release_sha256"]


def make_plan(directory, action, target, payload):
    path = Path(target)
    if not path.is_absolute():
        raise Denied("target_must_be_absolute")
    if action not in ("configure", "enroll", "exit", "upgrade", "rollback", "restore"):
        raise Denied("unsupported_action")
    return {"actor": "local-operator", "action": action, "target": str(path.resolve()),
            "release_sha256": release(), "payload": payload,
            "authority": str(Path(directory).resolve())}


def database(directory):
    path = Path(directory).resolve() / "authority.sqlite"
    return sqlite3.connect(f"{path.as_uri()}?mode=rw", uri=True, timeout=3,
                           isolation_level=None)


def state_of(db):
    return json.loads(db.execute("SELECT body FROM state WHERE id=1").fetchone()[0])


def validate_plan(directory, plan, target):
    if plan["target"] != str(Path(target).resolve()):
        raise Denied("target_changed")
    if plan["authority"] != str(Path(directory).resolve()) or plan["release_sha256"] != release():
        raise Denied("plan_changed")


def issue(directory, plan, seconds):
    validate_plan(directory, plan, plan["target"])
    if not 0 <= seconds <= 300:
        raise Denied("invalid_approval_duration")
    with database(directory) as db:
        db.execute("BEGIN IMMEDIATE")
        authority = state_of(db)
        if not authority["active"] or authority["approver"] != plan["actor"]:
            raise Denied("approver_inactive")
        approval = {"actor": plan["actor"], "action": plan["action"], "target": plan["target"],
                    "release_sha256": plan["release_sha256"], "plan_sha256": sha(canonical(plan)),
                    "authority_revision": authority["revision"], "expires": int(time.time()) + seconds,
                    "operation_id": uuid.uuid4().hex}
        db.execute("INSERT INTO decisions VALUES (?, ?, NULL)",
                   (approval["operation_id"], canonical(approval).decode()))
        return approval


def mutate(authority, plan):
    action, body = plan["action"], plan["payload"]
    if action == "configure":
        if set(body) != {"name", "protocol"} or body["protocol"] != 1:
            raise Denied("configuration_incompatible")
        authority["settings"] = body
    elif action == "enroll":
        if set(body) != {"operator", "operator_sha256", "publication_sha256",
                         "serving_sha256", "locator", "protocol"} or body["protocol"] != 1:
            raise Denied("card_incompatible")
        authority["peers"][body["operator"]] = body
        if body["operator"] in authority["withdrawn"]:
            authority["withdrawn"].remove(body["operator"])
    elif action == "exit":
        peer = body["operator"]
        authority["peers"].pop(peer, None)
        authority["withdrawn"] = sorted(set([*authority["withdrawn"], peer]))
    elif action in ("upgrade", "rollback"):
        if body.get("protocol") != 1 or body.get("state_schema") != 1:
            raise Denied("release_incompatible")
        authority["selected_configuration"] = body["configuration"]
    elif action == "restore":
        if body.get("ingress_fenced") is not True or body.get("writer_fenced") is not True:
            raise Denied("protected_service_closed")
        if body.get("authority_revision") != authority["revision"]:
            raise Denied("authority_superseded_or_revoked")
        if (body.get("backup_sha256") != sha(canonical(body["application"]))
                or body.get("binding_revision", 0) <= authority["binding_floor"]):
            raise Denied("backup_or_binding_rejected")
        authority["application"] = body["application"]
        authority["binding_floor"] = body["binding_revision"]
    return authority


def apply(directory, plan, approval, target):
    if not approval:
        raise Denied("approval_required")
    validate_plan(directory, plan, target)
    if approval.get("target") != str(Path(target).resolve()):
        raise Denied("target_changed")
    if approval.get("plan_sha256") != sha(canonical(plan)):
        raise Denied("peer_card_changed" if plan["action"] == "enroll" else "plan_changed")
    with database(directory) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT approval,result FROM decisions WHERE id=?",
                         (approval.get("operation_id"),)).fetchone()
        if not row or json.loads(row[0]) != approval:
            raise Denied("unknown_approval")
        if row[1]:
            return json.loads(row[1])
        authority = state_of(db)
        if (not authority["active"] or approval["actor"] != authority["approver"]
                or approval["authority_revision"] != authority["revision"]):
            raise Denied("authority_superseded_or_revoked")
        if int(time.time()) >= approval["expires"]:
            raise Denied("approval_expired")
        result = {"decision": "applied", "operation_id": approval["operation_id"],
                  "action": plan["action"], "target": plan["target"]}
        updated = mutate(authority, plan)
        db.execute("UPDATE state SET body=? WHERE id=1", (canonical(updated).decode(),))
        db.execute("UPDATE decisions SET result=? WHERE id=?",
                   (canonical(result).decode(), approval["operation_id"]))
        return result


def rotate(directory, active):
    with database(directory) as db:
        db.execute("BEGIN IMMEDIATE")
        current = state_of(db)
        current["revision"] += 1
        current["active"] = active
        db.execute("UPDATE state SET body=? WHERE id=1", (canonical(current).decode(),))
        return {"decision": "authority_updated", "revision": current["revision"], "active": active}


def export(directory, failure, confirmed):
    if not confirmed:
        raise Denied("diagnostic_review_required")
    if failure not in ("configuration", "discovery", "reachability", "identity", "version", "authorization"):
        raise Denied("unrecognized_diagnostic_boundary")
    with database(directory) as db:
        revision = state_of(db)["revision"]
    return {"schema": 1, "boundary": failure, "authority_revision": revision}


def main(argv):
    parser = argparse.ArgumentParser(prog="commonwealth operator")
    parser.add_argument("action", choices=("init", "plan", "approve", "apply", "rotate", "inspect",
                                           "diagnostics", "guide", "bootstrap"))
    parser.add_argument("--authority", required=True)
    for key in ("operation", "target", "payload", "plan", "approval", "out", "boundary",
                "ready", "name"):
        parser.add_argument(f"--{key}")
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--withdraw", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args(argv)
    directory = args.authority
    try:
        if args.action == "init":
            result = init(directory)
        elif args.action == "plan":
            result = make_plan(directory, args.operation, args.target, load(args.payload))
        elif args.action == "approve":
            if not args.confirm:
                raise Denied("explicit_confirmation_required")
            result = issue(directory, load(args.plan), args.seconds)
        elif args.action == "apply":
            result = apply(directory, load(args.plan), load(args.approval) if args.approval else None, args.target)
        elif args.action == "rotate":
            if not args.confirm:
                raise Denied("explicit_confirmation_required")
            result = rotate(directory, not args.withdraw)
        elif args.action == "diagnostics":
            result = export(directory, args.boundary, args.confirm)
        elif args.action == "inspect":
            with database(directory) as db:
                result = state_of(db)
        elif args.action == "guide":
            from guide9 import serve
            return serve(directory, args.ready)
        else:
            from bootstrap9 import bootstrap
            result = bootstrap(directory, args.name)
        if args.out:
            save(args.out, result)
    except (Denied, OSError, KeyError, TypeError, ValueError, sqlite3.Error) as exc:
        result = {"decision": "denied", "reason": str(exc) if isinstance(exc, Denied) else type(exc).__name__}
        print(canonical(result).decode(), end="")
        return 2
    print(canonical(result).decode(), end="")
    return 0
