"""Durable serving authority for the installed loopback lifecycle profile."""
from pathlib import Path
from operator9 import Denied, canonical, database, load, save, sha, state_of


def identity(config, certificate):
    return {"operator": config["operator"], "service": config["service"],
            "generation": config["generation"], "certificate": certificate,
            "application": str(Path(config["application"]).resolve())}


def transition(state, plan):
    action, body = plan["action"], plan["payload"]
    active = state.get("serving")
    key = body["identity"]
    if plan["target"] != key["application"]:
        raise Denied("application_target_changed")
    path = Path(key["application"])
    if action == "service-activate":
        if active or key["generation"] != 1 or not path.is_file():
            raise Denied("initial_service_invalid")
        state["serving"] = {**key, "fenced": False}
    elif action == "service-backup":
        if active != {**key, "fenced": False}:
            raise Denied("inactive_generation")
        data = load(path)
        state["service_backup"] = {"identity": key, "data": data, "sha256": sha(canonical(data))}
    elif action == "service-fence":
        if active != {**key, "fenced": False}:
            raise Denied("inactive_generation")
        state["serving"] = {**key, "fenced": True}
    elif action == "service-restore":
        backup = state.get("service_backup")
        if not active or not active["fenced"] or not backup:
            raise Denied("protected_service_closed")
        if (backup["identity"] != {name: active[name] for name in key}
                or body["backup_sha256"] != backup["sha256"]
                or key["generation"] != active["generation"] + 1
                or key["certificate"] == active["certificate"]
                or key["application"] == active["application"]
                or (key["operator"], key["service"]) != (active["operator"], active["service"])):
            raise Denied("replacement_identity_invalid")
        if path.exists():
            raise Denied("replacement_target_not_clean")
        with path.open("xb") as output:
            output.write(canonical(backup["data"]))
        state["serving"] = {**key, "fenced": False}
        state["binding_floor"] = key["generation"]
    else:
        raise Denied("unsupported_service_operation")


def dispatch(config, serving, peer, request, disclose):
    """Hold the authoritative lock through disclosure or application commit."""
    operation = request.get("operation")
    action = request.get("action")
    key = identity(config, serving)
    with database(config["authority"]) as db:
        db.execute("BEGIN IMMEDIATE")
        state = state_of(db)
        accepted = any(card["workload_sha256"] == peer for card in state["peers"].values())
        current = state.get("serving") == {**key, "fenced": False}
        shaped = request.get("protocol") == 1 and request.get("service") == key["service"]
        reply = {"decision": "denied", "reason": "generation_fenced" if not current else "destination_policy",
                 "request_id": request.get("request_id"), "mutated": False}
        if current and operation == "discover":
            disclose(None)
            return
        if current and accepted and shaped:
            path = Path(key["application"])
            if action == "fixture.read":
                reply.update(decision="allowed", reason="current_peer", result=load(path)["record"])
            elif action == "fixture.write" and isinstance(request.get("value"), str):
                from runtime import save as atomic_save
                atomic_save(path, {"record": request["value"]})
                reply.update(decision="allowed", reason="current_peer", mutated=True)
        disclose(reply)
