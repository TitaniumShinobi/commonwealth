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

def relay(socket_path, request, endpoint, proof=None):
    import socket
    from runtime import receive, send
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(2)
        channel.connect(socket_path)
        with channel.makefile("rwb") as stream:
            send(stream, {"request": request, "endpoint": endpoint, "proof": proof})
            return receive(stream)


def broker(config_path, socket_path, old_uid):
    import os
    import socket
    import socketserver
    import secrets, struct, tempfile, time, subprocess
    from runtime import cert_digest, discovery_record, read_config, receive, run_ssl, send, verify
    config = read_config(config_path)
    serving = cert_digest(config["certificate"])

    pending = {}

    class Authority(socketserver.StreamRequestHandler):
        def handle(self):
            credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", credentials)
            if uid != old_uid:
                send(self.wfile, {"decision": "denied", "reason": "authority_caller_denied"})
                return
            self.request.settimeout(2)
            message = receive(self.rfile)
            request = message["request"]
            def respond(result):
                if result is None:
                    result = discovery_record(config, message["endpoint"], serving)
                send(self.wfile, result)
            if request.get("operation") == "discover":
                dispatch(config, serving, "", request, respond)
                return
            def deny(reason):
                respond({"decision": "denied", "reason": reason,
                         "request_id": request.get("request_id"), "mutated": False})
            now = time.monotonic()
            for nonce, (expires, _) in list(pending.items()):
                if expires <= now:
                    del pending[nonce]
            proof = message.get("proof")
            if proof is None:
                if len(pending) >= 64:
                    return deny("challenge_capacity")
                challenge = {"nonce": secrets.token_hex(32), "service": config["service"],
                             "generation": config["generation"], "serving_sha256": serving,
                             "request_sha256": sha(canonical(request))}
                pending[challenge["nonce"]] = (now + 5, challenge)
                respond({"decision": "peer_challenge", "challenge": challenge})
                return
            if not isinstance(proof, dict) or not isinstance(proof.get("nonce"), str):
                return deny("peer_proof_invalid")
            entry = pending.pop(proof["nonce"], None)
            if entry is None:
                return deny("challenge_unknown_expired_or_used")
            challenge = entry[1]
            if challenge["request_sha256"] != sha(canonical(request)):
                return deny("challenge_operation_changed")
            try:
                certificate = proof["certificate"]
                if not isinstance(certificate, str) or len(certificate) > 4096:
                    return deny("peer_proof_invalid")
                with tempfile.TemporaryDirectory() as temp:
                    cert = Path(temp) / "peer.pem"
                    public = Path(temp) / "peer.pub"
                    cert.write_text(certificate)
                    peer = cert_digest(cert)
                    public.write_bytes(run_ssl("x509", "-in", cert, "-pubkey", "-noout"))
                    verify(public, challenge, proof["signature"])
            except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
                return deny("peer_proof_invalid")
            dispatch(config, serving, peer, request, respond)

    with socketserver.UnixStreamServer(socket_path, Authority) as server:
        os.chmod(socket_path, 0o666)
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    import sys
    broker(sys.argv[1], sys.argv[2], int(sys.argv[3]))
