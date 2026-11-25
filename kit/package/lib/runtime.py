"""Installed Commonwealth Kit runtime, loopback fixture profile."""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import simulation_adapter

SERVICE = "life.reference"
ORIGIN = Path(__file__).resolve()
ENTRY = ORIGIN.parent.parent / "bin/commonwealth"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha(value):
    return hashlib.sha256(value).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        output.write(canonical(value))
    Path(output.name).replace(path)


def run_ssl(*args):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True,
                          timeout=4).stdout


def sign(private, value):
    with tempfile.TemporaryDirectory() as temp:
        body = Path(temp) / "message"
        body.write_bytes(canonical(value))
        return run_ssl("pkeyutl", "-sign", "-rawin", "-inkey", private, "-in", body).hex()


def verify(public, value, signature):
    try:
        with tempfile.TemporaryDirectory() as temp:
            body, sig = Path(temp) / "message", Path(temp) / "signature"
            body.write_bytes(canonical(value))
            sig.write_bytes(bytes.fromhex(signature))
            run_ssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                    "-in", body, "-sigfile", sig)
    except (ValueError, subprocess.SubprocessError) as exc:
        raise ValueError("publication_signature_invalid") from exc


def fingerprint(public):
    return sha(run_ssl("pkey", "-pubin", "-in", public, "-outform", "DER"))


def cert_digest(path):
    return sha(ssl.PEM_cert_to_DER_cert(Path(path).read_text()))


def origin():
    return {"pid": os.getpid(), "entrypoint": str(ENTRY), "entrypoint_sha256": sha(ENTRY.read_bytes()),
            "module": str(ORIGIN), "module_sha256": sha(ORIGIN.read_bytes())}


def safe_endpoint(value):
    address, port = value
    if str(ipaddress.IPv4Address(address)) != "127.0.0.1" or type(port) is not int or not 0 < port < 65536:
        raise ValueError("loopback_endpoint_required")
    return address, port


def paths(config, path, names):
    for k in names:
        if k in config:
            config[k] = str((Path(path).resolve().parent / config[k]).resolve())
    return config


def read_config(path):
    return paths(load(path), path, ("ca", "certificate", "tls_key", "client_certificate", "client_key", "operator_public", "operator_key",
                                    "publication_public", "publication_key", "state", "audit"))


def context(config, server=False):
    result = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH,
                                        cafile=config["ca"])
    result.minimum_version = ssl.TLSVersion.TLSv1_3
    result.verify_mode = ssl.CERT_REQUIRED
    certificate, key = ("certificate", "tls_key") if server else ("client_certificate", "client_key")
    result.load_cert_chain(config[certificate], config[key])
    return result


def receive(stream):
    message = stream.readline(16_385)
    if len(message) > 16384 or not message.endswith(b"\n"):
        raise ValueError("invalid_message")
    return json.loads(message)


def send(stream, value):
    message = canonical(value)
    if len(message) > 16384:
        raise ValueError("message_too_large")
    stream.write(message)
    stream.flush()


def call(config, endpoint, request, expected):
    with socket.create_connection(safe_endpoint(endpoint), timeout=2) as connection:
        with context(config).wrap_socket(connection, server_hostname="localhost") as channel:
            certificate = sha(channel.getpeercert(binary_form=True))
            if certificate != expected:
                raise ValueError("reference_identity_mismatch")
            with channel.makefile("rwb") as stream:
                send(stream, request)
                response = receive(stream)
                if response.get("decision") == "peer_challenge":
                    challenge = response["challenge"]
                    if (challenge["request_sha256"] != sha(canonical(request))
                            or challenge["serving_sha256"] != expected
                            or challenge["service"] != request["service"]):
                        raise ValueError("authority_challenge_mismatch")
                    send(stream, {"nonce": challenge["nonce"],
                                  "certificate": Path(config["client_certificate"]).read_text(),
                                  "signature": sign(config["client_key"], challenge)})
                    response = receive(stream)
                return response


def peer_state(config):
    if "authority" in config:
        from operator9 import database, state_of
        with database(config["authority"]) as db:
            return state_of(db)
    return load(config["state"])


def discovery_record(config, endpoint, serving):
    publication = fingerprint(config["publication_public"])
    operator = fingerprint(config["operator_public"])
    delegation = {"operator_sha256": operator, "publication_sha256": publication, "service": config["service"]}
    mismatch = Path(config["audit"]).with_name("wrong-binding")
    bound_cert = mismatch.read_text() if mismatch.exists() else serving
    binding = {"operator": config["operator"], "service": config["service"], "protocol": 1,
               "endpoint": endpoint, "serving_sha256": bound_cert,
               "revision": config.get("generation", 1), "expiry": int(time.time()) + 60}
    return {"decision": "discovered", "delegation": delegation,
            "delegation_signature": sign(config["operator_key"], delegation),
            "binding": binding, "binding_signature": sign(config["publication_key"], binding)}


def listener(config_path, ready_path):
    config = read_config(config_path)
    if config["host"] != "127.0.0.1":
        raise ValueError("loopback_endpoint_required")
    ctx = context(config, server=True)
    service = config["service"]
    publication = fingerprint(config["publication_public"])
    operator = fingerprint(config["operator_public"])
    serving = cert_digest(config["certificate"])
    workload = cert_digest(config["client_certificate"])

    class Handler(socketserver.StreamRequestHandler):
        def discovery(self):
            return discovery_record(config, list(self.server.server_address), serving)

        def handle(self):
            request = receive(self.rfile)
            peer = sha(self.request.getpeercert(binary_form=True))
            operation = request.get("operation")
            if "generation" in config and operation in ("discover", "request"):
                from network9 import dispatch
                def deliver(response):
                    if response is None:
                        response = self.discovery()
                    if operation == "request":
                        with Path(config["audit"]).open("ab") as log:
                            log.write(canonical({**response, "action": request.get("action"),
                                                 "generation": config["generation"], "client_sha256": peer}))
                    send(self.wfile, response)
                if "authority_socket" in config:
                    from network9 import relay
                    try:
                        endpoint = list(self.server.server_address)
                        reply = relay(config["authority_socket"], request, endpoint)
                        if reply.get("decision") == "peer_challenge":
                            send(self.wfile, reply)
                            proof = receive(self.rfile)
                            reply = relay(config["authority_socket"], request, endpoint, proof)
                    except (OSError, ValueError):
                        reply = {"decision": "denied", "reason": "authority_unavailable",
                                 "request_id": request.get("request_id"), "mutated": False}
                    deliver(reply)
                else:
                    dispatch(config, serving, peer, request, deliver)
                return
            if operation == "discover":
                result = self.discovery()
            elif operation == "health":
                result = {"decision": "reachable", "service": service}
            elif operation == "request":
                state = peer_state(config)
                accepted = (peer in config.get("participant_grants", []) or
                            any(card["workload_sha256"] == peer for card in state["peers"].values()))
                shape = request.get("protocol") == 1 and request.get("service") == service
                allowed = shape and accepted and request.get("action") == "fixture.read"
                result = {"decision": "allowed" if allowed else "denied",
                          "reason": "fixture_grant" if allowed else "destination_policy",
                          "request_id": request.get("request_id"), "mutated": False}
                if allowed:
                    result["result"] = "commonwealth-reference-v1"
                with Path(config["audit"]).open("ab") as log:
                    log.write(canonical({"request_id": result["request_id"], "decision": result["decision"],
                                         "action": request.get("action"), "client_sha256": peer,
                                         "disclosed": allowed, "mutated": False, "server": origin()}))
            else:
                result = {"decision": "unsupported_operation"}
            send(self.wfile, result)

    class Server(socketserver.TCPServer):
        def get_request(self):
            raw, address = super().get_request()
            raw.settimeout(2)
            try:
                return ctx.wrap_socket(raw, server_side=True), address
            except OSError:
                raw.close()
                raise

    with Server(("127.0.0.1", 0), Handler) as server:
        save(ready_path, {"endpoint": list(server.server_address), "listener": "ready",
                          "operator": config["operator"], "operator_sha256": operator,
                          "publication_sha256": publication, "serving_sha256": serving,
                          "workload_sha256": workload, "recovery_authority": config["recovery_authority"],
                          "service": service, "configuration_sha256": sha(Path(config_path).read_bytes()),
                          "origin": origin()})
        if "authority_socket" in config:
            Path(ready_path).chmod(0o644)
        server.serve_forever(poll_interval=0.2)


def setup_plan(args):
    config_path = Path(args.config).resolve()
    value = load(config_path)
    names = ("ca", "certificate", "tls_key", "client_certificate", "client_key",
             "operator_public", "operator_key", "publication_public",
             "publication_key", "state", "audit", "node_config", "peer_state")
    value = paths(value, config_path, names)
    plan = {"actor": "fixture-local-operator", "action": args.mode, "target": str(Path(args.target).resolve()),
            "release_sha256": load(ORIGIN.parent.parent / ".release-proof.json")["release_sha256"], "configuration": value}
    save(args.out, plan)
    return {"decision": "planned", "plan_sha256": sha(canonical(plan)), "target": plan["target"]}


def setup_apply(args):
    p = load(args.plan)
    target = Path(args.target).resolve()
    if not args.approval or not Path(args.approval).is_file():
        raise ValueError("approval_required")
    if str(target) != p["target"]:
        raise ValueError("approved_target_changed")
    expected = {k: p[k] for k in ("actor", "action", "target", "release_sha256")}
    if load(args.approval) != {**expected, "plan_sha256": sha(canonical(p))}:
        raise ValueError("approved_plan_changed")
    if p["release_sha256"] != load(ORIGIN.parent.parent / ".release-proof.json")["release_sha256"]:
        raise ValueError("release_changed")
    if target.exists():
        raise ValueError("target_already_exists")
    with tempfile.TemporaryDirectory(prefix=".setup-", dir=target.parent) as directory:
        staging = Path(directory) / "node"
        staging.mkdir(mode=0o700)
        save(staging / "config.json", p["configuration"])
        staging.rename(target)
    return {"decision": "applied", "target": str(target), "configuration": str(target / "config.json")}


def trust(args):
    card = paths(load(args.reference), args.reference, ("operator_public", "publication_public"))
    approval = load(args.approval) if args.approval and Path(args.approval).is_file() else None
    if approval != {"actor": "fixture-local-operator", "accept": True,
                    "operator_sha256": card["operator_sha256"]}:
        raise ValueError("local_reference_declined")
    if fingerprint(card["operator_public"]) != card["operator_sha256"]:
        raise ValueError("operator_fingerprint_mismatch")
    safe_endpoint(card["endpoint"])
    state = load(args.state)
    state["peers"][card["operator"]] = card
    save(args.state, state)
    return {"decision": "locally_enrolled", "operator": card["operator"],
            "operator_sha256": card["operator_sha256"]}


def exchange(args):
    config = read_config(args.config)
    state = peer_state(config) if "authority" in config else load(args.state)
    card = state["peers"].get(args.peer)
    if not card:
        raise ValueError("peer_not_enrolled")
    root = card["serving_sha256"]
    if "authority" in config and (fingerprint(card["operator_public"]) != card["operator_sha256"]
            or fingerprint(card["publication_public"]) != card["publication_sha256"]):
        raise ValueError("enrolled_key_changed")
    try:
        data = call(config, card["endpoint"], {"operation": "discover"}, root)
    except (ConnectionError, TimeoutError) as exc:
        raise ValueError("discovery_unavailable") from exc
    if data.get("decision") == "denied":
        raise ValueError(data["reason"])
    delegation, binding = data["delegation"], data["binding"]
    verify(card["operator_public"], delegation, data["delegation_signature"])
    verify(card["publication_public"], binding, data["binding_signature"])
    if delegation != {"operator_sha256": card["operator_sha256"],
                      "publication_sha256": fingerprint(card["publication_public"]),
                      "service": args.service}:
        raise ValueError("publication_authority_mismatch")
    if (binding["operator"] != args.peer or binding["service"] != args.service or binding["protocol"] != 1
            or binding["expiry"] <= int(time.time()) or binding["revision"] != card.get("revision", 1)):
        raise ValueError("binding_mismatch")
    protected = {"operation": "request", "protocol": args.wire_version, "service": args.service,
                 "action": args.action, "request_id": args.request_id}
    result = call(config, binding["endpoint"], protected, binding["serving_sha256"])
    return {**result, "binding_verified": True, "endpoint_sha256": binding["serving_sha256"],
            "cache_initial": "empty", "binding_revision": binding["revision"]}


def lab(args):
    config = load(args.config)
    node = read_config(config["node_config"])
    response = call(node, config["endpoint"], {"operation": "health"}, config["serving_sha256"])
    if config["adapter"] != "simulation-v1":
        return {"decision": "adapter_version_unsupported", "scope": "Simulation", "model": "simulation-v1",
                "node_reachable": response["decision"] == "reachable", "adapter_ready": False,
                "reservations_created": 0}
    base = {"scope": "Simulation", "model": "simulation-v1", "node_reachable": True,
            "adapter_ready": True, "adapter_origin": str(Path(simulation_adapter.__file__).resolve()),
            "adapter_sha256": sha(Path(simulation_adapter.__file__).read_bytes())}
    if args.command == "check":
        return {"decision": "checked", **base}
    return {**base, **simulation_adapter.exercise(args.template, args.seed, args.scenario)}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "operator":
        from operator9 import main as operator_main
        return operator_main(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parts = parser.add_subparsers(dest="part", required=True)
    spec = {
        "setup": {"plan": (("mode", "config", "target", "out"), setup_plan),
                  "apply": (("plan", "approval", "target"), setup_apply)},
        "node": {"start": (("config", "ready-out"), None)},
        "service": {"trust": (("state", "reference", "approval"), trust),
                    "request": (("state", "config", "peer", "service", "action", "request-id"), exchange)},
        "peer": {"enroll": (("state", "reference", "approval"), trust),
                 "exchange": (("state", "config", "peer", "service", "action", "request-id"), exchange)},
        "lab": {"check": (("config",), lab),
                "run": (("config", "template", "seed", "scenario"), lab)},
    }
    for part, commands in spec.items():
        child = parts.add_parser(part).add_subparsers(dest="command", required=True)
        for name, (fields, handler) in commands.items():
            command = child.add_parser(name)
            command.set_defaults(handler=handler)
            for field in fields:
                command.add_argument(f"--{field}", required=field != "approval", type=int if field == "seed" else str)
            if handler is exchange:
                command.add_argument("--wire-version", type=int, default=1)
    args = parser.parse_args()
    try:
        if args.handler is None:
            listener(args.config, args.ready_out)
            return 0
        result = args.handler(args)
        print(canonical({**result, "origin": origin()}).decode(), end="")
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(canonical({"decision": "rejected", "reason": reason, "origin": origin()}).decode(), end="")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
