"""Independent protocol-1 status service fixture. Imports no Kit runtime."""
import argparse
import hashlib
import json
import socketserver
import ssl
import subprocess
import tempfile
import time
from pathlib import Path


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def signature(key, value):
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / "message"
        message.write_bytes(canon(value))
        return subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                                        key, "-in", str(message)], timeout=4).hex()


def fingerprint(path):
    return sha(subprocess.check_output(["openssl", "pkey", "-pubin", "-in", path,
                                        "-outform", "DER"], timeout=4))


def start(config, ready, contract):
    if contract != {"protocol": 1, "service": "extension.status", "action": "status.read",
                    "result": {"schema": 1, "status": "ready"}}:
        raise SystemExit("incompatible_extension")
    tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=config["ca"])
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.load_cert_chain(config["certificate"], config["tls_key"])
    serving = sha(ssl.PEM_cert_to_DER_cert(Path(config["certificate"]).read_text()))
    operator = fingerprint(config["operator_public"])
    publisher = fingerprint(config["publication_public"])

    class Server(socketserver.TCPServer):
        def get_request(self):
            channel, address = super().get_request()
            channel.settimeout(2)
            try:
                return tls.wrap_socket(channel, server_side=True), address
            except OSError:
                channel.close()
                raise

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            raw = self.rfile.readline(16385)
            if len(raw) > 16384 or not raw.endswith(b"\n"):
                return
            request = json.loads(raw)
            if request["operation"] == "discover":
                delegation = {"operator_sha256": operator, "publication_sha256": publisher,
                              "service": contract["service"]}
                binding = {"operator": config["operator"], "service": contract["service"],
                           "protocol": 1, "endpoint": list(self.server.server_address),
                           "serving_sha256": serving, "revision": 1, "expiry": int(time.time()) + 60}
                output = {"decision": "discovered", "delegation": delegation,
                          "delegation_signature": signature(config["operator_key"], delegation),
                          "binding": binding, "binding_signature": signature(config["publication_key"], binding)}
            else:
                peer = sha(self.request.getpeercert(binary_form=True))
                version = request.get("protocol")
                allowed = (version == 1 and peer == config["client_grant"]
                           and request.get("service") == contract["service"]
                           and request.get("action") == contract["action"])
                status = "allowed" if allowed else "unsupported_version" if version != 1 else "denied"
                output = {"decision": status, "request_id": request.get("request_id"),
                          "protected_handler_invoked": allowed}
                if allowed:
                    output["result"] = contract["result"]
                with Path(config["audit"]).open("ab") as audit:
                    audit.write(canon({"protocol": version, "client_sha256": peer, **output}))
            self.wfile.write(canon(output))

    with Server(("127.0.0.1", 0), Handler) as server:
        ready.write_bytes(canon({"operator": config["operator"], "endpoint": list(server.server_address),
                                 "operator_sha256": operator, "publication_sha256": publisher,
                                 "serving_sha256": serving, "service": contract["service"],
                                 "build_sha256": sha(Path(__file__).read_bytes())}))
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--config", type=Path, required=True)
    cli.add_argument("--contract", type=Path, required=True)
    cli.add_argument("--ready", type=Path, required=True)
    args = cli.parse_args()
    start(json.loads(args.config.read_text()), args.ready, json.loads(args.contract.read_text()))
