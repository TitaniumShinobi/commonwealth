"""Credential bootstrap under a private, operator-owned fixture authority."""
import os
import re
import subprocess
from pathlib import Path

from operator9 import Denied, init, save, sha


def ssl(*args):
    return subprocess.run(["openssl", *map(str, args)], check=True,
                          capture_output=True, timeout=5).stdout


def bootstrap(authority, name):
    if not name or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
        raise Denied("invalid_operator_name")
    if Path(authority).exists():
        raise Denied("bootstrap_target_exists")
    init(authority)
    root = Path(authority).resolve()
    private = root / "credentials"
    private.mkdir(mode=0o700)
    old = os.umask(0o077)
    try:
        for role in ("operator", "publication", "serving", "workload", "issuer"):
            key = private / f"{role}.key"
            ssl("genpkey", "-algorithm", "Ed25519", "-out", key)
            (private / f"{role}.pub").write_bytes(ssl("pkey", "-in", key, "-pubout"))
        ca = private / "ca.pem"
        ssl("req", "-x509", "-new", "-key", private / "issuer.key", "-subj", f"/CN={name}-fixture",
            "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-out", ca)
        for serial, role, usage in ((1, "serving", "serverAuth"), (2, "workload", "clientAuth")):
            csr = private / f"{role}.csr"
            extension = private / f"{role}.ext"
            extension.write_text(f"subjectAltName=DNS:localhost\nextendedKeyUsage={usage}\n")
            ssl("req", "-new", "-key", private / f"{role}.key", "-subj", f"/CN={name}-{role}", "-out", csr)
            ssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", private / "issuer.key",
                "-set_serial", str(serial), "-days", "1", "-extfile", extension,
                "-out", private / f"{role}.pem")
        save(root / "peers.json", {"peers": {}})
        save(root / "node.json", {"host": "127.0.0.1", "operator": name, "service": "life.reference",
             "ca": str(ca), "certificate": str(private / "serving.pem"), "tls_key": str(private / "serving.key"),
             "client_certificate": str(private / "workload.pem"), "client_key": str(private / "workload.key"),
             "operator_public": str(private / "operator.pub"), "operator_key": str(private / "operator.key"),
             "publication_public": str(private / "publication.pub"), "publication_key": str(private / "publication.key"),
             "state": str(root / "peers.json"), "authority": str(root), "audit": str(root / "audit.ndjson"),
             "recovery_authority": f"fixture-local:{name}"})
    finally:
        os.umask(old)
    return {"decision": "bootstrapped", "role_fingerprints": {
        role: sha(ssl("pkey", "-pubin", "-in", private / f"{role}.pub", "-outform", "DER"))
        for role in ("operator", "publication", "serving", "workload")},
        "node_configuration": str(root / "node.json")}
