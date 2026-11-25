"""Trusted workflow phase provisions public pins, then signs verified candidate inputs."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from verify_kit import ARCHIVE, VERSION, canonical, load, sha, write


def ssl(*args):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True, timeout=5).stdout


def provision(base):
    bootstrap, secrets = base / "bootstrap", base / "private"
    bootstrap.mkdir(parents=True)
    secrets.mkdir(mode=0o700)
    for private, public in (("release.key", "release-root.pem"), ("alternate.key", "wrong-root.pem")):
        key = secrets / private
        ssl("genpkey", "-algorithm", "Ed25519", "-out", key)
        key.chmod(0o600)
        (bootstrap / public).write_bytes(ssl("pkey", "-in", key, "-pubout"))
    source = Path(__file__).resolve().parent
    for name in ("verify_kit.py", "consume.py", "step9.py", "browser9.mjs", "host9.py"):
        shutil.copyfile(source / name, bootstrap / name)
    digest = sha(ssl("pkey", "-pubin", "-in", bootstrap / "release-root.pem", "-outform", "DER"))
    pins = {"fingerprint": digest, "encoding": "SHA-256(DER SubjectPublicKeyInfo)",
            "source_revision": os.environ["GITHUB_SHA"], "version": VERSION,
            "verify_sha256": sha((source / "verify_kit.py").read_bytes()),
            "consumer_sha256": sha((source / "consume.py").read_bytes()),
            "provision": "trusted workflow orchestration before unsigned candidate build"}
    write(bootstrap / "trust.json", pins)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as out:
        for name in ("fingerprint", "source_revision", "version", "verify_sha256", "consumer_sha256"):
            out.write(f"{name}={pins[name]}\n")
        out.write(f'trust_sha256={sha((bootstrap / "trust.json").read_bytes())}\n')
    print(canonical(pins).decode(), end="")


def sign(base, unsigned):
    public = base / "bootstrap"
    secrets = base / "private"
    release = base / "release"
    pins = load(public / "trust.json")
    release.mkdir()
    try:
        for case, source, key in (("valid", "valid", "release.key"),
                                  ("forbidden", "forbidden", "release.key"),
                                  ("alternate", "valid", "alternate.key"),
                                  ("step9-base", "step9-base", "release.key"),
                                  ("step9-upgrade", "step9-upgrade", "release.key"),
                                  ("step9-incompatible", "step9-incompatible", "release.key")):
            candidate = unsigned / source
            destination = release / case
            destination.mkdir()
            manifest = load(candidate / "manifest.json")
            version = {"step9-base": "0.1.0-test.2", "step9-upgrade": "0.1.0-test.3",
                       "step9-incompatible": "0.1.0-test.3"}.get(case, pins["version"])
            basename = f"commonwealth-kit-{version}.tar.gz"
            archive = (candidate / basename).read_bytes()
            expected = {"schema": 1, "kit_version": version,
                        "source_revision": pins["source_revision"], "archive": basename,
                        "bytes": len(archive), "sha256": sha(archive)}
            if manifest != expected or len(archive) > 4 * 1024 ** 2:
                raise SystemExit("unsigned candidate does not match pinned release coordinate or digest")
            (destination / basename).write_bytes(archive)
            signed = destination / "manifest.json"
            write(signed, manifest)
            ssl("pkeyutl", "-sign", "-rawin", "-inkey", secrets / key, "-in", signed,
                "-out", destination / "manifest.sig")
        shutil.copyfile(public / "wrong-root.pem", release / "alternate" / "candidate-root.pem")
    finally:
        shutil.rmtree(secrets)
    print(canonical({"decision": "signed", "source_revision": pins["source_revision"],
                     "private_signing_keys_removed": not secrets.exists()}).decode(), end="")


if __name__ == "__main__":
    if sys.argv[1] == "provision":
        provision(Path(sys.argv[2]))
    elif sys.argv[1] == "sign":
        sign(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit("unknown trust phase")
