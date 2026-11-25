"""Create separate public bootstrap and signed release artifacts."""
import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from verify_kit import ARCHIVE, MEMBERS, VERSION, canonical, sha, write


def ssl(*args):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True, timeout=5).stdout


def package(directory, entries, revision, private):
    directory.mkdir()
    with (directory / ARCHIVE).open("wb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name in sorted(entries):
                    content = entries[name]
                    member = tarfile.TarInfo(name)
                    member.uid = member.gid = member.mtime = 0
                    member.mode = 0o755 if name == "bin/commonwealth" else 0o644
                    member.size = len(content)
                    tar.addfile(member, io.BytesIO(content))
    body = (directory / ARCHIVE).read_bytes()
    manifest = directory / "manifest.json"
    write(manifest, {"schema": 1, "kit_version": VERSION, "source_revision": revision,
                     "archive": ARCHIVE, "bytes": len(body), "sha256": sha(body)})
    ssl("pkeyutl", "-sign", "-rawin", "-inkey", private, "-in", manifest,
        "-out", directory / "manifest.sig")


def main():
    output = Path(sys.argv[1])
    revision = os.environ["GITHUB_SHA"]
    root = Path(__file__).resolve().parent
    bootstrap, release = output / "bootstrap", output / "release"
    bootstrap.mkdir(parents=True)
    release.mkdir()
    entries = {name: (root / "package" / name).read_bytes()
               for name in MEMBERS if name != "release.json"}
    entries["release.json"] = canonical({"kit_version": VERSION, "source_revision": revision})
    with tempfile.TemporaryDirectory(prefix="cw-producer-key-") as secret:
        private, alternate = Path(secret) / "sign.pem", Path(secret) / "alternate.pem"
        for key in (private, alternate):
            ssl("genpkey", "-algorithm", "Ed25519", "-out", key)
            key.chmod(0o600)
        public = bootstrap / "release-root.pem"
        public.write_bytes(ssl("pkey", "-in", private, "-pubout"))
        wrong = bootstrap / "wrong-root.pem"
        wrong.write_bytes(ssl("pkey", "-in", alternate, "-pubout"))
        digest = sha(ssl("pkey", "-pubin", "-in", public, "-outform", "DER"))
        write(bootstrap / "trust.json", {"fingerprint": digest, "encoding": "SHA-256(DER SubjectPublicKeyInfo)",
                                        "source_revision": revision, "version": VERSION,
                                        "provision": "producer bootstrap artifact separate from candidate"})
        for name in ("verify_kit.py", "consume.py"):
            shutil.copyfile(root / name, bootstrap / name)
        package(release / "valid", entries, revision, private)
        package(release / "alternate", entries, revision, alternate)
        shutil.copyfile(wrong, release / "alternate" / "candidate-root.pem")
        package(release / "forbidden", {**entries, "../outside-sentinel": b"forbidden\n"}, revision, private)
    print(canonical({"kit_version": VERSION, "source_revision": revision, "release_root_sha256": digest,
                     "openssl": ssl("version").decode().strip(), "private_signing_keys_removed": True}).decode(), end="")


if __name__ == "__main__":
    main()
