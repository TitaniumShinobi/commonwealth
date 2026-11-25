"""Trusted release verifier for the fixed Step 8 fixture coordinate."""
import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

VERSION = "0.1.0-test.1"
ARCHIVE = f"commonwealth-kit-{VERSION}.tar.gz"
MEMBERS = {"bin/commonwealth", "lib/runtime.py", "lib/simulation_adapter.py", "GUIDE.md",
           "PROTOCOL.md", "ADAPTER.md", "fixtures/conformance.json", "fixtures/simulation.json",
           "release.json", "STEP9.md", "lib/operator9.py", "lib/bootstrap9.py", "lib/guide9.py",
           "extension/status_peer.py", "extension/contract.json",
           "plugin/plugin.json", "plugin/skills/commonwealth-help/SKILL.md", "profile.json"}
M = 1024 * 1024


class Rejected(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_key")
        result[key] = value
    return result


def get(path, limit=64 * 1024):
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(limit + 1)
    except FileNotFoundError as exc:
        raise Rejected("input_missing") from exc
    if len(value) > limit:
        raise Rejected("input_too_large")
    return value


def load(path):
    return json.loads(get(path), object_pairs_hook=checked_pairs)


def write(path, value):
    Path(path).write_bytes(canonical(value))


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, timeout=5, check=False)


def verified(inputs):
    root = Path(inputs["trust_root"])
    if not root.is_file():
        raise Rejected("trust_root_missing")
    root_bytes = get(root, 4096)
    signed = get(inputs["manifest"], 16384)
    signature = get(inputs["signature"], 256)
    with tempfile.TemporaryDirectory(prefix="cw-verify-") as temp:
        directory = Path(temp)
        for name, content in (("root", root_bytes), ("manifest", signed), ("signature", signature)):
            (directory / name).write_bytes(content)
        key = openssl("pkey", "-pubin", "-in", directory / "root", "-outform", "DER")
        if key.returncode or key.stdout[:12] != bytes.fromhex("302a300506032b6570032100"):
            raise Rejected("trust_root_invalid")
        fingerprint = sha(key.stdout)
        if fingerprint != inputs["fingerprint"]:
            raise Rejected("trust_root_mismatch")
        verified_signature = openssl("pkeyutl", "-verify", "-pubin", "-inkey", directory / "root",
                                     "-rawin", "-in", directory / "manifest", "-sigfile", directory / "signature")
        if verified_signature.returncode:
            raise Rejected("manifest_signature_invalid")
    metadata = json.loads(signed, object_pairs_hook=checked_pairs)
    version = inputs.get("version", VERSION)
    archive_name = f"commonwealth-kit-{version}.tar.gz"
    if version not in (VERSION, "0.1.0-test.2", "0.1.0-test.3"):
        raise Rejected("release_coordinates_mismatch")
    expected = {"schema": 1, "kit_version": version, "source_revision": inputs["revision"], "archive": archive_name}
    if (set(metadata) != {*expected, "bytes", "sha256"}
            or any(metadata.get(k) != v for k, v in expected.items())
            or not re.fullmatch(r"[a-f0-9]{40}", inputs["revision"])):
        raise Rejected("release_coordinates_mismatch")
    archive = Path(inputs["archive"])
    if archive.name != archive_name:
        raise Rejected("archive_name_mismatch")
    body = get(archive, 4 * M)
    if type(metadata["bytes"]) is not int or metadata["bytes"] != len(body) or metadata["sha256"] != sha(body):
        raise Rejected("artifact_digest_or_size_mismatch")
    return metadata, body, sha(signed), fingerprint


def inventory(body):
    entries = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(body), mode="r|gz") as archive:
        for member in archive:
            if member.name not in MEMBERS or member.name in entries or not member.isreg():
                raise Rejected("forbidden_archive_member")
            total += member.size
            if member.size < 0 or total > 16 * M:
                raise Rejected("expanded_archive_too_large")
            with archive.extractfile(member) as stream:
                content = stream.read(member.size + 1)
            if len(content) != member.size:
                raise Rejected("archive_member_truncated")
            entries[member.name] = content
    if entries.keys() != MEMBERS:
        raise Rejected("archive_inventory_mismatch")
    return entries


def plan(args):
    target = str(Path(args.target).resolve())
    inputs = {name: str(Path(getattr(args, name)).resolve())
              for name in ("manifest", "signature", "archive", "trust_root")}
    inputs.update(fingerprint=args.fingerprint, revision=args.revision, version=args.version)
    metadata, _, manifest, fingerprint = verified(inputs)
    return {"actor": "fixture-install-operator", "action": "install", "target": target,
            "release_sha256": metadata["sha256"], "manifest_sha256": manifest,
            "root_sha256": fingerprint, "inputs": inputs}


def approve(plan_value):
    return {**{key: plan_value[key] for key in ("actor", "action", "target", "release_sha256")},
            "plan_sha256": sha(canonical(plan_value))}


def promote_absent(staged, target):
    libc = ctypes.CDLL(None, use_errno=True)
    move = libc.renameat2
    move.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if move(-100, os.fsencode(staged), -100, os.fsencode(target), 1):
        status = ctypes.get_errno()
        if status == errno.EEXIST:
            raise Rejected("target_already_exists")
        raise OSError(status, os.strerror(status))


def install(args):
    value = load(args.plan)
    target = Path(args.target).resolve()
    if not args.approval or not Path(args.approval).is_file():
        raise Rejected("approval_required")
    if str(target) != value["target"]:
        raise Rejected("approved_target_changed")
    if load(args.approval) != approve(value):
        raise Rejected("approved_plan_changed")
    if target.exists() or target.is_symlink():
        raise Rejected("target_already_exists")
    metadata, archive, manifest, fingerprint = verified(value["inputs"])
    if (metadata["sha256"], manifest, fingerprint) != (
            value["release_sha256"], value["manifest_sha256"], value["root_sha256"]):
        raise Rejected("release_changed_at_apply")
    entries = inventory(archive)
    if json.loads(entries["release.json"]) != {k: metadata[k] for k in ("kit_version", "source_revision")}:
        raise Rejected("installed_release_mismatch")
    with tempfile.TemporaryDirectory(prefix=".kit-stage-", dir=target.parent) as stage:
        staged = Path(stage) / "root"
        staged.mkdir(mode=0o700)
        for name, content in entries.items():
            path = staged / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o755 if name == "bin/commonwealth" else 0o644)
        manifest_inventory = {k: sha(v) for k, v in sorted(entries.items())}
        if any(sha((staged / k).read_bytes()) != v for k, v in manifest_inventory.items()):
            raise Rejected("staged_inventory_mismatch")
        if target.exists():
            raise Rejected("target_already_exists")
        write(staged / ".release-proof.json", {"release_sha256": metadata["sha256"],
              "manifest_sha256": manifest, "inventory": manifest_inventory})
        promote_absent(staged, target)
    return {"decision": "installed", "target": str(target), "inventory": manifest_inventory,
            "entrypoint": str(target / "bin/commonwealth"), "manifest_sha256": manifest,
            "release_sha256": metadata["sha256"], "root_sha256": fingerprint}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    planned = commands.add_parser("plan")
    for name in ("manifest", "signature", "archive", "trust-root", "target", "out", "revision", "fingerprint"):
        planned.add_argument(f"--{name}", required=True)
    planned.add_argument("--version", default=VERSION)
    applied = commands.add_parser("apply")
    applied.add_argument("--plan", required=True)
    applied.add_argument("--target", required=True)
    applied.add_argument("--approval")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            value = plan(args)
            write(args.out, value)
            result = {"decision": "verified_plan", **approve(value), "root_sha256": value["root_sha256"]}
        else:
            result = install(args)
        print(canonical(result).decode(), end="")
    except (Rejected, OSError, ValueError, tarfile.TarError) as exc:
        reason = str(exc) if isinstance(exc, Rejected) else type(exc).__name__
        print(canonical({"decision": "rejected", "reason": reason}).decode(), end="")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
