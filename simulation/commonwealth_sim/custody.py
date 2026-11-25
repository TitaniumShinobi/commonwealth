"""Verify extracted archive members and emit reconstructable cloud evidence."""
import base64
import gzip
import hashlib
import json
import os
import sys
from pathlib import Path

from .actor import decode, encode
from .replay import semantic


def sha(data):
    return hashlib.sha256(data).hexdigest()


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def chunks(name, value):
    packed = gzip.compress(value, mtime=0)
    encoded = base64.b64encode(packed).decode()
    for pos in range(0, len(encoded), 4096):
        emit({"proof": name, "encoding": "base64+gzip", "offset": pos, "size": len(encoded),
              "bytes": len(value), "sha256": sha(value), "chunk": encoded[pos:pos + 4096]})


def main():
    command, original, *other = sys.argv[1:]
    root = Path(original)
    manifest = "archive-members.json"
    if command == "prepare":
        members = {str(p.relative_to(root)): sha(p.read_bytes())
                   for p in sorted(root.rglob("*")) if p.is_file()}
        from .__main__ import save
        save(root / manifest, {"members": members, "revision": os.environ["GITHUB_SHA"]})
        return
    archive = Path(other[0])
    originals = decode((root / manifest).read_bytes())
    recovered = decode((archive / manifest).read_bytes())
    archived = {str(p.relative_to(archive)): sha(p.read_bytes())
                for p in sorted(archive.rglob("*")) if p.is_file() and p.name != manifest}
    if originals != recovered or recovered["members"] != archived:
        raise SystemExit("Archived member verification failed")
    emit({"custody": "verified_archived_member_sha256", "artifact_id": os.environ["ARTIFACT_ID"],
          "artifact_sha256": os.environ["ARTIFACT_DIGEST"], "artifact_url": os.environ["ARTIFACT_URL"],
          "run": os.environ["GITHUB_RUN_ID"], "revision": recovered["revision"],
          "download_action_sha": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
          "members": archived, "manifest_sha256": sha((archive / manifest).read_bytes())})
    comparison = decode((archive / "replay-comparison.json").read_bytes())
    for suite, number in (("step-6", 0), ("step-6-replay", 1)):
        for case, result in comparison["cases"].items():
            path = f"{suite}/{case}.json"
            data = (archive / path).read_bytes()
            semantic_bytes = encode(semantic(decode(data)))
            if sha(semantic_bytes) != result["semantic_sha256"][number]:
                raise SystemExit(f"Archived semantic operands differ: {path}")
            chunks(f"original/{path}", data)
            chunks(f"semantic/{path}", semantic_bytes)
    emit({"custody": "archive_replay_operands_verified", "cases": len(comparison["cases"]),
          "original_sets": 2, "revision": recovered["revision"]})


if __name__ == "__main__":
    main()
