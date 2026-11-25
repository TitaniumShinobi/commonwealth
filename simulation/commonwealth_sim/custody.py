"""Verify extracted archive members and emit reconstructable cloud evidence."""
import base64
import gzip
import hashlib
import json
import os
import time
from io import BytesIO
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZipFile
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


def download(original, archive):
    class StripAuth(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            request = super().redirect_request(req, fp, code, msg, headers, newurl)
            if request is not None:
                request.remove_header("Authorization")
            return request

    ref = os.environ["ARTIFACT_ID"]
    url = (f'{os.environ["GITHUB_API_URL"]}/repos/{os.environ["GITHUB_REPOSITORY"]}'
           f'/actions/artifacts/{ref}/zip')
    request = Request(url, headers={"Accept": "application/vnd.github+json"})
    request.add_unredirected_header("Authorization", f'Bearer {os.environ["GITHUB_TOKEN"]}')
    opener = build_opener(StripAuth())
    for attempt in range(3):
        try:
            with opener.open(request, timeout=8) as response:
                archive_bytes = response.read(8 * 1024 ** 2 + 1)
            break
        except HTTPError as exc:
            emit({"custody": "archive_api_retry", "status": exc.code, "attempt": attempt + 1})
            if attempt == 2 or exc.code not in (404, 429, 500, 502, 503):
                raise SystemExit(f"GitHub archive endpoint returned HTTP {exc.code}") from None
            time.sleep(2)
    if (len(archive_bytes) > 8 * 1024 ** 2
            or sha(archive_bytes) != os.environ["ARTIFACT_DIGEST"].removeprefix("sha256:")):
        raise SystemExit("Archive ZIP digest or size differs from upload receipt")
    wanted = set(decode((original / "archive-members.json").read_bytes())["members"])
    wanted.add("archive-members.json")
    with ZipFile(BytesIO(archive_bytes)) as bundle:
        files = [item for item in bundle.infolist() if not item.is_dir()]
        if ({item.filename for item in files} != wanted or len(files) != len(wanted)
                or sum(item.file_size for item in files) > 8 * 1024 ** 2):
            raise SystemExit("Archive member names or expanded size differ from manifest")
        for item in files:
            target = archive / item.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(item))
    emit({"custody": "verified_zip_sha256", "artifact_id": ref, "sha256": sha(archive_bytes)})


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
    archive = Path(other[0]) if other else root
    if command == "recover":
        download(root, archive)
        return
    originals = decode((root / manifest).read_bytes())
    recovered = decode((archive / manifest).read_bytes())
    source = "verified_archived_member_sha256" if command == "verify" else "original_runner_member_sha256"
    archived = {str(p.relative_to(archive)): sha(p.read_bytes())
                for p in sorted(archive.rglob("*")) if p.is_file() and p.name != manifest}
    if originals != recovered or recovered["members"] != archived:
        raise SystemExit("Archived member verification failed")
    emit({"custody": source, "artifact_id": os.environ["ARTIFACT_ID"],
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
    emit({"custody": "archive_replay_operands_verified" if command == "verify" else "original_replay_operands_verified", "cases": len(comparison["cases"]),
          "original_sets": 2, "revision": recovered["revision"]})


if __name__ == "__main__":
    main()
