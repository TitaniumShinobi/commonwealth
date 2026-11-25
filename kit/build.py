"""Unprivileged deterministic candidate builder. Produces unsigned archives only."""
import gzip
import io
import os
import sys
import tarfile
from pathlib import Path

from verify_kit import ARCHIVE, MEMBERS, VERSION, canonical, sha, write


def package(directory, entries, revision):
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


def main():
    output = Path(sys.argv[1])
    revision = os.environ["GITHUB_SHA"]
    root = Path(__file__).resolve().parent
    entries = {name: (root / "package" / name).read_bytes()
               for name in MEMBERS if name != "release.json"}
    entries["release.json"] = canonical({"kit_version": VERSION, "source_revision": revision})
    package(output / "valid", entries, revision)
    package(output / "forbidden", {**entries, "../outside-sentinel": b"forbidden\n"}, revision)


if __name__ == "__main__":
    main()
