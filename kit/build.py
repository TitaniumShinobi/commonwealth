"""Unprivileged deterministic candidate builder. Produces unsigned archives only."""
import gzip
import io
import os
import sys
import tarfile
from pathlib import Path

from verify_kit import ARCHIVE, MEMBERS, VERSION, canonical, sha, write


def package(directory, entries, revision, version=VERSION):
    directory.mkdir()
    archive = f"commonwealth-kit-{version}.tar.gz"
    with (directory / archive).open("wb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name in sorted(entries):
                    content = entries[name]
                    member = tarfile.TarInfo(name)
                    member.uid = member.gid = member.mtime = 0
                    member.mode = 0o755 if name == "bin/commonwealth" else 0o644
                    member.size = len(content)
                    tar.addfile(member, io.BytesIO(content))
    body = (directory / archive).read_bytes()
    manifest = directory / "manifest.json"
    write(manifest, {"schema": 1, "kit_version": version, "source_revision": revision,
                     "archive": archive, "bytes": len(body), "sha256": sha(body)})


def main():
    output = Path(sys.argv[1])
    revision = os.environ["GITHUB_SHA"]
    root = Path(__file__).resolve().parent
    entries = {name: (root / "package" / name).read_bytes()
               for name in MEMBERS if name != "release.json"}
    entries["release.json"] = canonical({"kit_version": VERSION, "source_revision": revision})
    package(output / "valid", entries, revision)
    package(output / "forbidden", {**entries, "../outside-sentinel": b"forbidden\n"}, revision)
    for name, version, protocol in (("step9-base", "0.1.0-test.2", 1),
                                    ("step9-upgrade", "0.1.0-test.3", 1),
                                    ("step9-incompatible", "0.1.0-test.3", 2)):
        variant = {**entries, "release.json": canonical({"kit_version": version, "source_revision": revision}),
                   "profile.json": canonical({"protocol": protocol, "state_schema": 1})}
        package(output / name, variant, revision, version)


if __name__ == "__main__":
    main()
