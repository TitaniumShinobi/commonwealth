"""Read-only offline integrity and readiness assessment for supplied field evidence."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "simulation"))
from commonwealth_sim.pilot import assess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    args = parser.parse_args()
    field = json.loads(args.receipt.read_text())
    manifest = json.loads(args.source_manifest.read_text()) if args.source_manifest else {}
    evidence_root = args.source_manifest.resolve().parent if args.source_manifest else None
    invalid = []

    def available(row):
        if not isinstance(row, dict):
            return False
        reference = row.get("reference")
        entry = manifest.get(reference)
        try:
            requested = Path(entry["path"])
            local = (evidence_root / requested).resolve()
            if requested.is_absolute() or not local.is_relative_to(evidence_root):
                return False
            return local.is_file() and hashlib.file_digest(local.open("rb"), "sha256").hexdigest() == entry["sha256"]
        except (KeyError, TypeError, OSError, ValueError):
            return False

    for group in ("readiness", "observations"):
        for name, row in field[group].items():
            if row is not None and not available(row):
                invalid.append(f"{group}.{name}")
                field[group][name] = None
    if field.get("activation_authority") and not available(field["activation_authority"]):
        invalid.append("activation_authority")
        field["activation_authority"] = None
    result = assess(field)
    print(json.dumps({"mode": "offline_assessment_only", "source_rejections": invalid, "assessment": result},
                     sort_keys=True))


if __name__ == "__main__":
    main()
