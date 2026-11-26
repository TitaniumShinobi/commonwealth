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
            if not local.is_file():
                return False
            with local.open("rb") as source:
                return hashlib.file_digest(source, "sha256").hexdigest() == entry["sha256"]
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
    structure = assess(field)
    result = {"field_acceptance": "UNVERIFIED", "ready_to_request_activation": "UNVERIFIED", "activation": "HELD"}
    completeness = {"missing_readiness": structure["missing_readiness"],
                    "missing_field_observations": structure["missing_field_observations"],
                    "receipt_binding_rejections": structure["receipt_binding_rejections"],
                    "all_required_records_supplied": not (invalid or structure["missing_readiness"]
                        or structure["missing_field_observations"] or structure["receipt_binding_rejections"])}
    print(json.dumps({"mode": "offline_assessment_only", "source_integrity": "MATCHED" if not invalid and manifest else "INCOMPLETE",
                      "source_rejections": invalid, "completeness": completeness, "assessment": result},
                     sort_keys=True))


if __name__ == "__main__":
    main()
