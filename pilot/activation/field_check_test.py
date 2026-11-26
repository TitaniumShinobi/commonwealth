"""Show that complete, hash-consistent self-attestation still earns no field authorization."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "simulation"))
from commonwealth_sim.pilot import FIELD, LIMITS, READINESS, TARGET, assess

out = Path(sys.argv[1])
source = out / "fabricated-source.txt"
source.write_text("Synthetic self-attestation; this contains no independent field evidence.\n")
fake = {"owner": "self-asserted-owner", "reference": "fake-source", "site_ref": "invented-site",
        "configuration_ref": "invented-config", "observed_at": "2026-11-01T00:01:00Z"}
run = {"run_ref": "invented-run", "starts_at": "2026-11-01T00:00:00Z", "ends_at": "2026-11-01T00:05:00Z",
       "authority_ref": fake["reference"]}
approval = {**fake, **run, "scope": "direct", "observed_at": "2026-10-31T23:59:00Z"}
field = {"site_ref": fake["site_ref"], "configuration_ref": fake["configuration_ref"], "target": TARGET,
         "readiness": {item: {**fake, "scope": "direct"} for item in READINESS},
         "limits": dict.fromkeys(LIMITS, 1), "participant_price_minor": 0,
         "field_run": run, "activation_authority": approval,
         "observations": {item: {**fake, **run, "scope": "field", "verdict": "PASS", "vantage": "claimed",
                                "criterion_ref": "claimed", "enforcement_boundary": "claimed", "observed_result": "claimed"}
                          for item in FIELD}}
assert assess(field)["field_acceptance"] == "PASS"
receipt, manifest = (out / name for name in ("fabricated-field-receipt.json", "fabricated-source-manifest.json"))
receipt.write_text(json.dumps(field))
manifest.write_text(json.dumps({"fake-source": {"path": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}}))
run = subprocess.run([sys.executable, str(Path(__file__).with_name("field_check.py")), receipt,
                      "--source-manifest", manifest], capture_output=True, text=True, check=True)
checked = json.loads(run.stdout)
assert checked["source_integrity"] == "MATCHED"
assert checked["completeness"]["all_required_records_supplied"]
assert checked["assessment"] == {"field_acceptance": "UNVERIFIED", "ready_to_request_activation": "UNVERIFIED",
                                  "activation": "HELD"}
(out / "forged-field-check.json").write_text(run.stdout)
