"""Re-run exported experiments in a different interpreter and compare exact results."""
import json
import os
import sys
from pathlib import Path

from bell import trial

root = Path(sys.argv[1])
trace = root / "trace.ndjson"
rows = [json.loads(line) for line in trace.read_text().splitlines()]
browser = json.loads((root / "browser.json").read_text())
exported = [r for r in rows if r["layer"] == "simulation"]
expected = {"ideal-0", "ideal-1", "ideal-2", "ideal-3", "ideal-4", "ideal-5", "dephasing",
            "missing", "cancelled", "unavailable"}
if len(exported) != len(expected) or {row["trial_id"] for row in exported} != expected:
    raise SystemExit("incomplete exported experiment set")
for row in exported:
    identifier = row["trial_id"]
    replayed = trial(row["run_id"], identifier, row["state"], row["mode"])
    observed = {name: value for name, value in row.items() if name != "layer"}
    if replayed != observed or browser["trials"][identifier]["result"] != observed:
        raise SystemExit("replay mismatch: " + identifier)
    with trace.open("a") as output:
        print(json.dumps({"run_id": row["run_id"], "trial_id": identifier, "layer": "replay",
                          "verdict": "PASS", "comparison": "exported trace, browser result and fresh workers"}), file=output)
with trace.open("a") as output:
    print(json.dumps({"run_id": browser["run_id"], "layer": "gate", "revision": os.environ["GITHUB_SHA"],
                      "verdict": "PASS", "trials": len(exported), "scope": "cloud fixture simulation"}), file=output)
