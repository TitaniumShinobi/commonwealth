"""Compare ordered semantic evidence from two clean Step 6 executions."""
import hashlib
import sys
from pathlib import Path

from .__main__ import save
from .actor import decode, encode


def semantic(receipt):
    trace = receipt["trace"]
    for entry in trace:
        request = entry.get("request") or {}
        if request.get("kind") == "deliver":
            # Run ID belongs to custody. The signature covers that ID.
            request["envelope"].pop("run", None)
            request.pop("tag", None)
    return {"checks": receipt["checks"], "trace": trace,
            "fixture": receipt["resolved_fixture_sha256"], "revision": receipt["revision"]}


def compare(root):
    paths = [root / "step-6", root / "step-6-replay"]
    summaries = [decode((directory / "summary.json").read_bytes()) for directory in paths]
    names = set(summaries[0]["cases"]) | set(summaries[1]["cases"])
    cases = {}
    for name in sorted(names):
        try:
            documents = [decode((directory / f"{name}.json").read_bytes()) for directory in paths]
            hashes = [hashlib.sha256(encode(semantic(receipt))).hexdigest() for receipt in documents]
            verdict = "PASS" if hashes[0] == hashes[1] else "FAIL"
            if any(doc["verdict"] != "PASS" for doc in documents):
                verdict = "FAIL" if any(doc["verdict"] == "FAIL" for doc in documents) else "UNVERIFIED"
            cases[name] = {"verdict": verdict, "semantic_sha256": hashes}
        except (OSError, KeyError, ValueError) as exc:
            cases[name] = {"verdict": "UNVERIFIED", "reason": str(exc)}
    verdicts = {value["verdict"] for value in cases.values()}
    verdict = "FAIL" if "FAIL" in verdicts else "PASS" if verdicts == {"PASS"} else "UNVERIFIED"
    save(root / "replay-comparison.json", {"version": 1, "cases": cases, "verdict": verdict,
         "normalized": ["envelope.run", "envelope.tag"], "sources": ["step-6", "step-6-replay"]})
    print(f"step-6 replay: {verdict}")
    return {"PASS": 0, "FAIL": 1, "UNVERIFIED": 2}[verdict]


if __name__ == "__main__":
    raise SystemExit(compare(Path(sys.argv[1])))
