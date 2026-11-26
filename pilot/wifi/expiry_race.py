"""Fault fixture: pause a verified renewal after its last precheck, before nft apply."""
import contextlib
import io
import json
import sys
import time
from pathlib import Path

import policy

configuration, approval, readback = map(Path, sys.argv[1:])
state = Path(json.loads(configuration.read_text())["state"])
deadline = json.loads((state / "live-until").read_text())["monotonic_until"]
actual_run = policy.run
receipt = {"deadline": deadline, "rejected": False}


def delayed(*args, text=None, **options):
    if args == ("nft", "-f", "-") and text and text.startswith("delete element"):
        receipt["userspace_checks_done"] = time.monotonic()
        if receipt["userspace_checks_done"] >= deadline:
            raise AssertionError("induced fault failed to start before deadline")
        time.sleep(max(0, deadline - time.monotonic()) + 0.4)
        receipt["kernel_submit_at"] = time.monotonic()
        try:
            return actual_run(*args, text=text, **options)
        except RuntimeError as exc:
            receipt["rejected"] = True
            receipt["kernel_failure"] = str(exc)
            raise
    return actual_run(*args, text=text, **options)


policy.run = delayed
sys.argv = ["policy.py", "renew", str(configuration), "--approval", str(approval), "--readback", str(readback)]
try:
    with contextlib.redirect_stdout(io.StringIO()):
        policy.main()
except RuntimeError:
    if not receipt["rejected"]:
        raise
if "kernel_submit_at" not in receipt:
    raise RuntimeError("no kernel transaction observed")
print(json.dumps(receipt))
