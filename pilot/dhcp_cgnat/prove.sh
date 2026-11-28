#!/usr/bin/env bash
# Orchestrate two independent WAN DHCP / CGNAT histories with clean state each.
# Local /tmp runs are development provenance only — not Actions acceptance.
# Cleanup is PID/namespace scoped inside history.sh; never use broad process-name kills.
set -euo pipefail
out=$1
src=$(realpath "$(dirname "$0")")
HISTORY_TIMEOUT="${HISTORY_TIMEOUT:-180}"
mkdir -p "$out/history-a" "$out/history-b"
: > "$out/trace.txt"
emit() { printf '%s\n' "$*" | tee -a "$out/trace.txt"; }

write_incomplete() {
  local dir=$1 mode=$2 reason=$3 status=$4
  mkdir -p "$dir/stages"
  python3 - "$dir/stages/history-incomplete.json" "$mode" "$reason" "$status" <<'PY'
import json, os, sys, time
from pathlib import Path
path, mode, reason, status = sys.argv[1:]
Path(path).write_text(json.dumps({
    "stage": "history-incomplete",
    "history": mode,
    "verdict": "INCOMPLETE",
    "reason": reason,
    "exit_status": int(status),
    "observed_at": time.time(),
    "observed_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "sha": os.environ.get("GITHUB_SHA", "local"),
    "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    "job": os.environ.get("GITHUB_JOB", "local"),
    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
}, indent=2, sort_keys=True) + "\n")
PY
}

run_history() {
  local dir=$1 mode=$2
  mkdir -p "$dir/receipts" "$dir/stages"
  local status=0
  set +e
  timeout --foreground --signal=TERM --kill-after=20s "$HISTORY_TIMEOUT" \
    bash "$src/history.sh" "$dir" "$mode"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    emit "PASS: history $mode complete in isolated state"
    return 0
  fi
  local reason="history_failed"
  if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
    reason="history_timeout_${HISTORY_TIMEOUT}s"
  fi
  write_incomplete "$dir" "$mode" "$reason" "$status"
  emit "INCOMPLETE: history $mode status=$status reason=$reason"
  return "$status"
}

emit "BEGIN dhcp-cgnat prove sha=${GITHUB_SHA:-local} run=${GITHUB_RUN_ID:-local} job=${GITHUB_JOB:-local} history_timeout=${HISTORY_TIMEOUT}s"

bash -n "$src/history.sh"
bash -n "$src/wan_lease.sh"

status_a=0
status_b=0
run_history "$out/history-a" A || status_a=$?
if [[ "$status_a" -eq 0 ]]; then
  run_history "$out/history-b" B || status_b=$?
else
  write_incomplete "$out/history-b" B "skipped_after_A_failure" "$status_a"
  emit "INCOMPLETE: history B skipped after A failure"
  status_b=1
fi

python3 - "$out" "$status_a" "$status_b" <<'PY'
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[1])
status_a, status_b = map(int, sys.argv[2:4])
def load(mode):
    complete = root / f"history-{mode.lower()}" / "stages" / "history-complete.json"
    incomplete = root / f"history-{mode.lower()}" / "stages" / "history-incomplete.json"
    if complete.is_file():
        return json.loads(complete.read_text())
    if incomplete.is_file():
        return json.loads(incomplete.read_text())
    return {"history": mode, "verdict": "INCOMPLETE", "reason": "missing_receipt"}
summary = {
    "verdict": "PASS" if status_a == 0 and status_b == 0 else "INCOMPLETE",
    "sha": os.environ.get("GITHUB_SHA", "local"),
    "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    "job": os.environ.get("GITHUB_JOB", "local"),
    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    "observed_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "histories": {"A": load("A"), "B": load("B")},
    "exit_status": {"A": status_a, "B": status_b},
    "field_acceptance": "UNVERIFIED",
    "activation": "HELD",
    "claim": "actions_acceptance_requires_this_exact_sha_artifacts",
    "local_dev_provenance_only_if_sha_local": os.environ.get("GITHUB_SHA", "local") == "local",
}
(root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
if status_a or status_b:
    raise SystemExit(1)
PY

emit "PASS: WAN DHCP + modeled carrier NAT independent histories revision ${GITHUB_SHA:-local}"
