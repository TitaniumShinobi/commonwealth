#!/usr/bin/env bash
# Orchestrate two independent WAN DHCP / CGNAT histories with clean state each.
# Local /tmp runs are development provenance only — not Actions acceptance.
# Cleanup is PID/namespace scoped inside history.sh; never use broad process-name kills.
#
# Exit taxonomy (history.sh / prove.sh):
#   0   PASS — observed criteria satisfied
#   1   FAIL — observed criterion violated
#   2   UNVERIFIED — missing/stale evidence (explicit)
#   124/137 UNVERIFIED — timeout / killed (missing evidence)
#   127 UNVERIFIED — launcher/setup error (never treated as denial)
# Aggregation: any FAIL wins over UNVERIFIED; never map observed FAIL → INCOMPLETE.
set -euo pipefail
out=$1
src=$(realpath "$(dirname "$0")")
HISTORY_TIMEOUT="${HISTORY_TIMEOUT:-180}"
mkdir -p "$out/history-a" "$out/history-b"
: > "$out/trace.txt"
emit() { printf '%s\n' "$*" | tee -a "$out/trace.txt"; }

classify_status() {
  # stdout: PASS | FAIL | UNVERIFIED
  local status=$1
  case "$status" in
    0) printf 'PASS' ;;
    1) printf 'FAIL' ;;
    2|124|137|127) printf 'UNVERIFIED' ;;
    *) printf 'UNVERIFIED' ;;
  esac
}

write_outcome() {
  local dir=$1 mode=$2 verdict=$3 reason=$4 status=$5
  mkdir -p "$dir/stages"
  python3 - "$dir/stages/history-outcome.json" "$mode" "$verdict" "$reason" "$status" <<'PY'
import json, os, sys, time
from pathlib import Path
path, mode, verdict, reason, status = sys.argv[1:]
Path(path).write_text(json.dumps({
    "stage": "history-outcome",
    "history": mode,
    "verdict": verdict,
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
  local verdict
  verdict=$(classify_status "$status")
  local reason="ok"
  if [[ "$status" -eq 0 ]]; then
    emit "PASS: history $mode complete in isolated state"
    return 0
  fi
  if [[ "$status" -eq 1 ]]; then
    reason="observed_criterion_violated"
  elif [[ "$status" -eq 2 ]]; then
    reason="missing_or_stale_evidence"
  elif [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
    reason="history_timeout_${HISTORY_TIMEOUT}s"
  elif [[ "$status" -eq 127 ]]; then
    reason="launcher_or_setup_error"
  else
    reason="unexpected_status_${status}"
  fi
  write_outcome "$dir" "$mode" "$verdict" "$reason" "$status"
  emit "${verdict}: history $mode status=$status reason=$reason"
  return "$status"
}

emit "BEGIN dhcp-cgnat prove sha=${GITHUB_SHA:-local} run=${GITHUB_RUN_ID:-local} job=${GITHUB_JOB:-local} history_timeout=${HISTORY_TIMEOUT}s"

bash -n "$src/history.sh"
bash -n "$src/wan_lease.sh"

status_a=0
status_b=0
run_history "$out/history-a" A || status_a=$?
verdict_a=$(classify_status "$status_a")
if [[ "$status_a" -eq 0 ]]; then
  run_history "$out/history-b" B || status_b=$?
else
  # Do not run B after A failure/unverifiable; preserve A's verdict (FAIL wins).
  write_outcome "$out/history-b" B "UNVERIFIED" "skipped_after_A_${verdict_a}" "$status_a"
  emit "UNVERIFIED: history B skipped after A ${verdict_a}"
  status_b=2
fi
verdict_b=$(classify_status "$status_b")

python3 - "$out" "$status_a" "$status_b" "$verdict_a" "$verdict_b" <<'PY'
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[1])
status_a, status_b = int(sys.argv[2]), int(sys.argv[3])
verdict_a, verdict_b = sys.argv[4], sys.argv[5]

def load(mode, fallback_verdict, fallback_status):
    complete = root / f"history-{mode.lower()}" / "stages" / "history-complete.json"
    outcome = root / f"history-{mode.lower()}" / "stages" / "history-outcome.json"
    if complete.is_file() and fallback_status == 0:
        row = json.loads(complete.read_text())
        row.setdefault("verdict", "PASS")
        return row
    if outcome.is_file():
        return json.loads(outcome.read_text())
    return {
        "history": mode,
        "verdict": fallback_verdict,
        "reason": "missing_receipt",
        "exit_status": fallback_status,
    }

# Any observed FAIL is preserved even if the other history is UNVERIFIED.
if verdict_a == "FAIL" or verdict_b == "FAIL":
    overall = "FAIL"
    exit_code = 1
elif verdict_a == "UNVERIFIED" or verdict_b == "UNVERIFIED":
    overall = "UNVERIFIED"
    exit_code = 2
elif verdict_a == "PASS" and verdict_b == "PASS":
    overall = "PASS"
    exit_code = 0
else:
    overall = "UNVERIFIED"
    exit_code = 2

summary = {
    "verdict": overall,
    "sha": os.environ.get("GITHUB_SHA", "local"),
    "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    "job": os.environ.get("GITHUB_JOB", "local"),
    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    "observed_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "histories": {
        "A": load("A", verdict_a, status_a),
        "B": load("B", verdict_b, status_b),
    },
    "exit_status": {"A": status_a, "B": status_b},
    "verdicts": {"A": verdict_a, "B": verdict_b},
    "field_acceptance": "UNVERIFIED",
    "activation": "HELD",
    "claim": "actions_acceptance_requires_this_exact_sha_artifacts",
    "local_dev_provenance_only_if_sha_local": os.environ.get("GITHUB_SHA", "local") == "local",
}
(root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
raise SystemExit(exit_code)
PY
