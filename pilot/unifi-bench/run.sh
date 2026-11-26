#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(realpath "$(dirname "$0")")
if [[ $# != 4 ]]; then echo "usage: bash run.sh CONTROLLER_JSON PRIVATE_KEY_FILE BENCH_JSON NEW_OUTPUT_DIR" >&2; exit 2; fi
controller=$1
key=$2
bench=$3
out=$4
mkdir -m 700 "$out"
controller_receipt=$out/controller-readback.json
tagged_receipt=$out/tagged-bench.json
score=$out/receipt-score.json

if python3 "$here/readback.py" "$controller" --api-key-file "$key" --out "$controller_receipt" &&
   python3 - "$controller_receipt" <<'PY'
import json
import sys

with open(sys.argv[1]) as stream:
    receipt = json.load(stream)
sys.exit(0 if receipt.get("configuration_consistent") is True else 2)
PY
then
  echo "Observation only. Start separately approved A, B and C probe traffic when prompted." >&2
  if ! python3 "$here/bench.py" "$bench" --controller-receipt "$controller_receipt" \
       --capture-tags --out "$tagged_receipt"; then
    echo "HELD: scoring any available capture evidence." >&2
  fi
else
  echo "HELD: controller inventory incomplete; capture skipped." >&2
fi

score_status=0
python3 "$here/check_receipts.py" "$controller" "$bench" "$controller_receipt" "$tagged_receipt" \
  > "$score.tmp" || score_status=$?
if [[ "$score_status" != 0 && "$score_status" != 2 ]]; then
  rm -f "$score.tmp"
  exit "$score_status"
fi
mv "$score.tmp" "$score"
echo "Receipt score: $score" >&2
# Even a fully consistent bench observation cannot authorize signed admission.
exit 2
