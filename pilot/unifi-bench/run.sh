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
python3 "$here/readback.py" "$controller" --api-key-file "$key" --out "$out/controller-readback.json"
if ! python3 - "$out/controller-readback.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))["configuration_consistent"]
PY
then
  echo "HELD: review controller-readback.json before any capture" >&2
  exit 2
fi
echo "Observation only. Start separately approved A, B and C probe traffic when prompted." >&2
exec python3 "$here/bench.py" "$bench" --controller-receipt "$out/controller-readback.json" \
  --capture-tags --out "$out/tagged-bench.json"
