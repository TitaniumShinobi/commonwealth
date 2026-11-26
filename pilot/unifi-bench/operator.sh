#!/bin/sh
# Observation-only while the supported AP-applied membership source is unavailable.
set -eu
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 CONTROLLER_JSON PRIVATE_API_KEY_FILE BENCH_JSON NEW_RECEIPT_DIR" >&2
    exit 2
fi
exec bash "$(dirname "$0")/run.sh" "$@"
