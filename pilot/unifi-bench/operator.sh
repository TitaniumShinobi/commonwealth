#!/bin/sh
# Observation-only while the supported AP-applied membership source is unavailable.
set -eu
if [ "${1:-}" = "--admit" ]; then
    printf '%s\n' '{"signed_admission":"HELD","blocker":"NO_SUPPORTED_U7_LITE_AP_APPLIED_MEMBERSHIP_PROVIDER","guard_called":false}'
    exit 2
fi
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 CONTROLLER_JSON PRIVATE_API_KEY_FILE BENCH_JSON NEW_RECEIPT_DIR" >&2
    exit 2
fi
exec bash "$(dirname "$0")/run.sh" "$@"
