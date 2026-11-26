#!/usr/bin/env bash
set -euo pipefail
installer=$1
out=$2
root=$PWD
ns=cwpi-controller
unit=uosserver.service
slice=cwpi.slice
drop=/run/systemd/system/uosserver.service.d/50-cwpi.conf
limit=8589934592
record() { printf '%s\n' "$*" | tee -a "$out/qualification.txt"; }
cleanup() {
  sudo -n systemctl stop "$unit" cwpi-wired.service 2>/dev/null || true
  sudo -n systemctl disable "$unit" 2>/dev/null || true
  while read -r pid; do
    if [[ -n "$pid" ]]; then sudo -n kill "$pid" 2>/dev/null || true; fi
  done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  sudo -n ip netns del "$ns" 2>/dev/null || true
  sudo -n rm -f "$drop" "/run/systemd/system/$slice"
  sudo -n systemctl daemon-reload
  sudo -n ss -H -lntu > "$out/host-listeners-after.txt"
}
trap cleanup EXIT
sudo -n systemctl is-active --quiet "$unit" && exit 1
sudo -n ss -H -lntu > "$out/host-listeners-before.txt"
sudo -n ip netns add "$ns"
sudo -n ip -n "$ns" link set lo up
sudo -n ip -n "$ns" link add management0 type dummy
sudo -n ip -n "$ns" addr add 192.0.2.20/24 dev management0
sudo -n ip -n "$ns" link set management0 up
sudo -n ip -n "$ns" route show > "$out/controller-routes.txt"
test "$(sudo -n ip -n "$ns" -o link show | wc -l)" -eq 2
test -z "$(sudo -n ip -n "$ns" route show default)"
sudo -n install -d /run/systemd/system/uosserver.service.d
printf '[Slice]\nMemoryAccounting=yes\nMemoryMax=%s\nMemorySwapMax=0\n' "$limit" |
  sudo -n tee "/run/systemd/system/$slice" >/dev/null
printf '[Service]\nSlice=%s\nNetworkNamespacePath=/run/netns/%s\n' "$slice" "$ns" |
  sudo -n tee "$drop" >/dev/null
sudo -n systemctl daemon-reload
sudo -n systemctl start "$slice"
test "$(cat /sys/fs/cgroup/cwpi.slice/memory.max)" = "$limit"
test "$(cat /sys/fs/cgroup/cwpi.slice/memory.swap.max)" = 0
record "ARM64 aggregate slice hard memory limit=$limit; swap=0"
test ! -e /usr/local/bin/uosserver
sudo -n nsenter --net="/run/netns/$ns" -- stat -fc %T /sys/fs/cgroup | tee "$out/installer-cgroup-fs.txt"
grep -qx cgroup2fs "$out/installer-cgroup-fs.txt"
chmod 700 "$installer"
set +e
printf 'y\n' | sudo -n systemd-run --scope --slice="$slice" \
  timeout 300s nsenter --net="/run/netns/$ns" -- "$installer" > "$out/install.log" 2>&1
install_status=$?
set -e
tail -n 60 "$out/install.log"
record "installer_exit=$install_status"
if ((install_status != 0)); then
  record 'UNVERIFIED: vendor install did not complete; wired co-host proof did not start'
  exit 2
fi
sample() {
  local label=$1
  {
    printf '%s %s\n' "$label" "$(date -u +%FT%TZ)"
    sudo -n systemctl show "$unit" -p MainPID -p ControlGroup -p ActiveState -p SubState -p NRestarts
    for metric in memory.current memory.peak memory.max memory.swap.current memory.events; do
      printf '%s=' "$metric"
      cat "/sys/fs/cgroup/$slice/$metric"
    done
    if [[ -n "$controller_cgroup" ]]; then
      for metric in memory.current memory.peak memory.max memory.swap.current memory.events; do
        printf "container.%s=" "$metric"
        cat "$controller_cgroup/$metric"
      done
    fi
  } >> "$out/resources.txt"
}
probe() {
  sudo -n ip netns exec "$ns" curl --noproxy '*' -kfsS --max-time 3 \
    https://127.0.0.1:11443/api/ping
}
wait_ready() {
  local label=$1
  for attempt in {1..45}; do
    if probe > "$out/$label-health.txt" 2>"$out/$label-health.err"; then return 0; fi
    sleep 3
  done
  return 1
}
guard_process() {
  local pid
  pid=$(systemctl show -p MainPID --value "$unit")
  test "$pid" -gt 1
  sudo -n grep -F "/$slice/" "/proc/$pid/cgroup"
  local controller_uid container_pid container_id actual prefix
  controller_uid=$(id -u uosserver)
  (
    cd /
    sudo -n nsenter --net="/run/netns/$ns" -- runuser -u uosserver -- \
      env HOME=/home/uosserver XDG_CONFIG_HOME=/home/uosserver/.config \
        XDG_RUNTIME_DIR="/run/user/$controller_uid" podman inspect uosserver \
      --format "{{.Id}} {{.State.Pid}}"
  ) > "$out/controller-container.pid"
  read -r container_id container_pid < "$out/controller-container.pid"
  test "$container_pid" -gt 1
  actual=$(sudo -n awk -F: '$1=="0" {print $3}' "/proc/$container_pid/cgroup")
  printf 'controller_container_cgroup=%s\n' "$actual"
  controller_cgroup=
  if [[ "$actual" == "/$slice/"* ]]; then
    sudo -n systemctl set-property --runtime "$slice" MemoryMax="$limit" MemorySwapMax=0
    return
  fi
  # Use the Podman container ancestor, including inner-systemd child cgroups.
  prefix=$(python3 - "$actual" "$container_id" <<'PY'
import sys
path, identity = sys.argv[1:]
parts = path.split("/")
for i, segment in enumerate(parts):
    if identity in segment:
        print("/".join(parts[:i+1]))
        break
PY
)
  if [[ -z "$prefix" ]]; then
    record 'UNVERIFIED: could not identify the rootless container ancestor'
    return 2
  fi
  controller_cgroup="/sys/fs/cgroup$prefix"
  sudo -n systemctl set-property --runtime "$slice" MemoryMax=2147483648 MemorySwapMax=0
  printf '6442450944\n' | sudo -n tee "$controller_cgroup/memory.max" >/dev/null
  printf '0\n' | sudo -n tee "$controller_cgroup/memory.swap.max" >/dev/null
  test "$(cat "$controller_cgroup/memory.max")" = 6442450944
  test "$(cat "/sys/fs/cgroup/$slice/memory.max")" = 2147483648
  record 'Effective aggregate cap: 2 GiB service/wired slice + 6 GiB rootless container; swap=0'
  test "$(sudo -n readlink "/proc/$pid/ns/net")" = "$(sudo -n ip netns exec "$ns" readlink /proc/self/ns/net)"
}
controller_cgroup=
sample installed
sudo -n systemctl start "$unit"
if ! wait_ready before; then
  sudo -n journalctl -u "$unit" -n 60 --no-pager > "$out/controller-journal.txt"
  record 'UNVERIFIED: isolated local controller health did not reach HTTP success'
  exit 2
fi
guard_process > "$out/controller-cgroup.txt"
cat "$out/controller-cgroup.txt"
sudo -n ip netns exec "$ns" ss -H -lntu > "$out/private-listeners.txt"
sudo -n ss -H -lntu > "$out/host-during.txt"
if awk '{print $5}' "$out/host-during.txt" | grep -Eq ':(9543|11443|28082|3478|5514|5671|6789|8080|8444|8880|8881|8882|11084|10003)$'; then
  record 'FAIL: controller listener appeared in runner namespace'
  exit 1
fi
sample ready
{
  echo 'Local controller probes without API key. Self-signed TLS is fixture-scoped.'
  for path in /api/ping /proxy/network/integration/v1/sites /integration/v1/sites; do
    response=$(mktemp "$out/.response.XXXXXX")
    metadata=$(sudo -n ip netns exec "$ns" curl --noproxy '*' -ksS --max-time 5 --max-filesize 262144 \
      -H 'Accept: application/json' --output "$response" --write-out '%{http_code}|%{content_type}' \
      "https://127.0.0.1:11443$path")
    python3 - "$path" "$metadata" "$response" <<'PY'
import hashlib, json, sys
from pathlib import Path
path, metadata, response = sys.argv[1:]
status, media = metadata.split("|", 1)
body = Path(response).read_bytes()
try:
    value = json.loads(body)
    shape = sorted(value) if isinstance(value, dict) else type(value).__name__
except ValueError:
    shape = "non-json" if body else "empty"
print(json.dumps({"path": path, "status": int(status), "media": media, "json_shape": shape,
                  "authenticated": False, "sha256": hashlib.sha256(body).hexdigest()}))
PY
    rm -f "$response"
  done
} | tee "$out/controller-local-api-probe.txt"
sudo -n systemctl restart "$unit"
wait_ready restarted
guard_process
sample restarted
sudo -n systemd-run --wait --pipe --collect --unit=cwpi-wired --slice="$slice" \
  --uid="$(id -u)" --gid="$(id -g)" --working-directory="$root" --setenv="GITHUB_SHA=$GITHUB_SHA" \
  bash -c 'cat /proc/self/cgroup; exec bash "$1" "$2"' _ "$root/pilot/activation/prove.sh" "$out/wired" > "$out/wired-run.log" 2>&1 &
wired_pid=$!
healthy=0
while kill -0 "$wired_pid" 2>/dev/null; do
  sample concurrent
  if probe >> "$out/concurrent-health.txt" 2>> "$out/concurrent-health.err"; then
    healthy=$((healthy + 1))
  else
    record 'FAIL: controller health failed during wired exercise'
    wait "$wired_pid" || true
    exit 1
  fi
  sleep 2
done
wait "$wired_pid"
tail -n 45 "$out/wired-run.log"
grep -F "/$slice/" "$out/wired-run.log"
grep -F 'exact approved baseline cannot bypass durable withdrawal' "$out/wired/trace.txt"
test "$healthy" -ge 2
sample completed
test "$(awk '$1=="oom_kill" {print $2}' "/sys/fs/cgroup/$slice/memory.events")" -eq 0
if [[ -n "$controller_cgroup" ]]; then
  test "$(awk '$1=="oom_kill" {print $2}' "$controller_cgroup/memory.events")" -eq 0
fi
tail -n 27 "$out/resources.txt"
record "PASS: isolated controller responded to $healthy overlapping health observations"

set +e
sudo -n ip netns exec "$ns" env PLAYWRIGHT_BROWSERS_PATH="$RUNNER_TEMP/unifi-browsers" \
  "$(command -v node)" "$root/pilot/unifi-bench/local-ui.mjs" "$RUNNER_TEMP/unifi-ui" \
  "$out/local-ui.json" "$GITHUB_SHA"
ui_status=$?
set -e
record "local_ui_exit=$ui_status"
exit "$ui_status"
