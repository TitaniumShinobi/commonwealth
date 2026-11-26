#!/usr/bin/env bash
set -euo pipefail
umask 022
work=$1
node=$2
chrome=$3
stock_source=$4
stock_revision=9175a66ff0af9d7b29c80a5816a6c46ba4b25d0a
test "$(git -C "$stock_source" rev-parse HEAD)" = "$stock_revision"
stock_pid=
caller_uid=$SUDO_UID
caller_gid=$SUDO_GID
trap 'if [[ -n "$stock_pid" ]]; then kill "$stock_pid" 2>/dev/null || true; wait "$stock_pid" 2>/dev/null || true; fi; chown "$caller_uid:$caller_gid" "$work/trace.ndjson" "$work/browser.json" 2>/dev/null || true' EXIT
ip link set lo up
test "$(ip -o link show | wc -l)" -eq 1
test -z "$(ip route show default)"
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:2\n' > "$work/resolv.conf"
mount --bind "$work/resolv.conf" /etc/resolv.conf
cd "$work"
export HOME="$work/home"
export DBUS_SESSION_BUS_ADDRESS=unix:path=/dev/null
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/dev/null
mkdir -p "$HOME/.pki/nssdb"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout ca.key -out ca.pem \
  -subj '/CN=Commonwealth Step 11 Fixture CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
for role in gateway origin; do
  name=localhost
  if [[ "$role" == gateway ]]; then name=lab.example; fi
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$name" -keyout "$role.key" -out "$role.csr"
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$name" > "$role.ext"
  openssl x509 -req -in "$role.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 1 -extfile "$role.ext" -out "$role.pem"
done
certutil -N --empty-password -d "sql:$HOME/.pki/nssdb"
certutil -A -d "sql:$HOME/.pki/nssdb" -t 'C,,' -n 'Step 11 fixture root' -i ca.pem
cd - >/dev/null
(cd "$stock_source" && exec openssl s_server -quiet -WWW -accept 127.0.0.1:8443 \
  -cert "$work/origin.pem" -key "$work/origin.key") > "$work/stock-origin.log" 2>&1 &
stock_pid=$!
for attempt in {1..20}; do
  if curl --noproxy '*' --cacert "$work/ca.pem" --max-time 2 --fail --silent \
    https://localhost:8443/kit/package/GUIDE.md -o "$work/stock-probe"; then break; fi
  kill -0 "$stock_pid"
  sleep 0.1
done
cmp "$work/stock-probe" "$stock_source/kit/package/GUIDE.md"
PYTHONDONTWRITEBYTECODE=1 python3 simulation/step11/fixture.py "$work" "$node" "$chrome" "$stock_source"

PYTHONDONTWRITEBYTECODE=1 python3 simulation/step11/replay.py "$work"
