#!/usr/bin/env bash
set -euo pipefail
umask 022
work=$1
node=$2
chrome=$3
caller_uid=$SUDO_UID
caller_gid=$SUDO_GID
trap 'chown "$caller_uid:$caller_gid" "$work/trace.ndjson" "$work/browser.json" 2>/dev/null || true' EXIT
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
PYTHONDONTWRITEBYTECODE=1 python3 simulation/step11/fixture.py "$work" "$node" "$chrome"

PYTHONDONTWRITEBYTECODE=1 python3 simulation/step11/replay.py "$work"
