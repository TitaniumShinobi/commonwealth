#!/usr/bin/env bash
set -euo pipefail
out=$1 src=$2 guest=$3 edge=$4 peer=$5 operator=$6 keys=$7
g() { sudo -n ip netns exec "$guest" "$@"; }
e() { sudo -n ip netns exec "$edge" "$@"; }
public() {
  g env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error --connect-timeout 4 \
    --max-time 8 --output /dev/null --write-out '%{http_code} %{ssl_verify_result}\n' https://example.com/
}
emit() { printf '%s\n' "$*" | tee -a "$out/trace.txt"; }
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$keys/ca.key" -out "$keys/ca.pem" \
  -subj '/CN=Commonwealth wired fixture CA' 2>/dev/null
for role in server client; do
  cn=peer.fixture.test
  extension=serverAuth
  if [[ "$role" == client ]]; then cn=wired-guest-peer; extension=clientAuth; fi
  openssl req -new -newkey rsa:2048 -nodes -keyout "$keys/$role.key" -out "$keys/$role.csr" \
    -subj "/CN=$cn" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=%s\n' "$cn" "$extension" > "$keys/$role.ext"
  openssl x509 -req -in "$keys/$role.csr" -CA "$keys/ca.pem" -CAkey "$keys/ca.key" -CAcreateserial \
    -days 1 -extfile "$keys/$role.ext" -out "$keys/$role.pem" 2>/dev/null
done
sudo -n ip netns exec "$peer" python3 -u "$src/peer.py" "$keys" > "$out/peer-audit.log" 2>&1 &
for attempt in {1..30}; do
  if grep -qx ready "$out/peer-audit.log"; then break; fi
  sleep 0.1
done
grep -qx ready "$out/peer-audit.log"
for endpoint in 10.231.60.3 10.231.60.4; do
  e curl -fsS --noproxy '*' --max-time 3 "http://$endpoint:8080/" >> "$out/protected-positive.txt"
  if g curl -fsS --noproxy '*' --max-time 2 "http://$endpoint:8080/" >> "$out/protected-deny.txt" 2>&1; then
    exit 1
  fi
done
emit 'PASS: guest cannot reach active household and management endpoints'
probe() {
  g curl --silent --show-error --fail --noproxy '*' --max-time 4 \
    --resolve peer.fixture.test:8443:10.231.60.2 --cacert "$keys/ca.pem" \
    --cert "$keys/client.pem" --key "$keys/client.key" "$@"
}
# Before opening the crossing, the working destination is inaccessible from the guest.
url=https://peer.fixture.test:8443/records/record-01
if probe "$url" > "$out/peer-before-denial.txt" 2>&1; then exit 1; fi
python3 "$src/edge.py" approve "$out/target.json" cross-open "$operator/operator.key" > "$out/cross-open.json"
python3 "$src/edge.py" render "$out/target.json" crossing "$out/cross-open.json" "$operator/operator.pub" "$operator" > "$out/crossing.nft"
e nft --check -f "$out/crossing.nft"
e nft -f "$out/crossing.nft"
probe "$url" > "$out/peer-allowed.json"
grep -F '"record-01":"wired-crossing-fixture"' "$out/peer-allowed.json"
if probe https://peer.fixture.test:8443/private > "$out/peer-scope-denial.txt" 2>&1; then exit 1; fi
grep -F '"decision": "denied"' "$out/peer-audit.log"
public > "$out/https-during-crossing.txt"
grep -x '200 0' "$out/https-during-crossing.txt"
e conntrack -L -p tcp -d 10.231.60.2 --dport 8443 > "$out/cross-conntrack-before.txt"
grep -F 'dst=10.231.60.2' "$out/cross-conntrack-before.txt"
python3 "$src/edge.py" approve "$out/target.json" cross-close "$operator/operator.key" > "$out/cross-close.json"
python3 "$src/edge.py" render "$out/target.json" post-crossing "$out/cross-close.json" "$operator/operator.pub" > "$out/post-crossing.nft"
e nft --check -f "$out/post-crossing.nft"
e nft -f "$out/post-crossing.nft"
python3 "$src/edge.py" record-cross-close "$out/target.json" "$out/cross-close.json" "$operator/operator.pub" "$operator"
if python3 "$src/edge.py" render "$out/target.json" crossing "$out/cross-open.json" "$operator/operator.pub" "$operator" > "$out/stale-crossing.txt" 2>&1; then exit 1; fi
e conntrack -D -p tcp -d 10.231.60.2 --dport 8443 > "$out/cross-delete.txt" 2>&1
e conntrack -L -p tcp -d 10.231.60.2 --dport 8443 > "$out/cross-conntrack-after.txt"
test ! -s "$out/cross-conntrack-after.txt"
if probe "$url" > "$out/peer-stale-denial.txt" 2>&1; then exit 1; fi
test "$(grep -c '"decision": "allowed"' "$out/peer-audit.log")" -eq 1
public > "$out/https-after-crossing.txt"
grep -x '200 0' "$out/https-after-crossing.txt"
emit 'PASS: authorized mTLS crossing, destination scope denial, stale read blocked, unrelated HTTPS retained'
