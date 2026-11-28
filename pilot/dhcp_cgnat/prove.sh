#!/usr/bin/env bash
# Isolated WAN DHCP + modeled carrier NAT fixture. Reuses pilot/activation edge policy.
# Carrier path stays off host egress; origin uses reserved TEST-NET-3 addresses.
set -euo pipefail
out=$1
act=$(realpath "$(dirname "$0")/../activation")
src=$(realpath "$(dirname "$0")")
guest="cwg$$"
edge="cwe$$"
isp="cwi$$"
origin="cwo$$"
attacker="cwa$$"
unaffected="cwc$$"
mgmt="cwm$$"
operator=$(mktemp -d)
rmdir "$operator"
keys=$(mktemp -d)
portal=10.231.56.1
leased=10.231.56.50
mac=02:23:15:60:00:50
origin_ip=203.0.113.10
origin_name=origin.fixture.test
guest_dns_pid=
isp_dhcp_pid=
origin_pid=
mgmt_pid=
mkdir -p "$out/history-a" "$out/history-b" "$out/receipts" "$keys"
emit() { printf '%s\n' "$*" | tee -a "$out/trace.txt"; }
cleanup() {
  if [[ -n "${origin_pid:-}" ]]; then sudo -n kill "$origin_pid" 2>/dev/null || true; fi
  if [[ -n "${guest_dns_pid:-}" ]]; then sudo -n kill "$guest_dns_pid" 2>/dev/null || true; fi
  if [[ -n "${isp_dhcp_pid:-}" ]]; then sudo -n kill "$isp_dhcp_pid" 2>/dev/null || true; fi
  if [[ -n "${mgmt_pid:-}" ]]; then sudo -n kill "$mgmt_pid" 2>/dev/null || true; fi
  local ns pid
  for ns in "$guest" "$edge" "$isp" "$origin" "$attacker" "$unaffected" "$mgmt"; do
    while read -r pid; do
      if [[ -n "$pid" ]]; then sudo -n kill "$pid" 2>/dev/null || true; fi
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  for ns in "$guest" "$edge" "$isp" "$origin" "$attacker" "$unaffected" "$mgmt"; do
    sudo -n ip netns del "$ns" 2>/dev/null || true
  done
  sudo -n rm -rf "/etc/netns/$guest" "/etc/netns/$edge"
  rm -rf -- "$operator" "$operator-wrong" "$keys"
}
trap cleanup EXIT

g() { sudo -n ip netns exec "$guest" "$@"; }
e() { sudo -n ip netns exec "$edge" "$@"; }
i() { sudo -n ip netns exec "$isp" "$@"; }
o() { sudo -n ip netns exec "$origin" "$@"; }
m() { sudo -n ip netns exec "$mgmt" "$@"; }

for ns in "$guest" "$edge" "$isp" "$origin" "$attacker" "$unaffected" "$mgmt"; do
  sudo -n ip netns add "$ns"
  sudo -n ip -n "$ns" link set lo up
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done

# Guest <-> edge LAN
sudo -n ip link add "g$$" netns "$guest" type veth peer name "l$$" netns "$edge"
sudo -n ip -n "$guest" link set "g$$" name lan0
sudo -n ip -n "$edge" link set "l$$" name lan0
g ip link set lan0 address "$mac"
g ip link set lan0 up
e ip addr add "$portal/24" dev lan0
e ip link set lan0 up

# Edge WAN <-> ISP (no static WAN address; DHCP hook installs it)
sudo -n ip link add "w$$" netns "$edge" type veth peer name "e$$" netns "$isp"
sudo -n ip -n "$edge" link set "w$$" name wan0
sudo -n ip -n "$isp" link set "e$$" name edge0
e ip link set wan0 up
i ip link set edge0 up
wan_mac=$(e cat /sys/class/net/wan0/address)
printf '%s\n' "$wan_mac" > "$out/receipts/wan-mac.txt"

# ISP <-> origin (reserved public TEST-NET-3; isolated from host egress)
sudo -n ip link add "p$$" netns "$isp" type veth peer name "o$$" netns "$origin"
sudo -n ip -n "$isp" link set "p$$" name pub0
sudo -n ip -n "$origin" link set "o$$" name pub0
i ip addr add 203.0.113.1/24 dev pub0
i ip link set pub0 up
o ip addr add "$origin_ip/24" dev pub0
o ip link set pub0 up
o ip route add default via 203.0.113.1

# Attacker / unaffected / local management (activation patterns)
sudo -n ip link add lan1 netns "$edge" type veth peer name lan0 netns "$attacker"
e ip addr add 10.231.59.1/24 dev lan1
e ip link set lan1 up
sudo -n ip -n "$attacker" link set lan0 address "$mac"
sudo -n ip -n "$attacker" addr add "$leased/24" dev lan0
sudo -n ip -n "$attacker" link set lan0 up
sudo -n ip -n "$attacker" route add default via 10.231.59.1 dev lan0 onlink
sudo -n ip link add lan2 netns "$edge" type veth peer name lan0 netns "$unaffected"
e ip addr add 10.231.61.1/24 dev lan2
e ip link set lan2 up
sudo -n ip -n "$unaffected" link set lan0 address 02:23:15:61:00:02
sudo -n ip -n "$unaffected" addr add 10.231.61.2/24 dev lan0
sudo -n ip -n "$unaffected" link set lan0 up
sudo -n ip -n "$unaffected" route add default via 10.231.61.1
sudo -n ip link add mgmt0 netns "$edge" type veth peer name mgmt0 netns "$mgmt"
e ip addr add 10.231.62.1/24 dev mgmt0
e ip link set mgmt0 up
sudo -n ip -n "$mgmt" addr add 10.231.62.2/24 dev mgmt0
sudo -n ip -n "$mgmt" link set mgmt0 up
mkdir -p "$keys/mgmt"
printf 'local-management-ok\n' > "$keys/mgmt/index.html"
m python3 -u -m http.server 8088 --bind 10.231.62.2 --directory "$keys/mgmt" > "$out/mgmt.log" 2>&1 &
mgmt_pid=$!
for _ in {1..40}; do
  if e curl -fsS --noproxy '*' --max-time 1 http://10.231.62.2:8088/ > "$out/receipts/mgmt-baseline.txt" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
grep -x 'local-management-ok' "$out/receipts/mgmt-baseline.txt"
# Carrier NAT + withhold table (ISP). Isolated: no route to host/public Internet.
i sysctl -qw net.ipv4.ip_forward=1
i nft -f - <<'NFT'
flush ruleset
table inet cgnat {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related counter accept
    iifname "edge0" oifname "pub0" ip protocol { tcp, udp, icmp } counter accept
    iifname "pub0" oifname "edge0" ct state established,related counter accept
  }
  chain withhold {
    type filter hook forward priority -50; policy accept;
  }
}
table ip cgnat_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "pub0" ip saddr 100.64.0.0/10 counter masquerade
  }
}
NFT

# Fixture TLS material for reserved-name origin
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$keys/origin.key" -out "$keys/origin.pem" \
  -subj "/CN=$origin_name" -addext "subjectAltName=DNS:$origin_name,DNS:fixture.test" 2>/dev/null
o python3 -u "$src/origin.py" --cert "$keys/origin.pem" --key "$keys/origin.key" \
  --query-log "$out/receipts/dns-queries.ndjson" --nonce-log "$out/receipts/tls-nonces.ndjson" \
  > "$out/origin.log" 2>&1 &
origin_pid=$!
for _ in {1..40}; do
  if grep -qx ready "$out/origin.log"; then break; fi
  sleep 0.1
done
grep -qx ready "$out/origin.log"

# Edge operator target + default-closed guest policy (activation edge)
sudo -n install -d -m 755 "/etc/netns/$guest" "/etc/netns/$edge"
printf '# managed by fixture DHCP\n' | sudo -n tee "/etc/netns/$guest/resolv.conf" >/dev/null
pin=$(python3 "$act/edge.py" bootstrap "$operator")
python3 - "$out/target.json" "$edge" "$leased" "$mac" "$pin" <<'PY'
import json, sys
from pathlib import Path
out, node, ip, mac, pin = sys.argv[1:]
Path(out).write_text(json.dumps({
    "node": node, "inside": "lan0", "outside": "wan0",
    "guest_ip": ip, "guest_mac": mac, "operator": "runner",
    "relay_ips": ["203.0.113.10"], "operator_key_sha256": pin
}))
PY
allow_mgmt_input() {
  # Explicit fixture-only input: dedicated mgmt iface + mgmt address + management port replies.
  # Not a broad established bypass; guest/private forward policy stays default-drop.
  e nft add rule inet guest_edge input iifname '"mgmt0"' ip saddr 10.231.62.2 tcp sport 8088 ct state established,related counter accept
}
python3 "$act/edge.py" render "$out/target.json" closed > "$out/closed.nft"
e nft --check -f "$out/closed.nft"
e nft -f "$out/closed.nft"
allow_mgmt_input
e sysctl -qw net.ipv4.ip_forward=1
# Confirm local management after guest policy is loaded
e curl -fsS --noproxy '*' --max-time 2 http://10.231.62.2:8088/ > "$out/receipts/mgmt-after-closed.txt"
grep -x 'local-management-ok' "$out/receipts/mgmt-after-closed.txt"

# Guest LAN DHCP + recursive forwarder to fixture origin through WAN
start_guest_dns() {
  if [[ -n "${guest_dns_pid:-}" ]]; then sudo -n kill "$guest_dns_pid" 2>/dev/null || true; fi
  sudo -n ip netns exec "$edge" dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --bind-interfaces \
    --interface=lan0 --listen-address="$portal" --log-dhcp --log-queries --log-facility=- \
    --dhcp-range=10.231.56.40,10.231.56.60,255.255.255.0,10m \
    --dhcp-host="$mac,$leased" --dhcp-option="3,$portal" --dhcp-option="6,$portal" \
    --server=203.0.113.10 > "$out/guest-dnsmasq.log" 2>&1 &
  guest_dns_pid=$!
  sleep 0.2
}
start_guest_dns

stop_isp_dhcp() {
  if [[ -n "${isp_dhcp_pid:-}" ]]; then
    sudo -n kill "$isp_dhcp_pid" 2>/dev/null || true
    wait "$isp_dhcp_pid" 2>/dev/null || true
    isp_dhcp_pid=
  fi
}

# ISP DHCP for edge WAN. Addresses/routes change only through udhcpc hook.
start_isp_dhcp() {
  local subnet=$1 router=$2 host=$3 range_start=$4 range_end=$5
  stop_isp_dhcp
  i ip addr flush dev edge0
  i ip addr add "$router/24" dev edge0
  # Optional secondary next-hop for history B
  if [[ -n "${6:-}" ]]; then
    i ip addr add "$6/24" dev edge0
  fi
  : > "$out/isp-dhcp.leases"
  sudo -n chmod 666 "$out/isp-dhcp.leases"
  sudo -n ip netns exec "$isp" dnsmasq --keep-in-foreground --conf-file=/dev/null --bind-interfaces \
    --interface=edge0 --listen-address="$router" --dhcp-authoritative --log-dhcp --log-facility=- \
    --dhcp-leasefile="$out/isp-dhcp.leases" --dhcp-script=/bin/true \
    --dhcp-range="$range_start,$range_end,255.255.255.0,5m" \
    --dhcp-host="${wan_mac},${host}" \
    --dhcp-option="3,${router}" --dhcp-option="6,${origin_ip}" \
    > "$out/isp-dhcp.log" 2>&1 &
  isp_dhcp_pid=$!
  sleep 0.3
}

wan_dhcp() {
  local label=$1
  local log="$out/receipts/wan-lease-$label.ndjson"
  sudo -n install -m 666 /dev/null "$log"
  # Edge WAN DHCP client; hook installs address and default route.
  e env CW_WAN_LEASE_LOG="$log" timeout 20s udhcpc -n -q -f -s "$src/wan_lease.sh" -i wan0 \
    > "$out/receipts/wan-udhcpc-$label.log" 2>&1
  e ip -4 addr show dev wan0 > "$out/receipts/wan-addr-$label.txt"
  e ip -4 route > "$out/receipts/wan-route-$label.txt"
  test -s "$log"
  grep -E '"event":"(bound|renew)"' "$log"
}

withhold_on() {
  i nft flush chain inet cgnat withhold
  i nft add rule inet cgnat withhold iifname '"edge0"' udp dport 53 counter drop
  i nft add rule inet cgnat withhold iifname '"edge0"' tcp dport 53 counter drop
  i nft add rule inet cgnat withhold iifname '"edge0"' tcp dport 443 counter drop
}
withhold_off() {
  i nft flush chain inet cgnat withhold
}

guest_lease() {
  g timeout 25s udhcpc -n -q -f -s "$act/lease.sh" -i lan0 > "$out/client-dhcp.log" 2>&1
  g ip -br address > "$out/guest-addresses.txt"
  g ip -4 route > "$out/guest-routes.txt"
  test "$(g ip -o link show | wc -l)" -eq 2
  test "$(g ip -4 route show default | wc -l)" -eq 1
  grep -F "$leased/24" "$out/guest-addresses.txt"
  grep -F "via $portal dev lan0" "$out/guest-routes.txt"
}

tls_probe() {
  local dest=$1
  g env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error \
    --cacert "$keys/origin.pem" --resolve "$origin_name:443:$origin_ip" \
    --connect-timeout 3 --max-time 8 \
    --write-out '%{http_code} %{ssl_verify_result}\n' \
    --output "$dest.body" "https://$origin_name/" > "$dest.meta" 2>"$dest.err" || return 1
  grep -E '^200 0$' "$dest.meta"
  grep -E '^ok nonce=[0-9a-f]{32}$' "$dest.body"
}

dns_probe() {
  local dest=$1
  g env -i PATH=/usr/bin:/bin getent ahostsv4 "$origin_name" > "$dest" 2>"$dest.err" || return 1
  grep -F "$origin_ip" "$dest"
}

deny_tls() {
  if tls_probe "$out/receipts/$1"; then emit "FAIL: expected denial $1"; exit 1; fi
  emit "PASS: negative $1"
}

admit_open() {
  python3 "$act/edge.py" approve "$out/target.json" admit "$operator/operator.key" > "$out/admission.json"
  cp "$operator/operator.pub" "$out/operator.pub"
  python3 "$act/edge.py" record-session "$out/target.json" "$out/admission.json" "$operator/operator.pub" "$operator"
  python3 "$act/edge.py" guard "$out/target.json" "$operator/operator.pub" "$operator" > "$out/admitted-guard.nft"
  e nft --check -f "$out/admitted-guard.nft"
  e nft -f "$out/admitted-guard.nft"
  python3 "$act/edge.py" render "$out/target.json" open "$out/admission.json" "$operator/operator.pub" "$operator" > "$out/open.nft"
  cp "$out/open.nft" "$out/exact-rollback.nft"
  e nft --check -f "$out/open.nft"
  e nft -f "$out/open.nft"
  allow_mgmt_input
}

unaffected_tls() {
  local tag=$1
  # Unaffected uses edge resolver mapping via explicit resolve to fixture IP (same carrier path).
  sudo -n ip netns exec "$unaffected" env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' \
    --silent --show-error --cacert "$keys/origin.pem" --resolve "$origin_name:443:$origin_ip" \
    --connect-timeout 3 --max-time 8 --output /dev/null --write-out '%{http_code} %{ssl_verify_result}\n' \
    "https://$origin_name/" > "$out/receipts/unaffected-$tag.txt"
  grep -x '200 0' "$out/receipts/unaffected-$tag.txt"
}

record_nat() {
  local tag=$1
  i nft list chain ip cgnat_nat postrouting > "$out/receipts/nat-$tag.txt"
  i nft list chain inet cgnat forward > "$out/receipts/fwd-$tag.txt"
  i conntrack -L 2>/dev/null | grep -E '203\.0\.113\.|100\.64\.' > "$out/receipts/ct-$tag.txt" || true
}

########################################
# Negative: before any WAN lease
########################################
guest_lease
emit 'DHCP PASS: guest lease AND only guest default route'
g cat /etc/resolv.conf > "$out/guest-resolver.txt"
grep -F "nameserver $portal" "$out/guest-resolver.txt"
# Edge has no WAN lease yet -> guest DNS/TLS through carrier must fail
deny_tls before-wan-lease
emit 'PASS: before-WAN-lease DNS/TLS denied'

########################################
# History A: subnet/address renumber + next-hop change via DHCP hook
########################################
start_isp_dhcp 100.64.10.0/24 100.64.10.1 100.64.10.50 100.64.10.40 100.64.10.60
wan_dhcp a1
grep -F '100.64.10.50' "$out/receipts/wan-addr-a1.txt"
grep -F 'via 100.64.10.1' "$out/receipts/wan-route-a1.txt"
grep -F '"ip":"100.64.10.50"' "$out/receipts/wan-lease-a1.ndjson"
grep -F '"router":"100.64.10.1"' "$out/receipts/wan-lease-a1.ndjson"

# Lease present but withhold DNS/TLS briefly (lease ≠ usable recovery)
withhold_on
deny_tls lease-before-recovery-a
e ip -4 addr show dev wan0 | grep -F '100.64.10.50'
emit 'PASS: lease-before-recovery withhold (address present, DNS/TLS denied)'
withhold_off

admit_open
dns_probe "$out/receipts/dns-a1.txt"
tls_probe "$out/receipts/tls-a1"
nonce1=$(sed -n 's/^ok nonce=//p' "$out/receipts/tls-a1.body")
test -n "$nonce1"
record_nat a1
unaffected_tls a1
# Guest has working egress; management still must stay unreachable (no guest→mgmt forward).
if g curl -fsS --noproxy '*' --max-time 2 http://10.231.62.2:8088/ > "$out/receipts/guest-mgmt-deny.txt" 2>&1; then
  emit 'FAIL: guest reached local management'
  exit 1
fi
emit 'PASS: guest-to-management denial'
emit 'PASS: history A initial lease DNS+TLS through carrier NAT'

# Sole-uplink outage: ISP public link down; local management remains
i ip link set pub0 down
deny_tls sole-uplink-outage-a
if ! e curl -fsS --noproxy '*' --connect-timeout 2 --max-time 3 http://10.231.62.2:8088/ \
  > "$out/receipts/mgmt-during-outage.txt"; then
  emit 'FAIL: local management unreachable during sole-uplink outage'
  cat "$out/mgmt.log" || true
  e ip -4 addr; e ip -4 route
  exit 1
fi
grep -x 'local-management-ok' "$out/receipts/mgmt-during-outage.txt"
emit 'PASS: sole-uplink outage blocks guest; local management continues'
i ip link set pub0 up
dns_probe "$out/receipts/dns-a1-recover.txt"
tls_probe "$out/receipts/tls-a1-recover"
emit 'PASS: uplink recovery'

# Renumber WAN subnet/address and next hop via DHCP only (no shell addr/route writes)
start_isp_dhcp 100.64.20.0/24 100.64.20.1 100.64.20.50 100.64.20.40 100.64.20.60
# Release then rediscover so hook replaces address/default route
sudo -n install -m 666 /dev/null "$out/receipts/wan-lease-a2-release.ndjson"
e env CW_WAN_LEASE_LOG="$out/receipts/wan-lease-a2-release.ndjson" udhcpc -R -n -q -f -s "$src/wan_lease.sh" -i wan0 \
  > "$out/receipts/wan-udhcpc-a2-release.log" 2>&1 || true
wan_dhcp a2
grep -F '100.64.20.50' "$out/receipts/wan-addr-a2.txt"
grep -F 'via 100.64.20.1' "$out/receipts/wan-route-a2.txt"
grep -F '"ip":"100.64.20.50"' "$out/receipts/wan-lease-a2.ndjson"
grep -F '"router":"100.64.20.1"' "$out/receipts/wan-lease-a2.ndjson"
# Ensure old address is gone (hook replaced, not stacked by test shell)
if grep -F '100.64.10.50' "$out/receipts/wan-addr-a2.txt"; then emit 'FAIL: old WAN address remained'; exit 1; fi
dns_probe "$out/receipts/dns-a2.txt"
tls_probe "$out/receipts/tls-a2"
nonce2=$(sed -n 's/^ok nonce=//p' "$out/receipts/tls-a2.body")
test -n "$nonce2"
test "$nonce1" != "$nonce2"
record_nat a2
cp "$out/receipts/wan-lease-a1.ndjson" "$out/history-a/lease-before.ndjson"
cp "$out/receipts/wan-lease-a2.ndjson" "$out/history-a/lease-after.ndjson"
cp "$out/receipts/wan-route-a1.txt" "$out/history-a/route-before.txt"
cp "$out/receipts/wan-route-a2.txt" "$out/history-a/route-after.txt"
emit 'PASS: history A renumber + next-hop change via DHCP hook with fresh TLS nonce'

########################################
# History B: same WAN address, changed DHCP next hop (independent)
########################################
# Tear WAN lease and restart ISP on original subnet with two routers
sudo -n install -m 666 /dev/null "$out/receipts/wan-lease-b-deconfig.ndjson"
e env CW_WAN_LEASE_LOG="$out/receipts/wan-lease-b-deconfig.ndjson" udhcpc -R -n -q -f -s "$src/wan_lease.sh" -i wan0 \
  > "$out/receipts/wan-udhcpc-b-release.log" 2>&1 || true
# Do not shell-install the next history's address/route; only clear so DHCP can bind fresh.
e ip addr flush dev wan0 2>/dev/null || true
e ip route del default 2>/dev/null || true
start_isp_dhcp 100.64.10.0/24 100.64.10.1 100.64.10.50 100.64.10.40 100.64.10.60
wan_dhcp b1
grep -F '100.64.10.50' "$out/receipts/wan-addr-b1.txt"
grep -F 'via 100.64.10.1' "$out/receipts/wan-route-b1.txt"
dns_probe "$out/receipts/dns-b1.txt"
tls_probe "$out/receipts/tls-b1"
nonce_b1=$(sed -n 's/^ok nonce=//p' "$out/receipts/tls-b1.body")

# Change DHCP next hop only; keep leased address. Hook must replace default route.
stop_isp_dhcp
i ip addr flush dev edge0
i ip addr add 100.64.10.1/24 dev edge0
i ip addr add 100.64.10.2/24 dev edge0
: > "$out/isp-dhcp.leases"
sudo -n chmod 666 "$out/isp-dhcp.leases"
sudo -n ip netns exec "$isp" dnsmasq --keep-in-foreground --conf-file=/dev/null --bind-interfaces \
  --interface=edge0 --listen-address=100.64.10.1 --listen-address=100.64.10.2 \
  --dhcp-authoritative --log-dhcp --log-facility=- \
  --dhcp-leasefile="$out/isp-dhcp.leases" --dhcp-script=/bin/true \
  --dhcp-range=100.64.10.40,100.64.10.60,255.255.255.0,5m \
  --dhcp-host="${wan_mac},100.64.10.50" \
  --dhcp-option="3,100.64.10.2" --dhcp-option="6,$origin_ip" \
  > "$out/isp-dhcp-b2.log" 2>&1 &
isp_dhcp_pid=$!
sleep 0.3
wan_dhcp b2
grep -F '100.64.10.50' "$out/receipts/wan-addr-b2.txt"
grep -F 'via 100.64.10.2' "$out/receipts/wan-route-b2.txt"
grep -F '"router":"100.64.10.2"' "$out/receipts/wan-lease-b2.ndjson"
grep -F '"ip":"100.64.10.50"' "$out/receipts/wan-lease-b2.ndjson"
if grep -F 'via 100.64.10.1' "$out/receipts/wan-route-b2.txt"; then emit 'FAIL: old next hop remained'; exit 1; fi
dns_probe "$out/receipts/dns-b2.txt"
tls_probe "$out/receipts/tls-b2"
nonce_b2=$(sed -n 's/^ok nonce=//p' "$out/receipts/tls-b2.body")
test "$nonce_b1" != "$nonce_b2"
record_nat b2
cp "$out/receipts/wan-lease-b1.ndjson" "$out/history-b/lease-before.ndjson"
cp "$out/receipts/wan-lease-b2.ndjson" "$out/history-b/lease-after.ndjson"
cp "$out/receipts/wan-route-b1.txt" "$out/history-b/route-before.txt"
cp "$out/receipts/wan-route-b2.txt" "$out/history-b/route-after.txt"
emit 'PASS: history B same address with DHCP next-hop change via hook'

########################################
# Isolation, optional diagnostics, durable withdrawal through rollback
########################################
# Copied guest on separate ingress denied
sudo -n ip netns exec "$attacker" env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error \
  --cacert "$keys/origin.pem" --resolve "$origin_name:443:$origin_ip" --max-time 3 \
  "https://$origin_name/" > "$out/spoof.txt" 2>&1 && exit 1
e nft list chain inet guest_edge forward > "$out/spoof-edge-counters.txt"
grep -E 'iifname "lan1".*packets [1-9][0-9]*.*drop' "$out/spoof-edge-counters.txt"
emit 'PASS: copied IP/MAC denied on separate ingress'

# Optional ISP diagnostics: read-only and stoppable without forwarding changes
python3 "$src/diagnostics.py" start --namespace "$isp" --state "$out/diagnostics" --interface edge0
tls_probe "$out/receipts/tls-diag"
python3 "$src/diagnostics.py" stop --namespace "$isp" --state "$out/diagnostics" --interface edge0
python3 "$src/diagnostics.py" verify --namespace "$isp" --state "$out/diagnostics" --interface edge0 \
  | tee "$out/receipts/diagnostics-verify.json"
emit 'PASS: ISP diagnostics stop without forwarding changes'

# Durable withdrawal + exact rollback (guard/tombstone outside rollback)
python3 "$act/edge.py" approve "$out/target.json" withdraw "$operator/operator.key" > "$out/withdrawal.json"
python3 "$act/edge.py" record-session "$out/target.json" "$out/withdrawal.json" "$operator/operator.pub" "$operator"
python3 "$act/edge.py" guard "$out/target.json" "$operator/operator.pub" "$operator" > "$out/withdrawn-guard.nft"
e nft -f "$out/withdrawn-guard.nft"
python3 "$act/edge.py" render "$out/target.json" withdraw "$out/withdrawal.json" "$operator/operator.pub" > "$out/withdrawn.nft"
e nft -f "$out/withdrawn.nft"
allow_mgmt_input
e conntrack -D -p tcp -s "$leased" --dport 443 > "$out/conntrack-delete.txt" 2>&1 || true
deny_tls revoked-guest
unaffected_tls after-withdraw
# Exact baseline rollback leaves revocation table; withdrawn guest stays denied
cmp "$out/open.nft" "$out/exact-rollback.nft"
e nft -f "$out/exact-rollback.nft"
allow_mgmt_input
deny_tls revoked-after-exact-rollback
unaffected_tls after-rollback
e conntrack -L -p tcp -s "$leased" --dport 443 > "$out/conntrack-after-rollback.txt" || true
test ! -s "$out/conntrack-after-rollback.txt"
emit 'PASS: durable both-direction withdrawal survives recovery/rollback; unaffected continues'

# Field hold preserved
python3 "$act/field_check.py" "$act/../field-receipt.json" > "$out/field-assessment.json"
python3 - "$out/field-assessment.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["assessment"]["field_acceptance"] == "UNVERIFIED"
assert report["assessment"]["activation"] == "HELD"
PY
emit 'PASS: field acceptance UNVERIFIED and activation HELD'

# Summarize nonces and lease receipts
python3 - "$out" <<'PY'
import json, hashlib, sys
from pathlib import Path
root = Path(sys.argv[1])
nonces = []
for line in (root / "receipts/tls-nonces.ndjson").read_text().splitlines():
    if line.strip():
        nonces.append(json.loads(line)["nonce"])
assert len(set(nonces)) >= 4, nonces
summary = {
    "histories": ["A-renumber-next-hop", "B-same-address-next-hop"],
    "distinct_tls_server_nonces": len(set(nonces)),
    "dns_queries": sum(1 for line in (root / "receipts/dns-queries.ndjson").read_text().splitlines() if line.strip()),
    "carrier": "isolated-100.64-to-203.0.113",
    "host_egress": "not_used",
    "field_acceptance": "UNVERIFIED",
    "activation": "HELD",
}
(root / "receipts/summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary))
PY
sha256sum "$out/target.json" "$out/"*.nft "$out/receipts/"*.txt "$out/receipts/"*.ndjson \
  "$out/history-a/"* "$out/history-b/"* 2>/dev/null | tee "$out/config-digests.txt" >/dev/null
emit "PASS: WAN DHCP + modeled carrier NAT fixture revision ${GITHUB_SHA:-local}"
