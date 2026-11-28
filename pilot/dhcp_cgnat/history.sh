#!/usr/bin/env bash
# One independent WAN DHCP / carrier-NAT history in a clean namespace+authority state.
# Usage: history.sh <out-dir> <A|B>
set -euo pipefail
out=$1
mode=$2
act=$(realpath "$(dirname "$0")/../activation")
src=$(realpath "$(dirname "$0")")
# Namespace/node names must match edge.py [a-z][a-z0-9-]{0,14}; keep mode label separate.
tag=$(printf '%s' "$mode" | tr '[:upper:]' '[:lower:]')
guest="cwg${tag}$$"
edge="cwe${tag}$$"
isp="cwi${tag}$$"
origin_ns="cwo${tag}$$"
attacker="cwa${tag}$$"
unaffected="cwc${tag}$$"
mgmt="cwm${tag}$$"
operator=$(mktemp -d)
rmdir "$operator"
keys=$(mktemp -d)
portal=10.231.56.1
leased=10.231.56.50
mac=02:23:15:60:00:50
origin_ip=203.0.113.10
guest_dns_pid=
isp_dhcp_pid=
origin_pid=
mgmt_pid=
flow_pid=
mkdir -p "$out/receipts" "$out/stages" "$keys"
: > "$out/trace.txt"

receipt() {
  local stage=$1 verdict=$2
  shift 2
  python3 - "$out/stages/${stage}.json" "$stage" "$verdict" "$mode" "$@" <<'PY'
import hashlib, json, os, sys, time
from pathlib import Path
path, stage, verdict, mode, *pairs = sys.argv[1:]
extra = {}
for item in pairs:
    key, value = item.split("=", 1)
    extra[key] = value
body = {
    "stage": stage,
    "history": mode,
    "verdict": verdict,
    "observed_at": time.time(),
    "observed_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "sha": os.environ.get("GITHUB_SHA", "local"),
    "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    "job": os.environ.get("GITHUB_JOB", "local"),
    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    **extra,
}
path = Path(path)
path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
print(json.dumps({"receipt": stage, "verdict": verdict}))
PY
}

emit() { printf '%s\n' "$*" | tee -a "$out/trace.txt"; }

cleanup() {
  # Scoped cleanup only: recorded PIDs and this history's namespaces. Never pkill -f by name.
  local pid
  for pid in "${flow_pid:-}" "${origin_pid:-}" "${guest_dns_pid:-}" "${isp_dhcp_pid:-}" "${mgmt_pid:-}"; do
    if [[ -n "$pid" ]]; then sudo -n kill "$pid" 2>/dev/null || true; fi
  done
  local ns
  for ns in "$guest" "$edge" "$isp" "$origin_ns" "$attacker" "$unaffected" "$mgmt"; do
    while read -r pid; do
      if [[ -n "$pid" ]]; then sudo -n kill "$pid" 2>/dev/null || true; fi
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  for ns in "$guest" "$edge" "$isp" "$origin_ns" "$attacker" "$unaffected" "$mgmt"; do
    sudo -n ip netns del "$ns" 2>/dev/null || true
  done
  if [[ -n "${guest:-}" ]]; then sudo -n rm -rf "/etc/netns/$guest"; fi
  if [[ -n "${edge:-}" ]]; then sudo -n rm -rf "/etc/netns/$edge"; fi
  if [[ -n "${unaffected:-}" ]]; then sudo -n rm -rf "/etc/netns/$unaffected"; fi
  rm -rf -- "${operator:-}" "${keys:-}"
  exec 9>&- 2>/dev/null || true
}
trap cleanup EXIT

g() { sudo -n ip netns exec "$guest" "$@"; }
e() { sudo -n ip netns exec "$edge" "$@"; }
i() { sudo -n ip netns exec "$isp" "$@"; }
o() { sudo -n ip netns exec "$origin_ns" "$@"; }
m() { sudo -n ip netns exec "$mgmt" "$@"; }

unique_name() {
  # DNS labels are matched lowercase at the origin; keep names lowercase end-to-end.
  printf '%s-%s-%s.fixture.test' "$tag" "$1" "$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
}

for ns in "$guest" "$edge" "$isp" "$origin_ns" "$attacker" "$unaffected" "$mgmt"; do
  sudo -n ip netns add "$ns"
  sudo -n ip -n "$ns" link set lo up
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done

sudo -n ip link add "g$$" netns "$guest" type veth peer name "l$$" netns "$edge"
sudo -n ip -n "$guest" link set "g$$" name lan0
sudo -n ip -n "$edge" link set "l$$" name lan0
g ip link set lan0 address "$mac"
g ip link set lan0 up
e ip addr add "$portal/24" dev lan0
e ip link set lan0 up

sudo -n ip link add "w$$" netns "$edge" type veth peer name "e$$" netns "$isp"
sudo -n ip -n "$edge" link set "w$$" name wan0
sudo -n ip -n "$isp" link set "e$$" name edge0
e ip link set wan0 up
i ip link set edge0 up
wan_mac=$(e cat /sys/class/net/wan0/address)
printf '%s\n' "$wan_mac" > "$out/receipts/wan-mac.txt"

sudo -n ip link add "p$$" netns "$isp" type veth peer name "o$$" netns "$origin_ns"
sudo -n ip -n "$isp" link set "p$$" name pub0
sudo -n ip -n "$origin_ns" link set "o$$" name pub0
i ip addr add 203.0.113.1/24 dev pub0
i ip link set pub0 up
o ip addr add "$origin_ip/24" dev pub0
o ip link set pub0 up
o ip route add default via 203.0.113.1

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
  if e curl -fsS --noproxy '*' --max-time 1 http://10.231.62.2:8088/ >/dev/null 2>&1; then break; fi
  sleep 0.1
done

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

# Wildcard SAN so unique per-stage names verify without --resolve.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$keys/origin.key" -out "$keys/origin.pem" \
  -subj '/CN=origin.fixture.test' \
  -addext 'subjectAltName=DNS:origin.fixture.test,DNS:*.fixture.test' 2>/dev/null
o python3 -u "$src/origin.py" --cert "$keys/origin.pem" --key "$keys/origin.key" \
  --query-log "$out/receipts/dns-queries.ndjson" --nonce-log "$out/receipts/tls-nonces.ndjson" \
  > "$out/origin.log" 2>&1 &
origin_pid=$!
for _ in {1..40}; do
  if grep -qx ready "$out/origin.log"; then break; fi
  sleep 0.1
done
grep -qx ready "$out/origin.log"

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
  e nft add rule inet guest_edge input iifname '"mgmt0"' ip saddr 10.231.62.2 tcp sport 8088 ct state established,related counter accept
}
allow_unaffected_dns() {
  # Narrow fixture input: unaffected iface/addr may query the edge resolver only.
  e nft add rule inet guest_edge input iifname '"lan2"' ether saddr 02:23:15:61:00:02 ip saddr 10.231.61.2 udp dport 53 counter accept
  e nft add rule inet guest_edge input iifname '"lan2"' ether saddr 02:23:15:61:00:02 ip saddr 10.231.61.2 tcp dport 53 counter accept
}
allow_protected_echo() {
  # Narrow fixture forward for the held protected echo (TCP 8443) used during outage revoke.
  e nft add rule inet guest_edge forward iifname '"lan0"' oifname '"wan0"' ether saddr "$mac" ip saddr "$leased" tcp dport 8443 ct state new,established counter accept
  e nft add rule inet guest_edge forward iifname '"wan0"' oifname '"lan0"' ip daddr "$leased" tcp sport 8443 ct state established counter accept
}
apply_fixture_input() {
  # Closed/open common fixture input only — never open protected echo here.
  allow_mgmt_input
  allow_unaffected_dns
}

python3 "$act/edge.py" render "$out/target.json" closed > "$out/closed.nft"
e nft --check -f "$out/closed.nft"
e nft -f "$out/closed.nft"
apply_fixture_input
e sysctl -qw net.ipv4.ip_forward=1

# Guest + unaffected uncached recursive forwarder (cache-size 0).
sudo -n install -d -m 755 "/etc/netns/$unaffected"
printf 'nameserver 10.231.61.1\n' | sudo -n tee "/etc/netns/$unaffected/resolv.conf" >/dev/null
sudo -n ip netns exec "$edge" dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --bind-interfaces \
  --interface=lan0 --interface=lan2 --listen-address="$portal" --listen-address=10.231.61.1 \
  --log-dhcp --log-queries --log-facility=- --cache-size=0 \
  --dhcp-range=10.231.56.40,10.231.56.60,255.255.255.0,10m \
  --dhcp-host="$mac,$leased" --dhcp-option="3,$portal" --dhcp-option="6,$portal" \
  --server=203.0.113.10 > "$out/guest-dnsmasq.log" 2>&1 &
guest_dns_pid=$!
sleep 0.2

stop_isp_dhcp() {
  if [[ -n "${isp_dhcp_pid:-}" ]]; then
    sudo -n kill "$isp_dhcp_pid" 2>/dev/null || true
    wait "$isp_dhcp_pid" 2>/dev/null || true
    isp_dhcp_pid=
  fi
}

start_isp_dhcp() {
  local router=$1 host=$2 range_start=$3 range_end=$4
  stop_isp_dhcp
  i ip addr flush dev edge0
  i ip addr add "$router/24" dev edge0
  if [[ -n "${5:-}" ]]; then i ip addr add "$5/24" dev edge0; fi
  sudo -n install -m 666 /dev/null "$out/isp-dhcp.leases"
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
withhold_off() { i nft flush chain inet cgnat withhold; }

read_carrier() {
  local tag=$1
  i nft list chain inet cgnat withhold > "$out/receipts/withhold-$tag.txt"
  i nft list chain ip cgnat_nat postrouting > "$out/receipts/nat-$tag.txt"
  i nft list chain inet cgnat forward > "$out/receipts/fwd-$tag.txt"
}

guest_lease() {
  g timeout 25s udhcpc -n -q -f -s "$act/lease.sh" -i lan0 > "$out/client-dhcp.log" 2>&1
  g ip -4 route > "$out/guest-routes.txt"
  test "$(g ip -o link show | wc -l)" -eq 2
  test "$(g ip -4 route show default | wc -l)" -eq 1
  grep -F "via $portal dev lan0" "$out/guest-routes.txt"
}

# Fresh DNS via unique name; no --resolve. Correlate origin query log + TLS nonce/host.
dns_ok() {
  local stage=$1 name=$2
  local before after
  before=$(wc -l < "$out/receipts/dns-queries.ndjson")
  if ! g env -i PATH=/usr/bin:/bin getent ahostsv4 "$name" > "$out/receipts/dns-$stage.txt" 2>"$out/receipts/dns-$stage.err"; then
    return 1
  fi
  grep -F "$origin_ip" "$out/receipts/dns-$stage.txt"
  after=$(wc -l < "$out/receipts/dns-queries.ndjson")
  test "$after" -gt "$before"
  python3 - "$out/receipts/dns-queries.ndjson" "$name" "$before" <<'PY'
import json, sys
from pathlib import Path
path, name, before = Path(sys.argv[1]), sys.argv[2].lower(), int(sys.argv[3])
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
fresh = rows[before:]
if not any(str(row.get("qname", "")).lower() == name and row.get("answered") for row in fresh):
    raise SystemExit(f"origin missing fresh query for {name}: {fresh}")
print(json.dumps({"correlated_qname": name, "fresh_queries": len(fresh)}))
PY
}

dns_fail() {
  local stage=$1 name=$2
  if g env -i PATH=/usr/bin:/bin getent ahostsv4 "$name" > "$out/receipts/dns-$stage.txt" 2>"$out/receipts/dns-$stage.err"; then
    return 1
  fi
  return 0
}

tls_ok() {
  local stage=$1 name=$2
  # Intentionally no --resolve: destination must come from the resolver path.
  if ! g env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error \
    --cacert "$keys/origin.pem" --connect-timeout 3 --max-time 8 \
    --write-out '%{http_code} %{remote_ip} %{ssl_verify_result}\n' \
    --output "$out/receipts/tls-$stage.body" "https://$name/" \
    > "$out/receipts/tls-$stage.meta" 2>"$out/receipts/tls-$stage.err"; then
    return 1
  fi
  grep -E "^200 ${origin_ip//./\\.} 0$" "$out/receipts/tls-$stage.meta"
  grep -E "^ok nonce=[0-9a-f]{32} host=${name}(:443)?$" "$out/receipts/tls-$stage.body"
  python3 - "$out/receipts/tls-nonces.ndjson" "$name" <<'PY'
import json, sys
from pathlib import Path
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
name = sys.argv[2]
if not any(row.get("host", "").split(":")[0] == name for row in rows[-5:]):
    raise SystemExit(f"origin nonce log missing host {name}")
print(json.dumps({"tls_host": name, "nonce": rows[-1]["nonce"]}))
PY
}

tls_fail() {
  local stage=$1 name=$2
  if g env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error \
    --cacert "$keys/origin.pem" --connect-timeout 2 --max-time 4 \
    --output "$out/receipts/tls-$stage.body" "https://$name/" \
    > "$out/receipts/tls-$stage.meta" 2>"$out/receipts/tls-$stage.err"; then
    return 1
  fi
  return 0
}

admit_open() {
  python3 "$act/edge.py" approve "$out/target.json" admit "$operator/operator.key" > "$out/admission.json"
  cp "$operator/operator.pub" "$out/operator.pub"
  python3 "$act/edge.py" record-session "$out/target.json" "$out/admission.json" "$operator/operator.pub" "$operator"
  python3 "$act/edge.py" guard "$out/target.json" "$operator/operator.pub" "$operator" > "$out/admitted-guard.nft"
  e nft -f "$out/admitted-guard.nft"
  python3 "$act/edge.py" render "$out/target.json" open "$out/admission.json" "$operator/operator.pub" "$operator" > "$out/open.nft"
  cp "$out/open.nft" "$out/exact-rollback.nft"
  e nft -f "$out/open.nft"
  apply_fixture_input
  allow_protected_echo
}

unaffected_tls() {
  local stage=$1 name=$2
  if ! sudo -n ip netns exec "$unaffected" env -i PATH=/usr/bin:/bin getent ahostsv4 "$name" \
    > "$out/receipts/unaffected-dns-$stage.txt"; then
    return 1
  fi
  grep -F "$origin_ip" "$out/receipts/unaffected-dns-$stage.txt"
  sudo -n ip netns exec "$unaffected" env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' \
    --silent --show-error --cacert "$keys/origin.pem" --connect-timeout 3 --max-time 8 \
    --write-out '%{http_code} %{remote_ip} %{ssl_verify_result}\n' --output /dev/null \
    "https://$name/" > "$out/receipts/unaffected-tls-$stage.txt"
  grep -E "^200 ${origin_ip//./\\.} 0$" "$out/receipts/unaffected-tls-$stage.txt"
}

mgmt_ok() {
  local tag=$1
  e curl -fsS --noproxy '*' --connect-timeout 2 --max-time 3 http://10.231.62.2:8088/ \
    > "$out/receipts/mgmt-$tag.txt"
  grep -x 'local-management-ok' "$out/receipts/mgmt-$tag.txt"
}

guest_mgmt_deny() {
  local tag=$1
  if g curl -fsS --noproxy '*' --max-time 2 http://10.231.62.2:8088/ \
    > "$out/receipts/guest-mgmt-$tag.txt" 2>&1; then
    emit "FAIL: guest reached management ($tag)"
    exit 1
  fi
}

########################################
# Guest lease, then ADMIT before WAN negatives
########################################
guest_lease
emit "PASS[$mode]: guest lease sole default route"
admit_open
emit "PASS[$mode]: guest admitted before WAN lease"
mgmt_ok after-admit
guest_mgmt_deny after-admit

# before-WAN: admitted guest, no WAN lease → DNS and TLS fail (path control, not closed policy)
name_before=$(unique_name beforewan)
dns_fail before-wan "$name_before"
tls_fail before-wan "$name_before"
read_carrier before-wan
receipt before-wan PASS "dns_failed=true" "tls_failed=true" "wan_lease=absent" "guest_policy=open"
emit "PASS[$mode]: before-WAN DNS and TLS fail while admitted"

# Acquire WAN via DHCP hook only
start_isp_dhcp 100.64.10.1 100.64.10.50 100.64.10.40 100.64.10.60
wan_dhcp initial
grep -F '100.64.10.50' "$out/receipts/wan-addr-initial.txt"
grep -F 'via 100.64.10.1' "$out/receipts/wan-route-initial.txt"
receipt wan-lease-initial PASS "wan_ip=100.64.10.50" "wan_router=100.64.10.1"

# Establish permitted path with unique names (no --resolve)
name_ok1=$(unique_name path1)
dns_ok path1 "$name_ok1"
tls_ok path1 "$name_ok1"
nonce1=$(sed -n 's/^ok nonce=\([0-9a-f]\{32\}\).*/\1/p' "$out/receipts/tls-path1.body")
read_carrier path1
grep -E 'packets [1-9]' "$out/receipts/nat-path1.txt"
unaffected_tls path1 "$(unique_name una1)"
guest_mgmt_deny path1
receipt path-established PASS "dns_name=$name_ok1" "tls_nonce=$nonce1"

# lease-before-recovery: withhold at carrier after lease+admit+working path
withhold_on
name_hold=$(unique_name withhold)
dns_fail lease-before-recovery "$name_hold"
tls_fail lease-before-recovery "$name_hold"
e ip -4 addr show wan0 | grep -F '100.64.10.50'
read_carrier lease-before-recovery
grep -E 'udp dport 53.*packets [1-9]|tcp dport 443.*packets [1-9]|dport 53 counter packets [1-9]|dport 443 counter packets [1-9]' \
  "$out/receipts/withhold-lease-before-recovery.txt"
receipt lease-before-recovery PASS "dns_failed=true" "tls_failed=true" "wan_lease=present" "carrier_withhold=true"
emit "PASS[$mode]: lease-before-recovery DNS and TLS fail at carrier withhold"
withhold_off

# Usable recovery: fresh unique DNS + new TLS nonce through carrier (no --resolve, no cache)
name_rec=$(unique_name recover)
dns_ok recover "$name_rec"
tls_ok recover "$name_rec"
nonce_rec=$(sed -n 's/^ok nonce=\([0-9a-f]\{32\}\).*/\1/p' "$out/receipts/tls-recover.body")
test "$nonce1" != "$nonce_rec"
receipt usable-recovery PASS "dns_name=$name_rec" "tls_nonce=$nonce_rec" "prior_nonce=$nonce1"
emit "PASS[$mode]: usable recovery with fresh DNS and TLS nonce"

########################################
# History-specific DHCP transition via hook
########################################
if [[ "$mode" == "A" ]]; then
  start_isp_dhcp 100.64.20.1 100.64.20.50 100.64.20.40 100.64.20.60
  sudo -n install -m 666 /dev/null "$out/receipts/wan-lease-release.ndjson"
  e env CW_WAN_LEASE_LOG="$out/receipts/wan-lease-release.ndjson" udhcpc -R -n -q -f -s "$src/wan_lease.sh" -i wan0 \
    > "$out/receipts/wan-udhcpc-release.log" 2>&1 || true
  wan_dhcp renumber
  grep -F '100.64.20.50' "$out/receipts/wan-addr-renumber.txt"
  grep -F 'via 100.64.20.1' "$out/receipts/wan-route-renumber.txt"
  if grep -F '100.64.10.50' "$out/receipts/wan-addr-renumber.txt"; then exit 1; fi
  name_a=$(unique_name renumber)
  dns_ok renumber "$name_a"
  tls_ok renumber "$name_a"
  receipt history-transition PASS "kind=renumber" "wan_ip=100.64.20.50" "wan_router=100.64.20.1" "dns_name=$name_a"
  emit "PASS[A]: renumber + next-hop via DHCP hook"
else
  stop_isp_dhcp
  i ip addr flush dev edge0
  i ip addr add 100.64.10.1/24 dev edge0
  i ip addr add 100.64.10.2/24 dev edge0
  sudo -n install -m 666 /dev/null "$out/isp-dhcp.leases"
  sudo -n ip netns exec "$isp" dnsmasq --keep-in-foreground --conf-file=/dev/null --bind-interfaces \
    --interface=edge0 --listen-address=100.64.10.1 --listen-address=100.64.10.2 \
    --dhcp-authoritative --log-dhcp --log-facility=- \
    --dhcp-leasefile="$out/isp-dhcp.leases" --dhcp-script=/bin/true \
    --dhcp-range=100.64.10.40,100.64.10.60,255.255.255.0,5m \
    --dhcp-host="${wan_mac},100.64.10.50" \
    --dhcp-option="3,100.64.10.2" --dhcp-option="6,$origin_ip" \
    > "$out/isp-dhcp-nexthop.log" 2>&1 &
  isp_dhcp_pid=$!
  sleep 0.3
  wan_dhcp nexthop
  grep -F '100.64.10.50' "$out/receipts/wan-addr-nexthop.txt"
  grep -F 'via 100.64.10.2' "$out/receipts/wan-route-nexthop.txt"
  if grep -F 'via 100.64.10.1' "$out/receipts/wan-route-nexthop.txt"; then exit 1; fi
  name_b=$(unique_name nexthop)
  dns_ok nexthop "$name_b"
  tls_ok nexthop "$name_b"
  receipt history-transition PASS "kind=same-address-next-hop" "wan_ip=100.64.10.50" "wan_router=100.64.10.2" "dns_name=$name_b"
  emit "PASS[B]: same address with changed DHCP next hop via hook"
fi

########################################
# Open protected flow, sole-uplink outage, revoke during outage
########################################
name_flow=$(unique_name flow)
dns_ok flow "$name_flow"
rm -f "$out/receipts/flow.cmd"
mkfifo "$out/receipts/flow.cmd"
# Hold open TLS session (original association identity). Writer fd opened after start.
g env -i PATH=/usr/bin:/bin python3 -u "$src/hold_flow.py" --host "$name_flow" --ca "$keys/origin.pem" \
  --status "$out/receipts/flow-status.json" > "$out/receipts/flow.log" 2>&1 < "$out/receipts/flow.cmd" &
flow_pid=$!
exec 9>"$out/receipts/flow.cmd"
for _ in {1..50}; do
  if grep -qx ready "$out/receipts/flow.log" 2>/dev/null; then break; fi
  sleep 0.1
done
grep -qx ready "$out/receipts/flow.log"
printf 'probe\n' >&9
for _ in {1..30}; do
  if grep -F '"sent": true' "$out/receipts/flow.log" 2>/dev/null; then break; fi
  sleep 0.1
done
grep -F '"sent": true' "$out/receipts/flow.log"
grep -F '"recv": true' "$out/receipts/flow.log"
receipt protected-flow-open PASS "host=$name_flow"

# Sole uplink down while flow exists
i ip link set pub0 down
mgmt_ok during-outage
guest_mgmt_deny during-outage
name_out=$(unique_name outage)
dns_fail outage "$name_out"
tls_fail outage "$name_out"
# Isolation still denies spoofed ingress
sudo -n ip netns exec "$attacker" env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent \
  --cacert "$keys/origin.pem" --max-time 2 "https://$name_flow/" >"$out/receipts/spoof-outage.txt" 2>&1 && exit 1
receipt sole-uplink-outage PASS "mgmt=ok" "guest_mgmt=denied" "dns_failed=true" "tls_failed=true"

# Revoke while uplink down; keep session identity; clear conntrack
python3 "$act/edge.py" approve "$out/target.json" withdraw "$operator/operator.key" > "$out/withdrawal.json"
python3 "$act/edge.py" record-session "$out/target.json" "$out/withdrawal.json" "$operator/operator.pub" "$operator"
python3 "$act/edge.py" guard "$out/target.json" "$operator/operator.pub" "$operator" > "$out/withdrawn-guard.nft"
e nft -f "$out/withdrawn-guard.nft"
python3 "$act/edge.py" render "$out/target.json" withdraw "$out/withdrawal.json" "$operator/operator.pub" > "$out/withdrawn.nft"
e nft -f "$out/withdrawn.nft"
apply_fixture_input
# Echo forward may be absent after withdraw render; revocation guard covers both directions.
e conntrack -D -s "$leased" >/dev/null 2>&1 || true
e conntrack -D -d "$leased" >/dev/null 2>&1 || true
printf 'probe\n' >&9
for _ in {1..30}; do
  if python3 - "$out/receipts/flow.log" <<'PY'
import json, sys
from pathlib import Path
probes = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith("{")]
sys.exit(0 if probes and probes[-1].get("recv") is False else 1)
PY
  then break; fi
  sleep 0.1
done
python3 - "$out/receipts/flow.log" <<'PY'
import json, sys
from pathlib import Path
probes = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith("{")]
if not probes or probes[-1].get("recv") is not False:
    raise SystemExit(f"expected reverse direction stopped during outage revoke: {probes[-1] if probes else None}")
print(json.dumps({"flow_reverse": "stopped", "last": probes[-1]}))
PY
receipt revoke-during-outage PASS "flow_reverse_stopped=true"

# DHCP handoff / uplink recovery; revoked denial retained for both directions + new flows
i ip link set pub0 up
wan_dhcp post-outage || wan_dhcp post-outage-retry
# Held flow after recovery: neither direction remains usable.
for _ in 1 2 3 4 5; do printf 'probe\n' >&9; sleep 0.15; done
python3 - "$out/receipts/flow.log" <<'PY'
import json, sys
from pathlib import Path
probes = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith("{")]
if len(probes) < 2:
    raise SystemExit("missing post-recovery flow probes")
last = probes[-1]
if last.get("sent") and last.get("recv"):
    raise SystemExit(f"held flow still bidirectional after recovery revoke: {last}")
print(json.dumps({"held_flow_after_recovery": last}))
PY
name_new=$(unique_name postrevoke)
dns_ok post-revoke-dns "$name_new" || dns_fail post-revoke-dns "$name_new"
tls_fail post-revoke-new "$name_new"
# New protected echo also denied (bounded; do not hang on dropped SYN).
if timeout --foreground 5s g env -i PATH=/usr/bin:/bin python3 -c "
import socket, ssl, sys
ctx = ssl.create_default_context(cafile='$keys/origin.pem')
sock = socket.socket(); sock.settimeout(1.5)
try:
    sock.connect(('$origin_ip', 8443))
    tls = ctx.wrap_socket(sock, server_hostname='$name_new')
    tls.settimeout(1.5)
    tls.sendall(b'n')
    sys.exit(0 if tls.recv(1) else 1)
except OSError:
    sys.exit(1)
"; then
  emit 'FAIL: new protected echo succeeded after revoke'
  exit 1
fi
e nft list chain inet guest_revocation ingress > "$out/receipts/revocation-ingress.txt"
e nft list chain inet guest_revocation replies > "$out/receipts/revocation-replies.txt"
grep -F "$leased" "$out/receipts/revocation-ingress.txt"
grep -F "$leased" "$out/receipts/revocation-replies.txt"
grep -E 'drop' "$out/receipts/revocation-ingress.txt"
grep -E 'drop' "$out/receipts/revocation-replies.txt"
mgmt_ok after-recovery
guest_mgmt_deny after-recovery
unaffected_tls after-recovery "$(unique_name una-rec)"
receipt post-recovery-revoked PASS "new_tls_denied=true" "new_echo_denied=true" "both_direction_drops=present" "unaffected=ok" "mgmt=ok"

# Exact rollback cannot bypass durable withdrawal
cmp "$out/open.nft" "$out/exact-rollback.nft"
e nft -f "$out/exact-rollback.nft"
apply_fixture_input
allow_protected_echo
name_rb=$(unique_name rollback)
tls_fail after-rollback "$name_rb"
unaffected_tls after-rollback "$(unique_name una-rb)"
e conntrack -L -p tcp -s "$leased" --dport 443 > "$out/receipts/ct-after-rollback.txt" 2>/dev/null || true
test ! -s "$out/receipts/ct-after-rollback.txt"
receipt exact-rollback-revoked PASS "tls_denied=true" "unaffected=ok"

########################################
# Optional diagnostics + field hold
########################################
python3 "$src/diagnostics.py" start --namespace "$isp" --state "$out/diagnostics" --interface edge0
name_diag=$(unique_name diag)
# Unaffected traffic during diagnostics (revoked guest stays denied)
unaffected_tls diag "$name_diag"
python3 "$src/diagnostics.py" stop --namespace "$isp" --state "$out/diagnostics" --interface edge0 \
  | tee "$out/receipts/diagnostics-stop.json"
python3 "$src/diagnostics.py" verify --namespace "$isp" --state "$out/diagnostics" --interface edge0 \
  | tee "$out/receipts/diagnostics-verify.json"
grep -F 'child_stopped_confirmed' "$out/receipts/diagnostics-stop.json"
grep -F 'child_stopped_confirmed": true' "$out/receipts/diagnostics-verify.json"
receipt diagnostics PASS "child_stopped_confirmed=true"

python3 "$act/field_check.py" "$act/../field-receipt.json" > "$out/field-assessment.json"
python3 - "$out/field-assessment.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["assessment"]["field_acceptance"] == "UNVERIFIED"
assert report["assessment"]["activation"] == "HELD"
PY

sha256sum "$out/target.json" "$out/"*.nft "$out/receipts/"wan-*.txt "$out/stages/"*.json 2>/dev/null \
  | tee "$out/config-digests.txt" >/dev/null
config_digest=$(sha256sum "$out/config-digests.txt" | awk '{print $1}')
receipt history-complete PASS "config_digest=$config_digest" "field_acceptance=UNVERIFIED" "activation=HELD"
emit "PASS[$mode]: independent history complete sha=${GITHUB_SHA:-local}"
printf 'quit\n' >&9 || true
exec 9>&- || true
