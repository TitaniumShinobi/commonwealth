#!/usr/bin/env bash
# Disposable Linux guest and gateway; all addresses and policy are fixture scoped.
set -euo pipefail
out=$1
src=$(realpath "$(dirname "$0")")
guest="cwg$$"
edge="cwe$$"
uplink="cwu$"
attacker="cwa$"
peer="cwp$"
operator=$(mktemp -d)
rmdir "$operator"
peer_keys=$(mktemp -d)
portal=10.231.56.1
leased=10.231.56.50
gateway=10.231.57.2
mac=02:23:15:60:00:50
url=https://example.com/
dns_pid=
old_forward=$(sysctl -n net.ipv4.ip_forward)
mkdir -p "$out"
emit() { printf '%s\n' "$*" | tee -a "$out/trace.txt"; }
cleanup() {
  if [[ -n "$dns_pid" ]]; then sudo -n kill "$dns_pid" 2>/dev/null || true; fi
  sudo -n iptables -D FORWARD -i "$uplink" -s "$gateway" -j ACCEPT 2>/dev/null || true
  sudo -n iptables -D FORWARD -o "$uplink" -d "$gateway" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  sudo -n iptables -D INPUT -i "$uplink" -j DROP 2>/dev/null || true
  sudo -n iptables -t nat -D POSTROUTING -s "$gateway" ! -o "$uplink" -j MASQUERADE 2>/dev/null || true
  local ns pid
  for ns in "$guest" "$edge" "$attacker" "$peer"; do
    while read -r pid; do
      if [[ -n "$pid" ]]; then sudo -n kill "$pid" 2>/dev/null || true; fi
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  sudo -n ip netns del "$attacker" 2>/dev/null || true
  sudo -n ip netns del "$peer" 2>/dev/null || true
  rm -rf -- "$operator" "$operator-wrong" "$peer_keys"
  sudo -n ip netns del "$guest" 2>/dev/null || true
  sudo -n ip netns del "$edge" 2>/dev/null || true
  sudo -n ip link del "$uplink" 2>/dev/null || true
  sudo -n rm -rf "/etc/netns/$guest"
  sudo -n sysctl -qw "net.ipv4.ip_forward=$old_forward"
}
trap cleanup EXIT
g() { sudo -n ip netns exec "$guest" "$@"; }
e() { sudo -n ip netns exec "$edge" "$@"; }
sudo -n ip netns add "$guest"
sudo -n ip netns add "$edge"
sudo -n ip netns add "$attacker"
sudo -n ip netns add "$peer"
for ns in "$guest" "$edge" "$attacker" "$peer"; do
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
sudo -n ip link add "$uplink" type veth peer name "w$$" netns "$edge"
sudo -n ip -n "$edge" link set "w$$" name wan0
sudo -n ip addr add 10.231.57.1/30 dev "$uplink"
e ip addr add "$gateway/30" dev wan0
e ip link set wan0 up
sudo -n ip link set "$uplink" up
e ip route add default via 10.231.57.1 dev wan0
sudo -n ip link add lan1 netns "$edge" type veth peer name lan0 netns "$attacker"
e ip addr add 10.231.59.1/24 dev lan1
e ip link set lan1 up
sudo -n ip -n "$attacker" link set lan0 address "$mac"
sudo -n ip -n "$attacker" addr add "$leased/24" dev lan0
sudo -n ip -n "$attacker" link set lan0 up
sudo -n ip -n "$attacker" route add default via 10.231.59.1 dev lan0 onlink
lan1_mac=$(e cat /sys/class/net/lan1/address)
sudo -n ip -n "$attacker" neigh replace 10.231.59.1 lladdr "$lan1_mac" nud permanent dev lan0
sudo -n ip link add peer0 netns "$edge" type veth peer name peer0 netns "$peer"
e ip addr add 10.231.60.1/24 dev peer0
e ip link set peer0 up
sudo -n ip -n "$peer" addr add 10.231.60.2/24 dev peer0
sudo -n ip -n "$peer" link set peer0 up
sudo -n ip -n "$peer" route add 10.231.56.0/24 via 10.231.60.1
sudo -n ip -n "$peer" addr add 10.231.60.3/24 dev peer0
sudo -n ip -n "$peer" addr add 10.231.60.4/24 dev peer0
sudo -n install -d -m 755 "/etc/netns/$guest"
printf '# managed by fixture DHCP\n' | sudo -n tee "/etc/netns/$guest/resolv.conf" >/dev/null
mapfile -t relays < <(awk '$1=="nameserver" && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ {print $2}' /etc/resolv.conf)
if (("${#relays[@]}" == 0)); then relays=(1.1.1.1 8.8.8.8); fi
pin=$(python3 "$src/edge.py" bootstrap "$operator")
python3 - "$out/target.json" "$edge" "$leased" "$mac" "$pin" "${relays[@]}" <<'PY'
import json, sys
from pathlib import Path
out, node, ip, mac, pin, *relays = sys.argv[1:]
Path(out).write_text(json.dumps({"node": node, "inside": "lan0", "outside": "wan0",
                               "guest_ip": ip, "guest_mac": mac, "operator": "runner", "relay_ips": relays, "operator_key_sha256": pin}))
PY
python3 "$src/edge.py" render "$out/target.json" closed > "$out/closed.nft"
e nft --check -f "$out/closed.nft"
e nft -f "$out/closed.nft"
e sysctl -qw net.ipv4.ip_forward=1
sudo -n iptables -I INPUT -i "$uplink" -j DROP
sudo -n iptables -I FORWARD -i "$uplink" -s "$gateway" -j ACCEPT
sudo -n iptables -I FORWARD -o "$uplink" -d "$gateway" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo -n iptables -t nat -I POSTROUTING -s "$gateway" ! -o "$uplink" -j MASQUERADE
sudo -n sysctl -qw net.ipv4.ip_forward=1
servers=()
for relay in "${relays[@]}"; do servers+=("--server=$relay"); done
sudo -n ip netns exec "$edge" dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --bind-interfaces \
  --interface=lan0 --listen-address="$portal" --log-dhcp --log-queries --log-facility=- \
  --dhcp-range=10.231.56.40,10.231.56.60,255.255.255.0,10m \
  --dhcp-host="$mac,$leased" --dhcp-option="3,$portal" --dhcp-option="6,$portal" \
  "${servers[@]}" > "$out/dnsmasq.log" 2>&1 &
dns_pid=$!
g timeout 25s udhcpc -n -q -f -s "$src/lease.sh" -i lan0 > "$out/client-dhcp.log" 2>&1
g ip -br address > "$out/guest-addresses.txt"
g ip -4 route > "$out/guest-routes.txt"
test "$(g ip -o link show | wc -l)" -eq 2
test "$(g ip -4 route show default | wc -l)" -eq 1
grep -F "$leased/24" "$out/guest-addresses.txt"
grep -F "via $portal dev lan0" "$out/guest-routes.txt"
grep -F "lease of $leased" "$out/client-dhcp.log"
emit 'DHCP PASS: lease AND only guest default route'
client() {
  g env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error \
    --connect-timeout 4 --max-time 12 --output /dev/null \
    --write-out '%{http_code} %{remote_ip} %{ssl_verify_result}\n' "$url"
}
deny() {
  if client >> "$out/https-denials.txt" 2>&1; then emit "FAIL: $1"; exit 1; fi
  emit "PASS: $1"
}
g cat /etc/resolv.conf > "$out/guest-resolver.txt"
grep -F "nameserver $portal" "$out/guest-resolver.txt"
g getent ahostsv4 example.com > "$out/dns-a.txt"
emit 'DNS PASS: guest queried configured edge resolver for example.com'
deny 'default-closed with working DNS'
python3 "$src/edge.py" approve "$out/target.json" admit "$operator/operator.key" > "$out/admission.json"
cp "$operator/operator.pub" "$out/operator.pub"
python3 "$src/edge.py" bootstrap "$operator-wrong" > "$out/wrong-operator-pin.txt"
python3 "$src/edge.py" approve "$out/target.json" admit "$operator-wrong/operator.key" > "$out/wrong-operator.json"
if python3 "$src/edge.py" render "$out/target.json" open "$out/wrong-operator.json" "$operator-wrong/operator.pub" >/dev/null 2>&1; then exit 1; fi
if python3 "$src/edge.py" render "$out/target.json" open "$out/wrong-operator.json" "$operator/operator.pub" >/dev/null 2>&1; then exit 1; fi
emit 'PASS: wrong operator key and forged proof denied'
python3 - "$out/target.json" "$out/wrong-target.json" <<'PY'
import json, sys
from pathlib import Path
target = json.loads(Path(sys.argv[1]).read_text())
target["operator"] = "different"
Path(sys.argv[2]).write_text(json.dumps(target))
PY
if python3 "$src/edge.py" render "$out/wrong-target.json" open "$out/admission.json" "$operator/operator.pub" >/dev/null 2>&1; then exit 1; fi
emit 'PASS: operator credential proof rejected on changed target'
python3 "$src/edge.py" render "$out/target.json" open "$out/admission.json" "$operator/operator.pub" > "$out/open.nft"
e nft --check -f "$out/open.nft"
e nft -f "$out/open.nft"
if ! client > "$out/https-admitted.txt" 2> "$out/https-admitted.err"; then
  emit 'UNVERIFIED: admitted guest could not complete ordinary public HTTPS'
  exit 2
fi
grep -E '^2[0-9]{2} [0-9.]+ 0$' "$out/https-admitted.txt"
emit 'PASS: ordinary public HTTPS, verified TLS, routed guest only'
e nft list ruleset > "$out/admitted-kernel.nft"
e conntrack -L -p tcp -s "$leased" --dport 443 > "$out/conntrack-before.txt"
grep -F "src=$leased" "$out/conntrack-before.txt"
g ip link set lan0 address 02:23:15:60:00:51
deny 'unbound guest MAC on admitted IPv4 address'
g ip link set lan0 address "$mac"
e ip link set wan0 down
deny 'upstream link down'
e ip link set wan0 up
e ip route replace default via 10.231.57.1 dev wan0
client > "$out/https-recovered.txt"
grep -E '^2[0-9]{2} [0-9.]+ 0$' "$out/https-recovered.txt"
emit 'PASS: upstream link recovery'
sudo -n ip netns exec "$attacker" env -i PATH=/usr/bin:/bin curl -4 --noproxy '*' --silent --show-error \
  --resolve example.com:443:"$(awk 'NR==1 {print $1}' "$out/dns-a.txt")" --max-time 4 "$url" > "$out/spoof.txt" 2>&1 && exit 1
e nft list chain inet guest_edge forward > "$out/spoof-edge-counters.txt"
grep -E 'iifname "lan1".*packets [1-9][0-9]*.*drop' "$out/spoof-edge-counters.txt"
emit 'PASS: copied IP and MAC denied on a separate wired ingress'
sudo -n ip -n "$attacker" addr del "$leased/24" dev lan0
sudo -n ip -n "$attacker" addr add 10.231.59.2/24 dev lan0
mkdir "$peer_keys/second-guest"
printf "isolated guest control\n" > "$peer_keys/second-guest/index.html"
sudo -n ip netns exec "$attacker" python3 -u -m http.server 8086 --bind 10.231.59.2 \
  --directory "$peer_keys/second-guest" > "$out/other-guest.log" 2>&1 &
sudo -n ip netns exec "$attacker" curl -fsS --noproxy '*' --retry 3 --retry-connrefused \
  --max-time 3 http://10.231.59.2:8086/ > "$out/other-guest-positive.txt"
grep -x 'isolated guest control' "$out/other-guest-positive.txt"
if g curl -fsS --noproxy '*' --max-time 2 http://10.231.59.2:8086/ > "$out/other-guest-denied.txt" 2>&1; then exit 1; fi
emit 'PASS: populated second wired guest segment isolated'
bash "$src/crossing.sh" "$out" "$src" "$guest" "$edge" "$peer" "$operator" "$peer_keys"
e nft -f "$out/closed.nft"
deny 'restart from persisted default-closed configuration'
e nft list ruleset > "$out/restarted-kernel.nft"
e nft -f "$out/open.nft"
client > "$out/https-rollback.txt"
grep -E '^2[0-9]{2} [0-9.]+ 0
python3 "$src/edge.py" approve "$out/target.json" withdraw "$operator/operator.key" > "$out/withdrawal.json"
python3 "$src/edge.py" render "$out/target.json" withdraw "$out/withdrawal.json" "$operator/operator.pub" > "$out/withdrawn.nft"
e nft --check -f "$out/withdrawn.nft"
e nft -f "$out/withdrawn.nft"
e conntrack -D -p tcp -s "$leased" --dport 443 > "$out/conntrack-delete.txt" 2>&1
e conntrack -L -p tcp -s "$leased" --dport 443 > "$out/conntrack-after.txt"
test ! -s "$out/conntrack-after.txt"
deny 'withdrawal and conntrack cleanup'
sha256sum "$out/target.json" "$out/"*.nft > "$out/config-digests.txt"
python3 "$src/field_check.py" "$src/../field-receipt.json" > "$out/field-assessment.json"
python3 - "$out/field-assessment.json" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    report = json.load(source)
assert report["mode"] == "offline_assessment_only"
assert report["assessment"]["field_acceptance"] == "UNVERIFIED"
assert report["assessment"]["activation"] == "HELD"
PY
emit 'PASS: offline field checker preserves absent-evidence verdict and held activation'
emit "PASS: guest-edge wired fixture revision $GITHUB_SHA"
 "$out/https-rollback.txt"
emit 'PASS: approved baseline restored before withdrawal'
python3 "$src/edge.py" approve "$out/target.json" withdraw "$operator/operator.key" > "$out/withdrawal.json"
python3 "$src/edge.py" render "$out/target.json" withdraw "$out/withdrawal.json" "$operator/operator.pub" > "$out/withdrawn.nft"
e nft --check -f "$out/withdrawn.nft"
e nft -f "$out/withdrawn.nft"
e conntrack -D -p tcp -s "$leased" --dport 443 > "$out/conntrack-delete.txt" 2>&1
e conntrack -L -p tcp -s "$leased" --dport 443 > "$out/conntrack-after.txt"
test ! -s "$out/conntrack-after.txt"
deny 'withdrawal and conntrack cleanup'
sha256sum "$out/target.json" "$out/"*.nft > "$out/config-digests.txt"
emit "PASS: guest-edge wired fixture revision $GITHUB_SHA"
