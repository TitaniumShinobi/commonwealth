#!/bin/sh
# Busybox udhcpc hook: installs/replaces WAN address and default route only.
set -eu
log=${CW_WAN_LEASE_LOG:?}
case "$1" in
bound|renew)
	test -n "${ip:-}"
	test -n "${mask:-}"
	test -n "${router:-}"
	test -n "${interface:-}"
	ip addr replace "$ip/$mask" dev "$interface"
	ip route replace default via "$router" dev "$interface"
	# shellcheck disable=SC2154
	printf '{"event":"%s","ip":"%s","mask":%s,"router":"%s","dns":"%s","interface":"%s"}\n' \
		"$1" "$ip" "$mask" "$router" "${dns:-}" "$interface" >> "$log"
	;;
deconfig)
	test -n "${interface:-}"
	ip route del default dev "$interface" 2>/dev/null || true
	ip addr flush dev "$interface"
	printf '{"event":"deconfig","interface":"%s"}\n' "$interface" >> "$log"
	;;
esac
