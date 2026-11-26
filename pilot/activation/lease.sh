#!/bin/sh
set -eu
case "$reason" in
BOUND|RENEW|REBIND|REBOOT)
    test "$new_subnet_mask" = 255.255.255.0
    test "$new_ip_address" = 10.231.56.50
    test "$new_routers" = 10.231.56.1
    test "$new_domain_name_servers" = 10.231.56.1
    ip addr replace "$new_ip_address/24" dev "$interface"
    ip route replace default via "$new_routers" dev "$interface"
    printf 'nameserver %s\n' "$new_domain_name_servers" > /etc/resolv.conf
    ;;
esac
