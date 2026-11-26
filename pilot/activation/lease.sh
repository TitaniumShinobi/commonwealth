#!/bin/sh
set -eu
case "$1" in
bound|renew)
    test "$subnet" = 255.255.255.0
    test "$ip" = 10.231.56.50
    test "$router" = 10.231.56.1
    test "$dns" = 10.231.56.1
    ip addr replace "$ip/24" dev "$interface"
    ip route replace default via "$router" dev "$interface"
    printf 'nameserver %s\n' "$dns" > /etc/resolv.conf
    ;;
esac
