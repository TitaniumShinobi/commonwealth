# WAN DHCP and modeled carrier NAT cloud fixture

Review-branch workflow only (`hydro/dhcp-cgnat-review`). Smoke and inherited Steps 3–9, Step 11, and the wired activation edge run first. This fixture then exercises native IPv4 WAN DHCP on the reused `pilot/activation` Linux guest edge, with a modeled carrier NAT path that never uses host egress.

## Topology

```text
guest --LAN DHCP--> edge --WAN DHCP--> ISP/CGNAT --TEST-NET-3--> fixture origin
                      |-- unaffected guest
                      |-- attacker ingress
                      `-- local management
```

The ISP namespace leases `100.64.0.0/10` addresses, applies narrowly scoped forwarding, and masquerades toward reserved `203.0.113.0/24` origin addresses. Guest policy, durable guard/tombstone, and exact baseline rollback come from `pilot/activation/edge.py`. WAN DHCP replies are admitted only as `iif outside udp sport 67 dport 68`.

## What is scored

1. **Hook-installed WAN lease** · `udhcpc` + `wan_lease.sh` install/replace address and default route. Tested transitions do not shell-configure the WAN address or next hop.
2. **History A** · Fresh subnet/address renumber with next-hop change via DHCP.
3. **History B** · Independent run: same WAN address with a changed DHCP next hop via DHCP.
4. **Lease vs usable recovery** · After lease, DNS/TLS are withheld briefly; address remains while probes fail; then recovery with fresh DNS and new TLS server nonces through carrier NAT.
5. **Sole-uplink outage** · Public ISP link down denies guest path; local management continues.
6. **Negative controls** · Before WAN lease; outage; lease-before-recovery; revoked guest through exact rollback.
7. **Isolation / continuity** · Copied ingress denied; unaffected guest keeps HTTPS.
8. **Optional ISP diagnostics** · Read-only capture, stoppable, verified to leave nft forwarding unchanged.

Field acceptance remains `UNVERIFIED` and activation remains `HELD`. This branch does not activate hardware or any site.

Local development runs under `/tmp` (or a private workspace path) are provenance for engineering only. Actions acceptance requires the review-branch workflow at the exact candidate SHA, with archived artifact digests and member hashes from that run.
