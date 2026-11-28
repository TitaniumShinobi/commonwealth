# WAN DHCP and modeled carrier NAT cloud fixture

Review-branch workflow only (`hydro/dhcp-cgnat-review`). Smoke and inherited Steps 3–9, Step 11, wired activation readiness, and the Wi-Fi withdrawal regression run first. This fixture then runs **two independent histories** (A renumber+next-hop, B same address+next-hop). Each history uses a fresh namespace set, operator authority, conntrack table, and receipt tree.

## Topology (per history)

```text
guest --LAN DHCP--> edge --WAN DHCP--> ISP/CGNAT --TEST-NET-3--> fixture origin
                      |-- unaffected guest
                      |-- attacker ingress
                      `-- local management
```

Carrier traffic stays off host egress. WAN DHCP replies are admitted only as `iif outside udp sport 67 dport 68`. Guest policy, durable guard/tombstone, and exact baseline rollback come from `pilot/activation/edge.py`.

## Acceptance controls

1. **Admit before negatives** · Guest is admitted and open before before-WAN and lease-withhold stages. Both **DNS and TLS** must fail at the intended control, with carrier NAT/withhold readback.
2. **Fresh DNS/TLS** · Edge dnsmasq uses `--cache-size=0`. Each stage uses a unique `*.fixture.test` name. Recovery/path probes never use `--resolve`. Origin query logs must show the requested qname; TLS receipts bind remote IP + server nonce + Host.
3. **Revoke during sole-uplink outage** · An open protected TLS flow is held. Uplink drops, then withdrawal applies. Both directions on the held flow stop; new flows stay denied through DHCP handoff/recovery and exact rollback. Unaffected guest resumes; management and guest→mgmt isolation are checked during fault and after recovery.
4. **Diagnostics** · Optional read-only capture must confirm the child process stopped and leave forwarding structure unchanged.
5. **Receipts** · Stage JSON binds `sha`, `run_id`, `job`, config digests, observed time, and verdict.

Field acceptance remains `UNVERIFIED` and activation remains `HELD`. Local `/tmp/dev-provenance` runs are engineering provenance only. Actions acceptance requires this review-branch workflow at the exact candidate SHA with archived artifact digests and member hashes. First green CI is not acceptance until the controls above pass.

## Bounds and cleanup

- Each history is wrapped in `timeout` (default 180s). Suite failures write `stages/history-incomplete.json` and keep partial receipts.
- Fixture cleanup kills only recorded task PIDs and deletes the history’s namespaces. Do not use broad `pkill -f` patterns for `dnsmasq` / `origin.py` / `hold_flow`.
