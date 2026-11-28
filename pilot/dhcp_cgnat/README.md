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
3. **Revoke during sole-uplink outage** · An open protected TLS flow is held for identified probes/audit. Uplink drops, then withdrawal applies. Provider handoff may interrupt carrier NAT mappings — that loss is recorded as its own boundary (`nat-mapping-loss`); **no claim** that the original end-to-end TLS session survives the NAT reset. Measured proof after recovery: held-socket probes show **no client-recv and no server-recv** (independent no-disclosure); ingress guard drop counters increase from forward attempts; a **distinct bounded fixture reverse UDP probe** (temporary ISP→guest route, removed immediately, not the original TLS session) drives reply-drop counter increase. New flows stay denied through DHCP handoff/recovery and exact rollback. Unaffected guest resumes; management and guest→mgmt isolation are checked during fault and after recovery.
4. **Diagnostics** · Optional fixture-only read-only capture on the ISP namespace (`tcpdump -U`, `--immediate-mode` when available): after exercised traffic, a bounded observed-packet barrier (parseable count ≥1, not a fixed sleep) runs before child-first stop/flush; confirm wrapper + in-namespace tcpdump gone, forwarding nft unchanged, and parseable `capture.pcap` with ≥1 packet. No portal/UI claim.
5. **Receipts** · Stage JSON binds `sha`, `run_id`, `job`, config digests, observed time, and verdict.

Field acceptance remains `UNVERIFIED` and activation remains `HELD`. Local `/tmp/dev-provenance` runs are engineering provenance only. Actions acceptance requires this review-branch workflow at the exact candidate SHA with archived artifact digests and member hashes. First green CI is not acceptance until the controls above pass.

## Bounds and cleanup

- Each history is wrapped in `timeout` (default 180s). Observed violations write FAIL (exit 1); timeout/missing evidence write UNVERIFIED (exit 2/124); never map FAIL to incomplete.
- Fixture cleanup kills only recorded task PIDs and deletes the history’s namespaces. Do not use broad `pkill -f` patterns for `dnsmasq` / `origin.py` / `hold_flow`.
