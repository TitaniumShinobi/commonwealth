# Pi 4 and UniFi observation bench

This is an observation bundle. It never changes UniFi configuration, signs AP readback for the forwarding guard, or turns on forwarding. The pinned ARM64 cloud profile qualifies UniFi OS Server 5.1.42 and the Linux edge at an enforced 8 GiB budget. It cannot identify real radio behavior, Pi storage endurance, or physical power.

## Design under review

One personal PSK per SSID, with one explicitly selected AP and a static, exclusive VLAN, is a **separate candidate design**. It leaves the existing shared-SSID PPSK model unchanged. The example has A and B share one SSID credential and VLAN, and C use another. The collector reads complete network, Wi-Fi broadcast, adopted device, and client lists, plus details for the nominated clients. It conservatively rejects enabled dynamic or unresolved broadcasts and any other enabled broadcast or network on a reserved VLAN. Values for API types must be taken from the installed controller's local integration documentation and confirmed by the operator.

The supported API exposes controller configuration and some client association facts. This does not establish exclusive PSK cardinality, the applied AP configuration on the radio, or nonce-bound current membership. The bench correlates the controller's identities and expected VLAN with fresh tagged frames on a real trunk, and reports that evidence separately. No output from this bundle is a signed admission envelope. The established edge guard stays closed unless a reviewed AP adapter supplies its full, independently authenticated readback contract.

RADIUS-assigned VLANs with 802.1X are another design option. This needs a separately approved RADIUS service and compatible clients. Accounting and authentication records may help bind sessions to intended VLANs. They still need independent AP-applied membership and tagged dataplane observations, freshness, and withdrawal controls. This bundle does not deploy RADIUS or silently substitute it for PPSK.

## Run the bench after separate approval

1. Prepare a dedicated Pi 4 8 GB with supported ARM64 Ubuntu 24.04 or Debian 13, reviewed storage and power, and a protected management path. Keep forwarding and WAN ingress closed. Inventory the actual AP/controller, trunk, switch and participant clients. Confirm association is intentionally retained for the withdrawal exercise.
2. On the isolated local controller, use **Network > Integrations** to review the installed version's local routes and provision a locally approved key. Put the key alone in a 0600 file. Obtain the management certificate and its SHA-256 DER fingerprint from the site operator through a trusted channel. Keep the API reachable only from the management bench.
3. Copy the two example JSON files and fill in the actual approved design, controller address and TLS name, reviewed type values, IDs, trunk, station MAC/IP/VLAN and bench authorization reference. The authorization reference records the decision. It cannot grant permission. The readback collector pins the private address, certificate chain, TLS name and leaf digest. It uses only GET and follows no redirects.
4. Stage Python 3, iproute2, tcpdump and the repository files. Run the preflight first. `lo` in the example is a deliberate safe cloud placeholder, never the wired trunk.

```bash
python3 pilot/unifi-bench/bench.py "$BENCH_JSON" --out "$WORK/preflight.json"
bash pilot/unifi-bench/run.sh "$CONTROLLER_JSON" "$PRIVATE_API_KEY_FILE" "$BENCH_JSON" "$WORK/new-bench-receipts"
```

The preflight and bench return code 2 while physical authority remains unverified. Capture requires an account that can run tcpdump on the reviewed trunk. If privileges are needed, use the local owner-approved root console and private output paths. At each prompt send approved IPv4 traffic from only that station. The collector waits up to 15 seconds per station and records only a bounded packet summary. A source must match the controller's client ID, MAC, IP and expected VLAN. An offload that strips tags or a missing frame is an observation blocker. Use a verified trunk mirror or reviewed capture path and rerun. Never weaken the criteria to accommodate a missing tag.

Review receipts privately. If local API returns 401/403, verify the local key and route with the operator. A 404, redirect or non-JSON response requires the installed controller's documented integration URL. Certificate mismatch is a stop condition. A dynamic or conflicting VLAN route requires a new design review. Missing AP readback, actual Wi-Fi test devices, approved AP ownership, and physical test authority keep activation held.

After separate approval and an accepted adapter, use the existing [guard runbook](../wifi/README.md) for the real withdrawal. Preserve before/after controller and trunk evidence, maintain C as a positive control, withdraw A/B with eviction withheld, verify both directions and stale reassociation denial, and repeat rollback/restart. This bench intentionally does not execute those field changes.

- [Official local Integration API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
- [Wi-Fi broadcasts](https://developer.ui.com/network/v10.6.106/getwifibroadcastpage) · [Networks](https://developer.ui.com/network/v10.6.106/getnetworksoverviewpage) · [Connected clients](https://developer.ui.com/network/v10.6.106/getconnectedclientoverviewpage)
- [Ubiquiti PPSK and RADIUS VLAN assignment](https://help.ui.com/hc/en-us/articles/29887064407319-Using-PPSK-RADIUS-for-Multiple-VLANs-On-an-SSID-in-UniFi-Network)
