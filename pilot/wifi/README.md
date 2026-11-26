# Shared Wi-Fi credential withdrawal cloud fixture

Run the branch-scoped GitHub Actions workflow. Smoke and inherited Steps 3–9, Step 11 and wired activation readiness are prerequisites. The fixture then creates Linux namespaces, an AP-stand-in bridge with VLAN filtering, a tagged trunk, a guest edge and an isolated origin. A and B remain on the same exclusive credential VLAN. C has a separate VLAN and an independent connection.

The operator and AP fixture generate separate Ed25519 keys. Admission binds the credential reference, edge, AP, generation and exclusive VLAN to a signed operator request and the AP fixture's signed response to a fresh challenge. Missing, stale, forged, mismatched and nonexclusive responses leave the edge guard closed. The observed bridge membership is recorded independently. The operator applies the kernel deny before syncing the signed withdrawal. The guard blocks both directions and survives exact baseline restoration because policy replacement leaves the guard table in place. Withdrawn connection state is cleared while C's existing connection and conntrack tuple are checked. The association is intentionally retained during denial probes. A separate signed AP fixture readback records future admission denied.

[Ubiquiti's supported PPSK and RADIUS VLAN configuration](https://help.ui.com/hc/en-us/articles/29887064407319-Using-PPSK-RADIUS-for-Multiple-VLANs-On-an-SSID-in-UniFi-Network) documents the model for mapping credentials to VLANs. The fixture readback is synthetic and does not call a UniFi controller API. A field gate still needs an approved AP/controller, authenticated current readback from that deployment, actual Wi-Fi association and reassociation, and equivalent tests with eviction withheld. This branch does not activate any network or site.

The withdrawal transaction first applies the kernel deny and waits for acknowledgment. It then syncs the signed withdrawal and parent directory. The injected crash occurs after the sync, before conntrack cleanup. Existing A/B sockets receive no payload in either direction before any recovery action; continuous fresh probes verify the same window. A separate process reconstructs the guard from disk and removes scoped connection state.

C uses a continuous fresh-connection probe during the live crash, withdrawal, and rollback window. The receipt requires each probe to succeed and bounds its latency and the gap between probes to 0.9 seconds. It reports fresh gateway recovery separately. The replacement namespace starts with IPv4 forwarding disabled, reconstructs the guard before enabling forwarding, and applies byte-identical baseline rules. After startup, A and B remain blocked and C can establish a new session. This is a Linux namespace restart fixture, with no claim about hardware reboot timing.

## Staged Pi 4 ARM64 edge

Use a dedicated ARM64 Linux gateway with nftables, conntrack, iproute2, Python 3 and OpenSSL. Verify the wired management interface and AP trunk separately before installation. The branch also reuses the pinned Ubuntu ARM64 co-hosting profile and UniFi OS Server 5.1.42 installer at `b5b4135a8aee06918649698b7a7a675584a0c98f`. Keep controller management isolated. Review the vendor prerequisites and do not enroll a remote account in the fixture.

The deployable guard takes an operator-reviewed JSON target. Supply `edge`, `ap`, `credential`, `generation`, `vlan`, `interface`, and the exclusive IPv4 `subnet`. Also supply private absolute `state` storage, `operator_public`, `operator_key_sha256`, `ap_public`, and `ap_key_sha256`. The key hashes are SHA-256 over DER SubjectPublicKeyInfo. Reserve the entire VLAN and subnet for one shared credential. Keep the guard nftables table outside the baseline rollback set.

Stage `policy.py` and `pilot/activation/edge.py` together in `/usr/local/lib/commonwealth/wifi`, the template below as `/etc/commonwealth/wifi.json` after replacing the fixture values, (see `wifi.example.json`) and `commonwealth-wifi-guard.service` in the systemd unit directory. On a separately authorized dedicated edge, keep forwarding off while loading the baseline and startup guard, and verify the guard before enabling forwarding for unaffected networks. The startup action never reopens a withdrawn VLAN.

```bash
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py boot-closed /etc/commonwealth/wifi.json
sudo nft list tables
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py challenge /etc/commonwealth/wifi.json
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py admit /etc/commonwealth/wifi.json \
  --approval /run/commonwealth/admit.json --readback /run/commonwealth/readback.json
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py withdraw /etc/commonwealth/wifi.json \
  --approval /run/commonwealth/withdraw.json
```

Each envelope contains `body` and an Ed25519 `signature` encoded as hex. Sign UTF-8 compact JSON with sorted keys using OpenSSL `pkeyutl -sign -rawin`. Operator approvals contain the seven target fields and `intent` (`admit` or `withdraw`). AP readback contains the seven fields, the emitted `nonce`, `epoch`, `kind`, and `expires_at`, `future_admission: "allowed"`, and `vlan_credentials` with exactly the target credential. The tool consumes the challenge, verifies both pins and signatures, checks the live Linux VLAN interface ID, and admits only while the kernel timeout is current. Record every command result and separately retain current AP evidence, guard counters, scoped conntrack counts, and the unaffected control probe. Restore only the reviewed baseline policy tables. Never flush the full nftables ruleset during rollback. Verify the guard again before forwarding.

### Physical AP readback blocker

Ubiquiti's supported [connected-client list](https://developer.ui.com/network/v10.6.106/getconnectedclientoverviewpage) and [client details](https://developer.ui.com/network/v10.6.102/getconnectedclientdetails) report identity, attachment and authorization. These documented responses do not provide the nonce-bound, exclusive PPSK-to-VLAN evidence required by this gate. [The supported PPSK and RADIUS configuration guide](https://help.ui.com/hc/en-us/articles/29887064407319-Using-PPSK-RADIUS-for-Multiple-VLANs-On-an-SSID-in-UniFi-Network) describes assignments, not this readback contract. No real AP or controller readback was queried in the Wi-Fi fixture. Admission stays closed until an independently validated AP adapter supplies the required readback. The physical AP and user-device exercise remains held.


### Boot, renewal, and rollback evidence

Stage files on the approved dedicated edge from a separately reviewed local console. The following prepares files and validates units. It keeps the installed services inactive until a site authority permits them.

```bash
sudo install -d -m 0755 /usr/local/lib/commonwealth/wifi /etc/commonwealth /var/lib/commonwealth
sudo install -d -m 0700 /var/lib/commonwealth/wifi
sudo install -m 0644 pilot/wifi/policy.py pilot/activation/edge.py /usr/local/lib/commonwealth/wifi/
sudo install -m 0644 pilot/wifi/commonwealth-wifi-{guard,forward}.service /etc/systemd/system/
sudo install -m 0644 pilot/wifi/90-commonwealth-edge-closed.conf /etc/sysctl.d/
sudo install -m 0600 "$REVIEWED_WIFI_CONFIG" /etc/commonwealth/wifi.json
sudo systemd-analyze verify /etc/systemd/system/commonwealth-wifi-{guard,forward}.service
sudo systemctl daemon-reload
```

Review effective sysctl ordering and remove any competing configuration that enables forwarding before the guard. Verify the pinned public keys and exclusive subnet, keep the operator state on persistent storage, and validate that the baseline never flushes the credential-specific guard table. After separate activation approval, the dedicated forwarding unit may be started under its hard guard dependency. Record `systemctl status commonwealth-wifi-guard commonwealth-wifi-forward`, `sysctl -n net.ipv4.ip_forward`, and `nft list tables`. A failed guard must leave forwarding at `0`. The cloud evidence uses an injected guard start failure under the staged unit dependencies in a network namespace.

For ongoing authorization, run `policy.py renew-challenge /etc/commonwealth/wifi.json`, obtain independently authenticated current AP readback, and run `policy.py renew /etc/commonwealth/wifi.json --approval /run/commonwealth/renew.json --readback /run/commonwealth/readback.json`. Use the exact target fields and `intent: "renew"` for the renewed operator envelope. The AP envelope must bind the newly emitted epoch and nonce. Renew well before expiry. The guard keeps the current kernel allowance during verification. Replayed or invalid renewal cannot extend it. When no timely valid renewal arrives, both directions close at the kernel deadline. Capture fresh probes spanning renewal and expiry, the challenge epochs, kernel set expiration, and unaffected traffic.

For rollback, stop `commonwealth-wifi-forward`, check forwarding is `0`, and restore only the separately reviewed baseline policy and NAT tables. Keep the current private operator state and guard table. Start the guard before forwarding, then repeat old-generation denial and unaffected control probes. A real AP must also reject reassociation with the revoked credential even if its existing station entry is retained.

### RADIUS viability

[UniFi documents external RADIUS, dynamic VLAN assignment and accounting](https://help.ui.com/hc/en-us/articles/360015268353-Configuring-a-RADIUS-Server-in-UniFi). A separately approved RADIUS authority could establish authentication and VLAN assignment for an 802.1X session. Accounting can add session observations. Verify the actual AP's applied VLAN and session membership, bounded accounting freshness, reconnect and withdrawal behavior, and independent proof that the VLAN serves only the intended credential. Accounting alone cannot establish the exclusive, current AP evidence this guard requires. Moving from PPSK to 802.1X also changes the participant client requirements. No external RADIUS service, customer AP, or owner-approved adapter was provisioned for this run.

Each credential gets a stable table derived from its edge, AP, credential, VLAN interface and subnet. Set `registry` to a shared private registry directory on the same edge. Registration refuses duplicate interfaces, duplicate VLAN IDs and overlapping subnets. Keep all guard tables and registry records outside baseline rollback. Renewal changes only its live set element in one kernel transaction. The transaction deletes the prior live element and adds the replacement atomically. The cloud race fixture pauses after userspace verification, allows the prior element to expire, then submits the transaction and expects kernel rejection with no resumed traffic.
