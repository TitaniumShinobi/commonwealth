# Shared Wi-Fi credential withdrawal cloud fixture

Run the branch-scoped GitHub Actions workflow. Smoke and inherited Steps 3–9, Step 11 and wired activation readiness are prerequisites. The fixture then creates Linux namespaces, an AP-stand-in bridge with VLAN filtering, a tagged trunk, a guest edge and an isolated origin. A and B remain on the same exclusive credential VLAN. C has a separate VLAN and an independent connection.

The operator and AP fixture generate separate Ed25519 keys. Admission binds the credential reference, edge, AP, generation and exclusive VLAN to a signed operator request and the AP fixture's signed response to a fresh challenge. Missing, stale, forged, mismatched and nonexclusive responses leave the edge guard closed. The observed bridge membership is recorded independently. The operator fsyncs the signed withdrawal before updating the kernel guard. The guard blocks both directions and survives exact baseline restoration because policy replacement leaves the guard table in place. Withdrawn connection state is cleared while C's existing connection and conntrack tuple are checked. The association is intentionally retained during denial probes. A separate signed AP fixture readback records future admission denied.

[Ubiquiti's supported PPSK and RADIUS VLAN configuration](https://help.ui.com/hc/en-us/articles/29887064407319-Using-PPSK-RADIUS-for-Multiple-VLANs-On-an-SSID-in-UniFi-Network) documents the model for mapping credentials to VLANs. The fixture readback is synthetic and does not call a UniFi controller API. A field gate still needs an approved AP/controller, authenticated current readback from that deployment, actual Wi-Fi association and reassociation, and equivalent tests with eviction withheld. This branch does not activate any network or site.

The withdrawal transaction first applies the kernel deny and waits for acknowledgment. It then syncs the signed withdrawal and parent directory. The injected crash occurs after the sync, before conntrack cleanup. Existing A/B sockets receive no payload in either direction before any recovery action; continuous fresh probes verify the same window. A separate process reconstructs the guard from disk and removes scoped connection state.

C uses a continuous fresh-connection probe during the live crash, withdrawal, and rollback window. The receipt requires each probe to succeed and bounds its latency and the gap between probes to 0.9 seconds. It reports fresh gateway recovery separately. The replacement namespace starts with IPv4 forwarding disabled, reconstructs the guard before enabling forwarding, and applies byte-identical baseline rules. After startup, A and B remain blocked and C can establish a new session. This is a Linux namespace restart fixture, with no claim about hardware reboot timing.

## Staged Pi 4 ARM64 edge

Use a dedicated ARM64 Linux gateway with nftables, conntrack, iproute2, Python 3 and OpenSSL. Verify the wired management interface and AP trunk separately before installation. The branch also reuses the pinned Ubuntu ARM64 co-hosting profile and UniFi OS Server 5.1.42 installer at `b5b4135a8aee06918649698b7a7a675584a0c98f`. Keep controller management isolated. Review the vendor prerequisites and do not enroll a remote account in the fixture.

The deployable guard takes an operator-reviewed JSON target. Supply `edge`, `ap`, `credential`, `generation`, `vlan`, `interface`, and the exclusive IPv4 `subnet`. Also supply private absolute `state` storage, `operator_public`, `operator_key_sha256`, `ap_public`, and `ap_key_sha256`. The key hashes are SHA-256 over DER SubjectPublicKeyInfo. Reserve the entire VLAN and subnet for one shared credential. Keep the guard nftables table outside the baseline rollback set.

Stage `policy.py` and `pilot/activation/edge.py` together in `/usr/local/lib/commonwealth/wifi`, the template below as `/etc/commonwealth/wifi.json` after replacing the fixture values, (see `wifi.example.json`) and `commonwealth-wifi-guard.service` in the systemd unit directory. On a separately authorized dedicated edge, keep forwarding off while loading the baseline and startup guard, and verify the guard before enabling forwarding for unaffected networks. The startup action never reopens a withdrawn VLAN.

```bash
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py boot-closed /etc/commonwealth/wifi.json
sudo nft list table inet cw_wifi_guard
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py challenge /etc/commonwealth/wifi.json
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py admit /etc/commonwealth/wifi.json \
  --approval /run/commonwealth/admit.json --readback /run/commonwealth/readback.json
sudo python3 /usr/local/lib/commonwealth/wifi/policy.py withdraw /etc/commonwealth/wifi.json \
  --approval /run/commonwealth/withdraw.json
```

Each envelope contains `body` and an Ed25519 `signature` encoded as hex. Sign UTF-8 compact JSON with sorted keys using OpenSSL `pkeyutl -sign -rawin`. Operator approvals contain the seven target fields and `intent` (`admit` or `withdraw`). AP readback contains the seven fields, the emitted `nonce` and `expires_at`, `future_admission: "allowed"`, and `vlan_credentials` with exactly the target credential. The tool consumes the challenge, verifies both pins and signatures, and checks the live Linux VLAN interface ID. Record every command result and separately retain current AP evidence, guard counters, scoped conntrack counts, and the unaffected control probe. Restore only the reviewed baseline policy tables. Never flush the full nftables ruleset during rollback. Verify the guard again before forwarding.

### Physical AP readback blocker

Ubiquiti's supported [connected-client list](https://developer.ui.com/network/v10.6.106/getconnectedclientoverviewpage) and [client details](https://developer.ui.com/network/v10.6.102/getconnectedclientdetails) report identity, attachment and authorization. These documented responses do not provide the nonce-bound, exclusive PPSK-to-VLAN evidence required by this gate. [The supported PPSK and RADIUS configuration guide](https://help.ui.com/hc/en-us/articles/29887064407319-Using-PPSK-RADIUS-for-Multiple-VLANs-On-an-SSID-in-UniFi-Network) describes assignments, not this readback contract. No real AP or controller readback was queried in the Wi-Fi fixture. Admission stays closed until an independently validated AP adapter supplies the required readback. The physical AP and user-device exercise remains held.
