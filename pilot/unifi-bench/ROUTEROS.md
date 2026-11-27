# MikroTik cAP ax registration observer

RouterOS documents the matched PPSK entry comment in Wi-Fi registration table
detail output and lists the client `vlan-id` as a read-only property. The
observer requires both on the same authorized station row. It queries no
passphrase configuration and emits only selected nonsecret evidence.

Use a locally approved read-only SSH account without the sensitive policy and a
private management path. Provision the AP's host key in a dedicated known-hosts
file using an independent trusted source. Use a separate SSH identity for the
observer. The JSON configuration contains `address`, `user` and a `stations`
array. Each station specifies `role` (A/B/C), `mac`, `vlan`,
`credential_comment`, `interface` and `ssid`. A and B use one comment and
VLAN, while C uses its own. Use nonsecret identifiers for comments.

```bash
python3 pilot/unifi-bench/routeros_readback.py "$ROUTEROS_JSON" \
  --known-hosts "$REVIEWED_KNOWN_HOSTS" --identity "$READ_ONLY_SSH_IDENTITY"
```

Exit 2 always holds signed admission. A matching report verifies only the three
reported registrations. Before a physical signer can run, verify the deployed
cAP ax identity, exact RouterOS version and wifi-qcom package, and capture both
fields concurrently on the installed radio. Validate a complete effective
inventory of active Wi-Fi interfaces, PPSK assignments, default and override
VLAN paths, access-list rules and bridge trunk membership. Then correlate
independent A/B/C tagged frames with the current gateway target, nonce, epoch
and deadline. A CHR or transcript fixture cannot populate physical client radio
registrations. No guard command is called by this observer.

- [MikroTik PPSK registration example](https://manual.mikrotik.com/docs/wireless/wifi/configuring-ppsk/)
- [Wi-Fi registration-table CLI reference](https://manual.mikrotik.com/docs/cli-reference/interface/wifi/registration-table/)
