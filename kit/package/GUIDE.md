# Commonwealth Kit 0.1.0-test.1

This is the signed **test** Kit. Run in a disposable isolated Linux x64 consumer with Python 3.12+, OpenSSL 3 and loopback only. The trusted GitHub Actions orchestration phase at the dispatched SHA pins the verifier and fixture driver digests, exact source SHA and Kit version, and Ed25519 public fingerprint before any unsigned candidate build. It provisions these via workflow outputs and supplies the public bootstrap as a separate artifact. The consumer checks the downloaded files against those outputs before fetching the candidate. The unsigned builder runs without read access to signing keys or write access to bootstrap. A later trusted signer verifies the coordinate and archive digest, signs, and removes the private keys. This trust model covers the controlled fixture workflow and runner. Production signing and independently administered custody require separate evidence. Record SHA-256 of its DER SubjectPublicKeyInfo. Keep private keys in disposable role stores outside all evidence.

```bash
python3 "$BOOTSTRAP/verify_kit.py" plan --manifest "$RELEASE/manifest.json" --signature "$RELEASE/manifest.sig" --archive "$RELEASE/commonwealth-kit-0.1.0-test.1.tar.gz" --trust-root "$BOOTSTRAP/release-root.pem" --revision "$REVISION" --fingerprint "$ROOT_SHA256" --target "$TARGET" --out "$WORK/install-plan.json"
python3 "$BOOTSTRAP/verify_kit.py" apply --plan "$WORK/install-plan.json" --approval "$WORK/install-approval.json" --target "$TARGET"
```

The local fixture operator reviews the plan before writing the approval. Approval repeats its actor, action, canonical target and release digest, and includes `plan_sha256`, the SHA-256 of its canonical sorted compact JSON plus newline. A modified target or plan requires a new local decision. The approved fixture operator controls the approval file and its directory. The consumer harness creates approvals under this declared role. The release signature supplies integrity and test release provenance.

### Connect to a service

Use a foreground LIFE fixture with separate operator and publication signing keys, CA-signed loopback TLS serving certificate, distinct client workload certificates, explicit participant workload certificate grant and peer-state file initially containing `{"peers":{}}`. The consumer generates those inputs in disposable stores.

**Shell A.** Start the foreground reference node and leave it running.

```bash
"$TARGET/bin/commonwealth" node start --config "$WORK/life-reference/config.json" --ready-out "$WORK/life-ready.json"
```

**Shell B.** Use the same `TARGET` and `WORK` values. Wait for readiness before trusting the reference card and making both requests.

```bash
timeout 5s sh -c 'until test -s "$1"; do sleep 0.1; done' sh "$WORK/life-ready.json"
"$TARGET/bin/commonwealth" service trust --state "$WORK/participant/peer-state.json" --reference "$WORK/life-card.json" --approval "$WORK/participant-local.json"
"$TARGET/bin/commonwealth" service request --state "$WORK/participant/peer-state.json" --config "$WORK/participant/config.json" --peer life-reference --service life.reference --action fixture.read --request-id service-allow
"$TARGET/bin/commonwealth" service request --state "$WORK/participant/peer-state.json" --config "$WORK/participant/config.json" --peer life-reference --service life.reference --action fixture.write --request-id service-deny
```

Match both IDs to the server audit. The read returns `commonwealth-reference-v1`. The write is denied at destination policy with no protected result and no mutation. After both requests, interrupt the listener in Shell A and wait for it to exit. In Shell B, verify a new connection to the recorded loopback port fails. Remove the disposable role stores after preserving the allowed public receipts.

### Run a node

Use the verified installation, a fresh `$WORK/setup-operator` target, and separate LIFE and operator configurations and peer states. Each fresh peer-state file contains `{"peers":{}}`. Keep the LIFE reference listener running in its own terminal as shown in **Connect to a service**. Use two additional shells for the operator startup and the peer actions. If the reference listener was stopped after the service exercise, start it again with a fresh readiness file and refresh its card from that listener's endpoint and identity.

**Operator Shell A · plan, approve, apply, start.** Generate the node plan first. Review the target, release digest, and configuration, then write the separate local setup approval described above. Run apply only after approval. An applied configuration has no listener until startup succeeds.

```bash
"$TARGET/bin/commonwealth" setup plan --mode node --config "$WORK/operator-node/config.json" --target "$WORK/setup-operator" --out "$WORK/operator-plan.json"
```

```bash
"$TARGET/bin/commonwealth" setup apply --plan "$WORK/operator-plan.json" --approval "$WORK/operator-approval.json" --target "$WORK/setup-operator"
"$TARGET/bin/commonwealth" node start --config "$WORK/setup-operator/config.json" --ready-out "$WORK/operator-ready.json"
```

Leave the operator node running. Listener readiness identifies a reachable local endpoint and configuration. Peer acceptance requires two separate decisions in Shell B.

**Operator Shell B · verify readiness and prepare cards.** Use the same `TARGET` and `WORK`, inside the same loopback-only fixture. Use readiness files from the current listeners and check the operator and serving identities before exchanging their public cards. When the fixture driver has already provisioned the cards, use its verified copies.

```bash
timeout 5s sh -c 'until test -s "$1" && test -s "$2"; do sleep 0.1; done' sh "$WORK/operator-ready.json" "$WORK/life-ready.json"
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path

work = Path(sys.argv[1])
for label, config in (("life", "life-reference/config.json"),
                      ("operator", "setup-operator/config.json")):
    config_path = work / config
    ready = json.loads((work / f"{label}-ready.json").read_text())
    if ready["listener"] != "ready" or ready["endpoint"][0] != "127.0.0.1":
        raise SystemExit(f"{label} listener unavailable")
    settings = json.loads(config_path.read_text())
    for key in ("operator_public", "publication_public"):
        ready[key] = str((config_path.parent / settings[key]).resolve())
    (work / f'{ready["operator"]}-card.json').write_text(json.dumps(ready))
PY
```

**Record both local acceptances.** The operator reviews the LIFE card and writes `operator-peer-local.json`. Separately, the LIFE operator reviews the operator card and writes `life-peer-local.json`. Each approval contains `actor: "fixture-local-operator"`, the approved card's `operator_sha256`, and the operator's own boolean `accept` decision. Run each enrollment under the corresponding fixture role with its own state file. Both commands must report `locally_enrolled` before an authorized exchange. If either side declines in a fresh refusal exercise, stop before enrolling the other side. Verify both peer states remain empty and an operator exchange reports `peer_not_enrolled` without a protected request.

```bash
"$TARGET/bin/commonwealth" peer enroll --state "$WORK/operator-node/peer-state.json" --reference "$WORK/life-reference-card.json" --approval "$WORK/operator-peer-local.json"
"$TARGET/bin/commonwealth" peer enroll --state "$WORK/life-reference/peer-state.json" --reference "$WORK/operator-node-card.json" --approval "$WORK/life-peer-local.json"
```

**Score both requests with both listeners running.** The allowed response must contain `commonwealth-reference-v1`. The denied response must contain no protected result and report `mutated: false`. Match both request IDs to the LIFE server audit.

```bash
"$TARGET/bin/commonwealth" peer exchange --state "$WORK/operator-node/peer-state.json" --config "$WORK/setup-operator/config.json" --peer life-reference --service life.reference --action fixture.read --request-id peer-allow
"$TARGET/bin/commonwealth" peer exchange --state "$WORK/operator-node/peer-state.json" --config "$WORK/setup-operator/config.json" --peer life-reference --service life.reference --action fixture.write --request-id peer-deny
```

**Stop and verify cleanup.** After scoring, interrupt the operator listener in Shell A and wait for it to exit. Stop the LIFE listener in its terminal after its remaining checks. Verify that connections to both recorded loopback ports fail and remove the disposable role stores after retaining public receipts. The exchange uses the installed commands, the fixture CA, and the published [protocol](PROTOCOL.md).

### Connect a lab

Keep a verified fixture listener running in its own terminal for the lab checks. After a previous cleanup, restart it and update the lab configuration with its new endpoint and serving digest. Plan and apply mode `lab` with a separate target. Its configuration names the installed node configuration, the loopback endpoint and serving certificate digest, and `simulation-v1`. Check reachability and adapter readiness separately.

```bash
"$TARGET/bin/commonwealth" lab check --config "$WORK/setup-lab/config.json"
"$TARGET/bin/commonwealth" lab run --config "$WORK/setup-lab/config.json" --template two-endpoint-v1 --seed 42 --scenario herald
"$TARGET/bin/commonwealth" lab run --config "$WORK/setup-lab/config.json" --template two-endpoint-v1 --seed 42 --scenario confirm-timeout
```

After all lab checks, stop the fixture listener and verify its port closes. Use the published [adapter contract](ADAPTER.md). The cloud receipt authenticates the archive and installed entry-point digests, correlates client and server request IDs, and records simulation, replay, and cleanup separately. The tested fixture establishes neither production release authority nor a public deployment, independent organizational custody, field acceptance, or a physical result.

The public bootstrap's `consume.py` fixture driver provisions the example inputs, applies both setup modes, and prints the exact command argv and receipts. In the cloud job, the driver receives only the separately downloaded bootstrap and release artifacts. The observer consumes only public receipts, not the temporary role stores.
