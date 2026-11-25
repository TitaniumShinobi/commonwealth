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

```bash
"$TARGET/bin/commonwealth" setup plan --mode node --config "$WORK/operator-node/config.json" --target "$WORK/setup-operator" --out "$WORK/operator-plan.json"
"$TARGET/bin/commonwealth" setup apply --plan "$WORK/operator-plan.json" --approval "$WORK/operator-approval.json" --target "$WORK/setup-operator"
"$TARGET/bin/commonwealth" node start --config "$WORK/setup-operator/config.json" --ready-out "$WORK/operator-ready.json"
"$TARGET/bin/commonwealth" peer enroll --state "$WORK/operator-node/peer-state.json" --reference "$WORK/life-card.json" --approval "$WORK/operator-local.json"
"$TARGET/bin/commonwealth" peer exchange --state "$WORK/operator-node/peer-state.json" --config "$WORK/setup-operator/config.json" --peer life-reference --service life.reference --action fixture.read --request-id peer-allow
```

LIFE independently approves the operator card with the same enrollment command and its own local state. Refusal leaves both fresh peer stores empty. The exchange uses only the verified installed commands, the fixture CA, and published [protocol](PROTOCOL.md).

### Connect a lab

Plan and apply mode `lab` with a separate target. Its configuration names the installed node configuration, the loopback endpoint and serving certificate digest, and `simulation-v1`. Check reachability and adapter readiness separately.

```bash
"$TARGET/bin/commonwealth" lab check --config "$WORK/setup-lab/config.json"
"$TARGET/bin/commonwealth" lab run --config "$WORK/setup-lab/config.json" --template two-endpoint-v1 --seed 42 --scenario herald
"$TARGET/bin/commonwealth" lab run --config "$WORK/setup-lab/config.json" --template two-endpoint-v1 --seed 42 --scenario confirm-timeout
```

Use the published [adapter contract](ADAPTER.md). The cloud receipt authenticates the archive and installed entry-point digests, correlates client and server request IDs, and records simulation, replay, and cleanup separately. The tested fixture establishes neither production release authority nor a public deployment, independent organizational custody, field acceptance, or a physical result.

The public bootstrap's `consume.py` fixture driver provisions the example inputs, applies both setup modes, and prints the exact command argv and receipts. In the cloud job, the driver receives only the separately downloaded bootstrap and release artifacts. The observer consumes only public receipts, not the temporary role stores.
