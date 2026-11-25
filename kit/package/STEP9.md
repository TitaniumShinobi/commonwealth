# Step 9 · independent fixture setup

Run from a verified installed test Kit on Linux x64. Use Python 3.12+, OpenSSL 3 and the installed CLI. No model call or live LIFE service is required. The optional plugin supplies public setup guidance and has no shell, MCP server, hook, credential store, or authority.

```bash
"$TARGET/bin/commonwealth" operator bootstrap --authority "$WORK/operator-private" --name fixture-operator
"$TARGET/bin/commonwealth" operator plan --authority "$WORK/operator-private" --operation configure --target "$WORK/target" --payload "$WORK/configure.json" --out "$WORK/configure-plan.json"
"$TARGET/bin/commonwealth" operator approve --authority "$WORK/operator-private" --plan "$WORK/configure-plan.json" --confirm --out "$WORK/configure-approval.json"
"$TARGET/bin/commonwealth" operator apply --authority "$WORK/operator-private" --plan "$WORK/configure-plan.json" --approval "$WORK/configure-approval.json" --target "$WORK/target"
```

Use an absolute target and a payload such as `{"name":"fixture-operator","protocol":1}`. Bootstrap writes `node.json`, four credential roles, and a private authority. An operation approval binds the exact plan, release, target, action, authority revision, expiry, and ID. Authority and applied-operation history stay in the private SQLite store. Leave that store outside restored application data.

`commonwealth operator guide --authority "$WORK/operator-private" --ready "$WORK/guide-ready.json"` serves only on an assigned literal loopback address. Leave it running in a separate terminal. Open the one-time URL from the private readiness file. Review the typed plan, click approval, then apply. Terminate the guide before removing its temporary state. Keep the URL and cookies out of receipts. `operator diagnostics --boundary reachability --confirm` exports only the schema, boundary, and authority revision. Review the export before sharing.

The signed test.2 and test.3 packages can be installed to separate absent targets by adding the expected `--version` to the bootstrap verifier's plan command. The Step 9 fixture checks verified compatible and incompatible candidates and executes the selected supported client against the local counterpart. For an operator node, launch the listener in the first shell.

```bash
"$TARGET/bin/commonwealth" node start --config "$WORK/operator-private/node.json" --ready-out "$WORK/operator-ready.json"
```

In a separate shell, wait for the listener to write `operator-ready.json`, then export the public card.

```bash
"$TARGET/bin/commonwealth" operator export-card --authority "$WORK/operator-private" --ready "$WORK/operator-ready.json" --out "$WORK/operator-public"
```

The export contains a card and the two public verification keys. Use a separate operator directory for the counterpart. In this loopback fixture, make both fixture CA certificates available to both nodes in a public CA bundle and point each node configuration's `ca` field at that bundle before startup. Each operator reviews the other party's card and issues and applies a local approval. Repeat the following on the other side before attempting a protected exchange.

```bash
"$TARGET/bin/commonwealth" operator plan --authority "$WORK/operator-private" --operation enroll --target "$WORK/operator-private" --payload "$WORK/counterpart-public/card.json" --out "$WORK/counterpart-plan.json"
"$TARGET/bin/commonwealth" operator approve --authority "$WORK/operator-private" --plan "$WORK/counterpart-plan.json" --confirm --out "$WORK/counterpart-approval.json"
"$TARGET/bin/commonwealth" operator apply --authority "$WORK/operator-private" --plan "$WORK/counterpart-plan.json" --approval "$WORK/counterpart-approval.json" --target "$WORK/operator-private"
"$TARGET/bin/commonwealth" peer exchange --state "$WORK/operator-private/peers.json" --config "$WORK/operator-private/node.json" --peer local-counterpart --service life.reference --action fixture.read --request-id first-read
"$TARGET/bin/commonwealth" peer exchange --state "$WORK/operator-private/peers.json" --config "$WORK/operator-private/node.json" --peer local-counterpart --service life.reference --action fixture.write --request-id denied-write
```

With the peer named `local-counterpart`, expect `commonwealth-reference-v1` for the read and a policy denial for the write. Keep both listeners running through both requests and stop them before removing the disposable state. A failed discovery on the reference path calls for a separate, locally approved counterpart identity. Use the counterpart's own audit to correlate the permitted and denied requests.

The fixture tests local lifecycle authority state, including a modeled blocked restore and preservation of a peer withdrawal and binding floor across application-state restoration. Full installed network-peer lifecycle and complete browser/CLI lifecycle parity have separate evidence gates. The independent status extension uses the published protocol profile and its own Python implementation, source and artifact hashes, TLS endpoint, and publication authority. The fixture tests compatible build, incompatible startup, and version rejection on the active service.

The optional package targets the explicitly exercised Codex Linux x64 build only. The cloud job supplies a disposable public workspace under an unprivileged identity, stages the official host binary by release archive SHA-256, and attempts local App Server installation and skill discovery without model calls. Host compatibility requires actual host results. Neither release publication nor unsupported hosts are in scope.

## Run the trusted installer and guided peer lifecycle

Provision the verifier and the independently pinned release inputs before opening the guide. Run the following in a terminal and leave it running while you complete the browser steps. The target and authority directories must be absent.

```bash
python3 "$BOOTSTRAP/verify_kit.py" guide --manifest "$RELEASE/manifest.json" \
  --signature "$RELEASE/manifest.sig" --archive "$RELEASE/commonwealth-kit-0.1.0-test.2.tar.gz" \
  --trust-root "$BOOTSTRAP/release-root.pem" --fingerprint "$ROOT_FINGERPRINT" \
  --revision "$SOURCE_SHA" --version 0.1.0-test.2 --target "$TARGET" \
  --out "$WORK/install-plan.json" --approval "$WORK/install-approval.json" \
  --ready "$WORK/installer-ready.json" --authority "$WORK/operator-private" --name fixture-operator
```

Open the one-time loopback URL in the readiness file. Click **Verify release**, **Approve verified installation**, **Install verified Kit**, then **Create operator**. For the CLI equivalent, run the verifier's `plan` command with the same release inputs, inspect the returned approval binding, write it to the approval file after local approval, and run `apply --plan "$WORK/install-plan.json" --approval "$WORK/install-approval.json" --target "$TARGET"`. Then invoke the installed `operator bootstrap` command above.

In the installed operator guide, select the action and supply the exact target and JSON payload. Click **Review plan**, **Approve reviewed plan**, then **Apply approved plan**. The command equivalent is `operator plan --operation ACTION --target TARGET --payload FILE --out PLAN`, followed by `operator approve --plan PLAN --confirm --out APPROVAL` and `operator apply --plan PLAN --approval APPROVAL --target TARGET`. Pass the same `--authority` to each command.

- Use `enroll` on each side with its independently reviewed peer card. Use `exchange` with `peer`, `service`, `action` set to `fixture.read`, and a unique `request_id`. The result includes the verified revision or a specific failure such as `discovery_unavailable`. Repeat from the unaffected peer to distinguish one unavailable endpoint from a wider outage.
- Use `exit` with `operator` set to the peer name. Apply independently at both endpoints. Verify the withdrawn client cannot read at the destination.
- The fixture lifecycle uses `service-activate`, `service-backup`, `service-fence`, then `service-restore` under the serving authority. Each payload includes the approved `identity` with `operator`, `service`, `generation`, `certificate` SHA-256, and absolute `application` path. The target is that application path. Restore also requires the authoritative `backup_sha256`, a clean target, a fresh serving certificate, and the next generation. Enroll the new signed binding and verify a peer read, then check that the old generation still rejects reads and writes.

The loopback fixture uses a protected authority broker and separate old-host OS identity. It does not configure a field or production service.
