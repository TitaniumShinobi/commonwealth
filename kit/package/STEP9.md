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

The signed test.2 and test.3 packages can be installed to separate absent targets by adding the expected `--version` to the bootstrap verifier's plan command. The Step 9 fixture checks verified compatible and incompatible candidates and executes the selected supported client against the local counterpart. For a reachable node use the setup, foreground startup, and peer exchange instructions in GUIDE.md. A failed discovery on the reference path calls for a separate, locally approved counterpart identity. Use the counterpart's own audit to correlate the permitted and denied requests.

The fixture tests local lifecycle authority state, including a modeled blocked restore and preservation of a peer withdrawal and binding floor across application-state restoration. Full installed network-peer lifecycle and complete browser/CLI lifecycle parity have separate evidence gates. The independent status extension uses the published protocol profile and its own Python implementation, source and artifact hashes, TLS endpoint, and publication authority. The fixture tests compatible build, incompatible startup, and version rejection on the active service.

The optional package targets the explicitly exercised Codex Linux x64 build only. The cloud job supplies a disposable public workspace under an unprivileged identity, stages the official host binary by release archive SHA-256, and attempts local App Server installation and skill discovery without model calls. Host compatibility requires actual host results. Neither release publication nor unsupported hosts are in scope.
