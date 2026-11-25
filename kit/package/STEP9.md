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

The installed fixture exercises clean signed setup, first exchange, transport failure, bilateral exit, and fenced restore through the command and browser paths. The independent status extension uses its own Python implementation, source and artifact hashes, TLS endpoint, and publication authority. The fixture tests compatible build, incompatible startup, and version rejection on the active service.

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

## Work through upgrade, incompatible rejection, and rollback

Stage three verified signed Kits at absolute directories `$BASE`, `$UPGRADE`, and `$INCOMPATIBLE`. Use the verifier's plan, local approval, and apply sequence for each candidate. The base is `0.1.0-test.2`. The compatible and incompatible candidates are separately signed `0.1.0-test.3` packages. Keep using the operator authority and the enrolled counterpart established above.

Generate each exact payload from the corresponding verified installation proof.

```bash
for name in upgrade incompatible rollback; do
  case "$name" in
    upgrade) candidate="$UPGRADE" ;;
    incompatible) candidate="$INCOMPATIBLE" ;;
    rollback) candidate="$BASE" ;;
  esac
  python3 - "$candidate" > "$WORK/$name.json" <<'PY'
import json, sys
from pathlib import Path
candidate = Path(sys.argv[1]).resolve()
proof = json.loads((candidate / ".release-proof.json").read_text())
print(json.dumps({"candidate_sha256": proof["release_sha256"], "configuration": str(candidate)}))
PY
done
```

For the browser route, open the installed operator guide using the authority for that route. Select `upgrade` with the contents of `upgrade.json`, then `upgrade` with `incompatible.json`, and finally `rollback` with `rollback.json`. For each decision, use the absolute operator directory as **Target**. Click **Review plan**, confirm the target, configuration path, and release digest, then click **Approve reviewed plan** and **Apply approved plan**. After each decision, run the selected binary exchange below using the browser route's operator directory.

For the CLI route, use its independently installed base and operator directory. Run the following after inspecting the three payloads. Review each emitted plan before confirming it.

```bash
STATE="$WORK/operator-private"
for name in upgrade incompatible rollback; do
  operation=upgrade
  if [ "$name" = rollback ]; then operation=rollback; fi
  "$BASE/bin/commonwealth" operator plan --authority "$STATE" --operation "$operation" \
    --target "$STATE" --payload "$WORK/$name.json" --out "$WORK/$name-plan.json"
  cat "$WORK/$name-plan.json"
  read -r -p "Type approve to apply this plan: " decision
  if [ "$decision" != approve ]; then break; fi
  "$BASE/bin/commonwealth" operator approve --authority "$STATE" --plan "$WORK/$name-plan.json" \
    --confirm --out "$WORK/$name-approval.json"
  "$BASE/bin/commonwealth" operator apply --authority "$STATE" --plan "$WORK/$name-plan.json" \
    --approval "$WORK/$name-approval.json" --target "$STATE"
  selected=$("$BASE/bin/commonwealth" operator inspect --authority "$STATE" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["selected_configuration"])')
  sha256sum "$selected/bin/commonwealth"
  "$selected/bin/commonwealth" peer exchange --state "$STATE/peers.json" --config "$STATE/node.json" \
    --peer local-counterpart --service life.reference --action fixture.read --request-id "cli-$name"
done
```

For the browser route, run the same inspect, digest, and exchange commands after each click sequence. Substitute the browser operator's state directory and use request IDs `browser-upgrade`, `browser-incompatible`, and `browser-rollback`. The compatible upgrade selects the staged upgrade directory. The incompatible plan returns `release_incompatible` and leaves the upgrade selected. Rollback selects the base. Each selected binary must read `commonwealth-reference-v1`; match its request ID and client identity against the counterpart's audit. A temporary LIFE restart in this cloud fixture has a **15-second** bound from stop request to first authorized read through the restored binding, using the original enrollment and unchanged trust and policy.
