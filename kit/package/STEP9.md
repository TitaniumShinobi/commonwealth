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

## Restart LIFE with the original enrollment

Use the already-running loopback LIFE fixture and its enrolled client. In the commands below, `$LIFE_CONFIG` and `$LIFE_READY` identify the original listener configuration and readiness file, and `$LIFE_PID` is the original foreground listener's PID recorded by the shell that started it. `$CLIENT` is the enrolled operator authority directory. Finish the baseline read before stopping the listener.

```bash
BIN="$TARGET/bin/commonwealth"
life_read() {
  "$BIN" peer exchange --state "$CLIENT/peers.json" --config "$CLIENT/node.json" \
    --peer life-reference --service life.reference --action fixture.read --request-id "$1"
}
life_read before-outage > "$WORK/life-before.json"
"$BIN" operator inspect --authority "$CLIENT" > "$WORK/life-trust-before.json"
sha256sum "$CLIENT/node.json" > "$WORK/life-client-policy-before"
python3 - "$LIFE_CONFIG" "$LIFE_READY" "$WORK/life-restart.json" <<'PY'
import json, sys
from pathlib import Path
original, ready, output = map(Path, sys.argv[1:])
config = json.loads(original.read_text())
endpoint = json.loads(ready.read_text())["endpoint"]
assert endpoint[0] == config["host"] == "127.0.0.1"
config["listen_port"] = endpoint[1]
output.write_text(json.dumps(config))
PY
python3 -c 'import time; print(time.monotonic())' > "$WORK/life-stop-time"
kill -TERM "$LIFE_PID"
for ((i=0; i<80; i++)); do
  if ! kill -0 "$LIFE_PID" 2>/dev/null; then break; fi
  sleep 0.05
done
life_read during-outage > "$WORK/life-outage.json" || true
python3 - "$WORK/life-outage.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["reason"] == "discovery_unavailable"
PY
"$BIN" peer exchange --state "$CLIENT/peers.json" --config "$CLIENT/node.json" \
  --peer local-counterpart --service life.reference --action fixture.read --request-id outage-control
"$BIN" node start --config "$WORK/life-restart.json" --ready-out "$WORK/life-restart-ready.json" &
LIFE_RESTART_PID=$!
for ((i=0; i<80; i++)); do
  if [ -s "$WORK/life-restart-ready.json" ]; then break; fi
  sleep 0.05
done
test -s "$WORK/life-restart-ready.json"
life_read reference-recovered > "$WORK/life-after.json"
python3 -c 'import time; print(time.monotonic())' > "$WORK/life-read-time"
"$BIN" operator inspect --authority "$CLIENT" > "$WORK/life-trust-after.json"
cmp "$WORK/life-trust-before.json" "$WORK/life-trust-after.json"
sha256sum --check "$WORK/life-client-policy-before"
python3 - "$WORK" "$LIFE_CONFIG" <<'PY'
import json, sys
from pathlib import Path
work, original = map(Path, sys.argv[1:])
before = json.loads((work / "life-before.json").read_text())
after = json.loads((work / "life-after.json").read_text())
config = json.loads(original.read_text())
restart = json.loads((work / "life-restart.json").read_text())
assert restart.pop("listen_port") == before["binding_identity"]["endpoint"][1]
assert restart == config
assert before["binding_identity"] == after["binding_identity"]
assert after["binding_verified"] and after["result"] == "commonwealth-reference-v1"
rows = [json.loads(line) for line in Path(config["audit"]).read_text().splitlines()]
assert any(row["request_id"] == "reference-recovered" and row["decision"] == "allowed"
           and row["disclosed"] for row in rows)
seconds = float((work / "life-read-time").read_text()) - float((work / "life-stop-time").read_text())
assert 0 <= seconds <= 15, seconds
print(json.dumps({"seconds_to_first_audited_read": seconds, "binding": after["binding_identity"]}))
PY
```

Keep the original enrollment throughout. The two signed binding digests in the exchange receipts may differ because the binding's expiry is refreshed. Preserve both receipts, the failure and control receipts, the trust snapshots, and the destination audit. Terminate `$LIFE_RESTART_PID` after collecting evidence.

## Execute the fenced restore

Use the installed loopback fixture with an active broker-backed generation-1 listener, an enrolled reader, and an unrelated enrolled counterpart. Keep the reader listener running and set `$CLIENT_READY` to its original readiness file. The cloud fixture sets up those processes with the installed Kit and separates the old listener's OS account from the authority. For this procedure, `$OWNER` is the serving authority directory, `$OLD_CONFIG` is its protected generation-1 configuration, and `$OLD_READY` is the running old listener's readiness file. `$REPLACEMENT` and `$WORK/restored-app.json` must be absent. Keep the old listener and its authority broker running throughout.

```bash
"$BIN" operator bootstrap --authority "$REPLACEMENT" --name replacement-host
python3 - "$OLD_CONFIG" "$REPLACEMENT/node.json" "$WORK" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
old_path, fresh_path, work = map(Path, sys.argv[1:])
old = json.loads(old_path.read_text())
fresh = json.loads(fresh_path.read_text())
bundle = Path(old["ca"])
with bundle.open("ab") as out:
    out.write(Path(fresh["ca"]).read_bytes())
new = {**old, "generation": 2, "application": str(work / "restored-app.json"),
       "certificate": fresh["certificate"], "tls_key": fresh["tls_key"],
       "audit": str(work / "restored-audit.ndjson")}
new.pop("listen_port", None)
assert not Path(new["application"]).exists()
(work / "replacement.json").write_text(json.dumps(new))
for label, node in (("old", old), ("replacement", new)):
    der = subprocess.check_output(["openssl", "x509", "-in", node["certificate"], "-outform", "DER"])
    identity = {"operator": node["operator"], "service": node["service"], "generation": node["generation"],
                "certificate": hashlib.sha256(der).hexdigest(), "application": node["application"]}
    (work / (label + "-identity.json")).write_text(json.dumps({"identity": identity}))
PY
OLD_APP=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"]["application"])' "$WORK/old-identity.json")
NEW_APP="$WORK/restored-app.json"
apply_plan() {
  local action=$1 payload=$2 target=$3 label=${4:-$1}
  "$BIN" operator plan --authority "$OWNER" --operation "$action" --target "$target" \
    --payload "$payload" --out "$WORK/$label-plan.json" >&2 || return
  cat "$WORK/$label-plan.json" >&2
  read -r -p "Type approve to apply this plan: " answer
  [ "$answer" = approve ] || return 1
  "$BIN" operator approve --authority "$OWNER" --plan "$WORK/$label-plan.json" \
    --confirm --out "$WORK/$label-approval.json" >&2 || return
  "$BIN" operator apply --authority "$OWNER" --plan "$WORK/$label-plan.json" \
    --approval "$WORK/$label-approval.json" --target "$target"
}
sha256sum "$OLD_APP" > "$WORK/old-application-before.sha256"
apply_plan service-backup "$WORK/old-identity.json" "$OLD_APP"
```

For the guided route, run the same payload-generation commands. Instead of each `apply_plan` command, open the installed guide under the stated authority, select the same operation, enter the stated **Target**, and paste the referenced JSON payload. Click **Review plan**, inspect it, then click **Approve reviewed plan** and **Apply approved plan**. Start with `service-backup` under `$OWNER`, targeting `$OLD_APP`.

### Withdraw both directions before fencing

After backup, generate one `exit` payload per authority. Each local operator approves only its own withdrawal. The peer names come from the running listener readiness files.

```bash
python3 - "$OLD_READY" "$CLIENT_READY" "$WORK" <<'PY'
import json, sys
from pathlib import Path
old, reader, work = map(Path, sys.argv[1:])
for label, ready in (("reader-exit", old), ("owner-exit", reader)):
    operator = json.loads(ready.read_text())["operator"]
    (work / (label + ".json")).write_text(json.dumps({"operator": operator}))
PY
OWNER="$CLIENT" apply_plan exit "$WORK/reader-exit.json" "$CLIENT" reader-exit
apply_plan exit "$WORK/owner-exit.json" "$OWNER" owner-exit
```

In the browser, first open the reader's guide under `$CLIENT`, choose `exit`, target `$CLIENT`, and paste `reader-exit.json`. Then open the serving guide under `$OWNER`, choose `exit`, target `$OWNER`, and paste `owner-exit.json`. Review, approve, and apply each plan separately. Both decisions must be `applied`.

Verify the reader's installed `exchange` handler rejects the withdrawn peer. Use the same `exchange` payload and three guided buttons under `$CLIENT` for the browser route. The expected result is nested under `exchange`.

```bash
python3 - "$OLD_READY" > "$WORK/post-exit.json" <<'PY'
import json, sys
ready = json.load(open(sys.argv[1]))
print(json.dumps({"peer": ready["operator"], "service": ready["service"],
                  "action": "fixture.read", "request_id": "post-exit"}))
PY
OWNER="$CLIENT" apply_plan exchange "$WORK/post-exit.json" "$CLIENT" post-exit > "$WORK/post-exit-receipt.json"
python3 - "$WORK/post-exit-receipt.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))["exchange"]
assert result == {"decision": "rejected", "reason": "peer_not_enrolled"}, result
PY
```

The approval stays interactive while standard output contains the receipt. Next, probe the old listener directly to verify the destination independently denies the withdrawn reader.

```bash
probe_denial() {
  python3 - "$TARGET/lib" "$CLIENT/node.json" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from runtime import call, read_config
ready = json.loads(Path(sys.argv[3]).read_text())
request = {"operation": "request", "protocol": 1, "service": ready["service"],
           "action": sys.argv[6], "request_id": sys.argv[5], "value": "unauthorized-replacement"}
result = call(read_config(sys.argv[2]), ready["endpoint"], request, ready["serving_sha256"])
assert result["reason"] == sys.argv[4] and not result["mutated"] and "result" not in result, result
print(json.dumps(result))
PY
}
probe_denial "$OLD_READY" destination_policy withdrawn fixture.read
```

### Fence, restore, and test stale authority

For the guided route, use the serving authority's guide for `service-fence` with `old-identity.json` and target `$OLD_APP`. Run the same direct read and write probes on the still-running old listener before proceeding.

```bash
apply_plan service-fence "$WORK/old-identity.json" "$OLD_APP"
probe_denial "$OLD_READY" generation_fenced fenced-read fixture.read
probe_denial "$OLD_READY" generation_fenced fenced-write fixture.write
"$BIN" operator inspect --authority "$OWNER" > "$WORK/authority-fenced.json"
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
state = json.loads((work / "authority-fenced.json").read_text())
assert state["serving"]["fenced"]
payload = json.loads((work / "replacement-identity.json").read_text())
payload["backup_sha256"] = state["service_backup"]["sha256"]
(work / "service-restore.json").write_text(json.dumps(payload))
PY
test ! -e "$NEW_APP"
apply_plan service-restore "$WORK/service-restore.json" "$NEW_APP"
```

For the guided restore, select `service-restore` under `$OWNER`, use `service-restore.json`, and target `$NEW_APP`. Review the backup digest and replacement identity before approving and applying. For both routes, start the replacement in a separate terminal and wait for its fresh readiness file.

```bash
"$BIN" node start --config "$WORK/replacement.json" --ready-out "$WORK/replacement-ready.json"
```

**Before either side renews enrollment**, compare the preserved authority state and prove the replacement rejects the original reader.

```bash
probe_denial "$WORK/replacement-ready.json" destination_policy restore-stale fixture.read
"$BIN" operator inspect --authority "$OWNER" > "$WORK/authority-restored.json"
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
before = json.loads((work / "authority-fenced.json").read_text())
after = json.loads((work / "authority-restored.json").read_text())
assert before["withdrawn"] == after["withdrawn"]
assert before["peer_binding_floors"] == after["peer_binding_floors"]
assert after["binding_floor"] == 2
PY
```

### Renew both directions and verify recovery

After the stale-reader denial, export both cards from the running listeners. Create revision-2 copies for the two independent enrollment reviews.

```bash
"$BIN" operator export-card --authority "$OWNER" --ready "$WORK/replacement-ready.json" --out "$WORK/replacement-public"
"$BIN" operator export-card --authority "$CLIENT" --ready "$CLIENT_READY" --out "$WORK/reader-public"
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
for role in ("replacement", "reader"):
    card = json.loads((work / (role + "-public") / "card.json").read_text())
    card["revision"] = 2
    (work / (role + "-enroll.json")).write_text(json.dumps(card))
PY
OWNER="$CLIENT" apply_plan enroll "$WORK/replacement-enroll.json" "$CLIENT" replacement-enroll
apply_plan enroll "$WORK/reader-enroll.json" "$OWNER" reader-enroll
```

In the browser select `enroll` first under `$CLIENT`, targeting `$CLIENT` with `replacement-enroll.json`. Then select `enroll` under `$OWNER`, targeting `$OWNER` with `reader-enroll.json`. Review and approve both separately. Verify the recovered read first, then repeat the old-generation probes and the control read.

```bash
PEER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["operator"])' "$WORK/replacement-ready.json")
"$BIN" peer exchange --state "$CLIENT/peers.json" --config "$CLIENT/node.json" \
  --peer "$PEER" --service life.reference --action fixture.read --request-id network-recovered \
  > "$WORK/network-recovered.json"
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
result = json.loads((work / "network-recovered.json").read_text())
ready = json.loads((work / "replacement-ready.json").read_text())
assert result["result"] == "recoverable-version" and result["binding_revision"] == 2
assert result["endpoint_sha256"] == ready["serving_sha256"]
PY
probe_denial "$OLD_READY" generation_fenced restored-old-read fixture.read
probe_denial "$OLD_READY" generation_fenced restored-old-write fixture.write
sha256sum --check "$WORK/old-application-before.sha256"
"$BIN" peer exchange --state "$CLIENT/peers.json" --config "$CLIENT/node.json" \
  --peer local-counterpart --service life.reference --action fixture.read --request-id network-control
```

For a guided recovered read, select `exchange` under `$CLIENT` with **Target** set to `$CLIENT`. Use the JSON payload `{"peer":"fenced-service","service":"life.reference","action":"fixture.read","request_id":"network-recovered-guided"}`, substituting the actual operator from replacement readiness. Complete **Review plan**, **Approve reviewed plan**, and **Apply approved plan**. The nested `exchange` result contains the restored record, revision, and certificate digest. Use the same action with peer `local-counterpart` and a different request ID for the guided control read.

Expect `commonwealth-reference-v1` from the unaffected counterpart. Preserve the old and replacement destination audit rows, the signed-binding receipt, the direct old-generation denials, and the control exchange.
