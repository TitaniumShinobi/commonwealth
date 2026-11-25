"""Cloud Step 9 fixture driver; installed paths provide all operation behavior."""
import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from verify_kit import approve, canonical, load, sha, write

CHECKS = []
COMMANDS = []


def check(name, expected, observed):
    CHECKS.append({"case": name, "expected": expected, "observed": observed, "matches": expected == observed})


def run(*argv, limit=12, **kwargs):
    args = list(map(str, argv))
    COMMANDS.append(args)
    return subprocess.run(args, capture_output=True, timeout=limit, **kwargs)


def command(*argv, limit=12):
    done = run(*argv, limit=limit)
    return json.loads(done.stdout)


def install(boot, releases, root, name, version, revision):
    verifier = [sys.executable, boot / "verify_kit.py"]
    target, plan, approval = root / name, root / (name + ".plan"), root / (name + ".approval")
    package = releases / name
    trust = load(boot / "trust.json")
    p = command(*verifier, "plan", "--manifest", package / "manifest.json", "--signature", package / "manifest.sig",
                "--archive", package / f"commonwealth-kit-{version}.tar.gz",
                "--trust-root", boot / "release-root.pem", "--fingerprint", trust["fingerprint"],
                "--revision", revision, "--version", version, "--target", target, "--out", plan)
    check(name + "_verified", "verified_plan", p["decision"])
    write(approval, approve(load(plan)))
    r = command(*verifier, "apply", "--plan", plan, "--approval", approval, "--target", target)
    check(name + "_installed", "installed", r["decision"])
    return target, r


def install_guided(boot, releases, root, revision, chrome, authority):
    trust = load(boot / "trust.json")
    release = releases / "step9-base"
    target = root / "kit"
    version = "0.1.0-test.2"
    if not chrome:
        raise RuntimeError("guided installation browser unavailable")
    failures = []
    for attempt in range(3):
        ready = root / f"install-ready-{attempt}"
        args = [sys.executable, boot / "verify_kit.py", "guide", "--manifest", release / "manifest.json",
                "--signature", release / "manifest.sig", "--archive", release / f"commonwealth-kit-{version}.tar.gz",
                "--trust-root", boot / "release-root.pem", "--fingerprint", trust["fingerprint"],
                "--revision", revision, "--version", version, "--target", target, "--out", root / "install-plan",
                "--approval", root / "install-approval", "--ready", ready, "--authority", authority, "--name", "guided"]
        guide, listening = start(args, ready)
        try:
            process = subprocess.run([os.environ.get("CW_NODE", "node"), str(boot / "browser9.mjs"), chrome,
                                      listening["url"], str(target), "install"], capture_output=True, timeout=25)
            if process.returncode == 0:
                return target, json.loads(process.stdout)
            diagnostic = process.stderr.decode(errors="replace").replace(listening["url"], "<private launch URL>")
            failures.append(diagnostic[-700:])
        except subprocess.TimeoutExpired:
            failures.append("browser timeout")
        finally:
            stop(guide)
        # These paths are newly allocated for this disposable fixture only.
        for attempt_path in (target, Path(authority)):
            if attempt_path.exists():
                shutil.rmtree(attempt_path)
    raise RuntimeError("trusted installer clicks did not reach bootstrap: " + " / ".join(failures))


def operate(binary, directory, action, *args):
    return command(binary, "operator", action, "--authority", directory, *args)


def approval(binary, authority, root, label, operation, target, body, seconds=120):
    payload, plan, approved = (root / f"{label}.{extension}" for extension in ("body", "plan", "approval"))
    write(payload, body)
    operate(binary, authority, "plan", "--operation", operation, "--target", target, "--payload", payload, "--out", plan)
    operate(binary, authority, "approve", "--plan", plan, "--confirm", "--seconds", seconds, "--out", approved)
    return plan, approved


def apply(binary, authority, target, plan, approved=None):
    return operate(binary, authority, "apply", "--plan", plan, "--target", target,
                   *(("--approval", approved) if approved else ()))


def start(args, ready):
    arguments = list(map(str, args))
    # Do not pass launch URLs or private key contents in logged argv.
    COMMANDS.append(arguments)
    proc = subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(120):
        if ready.is_file():
            try:
                return proc, load(ready)
            except (ValueError, PermissionError):
                pass
        if proc.poll() is not None:
            break
        time.sleep(0.04)
    stop(proc)
    raise RuntimeError("fixture listener did not start")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def card(root, name, config, ready):
    path = root / (name + ".card")
    write(path, {**ready, "operator_public": config["operator_public"],
                 "publication_public": config["publication_public"]})
    return path


def approved_card(reference):
    fields = ("operator", "operator_sha256", "publication_sha256", "serving_sha256",
              "endpoint", "operator_public", "publication_public")
    source = load(reference)
    return {**{name: source[name] for name in fields},
            "workload_sha256": source.get("workload_sha256", source["serving_sha256"]), "protocol": 1}


def enroll(binary, root, config, reference, label):
    authority = Path(config["authority"])
    plan, permit = approval(binary, authority, root, label, "enroll", authority, approved_card(reference))
    return apply(binary, authority, authority, plan, permit)


def exchange(binary, config_path, peer, service, action, request_id, version=1):
    config = load(config_path)
    return command(binary, "peer", "exchange", "--state", config["state"], "--config", config_path,
                   "--peer", peer, "--service", service, "--action", action,
                   "--request-id", request_id, "--wire-version", version)


def browser_apply(binary, root, boot, chrome, authority, target, operation, body, expected, guided_observations):
    if not chrome:
        return None
    for attempt in range(2):
        address = root / f"guide-{len(guided_observations)}-{attempt}"
        guide, ready = start([binary, "operator", "guide", "--authority", authority, "--ready", address], address)
        try:
            browser = subprocess.run(
                [os.environ.get("CW_NODE", "node"), str(boot / "browser9.mjs"), chrome, ready["url"], str(target),
                 operation, canonical(body).decode(), expected], capture_output=True, timeout=20)
            if browser.returncode == 0:
                events = json.loads(browser.stdout)
                guided_observations.append({"operation": operation, "clicks": events})
                return events[-1]
        except subprocess.TimeoutExpired:
            pass
        finally:
            stop(guide)
    guided_observations.append({"operation": operation, "verdict": "UNVERIFIED"})
    return None



def network_lifecycle(binary, root, client, reference, control, browser=None):
    owner = Path(load(reference)["authority"])
    reader = Path(load(client)["authority"])
    old = root / "fenced-old.json"
    old_app = root / "old-app.json"
    write(old_app, {"record": "recoverable-version"})
    old_config = {**load(reference), "generation": 1, "application": str(old_app),
                  "audit": str(root / "old-network-audit")}
    write(old, old_config)
    replacement = root / "fresh-credentials"
    operate(binary, replacement, "bootstrap", "--name", "replacement-host")
    fresh = load(replacement / "node.json")
    bundle = Path(old_config["ca"])
    bundle.write_bytes(bundle.read_bytes() + Path(fresh["ca"]).read_bytes())
    new_app = root / "clean-application.json"
    new = root / "fenced-new.json"
    write(new, {**old_config, "generation": 2, "application": str(new_app),
                "certificate": fresh["certificate"], "tls_key": fresh["tls_key"],
                "audit": str(root / "new-network-audit")})
    def identity(config):
        value = load(config)
        cert = subprocess.check_output(["openssl", "x509", "-in", value["certificate"], "-outform", "DER"])
        return {"operator": value["operator"], "service": value["service"], "generation": value["generation"],
                "certificate": sha(cert), "application": value["application"]}
    def commit(authority, label, operation, target, body):
        if browser:
            boot, chrome, clicks = browser
            result = browser_apply(binary, root, boot, chrome, authority, target, operation, body, "applied", clicks)
            if result is None:
                raise RuntimeError("guided network operation unverified: " + label)
            return result
        plan, permit = approval(binary, authority, root, label, operation, target, body)
        return apply(binary, authority, target, plan, permit)
    def wire(config, endpoint, fingerprint, identifier, action):
        code = ("import json,sys;sys.path.insert(0,sys.argv[1]);from runtime import call,read_config;"
                "print(json.dumps(call(read_config(sys.argv[2]),json.loads(sys.argv[3]),"
                "json.loads(sys.argv[4]),sys.argv[5])))")
        message = {"operation": "request", "protocol": 1, "service": "life.reference",
                   "action": action, "request_id": identifier, "value": "unauthorized-replacement"}
        return command(sys.executable, "-c", code, binary.parent.parent / "lib", config, json.dumps(endpoint),
                       json.dumps(message), fingerprint)
    def network_card(config, ready, label, revision):
        path = card(root, label, load(config), ready)
        return {**approved_card(path), "revision": revision}
    def score(label, expected, observed):
        check(("guided_network_" if browser else "network_") + label, expected, observed)

    old_id = identity(old)
    score("activate", "applied", commit(owner, "network-activate", "service-activate", old_app,
                                        {"identity": old_id})["decision"])
    listeners = []
    isolated = tempfile.TemporaryDirectory(prefix="cw-old-host-")
    public = Path(isolated.name)
    legacy = public / "kit"
    broker_process = None
    try:
        public.chmod(0o755)
        shutil.copytree(binary.parent.parent, legacy)
        for path in (legacy, *legacy.rglob("*")):
            if path.is_dir():
                path.chmod(0o755)
        uid = int(run("id", "-u", "nobody").stdout)
        score("authority_and_old_host_uid_distinct", True, uid != os.getuid())
        for path in (owner / "authority.sqlite", old_app, Path(old_config["publication_key"])):
            scores = [run("sudo", "-n", "runuser", "-u", "nobody", "--", "test", flag, path).returncode
                      for flag in ("-r", "-w")]
            score("direct_access_denied_" + path.name, [1, 1], scores)
        socket_path = public / "authority.sock"
        broker_args = [sys.executable, binary.parent.parent / "lib/network9.py", old, socket_path, str(uid)]
        COMMANDS.append(list(map(str, broker_args)))
        broker_process = subprocess.Popen(broker_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(120):
            if socket_path.exists() and socket_path.stat().st_mode & 0o002:
                break
            if broker_process.poll() is not None:
                raise RuntimeError("external authority broker failed to start")
            time.sleep(0.04)
        exposed = dict(old_config, authority_socket=str(socket_path))
        for key in ("ca", "certificate", "tls_key", "client_certificate", "client_key",
                    "operator_public", "publication_public"):
            dest = public / (key + ".pem")
            if key in ("tls_key", "client_key"):
                subprocess.run(["sudo", "-n", "install", "-m", "600", "-o", "nobody", old_config[key], dest], check=True)
            else:
                shutil.copyfile(old_config[key], dest)
            exposed[key] = str(dest)
        for key in ("operator_key", "publication_key", "authority", "application", "state"):
            exposed.pop(key, None)
        untrusted = public / "host"
        subprocess.run(["sudo", "-n", "install", "-d", "-m", "755", "-o", "nobody", untrusted], check=True)
        exposed["audit"] = str(untrusted / "audit")
        public_config = public / "node.json"
        write(public_config, exposed)
        old_ready = untrusted / "ready"
        old_process, old_seen = start(["sudo", "-n", "runuser", "-u", "nobody", "--",
                                      legacy / "bin/commonwealth", "node", "start", "--config",
                                      public_config, "--ready-out", old_ready], old_ready)
        listeners.append(old_process)
        client_ready = root / "client-network-ready"
        client_process, client_seen = start([binary, "node", "start", "--config", client,
                                             "--ready-out", client_ready], client_ready)
        listeners.append(client_process)
        other = network_card(client, client_seen, "network-client", 1)
        peer = network_card(old, old_seen, "network-old", 1)
        # The fixture is distinct from the prior reference by source configuration.
        score("client_enroll", "applied", commit(reader, "network-peer", "enroll", reader, peer)["decision"])
        score("destination_enroll", "applied", commit(owner, "network-client-peer", "enroll", owner, other)["decision"])
        def read(label):
            payload = {"peer": old_config["operator"], "service": "life.reference", "action": "fixture.read",
                       "request_id": label}
            return commit(reader, label, "exchange", reader, payload)["exchange"]
        score("baseline_read", ["recoverable-version", 1],
              [read("baseline-network").get("result"), read("baseline-revision").get("binding_revision")])
        relay_code = ("import json,sys;sys.path.insert(0,sys.argv[1]);from network9 import relay;"
                      "m=json.load(sys.stdin);print(json.dumps(relay(sys.argv[2],m['request'],m['endpoint'],m.get('proof'))))")
        message = {"operation": "request", "protocol": 1, "service": "life.reference",
                   "action": "fixture.read", "request_id": "isolated-broker-proof"}
        def relay_probe(proof=None, operation=None):
            submitted = {"request": message if operation is None else operation,
                         "endpoint": old_seen["endpoint"], "proof": proof}
            proc = run("sudo", "-n", "runuser", "-u", "nobody", "--", sys.executable, "-c", relay_code,
                       legacy / "lib", socket_path, input=canonical(submitted))
            return json.loads(proc.stdout)
        def signed_challenge(key):
            challenge = relay_probe()["challenge"]
            code = ("import json,sys;sys.path.insert(0,sys.argv[1]);from runtime import sign;"
                    "print(sign(sys.argv[2],json.load(sys.stdin)))")
            signed = run(sys.executable, "-c", code, binary.parent.parent / "lib", key,
                         input=canonical(challenge)).stdout.decode().strip()
            return {"nonce": challenge["nonce"], "signature": signed,
                    "certificate": Path(load(client)["client_certificate"]).read_text()}
        forged = signed_challenge(Path(old_config["client_key"]))
        valid = signed_challenge(Path(load(client)["client_key"]))
        altered = signed_challenge(Path(load(client)["client_key"]))
        def rejection(result):
            return [result["reason"], result.get("result"), result["mutated"]]
        score("untrusted_host_cannot_forge_peer", ["peer_proof_invalid", None, False], rejection(relay_probe(forged)))
        score("authority_verifies_enrolled_signature", "recoverable-version", relay_probe(valid).get("result"))
        score("authority_consumes_challenge", ["challenge_unknown_expired_or_used", None, False],
              rejection(relay_probe(valid)))
        score("authority_rejects_changed_action", ["challenge_operation_changed", None, False],
              rejection(relay_probe(altered, {**message, "action": "fixture.write", "value": "changed"})))
        score("broker_challenges_did_not_modify_data", {"record": "recoverable-version"}, load(old_app))
        score("backup", "applied", commit(owner, "network-backup", "service-backup", old_app,
                                          {"identity": old_id})["decision"])
        score("bilateral_exit", ["applied", "applied"], [
            commit(reader, "network-exit-reader", "exit", reader, {"operator": peer["operator"]})["decision"],
            commit(owner, "network-exit-owner", "exit", owner, {"operator": other["operator"]})["decision"]])
        score("client_exit_denial", "peer_not_enrolled", read("post-exit").get("reason"))
        excluded = wire(client, old_seen["endpoint"], old_id["certificate"], "withdrawn", "fixture.read")
        score("network_exit_denial", ["destination_policy", None], [excluded["reason"], excluded.get("result")])
        score("fence", "applied", commit(owner, "network-fence", "service-fence", old_app,
                                         {"identity": old_id})["decision"])
        for action in ("fixture.read", "fixture.write"):
            denied = wire(client, old_seen["endpoint"], old_id["certificate"], action, action)
            score(action + "_fenced", ["generation_fenced", None, False],
                  [denied["reason"], denied.get("result"), denied["mutated"]])
        score("old_data_intact", {"record": "recoverable-version"}, load(old_app))
        snapshot = operate(binary, owner, "inspect")
        new_id = identity(new)
        score("clean_restore", [False, "applied"], [new_app.exists(),
              commit(owner, "network-restore", "service-restore", new_app,
                     {"identity": new_id, "backup_sha256": snapshot["service_backup"]["sha256"]})["decision"]])
        score("fresh_serving_identity", True, old_id["certificate"] != new_id["certificate"])
        after = operate(binary, owner, "inspect")
        score("exit_floor_preserved", [snapshot["withdrawn"], snapshot["peer_binding_floors"], 2],
              [after["withdrawn"], after["peer_binding_floors"], after["binding_floor"]])
        new_ready = root / "new-network-ready"
        proc, observed = start([binary, "node", "start", "--config", new, "--ready-out", new_ready], new_ready)
        listeners.append(proc)
        score("stale_peer_still_denied", "destination_policy",
              wire(client, observed["endpoint"], new_id["certificate"], "restore-stale", "fixture.read")["reason"])
        # Fresh, explicit bilateral approvals are required after withdrawal.
        score("replacement_enrollment", "applied",
              commit(reader, "network-new-card", "enroll", reader, network_card(new, observed, "network-new", 2))["decision"])
        score("renewed_client_approval", "applied",
              commit(owner, "network-new-client", "enroll", owner, {**other, "revision": 2})["decision"])
        result = read("network-recovered")
        score("peer_recovered_read", ["recoverable-version", 2, new_id["certificate"]],
              [result.get("result"), result.get("binding_revision"), result.get("endpoint_sha256")])
        for action in ("fixture.read", "fixture.write"):
            denied = wire(client, old_seen["endpoint"], old_id["certificate"], "restored-" + action, action)
            score(action + "_old_after_restore", ["generation_fenced", None, False],
                  [denied["reason"], denied.get("result"), denied["mutated"]])
        score("old_listener_alive", None, old_process.poll())
        score("control_peer_continues", "commonwealth-reference-v1",
              exchange(binary, client, control, "life.reference", "fixture.read", "network-control").get("result"))
        stop(proc)
        score("troubleshooting_locates_transport_failure", "discovery_unavailable",
              read("replacement-unavailable").get("reason"))
        stop(broker_process)
        unavailable = wire(client, old_seen["endpoint"], old_id["certificate"], "broker-stopped", "fixture.read")
        score("external_authority_unavailable_fail_closed", ["authority_unavailable", None, False],
              [unavailable["reason"], unavailable.get("result"), unavailable["mutated"]])
        return {"old": old_id, "new": new_id, "authority_uid": os.getuid(), "old_host_uid": uid,
                "old_audit": Path(exposed["audit"]).read_text().splitlines(),
                "new_audit": Path(load(new)["audit"]).read_text().splitlines()}
    finally:
        for proc in reversed(listeners):
            stop(proc)
        if broker_process:
            stop(broker_process)
        subprocess.run(["sudo", "-n", "chown", "-R", str(os.getuid()), str(public)], check=True)
        isolated.cleanup()


def lifecycle(binary, root, targets, boot, chrome, codex, installation_clicks):
    scripted, guided, reference, counterpart, ext = [root / name for name in
                   ("scripted", "guided", "life-reference", "local-counterpart", "ext-operator")]
    for authority in (scripted, guided, reference, counterpart, ext):
        if authority == guided:
            ready = installation_clicks[-1]
        else:
            ready = operate(binary, authority, "bootstrap", "--name", authority.name)
        check(authority.name + "_bootstrap_credential_roles", 4,
              len(set(ready.get("role_fingerprints", {}).values())))
    target = root / "target"
    plan, permit = approval(binary, scripted, root, "configure", "configure", target,
                            {"name": "fixture-operator", "protocol": 1})
    denied = apply(binary, scripted, target, plan)
    check("no_approval_no_effect", ["approval_required", {}],
          [denied["reason"], operate(binary, scripted, "inspect")["settings"]])
    check("changed_target", "target_changed", apply(binary, scripted, root / "substitute", plan, permit)["reason"])
    modified = root / "modified"
    write(modified, {**load(plan), "payload": {"name": "different", "protocol": 1}})
    check("changed_plan", "plan_changed", apply(binary, scripted, target, modified, permit)["reason"])
    operate(binary, scripted, "rotate", "--confirm")
    check("superseded_approval", "authority_superseded_or_revoked", apply(binary, scripted, target, plan, permit)["reason"])
    plan, permit = approval(binary, scripted, root, "withdrawn", "configure", target,
                            {"name": "fixture-operator", "protocol": 1})
    operate(binary, scripted, "rotate", "--confirm", "--withdraw")
    check("withdrawn_approval", "authority_superseded_or_revoked", apply(binary, scripted, target, plan, permit)["reason"])
    operate(binary, scripted, "rotate", "--confirm")
    plan, permit = approval(binary, scripted, root, "expired", "configure", target,
                            {"name": "fixture-operator", "protocol": 1}, seconds=0)
    check("expired_approval", "approval_expired", apply(binary, scripted, target, plan, permit)["reason"])
    check("denials_preserve_settings", {}, operate(binary, scripted, "inspect")["settings"])
    plan, permit = approval(binary, scripted, root, "valid", "configure", target,
                            {"name": "fixture-operator", "protocol": 1})
    applied = apply(binary, scripted, target, plan, permit)
    check("configure", "applied", applied["decision"])
    check("operation_retry", applied, apply(binary, scripted, target, plan, permit))
    diagnostic = operate(binary, scripted, "diagnostics", "--boundary", "reachability", "--confirm")
    check("diagnostics_public_fields", ["authority_revision", "boundary", "schema"], sorted(diagnostic))
    canary = "PRIVATE-FIXTURE-SECRET-9"
    (scripted / "private-canary").write_text(canary)
    details = {"diagnostic": diagnostic}
    guided_observations = []
    def guided_apply(operation, body, expected):
        return browser_apply(binary, root, boot, chrome, guided, target, operation, body,
                             expected, guided_observations)

    configured = guided_apply("configure", {"name": "fixture-operator", "protocol": 1}, "applied")
    if configured:
        check("browser_setup_parity", operate(binary, scripted, "inspect")["settings"],
              operate(binary, guided, "inspect")["settings"])
    details["browser"] = guided_observations

    def inspect_http(url, data=None, headers=None):
        request = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, response.headers, response.read(8192)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read(8192)

    before_browser_controls = operate(binary, guided, "inspect")
    guide_ready = root / "security-ready"
    isolated_guide, address = start([binary, "operator", "guide", "--authority", guided,
                                     "--ready", guide_ready, "--seconds", "2"], guide_ready)
    try:
        site = urllib.parse.urlsplit(address["url"])
        origin = f"{site.scheme}://{site.netloc}"
        check("guide_missing_session_denied", 403, inspect_http(origin + "/apply", b"confirmed=yes")[0])
        status, headers, page = inspect_http(address["url"])
        check("guide_single_launch", 200, status)
        cookie = headers["Set-Cookie"].split(";")[0]
        csrf = re.search(rb'name="csrf" type="hidden" value="([^"]+)"', page).group(1)
        replay_status, _, replay_page = inspect_http(address["url"])
        check("guide_launch_replay_denied", [403, False], [replay_status, csrf in replay_page])
        check("guide_wrong_origin_denied", 403, inspect_http(origin + "/apply", b"confirmed=yes",
              {"Origin": "http://untrusted.test", "Cookie": cookie})[0])
        unapproved, _, body = inspect_http(origin + "/apply", b"confirmed=yes&csrf=" + csrf,
                                          {"Origin": origin, "Cookie": cookie})
        check("guide_unapproved_mutation_denied", [422, True],
              [unapproved, b"explicit_confirmation_required" in body])
        time.sleep(2.1)
        check("guide_expired_session_denied", 403,
              inspect_http(origin + "/apply", b"confirmed=yes", {"Origin": origin, "Cookie": cookie})[0])
        check("guide_security_denials_preserve_state", before_browser_controls, operate(binary, guided, "inspect"))
    finally:
        stop(isolated_guide)

    # Fixture-local child roots trust only the public issuer bundle.
    bundle = root / "fixture-ca-bundle.pem"
    paths = [x / "node.json" for x in (scripted, reference, counterpart, ext, guided)]
    bundle.write_bytes(b"".join(Path(load(path)["ca"]).read_bytes() for path in paths))
    for path in paths:
        write(path, {**load(path), "ca": str(bundle)})
    client, ref, local, ext_conf, guided_client = paths
    grant = sha(subprocess.check_output(["openssl", "x509", "-in", load(client)["client_certificate"], "-outform", "DER"]))
    guided_grant = sha(subprocess.check_output(["openssl", "x509", "-in",
              load(guided_client)["client_certificate"], "-outform", "DER"]))
    processes = []
    try:
        cards = {}
        for name, cfg in (("reference", ref), ("counterpart", local)):
            ready = root / (name + "-ready")
            write(cfg, {**load(cfg), "participant_grants": [grant, guided_grant]})
            proc, observed = start([binary, "node", "start", "--config", cfg, "--ready-out", ready], ready)
            processes.append(proc)
            exported = operate(binary, Path(load(cfg)["authority"]), "export-card", "--ready", ready,
                               "--out", root / (name + "-public"))
            cards[name] = Path(exported["card"])
            check(name + "_exports_public_card", ["public_card_exported", ["card.json", "operator.pem", "publication.pem"]],
                  [exported["decision"], sorted(path.name for path in cards[name].parent.iterdir())])
        for name in cards:
            check(name + "_locally_accepted", "applied",
                  enroll(binary, root, load(client), cards[name], name)["decision"])
        def request(executable, operator, label, action="fixture.read"):
            return exchange(executable, client, operator, "life.reference", action, label)
        before = request(binary, "life-reference", "before-outage")
        check("reference_before_outage", "commonwealth-reference-v1", before.get("result"))
        baseline_trust = operate(binary, scripted, "inspect")
        baseline_policy = sha(client.read_bytes())
        prior_destination = sha(ref.read_bytes())
        reference_card = load(cards["reference"])
        # Rebind the same locator and serving identity after a temporary fixture outage.
        # Measured from stop request through the first authorized recovered read.
        started = time.monotonic()
        stop(processes[0])
        outage = request(binary, "life-reference", "during-outage")
        check("reference_outage_reached_transport", "discovery_unavailable", outage.get("reason"))
        control = request(binary, "local-counterpart", "local-allow")
        check("counterpart_during_outage", "commonwealth-reference-v1", control.get("result"))
        denied = request(binary, "local-counterpart", "local-deny", "fixture.write")
        check("counterpart_destination_denial", ["denied", None], [denied["decision"], denied.get("result")])
        write(ref, {**load(ref), "listen_port": reference_card["endpoint"][1]})
        ready = root / "reference-recovered"
        proc, recovered = start([binary, "node", "start", "--config", ref, "--ready-out", ready], ready)
        processes.append(proc)
        after = request(binary, "life-reference", "reference-recovered")
        elapsed = round(time.monotonic() - started, 3)
        recovered_trust = operate(binary, scripted, "inspect")
        recovered_policy = sha(client.read_bytes())
        # The restart locator is the sole server configuration change.
        server_policy = load(ref)
        server_policy.pop("listen_port")
        check("reference_recovery_original_enrollment", [baseline_trust, baseline_policy, prior_destination],
              [recovered_trust, recovered_policy, sha(canonical(server_policy))])
        check("reference_recovery_binding", [before["binding_identity"], "commonwealth-reference-v1"],
              [after.get("binding_identity"), after.get("result")])
        check("reference_recovery_within_cloud_bound", True, elapsed <= 15)
        details["reference_recovery"] = {
            "bound_seconds": 15, "elapsed_seconds": elapsed,
            "intervening_actions": ["stop_reference", "probe_reference", "read_counterpart", "deny_counterpart_write",
                                     "restart_same_locator", "read_original_enrollment"],
            "before": {"binding": before["binding_identity"], "signed_binding_sha256": before["signed_binding_sha256"],
                       "trust_sha256": sha(canonical(baseline_trust)), "client_policy_sha256": baseline_policy,
                       "destination_policy_sha256": prior_destination},
            "after": {"binding": after.get("binding_identity"), "signed_binding_sha256": after.get("signed_binding_sha256"),
                      "trust_sha256": sha(canonical(recovered_trust)), "client_policy_sha256": recovered_policy,
                      "destination_policy_sha256": sha(canonical(server_policy))},
            "destination_audit": Path(load(ref)["audit"]).read_text().splitlines()}
        new_card = cards["reference"]

        guided_binary = targets["guided-base"] / "bin/commonwealth"
        guided_enrollment = browser_apply(guided_binary, root, boot, chrome, guided, guided, "enroll",
                                          approved_card(cards["counterpart"]), "applied", guided_observations)
        if not guided_enrollment:
            raise RuntimeError("guided counterpart enrollment unavailable")
        details["release_selection"] = []
        for label, choice, success in (("upgrade", "step9-upgrade", True),
                                       ("incompatible", "step9-incompatible", False),
                                       ("rollback", "step9-base", True)):
            operation = "rollback" if label == "rollback" else "upgrade"
            outcomes = []
            for surface, owner, config, name, installer, workload in (
                    ("cli", scripted, client, choice, binary, grant),
                    ("browser", guided, guided_client, choice.replace("step9-", "guided-"), guided_binary, guided_grant)):
                chosen = targets[name]
                old = operate(installer, owner, "inspect").get("selected_configuration")
                candidate = {"candidate_sha256": load(chosen / ".release-proof.json")["release_sha256"],
                             "configuration": str(chosen)}
                expected = "applied" if success else "denied"
                if surface == "browser":
                    result = browser_apply(installer, root, boot, chrome, owner, owner, operation,
                                           candidate, expected, guided_observations)
                    if not result:
                        raise RuntimeError("guided release selection unavailable: " + label)
                else:
                    plan, permit = approval(installer, owner, root, label, operation, owner, candidate)
                    result = apply(installer, owner, owner, plan, permit)
                selected = operate(installer, owner, "inspect")["selected_configuration"]
                check(label + "_" + surface + "_selection", [expected, str(chosen) if success else old],
                      [result["decision"], selected])
                executable = Path(selected) / "bin/commonwealth"
                digest = sha(executable.read_bytes())
                request_id = f"release-{label}-{surface}"
                observed = exchange(executable, config, "local-counterpart", "life.reference", "fixture.read", request_id)
                audit = [row for row in map(json.loads, Path(load(local)["audit"]).read_text().splitlines())
                         if row["request_id"] == request_id]
                check(label + "_" + surface + "_selected_exchange",
                      ["commonwealth-reference-v1", str(executable), digest, [(workload, "allowed")]],
                      [observed.get("result"), observed.get("origin", {}).get("entrypoint"),
                       observed.get("origin", {}).get("entrypoint_sha256"),
                       [(row["client_sha256"], row["decision"]) for row in audit]])
                outcomes.append({"surface": surface, "decision": result["decision"], "reason": result.get("reason"),
                                 "executable": str(executable), "executable_sha256": digest,
                                 "authority": str(owner), "request_id": request_id, "destination_audit": audit})
            check(label + "_guided_parity", [outcomes[0]["decision"], outcomes[0]["reason"], outcomes[0]["executable_sha256"]],
                  [outcomes[1]["decision"], outcomes[1]["reason"], outcomes[1]["executable_sha256"]])
            details["release_selection"].append({"case": label, "observations": outcomes})
        details["counterpart_audit"] = Path(load(local)["audit"]).read_text().splitlines()

        extension = targets["step9-base"] / "extension"
        source = extension / "status_peer.py"
        artifact = root / "status-peer.pyc"
        built = run(sys.executable, "-c",
                    "import py_compile,sys; py_compile.compile(sys.argv[1],cfile=sys.argv[2],dfile='status_peer.py',doraise=True)",
                    source, artifact)
        check("independent_extension_build", [0, True], [built.returncode, artifact.is_file()])
        write(ext_conf, {**load(ext_conf), "client_grant": grant})
        bad = root / "invalid-contract"
        write(bad, {**load(extension / "contract.json"), "protocol": 2})
        failed_ready = root / "incompatible-ready"
        attempt = run(sys.executable, artifact, "--config", ext_conf, "--contract", bad, "--ready", failed_ready)
        check("extension_incompatible_pre_readiness", [True, False],
              [attempt.returncode != 0, failed_ready.exists()])
        ready = root / "extension-ready"
        proc, observed = start([sys.executable, artifact, "--config", ext_conf, "--contract",
                                extension / "contract.json", "--ready", ready], ready)
        processes.append(proc)
        extension_card = card(root, "extension", load(ext_conf), observed)
        check("extension_operator_publication_accepted", "applied",
              enroll(binary, root, load(client), extension_card, "extension")["decision"])
        for label, version in (("extension-first", 1), ("extension-unsupported", 2), ("extension-after", 1)):
            r = exchange(binary, client, "ext-operator", "extension.status", "status.read", label, version)
            check(label, ["allowed", True, {"schema": 1, "status": "ready"}] if version == 1
                  else ["unsupported_version", False, None],
                  [r["decision"], r["protected_handler_invoked"], r.get("result")])
        details["extension"] = {"source_sha256": sha(source.read_bytes()), "artifact_sha256": sha(artifact.read_bytes()),
                                "contract_sha256": sha((extension / "contract.json").read_bytes()),
                                "published": observed, "audit": Path(load(ext_conf)["audit"]).read_text().splitlines()}
        dedicated = root / "fenced-service"
        operate(binary, dedicated, "bootstrap", "--name", "fenced-service")
        dedicated_config = dedicated / "node.json"
        separate = load(dedicated_config)
        bundle.write_bytes(bundle.read_bytes() + Path(separate["ca"]).read_bytes())
        write(dedicated_config, {**separate, "ca": str(bundle)})
        details["network_lifecycle"] = network_lifecycle(binary, root, client, dedicated_config,
                                                           "local-counterpart")
        guided_root = root / "guided-network"
        guided_root.mkdir()
        guided_owner = guided_root / "authority"
        operate(binary, guided_owner, "bootstrap", "--name", "guided-fenced-service")
        guided_owner_config = guided_owner / "node.json"
        owner_config = load(guided_owner_config)
        bundle.write_bytes(bundle.read_bytes() + Path(owner_config["ca"]).read_bytes())
        write(guided_owner_config, {**owner_config, "ca": str(bundle)})
        guided_binary = targets["guided-base"] / "bin/commonwealth"
        guided_clicks = []
        peer = approved_card(cards["counterpart"])
        enrolled = browser_apply(guided_binary, guided_root, boot, chrome, guided, guided, "enroll",
                                 peer, "applied", guided_clicks)
        if enrolled:
            details["guided_network_lifecycle"] = network_lifecycle(
                guided_binary, guided_root, guided_client, guided_owner_config, "local-counterpart",
                (boot, chrome, guided_clicks))
        details["guided_network_clicks"] = guided_clicks
        approved = approved_card(new_card)
        plan, permit = approval(binary, scripted, root, "enroll-check", "enroll", target, approved)
        change = root / "changed-card"
        write(change, {**load(plan), "payload": {**approved, "endpoint": ["127.0.0.1", 1]}})
        check("changed_complete_card_denied", "peer_card_changed", apply(binary, scripted, target, change, permit)["reason"])
        prior_reference = Path(load(ref)["audit"]).read_bytes()
        plan, permit = approval(binary, scripted, root, "exit", "exit", target, {"operator": "life-reference"})
        check("exit_authority_operation", "applied", apply(binary, scripted, target, plan, permit)["decision"])
        check("exited_peer_rejected_at_installed_client", "peer_not_enrolled",
              exchange(binary, client, "life-reference", "life.reference", "fixture.read", "exited").get("reason"))
        state = operate(binary, scripted, "inspect")
        restored = {"data": "older-application"}
        payload = {"application": restored, "backup_sha256": sha(canonical(restored)), "binding_revision": 2,
                   "authority_revision": state["revision"], "ingress_fenced": True, "writer_fenced": True}
        plan, permit = approval(binary, scripted, root, "restore-no-fence", "restore", target,
                                {**payload, "writer_fenced": False})
        check("restore_without_fence", "protected_service_closed", apply(binary, scripted, target, plan, permit)["reason"])
        plan, permit = approval(binary, scripted, root, "restore", "restore", target, payload)
        check("restore_approved_state", "applied", apply(binary, scripted, target, plan, permit)["decision"])
        newer = operate(binary, scripted, "inspect")
        check("restore_preserves_exit_and_revision", [["life-reference"], False, 2, restored],
              [newer["withdrawn"], "life-reference" in newer["peers"], newer["binding_floor"], newer["application"]])
        check("exited_peer_rejected_after_older_state_restore", "peer_not_enrolled",
              exchange(binary, client, "life-reference", "life.reference", "fixture.read", "exit-after-restore").get("reason"))

        check("reference_listener_stayed_running_through_exit_and_restore", True, processes[-2].poll() is None)
        check("exited_client_generated_no_destination_request", sha(prior_reference),
              sha(Path(load(ref)["audit"]).read_bytes()))
        check("unrelated_counterpart_operated_after_exit_and_restore", "commonwealth-reference-v1",
              request(binary, "local-counterpart", "control-after-restore").get("result"))
        details["counterpart_audit"] = Path(load(local)["audit"]).read_text().splitlines()

    finally:
        for process in reversed(processes):
            stop(process)

    # The host process has no ability to read the private authority. It consumes
    # a separate public workspace and an allowlisted reviewed diagnostic.
    if codex and os.getenv("CW_HOST_PUBLIC"):
        public = Path(os.environ["CW_HOST_PUBLIC"])
        ws = public / "workspace"
        (ws / ".agents/plugins").mkdir(parents=True, exist_ok=True)
        shutil.copytree(targets["step9-base"] / "plugin", ws / "operator-help")
        write(ws / ".agents/plugins/marketplace.json", {"name": "commonwealth-fixture", "plugins": [
            {"name": "commonwealth-operator-help", "source": {"source": "local", "path": "./operator-help"},
             "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}}]})
        shutil.copyfile(boot / "host9.py", public / "host9.py")
        write(public / "reviewed.json", diagnostic)
        done = run("sudo", "-n", "runuser", "-u", "nobody", "--", "test", "-r", scripted / "private-canary")
        check("host_private_read_denied", 1, done.returncode)
        done = run("sudo", "-n", "runuser", "-u", "nobody", "--", "python3", public / "host9.py",
                   codex, public, public / "host.json", limit=28)
        archived_host = run("sudo", "-n", "runuser", "-u", "nobody", "--", "cat", public / "host.json")
        details["host"] = json.loads(archived_host.stdout) if archived_host.returncode == 0 and archived_host.stdout else {
            "verdict": "UNVERIFIED", "exit": done.returncode}
        manifest = ws / "operator-help/plugin.json"
        details["host"]["binary_sha256"] = sha(Path(codex).read_bytes())
        details["host"]["plugin_manifest_sha256"] = sha(manifest.read_bytes())
        proposed = public / "proposed-plan.json"
        shutil.copyfile(plan, proposed)
        public_kit = public / "verified-kit"
        shutil.copytree(targets["step9-base"], public_kit)
        public_binary = public_kit / "bin/commonwealth"
        public_kit.chmod(0o755)
        for directory in public_kit.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        prior = operate(binary, scripted, "inspect")
        proposal = command("sudo", "-n", "runuser", "-u", "nobody", "--", public_binary,
                 "operator", "apply", "--authority", scripted, "--plan", proposed, "--target", target)
        check("host_unapproved_change_denied_by_installed_cli", ["approval_required", prior],
              [proposal.get("reason"), operate(binary, scripted, "inspect")])
        public_bytes = b"".join(p.read_bytes() for p in (ws / "operator-help").rglob("*") if p.is_file())
        check("public_material_contains_no_secret_canary", False,
              canary.encode() in (public_bytes + canonical(diagnostic) + canonical(details["host"])))
    else:
        details["host"] = {"verdict": "UNVERIFIED", "reason": "pinned Codex CLI unavailable"}
    return details


def main():
    parser = argparse.ArgumentParser()
    for name in ("bootstrap", "release", "out", "revision", "chrome", "codex"):
        parser.add_argument(f"--{name}", default="")
    args = parser.parse_args()
    detail = {}
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="cw-step9-") as work:
            root = Path(work)
            boot, release = Path(args.bootstrap), Path(args.release)
            check("loopback_isolated", ["lo"], sorted(name for _, name in socket.if_nameindex()))
            targets, installations = {}, {}
            for name, version in (("step9-base", "0.1.0-test.2"), ("step9-upgrade", "0.1.0-test.3"),
                                  ("step9-incompatible", "0.1.0-test.3")):
                targets[name], installations[name] = install(boot, release, root, name, version, args.revision)
            guided_root = root / "guided-install"
            guided_root.mkdir()
            targets["guided-base"], installation_clicks = install_guided(boot, release, guided_root,
                args.revision, args.chrome, root / "guided")
            for suffix in ("upgrade", "incompatible"):
                staging = guided_root / suffix
                staging.mkdir()
                targets["guided-" + suffix], installations["guided-" + suffix] = install(boot, release, staging,
                    "step9-" + suffix, "0.1.0-test.3", args.revision)
            for field in ("release_sha256", "inventory"):
                proofs = [load(targets[name] / ".release-proof.json")[field] for name in ("step9-base", "guided-base")]
                check("install_parity_" + field, proofs[0], proofs[1])
            detail = {"installations": installations, "installation_clicks": installation_clicks, **lifecycle(targets["step9-base"] / "bin/commonwealth",
                      root, targets, boot, args.chrome, args.codex, installation_clicks)}
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        error = str(exc)
    matched = not any(not row["matches"] for row in CHECKS)
    unverified = []
    if not detail.get("installation_clicks") or not detail.get("guided_network_lifecycle"):
        unverified.append("guided parity for installation, exchange and lifecycle")
    if not detail.get("network_lifecycle"):
        unverified.append("network peer exit and fenced restore with fresh serving identity")
    if detail.get("host", {}).get("verdict") != "PASS":
        unverified.append("Codex local installation and enabled-skill discovery")
    browser = detail.get("browser")
    if not browser or any(row.get("verdict") == "UNVERIFIED" for row in browser):
        unverified.append("browser setup clicks")
    verdict = "FAIL" if not matched else "UNVERIFIED" if unverified or error else "PASS"
    receipt = {"revision": args.revision, "verdict": verdict, "incomplete": error,
               "checks": CHECKS, "commands": COMMANDS, "detail": detail, "unverified_gates": unverified}
    write(args.out, receipt)
    print(json.dumps({"step9": verdict, "checks": len(CHECKS), "incomplete": error}))
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
