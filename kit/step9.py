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
            except ValueError:
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


def lifecycle(binary, root, targets, boot, chrome, codex):
    scripted, guided, reference, counterpart, ext = [root / name for name in
                   ("scripted", "guided", "life-reference", "local-counterpart", "ext-operator")]
    for authority in (scripted, guided, reference, counterpart, ext):
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
    if chrome:
        address = root / "guide-ready"
        guide, ready = start([binary, "operator", "guide", "--authority", guided, "--ready", address], address)
        try:
            # Browser commands contain a private one-time launch URL and are omitted from receipts.
            browser = subprocess.run([os.environ.get("CW_NODE", "node"), str(boot / "browser9.mjs"), chrome, ready["url"], str(target)],
                                     capture_output=True, timeout=20)
            if browser.returncode:
                details["browser"] = {"verdict": "UNVERIFIED", "reason": "browser fixture exited unsuccessfully"}
            else:
                details["browser"] = json.loads(browser.stdout)
                check("browser_setup_parity", operate(binary, scripted, "inspect")["settings"],
                  operate(binary, guided, "inspect")["settings"])
        finally:
            stop(guide)
    else:
        details["browser"] = {"verdict": "UNVERIFIED", "reason": "headless browser unavailable"}

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
    paths = [x / "node.json" for x in (scripted, reference, counterpart, ext)]
    bundle.write_bytes(b"".join(Path(load(path)["ca"]).read_bytes() for path in paths))
    for path in paths:
        write(path, {**load(path), "ca": str(bundle)})
    client, ref, local, ext_conf = paths
    grant = sha(subprocess.check_output(["openssl", "x509", "-in", load(client)["client_certificate"], "-outform", "DER"]))
    processes = []
    try:
        cards = {}
        for name, cfg in (("reference", ref), ("counterpart", local)):
            ready = root / (name + "-ready")
            write(cfg, {**load(cfg), "participant_grants": [grant]})
            proc, observed = start([binary, "node", "start", "--config", cfg, "--ready-out", ready], ready)
            processes.append(proc)
            cards[name] = card(root, name, load(cfg), observed)
        for name in cards:
            check(name + "_locally_accepted", "applied",
                  enroll(binary, root, load(client), cards[name], name)["decision"])
        def request(executable, operator, label, action="fixture.read"):
            return exchange(executable, client, operator, "life.reference", action, label)
        check("reference_before_outage", "commonwealth-reference-v1",
              request(binary, "life-reference", "before-outage").get("result"))
        stop(processes[0])
        check("reference_outage_reached_transport", "discovery_unavailable",
              request(binary, "life-reference", "during-outage").get("reason"))
        check("counterpart_during_outage", "commonwealth-reference-v1",
              request(binary, "local-counterpart", "local-allow").get("result"))
        denied = request(binary, "local-counterpart", "local-deny", "fixture.write")
        check("counterpart_destination_denial", ["denied", None], [denied["decision"], denied.get("result")])
        details["counterpart_audit"] = Path(load(local)["audit"]).read_text().splitlines()
        write(ref, {**load(ref), "participant_grants": [grant]})
        ready = root / "reference-recovered"
        proc, recovered = start([binary, "node", "start", "--config", ref, "--ready-out", ready], ready)
        processes.append(proc)
        new_card = card(root, "reference-recovered", load(ref), recovered)
        check("reference_recovery_distinct_exchange", ["applied", "commonwealth-reference-v1"],
              [enroll(binary, root, load(client), new_card, "reference-recovered")["decision"],
               request(binary, "life-reference", "reference-recovered").get("result")])

        # Signed, independently verified releases were staged before selection.
        for label, choice, success in (("upgrade", "step9-upgrade", True),
                                       ("incompatible", "step9-incompatible", False),
                                       ("rollback", "step9-base", True)):
            chosen = targets[choice]
            profile = load(chosen / "profile.json")
            old = operate(binary, scripted, "inspect").get("selected_configuration")
            candidate = {"candidate_sha256": load(chosen / ".release-proof.json")["release_sha256"],
                         "configuration": str(chosen)}
            operation = "rollback" if label == "rollback" else "upgrade"
            plan, permit = approval(binary, scripted, root, label, operation, target, candidate)
            result = apply(binary, scripted, target, plan, permit)
            selected = operate(binary, scripted, "inspect")["selected_configuration"]
            check(label + "_selection", ["applied" if success else "denied", str(chosen) if success else old],
                  [result["decision"], selected])
            check(label + "_selected_client_exchange", "commonwealth-reference-v1",
                  request(Path(selected) / "bin/commonwealth", "local-counterpart", label).get("result"))

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
    finally:
        for process in reversed(processes):
            stop(process)

    approved = approved_card(new_card)
    plan, permit = approval(binary, scripted, root, "enroll-check", "enroll", target, approved)
    change = root / "changed-card"
    write(change, {**load(plan), "payload": {**approved, "endpoint": ["127.0.0.1", 1]}})
    check("changed_complete_card_denied", "peer_card_changed", apply(binary, scripted, target, change, permit)["reason"])
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
            detail = {"installations": installations, **lifecycle(targets["step9-base"] / "bin/commonwealth",
                      root, targets, boot, args.chrome, args.codex)}
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        error = str(exc)
    matched = not any(not row["matches"] for row in CHECKS)
    unverified = ["guided parity for installation, exchange and lifecycle",
                  "network peer exit and fenced restore with fresh serving identity"]
    if detail.get("host", {}).get("verdict") != "PASS":
        unverified.append("Codex local installation and enabled-skill discovery")
    browser = detail.get("browser")
    if not browser or (isinstance(browser, dict) and browser.get("verdict") == "UNVERIFIED"):
        unverified.append("browser setup clicks")
    verdict = "FAIL" if not matched else "UNVERIFIED" if unverified or error else "PASS"
    receipt = {"revision": args.revision, "verdict": verdict, "incomplete": error,
               "checks": CHECKS, "commands": COMMANDS, "detail": detail, "unverified_gates": unverified}
    write(args.out, receipt)
    print(json.dumps({"step9": verdict, "checks": len(CHECKS), "incomplete": error}))
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
