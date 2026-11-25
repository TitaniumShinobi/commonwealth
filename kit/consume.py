"""Independent clean-run fixture driver. Runtime code comes only from the installed Kit."""
import argparse
import json
import os
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from verify_kit import ARCHIVE, VERSION, approve, canonical, load, sha, write

CHECKS = []
COMMANDS = []


def check(name, expected, observed):
    CHECKS.append({"case": name, "expected": expected, "observed": observed, "matches": expected == observed})


def execute(*argv):
    arguments = list(map(str, argv))
    COMMANDS.append(arguments)
    done = subprocess.run(arguments, capture_output=True, timeout=8)
    return done


def command(*argv):
    done = execute(*argv)
    if len(done.stdout) > 65536:
        raise RuntimeError("excess command output")
    return json.loads(done.stdout)


def ssl(*args):
    done = execute("openssl", *args)
    if done.returncode:
        raise RuntimeError(f"OpenSSL setup failed: {args[0]}")
    return done.stdout


def verification(boot, releases, work, revision):
    verifier = [sys.executable, boot / "verify_kit.py"]
    trust = load(boot / "trust.json")
    check("coordinate", [revision, VERSION], [trust["source_revision"], trust["version"]])
    check("independent_trust_input", True, boot.resolve() != releases.resolve()
          and not (releases / "valid" / "release-root.pem").exists())
    sentinel = work / "outside-sentinel"
    sentinel.write_text("unchanged\n")

    def prepare(label, artifact, root=None, source=None):
        directory = releases / artifact if source is None else source
        target = work / f"installed-{label}"
        plan = work / f"plan-{label}.json"
        result = command(*verifier, "plan", "--manifest", directory / "manifest.json",
                         "--signature", directory / "manifest.sig", "--archive", directory / ARCHIVE,
                         "--trust-root", root or boot / "release-root.pem", "--target", target,
                         "--fingerprint", trust["fingerprint"], "--revision", revision, "--out", plan)
        return result, target, plan

    def approve_file(plan, label, change=None):
        p = load(plan)
        approval = work / f"approval-{label}.json"
        write(approval, approve(p))
        if change:
            p["inputs"]["revision"] = "0" * 40
            write(plan, p)
        return approval

    def apply(target, plan, approval=None):
        extra = ["--approval", approval] if approval else []
        return command(*verifier, "apply", "--plan", plan, "--target", target, *extra)

    negatives = [
        ("missing_root", "valid", work / "missing.pem", "trust_root_missing"),
        ("wrong_root", "valid", boot / "wrong-root.pem", "trust_root_mismatch"),
        ("candidate_own_key", "alternate", None, "manifest_signature_invalid"),
    ]
    for label, artifact, root, reason in negatives:
        r, target, plan = prepare(label, artifact, root)
        check(label, [reason, False, False], [r.get("reason"), target.exists(), plan.exists()])
    check("candidate_supplied_key_ignored", True, (releases / "alternate" / "candidate-root.pem").is_file())
    for label, changed, reason in (
            ("altered_signature", "manifest.sig", "manifest_signature_invalid"),
            ("altered_manifest", "manifest.json", "manifest_signature_invalid"),
            ("altered_archive", ARCHIVE, "artifact_digest_or_size_mismatch")):
        variant = work / label
        shutil.copytree(releases / "valid", variant)
        path = variant / changed
        path.write_bytes(path.read_bytes() + b"x")
        r, target, plan = prepare(label, "valid", source=variant)
        check(label, [reason, False, False], [r.get("reason"), target.exists(), plan.exists()])
    r, target, plan = prepare("forbidden", "forbidden")
    check("forbidden_archive_signature_valid", "verified_plan", r["decision"])
    r = apply(target, plan, approve_file(plan, "forbidden"))
    check("forbidden_archive_member", ["forbidden_archive_member", False, "unchanged\n", []],
          [r.get("reason"), target.exists(), sentinel.read_text(), [str(p) for p in work.glob(".kit-stage-*")]])
    r, target, plan = prepare("missing-approval", "valid")
    r = apply(target, plan)
    check("missing_approval", ["approval_required", False], [r.get("reason"), target.exists()])
    r, target, plan = prepare("changed-plan", "valid")
    r = apply(target, plan, approve_file(plan, "changed-plan", True))
    check("changed_plan", ["approved_plan_changed", False], [r.get("reason"), target.exists()])
    r, target, plan = prepare("changed-target", "valid")
    other = work / "substituted"
    r = apply(other, plan, approve_file(plan, "changed-target"))
    check("changed_target", ["approved_target_changed", False, False],
          [r.get("reason"), target.exists(), other.exists()])
    r, target, plan = prepare("valid", "valid")
    check("install_target_absent", True, not target.exists())
    approved = approve_file(plan, "valid")
    receipt = apply(target, plan, approved)
    check("installed", "installed", receipt["decision"])
    check("staging_clean", [], [str(p) for p in work.glob(".kit-stage-*")])
    r = apply(target, plan, approved)
    check("existing_install_preserved", ["target_already_exists", receipt["inventory"]["bin/commonwealth"]],
          [r.get("reason"), sha((target / "bin/commonwealth").read_bytes())])
    return target, receipt, trust, load(approved)


def new_key(folder, name):
    private, public = folder / f"{name}.key", folder / f"{name}.pub"
    ssl("genpkey", "-algorithm", "Ed25519", "-out", private)
    private.chmod(0o600)
    public.write_bytes(ssl("pkey", "-in", private, "-pubout"))
    return private, public


def configure(work, name, ca, ca_key, serial):
    folder = work / name
    folder.mkdir()
    key, _ = new_key(folder, "endpoint" if name != "participant" else "workload")
    operator, operator_pub = new_key(folder, "operator")
    publisher, publisher_pub = new_key(folder, "publication")
    csr, cert = folder / "request.pem", folder / "certificate.pem"
    ssl("req", "-new", "-key", key, "-subj", f"/CN={name}", "-out", csr)
    extension = folder / "extensions"
    extension.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\n")
    ssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-set_serial", str(serial),
        "-days", "1", "-extfile", extension, "-out", cert)
    state, config = folder / "peer-state.json", folder / "config.json"
    write(state, {"peers": {}})
    write(config, {"host": "127.0.0.1", "operator": name, "service": "life.reference",
                   "ca": str(ca), "certificate": str(cert), "tls_key": str(key),
                   "operator_key": str(operator), "operator_public": str(operator_pub),
                   "publication_key": str(publisher), "publication_public": str(publisher_pub),
                   "state": str(state), "audit": str(folder / "requests.ndjson")})
    return config


def setup(binary, work, name, config, mode):
    target, planned, approval = work / f"setup-{name}", work / f"{name}-plan", work / f"{name}-approval"
    check(name + "_empty_before_setup", False, target.exists())
    result = command(binary, "setup", "plan", "--mode", mode, "--config", config, "--target", target, "--out", planned)
    check(name + "_setup_plan", "planned", result["decision"])
    write(approval, approve(load(planned)))
    applied = command(binary, "setup", "apply", "--plan", planned, "--target", target, "--approval", approval)
    check(name + "_setup_apply", "applied", applied["decision"])
    return target / "config.json", load(approval), applied["origin"]


def node(binary, cfg, ready):
    args = list(map(str, [binary, "node", "start", "--config", cfg, "--ready-out", ready]))
    COMMANDS.append(args)
    log = ready.with_suffix(".log").open("wb")
    try:
        proc = subprocess.Popen(args, stdout=log, stderr=log)
    finally:
        log.close()
    until = time.monotonic() + 5
    while not ready.is_file() and proc.poll() is None and time.monotonic() < until:
        time.sleep(0.025)
    if not ready.is_file():
        proc.kill()
        proc.wait()
        raise RuntimeError(f"listener failed readiness: {ready.with_suffix('.log').read_text()[-1500:]}")
    return proc, load(ready)


def card_for(work, cfg, readiness):
    raw = load(cfg)
    card = work / f"{readiness['operator']}-card.json"
    write(card, {**readiness, "operator_public": raw["operator_public"],
                 "publication_public": raw["publication_public"]})
    return card


def runtime(target, work):
    binary = target / "bin/commonwealth"
    ca_key, _ = new_key(work, "ca")
    ca = work / "ca.pem"
    ssl("req", "-x509", "-new", "-key", ca_key, "-subj", "/CN=Commonwealth test only",
        "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-out", ca)
    life = configure(work, "life-reference", ca, ca_key, 1)
    participant = configure(work, "participant", ca, ca_key, 2)
    operator_source = configure(work, "operator-node", ca, ca_key, 3)
    participant_id = sha(ssl("x509", "-in", load(participant)["certificate"], "-outform", "DER"))
    write(life, {**load(life), "participant_grants": [participant_id]})
    operator, op_approval, setup_origin = setup(binary, work, "operator", operator_source, "node")
    launched = []
    origins = [setup_origin]
    approvals = {"node": op_approval}
    results = {}
    audit_file = Path(load(life)["audit"])
    def read_audit():
        return [json.loads(line) for line in audit_file.read_text().splitlines()] if audit_file.exists() else []

    def start(config, name):
        process, ready = node(binary, config, work / f"{name}-ready.json")
        launched.append((process, ready["endpoint"]))
        origins.append(ready["origin"])
        check(name + "_listener_identity", [True, "127.0.0.1", process.pid, sha(config.read_bytes())],
              [ready["listener"] == "ready", ready["endpoint"][0], ready["origin"]["pid"], ready["configuration_sha256"]])
        return ready

    def enroll(config, reference, accepted, part, label):
        state = load(config)["state"]
        approval = work / f"{label}-local.json"
        write(approval, {"actor": "fixture-local-operator", "accept": accepted,
                         "operator_sha256": load(reference)["operator_sha256"]})
        approvals[label] = load(approval)
        r = command(binary, part, "trust" if part == "service" else "enroll",
                    "--state", state, "--reference", reference, "--approval", approval)
        origins.append(r["origin"])
        return r

    def request(config, peer, name, action, part="service"):
        r = command(binary, part, "request" if part == "service" else "exchange",
                    "--state", load(config)["state"], "--config", config, "--peer", peer,
                    "--service", "life.reference", "--action", action, "--request-id", name)
        origins.append(r["origin"])
        results[name] = r
        return r

    try:
        life_ready = start(life, "life")
        op_ready = start(operator, "operator")
        cards = {key: card_for(work, config, ready) for key, config, ready in
                 (("life", life, life_ready), ("operator", operator, op_ready))}
        refused = enroll(operator, cards["life"], False, "peer", "refused-peer")
        refused_exchange = request(operator, "life-reference", "refused-exchange", "fixture.read", "peer")
        check("refused_local_enrollment", ["local_reference_declined", "peer_not_enrolled", {}, {}, []],
              [refused.get("reason"), refused_exchange.get("reason"), load(load(operator)["state"])["peers"],
               load(load(life)["state"])["peers"], read_audit()])
        check("local_service_acceptance", "locally_enrolled",
              enroll(participant, cards["life"], True, "service", "participant-peer")["decision"])
        before = len(read_audit())
        (work / "life-reference" / "wrong-binding").write_text("0" * 64)
        mismatch = request(participant, "life-reference", "endpoint-mismatch", "fixture.read")
        (work / "life-reference" / "wrong-binding").unlink()
        check("endpoint_mismatch_sends_no_protected_request", ["reference_identity_mismatch", before],
              [mismatch.get("reason"), len(read_audit())])
        for name, action in (("service-allow", "fixture.read"), ("service-deny", "fixture.write")):
            request(participant, "life-reference", name, action)
        check("separate_acceptance_on_both_peers", ["locally_enrolled", "locally_enrolled"],
              [enroll(operator, cards["life"], True, "peer", "operator-peer")["decision"],
               enroll(life, cards["operator"], True, "peer", "life-peer")["decision"]])
        for name, action in (("peer-allow", "fixture.read"), ("peer-deny", "fixture.write")):
            request(operator, "life-reference", name, action, "peer")
        audit = read_audit()
        check("no_extra_protected_requests", ["service-allow", "service-deny", "peer-allow", "peer-deny"],
              [event["request_id"] for event in audit])
        for event in audit:
            name = event["request_id"]
            positive = name.endswith("allow")
            r = results[name]
            check(name + "_correlated", ["allowed" if positive else "denied", positive, False, name, True,
                                        "commonwealth-reference-v1" if positive else None,
                                        participant_id if name.startswith("service") else op_ready["serving_sha256"]],
                  [event["decision"], event["disclosed"], event["mutated"], r["request_id"],
                   r["binding_verified"], r.get("result"), event["client_sha256"]])
        lab_source = work / "lab-source.json"
        write(lab_source, {**{k: life_ready[k] for k in ("endpoint", "serving_sha256")},
                           "node_config": str(participant), "adapter": "simulation-v1"})
        lab, lab_approval, lab_origin = setup(binary, work, "lab", lab_source, "lab")
        origins.append(lab_origin)
        approvals["lab"] = lab_approval
        lab_check = command(binary, "lab", "check", "--config", lab)
        check("lab_readiness", [True, True, "Simulation"],
              [lab_check["node_reachable"], lab_check["adapter_ready"], lab_check["scope"]])
        origins.append(lab_check["origin"])
        conformance = load(target / "fixtures/conformance.json")
        simulation = load(target / "fixtures/simulation.json")
        check("installed_conformance_fixture", ["fixture.read", "fixture.write"],
              [conformance["allowed"], conformance["denied"]])
        def lab_run(scenario):
            value = command(binary, "lab", "run", "--config", lab, "--template", simulation["template"],
                            "--seed", simulation["seed"], "--scenario", scenario)
            origins.append(value.pop("origin"))
            check(scenario + "_adapter_origin", str(target / "lib/simulation_adapter.py"), value["adapter_origin"])
            return value
        herald, timeout, repeated = lab_run("herald"), lab_run("confirm-timeout"), lab_run("herald")
        empty = {"lab-a": 0, "lab-b": 0}
        for label, expected, record in (("lab_herald", "modeled_herald", herald),
                                        ("lab_timeout", "confirmation_timeout", timeout)):
            check(label, [expected, empty, "no_current_reservation", empty, True],
                  [record["decision"], record["allocations"], record["trace"][0]["result"],
                   record["trace"][-1]["allocations"],
                   all(event["scope"] == "Simulation" for event in record["trace"])])
        check("lab_semantic_replay", herald, repeated)
        unsupported = work / "unsupported-lab.json"
        write(unsupported, {**load(lab), "adapter": "unknown"})
        bad = command(binary, "lab", "check", "--config", unsupported)
        check("unsupported_adapter", ["adapter_version_unsupported", True, False, 0],
              [bad["decision"], bad["node_reachable"], bad["adapter_ready"], bad["reservations_created"]])
        origins += [bad["origin"], *(row["server"] for row in audit)]
        check("installed_execution_origins", True, all(
            origin["entrypoint"] == str(binary) and origin["module"] == str(target / "lib/runtime.py")
            and origin["entrypoint_sha256"] == sha(binary.read_bytes())
            and origin["module_sha256"] == sha((target / "lib/runtime.py").read_bytes()) for origin in origins))
        return {"reference": life_ready, "operator": op_ready, "origins": origins, "approvals": approvals,
                "requests": results, "server_audit": audit, "simulation": [herald, timeout, bad]}
    finally:
        for process, endpoint in launched:
            process.terminate()
            try:
                process.wait(2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            try:
                with socket.create_connection(tuple(endpoint), timeout=0.4):
                    still_open = True
            except OSError:
                still_open = False
            check("listener_reaped_" + str(endpoint[1]), False, still_open)


def main():
    parser = argparse.ArgumentParser()
    for key in ("bootstrap", "release", "out", "revision"):
        parser.add_argument(f"--{key}", required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    receipt = {"revision": args.revision, "run": os.getenv("GITHUB_RUN_ID"),
               "workflow_revision": os.getenv("GITHUB_WORKFLOW_SHA"),
               "openssl": ssl("version").decode().strip(), "install_source": "archive_only",
               "limits": {"address_space_bytes": 1024 ** 3, "listener_ready_seconds": 5}}
    error = None
    try:
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        ipv6 = Path("/proc/net/ipv6_route").read_text().splitlines()
        check("loopback_only_network", [[], ["lo"], True],
              [routes, sorted(p.name for p in Path("/sys/class/net").iterdir()),
               all(line.split()[-1] == "lo" for line in ipv6)])
        if not CHECKS[-1]["matches"]:
            raise RuntimeError("consumer network namespace is not isolated")
        with tempfile.TemporaryDirectory(prefix="cw-kit-consumer-") as directory:
            root = Path(directory)
            bound, install, trust, approval = verification(Path(args.bootstrap), Path(args.release), root, args.revision)
            receipt.update(installation=install, trust=trust, install_approval=approval)
            receipt["runtime"] = runtime(bound, root)
        check("consumer_workspace_and_keys_removed", False, root.exists())
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        error = str(exc)
    verdict = "FAIL" if any(not item["matches"] for item in CHECKS) else "UNVERIFIED" if error else "PASS"
    receipt.update(verdict=verdict, incomplete=error, checks=CHECKS, commands=COMMANDS)
    body = canonical(receipt)
    if len(body) > 2 * 1024 ** 2:
        raise SystemExit("receipt bound exceeded")
    Path(args.out).write_bytes(body)
    print(canonical({"verdict": verdict, "checks": len(CHECKS), "incomplete": error}).decode(), end="")
    return {"PASS": 0, "FAIL": 1, "UNVERIFIED": 2}[verdict]


if __name__ == "__main__":
    raise SystemExit(main())
