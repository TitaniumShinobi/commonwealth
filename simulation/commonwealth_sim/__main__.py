"""Bounded Step 3 cloud smoke and classical access simulation."""
import argparse
import hashlib
import heapq
import os
import platform
import resource
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .actor import LINE, MEMORY, decode, encode, tag
from .recovery_audit import digest as audit_digest, summarize

BASELINE = "6c2dbf2a79daea32ecafd51d56eae0d9f35dd8d3"
ROLES = ("a-authority", "a-application", "b", "access")
TOTAL_OUTPUT = 8 * 1024 ** 2


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(target, value):
    data = encode(value) + b"\n"
    root = Path(os.environ["RUNNER_TEMP"]) / "commonwealth"
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("output must be under the runner evidence directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    files = [path for path in root.rglob("*") if path.is_file() and path != target]
    reserve = 256 * 1024 if target.name not in ("summary.json", "smoke.json", "execution-manifest.json") else 0
    if len(data) + sum(path.stat().st_size for path in files) > TOTAL_OUTPUT - reserve:
        raise ValueError("evidence output limit")
    target.write_bytes(data)


class Process:
    def __init__(self, role, directory, path, run, case, start=0):
        self.role = role
        self.child = subprocess.Popen(
            [sys.executable, "-m", "commonwealth_sim.actor", role, str(directory),
             str(path), run, case, str(start)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0)
        os.set_blocking(self.child.stdin.fileno(), False)
        self.pending = bytearray()
        self.diagnostics = bytearray()
        self.truncated = False

    def collect_error(self, chunk):
        remaining = 65_536 - len(self.diagnostics)
        self.diagnostics.extend(chunk[:remaining])
        self.truncated |= len(chunk) > remaining

    def exchange(self, request, deadline):
        outgoing = b"" if request is None else encode(request) + b"\n"
        if len(outgoing) > LINE:
            raise ValueError("request line limit")
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ, "reply")
            if not self.child.stderr.closed:
                selector.register(self.child.stderr, selectors.EVENT_READ, "diagnostic")
            if outgoing:
                selector.register(self.child.stdin, selectors.EVENT_WRITE, "send")
            while True:
                if not outgoing and b"\n" in self.pending:
                    line, _, rest = self.pending.partition(b"\n")
                    self.pending = rest
                    if len(line) + 1 > LINE:
                        raise ValueError("reply line limit")
                    return decode(line)
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise TimeoutError(f"{self.role} acknowledgment deadline")
                for key, _ in selector.select(wait):
                    if key.data == "send":
                        outgoing = outgoing[os.write(key.fd, outgoing):]
                        if not outgoing:
                            selector.unregister(key.fileobj)
                    else:
                        chunk = os.read(key.fd, 4096)
                        if key.data == "diagnostic":
                            self.collect_error(chunk)
                            if not chunk:
                                selector.unregister(key.fileobj)
                        elif not chunk:
                            raise RuntimeError(f"{self.role} closed reply pipe")
                        else:
                            self.pending.extend(chunk)
                            if len(self.pending) > LINE:
                                raise ValueError("reply line limit")

    def finish(self, abort):
        if self.child.poll() is None and not abort:
            try:
                os.write(self.child.stdin.fileno(), b'{"kind":"shutdown"}\n')
                self.child.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                abort = True
        self.child.stdin.close()
        self.child.stdout.close()
        if self.child.poll() is None:
            self.child.terminate()

    def reap(self, deadline):
        try:
            self.child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait()
        self.collect_error(self.child.stderr.read(65_537))
        self.child.stderr.close()
        return {"role": self.role, "exit": self.child.returncode,
                "stderr": self.diagnostics.decode("utf-8", "replace"), "truncated": self.truncated}


class Case:
    def __init__(self, topology, path, run, case, deadline):
        self.topology, self.path, self.run, self.case = topology, path, run, case
        self.deadline = deadline
        self.children, self.sequence, self.trace, self.results = {}, {}, [], []
        self.messages = 0

    def call(self, role, request, seconds=2):
        self.messages += 1
        if self.messages > 2048:
            raise ValueError("message count limit")
        if len(self.trace) >= 4096:
            raise ValueError("trace limit")
        result = self.children[role].exchange(request, min(self.deadline, time.monotonic() + seconds))
        self.trace.append({"actor": role, "request": request, "reply": result})
        return result

    def start(self, root):
        for role in ROLES:
            child = Process(role, root / role, self.path, self.run, self.case)
            self.children[role] = child
            reply = self.call(role, None, seconds=5)
            if reply != {"ready": role, "limits": [MEMORY, MEMORY]}:
                raise RuntimeError(f"failed startup readiness for {role}")

    def envelope(self, tick, role, sender, purpose, payload):
        sequence = self.sequence.get(sender, 0) + 1
        self.sequence[sender] = sequence
        envelope = {"version": 1, "run": self.run, "case": self.case, "sender": sender,
                    "recipient": role, "purpose": purpose, "id": str(sequence),
                    "sequence": sequence, "tick": tick, "valid_from": tick,
                    "expires": tick + 1, "payload": payload}
        return (tick, sender, sequence, {"kind": "deliver", "envelope": envelope,
                "tag": tag(self.topology["keys"][sender][purpose], envelope)})

    def advance(self, tick, pending):
        deliveries = 0
        while pending and pending[0][0] <= tick:
            due, _, _, request = heapq.heappop(pending)
            deliveries += 1
            if due < tick or deliveries > 256:
                raise ValueError("delivery tick or bound violated")
            result = self.call(request["envelope"]["recipient"], request)
            for emitted in result.get("emit", []):
                heapq.heappush(pending, self.envelope(tick, emitted["recipient"], emitted["sender"],
                                                     emitted.get("purpose", "federation"), emitted["payload"]))
            yield result
        for role in self.children:
            if self.call(role, {"kind": "close_tick", "tick": tick}) != {"closed": tick}:
                raise RuntimeError("tick close was not acknowledged")

    def smoke(self, root):
        pending = [self.envelope(0, role, "harness", "smoke", {}) for role in ROLES]
        heapq.heapify(pending)
        for role, reply in zip(ROLES, self.advance(0, pending), strict=True):
            expected = {"decision": "accepted", "role": role,
                        "limits": [MEMORY, MEMORY], "state_directory": str(root / role)}
            self.results.append({"criterion": role, "expected": expected, "observed": reply,
                                 "matches": expected == reply})

    def run_fixture(self, actions):
        pending = []
        expectations = {}
        for action in actions:
            entry = self.envelope(action["tick"], "access", "access-operator", "access", action["input"])
            expectations[entry[2]] = action
            heapq.heappush(pending, entry)
        for tick in range(max(action["tick"] for action in actions) + 1):
            for reply in self.advance(tick, pending):
                request = self.trace[-1]["request"]["envelope"]
                action = expectations[request["sequence"]]
                actual = reply.get("observation")
                self.results.append({"criterion": action["criterion"], "tick": tick,
                                     "expected": action["expected"], "observed": actual,
                                     "matches": reply.get("decision") == "accepted" and actual == action["expected"]})

    def run_scripted(self, steps, purpose):
        next_tick = 0
        for step in steps:
            tick = step["tick"]
            for idle in range(next_tick, tick):
                list(self.advance(idle, []))
            payload = dict(step["input"])
            if payload.get("locator") == "fixture":
                descriptor = self.topology["federation"]["locator"]
                signature = tag(self.topology["keys"]["op-a"]["operator"], descriptor)
                payload["locator"] = {"data": descriptor, "tag": signature}
            pending = [self.envelope(tick, step["actor"], step["sender"], purpose, payload)]
            for peer in step.get("also", []):
                heapq.heappush(pending, self.envelope(tick, peer["actor"], peer["sender"],
                                                     purpose, peer["input"]))
            start = len(self.trace)
            list(self.advance(tick, pending))
            seen = {}
            for entry in self.trace[start:]:
                request = entry["request"]
                if request["kind"] == "deliver":
                    operation = request["envelope"]["payload"]["op"]
                    seen[operation] = entry["reply"].get("observation", entry["reply"])
            for operation, expected in step["expect"].items():
                actual = seen.get(operation)
                matches = actual is not None and all(actual.get(k) == v and k in actual
                                                     for k, v in expected.items())
                self.results.append({"criterion": operation, "tick": tick,
                                     "expected": expected, "observed": actual, "matches": matches})
            next_tick = tick + 1

    def lifecycle(self, tick, command, root):
        role = "a-application"
        if command == "lose":
            self.audit_actor(tick - 1, role)
            child = self.children.pop(role)
            child.finish(False)
            observation = child.reap(time.monotonic() + 2)
            self.trace.append({"lifecycle": "old_host_reaped", "tick": tick, **observation})
            if observation["exit"] != 0:
                raise RuntimeError("original host did not stop cleanly")
        elif command == "replace":
            if role in self.children:
                raise RuntimeError("cannot overlap old and replacement hosts")
            child = Process(role, root / "a-host-2", self.path, self.run, self.case, tick)
            self.children[role] = child
            observed = self.call(role, None, seconds=5)
            if observed != {"ready": role, "limits": [MEMORY, MEMORY]}:
                raise RuntimeError("replacement did not acknowledge readiness")
            self.trace.append({"lifecycle": "clean_host_started", "tick": tick, "host": "a-host-2"})

    def check(self, tick, operation, expected, actual):
        matches = actual is not None and all(k in actual and actual[k] == v for k, v in expected.items())
        self.results.append({"criterion": operation, "tick": tick, "expected": expected,
                             "observed": actual, "matches": matches})

    def run_recovery(self, fixture, root):
        for tick in range(fixture["end"] + 1):
            step = fixture["ticks"].get(str(tick), {})
            if "lifecycle" in step:
                self.lifecycle(tick, step["lifecycle"], root)
            pending = [self.envelope(tick, item["actor"], item["sender"], "recovery", item["payload"])
                       for item in step.get("actions", [])]
            heapq.heapify(pending)
            start = len(self.trace)
            list(self.advance(tick, pending))
            seen = {}
            for entry in self.trace[start:]:
                request = entry["request"]
                if request["kind"] == "deliver":
                    name = request["envelope"]["payload"]["op"]
                    observation = entry["reply"].get("observation", entry["reply"])
                    seen[name] = observation
                    seen[f'{entry["actor"]}/{name}'] = observation
                    if name == "fence":
                        seen[f'fence/{observation.get("boundary")}'] = observation
            for name, expected in step.get("expect", {}).items():
                self.check(tick, name, expected, seen.get(name))
            operation = f"control-{tick}"
            for name, decision in (("control_commit", "control_committed"),
                                   ("control_read", "control_read")):
                entry = self.envelope(tick, "b", "fixture-observer", "recovery",
                                      {"op": name, "operation": operation})
                entry[3]["envelope"]["phase"] = "post_close_probe"
                message = entry[3]["envelope"]
                entry[3]["tag"] = tag(self.topology["keys"]["fixture-observer"]["recovery"], message)
                result = self.call("b", entry[3]).get("observation")
                self.check(tick, name, {"decision": decision, "operation": operation, "count": tick + 1}, result)
        tick = fixture["end"]
        for role in ("a-authority", "a-application", "b"):
            self.audit_actor(tick, role)
        self.score_recovery(fixture)

    def audit_actor(self, tick, role):
        offset = 0
        while True:
            request = self.envelope(tick, role, "fixture-observer", "recovery",
                                    {"op": "audit_state", "offset": offset})[3]
            request["envelope"]["phase"] = "post_close_probe"
            request["tag"] = tag(self.topology["keys"]["fixture-observer"]["recovery"], request["envelope"])
            result = self.call(role, request).get("observation", {})
            if result.get("decision") != "audited" or result.get("offset") != offset:
                raise RuntimeError("actor ledger page unavailable")
            total, count = result["total"], len(result["events"])
            offset += count
            if offset == total:
                return
            if count == 0 or offset > total:
                raise RuntimeError("actor ledger coverage incomplete")

    def score_recovery(self, fixture):
        observations = [e for e in self.trace if (e.get("request") or {}).get("kind") == "deliver"]
        pages = [e for e in observations if e["request"]["envelope"]["payload"]["op"] == "audit_state"]
        records = [row for e in pages for row in e["reply"]["observation"]["events"]]
        lifecycle = [e for e in self.trace if "lifecycle" in e]
        accounting = summarize(observations, records, fixture, lifecycle)
        self.check(fixture["end"], "modeled_audit_and_effect_accounting",
                   {"reconciled": True, "unauthorized_effects": 0,
                    "founder_or_delegate_effects": 0, "unaccounted_effects": 0,
                    "unobserved_declared_effects": 0}, accounting)
        # Exercise the independent scorer on an intentionally different ledger,
        # retaining the genuine trace and audit records in the original receipt.
        template = next(row for row in records if row["operation"] == "issue"
                        and row["decision"] == "credential_issued") if any(
                           row["operation"] == "issue" and row["decision"] == "credential_issued"
                           for row in records) else records[0]
        anomaly = {**template, "principal": "founder-delegate", "id": "unaccounted-test",
                   "post_state_sha256": "forced-scoring-test-change"}
        challenged = summarize(observations, [*records, anomaly], fixture, lifecycle)
        self.check(fixture["end"], "scorer_rejects_delegate_and_unaccounted_effect",
                   {"reconciled": False, "founder_or_delegate_effects": 1,
                    "unaccounted_effects": 1}, challenged)
        # A genuine capability-bearing principal and matching transport/journal
        # pair are insufficient when this effect is not in the trusted fixture.
        fence = next(row for row in records if row["operation"] == "fence" and row["decision"] == "fenced")
        original = next(entry for entry in observations
                        if entry["actor"] == fence["actor"]
                        and entry["request"]["envelope"]["sender"] == fence["principal"]
                        and entry["request"]["envelope"]["id"] == fence["id"])
        prior = original["request"]["envelope"]
        new_tick = fixture["end"]
        sequence = max(entry["request"]["envelope"]["sequence"] for entry in observations
                       if entry["request"]["envelope"]["sender"] == fence["principal"]) + 1
        envelope = {**prior, "id": str(sequence), "sequence": sequence, "tick": new_tick,
                    "valid_from": new_tick, "expires": new_tick + 1}
        request = {"kind": "deliver", "envelope": envelope,
                   "tag": tag(self.topology["keys"][fence["principal"]]["recovery"], envelope)}
        injected_dispatch = {"actor": fence["actor"], "request": request, "reply": original["reply"]}
        injected_row = {**fence, "tick": new_tick, "id": envelope["id"],
                        "request_sha256": audit_digest(envelope["payload"]),
                        "reply_sha256": audit_digest(injected_dispatch["reply"])}
        challenged = summarize([*observations, injected_dispatch], [*records, injected_row],
                               fixture, lifecycle)
        self.check(new_tick, "scorer_rejects_reconciled_undeclared_fence",
                   {"reconciled": True, "unauthorized_effects": 1, "unaccounted_effects": 0,
                    "founder_or_delegate_effects": 0, "unobserved_declared_effects": 0}, challenged)
        if fixture.get("score_restore"):
            baseline = next((x["observed"] for x in self.results if x["criterion"] == "peer_state"), None)
            ending = next((x["observed"] for x in reversed(self.results)
                           if x["criterion"] == "peer_state"), None)
            retrieval = next((e["reply"]["observation"] for e in observations
                              if e["request"]["envelope"]["payload"]["op"] == "read_result"
                              and e["reply"]["observation"].get("disclosed")
                              and e["reply"]["observation"].get("host") == "a-host-2"), None)
            lost = next((e["tick"] for e in self.trace if e.get("lifecycle") == "old_host_reaped"), None)
            version = next((e["reply"]["observation"] for e in observations
                            if e["request"]["envelope"]["payload"]["op"] == "observe_version"), None)
            verified = bool(retrieval and version and lost is not None
                            and retrieval.get("source_version_digest") == version.get("version_digest")
                            and retrieval["data_tick"] == version["data_tick"])

            recovery_time = retrieval["tick"] - lost if verified else None
            age = lost - version["data_tick"] if verified else None
            self.check(fixture["end"], "restore_limits", {"met": True},
                       {"met": verified and recovery_time <= 5 and 0 <= age <= 2,
                        "loss_tick": lost, "retrieval_tick": retrieval and retrieval["tick"],
                        "data_tick": version and version["data_tick"], "source_version": version,
                        "recovery_time": recovery_time,
                        "restored_data_age": age, "max_recovery_time": 5, "max_data_age": 2})
            unchanged = bool(baseline and ending and
                             all(baseline[k] == ending[k] for k in ("trust_digest", "policy_digest"))
                             and not ending["configuration_changes"])
            self.check(fixture["end"], "peer_configuration_unchanged", {"unchanged": True},
                       {"unchanged": unchanged, "before": baseline, "after": ending})

    def stop(self, abort):
        for child in self.children.values():
            child.finish(abort)
        deadline = time.monotonic() + 2
        return [child.reap(deadline) for child in self.children.values()]


def execute(topology, path, run, fixture, suite_deadline, action=None, suite='step-3'):
    case = Case(topology, path, run, fixture, min(suite_deadline, time.monotonic() + 30))
    error = None
    with tempfile.TemporaryDirectory(prefix="cw-sim-", dir=os.environ["RUNNER_TEMP"]) as directory:
        try:
            case.start(Path(directory))
            if action is None:
                case.smoke(Path(directory))
            elif suite == "step-6":
                case.run_recovery(action, Path(directory))
            elif suite in ("step-4", "step-5"):
                case.run_scripted(action, "federation" if suite == "step-4" else "household")
            else:
                case.run_fixture(action)
        except (OSError, RuntimeError, TimeoutError, ValueError, KeyError) as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            diagnostics = case.stop(error is not None)
    if suite == "step-6" and not error and any(result["observed"] is None for result in case.results):
        error = "required enforcement observation missing"
    observed_failure = any(not result["matches"] and (suite != "step-6" or result["observed"] is not None)
                           for result in case.results)
    verdict = "FAIL" if observed_failure else "UNVERIFIED" if error else "PASS"
    return {"case": fixture, "suite": "smoke" if action is None else suite,
            "run": run, "revision": os.getenv("CHECKOUT_SHA"), "topology_sha256": digest(path),
            "initial_state": "fresh process directories and case-local logical state",
            "authorities": ({"orchestration": "harness", "backup": "backup-owner", "approval": "restore-owner",
                             "restore": "a-steward", "service_peer": "op-b", "ingress": "ingress-owner",
                             "writer": "writer-owner", "authorization": ["authz-owner", "recover-authz"],
                             "publication": ["publisher", "recover-pub"],
                             "credentials": ["credential-owner", "recover-creds"],
                             "observation": "fixture-observer"} if suite == "step-6"
                            else {"orchestration": "harness", "access": "access-operator"}),
            "verdict": verdict, "incomplete": error, "trace": case.trace,
            "checks": case.results, "diagnostics": diagnostics}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("smoke", "run"))
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--suite", choices=("step-3", "step-4", "step-5", "step-6"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    revision = os.getenv("CHECKOUT_SHA")
    directory = args.out.parent if args.command == "smoke" else args.out
    manifest = {"design_baseline": BASELINE, "implementation_parent": "061967633e433beaf25b754e573d5f7564589b36", "checkout_sha": revision, "dispatch_sha": os.getenv("GITHUB_SHA"),
                "workflow_ref": os.getenv("GITHUB_WORKFLOW_REF"), "workflow_sha": os.getenv("GITHUB_WORKFLOW_SHA"),
                "checkout_action_sha": os.getenv("CHECKOUT_ACTION_SHA"),
                "upload_action_sha": os.getenv("UPLOAD_ACTION_SHA"),
                "runner_label": "ubuntu-24.04", "runner_os": os.getenv("RUNNER_OS"),
                "runner_arch": os.getenv("RUNNER_ARCH"), "machine": platform.machine(),
                "image_os": os.getenv("ImageOS", "unavailable"), "image_version": os.getenv("ImageVersion", "unavailable"),
                "command": [sys.executable, "-m", "commonwealth_sim", *sys.argv[1:]],
                "python": platform.python_version(), "implementation": platform.python_implementation(),
                "limits": {"processes": 5, "address_space_per_process": MEMORY, "ack_seconds": 2,
                           "actor_lifecycle_seconds": 5, "case_seconds": 30, "suite_seconds": 90,
                           "messages": 2048, "deliveries_per_tick": 256, "line_bytes": LINE,
                           "trace_entries": 4096, "diagnostic_bytes_per_actor": 65_536,
                           "output_bytes": TOTAL_OUTPUT}}
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))
        manifest["verified_harness_address_space"] = list(resource.getrlimit(resource.RLIMIT_AS))
        manifest["topology_sha256"] = digest(args.topology)
        if args.cases:
            manifest["cases_sha256"] = digest(args.cases)
        save(directory / "execution-manifest.json", manifest)
        if (manifest["runner_os"], manifest["runner_arch"], manifest["machine"]) != ("Linux", "X64", "x86_64"):
            raise ValueError("expected GitHub Linux X64 runner")
        if not revision or revision != manifest["dispatch_sha"]:
            raise ValueError("checkout revision does not match dispatch")
        topology = decode(args.topology.read_bytes())
        run = f"{os.getenv('GITHUB_RUN_ID', 'unknown')}-{os.getenv('GITHUB_RUN_ATTEMPT', 'unknown')}"
        deadline = time.monotonic() + 90
        if args.command == "smoke":
            receipt = execute(topology, args.topology, run, "smoke", deadline)
            save(args.out, receipt)
            verdict = receipt["verdict"]
        else:
            if not args.cases or args.suite is None:
                parser.error("run requires --cases and --suite")
            smoke = decode((directory.parent / "smoke.json").read_bytes())
            if smoke["verdict"] != "PASS" or smoke["revision"] != revision or smoke["run"] != run:
                raise ValueError("same-run smoke PASS required")
            cases = decode(args.cases.read_bytes())
            results = {}
            for name, actions in cases[args.suite].items():
                receipt = execute(topology, args.topology, run, name, deadline, actions, args.suite)
                receipt["cases_sha256"] = manifest["cases_sha256"]
                if args.suite == "step-6":
                    receipt["resolved_fixture_sha256"] = hashlib.sha256(encode(actions)).hexdigest()
                results[name] = receipt["verdict"]
                save(directory / f"{name}.json", receipt)
            verdict = ("FAIL" if "FAIL" in results.values() else
                       "UNVERIFIED" if not results or "UNVERIFIED" in results.values() else "PASS")
            save(directory / "summary.json", {"verdict": verdict, "cases": results,
                 "later_cases": {name: "UNVERIFIED" for name in cases["later"]
                                 if int(name.split("-")[1]) > int(args.suite.split("-")[1])}, "revision": revision})
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        target = args.out if args.command == "smoke" else directory / "summary.json"
        verdict = "FAIL" if "FAIL" in locals().get("results", {}).values() else "UNVERIFIED"
        save(target, {"verdict": verdict, "incomplete": str(exc), "revision": revision,
                      "cases": locals().get("results", {})})
    print(f"{args.command}: {verdict}")
    if verdict == "UNVERIFIED":
        print("::warning::Simulation evidence is incomplete")
    return {"PASS": 0, "FAIL": 1, "UNVERIFIED": 2}[verdict]


if __name__ == "__main__":
    raise SystemExit(main())
