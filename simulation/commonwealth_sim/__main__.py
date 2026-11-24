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
    def __init__(self, role, directory, path, run, case):
        self.role = role
        self.child = subprocess.Popen(
            [sys.executable, "-m", "commonwealth_sim.actor", role, str(directory),
             str(path), run, case], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
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
            yield result
        for role in ROLES:
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

    def stop(self, abort):
        for child in self.children.values():
            child.finish(abort)
        deadline = time.monotonic() + 2
        return [child.reap(deadline) for child in self.children.values()]


def execute(topology, path, run, fixture, suite_deadline, action=None):
    case = Case(topology, path, run, fixture, min(suite_deadline, time.monotonic() + 30))
    error = None
    with tempfile.TemporaryDirectory(prefix="cw-sim-", dir=os.environ["RUNNER_TEMP"]) as directory:
        try:
            case.start(Path(directory))
            if action is None:
                case.smoke(Path(directory))
            else:
                case.run_fixture(action)
        except (OSError, RuntimeError, TimeoutError, ValueError, KeyError) as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            diagnostics = case.stop(error is not None)
    observed_failure = any(not result["matches"] for result in case.results)
    verdict = "FAIL" if observed_failure else "UNVERIFIED" if error else "PASS"
    return {"case": fixture, "suite": "smoke" if action is None else "step-3",
            "run": run, "revision": os.getenv("CHECKOUT_SHA"), "topology_sha256": digest(path),
            "initial_state": "fresh process directories and case-local logical state",
            "authorities": {"orchestration": "harness", "access": "access-operator"},
            "verdict": verdict, "incomplete": error, "trace": case.trace,
            "checks": case.results, "diagnostics": diagnostics}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("smoke", "run"))
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--suite", choices=("step-3",))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    revision = os.getenv("CHECKOUT_SHA")
    directory = args.out.parent if args.command == "smoke" else args.out
    manifest = {"baseline": BASELINE, "checkout_sha": revision, "dispatch_sha": os.getenv("GITHUB_SHA"),
                "workflow_ref": os.getenv("GITHUB_WORKFLOW_REF"), "workflow_sha": os.getenv("GITHUB_WORKFLOW_SHA"),
                "checkout_action_sha": os.getenv("CHECKOUT_ACTION_SHA"),
                "upload_action_sha": os.getenv("UPLOAD_ACTION_SHA"),
                "runner_label": "ubuntu-24.04", "runner_os": os.getenv("RUNNER_OS"),
                "runner_arch": os.getenv("RUNNER_ARCH"), "machine": platform.machine(),
                "image_os": os.getenv("ImageOS", "unavailable"), "image_version": os.getenv("ImageVersion", "unavailable"),
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
            for name, actions in cases["step-3"].items():
                receipt = execute(topology, args.topology, run, name, deadline, actions)
                receipt["cases_sha256"] = manifest["cases_sha256"]
                results[name] = receipt["verdict"]
                save(directory / f"{name}.json", receipt)
            verdict = ("FAIL" if "FAIL" in results.values() else
                       "UNVERIFIED" if not results or "UNVERIFIED" in results.values() else "PASS")
            save(directory / "summary.json", {"verdict": verdict, "cases": results,
                 "later_cases": {name: "UNVERIFIED" for name in cases["later"]}, "revision": revision})
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
