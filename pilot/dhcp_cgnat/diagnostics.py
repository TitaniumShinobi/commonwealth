"""Optional ISP diagnostics: read-only capture that stops without forwarding changes."""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path


def nft_snapshot(namespace: str) -> str:
    raw = subprocess.check_output(
        ["sudo", "-n", "ip", "netns", "exec", namespace, "nft", "list", "ruleset"], text=True
    )
    return subprocess.check_output(
        ["sed", "-E", r"s/packets [0-9]+ bytes [0-9]+/packets 0 bytes 0/g"],
        input=raw,
        text=True,
    )


def alive(pid: int) -> bool:
    # /proc check — os.kill(pid, 0) fails with EPERM on root-owned tcpdump children.
    return Path(f"/proc/{pid}").exists()


def namespace_tcpdump_pids(namespace: str) -> list[int]:
    """Return tcpdump PIDs living in the fixture netns (not the sudo wrapper)."""
    try:
        raw = subprocess.check_output(
            ["sudo", "-n", "ip", "netns", "pids", namespace], text=True
        )
    except subprocess.CalledProcessError:
        return []
    found: list[int] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.isdigit():
            continue
        pid = int(line)
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            continue
        if comm == "tcpdump":
            found.append(pid)
    return found


def signal_pid(pid: int, sig: int) -> None:
    try:
        # Prefer killing via sudo so root-owned tcpdump children receive the signal.
        subprocess.run(["sudo", "-n", "kill", f"-{sig}", str(pid)], check=False)
    except OSError:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass


def wait_gone(pids: list[int], seconds: float = 2.0) -> bool:
    deadline = time.monotonic() + seconds
    remaining = set(pids)
    while time.monotonic() < deadline and remaining:
        remaining = {pid for pid in remaining if alive(pid)}
        if not remaining:
            return True
        time.sleep(0.05)
    return not any(alive(pid) for pid in pids)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("start", "stop", "verify"))
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--interface", default="edge0")
    args = parser.parse_args()
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    pid_path = state / "diag.pid"
    before = state / "nft-before.txt"
    after = state / "nft-after.txt"
    capture = state / "capture.pcap"
    meta = state / "diag.json"

    if args.command == "start":
        before.write_text(nft_snapshot(args.namespace))
        proc = subprocess.Popen(
            [
                "sudo",
                "-n",
                "ip",
                "netns",
                "exec",
                args.namespace,
                "tcpdump",
                "-n",
                "-i",
                args.interface,
                "-c",
                "64",
                "-w",
                str(capture),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait briefly for tcpdump to appear inside the fixture namespace.
        child_pids: list[int] = []
        for _ in range(40):
            child_pids = namespace_tcpdump_pids(args.namespace)
            if child_pids:
                break
            time.sleep(0.05)
        if not child_pids:
            try:
                proc.terminate()
            except OSError:
                pass
            raise SystemExit("tcpdump did not start inside fixture namespace")
        pid_path.write_text(str(proc.pid))
        meta.write_text(
            json.dumps(
                {
                    "status": "running",
                    "wrapper_pid": proc.pid,
                    "tcpdump_pids": child_pids,
                    "mode": "read_only",
                    "child": "tcpdump",
                }
            )
        )
        print(
            json.dumps(
                {
                    "diagnostics": "started",
                    "wrapper_pid": proc.pid,
                    "tcpdump_pids": child_pids,
                }
            )
        )
        return

    if args.command == "stop":
        record = json.loads(meta.read_text()) if meta.exists() else {}
        wrapper_pid = None
        if pid_path.exists():
            wrapper_pid = int(pid_path.read_text().strip())
        child_pids = list(record.get("tcpdump_pids") or [])
        # Re-scan namespace so we catch children even if start meta is stale.
        child_pids = sorted(set(child_pids) | set(namespace_tcpdump_pids(args.namespace)))
        targets = list(child_pids)
        if wrapper_pid is not None:
            targets.append(wrapper_pid)
        for pid in targets:
            if alive(pid):
                signal_pid(pid, signal.SIGTERM)
        if not wait_gone(targets, 2.0):
            for pid in targets:
                if alive(pid):
                    signal_pid(pid, signal.SIGKILL)
            wait_gone(targets, 1.0)
        # Claim requires the actual tcpdump process tree inside the fixture ns to be gone.
        remaining = namespace_tcpdump_pids(args.namespace)
        wrapper_alive = bool(wrapper_pid is not None and alive(wrapper_pid))
        child_stopped_confirmed = not remaining and not wrapper_alive
        pid_path.unlink(missing_ok=True)
        after.write_text(nft_snapshot(args.namespace))
        meta.write_text(
            json.dumps(
                {
                    "status": "stopped",
                    "mode": "read_only",
                    "wrapper_pid": wrapper_pid,
                    "tcpdump_pids": child_pids,
                    "remaining_tcpdump_pids": remaining,
                    "child_stopped_confirmed": child_stopped_confirmed,
                }
            )
        )
        if not child_stopped_confirmed:
            raise SystemExit(
                f"diagnostics tcpdump still in namespace: remaining={remaining} wrapper_alive={wrapper_alive}"
            )
        print(
            json.dumps(
                {
                    "diagnostics": "stopped",
                    "child_stopped_confirmed": True,
                    "namespace_tcpdump_gone": True,
                }
            )
        )
        return

    if not before.exists() or not after.exists():
        raise SystemExit("missing snapshots")
    if before.read_text() != after.read_text():
        raise SystemExit("forwarding rules changed during diagnostics")
    record = json.loads(meta.read_text()) if meta.exists() else {}
    if not record.get("child_stopped_confirmed"):
        raise SystemExit("diagnostics child stop not confirmed")
    if record.get("remaining_tcpdump_pids"):
        raise SystemExit("diagnostics tcpdump still recorded in namespace")
    print(
        json.dumps(
            {
                "diagnostics": "verified_unchanged_forwarding",
                "child_stopped_confirmed": True,
                "namespace_tcpdump_gone": True,
                "capture_bytes": capture.stat().st_size if capture.exists() else 0,
            }
        )
    )


if __name__ == "__main__":
    main()
