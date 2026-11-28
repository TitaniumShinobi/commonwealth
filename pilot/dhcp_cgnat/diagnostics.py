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
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


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
        pid_path.write_text(str(proc.pid))
        meta.write_text(
            json.dumps({"status": "running", "pid": proc.pid, "mode": "read_only", "child": "tcpdump"})
        )
        print(json.dumps({"diagnostics": "started", "pid": proc.pid}))
        return

    if args.command == "stop":
        stopped_confirmed = True
        pid = None
        if pid_path.exists():
            pid = int(pid_path.read_text().strip())
            if alive(pid):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            for _ in range(40):
                if not alive(pid):
                    break
                time.sleep(0.05)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                time.sleep(0.05)
            stopped_confirmed = not alive(pid)
            pid_path.unlink(missing_ok=True)
        after.write_text(nft_snapshot(args.namespace))
        meta.write_text(
            json.dumps(
                {
                    "status": "stopped",
                    "mode": "read_only",
                    "pid": pid,
                    "child_stopped_confirmed": stopped_confirmed,
                }
            )
        )
        if not stopped_confirmed:
            raise SystemExit("diagnostics child still running")
        print(json.dumps({"diagnostics": "stopped", "child_stopped_confirmed": True}))
        return

    if not before.exists() or not after.exists():
        raise SystemExit("missing snapshots")
    if before.read_text() != after.read_text():
        raise SystemExit("forwarding rules changed during diagnostics")
    record = json.loads(meta.read_text()) if meta.exists() else {}
    if not record.get("child_stopped_confirmed"):
        raise SystemExit("diagnostics child stop not confirmed")
    print(
        json.dumps(
            {
                "diagnostics": "verified_unchanged_forwarding",
                "child_stopped_confirmed": True,
                "capture_bytes": capture.stat().st_size if capture.exists() else 0,
            }
        )
    )


if __name__ == "__main__":
    main()
