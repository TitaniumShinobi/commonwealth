"""Optional ISP diagnostics: read-only capture that stops without forwarding changes."""
from __future__ import annotations

import argparse
import json
import os
import signal
import struct
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


def pcap_packet_count(path: Path) -> int:
    """Return number of packets in a classic/nano libpcap file, or raise on unparseable."""
    raw = path.read_bytes()
    if len(raw) < 24:
        raise ValueError(f"pcap too short for global header: {len(raw)} bytes")
    magic = struct.unpack("<I", raw[0:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        raise ValueError(f"unparseable pcap magic={magic:#010x}")
    offset = 24
    count = 0
    while offset + 16 <= len(raw):
        incl_len = struct.unpack(endian + "IIII", raw[offset : offset + 16])[2]
        offset += 16
        if incl_len < 0 or offset + incl_len > len(raw):
            raise ValueError(f"truncated pcap record at packet {count}")
        offset += incl_len
        count += 1
    if offset != len(raw):
        raise ValueError(f"pcap trailing bytes after {count} packets")
    return count


def tcpdump_supports_immediate() -> bool:
    try:
        help_text = subprocess.check_output(["tcpdump", "--help"], stderr=subprocess.STDOUT, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        help_text = getattr(exc, "output", "") or ""
    return "--immediate-mode" in help_text


def wait_observed_packets(capture: Path, minimum: int, timeout: float) -> dict:
    """Bounded barrier: poll parseable pcap until count >= minimum (not a fixed sleep)."""
    deadline = time.monotonic() + timeout
    last_error = None
    packets = 0
    while time.monotonic() < deadline:
        if capture.exists():
            try:
                packets = pcap_packet_count(capture)
                last_error = None
                if packets >= minimum:
                    return {
                        "observed": True,
                        "capture_packets": packets,
                        "capture_bytes": capture.stat().st_size,
                    }
            except ValueError as exc:
                last_error = str(exc)
        time.sleep(0.05)
    detail = {
        "observed": False,
        "capture_packets": packets,
        "capture_bytes": capture.stat().st_size if capture.exists() else 0,
        "pcap_error": last_error,
        "timeout_s": timeout,
        "minimum": minimum,
    }
    raise SystemExit(f"diagnostics packet barrier unmet: {json.dumps(detail)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("start", "wait-packets", "stop", "verify"),
    )
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--interface", default="edge0")
    parser.add_argument("--min-packets", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=5.0)
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
        subprocess.run(["sudo", "-n", "install", "-m", "666", "/dev/null", str(capture)], check=True)
        immediate = tcpdump_supports_immediate()
        cmd = [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            args.namespace,
            "tcpdump",
            "-n",
            "-U",  # packet-buffered userspace flush
        ]
        if immediate:
            cmd.append("--immediate-mode")  # avoid TPACKET_V3 block-timeout delivery race
        cmd.extend(["-i", args.interface, "-c", "64", "-w", str(capture)])
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        child_pids: list[int] = []
        for _ in range(40):
            child_pids = namespace_tcpdump_pids(args.namespace)
            if child_pids:
                break
            if proc.poll() is not None:
                err = (proc.stderr.read() or b"").decode("utf-8", "replace")
                raise SystemExit(f"tcpdump exited early status={proc.returncode}: {err}")
            time.sleep(0.05)
        if not child_pids:
            try:
                proc.terminate()
            except OSError:
                pass
            err = (proc.stderr.read() or b"").decode("utf-8", "replace") if proc.stderr else ""
            raise SystemExit(f"tcpdump did not start inside fixture namespace: {err}")
        # Readiness = child present in ns; packet evidence is gated by wait-packets after traffic.
        pid_path.write_text(str(proc.pid))
        meta.write_text(
            json.dumps(
                {
                    "status": "running",
                    "wrapper_pid": proc.pid,
                    "tcpdump_pids": child_pids,
                    "mode": "read_only",
                    "child": "tcpdump",
                    "packet_buffered": True,
                    "immediate_mode": immediate,
                }
            )
        )
        print(
            json.dumps(
                {
                    "diagnostics": "started",
                    "wrapper_pid": proc.pid,
                    "tcpdump_pids": child_pids,
                    "packet_buffered": True,
                    "immediate_mode": immediate,
                }
            )
        )
        return

    if args.command == "wait-packets":
        # Observed-packet barrier after exercised fixture traffic; not a fixed sleep.
        result = wait_observed_packets(capture, args.min_packets, args.timeout)
        record = json.loads(meta.read_text()) if meta.exists() else {}
        record["packet_barrier"] = result
        meta.write_text(json.dumps(record))
        print(json.dumps({"diagnostics": "packets_observed", **result}))
        return

    if args.command == "stop":
        record = json.loads(meta.read_text()) if meta.exists() else {}
        wrapper_pid = None
        if pid_path.exists():
            wrapper_pid = int(pid_path.read_text().strip())
        child_pids = list(record.get("tcpdump_pids") or [])
        child_pids = sorted(set(child_pids) | set(namespace_tcpdump_pids(args.namespace)))
        # Child-first graceful stop so -U / immediate buffers flush into the pcap.
        for pid in child_pids:
            if alive(pid):
                signal_pid(pid, signal.SIGTERM)
        if not wait_gone(child_pids, 2.0):
            for pid in child_pids:
                if alive(pid):
                    signal_pid(pid, signal.SIGKILL)
            wait_gone(child_pids, 1.0)
        if wrapper_pid is not None and alive(wrapper_pid):
            signal_pid(wrapper_pid, signal.SIGTERM)
            if not wait_gone([wrapper_pid], 1.0):
                signal_pid(wrapper_pid, signal.SIGKILL)
                wait_gone([wrapper_pid], 0.5)
        try:
            dir_fd = os.open(str(state), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
        remaining = namespace_tcpdump_pids(args.namespace)
        wrapper_alive = bool(wrapper_pid is not None and alive(wrapper_pid))
        child_stopped_confirmed = not remaining and not wrapper_alive
        capture_bytes = capture.stat().st_size if capture.exists() else 0
        try:
            packets = pcap_packet_count(capture) if capture.exists() else 0
            pcap_error = None
        except ValueError as exc:
            packets = 0
            pcap_error = str(exc)
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
                    "capture_bytes": capture_bytes,
                    "capture_packets": packets,
                    "pcap_error": pcap_error,
                    "packet_barrier": record.get("packet_barrier"),
                    "immediate_mode": record.get("immediate_mode"),
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
                    "capture_bytes": capture_bytes,
                    "capture_packets": packets,
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
    if not capture.exists():
        raise SystemExit("diagnostics capture.pcap missing")
    try:
        packets = pcap_packet_count(capture)
    except ValueError as exc:
        raise SystemExit(f"diagnostics capture unparseable: {exc}") from exc
    capture_bytes = capture.stat().st_size
    if packets < 1:
        raise SystemExit(
            f"diagnostics capture has no packets (bytes={capture_bytes}); fixture traffic not evidenced"
        )
    try:
        listed = subprocess.check_output(
            ["tcpdump", "-nn", "-r", str(capture)], stderr=subprocess.DEVNULL, text=True
        )
        if not any(line.strip() for line in listed.splitlines()):
            raise SystemExit("tcpdump -r produced no packet lines")
    except FileNotFoundError:
        pass
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"tcpdump -r failed status={exc.returncode}") from exc
    print(
        json.dumps(
            {
                "diagnostics": "verified_unchanged_forwarding",
                "child_stopped_confirmed": True,
                "namespace_tcpdump_gone": True,
                "capture_bytes": capture_bytes,
                "capture_packets": packets,
                "capture_parseable": True,
                "immediate_mode": record.get("immediate_mode"),
            }
        )
    )


if __name__ == "__main__":
    main()
