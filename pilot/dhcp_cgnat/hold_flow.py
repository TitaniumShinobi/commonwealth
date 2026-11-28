"""Hold one TLS echo session across long phases; identified probes and reverse waits."""
from __future__ import annotations

import argparse
import json
import select
import socket
import ssl
import sys
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca)
    sock = socket.create_connection((args.host, args.port), timeout=4)
    tls = context.wrap_socket(sock, server_hostname=args.host)
    tls.setblocking(False)
    # Opening handshake probe.
    open_id = "open"
    tls.setblocking(True)
    tls.settimeout(3)
    tls.sendall(b"C" + open_id.encode()[:4].ljust(4, b"0") + b"O")
    expected = b"S" + open_id.encode()[:4].ljust(4, b"0") + b"O"
    got = b""
    while len(got) < len(expected):
        got += tls.recv(16)
    if got != expected:
        raise SystemExit(f"initial protected echo missing: {got!r}")
    tls.setblocking(False)
    Path(args.status).write_text(
        json.dumps({"state": "open", "opened_at": time.time(), "port": args.port}) + "\n"
    )
    print("ready", flush=True)
    inbox = b""

    def server_seen(probe_id: str) -> bool:
        if not Path(args.audit).is_file():
            return False
        for line in Path(args.audit).read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "server_recv" and row.get("probe_id") == probe_id:
                return True
        return False

    def read_available(deadline: float) -> bytes:
        nonlocal inbox
        while time.monotonic() < deadline:
            readable, _, _ = select.select([tls], [], [], max(0.0, min(0.2, deadline - time.monotonic())))
            if not readable:
                continue
            try:
                chunk = tls.recv(64)
            except (ssl.SSLWantReadError, BlockingIOError):
                continue
            except OSError:
                return b""
            if not chunk:
                return b""
            inbox += chunk
            return inbox
        return inbox

    for line in sys.stdin:
        command = line.strip()
        if not command:
            continue
        parts = command.split()
        if parts[0] == "probe" and len(parts) == 2:
            probe_id = parts[1][:4]
            frame = b"C" + probe_id.encode()[:4].ljust(4, b"0") + b"x"
            client_sent = False
            client_recv = False
            try:
                tls.setblocking(True)
                tls.settimeout(0.5)
                tls.sendall(frame)
                client_sent = True
            except OSError:
                client_sent = False
            finally:
                tls.setblocking(False)
            expect = b"S" + probe_id.encode()[:4].ljust(4, b"0") + b"x"
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                buf = read_available(deadline)
                idx = buf.find(expect)
                if idx >= 0:
                    client_recv = True
                    inbox = buf[idx + len(expect) :]
                    break
            # Allow audit file to catch up.
            time.sleep(0.05)
            print(
                json.dumps(
                    {
                        "probe_id": probe_id,
                        "client_sent": client_sent,
                        "client_recv": client_recv,
                        "server_recv": server_seen(probe_id),
                        "observed_at": time.time(),
                    }
                ),
                flush=True,
            )
        elif parts[0] == "wait_push" and len(parts) == 2:
            probe_id = parts[1][:4]
            expect = b"H" + probe_id.encode()[:4].ljust(4, b"0") + b"h"
            client_recv = False
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                buf = read_available(deadline)
                idx = buf.find(expect)
                if idx >= 0:
                    client_recv = True
                    inbox = buf[idx + len(expect) :]
                    break
            print(
                json.dumps(
                    {
                        "probe_id": probe_id,
                        "kind": "wait_push",
                        "client_recv": client_recv,
                        "observed_at": time.time(),
                    }
                ),
                flush=True,
            )
        elif parts[0] == "quit":
            break
    try:
        tls.close()
    except OSError:
        pass


if __name__ == "__main__":
    main()
