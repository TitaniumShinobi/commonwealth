"""Hold one TLS echo session and report bidirectional send/recv outcomes."""
from __future__ import annotations

import argparse
import json
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
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca)
    sock = socket.create_connection((args.host, args.port), timeout=4)
    tls = context.wrap_socket(sock, server_hostname=args.host)
    tls.settimeout(2)
    tls.sendall(b"O")
    if tls.recv(1) != b"O":
        raise SystemExit("initial protected echo missing")
    Path(args.status).write_text(json.dumps({"state": "open", "opened_at": time.time(), "port": args.port}) + "\n")
    print("ready", flush=True)
    for line in sys.stdin:
        command = line.strip()
        if command == "probe":
            sent = recv = False
            try:
                tls.sendall(b"x")
                sent = True
                recv = tls.recv(1) == b"x"
            except OSError:
                pass
            print(json.dumps({"sent": sent, "recv": recv}), flush=True)
        elif command == "quit":
            break
    try:
        tls.close()
    except OSError:
        pass


if __name__ == "__main__":
    main()
