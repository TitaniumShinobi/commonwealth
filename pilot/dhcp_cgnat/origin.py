"""Isolated fixture origin: authoritative DNS and HTTPS with fresh server nonces."""
from __future__ import annotations

import argparse
import json
import secrets
import socket
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn


NAME = b"origin.fixture.test"
A_RR = socket.inet_aton("203.0.113.10")


def dns_reply(query: bytes) -> bytes | None:
    if len(query) < 12:
        return None
    tid, flags, qd, *_ = struct.unpack("!HHHHHH", query[:12])
    if qd != 1:
        return None
    # Echo question and answer A for origin.fixture.test or fixture.test alias.
    question = query[12:]
    end = question.find(b"\x00")
    if end < 0:
        return None
    qname = question[: end + 1]
    qtype_class = question[end + 1 : end + 5]
    if len(qtype_class) != 4:
        return None
    qtype, qclass = struct.unpack("!HH", qtype_class)
    labels = []
    index = 0
    while index < len(qname) and qname[index] != 0:
        length = qname[index]
        labels.append(qname[index + 1 : index + 1 + length].decode("ascii", "ignore"))
        index += length + 1
    host = ".".join(labels).lower()
    if host not in {"origin.fixture.test", "fixture.test"} or qtype not in (1, 255) or qclass != 1:
        # NXDOMAIN / empty answer keeps negative controls honest when mis-aimed.
        header = struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0)
        return header + question[: end + 5]
    answer = qname + struct.pack("!HHIH", 1, 1, 30, 4) + A_RR
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    return header + question[: end + 5] + answer


def serve_dns(port: int, query_log: Path, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("203.0.113.10", port))
    sock.settimeout(0.3)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        reply = dns_reply(data)
        record = {"client": addr[0], "bytes": len(data), "answered": reply is not None}
        with query_log.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        if reply:
            sock.sendto(reply, addr)
    sock.close()


class Handler(BaseHTTPRequestHandler):
    nonce_log: Path

    def log_message(self, *_args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        nonce = secrets.token_hex(16)
        # Server-issued nonce returned only after a completed TLS handshake.
        body = f"ok nonce={nonce}\n".encode()
        with self.nonce_log.open("a") as handle:
            handle.write(json.dumps({"path": self.path, "nonce": nonce}) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Origin(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--query-log")
    parser.add_argument("--nonce-log")
    args = parser.parse_args()
    query_log = Path(args.query_log)
    nonce_log = Path(args.nonce_log)
    query_log.write_text("")
    nonce_log.write_text("")
    stop = threading.Event()
    threading.Thread(target=serve_dns, args=(53, query_log, stop), daemon=True).start()
    Handler.nonce_log = nonce_log
    server = Origin(("203.0.113.10", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("ready", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        stop.set()
        server.server_close()


if __name__ == "__main__":
    main()
