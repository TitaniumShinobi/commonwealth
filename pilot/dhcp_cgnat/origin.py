"""Isolated fixture origin: uncached DNS for *.fixture.test and HTTPS with fresh nonces."""
from __future__ import annotations

import argparse
import json
import secrets
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

A_RR = socket.inet_aton("203.0.113.10")


def parse_qname(question: bytes) -> tuple[str, bytes, bytes] | None:
    end = question.find(b"\x00")
    if end < 0:
        return None
    qname = question[: end + 1]
    qtype_class = question[end + 1 : end + 5]
    if len(qtype_class) != 4:
        return None
    labels = []
    index = 0
    while index < len(qname) and qname[index] != 0:
        length = qname[index]
        labels.append(qname[index + 1 : index + 1 + length].decode("ascii", "ignore"))
        index += length + 1
    return ".".join(labels).lower(), qname, qtype_class


def allowed_host(host: str) -> bool:
    return host == "origin.fixture.test" or host.endswith(".fixture.test")


def dns_reply(query: bytes) -> tuple[bytes | None, str | None, bool]:
    if len(query) < 12:
        return None, None, False
    tid, flags, qd, *_ = struct.unpack("!HHHHHH", query[:12])
    if qd != 1:
        return None, None, False
    parsed = parse_qname(query[12:])
    if parsed is None:
        return None, None, False
    host, qname, qtype_class = parsed
    qtype, qclass = struct.unpack("!HH", qtype_class)
    if not allowed_host(host) or qtype not in (1, 255) or qclass != 1:
        header = struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0)
        return header + qname + qtype_class, host, False
    # TTL 0: answers must not be reused as fresh recovery evidence.
    answer = qname + struct.pack("!HHIH", 1, 1, 0, 4) + A_RR
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    return header + qname + qtype_class + answer, host, True


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
        reply, qname, answered = dns_reply(data)
        record = {
            "client": addr[0],
            "qname": qname,
            "answered": answered,
            "bytes": len(data),
            "observed_at": time.time(),
        }
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
        host = self.headers.get("Host", "")
        body = f"ok nonce={nonce} host={host}\n".encode()
        with self.nonce_log.open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "path": self.path,
                        "host": host,
                        "nonce": nonce,
                        "peer": self.client_address[0],
                        "observed_at": time.time(),
                    }
                )
                + "\n"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Origin(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def serve_echo(cert: str, key: str, stop: threading.Event) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("203.0.113.10", 8443))
    sock.listen(16)
    sock.settimeout(0.3)
    while not stop.is_set():
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            continue
        try:
            tls = context.wrap_socket(conn, server_side=True)
            tls.settimeout(2)
            while not stop.is_set():
                item = tls.recv(1)
                if not item:
                    break
                tls.sendall(item)
            tls.close()
        except OSError:
            try:
                conn.close()
            except OSError:
                pass
    sock.close()


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
    threading.Thread(target=serve_echo, args=(args.cert, args.key, stop), daemon=True).start()
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
