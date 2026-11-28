"""Isolated fixture origin: uncached DNS, HTTPS nonces, and long-lived TLS echo."""
from __future__ import annotations

import argparse
import json
import secrets
import select
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
        with query_log.open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "client": addr[0],
                        "qname": qname,
                        "answered": answered,
                        "bytes": len(data),
                        "observed_at": time.time(),
                    }
                )
                + "\n"
            )
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


class EchoHub:
    """Long-lived TLS echo with receive audit and queued reverse heartbeats."""

    def __init__(self, audit: Path, control: Path) -> None:
        self.audit = audit
        self.control = control
        self.lock = threading.Lock()
        self.clients: list[ssl.SSLSocket] = []
        self.audit.write_text("")
        self.control.write_text("")

    def log_recv(self, probe_id: str, payload: str, peer: str) -> None:
        with self.audit.open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "kind": "server_recv",
                        "probe_id": probe_id,
                        "payload": payload,
                        "peer": peer,
                        "observed_at": time.time(),
                    }
                )
                + "\n"
            )

    def log_push(self, probe_id: str, ok: bool) -> None:
        with self.audit.open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "kind": "server_push",
                        "probe_id": probe_id,
                        "ok": ok,
                        "observed_at": time.time(),
                    }
                )
                + "\n"
            )

    def register(self, tls: ssl.SSLSocket) -> None:
        with self.lock:
            self.clients.append(tls)

    def unregister(self, tls: ssl.SSLSocket) -> None:
        with self.lock:
            if tls in self.clients:
                self.clients.remove(tls)

    def push(self, probe_id: str) -> None:
        frame = b"H" + probe_id.encode()[:4].ljust(4, b"0") + b"h"
        with self.lock:
            targets = list(self.clients)
        for tls in targets:
            try:
                tls.sendall(frame)
                self.log_push(probe_id, True)
            except OSError:
                self.log_push(probe_id, False)
                self.unregister(tls)


def serve_echo(cert: str, key: str, audit: Path, control: Path, stop: threading.Event) -> None:
    hub = EchoHub(audit, control)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("203.0.113.10", 8443))
    sock.listen(16)
    sock.settimeout(0.3)

    def client_loop(tls: ssl.SSLSocket, peer: str) -> None:
        hub.register(tls)
        tls.setblocking(False)
        try:
            buf = b""
            while not stop.is_set():
                readable, _, _ = select.select([tls], [], [], 0.5)
                if not readable:
                    continue
                try:
                    chunk = tls.recv(64)
                except ssl.SSLWantReadError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 6 and buf[0:1] == b"C":
                    probe_id = buf[1:5].decode("ascii", "replace")
                    payload = chr(buf[5])
                    buf = buf[6:]
                    hub.log_recv(probe_id, payload, peer)
                    try:
                        tls.sendall(b"S" + probe_id.encode()[:4].ljust(4, b"0") + payload.encode())
                    except OSError:
                        return
        finally:
            hub.unregister(tls)
            try:
                tls.close()
            except OSError:
                pass

    def control_loop() -> None:
        offset = 0
        while not stop.is_set():
            try:
                data = control.read_text()
            except OSError:
                time.sleep(0.2)
                continue
            if len(data) > offset:
                chunk = data[offset:]
                offset = len(data)
                for line in chunk.splitlines():
                    parts = line.strip().split()
                    if len(parts) == 2 and parts[0] == "push":
                        hub.push(parts[1][:4])
            time.sleep(0.1)

    threading.Thread(target=control_loop, daemon=True).start()
    while not stop.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        try:
            tls = context.wrap_socket(conn, server_side=True)
        except OSError:
            conn.close()
            continue
        threading.Thread(target=client_loop, args=(tls, addr[0]), daemon=True).start()
    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--query-log")
    parser.add_argument("--nonce-log")
    parser.add_argument("--echo-audit")
    parser.add_argument("--echo-control")
    args = parser.parse_args()
    query_log = Path(args.query_log)
    nonce_log = Path(args.nonce_log)
    echo_audit = Path(args.echo_audit)
    echo_control = Path(args.echo_control)
    query_log.write_text("")
    nonce_log.write_text("")
    stop = threading.Event()
    threading.Thread(target=serve_dns, args=(53, query_log, stop), daemon=True).start()
    threading.Thread(
        target=serve_echo, args=(args.cert, args.key, echo_audit, echo_control, stop), daemon=True
    ).start()
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
