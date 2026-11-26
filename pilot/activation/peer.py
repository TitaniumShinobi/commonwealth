"""Protected mTLS fixture peer and two separate isolation probes."""
import http.server
import json
import ssl
import sys
import threading
from pathlib import Path

keys = Path(sys.argv[1])


class Peer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        identity = self.connection.getpeercert()
        allowed = self.path == "/records/record-01" and any(
            pair == ("commonName", "wired-guest-peer")
            for group in identity.get("subject", ()) for pair in group)
        body = (b'{"record-01":"wired-crossing-fixture"}' if allowed else b'{}')
        self.send_response(200 if allowed else 403)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(json.dumps({"decision": "allowed" if allowed else "denied", "path": self.path,
                          "subject": identity.get("subject", ())}), flush=True)


class Control(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"protected fixture")


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(keys / "server.pem", keys / "server.key")
context.load_verify_locations(keys / "ca.pem")
context.verify_mode = ssl.CERT_REQUIRED
with http.server.ThreadingHTTPServer(("10.231.60.2", 8443), Peer) as peer, \
        http.server.ThreadingHTTPServer(("10.231.60.3", 8080), Control) as household, \
        http.server.ThreadingHTTPServer(("10.231.60.4", 8080), Control) as management:
    peer.socket = context.wrap_socket(peer.socket, server_side=True)
    for other in (household, management):
        threading.Thread(target=other.serve_forever, daemon=True).start()
    print("ready", flush=True)
    peer.serve_forever()
