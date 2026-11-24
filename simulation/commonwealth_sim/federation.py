"""Federation decisions for the offline Step 4 fixture."""
import hmac

from . import actor as wire


class Federation:
    def __init__(self, role, directory, config):
        self.role, self.file, self.config = role, directory / "federation.json", config
        self.state = {"peers": [], "binding": None, "floor": None, "session": False}
        self.endpoint = "a-host-1"
        self.revision = 1

    def signed(self, purpose, data):
        return {"data": data, "tag": wire.tag(self.config["keys"]["op-a"][purpose], data)}

    def verified(self, purpose, signed):
        return hmac.compare_digest(self.signed(purpose, signed["data"])["tag"], signed["tag"])

    def emit(self, sender, recipient, op, **fields):
        return {"sender": sender, "recipient": recipient, "payload": {"op": op, **fields}}

    def apply(self, sender, tick, p):
        handlers = {
            "a-authority": {"enroll": ("op-a", self.enroll), "lookup": ("op-b", self.lookup),
                            "move": ("op-a", self.move)},
            "b": {"enroll": ("op-b", self.enroll), "discover": ("op-b", self.discover),
                  "discovery": ("op-a", self.discovery), "request": ("op-b", self.request),
                  "reply": ("op-a", self.reply), "exit": ("op-b", self.exit),
                  "control": ("op-b", self.control),
                  "control_reply": ("control-peer", self.control_reply)},
            "access": {"control_call": ("op-b", self.control_call)},
            "a-application": {"call": ("op-b", self.service_call), "serve": ("op-a", self.serve)},
        }
        entry = handlers.get(self.role, {}).get(p["op"])
        if not entry or sender != entry[0]:
            return {"decision": "local_authority_denied"}
        observation, emitted = entry[1](tick, p)
        self.file.write_bytes(wire.encode(self.state))
        return {"observation": observation, "emit": emitted}

    def enroll(self, tick, p):
        peer = "op-a" if self.role == "b" else "op-b"
        expected = self.config["federation"]["fingerprints"][peer]
        if p["peer"] != peer or p["fingerprint"] != expected:
            return {"decision": "fingerprint_denied"}, []
        if self.role == "b":
            descriptor = p["locator"]
            if not self.verified("operator", descriptor) or descriptor["data"] != self.config["federation"]["locator"]:
                return {"decision": "locator_denied"}, []
            self.state["locator"] = descriptor["data"]
        if peer not in self.state["peers"]:
            self.state["peers"].append(peer)
        return {"decision": "enrolled", "peer": peer, "fingerprint": expected,
                "binding": self.state["binding"]}, (
                    [self.emit("op-a", "a-application", "serve", endpoint=self.endpoint,
                               peers=self.state["peers"])] if self.role == "a-authority" else [])

    def discover(self, tick, p):
        if "op-a" not in self.state["peers"]:
            return {"decision": "peer_unenrolled"}, []
        return {"decision": "lookup_sent", "cache_empty": self.state["binding"] is None}, [
            self.emit("op-b", "a-authority", "lookup", locator=self.state["locator"],
                      service=p["service"], fault=p.get("fault", "none"))]

    def lookup(self, tick, p):
        if "op-b" not in self.state["peers"] or p["locator"] != self.config["federation"]["locator"]:
            return {"decision": "lookup_rejected"}, []
        fault = p["fault"]
        response = {"transport": "authenticated", "status": 200, "pin": p["locator"]["pin"]}
        if fault == "timeout":
            response = {"transport": "timeout"}
        elif fault == "tls_failure":
            response = {"transport": "tls_failure"}
        elif fault == "unavailable":
            response["status"] = 503
        elif p["service"] != "a.records":
            response["status"] = 404
        else:
            endpoint = self.endpoint if fault != "conflict" else "a-conflict"
            revision = self.revision if fault != "stale" else 1
            delegation = {"operator": "op-a", "service": "a.records", "publisher": "a-publisher"}
            record = {"service": "a.records", "publisher": "a-publisher", "endpoint": endpoint,
                      "endpoint_key": f"fixture:{endpoint}", "epoch": 1, "revision": revision,
                      "issued": tick if fault != "expired" else tick - 5,
                      "expires": tick + 5 if fault != "expired" else tick}
            response.update(pin=p["locator"]["pin"], delegation=self.signed("operator", delegation),
                            record=self.signed("publication", record))
            if fault == "bad_publication":
                response["record"]["tag"] = "invalid"
        return {"decision": "lookup_result", **response}, [
            self.emit("op-a", "b", "discovery", **response)]

    def discovery(self, tick, p):
        cached = self.state["binding"]
        floor = self.state["floor"]
        decision = self.binding_decision(tick, p)
        if decision == "accepted":
            record = p["record"]["data"]
            content = [record[key] for key in ("service", "endpoint", "endpoint_key")]
            self.state["binding"] = record
            self.state["floor"] = {"revision": record["revision"], "content": content}
        elif (cached and tick >= cached["expires"]) or decision == "unknown_service":
            self.state["binding"] = None
        return {"decision": decision, "binding": self.state["binding"], "floor": self.state["floor"],
                "floor_before": floor}, []

    def binding_decision(self, tick, p):
        if "op-a" not in self.state["peers"]:
            return "peer_unenrolled"
        if p["transport"] != "authenticated":
            return p["transport"]
        if p.get("pin") != self.state["locator"]["pin"]:
            return "authority_denied"
        if p["status"] != 200:
            return {503: "authenticated_unavailable", 404: "unknown_service"}[p["status"]]
        delegation, record = p["delegation"], p["record"]
        value = record["data"]
        if (p["pin"] != self.state["locator"]["pin"] or not self.verified("operator", delegation)
                or not self.verified("publication", record)
                or delegation["data"] != {"operator": "op-a", "service": value["service"],
                                          "publisher": value["publisher"]}
                or value["service"] != "a.records" or value["epoch"] != 1):
            return "authority_denied"
        if not value["issued"] <= tick < value["expires"]:
            return "expired"
        floor = self.state["floor"]
        if floor and value["revision"] < floor["revision"]:
            return "stale"
        content = [value[key] for key in ("service", "endpoint", "endpoint_key")]
        if floor and value["revision"] == floor["revision"] and content != floor["content"]:
            return "conflict"
        return "accepted"

    def move(self, tick, p):
        self.endpoint, self.revision = "a-host-2", 2
        return {"decision": "published", "revision": 2, "endpoint": self.endpoint}, [
            self.emit("op-a", "a-application", "serve", endpoint=self.endpoint, peers=self.state["peers"])]

    def serve(self, tick, p):
        self.endpoint = p["endpoint"]
        self.state["peers"] = p["peers"]
        return {"decision": "serving", "endpoint": self.endpoint}, []

    def request(self, tick, p):
        binding = self.state["binding"]
        if "op-a" not in self.state["peers"] or not binding or tick >= binding["expires"]:
            self.state["binding"] = None
            return {"decision": "no_usable_binding", "binding": None,
                    "floor": self.state["floor"]}, []
        return {"decision": "request_sent", "endpoint": binding["endpoint"]}, [
            self.emit("op-b", "a-application", "call", action=p["action"], endpoint=binding["endpoint"],
                      endpoint_key=binding["endpoint_key"])]

    def service_call(self, tick, p):
        if "op-b" not in self.state["peers"]:
            reply = {"decision": "peer_unenrolled"}
        elif p["endpoint"] != self.endpoint or p["endpoint_key"] != f"fixture:{self.endpoint}":
            reply = {"decision": "service_identity_denied"}
        elif p["action"] != "record.read":
            reply = {"decision": "destination_denied"}
        else:
            reply = {"decision": "allowed", "record-01": "commonwealth-fixture-v1"}
        reply["endpoint"] = self.endpoint
        if reply["decision"] != "allowed":
            reply["protected_payload"] = any(key.startswith("record-") for key in reply)
        return reply, [self.emit("op-a", "b", "reply", result=reply)]

    def reply(self, tick, p):
        self.state["session"] = p["result"]["decision"] == "allowed" or self.state["session"]
        return p["result"], []

    def exit(self, tick, p):
        self.state.update(peers=[], binding=None, session=False)
        return {"decision": "local_exit", "binding": None, "session": False,
                "notice": "unavailable"}, []

    def control(self, tick, p):
        return {"decision": "control_sent", "workload": "b.control"}, [
            self.emit("op-b", "access", "control_call")]

    def control_call(self, tick, p):
        return {"decision": "control_served"}, [
            self.emit("control-peer", "b", "control_reply", result="healthy")]

    def control_reply(self, tick, p):
        return {"decision": "control_received", "workload": "b.control", "result": p["result"]}, []
