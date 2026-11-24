"""Scoped authorization and cleanup decisions for synthetic Step 5 cases."""


class Household:
    def __init__(self, role, topology):
        self.role = role
        self.config = topology.get("household", {})
        self.devices = {}
        self.grants = {}
        self.crossings = {}
        self.available = True
        self.revision = 0

    def apply(self, sender, tick, payload):
        operation = payload["op"]
        routes = {
            "enroll_device": ("a-authority", "a-admin", self.enroll_device),
            "appraise": ("a-authority", "fixture-verifier", self.appraise),
            "grant": ("a-authority", "a-admin", self.grant),
            "open": ("a-authority", None, self.open_crossing),
            "action": ("a-authority", None, self.action),
            "commit": ("a-authority", "a-worker", self.commit),
            "close": ("a-authority", "a-admin", self.close),
            "authority": ("a-authority", "a-admin", self.authority),
            "inspect": ("a-authority", "a-admin", self.inspect),
            "boundary": ("a-application", None, self.boundary),
            "source_health": ("b", "fixture-probe", self.health),
            "destination_health": ("a-application", "fixture-probe", self.health),
        }
        entry = routes.get(operation)
        if not entry or self.role != entry[0] or (entry[1] and sender != entry[1]):
            return {"decision": "local_authority_denied"}
        result = entry[2](sender, tick, payload)
        if operation == "boundary" and result["decision"] == "forwarded_to_gateway" and "request" in payload:
            return {"observation": result, "emit": [{"sender": sender, "recipient": "a-authority",
                    "purpose": "household", "payload": {"op": "action", **payload["request"]}}]}
        return {"observation": result}

    def enroll_device(self, sender, tick, payload):
        device = payload["device"]
        if device in self.devices:
            return {"decision": "already_enrolled"}
        self.devices[device] = {"challenge": payload["challenge"], "expires": None}
        return {"decision": "enrolled", "device": device, "appraised": False}

    def appraise(self, sender, tick, payload):
        device = self.devices.get(payload["device"])
        if (not device or device["challenge"] != payload["challenge"]
                or payload["evidence"] != "fixture-supported-device"):
            return {"decision": "appraisal_denied"}
        device["expires"] = tick + self.config["appraisal_ticks"]
        device["challenge"] = None
        return {"decision": "appraised", "expires": device["expires"]}

    def grant(self, sender, tick, payload):
        identity = payload["id"]
        principal = self.config["workloads"].get(payload["subject"])
        if (identity in self.grants or not principal or principal["device"] not in self.devices
                or payload["resource"] != "household/calendar"
                or payload["audience"] != "calendar-gateway" or payload["action"] != "calendar.view"
                or payload["expires"] <= tick):
            return {"decision": "grant_denied"}
        self.revision += 1
        self.grants[identity] = {**payload, "issued_revision": self.revision, "revoked": False}
        return {"decision": "granted", "id": identity, "revision": self.revision}

    def authorize(self, sender, tick, request):
        if not self.available:
            return "current_authority_unavailable"
        workload = self.config["workloads"].get(sender)
        if not workload or request["workload"] != workload["identity"]:
            return "workload_denied"
        device = self.devices.get(request["device"])
        if (request["device"] != workload["device"] or not device or
                device["expires"] is None or tick >= device["expires"]):
            return "device_evidence_denied"
        grant = self.grants.get(request["grant"])
        if not grant or grant["revoked"] or tick >= grant["expires"]:
            return "grant_inactive"
        if (grant["subject"] != sender or any(
                request[field] != grant[field] for field in ("resource", "audience", "action"))):
            return "scope_denied"
        return "allowed"

    def open_crossing(self, sender, tick, payload):
        decision = self.authorize(sender, tick, payload)
        identity = payload["crossing"]
        if decision != "allowed":
            return {"decision": decision}
        if identity in self.crossings:
            return {"decision": "crossing_id_in_use"}
        self.crossings[identity] = {"request": dict(payload), "owner": sender,
                                    "session": True, "credential": f"scoped:{identity}",
                                    "buffer": f"transient:{identity}", "pending": {},
                                    "effects": {}, "closed": False}
        return {"decision": "opened", "credential": f"scoped:{identity}",
                "crossing": identity, "revision": self.revision}

    def action(self, sender, tick, payload):
        decision = self.authorize(sender, tick, payload)
        crossing = self.crossings.get(payload["crossing"])
        if decision != "allowed":
            return {"decision": decision, "disclosed": False}
        if (not crossing or crossing["owner"] != sender or not crossing["session"]
                or crossing["request"]["grant"] != payload["grant"]
                or crossing["credential"] != payload["credential"]):
            return {"decision": "crossing_denied", "disclosed": False}
        operation = payload["operation"]
        body = payload["body"]
        if operation in crossing["effects"]:
            if crossing["effects"][operation] != body:
                return {"decision": "operation_conflict", "disclosed": False}
            return {"decision": "stored_result", "record": self.config["record"]}
        if operation in crossing["pending"]:
            decision = "already_queued" if crossing["pending"][operation] == body else "operation_conflict"
            return {"decision": decision, "disclosed": False}
        if payload["mode"] == "queue":
            crossing["pending"][operation] = body
            return {"decision": "queued", "disclosed": False}
        crossing["effects"][operation] = body
        return {"decision": "allowed", "record": self.config["record"]}

    def commit(self, sender, tick, payload):
        crossing = self.crossings[payload["crossing"]]
        operation = payload["operation"]
        decision = self.authorize(crossing["owner"], tick, crossing["request"])
        if decision != "allowed":
            return {"decision": decision, "committed": False,
                    "effect_count": len(crossing["effects"])}
        if crossing["closed"] or operation not in crossing["pending"]:
            return {"decision": "not_pending", "committed": False}
        crossing["effects"][operation] = crossing["pending"].pop(operation)
        return {"decision": "committed", "committed": True,
                "effect_count": len(crossing["effects"])}

    def close(self, sender, tick, payload):
        identity = payload["crossing"]
        crossing = self.crossings[identity]
        if not crossing["closed"]:
            grant = crossing["request"]["grant"]
            self.grants[grant]["revoked"] = True
            self.revision += 1
            for related in self.crossings.values():
                if related["request"]["grant"] == grant:
                    related.update(session=False, credential=None, buffer=None, pending={}, closed=True)
        return self.inspect(sender, tick, payload)

    def authority(self, sender, tick, payload):
        self.available = payload["available"]
        return {"decision": "authority_updated", "available": self.available}

    def inspect(self, sender, tick, payload):
        crossing = self.crossings[payload["crossing"]]
        return {"decision": "state", "session": crossing["session"],
                "credential": crossing["credential"], "buffer": crossing["buffer"],
                "pending": sorted(crossing["pending"]), "effect_count": len(crossing["effects"]),
                "closed": crossing["closed"], "revision": self.revision,
                "grant_revoked": self.grants[crossing["request"]["grant"]]["revoked"]}

    def boundary(self, sender, tick, payload):
        workload = self.config["workloads"].get(sender)
        allowed = (workload is not None and payload["workload"] == workload["identity"]
                   and payload["target"] == "calendar-gateway"
                   and payload["tenant"] == "household"
                   and payload["path"] == "controlled-interface")
        return {"decision": "forwarded_to_gateway" if allowed else "boundary_denied",
                "target": payload["target"], "protected_payload": False}

    def health(self, sender, tick, payload):
        return {"decision": "healthy", "domain": self.role, "tick": tick}
