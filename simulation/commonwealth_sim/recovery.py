"""Step 6 recovery authorities and protected exchange for the offline fixture."""
import hashlib
import hmac

from . import actor as wire

OLD, NEW, SERVICE = "a-host-1", "a-host-2", "a.records"
STORE_ROLES = {"authorization": "recover-authz", "publication": "recover-pub",
               "credentials": "recover-creds"}
FENCE_ROLES = {"ingress": "ingress-owner", "writer": "writer-owner"}
PRIVILEGED = {"enroll", "backup", "loss", "fence", "withdraw", "approve", "restore",
              "restore_commit", "reopen", "issue", "publish", "checkpoint", "reconcile",
              "renew", "cross_queue", "write"}


def digest(value):
    return hashlib.sha256(wire.encode(value)).hexdigest()


class Recovery:
    def __init__(self, role, directory, config):
        self.role, self.directory, self.config = role, directory, config
        self.host = NEW if directory.name == NEW else OLD
        self.store_path = directory / "records.json"
        if role == "a-application" and self.host == OLD:
            self.store_path.write_bytes(wire.encode({"records": {"record-01": "commonwealth-fixture-v1"},
                                                     "data_tick": 8, "restore": None}))
        self.fences = {name: 1 for name in FENCE_ROLES}
        self.readback = {name: True for name in FENCE_ROLES}
        # Journals are preserved independently of each recovered active checkpoint.
        self.journal = {"authorization": {"revision": 1, "revoked": []},
                        "publication": {"revision": 1, "withdrawn": []},
                        "credentials": {"revision": 1, "withdrawn": []}}
        self.current = {name: dict(state) for name, state in self.journal.items()}
        self.uncertain = set()
        self.approved = None
        self.backup_data = None
        self.restored = None
        self.lost = None
        self.active = OLD
        self.credential = "serve:1"
        self.writes = 0
        self.enrolled = False
        self.trust = {"operator": "op-a", "publication_principal": "publisher"}
        self.policy = {"allowed_service": SERVICE}
        self.binding = None
        self.floor = 0
        self.controls = {}
        self.crossings = {"old": {"live": True, "queued": [], "session": "session:old",
                                  "credential": "token:old", "buffer": "buffer:old"},
                          "unrelated": {"live": True, "queued": [], "session": "session:other",
                                        "credential": "token:other", "buffer": None}}
        self.cross_effects = 0
        self.unrelated_operations = []
        self.audit = []

    def sign(self, purpose, value):
        key = self.config["recovery_keys"][purpose]
        return {"data": value, "tag": wire.tag(key, value)}

    def verify(self, purpose, envelope):
        return hmac.compare_digest(self.sign(purpose, envelope["data"])["tag"], envelope["tag"])

    def emit(self, sender, recipient, op, **kwargs):
        return {"sender": sender, "recipient": recipient, "purpose": "recovery",
                "payload": {"op": op, **kwargs}}

    def apply(self, sender, tick, p):
        routes = {
            "a-authority": {
                "enroll": "op-a", "capture": "backup-owner", "backup": "old-host",
                "loss": "00-lifecycle", "fence": FENCE_ROLES.get(p.get("boundary")),
                "withdraw": "authz-owner", "approve": "restore-owner",
                "restore": "a-steward", "restore_result": "new-host",
                "issue": "credential-owner", "publish": "publisher",
                "read_gate": "op-b", "disclose": ("old-host", "new-host"),
                "old_read": "old-host", "write": "old-host",
                "checkpoint": STORE_ROLES.get(p.get("store")),
                "reconcile": STORE_ROLES.get(p.get("store")),
                "credential_check": "old-host", "rejoin_candidate": ("publisher", "op-b"),
                "cross_queue": "op-b", "cross_use": "op-b", "renew": "authz-owner",
                "audit_state": "fixture-observer", "authority_state": "fixture-observer",
            },
            "a-application": {"snapshot": "backup-owner", "restore_commit": "restore-owner",
                              "store_state": "fixture-observer", "read_store": "serve-gate"},
            "b": {"enroll": "op-b", "binding": ("publisher", "sim-controller"),
                  "read": "op-b", "read_result": "serve-gate", "peer_state": "fixture-observer",
                  "control_commit": "fixture-observer", "control_read": "fixture-observer"},
        }
        op = p["op"]
        allowed = routes.get(self.role, {}).get(op)
        if not allowed or sender not in ((allowed,) if isinstance(allowed, str) else allowed):
            result, messages = {"decision": "role_denied"}, []
        else:
            result, messages = getattr(self, "accept_binding" if op == "binding" else op)(tick, p)
        if op in PRIVILEGED or sender == "founder":
            self.audit.append({"tick": tick, "sender": sender, "operation": op,
                               "target": self.role, "decision": result["decision"]})
        return {"observation": result, "emit": messages}

    def enroll(self, tick, p):
        peer = "op-a" if self.role == "b" else "op-b"
        if p["peer"] != peer or p["fingerprint"] != self.config["federation"]["fingerprints"][peer]:
            return {"decision": "identity_denied"}, []
        self.enrolled = True
        return {"decision": "enrolled", "peer": peer}, []

    def capture(self, tick, p):
        return {"decision": "snapshot_requested"}, [self.emit("backup-owner", "a-application", "snapshot")]

    def snapshot(self, tick, p):
        state = wire.decode(self.store_path.read_bytes())
        manifest = {"service": SERVICE, "source": self.host, "data_tick": state["data_tick"],
                    "digest": digest(state["records"])}
        return {"decision": "snapshot_read", "manifest": manifest}, [
            self.emit("old-host", "a-authority", "backup", manifest=self.sign("backup", manifest),
                      records=state["records"])]

    def backup(self, tick, p):
        envelope = p["manifest"]
        manifest = envelope["data"]
        if (not self.verify("backup", envelope) or manifest["source"] != OLD
                or manifest["service"] != SERVICE or manifest["data_tick"] > tick
                or manifest["digest"] != digest(p["records"])):
            return {"decision": "backup_denied"}, []
        self.backup_data = {"manifest": envelope, "records": p["records"]}
        self.directory.joinpath("backup.json").write_bytes(wire.encode(self.backup_data))
        return {"decision": "backup_verified", "manifest": manifest}, []

    def change(self, store, **changes):
        state = {**self.journal[store], **changes}
        self.journal[store] = state
        self.current[store] = dict(state)
        self.directory.joinpath(f"{store}.json").write_bytes(wire.encode(state))
        self.directory.joinpath(f"{store}-journal.json").write_bytes(wire.encode(state))

    def loss(self, tick, p):
        self.lost, self.active = tick, None
        self.readback = dict.fromkeys(FENCE_ROLES, False)
        self.change("credentials", revision=2, withdrawn=["serve:1"])
        self.change("publication", withdrawn=[1])
        return {"decision": "host_lost", "tick": tick, "active": None}, []

    def fence(self, tick, p):
        name = p["boundary"]
        if self.lost is None:
            return {"decision": "loss_required"}, []
        if not p.get("available", True):
            return {"decision": "readback_unavailable", "boundary": name}, []
        self.fences[name] = 2
        self.directory.joinpath(f"fence-{name}").write_text("2")
        observed = int(self.directory.joinpath(f"fence-{name}").read_text())
        self.readback[name] = observed == 2
        return {"decision": "fenced", "boundary": name, "generation": observed}, []

    def withdraw(self, tick, p):
        self.change("authorization", revision=2, revoked=["b-revoked-01"])
        self.crossings["old"].update(live=False, queued=[], session=None, credential=None, buffer=None)
        return {"decision": "withdrawn", "credential": "b-revoked-01",
                "crossing": dict(self.crossings["old"])}, []

    def approve(self, tick, p):
        if not self.backup_data or self.lost is None:
            return {"decision": "restore_not_ready"}, []
        approval = {"steward": "a-steward", "operation": p["operation"], "service": SERVICE,
                    "target": NEW, "backup_digest": self.backup_data["manifest"]["data"]["digest"]}
        self.approved = approval
        return {"decision": "approved", "approval": approval}, []

    def restore(self, tick, p):
        approval = self.approved
        if not approval or p["operation"] != approval["operation"] or p["target"] != approval["target"]:
            return {"decision": "restore_authority_denied"}, []
        backup = wire.decode(self.directory.joinpath("backup.json").read_bytes())
        if p.get("tamper"):
            backup["records"]["record-01"] = "altered"
        if (not self.verify("backup", backup["manifest"])
                or digest(backup["records"]) != approval["backup_digest"]):
            return {"decision": "integrity_denied"}, []
        return {"decision": "restore_admitted"}, [
            self.emit("restore-owner", "a-application", "restore_commit",
                      approval=self.sign("approval", approval), **backup)]

    def restore_commit(self, tick, p):
        approval = p["approval"]["data"]
        manifest = p["manifest"]["data"]
        if (self.host != NEW or not self.verify("approval", p["approval"])
                or approval["target"] != self.host or approval["steward"] != "a-steward"
                or approval["service"] != manifest["service"] or manifest["service"] != SERVICE
                or not self.verify("backup", p["manifest"])
                or digest(p["records"]) != manifest["digest"]
                or manifest["digest"] != approval["backup_digest"]):
            return {"decision": "commit_denied"}, []
        if not self.store_path.exists():
            state = {"records": p["records"], "data_tick": manifest["data_tick"],
                     "restore": approval, "commits": 1}
            staged = self.store_path.with_suffix(".next")
            with staged.open("xb") as stream:
                stream.write(wire.encode(state))
                stream.flush()
                import os
                os.fsync(stream.fileno())
            staged.replace(self.store_path)
            decision = "restored"
        else:
            state = wire.decode(self.store_path.read_bytes())
            if state["restore"] != approval:
                return {"decision": "target_not_clean"}, []
            decision = "duplicate_restore"
        persisted = wire.decode(self.store_path.read_bytes())
        result = {"decision": decision, "host": self.host, "commits": persisted["commits"],
                  "operation": approval["operation"], "data_tick": persisted["data_tick"],
                  "digest": digest(persisted["records"]), "clean_prestate": decision == "restored"}
        return result, [self.emit("new-host", "a-authority", "restore_result", result=result)]

    def restore_result(self, tick, p):
        result = p["result"]
        if (not self.approved or result["operation"] != self.approved["operation"]
                or result["digest"] != self.approved["backup_digest"] or result["host"] != NEW):
            return {"decision": "restore_result_denied"}, []
        self.restored = result
        return {"decision": "restore_recorded", "commits": result["commits"]}, []

    def store_state(self, tick, p):
        state = wire.decode(self.store_path.read_bytes()) if self.store_path.exists() else {}
        return {"decision": "store_observed", "host": self.host, "empty": not state,
                "commits": state.get("commits", 0), "state_digest": digest(state)}, []

    def issue(self, tick, p):
        if "credentials" in self.uncertain:
            return {"decision": "issuer_uncertain"}, []
        missing = sorted(name for name in FENCE_ROLES if not self.readback[name] or self.fences[name] != 2)
        if missing or self.uncertain or not self.restored:
            return {"decision": "admission_closed", "missing_fences": missing}, []
        if p["host"] != self.restored["host"]:
            return {"decision": "credential_target_denied"}, []
        self.credential = "serve:2"
        self.change("credentials", revision=3, withdrawn=["serve:1"], current=self.credential, host=NEW)
        return {"decision": "credential_issued", "host": NEW, "credential": self.credential}, []

    def publish(self, tick, p):
        if "publication" in self.uncertain:
            return {"decision": "publisher_uncertain"}, []
        host = p["host"]
        if host == OLD and self.lost is None and self.enrolled:
            revision = 1
        elif (host == NEW and self.restored and self.credential == "serve:2"
              and all(self.readback.values()) and not self.uncertain):
            revision = 2
            self.active = NEW
            self.change("publication", revision=2, withdrawn=[1])
        else:
            return {"decision": "publication_closed"}, []
        data = {"service": SERVICE, "host": host, "revision": revision,
                "credential": self.credential, "generation": revision}
        return {"decision": "published", **data}, [
            self.emit("publisher", "b", "binding", record=self.sign("publication", data),
                      rejoin=self.sign("rejoin", data))]

    def accept_binding(self, tick, p):
        data = p["record"]["data"]
        before = self.binding
        if not self.enrolled or data["service"] != self.policy["allowed_service"]:
            decision = "peer_denied"
        elif not self.verify("publication", p["record"]):
            decision = "publication_denied"
        elif not self.verify("rejoin", p["rejoin"]) or p["rejoin"]["data"] != data:
            decision = "rejoin_denied"
        elif data["revision"] < self.floor or (before and data["revision"] == self.floor and before != data):
            decision = "binding_rollback_denied"
        elif (data["host"], data["credential"], data["generation"]) != (
                OLD if data["revision"] == 1 else NEW, f"serve:{data['revision']}", data["revision"]):
            decision = "serving_identity_denied"
        else:
            self.binding, self.floor = data, data["revision"]
            self.directory.joinpath("binding.json").write_bytes(wire.encode(data))
            decision = "binding_accepted"
        return {"decision": decision, "before": before, "binding": self.binding,
                "binding_digest": digest(self.binding), "trust_digest": digest(self.trust),
                "policy_digest": digest(self.policy), "configuration_changes": []}, []

    def peer_state(self, tick, p):
        return {"decision": "peer_state", "trust_digest": digest(self.trust),
                "policy_digest": digest(self.policy), "binding_digest": digest(self.binding),
                "binding": self.binding, "configuration_changes": []}, []

    def rejoin_candidate(self, tick, p):
        revision = p["revision"]
        data = {"service": SERVICE, "host": OLD if revision == 1 else NEW, "revision": revision,
                "credential": f"serve:{revision}", "generation": revision}
        rejoin = self.sign("rejoin", data)
        if p.get("invalid"):
            rejoin["tag"] = "invalid"
        return {"decision": "candidate_delivered"}, [
            self.emit("publisher", "b", "binding", record=self.sign("publication", data), rejoin=rejoin)]

    def read(self, tick, p):
        target = self.binding
        if p.get("target"):
            target = {"host": p["target"], "generation": 2, "credential": "serve:2"}
        if not target:
            return {"decision": "no_binding"}, []
        return {"decision": "requested", "host": target["host"]}, [
            self.emit("op-b", "a-authority", "read_gate", target=target, user=p.get("user", "b-allowed"))]

    def access_decision(self, tick, user, target):
        if target["host"] == OLD and self.lost is not None:
            return "ingress_fenced" if self.fences["ingress"] > target["generation"] else "service_unavailable"
        if self.uncertain:
            return "authority_uncertain"
        if (target["host"] != self.active or target["credential"] != self.credential
                or target["generation"] != self.fences["ingress"]):
            return "service_closed"
        if user in self.current["authorization"]["revoked"] or user not in ("b-allowed", "b-revoked-01"):
            return "credential_denied"
        return "allowed"

    def read_gate(self, tick, p):
        target = p["target"]
        decision = self.access_decision(tick, p["user"], target)
        if decision != "allowed":
            result = {"decision": decision, "host": target["host"], "disclosed": False}
            return result, [self.emit("serve-gate", "b", "read_result", result=result)]
        return {"decision": "read_admitted", "host": target["host"]}, [
            self.emit("serve-gate", "a-application", "read_store", target=target, user=p["user"])]

    def read_store(self, tick, p):
        if p["target"]["host"] != self.host:
            return {"decision": "host_identity_mismatch"}, []
        state = wire.decode(self.store_path.read_bytes())
        principal = "old-host" if self.host == OLD else "new-host"
        return {"decision": "store_read", "host": self.host, "data_digest": digest(state["records"])}, [
            self.emit(principal, "a-authority", "disclose", user=p["user"], target=p["target"],
                      records=state["records"], data_tick=state["data_tick"])]

    def disclose(self, tick, p):
        target = p["target"]
        decision = self.access_decision(tick, p["user"], target)
        result = {"decision": decision, "host": target["host"], "disclosed": decision == "allowed"}
        if decision == "allowed":
            result.update(records=p["records"], data_tick=p["data_tick"], revision=target["generation"])
        return result, [self.emit("serve-gate", "b", "read_result", result=result)]

    def read_result(self, tick, p):
        return {**p["result"], "tick": tick}, []

    def old_read(self, tick, p):
        return self.read_gate(tick, p)

    def write(self, tick, p):
        allowed = p["generation"] == self.fences["writer"] and self.readback["writer"]
        if allowed:
            self.writes += 1
        return {"decision": "committed" if allowed else "writer_fenced",
                "committed": allowed, "writes": self.writes, "issued_tick": p["issued_tick"]}, []

    def checkpoint(self, tick, p):
        store = p["store"]
        stale = {"revision": 0, {"authorization": "revoked", "publication": "withdrawn",
                 "credentials": "withdrawn"}[store]: []}
        self.current[store] = stale
        self.uncertain.add(store)
        self.directory.joinpath(f"{store}.json").write_bytes(wire.encode(stale))
        return {"decision": "checkpoint_loaded", "store": store, "current_verified": False}, []

    def reconcile(self, tick, p):
        store = p["store"]
        if store not in self.uncertain:
            return {"decision": "recovery_not_pending"}, []
        verified = wire.decode(self.directory.joinpath(f"{store}-journal.json").read_bytes())
        if verified != self.journal[store]:
            return {"decision": "reconciliation_denied"}, []
        self.change(store, **verified)
        self.uncertain.remove(store)
        return {"decision": "reconciled", "store": store, "state": verified}, []

    def credential_check(self, tick, p):
        allowed = ("credentials" not in self.uncertain
                   and p["credential"] == self.current["credentials"].get("current")
                   and p["credential"] not in self.current["credentials"]["withdrawn"])
        return {"decision": "credential_allowed" if allowed else "credential_denied",
                "credential": p["credential"]}, []

    def cross_queue(self, tick, p):
        crossing = self.crossings[p["id"]]
        crossing["queued"].append(p["operation"])
        return {"decision": "queued", "queued": list(crossing["queued"])}, []

    def cross_use(self, tick, p):
        crossing = self.crossings.get(p["id"])
        if not crossing or not crossing["live"] or crossing["credential"] != p["credential"]:
            return {"decision": "crossing_denied", "disclosed": False, "committed": False,
                    "effects": self.cross_effects}, []
        if p["id"] == "unrelated":
            self.unrelated_operations.append(p["operation"])
        else:
            self.cross_effects += 1
        return {"decision": "crossing_operated", "effect": p["operation"], "domain": "a-authority"}, []

    def renew(self, tick, p):
        if p["id"] in self.crossings or "authorization" in self.uncertain:
            return {"decision": "renewal_denied"}, []
        self.crossings[p["id"]] = {"live": True, "queued": [], "session": "session:new",
                                   "credential": "token:new", "buffer": None}
        return {"decision": "fresh_authorization", "credential": "token:new"}, []

    def control_commit(self, tick, p):
        operation = p["operation"]
        self.controls.setdefault(operation, len(self.controls) + 1)
        self.directory.joinpath("control.json").write_bytes(wire.encode(self.controls))
        return {"decision": "control_committed", "operation": operation,
                "count": self.controls[operation]}, []

    def control_read(self, tick, p):
        persisted = wire.decode(self.directory.joinpath("control.json").read_bytes())
        return {"decision": "control_read", "operation": p["operation"],
                "count": persisted.get(p["operation"])}, []

    def authority_state(self, tick, p):
        return {"decision": "authority_state", "active": self.active, "fences": dict(self.fences),
                "readback": dict(self.readback), "writes": self.writes, "restored": self.restored,
                "uncertain": sorted(self.uncertain), "crossings": self.crossings,
                "unrelated_operations": list(self.unrelated_operations),
                "state_digest": digest(self.current)}, []

    def audit_state(self, tick, p):
        return {"decision": "audited", "events": list(self.audit), "role": self.role}, []
