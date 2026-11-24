"""Line-delimited protocol and offline actors for synthetic fixtures."""
import hashlib
import hmac
import json
import resource
import sys
from pathlib import Path

LINE = 16 * 1024
MEMORY = 1024 ** 3


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_number(value):
    raise ValueError(f"unsupported number: {value}")


def integer(value):
    number = int(value)
    if not -(2 ** 63) <= number < 2 ** 63:
        raise ValueError("integer outside signed 64-bit range")
    return number


def decode(data):
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                       parse_int=integer, parse_float=reject_number,
                       parse_constant=reject_number)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def tag(key, envelope):
    return hmac.new(key.encode(), encode(envelope), hashlib.sha256).hexdigest()


class Access:
    def __init__(self, fixture):
        self.fixture = fixture
        self.credentials = set(fixture["guests"])
        self.sessions = {}
        self.cache = {}
        self.flows = {}
        self.resolver_online = True

    def apply(self, tick, payload):
        action = payload["action"]
        session = payload.get("session")
        profile = self.sessions.get(session)
        active = profile is not None and profile["credential"] in self.credentials
        provisioned = active and "lease" in profile
        if action == "attach":
            credential = payload["credential"]
            guest = self.fixture["guests"].get(credential)
            allowed = credential in self.credentials and guest["session"] == session
            if allowed:
                self.sessions.setdefault(session, {"credential": credential})
            return {"allowed": allowed}
        if action == "provision":
            if not active:
                return {"allowed": False}
            guest = self.fixture["guests"][profile["credential"]]
            profile.update(lease=guest["lease"], gateway=self.fixture["gateway"],
                           resolver=self.fixture["resolver"])
            return {key: profile[key] for key in ("lease", "gateway", "resolver")}
        if action == "resolver_offline":
            self.resolver_online = False
            return {"online": False}
        if action == "resolve":
            if not provisioned:
                return {"allowed": False}
            name = payload["name"]
            cached = self.cache.get(name)
            if cached and tick < cached["expiry"]:
                return {"source": "cache", **cached}
            self.cache.pop(name, None)
            if not self.resolver_online or name not in self.fixture["dns"]:
                return {"allowed": False}
            record = {"address": self.fixture["dns"][name], "expiry": tick + self.fixture["ttl"]}
            self.cache[name] = record
            return {"source": "resolver", **record}
        if action == "forward":
            allowed = provisioned and payload["destination"] in self.fixture["public_destinations"]
            if allowed:
                self.flows[payload["flow"]] = session
                return {"allowed": True, "translated_source": self.fixture["nat"]}
            return {"allowed": False}
        if action == "withdraw":
            credential = payload["credential"]
            self.credentials.discard(credential)
            for flow, owner in tuple(self.flows.items()):
                if self.sessions[owner]["credential"] == credential:
                    del self.flows[flow]
            return {"withdrawn": credential}
        if action == "observe":
            return {"attached": profile is not None, "lease": profile and profile.get("lease"),
                    "flow_active": self.flows.get(payload["flow"]) == session}
        raise ValueError(f"unknown access action {action}")


class Actor:
    def __init__(self, role, directory, topology, run, case):
        self.role, self.directory, self.topology = role, directory, topology
        self.run, self.case = run, case
        self.accepted = {}
        self.sequence = {}
        self.closed_tick = -1
        from .federation import Federation
        from .household import Household
        self.household = Household(role, topology)
        self.federation = Federation(role, directory, topology)
        self.access = Access(topology["access"]) if role == "access" else None

    def receive(self, envelope, signature):
        sender, purpose = envelope["sender"], envelope["purpose"]
        key = self.topology["keys"].get(sender, {}).get(purpose)
        if not key or not hmac.compare_digest(tag(key, envelope), signature):
            return {"decision": "authentication_rejected"}
        if (envelope["version"], envelope["run"], envelope["case"], envelope["recipient"]) != (
                1, self.run, self.case, self.role):
            return {"decision": "context_rejected"}
        digest = hashlib.sha256(encode(envelope)).hexdigest()
        identity = (self.run, self.case, sender, envelope["id"])
        if identity in self.accepted:
            return {"decision": "duplicate" if self.accepted[identity] == digest else "id_conflict"}
        tick = envelope["tick"]
        if (tick <= self.closed_tick or not envelope["valid_from"] <= tick < envelope["expires"]
                or envelope["sequence"] <= self.sequence.get(sender, 0)):
            return {"decision": "stale_rejected"}
        permitted = (sender, purpose) == ("harness", "smoke") or (
            self.role == "access" and (sender, purpose) == ("access-operator", "access"))
        if not permitted and purpose not in ("federation", "household"):
            return {"decision": "authority_rejected"}
        self.accepted[identity] = digest
        self.sequence[sender] = envelope["sequence"]
        if purpose == "smoke":
            return {"decision": "accepted", "role": self.role,
                    "state_directory": str(self.directory), "limits": list(resource.getrlimit(resource.RLIMIT_AS))}
        if purpose == "household":
            return {"decision": "accepted", **self.household.apply(sender, tick, envelope["payload"])}
        if purpose == "federation":
            return {"decision": "accepted", **self.federation.apply(sender, tick, envelope["payload"])}
        return {"decision": "accepted", "observation": self.access.apply(tick, envelope["payload"])}

    def dispatch(self, request):
        kind = request["kind"]
        if kind == "deliver":
            return self.receive(request["envelope"], request["tag"])
        if kind == "close_tick" and request["tick"] == self.closed_tick + 1:
            self.closed_tick = request["tick"]
            return {"closed": self.closed_tick}
        if kind == "probe" and self.role == "b" and request["tick"] == self.closed_tick:
            return {"healthy": True, "workload": "b.control", "tick": self.closed_tick}
        raise ValueError(f"invalid control message: {kind}")


def main():
    role, directory, topology_path, run, case = sys.argv[1:]
    directory = Path(directory)
    directory.mkdir(exist_ok=False)
    actor = Actor(role, directory, decode(Path(topology_path).read_bytes()), run, case)
    sys.stdout.buffer.write(encode({"ready": role, "limits": list(resource.getrlimit(resource.RLIMIT_AS))}) + b"\n")
    sys.stdout.buffer.flush()
    while line := sys.stdin.buffer.readline(LINE + 1):
        if len(line) > LINE or not line.endswith(b"\n"):
            raise ValueError("invalid request line size")
        request = decode(line)
        if request["kind"] == "shutdown":
            return
        sys.stdout.buffer.write(encode(actor.dispatch(request)) + b"\n")
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
