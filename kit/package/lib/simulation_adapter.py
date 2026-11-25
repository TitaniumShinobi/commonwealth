"""Deterministic simulation-v1 with endpoint-owned allocation stores."""
import json
import random
import tempfile
from pathlib import Path

ENDPOINTS = ("lab-a", "lab-b")


class Endpoint:
    def __init__(self, name, directory):
        self.name = name
        self.path = directory / f"{name}.json"
        self.write({})

    def write(self, state):
        self.path.write_text(json.dumps(state, sort_keys=True))

    def snapshot(self):
        return json.loads(self.path.read_text())

    def reserve(self, reservation, generation, expiry):
        state = self.snapshot()
        if reservation in state:
            raise ValueError("duplicate_local_reservation")
        state[reservation] = {"generation": generation, "expiry": expiry, "confirmed": False}
        self.write(state)

    def confirm(self, reservation, generation, tick):
        state = self.snapshot()
        entry = state.get(reservation)
        if not entry or entry["generation"] != generation or tick >= entry["expiry"]:
            raise ValueError("no_current_reservation")
        entry["confirmed"] = True
        self.write(state)

    def release(self, reservation):
        state = self.snapshot()
        state.pop(reservation, None)
        self.write(state)


class Adapter:
    def __init__(self, directory):
        self.endpoints = {name: Endpoint(name, directory) for name in ENDPOINTS}

    def observe(self, reservation):
        return {name: endpoint.snapshot().get(reservation)
                for name, endpoint in self.endpoints.items()}

    def reserve(self, reservation, endpoints, generation, expiry):
        if set(endpoints) != set(self.endpoints) or len(endpoints) != len(self.endpoints):
            raise ValueError("invalid_reservation")
        for endpoint in self.endpoints.values():
            endpoint.reserve(reservation, generation, expiry)

    def attempt(self, reservation, generation, tick, seed):
        states = self.observe(reservation)
        if any(not entry or entry["generation"] != generation for entry in states.values()):
            return "no_current_reservation"
        if tick >= min(entry["expiry"] for entry in states.values()):
            return "confirmation_timeout" if not all(entry["confirmed"] for entry in states.values()) else "no_current_reservation"
        if not all(entry["confirmed"] for entry in states.values()):
            return "confirmation_pending"
        return "modeled_herald" if random.Random(seed).random() < 0.8 else "modeled_no_herald"

    def release(self, reservation):
        for endpoint in self.endpoints.values():
            endpoint.release(reservation)
        return {name: len(endpoint.snapshot()) for name, endpoint in self.endpoints.items()}


def exercise(template, seed, scenario):
    if template != "two-endpoint-v1" or scenario not in ("herald", "confirm-timeout"):
        raise ValueError("unsupported_simulation_input")
    key, generation, deadline = "reservation-1", 1, 5
    def event(name, **fields):
        return {"scope": "Simulation", "model": "simulation-v1", "event": name, **fields}

    with tempfile.TemporaryDirectory(prefix="cw-adapter-") as directory:
        adapter = Adapter(Path(directory))
        pre = adapter.attempt(key, generation, 0, seed)
        adapter.reserve(key, ENDPOINTS, generation, deadline)
        adapter.endpoints["lab-a"].confirm(key, generation, 0)
        trace = [event("unreserved_attempt", result=pre),
                 event("reserved", id=key, generation=generation, expiry=deadline, endpoints=list(ENDPOINTS),
                       observed=adapter.observe(key))]
        for tick in range(1, deadline + 1):
            if tick == 2 and scenario == "herald":
                adapter.endpoints["lab-b"].confirm(key, generation, tick)
            result = adapter.attempt(key, generation, tick, seed)
            trace.append(event("attempt", tick=tick, result=result, observed=adapter.observe(key)))
            if result != "confirmation_pending":
                break
        trace.append(event(result, tick=tick))
        # Record each endpoint's values from its own store before and after release.
        pre_release = adapter.observe(key)
        closed = adapter.release(key)
        post_release = adapter.observe(key)
        trace.append(event("released", allocations=closed, independently_read_back=post_release))
        again = adapter.release(key)
        trace.append(event("release_replayed", allocations=again, independently_read_back=adapter.observe(key)))
    return {"decision": result, "template": template, "seed": seed, "scenario": scenario,
            "scheduler": "virtual-tick-order-v1", "reservations_created": 1, "allocations": closed,
            "deadline": deadline, "terminal_tick": tick, "pre_release": pre_release,
            "post_release": post_release, "trace": trace}
