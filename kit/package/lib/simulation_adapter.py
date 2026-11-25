"""Versioned simulation-v1 adapter. No physical operations."""
import random


class Adapter:
    def __init__(self):
        self.allocations = {}

    def reserve(self, reservation, endpoints, generation, expiry):
        if reservation in self.allocations or len(set(endpoints)) != 2:
            raise ValueError("invalid_reservation")
        self.allocations[reservation] = (tuple(endpoints), generation, expiry)

    def attempt(self, reservation, generation, tick, confirmed, seed):
        entry = self.allocations.get(reservation)
        if not entry or entry[1] != generation or tick >= entry[2]:
            return "no_current_reservation"
        if not confirmed:
            return "confirmation_timeout"
        return "modeled_herald" if random.Random(seed).random() < 0.8 else "modeled_no_herald"

    def release(self, reservation):
        self.allocations.pop(reservation, None)
        return {endpoint: sum(endpoint in r[0] for r in self.allocations.values())
                for endpoint in ("lab-a", "lab-b")}


def exercise(template, seed, scenario):
    if template != "two-endpoint-v1" or scenario not in ("herald", "confirm-timeout"):
        raise ValueError("unsupported_simulation_input")
    adapter = Adapter()
    key, generation, expiry = "reservation-1", 1, 5
    pre = adapter.attempt(key, generation, 0, True, seed)
    adapter.reserve(key, ("lab-a", "lab-b"), generation, expiry)
    result = adapter.attempt(key, generation, 1, scenario == "herald", seed)
    closed = adapter.release(key)
    again = adapter.release(key)
    def event(name, **fields):
        return {"scope": "Simulation", "model": "simulation-v1", "event": name, **fields}
    return {"decision": result, "template": template, "seed": seed, "scenario": scenario,
            "scheduler": "virtual-tick-order-v1", "reservations_created": 1, "allocations": closed,
            "trace": [event("unreserved_attempt", result=pre),
                      event("reserved", id=key, generation=generation, expiry=expiry,
                            endpoints=["lab-a", "lab-b"]),
                      event("attempt", tick=1), event(result), event("released", allocations=closed),
                      event("release_replayed", allocations=again)]}
