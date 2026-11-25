"""Deterministic pure-state Bell transfer with separate endpoint workers."""
import cmath
import hashlib
import json
import math
import random
import subprocess
import sys
from pathlib import Path

SEED = 110427
H = 1 / math.sqrt(2)
STATES = {"0": (1, 0), "1": (0, 1), "+": (H, H), "-": (H, -H),
          "+i": (H, 1j * H), "-i": (H, -1j * H)}
BASES = {"X": STATES["+"], "Y": STATES["+i"], "Z": STATES["0"]}


def sender(label, phase, draw):
    a, b = STATES[label]
    state = [a * H, 0, 0, a * H * phase, b * H, 0, 0, b * H * phase]
    cnot = [0j] * 8
    for index, amplitude in enumerate(state):
        cnot[index ^ (2 if index & 4 else 0)] = amplitude
    transformed = [(cnot[index & 3] + (-1 if index & 4 else 1) * cnot[(index & 3) | 4]) * H
                   for index in range(8)]
    branches = [transformed[i:i + 2] for i in range(0, 8, 2)]
    weights = [sum(abs(c) ** 2 for c in pair) for pair in branches]
    cumulative = 0
    for selected, weight in enumerate(weights):
        cumulative += weight
        if draw < cumulative or selected == 3:
            break
    return {"bits": [selected >> 1, selected & 1], "weights": weights,
            "backend_slot": [[c.real / math.sqrt(weights[selected]), c.imag / math.sqrt(weights[selected])]
                             for c in branches[selected]]}


def worker(role, payload):
    if role == "A":
        return sender(payload["state"], payload["phase"], payload["draw"])
    if set(payload) != {"bits"} or len(payload["bits"]) != 2 or any(type(b) is not int or b not in (0, 1) for b in payload["bits"]):
        raise ValueError("recipient_requires_two_bits")
    z, x = payload["bits"]
    return {"gates": ["X"] * x + ["Z"] * z}


def endpoint(role, payload):
    completed = subprocess.run([sys.executable, __file__, role], input=json.dumps(payload),
                               capture_output=True, text=True, check=True, timeout=3)
    return json.loads(completed.stdout)


def probability(state, axis):
    vector = BASES[axis]
    return round(abs(sum(complex(v).conjugate() * q for v, q in zip(vector, state))) ** 2, 12)


def trial(run, trial_id, label, mode):
    rng = random.Random(SEED + int.from_bytes(hashlib.sha256(f"{trial_id}:{mode}".encode()).digest()[:8], "big"))
    result = {"run_id": run, "trial_id": trial_id, "scope": "Simulation", "backend": "python-complex-bell-v1",
              "seed": SEED, "state": label, "mode": mode, "bases": list(BASES)}
    if mode == "unavailable":
        return {**result, "terminal": "quantum_link_unavailable", "leases": {},
                "events": ["reservation_requested", "link_unavailable"]}
    phases = (1, -1) if mode == "dephasing" else (1,)
    leases = {"A": {"expires": 5}, "B": {"expires": 5}}
    result["lease_trace"] = [{"tick": 0, "event": "reservation", "owners": sorted(leases)},
                             {"tick": 1, "event": "herald", "owners": sorted(leases)}]
    def release(tick):
        for owner in ("A", "B"):
            del leases[owner]
            result["lease_trace"].append({"tick": tick, "event": "release_" + owner,
                                          "owners": sorted(leases)})
        return leases
    result["events"] = ["reserve_A", "reserve_B", "herald", "bell_pair_delivered", "sender_bell_measurement"]
    outputs = []
    for phase in phases:
        measured = endpoint("A", {"state": label, "phase": phase, "draw": rng.random()})
        slot = [complex(*amplitude) for amplitude in measured["backend_slot"]]
        if mode == "missing":
            return {**result, "terminal": "classical_bits_expired", "recipient_messages": [],
                    "events": result["events"] + ["bits_withheld", "expire", "release_A", "release_B"], "leases": release(5)}
        recipient = {"bits": measured["bits"]}
        correction = endpoint("B", recipient)
        for gate in correction["gates"]:
            slot = slot[::-1] if gate == "X" else [slot[0], -slot[1]]
        outputs.append({"recipient_input": recipient, "recipient_correction": correction,
                        "bell_measurement_weights": measured["weights"],
                        "probabilities": {axis: probability(slot, axis) for axis in BASES}})
    observed = {axis: sum(o["probabilities"][axis] for o in outputs) / len(outputs) for axis in BASES}
    expected = dict(zip(BASES, {"0": (0.5, 0.5, 1), "1": (0.5, 0.5, 0),
                                "+": (1, 0.5, 0.5), "-": (0, 0.5, 0.5),
                                "+i": (0.5, 1, 0.5), "-i": (0.5, 0, 0.5)}[label]))
    if mode == "dephasing":
        expected.update(X=0.5, Y=0.5)
    if observed != expected:
        raise ValueError(f"measurement_mismatch: {label}: {mode}: {observed}")
    return {**result, "terminal": "measured", "recipient_messages": outputs, "observed": observed,
            "expected": expected, "sampled_plus_counts": {axis: sum(rng.random() < p for _ in range(64))
                                                        for axis, p in observed.items()},
            "shots_per_basis": 64, "leases": release(4),
            "events": result["events"] + ["classical_bits_delivered", "correct", "measure", "release_A", "release_B"]}


if __name__ == "__main__":
    print(json.dumps(worker(sys.argv[1], json.load(sys.stdin)), separators=(",", ":")))
