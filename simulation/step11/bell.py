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


class Endpoint:
    def __init__(self, role):
        self.role = role
        self.process = subprocess.Popen([sys.executable, __file__, role], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, text=True)
        self.events = []

    def call(self, action, **fields):
        print(json.dumps({"action": action, **fields}), file=self.process.stdin, flush=True)
        answer = json.loads(self.process.stdout.readline())
        self.events.append({"action": action, **{k: answer[k] for k in ("owner", "lease", "decision", "tick")}})
        return answer

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=3)
        self.process.stdout.close()


def worker(role):
    lease = None
    slot = None
    tick = 0
    for line in sys.stdin:
        message = json.loads(line)
        action = message["action"]
        result = {}
        decision = "ok"
        if action == "advance":
            next_tick = message["tick"]
            if type(next_tick) is not int or next_tick < tick:
                decision = "denied"
            else:
                tick = next_tick
                if lease and tick >= lease["expires"]:
                    lease, slot = None, None
                    decision = "self_expired"
        elif action == "reserve" and lease is None:
            lease = {"owner": role, "trial_id": message["trial_id"], "expires": 5}
        elif action in ("cancel", "release") and lease:
            lease, slot = None, None
        elif lease and action == "bell_measure" and role == "A":
            result = sender(message["state"], message["phase"], message["draw"])
        elif lease and action == "deliver_quantum_slot" and role == "B":
            slot = [complex(*v) for v in message["slot"]]
        elif lease and action == "correct_and_measure" and role == "B" and slot is not None:
            classical = message["classical"]
            if set(classical) != {"bits"} or len(classical["bits"]) != 2 or any(type(b) is not int or b not in (0, 1) for b in classical["bits"]):
                raise ValueError("recipient_requires_two_bits")
            z, x = classical["bits"]
            if x:
                slot = slot[::-1]
            if z:
                slot = [slot[0], -slot[1]]
            rng = random.Random(message["seed"])
            probs = {axis: probability(slot, axis) for axis in BASES}
            result = {"gates": ["X"] * x + ["Z"] * z, "probabilities": probs,
                      "counts": {axis: sum(rng.random() < p for _ in range(message["shots"]))
                                 for axis, p in probs.items()}, "shots": message["shots"]}
            slot = None
        else:
            decision = "denied"
        print(json.dumps({"owner": role, "lease": lease, "decision": decision, "tick": tick, **result}), flush=True)


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
    endpoints = [Endpoint("A"), Endpoint("B")]
    alice, bob = endpoints
    try:
        for endpoint in endpoints:
            response = endpoint.call("reserve", trial_id=trial_id)
            if response["lease"]["owner"] != endpoint.role:
                raise ValueError("lease_owner_mismatch")
        result["events"] = ["reserve_A", "reserve_B", "herald", "bell_pair_delivered"]
        if mode == "cancelled":
            terminal = "cancelled"
            release = "cancel"
        elif mode == "missing":
            alice.call("bell_measure", state=label, phase=1, draw=rng.random())
            result["events"] += ["sender_bell_measurement", "bits_withheld", "lease_expired_at_tick_5"]
            terminal = "classical_bits_expired"
            release = None
            for endpoint in endpoints:
                pending = endpoint.call("advance", tick=4)
                expired = endpoint.call("advance", tick=5)
                if not pending["lease"] or pending["decision"] != "ok" or expired["lease"] is not None or expired["decision"] != "self_expired":
                    raise ValueError("endpoint_expiry_invariant")
            late = bob.call("deliver_quantum_slot", slot=[[1, 0], [0, 0]])
            late_bits = bob.call("correct_and_measure", classical={"bits": [0, 0]}, seed=SEED, shots=64)
            late_sender = alice.call("bell_measure", state=label, phase=1, draw=0)
            if any(row["decision"] != "denied" or row["lease"] is not None for row in (late, late_bits, late_sender)):
                raise ValueError("late_delivery_was_accepted")
        else:
            shots = 64 // len(phases)
            outputs = []
            for phase in phases:
                measured = alice.call("bell_measure", state=label, phase=phase, draw=rng.random())
                bob.call("deliver_quantum_slot", slot=measured["backend_slot"])
                classical = {"bits": measured["bits"]}
                observed = bob.call("correct_and_measure", classical=classical, seed=rng.randrange(2**32), shots=shots)
                outputs.append({"recipient_classical_input": classical, "gates": observed["gates"],
                                "bell_measurement_weights": measured["weights"], "probabilities": observed["probabilities"],
                                "counts": observed["counts"], "shots": shots})
            combined = {axis: sum(row["probabilities"][axis] for row in outputs) / len(outputs) for axis in BASES}
            expected = dict(zip(BASES, {"0": (0.5, 0.5, 1), "1": (0.5, 0.5, 0),
                                        "+": (1, 0.5, 0.5), "-": (0, 0.5, 0.5),
                                        "+i": (0.5, 1, 0.5), "-i": (0.5, 0, 0.5)}[label]))
            if mode == "dephasing":
                expected.update(X=0.5, Y=0.5)
            counts = {axis: sum(row["counts"][axis] for row in outputs) for axis in BASES}
            if combined != expected or any(abs(counts[axis] - 64 * val) > (0 if val in (0, 1) else 16)
                                            for axis, val in expected.items()):
                raise ValueError(f"measurement_mismatch: {label}: {mode}: {combined}, {counts}")
            result.update(recipient_messages=outputs, observed=combined, expected=expected, sampled_plus_counts=counts,
                          shots_per_basis=64, threshold={"deterministic_tolerance_shots": 0,
                                                          "half_probability_tolerance_shots": 16})
            result["events"] += ["sender_bell_measurement", "classical_bits_delivered", "recipient_corrected_and_measured"]
            terminal = "measured"
            release = "release"
        if release:
            for endpoint in endpoints:
                if endpoint.call(release)["lease"] is not None:
                    raise ValueError("lease_not_released")
        return {**result, "terminal": terminal, "leases": {},
                "endpoint_receipts": {endpoint.role: endpoint.events for endpoint in endpoints}}
    finally:
        for endpoint in endpoints:
            endpoint.close()


if __name__ == "__main__":
    worker(sys.argv[1])
