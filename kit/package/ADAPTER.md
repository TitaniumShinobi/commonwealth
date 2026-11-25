# Simulation adapter v1

The installed adapter exposes reserve(reservation, endpoints, generation, expiry), attempt(reservation, generation, tick, confirmed, seed), and idempotent release(reservation). A reservation owns two distinct simulated endpoint IDs. Attempts require matching generation and unexpired allocation. Timeout and modeled herald are distinct outcomes. Release reports both endpoint allocation counts. Record scope Simulation, model simulation-v1, template, seed, scheduler, and terminal state. A simulated outcome supplies no physical evidence.
