# Step 11 · browser-to-lab simulation

The GitHub Actions branch workflow runs smoke and the inherited regressions before starting the Step 11 job. The job uses a private network and mount namespace with only loopback and no default route. Its resolver listens on UDP 53 and maps `lab.example` and `wrong.lab.example` to 127.0.0.1. Chrome trusts the ephemeral fixture CA installed in its NSS profile. The gateway presents a certificate for `lab.example` on TCP 443. The wrong-name browser trial reaches the same listener and CA, fails hostname validation, and must forward zero HTTP requests to an origin.

| Gateway request | Upstream | Rule |
| --- | --- | --- |
| `GET /` and `GET /app.js` | Stock OpenSSL HTTPS file server, TCP 8443 | Serves static index and asset as supplied, with no quantum code in the origin executable. The gateway rewrites only the root path to `/index.html` and omits the trial query in the upstream path. |
| `POST /experiment` | Separate TLS quantum API on an assigned loopback port | Accepts a listed trial and the fixture browser's HttpOnly session cookie. The same valid trial is denied before the cookie is installed and must cause no worker dispatch. |
| Other host or path | No upstream | The gateway returns 421 for an unrecognized HTTP host and 404 for other paths. |

Only the gateway forwards to the two HTTPS origin routes. Its upstream TLS client verifies the fixture CA and localhost certificate. The browser uses CDP input to type the address into a fixture form and clicks the experiment button on the served page. The ephemeral cookie is supplied by the fixture harness outside the page and asset. The namespace has no public Internet route.

The deterministic complex-state backend uses seed 110427 and a fixed order of six ideal preparations (0, 1, +, −, +i, −i), dephasing, withheld bits followed by expiry, cancellation, and unavailable link. Each endpoint process owns its own lease and reports its terminal release. The classical receiver message contains only two bits. A separate modeled quantum delivery passes the conditional slot to the receiver, which applies X/Z and measures X/Y/Z inside its process. A cancellation issues no correction, and missing bits expire at modeled tick 5. Unavailable link creates no lease and the page remains usable.

Each measured trial reports exact expected and observed basis probabilities and 64 reproducible seeded shots per basis. Deterministic outcomes allow zero shot-count difference. For probabilities of one half, the raw count must be within 16 shots of 32. The dephasing control combines two 32-shot phase branches. Replay reads the exported trace and browser result in a fresh Python process, launches new endpoint workers, and compares full simulation receipts. DNS and TLS are network fixture observations. All measurements and lab resources are simulated.
