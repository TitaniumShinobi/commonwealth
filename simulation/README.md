# Commonwealth cloud simulation

Run **Commonwealth cloud simulation** through GitHub Actions. Its manually dispatched workflow requires registration on the repository's default branch. The job checks out and verifies the dispatched SHA, runs smoke, and proceeds to the Step 3 classical access fixtures only on smoke success. Evidence is uploaded for 14 days.

The standard-library harness uses line-delimited JSON pipes, an integer virtual clock, public synthetic HMAC keys, and fresh actor state for each case. It uses no network calls or credentials. GitHub checkout and artifact transfer are workflow infrastructure. The access model covers attachment, IPv4 configuration, public forwarding, resolver loss and expiry, isolation, and withdrawal with failed eviction.

The A authority, A application and B actors provide process and authenticated round-trip scaffolding in this step. The later exchange, controls, restore and rejection fixtures are declarations with UNVERIFIED results. Separate process directories model ownership and do not prove operational isolation or independent custody.

Verdicts: PASS exits 0, FAIL exits 1, and incomplete evidence without a scored failure exits 2. Read the artifact's smoke receipt, manifests, case receipts, and summary for the tested revision.

Step 4 runs after smoke and the Step 3 regression suite. Its synthetic operator actors exercise local enrollment and locator bootstrap, publication verification, service authorization, endpoint revision and exit. TLS failure and HTTP transport states are modeled, with no sockets or TLS handshakes. The unrelated control fixture uses a separate logical peer hosted by the access actor to stay within the process bound. Step 5 and Step 6 are unexecuted.

Step 5 runs after smoke and the Step 3 and Step 4 regressions. It exercises synthetic enrollment and appraisal, scoped household grants, execution-domain denials, current authority, same-tick withdrawal and retry, queued effect denial, scoped cleanup, and fresh authorization. Expected/observed receipts include an independent control crossing and domain probes. The evaluator and network boundaries are process models, not platform or device-attestation tests. Step 6 is a separate suite.

## Step 6

The branch workflow runs smoke and Steps 3–5 before two clean Step 6 runs. With the verified runner checkout and smoke receipt already available, the workflow invokes:

```bash
export PYTHONPATH=simulation
root="$RUNNER_TEMP/commonwealth"
for result in step-6 step-6-replay; do
  python3 -m commonwealth_sim run --topology simulation/fixtures/topology.json --cases simulation/fixtures/cases.json --suite step-6 --out "$root/$result"
done
python3 -m commonwealth_sim.replay "$root"
```

The harness stops and reaps the original application before starting the replacement. The restore authority binds one operation to the steward, service, backup digest and clean target. Separate synthetic roles enforce ingress and writer fences, reconcile authorization, publication and credentials, and authorize replacement issuance and publication. The B actor independently validates binding and rejoin, and commits and reads back its own workload on every virtual tick. The normal run and replay retain complete original traces. The replay digest compares semantic trace and checks, including virtual ticks, role decisions and committed-state digests. Run-specific authenticated envelope metadata is outside that comparison.

The evidence covers a single runner, public fixture credentials, modeled authority stores, and modeled fences. It does not establish separate production custody, platform isolation, real network fencing or live recovery.

### Source age, audit, and archived custody

Tick 8 commits a fresh source version. The observer rereads it from disk, B checks its digest and tick, and A verifies that observation before taking the backup. Recovery age is based on the observed source version whose digest is carried through the replacement response. The manifest separates the Step 2 design baseline from the Step 6 implementation parent.

Every modeled recovery dispatch has an append-only recipient-side journal entry with pre/post state and disclosure evidence. The independent scorer reconciles these entries against the authenticated ordered harness trace, principal inventory, approved lifecycle, and fixture constraints. The founder-delegate challenge verifies that the scorer rejects an unaccounted successful effect. The audit covers modeled controls only. An actual privileged GitHub runner or fixture key holder is outside that synthetic custody boundary.

The workflow hashes all members before upload, downloads that same run's artifact using pinned Download Artifact, and checks all archived member hashes and replay operands. In the cloud evidence step, group proof rows by name, order by offset, concatenate the base64 chunks, then decode base64 and gzip. Verify length and SHA-256 against each row. Original and semantic streams are separately labeled. Keep the job, run, artifact ID and service-reported archive digest with any exported proof.
