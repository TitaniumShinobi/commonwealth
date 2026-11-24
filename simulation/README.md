# Commonwealth cloud simulation

Run **Commonwealth cloud simulation** through GitHub Actions. Its manually dispatched workflow requires registration on the repository's default branch. The job checks out and verifies the dispatched SHA, runs smoke, and proceeds to the Step 3 classical access fixtures only on smoke success. Evidence is uploaded for 14 days.

The standard-library harness uses line-delimited JSON pipes, an integer virtual clock, public synthetic HMAC keys, and fresh actor state for each case. It uses no network calls or credentials. GitHub checkout and artifact transfer are workflow infrastructure. The access model covers attachment, IPv4 configuration, public forwarding, resolver loss and expiry, isolation, and withdrawal with failed eviction.

The A authority, A application and B actors provide process and authenticated round-trip scaffolding in this step. The later exchange, controls, restore and rejection fixtures are declarations with UNVERIFIED results. Separate process directories model ownership and do not prove operational isolation or independent custody.

Verdicts: PASS exits 0, FAIL exits 1, and incomplete evidence without a scored failure exits 2. Read the artifact's smoke receipt, manifests, case receipts, and summary for the tested revision.
