# Commonwealth one-site public Internet pilot

**Target** · November 30, 2026. **Activation** · HELD. The pilot is $0 to participants. The cloud fixture exercises preparation only. The real site, accountable operator, funding, equipment, permitted upstream, exercise limits, and field authority need direct evidence.

## Select and qualify a site

| Evidence | Owner and acceptance |
|---|---|
| Site and audience | Site owner identifies one site, public audience, permission to use the space and equipment, and the proposed test window. Retain the signed reference separately from any public receipt. |
| Staff | Name the site operator, offline support contact, incident owner and recovery owner. Record their accepted duties and an independent local recovery path. |
| Funding | Funding owner commits installation, equipment, spares, upstream and extra usage, power, staffing, support, maintenance and continuity. Record dates and accountable parties in the controlled record. Confirm $0 in the terms and actual join flow. If funding ends, use the agreed supported transfer or closure. |
| Uplink | Prefer the existing host uplink when the account agreement covers the intended audience. If it qualifies but installed forwarding cannot enforce withdrawal, qualify separate guest gateway and APs. Otherwise compare fiber, terrestrial radio and Starlink on permitted use, usable handoff, capacity, power, support, and cost at this site. Keep provider addressing and equipment mode in the WAN profile. |
| Equipment | Record model, firmware, owned interface and cable endpoints, forwarding mode, admin authority, power draw and backup runtime. Verify that every applicable controller or bridge emits authenticated credential-to-session mapping and can deny both directions without an eviction acknowledgment. |

```text
Provider terminal / ONT / radio -> Ethernet WAN handoff -> Linux reference gateway
  -> managed guest switch / controller -> participant APs -> ordinary devices
Dedicated local management -> approved site operator and recovery owner
Gateway -> local IPv4 DHCP + restricted recursive resolver
Guest routing -> outbound NAT to WAN; default-deny guest, household, service and management
Local bridge -> enforced guest isolation and withdrawal independent of routed NAT
```

Qualify the complete power path including gateway, terminal, DHCP/DNS, switch/controller, PoE headroom and APs. Capture overlapping-network checks against the host and upstream before assigning a guest pool. Keep participant IPv6 and unintended router advertisements disabled until separately qualified. Review all local forwarding paths on the actual firmware and AP operating mode.

## Operator and participant setup

1. From dedicated local management, verify interface inventory, baseline/readback, DHCP and recursive resolver binding, NAT, isolation, credential association, and the local withdrawal and recovery path. Capture timestamps and distinguish a managed probe from the participant vantage.
2. Under separately authorized field operation, issue an individually revocable credential per device. Provide an offline card with exact network name, password, support contact, and support reference. Record the reference and device label in support, excluding the password and browsing history.
3. The eligible participant uses native Wi-Fi settings, automatic IPv4 and DNS, and an ordinary browser. Exclude alternate connectivity from the test with recorded evidence. Observe association, lease/gateway/resolver, fresh DNS, and HTTPS to independent public destinations separately. Time from selecting Wi-Fi to the first successful HTTPS request. Repeat under the approved load and verify the join offers $0 access.
4. Diagnose from the first failing boundary. Wrong credentials remain denied. A DHCP service or exhausted pool fault occurs after attachment, then clears when provisioning is restored. During resolver loss use an unexpired cached name, an uncached name, and the expired entry. After restoration, verify fresh lookup and HTTPS from the participant device.

## Withdraw, close crossings, and interrupt the link

With one open flow, one copied credential on another AP and one unaffected participant, hold AP eviction back. Operator withdrawal durably denies both traffic directions on all associated sessions ahead of established-flow acceptance, clears connection state, and blocks future admission. Record AP eviction independently. Test existing and new flows, local paths that bypass NAT, copied credentials, AP roaming, changed leases, and restart. Reload durable denial before opening forwarding. If a restarted control cannot verify the association, the affected path stays closed. Any surviving unauthorized traffic is a field failure.

Close one actually deployed scoped crossing. Verify temporary sessions, credentials, buffers and pending state at the enforcement point. Deliver queued work, retry and reuse its old identifier. Verify zero protected disclosures or committed effects, then repeat cleanup and independently probe the unaffected crossing. A new crossing requires fresh authorization. Keep this receipt separate from guest withdrawal.

Remove only the authorized site uplink during the approved controlled exercise. Confirm attachment, local management and withdrawal remain available and public forwarding stops. Restore the uplink and observer path, verify fresh DNS and independent HTTPS from the unaffected ordinary device, and confirm a withdrawn credential stays denied. Measure interruption and recovery against the approved limits.

## Target-bound deploy and rollback

- **Baseline** · The recovery owner exports an exact known-good configuration with digest, firmware and interfaces, dependency/probe list, verified local recovery access, and safe restore instructions. Reserve time for rollback and retest.
- **Stage** · Prepare a target-bound plan showing candidate and baseline digests, interface, route, firewall, DHCP, DNS, NAT and admission changes, affected devices and approvers. Validate syntax and policy offline. Keep the guest issuance and live access closed until there is explicit activation authority and the authorized prerequisite checks pass.
- **Verify** · Apply only within the authorized site window. Check local management, host dependencies and unchanged administrative access from independent paths. Conduct the documented participant flow and failure checks. Use a separate unaffected participant. Record approved numerical join, load, withdrawal, interruption, recovery and probe criteria before scoring.
- **Abort** · Stop issuance and close the candidate guest path on loss of management, host regression, protected-path leakage, failed isolation, incomplete or late withdrawal, or an unmet connectivity limit. Use local management to restore the verified baseline. Reconcile current durable revocations before allowing any guest reopening. Probe host services, guest-path closure and the revoked device's denial. If restoration cannot be verified, declare an incident, identify the remaining degraded state, and keep access closed. Reopening requires a new readiness check and applicable authority.

## Score and retain receipts

Use [field-receipt.json](field-receipt.json) with references to direct evidence. For each readiness item supply scope `direct`, owner, site and configuration references, timestamp and evidence reference. Use one authoritative `field_run` with `run_ref`, offset-bearing ISO 8601 `starts_at` and `ends_at`, and `authority_ref`. The direct activation record must match that run and its exact window, site, and configuration and must have been observed by the time the window starts. Each field observation must use scope `field`, that run and authority reference, its site and configuration, and an offset-bearing timestamp in the half-open interval [starts_at, ends_at). Also supply observer/vantage, criterion reference, enforcement boundary, measured result, and assigned verdict. Rows from another run, an unauthorized window, or outside the window are rejected and cannot contribute to a pass. Assign PASS only when the named approved criterion and measured result agree. Record separate enforcement observations for future admission, old and new forwarding, and association. Blank evidence is UNVERIFIED. A direct observed violation is FAIL even when other items remain missing. Keep authorization separate from readiness. The field evaluator checks completeness and binding of evidence references and verdicts. The field authority checks the underlying signed evidence and measurements.

| Decision | Evidence |
|---|---|
| Deterministic cloud preparation | Fixture profile validation, negative configurations, modeled flows and readiness scoring, exact revision and fixture hashes. |
| Isolated Linux gateway | Kernel and nftables checks, disconnected synthetic WAN, controlled route and bridge packet evidence, and DHCP/resolver syntax test when available. Simulated DHCP/cache and radio/session tests are separate. Missing tooling or permission leaves the affected Linux layer UNVERIFIED. |
| Ready to request activation | Direct approved site/audience, operator, funding, authorized uplink, equipment/power, local recovery and approved plan, limits and window. The checked-in template is blank and supplies none of this evidence. |
| Field acceptance | Authorized ordinary-device run with direct scoped field observations. The cloud job supplies no field verdict. Federation and quantum use their own receipts. |

The branch workflow verifies its exact checkout, runs smoke and Steps 3–6 with recovery replay, then uses these commands inside the GitHub runner:

```bash
export PYTHONPATH=simulation
root="$RUNNER_TEMP/commonwealth"
python3 -m commonwealth_sim.pilot model pilot/fixture-profile.json pilot/field-receipt.json pilot/cases.json "$root/step-7/model.json"
python3 -m commonwealth_sim.pilot gateway pilot/fixture-profile.json pilot/field-receipt.json pilot/cases.json "$root/step-7/gateway.json"
```

The workflow stages Ubuntu's dnsmasq-base syntax checker and conntrack CLI outside the fixture when missing. The isolated run confirms tracked TCP exists, denies forwarding, deletes all exercised matching state, then independently rereads it. It restarts the guest policy in a closed state, rereads persistent denial before forwarding resumes, and tests the unaffected participant and withdrawn session. It captures and restores the target-bound baseline ruleset, checks an independent management-side TCP service before and after the change, verifies exact baseline readback before overlaying durable revocations, and confirms closure and guest conntrack cleanup. Package retrieval is CI tooling traffic. No package is installed as a runner service. Namespace commands use disposable isolated interfaces. Both gateway and synthetic WAN have no default route. The job retains each layer's verdict and original command evidence in the verified archive. A successful workflow with an UNVERIFIED layer remains incomplete for that layer. The procedure confers no activation authority.

Sources · [Pilot rubric](https://github.com/TitaniumShinobi/commonwealth/blob/e54c79849a7c77dbc5fe0204a2cec735b9eca6b5/COMMONWEALTH.md#classical-internet-pilot) · [Pinned roadmap](https://github.com/TitaniumShinobi/commonwealth/blob/e54c79849a7c77dbc5fe0204a2cec735b9eca6b5/ROADMAP.md) · [Connectivity profile](https://github.com/TitaniumShinobi/commonwealth/blob/e54c79849a7c77dbc5fe0204a2cec735b9eca6b5/COMMONWEALTH.md#connectivity-uplinks-and-routing)
