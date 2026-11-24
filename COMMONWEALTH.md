# COMMONWEALTH

*The People’s Network · Open-source Internet for all*

**Review candidate**

◆ Requirement or adopted default · → Expected decision or state transition · ▣ Evidence receipt

## YOU ARE HERE

```text
Commonwealth-operated site
  Participant device -- per-device Wi-Fi credential --> site operator's access network
  Site gateway -- public IP traffic --> authorized upstream --> public destinations
  Commonwealth node -- authenticated exchange --> independent Commonwealth peer

Existing provider connection
  Participant device -- ordinary IP traffic --> existing router and provider
                     --> public destinations
  Commonwealth node on router or LAN -- peer traffic over existing IP path -->
                     independent Commonwealth peer --> destination authorization

Acceptance scopes
  Classical Internet pilot  <- field evidence from one authorized, funded site
  Full product               <- independent deployment and interoperable operation
                              + household and execution controls
                              + recovery and sustainable $0 site access
  Simulated quantum          <- reproducible behavior under a declared model
  Physical quantum           <- calibrated measurements and independent reproduction
```

## Commands

### Guided setup

| Action | Actor, input, and result | Worked flow |
|---|---|---|
| **Connect to a service** | A participant supplies an approved connection and service reference. The client reports discovery, endpoint identity, and the requested action’s result separately. | [Connect to a service](#connect-to-a-service) |
| **Run a node** | An independent operator verifies the kit, reviews a target-bound setup plan, and configures the node under local authority. Local readiness and external reachability are separate results. | [Run a node](#run-a-node) |
| **Connect a lab** | A lab steward configures the classical control endpoint and a supported adapter. The kit reports adapter readiness, simulation results, and physical reservation eligibility separately. | [Connect a lab](#connect-a-lab) |

### Operator and participant actions

The controls marked **Proposed** below retain the status of their worked interactions. The operator or resource owner performs the action at the named control surface.

| Action | Actor and effect | Worked flow |
|---|---|---|
| **Issue device credential** · Proposed | The site operator verifies eligibility, issues one individually revocable credential, and gives the participant a support reference. | [Participant Access](#participant-access) |
| **Withdraw access** · Proposed | The site operator withdraws the credential. The access system reports future admission denial, existing forwarding denial, and AP eviction separately. | [Participant Access](#participant-access) |
| **Add peer** · Proposed | Each operator verifies the peer fingerprint and approves its own enrollment. | [Peer Enrollment, First Exchange, Governance, and Exit](#peer-enrollment-first-exchange-governance-and-exit) |
| **Run first exchange** · Proposed | An enrolled operator starts from the discovery locator and observes a permitted fixture request and a separate destination denial. | [Peer Enrollment, First Exchange, Governance, and Exit](#peer-enrollment-first-exchange-governance-and-exit) |
| **Withdraw peer** · Proposed | An operator ends its local relationship and observes binding and session invalidation independently of notice delivery. | [Peer Enrollment, First Exchange, Governance, and Exit](#peer-enrollment-first-exchange-governance-and-exit) |
| **Register service**, **Publish**, **Replace endpoint** · Proposed | A delegated steward submits the endpoint, authentication key, interface version, and safe probe. Publication returns a signed binding after verification. Replacement uses a higher revision after the applicable fences are verified. | [Service Publication, Discovery, and Endpoint Move](#service-publication-discovery-and-endpoint-move) |
| **Request device enrollment**, **Grant access**, **Revoke grant**, **Revoke device** · Proposed | A device holder requests enrollment. The household administrator makes separate enrollment, grant, and revocation decisions. Enforcement confirms the resulting access state. | [Household Onboarding, Grants, and Revocation](#household-onboarding-grants-and-revocation) |
| **Stop application** · Proposed | The local operator invalidates the workload identity, closes affected sessions, and records the disposition of in-flight work. | [Application Publication and Isolated Execution](#application-publication-and-isolated-execution) |
| **Replay a recorded decision** or **run an approved safe diagnostic** | The responsible operator reproduces the decision from recorded inputs or takes a fresh observation from a named vantage. Decision replay creates no new service effect. | [Support, Incidents, and Operational Changes](#support-incidents-and-operational-changes) |
| **Restore and verify** | A’s recovery authority authorizes its steward to restore one protected service. B verifies the replacement and retrieves the expected record under existing trust and policy. | [Routine Restore and Authority Recovery](#routine-restore-and-authority-recovery) |
| **Request LIFE lab session** · Proposed | A lab steward submits an experiment plan. Each laboratory decides independently whether to allocate its own apparatus. | [Connect a lab](#connect-a-lab) |

◆ **Standard-tool equivalent** · The versioned kit guide pairs each guided action with the supported standard-tool command sequence, required inputs, authority, target, and expected outputs. The guide identifies which checks can be run without privileges and which changes require local approval or delegated policy. This index names product actions and workflow references.

## Core

- ◆ **Mission** · Commonwealth is LIFE Technology’s open-source Internet initiative. Communities and laboratories can build, operate, extend, and interconnect compatible networks under their own administration.
- ◆ **Public access** · Commonwealth-operated sites provide public Internet access at $0 to participants. A participant using an existing provider keeps that provider’s connectivity and support arrangement.
- ◆ **Authority** · The site operator admits devices to the site network. Each federation operator controls its peers, keys, exports, and policies. A household decides who may act on its protected resources. Each laboratory controls its apparatus and experimental allocations.
- ◆ **Open operation** · Publish source, versioned protocols and interfaces, reproducible build instructions, conformance fixtures, and recovery runbooks. An independent operator supplies its own administrative authority and can build a compatible extension.
- ◆ **Quantum objective** · Independent laboratories use interoperable protocols and physical apparatus to establish and use shared entanglement. Classical coordination, simulated outcomes, and physical observations have separate interfaces and receipts.
- ▣ **Receipt form** · Record each observation where the decision or effect occurred. A participant report, a successful health probe, and an enforcement acknowledgment each support a different claim.

```text
receipt_type, claim_ref, gate_ref, approved_criterion_ref
environment, configuration_or_model_ref, run_ref
actor, authority_ref, starting_state, fixture_or_input, action
expected_decision, expected_resulting_state, expected_failure_state
approved_limit_and_unit, observation_window, measurement_method
observed_decision, observed_resulting_state, observation_point
evidence_refs, verdict
```

**PASS** requires direct evidence meeting the approved criterion. **FAIL** records an observed violation. **UNVERIFIED** applies when required evidence or an approved criterion is missing.

*Source anchors · Commonwealth ISP, “The Vision,” “The Proposed Architecture,” “Free and Open-Source,” and “Toward a Quantum Internet.” GRID, “Signin & Signup” and “Writeout receipt.”*

## Rubric



### Acceptance and Traceability

#### Gate index

| Claim and workflow | Authority and decision status | Independently scorable receipt |
|---|---|---|
| **CW-01 · Core and node setup** | Commonwealth ISP, open independent operation and extension. Arbiter, reproducible builds. Setup screen and enrollment card proposed. | Independent install, conformance, external readiness, authorized recovery readiness, and a separate independent extension receipt covering source, version, operator authority, peer exchange, and incompatible behavior |
| **CW-02 · Participant access, uplinks, and pilot** | Arbiter, initial IPv4 site profile, isolation, withdrawal, and $0 access. Uplink and conditional BGP depend on deployment. | Attachment, provisioning, DNS, HTTPS, separate withdrawal observations, routing or cutover, authorized site field run |
| **CW-03 · Peer enrollment, governance, publication, and discovery** | Arbiter, bilateral trust, mutual TLS, refresh, expiry, and revision protection. Locator and lookup mechanics proposed. | Empty-cache first exchange, independent denial, bilateral change, local exit, publication, rollback protection, locator change, fenced move |
| **CW-04 · Household and capability execution** | Arbiter, household authority, fresh challenge-bound appraisal, current authorization and atomic retry-safe effects. Setup and pairing controls proposed. | Administrator recovery, appraisal and grant, revocation and commit, decision replay, retry and result disclosure |
| **CW-05 · Application execution and independent clients** | Commonwealth ISP, separate execution domains and optional client choice. Registry and controls proposed. | Publisher, pinned installation, separate grant, isolation, upgrade, stop, rollback, independent client exchange |
| **CW-06 · Signed records and shared state** | Arbiter, signed operator records and witnessed checkpoints. Consensus conditional on a named shared record. | Signature, witness and coverage verification, underlying outcome, conditional ordering and recovery |
| **CW-07 · Support and recovery** | Arbiter, bounded clean-host restore and independently recoverable authorities. Engineer and QC, failure boundaries. | Incident and rollback, one authorized restore, three authority-store recoveries, B continuity and policy evidence, privileged audit, three rejection receipts |
| **CW-08 · Funding and institutional engagement** | Commonwealth ISP, sustainable free access and exploratory engagement. License and contribution defaults conditional. | Funded obligations, $0 terms, transfer or closure, rights-holder approval where applicable, agreement evidence for any claimed commitment |
| **CW-09 · Simulated quantum** | Commonwealth ISP and Arbiter, evidence scoped to the model. | Versioned run, modeled failure and cleanup, independent replay, labeled export |
| **CW-10 · Physical quantum** | Commonwealth ISP and Arbiter, physical measurements and independent reproduction. Independently enforced expiring laboratory leases adopted. Coordinator interaction, lease-message details, and Bell criterion proposed. | Separate local lease and terminal receipts and verdicts for Lab A and Lab B. Both terminal receipts must pass for cleanup to pass. Score herald detection, delivery eligibility, measured entanglement, and independent reproduction separately. Record usable-pair rate if claimed. |

#### Working scoring record

| Accountable role | Decision or procedure required before scoring |
|---|---|
| Site operator and funding owner | Site and upstream authority, supported equipment, funded capacity and duties, join and load criteria, withdrawal and recovery limits. |
| Access engineering | Credential-to-session and forwarding association across all applicable paths, restart enforcement, and equivalent IPv6 criteria before IPv6 use. |
| Federation engineering | Bootstrap approval, authenticated descriptor exchange, clock tolerance and expiry comparison, backoff ceiling, durable acceptance of all discovery generations, and scoped withdrawal persistence. |
| Protected-profile owner | Supported device class and verifier, evidence format, challenge and freshness rules, appraisal policy, revocation bound, commit ordering mechanism, and idle-stream enforcement verification. |
| Capability and application owners | Transaction scope, deduplication retention and stale-ID recognition, external reconciliation, in-flight work disposition, state migration, and rollback compatibility. |
| Recovery and authority owners | Recovery principals, checkpoints, reconciliation and verifiable fences for each store. Approve recovery time, restored-data age, B’s continuity limit, probe cadence, repeat count, and audit coverage. |
| Model and laboratory owners | Model invariants and replay criteria. For physical proof, named independent labs, apparatus, declared claim, trial selection, analysis, uncertainty, release behavior, and reproduction tolerances. |
| Rights holder and maintainers | Publication terms, contribution terms, and dependency compatibility. |

**Full-product acceptance** requires evidence for independent deployment and extension, federation and bilateral governance, household and execution controls, routine restore and separate authority recovery, and sustainable $0 operation. Score the classical pilot, simulated quantum, and physical quantum gates independently from their specified receipts.

## VVAULT

### Runtime and evidence boundary

◆ **Dependency** · The Commonwealth source brief and adopted operating model establish no VVAULT integration or runtime dependency. Participant access, federation, household authorization, recovery, and lab coordination use the controlling authorities and evidence paths in their worked flows.

▣ **Evidence** · Operators sign their own records, witnesses retain checkpoints, and reviewers trace each claim to the relevant direct observation or artifact. Households retain authority over protected data and grants. Laboratories retain authority over apparatus records and measurement disclosure. See [Signed Records, Checkpoints, and Shared State](#signed-records-checkpoints-and-shared-state).

**Optional future integration** · A VVAULT export or evidence attachment would require its own approved data scope, controlling authority, access and retention rules, and verification contract before it could be treated as a supported capability.

## Handshake



### Peer Enrollment, First Exchange, Governance, and Exit

**Proposed controls · Add peer, Run first exchange, Withdraw peer**

1. **Verify both identities.** A and B exchange public enrollment cards through a steward-verified channel. An administrator on each side compares the other’s fingerprint through that channel, verifies the signed locator descriptor against the corresponding operator key, and approves locally. The peer record shows operator ID, fingerprint, approved discovery locator, and compatible versions. An unknown or changed fingerprint requires a verified trust update before use. A’s approval alone leaves B free to decline.
2. **Run the first exchange.** B enters A’s operator ID and the logical ID of A’s published test capability. B starts with no service binding, fetches the record from the enrolled locator, and verifies it before connecting. A permits B to read a known fixture and withholds a separate action. B sees the fixture and the separate destination denial, each with a request reference. The results distinguish name resolution, discovery transport, signed binding, service reachability, service identity, version compatibility, and destination policy.
3. **Change a bilateral rule.** The proposing operator enters the rule, scope, rationale, and compatibility effects and signs the proposal. The other administrator reviews and signs assent or records a signed rejection. One signature leaves the prior rule in force. A compatibility change uses the published transition before the new rule governs exchanges. Either operator can submit a dispute referencing the relevant signed record. The disposition identifies the parties and the affected bilateral rule.
4. **Withdraw or rejoin.** The withdrawing operator selects the peer and reviews the affected exchanges. Its node commits withdrawal, invalidates usable bindings and affected sessions, and rejects new requests from that peer. If the remote endpoint is reachable, send signed notice. Display proposed **Local access ended** separately from **Notice delivered** or **Delivery pending**. Local enforcement survives restart and restore even when notice fails. Rejoin requires fresh acceptance by both operators.

```text
A and B steward exchange --> local fingerprint verification on both sides
                         --> two independent approvals

B -- A operator ID + logical service ID --> enrolled A discovery locator
B <-- signed record + authority chain -- A discovery
B -- service-side mutual TLS + versioned request --> A enforcement boundary
B <-- fixture or stable denial -- A destination authority

Local exit --> persist withdrawal --> invalidate affected bindings and sessions
           --> attempt signed notice independently
```

- ▣ **Enrollment and first-exchange receipt** · Record both approvals, trust fingerprints, empty-cache lookup, negotiated version, service-side identity, fixture response, and destination denial. Exercise unknown operator, changed authority, and unsupported version.
- ▣ **Governance receipt** · Record a rejected one-signature rule, a rule accepted by both, compatible upgrade outcomes, and the signed dispute disposition. Observe each operator’s active rule revision.
- ▣ **Exit receipt** · Withdraw one peer with an active exchange and unavailable notice delivery. Verify binding invalidation, session closure, denial of new requests, persistence through restart and restore, continued unrelated exchanges, and fresh approvals before rejoin.

*Source anchors · Arbiter, “Federation and governance” and “Transport and discovery.” Designer, peer setup and exit. Engineer, enrollment and shared governance.*

### Service Publication, Discovery, and Endpoint Move

**Proposed controls · Register service, Publish, Replace endpoint**

#### Register and publish

An authorized steward enters the service display name, versioned interface, endpoint, endpoint authentication key, and an approved safe health action. The operator assigns a stable logical service ID and signs a publication delegation scoped to that ID. The discovery system verifies the authority and independently probes the endpoint’s declared key, version, and health action before publication. An invalid delegation, identity mismatch, unsupported interface, unsafe probe, or conflicting revision leaves the record unpublished. The proposed view displays **Record published** and **External endpoint health** independently.

#### Bootstrap and lookup

The discovery locator is a **Proposed** enrollment input. A’s operator key signs the locator descriptor. B’s locally pinned copy of that key validates both the descriptor and A’s service-scoped publication delegation. B authenticates the discovery server against the enrolled TLS public-key pin. Public DNS can resolve the locator’s hostname. A DNS answer supplies an address and conveys no publication authority.

```text
Proposed lookup
  GET {enrolled_base_url}/v1/services/{operator_id}/{logical_service_id}

200
  A-operator-signed publication delegation
  verified epoch transition, when applicable
  endpoint record signed by delegated publication key {
    operator_id, service_id, endpoint, endpoint_key_binding, interface_versions
    publication_epoch, binding_revision, renewal_generation
    withdrawal_generation, issued_at, expires_at, publication_authority_ref
  }

404 unknown_service
  no available binding for this lookup key

Authenticated HTTP 503 discovery_unavailable
  show discovery unavailable; supply no new binding
  retain an eligible verified cached binding only through signed expiry

Request timeout
  show discovery timed out; no HTTP response was received
  retain an eligible verified cached binding only through signed expiry

TLS authentication failure
  show discovery identity could not be verified; no authenticated HTTP response exists
  trust no update to locator, binding, authority, or accepted generation state
  retain only a previously verified eligible binding through its original signed expiry
```

- ◆ **Binding verification** · B matches the lookup key and authority scope, verifies the delegated signature, checks the epoch and generations, and checks signed time validity. B persists accepted state before use. The endpoint key binding authenticates the service during peer TLS. The destination checks current resource authorization separately.
- ◆ **Refresh and renewal** · Signed validity is five minutes. Refresh once per minute during active use. Endpoint failure triggers one immediate refresh followed by bounded backoff. A same-revision renewal may advance its renewal generation and change validity metadata only. It cannot change the endpoint, key binding, interface versions, or other binding content.
- ◆ **Cache and withdrawal** · During an unavailable refresh, an eligible cached record remains usable through signed expiry if the relationship and authority state permit it. A verified withdrawal invalidates the binding and advances the durable withdrawal state. Under the proposed lookup contract, authenticated `unknown_service` also stops cached use for that lookup. It does not erase the rollback floor or substitute for a signed withdrawal.
- ◆ **Persistent acceptance** · Preserve accepted epoch, binding revision, renewal generation, and withdrawal generation across restart and restore. Reject lower state, same-revision binding conflicts, expired records, and unverified epoch transitions. Publication-key rotation requires an operator-signed transition that preserves rollback protection.
- **Proposed locator change** · A sends an operator-signed descriptor with a higher locator revision through the authenticated enrollment channel. B verifies it with the enrolled operator key, approves it locally, and persists it before use. DNS changes, redirects, locator outages, and untrusted replies do not authorize a replacement. If the old locator is offline, the enrollment channel still supplies the updated descriptor. Reverting to a previous locator requires a new higher revision. Updating the locator preserves service acceptance state.
- → **Visible failure** · The operator sees **Discovery unavailable** for an authenticated `503`, **Discovery timed out** when no HTTP response arrives, and **Discovery identity could not be verified** when TLS authentication fails. The client distinguishes those outcomes from **Record invalid or expired**, **Endpoint unreachable**, **Identity mismatch**, and **Request denied**. When there is no eligible cached binding or verified replacement, the client stops before opening the protected exchange.

#### Move a serving endpoint

The steward selects **Replace endpoint**, enters the replacement address and key, and stages it for a safe external probe. Before admitting it to production service, confirm old ingress fencing, applicable shared-write fencing, and current authorization and credential authority. A missing fence keeps the replacement closed. Planned overlap requires an approved concurrency rule and evidence for that rule.

```text
stage replacement -> verify staged endpoint -> verify old-host fences
  -> verify current authority -> publish higher-revision binding
  -> admit replacement -> B verifies binding and performs permitted request

replacement failure
  -> keep protected service closed if safe authority or fencing is uncertain
  -> or verify a trustworthy endpoint and publish another higher revision
```

B fetches the replacement binding through its enrolled locator and uses its existing trust and policy. A previous signed record cannot perform rollback. A return to a verified endpoint is a new higher-revision publication.

- ▣ **Publication receipt** · Record steward delegation, submitted service fields, external probe and observation point, signed record, and independent endpoint status. Exercise invalid delegation and identity mismatch.
- ▣ **Bootstrap receipt** · Begin with an empty service cache and only approved enrollment material. Record DNS, locator TLS pin, lookup key, response, authority chain, durable acceptance, and service authentication. Exercise `unknown_service`, an authenticated `503`, a request timeout, and a TLS authentication failure independently. For the latter three cases, test with and without an eligible cache and observe the caller-visible result and binding decision through signed expiry. For the TLS failure, verify independently that no locator, binding, authority, or generation update was trusted. Exercise locator replacement while the old locator is down.
- ▣ **Persistence receipt** · Exercise valid renewal, same-revision conflict, expiry, verified withdrawal, unknown epoch, verified rotation, failed-endpoint immediate refresh and backoff, restart, and stale restore. Record durable state before and after every applicable transition.
- ▣ **Cutover receipt** · Record staging checks, fences and current authority, binding revisions, B’s unchanged trust and policy, and B’s request from the replacement path. Exercise an unavailable fence and a rollback using a new revision.

*Source anchors · Arbiter, “Transport and discovery” and “Routine recovery.” Designer and Engineer, service publication and binding replacement. QC and Clean, persistence and cutover. Locator and lookup mechanics are proposed.*

## Signin & Signup



### Participant Access

**Worked product specification · Commonwealth-operated access**

An eligible participant gets one Wi‑Fi credential for one device, joins from the device’s Wi‑Fi settings, and uses the public Internet at $0. The site operator can issue and withdraw access and identify where a connection failed. The participant uses the operating system’s Wi‑Fi controls and an ordinary browser. Commonwealth provides the join instructions and the operator’s access controls.

The access profile is an approved site, operator-issued per-device Wi‑Fi credentials, IPv4 provisioning over DHCP, a site recursive DNS resolver, outbound NAT, and isolation from other participants, household resources, and management. The credential handoff, operator screen, and messages below are **Proposed** product choices. Device Wi‑Fi screens and system messages vary by platform. *Source anchors · Commonwealth ISP, “The Proposed Architecture,” “Security: Protecting the Household,” and “Development and Verification.” GRID, “Signin & Signup.”*

#### 1. The operator prepares the site

The site operator opens **Participant Access** for the approved site. The page identifies the site, the exact Wi‑Fi name participants should select, and the support contact available to someone who is offline. The operator verifies the upstream, access points, guest gateway, DHCP, and resolver. A managed test device joins through a test credential and shows that it can obtain network settings, resolve a name, and reach a public HTTPS destination through the site.

The site check also exercises isolation and withdrawal. A guest must be prevented from reaching another guest, a protected household resource, or a management endpoint. A withdrawn test credential must lose forwarding even if the access point fails to disconnect it. The operator view shows the individual check results and their timestamps so a prior site check cannot be mistaken for current health. An incomplete or failed readiness check disables **Issue device credential** and identifies the failed check. When a site that has already issued credentials loses its uplink, existing participants can still attach. The operator sees the upstream fault and can still withdraw access.

The operator manages upstream addressing and NAT, DHCP settings, resolver configuration, and network isolation from the site’s infrastructure controls. The Participant Access page shows their effects on service and offers credential actions. Participants use automatic IP and DNS settings.

#### 2. The participant gets a credential and joins

The participant asks the site operator for access. The operator confirms eligibility under the site’s admission rules, selects **Issue device credential**, and enters a short label the participant can recognize, such as `Sam’s tablet`. Commonwealth generates a unique Wi‑Fi password, assigns a support reference, and records its issuing operator. The operator hands the participant a join card in person. A printed card is the proposed default because it works before the device has a connection. A Wi‑Fi QR code can supplement the manual instructions on supported devices.

**Proposed join card**

```text
Commonwealth Wi-Fi · [Site name]

1. Open Settings → Wi-Fi.
2. Select [exact network name].
3. Enter [device Wi-Fi password].
4. Open your browser and load a website.

Access is free. Use this password on one device.
Need help? Contact [offline support contact].
Give support this reference: [reference].
```

The card shows the password. The routine support view shows the reference and device label. A participant who loses the card can ask the operator for a replacement. After verifying the request, the operator withdraws the old credential and issues a new one. An additional device gets its own credential.

The participant selects the named network and enters the password. The access point accepts the credential and attaches the device to the isolated guest network. DHCP supplies the IPv4 address, subnet, default gateway, and recursive resolver. When the participant opens a public site, the resolver answers from its unexpired cache or resolves the name, and the gateway forwards the outbound connection through NAT. The participant sees the device’s normal Wi‑Fi indication and the requested page. The browser provides the visible confirmation that public access works. This flow requires only the device’s existing Wi‑Fi and browser surfaces.

A per-device password is an individually revocable access credential. It can be copied. The proposed profile treats one device per credential as an issuance rule and validates withdrawal for every active session associated with that credential. Household authorization remains a separate resource decision.

```text
Device -- per-device password --> AP / site admission
       <-- accepted association -- AP
       -- DHCP request --> site DHCP
       <-- IPv4 lease, subnet, default route, resolver --
       -- name query --> recursive DNS
       -- public IPv4 connection --> NAT gateway --> authorized upstream

Guest forwarding policy
  guest -> public destinations        allowed subject to site access policy
  guest -> other guest                denied
  guest -> protected service network  denied
  guest -> management                 denied
  unsolicited inbound -> guest        denied
```

◆ **IP-family gate** · The initial profile uses IPv4. Enable IPv6 only after equivalent isolation and withdrawal checks pass for its forwarding paths.

#### 3. Support can find the failed boundary

The participant tells support the reference, device type, and what happened immediately after selecting the network. The operator checks the latest event at each boundary. Public DNS and HTTPS checks report the site or test-device path. The view labels that vantage point so support can distinguish site health from a particular participant’s result.

| Boundary | What the participant sees | What the operator checks and does |
|---|---|---|
| **Attachment** | The network is visible, but the device returns to the password prompt or reports that it could not join. | Check whether the credential is active and installed on the site’s access points. A rejected attempt may be visible only by access point and time because a wrong password may not identify a credential. Ask the participant to confirm the exact network name and retry once. Replace the credential if needed. |
| **IPv4 provisioning** | The device shows Wi‑Fi connected, but cannot load a page. Some devices report no Internet or show a self-assigned address. | Confirm that the device attached and inspect whether the guest DHCP server issued a lease. If the pool is exhausted, restore capacity and ask the participant to reconnect so the device can request a lease again. |
| **Public DNS** | A named site fails to load. A recently used site may still work through an unexpired cached answer. | Check a fresh lookup through the site resolver and independently check upstream IP reachability. Repair the resolver path if IP is working. Support tells the participant that the site is having a name-resolution problem. |
| **Upstream forwarding** | Wi‑Fi remains connected, but multiple public sites stop loading. | Confirm the guest lease and gateway, inspect WAN and NAT health, and run a test from the guest network. If the WAN has lost its route, escalate to the upstream provider. Existing credentials stay valid so participants can resume once the path returns. |
| **Guest isolation** | Ordinary websites work, while another guest device or a protected local resource is unreachable over the guest network. | Verify the applicable isolation rule. If the participant needs a protected resource, direct them to that resource owner’s authorized access path. Keep the site access grant scoped to guest connectivity. |

If one browser or destination fails while an independent HTTPS check succeeds, support records the narrower symptom and checks the device or destination before replacing the Wi‑Fi credential. The operator view needs join and lease events, infrastructure health, and withdrawal evidence for this workflow. Participant browsing history is outside the support record.

#### 4. The operator withdraws access

From the device row, the operator selects **Withdraw access**. The confirmation identifies the site, device label, and support reference and says, “Internet access for this credential will end. A new credential is required to rejoin.”

Commonwealth applies a forwarding deny for every active session tied to the credential and clears existing forwarding and NAT state. The access points disable the credential for future associations and attempt to disconnect active sessions. The operator view reports enforcement and disconnection separately.

◆ **Enforcement correction** · The withdrawal covers future admission and every applicable existing forwarding path for every session using the credential. That includes copied credentials, sessions on multiple access points, sessions that roam or change leases, and local traffic that bypasses NAT. Enforcement must survive restart. Before forwarding resumes after restart, each applicable enforcement point reapplies the committed withdrawal. The equipment must support blocking those paths independently of station eviction.

```text
Withdraw access
  → Commit credential withdrawal
  → Verify future admission is blocked across applicable access points
  → Verify existing forwarding is blocked across applicable paths
      → Both verified: Access withdrawn
          → Device disconnected
          → or Device still attached · forwarding blocked
      → Either unverified: Withdrawal incomplete · operator action required
```

The implementation must associate a credential with every current guest session at the enforcement point, including across access points and after an address change. A device label or last-seen IPv4 address is insufficient. If the selected equipment cannot maintain that association or block forwarding independently of eviction, it cannot support this profile.

If the access point disconnects the device, the participant sees the Wi‑Fi connection drop or a subsequent join fail. If eviction fails, the device may keep its Wi‑Fi indicator and lease, but new and existing flows through the site stop. The operator can explain that access ended even though the device still shows an association. To verify the boundary, exercise withdrawal while a test device has an open connection and eviction is held back. Confirm that the open flow stops, a new public connection fails, reconnect with the withdrawn credential fails, and another guest retains service. Record enforcement and eviction separately.

- ▣ **Attachment receipt** · Record the device-side join result and AP-side association or rejection. Exercise wrong credentials and replacement. Record when the AP cannot attribute an attempt to a credential.
- ▣ **Provisioning receipt** · Record the participant’s configuration and the DHCP server’s lease decision. Exercise pool exhaustion and a successful request after capacity returns.
- ▣ **DNS and HTTPS receipts** · Record fresh lookup, cache expiry, upstream IP reachability, and HTTPS as separate observations. Identify which came from the participant and which came from a managed guest-network probe.
- ▣ **Future admission receipt** · Record withdrawal commit and rejoin attempts across applicable APs, including after restart. Attempt rejoin with a copied credential.
- ▣ **Existing forwarding receipt** · Record active and new public flows and applicable local forwarding for every test association. Include a copied credential, a roam, a lease change, failed eviction, and restart. Record the last permitted traffic and enforcement acknowledgment at each path. Observe a separate guest as a control.
- ▣ **AP eviction observation** · Record whether the AP disconnected each association. When an association remains, independently verify whether forwarding stopped. Record **Withdrawal incomplete** whenever an admission or forwarding path remains unverified.

#### Bring your own uplink

A participant using an existing home, campus, or other provider connection joins that network as usual. Its operator supplies the Wi‑Fi credential, IP address, gateway, resolver, and public Internet support. Commonwealth issues no site credential for that path. A compatible Commonwealth client can use the existing connection for separately authorized services. Withdrawing Commonwealth service permission ends that service access. Public Internet connectivity remains under the existing provider arrangement.

The first review should exercise the full site flow on an ordinary device, then force the failure cases and withdrawal with eviction held back. The proposed join card and operator controls can be revised after that exercise. The acceptance condition is that a participant can get online, support can identify the failed boundary, and the operator can verify that withdrawn access has stopped.

*Decision anchors · Arbiter, “Site access.” Engineer, site admission and withdrawal contracts. QC and Clean, participant access and withdrawal coverage.*

### Household Onboarding, Grants, and Revocation

#### Establish administrator authority

**Proposed onboarding** · From the isolated administration network, the intended administrator supplies a single-use setup code obtained through an administrator-controlled handoff and registers the first administrator credential. The setup flow verifies possession, consumes the code, and binds the administrator in one enrollment decision. An expired code requires a fresh authorized handoff. Concurrent valid submissions yield at most one binding. The administrator registers and verifies a separate recovery authenticator. If recovery authority cannot be verified, administration remains closed and the household follows its authorized recovery procedure.

#### Pair a device and issue a grant

**Proposed pairing interaction** · The client generates a device key and displays a short pairing reference. The administrator compares the references on both devices and approves the key enrollment. Under the first protected profile, the configured verifier appraises fresh evidence bound to the device and its challenge. The view distinguishes **Key enrolled**, **Evidence appraised**, and **Grant issued**. Unsupported device class, expired evidence, challenge mismatch, or verifier unavailability after evidence expires blocks protected actions under that profile. Public access eligibility follows site admission.

```text
Proposed grant form
  subject: Riley
  enrolled_device: Riley's tablet
  resource: Shared household calendar
  action: View
  audience: Calendar service
  limits / expiry: administrator-selected scope
```

The household store validates the administrator or delegate, commits the scoped grant, and returns its ID and effective revision. An over-broad delegation, unknown resource, or invalid expiry leaves the store unchanged. Riley can view through the protected service. A request to edit receives a denial without protected results. If the service cannot establish current authority, it denies the action and the client reports that access could not be verified.

#### Revoke or replace

The administrator chooses proposed **Revoke grant** or **Revoke device**. The store records the effective revocation. Enforcement points invalidate affected cached decisions, acknowledge enforcement, reject subsequent actions, and close affected streams within the approved bound, including idle streams. The operator view distinguishes **Revocation saved** from **Enforcement confirmed**.

◆ **Commit ordering** · A revocation effective before a queued effect commits must block that effect. A prior admission check supplies no commit authority after revocation. Where current authority cannot be established at commit, the effect remains uncommitted. Current authority is also required before disclosing any protected stored result.

A replacement device enrolls a new key, completes its own appraisal where required, and receives explicitly issued grants. Restoring an older application backup cannot revive withdrawn device authority or grants. Revocation controls subsequent access and disclosure. Data already delivered remains outside recall.

- ▣ **Administrator and recovery receipt** · Record authorized setup handoff, first binding, expiry, concurrent consumption, recovery authenticator verification, and recovery result without storing the setup secret.
- ▣ **Pairing, appraisal, and grant receipts** · Record the device key, challenge and evidence references, verifier decision, policy profile, grant scope and revision, allowed view, adjacent edit denial, and no protected disclosure on denial.
- ▣ **Revocation receipt** · Record effective revocation, each enforcement acknowledgment and delay, active and idle stream closure, existing session and reconnect denial, and public access as a control. Force a revocation before queued commit and verify no effect commits. Exercise stale or replayed evidence, verifier failure after expiry, and authority-store unavailability.
- ▣ **Replacement receipt** · Verify the old key remains denied and the replacement receives only grants explicitly issued to it. Repeat after application restore.

*Source anchors · Commonwealth ISP, “Security: Protecting the Household.” Arbiter, “Household authority.” Designer, household onboarding. Engineer and QC, revocation ordering and appraisal. [RATS architecture, RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html).*

## Security

### Authority and tenancy

◆ **Default denial** · Guest, service, household, workload, management, and lab boundaries enforce access under their own authorities. A site credential grants guest connectivity. A peer relationship grants federation eligibility. The destination decides each protected action. An operator’s administrative role applies to its own node. A workload identity applies to its execution domain. An apparatus reservation applies to the local lab resources and generation that the lab approved.

| Boundary | Authority and allowed path | Denied path and observation |
|---|---|---|
| Site access | The site operator admits a device, provisions the guest path, and allows public forwarding. | Observe guest-to-guest, guest-to-service, guest-to-management, and withdrawn-credential denial at the participating enforcement points. [Participant Access](#participant-access) |
| Operator and service | Each operator approves bilateral trust. A delegated publisher can sign bindings within scope. The service endpoint authenticates the channel and evaluates destination policy. | Observe an unenrolled peer, invalid publication authority, and authenticated but unauthorized service action separately. [Peer Enrollment, First Exchange, Governance, and Exit](#peer-enrollment-first-exchange-governance-and-exit) |
| Household and workload | The household issues scoped resource grants. The operator confines each workload to its own identity, storage, and controlled interfaces. | Observe an adjacent action denial at the resource gateway and a direct storage or management denial at its boundary. [Household Onboarding, Grants, and Revocation](#household-onboarding-grants-and-revocation) · [Application Publication and Isolated Execution](#application-publication-and-isolated-execution) |
| Laboratory | Each steward authorizes its own apparatus allocation and enforces the lease locally. | Observe expired or mismatched generations at each lab and verify that the rejected instruction starts no attempt. [Physical Quantum Workflow](#physical-quantum-workflow) |

### Credential issue, withdrawal, and evidence

- ◆ **Site credentials** · The site operator issues and withdraws per-device credentials. Withdrawal blocks future association and every applicable forwarding path for all sessions using the credential, including traffic outside NAT. Observe admission and forwarding independently of AP eviction, and verify persistence after restart.
- ◆ **Operator and publication keys** · The operator controls its operator key and service-scoped publication delegations. Each peer independently verifies or withdraws local trust. On scoped withdrawal, invalidate affected bindings and sessions, preserve durable withdrawal state, and observe unrelated peers as a control. A publication-key epoch change requires verified transition and rollback protection.
- ◆ **TLS credentials** · The controlling credential authority issues and withdraws serving and peer authentication credentials. The destination terminates protected mutual TLS at the enforcement boundary. Verify the service key against the signed binding and close the connection on authentication failure. Restore uses fresh serving credentials under current authority.
- ◆ **Household device keys and grants** · The household administrator enrolls or withdraws the device key and controls its grants. For the protected profile, verify challenge-bound appraisal when required. Confirm withdrawal on active and idle streams, existing sessions, reconnect, queued effects at commit, and requests for protected stored results. Observe enforcement acknowledgment and any disclosure separately.
- ◆ **Workload identities** · The local operator issues the runtime identity to the reviewed execution domain. Stopping the workload invalidates its access, closes applicable sessions, and resolves in-flight work under the approved contract. Record committed effects separately from canceled or denied work.

### Scoped cross-container grant

```text
source_tenant, source_identity, source_execution_domain
resource_tenant, destination_resource, destination_interface
permitted_action, audience, scope, expiry, issuing_authority
current_authority_check, decision, enforcement_point
```

→ **Allowed** · A calendar viewer in the application domain presents its workload identity and a current household-issued `calendar:view` grant to the controlled interface. The destination checks the tenant, identity, resource, action, audience, scope, expiry, and current grant. It returns the permitted view through that interface.

→ **Denied** · The same viewer requests `calendar:edit`, presents an expired grant, or tries direct storage access. The resource gateway denies the unauthorized action or expired grant. The network boundary blocks the direct path. Observe the attempted action, decision, resulting state, and absence of protected disclosure or a committed effect. The audit record stays subject to its own retention rules.

▣ **Crossing receipt** · Record the actual source and destination tenants, authority and scope, interface decision, observation point, and resulting state. A grant effective at admission must still be current where a protected effect commits or a protected stored result is returned.

### Guided setup and plugin boundary

◆ **Privileged changes** · Enrollment, grant and revocation, endpoint publication, restore, and apparatus approval occur through the controlling local surface under actor approval or delegated policy. The tool binds an approved privileged change to its target and plan digest and checks them at execution. The plugin can explain public instructions, propose commands, and interpret user-reviewed redacted diagnostics. Private keys, session tokens, unrestricted shell access, privileged controls, household records, and apparatus controls stay outside the plugin boundary. Commonwealth applies the same authorization path without a plugin or AI host.

▣ **Unauthorized publication receipt** · Submit a publication request from a caller lacking service-scoped delegation, such as an unapproved setup suggestion passed to the control surface. Observe denial at publication enforcement. Compare the accepted binding and revision before and after. Inspect the response and allowed diagnostic output for credential disclosure, and verify cleanup of the attempt’s scoped resources. **PASS** requires denial, unchanged binding and revision, no credential disclosure, and verified cleanup within its approved scope and limit.

### Crossing cleanup and independent physical state

◆ **Named cleanup rules** · At completion, denial, or timeout, the boundary owner closes temporary sessions, invalidates transient or scoped credentials, clears in-scope transient buffers, and resolves pending effects under their own commit or reconciliation rules. Keep approved audit evidence under its retention policy. Each cleanup action acts on resources attributable to the crossing and under the boundary owner’s authority. A repeated cleanup run must preserve the terminal state and leave unrelated resources alone.

**Proposed retained-material purge** · Any purge beyond the crossing’s transient resources requires an approved policy naming the material, owning authority, allowed operation, timing limit, and verification evidence. Each domain owner acts within its own scope. There is no general-purpose purge authority over another tenant, household, operator, or lab.

▣ **Repeatable cleanup receipt** · Inventory the scoped sessions, credentials, buffers, and pending effects for the fixture. Observe their disposition after completion, denial, and timeout, then rerun cleanup and verify the same terminal state. Verify unrelated resources and retained audit evidence separately. Record the boundary, actor, authority, timing, resulting state for each scoped resource, and any unresolved disposition. Use **FAIL** for observed violations and **UNVERIFIED** for missing evidence or approved limits.

◆ **Classical and physical separation** · A classical request, authorization decision, and approved telemetry can cross a controlled interface. Each lab controls physical quantum memory and apparatus state under its experiment lifecycle, including consumption, hold expiry, or reset. Score physical state and release from the lab’s own instrument and lifecycle evidence. A classical cleanup receipt establishes only the classical disposition.

### Restore safeguards and optional CleanHouse verification

◆ **Restore gate** · A’s authorized steward restores one protected service once onto a clean host. Verify old ingress and applicable shared-write fences, current independently recoverable authorization, publication and credential authorities, fresh serving credentials, and a higher-revision binding for the same service. B retrieves the expected record through the approved binding with unchanged trust and policy while B’s own workload remains under probe. If fencing or current authority is uncertain, keep protected service closed. Score zero unauthorized successes and zero privileged founder interventions from direct observations and complete audit coverage. Use separate revoked-credential, tampered-backup, and unauthorized-rejoin verdicts. [Routine Restore and Authority Recovery](#routine-restore-and-authority-recovery)

**Optional CleanHouse attachment** · The host owner may attach a scoped baseline identifying the host, configuration, collection authority, provenance, and observations. It can document the observed host state or changes within that scope. Direct enforcement, restore, and instrument receipts supply the respective security and physical verdicts.

▣ **Pre-score security record** · The responsible owners approve the setup actions eligible for delegated local approval, authenticated release-trust distribution and recovery procedures, diagnostic sharing and retention rules, and cleanup and recovery limits. Use those approvals with the direct receipts for the affected gates.

*Source anchors · Commonwealth ISP, “Security: Protecting the Household,” “The Proposed Architecture,” and “Toward a Quantum Internet.” Arbiter, Commonwealth Kit ruling, optional AI and enforcement, and proof boundaries. Designer, plugin authority and crossing cleanup. Clean, security controls and evidence obligations.*

## Network Services and Orchestration

### LIFE flagship reference lab and Commonwealth Kit

◆ **Purpose** · LIFE reimagines the Internet through quantum technology. The kit connects people over ordinary IP, gives independent operators a reproducible path to interoperable services, and gives laboratories a common path from simulation to a separately measured physical experiment.

◆ **Adopted guided setup** · LIFE’s default is one versioned **Commonwealth Kit** with **Connect to a service**, **Run a node**, and **Connect a lab**. The kit includes a signed release manifest, compatible client, node service, published guides and standard-tool steps, conformance fixtures, simulator, and documented adapter interfaces and configuration templates. The screens and messages described here are **Proposed** unless identified as adopted behavior.

◆ **Reference ownership** · LIFE owns the proposed flagship reference lab, its classical control endpoint and apparatus, its reference node and ingress, reference service, sandbox, and official release and documentation channels. LIFE decides access to its own services and apparatus. The reference deployment remains proposed until the relevant receipts establish operation. Independent operators own their infrastructure, keys, policies, service exports, backups, and recovery authority. Each lab controls its apparatus and experimental allocations. Households authorize their own resources. At a Commonwealth-operated site, the site operator provisions and supports participants and the upstream provides the contracted IP link.

### Verify and apply setup

1. Open the versioned official guide and obtain the kit manifest. Obtain the release trust root through the separately authenticated channel identified by the guide. Verify the manifest and the applicable artifact digests before opening a setup action. A signature, digest, or trust-root failure stops setup before changes occur and identifies the failed check.
2. Choose a setup action and enter the options for the intended target. The local tool presents the target, changes, required privileges, and a digest binding the plan to that target. An authorized actor approves that plan, or a previously authorized local policy approves it within its delegated scope. An AI suggestion supplies no execution authority.
3. Apply through the local tool. The tool checks the target, plan digest, and approval at the privileged boundary. A changed plan, different target, or missing authority stops the change and requires a new decision. The result separates applied changes, failed checks, and any remaining partial state. Use the documented standard-tool steps to reproduce the same checks and approved actions without the guided surface or AI.

▣ **Setup authority receipt** · Record guide and kit versions, trust-root verification reference, manifest and artifact checks, target, plan digest, actor or delegated policy, and resulting state. Exercise a bad release verification, changed target or plan, and absent approval. Verify at the enforcement point that the rejected privileged change did not occur.

### Connect to a service

1. Open the guide over an existing provider connection, or join a Commonwealth-operated site through [Participant Access](#participant-access). At a site, use the operating system’s Wi-Fi controls and confirm public access in a browser. Site access and reference service access have separate credentials and decisions.
2. Verify and install the client, choose **Connect to a service**, and select proposed **Try LIFE reference service**. Review the LIFE operator identity, service reference, and requested action. Confirm the reference choice locally. The client uses the approved discovery locator and signed binding, verifies the service endpoint, and submits the fixture request over the authenticated service path. LIFE decides whether to return its fixture. The client displays the typed result and support reference.
3. A public connectivity fault directs the participant to the site operator or existing provider. A discovery failure identifies the lookup boundary. An identity mismatch stops before the protected request. A destination denial identifies the attempted action and reference without disclosing protected data. An independent compatible client can exercise the same published interface.

▣ **Reference service receipt** · Record connection path, client and kit versions, local reference acceptance, discovery and authenticated identity, request reference, and LIFE’s fixture or denial result. Keep the site’s public access and local control receipts separate. A passing LIFE exchange establishes the reference path.

### Run a node

1. Choose **Run a node**. Enter the operator identity, local interface, operator-controlled ingress and discovery settings, and designated recovery authority. Review and approve the local setup plan. Create local operator, publication, TLS, and workload credentials in their respective roles. The checks report release verification, local conformance, DNS, TCP reachability, endpoint identity, and recovery readiness separately.
2. Choose an independent peer, the local test counterpart, or LIFE’s disclosed reference peer. To use LIFE, review and verify its enrollment material through the authenticated channel, then approve locally. LIFE independently decides whether to enroll the operator. To use an independent peer, follow the same bilateral flow with that operator’s keys and locator. A failed reachability or identity check leaves the exchange incomplete. An unapproved peer remains unenrolled.
3. Run the first exchange. Start with an empty service cache and approved enrollment inputs. Discover the delegated signed binding, authenticate the destination, and request a known fixture. Then request a distinct action that the destination deliberately withholds. Observe the allowed fixture and the denial at both ends. Each operator retains its own keys and policy throughout.

▣ **Independent first-exchange receipt** · Use two independently administered implementations. Record each implementation and version, local approvals and keys by public reference, empty-cache lookup, endpoint authentication, negotiated interface, matched request references, expected fixture, and destination-observed denial with no protected disclosure. Keep the local test counterpart and LIFE reference results as separate evidence.

▣ **Sandbox loss and recovery receipts** · With the LIFE sandbox unavailable, record the failure at the reference boundary and run the kit’s conformance fixtures against the supplied local counterpart. Record which fixtures pass and which reference checks remain unavailable. Score sandbox recovery independently: an enrolled peer re-verifies the restored sandbox binding and completes the authorized fixture against the same logical service identity under unchanged peer trust and policy. Record before-and-after identity, binding evidence, peer trust and policy snapshots and intervening changes, the first authorized success, and recovery time against the approved bound. Local conformance during the outage and a successful reference recovery support different verdicts.

### Connect a lab

1. The steward chooses **Connect a lab**, verifies the kit, configures the lab node and classical control endpoint, and selects a supported adapter. Review and approve the target-bound plan locally. The kit checks the node path and the adapter’s reported software capabilities separately. A lab behind NAT can use an operator-controlled ingress with TCP pass-through to its service enforcement boundary. A reachable node can still report an unsupported or unready adapter.
2. Enroll a peer and exercise the classical exchange. Rehearse with the reference two-endpoint template, declared model and version, and seed where applicable. Choose the sandbox or the local simulator. The run reports **Simulation**, its inputs, reservation, attempts, modeled herald or timeout, and release. If an endpoint fails to confirm, record the failure and terminal allocation state before replaying.
3. For a physical session, the steward selects proposed **Request LIFE lab session** or uses the documented equivalent with an independent lab. Submit experiment version, requested capabilities, target state, timing constraints, and measurement plan. Each lab approves its own resources and enforces its own expiring reservation. Two current approvals for the same generation are required for a coordinated attempt. A decline, expiry, lost readiness, or coordination fault stops the affected attempt and triggers local release or reconciliation at each lab. Ordinary Internet traffic continues on its separate path.
4. Each lab supplies authorized instrument records with correlated attempt references, calibration, and timing. The reviewer scores herald detection, delivery eligibility, the physical result and uncertainty, and independent reproduction separately. Missing or uncorrelatable records leave the affected physical gate unverified. See [Simulated Quantum Workflow](#simulated-quantum-workflow) and [Physical Quantum Workflow](#physical-quantum-workflow).

◆ **Hardware boundary** · Guided setup covers supported software and adapters. Physical execution requires qualified apparatus and channel, calibration, synchronization, current approvals from both labs, and locally enforced expiring reservations. The selected apparatus, channel qualification criteria, claim, and measurement method require approval before scoring.

▣ **Lab setup, rehearsal, and physical receipts** · Record local node and adapter results, classical peer exchange, model and simulation trace, and any separately authorized physical run. For physical evidence, capture both leases, apparatus and calibration references, correlated measurements, analysis, each lab’s terminal verdict, and continued public reachability. The lab can optionally attach a scoped CleanHouse baseline with provenance. That attachment supports only the host observations it records.

### Documentation and optional AI help

◆ **Equivalent setup paths** · Publish the official step-by-step guide, standard-tool procedures, fixtures, and supported platform and AI-host lists with the kit version. A user can complete the same authoritative steps with documentation alone or use an official plugin in a supported AI host of their choice.

**Proposed plugin interaction** · The plugin reads public setup instructions, explains the current step, suggests commands, or interprets a diagnostic export the user first reviews and redacts. The user returns to the local tool to review and approve any privileged plan. If the plugin or host is unavailable, continue at the corresponding documented step. See [Security](#security) for access and retention boundaries.

*Source anchors · Commonwealth ISP, “The Vision,” “The Proposed Architecture,” “Toward a Quantum Internet,” and “Free and Open-Source.” Arbiter, Commonwealth Kit ruling, selected defaults, and proof boundaries. Designer, LIFE reference operating model.*

### Independent Node Setup

**Proposed operator interaction**

1. **Verify release.** The independent operator selects a published platform profile and supplies the release manifest, artifacts or source revision, and release verification material. The installer verifies the signature and artifact digests before loading the software. The operator sees the release identity and verification result. An invalid signature or digest stops installation. A failed conformance fixture leaves the node locally installed and ineligible for federation readiness.
2. **Configure node.** The operator enters a display name, selects the network interface, and supplies the ingress hostname or address they control. The node records distinct credentials for operator trust, delegated service publication, TLS endpoints, and runtime workloads. The operator selects the approved recovery authority and performs a recovery check using the documented procedure. The view reports recovery readiness separately from network readiness.
3. **Check ingress.** The operator requests an independent probe of the ingress name, TCP path, and expected endpoint identity. The proposed view reports **Local conformance**, **Name resolution**, **Ingress reachable**, and **Endpoint identity** independently. A node with passing local fixtures can prepare an enrollment card while ingress is unavailable. A remote exchange requires the probe and the peer’s own validation to reach the destination.
4. **Export enrollment card.** The operator exports public enrollment material. Under the proposed discovery bootstrap, the card carries the signed locator descriptor that a peer can use before it knows any service endpoint.

```text
Proposed enrollment card
  operator_display_name, operator_id, public_operator_key, fingerprint
  supported_protocol_versions
  signed_discovery_descriptor {
    discovery_base_url, discovery_TLS_public_key_pin
    locator_revision, operator_signature
  }

Readiness observations
  release_verified -> configured -> conformance_passed
  independent DNS -> TCP ingress -> expected endpoint identity
  designated authority -> recovery material verified under approved procedure
```

- → **Failure response** · **Name unavailable** directs the operator to the published hostname and resolver path. **Ingress unreachable** directs them to addressing, routing, or the ingress tunnel. **Identity mismatch** stops peer use and directs the operator to the endpoint binding and serving credential. Conformance or recovery failure stays visible after a successful network probe.
- ▣ **Independent installation receipt** · A second operator builds or installs from published materials using its own keys. Record release verification, platform, build identity, configuration digest, fixture results, credential roles, and any founder credential or unpublished service dependency.
- ▣ **External readiness receipt** · Record DNS answer, independent probe vantage, TCP result, expected and observed identity, and each failure boundary. Verify the public enrollment card contains only public material.
- ▣ **Operator recovery readiness receipt** · Identify the designated recovery principal, approved procedure, and observed verification of recoverable authority without recording secret material.

#### Build and exercise an independent extension

Operator B selects a published interface version, obtains its schema, build instructions, and conformance fixtures, and implements a compatible capability independently. For the worked fixture, B implements a read action that returns a known record in the published result format. B builds the extension, runs the applicable fixtures, and installs the verified artifact on its own node under its own administrative and workload authority. B delegates publication for the service, publishes its signed binding, and grants independent peer A the fixture read.

→ **Compatible result** · A discovers B’s extension through the enrolled peer relationship, authenticates the service, selects the supported interface version, and invokes the granted read. A observes the expected typed record and a request reference. B observes the matching authorized action and result under its own policy.

→ **Incompatible result** · Submit a variant that fails an applicable schema fixture. B reports the failing check, blocks that variant from federation readiness, and keeps the compatible release active. From A, request an unsupported interface version against the active release. A receives a compatibility error. B observes that the capability did not execute and no protected result was disclosed.

- ▣ **Independent extension receipt** · Record the published contract and fixture references, B’s independent implementation source and build identity, artifact digest and interface version, B’s deployment, workload and publication authority, and conformance decisions. Tie A’s discovery, authentication, request and typed response to the matching observation at B. Record the incompatible variant’s failed fixture and resulting deployment state, and A’s unsupported-version response and B’s no-execution observation separately.

*Source anchors · Commonwealth ISP, “Free and Open-Source” and “Development and Verification.” Arbiter, independent operation. Designer and Engineer, node setup and installation.*

### Connectivity, Uplinks, and Routing

```text
EXISTING PROVIDER
  Device -- public IP traffic --> existing router/provider --> public Internet
  Node on router or LAN -- peer IP traffic over same uplink --> independent peer

DIRECT INGRESS
  Peer -- TCP carrying mutual TLS 1.3 --> destination node
       <-- authenticated service identity -- service enforcement boundary

PROPOSED TUNNEL PATH
  Destination node -- authenticated outbound tunnel --> operator-controlled public ingress
  Peer -- TCP carrying mutual TLS 1.3 --> public ingress
       -- TCP pass-through inside tunnel --> destination service enforcement boundary
  Destination -- versioned service response --> authenticated peer
```

- ◆ **Choose uplink.** The site operator records the authorized upstream, equipment and power ownership, capacity, and support contact. Starlink, fiber, and terrestrial radio are candidates. Provider-assigned addressing and a default route are the proposed starting configuration. An operator declares supported IP families, outbound translation, and any inbound reachability it offers.
- **Proposed tunnel interaction** · The operator with no usable inbound path registers a public ingress it administers and configures the node’s authenticated outbound tunnel. The ingress accepts the authorized tunnel and forwards the peer’s TCP session. The service enforcement boundary terminates mutual TLS 1.3 and evaluates the request. An ingress can report **Tunnel connected** while peer authentication fails. The operator checks those outcomes separately. Tunnel recovery re-establishes the path and repeats an independent identity and request check. [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- ◆ **Change upstream.** The site operator supplies the authorized replacement uplink, captures the current route and addressing baseline, and records the abort condition. Switching can change provider addresses and interrupt sessions. Re-establish ingress, verify the service identity, and publish a higher-revision endpoint binding where needed. Record public reachability and federation recovery separately. Retain the logical service ID and existing grant authority.
- → **Interrupted or failed cutover** · With the sole uplink down, public traffic and remote federation over that link pause. Local services continue where their dependencies and authorization remain locally operable. If the replacement fails, restore the verified previous configuration where available or enter **Degraded** and open an incident. Alternate links have their own acceptance configuration.
- **Conditional public routing** · Where an operator needs to originate prefixes, its routing administrator supplies the ASN, authorized prefixes, upstream or peer arrangements, and import and export policy. The routing system rejects a candidate announcement failing its configured authorization or policy checks. For an authorized change, check external prefix and origin visibility separately from data-plane reachability to ingress. On a regression, withdraw the change or restore the baseline and repeat both checks. [BGP-4, RFC 4271](https://www.rfc-editor.org/rfc/rfc4271.html)
- ▣ **Connectivity receipt** · From an ordinary device and an independent peer, record public and service paths separately for the applicable topology. For tunnel deployments, record tunnel authority, interruption and reconnection, service-side TLS identity, and a completed protected exchange.
- ▣ **Uplink-change receipt** · Record before-and-after addresses, routes, public interruption, federation recovery, endpoint revisions, and preserved service and grant identifiers. Include baseline, abort condition, and observed rollback or degraded state.
- ▣ **Conditional routing receipt** · Record prefix and origin authority, policy decision, independent route visibility, data-plane reachability, rejected change, and verified rollback.

*Source anchors · Commonwealth ISP, “The Proposed Architecture.” Arbiter, uplink and routing conditions. Designer, connectivity paths. Engineer, upstream replacement.*

### Deterministic Capability Execution and Retry

```text
Versioned HTTPS / typed JSON request
  interface_version, operation_id, action, resource, typed_body, authority_evidence

Recorded evaluation envelope
  authenticated_caller, authenticated_workload_or_explicitly_absent
  canonical_request_ref_and_digest, interface_version, evaluator_version, evaluation_time
  policy_revision, trust_and_revocation_state, evidence_versions
  applicable_device_appraisal_ref_or_explicitly_not_required
  appraisal_freshness_context {challenge_ref, appraised_at, applicable_freshness_limit, freshness_decision}
  decision, stable_reason, effect_reference_if_committed

Caller-visible result
  typed result and effect reference
  or stable error and permitted detail
```

1. **Validate and decide.** An authenticated client submits the request through the versioned interface. The service validates the version and body before execution. It evaluates authority using the recorded inputs. An unsupported version returns a compatibility error. Invalid input returns a validation error. Required stale or unavailable authority returns denial. Independent evaluators replay the recorded decision with the same canonical inputs and return the same decision and reason. AI and development tooling are outside the decision path.
2. **Commit and return.** An admitted request proceeds to its declared effect boundary. For queued protected work, enforce the household revocation ordering at commit. For a declared retry-safe local effect, commit the effect and deduplication record atomically under the scoped caller and operation identity. Return the typed result and effect reference. A crash after commit and before response leaves one committed effect and its durable result reference.
3. **Handle retries.** A permitted identical retry inside the declared scope and retention can return the original result after rechecking current authorization. A concurrent identical retry yields one effect. Changed body under the same operation identity returns conflict. A revoked caller receives no protected result. An operation beyond recognized retention returns the published stale-operation outcome or goes to reconciliation. An ambiguous external effect returns `outcome_unknown`. The caller follows reconciliation before retrying.

| Caller action | Expected visible result | Expected effect |
|---|---|---|
| Repeat the identical operation within scope | Original authorized result | One committed local effect |
| Retry after grant withdrawal | Protected denial | No new effect or stored-result disclosure |
| Reuse the operation ID with changed input | Conflict | No second effect |
| Retry outside recognized retention | Declared stale outcome or reconciliation reference | No blind replay |
| Retry an ambiguous external operation | `outcome_unknown` or reconciliation status | No retry until reconciled |

- ▣ **Decision replay receipt** · Retain the full recorded evaluation envelope, including distinct caller and workload identities, interface and evaluator versions, and the applicable device appraisal and freshness context. Compare decisions and reason codes across independent implementations using the same canonical request, authority inputs, and evaluation time. Include unsupported version and stale authority. Use paired fixtures that keep the other inputs fixed and substitute a workload without the required authority or an appraisal that is stale at the recorded evaluation time. Record the resulting decision and reason for each fixture.
- ▣ **Commit and retry receipt** · Trace the effect count independently of responses. Exercise concurrency, crash after commit, changed body, revoked stored-result access, expired retention, revocation before queued commit, and ambiguous external reconciliation. Record the approved transaction scope and retention applicable to the run.

*Source anchors · Commonwealth ISP, MDBO principles in “The Proposed Architecture.” Arbiter, “Execution and retries.” Engineer, capability execution and retry. QC, commit and stored-result coverage. [HTTP semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html).*

### Application Publication and Isolated Execution

#### Publish and install

**Proposed release workflow** · An independent publisher runs the published fixtures and submits a signed manifest and artifact to a registry it runs or one that accepts its publisher key. The manifest identifies publisher, version, artifact digest, interface versions, requested capabilities, and declared network destinations. The registry verifies signature, digest and schema. A mismatch returns the failing check and leaves the version unadmitted. The publisher can correct the package and submit it for a new decision.

The local operator opens the release by publisher, version, and digest and reviews its requested capabilities and egress. Installation approval pins the digest of the main executable artifact and every separately loaded executable component, including libraries or plugins loaded at runtime. The runtime verifies each component against its reviewed digest before loading it. An unreviewed component or digest mismatch blocks that load and reports the failed check. The approved release runs under a dedicated workload identity in its execution domain. Household access requires a separate grant from the household administrator. The review can show **Installed** alongside **Household access pending**.

#### Exercise the execution boundary

```text
Application workload -- identity + calendar:view capability --> controlled gateway
  gateway -- authorized view request --> household calendar
  gateway <-- permitted result -- household calendar

Application workload -- calendar:edit --> gateway --> denied by resource policy
Application workload -- direct storage connection --> network boundary --> blocked
Application workload -- undeclared network destination --> egress boundary --> blocked
Website workload -- management request --> management boundary --> denied
```

Websites, applications, search, experiments, and management run in separately secured domains. Each controlled cross-domain call checks source identity, destination, operation, and current authority. For a name-based egress grant, the enforcement point checks both the approved name and the resolved address actually used for each connection. A newly resolved address can be used if it satisfies the address policy. A prohibited address remains blocked even when returned for an approved name. The enforcement point connects only to the address it checked and repeats the check on reconnect or address change. The operator sees whether a failure occurred at the network, egress, interface, or grant boundary. The participant sees the relevant outcome, such as the proposed message “This app has view access only.”

#### Upgrade, stop, and roll back

The publisher submits a new signed artifact. When it requests broader capabilities or new egress, the operator reviews the differences before enabling them. A household owner separately approves any broader household grant. Before adopting an application-state migration, verify compatibility with the starting state and the declared rollback path.

With proposed **Stop application**, the operator invalidates the workload identity, closes affected sessions, and applies the declared in-flight work contract. Queued protected effects require current authority at commit. Verify which effects were already committed and which work ended without an effect. A proposed rollback selects a verified older artifact independently of any state rollback. Restore or migrate application state only through its approved compatible procedure. Current grants and revocations govern the rolled-back version.

- ▣ **Publisher and installation receipt** · Record signature, digest, manifest version, conformance, pinned executable, runtime identity, and separate installation and household decisions. Exercise a rejected manifest or artifact.
- ▣ **Controlled execution receipt** · Record the permitted view, denied edit, direct storage block, undeclared egress denial, and denied management call at their respective enforcement points. Change an approved name to a permitted address, then to a prohibited address. Record the resolved and actual connection addresses, the enforcement decision, and whether a connection was established. Substitute a separately loaded executable component with a changed digest and record the reviewed and presented digests, the load decision, and evidence that the changed component did not execute.
- ▣ **Upgrade and stop receipts** · Record capability and egress differences, approvals, state migration checks, artifact rollback, state compatibility, runtime identity invalidation, session closure, and resulting in-flight effects. Verify no prior grant returns with the artifact.

*Source anchors · Commonwealth ISP, “The Proposed Architecture” and “Security: Protecting the Household.” Designer, independent application publishing. Engineer, execution-domain crossing. QC and Clean, upgrade and stop coverage.*

### Signed Records, Checkpoints, and Shared State

1. **Issue.** An operator signs a record under its own authority. For a service decision, include the claim, issuing scope, sequence, configuration, and a reference to the result or resulting-state observation. A reviewer can trace a signed “access denied” claim to the response and disclosure evidence at the service boundary.
2. **Witness.** An independent witness retains a checkpoint identifying the operator’s history and covered sequence. A later reviewer obtains the relevant record, authority chain, checkpoint, and inclusion or consistency evidence under the chosen record format.
3. **Review.** Verify authority, signature, and consistency against the retained checkpoint, then inspect the observation behind the claim. Altered content fails integrity. Omission relative to a retained checkpoint yields an inconsistency or coverage gap. When required witness evidence is unavailable, the witnessed claim remains **UNVERIFIED**. An authorized correction references and supersedes the original record.
4. **Keep household authority local.** Household grants and contents remain with the controlling household. Export a permitted reference or limited evidence under its disclosure rules. An audit or publication record supplies no additional household grant.

```text
Operator -- signed sequenced record + outcome reference --> reviewer
Operator -- checkpoint of covered history --> independent witness
Witness -- retained checkpoint and verification evidence --> reviewer
Reviewer -- outcome reference --> authorized underlying observation
```

- **Conditional shared state** · Consider consensus only when operators identify a named shared record with conflicting authorized writes that require common ordering. Before choosing a mechanism, identify writers, validators, quorum, finality, partition behavior, recovery, and correction. A candidate then needs its own worked case for competing writes, unavailability, finality, and reconciliation. Household grants and contents stay under household authority.
- ▣ **Record and witness receipt** · Record signer authority, sequence, signature decision, witness identity, checkpoint coverage, inclusion or consistency result, outcome evidence, and any superseding record. Exercise alteration, omission, and unavailable witness evidence. Score record integrity and the underlying claim separately.

*Source anchors · Commonwealth ISP, “The Proposed Architecture” and “Toward a Quantum Internet.” Arbiter, distributed trust and conditional consensus. Engineer, ledger scope. [Transparency log reference, RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html).*

### Support, Incidents, and Operational Changes

**Proposed support interaction**

A participant supplies the site access reference, device type, and symptom. A household user supplies the grant or request reference to the household administrator. A federation peer supplies the service and request references to its operator. The receiving operator opens the incident and identifies the responsible access operator, household administrator, service steward, or upstream provider.

The proposed incident view distinguishes **Reported symptom**, **Recorded decision**, and **Live probe**. A report retains the reporter’s vantage. A decision replay evaluates recorded inputs and produces the decision and reason without executing the operation. A safe diagnostic runs an approved probe with an identified target and observation point. If the requester lacks access to a protected record, return a limited status and direct them to the controlling authority.

```text
reported -> assigned -> triaged -> contained -> diagnosed -> recovered -> reviewed

change request
  baseline + affected scope + planned action + abort condition
  -> apply -> verify from affected participant or peer path
     -> accept resulting configuration
     -> or abort -> restore baseline -> verify again
        -> verification fails -> escalate incident
```

- ◆ **Work the fault** · The operator identifies the latest completed boundary and isolates the affected credential, peer, service, or uplink as appropriate. Record the containment action and verify that unrelated paths still operate. Notify affected participants with the observed scope and support reference. Escalate upstream faults to the provider. Household authorities control disclosure of protected data.
- → **Example** · A peer reports that a service stopped after an uplink change. The receiving operator checks public forwarding from the site and the service from the peer path, then compares discovery and TLS outcomes. Public traffic can recover while the peer still has an expired binding. Repair the failing boundary and confirm the authorized service exchange from the affected peer before closing that incident.
- ◆ **Operational change** · Before modifying a route, ingress, resolver, or service configuration, record the baseline, approval, expected outcome, abort condition, and rollback procedure. A successful local check does not close a change that affects a remote participant. Verify the resulting configuration and the affected path. Failed rollback enters incident escalation and stays open until recovery is verified.
- ▣ **Incident receipt** · Record the case owner, authority, timestamps, reported symptom, diagnostic or decision-replay inputs, vantage, containment, communication, escalation, and recovery observation. Exercise provisioning, DNS, uplink, credential, and service faults.
- ▣ **Change receipt** · Record configuration baseline, action, resulting configuration, abort decision, rollback result, and participant or peer verification. Exercise rollback failure and record the escalation and remaining degraded state.

*Source anchors · Designer, routine help and operations. Engineer, incident and upstream changes. QC and Clean, decision replay, diagnostics, and rollback verification.*

### Routine Restore and Authority Recovery

#### Restore one protected service

A and B administer separate cloud nodes. A serves one protected resource with a known record, an allowed request from B, and a revoked credential. B verifies the baseline exchange and starts probing its own independent workload. A’s designated recovery authority records the host loss and authorizes a named steward to restore the service once onto a clean replacement.

```text
BASELINE
  B -- authorized request --> A's original service -- known record --> B
  B records trust/policy and starts probes of B's independent workload.

HOST LOSS AND FENCING
  Record A host-loss time; B continues independent-workload probes.
  A recovery authority -- authorization --> A steward
  Ingress authority -- deny old serving path --> original host
  Shared-write authority -- deny old writer --> each applicable write boundary

ONE CLEAN-HOST RESTORE
  Steward verifies backup provenance, integrity, and recoverable data.
  Steward restores verified state once onto a clean replacement.
  Credential authority issues fresh serving credentials.
  Authorization authority confirms current grants and revocations.
  Publication authority signs a higher-revision binding for the same service ID.
  Verified fences and current authorities --> admit replacement
  Missing fence or uncertain authority --> keep protected service closed

PEER REJOIN
  B fetches and verifies replacement binding and rejoin authority.
  B -- request through approved binding under existing trust and policy --> A
  A -- authorized response containing expected restored record --> B
  Record B's first authorized retrieval and continue continuity observations.
```

If the old host returns, it cannot serve through ingress or write through a shared boundary. The steward checks those effects independently. An unavailable fence keeps the replacement closed. A failed backup integrity check leaves its target unrestored. If any required current authority is unavailable, reconcile that authority before reopening.

#### Recover each authority separately

| Store | Authorized actor and action | Reopen or remain closed |
|---|---|---|
| **Authorization** | Its designated recovery principal restores from a trusted checkpoint and reconciles later grants and revocations. | Reopen dependent protected actions only when current authority is established. A revocation newer than the backup still denies access. |
| **Publication** | Its designated principal recovers the signed publication authority and accepted monotonic state, including epochs, binding revisions, renewals, and withdrawals. | Publish only once rollback protection and current delegation are verified. An older publication checkpoint cannot re-enable a withdrawn binding or epoch. |
| **Credentials** | Its designated principal reconciles withdrawals and current issuance authority, rotating compromised credentials where required. | Issue fresh serving authority only from verified current state. With uncertain authority, dependent protected service stays closed. |

The approved procedure for each store identifies the recovery principal, trusted checkpoints, reconciliation material, fencing, and reopening conditions. An application steward acts only within the application restore authority.

#### Score restore, continuity, and rejections

- ◆ **Recovery time** · Measure from host loss to B’s first authorized retrieval of the expected record through the approved replacement binding. The endpoint becoming reachable is a separate observation.
- ◆ **Restored-data age** · Subtract the newest verified restored-data timestamp from host-loss time. Use synchronized timestamp provenance or a documented clock-offset bound. Negative restored-data age yields **UNVERIFIED** for that measure.
- ◆ **Independent operation** · Keep B’s own workload under probe throughout. Compare its results to the approved continuity limit. Verify unchanged B trust and policy using before-and-after snapshots and intervening change evidence. Score zero privileged founder interventions only with named audit sources, covered principals, and a complete observation window.
- ▣ **Restore receipt** · Require exactly one authorized restore, expected restored data, approved binding and rejoin, recovery time and restored-data age within limits, and current authority before reopening.

```text
Restore receipt additions
  independently_administered_A_and_B, baseline_exchange, known_record
  host_loss_at, authorizer, steward, authority_ref, authorized_restore_count
  original_host, clean_replacement_host, backup_provenance, integrity_result
  old_ingress_fence, applicable_shared_write_fences, returning_host_observation
  fresh_serving_credential, current_authority_checks, higher_revision_binding
  B_binding_and_rejoin_decisions, first_authorized_retrieval_at, restored_record
  newest_verified_restored_data_at, timestamp_basis, recovery_time, restored_data_age
  B_workload_probe_cadence, results, detection_limits
  B_trust_policy_before_and_after, intervening_change_evidence
  audit_sources, covered_principals, window, privileged_founder_intervention_count
```

- ▣ **Authority and fence receipts** · Run each store recovery separately. Include checkpoints older than a revocation, publication revision, or credential withdrawal as applicable. Record checkpoint authority, reconciliation result, rollback rejection, and reopening decision. Exercise an unavailable fence and a returning old host. Observe both ingress and shared-write state.
- ▣ **Revoked credential receipt** · After authorized restore, present the revoked credential. Observe A’s current decision and actual response. → Denied. No protected data is disclosed.
- ▣ **Tampered backup receipt** · Present a tampered backup in a separate case. Observe the integrity decision and inspect the target. → Rejected. The test target remains unrestored.
- ▣ **Unauthorized rejoin receipt** · Present a replacement endpoint without valid rejoin authority. Observe B’s authority and binding decisions, accepted endpoint, trust, and policy. → Rejected. B retains its accepted binding and unchanged trust and policy.
- ◆ **Rejection gate** · Require an independently supported verdict for each case and zero unauthorized successes. Keep all three cases separate from the authorized restore count.

*Source anchors · Commonwealth ISP, “Development and Verification.” Arbiter, “Routine recovery.” Engineer, restore and authority-store recovery. QC and Clean, recovery failure boundaries.*

### Sustainable Site Funding

1. **Fund the scope.** The funding owner and site operator review equipment, installation, connectivity, power, capacity, staffing, maintenance, spares, support, escalation, and continuity obligations. The agreement names who pays and who performs each duty. It fixes participant access at $0 and states the contingency for incomplete or withdrawn funding.
2. **Approve operation.** The funding owner commits coverage and the site operator accepts the operating duties. Under the **Proposed** operating view, **Funding incomplete** identifies uncovered categories and leaves the site ineligible for funded operation or field acceptance. A signed funding commitment conveys no gateway, household, or federation authority.
3. **Transfer sponsorship.** When the sponsor withdraws, the operator invokes the agreement’s continuity process. An incoming funding owner signs coverage for the defined scope. The operator verifies continuity and issues the agreed participant notice. If technical duties also transfer, the controlling operator approves that transfer separately and verifies authority and access changes.
4. **Close in order.** If funded coverage cannot continue, the operator follows the agreed closure process. Notify participants, provide authorized export of operator-owned configuration where applicable, deprovision site access, and handle retained records according to the governing dispositions and household authority. Participant charges cannot replace missing coverage.

```text
proposed -> coverage committed -> duties accepted -> provisioned -> operated
  uncovered obligation -> funding incomplete
  coverage interruption -> funded continuation or signed sponsor transfer
                        -> or notified orderly closure
```

- ▣ **Funding receipt** · Record signed coverage, funds and duties by category, responsible parties, covered capacity and interval, continuity obligations, and $0 participant terms.
- ▣ **Transfer and closure receipts** · Exercise incomplete coverage and sponsor withdrawal. Record funding and operator approvals, notices, authority changes, authorized configuration export, access deprovisioning, and retained-data disposition.
- ◆ **Project release terms** · Apache-2.0 for project software and DCO sign-off for contributions are conditional defaults. Rights-holder approval and dependency compatibility review control finalization. A maintainer verifies source revision, compatibility and integrity checks, and dependency information before signing a release manifest and providing migration or rollback instructions.

*Source anchors · Commonwealth ISP, “Free and Open-Source.” Arbiter, “Openness and funding.” Engineer, site sustainability and release workflows.*

### Clients and Institutional Engagement

- ◆ **Independent client interaction** · A client developer uses the published discovery and service interfaces. The operator approves the discovery configuration. The client looks up a logical service ID, validates the signed binding, checks the service’s TLS identity, selects a supported version, and sends a typed request. A supported, permitted action returns its typed result. An unsupported version returns a compatibility error. A denied request returns a stable reason and no protected result. When the client exercises B’s independently implemented capability, link the client’s observed result to the independent extension receipt so the exchange can be verified from both sides.
- **Quantum** · LIFE Technology’s optional browser and discovery client can implement the same interfaces. The independent-client gate uses a compatible client under separate development and administration.
- **WRECK** · Intended early user for provenance and consent applications. The publisher submits its application and an authorized operator and resource owner approve their respective installation and capability decisions under the ordinary workflow.
- **Exploratory Commonwealth of Nations engagement** · Authorized representatives may propose professional or research collaboration. A proposal identifies the parties, scope, contributions, funding, data terms, intellectual property, and operating duties. Each named party reviews and approves through its authorized process. A rejected or unsigned proposal remains exploratory. An executed agreement supports only the commitments in its signed scope. Any site, service, household, or lab authority follows a separate grant from its controlling party.
- ▣ **Client receipt** · Record client provenance and version, independently implemented interface, discovery and TLS outcomes, permitted typed result, unsupported version, and destination denial.
- ▣ **Institutional scope receipt** · Where an agreement exists, record named parties, approving authority, signed scope, commitments, and any independently granted technical authority. Use the agreement to substantiate any claimed relationship.

*Source anchors · Commonwealth ISP, “Quantum: Discovery and Access” and “The Commonwealth of Nations Relationship.” Arbiter, optional clients and exploratory engagement. Engineer, institutional approvals.*

### Classical Internet Pilot

- ◆ **Field fixture** · One authorized site with an identified site operator and funding owner, authorized uplink, funded capacity and support, and equipment that supports site credential withdrawal independently of AP eviction. Record permission for the field exercise and the equipment and configuration in scope.
- → **Run the participant flow** · Issue a test credential through **Participant Access**, join using an ordinary participant device, and exclude alternate connectivity. Observe association, IPv4 provisioning, recursive DNS, and HTTPS to independent public destinations in that order. Confirm $0 participant access from the site terms and the participant interaction. Measure join time and the approved load profile.
- → **Work the failures** · Exercise invalid credentials, DHCP exhaustion or failure, fresh DNS failure and cache expiry, sole-uplink loss, and recovery. Verify the intended local attachment and isolation behavior during loss. Withdraw a credential with active traffic and AP eviction held back. Score future admission, forwarded traffic, and eviction separately. Observe another participant throughout withdrawal.
- ◆ **Verdict scope** · The pilot gate applies to the site, public access path, and local controls actually exercised. Independent federation, full-product deployment and recovery, and both quantum gates use their own evidence.

```text
Field receipt additions
  site_and_run_authority, operator, funding_owner, funded_obligations
  authorized_uplink, supported_equipment, guest_configuration
  device_and_access_ref, alternate_paths_excluded, participant_price_evidence
  AP_attachment, DHCP_lease, DNS_result, HTTPS_destinations_and_results
  join_measurement, load_profile_and_results, isolation_receipts
  future_admission_receipt, existing_forwarding_receipt, eviction_observation
  provisioning_failure, DNS_failure, uplink_loss, participant_path_recovery
  observation_vantage_by_result
```

*Source anchors · Commonwealth ISP, “Development and Verification.” Arbiter, “Classical field acceptance.” QC and Clean, classical field controls.*

### Simulated Quantum Workflow

**Proposed experiment interaction**

1. **Set up.** An authorized experiment operator selects the simulator and version, the modeled endpoints and channel, initial state, scheduler and event ordering, randomness implementation and seed where applicable, and the invariants to verify. The setup view identifies the backend as **Simulation** and displays the selected configuration and limits. Unsupported inputs fail setup with a typed reason and allocate no run resources.
2. **Run.** The operator submits the reservation and starts the model. It records reservation, attempt, modeled herald, modeled delivery, failure, or timeout under the selected event ordering. Define modeled herald and delivery as distinct expected transitions. The operator can cancel the run. Cancellation, expiry, and modeled coordination loss reach a terminal state and release the modeled allocations.
3. **Inspect and export.** The operator opens the trace and sees modeled timestamps, modeled measurements, resulting state, and invariant decisions. The export carries those labels and the model and software identities. An incomplete trace or violated invariant produces a receipt with the observed stopping state or violation.
4. **Replay.** An independent evaluator imports the record, uses the same configuration, and repeats the run under the approved reproduction rule. Compare event traces for deterministic fixtures or declared aggregate observations within the approved tolerance for statistical runs.

```text
model + scheduler + inputs + randomness record
  -> validate -> reserve modeled resources -> execute modeled attempts
  -> modeled herald and delivery | failure | timeout
  -> terminal state -> release -> export labeled trace -> independent replay
```

- ▣ **Simulation run receipt** · Record model and software versions, scheduler, event ordering, initial state, inputs, randomness implementation and seed, trace, modeled measurements and timestamps, terminal state, and cleanup outcome. Exercise invalid configuration, expiry, cancellation, and modeled coordination loss.
- ▣ **Replay receipt** · Record independent evaluator, artifact and configuration references, comparison rule, observed differences, invariant result, and retained simulation labels. Scope the verdict to the model and fixtures recorded.

*Source anchors · Commonwealth ISP, “Toward a Quantum Internet” and “Development and Verification.” Arbiter, simulated quantum proof. QC and Clean, replay and export.*

### Physical Quantum Workflow

#### Reserve and attempt

◆ **Adopted local lease enforcement** · Each laboratory independently checks local authority and resource availability, grants or denies its own expiring lease, and enforces expiry locally. Coordinated attempts require two valid acceptances for the same reservation generation. Each endpoint checks its own current lease and the accepted generation before every attempt.

**Proposed laboratory interaction and message format** · The experiment caller submits an authenticated request naming the two independent laboratories, apparatus, claimed observable, trial plan, requested interval, and measurement protocol. The proposed coordinator view presents **Waiting for laboratory acceptance**, **Ready**, or the relevant denial or expiry. Wire fields, encoding, and authentication details for lease messages remain proposed.

```text
CLASSICAL
  Caller -- authorized reservation request --> coordinator
  Coordinator -- reservation ID, generation, proposal --> labs A and B
  Each lab -- signed or authenticated local acceptance + expiry --> coordinator
  Coordinator -- both current acceptances + trial ID --> endpoints A and B
  Endpoints -- readiness, attempt, herald, delivery, failure records --> evidence store

PHYSICAL
  Endpoint A <------ declared quantum channel and heralding apparatus ------> Endpoint B

TERMINAL
  cancellation | expiry | apparatus fault | coordination loss
    -> each laboratory independently stops attempts under its local lease rules
    -> each laboratory reconciles the reservation generation and outcomes
    -> observe A: verified release | verified reconciliation with no outstanding allocation
                 | unresolved allocation or missing terminal evidence
    -> observe B: verified release | verified reconciliation with no outstanding allocation
                 | unresolved allocation or missing terminal evidence
    -> cleanup can pass only when A and B each have a verified terminal outcome

PUBLIC INTERNET
  Device -- ordinary IP traffic --> site gateway --> authorized upstream
```

A laboratory that declines leaves the reservation ineligible to start. An expired lease or delayed instruction from an earlier generation cannot authorize a new attempt. An apparatus fault ends affected attempts and records the failure. During coordination loss, each laboratory stops under its local rules and releases expired allocations independently. After communication returns, reconcile outstanding reservation and trial state before reuse. Verify ordinary access from its public path during the interruption.

- ▣ **Lab A and Lab B terminal receipts** · Score each lab separately at its local resource authority. Record reservation generation, terminal trigger, last attempt, release or reconciliation decision, and direct evidence of remaining allocation state. **PASS** requires verified release or verified reconciliation with no outstanding allocation. **FAIL** records an observed violation of the approved terminal criterion, including an allocation confirmed outstanding beyond the required terminal point. **UNVERIFIED** applies when terminal evidence or the approved criterion is missing. The combined cleanup gate passes only when both lab receipts pass.

#### Correlate and score

- ▣ **Herald detection** · For a declared trial, use the preregistered event, timing window, and correlation method to decide whether a valid herald occurred. Record misses, false or late heralds, and timeouts.
- ▣ **Delivery eligibility** · From the heralded trials, determine which satisfy the preregistered delivery and usability rules. A valid herald and usable delivery have separate decisions and observation points.
- ▣ **Measured entanglement** · Named independent laboratories approve the specific physical claim, apparatus, calibration, trial selection, estimator, confidence level, uncertainty method, and reproduction tolerances before collecting acceptance data. Retain calibrated raw endpoint observations and the method that correlates them. The analysis and measurements support the physical verdict.
- **Proposed Bell-state criterion** · For the declared two-qubit Bell target and analysis, consider a lower confidence bound on fidelity strictly above \(0.5\). The target has two equal Schmidt coefficients of \(1/\sqrt{2}\), so maximum squared overlap with a product state is \(1/2\). Fidelity to that pure target is linear in the measured state, so mixtures of product states obey the same bound. The applicable laboratories must approve the target, estimator, and criterion. [Two-endpoint measurement precedent, Knaut et al., Fig. 4c–d](https://arxiv.org/html/2310.01316#S4.F4)
- ▣ **Usable-pair rate** · Count heralded pairs that meet the declared delivery and usability rules. Divide by the full elapsed observation window, including elapsed time for failures, retries, and timeouts within it. Record both boundaries, duration, count, and any approved acceptance limit.
- ▣ **Independent reproduction** · A second lab uses the approved procedure and declared tolerances to reproduce the result. Record the method, apparatus and calibration, recomputation from retained evidence, and separate reproduction observations. Signed telemetry establishes provenance and integrity of the records within its coverage.

```text
Physical receipt additions
  labs_and_authorities, apparatus_ids, calibration, channel_and_clock_basis
  reservation_id, generation, both_local_acceptances, local_lease_expiries
  trial_ids, eligibility_rules, attempt_and_failure_records, late_message_decisions
  herald_rule_and_observations, delivery_rule_and_observations
  correlated_raw_endpoint_records, declared_claim, analysis_and_estimator
  confidence_level, uncertainty, criterion_ref, entanglement_result
  usable_pair_count, observation_start_and_end, elapsed_duration, rate
  cancellation_expiry_fault_and_coordination_loss_results
  lab_A_terminal_evidence_and_verdict, lab_B_terminal_evidence_and_verdict
  combined_cleanup_verdict, public_access_control_observation
  herald_detection_verdict, delivery_eligibility_verdict, measured_entanglement_verdict
  independent_reproduction_protocol_and_result, independent_reproduction_verdict
```

*Source anchors · Commonwealth ISP, “Toward a Quantum Internet” and “Development and Verification.” Arbiter, physical quantum proof. QC and Clean, separate herald, delivery, and physical gates. [Quantum Internet architectural principles, RFC 9340](https://www.rfc-editor.org/rfc/rfc9340.html).*

## Future Plans

- ◆ **IPv6** · Admit IPv6 after equivalent isolation and withdrawal checks pass.
- **Conditional consensus** · Evaluate shared consensus only for a named record that needs common ordering of conflicting authorized writes.
- **Institutional cooperation** · Explore professional and research relationships with Commonwealth institutions.
- **Software and lab interoperability** · Extend compatible clients and lab adapters through published interfaces and independent conformance. Physical qualification stays with each participating lab.
