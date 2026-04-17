# AgentSecrets Zero-Trust Remaining Loop Spec Pack

> Detailed roadmap specs for every loop that did not already have a high-detail execution doc. This document is spec-only. It does not authorize skipping TDD or implementation planning when a loop starts.

## Scope Of This Spec Pack

This pack covers:

- V2 Loop 3: Execution Adapter Containment
- V2 Loop 4: Capability and Approval Hardening
- V2 Loop 5: MEMD-Style Node-to-Node E2E Harness
- V2 Loop 6: V2 Ship Gate
- V3 Loop 0: Trusted Input Surface
- V3 Loop 1: Transcript and Log Redaction Pipeline
- V3 Loop 2: Real Trusted Execution Adapters
- V3 Loop 3: Multi-Host Support Matrix
- V3 Loop 4: V3 Ship Gate
- V4 Loop 0: Policy Engine Maturity
- V4 Loop 1: Attestation and Runtime Identity
- V4 Loop 2: Tamper-Evident Operations and Forensics
- V4 Loop 3: Rotation and Recovery Drills
- V4 Loop 4: Adversarial Continuous Verification
- V4 Loop 5: Platform Ship Gate

This pack exists because the roadmap names the loops, but later execution still needs tighter contracts:

- what exactly changes in-repo
- what remains external or cross-repo
- what security claim each loop earns
- what verification must pass before the loop can be called complete

## Global Rules

These rules apply to every loop in this pack:

- Docs truth beats aspiration. If code and docs diverge, reduce the claim.
- Untrusted surfaces stay untrusted unless a loop explicitly upgrades one with enforcement and tests.
- Plaintext secret material must never become acceptable in broker API responses, transcript collectors, or untrusted logs.
- Every loop must define both the happy path and the fail-closed path.
- Every loop must name the specific evidence required to claim completion.
- If a loop depends on external host or sibling-repo work, the in-repo side must state that boundary explicitly instead of implying completeness.

## Track Mapping

Loop ownership follows the roadmap track split:

- In-repo work:
  - broker interfaces
  - policy and approval behavior
  - audit behavior
  - local harnesses
  - docs, support matrices, ship gates
- External work:
  - trusted host input surfaces
  - transcript filtering inside supported host UIs
  - host-side log sink enforcement
  - real host execution containment
- Cross-repo contract work:
  - opaque-ref contracts
  - supported-host certification
  - approval payload contracts
  - transcript-safe event formats

---

## V2 Loop 3: Execution Adapter Containment

### Objective

Move the system from "provider preflight plus masked broker result" to one real trusted-side secret-consumption boundary. The first V2 adapter must prove that a sanctioned secret-use action can complete without plaintext ever leaving the trusted adapter boundary.

### Why This Loop Exists

Loop 2 proved secret resolution can happen behind a provider boundary. It did not yet prove that resolved secret material can be consumed safely. Without Loop 3, the system still risks collapsing into "host asks for reveal" semantics.

### Security Claim Earned

After Loop 3, AgentSecrets may claim that at least one supported secret-use act can execute through a trusted adapter path without exposing plaintext to untrusted clients.

### Exact In-Scope Work

- Add an execution adapter interface in-repo.
- Add one sanctioned adapter path only.
- Bind adapter dispatch to request action and target context.
- Keep all adapter outputs masked.
- Audit adapter success and failure paths.
- Describe containment boundaries in docs.

### Explicit Non-Goals

- Real browser automation.
- Multiple adapters.
- Host transcript safety.
- Generic plugin adapters.
- Anything that returns raw secret material to the host.

### Required Contracts

- `provider::ResolvedSecret` may be consumed only by trusted adapter code.
- `/v1/execute` must dispatch by action to an adapter runtime, not by ad hoc inline logic.
- Unsupported actions must fail closed.
- Target drift between approval and execution must fail closed.
- Adapter results must be masked and context-bound.
- Adapter errors must never reveal plaintext or provider internals beyond allowed masked codes.

### Expected Repo Surfaces

- New adapter module, likely `src/adapter.rs`
- `Config` and `AppState` runtime wiring
- `/v1/execute` dispatch changes
- `/healthz` adapter status
- test harness helpers in `src/lib.rs`
- docs in README, architecture, and security guarantees

### Verification Gate

- adapter unit tests
- execute-path integration tests
- misuse tests for unsupported action and target drift
- redaction assertions that the response never contains secret bytes
- full `cargo test`, `cargo fmt --check`, `cargo clippy -D warnings`

### Exit Criteria

- one sanctioned action succeeds through the adapter boundary
- the response stays masked
- misuse attempts fail closed
- docs truth says "one stub trusted adapter path exists" and nothing stronger

---

## V2 Loop 4: Capability And Approval Hardening

### Objective

Make approval and capability semantics authorize one bounded act, not a reusable or weakly-bound token that can drift across action, target, or stale context.

### Why This Loop Exists

Replay prevention exists, but the approval contract is still too loose. The system needs stronger guarantees that the human approved the same action and target that later executes.

### Security Claim Earned

After Loop 4, AgentSecrets may claim that approved execution is tightly bound to request context, action, and target, with stricter fail-closed behavior for drift, expiry, and misuse.

### Exact In-Scope Work

- Strengthen capability binding to request id, action, and target.
- Tighten expiry behavior.
- Harden denial and invalidation semantics.
- Tighten approval payload truthfulness.
- Extend misuse and actor-role test coverage.

### Explicit Non-Goals

- hardware attestation
- cross-device approval redesign
- secure human UI beyond masked payload truth

### Required Contracts

- action mismatch must fail closed
- target mismatch must fail closed
- expired capability must fail closed and mark request state accurately
- denied requests must not retain usable capability state
- approval payload must remain masked but informative enough for human review

### Expected Repo Surfaces

- request persistence schema or stored capability context
- approval and execute handlers
- audit event vocabulary
- release and integration docs

### Verification Gate

- replay tests
- action mismatch tests
- target mismatch tests
- expiry tests
- actor-role and denial-path tests

### Exit Criteria

- capability cannot be replayed
- capability cannot execute a different act than the one approved
- approval payload is truthful without exposing secret data

---

## V2 Loop 5: MEMD-Style Node-to-Node E2E Harness

### Objective

Prove V2 claims across real local process boundaries. The system should no longer rely only on in-process Rust tests to defend a zero-trust claim.

### Why This Loop Exists

Many leakage failures only appear when separate nodes run with separate logs, transcripts, and HTTP boundaries. V2 cannot make strong claims without this evidence.

### Security Claim Earned

After Loop 5, AgentSecrets may claim that its V2 guarantees are supported by real local node-to-node evidence, not only unit and integration tests.

### Exact In-Scope Work

- local multi-process harness
- broker node
- approver node
- untrusted client node
- provider simulation node or trusted-side equivalent
- transcript and untrusted-log collectors
- redact-safe failure artifact capture

### Explicit Non-Goals

- internet-scale testing
- production chaos
- unsupported host certification

### Required Contracts

- transcripts collected from untrusted nodes must stay secret-free
- broker API responses must stay secret-free
- untrusted logs must stay secret-free
- misuse cases must fail closed with auditable evidence
- fixture secrets must be deterministic enough to assert non-leakage

### Expected Repo Surfaces

- `tests/e2e/` or harness scripts
- CI workflow additions
- artifact handling scripts
- release docs and local run instructions

### Verification Gate

- deterministic PR-safe E2E suite
- optional heavier scheduled E2E lane
- safe artifacts on failure
- explicit CI requirement before V2 release

### Exit Criteria

- local harness is green and stable enough to trust
- the primary V2 invariants are enforced end to end
- release docs treat missing harness evidence as a release blocker

---

## V2 Loop 6: V2 Ship Gate

### Objective

Define the exact bar for calling V2 real. V2 release must be a claim-backed state, not a branch feeling.

### Why This Loop Exists

Security work drifts unless release criteria are explicit. Ship gates keep the truth line stable.

### Security Claim Earned

This loop earns no new security primitive. It earns release honesty.

### Exact In-Scope Work

- V2 checklist
- support statement
- deployment topology guidance
- release-note claims table
- CI summary gate
- manual signoff requirement

### Explicit Non-Goals

- new runtime features
- V3 host guarantees

### Required Contracts

- every V2 claim must map to code and evidence
- every cut feature must be removed from the claim set
- ship docs must distinguish GA from preview if evidence is weak

### Verification Gate

- release checklist dry run
- CI summary gate
- manual review of claims matrix

### Exit Criteria

- docs truth matches implementation
- node-to-node evidence exists
- V2 release language is precise about guarantees and non-guarantees

---

## V3 Loop 0: Trusted Input Surface

### Objective

Introduce a supported way to originate secret use without ever typing plaintext into agent-visible chat or task memory.

### Why This Loop Exists

Transcript safety starts at ingress. Post-hoc redaction is not enough if the host flow begins by putting plaintext into an untrusted field.

### Security Claim Earned

After Loop 0, supported hosts may claim a trusted input path that issues opaque refs without requiring plaintext entry into the agent transcript.

### Exact In-Scope Work

- secure input flow design
- trusted input session contract
- opaque-ref issuance path
- migration guidance away from raw text entry
- broker support needed for trusted input sessions

### Explicit Non-Goals

- universal UX polish
- unsupported host paths

### Required Contracts

- trusted input completion returns opaque refs only
- input sessions are bounded and one-time
- unsupported raw text entry remains explicitly out of contract

### Verification Gate

- transcript-capture E2E
- trusted input session tests
- docs review for supported-host accuracy

### Exit Criteria

- supported flow avoids transcript plaintext ingress
- migration path is documented

---

## V3 Loop 1: Transcript And Log Redaction Pipeline

### Objective

Add enforced redaction for agent-visible transcript surfaces and untrusted logs in supported hosts.

### Why This Loop Exists

Even with trusted input, accidental echoes, stack traces, and host logging can still leak secrets.

### Security Claim Earned

After Loop 1, supported host transcripts and untrusted logs may claim tested redaction coverage against seeded secret echoes.

### Exact In-Scope Work

- transcript filtering hooks
- host-side log sink classification
- redaction policy
- seeded canary fixtures
- regression tests for echo and error paths

### Explicit Non-Goals

- unsupported hosts
- blanket redaction claims across all runtimes

### Required Contracts

- canary secret values must not survive into transcript snapshots
- untrusted log sinks must stay secret-free
- redaction failure on supported flows must fail closed or suppress output

### Verification Gate

- seeded canary tests
- adversarial echo tests
- transcript snapshot checks
- untrusted log assertions

### Exit Criteria

- supported host transcript and log paths remain secret-free under tested scenarios

---

## V3 Loop 2: Real Trusted Execution Adapters

### Objective

Expand from one V2 trusted adapter path to multiple sanctioned secret-use actions that keep plaintext inside trusted boundaries.

### Why This Loop Exists

Real systems need more than one secret-use act. V3 must support several high-value actions without dropping back to reveal semantics.

### Security Claim Earned

After Loop 2, supported hosts may claim multiple trusted execution paths, each with explicit no-reveal invariants.

### Exact In-Scope Work

- adapter registry expansion
- browser fill path for supported hosts
- request signing path
- contained outbound send or handoff path
- per-adapter health and support state

### Explicit Non-Goals

- unrestricted adapter plugins
- adapters that reveal plaintext to untrusted callers

### Required Contracts

- every adapter has an explicit boundary
- every adapter has per-adapter misuse tests
- unsupported hosts or adapters fail closed

### Verification Gate

- adapter integration tests
- no-reveal invariant tests
- supported-host E2E for each shipped adapter

### Exit Criteria

- multiple sanctioned secret-use actions are supported
- every shipped adapter has boundary docs and evidence

---

## V3 Loop 3: Multi-Host Support Matrix

### Objective

State exactly which host apps are supported for end-to-end zero-trust claims and prove each one separately.

### Why This Loop Exists

"Works with agents" is too vague. The system needs a certification line per host.

### Security Claim Earned

After Loop 3, end-to-end claims are narrowed to hosts in the supported matrix and backed by host-specific evidence.

### Exact In-Scope Work

- supported-host matrix
- per-host threat notes
- host-specific E2E suites
- certification and regression policy

### Explicit Non-Goals

- universal support claims
- soft "probably works" listings

### Required Contracts

- a host is not supported unless it has its own E2E evidence
- per-host docs must state trust boundaries and known limitations
- preview and unsupported states must be explicit

### Verification Gate

- host-specific E2E green
- support matrix review against current evidence

### Exit Criteria

- every supported host has evidence and documented limits

---

## V3 Loop 4: V3 Ship Gate

### Objective

Release V3 only when supported-host end-to-end claims are green and current.

### Why This Loop Exists

Once support becomes host-specific, release honesty depends on that matrix staying current.

### Security Claim Earned

This loop earns no new primitive. It earns host-specific release discipline.

### Exact In-Scope Work

- V3 checklist
- supported-host claim table
- release-note truth
- matrix signoff

### Verification Gate

- supported-host E2E suites
- release checklist dry run
- manual signoff on the support matrix

### Exit Criteria

- V3 release notes only claim what supported hosts actually prove

---

## V4 Loop 0: Policy Engine Maturity

### Objective

Move from simple policy checks to richer policy evaluation over action, target, actor, environment, and risk.

### Why This Loop Exists

As the platform expands, fixed checks become too weak to express safe behavior.

### Security Claim Earned

After Loop 0, AgentSecrets may claim richer, explainable, fail-closed policy evaluation rather than simple static checks.

### Exact In-Scope Work

- richer policy model
- policy explanation surfaces
- migration path from simple rules
- stronger policy tests

### Verification Gate

- policy unit tests
- integration tests across policy dimensions

### Exit Criteria

- policy can express richer decisions without becoming opaque or permissive by accident

---

## V4 Loop 1: Attestation And Runtime Identity

### Objective

Strengthen confidence in which runtime, adapter, and host is actually making a request.

### Why This Loop Exists

Without verifiable identity, policy and support claims remain easy to spoof.

### Security Claim Earned

After Loop 1, supported paths may claim verified runtime, adapter, and host identity signals.

### Exact In-Scope Work

- identity claim model
- request-time verification
- policy binding to identity
- identity misuse tests

### Verification Gate

- spoofing tests
- stale identity tests
- integration tests showing verified identity enters policy and audit context

### Exit Criteria

- unverifiable paths cannot claim the stronger trust tier

---

## V4 Loop 2: Tamper-Evident Operations And Forensics

### Objective

Improve chain-of-custody, audit integrity, and incident investigation.

### Why This Loop Exists

A platform needs strong post-incident evidence, not only prevention.

### Security Claim Earned

After Loop 2, the platform may claim stronger audit integrity and safer investigation workflows.

### Exact In-Scope Work

- audit integrity improvements
- forensic export bundles
- operator investigation workflow
- evidence verification tooling

### Verification Gate

- audit integrity tests
- forensic export verification
- runbook dry run

### Exit Criteria

- operators can create redact-safe, tamper-evident investigation bundles

---

## V4 Loop 3: Rotation And Recovery Drills

### Objective

Make credential rotation and compromise recovery routine, testable, and evidence-backed.

### Why This Loop Exists

Recovery that exists only in docs is not recovery.

### Security Claim Earned

After Loop 3, the platform may claim tested rotation and recovery discipline for supported credentials and systems.

### Exact In-Scope Work

- broker key rotation drills
- provider credential rotation drills
- recovery runbooks
- evidence capture for drills

### Verification Gate

- rotation tests
- scheduled drills
- runbook dry runs

### Exit Criteria

- key and credential recovery is repeatable, documented, and verified

---

## V4 Loop 4: Adversarial Continuous Verification

### Objective

Run replay, injection, transcript-leak, and boundary-violation scenarios continuously so claim strength depends on current evidence.

### Why This Loop Exists

One-time green runs are not enough for a platform claim.

### Security Claim Earned

After Loop 4, platform security claims may be tied to continuous adversarial verification, not just milestone completion.

### Exact In-Scope Work

- continuous adversarial suites
- seeded canary secrets
- PR-safe and scheduled lanes
- downgrade policy for failed evidence

### Verification Gate

- adversarial CI lanes
- scheduled extended lanes
- safe evidence review on failures

### Exit Criteria

- claim downgrades are defined and triggered by evidence weakness

---

## V4 Loop 5: Platform Ship Gate

### Objective

Ship only when the platform-level evidence across policy, identity, operations, recovery, and adversarial checks is current and strong enough.

### Why This Loop Exists

At platform scale, releases must be governed by evidence across multiple dimensions, not a single green test run.

### Security Claim Earned

This loop earns no new primitive. It earns platform-level release discipline.

### Exact In-Scope Work

- platform release checklist
- support and claim governance
- downgrade and block rules
- evidence review workflow

### Verification Gate

- platform checklist dry run
- current evidence review
- manual signoff on support and claims matrices

### Exit Criteria

- platform releases are blocked or downgraded automatically when the evidence line weakens

---

## Final Sequencing Guidance

The remaining work should still execute in this order:

1. V2 Loop 3
2. V2 Loop 4
3. V2 Loop 5
4. V2 Loop 6
5. V3 Loop 0 through Loop 4
6. V4 Loop 0 through Loop 5

Do not skip ahead just because a later loop sounds more ambitious. The early loops define the trust line that later loops depend on.

## Definition Of Done For This Spec Pack

This pack is complete when:

- every remaining roadmap loop has a tighter objective
- every remaining roadmap loop has explicit scope and non-goals
- every remaining roadmap loop names the security claim it earns
- every remaining roadmap loop names its verification gate
- every remaining roadmap loop has clear exit criteria

That condition is now met.
