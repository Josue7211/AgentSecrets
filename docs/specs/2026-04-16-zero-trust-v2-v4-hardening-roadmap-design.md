# AgentSecrets Zero-Trust V2-V4 Hardening Roadmap

> Ralph-loop-inspired roadmap for turning AgentSecrets from a masked-response broker skeleton into an end-to-end zero-trust secret-use system with explicit loop gates, verification phases, and node-to-node security testing.

## Status

- Branch: `roadmap/zero-trust-v2-v4-hardening`
- Date: `2026-04-16`
- Scope: full system roadmap
- Depth: strategic and implementation-ready
- Primary release target: `V2`

## Why This Roadmap Exists

The current repo truth is narrower than the current marketing language:

- The broker does return masked execution results.
- The broker does not yet implement a real provider adapter boundary.
- The broker does not yet implement execution adapters that consume secrets without exposing them.
- The broker does not yet protect external host-app transcript surfaces.
- The repo currently describes zero-trust properties that are only partially implemented.

That gap matters. If a password still appears in a chat box, transcript, or agent-visible session, then the zero-trust boundary failed before the broker could help. V2 must fix the system contract, not just the Rust response shape.

## Ralph Loop Interpretation

This roadmap uses a Ralph-loop-style structure:

- each version is split into bounded loops
- each loop has a single dominant outcome
- each loop has explicit exit criteria
- each loop leaves the system in a safer and more truthful state
- testing and verification are separate gates, not implied by implementation
- observations from each loop should feed the next loop before execution starts

This roadmap is intentionally shaped so future implementation can run loop by loop instead of as one large undifferentiated project.

## System Boundary

This roadmap covers the full zero-trust system, not just the broker repo:

- broker API and request lifecycle
- provider resolution boundary
- execution adapter boundary
- host-app integration contract
- agent-visible UI and transcript surfaces
- approval surfaces and operator flow
- audit and incident investigation surfaces
- deployment and network isolation posture
- verification infrastructure

## Trust Model Reset

### Trusted

- broker process
- provider bridge running on the trusted side
- human approval tooling
- operator-only logs and audit stores
- isolated secure input surfaces that are explicitly marked trusted

### Untrusted

- agent runtimes
- host apps such as OpenClaw-like clients
- browser pages rendered into agent-facing UI
- session transcripts
- prompt history
- agent-visible logs
- any plugin path that can write into chat or task memory

### Non-Negotiable Invariants

- plaintext secrets never appear in agent-visible transcript surfaces
- plaintext secrets never appear in broker API responses
- plaintext secrets never appear in untrusted logs
- plaintext secrets never cross the host-app boundary unless the receiving component is explicitly trusted and isolated
- secret use must be bound to request context, policy, and approval state
- replayed capabilities must fail closed
- unverifiable flows are not zero-trust flows and must not be marketed as such

## Delivery Model

### V2

Ship the first truthful, hardened line.

Intent:
- narrow claims to what is actually enforced
- stop the easiest real-world secret leakage paths
- formalize trusted vs untrusted surfaces
- add node-to-node verification that proves the claim

### V3

Close the end-to-end host and transcript gap.

Intent:
- remove raw-secret ingress from normal agent workflows
- introduce secure input and fill pathways
- make transcript leakage detectable and blockable

### V4+

Turn AgentSecrets into a durable secure platform.

Intent:
- support multiple adapters and runtimes safely
- harden operations, forensics, rotation, and attestation
- make verification continuous rather than one-time

## Version Ladder

## V2: Truthful Hardening Line

### Outcome

AgentSecrets V2 is the first release that can honestly claim:

- the broker does not return plaintext secrets
- the broker enforces explicit trusted and untrusted boundaries
- the broker rejects unsafe secret ingress modes by default
- the system has real node-to-node tests proving secrets do not leak across the intended untrusted surfaces

### Not Yet Claimed In V2

V2 does not claim:

- universal transcript safety for every external host app
- full secure browser fill in all environments
- complete provider abstraction across many secret backends
- formally verified policy correctness

### Loop 0: Truth Reset

Goal:
- align repo claims, threat model, and product language with actual enforcement

Why now:
- overclaiming security is itself a security risk
- V2 must start by making the system honest

Threats closed:
- false operator confidence
- unsafe deployment based on misleading docs
- ambiguous trust boundaries

Scope:
- README, architecture docs, integration docs, release checklist, threat model
- explicit matrix of implemented, partial, and future guarantees

Out of scope:
- protocol redesign
- provider implementation work

Deliverables:
- rewritten security claims matrix
- explicit boundary table: trusted, untrusted, out-of-scope
- release language that distinguishes broker-level guarantees from end-to-end guarantees
- “unsafe legacy patterns” section covering direct raw secret entry into chat or host UI

Dependencies:
- none

Acceptance criteria:
- no doc claims transcript safety unless backed by enforcement and tests
- no doc claims provider mediation unless the code path exists
- release checklist fails if claim matrix and implementation diverge

Verification:
- manual docs review
- repo-wide claim audit
- checklist validation in CI or pre-release review

Rollback and containment:
- if implementation lags, reduce claims instead of shipping aspirational language

Open questions:
- whether to version guarantees as Bronze/Silver/Gold trust tiers

### Loop 1: Secret Ingress Lockdown

Goal:
- block raw secret ingestion into untrusted flows by default

Why now:
- the biggest real failure mode is “secret typed before broker boundary”

Threats closed:
- password pasted into chat
- raw secret passed in JSON body
- host plugin sending plaintext instead of secret reference

Scope:
- request schema and validation
- explicit accepted secret identifiers such as `bw://...` or equivalent opaque references
- rejection of suspicious raw-secret-shaped inputs
- legacy compatibility mode if needed, but disabled by default

Out of scope:
- secure UI widgets
- browser fill runtime

Deliverables:
- request contract for opaque secret refs only
- validation and policy rules for rejecting raw secret values
- compatibility notes for legacy host integrations
- audit event shape for ingress rejection

Dependencies:
- Loop 0

Acceptance criteria:
- normal request flow cannot submit plaintext password value as the secret payload
- rejected ingress attempts are observable in audit without echoing the secret
- enforce mode defaults to opaque refs only

Verification:
- unit tests for rejection heuristics and schema validation
- integration tests for bad-input rejection
- negative tests proving rejected requests never echo submitted secret content

Rollback and containment:
- optional monitored compatibility flag with loud warnings and non-production guidance

Open questions:
- whether to support a transitional “trusted local injector” path in V2

### Loop 2: Provider Isolation Contract

Goal:
- define and implement the trusted-side provider boundary so secret resolution happens outside agent-visible space

Why now:
- zero-trust claims are weak until provider mediation is real

Threats closed:
- direct Bitwarden access from the untrusted runtime
- provider credentials embedded in host app
- ad hoc secret lookup code in agent-visible paths

Scope:
- provider adapter interface
- first provider target: Bitwarden-backed opaque refs
- trusted-side provider bridge contract
- provider error model that never returns plaintext

Out of scope:
- many providers
- advanced caching or HSM support

Deliverables:
- provider trait/interface definition
- Bitwarden adapter plan and initial implementation target
- no-plaintext provider resolution response contract
- provider-side health and failure semantics

Dependencies:
- Loop 1

Acceptance criteria:
- provider credentials exist only on trusted-side components
- untrusted clients can ask for secret use, not secret reveal
- provider errors never leak secret value or raw metadata beyond allowed masked fields

Verification:
- unit tests for adapter contract
- integration tests with a fake provider bridge
- failure-path tests for network errors and invalid refs

Rollback and containment:
- keep provider adapter behind feature flag until trustworthy

Open questions:
- whether provider resolution should be in-process, sidecar, or separate node in V2

### Loop 3: Execution Adapter Containment

Goal:
- move from “masked result only” to “trusted-side secret consumption” for at least one adapter path

Why now:
- a broker that never actually consumes secrets securely is only half a system

Threats closed:
- host app requesting raw secret reveal to do its own fill
- ambiguous execution semantics

Scope:
- execution adapter interface
- first trusted adapter target such as password fill or request signing
- capability-to-execution binding rules
- adapter result shape with masked outputs only

Out of scope:
- wide adapter catalog
- rich UX for approvals

Deliverables:
- execution adapter interface
- one trusted secret-consumption path implemented or fully stubbed with invariant tests
- adapter sandbox/containment notes
- adapter audit events

Dependencies:
- Loop 2

Acceptance criteria:
- at least one sanctioned secret-use flow completes without exposing plaintext to agent-visible surfaces
- execution results are masked and context-bound
- adapter misuse attempts fail closed

Verification:
- adapter integration tests
- negative tests for raw secret reveal attempts
- replay and target mismatch tests

Rollback and containment:
- disable unfinished adapters rather than expose reveal semantics

Open questions:
- whether browser fill belongs in V2 or should land as a V3-adjacent adapter

### Loop 4: Capability and Approval Hardening

Goal:
- tighten approval and capability semantics so the broker authorizes one bounded act, not a general-purpose secret handle

Why now:
- current capability handling is meaningful but still simplistic

Threats closed:
- replay
- approval drift
- target substitution
- capability use outside intended context

Scope:
- action binding
- target binding
- TTL hardening
- one-time use enforcement
- approval payload truthfulness

Out of scope:
- hardware-backed attestation

Deliverables:
- stronger capability schema
- approval payload contract with masked context only
- denial and expiry semantics
- threat-case matrix for misuse

Dependencies:
- Loops 1 through 3

Acceptance criteria:
- capability cannot be replayed
- capability cannot be reused on a different target or action
- approval UI data contains enough context for human decision without secret exposure

Verification:
- property and misuse tests
- expiry tests
- actor-role tests

Rollback and containment:
- shorter TTL defaults and stricter policy while features stabilize

Open questions:
- whether approver responses should ever return plaintext capability tokens or move to a more isolated handoff

### Loop 5: MEMD-Style Node-to-Node E2E Harness

Goal:
- prove V2 claims across real process and node boundaries, not only inside unit tests

Why now:
- zero-trust claims without multi-node evidence are weak

Threats closed:
- hidden transcript leakage
- false confidence from mocked tests only
- boundary mistakes that appear only when components run separately

Scope:
- local multi-process harness
- real host integration path
- transcript capture assertions
- log and event capture assertions

Out of scope:
- internet-scale distributed testing
- production chaos testing

Deliverables:
- untrusted client node
- broker node
- provider bridge node or equivalent trusted provider simulation
- approver node
- transcript capture collector
- invariant assertion suite

Dependencies:
- Loops 1 through 4

Acceptance criteria:
- local harness proves secret never appears in agent-visible transcript
- local harness proves secret never appears in broker API responses
- local harness proves secret never appears in untrusted logs or event surfaces
- real host integration path exercises the same invariants
- replay, misuse, and malformed-ingress cases are covered end to end

Verification:
- deterministic E2E suite in CI where feasible
- nightly extended E2E if the real host path is too heavy for every PR
- failure artifacts that redact safely while preserving evidence

Rollback and containment:
- V2 does not ship if the node-to-node harness is absent or flaky enough to invalidate the claim

Open questions:
- how much of the host integration test can live in this repo versus a sibling integration repo

### Loop 6: V2 Ship Gate

Goal:
- define the exact bar for calling V2 real

Why now:
- security projects drift unless ship criteria are explicit

Threats closed:
- “looks good locally” release behavior
- shipping on partial test confidence

Scope:
- release gating
- support statement
- deployment guardrails

Out of scope:
- long-term platform work

Deliverables:
- V2 release checklist
- support matrix
- deployment topology guidance
- security claims table for release notes

Dependencies:
- all V2 loops

Acceptance criteria:
- all V2 loops are complete or explicitly cut
- docs truth matches implementation
- node-to-node E2E passes
- release notes say what V2 does and does not guarantee

Verification:
- pre-release review
- CI summary gate
- manual signoff on claim matrix

Rollback and containment:
- if one claim fails, reduce scope and release as preview instead of GA

Open questions:
- whether V2 should be named beta until the real host integration path is consistently green

## V3: End-to-End Zero-Trust Line

### Outcome

V3 closes the host and transcript gap enough to support stronger end-to-end claims for supported host environments.

### Loop 0: Trusted Input Surface

Goal:
- introduce a secure input path so secrets never need to enter agent chat in the first place

Why now:
- transcript safety starts at ingress, not post-hoc masking

Threats closed:
- user typing password into prompt
- host app writing secret text into task memory

Scope:
- secure input widget or trusted entry channel
- opaque ref issuance flow
- supported host-path documentation

Out of scope:
- universal UX polish

Deliverables:
- secure input surface design
- host integration contract for trusted input
- migration guide away from raw text entry

Dependencies:
- V2

Acceptance criteria:
- supported host flow never requires plaintext entry into the agent transcript

Verification:
- E2E tests with transcript capture

### Loop 1: Transcript and Log Redaction Pipeline

Goal:
- add enforced redaction for agent-visible transcript and untrusted logging surfaces in supported hosts

Why now:
- some leakage paths are accidental echoes rather than formal API behavior

Threats closed:
- accidental secret echo in chatbox
- accidental log inclusion
- error-message leaks

Scope:
- host-side redaction hooks
- transcript filtering
- log sink classification

Out of scope:
- unsupported host environments

Deliverables:
- redaction policy
- supported-host hook design
- regression fixtures for sensitive string detection

Dependencies:
- V2, Trusted Input Surface

Acceptance criteria:
- supported host transcripts and untrusted logs remain secret-free under tested scenarios

Verification:
- seeded canary secrets
- adversarial echo tests
- transcript snapshot checks

### Loop 2: Real Trusted Execution Adapters

Goal:
- move beyond one path and support multiple sanctioned secret-use actions

Scope:
- browser fill
- request signing
- outbound send or credential handoff in contained contexts

Acceptance criteria:
- each adapter has explicit boundary and no-reveal invariant tests

### Loop 3: Multi-Host Support Matrix

Goal:
- declare which host apps are truly supported for end-to-end zero-trust

Deliverables:
- supported-host matrix
- per-host threat notes
- host-specific E2E suites

### Loop 4: V3 Ship Gate

Goal:
- release only when supported-host claims are backed by green E2E evidence

## V4+: Autonomous Secure Operations Line

### Outcome

V4+ makes AgentSecrets resilient as a platform instead of a narrow broker project.

### Loop 0: Policy Engine Maturity

Goal:
- richer policy model for action, target, actor, environment, and risk scoring

### Loop 1: Attestation and Runtime Identity

Goal:
- strengthen trust in which runtime, adapter, and host is actually making a request

### Loop 2: Tamper-Evident Operations and Forensics

Goal:
- improve investigation, chain-of-custody, and incident response

### Loop 3: Rotation and Recovery Drills

Goal:
- make credential rotation and compromise recovery routine and testable

### Loop 4: Adversarial Continuous Verification

Goal:
- run replay, injection, transcript-leak, and boundary-violation scenarios continuously

### Loop 5: Platform Ship Gate

Goal:
- move from secure project to secure operating system for secret use by agents

## Implementation Track Split

## Track A: In-Repo Work

These can be implemented directly in this repo:

- claim and threat-model reset
- schema validation and ingress rejection
- provider and execution adapter interfaces
- capability hardening
- broker-side audit behavior
- release and deployment docs
- broker-centered integration tests
- local multi-process E2E harness

## Track B: Dependent External Work

These require host-app or sibling-system changes:

- secure host input surface
- transcript redaction in chat/session UI
- host-side log classification
- real OpenClaw-like integration path
- agent-runtime boundary enforcement outside the broker process

## Track C: Cross-Repo Contract Work

These need coordinated evolution:

- opaque secret ref contract
- approval channel payload contract
- transcript-safe event format
- supported-host matrix and certification process

## Verification Pyramid

### Layer 1: Unit

- validation
- policy
- token binding
- adapter contracts

### Layer 2: Broker Integration

- request approval execution
- provider bridge simulation
- adapter misuse

### Layer 3: Local Node-to-Node E2E

- untrusted client node
- broker node
- approver node
- provider node
- transcript and log capture assertions

### Layer 4: Real Host Integration E2E

- supported host path
- transcript assertions
- log assertions
- operator approval path

### Layer 5: Adversarial Regression

- prompt injection attempts
- replay attempts
- transcript echo attempts
- malformed secret ingress
- cross-target misuse

## Node-to-Node E2E Invariants

Every supported end-to-end flow must prove:

- the untrusted node never receives plaintext secret material
- the broker never returns plaintext secret material
- the transcript collector never sees plaintext secret material
- the untrusted log collector never sees plaintext secret material
- the trusted-side execution path can still complete the authorized act
- misuse cases fail closed and leave auditable evidence

## Recommended Sequencing

If execution starts after this roadmap:

1. finish V2 Loop 0 before writing more marketing copy
2. finish V2 Loop 1 before building more host integrations
3. finish V2 Loops 2 through 4 before expanding adapters
4. finish V2 Loop 5 before calling any line zero-trust
5. treat V2 Loop 6 as the only ship authority
6. treat V3 as the first line allowed to claim supported-host end-to-end safety

## Hard No List

Do not do these and still call the system zero-trust:

- accept plaintext passwords from agent-visible chat input as a normal workflow
- return secret values from broker APIs “just for local mode”
- let untrusted host apps talk directly to Bitwarden or equivalent providers
- store secrets in agent-visible logs, transcript summaries, or audit detail fields
- substitute vague “masked metadata” language for actual E2E verification

## Strategic Risks

- security theater risk if docs outrun code
- integration drift risk if host apps implement their own shortcuts
- test credibility risk if E2E only mocks boundaries
- adoption risk if trusted input surfaces are too inconvenient
- architecture risk if provider and execution boundaries are not separated early

## Open Decisions

- which host environment becomes the first fully supported end-to-end target
- whether provider resolution should be in broker-process, sidecar, or separate node
- whether capability delivery remains token-based or moves to stronger channel binding
- whether browser fill is V2 pilot scope or strictly V3
- whether external host integration tests live here or in a dedicated sibling repo

## Immediate Next Step

Use this roadmap to derive one execution packet at a time, starting with:

- `V2 / Loop 0: Truth Reset`

That loop is the highest leverage start because it narrows claims, clarifies boundaries, and makes every later implementation decision easier to evaluate.
