# Secret Broker Roadmap

`ROADMAP.md` is the single roadmap source of truth for this repo.

<!-- ROADMAP_STATE
truth_date: 2026-04-17
version: v5
version_status: planned
current_milestone: V5
milestone_status: planned
current_phase: V5L0
phase_status: not_started
next_milestone: V5
next_step: V5 Loop 0 Host Contract Canon — define the canonical first-class host contract before certifying Hermes, OpenClaw, Claude, or Codex
active_blockers: [no-canonical-v5-host-contract, no-hermes-host-certification-lane, no-claude-host-certification-lane, no-codex-host-certification-lane]
v2_status: shipped
v3_status: shipped_with_matrix_bound_external_claims
v4_status: shipped
note: V2 through V4 are complete and verified. Next product ladder is V5 through V10. North star: Secret Broker becomes the trust control plane for agent work across Hermes, OpenClaw, Claude, and Codex, then expands into the enterprise and category platform.
last_handoff: post_v4_complete_v5_v10_roadmap_seed_2026-04-17
-->

## Status Snapshot

- truth date: `2026-04-17`
- current version: `v5`
- version status: `planned`
- current milestone: `V5: Multi-Host Ship`
- current phase: `V5 Loop 0: Host Contract Canon`
- completed foundation: `V2`, `V3`, `V4` shipped and verified
- V2 status: `shipped`
- V3 status: `shipped` with matrix-bound external claims
- V4 status: `shipped`
- next step: define the canonical first-class host contract before certifying Hermes, OpenClaw, Claude, or Codex
- north star: Secret Broker becomes the trust control plane for agent work, then grows into enterprise infrastructure and finally a category platform

## Product Definition

Secret Broker is not just a secret broker.

It is the system that answers:

- who this agent or session really is
- what exact action it is requesting
- what secret or capability is required
- whether policy allows it
- whether approval is required
- how the action executes on the trusted side
- what audit evidence must exist
- what must never cross into host-visible transcripts, logs, or responses

First-class hosts for this roadmap:

- Hermes
- OpenClaw
- Claude
- Codex

Each host earns `shipped` separately.
No umbrella fake badge.

## Non-Negotiable Invariants

- plaintext secrets never appear in host-visible transcripts, logs, or responses
- provider mediation stays on the trusted side
- production actions execute through trusted adapters, not raw secret reveal
- each first-class host has its own trust boundary, evidence lane, and downgrade policy
- no version may widen claims past its evidence
- downgrade rules must be automatic when evidence goes stale

## Blockers

- **no-canonical-v5-host-contract**: there is no single host contract yet that Hermes, OpenClaw, Claude, and Codex must all satisfy before earning `shipped`
- **no-hermes-host-certification-lane**: Hermes is intended as first-class but has no host-specific certification path yet
- **no-claude-host-certification-lane**: Claude does not yet have host-specific transcript, identity, and E2E proof
- **no-codex-host-certification-lane**: Codex does not yet have host-specific transcript, identity, and E2E proof

## Process

- Release and claim authority: [[docs/product/RELEASE.md]]
- Current host matrix: [[docs/product/SUPPORTED_HOSTS.md]]
- Current platform support matrix: [[docs/product/PLATFORM_SUPPORT.md]]
- Current post-V4 expansion plan: [[docs/plans/v5/2026-04-17-post-v4-vision-completion.md]]
- Prior roadmap design reference: [[docs/specs/2026-04-16-zero-trust-v2-v4-hardening-roadmap-design.md]]

## Completed Foundation

### V2: Truthful Hardening Line

Status: `shipped`

Delivered:

- truthful claim reset
- raw secret ingress lockdown
- provider isolation contract
- execution adapter containment
- capability and approval hardening
- node-to-node harness and ship gate

### V3: Host Boundary Foundation

Status: `shipped` with matrix-bound external claims

Delivered:

- trusted-input sessions
- transcript and log redaction pipeline
- sanctioned adapter registry
- host support matrix
- V3 ship gate

Current truth:

- local helper harness is `shipped`
- OpenClaw is `preview`
- Claude, Codex, and arbitrary external runtimes are not shipped

### V4: Platform Hardening

Status: `shipped`

Delivered:

- explainable policy engine
- runtime, host, and adapter identity verification
- tamper-evident audit and forensics
- rotation and recovery drills
- adversarial verification lanes
- platform ship gate

## V5: Multi-Host Ship

### Outcome

Secret Broker becomes the first real shared trust layer across Hermes, OpenClaw, Claude, and Codex.

### Ship Bar

V5 is real only when all four hosts have:

- host-specific trusted-input evidence
- host-specific transcript and log redaction evidence
- host-specific identity and session binding evidence
- host-specific E2E coverage
- host-specific threat notes
- a current `shipped` row in the host matrix

### Not Yet Claimed In V5

- full production action surface across every high-risk action
- full enterprise operating model
- external developer ecosystem

### Loops

| Loop | Name | Status | Outcome |
| --- | --- | --- | --- |
| V5L0 | Host Contract Canon | `planned` | define the canonical first-class host contract |
| V5L1 | Hermes First-Class Host Lane | `planned` | certify Hermes as a real shipped host |
| V5L2 | OpenClaw First-Class Host Lane | `planned` | move OpenClaw from preview to shipped |
| V5L3 | Claude First-Class Host Lane | `planned` | certify Claude as a real shipped host |
| V5L4 | Codex First-Class Host Lane | `planned` | certify Codex as a real shipped host |
| V5L5 | Multi-Host Identity And Session Model | `planned` | unify session truth without collapsing host-specific trust |
| V5L6 | Multi-Host Ship Gate | `planned` | make “all hosts shipped” impossible to overclaim |

## V6: Production Action Surface

### Outcome

Secret Broker becomes the trusted execution layer for real sensitive work, not just safe secret plumbing.

### Ship Bar

V6 is real only when these action classes are production-backed:

- login
- signing
- deploy and prod access
- customer-data operations
- payments and admin actions

Each action class must have:

- production adapter path
- policy and approval semantics
- fail-closed misuse handling
- audit visibility
- action-specific E2E and adversarial evidence

### Not Yet Claimed In V6

- full enterprise operating platform depth
- external developer ecosystem

### Loops

| Loop | Name | Status | Outcome |
| --- | --- | --- | --- |
| V6L0 | Browser And Login Actions | `planned` | ship production browser and login flows |
| V6L1 | Signing And Key-Use Actions | `planned` | broaden signing into a real production action family |
| V6L2 | Deploy And Prod Access Actions | `planned` | support bounded deploy and infrastructure actions |
| V6L3 | Customer-Data Action Controls | `planned` | support high-risk customer-data operations safely |
| V6L4 | Payment And Admin Actions | `planned` | support money-moving and admin actions under the trust model |
| V6L5 | Action Packs And Approval UX | `planned` | make approvals understandable and operable |
| V6L6 | Action-Class Ship Gates | `planned` | tie every action claim to evidence |

## V7: Enterprise Trust Platform

### Outcome

Secret Broker becomes something a company can actually run on top of, not just a strong engineer tool.

### Ship Bar

V7 is real only when enterprise operators have:

- org, team, and workspace boundaries
- multi-party approvals
- incident review
- revoke and kill-switch controls
- forensic timelines
- Claw Control operator integration

### Not Yet Claimed In V7

- full compliance depth for every regime
- broad external developer ecosystem

### Loops

| Loop | Name | Status | Outcome |
| --- | --- | --- | --- |
| V7L0 | Org, Team, And Workspace Model | `planned` | add first-class enterprise structure |
| V7L1 | Multi-Party Approvals And Delegation | `planned` | support real org approval semantics |
| V7L2 | Incident Review, Revoke, Kill Switch, Break-Glass | `planned` | make the system survivable in incident conditions |
| V7L3 | Operator Console And Claw Control Integration | `planned` | make Claw Control the operator shell above Secret Broker |
| V7L4 | Policy Packs And Environment Tiers | `planned` | make policy manageable across environments |
| V7L5 | Forensic Timelines And Investigation UX | `planned` | turn audit into real investigation workflows |
| V7L6 | Enterprise Ship Gate | `planned` | prevent fake “enterprise-ready” claims |

## V8: Enterprise Depth

### Outcome

Secret Broker becomes hard to replace inside serious organizations because it satisfies security, reliability, and governance pressure at once.

### Ship Bar

V8 is real only when the system has:

- stronger attestation tiers, including hardware-backed paths where applicable
- tenant isolation controls
- compliance-grade evidence export
- policy change lifecycle
- disaster recovery and trust continuity
- adaptive risk-based approval

### Loops

| Loop | Name | Status | Outcome |
| --- | --- | --- | --- |
| V8L0 | Strong Attestation Tiers | `planned` | move beyond the current weaker trust baseline |
| V8L1 | Tenant And Data Boundary Controls | `planned` | support multi-tenant and cross-boundary use safely |
| V8L2 | Compliance Evidence Bundles | `planned` | produce evidence packages fit for audit |
| V8L3 | Policy Change Lifecycle | `planned` | make policy evolution safe and reviewable |
| V8L4 | Disaster Recovery And Trust Continuity | `planned` | preserve trust guarantees across restore events |
| V8L5 | Adaptive Risk And Approval | `planned` | make approval policy dynamic and context-aware |

## V9: Platform Breadth

### Outcome

Secret Broker becomes a platform other systems can build on rather than a single internal stack.

### Ship Bar

V9 is real only when outside integrations can be added through supported frameworks, not custom surgery.

### Loops

| Loop | Name | Status | Outcome |
| --- | --- | --- | --- |
| V9L0 | Host Integration SDKs | `planned` | make host integration reproducible |
| V9L1 | Adapter SDK And Certification Kit | `planned` | let new trusted adapters be built under one standard |
| V9L2 | Provider Integration Framework | `planned` | generalize provider mediation without weakening trust |
| V9L3 | External Approval And Audit Integrations | `planned` | connect to surrounding enterprise systems safely |
| V9L4 | Self-Serve Host Onboarding Pipeline | `planned` | reduce new-host integration cost |
| V9L5 | Developer Docs And Certification Program | `planned` | make outside adoption possible without tribal knowledge |

## V10: Category Platform

### Outcome

Secret Broker becomes the category-defining trust layer for agent actions, not only the best internal implementation of one team’s stack.

### Ship Bar

V10 is real only when:

- the trust protocol is stable and public
- ecosystem certification exists
- cross-org delegation and federation are possible
- benchmark suites define trust quality for hosts, actions, and providers
- outside adopters can use the platform without rewriting the model

### Loops

| Loop | Name | Status | Outcome |
| --- | --- | --- | --- |
| V10L0 | Stable Public Trust Protocol | `planned` | define the durable protocol others can rely on |
| V10L1 | Ecosystem Certification And Trust Marks | `planned` | make trust claims externally legible |
| V10L2 | Cross-Org Federation And Delegation | `planned` | support trust across company boundaries |
| V10L3 | Policy Intelligence And Recommended Controls | `planned` | help operators choose safer defaults |
| V10L4 | Trust Benchmark Suite | `planned` | make host, action, and provider trust measurable |
| V10L5 | Category Launch Bar | `planned` | make Secret Broker feel like infrastructure |

## Sequencing Logic

- `V5` comes first because fragmented host support kills the product
- `V6` comes second because real value comes from sensitive actions, not only secret plumbing
- `V7` comes third because enterprise surface matters only after hosts and actions are real
- `V8` deepens enterprise readiness
- `V9` broadens the platform for builders and integrations
- `V10` turns the product into category infrastructure

## Non-Goals

- fake umbrella support badges for first-class hosts
- shipping new action classes without their own evidence and ship bars
- using ecosystem expansion to dodge enterprise depth
- treating “works in one session” as certification
