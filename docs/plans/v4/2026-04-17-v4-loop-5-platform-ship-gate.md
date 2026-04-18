# V4 Loop 5 Platform Ship Gate

Goal: move from a secure project line to a secure operating platform for secret use by agents, with ship criteria tied to continuous evidence.

Scope:
- platform-level release gate
- support statement for runtimes, adapters, and hosts
- operational evidence review
- claim downgrade policy when evidence weakens

Out of scope:
- experimental paths without continuous verification
- support claims that exceed current evidence

Implementation order:

1. Platform readiness bar
- define the platform ship checklist across policy maturity, identity, forensics, rotation, and adversarial verification
- require supported runtime, adapter, and host matrices to be current
- tie ship readiness to continuous evidence rather than static milestone completion

2. Claim and support governance
- define how claims expand, contract, or revert based on current verification status
- add support statement language for supported, preview, deprecated, and unsupported paths
- require operational evidence review before every platform release

3. Release process integration
- wire platform ship criteria into release docs, CI summaries, and manual signoff
- ensure any missing evidence downgrades or blocks release automatically

Verification:
- platform checklist dry run
- continuous verification evidence review
- manual signoff on support and claims matrices

Acceptance:
- platform releases are gated by continuous evidence across policy, identity, operations, and adversarial checks
- support statements match the current matrices
- claim downgrades happen automatically when evidence weakens

