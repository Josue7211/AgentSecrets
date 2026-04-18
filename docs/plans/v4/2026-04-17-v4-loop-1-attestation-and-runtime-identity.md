# V4 Loop 1 Attestation And Runtime Identity

Goal: strengthen trust in which runtime, adapter, and host is actually making a request.

Scope:
- runtime identity model
- adapter identity model
- host identity and attestation claims
- verification of identity claims at request time

Out of scope:
- vendor-specific hardware requirements as a release prerequisite
- unsupported runtimes without identity plumbing

Implementation order:

1. Identity contract
- define signed or otherwise verifiable identity claims for runtime, host, and adapter
- define how those claims attach to request creation, approval, and execution flows
- keep unverifiable identity paths out of the strong trust claim set

2. Verification path
- add broker-side verification of identity claims
- bind verified identity into policy, approval, and audit context
- fail closed on missing, stale, or invalid identity signals

3. Evidence and docs
- document trusted identity sources and unsupported identity paths
- add tests for identity mismatch, spoofing attempts, and stale attestation

Verification:
- identity verification tests
- spoofing and stale-attestation misuse tests
- integration tests showing verified identity reaches policy and audit context

Acceptance:
- runtime, adapter, and host identity can be verified on supported paths
- unverifiable identity paths cannot claim the stronger trust tier
- identity misuse attempts fail closed

