# V3 Loop 2 Real Trusted Execution Adapters

Goal: move beyond one trusted adapter path and support multiple sanctioned secret-use actions with explicit no-reveal invariants.

Scope:
- browser fill
- request signing
- outbound send or credential handoff in contained contexts
- per-adapter boundary and invariant tests

Out of scope:
- unrestricted adapter plugins
- adapters that reveal raw secrets to untrusted clients

Implementation order:

1. Adapter expansion model
- extend the V2 execution adapter boundary into a registry of sanctioned adapter types
- define per-adapter capability requirements, target validation, and masked result shapes
- keep unsupported adapters disabled by default

2. Real adapter paths
- implement a trusted browser fill path for supported hosts
- implement a trusted request-signing path
- implement one contained outbound send or credential handoff path with explicit boundary controls
- keep secret bytes inside trusted execution boundaries for every adapter

3. Invariant and misuse coverage
- add no-reveal invariant tests per adapter
- add negative tests for reveal attempts, target drift, replay, and unsupported host use
- expose per-adapter health and support state in operator-facing surfaces only

Verification:
- adapter integration tests
- per-adapter no-reveal invariant tests
- replay and target-drift misuse tests
- supported-host E2E for each sanctioned adapter

Acceptance:
- each shipped adapter has explicit boundary documentation and no-reveal invariant tests
- multiple sanctioned secret-use flows complete without exposing plaintext to untrusted surfaces
- unsupported adapters fail closed

