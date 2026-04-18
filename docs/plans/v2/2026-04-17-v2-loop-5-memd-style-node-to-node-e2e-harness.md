# V2 Loop 5 MEMD-Style Node-to-Node E2E Harness

Goal: prove V2 claims across real local node boundaries instead of relying only on in-process tests.

Scope:
- add a local multi-process harness for untrusted client, broker, approver, and trusted provider simulation nodes
- capture transcript-like output and untrusted log surfaces
- exercise at least one real host-shaped integration path through the broker
- produce redact-safe failure artifacts for debugging and CI

Out of scope:
- internet-scale distributed testing
- production chaos testing
- unsupported host environments

Implementation order:

1. Harness topology
- add a deterministic local harness runner under `scripts/` or `tests/e2e/`
- stand up broker, approver, untrusted client, and trusted provider simulation as separate processes
- add transcript and log collectors for every untrusted surface
- keep fixture secrets stable so leak assertions are deterministic

2. End-to-end scenarios
- add happy-path execution using opaque refs, approval, provider resolve, and trusted adapter use
- add malformed ingress, replay, target mismatch, unsupported action, and provider failure cases
- make every scenario assert that plaintext never appears in broker responses, transcripts, or untrusted logs
- store only masked evidence when scenarios fail

3. CI and artifact strategy
- add a PR-safe deterministic E2E suite
- add a heavier nightly or scheduled job for real host-shaped flows if needed
- emit redact-safe artifacts for transcripts, logs, and HTTP traces
- fail the claim gate if artifacts or assertions are missing

4. Docs and release wiring
- document how to run the harness locally
- wire the harness into release gating and claim-audit docs
- state plainly that V2 cannot ship without this harness staying green enough to defend the claim

Verification:
- `cargo test e2e_harness::tests -- --nocapture`
- `scripts/run-e2e-harness.sh`
- CI job for deterministic node-to-node E2E on pull requests
- scheduled extended E2E for heavier host-shaped coverage

Acceptance:
- local harness proves secrets never appear in agent-visible transcript surfaces
- local harness proves secrets never appear in broker API responses
- local harness proves secrets never appear in untrusted logs or event surfaces
- replay, misuse, and malformed-ingress cases are covered end to end

