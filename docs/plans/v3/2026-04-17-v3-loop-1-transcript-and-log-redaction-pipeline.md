# V3 Loop 1 Transcript And Log Redaction Pipeline

Goal: add enforced redaction for agent-visible transcript and untrusted logging surfaces in supported host environments.

Scope:
- host-side redaction hooks
- transcript filtering
- log sink classification
- seeded canary fixtures and regression coverage for secret echo paths

Out of scope:
- unsupported host environments
- retroactive cleanup of external systems outside the supported-host matrix

Implementation order:

1. Redaction policy and sink classification
- define which transcript and log surfaces are untrusted and must remain secret-free
- add a redaction policy document with masking, suppression, and failure semantics
- classify supported host log sinks and transcript channels by trust level

2. Host-side hooks and filtering
- add supported-host hook interfaces for transcript filtering and log sanitization
- ensure secret-like values, canary secrets, and known provider payloads are filtered before they hit untrusted sinks
- make redaction failures fail closed for supported paths

3. Regression coverage
- add seeded canary secret fixtures
- add adversarial echo tests, transcript snapshot checks, and error-path leak checks
- capture redact-safe artifacts when a supported-host test fails

Verification:
- seeded canary secret tests
- adversarial echo tests
- transcript snapshot checks
- supported-host E2E with untrusted log assertions

Acceptance:
- supported host transcripts remain secret-free under tested scenarios
- supported host untrusted logs remain secret-free under tested scenarios
- error messages and accidental echoes are redacted or suppressed before reaching untrusted surfaces

