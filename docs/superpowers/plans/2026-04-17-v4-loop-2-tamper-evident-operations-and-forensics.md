# V4 Loop 2 Tamper-Evident Operations And Forensics

Goal: improve investigation, chain-of-custody, and incident response so secret-use operations remain auditable under pressure.

Scope:
- stronger audit integrity
- forensic export and evidence bundling
- incident investigation workflow
- operator-facing investigation documentation

Out of scope:
- external SIEM product integrations as a prerequisite
- unsupported environments without audit storage controls

Implementation order:

1. Audit and evidence integrity
- extend audit chain integrity checks and operator-facing verification tools
- add redact-safe forensic export bundles with timestamps and integrity metadata
- preserve enough context for investigation without exposing secret material

2. Incident response workflow
- document investigation, evidence collection, and chain-of-custody flow
- add operator tools or scripts for incident bundle creation and verification
- define how compromised paths are isolated without destroying evidence

3. Verification
- add tamper-detection tests
- add forensic export tests
- add incident-runbook validation exercises

Verification:
- audit integrity tests
- forensic export verification tests
- incident-runbook dry run

Acceptance:
- operators can produce tamper-evident, redact-safe investigation bundles
- audit integrity failures are detectable
- incident response flow is documented and testable

