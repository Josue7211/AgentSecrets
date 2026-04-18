# V2 Loop 6 V2 Ship Gate

Goal: define the exact bar for calling V2 real and block release drift when one claim or test line is weak.

Scope:
- release gating
- deployment guardrails
- support statement
- security claims table for release notes

Out of scope:
- V3 host-surface work
- long-term platform operations work

Implementation order:

1. Release criteria
- update `docs/product/RELEASE.md` with an explicit V2 checklist tied to Loops 0 through 5
- add a support matrix that distinguishes shipped, preview, and unsupported paths
- add release-note language for what V2 does and does not guarantee
- require docs truth to match current implementation and test evidence

2. CI and review gates
- add a CI summary gate that requires unit, integration, claim audit, and node-to-node E2E results
- fail the release path if any required evidence is missing
- add a manual signoff section for claim review and deployment topology review
- keep preview-release fallback language when one loop must be cut

3. Deployment guidance
- tighten deployment topology docs around private-network placement, trusted-side provider placement, and supported host flows
- add operator guardrails for logs, audit export, and key handling
- make release docs point back to the claims matrix and support matrix

Verification:
- release checklist dry run
- CI summary gate passes with all required evidence present
- manual signoff on claims matrix and support matrix

Acceptance:
- all V2 loops are complete or explicitly cut from the V2 claim set
- docs truth matches implementation
- node-to-node E2E evidence is green
- release notes clearly state what V2 does and does not guarantee
