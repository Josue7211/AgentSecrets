# V3 Loop 4 V3 Ship Gate

Goal: release V3 only when supported-host end-to-end claims are backed by green evidence and current docs tell the truth.

Scope:
- supported-host release gate
- end-to-end evidence review
- support statement and release-note truth

Out of scope:
- V4 platform operations work
- unsupported host enablement

Implementation order:

1. V3 release bar
- add a V3 release checklist tied to Trusted Input Surface, Redaction Pipeline, Real Trusted Execution Adapters, and Multi-Host Support Matrix
- require supported-host E2E evidence for every host in the release notes
- define preview fallback language if a host path is not ready for GA claims

2. Evidence and signoff
- require green supported-host suites, transcript assertions, log assertions, and claims review before release
- add a release-note claims table that lists supported hosts and excluded hosts
- add manual signoff for matrix accuracy and regression review

Verification:
- supported-host E2E suites are green
- release checklist dry run
- manual signoff on support matrix and claims table

Acceptance:
- V3 ships only with supported-host evidence attached
- release notes limit claims to supported hosts that are green
- docs truth and evidence stay aligned at ship time

