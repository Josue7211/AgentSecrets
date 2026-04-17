# V3 Loop 3 Multi-Host Support Matrix

Goal: declare which host apps are truly supported for end-to-end zero-trust claims and back that claim with host-specific evidence.

Scope:
- supported-host matrix
- per-host threat notes
- host-specific E2E suites
- certification and regression policy for supported hosts

Out of scope:
- blanket support claims for every host app
- unsupported hosts without dedicated E2E evidence

Implementation order:

1. Support matrix definition
- add a supported-host matrix document covering shipped, preview, and unsupported hosts
- define minimum bars for entering and staying in the supported set
- document per-host trust boundaries, transcript surfaces, and known limitations

2. Host-specific verification
- add or link host-specific E2E suites for each supported host
- require transcript, log, trusted input, and trusted adapter assertions per host
- keep unsupported hosts out of the supported matrix until their evidence exists

3. Certification workflow
- define how a host path is certified, reviewed, and re-verified over time
- add regression policy for host version drift and breaking changes
- wire matrix updates into release and support docs

Verification:
- host-specific E2E suites for each supported host
- matrix review against current evidence
- regression checks when a supported host changes version or integration path

Acceptance:
- every supported host has host-specific threat notes and E2E evidence
- unsupported hosts are explicitly called out as unsupported or preview
- end-to-end claims are limited to hosts in the supported matrix

