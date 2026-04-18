# V3 Loop 0 Trusted Input Surface

Goal: introduce a trusted input path so supported host flows never need plaintext secret entry inside agent-visible chat or task memory.

Scope:
- secure input widget or trusted entry channel for supported hosts
- opaque ref issuance flow from trusted input to broker/provider boundary
- supported-host documentation and migration guidance away from raw secret text entry
- broker-side contract needed to accept trusted input output as opaque refs

Out of scope:
- universal UX polish
- unsupported host environments
- transcript redaction beyond the trusted input flow itself

Implementation order:

1. Trusted input contract
- define the trusted input session model and one-time completion flow
- define how a trusted input surface turns entered secret material into an opaque ref without exposing plaintext to the agent runtime
- document the roles of host, broker, and trusted provider boundary
- add sequence diagrams and threat notes for supported hosts

2. Broker-side support
- add any broker endpoints or issuance hooks needed to create and complete trusted input sessions
- ensure completion responses return only opaque refs and masked metadata
- add expiry, one-time-use, and audit behavior for trusted input sessions

3. Host-path migration and testing
- document migration away from raw text entry for supported hosts
- add E2E transcript-capture coverage proving supported host flows avoid plaintext ingress
- add negative tests showing unsupported raw-input paths are still out of contract

Verification:
- trusted input session tests
- E2E tests with transcript capture across supported host flows
- docs review for supported-host contract accuracy

Acceptance:
- supported host flow never requires plaintext entry into the agent transcript
- trusted input completion returns opaque refs only
- migration path away from raw text entry is documented for supported hosts

