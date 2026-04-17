# V2 Loop 3 Execution Adapter Containment

Goal: move from masked-only broker results to one trusted-side secret-consumption path that never exposes plaintext to untrusted clients.

Scope:
- add `src/adapter.rs` for execution adapter types, runtime, and error model
- wire adapter mode into config and app state
- make `/v1/execute` dispatch one sanctioned trusted adapter path after provider resolution
- keep adapter outputs masked and context-bound
- add adapter audit events and docs describing containment boundaries

Out of scope:
- real browser automation
- multiple production adapters
- host-side UX work
- anything from V3 transcript-safe host support

Implementation order:

1. Execution adapter contract
- add `ExecutionAdapterMode`
- add `ExecutionAdapterRuntime`
- add `TrustedExecutionAdapter` trait
- add masked adapter result and masked adapter error types
- add one stub `password_fill` adapter that consumes provider-resolved secret bytes but never returns them

2. Runtime wiring
- add `SECRET_BROKER_EXECUTION_ADAPTER_MODE=off|stub`
- add adapter runtime to `Config` and `AppState`
- expose adapter health alongside provider health
- extend the test harness with `setup_app_with_adapter_mode(...)`

3. Execute dispatch and fail-closed semantics
- require the trusted adapter path to run only for explicitly supported actions
- bind adapter selection to request action and target context
- fail closed on unsupported action, target drift, or adapter runtime failure
- return only masked adapter summaries in `/v1/execute`
- append adapter success and failure audit events without plaintext

4. Docs and containment notes
- update README and architecture/security docs to say one trusted execution adapter path exists in stub form
- add containment notes explaining that secret bytes stay inside the trusted adapter boundary
- keep docs explicit that browser fill and host transcript safety still belong to later loops

Verification:
- `cargo test adapter::tests -- --nocapture`
- `cargo test execute_uses_stub_adapter_without_leaking_plaintext -- --nocapture`
- `cargo test execute_rejects_unsupported_adapter_actions -- --nocapture`
- `cargo test execute_rejects_adapter_target_mismatch -- --nocapture`
- `cargo test -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`

Acceptance:
- at least one sanctioned secret-use flow completes without exposing plaintext to agent-visible surfaces
- execution results remain masked and request-context-bound
- adapter misuse attempts fail closed and leave auditable evidence

