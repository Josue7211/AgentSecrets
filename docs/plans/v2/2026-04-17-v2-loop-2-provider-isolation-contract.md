# V2 Loop 2 Provider Isolation Contract

Goal: add a trusted-side provider boundary for `bw://...` refs without exposing plaintext or provider credentials to untrusted clients.

Scope:
- add `src/provider.rs` for provider types and runtime
- wire provider mode into config and app state
- make `/v1/execute` do provider preflight before masked execution
- expose provider status in `/healthz`
- update docs to say stub bridge exists, not full production Bitwarden mediation

Out of scope:
- browser fill
- signing adapters
- real production Bitwarden integration
- anything from Loop 3

Implementation order:

1. Provider contract
- add `ProviderBridgeMode`
- add `ProviderRuntime`
- add `SecretProvider` trait
- add stub Bitwarden provider for known test refs only
- add unit tests for resolve success, masked failure, and mode parsing

2. Runtime wiring
- add provider mode to `Config`
- add provider runtime to `AppState`
- support `SECRET_BROKER_PROVIDER_BRIDGE_MODE=off|stub`
- extend test harness with `setup_app_with_provider_mode(...)`

3. Execute preflight
- fetch `secret_ref` in `/v1/execute`
- call provider runtime before execution result is written
- on provider failure, return masked `provider_*` error and audit it
- on provider success, include only masked provider summary in the response

4. Health and docs
- include provider state in `/healthz`
- update README and docs to reflect Loop 2 truth

Verification:
- `cargo test provider::tests -- --nocapture`
- `cargo test health_reports_provider_bridge_mode -- --nocapture`
- `cargo test execute_uses_stub_provider_without_leaking_plaintext -- --nocapture`
- `cargo test execute_masks_provider_failures_and_keeps_request_unexecuted -- --nocapture`
- `cargo test -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`

Acceptance:
- untrusted clients still never receive plaintext
- provider failures are masked
- provider state is visible in health
- docs do not claim full Bitwarden mediation
