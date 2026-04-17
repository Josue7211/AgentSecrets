# V2 Loop 1 Secret Ingress Lockdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block raw secret ingestion into `POST /v1/requests` by default so the broker only accepts opaque secret references, rejects suspicious plaintext-like inputs without echoing them, and records those rejections in audit.

**Architecture:** Keep the request contract narrow at the broker boundary. Add one focused validation layer in `src/policy.rs`, call it from `src/handlers/requests.rs` before any request insert, and record ingress rejection through the existing audit chain with redacted details only. Verify the behavior with both unit tests for heuristics and integration tests for HTTP responses and audit visibility.

**Tech Stack:** Rust, Axum, SQLx, Tokio, serde_json

---

## File Structure

- Modify: `src/policy.rs`
- Modify: `src/handlers/requests.rs`
- Modify: `src/lib.rs`
- Modify: `README.md`
- Modify: `docs/INTEGRATION.md`
- Modify: `docs/OPENCLAW.md`

## Task 1: Add Secret Ref Validation Heuristics

**Files:**
- Modify: `src/policy.rs`

- [ ] **Step 1: Write the failing unit tests for allowed opaque refs and rejected plaintext-like values**

Add these tests at the bottom of `src/policy.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::{classify_secret_ref, SecretRefValidation};

    #[test]
    fn accepts_bitwarden_opaque_refs() {
        assert_eq!(
            classify_secret_ref("bw://vault/item/login"),
            SecretRefValidation::Accepted
        );
    }

    #[test]
    fn rejects_plaintext_password_like_values() {
        assert_eq!(
            classify_secret_ref("Sup3rSecret!"),
            SecretRefValidation::RejectedPlaintextLike
        );
    }

    #[test]
    fn rejects_non_opaque_malformed_values() {
        assert_eq!(
            classify_secret_ref("vault/item/login"),
            SecretRefValidation::RejectedMalformed
        );
    }
}
```

- [ ] **Step 2: Run the unit tests to verify they fail**

Run:

```bash
cargo test policy::tests -- --nocapture
```

Expected:
- FAIL because `classify_secret_ref` and `SecretRefValidation` do not exist yet

- [ ] **Step 3: Add the minimal validation types and classifier**

Add this code to `src/policy.rs` after `requires_approval`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretRefValidation {
    Accepted,
    RejectedPlaintextLike,
    RejectedMalformed,
}

pub(crate) fn classify_secret_ref(secret_ref: &str) -> SecretRefValidation {
    let value = secret_ref.trim();

    if value.starts_with("bw://") {
        let rest = &value["bw://".len()..];
        if !rest.is_empty()
            && rest.contains('/')
            && !rest.starts_with('/')
            && !rest.ends_with('/')
            && !rest.contains(char::is_whitespace)
        {
            return SecretRefValidation::Accepted;
        }
        return SecretRefValidation::RejectedMalformed;
    }

    if looks_like_plaintext_secret(value) {
        return SecretRefValidation::RejectedPlaintextLike;
    }

    SecretRefValidation::RejectedMalformed
}

fn looks_like_plaintext_secret(value: &str) -> bool {
    if value.len() < 8 || value.len() > 256 {
        return false;
    }
    if value.contains("://") || value.contains('/') || value.contains(char::is_whitespace) {
        return false;
    }

    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_symbol = value.chars().any(|c| !c.is_ascii_alphanumeric());

    (has_lower && has_upper && has_digit) || (has_lower && has_digit && has_symbol)
}
```

- [ ] **Step 4: Run the unit tests to verify they pass**

Run:

```bash
cargo test policy::tests -- --nocapture
```

Expected:
- PASS for all three new tests

- [ ] **Step 5: Commit the policy validation layer**

Run:

```bash
git add src/policy.rs
git commit -m "feat: classify opaque secret refs"
```

Expected:
- a commit exists containing only the new secret-ref classifier and unit tests

## Task 2: Enforce Opaque Refs At Request Creation

**Files:**
- Modify: `src/handlers/requests.rs`
- Modify: `src/policy.rs`

- [ ] **Step 1: Write the failing integration tests for plaintext and malformed ingress rejection**

Add these tests to the existing test module in `src/lib.rs` near the other request tests:

```rust
#[tokio::test]
async fn request_rejects_plaintext_secret_ref() -> anyhow::Result<()> {
    let (app, cfg) = setup_app().await?;
    let leaked_secret = "Sup3rSecret!";

    let req = Request::builder()
        .method("POST")
        .uri("/v1/requests")
        .header("content-type", "application/json")
        .header("x-api-key", &cfg.client_api_key)
        .body(Body::from(
            json!({
                "request_type": "password_fill",
                "secret_ref": leaked_secret,
                "action": "password_fill",
                "target": "https://example.com/login",
                "reason": "login automation"
            })
            .to_string(),
        ))?;

    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = json_response(resp).await;
    assert_eq!(body["code"], "raw_secret_rejected");
    assert!(!body.to_string().contains(leaked_secret));
    Ok(())
}

#[tokio::test]
async fn request_rejects_malformed_non_opaque_secret_ref() -> anyhow::Result<()> {
    let (app, cfg) = setup_app().await?;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/requests")
        .header("content-type", "application/json")
        .header("x-api-key", &cfg.client_api_key)
        .body(Body::from(
            json!({
                "request_type": "password_fill",
                "secret_ref": "vault/item/login",
                "action": "password_fill",
                "target": "https://example.com/login",
                "reason": "login automation"
            })
            .to_string(),
        ))?;

    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = json_response(resp).await;
    assert_eq!(body["code"], "invalid_secret_ref");
    Ok(())
}
```

- [ ] **Step 2: Run the integration tests to verify they fail**

Run:

```bash
cargo test request_rejects_plaintext_secret_ref request_rejects_malformed_non_opaque_secret_ref -- --nocapture
```

Expected:
- FAIL because the handler still accepts these inputs today

- [ ] **Step 3: Enforce the classifier in the request handler**

Change the `src/handlers/requests.rs` imports to include the classifier:

```rust
use crate::policy::{
    classify_secret_ref, contains_illegal_chars, is_valid_status_filter, requires_approval,
    target_allowed, SecretRefValidation,
};
```

Then replace the current `secret_ref` validation block in `create_request`:

```rust
if secret_ref.is_empty() || secret_ref.len() > 256 || contains_illegal_chars(secret_ref) {
    return Err(err(
        StatusCode::BAD_REQUEST,
        "invalid_secret_ref",
        "Invalid secret_ref",
    ));
}
```

with:

```rust
if secret_ref.is_empty() || secret_ref.len() > 256 || contains_illegal_chars(secret_ref) {
    return Err(err(
        StatusCode::BAD_REQUEST,
        "invalid_secret_ref",
        "Invalid secret_ref",
    ));
}

match classify_secret_ref(secret_ref) {
    SecretRefValidation::Accepted => {}
    SecretRefValidation::RejectedPlaintextLike => {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.ingress_rejected",
            None,
            &json!({
                "reason": "raw_secret_rejected",
                "request_type": request_type,
                "action": action,
                "target": target,
            }),
        )
        .await;

        return Err(err(
            StatusCode::BAD_REQUEST,
            "raw_secret_rejected",
            "Plaintext secret values are not accepted; use an opaque secret_ref",
        ));
    }
    SecretRefValidation::RejectedMalformed => {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.ingress_rejected",
            None,
            &json!({
                "reason": "invalid_secret_ref",
                "request_type": request_type,
                "action": action,
                "target": target,
            }),
        )
        .await;

        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_secret_ref",
            "Invalid secret_ref",
        ));
    }
}
```

- [ ] **Step 4: Run the integration tests to verify they pass**

Run:

```bash
cargo test request_rejects_plaintext_secret_ref request_rejects_malformed_non_opaque_secret_ref -- --nocapture
```

Expected:
- PASS for both tests
- the plaintext-like input is rejected with `raw_secret_rejected`
- the malformed non-opaque input is rejected with `invalid_secret_ref`

- [ ] **Step 5: Commit request ingress enforcement**

Run:

```bash
git add src/handlers/requests.rs src/policy.rs src/lib.rs
git commit -m "feat: reject raw secret ingress"
```

Expected:
- a commit exists containing request-handler enforcement and the first integration tests

## Task 3: Prove Audit Visibility Without Secret Echo

**Files:**
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing audit regression test**

Add this test to the `src/lib.rs` test module:

```rust
#[tokio::test]
async fn ingress_rejection_is_audited_without_echoing_secret() -> anyhow::Result<()> {
    let (app, cfg) = setup_app().await?;
    let leaked_secret = "Sup3rSecret!";

    let create_req = Request::builder()
        .method("POST")
        .uri("/v1/requests")
        .header("content-type", "application/json")
        .header("x-api-key", &cfg.client_api_key)
        .body(Body::from(
            json!({
                "request_type": "password_fill",
                "secret_ref": leaked_secret,
                "action": "password_fill",
                "target": "https://example.com/login",
                "reason": "login automation"
            })
            .to_string(),
        ))?;

    let create_resp = app.clone().oneshot(create_req).await?;
    assert_eq!(create_resp.status(), StatusCode::BAD_REQUEST);

    let audit_req = Request::builder()
        .method("GET")
        .uri("/v1/audit?limit=20")
        .header("x-api-key", &cfg.approver_api_key)
        .body(Body::empty())?;
    let audit_resp = app.clone().oneshot(audit_req).await?;
    assert_eq!(audit_resp.status(), StatusCode::OK);

    let audit_json = json_response(audit_resp).await;
    let rows = audit_json["data"].as_array().expect("audit rows");
    let item = rows
        .iter()
        .find(|row| row["action"] == "request.ingress_rejected")
        .expect("ingress rejection audit row");

    assert_eq!(item["details"]["reason"], "raw_secret_rejected");
    assert!(!item.to_string().contains(leaked_secret));
    Ok(())
}
```

- [ ] **Step 2: Run the audit regression test to verify it fails if audit shape is missing**

Run:

```bash
cargo test ingress_rejection_is_audited_without_echoing_secret -- --nocapture
```

Expected:
- FAIL until the handler emits the new `request.ingress_rejected` audit event shape

- [ ] **Step 3: Verify the existing audit list shape exposes the sanitized event**

Do not add a new endpoint. The existing `GET /v1/audit` response should already be sufficient. If the test shows the event is missing, keep the `append_audit` call from Task 2 exactly as shown and do not include `secret_ref` in the audit details.

- [ ] **Step 4: Run the audit regression test to verify it passes**

Run:

```bash
cargo test ingress_rejection_is_audited_without_echoing_secret -- --nocapture
```

Expected:
- PASS
- the audit row exists
- the secret string does not appear in the serialized audit payload

- [ ] **Step 5: Commit the audit regression coverage**

Run:

```bash
git add src/lib.rs
git commit -m "test: cover ingress rejection audit redaction"
```

Expected:
- a commit exists containing only the new audit regression test or any minimal fix it required

## Task 4: Update The Integration Contract Docs

**Files:**
- Modify: `README.md`
- Modify: `docs/INTEGRATION.md`
- Modify: `docs/OPENCLAW.md`

- [ ] **Step 1: Add explicit Loop 1 contract language to the README**

In `README.md`, update the request-contract language so it says opaque refs are enforced instead of merely intended. Use this wording in the most relevant request-flow section:

```markdown
- `secret_ref` must be an opaque identifier such as `bw://vault/item/login`.
- Plaintext secret values are rejected at request creation.
- Rejected ingress attempts are audited without echoing the submitted secret content.
```

- [ ] **Step 2: Tighten the integration guidance for host apps**

In `docs/INTEGRATION.md`, replace any soft language about opaque refs with this stricter contract block:

```markdown
## Secret ingress contract

- Send opaque secret references only, for example `bw://vault/item/login`.
- Do not send plaintext passwords or recovery codes to `POST /v1/requests`.
- Treat `raw_secret_rejected` as a hard integration error that must be fixed in the caller.
```

- [ ] **Step 3: Tighten the OpenClaw host guidance the same way**

In `docs/OPENCLAW.md`, add or replace the host-contract bullets with:

```markdown
- Never send raw secret values to the broker.
- Use opaque refs such as `bw://...` only.
- If the broker returns `raw_secret_rejected`, the host flow is violating the trusted-boundary contract.
```

- [ ] **Step 4: Re-read the edited docs to verify the contract is now enforce-language, not aspirational-language**

Run:

```bash
sed -n '1,220p' README.md
sed -n '1,220p' docs/INTEGRATION.md
sed -n '1,220p' docs/OPENCLAW.md
```

Expected:
- all three docs describe opaque refs as the current enforced contract
- at least one doc mentions `raw_secret_rejected`
- no edited doc tells integrators they may send plaintext into `secret_ref`

- [ ] **Step 5: Commit the Loop 1 contract docs**

Run:

```bash
git add README.md docs/INTEGRATION.md docs/OPENCLAW.md
git commit -m "docs: document opaque secret ingress contract"
```

Expected:
- a commit exists containing only the Loop 1 contract-doc updates

## Task 5: Run The Loop 1 Verification Sweep

**Files:**
- Modify: none

- [ ] **Step 1: Run the unit and targeted integration tests together**

Run:

```bash
cargo test policy::tests request_rejects_plaintext_secret_ref request_rejects_malformed_non_opaque_secret_ref ingress_rejection_is_audited_without_echoing_secret -- --nocapture
```

Expected:
- PASS for the policy tests
- PASS for the bad-ingress integration tests
- PASS for the audit redaction regression test

- [ ] **Step 2: Run the full test suite**

Run:

```bash
cargo test
```

Expected:
- PASS with no regressions in the existing request, approval, execution, and audit flows

- [ ] **Step 3: Run formatting and lint verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Expected:
- PASS for both commands

- [ ] **Step 4: Review the final diff against Loop 1 acceptance criteria**

Run:

```bash
git diff --stat HEAD~4..HEAD
git diff -- src/policy.rs src/handlers/requests.rs src/lib.rs README.md docs/INTEGRATION.md docs/OPENCLAW.md
```

Expected:
- the diff shows opaque-ref-only enforcement
- the diff shows ingress-rejection audit logging without `secret_ref`
- the diff shows docs aligned with the enforced contract

- [ ] **Step 5: Commit any final mechanical fixes**

Run:

```bash
git add src/policy.rs src/handlers/requests.rs src/lib.rs README.md docs/INTEGRATION.md docs/OPENCLAW.md
git commit -m "chore: finish loop 1 verification sweep"
```

Expected:
- either no-op because the tree is already clean, or a final small commit for formatting or lint fixes only

## Self-Review

- Spec coverage: this plan covers the Loop 1 roadmap requirements for opaque-ref-only request validation, rejection heuristics, rejection audit visibility, and contract docs.
- Placeholder scan: no `TODO`, `TBD`, or “appropriate validation” placeholders remain.
- Type consistency: the plan consistently uses `classify_secret_ref`, `SecretRefValidation`, `raw_secret_rejected`, and `request.ingress_rejected`.
