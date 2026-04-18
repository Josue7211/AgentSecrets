use crate::{AuthRole, BrokerMode, Config};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PolicySummary {
    pub(crate) outcome: String,
    pub(crate) risk_score: i64,
    pub(crate) environment: String,
    pub(crate) reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyOutcome {
    Allow,
    Deny,
    RequireApproval,
    StepUp,
}

impl PolicyOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PolicyOutcome::Allow => "allow",
            PolicyOutcome::Deny => "deny",
            PolicyOutcome::RequireApproval => "require_approval",
            PolicyOutcome::StepUp => "step_up",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyEnvironment {
    TrustedLocal,
    Private,
    Public,
}

impl PolicyEnvironment {
    fn as_str(self) -> &'static str {
        match self {
            PolicyEnvironment::TrustedLocal => "trusted_local",
            PolicyEnvironment::Private => "private",
            PolicyEnvironment::Public => "public",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyInput<'a> {
    pub(crate) actor_role: AuthRole,
    pub(crate) action: &'a str,
    pub(crate) target: &'a str,
    pub(crate) amount_cents: Option<i64>,
}

pub(crate) fn parse_mode(raw: &str) -> BrokerMode {
    match raw.trim().to_lowercase().as_str() {
        "off" => BrokerMode::Off,
        "enforce" => BrokerMode::Enforce,
        _ => BrokerMode::Monitor,
    }
}

pub(crate) fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn contains_illegal_chars(v: &str) -> bool {
    v.contains('\n') || v.contains('\r') || v.contains('\0')
}

pub(crate) fn is_valid_status_filter(status: &str) -> bool {
    matches!(
        status,
        "pending_approval" | "approved" | "denied" | "expired" | "executed"
    )
}

pub(crate) fn target_allowed(cfg: &Config, target: &str) -> bool {
    if cfg.allowed_target_prefixes.is_empty() {
        return true;
    }
    cfg.allowed_target_prefixes
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

pub(crate) fn requires_approval(action: &str, amount_cents: Option<i64>) -> bool {
    if amount_cents.unwrap_or(0) > 0 {
        return true;
    }
    let a = action.to_lowercase();
    a.contains("payment")
        || a.contains("purchase")
        || a.contains("password")
        || a.contains("secret")
        || a.contains("credential")
        || a.contains("sign")
        || a.contains("handoff")
}

fn classify_environment(target: &str) -> PolicyEnvironment {
    if target.starts_with("handoff://local-helper/") {
        PolicyEnvironment::TrustedLocal
    } else if target.starts_with("http://127.0.0.1")
        || target.starts_with("http://localhost")
        || target.starts_with("https://127.0.0.1")
        || target.starts_with("https://localhost")
    {
        PolicyEnvironment::Private
    } else {
        PolicyEnvironment::Public
    }
}

pub(crate) fn evaluate_request_policy(_cfg: &Config, input: PolicyInput<'_>) -> PolicySummary {
    let action = input.action.to_lowercase();
    let environment = classify_environment(input.target);
    let mut risk_score = 0_i64;
    let mut reasons = Vec::new();

    match input.actor_role {
        AuthRole::Client => {
            risk_score += 10;
            reasons.push("client_actor".to_string());
        }
        AuthRole::Approver => reasons.push("approver_actor".to_string()),
    }

    if action.contains("export") || action.contains("reveal") || action.contains("copy_secret") {
        return PolicySummary {
            outcome: PolicyOutcome::Deny.as_str().to_string(),
            risk_score: 100,
            environment: environment.as_str().to_string(),
            reasons: vec!["secret_export_blocked".to_string()],
        };
    }

    if input.amount_cents.unwrap_or(0) > 0 {
        risk_score += 45;
        reasons.push("monetary_amount".to_string());
    }
    if action.contains("sign") {
        risk_score += 40;
        reasons.push("signing_action".to_string());
    }
    if action.contains("password") || action.contains("secret") {
        risk_score += 25;
        reasons.push("credential_use".to_string());
    }
    if action.contains("credential") || action.contains("handoff") {
        risk_score += 35;
        reasons.push("credential_handoff".to_string());
    }

    match environment {
        PolicyEnvironment::TrustedLocal => reasons.push("trusted_local_target".to_string()),
        PolicyEnvironment::Private => {
            risk_score += 10;
            reasons.push("private_target".to_string());
        }
        PolicyEnvironment::Public => {
            risk_score += 20;
            reasons.push("public_target".to_string());
        }
    }

    if reasons.is_empty() && requires_approval(input.action, input.amount_cents) {
        risk_score += 35;
        reasons.push("legacy_approval_trigger".to_string());
    }

    let outcome = if risk_score >= 80 {
        PolicyOutcome::Deny
    } else if risk_score >= 60 {
        PolicyOutcome::StepUp
    } else if risk_score >= 35 || requires_approval(input.action, input.amount_cents) {
        PolicyOutcome::RequireApproval
    } else {
        PolicyOutcome::Allow
    };

    PolicySummary {
        outcome: outcome.as_str().to_string(),
        risk_score,
        environment: environment.as_str().to_string(),
        reasons,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretRefValidation {
    Accepted,
    RejectedPlaintextLike,
    RejectedMalformed,
}

pub(crate) fn classify_secret_ref(secret_ref: &str) -> SecretRefValidation {
    let value = secret_ref.trim();

    if let Some(rest) = value.strip_prefix("bw://") {
        if !rest.is_empty()
            && rest.contains('/')
            && !rest.starts_with('/')
            && !rest.ends_with('/')
            && !rest.chars().any(|c| c.is_whitespace())
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
    if value.contains("://") || value.contains('/') || value.chars().any(|c| c.is_whitespace()) {
        return false;
    }

    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_symbol = value.chars().any(|c| !c.is_ascii_alphanumeric());

    has_lower && has_digit && (has_upper || has_symbol)
}

#[cfg(test)]
mod tests {
    use super::{classify_secret_ref, evaluate_request_policy, PolicyInput, SecretRefValidation};
    use crate::{AuthRole, Config};

    fn test_config() -> Config {
        Config {
            bind: "127.0.0.1:0".to_string(),
            db_url: "sqlite://policy-test.db?mode=memory".to_string(),
            mode: crate::BrokerMode::Enforce,
            provider_bridge_mode: crate::ProviderBridgeMode::Off,
            execution_adapter_mode: crate::adapter::ExecutionAdapterMode::Off,
            request_sign_adapter_url: String::new(),
            client_api_key: "test-client-key-123456".to_string(),
            approver_api_key: "test-approver-key-abcdef".to_string(),
            capability_ttl_seconds: 60,
            request_ttl_seconds: 3600,
            max_amount_cents: 2_000_000,
            allowed_target_prefixes: vec!["https://".to_string()],
            rate_limit_per_minute: 1000,
            identity_verification_mode: crate::identity::IdentityVerificationMode::Off,
            identity_attestation_key: String::new(),
            identity_attestation_max_age_seconds: 300,
            trusted_runtime_ids: Vec::new(),
            trusted_host_ids: Vec::new(),
            identity_host_signing_keys: std::collections::HashMap::new(),
            trusted_host_runtime_pairs: std::collections::HashMap::new(),
        }
    }

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

    #[test]
    fn policy_marks_public_request_sign_as_step_up() {
        let summary = evaluate_request_policy(
            &test_config(),
            PolicyInput {
                actor_role: AuthRole::Client,
                action: "request_sign",
                target: "https://example.com/sign",
                amount_cents: None,
            },
        );

        assert_eq!(summary.outcome, "step_up");
        assert_eq!(summary.environment, "public");
        assert!(summary.risk_score >= 60);
    }

    #[test]
    fn policy_blocks_secret_export_actions() {
        let summary = evaluate_request_policy(
            &test_config(),
            PolicyInput {
                actor_role: AuthRole::Client,
                action: "secret_export",
                target: "https://example.com/export",
                amount_cents: None,
            },
        );

        assert_eq!(summary.outcome, "deny");
        assert_eq!(summary.reasons, vec!["secret_export_blocked".to_string()]);
    }
}
