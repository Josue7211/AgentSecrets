use crate::{BrokerMode, Config};

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
