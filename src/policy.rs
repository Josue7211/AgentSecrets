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
