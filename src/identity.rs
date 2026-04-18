use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;

use crate::Config;

const HDR_RUNTIME_ID: &str = "x-secret-broker-runtime-id";
const HDR_HOST_ID: &str = "x-secret-broker-host-id";
const HDR_ADAPTER_ID: &str = "x-secret-broker-adapter-id";
const HDR_TS: &str = "x-secret-broker-attestation-ts";
const HDR_ATTESTATION_ID: &str = "x-secret-broker-attestation-id";
const HDR_SIG: &str = "x-secret-broker-attestation-sig";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityVerificationMode {
    Off,
    Stub,
    HostSigned,
    HardwareBacked,
}

impl FromStr for IdentityVerificationMode {
    type Err = &'static str;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_lowercase().as_str() {
            "off" => Ok(IdentityVerificationMode::Off),
            "stub" => Ok(IdentityVerificationMode::Stub),
            "host-signed" => Ok(IdentityVerificationMode::HostSigned),
            "hardware-backed" => Ok(IdentityVerificationMode::HardwareBacked),
            _ => Err("Invalid identity verification mode"),
        }
    }
}

pub(crate) fn parse_identity_verification_mode(
    raw: &str,
) -> Result<IdentityVerificationMode, &'static str> {
    raw.parse()
}

impl IdentityVerificationMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            IdentityVerificationMode::Off => "off",
            IdentityVerificationMode::Stub => "stub",
            IdentityVerificationMode::HostSigned => "host-signed",
            IdentityVerificationMode::HardwareBacked => "hardware-backed",
        }
    }

    pub(crate) fn strength_rank(self) -> u8 {
        match self {
            IdentityVerificationMode::Off => 0,
            IdentityVerificationMode::Stub => 1,
            IdentityVerificationMode::HostSigned => 2,
            IdentityVerificationMode::HardwareBacked => 3,
        }
    }
}

pub(crate) type IdentityReplayCache = Arc<Mutex<HashMap<String, i64>>>;

pub(crate) fn new_replay_cache() -> IdentityReplayCache {
    Arc::new(Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct IdentityHealth {
    pub(crate) mode: &'static str,
    pub(crate) configured: bool,
    pub(crate) ready: bool,
    pub(crate) max_age_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IdentitySummary {
    pub(crate) status: String,
    pub(crate) mode: String,
    pub(crate) runtime_id: String,
    pub(crate) host_id: String,
    pub(crate) adapter_id: String,
    pub(crate) verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityExpectations<'a> {
    pub(crate) action: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityClaims {
    runtime_id: String,
    host_id: String,
    adapter_id: String,
    timestamp: i64,
    attestation_id: Option<String>,
}

pub(crate) fn health(cfg: &Config) -> IdentityHealth {
    match cfg.identity_verification_mode {
        IdentityVerificationMode::Off => IdentityHealth {
            mode: "off",
            configured: false,
            ready: false,
            max_age_seconds: cfg.identity_attestation_max_age_seconds,
        },
        IdentityVerificationMode::Stub => IdentityHealth {
            mode: "stub",
            configured: !cfg.identity_attestation_key.is_empty(),
            ready: !cfg.identity_attestation_key.is_empty(),
            max_age_seconds: cfg.identity_attestation_max_age_seconds,
        },
        IdentityVerificationMode::HostSigned => IdentityHealth {
            mode: "host-signed",
            configured: !cfg.identity_host_signing_keys.is_empty()
                && !cfg.trusted_host_runtime_pairs.is_empty(),
            ready: !cfg.identity_host_signing_keys.is_empty()
                && !cfg.trusted_host_runtime_pairs.is_empty(),
            max_age_seconds: cfg.identity_attestation_max_age_seconds,
        },
        IdentityVerificationMode::HardwareBacked => IdentityHealth {
            mode: "hardware-backed",
            configured: false,
            ready: false,
            max_age_seconds: cfg.identity_attestation_max_age_seconds,
        },
    }
}

pub(crate) fn configured_mode_for_host(
    cfg: &Config,
    host_id: Option<&str>,
) -> IdentityVerificationMode {
    let required_mode = host_id
        .and_then(|host_id| cfg.required_host_identity_modes.get(host_id).copied())
        .unwrap_or(IdentityVerificationMode::Off);

    if cfg.identity_verification_mode.strength_rank() >= required_mode.strength_rank() {
        cfg.identity_verification_mode
    } else {
        required_mode
    }
}

pub(crate) fn adapter_id_for_action(action: &str) -> &'static str {
    match action {
        "password_fill" => "password_fill_stub",
        "request_sign" => "request_sign_stub",
        "credential_handoff" => "credential_handoff_stub",
        _ => "unsupported",
    }
}

pub(crate) fn sign_identity_claim(
    key: &str,
    runtime_id: &str,
    host_id: &str,
    adapter_id: &str,
    timestamp: i64,
) -> String {
    let canonical = format!("{runtime_id}|{host_id}|{adapter_id}|{timestamp}|{key}");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn sign_host_identity_claim(
    host_key: &str,
    runtime_id: &str,
    host_id: &str,
    adapter_id: &str,
    timestamp: i64,
    attestation_id: &str,
) -> String {
    let canonical =
        format!("{runtime_id}|{host_id}|{adapter_id}|{timestamp}|{attestation_id}|{host_key}");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn read_header(headers: &HeaderMap, name: &str) -> Result<String, IdentityError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or(IdentityError {
            code: "invalid_identity",
            message: "Missing identity attestation header",
        })
}

fn read_claims(headers: &HeaderMap) -> Result<(IdentityClaims, String), IdentityError> {
    let runtime_id = read_header(headers, HDR_RUNTIME_ID)?;
    let host_id = read_header(headers, HDR_HOST_ID)?;
    let adapter_id = read_header(headers, HDR_ADAPTER_ID)?;
    let timestamp = read_header(headers, HDR_TS)?
        .parse::<i64>()
        .map_err(|_| IdentityError {
            code: "invalid_identity",
            message: "Invalid identity attestation timestamp",
        })?;
    let signature = read_header(headers, HDR_SIG)?;

    Ok((
        IdentityClaims {
            runtime_id,
            host_id,
            adapter_id,
            timestamp,
            attestation_id: headers
                .get(HDR_ATTESTATION_ID)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
        },
        signature,
    ))
}

fn ensure_expected_adapter(
    claims: &IdentityClaims,
    expected: IdentityExpectations<'_>,
) -> Result<(), IdentityError> {
    let expected_adapter = adapter_id_for_action(expected.action);
    if expected_adapter == "unsupported" || claims.adapter_id != expected_adapter {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Identity adapter claim does not match the requested action",
        });
    }
    Ok(())
}

fn ensure_fresh_timestamp(
    cfg: &Config,
    claims: &IdentityClaims,
    now_unix: i64,
) -> Result<(), IdentityError> {
    if now_unix - claims.timestamp > cfg.identity_attestation_max_age_seconds
        || claims.timestamp - now_unix > cfg.identity_attestation_max_age_seconds
    {
        return Err(IdentityError {
            code: "invalid_identity",
            message: "Identity attestation is stale",
        });
    }
    Ok(())
}

fn verify_stub_headers(
    cfg: &Config,
    headers: &HeaderMap,
    expected: IdentityExpectations<'_>,
    now_unix: i64,
) -> Result<Option<IdentitySummary>, IdentityError> {
    if cfg.identity_attestation_key.is_empty() {
        return Err(IdentityError {
            code: "invalid_identity",
            message: "Identity attestation key is not configured",
        });
    }

    let (claims, signature) = read_claims(headers)?;
    ensure_expected_adapter(&claims, expected)?;
    ensure_fresh_timestamp(cfg, &claims, now_unix)?;

    if !cfg.trusted_runtime_ids.is_empty() && !cfg.trusted_runtime_ids.contains(&claims.runtime_id)
    {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Runtime identity is not in the trusted set",
        });
    }
    if !cfg.trusted_host_ids.is_empty() && !cfg.trusted_host_ids.contains(&claims.host_id) {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Host identity is not in the trusted set",
        });
    }

    let expected_sig = sign_identity_claim(
        &cfg.identity_attestation_key,
        &claims.runtime_id,
        &claims.host_id,
        &claims.adapter_id,
        claims.timestamp,
    );
    if expected_sig
        .as_bytes()
        .ct_eq(signature.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(IdentityError {
            code: "invalid_identity",
            message: "Identity attestation signature is invalid",
        });
    }

    Ok(Some(IdentitySummary {
        status: "verified".to_string(),
        mode: IdentityVerificationMode::Stub.as_str().to_string(),
        runtime_id: claims.runtime_id,
        host_id: claims.host_id,
        adapter_id: claims.adapter_id,
        verified_at: chrono::Utc::now().to_rfc3339(),
    }))
}

fn record_host_signed_envelope(
    replay_cache: &IdentityReplayCache,
    host_id: &str,
    attestation_id: &str,
    now_unix: i64,
    max_age_seconds: i64,
) -> Result<(), IdentityError> {
    let cache_key = format!("{host_id}:{attestation_id}");
    let mut guard = replay_cache.lock().map_err(|_| IdentityError {
        code: "invalid_identity",
        message: "Identity replay cache is unavailable",
    })?;
    guard.retain(|_, seen_at| now_unix - *seen_at <= max_age_seconds);
    if guard.contains_key(&cache_key) {
        return Err(IdentityError {
            code: "replayed_identity",
            message: "Identity attestation envelope has already been used",
        });
    }
    guard.insert(cache_key, now_unix);
    Ok(())
}

fn verify_host_signed_headers(
    cfg: &Config,
    headers: &HeaderMap,
    expected: IdentityExpectations<'_>,
    now_unix: i64,
    replay_cache: &IdentityReplayCache,
) -> Result<Option<IdentitySummary>, IdentityError> {
    if cfg.identity_host_signing_keys.is_empty() || cfg.trusted_host_runtime_pairs.is_empty() {
        return Err(IdentityError {
            code: "invalid_identity",
            message: "Host-signed identity is not configured",
        });
    }

    let (claims, signature) = read_claims(headers)?;
    ensure_expected_adapter(&claims, expected)?;
    ensure_fresh_timestamp(cfg, &claims, now_unix)?;

    let Some(attestation_id) = claims.attestation_id.clone() else {
        return Err(IdentityError {
            code: "invalid_identity",
            message: "Missing identity attestation header",
        });
    };
    let Some(host_key) = cfg.identity_host_signing_keys.get(&claims.host_id) else {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Host identity is not in the trusted host-signed set",
        });
    };
    let Some(allowed_runtimes) = cfg.trusted_host_runtime_pairs.get(&claims.host_id) else {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Host identity is not allowed for host-signed mode",
        });
    };
    if !allowed_runtimes.contains(&claims.runtime_id) {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Runtime identity is not allowed for the claimed host",
        });
    }

    let expected_sig = sign_host_identity_claim(
        host_key,
        &claims.runtime_id,
        &claims.host_id,
        &claims.adapter_id,
        claims.timestamp,
        &attestation_id,
    );
    if expected_sig
        .as_bytes()
        .ct_eq(signature.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(IdentityError {
            code: "invalid_identity",
            message: "Identity attestation signature is invalid",
        });
    }

    record_host_signed_envelope(
        replay_cache,
        &claims.host_id,
        &attestation_id,
        now_unix,
        cfg.identity_attestation_max_age_seconds,
    )?;

    Ok(Some(IdentitySummary {
        status: "verified".to_string(),
        mode: IdentityVerificationMode::HostSigned.as_str().to_string(),
        runtime_id: claims.runtime_id,
        host_id: claims.host_id,
        adapter_id: claims.adapter_id,
        verified_at: chrono::Utc::now().to_rfc3339(),
    }))
}

pub(crate) fn verify_headers(
    cfg: &Config,
    headers: &HeaderMap,
    expected: IdentityExpectations<'_>,
    now_unix: i64,
    replay_cache: &IdentityReplayCache,
) -> Result<Option<IdentitySummary>, IdentityError> {
    let claimed_host = headers
        .get(HDR_HOST_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match configured_mode_for_host(cfg, claimed_host) {
        IdentityVerificationMode::Off => Ok(None),
        IdentityVerificationMode::Stub => verify_stub_headers(cfg, headers, expected, now_unix),
        IdentityVerificationMode::HostSigned => {
            verify_host_signed_headers(cfg, headers, expected, now_unix, replay_cache)
        }
        IdentityVerificationMode::HardwareBacked => Err(IdentityError {
            code: "invalid_identity",
            message: "Hardware-backed identity is not implemented",
        }),
    }
}

pub(crate) fn approval_identity_guard(
    cfg: &Config,
    identity: Option<&IdentitySummary>,
) -> Result<(), IdentityError> {
    let Some(identity) = identity else {
        if cfg.identity_verification_mode.strength_rank()
            > IdentityVerificationMode::Off.strength_rank()
        {
            return Err(IdentityError {
                code: "identity_downgraded",
                message: "Stored request identity is below the required trust tier",
            });
        }
        return Ok(());
    };

    let stored_mode =
        parse_identity_verification_mode(&identity.mode).map_err(|_| IdentityError {
            code: "invalid_identity",
            message: "Stored request identity mode is invalid",
        })?;
    let required_mode = configured_mode_for_host(cfg, Some(&identity.host_id));

    if stored_mode.strength_rank() < required_mode.strength_rank()
        || required_mode.strength_rank() < stored_mode.strength_rank()
    {
        return Err(IdentityError {
            code: "identity_downgraded",
            message: "Stored request identity is below the required trust tier",
        });
    }

    Ok(())
}

pub(crate) fn execute_identity_guard(
    cfg: &Config,
    stored_identity: Option<&IdentitySummary>,
    current_identity: Option<&IdentitySummary>,
) -> Result<(), IdentityError> {
    let Some(stored_identity) = stored_identity else {
        if cfg.identity_verification_mode.strength_rank()
            > IdentityVerificationMode::Off.strength_rank()
        {
            return Err(IdentityError {
                code: "identity_downgraded",
                message: "Stored request identity is below the required trust tier",
            });
        }
        return Ok(());
    };

    approval_identity_guard(cfg, Some(stored_identity))?;
    let stored_mode =
        parse_identity_verification_mode(&stored_identity.mode).map_err(|_| IdentityError {
            code: "invalid_identity",
            message: "Stored request identity mode is invalid",
        })?;

    let Some(current_identity) = current_identity else {
        return Err(IdentityError {
            code: "identity_downgraded",
            message: "Current request identity is below the required trust tier",
        });
    };

    let current_mode =
        parse_identity_verification_mode(&current_identity.mode).map_err(|_| IdentityError {
            code: "invalid_identity",
            message: "Current request identity mode is invalid",
        })?;
    if current_mode.strength_rank() < stored_mode.strength_rank() {
        return Err(IdentityError {
            code: "identity_downgraded",
            message: "Current request identity is below the approved trust tier",
        });
    }

    if stored_identity.runtime_id != current_identity.runtime_id
        || stored_identity.host_id != current_identity.host_id
        || stored_identity.adapter_id != current_identity.adapter_id
    {
        return Err(IdentityError {
            code: "identity_mismatch",
            message: "Verified identity mismatch",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        adapter_id_for_action, parse_identity_verification_mode, sign_host_identity_claim,
        sign_identity_claim, IdentityVerificationMode,
    };

    #[test]
    fn identity_mode_parser_handles_known_tiers() {
        assert_eq!(
            parse_identity_verification_mode("off").expect("valid mode"),
            IdentityVerificationMode::Off
        );
        assert_eq!(
            parse_identity_verification_mode("stub").expect("valid mode"),
            IdentityVerificationMode::Stub
        );
        assert_eq!(
            parse_identity_verification_mode("host-signed").expect("valid mode"),
            IdentityVerificationMode::HostSigned
        );
        assert_eq!(
            parse_identity_verification_mode("hardware-backed").expect("valid mode"),
            IdentityVerificationMode::HardwareBacked
        );
    }

    #[test]
    fn identity_mode_parser_rejects_unknown_values() {
        assert!(parse_identity_verification_mode("typo-mode").is_err());
    }

    #[test]
    fn adapter_lookup_matches_known_actions() {
        assert_eq!(adapter_id_for_action("password_fill"), "password_fill_stub");
        assert_eq!(adapter_id_for_action("request_sign"), "request_sign_stub");
        assert_eq!(
            adapter_id_for_action("credential_handoff"),
            "credential_handoff_stub"
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let a = sign_identity_claim("key", "runtime", "host", "adapter", 123);
        let b = sign_identity_claim("key", "runtime", "host", "adapter", 123);
        assert_eq!(a, b);
    }

    #[test]
    fn host_signed_signing_is_deterministic() {
        let a = sign_host_identity_claim("host-key", "runtime", "host", "adapter", 123, "attest-1");
        let b = sign_host_identity_claim("host-key", "runtime", "host", "adapter", 123, "attest-1");
        assert_eq!(a, b);
    }
}
