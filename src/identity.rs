use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::Config;

const HDR_RUNTIME_ID: &str = "x-secret-broker-runtime-id";
const HDR_HOST_ID: &str = "x-secret-broker-host-id";
const HDR_ADAPTER_ID: &str = "x-secret-broker-adapter-id";
const HDR_TS: &str = "x-secret-broker-attestation-ts";
const HDR_SIG: &str = "x-secret-broker-attestation-sig";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityVerificationMode {
    Off,
    Stub,
}

pub(crate) fn parse_identity_verification_mode(raw: &str) -> IdentityVerificationMode {
    match raw.trim().to_lowercase().as_str() {
        "stub" => IdentityVerificationMode::Stub,
        _ => IdentityVerificationMode::Off,
    }
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
        },
        signature,
    ))
}

pub(crate) fn verify_headers(
    cfg: &Config,
    headers: &HeaderMap,
    expected: IdentityExpectations<'_>,
    now_unix: i64,
) -> Result<Option<IdentitySummary>, IdentityError> {
    match cfg.identity_verification_mode {
        IdentityVerificationMode::Off => Ok(None),
        IdentityVerificationMode::Stub => {
            if cfg.identity_attestation_key.is_empty() {
                return Err(IdentityError {
                    code: "invalid_identity",
                    message: "Identity attestation key is not configured",
                });
            }

            let (claims, signature) = read_claims(headers)?;
            let expected_adapter = adapter_id_for_action(expected.action);
            if expected_adapter == "unsupported" || claims.adapter_id != expected_adapter {
                return Err(IdentityError {
                    code: "identity_mismatch",
                    message: "Identity adapter claim does not match the requested action",
                });
            }

            if now_unix - claims.timestamp > cfg.identity_attestation_max_age_seconds
                || claims.timestamp - now_unix > cfg.identity_attestation_max_age_seconds
            {
                return Err(IdentityError {
                    code: "invalid_identity",
                    message: "Identity attestation is stale",
                });
            }

            if !cfg.trusted_runtime_ids.is_empty()
                && !cfg.trusted_runtime_ids.contains(&claims.runtime_id)
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
                mode: "stub".to_string(),
                runtime_id: claims.runtime_id,
                host_id: claims.host_id,
                adapter_id: claims.adapter_id,
                verified_at: chrono::Utc::now().to_rfc3339(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        adapter_id_for_action, parse_identity_verification_mode, sign_identity_claim,
        IdentityVerificationMode,
    };

    #[test]
    fn identity_mode_parser_handles_off_and_stub() {
        assert_eq!(
            parse_identity_verification_mode("off"),
            IdentityVerificationMode::Off
        );
        assert_eq!(
            parse_identity_verification_mode("stub"),
            IdentityVerificationMode::Stub
        );
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
}
