use async_trait::async_trait;

use crate::mask_secret_ref;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderBridgeMode {
    Off,
    Stub,
}

pub(crate) fn parse_provider_bridge_mode(raw: &str) -> ProviderBridgeMode {
    match raw.trim().to_lowercase().as_str() {
        "stub" => ProviderBridgeMode::Stub,
        _ => ProviderBridgeMode::Off,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedSecret {
    pub(crate) provider_name: &'static str,
    pub(crate) secret_ref_masked: String,
    pub(crate) secret_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderErrorCode {
    UnsupportedProvider,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderError {
    pub(crate) code: ProviderErrorCode,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ProviderHealth {
    pub(crate) mode: &'static str,
    pub(crate) provider: &'static str,
    pub(crate) configured: bool,
    pub(crate) ready: bool,
}

#[async_trait]
pub(crate) trait SecretProvider: Send + Sync {
    async fn resolve_for_use(&self, secret_ref: &str) -> Result<ResolvedSecret, ProviderError>;
    async fn health(&self) -> ProviderHealth;
}

#[derive(Debug, Default)]
pub(crate) struct StubBitwardenProvider;

#[async_trait]
impl SecretProvider for StubBitwardenProvider {
    async fn resolve_for_use(&self, secret_ref: &str) -> Result<ResolvedSecret, ProviderError> {
        match secret_ref {
            "bw://vault/item/login" => Ok(ResolvedSecret {
                provider_name: "bitwarden_stub",
                secret_ref_masked: mask_secret_ref(secret_ref),
                secret_bytes: b"stub-secret-material".to_vec(),
            }),
            value if !value.starts_with("bw://") => Err(ProviderError {
                code: ProviderErrorCode::UnsupportedProvider,
                message: "Unsupported provider ref",
            }),
            _ => Err(ProviderError {
                code: ProviderErrorCode::Unavailable,
                message: "Provider could not resolve the requested secret",
            }),
        }
    }

    async fn health(&self) -> ProviderHealth {
        ProviderHealth {
            mode: "stub",
            provider: "bitwarden_stub",
            configured: true,
            ready: true,
        }
    }
}

pub(crate) enum ProviderRuntime {
    Off,
    Stub(StubBitwardenProvider),
}

impl ProviderRuntime {
    pub(crate) fn off() -> Self {
        Self::Off
    }

    pub(crate) fn stub() -> Self {
        Self::Stub(StubBitwardenProvider)
    }
}

#[async_trait]
impl SecretProvider for ProviderRuntime {
    async fn resolve_for_use(&self, secret_ref: &str) -> Result<ResolvedSecret, ProviderError> {
        match self {
            ProviderRuntime::Off => Err(ProviderError {
                code: ProviderErrorCode::Unavailable,
                message: "Provider bridge is disabled",
            }),
            ProviderRuntime::Stub(provider) => provider.resolve_for_use(secret_ref).await,
        }
    }

    async fn health(&self) -> ProviderHealth {
        match self {
            ProviderRuntime::Off => ProviderHealth {
                mode: "off",
                provider: "none",
                configured: false,
                ready: false,
            },
            ProviderRuntime::Stub(provider) => provider.health().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_provider_bridge_mode, ProviderBridgeMode, ProviderErrorCode, ProviderRuntime,
        SecretProvider,
    };

    #[tokio::test]
    async fn stub_runtime_resolves_known_bitwarden_ref() {
        let runtime = ProviderRuntime::stub();

        let resolved = runtime
            .resolve_for_use("bw://vault/item/login")
            .await
            .expect("resolved");

        assert_eq!(resolved.provider_name, "bitwarden_stub");
        assert_eq!(resolved.secret_ref_masked, "bw****in");
        assert!(!resolved.secret_bytes.is_empty());
    }

    #[tokio::test]
    async fn stub_runtime_rejects_unknown_ref_without_plaintext() {
        let runtime = ProviderRuntime::stub();

        let err = runtime
            .resolve_for_use("bw://vault/item/missing")
            .await
            .expect_err("provider rejection");

        assert_eq!(err.code, ProviderErrorCode::Unavailable);
        assert!(!err.message.contains("missing"));
    }

    #[test]
    fn provider_mode_parser_handles_off_and_stub() {
        assert_eq!(parse_provider_bridge_mode("off"), ProviderBridgeMode::Off);
        assert_eq!(parse_provider_bridge_mode("stub"), ProviderBridgeMode::Stub);
        assert_eq!(
            parse_provider_bridge_mode("anything-else"),
            ProviderBridgeMode::Off
        );
    }
}
