use async_trait::async_trait;

use crate::provider::ResolvedSecret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionAdapterMode {
    Off,
    Stub,
}

pub(crate) fn parse_execution_adapter_mode(raw: &str) -> ExecutionAdapterMode {
    match raw.trim().to_lowercase().as_str() {
        "stub" => ExecutionAdapterMode::Stub,
        _ => ExecutionAdapterMode::Off,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct AdapterHealth {
    pub(crate) mode: &'static str,
    pub(crate) adapter: &'static str,
    pub(crate) configured: bool,
    pub(crate) ready: bool,
    pub(crate) supported_actions: Vec<AdapterSupport>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct AdapterSupport {
    pub(crate) action: &'static str,
    pub(crate) adapter: &'static str,
    pub(crate) target_hint: &'static str,
    pub(crate) status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct MaskedAdapterResult {
    pub(crate) adapter: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) target: String,
    pub(crate) secret_ref_masked: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterErrorCode {
    Disabled,
    UnsupportedAction,
    TargetMismatch,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterError {
    pub(crate) code: AdapterErrorCode,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterRequest<'a> {
    pub(crate) action: &'a str,
    pub(crate) target: &'a str,
}

#[async_trait]
pub(crate) trait TrustedExecutionAdapter: Send + Sync {
    async fn execute(
        &self,
        request: AdapterRequest<'_>,
        resolved: ResolvedSecret,
    ) -> Result<MaskedAdapterResult, AdapterError>;
    async fn health(&self) -> AdapterHealth;
}

#[derive(Debug, Default)]
pub(crate) struct StubPasswordFillAdapter;

impl StubPasswordFillAdapter {
    fn target_supported(target: &str) -> bool {
        target.ends_with("/login")
    }
}

#[async_trait]
impl TrustedExecutionAdapter for StubPasswordFillAdapter {
    async fn execute(
        &self,
        request: AdapterRequest<'_>,
        resolved: ResolvedSecret,
    ) -> Result<MaskedAdapterResult, AdapterError> {
        if request.action != "password_fill" {
            return Err(AdapterError {
                code: AdapterErrorCode::UnsupportedAction,
                message: "Unsupported execution adapter action",
            });
        }

        if !Self::target_supported(request.target) {
            return Err(AdapterError {
                code: AdapterErrorCode::TargetMismatch,
                message: "Execution adapter target mismatch",
            });
        }

        if resolved.secret_bytes.is_empty() {
            return Err(AdapterError {
                code: AdapterErrorCode::Unavailable,
                message: "Execution adapter is unavailable",
            });
        }

        Ok(MaskedAdapterResult {
            adapter: "password_fill_stub",
            outcome: "filled",
            target: request.target.to_string(),
            secret_ref_masked: resolved.secret_ref_masked,
        })
    }

    async fn health(&self) -> AdapterHealth {
        AdapterHealth {
            mode: "stub",
            adapter: "password_fill_stub",
            configured: true,
            ready: true,
            supported_actions: vec![AdapterSupport {
                action: "password_fill",
                adapter: "password_fill_stub",
                target_hint: "https://.../login",
                status: "preview",
            }],
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct StubRequestSignAdapter;

impl StubRequestSignAdapter {
    fn target_supported(target: &str) -> bool {
        target.ends_with("/sign")
    }
}

#[async_trait]
impl TrustedExecutionAdapter for StubRequestSignAdapter {
    async fn execute(
        &self,
        request: AdapterRequest<'_>,
        resolved: ResolvedSecret,
    ) -> Result<MaskedAdapterResult, AdapterError> {
        if request.action != "request_sign" {
            return Err(AdapterError {
                code: AdapterErrorCode::UnsupportedAction,
                message: "Unsupported execution adapter action",
            });
        }

        if !Self::target_supported(request.target) {
            return Err(AdapterError {
                code: AdapterErrorCode::TargetMismatch,
                message: "Execution adapter target mismatch",
            });
        }

        if resolved.secret_bytes.is_empty() {
            return Err(AdapterError {
                code: AdapterErrorCode::Unavailable,
                message: "Execution adapter is unavailable",
            });
        }

        Ok(MaskedAdapterResult {
            adapter: "request_sign_stub",
            outcome: "signed",
            target: request.target.to_string(),
            secret_ref_masked: resolved.secret_ref_masked,
        })
    }

    async fn health(&self) -> AdapterHealth {
        AdapterHealth {
            mode: "stub",
            adapter: "request_sign_stub",
            configured: true,
            ready: true,
            supported_actions: vec![AdapterSupport {
                action: "request_sign",
                adapter: "request_sign_stub",
                target_hint: "https://.../sign",
                status: "preview",
            }],
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct StubCredentialHandoffAdapter;

impl StubCredentialHandoffAdapter {
    fn target_supported(target: &str) -> bool {
        target.starts_with("handoff://local-helper/")
    }
}

#[async_trait]
impl TrustedExecutionAdapter for StubCredentialHandoffAdapter {
    async fn execute(
        &self,
        request: AdapterRequest<'_>,
        resolved: ResolvedSecret,
    ) -> Result<MaskedAdapterResult, AdapterError> {
        if request.action != "credential_handoff" {
            return Err(AdapterError {
                code: AdapterErrorCode::UnsupportedAction,
                message: "Unsupported execution adapter action",
            });
        }

        if !Self::target_supported(request.target) {
            return Err(AdapterError {
                code: AdapterErrorCode::TargetMismatch,
                message: "Execution adapter target mismatch",
            });
        }

        if resolved.secret_bytes.is_empty() {
            return Err(AdapterError {
                code: AdapterErrorCode::Unavailable,
                message: "Execution adapter is unavailable",
            });
        }

        Ok(MaskedAdapterResult {
            adapter: "credential_handoff_stub",
            outcome: "handed_off",
            target: request.target.to_string(),
            secret_ref_masked: resolved.secret_ref_masked,
        })
    }

    async fn health(&self) -> AdapterHealth {
        AdapterHealth {
            mode: "stub",
            adapter: "credential_handoff_stub",
            configured: true,
            ready: true,
            supported_actions: vec![AdapterSupport {
                action: "credential_handoff",
                adapter: "credential_handoff_stub",
                target_hint: "handoff://local-helper/...",
                status: "preview",
            }],
        }
    }
}

pub(crate) enum ExecutionAdapterRuntime {
    Off,
    Stub {
        password_fill: StubPasswordFillAdapter,
        request_sign: StubRequestSignAdapter,
        credential_handoff: StubCredentialHandoffAdapter,
    },
}

impl ExecutionAdapterRuntime {
    pub(crate) fn off() -> Self {
        Self::Off
    }

    pub(crate) fn stub() -> Self {
        Self::Stub {
            password_fill: StubPasswordFillAdapter,
            request_sign: StubRequestSignAdapter,
            credential_handoff: StubCredentialHandoffAdapter,
        }
    }
}

#[async_trait]
impl TrustedExecutionAdapter for ExecutionAdapterRuntime {
    async fn execute(
        &self,
        request: AdapterRequest<'_>,
        resolved: ResolvedSecret,
    ) -> Result<MaskedAdapterResult, AdapterError> {
        match self {
            ExecutionAdapterRuntime::Off => Err(AdapterError {
                code: AdapterErrorCode::Disabled,
                message: "Execution adapter is disabled",
            }),
            ExecutionAdapterRuntime::Stub {
                password_fill,
                request_sign,
                credential_handoff,
            } => match request.action {
                "password_fill" => password_fill.execute(request, resolved).await,
                "request_sign" => request_sign.execute(request, resolved).await,
                "credential_handoff" => credential_handoff.execute(request, resolved).await,
                _ => Err(AdapterError {
                    code: AdapterErrorCode::UnsupportedAction,
                    message: "Unsupported execution adapter action",
                }),
            },
        }
    }

    async fn health(&self) -> AdapterHealth {
        match self {
            ExecutionAdapterRuntime::Off => AdapterHealth {
                mode: "off",
                adapter: "none",
                configured: false,
                ready: false,
                supported_actions: vec![],
            },
            ExecutionAdapterRuntime::Stub { .. } => AdapterHealth {
                mode: "stub",
                adapter: "registry_stub",
                configured: true,
                ready: true,
                supported_actions: vec![
                    AdapterSupport {
                        action: "password_fill",
                        adapter: "password_fill_stub",
                        target_hint: "https://.../login",
                        status: "preview",
                    },
                    AdapterSupport {
                        action: "request_sign",
                        adapter: "request_sign_stub",
                        target_hint: "https://.../sign",
                        status: "preview",
                    },
                    AdapterSupport {
                        action: "credential_handoff",
                        adapter: "credential_handoff_stub",
                        target_hint: "handoff://local-helper/...",
                        status: "preview",
                    },
                ],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_execution_adapter_mode, AdapterErrorCode, AdapterRequest, ExecutionAdapterMode,
        ExecutionAdapterRuntime, TrustedExecutionAdapter,
    };
    use crate::provider::ResolvedSecret;

    fn resolved_secret() -> ResolvedSecret {
        ResolvedSecret {
            provider_name: "bitwarden_stub",
            secret_ref_masked: "bw****in".to_string(),
            secret_bytes: b"stub-secret-material".to_vec(),
        }
    }

    #[tokio::test]
    async fn stub_adapter_returns_masked_fill_result() {
        let runtime = ExecutionAdapterRuntime::stub();

        let result = runtime
            .execute(
                AdapterRequest {
                    action: "password_fill",
                    target: "https://example.com/login",
                },
                resolved_secret(),
            )
            .await
            .expect("masked adapter result");

        assert_eq!(result.adapter, "password_fill_stub");
        assert_eq!(result.outcome, "filled");
        assert_eq!(result.target, "https://example.com/login");
        assert_eq!(result.secret_ref_masked, "bw****in");
    }

    #[tokio::test]
    async fn stub_adapter_rejects_unsupported_actions_without_plaintext() {
        let runtime = ExecutionAdapterRuntime::stub();

        let err = runtime
            .execute(
                AdapterRequest {
                    action: "copy_secret",
                    target: "https://example.com/login",
                },
                resolved_secret(),
            )
            .await
            .expect_err("unsupported action");

        assert_eq!(err.code, AdapterErrorCode::UnsupportedAction);
        assert!(!err.message.contains("stub-secret-material"));
    }

    #[tokio::test]
    async fn stub_adapter_rejects_target_mismatch_without_plaintext() {
        let runtime = ExecutionAdapterRuntime::stub();

        let err = runtime
            .execute(
                AdapterRequest {
                    action: "password_fill",
                    target: "https://example.com/profile",
                },
                resolved_secret(),
            )
            .await
            .expect_err("target mismatch");

        assert_eq!(err.code, AdapterErrorCode::TargetMismatch);
        assert!(!err.message.contains("stub-secret-material"));
    }

    #[tokio::test]
    async fn stub_adapter_supports_request_sign_without_leaking_plaintext() {
        let runtime = ExecutionAdapterRuntime::stub();

        let result = runtime
            .execute(
                AdapterRequest {
                    action: "request_sign",
                    target: "https://api.example.com/sign",
                },
                resolved_secret(),
            )
            .await
            .expect("masked signing result");

        assert_eq!(result.adapter, "request_sign_stub");
        assert_eq!(result.outcome, "signed");
        assert_eq!(result.target, "https://api.example.com/sign");
        assert_eq!(result.secret_ref_masked, "bw****in");
    }

    #[tokio::test]
    async fn request_sign_adapter_rejects_unsupported_targets_without_plaintext() {
        let runtime = ExecutionAdapterRuntime::stub();

        let err = runtime
            .execute(
                AdapterRequest {
                    action: "request_sign",
                    target: "https://example.com/profile",
                },
                resolved_secret(),
            )
            .await
            .expect_err("target mismatch");

        assert_eq!(err.code, AdapterErrorCode::TargetMismatch);
        assert!(!err.message.contains("stub-secret-material"));
    }

    #[tokio::test]
    async fn stub_adapter_supports_credential_handoff_without_leaking_plaintext() {
        let runtime = ExecutionAdapterRuntime::stub();

        let result = runtime
            .execute(
                AdapterRequest {
                    action: "credential_handoff",
                    target: "handoff://local-helper/session",
                },
                resolved_secret(),
            )
            .await
            .expect("masked handoff result");

        assert_eq!(result.adapter, "credential_handoff_stub");
        assert_eq!(result.outcome, "handed_off");
        assert_eq!(result.target, "handoff://local-helper/session");
        assert_eq!(result.secret_ref_masked, "bw****in");
    }

    #[tokio::test]
    async fn credential_handoff_adapter_rejects_unsupported_targets_without_plaintext() {
        let runtime = ExecutionAdapterRuntime::stub();

        let err = runtime
            .execute(
                AdapterRequest {
                    action: "credential_handoff",
                    target: "handoff://other-host/session",
                },
                resolved_secret(),
            )
            .await
            .expect_err("target mismatch");

        assert_eq!(err.code, AdapterErrorCode::TargetMismatch);
        assert!(!err.message.contains("stub-secret-material"));
    }

    #[test]
    fn adapter_mode_parser_handles_off_and_stub() {
        assert_eq!(
            parse_execution_adapter_mode("off"),
            ExecutionAdapterMode::Off
        );
        assert_eq!(
            parse_execution_adapter_mode("stub"),
            ExecutionAdapterMode::Stub
        );
        assert_eq!(
            parse_execution_adapter_mode("anything-else"),
            ExecutionAdapterMode::Off
        );
    }
}
