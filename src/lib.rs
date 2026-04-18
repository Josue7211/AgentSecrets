mod adapter;
pub mod audit;
mod auth;
mod handlers;
mod identity;
mod keys;
mod policy;
mod provider;

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::{str::FromStr, time::Duration};
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    db: Arc<SqlitePool>,
    cfg: Arc<Config>,
    provider: Arc<dyn provider::SecretProvider>,
    adapter: Arc<adapter::ExecutionAdapterRuntime>,
    rate_state: Arc<Mutex<HashMap<String, Vec<i64>>>>,
    identity_replay_cache: identity::IdentityReplayCache,
}

#[derive(Clone, Debug)]
enum BrokerMode {
    Off,
    Monitor,
    Enforce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderBridgeMode {
    Off,
    Stub,
    BitwardenProduction,
}

#[derive(Clone)]
struct Config {
    bind: String,
    db_url: String,
    mode: BrokerMode,
    provider_bridge_mode: ProviderBridgeMode,
    execution_adapter_mode: adapter::ExecutionAdapterMode,
    request_sign_adapter_url: String,
    client_api_key: String,
    approver_api_key: String,
    capability_ttl_seconds: i64,
    request_ttl_seconds: i64,
    max_amount_cents: i64,
    allowed_target_prefixes: Vec<String>,
    rate_limit_per_minute: usize,
    identity_verification_mode: identity::IdentityVerificationMode,
    identity_attestation_key: String,
    identity_attestation_max_age_seconds: i64,
    trusted_runtime_ids: Vec<String>,
    trusted_host_ids: Vec<String>,
    identity_host_signing_keys: HashMap<String, String>,
    trusted_host_runtime_pairs: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthContext {
    role: AuthRole,
    key_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthRole {
    Client,
    Approver,
}

#[derive(Debug, Serialize)]
struct ApiError {
    ok: bool,
    error: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    ok: bool,
    data: T,
}

#[derive(Debug, Deserialize)]
struct CreateRequestBody {
    request_type: String,
    secret_ref: String,
    action: String,
    target: String,
    amount_cents: Option<i64>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateTrustedInputSessionBody {
    request_type: String,
    action: String,
    target: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompleteTrustedInputSessionBody {
    completion_token: String,
    secret_ref: String,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    status: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DecisionBody {
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExecuteBody {
    id: String,
    capability_token: String,
    action: Option<String>,
    target: Option<String>,
}

#[derive(Debug, Serialize)]
struct RequestView {
    id: String,
    request_type: String,
    secret_ref_masked: String,
    action: String,
    target: String,
    amount_cents: Option<i64>,
    reason: Option<String>,
    status: String,
    requires_approval: bool,
    deny_reason: Option<String>,
    capability_expires_at: Option<String>,
    capability_used_at: Option<String>,
    created_at: String,
    updated_at: String,
}

type RequestRow = (
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<String>,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

#[derive(sqlx::FromRow)]
struct ExecuteLookupRow {
    status: String,
    action: String,
    target: String,
    secret_ref: String,
    capability_hash: Option<String>,
    capability_expires_at: Option<String>,
    capability_request_id: Option<String>,
    capability_action: Option<String>,
    capability_target: Option<String>,
    capability_issued_at: Option<String>,
    policy_outcome: Option<String>,
    policy_risk_score: Option<i64>,
    policy_environment: Option<String>,
    policy_reasons: Option<String>,
    identity_status: String,
    identity_mode: String,
    identity_runtime_id: Option<String>,
    identity_host_id: Option<String>,
    identity_adapter_id: Option<String>,
    identity_verified_at: Option<String>,
}

type ApproveLookupRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

type AuditRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
);

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse { ok: true, data })
}

fn err(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            ok: false,
            error: message.to_string(),
            code: code.to_string(),
        }),
    )
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn request_id() -> String {
    format!("sbr_{}", random_hex(12))
}

fn trusted_input_session_id() -> String {
    format!("tis_{}", random_hex(12))
}

fn capability_token() -> String {
    format!("sbt_{}", random_hex(24))
}

fn trusted_input_completion_token() -> String {
    format!("tit_{}", random_hex(24))
}

fn execution_adapter_runtime(cfg: &Config) -> Arc<adapter::ExecutionAdapterRuntime> {
    Arc::new(match cfg.execution_adapter_mode {
        adapter::ExecutionAdapterMode::Off => adapter::ExecutionAdapterRuntime::off(),
        adapter::ExecutionAdapterMode::Stub => adapter::ExecutionAdapterRuntime::stub(),
        adapter::ExecutionAdapterMode::RequestSignProduction => {
            adapter::ExecutionAdapterRuntime::request_sign_production(
                cfg.request_sign_adapter_url.clone(),
            )
        }
    })
}

fn parse_provider_bridge_mode(raw: &str) -> anyhow::Result<ProviderBridgeMode> {
    match raw.trim().to_lowercase().as_str() {
        "off" => Ok(ProviderBridgeMode::Off),
        "stub" => Ok(ProviderBridgeMode::Stub),
        "bitwarden-production" => Ok(ProviderBridgeMode::BitwardenProduction),
        other => anyhow::bail!("SECRET_BROKER_PROVIDER_BRIDGE_MODE is invalid: {other}"),
    }
}

fn provider_runtime_for_config(cfg: &Config) -> Arc<dyn provider::SecretProvider> {
    match cfg.provider_bridge_mode {
        ProviderBridgeMode::Off => Arc::new(provider::ProviderRuntime::off()),
        ProviderBridgeMode::Stub => Arc::new(provider::ProviderRuntime::stub()),
        ProviderBridgeMode::BitwardenProduction => {
            Arc::new(BitwardenProductionProvider::from_env())
        }
    }
}

#[derive(Debug, Clone)]
struct BitwardenProductionProvider {
    endpoint: String,
    credential: String,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize)]
struct BitwardenResolveRequest<'a> {
    secret_ref: &'a str,
}

#[derive(Debug, Deserialize)]
struct BitwardenResolveResponse {
    provider_name: Option<String>,
    secret_ref_masked: String,
    secret_hex: String,
}

impl BitwardenProductionProvider {
    fn from_env() -> Self {
        Self {
            endpoint: std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_URL").unwrap_or_default(),
            credential: std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_TOKEN").unwrap_or_default(),
            client: reqwest::Client::new(),
        }
    }

    #[allow(dead_code)]
    fn new(endpoint: String, credential: String) -> Self {
        Self {
            endpoint,
            credential,
            client: reqwest::Client::new(),
        }
    }

    fn configured(&self) -> bool {
        (self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://"))
            && !self.credential.trim().is_empty()
    }
}

#[async_trait::async_trait]
impl provider::SecretProvider for BitwardenProductionProvider {
    async fn resolve_for_use(
        &self,
        secret_ref: &str,
    ) -> Result<provider::ResolvedSecret, provider::ProviderError> {
        if !self.configured() {
            return Err(provider::ProviderError {
                code: provider::ProviderErrorCode::Unavailable,
                message: "provider_unavailable",
            });
        }

        let response = self
            .client
            .post(&self.endpoint)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.credential),
            )
            .json(&BitwardenResolveRequest { secret_ref })
            .send()
            .await
            .map_err(|_| provider::ProviderError {
                code: provider::ProviderErrorCode::Unavailable,
                message: "provider_outage",
            })?;

        let status = response.status();
        if !status.is_success() {
            let message = match status.as_u16() {
                401 | 403 => "revoked_credential",
                404 => "missing_ref",
                409 => "binding_mismatch",
                502..=504 => "provider_outage",
                _ => "provider_unavailable",
            };
            return Err(provider::ProviderError {
                code: provider::ProviderErrorCode::Unavailable,
                message,
            });
        }

        let body = response
            .json::<BitwardenResolveResponse>()
            .await
            .map_err(|_| provider::ProviderError {
                code: provider::ProviderErrorCode::Unavailable,
                message: "provider_unavailable",
            })?;

        let secret_bytes =
            hex::decode(body.secret_hex.as_bytes()).map_err(|_| provider::ProviderError {
                code: provider::ProviderErrorCode::Unavailable,
                message: "provider_unavailable",
            })?;

        if body.secret_ref_masked.trim().is_empty() {
            return Err(provider::ProviderError {
                code: provider::ProviderErrorCode::Unavailable,
                message: "provider_unavailable",
            });
        }

        let _provider_name = body
            .provider_name
            .unwrap_or_else(|| "bitwarden_production_v1".to_string());

        Ok(provider::ResolvedSecret {
            provider_name: "bitwarden_production_v1",
            secret_ref_masked: body.secret_ref_masked,
            secret_bytes,
        })
    }

    async fn health(&self) -> provider::ProviderHealth {
        let configured = self.configured();
        provider::ProviderHealth {
            mode: "bitwarden-production",
            provider: "bitwarden_production_v1",
            configured,
            ready: configured,
        }
    }
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn key_fingerprint(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let full = hex::encode(hasher.finalize());
    format!("kfp_{}", &full[..12])
}

fn mask_secret_ref(secret_ref: &str) -> String {
    if secret_ref.len() <= 4 {
        return "****".to_string();
    }
    format!(
        "{}****{}",
        &secret_ref[..2],
        &secret_ref[secret_ref.len() - 2..]
    )
}

fn trusted_input_opaque_ref(session_id: &str) -> String {
    format!("tir://session/{session_id}")
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn unix_to_sqlite_datetime(unix: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn sqlite_datetime_to_unix(s: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|d| d.and_utc().timestamp())
}

fn parse_kv_map(raw: &str, env_name: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut parsed = HashMap::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            anyhow::bail!("{env_name} contains an invalid entry: {trimmed}");
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            anyhow::bail!("{env_name} contains an invalid entry: {trimmed}");
        }
        parsed.insert(key.to_string(), value.to_string());
    }
    Ok(parsed)
}

fn parse_host_runtime_pairs(raw: &str) -> anyhow::Result<HashMap<String, Vec<String>>> {
    parse_kv_map(raw, "SECRET_BROKER_TRUSTED_HOST_RUNTIME_PAIRS")?
        .into_iter()
        .map(|(host_id, runtimes)| -> anyhow::Result<(String, Vec<String>)> {
            let runtimes = runtimes
                .split('|')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if runtimes.is_empty() {
                anyhow::bail!(
                    "SECRET_BROKER_TRUSTED_HOST_RUNTIME_PAIRS contains an empty runtime list for {host_id}"
                );
            }
            Ok((host_id, runtimes))
        })
        .collect()
}

fn config_from_env() -> anyhow::Result<Config> {
    let bind = std::env::var("SECRET_BROKER_BIND").unwrap_or_else(|_| "127.0.0.1:4815".to_string());
    let db_url = std::env::var("SECRET_BROKER_DB")
        .unwrap_or_else(|_| "sqlite://secret-broker.db?mode=rwc".to_string());
    let mode = policy::parse_mode(
        &std::env::var("SECRET_BROKER_MODE").unwrap_or_else(|_| "monitor".to_string()),
    );
    let provider_bridge_mode = parse_provider_bridge_mode(
        &std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_MODE").unwrap_or_else(|_| "off".to_string()),
    )?;
    let execution_adapter_mode = adapter::parse_execution_adapter_mode(
        &std::env::var("SECRET_BROKER_EXECUTION_ADAPTER_MODE")
            .unwrap_or_else(|_| "off".to_string()),
    );
    let request_sign_adapter_url =
        std::env::var("SECRET_BROKER_REQUEST_SIGN_ADAPTER_URL").unwrap_or_default();

    let client_api_key = std::env::var("SECRET_BROKER_CLIENT_API_KEY")
        .or_else(|_| std::env::var("SECRET_BROKER_API_KEY"))
        .unwrap_or_else(|_| "dev-client-key".to_string());
    let approver_api_key = std::env::var("SECRET_BROKER_APPROVER_API_KEY")
        .or_else(|_| std::env::var("SECRET_BROKER_API_KEY"))
        .unwrap_or_else(|_| "dev-approver-key".to_string());

    let capability_ttl_seconds = std::env::var("SECRET_BROKER_CAPABILITY_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(60)
        .clamp(30, 600);

    let request_ttl_seconds = std::env::var("SECRET_BROKER_REQUEST_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3600)
        .clamp(60, 86_400);

    let max_amount_cents = std::env::var("SECRET_BROKER_MAX_AMOUNT_CENTS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2_000_000)
        .clamp(0, 100_000_000);

    let allowed_target_prefixes = policy::parse_list(
        &std::env::var("SECRET_BROKER_ALLOWED_TARGET_PREFIXES").unwrap_or_default(),
    );

    let rate_limit_per_minute = std::env::var("SECRET_BROKER_RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(120)
        .clamp(10, 10_000);

    let identity_verification_mode = identity::parse_identity_verification_mode(
        &std::env::var("SECRET_BROKER_IDENTITY_VERIFICATION_MODE")
            .unwrap_or_else(|_| "off".to_string()),
    )
    .map_err(|_| anyhow::anyhow!("SECRET_BROKER_IDENTITY_VERIFICATION_MODE is invalid"))?;
    let identity_attestation_key =
        std::env::var("SECRET_BROKER_IDENTITY_ATTESTATION_KEY").unwrap_or_default();
    let identity_attestation_max_age_seconds =
        std::env::var("SECRET_BROKER_IDENTITY_ATTESTATION_MAX_AGE_SECONDS")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(300)
            .clamp(30, 3_600);
    let trusted_runtime_ids =
        policy::parse_list(&std::env::var("SECRET_BROKER_TRUSTED_RUNTIME_IDS").unwrap_or_default());
    let trusted_host_ids =
        policy::parse_list(&std::env::var("SECRET_BROKER_TRUSTED_HOST_IDS").unwrap_or_default());
    let identity_host_signing_keys = parse_kv_map(
        &std::env::var("SECRET_BROKER_IDENTITY_HOST_SIGNING_KEYS").unwrap_or_default(),
        "SECRET_BROKER_IDENTITY_HOST_SIGNING_KEYS",
    )?;
    let trusted_host_runtime_pairs = parse_host_runtime_pairs(
        &std::env::var("SECRET_BROKER_TRUSTED_HOST_RUNTIME_PAIRS").unwrap_or_default(),
    )?;

    Ok(Config {
        bind,
        db_url,
        mode,
        provider_bridge_mode,
        execution_adapter_mode,
        request_sign_adapter_url,
        client_api_key,
        approver_api_key,
        capability_ttl_seconds,
        request_ttl_seconds,
        max_amount_cents,
        allowed_target_prefixes,
        rate_limit_per_minute,
        identity_verification_mode,
        identity_attestation_key,
        identity_attestation_max_age_seconds,
        trusted_runtime_ids,
        trusted_host_ids,
        identity_host_signing_keys,
        trusted_host_runtime_pairs,
    })
}

async fn init_db(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

async fn connect_sqlite(db_url: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(db_url)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    Ok(pool)
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/readyz", get(handlers::health::readyz))
        .route(
            "/v1/trusted-input/sessions",
            post(handlers::trusted_input::create_session),
        )
        .route(
            "/v1/trusted-input/sessions/:id",
            get(handlers::trusted_input::get_session),
        )
        .route(
            "/v1/trusted-input/sessions/:id/complete",
            post(handlers::trusted_input::complete_session),
        )
        .route(
            "/v1/requests",
            post(handlers::requests::create_request).get(handlers::requests::list_requests),
        )
        .route(
            "/v1/requests/:id/approve",
            post(handlers::requests::approve_request),
        )
        .route(
            "/v1/requests/:id/deny",
            post(handlers::requests::deny_request),
        )
        .route("/v1/execute", post(handlers::execution::execute_request))
        .route("/v1/audit", get(handlers::requests::list_audit))
        .route(
            "/v1/admin/keys/:role/rotate",
            post(handlers::admin::rotate_by_role),
        )
        .with_state(state)
}

fn validate_config(cfg: &Config) -> anyhow::Result<()> {
    if cfg.client_api_key == cfg.approver_api_key {
        anyhow::bail!("client and approver API keys must be different");
    }

    if matches!(cfg.mode, BrokerMode::Enforce) {
        if cfg.client_api_key == "dev-client-key" || cfg.approver_api_key == "dev-approver-key" {
            anyhow::bail!("refusing to run in enforce mode with default dev API keys");
        }
        if cfg.client_api_key.len() < 16 || cfg.approver_api_key.len() < 16 {
            anyhow::bail!("API keys are too short; use at least 16 characters");
        }
    }

    let provider_bridge_mode =
        std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_MODE").unwrap_or_else(|_| "off".to_string());
    if provider_bridge_mode
        .trim()
        .eq_ignore_ascii_case("bitwarden-production")
    {
        let provider_bridge_url =
            std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_URL").unwrap_or_default();
        let provider_bridge_token =
            std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_TOKEN").unwrap_or_default();
        if !(provider_bridge_url.starts_with("http://")
            || provider_bridge_url.starts_with("https://"))
        {
            anyhow::bail!(
                "SECRET_BROKER_PROVIDER_BRIDGE_MODE=bitwarden-production requires SECRET_BROKER_PROVIDER_BRIDGE_URL to be an http(s) URL"
            );
        }
        if provider_bridge_token.trim().is_empty() {
            anyhow::bail!(
                "SECRET_BROKER_PROVIDER_BRIDGE_MODE=bitwarden-production requires SECRET_BROKER_PROVIDER_BRIDGE_TOKEN"
            );
        }
    }

    match cfg.identity_verification_mode {
        identity::IdentityVerificationMode::Off => {}
        identity::IdentityVerificationMode::Stub => {
            if cfg.identity_attestation_key.is_empty() {
                anyhow::bail!(
                    "SECRET_BROKER_IDENTITY_VERIFICATION_MODE=stub requires SECRET_BROKER_IDENTITY_ATTESTATION_KEY"
                );
            }
        }
        identity::IdentityVerificationMode::HostSigned => {
            if identity::usable_host_signed_hosts(cfg).is_empty() {
                anyhow::bail!(
                    "SECRET_BROKER_IDENTITY_VERIFICATION_MODE=host-signed requires at least one host present in both SECRET_BROKER_IDENTITY_HOST_SIGNING_KEYS and SECRET_BROKER_TRUSTED_HOST_RUNTIME_PAIRS"
                );
            }
        }
        identity::IdentityVerificationMode::HardwareBacked => {
            anyhow::bail!("hardware-backed identity is not implemented")
        }
    }

    if matches!(
        cfg.execution_adapter_mode,
        adapter::ExecutionAdapterMode::RequestSignProduction
    ) && !(cfg.request_sign_adapter_url.starts_with("http://")
        || cfg.request_sign_adapter_url.starts_with("https://"))
    {
        anyhow::bail!(
            "SECRET_BROKER_EXECUTION_ADAPTER_MODE=request-sign-production requires SECRET_BROKER_REQUEST_SIGN_ADAPTER_URL to be an http(s) URL"
        );
    }

    Ok(())
}

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secret_broker=info".into()),
        )
        .init();

    let cfg = Arc::new(config_from_env()?);
    validate_config(&cfg)?;

    if cfg.client_api_key == "dev-client-key" || cfg.approver_api_key == "dev-approver-key" {
        tracing::warn!(
            "Using default dev API keys. Set SECRET_BROKER_CLIENT_API_KEY and SECRET_BROKER_APPROVER_API_KEY in production."
        );
    }

    let pool = connect_sqlite(&cfg.db_url).await?;
    init_db(&pool).await?;
    keys::ensure_api_keys(&pool, &cfg).await?;
    let state = AppState {
        db: Arc::new(pool),
        cfg: Arc::clone(&cfg),
        provider: provider_runtime_for_config(&cfg),
        adapter: execution_adapter_runtime(&cfg),
        rate_state: Arc::new(Mutex::new(HashMap::new())),
        identity_replay_cache: identity::new_replay_cache(),
    };

    let app = build_router(state);

    let addr: SocketAddr = cfg.bind.parse()?;
    tracing::info!("secret-broker listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use axum::{body::Body, http::Request};
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Stdio,
        sync::OnceLock,
        time::Duration,
    };
    use tempfile::NamedTempFile;
    use tokio::process::{Child, Command};
    use tokio::time::sleep;
    use tower::util::ServiceExt;

    fn test_config(
        db_url: String,
        provider_bridge_mode: ProviderBridgeMode,
        execution_adapter_mode: crate::adapter::ExecutionAdapterMode,
        request_sign_adapter_url: String,
    ) -> Arc<Config> {
        Arc::new(Config {
            bind: "127.0.0.1:0".to_string(),
            db_url,
            mode: BrokerMode::Enforce,
            provider_bridge_mode,
            execution_adapter_mode,
            request_sign_adapter_url,
            client_api_key: "test-client-key-123456".to_string(),
            approver_api_key: "test-approver-key-abcdef".to_string(),
            capability_ttl_seconds: 60,
            request_ttl_seconds: 3600,
            max_amount_cents: 2_000_000,
            allowed_target_prefixes: vec![
                "https://".to_string(),
                "handoff://local-helper/".to_string(),
            ],
            rate_limit_per_minute: 1000,
            identity_verification_mode: crate::identity::IdentityVerificationMode::Off,
            identity_attestation_key: String::new(),
            identity_attestation_max_age_seconds: 300,
            trusted_runtime_ids: Vec::new(),
            trusted_host_ids: Vec::new(),
            identity_host_signing_keys: HashMap::new(),
            trusted_host_runtime_pairs: HashMap::new(),
        })
    }

    #[derive(Deserialize)]
    struct MockRequestSignServicePayload {
        target: String,
        secret_hex: String,
        secret_ref_masked: String,
    }

    #[derive(Deserialize)]
    struct MockBitwardenResolvePayload {
        secret_ref: String,
    }

    async fn spawn_mock_request_sign_service() -> anyhow::Result<String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = Router::new().route(
            "/v1/request-sign",
            post(
                |Json(payload): Json<MockRequestSignServicePayload>| async move {
                    let secret_bytes = hex::decode(&payload.secret_hex).unwrap_or_default();
                    let mut hasher = Sha256::new();
                    hasher.update(b"request-sign-service|");
                    hasher.update(secret_bytes);
                    hasher.update(b"|");
                    hasher.update(payload.target.as_bytes());
                    hasher.update(b"|");
                    hasher.update(payload.secret_ref_masked.as_bytes());
                    let digest = hex::encode(hasher.finalize());
                    Json(json!({
                        "signature_ref": format!("sig_service_{}", &digest[..12])
                    }))
                },
            ),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(format!("http://{addr}/v1/request-sign"))
    }

    async fn spawn_mock_bitwarden_provider_service(
        expected_token: &'static str,
    ) -> anyhow::Result<String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = Router::new().route(
            "/v1/resolve",
            post(
                move |headers: axum::http::HeaderMap,
                      Json(payload): Json<MockBitwardenResolvePayload>| async move {
                    let auth_ok = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value == format!("Bearer {expected_token}"))
                        .unwrap_or(false);

                    if !auth_ok {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "code": "revoked_credential"
                            })),
                        );
                    }

                    let response = match payload.secret_ref.as_str() {
                        "bw://vault/item/login" => (
                            StatusCode::OK,
                            Json(json!({
                                "provider_name": "bitwarden_production_v1",
                                "secret_ref_masked": "bw****in",
                                "secret_hex": hex::encode(b"production-secret-material"),
                            })),
                        ),
                        "bw://vault/item/outage" => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "code": "provider_outage"
                            })),
                        ),
                        "bw://vault/item/revoked" => (
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "code": "revoked_credential"
                            })),
                        ),
                        "bw://vault/item/missing" => (
                            StatusCode::NOT_FOUND,
                            Json(json!({
                                "code": "missing_ref"
                            })),
                        ),
                        "bw://vault/item/binding-mismatch" => (
                            StatusCode::CONFLICT,
                            Json(json!({
                                "code": "binding_mismatch"
                            })),
                        ),
                        _ => (
                            StatusCode::NOT_FOUND,
                            Json(json!({
                                "code": "missing_ref"
                            })),
                        ),
                    };

                    response
                },
            ),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(format!("http://{addr}/v1/resolve"))
    }

    fn with_env_vars<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("lock env");

        let saved = vars
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
            .collect::<Vec<_>>();

        for (key, value) in vars {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }

        let result = f();

        for (key, value) in saved {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }

        result
    }

    async fn with_env_vars_async<T>(
        vars: &[(&str, Option<&str>)],
        fut: impl std::future::Future<Output = T>,
    ) -> T {
        static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        let guard = ENV_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;

        let saved = vars
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
            .collect::<Vec<_>>();

        for (key, value) in vars {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }

        let result = fut.await;

        for (key, value) in saved {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }

        drop(guard);
        result
    }

    async fn setup_app_with_modes(
        provider_bridge_mode: ProviderBridgeMode,
        adapter_mode: &str,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        setup_app_with_provider_and_adapter_modes(provider_bridge_mode, adapter_mode).await
    }

    async fn setup_app_with_provider_and_adapter_modes(
        provider_bridge_mode: ProviderBridgeMode,
        adapter_mode: &str,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        let db_file = NamedTempFile::new()?;
        let db_path = db_file.path().to_string_lossy().to_string();
        let db_url = format!("sqlite://{}?mode=rwc", db_path);
        std::mem::forget(db_file);
        let execution_adapter_mode = crate::adapter::parse_execution_adapter_mode(adapter_mode);
        let request_sign_adapter_url = if matches!(
            execution_adapter_mode,
            crate::adapter::ExecutionAdapterMode::RequestSignProduction
        ) {
            spawn_mock_request_sign_service().await?
        } else {
            String::new()
        };

        let cfg = test_config(
            db_url.clone(),
            provider_bridge_mode,
            execution_adapter_mode,
            request_sign_adapter_url,
        );
        let pool = connect_sqlite(&db_url).await?;
        init_db(&pool).await?;
        crate::keys::ensure_api_keys(&pool, &cfg).await?;

        let state = AppState {
            db: Arc::new(pool),
            cfg: Arc::clone(&cfg),
            provider: provider_runtime_for_config(&cfg),
            adapter: execution_adapter_runtime(&cfg),
            rate_state: Arc::new(Mutex::new(HashMap::new())),
            identity_replay_cache: identity::new_replay_cache(),
        };
        Ok((build_router(state), cfg))
    }

    async fn setup_app_with_provider_mode(
        provider_bridge_mode: ProviderBridgeMode,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        setup_app_with_modes(provider_bridge_mode, "off").await
    }

    async fn setup_app_with_bitwarden_provider_mode(
        provider_bridge_url: &str,
        provider_bridge_token: &str,
        adapter_mode: &str,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        with_env_vars_async(
            &[
                (
                    "SECRET_BROKER_PROVIDER_BRIDGE_MODE",
                    Some("bitwarden-production"),
                ),
                (
                    "SECRET_BROKER_PROVIDER_BRIDGE_URL",
                    Some(provider_bridge_url),
                ),
                (
                    "SECRET_BROKER_PROVIDER_BRIDGE_TOKEN",
                    Some(provider_bridge_token),
                ),
            ],
            setup_app_with_provider_and_adapter_modes(
                ProviderBridgeMode::BitwardenProduction,
                adapter_mode,
            ),
        )
        .await
    }

    async fn setup_app() -> anyhow::Result<(Router, Arc<Config>)> {
        setup_app_with_provider_mode(ProviderBridgeMode::Off).await
    }

    async fn setup_app_with_identity_mode(
        provider_bridge_mode: ProviderBridgeMode,
        adapter_mode: &str,
        identity_mode: crate::identity::IdentityVerificationMode,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        let (app, cfg) = setup_app_with_modes(provider_bridge_mode, adapter_mode).await?;
        let (identity_host_signing_keys, trusted_host_runtime_pairs) = match identity_mode {
            crate::identity::IdentityVerificationMode::HostSigned => (
                HashMap::from([
                    (
                        "openclaw-http-host".to_string(),
                        "openclaw-host-signing-key".to_string(),
                    ),
                    (
                        "unused-key-only-host".to_string(),
                        "unused-host-key".to_string(),
                    ),
                ]),
                HashMap::from([(
                    "openclaw-http-host".to_string(),
                    vec!["openclaw-runtime-v1".to_string()],
                )]),
            ),
            _ => (HashMap::new(), HashMap::new()),
        };
        let cfg = Arc::new(Config {
            identity_verification_mode: identity_mode,
            identity_attestation_key: "loop4-attestation-key".to_string(),
            identity_attestation_max_age_seconds: 300,
            trusted_runtime_ids: vec![
                "local-helper-runtime".to_string(),
                "secondary-helper-runtime".to_string(),
            ],
            trusted_host_ids: vec![
                "local-helper-host".to_string(),
                "secondary-helper-host".to_string(),
                "openclaw-http-host".to_string(),
            ],
            identity_host_signing_keys,
            trusted_host_runtime_pairs,
            ..(*cfg).clone()
        });
        validate_config(&cfg)?;
        let pool = connect_sqlite(&cfg.db_url).await?;
        let state = AppState {
            db: Arc::new(pool),
            cfg: Arc::clone(&cfg),
            provider: provider_runtime_for_config(&cfg),
            adapter: execution_adapter_runtime(&cfg),
            rate_state: Arc::new(Mutex::new(HashMap::new())),
            identity_replay_cache: identity::new_replay_cache(),
        };

        let _ = app;
        Ok((build_router(state), cfg))
    }

    async fn json_response(resp: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&body).expect("json")
    }

    async fn create_password_request(app: &Router, cfg: &Config) -> String {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": "bw://vault/item/login",
                    "action": "password_fill",
                    "target": "https://example.com/login",
                    "reason": "login automation"
                })
                .to_string(),
            ))
            .expect("request");

        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_response(resp).await;
        json["data"]["id"].as_str().expect("id").to_string()
    }

    #[allow(dead_code)]
    fn signed_identity_headers(
        cfg: &Config,
        action: &str,
        runtime_id: &str,
        host_id: &str,
    ) -> Vec<(&'static str, String)> {
        signed_identity_headers_with_timestamp_and_envelope(
            cfg,
            action,
            runtime_id,
            host_id,
            now_unix(),
            "env-default",
        )
    }

    fn signed_identity_headers_with_timestamp_and_envelope(
        cfg: &Config,
        action: &str,
        runtime_id: &str,
        host_id: &str,
        timestamp: i64,
        envelope_id: &str,
    ) -> Vec<(&'static str, String)> {
        let adapter_id =
            crate::identity::adapter_id_for_action_in_mode(action, cfg.execution_adapter_mode)
                .to_string();
        let signature = match crate::identity::configured_mode(cfg) {
            crate::identity::IdentityVerificationMode::HostSigned => {
                let host_key = cfg
                    .identity_host_signing_keys
                    .get(host_id)
                    .cloned()
                    .unwrap_or_else(|| cfg.identity_attestation_key.clone());
                crate::identity::sign_host_identity_claim(
                    &host_key,
                    runtime_id,
                    host_id,
                    &adapter_id,
                    timestamp,
                    envelope_id,
                )
            }
            _ => crate::identity::sign_identity_claim(
                &cfg.identity_attestation_key,
                runtime_id,
                host_id,
                &adapter_id,
                timestamp,
            ),
        };

        vec![
            ("x-secret-broker-runtime-id", runtime_id.to_string()),
            ("x-secret-broker-host-id", host_id.to_string()),
            ("x-secret-broker-adapter-id", adapter_id),
            ("x-secret-broker-attestation-ts", timestamp.to_string()),
            ("x-secret-broker-attestation-id", envelope_id.to_string()),
            ("x-secret-broker-attestation-sig", signature),
        ]
    }

    async fn create_request_for_action(
        app: &Router,
        cfg: &Config,
        request_type: &str,
        secret_ref: &str,
        action: &str,
        target: &str,
        reason: &str,
    ) -> anyhow::Result<String> {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": request_type,
                    "secret_ref": secret_ref,
                    "action": action,
                    "target": target,
                    "reason": reason
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_response(resp).await;
        Ok(json["data"]["id"].as_str().expect("id").to_string())
    }

    async fn start_trusted_input_session(app: &Router, cfg: &Config) -> Value {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/trusted-input/sessions")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "action": "password_fill",
                    "target": "https://example.com/login",
                    "reason": "trusted host input"
                })
                .to_string(),
            ))
            .expect("request");

        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        json_response(resp).await
    }

    async fn get_trusted_input_session(
        app: &Router,
        cfg: &Config,
        id: &str,
    ) -> axum::response::Response {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/trusted-input/sessions/{id}"))
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())
            .expect("request");

        app.clone().oneshot(req).await.expect("response")
    }

    async fn complete_trusted_input_session(
        app: &Router,
        cfg: &Config,
        id: &str,
        completion_token: &str,
        secret_ref: &str,
    ) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/trusted-input/sessions/{id}/complete"))
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "completion_token": completion_token,
                    "secret_ref": secret_ref
                })
                .to_string(),
            ))
            .expect("request");

        app.clone().oneshot(req).await.expect("response")
    }

    #[derive(Debug)]
    struct NodeInvocation {
        stdout: String,
        stderr: String,
        result: Value,
    }

    #[derive(Debug)]
    struct NodeToNodeOutcome {
        artifact_dir: PathBuf,
        fixture_secret: String,
        request_id: String,
        capability_token: String,
        client_stdout: String,
        client_stderr: String,
        approver_stdout: String,
        approver_stderr: String,
        execute_stdout: String,
        execute_stderr: String,
        create_result: Value,
        approve_result: Value,
        execute_result: Value,
    }

    #[derive(Debug)]
    struct TrustedInputNodeToNodeOutcome {
        artifact_dir: PathBuf,
        fixture_secret: String,
        opaque_ref: String,
        request_id: String,
        capability_token: String,
        trusted_start_stdout: String,
        trusted_start_stderr: String,
        trusted_complete_stdout: String,
        trusted_complete_stderr: String,
        create_stdout: String,
        create_stderr: String,
        approver_stdout: String,
        approver_stderr: String,
        execute_stdout: String,
        execute_stderr: String,
        trusted_start_result: Value,
        trusted_complete_result: Value,
        create_result: Value,
        approve_result: Value,
        execute_result: Value,
    }

    static E2E_BUILD: OnceLock<Result<(), String>> = OnceLock::new();

    fn assert_secret_free(surface: &str, secret: &str) {
        assert!(
            !surface.contains(secret),
            "secret leaked into captured surface: {surface}"
        );
    }

    fn assert_no_leaks(surface: &str, secret: &str, forbidden_values: &[&str]) {
        assert_secret_free(surface, secret);
        for value in forbidden_values {
            assert!(
                !surface.contains(value),
                "forbidden value leaked into captured surface: {value}\n{surface}"
            );
        }
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn e2e_binary_path(name: &str) -> PathBuf {
        repo_root()
            .join("target")
            .join("debug")
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
    }

    fn ensure_e2e_binaries_built() -> anyhow::Result<()> {
        let status = E2E_BUILD.get_or_init(|| {
            let output = std::process::Command::new("cargo")
                .args(["build", "--bin", "secret-broker", "--bin", "e2e-node"])
                .current_dir(repo_root())
                .output();

            match output {
                Ok(output) if output.status.success() => Ok(()),
                Ok(output) => Err(format!(
                    "cargo build failed\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )),
                Err(err) => Err(format!("failed to invoke cargo build: {err}")),
            }
        });

        match status {
            Ok(()) => Ok(()),
            Err(message) => anyhow::bail!("{message}"),
        }
    }

    fn new_artifact_dir(label: &str) -> anyhow::Result<PathBuf> {
        let path = repo_root()
            .join("target")
            .join("e2e-artifacts")
            .join(format!("{label}-{}", random_hex(6)));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn scrub_text(text: &str, sensitive_values: &[&str]) -> String {
        let mut scrubbed = text.to_string();
        for value in sensitive_values {
            if !value.is_empty() {
                scrubbed = scrubbed.replace(value, "[redacted]");
            }
        }
        scrubbed
    }

    fn write_redacted_artifact(
        path: &Path,
        content: &str,
        sensitive_values: &[&str],
    ) -> anyhow::Result<()> {
        fs::write(path, scrub_text(content, sensitive_values))?;
        Ok(())
    }

    fn write_redacted_artifacts(
        artifact_dir: &Path,
        entries: &[(&str, &str)],
        sensitive_values: &[&str],
    ) -> anyhow::Result<()> {
        for (name, content) in entries {
            write_redacted_artifact(&artifact_dir.join(name), content, sensitive_values)?;
        }
        Ok(())
    }

    fn host_command(prefix: &str, command: &str) -> String {
        format!("{prefix}{command}")
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum HarnessLane {
        Standard,
        OpenClaw,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum NodeOutputMode {
        Raw,
        Redacted,
    }

    impl HarnessLane {
        fn command_prefix(self) -> &'static str {
            match self {
                HarnessLane::Standard => "",
                HarnessLane::OpenClaw => "openclaw-",
            }
        }

        fn output_mode(self) -> NodeOutputMode {
            match self {
                HarnessLane::Standard => NodeOutputMode::Raw,
                HarnessLane::OpenClaw => NodeOutputMode::Redacted,
            }
        }

        async fn run(
            self,
            args: &[String],
            envs: &[(&str, &str)],
        ) -> anyhow::Result<NodeInvocation> {
            run_e2e_node_invocation(args, envs, self.output_mode()).await
        }
    }

    struct OpenClawResultSidecar {
        file: NamedTempFile,
    }

    impl OpenClawResultSidecar {
        fn new() -> anyhow::Result<Self> {
            Ok(Self {
                file: NamedTempFile::new().context("failed to allocate openclaw result sidecar")?,
            })
        }

        fn path(&self) -> &Path {
            self.file.path()
        }

        fn write_raw(&self, raw: &str) -> anyhow::Result<()> {
            fs::write(self.path(), raw)?;
            Ok(())
        }

        fn read_json(&self) -> anyhow::Result<Value> {
            let result_text = fs::read_to_string(self.path())?;
            serde_json::from_str(&result_text).context("openclaw result decode failed")
        }

        fn cleanup(self) -> anyhow::Result<()> {
            self.file
                .close()
                .context("failed to remove openclaw result sidecar")?;
            Ok(())
        }
    }

    fn parse_result_line(stdout: &str) -> anyhow::Result<Value> {
        let line = stdout
            .lines()
            .find(|line| line.starts_with("RESULT_JSON="))
            .context("missing RESULT_JSON line in node output")?;
        Ok(serde_json::from_str(
            line.trim_start_matches("RESULT_JSON="),
        )?)
    }

    fn random_local_port() -> anyhow::Result<u16> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    async fn wait_for_broker_ready(broker_url: &str) -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        for _ in 0..50 {
            match client.get(format!("{broker_url}/readyz")).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::OK => return Ok(()),
                _ => sleep(Duration::from_millis(100)).await,
            }
        }

        anyhow::bail!("broker did not become ready at {broker_url}");
    }

    async fn spawn_broker_with_adapter_mode(
        artifact_dir: &Path,
        adapter_mode: &str,
    ) -> anyhow::Result<(Child, String)> {
        ensure_e2e_binaries_built()?;

        let port = random_local_port()?;
        let broker_url = format!("http://127.0.0.1:{port}");
        let db_path = artifact_dir.join("broker.sqlite");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let stdout_log = fs::File::create(artifact_dir.join("broker.stdout.log"))?;
        let stderr_log = fs::File::create(artifact_dir.join("broker.stderr.log"))?;
        let request_sign_adapter_url = if adapter_mode == "request-sign-production" {
            Some(spawn_mock_request_sign_service().await?)
        } else {
            None
        };

        let mut command = Command::new(e2e_binary_path("secret-broker"));
        command
            .current_dir(repo_root())
            .env("SECRET_BROKER_BIND", format!("127.0.0.1:{port}"))
            .env("SECRET_BROKER_DB", db_url)
            .env("SECRET_BROKER_MODE", "enforce")
            .env(
                "SECRET_BROKER_CLIENT_API_KEY",
                "loop5-client-key-1234567890",
            )
            .env(
                "SECRET_BROKER_APPROVER_API_KEY",
                "loop5-approver-key-1234567890",
            )
            .env(
                "SECRET_BROKER_ALLOWED_TARGET_PREFIXES",
                "https://example.com,handoff://local-helper/",
            )
            .env("SECRET_BROKER_PROVIDER_BRIDGE_MODE", "stub")
            .env("SECRET_BROKER_EXECUTION_ADAPTER_MODE", adapter_mode)
            .stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log));
        if let Some(url) = &request_sign_adapter_url {
            command.env("SECRET_BROKER_REQUEST_SIGN_ADAPTER_URL", url);
        }
        let child = command.spawn().context("failed to spawn broker process")?;

        wait_for_broker_ready(&broker_url).await?;
        Ok((child, broker_url))
    }

    async fn spawn_broker(artifact_dir: &Path) -> anyhow::Result<(Child, String)> {
        spawn_broker_with_adapter_mode(artifact_dir, "stub").await
    }

    async fn stop_broker(mut child: Child) -> anyhow::Result<()> {
        if child.try_wait()?.is_none() {
            child.start_kill()?;
            let _ = child.wait().await?;
        }
        Ok(())
    }

    async fn run_e2e_node_invocation(
        args: &[String],
        envs: &[(&str, &str)],
        output_mode: NodeOutputMode,
    ) -> anyhow::Result<NodeInvocation> {
        ensure_e2e_binaries_built()?;

        let mut command = Command::new(e2e_binary_path("e2e-node"));
        command.current_dir(repo_root()).args(args);
        for (key, value) in envs {
            command.env(key, value);
        }

        match output_mode {
            NodeOutputMode::Raw => {}
            NodeOutputMode::Redacted => {
                command.env("SECRET_BROKER_E2E_RESULT_MODE", "redacted");
            }
        }

        let sidecar = match output_mode {
            NodeOutputMode::Raw => None,
            NodeOutputMode::Redacted => {
                let sidecar = OpenClawResultSidecar::new()?;
                command.env(
                    "SECRET_BROKER_E2E_RESULT_PATH",
                    sidecar.path().to_string_lossy().to_string(),
                );
                Some(sidecar)
            }
        };

        let output = command
            .output()
            .await
            .context("failed to run e2e-node helper")?;

        let stdout = String::from_utf8(output.stdout).context("stdout must be utf-8")?;
        let stderr = String::from_utf8(output.stderr).context("stderr must be utf-8")?;

        if !output.status.success() {
            anyhow::bail!("e2e-node failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
        }

        let result = match sidecar {
            Some(sidecar) => {
                let result = sidecar.read_json()?;
                sidecar.cleanup()?;
                result
            }
            None => parse_result_line(&stdout)?,
        };

        Ok(NodeInvocation {
            stdout,
            stderr,
            result,
        })
    }

    async fn run_e2e_node_with_env(
        args: &[String],
        envs: &[(&str, &str)],
    ) -> anyhow::Result<NodeInvocation> {
        run_e2e_node_invocation(args, envs, NodeOutputMode::Raw).await
    }

    async fn run_e2e_node_expect_failure(
        args: &[String],
        envs: &[(&str, &str)],
    ) -> anyhow::Result<NodeInvocation> {
        ensure_e2e_binaries_built()?;

        let mut command = Command::new(e2e_binary_path("e2e-node"));
        command.current_dir(repo_root()).args(args);
        for (key, value) in envs {
            command.env(key, value);
        }

        let output = command
            .output()
            .await
            .context("failed to run e2e-node helper")?;

        let stdout = String::from_utf8(output.stdout).context("stdout must be utf-8")?;
        let stderr = String::from_utf8(output.stderr).context("stderr must be utf-8")?;

        if output.status.success() {
            anyhow::bail!("expected e2e-node failure\nstdout:\n{stdout}\nstderr:\n{stderr}");
        }

        let result = stdout
            .lines()
            .find(|line| line.starts_with("RESULT_JSON="))
            .map(|line| line.trim_start_matches("RESULT_JSON="))
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or_else(|| json!({}));

        Ok(NodeInvocation {
            stdout,
            stderr,
            result,
        })
    }

    #[derive(Clone, Copy)]
    struct NodeToNodeScenarioSpec<'a> {
        label: &'a str,
        request_type: &'a str,
        action: &'a str,
        target: &'a str,
        reason: &'a str,
        adapter_mode: &'a str,
        lane: HarnessLane,
        envs: &'a [(&'a str, &'a str)],
    }

    #[derive(Clone, Copy)]
    struct TrustedInputScenarioSpec<'a> {
        label: &'a str,
        reason: &'a str,
        lane: HarnessLane,
        envs: &'a [(&'a str, &'a str)],
    }

    async fn run_node_to_node_scenario(
        spec: NodeToNodeScenarioSpec<'_>,
    ) -> anyhow::Result<NodeToNodeOutcome> {
        let artifact_dir = new_artifact_dir(spec.label)?;
        let fixture_secret = "stub-secret-material".to_string();

        let (broker_child, broker_url) =
            spawn_broker_with_adapter_mode(&artifact_dir, spec.adapter_mode).await?;

        let create = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "create"),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--request-type".to_string(),
                    spec.request_type.to_string(),
                    "--secret-ref".to_string(),
                    "bw://vault/item/login".to_string(),
                    "--action".to_string(),
                    spec.action.to_string(),
                    "--target".to_string(),
                    spec.target.to_string(),
                    "--reason".to_string(),
                    spec.reason.to_string(),
                ],
                spec.envs,
            )
            .await?;
        let request_id = create.result["id"]
            .as_str()
            .context("create result missing request id")?
            .to_string();

        let approve = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "approve"),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-approver-key-1234567890".to_string(),
                    "--id".to_string(),
                    request_id.clone(),
                ],
                spec.envs,
            )
            .await?;
        let capability_token = approve.result["capability_token"]
            .as_str()
            .context("approve result missing capability token")?
            .to_string();

        let execute = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "execute"),
                    "--broker-url".to_string(),
                    broker_url,
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--id".to_string(),
                    request_id.clone(),
                    "--capability-token".to_string(),
                    capability_token.clone(),
                    "--action".to_string(),
                    spec.action.to_string(),
                    "--target".to_string(),
                    spec.target.to_string(),
                ],
                spec.envs,
            )
            .await?;

        let create_result = create.result.clone();
        let approve_result = approve.result.clone();
        let execute_result = execute.result.clone();
        let artifact_sensitives = [fixture_secret.as_str(), capability_token.as_str()];

        write_redacted_artifacts(
            &artifact_dir,
            &[
                ("client.stdout.log", create.stdout.as_str()),
                ("client.stderr.log", create.stderr.as_str()),
                ("approver.stdout.log", approve.stdout.as_str()),
                ("approver.stderr.log", approve.stderr.as_str()),
                ("execute.stdout.log", execute.stdout.as_str()),
                ("execute.stderr.log", execute.stderr.as_str()),
            ],
            &artifact_sensitives,
        )?;
        write_redacted_artifact(
            &artifact_dir.join("summary.json"),
            &json!({
                "request_id": request_id,
                "capability_token": capability_token,
                "create": create_result,
                "approve": approve_result,
                "execute": execute_result
            })
            .to_string(),
            &artifact_sensitives,
        )?;

        stop_broker(broker_child).await?;

        Ok(NodeToNodeOutcome {
            artifact_dir,
            fixture_secret,
            request_id,
            capability_token,
            client_stdout: create.stdout,
            client_stderr: create.stderr,
            approver_stdout: approve.stdout,
            approver_stderr: approve.stderr,
            execute_stdout: execute.stdout,
            execute_stderr: execute.stderr,
            create_result,
            approve_result,
            execute_result,
        })
    }

    async fn run_node_to_node_happy_path() -> anyhow::Result<NodeToNodeOutcome> {
        run_node_to_node_scenario(NodeToNodeScenarioSpec {
            label: "node-to-node-happy-path",
            request_type: "password_fill",
            action: "password_fill",
            target: "https://example.com/login",
            reason: "loop 5 happy path",
            adapter_mode: "stub",
            lane: HarnessLane::Standard,
            envs: &[],
        })
        .await
    }

    async fn run_node_to_node_target_mismatch() -> anyhow::Result<NodeToNodeOutcome> {
        run_node_to_node_scenario(NodeToNodeScenarioSpec {
            label: "node-to-node-target-mismatch",
            request_type: "password_fill",
            action: "password_fill",
            target: "https://example.com/profile",
            reason: "loop 5 happy path",
            adapter_mode: "stub",
            lane: HarnessLane::Standard,
            envs: &[],
        })
        .await
    }

    async fn run_trusted_input_node_to_node_scenario(
        spec: TrustedInputScenarioSpec<'_>,
    ) -> anyhow::Result<TrustedInputNodeToNodeOutcome> {
        let artifact_dir = new_artifact_dir(spec.label)?;
        let fixture_secret = "stub-secret-material".to_string();
        let provider_secret_ref = "bw://vault/item/login".to_string();

        let (broker_child, broker_url) = spawn_broker(&artifact_dir).await?;

        let trusted_start = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "trusted-start"),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--request-type".to_string(),
                    "password_fill".to_string(),
                    "--action".to_string(),
                    "password_fill".to_string(),
                    "--target".to_string(),
                    "https://example.com/login".to_string(),
                    "--reason".to_string(),
                    spec.reason.to_string(),
                ],
                spec.envs,
            )
            .await?;
        let session_id = trusted_start.result["id"]
            .as_str()
            .context("trusted start result missing session id")?
            .to_string();
        let completion_token = trusted_start.result["completion_token"]
            .as_str()
            .context("trusted start result missing completion token")?
            .to_string();

        let trusted_complete = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "trusted-complete"),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--id".to_string(),
                    session_id,
                    "--completion-token".to_string(),
                    completion_token.clone(),
                    "--secret-ref".to_string(),
                    provider_secret_ref.clone(),
                ],
                spec.envs,
            )
            .await?;
        let opaque_ref = trusted_complete.result["opaque_ref"]
            .as_str()
            .context("trusted complete result missing opaque ref")?
            .to_string();

        let create = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "create"),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--request-type".to_string(),
                    "password_fill".to_string(),
                    "--secret-ref".to_string(),
                    opaque_ref.clone(),
                    "--action".to_string(),
                    "password_fill".to_string(),
                    "--target".to_string(),
                    "https://example.com/login".to_string(),
                    "--reason".to_string(),
                    spec.reason.to_string(),
                ],
                spec.envs,
            )
            .await?;
        let request_id = create.result["id"]
            .as_str()
            .context("create result missing request id")?
            .to_string();

        let approve = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "approve"),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-approver-key-1234567890".to_string(),
                    "--id".to_string(),
                    request_id.clone(),
                ],
                spec.envs,
            )
            .await?;
        let capability_token = approve.result["capability_token"]
            .as_str()
            .context("approve result missing capability token")?
            .to_string();

        let execute = spec
            .lane
            .run(
                &[
                    host_command(spec.lane.command_prefix(), "execute"),
                    "--broker-url".to_string(),
                    broker_url,
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--id".to_string(),
                    request_id.clone(),
                    "--capability-token".to_string(),
                    capability_token.clone(),
                    "--action".to_string(),
                    "password_fill".to_string(),
                    "--target".to_string(),
                    "https://example.com/login".to_string(),
                ],
                spec.envs,
            )
            .await?;

        let trusted_start_result = trusted_start.result.clone();
        let trusted_complete_result = trusted_complete.result.clone();
        let create_result = create.result.clone();
        let approve_result = approve.result.clone();
        let execute_result = execute.result.clone();
        let mut artifact_sensitives = vec![
            fixture_secret.as_str(),
            completion_token.as_str(),
            capability_token.as_str(),
            opaque_ref.as_str(),
            provider_secret_ref.as_str(),
        ];
        if matches!(spec.lane, HarnessLane::OpenClaw) {
            artifact_sensitives.push(spec.reason);
        }

        write_redacted_artifacts(
            &artifact_dir,
            &[
                ("trusted-start.stdout.log", trusted_start.stdout.as_str()),
                ("trusted-start.stderr.log", trusted_start.stderr.as_str()),
                (
                    "trusted-complete.stdout.log",
                    trusted_complete.stdout.as_str(),
                ),
                (
                    "trusted-complete.stderr.log",
                    trusted_complete.stderr.as_str(),
                ),
                ("client.stdout.log", create.stdout.as_str()),
                ("client.stderr.log", create.stderr.as_str()),
                ("approver.stdout.log", approve.stdout.as_str()),
                ("approver.stderr.log", approve.stderr.as_str()),
                ("execute.stdout.log", execute.stdout.as_str()),
                ("execute.stderr.log", execute.stderr.as_str()),
            ],
            &artifact_sensitives,
        )?;
        write_redacted_artifact(
            &artifact_dir.join("summary.json"),
            &json!({
                "host": if matches!(spec.lane, HarnessLane::OpenClaw) { "openclaw" } else { "standard" },
                "opaque_ref": opaque_ref,
                "request_id": request_id,
                "capability_token": capability_token,
                "trusted_start": trusted_start_result,
                "trusted_complete": trusted_complete_result,
                "create": create_result,
                "approve": approve_result,
                "execute": execute_result
            })
            .to_string(),
            &artifact_sensitives,
        )?;

        stop_broker(broker_child).await?;

        Ok(TrustedInputNodeToNodeOutcome {
            artifact_dir,
            fixture_secret,
            opaque_ref,
            request_id,
            capability_token,
            trusted_start_stdout: trusted_start.stdout,
            trusted_start_stderr: trusted_start.stderr,
            trusted_complete_stdout: trusted_complete.stdout,
            trusted_complete_stderr: trusted_complete.stderr,
            create_stdout: create.stdout,
            create_stderr: create.stderr,
            approver_stdout: approve.stdout,
            approver_stderr: approve.stderr,
            execute_stdout: execute.stdout,
            execute_stderr: execute.stderr,
            trusted_start_result,
            trusted_complete_result,
            create_result,
            approve_result,
            execute_result,
        })
    }

    async fn run_request_sign_node_to_node_happy_path() -> anyhow::Result<NodeToNodeOutcome> {
        run_node_to_node_scenario(NodeToNodeScenarioSpec {
            label: "node-to-node-request-sign",
            request_type: "request_sign",
            action: "request_sign",
            target: "https://example.com/sign",
            reason: "node-to-node-request-sign happy path",
            adapter_mode: "request-sign-production",
            lane: HarnessLane::Standard,
            envs: &[],
        })
        .await
    }

    async fn run_handoff_node_to_node_happy_path() -> anyhow::Result<NodeToNodeOutcome> {
        run_node_to_node_scenario(NodeToNodeScenarioSpec {
            label: "node-to-node-credential-handoff",
            request_type: "credential_handoff",
            action: "credential_handoff",
            target: "handoff://local-helper/session",
            reason: "node-to-node-credential-handoff happy path",
            adapter_mode: "stub",
            lane: HarnessLane::Standard,
            envs: &[],
        })
        .await
    }

    async fn run_openclaw_host_happy_path() -> anyhow::Result<TrustedInputNodeToNodeOutcome> {
        run_trusted_input_node_to_node_scenario(TrustedInputScenarioSpec {
            label: "openclaw-host-happy-path",
            reason: "openclaw-canary-secret",
            lane: HarnessLane::OpenClaw,
            envs: &[
                ("SECRET_BROKER_E2E_REDACTION_MODE", "supported"),
                ("SECRET_BROKER_E2E_CANARY_SECRET", "openclaw-canary-secret"),
            ],
        })
        .await
    }

    async fn run_trusted_input_node_to_node_happy_path(
    ) -> anyhow::Result<TrustedInputNodeToNodeOutcome> {
        run_trusted_input_node_to_node_scenario(TrustedInputScenarioSpec {
            label: "trusted-input-node-to-node-happy-path",
            reason: "trusted input happy path",
            lane: HarnessLane::Standard,
            envs: &[],
        })
        .await
    }

    async fn update_request_action_target(
        cfg: &Config,
        id: &str,
        action: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        let pool = connect_sqlite(&cfg.db_url).await?;
        sqlx::query(
            "UPDATE secret_broker_requests
             SET action = ?, target = ?, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(action)
        .bind(target)
        .bind(id)
        .execute(&pool)
        .await?;
        Ok(())
    }

    async fn clear_request_expiry(cfg: &Config, id: &str) -> anyhow::Result<()> {
        let pool = connect_sqlite(&cfg.db_url).await?;
        sqlx::query(
            "UPDATE secret_broker_requests
             SET capability_expires_at = NULL, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(id)
        .execute(&pool)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn health_reports_provider_bridge_mode() -> anyhow::Result<()> {
        let (app, _cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_response(resp).await;
        assert_eq!(body["provider"]["mode"], "stub");
        assert_eq!(body["provider"]["provider"], "bitwarden_stub");
        assert_eq!(body["adapter"]["mode"], "stub");
        assert_eq!(body["adapter"]["adapter"], "registry_stub");
        assert_eq!(
            body["adapter"]["supported_actions"][0]["action"],
            "password_fill"
        );
        assert_eq!(
            body["adapter"]["supported_actions"][1]["action"],
            "request_sign"
        );
        assert_eq!(
            body["adapter"]["supported_actions"][2]["action"],
            "credential_handoff"
        );
        Ok(())
    }

    #[tokio::test]
    async fn health_reports_request_sign_production_adapter_mode() -> anyhow::Result<()> {
        let (app, _cfg) =
            setup_app_with_modes(ProviderBridgeMode::Stub, "request-sign-production").await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_response(resp).await;
        assert_eq!(body["adapter"]["mode"], "request-sign-production");
        assert_eq!(body["adapter"]["adapter"], "request_sign_production_v1");
        assert_eq!(
            body["adapter"]["supported_actions"][0]["action"],
            "request_sign"
        );
        assert_eq!(body["adapter"]["supported_actions"][0]["status"], "shipped");
        Ok(())
    }

    #[tokio::test]
    async fn readyz_remains_green_when_stub_provider_is_enabled() -> anyhow::Result<()> {
        let (app, _cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;

        let req = Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn health_reports_bitwarden_production_provider_bridge_mode() -> anyhow::Result<()> {
        let provider_endpoint =
            spawn_mock_bitwarden_provider_service("bitwarden-production-token").await?;
        let (app, _cfg) = setup_app_with_bitwarden_provider_mode(
            &provider_endpoint,
            "bitwarden-production-token",
            "off",
        )
        .await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_response(resp).await;
        assert_eq!(body["provider"]["mode"], "bitwarden-production");
        assert_eq!(body["provider"]["provider"], "bitwarden_production_v1");
        assert_eq!(body["provider"]["configured"], true);
        assert_eq!(body["provider"]["ready"], true);
        Ok(())
    }

    #[tokio::test]
    async fn enforce_mode_requires_approval_for_password_actions() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let list_req = Request::builder()
            .method("GET")
            .uri("/v1/requests?limit=10")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())?;
        let list_resp = app.clone().oneshot(list_req).await?;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_json = json_response(list_resp).await;
        let item = list_json["data"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == id))
            .expect("created request in list");
        assert_eq!(item["status"], "pending_approval");
        assert_eq!(item["requires_approval"], true);
        Ok(())
    }

    #[tokio::test]
    async fn execute_token_is_single_use() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_body = json!({
            "id": id,
            "capability_token": token,
            "action": "password_fill",
            "target": "https://example.com/login"
        });
        let execute_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(exec_body.to_string()))?;
        let execute_resp = app.clone().oneshot(execute_req).await?;
        assert_eq!(execute_resp.status(), StatusCode::OK);

        let replay_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(exec_body.to_string()))?;
        let replay_resp = app.clone().oneshot(replay_req).await?;
        assert_eq!(replay_resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn trusted_input_session_lifecycle_returns_broker_opaque_ref_only() -> anyhow::Result<()>
    {
        let (app, cfg) = setup_app().await?;

        let session_json = start_trusted_input_session(&app, &cfg).await;
        let session_id = session_json["data"]["id"]
            .as_str()
            .expect("trusted input session id");
        let completion_token = session_json["data"]["completion_token"]
            .as_str()
            .expect("trusted input completion token");
        assert_eq!(session_json["data"]["status"], "pending_input");

        let pending_resp = get_trusted_input_session(&app, &cfg, session_id).await;
        assert_eq!(pending_resp.status(), StatusCode::OK);
        let pending_json = json_response(pending_resp).await;
        assert_eq!(pending_json["data"]["status"], "pending_input");
        assert!(pending_json["data"]["opaque_ref"].is_null());

        let provider_secret_ref = "bw://vault/item/login";
        let complete_resp = complete_trusted_input_session(
            &app,
            &cfg,
            session_id,
            completion_token,
            provider_secret_ref,
        )
        .await;
        assert_eq!(complete_resp.status(), StatusCode::OK);
        let complete_json = json_response(complete_resp).await;
        let opaque_ref = complete_json["data"]["opaque_ref"]
            .as_str()
            .expect("opaque ref");
        assert_eq!(complete_json["data"]["status"], "completed");
        assert!(opaque_ref.starts_with("tir://session/"));
        assert!(!complete_json.to_string().contains(provider_secret_ref));

        let completed_resp = get_trusted_input_session(&app, &cfg, session_id).await;
        assert_eq!(completed_resp.status(), StatusCode::OK);
        let completed_json = json_response(completed_resp).await;
        assert_eq!(completed_json["data"]["opaque_ref"], opaque_ref);
        assert!(!completed_json.to_string().contains(provider_secret_ref));
        Ok(())
    }

    #[tokio::test]
    async fn trusted_input_opaque_ref_can_only_be_consumed_once() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;

        let session_json = start_trusted_input_session(&app, &cfg).await;
        let session_id = session_json["data"]["id"]
            .as_str()
            .expect("trusted input session id");
        let completion_token = session_json["data"]["completion_token"]
            .as_str()
            .expect("trusted input completion token");

        let complete_resp = complete_trusted_input_session(
            &app,
            &cfg,
            session_id,
            completion_token,
            "bw://vault/item/login",
        )
        .await;
        assert_eq!(complete_resp.status(), StatusCode::OK);
        let complete_json = json_response(complete_resp).await;
        let opaque_ref = complete_json["data"]["opaque_ref"]
            .as_str()
            .expect("opaque ref")
            .to_string();

        let first_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": opaque_ref,
                    "action": "password_fill",
                    "target": "https://example.com/login",
                    "reason": "trusted host input"
                })
                .to_string(),
            ))?;
        let first_resp = app.clone().oneshot(first_req).await?;
        assert_eq!(first_resp.status(), StatusCode::OK);

        let second_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": opaque_ref,
                    "action": "password_fill",
                    "target": "https://example.com/login",
                    "reason": "trusted host input replay"
                })
                .to_string(),
            ))?;
        let second_resp = app.clone().oneshot(second_req).await?;
        assert_eq!(second_resp.status(), StatusCode::CONFLICT);
        let second_json = json_response(second_resp).await;
        assert_eq!(second_json["code"], "trusted_input_consumed");
        Ok(())
    }

    #[tokio::test]
    async fn execute_rejects_action_mismatch() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        update_request_action_target(&cfg, &id, "copy_secret", "https://example.com/login").await?;

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "copy_secret",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;
        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "action_mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn execute_rejects_target_mismatch() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        update_request_action_target(&cfg, &id, "password_fill", "https://evil.example.com/login")
            .await?;

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://evil.example.com/login"
                })
                .to_string(),
            ))?;
        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "target_mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn capability_expiry_is_enforced() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        clear_request_expiry(&cfg, &id).await?;

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;
        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "invalid_capability_context");
        Ok(())
    }

    #[tokio::test]
    async fn approval_payload_is_masked_and_truthful() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);

        let body = json_response(approve_resp).await;
        assert_eq!(body["data"]["id"], id);
        assert_eq!(body["data"]["status"], "approved");
        assert_eq!(
            body["data"]["approval_payload"]["request_type"],
            "password_fill"
        );
        assert_eq!(body["data"]["approval_payload"]["action"], "password_fill");
        assert_eq!(
            body["data"]["approval_payload"]["target"],
            "https://example.com/login"
        );
        assert_eq!(
            body["data"]["approval_payload"]["secret_ref_masked"],
            "bw****in"
        );
        assert_eq!(
            body["data"]["approval_payload"]["reason"],
            "login automation"
        );
        assert!(!body.to_string().contains("bw://vault/item/login"));
        Ok(())
    }

    #[tokio::test]
    async fn deny_clears_capability_state() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);

        let deny_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/deny"))
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::from(
                json!({ "reason": "no longer approved" }).to_string(),
            ))?;
        let deny_resp = app.clone().oneshot(deny_req).await?;
        assert_eq!(deny_resp.status(), StatusCode::OK);

        let list_req = Request::builder()
            .method("GET")
            .uri("/v1/requests?limit=10")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())?;
        let list_resp = app.clone().oneshot(list_req).await?;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_json = json_response(list_resp).await;
        let item = list_json["data"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == id))
            .expect("denied request in list");

        assert_eq!(item["status"], "denied");
        assert!(item["capability_expires_at"].is_null());
        assert!(item["capability_used_at"].is_null());
        Ok(())
    }

    #[tokio::test]
    async fn approve_endpoint_requires_approver_key() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn execute_uses_stub_adapter_without_leaking_plaintext() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(
            body["data"]["result"]["adapter"]["adapter"],
            "password_fill_stub"
        );
        assert_eq!(body["data"]["result"]["adapter"]["outcome"], "filled");
        assert_eq!(
            body["data"]["result"]["adapter"]["target"],
            "https://example.com/login"
        );
        assert!(!body.to_string().contains("stub-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn policy_denies_unsupported_adapter_actions_before_execution() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "clipboard_copy",
                    "secret_ref": "bw://vault/item/login",
                    "action": "copy_secret",
                    "target": "https://example.com/login",
                    "reason": "unsupported action test"
                })
                .to_string(),
            ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::FORBIDDEN);
        let create_json = json_response(create_resp).await;
        assert_eq!(create_json["code"], "policy_denied");
        Ok(())
    }

    #[tokio::test]
    async fn execute_rejects_adapter_target_mismatch() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": "bw://vault/item/login",
                    "action": "password_fill",
                    "target": "https://example.com/profile",
                    "reason": "unsupported target test"
                })
                .to_string(),
            ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_json = json_response(create_resp).await;
        let id = create_json["data"]["id"].as_str().expect("id").to_string();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/profile"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "adapter_target_mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn execute_uses_request_sign_adapter_without_leaking_plaintext() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;
        let id = create_request_for_action(
            &app,
            &cfg,
            "request_sign",
            "bw://vault/item/login",
            "request_sign",
            "https://example.com/sign",
            "sign outbound request",
        )
        .await?;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "request_sign",
                    "target": "https://example.com/sign"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(
            body["data"]["result"]["adapter"]["adapter"],
            "request_sign_stub"
        );
        assert_eq!(body["data"]["result"]["adapter"]["outcome"], "signed");
        assert!(!body.to_string().contains("stub-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn execute_uses_request_sign_production_adapter_without_leaking_plaintext(
    ) -> anyhow::Result<()> {
        let (app, cfg) =
            setup_app_with_modes(ProviderBridgeMode::Stub, "request-sign-production").await?;
        let id = create_request_for_action(
            &app,
            &cfg,
            "request_sign",
            "bw://vault/item/login",
            "request_sign",
            "https://example.com/sign",
            "sign outbound request in production mode",
        )
        .await?;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "request_sign",
                    "target": "https://example.com/sign"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(
            body["data"]["result"]["adapter"]["adapter"],
            "request_sign_production_v1"
        );
        assert_eq!(body["data"]["result"]["adapter"]["outcome"], "signed");
        assert_eq!(body["data"]["result"]["masked"]["action"], "request_sign");
        assert_eq!(
            body["data"]["result"]["masked"]["target"],
            "https://example.com/sign"
        );
        assert_eq!(body["data"]["result"]["policy"]["outcome"], "step_up");
        assert!(body["data"]["result"]["adapter"]["signature_ref_masked"]
            .as_str()
            .expect("signature ref mask")
            .starts_with("sig****"));
        assert!(!body.to_string().contains("stub-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn request_sign_production_adapter_audits_success_and_failure_without_plaintext(
    ) -> anyhow::Result<()> {
        let (app, cfg) =
            setup_app_with_modes(ProviderBridgeMode::Stub, "request-sign-production").await?;
        let id = create_request_for_action(
            &app,
            &cfg,
            "request_sign",
            "bw://vault/item/login",
            "request_sign",
            "https://example.com/sign",
            "audit request-sign production mode",
        )
        .await?;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_success_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "request_sign",
                    "target": "https://example.com/sign"
                })
                .to_string(),
            ))?;
        let exec_success_resp = app.clone().oneshot(exec_success_req).await?;
        assert_eq!(exec_success_resp.status(), StatusCode::OK);

        let failed_id = create_request_for_action(
            &app,
            &cfg,
            "request_sign",
            "bw://vault/item/login",
            "request_sign",
            "https://example.com/not-sign",
            "audit failed request-sign production mode",
        )
        .await?;

        let failed_approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{failed_id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let failed_approve_resp = app.clone().oneshot(failed_approve_req).await?;
        let failed_approve_json = json_response(failed_approve_resp).await;
        let failed_token = failed_approve_json["data"]["capability_token"]
            .as_str()
            .expect("failed capability token");

        let exec_failed_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": failed_id,
                    "capability_token": failed_token,
                    "action": "request_sign",
                    "target": "https://example.com/not-sign"
                })
                .to_string(),
            ))?;
        let exec_failed_resp = app.clone().oneshot(exec_failed_req).await?;
        assert_eq!(exec_failed_resp.status(), StatusCode::BAD_REQUEST);
        let failed_body = json_response(exec_failed_resp).await;
        assert_eq!(failed_body["code"], "adapter_target_mismatch");
        assert!(!failed_body.to_string().contains("stub-secret-material"));

        let audit_req = Request::builder()
            .method("GET")
            .uri("/v1/audit?limit=30")
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let audit_resp = app.clone().oneshot(audit_req).await?;
        assert_eq!(audit_resp.status(), StatusCode::OK);
        let audit_json = json_response(audit_resp).await;
        let rows = audit_json["data"].as_array().expect("audit rows");

        let success = rows
            .iter()
            .find(|row| {
                row["action"] == "request.adapter_succeeded" && row["request_id"] == id.as_str()
            })
            .expect("success audit row");
        assert_eq!(success["details"]["adapter"], "request_sign_production_v1");
        assert_eq!(success["details"]["mode"], "request-sign-production");
        assert_eq!(success["details"]["action"], "request_sign");
        assert_eq!(success["details"]["target"], "https://example.com/sign");
        assert_eq!(success["details"]["policy"]["outcome"], "step_up");
        assert!(!success.to_string().contains("stub-secret-material"));

        let failure = rows
            .iter()
            .find(|row| {
                row["action"] == "request.adapter_failed" && row["request_id"] == failed_id.as_str()
            })
            .expect("failure audit row");
        assert_eq!(failure["details"]["adapter"], "request_sign_production_v1");
        assert_eq!(failure["details"]["mode"], "request-sign-production");
        assert_eq!(failure["details"]["code"], "adapter_target_mismatch");
        assert_eq!(failure["details"]["action"], "request_sign");
        assert_eq!(failure["details"]["target"], "https://example.com/not-sign");
        assert_eq!(failure["details"]["policy"]["outcome"], "step_up");
        assert!(!failure.to_string().contains("stub-secret-material"));
        Ok(())
    }

    async fn bitwarden_provider_failure_case(
        provider_bridge_token: &str,
        secret_ref: &str,
        expected_reason: &str,
    ) -> anyhow::Result<()> {
        let provider_endpoint =
            spawn_mock_bitwarden_provider_service("bitwarden-production-token").await?;
        let (app, cfg) = setup_app_with_bitwarden_provider_mode(
            &provider_endpoint,
            provider_bridge_token,
            "off",
        )
        .await?;
        let id = create_request_for_action(
            &app,
            &cfg,
            "password_fill",
            secret_ref,
            "password_fill",
            "https://example.com/login",
            "production provider mediation",
        )
        .await?;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "provider_unavailable");
        assert!(!body.to_string().contains("production-secret-material"));

        let audit_req = Request::builder()
            .method("GET")
            .uri("/v1/audit?limit=25")
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let audit_resp = app.clone().oneshot(audit_req).await?;
        assert_eq!(audit_resp.status(), StatusCode::OK);
        let audit_json = json_response(audit_resp).await;
        let rows = audit_json["data"].as_array().expect("audit rows");
        let item = rows
            .iter()
            .find(|row| {
                row["action"] == "request.provider_resolve_failed" && row["request_id"] == id
            })
            .expect("provider failure audit row");
        assert_eq!(item["details"]["code"], "provider_unavailable");
        assert_eq!(item["details"]["reason"], expected_reason);
        assert_eq!(item["details"]["mode"], "bitwarden-production");
        assert_eq!(item["details"]["provider"], "bitwarden_production_v1");
        assert!(!item.to_string().contains("production-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn execute_uses_bitwarden_production_provider_without_leaking_plaintext(
    ) -> anyhow::Result<()> {
        let provider_endpoint =
            spawn_mock_bitwarden_provider_service("bitwarden-production-token").await?;
        let (app, cfg) = setup_app_with_bitwarden_provider_mode(
            &provider_endpoint,
            "bitwarden-production-token",
            "off",
        )
        .await?;
        let id = create_request_for_action(
            &app,
            &cfg,
            "password_fill",
            "bw://vault/item/login",
            "password_fill",
            "https://example.com/login",
            "production provider mediation success",
        )
        .await?;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(
            body["data"]["result"]["provider"]["provider"],
            "bitwarden_production_v1"
        );
        assert_eq!(body["data"]["result"]["provider"]["resolution"], "resolved");
        assert_eq!(
            body["data"]["result"]["provider"]["secret_ref_masked"],
            "bw****in"
        );
        assert!(!body.to_string().contains("production-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn bitwarden_production_provider_outage_is_masked_and_audited() -> anyhow::Result<()> {
        bitwarden_provider_failure_case(
            "bitwarden-production-token",
            "bw://vault/item/outage",
            "provider_outage",
        )
        .await
    }

    #[tokio::test]
    async fn bitwarden_production_provider_revoked_credential_is_masked_and_audited(
    ) -> anyhow::Result<()> {
        bitwarden_provider_failure_case(
            "revoked-broker-token",
            "bw://vault/item/login",
            "revoked_credential",
        )
        .await
    }

    #[tokio::test]
    async fn bitwarden_production_provider_missing_ref_is_masked_and_audited() -> anyhow::Result<()>
    {
        bitwarden_provider_failure_case(
            "bitwarden-production-token",
            "bw://vault/item/missing",
            "missing_ref",
        )
        .await
    }

    #[tokio::test]
    async fn bitwarden_production_provider_binding_mismatch_is_masked_and_audited(
    ) -> anyhow::Result<()> {
        bitwarden_provider_failure_case(
            "bitwarden-production-token",
            "bw://vault/item/binding-mismatch",
            "binding_mismatch",
        )
        .await
    }

    #[tokio::test]
    async fn execute_uses_credential_handoff_adapter_without_leaking_plaintext(
    ) -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;
        let id = create_request_for_action(
            &app,
            &cfg,
            "credential_handoff",
            "bw://vault/item/login",
            "credential_handoff",
            "handoff://local-helper/session",
            "handoff credential to trusted helper",
        )
        .await?;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "credential_handoff",
                    "target": "handoff://local-helper/session"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(
            body["data"]["result"]["adapter"]["adapter"],
            "credential_handoff_stub"
        );
        assert_eq!(body["data"]["result"]["adapter"]["outcome"], "handed_off");
        assert!(!body.to_string().contains("stub-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn execute_masks_provider_failures_and_keeps_request_unexecuted() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_provider_mode(ProviderBridgeMode::Stub).await?;

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": "bw://vault/item/missing",
                    "action": "password_fill",
                    "target": "https://example.com/login",
                    "reason": "login automation"
                })
                .to_string(),
            ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_json = json_response(create_resp).await;
        let id = create_json["data"]["id"].as_str().expect("id").to_string();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "provider_unavailable");
        assert!(!body.to_string().contains("missing"));

        let list_req = Request::builder()
            .method("GET")
            .uri("/v1/requests?limit=10")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())?;
        let list_resp = app.clone().oneshot(list_req).await?;
        let list_json = json_response(list_resp).await;
        let item = list_json["data"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == id))
            .expect("request still present");
        assert_eq!(item["status"], "approved");
        assert!(item["capability_used_at"].is_null());
        Ok(())
    }

    #[tokio::test]
    async fn audit_endpoint_requires_approver_key() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let req = Request::builder()
            .method("GET")
            .uri("/v1/audit")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn policy_denies_disallowed_target_prefix() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": "bw://vault/item/login",
                    "action": "password_fill",
                    "target": "ftp://not-allowed.example.com",
                    "reason": "login automation"
                })
                .to_string(),
            ))?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn policy_engine_marks_public_request_sign_as_step_up_with_explanation(
    ) -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;

        let req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "request_sign",
                    "secret_ref": "bw://vault/item/login",
                    "action": "request_sign",
                    "target": "https://example.com/sign",
                    "reason": "sign outbound request"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_response(resp).await;
        assert_eq!(body["data"]["status"], "pending_approval");
        assert_eq!(body["data"]["policy"]["outcome"], "step_up");
        assert_eq!(body["data"]["policy"]["environment"], "public");
        assert!(
            body["data"]["policy"]["risk_score"]
                .as_i64()
                .expect("risk score")
                >= 60
        );
        assert!(body["data"]["policy"]["reasons"]
            .as_array()
            .expect("policy reasons")
            .iter()
            .any(|item| item == "signing_action"));
        assert!(body["data"]["policy"]["reasons"]
            .as_array()
            .expect("policy reasons")
            .iter()
            .any(|item| item == "public_target"));
        Ok(())
    }

    #[tokio::test]
    async fn policy_engine_denies_secret_export_actions_fail_closed() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;

        let req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "secret_export",
                    "secret_ref": "bw://vault/item/login",
                    "action": "secret_export",
                    "target": "https://example.com/export",
                    "reason": "unsafe export"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "policy_denied");
        assert!(!body.to_string().contains("bw://vault/item/login"));
        Ok(())
    }

    #[tokio::test]
    async fn approval_payload_includes_policy_summary() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "request_sign",
                    "secret_ref": "bw://vault/item/login",
                    "action": "request_sign",
                    "target": "https://example.com/sign",
                    "reason": "sign outbound request"
                })
                .to_string(),
            ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_json = json_response(create_resp).await;
        let id = create_json["data"]["id"].as_str().expect("id").to_string();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;

        assert_eq!(
            approve_json["data"]["approval_payload"]["policy"]["outcome"],
            "step_up"
        );
        assert_eq!(
            approve_json["data"]["approval_payload"]["policy"]["environment"],
            "public"
        );
        assert!(
            approve_json["data"]["approval_payload"]["policy"]["risk_score"]
                .as_i64()
                .expect("risk score")
                >= 60
        );
        Ok(())
    }

    #[tokio::test]
    async fn health_reports_identity_verification_mode() -> anyhow::Result<()> {
        let (app, _cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::IdentityVerificationMode::Stub,
        )
        .await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(body["identity"]["mode"], "stub");
        assert_eq!(body["identity"]["configured"], true);
        assert_eq!(body["identity"]["ready"], true);
        Ok(())
    }

    #[tokio::test]
    async fn health_reports_host_signed_identity_verification_mode() -> anyhow::Result<()> {
        let (app, _cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(body["identity"]["mode"], "host-signed");
        Ok(())
    }

    #[tokio::test]
    async fn health_reports_host_signed_health_uses_only_usable_hosts() -> anyhow::Result<()> {
        let (app, _cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_response(resp).await;
        assert_eq!(body["identity"]["baseline_mode"], "host-signed");
        assert_eq!(
            body["identity"]["host_signed_hosts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            body["identity"]["host_signed_hosts"][0],
            "openclaw-http-host"
        );
        Ok(())
    }

    #[test]
    fn config_from_env_rejects_invalid_identity_mode() {
        let result = with_env_vars(
            &[(
                "SECRET_BROKER_IDENTITY_VERIFICATION_MODE",
                Some("typo-mode"),
            )],
            config_from_env,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_config_rejects_global_host_signed_without_host_config() {
        let result = with_env_vars(
            &[(
                "SECRET_BROKER_IDENTITY_VERIFICATION_MODE",
                Some("host-signed"),
            )],
            || config_from_env().and_then(|cfg| validate_config(&cfg)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_config_accepts_host_signed_without_attestation_key() {
        let result = with_env_vars(
            &[
                (
                    "SECRET_BROKER_IDENTITY_VERIFICATION_MODE",
                    Some("host-signed"),
                ),
                ("SECRET_BROKER_IDENTITY_ATTESTATION_KEY", None),
                (
                    "SECRET_BROKER_IDENTITY_HOST_SIGNING_KEYS",
                    Some("openclaw-http-host=openclaw-host-signing-key"),
                ),
                (
                    "SECRET_BROKER_TRUSTED_HOST_RUNTIME_PAIRS",
                    Some("openclaw-http-host=openclaw-runtime-v1"),
                ),
            ],
            || config_from_env().and_then(|cfg| validate_config(&cfg)),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_config_rejects_global_hardware_backed_mode() {
        let result = with_env_vars(
            &[(
                "SECRET_BROKER_IDENTITY_VERIFICATION_MODE",
                Some("hardware-backed"),
            )],
            || config_from_env().and_then(|cfg| validate_config(&cfg)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_config_rejects_stub_without_attestation_key() {
        let result = with_env_vars(
            &[
                ("SECRET_BROKER_IDENTITY_VERIFICATION_MODE", Some("stub")),
                ("SECRET_BROKER_IDENTITY_ATTESTATION_KEY", None),
            ],
            || config_from_env().and_then(|cfg| validate_config(&cfg)),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_request_rejects_missing_identity_headers_when_attestation_required(
    ) -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::IdentityVerificationMode::Stub,
        )
        .await?;

        let req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "request_type": "password_fill",
                    "secret_ref": "bw://vault/item/login",
                    "action": "password_fill",
                    "target": "https://example.com/login",
                    "reason": "identity enforced"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "invalid_identity");
        Ok(())
    }

    #[tokio::test]
    async fn approval_payload_includes_verified_identity_summary() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let mut create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "openclaw-http-host",
            now_unix(),
            "openclaw-approval-1",
        ) {
            create_req = create_req.header(key, value);
        }
        let create_req = create_req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign",
                "reason": "identity verified sign"
            })
            .to_string(),
        ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_json = json_response(create_resp).await;
        let id = create_json["data"]["id"].as_str().expect("id").to_string();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;

        assert_eq!(
            approve_json["data"]["approval_payload"]["identity"]["status"],
            "verified"
        );
        assert_eq!(
            approve_json["data"]["approval_payload"]["identity"]["mode"],
            "host-signed"
        );
        assert_eq!(
            approve_json["data"]["approval_payload"]["identity"]["runtime_id"],
            "openclaw-runtime-v1"
        );
        assert_eq!(
            approve_json["data"]["approval_payload"]["identity"]["host_id"],
            "openclaw-http-host"
        );
        Ok(())
    }

    #[tokio::test]
    async fn execute_rejects_identity_mismatch_after_approval() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Stub,
            "stub",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let mut create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "openclaw-http-host",
            now_unix(),
            "openclaw-exec-create-1",
        ) {
            create_req = create_req.header(key, value);
        }
        let create_req = create_req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign",
                "reason": "identity mismatch test"
            })
            .to_string(),
        ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_json = json_response(create_resp).await;
        let id = create_json["data"]["id"].as_str().expect("id").to_string();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let mut exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "secondary-helper-host",
            now_unix(),
            "openclaw-exec-run-1",
        ) {
            exec_req = exec_req.header(key, value);
        }
        let exec_req = exec_req.body(Body::from(
            json!({
                "id": id,
                "capability_token": token,
                "action": "request_sign",
                "target": "https://example.com/sign"
            })
            .to_string(),
        ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "identity_mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn create_request_rejects_replayed_host_signed_identity_envelope() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let replay_headers = signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "openclaw-http-host",
            now_unix(),
            "openclaw-replay-1",
        );

        for attempt in 0..2 {
            let mut req = Request::builder()
                .method("POST")
                .uri("/v1/requests")
                .header("content-type", "application/json")
                .header("x-api-key", &cfg.client_api_key);
            for (key, value) in &replay_headers {
                req = req.header(*key, value);
            }
            let req = req.body(Body::from(
                json!({
                    "request_type": "request_sign",
                    "secret_ref": "bw://vault/item/login",
                    "action": "request_sign",
                    "target": format!("https://example.com/sign/{attempt}"),
                    "reason": "replay envelope test"
                })
                .to_string(),
            ))?;

            let resp = app.clone().oneshot(req).await?;
            if attempt == 0 {
                assert_eq!(resp.status(), StatusCode::OK);
            } else {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                let body = json_response(resp).await;
                assert_eq!(body["code"], "replayed_identity");
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn create_request_rejects_expired_host_signed_identity() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "openclaw-http-host",
            now_unix() - (cfg.identity_attestation_max_age_seconds + 30),
            "openclaw-expired-1",
        ) {
            req = req.header(key, value);
        }
        let req = req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign",
                "reason": "expired identity test"
            })
            .to_string(),
        ))?;

        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "invalid_identity");
        Ok(())
    }

    #[tokio::test]
    async fn create_request_rejects_mismatched_host_runtime_pair() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "secondary-helper-runtime",
            "openclaw-http-host",
            now_unix(),
            "openclaw-mismatch-1",
        ) {
            req = req.header(key, value);
        }
        let req = req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign",
                "reason": "host runtime mismatch"
            })
            .to_string(),
        ))?;

        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "identity_mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn approve_rejects_downgraded_identity_mode_for_host_signed_request() -> anyhow::Result<()>
    {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let mut create_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "openclaw-http-host",
            now_unix(),
            "openclaw-downgrade-1",
        ) {
            create_req = create_req.header(key, value);
        }
        let create_req = create_req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign",
                "reason": "downgrade approval test"
            })
            .to_string(),
        ))?;
        let create_resp = app.clone().oneshot(create_req).await?;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_json = json_response(create_resp).await;
        let id = create_json["data"]["id"].as_str().expect("id").to_string();

        let downgraded_cfg = Arc::new(Config {
            db_url: cfg.db_url.clone(),
            identity_verification_mode: crate::identity::IdentityVerificationMode::Stub,
            ..(*cfg).clone()
        });
        let pool = connect_sqlite(&downgraded_cfg.db_url).await?;
        let state = AppState {
            db: Arc::new(pool),
            cfg: Arc::clone(&downgraded_cfg),
            provider: provider_runtime_for_config(&downgraded_cfg),
            adapter: execution_adapter_runtime(&downgraded_cfg),
            rate_state: Arc::new(Mutex::new(HashMap::new())),
            identity_replay_cache: identity::new_replay_cache(),
        };
        let downgraded_app = build_router(state);

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = downgraded_app.clone().oneshot(approve_req).await?;
        assert_eq!(approve_resp.status(), StatusCode::FORBIDDEN);
        let body = json_response(approve_resp).await;
        assert_eq!(body["code"], "identity_tier_changed");
        Ok(())
    }

    #[tokio::test]
    async fn host_signed_replay_rejection_is_process_local() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_identity_mode(
            ProviderBridgeMode::Off,
            "off",
            crate::identity::parse_identity_verification_mode("host-signed").expect("valid mode"),
        )
        .await?;

        let replay_headers = signed_identity_headers_with_timestamp_and_envelope(
            &cfg,
            "request_sign",
            "openclaw-runtime-v1",
            "openclaw-http-host",
            now_unix(),
            "openclaw-process-local-1",
        );

        let mut first_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in &replay_headers {
            first_req = first_req.header(*key, value);
        }
        let first_req = first_req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign/one",
                "reason": "first process-local replay check"
            })
            .to_string(),
        ))?;
        let first_resp = app.clone().oneshot(first_req).await?;
        assert_eq!(first_resp.status(), StatusCode::OK);

        let pool = connect_sqlite(&cfg.db_url).await?;
        let restarted_state = AppState {
            db: Arc::new(pool),
            cfg: Arc::clone(&cfg),
            provider: provider_runtime_for_config(&cfg),
            adapter: execution_adapter_runtime(&cfg),
            rate_state: Arc::new(Mutex::new(HashMap::new())),
            identity_replay_cache: identity::new_replay_cache(),
        };
        let restarted_app = build_router(restarted_state);

        let mut second_req = Request::builder()
            .method("POST")
            .uri("/v1/requests")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key);
        for (key, value) in &replay_headers {
            second_req = second_req.header(*key, value);
        }
        let second_req = second_req.body(Body::from(
            json!({
                "request_type": "request_sign",
                "secret_ref": "bw://vault/item/login",
                "action": "request_sign",
                "target": "https://example.com/sign/two",
                "reason": "second process-local replay check"
            })
            .to_string(),
        ))?;
        let second_resp = restarted_app.clone().oneshot(second_req).await?;
        assert_eq!(second_resp.status(), StatusCode::OK);
        Ok(())
    }

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

    #[tokio::test]
    async fn rotating_client_key_invalidates_old_key() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;

        let rotate_req = Request::builder()
            .method("POST")
            .uri("/v1/admin/keys/client/rotate")
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let rotate_resp = app.clone().oneshot(rotate_req).await?;
        assert_eq!(rotate_resp.status(), StatusCode::OK);
        let rotate_json = json_response(rotate_resp).await;
        let new_client_key = rotate_json["data"]["api_key"]
            .as_str()
            .expect("new api key")
            .to_string();

        let old_req = Request::builder()
            .method("GET")
            .uri("/v1/requests")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::empty())?;
        let old_resp = app.clone().oneshot(old_req).await?;
        assert_eq!(old_resp.status(), StatusCode::UNAUTHORIZED);

        let new_req = Request::builder()
            .method("GET")
            .uri("/v1/requests")
            .header("x-api-key", new_client_key)
            .body(Body::empty())?;
        let new_resp = app.clone().oneshot(new_req).await?;
        assert_eq!(new_resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn rotating_approver_key_invalidates_old_key() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;

        let rotate_req = Request::builder()
            .method("POST")
            .uri("/v1/admin/keys/approver/rotate")
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let rotate_resp = app.clone().oneshot(rotate_req).await?;
        assert_eq!(rotate_resp.status(), StatusCode::OK);
        let rotate_json = json_response(rotate_resp).await;
        let new_approver_key = rotate_json["data"]["api_key"]
            .as_str()
            .expect("new api key")
            .to_string();

        let old_req = Request::builder()
            .method("GET")
            .uri("/v1/audit")
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let old_resp = app.clone().oneshot(old_req).await?;
        assert_eq!(old_resp.status(), StatusCode::UNAUTHORIZED);

        let new_req = Request::builder()
            .method("GET")
            .uri("/v1/audit")
            .header("x-api-key", new_approver_key)
            .body(Body::empty())?;
        let new_resp = app.clone().oneshot(new_req).await?;
        assert_eq!(new_resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn audit_chain_verification_detects_tampering() -> anyhow::Result<()> {
        let (app, cfg) = setup_app().await?;
        let _id = create_password_request(&app, &cfg).await;

        let baseline = crate::audit::verify_audit_chain(&cfg.db_url).await?;
        assert!(baseline.ok);

        let pool = connect_sqlite(&cfg.db_url).await?;
        sqlx::query(
            "UPDATE audit_events SET details = ? WHERE id = (SELECT MAX(id) FROM audit_events)",
        )
        .bind("{\"tampered\":true}")
        .execute(&pool)
        .await?;

        let tampered = crate::audit::verify_audit_chain(&cfg.db_url).await?;
        assert!(!tampered.ok);
        assert!(tampered.broken_at_id.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn forensic_bundle_export_is_redact_safe_and_tamper_evident() -> anyhow::Result<()> {
        let (app, cfg) = setup_app_with_modes(ProviderBridgeMode::Stub, "stub").await?;
        let id = create_password_request(&app, &cfg).await;

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/requests/{id}/approve"))
            .header("x-api-key", &cfg.approver_api_key)
            .body(Body::empty())?;
        let approve_resp = app.clone().oneshot(approve_req).await?;
        let approve_json = json_response(approve_resp).await;
        let token = approve_json["data"]["capability_token"]
            .as_str()
            .expect("capability token");

        let exec_req = Request::builder()
            .method("POST")
            .uri("/v1/execute")
            .header("content-type", "application/json")
            .header("x-api-key", &cfg.client_api_key)
            .body(Body::from(
                json!({
                    "id": id,
                    "capability_token": token,
                    "action": "password_fill",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;
        let exec_resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(exec_resp.status(), StatusCode::OK);

        let bundle_dir = tempfile::tempdir()?;
        let bundle =
            crate::audit::export_forensic_bundle(&cfg.db_url, bundle_dir.path(), Some(&id)).await?;

        let summary = fs::read_to_string(bundle.summary_path)?;
        let audit_log = fs::read_to_string(bundle.audit_path)?;
        let request_log = fs::read_to_string(bundle.requests_path)?;

        assert!(summary.contains("\"ok\": true"));
        assert!(!summary.contains("bw://vault/item/login"));
        assert!(!audit_log.contains("bw://vault/item/login"));
        assert!(!request_log.contains("bw://vault/item/login"));
        Ok(())
    }

    mod e2e_harness {
        use super::*;

        #[tokio::test]
        async fn node_to_node_harness_keeps_transcripts_secret_free() -> anyhow::Result<()> {
            let outcome = run_node_to_node_happy_path().await?;

            assert_secret_free(&outcome.client_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.client_stderr, &outcome.fixture_secret);
            assert_secret_free(&outcome.approver_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.approver_stderr, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stderr, &outcome.fixture_secret);

            Ok(())
        }

        #[tokio::test]
        async fn node_to_node_misuse_case_fails_closed() -> anyhow::Result<()> {
            let outcome = run_node_to_node_target_mismatch().await?;

            assert_eq!(outcome.execute_result["status"], 400);
            assert_eq!(
                outcome.execute_result["body"]["code"],
                "adapter_target_mismatch"
            );
            assert_secret_free(&outcome.execute_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stderr, &outcome.fixture_secret);

            Ok(())
        }

        #[tokio::test]
        async fn node_to_node_execute_path_keeps_broker_response_secret_free() -> anyhow::Result<()>
        {
            let outcome = run_node_to_node_happy_path().await?;

            assert_eq!(outcome.execute_result["status"], 200);
            assert_eq!(outcome.execute_result["body"]["ok"], true);
            assert_eq!(outcome.request_id, outcome.create_result["id"]);
            assert_eq!(
                outcome.approve_result["body"]["data"]["capability_token"],
                outcome.capability_token
            );
            assert_secret_free(&outcome.create_result.to_string(), &outcome.fixture_secret);
            assert_secret_free(&outcome.approve_result.to_string(), &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_result.to_string(), &outcome.fixture_secret);

            Ok(())
        }

        #[tokio::test]
        async fn node_to_node_failure_artifacts_remain_redacted() -> anyhow::Result<()> {
            let outcome = run_node_to_node_target_mismatch().await?;
            let summary = fs::read_to_string(outcome.artifact_dir.join("summary.json"))?;
            let client_stdout = fs::read_to_string(outcome.artifact_dir.join("client.stdout.log"))?;
            let approver_stdout =
                fs::read_to_string(outcome.artifact_dir.join("approver.stdout.log"))?;
            let execute_stdout =
                fs::read_to_string(outcome.artifact_dir.join("execute.stdout.log"))?;

            assert_secret_free(&summary, &outcome.fixture_secret);
            assert_secret_free(&client_stdout, &outcome.fixture_secret);
            assert_secret_free(&approver_stdout, &outcome.fixture_secret);
            assert_secret_free(&execute_stdout, &outcome.fixture_secret);
            assert!(!summary.contains(&outcome.capability_token));
            assert!(!approver_stdout.contains(&outcome.capability_token));
            assert!(!execute_stdout.contains(&outcome.capability_token));

            Ok(())
        }

        #[tokio::test]
        async fn trusted_input_node_to_node_flow_keeps_transcripts_secret_free(
        ) -> anyhow::Result<()> {
            let outcome = run_trusted_input_node_to_node_happy_path().await?;
            let summary = fs::read_to_string(outcome.artifact_dir.join("summary.json"))?;
            let trusted_start_stdout =
                fs::read_to_string(outcome.artifact_dir.join("trusted-start.stdout.log"))?;
            let trusted_complete_stdout =
                fs::read_to_string(outcome.artifact_dir.join("trusted-complete.stdout.log"))?;

            assert_eq!(outcome.execute_result["status"], 200);
            assert_eq!(outcome.trusted_start_result["status"], 200);
            assert_eq!(outcome.create_result["id"], outcome.request_id);
            assert_eq!(
                outcome.trusted_complete_result["body"]["data"]["opaque_ref"],
                outcome.opaque_ref
            );
            assert_eq!(
                outcome.approve_result["body"]["data"]["capability_token"],
                outcome.capability_token
            );
            assert_secret_free(&outcome.trusted_start_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.trusted_start_stderr, &outcome.fixture_secret);
            assert_secret_free(&outcome.trusted_complete_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.trusted_complete_stderr, &outcome.fixture_secret);
            assert_secret_free(&outcome.create_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.create_stderr, &outcome.fixture_secret);
            assert_secret_free(&outcome.approver_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.approver_stderr, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stderr, &outcome.fixture_secret);
            assert_secret_free(&summary, &outcome.fixture_secret);
            assert_secret_free(&trusted_start_stdout, &outcome.fixture_secret);
            assert_secret_free(&trusted_complete_stdout, &outcome.fixture_secret);
            assert!(!outcome
                .trusted_complete_result
                .to_string()
                .contains("bw://vault/item/login"));

            Ok(())
        }

        #[tokio::test]
        async fn openclaw_host_lane_covers_trusted_input_redaction_and_execution(
        ) -> anyhow::Result<()> {
            let outcome = run_openclaw_host_happy_path().await?;
            let summary = fs::read_to_string(outcome.artifact_dir.join("summary.json"))?;
            let trusted_start_stdout =
                fs::read_to_string(outcome.artifact_dir.join("trusted-start.stdout.log"))?;
            let trusted_complete_stdout =
                fs::read_to_string(outcome.artifact_dir.join("trusted-complete.stdout.log"))?;
            let create_stdout = fs::read_to_string(outcome.artifact_dir.join("client.stdout.log"))?;
            let approver_stdout =
                fs::read_to_string(outcome.artifact_dir.join("approver.stdout.log"))?;
            let execute_stdout =
                fs::read_to_string(outcome.artifact_dir.join("execute.stdout.log"))?;

            let completion_token = outcome.trusted_start_result["completion_token"]
                .as_str()
                .context("openclaw completion token missing")?;
            let canary = "openclaw-canary-secret";
            let provider_secret_ref = "bw://vault/item/login";
            let create_masked = outcome.create_result["body"]["data"]["secret_ref_masked"]
                .as_str()
                .context("create masked secret ref missing")?;
            let approval_masked = outcome.approve_result["body"]["data"]["approval_payload"]
                ["secret_ref_masked"]
                .as_str()
                .context("approval masked secret ref missing")?;

            assert_eq!(outcome.trusted_start_result["host"], "openclaw");
            assert_eq!(outcome.trusted_complete_result["host"], "openclaw");
            assert_eq!(outcome.create_result["host"], "openclaw");
            assert_eq!(outcome.approve_result["host"], "openclaw");
            assert_eq!(outcome.execute_result["host"], "openclaw");
            assert_eq!(outcome.trusted_start_result["status"], 200);
            assert_eq!(outcome.trusted_complete_result["status"], 200);
            assert_ne!(create_masked, provider_secret_ref);
            assert!(!create_masked.contains(provider_secret_ref));
            assert_eq!(
                outcome.execute_result["body"]["data"]["result"]["adapter"]["adapter"],
                "password_fill_stub"
            );
            assert_eq!(
                outcome.execute_result["body"]["data"]["result"]["adapter"]["outcome"],
                "filled"
            );
            assert_eq!(
                outcome.trusted_complete_result["body"]["data"]["opaque_ref"],
                outcome.opaque_ref
            );
            assert!(outcome.opaque_ref.starts_with("tir://session/"));
            assert_ne!(approval_masked, provider_secret_ref);
            assert!(!approval_masked.contains(provider_secret_ref));
            assert!(!outcome
                .trusted_complete_result
                .to_string()
                .contains(provider_secret_ref));
            assert!(!outcome
                .execute_result
                .to_string()
                .contains("stub-secret-material"));
            for sink in [
                &outcome.trusted_start_stdout,
                &outcome.trusted_start_stderr,
                &outcome.trusted_complete_stdout,
                &outcome.trusted_complete_stderr,
                &outcome.create_stdout,
                &outcome.create_stderr,
                &outcome.approver_stdout,
                &outcome.approver_stderr,
                &outcome.execute_stdout,
                &outcome.execute_stderr,
                &summary,
                &trusted_start_stdout,
                &trusted_complete_stdout,
                &create_stdout,
                &approver_stdout,
                &execute_stdout,
            ] {
                assert_no_leaks(
                    sink,
                    &outcome.fixture_secret,
                    &[
                        canary,
                        completion_token,
                        &outcome.capability_token,
                        &outcome.opaque_ref,
                        provider_secret_ref,
                    ],
                );
            }

            Ok(())
        }

        #[test]
        fn openclaw_result_sidecar_is_removed_on_cleanup() -> anyhow::Result<()> {
            let sidecar = OpenClawResultSidecar::new()?;
            let path = sidecar.path().to_path_buf();

            sidecar.write_raw(r#"{"ok":true,"data":{"status":200}}"#)?;
            let decoded = sidecar.read_json()?;

            assert_eq!(decoded["ok"], true);
            assert!(path.exists());

            sidecar.cleanup()?;

            assert!(!path.exists());
            Ok(())
        }

        #[tokio::test]
        async fn supported_host_redaction_filters_canary_and_provider_refs() -> anyhow::Result<()> {
            let artifact_dir = new_artifact_dir("supported-host-redaction")?;
            let (broker_child, broker_url) = spawn_broker(&artifact_dir).await?;
            let canary = "loop1-canary-secret";

            let trusted_start = run_e2e_node_with_env(
                &[
                    "trusted-start".to_string(),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--request-type".to_string(),
                    "password_fill".to_string(),
                    "--action".to_string(),
                    "password_fill".to_string(),
                    "--target".to_string(),
                    "https://example.com/login".to_string(),
                    "--reason".to_string(),
                    canary.to_string(),
                ],
                &[
                    ("SECRET_BROKER_E2E_REDACTION_MODE", "supported"),
                    ("SECRET_BROKER_E2E_CANARY_SECRET", canary),
                ],
            )
            .await?;
            let session_id = trusted_start.result["id"]
                .as_str()
                .context("trusted start result missing session id")?
                .to_string();
            let completion_token = trusted_start.result["completion_token"]
                .as_str()
                .context("trusted start result missing completion token")?
                .to_string();

            let trusted_complete = run_e2e_node_with_env(
                &[
                    "trusted-complete".to_string(),
                    "--broker-url".to_string(),
                    broker_url.clone(),
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--id".to_string(),
                    session_id,
                    "--completion-token".to_string(),
                    completion_token,
                    "--secret-ref".to_string(),
                    "bw://vault/item/login".to_string(),
                ],
                &[
                    ("SECRET_BROKER_E2E_REDACTION_MODE", "supported"),
                    ("SECRET_BROKER_E2E_CANARY_SECRET", canary),
                ],
            )
            .await?;
            let opaque_ref = trusted_complete.result["opaque_ref"]
                .as_str()
                .context("trusted complete result missing opaque ref")?
                .to_string();

            let create = run_e2e_node_with_env(
                &[
                    "create".to_string(),
                    "--broker-url".to_string(),
                    broker_url,
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--request-type".to_string(),
                    "password_fill".to_string(),
                    "--secret-ref".to_string(),
                    opaque_ref,
                    "--action".to_string(),
                    "password_fill".to_string(),
                    "--target".to_string(),
                    "https://example.com/login".to_string(),
                    "--reason".to_string(),
                    canary.to_string(),
                ],
                &[
                    ("SECRET_BROKER_E2E_REDACTION_MODE", "supported"),
                    ("SECRET_BROKER_E2E_CANARY_SECRET", canary),
                ],
            )
            .await?;

            stop_broker(broker_child).await?;

            assert!(!trusted_start.stdout.contains(canary));
            assert!(!trusted_complete.stdout.contains("bw://vault/item/login"));
            assert!(!create.stdout.contains(canary));
            Ok(())
        }

        #[tokio::test]
        async fn supported_host_redaction_failure_fails_closed() -> anyhow::Result<()> {
            let artifact_dir = new_artifact_dir("supported-host-redaction-fail-closed")?;
            let (broker_child, broker_url) = spawn_broker(&artifact_dir).await?;

            let failed = run_e2e_node_expect_failure(
                &[
                    "trusted-start".to_string(),
                    "--broker-url".to_string(),
                    broker_url,
                    "--api-key".to_string(),
                    "loop5-client-key-1234567890".to_string(),
                    "--request-type".to_string(),
                    "password_fill".to_string(),
                    "--action".to_string(),
                    "password_fill".to_string(),
                    "--target".to_string(),
                    "https://example.com/login".to_string(),
                    "--reason".to_string(),
                    "loop1-fail-closed".to_string(),
                ],
                &[
                    ("SECRET_BROKER_E2E_REDACTION_MODE", "supported"),
                    ("SECRET_BROKER_E2E_REDACTION_FORCE_FAILURE", "1"),
                ],
            )
            .await?;

            stop_broker(broker_child).await?;

            assert!(failed.stderr.contains("redaction"));
            Ok(())
        }

        #[tokio::test]
        async fn request_sign_production_node_to_node_flow_keeps_transcripts_secret_free(
        ) -> anyhow::Result<()> {
            let outcome = run_request_sign_node_to_node_happy_path().await?;

            assert_eq!(outcome.execute_result["status"], 200);
            assert_eq!(
                outcome.execute_result["body"]["data"]["result"]["adapter"]["adapter"],
                "request_sign_production_v1"
            );
            assert_eq!(
                outcome.execute_result["body"]["data"]["result"]["masked"]["action"],
                "request_sign"
            );
            assert_eq!(
                outcome.execute_result["body"]["data"]["result"]["policy"]["outcome"],
                "step_up"
            );
            assert_secret_free(&outcome.client_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.approver_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stdout, &outcome.fixture_secret);
            Ok(())
        }

        #[tokio::test]
        async fn credential_handoff_node_to_node_flow_keeps_transcripts_secret_free(
        ) -> anyhow::Result<()> {
            let outcome = run_handoff_node_to_node_happy_path().await?;

            assert_eq!(outcome.execute_result["status"], 200);
            assert_eq!(
                outcome.execute_result["body"]["data"]["result"]["adapter"]["adapter"],
                "credential_handoff_stub"
            );
            assert_secret_free(&outcome.client_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.approver_stdout, &outcome.fixture_secret);
            assert_secret_free(&outcome.execute_stdout, &outcome.fixture_secret);
            Ok(())
        }
    }
}
