mod audit;
mod auth;
mod handlers;
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
    provider: Arc<provider::ProviderRuntime>,
    rate_state: Arc<Mutex<HashMap<String, Vec<i64>>>>,
}

#[derive(Clone, Debug)]
enum BrokerMode {
    Off,
    Monitor,
    Enforce,
}

#[derive(Clone)]
struct Config {
    bind: String,
    db_url: String,
    mode: BrokerMode,
    provider_bridge_mode: provider::ProviderBridgeMode,
    client_api_key: String,
    approver_api_key: String,
    capability_ttl_seconds: i64,
    request_ttl_seconds: i64,
    max_amount_cents: i64,
    allowed_target_prefixes: Vec<String>,
    rate_limit_per_minute: usize,
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

type ExecuteLookupRow = (
    String,
    String,
    String,
    String,
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

fn capability_token() -> String {
    format!("sbt_{}", random_hex(24))
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

fn config_from_env() -> Config {
    let bind = std::env::var("SECRET_BROKER_BIND").unwrap_or_else(|_| "127.0.0.1:4815".to_string());
    let db_url = std::env::var("SECRET_BROKER_DB")
        .unwrap_or_else(|_| "sqlite://secret-broker.db?mode=rwc".to_string());
    let mode = policy::parse_mode(
        &std::env::var("SECRET_BROKER_MODE").unwrap_or_else(|_| "monitor".to_string()),
    );
    let provider_bridge_mode = provider::parse_provider_bridge_mode(
        &std::env::var("SECRET_BROKER_PROVIDER_BRIDGE_MODE").unwrap_or_else(|_| "off".to_string()),
    );

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

    Config {
        bind,
        db_url,
        mode,
        provider_bridge_mode,
        client_api_key,
        approver_api_key,
        capability_ttl_seconds,
        request_ttl_seconds,
        max_amount_cents,
        allowed_target_prefixes,
        rate_limit_per_minute,
    }
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

    Ok(())
}

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secret_broker=info".into()),
        )
        .init();

    let cfg = Arc::new(config_from_env());
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
        provider: Arc::new(match cfg.provider_bridge_mode {
            provider::ProviderBridgeMode::Off => provider::ProviderRuntime::off(),
            provider::ProviderBridgeMode::Stub => provider::ProviderRuntime::stub(),
        }),
        rate_state: Arc::new(Mutex::new(HashMap::new())),
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
    use axum::{body::Body, http::Request};
    use serde_json::{json, Value};
    use tempfile::NamedTempFile;
    use tower::util::ServiceExt;

    fn test_config(
        db_url: String,
        provider_bridge_mode: crate::provider::ProviderBridgeMode,
    ) -> Arc<Config> {
        Arc::new(Config {
            bind: "127.0.0.1:0".to_string(),
            db_url,
            mode: BrokerMode::Enforce,
            provider_bridge_mode,
            client_api_key: "test-client-key-123456".to_string(),
            approver_api_key: "test-approver-key-abcdef".to_string(),
            capability_ttl_seconds: 60,
            request_ttl_seconds: 3600,
            max_amount_cents: 2_000_000,
            allowed_target_prefixes: vec!["https://".to_string()],
            rate_limit_per_minute: 1000,
        })
    }

    async fn setup_app_with_provider_mode(
        provider_bridge_mode: crate::provider::ProviderBridgeMode,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        let db_file = NamedTempFile::new()?;
        let db_path = db_file.path().to_string_lossy().to_string();
        let db_url = format!("sqlite://{}?mode=rwc", db_path);
        std::mem::forget(db_file);

        let cfg = test_config(db_url.clone(), provider_bridge_mode);
        let pool = connect_sqlite(&db_url).await?;
        init_db(&pool).await?;
        crate::keys::ensure_api_keys(&pool, &cfg).await?;

        let state = AppState {
            db: Arc::new(pool),
            cfg: Arc::clone(&cfg),
            provider: Arc::new(match cfg.provider_bridge_mode {
                crate::provider::ProviderBridgeMode::Off => crate::provider::ProviderRuntime::off(),
                crate::provider::ProviderBridgeMode::Stub => {
                    crate::provider::ProviderRuntime::stub()
                }
            }),
            rate_state: Arc::new(Mutex::new(HashMap::new())),
        };
        Ok((build_router(state), cfg))
    }

    async fn setup_app() -> anyhow::Result<(Router, Arc<Config>)> {
        setup_app_with_provider_mode(crate::provider::ProviderBridgeMode::Off).await
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

    #[tokio::test]
    async fn health_reports_provider_bridge_mode() -> anyhow::Result<()> {
        let (app, _cfg) =
            setup_app_with_provider_mode(crate::provider::ProviderBridgeMode::Stub).await?;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_response(resp).await;
        assert_eq!(body["provider"]["mode"], "stub");
        assert_eq!(body["provider"]["provider"], "bitwarden_stub");
        Ok(())
    }

    #[tokio::test]
    async fn readyz_remains_green_when_stub_provider_is_enabled() -> anyhow::Result<()> {
        let (app, _cfg) =
            setup_app_with_provider_mode(crate::provider::ProviderBridgeMode::Stub).await?;

        let req = Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
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
    async fn execute_uses_stub_provider_without_leaking_plaintext() -> anyhow::Result<()> {
        let (app, cfg) =
            setup_app_with_provider_mode(crate::provider::ProviderBridgeMode::Stub).await?;
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
        assert_eq!(body["data"]["result"]["provider"]["name"], "bitwarden_stub");
        assert_eq!(body["data"]["result"]["provider"]["resolution"], "resolved");
        assert!(!body.to_string().contains("stub-secret-material"));
        Ok(())
    }

    #[tokio::test]
    async fn execute_masks_provider_failures_and_keeps_request_unexecuted() -> anyhow::Result<()> {
        let (app, cfg) =
            setup_app_with_provider_mode(crate::provider::ProviderBridgeMode::Stub).await?;

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
}
