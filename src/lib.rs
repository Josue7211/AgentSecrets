mod adapter;
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
    adapter: Arc<adapter::ExecutionAdapterRuntime>,
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
    execution_adapter_mode: adapter::ExecutionAdapterMode,
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
    let execution_adapter_mode = adapter::parse_execution_adapter_mode(
        &std::env::var("SECRET_BROKER_EXECUTION_ADAPTER_MODE")
            .unwrap_or_else(|_| "off".to_string()),
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
        execution_adapter_mode,
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
        adapter: Arc::new(match cfg.execution_adapter_mode {
            adapter::ExecutionAdapterMode::Off => adapter::ExecutionAdapterRuntime::off(),
            adapter::ExecutionAdapterMode::Stub => adapter::ExecutionAdapterRuntime::stub(),
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
    use anyhow::Context;
    use axum::{body::Body, http::Request};
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
        provider_bridge_mode: crate::provider::ProviderBridgeMode,
        execution_adapter_mode: crate::adapter::ExecutionAdapterMode,
    ) -> Arc<Config> {
        Arc::new(Config {
            bind: "127.0.0.1:0".to_string(),
            db_url,
            mode: BrokerMode::Enforce,
            provider_bridge_mode,
            execution_adapter_mode,
            client_api_key: "test-client-key-123456".to_string(),
            approver_api_key: "test-approver-key-abcdef".to_string(),
            capability_ttl_seconds: 60,
            request_ttl_seconds: 3600,
            max_amount_cents: 2_000_000,
            allowed_target_prefixes: vec!["https://".to_string()],
            rate_limit_per_minute: 1000,
        })
    }

    async fn setup_app_with_modes(
        provider_bridge_mode: crate::provider::ProviderBridgeMode,
        adapter_mode: &str,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        let db_file = NamedTempFile::new()?;
        let db_path = db_file.path().to_string_lossy().to_string();
        let db_url = format!("sqlite://{}?mode=rwc", db_path);
        std::mem::forget(db_file);

        let cfg = test_config(
            db_url.clone(),
            provider_bridge_mode,
            crate::adapter::parse_execution_adapter_mode(adapter_mode),
        );
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
            adapter: Arc::new(match cfg.execution_adapter_mode {
                crate::adapter::ExecutionAdapterMode::Off => {
                    crate::adapter::ExecutionAdapterRuntime::off()
                }
                crate::adapter::ExecutionAdapterMode::Stub => {
                    crate::adapter::ExecutionAdapterRuntime::stub()
                }
            }),
            rate_state: Arc::new(Mutex::new(HashMap::new())),
        };
        Ok((build_router(state), cfg))
    }

    async fn setup_app_with_provider_mode(
        provider_bridge_mode: crate::provider::ProviderBridgeMode,
    ) -> anyhow::Result<(Router, Arc<Config>)> {
        setup_app_with_modes(provider_bridge_mode, "off").await
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

    static E2E_BUILD: OnceLock<Result<(), String>> = OnceLock::new();

    fn assert_secret_free(surface: &str, secret: &str) {
        assert!(
            !surface.contains(secret),
            "secret leaked into captured surface: {surface}"
        );
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

    async fn spawn_broker(artifact_dir: &Path) -> anyhow::Result<(Child, String)> {
        ensure_e2e_binaries_built()?;

        let port = random_local_port()?;
        let broker_url = format!("http://127.0.0.1:{port}");
        let db_path = artifact_dir.join("broker.sqlite");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let stdout_log = fs::File::create(artifact_dir.join("broker.stdout.log"))?;
        let stderr_log = fs::File::create(artifact_dir.join("broker.stderr.log"))?;

        let child = Command::new(e2e_binary_path("secret-broker"))
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
                "https://example.com",
            )
            .env("SECRET_BROKER_PROVIDER_BRIDGE_MODE", "stub")
            .env("SECRET_BROKER_EXECUTION_ADAPTER_MODE", "stub")
            .stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .context("failed to spawn broker process")?;

        wait_for_broker_ready(&broker_url).await?;
        Ok((child, broker_url))
    }

    async fn stop_broker(mut child: Child) -> anyhow::Result<()> {
        if child.try_wait()?.is_none() {
            child.start_kill()?;
            let _ = child.wait().await?;
        }
        Ok(())
    }

    async fn run_e2e_node(args: &[String]) -> anyhow::Result<NodeInvocation> {
        ensure_e2e_binaries_built()?;

        let output = Command::new(e2e_binary_path("e2e-node"))
            .current_dir(repo_root())
            .args(args)
            .output()
            .await
            .context("failed to run e2e-node helper")?;

        let stdout = String::from_utf8(output.stdout).context("stdout must be utf-8")?;
        let stderr = String::from_utf8(output.stderr).context("stderr must be utf-8")?;

        if !output.status.success() {
            anyhow::bail!("e2e-node failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
        }

        let result = parse_result_line(&stdout)?;
        Ok(NodeInvocation {
            stdout,
            stderr,
            result,
        })
    }

    async fn run_node_to_node_scenario(
        label: &str,
        execute_action: &str,
        execute_target: &str,
    ) -> anyhow::Result<NodeToNodeOutcome> {
        let artifact_dir = new_artifact_dir(label)?;
        let fixture_secret = "stub-secret-material".to_string();

        let (broker_child, broker_url) = spawn_broker(&artifact_dir).await?;

        let create = run_e2e_node(&[
            "create".to_string(),
            "--broker-url".to_string(),
            broker_url.clone(),
            "--api-key".to_string(),
            "loop5-client-key-1234567890".to_string(),
            "--request-type".to_string(),
            "password_fill".to_string(),
            "--secret-ref".to_string(),
            "bw://vault/item/login".to_string(),
            "--action".to_string(),
            "password_fill".to_string(),
            "--target".to_string(),
            "https://example.com/login".to_string(),
            "--reason".to_string(),
            "loop 5 happy path".to_string(),
        ])
        .await?;
        let request_id = create.result["id"]
            .as_str()
            .context("create result missing request id")?
            .to_string();

        let approve = run_e2e_node(&[
            "approve".to_string(),
            "--broker-url".to_string(),
            broker_url.clone(),
            "--api-key".to_string(),
            "loop5-approver-key-1234567890".to_string(),
            "--id".to_string(),
            request_id.clone(),
        ])
        .await?;
        let capability_token = approve.result["capability_token"]
            .as_str()
            .context("approve result missing capability token")?
            .to_string();

        let execute = run_e2e_node(&[
            "execute".to_string(),
            "--broker-url".to_string(),
            broker_url,
            "--api-key".to_string(),
            "loop5-client-key-1234567890".to_string(),
            "--id".to_string(),
            request_id.clone(),
            "--capability-token".to_string(),
            capability_token.clone(),
            "--action".to_string(),
            execute_action.to_string(),
            "--target".to_string(),
            execute_target.to_string(),
        ])
        .await?;

        let create_result = create.result.clone();
        let approve_result = approve.result.clone();
        let execute_result = execute.result.clone();

        write_redacted_artifact(
            &artifact_dir.join("client.stdout.log"),
            &create.stdout,
            &[&fixture_secret, &capability_token],
        )?;
        write_redacted_artifact(
            &artifact_dir.join("client.stderr.log"),
            &create.stderr,
            &[&fixture_secret, &capability_token],
        )?;
        write_redacted_artifact(
            &artifact_dir.join("approver.stdout.log"),
            &approve.stdout,
            &[&fixture_secret, &capability_token],
        )?;
        write_redacted_artifact(
            &artifact_dir.join("approver.stderr.log"),
            &approve.stderr,
            &[&fixture_secret, &capability_token],
        )?;
        write_redacted_artifact(
            &artifact_dir.join("execute.stdout.log"),
            &execute.stdout,
            &[&fixture_secret, &capability_token],
        )?;
        write_redacted_artifact(
            &artifact_dir.join("execute.stderr.log"),
            &execute.stderr,
            &[&fixture_secret, &capability_token],
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
            &[&fixture_secret, &capability_token],
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
        run_node_to_node_scenario(
            "node-to-node-happy-path",
            "password_fill",
            "https://example.com/login",
        )
        .await
    }

    async fn run_node_to_node_target_mismatch() -> anyhow::Result<NodeToNodeOutcome> {
        run_node_to_node_scenario(
            "node-to-node-target-mismatch",
            "password_fill",
            "https://example.com/profile",
        )
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
        let (app, _cfg) =
            setup_app_with_modes(crate::provider::ProviderBridgeMode::Stub, "stub").await?;

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
        assert_eq!(body["adapter"]["adapter"], "password_fill_stub");
        Ok(())
    }

    #[tokio::test]
    async fn readyz_remains_green_when_stub_provider_is_enabled() -> anyhow::Result<()> {
        let (app, _cfg) =
            setup_app_with_modes(crate::provider::ProviderBridgeMode::Stub, "stub").await?;

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
        let (app, cfg) =
            setup_app_with_modes(crate::provider::ProviderBridgeMode::Stub, "stub").await?;
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
    async fn execute_rejects_unsupported_adapter_actions() -> anyhow::Result<()> {
        let (app, cfg) =
            setup_app_with_modes(crate::provider::ProviderBridgeMode::Stub, "stub").await?;

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
                    "action": "copy_secret",
                    "target": "https://example.com/login"
                })
                .to_string(),
            ))?;

        let resp = app.clone().oneshot(exec_req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_response(resp).await;
        assert_eq!(body["code"], "adapter_action_unsupported");
        Ok(())
    }

    #[tokio::test]
    async fn execute_rejects_adapter_target_mismatch() -> anyhow::Result<()> {
        let (app, cfg) =
            setup_app_with_modes(crate::provider::ProviderBridgeMode::Stub, "stub").await?;

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

            assert_eq!(outcome.execute_result["status"], 403);
            assert_eq!(outcome.execute_result["body"]["code"], "target_mismatch");
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
    }
}
