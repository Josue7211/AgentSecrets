use axum::http::{header, HeaderMap, StatusCode};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;

use crate::{err, now_unix, token_hash, ApiError, AppState, AuthContext, AuthRole};

fn read_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    if let Some(rest) = auth.strip_prefix("Bearer ") {
        return Some(rest.trim().to_string());
    }
    None
}

fn read_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

async fn auth_context(headers: &HeaderMap, pool: &SqlitePool) -> Option<AuthContext> {
    let token = read_bearer(headers).or_else(|| read_api_key(headers))?;

    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT role, key_hash, key_fingerprint FROM api_keys")
            .fetch_all(pool)
            .await
            .ok()?;

    let presented_hash = token_hash(&token);
    for (role, key_hash, key_fingerprint) in rows {
        if constant_time_eq(&presented_hash, &key_hash) {
            let role = match role.as_str() {
                "approver" => AuthRole::Approver,
                "client" => AuthRole::Client,
                _ => continue,
            };
            return Some(AuthContext {
                role,
                key_fingerprint,
            });
        }
    }
    None
}

pub(crate) async fn require_client_or_approver(
    headers: &HeaderMap,
    db: &SqlitePool,
) -> Result<AuthContext, (StatusCode, axum::Json<ApiError>)> {
    auth_context(headers, db).await.ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Missing or invalid API key",
        )
    })
}

pub(crate) async fn require_approver(
    headers: &HeaderMap,
    db: &SqlitePool,
) -> Result<AuthContext, (StatusCode, axum::Json<ApiError>)> {
    let ctx = require_client_or_approver(headers, db).await?;
    if ctx.role != AuthRole::Approver {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Approver key required",
        ));
    }
    Ok(ctx)
}

pub(crate) async fn enforce_rate_limit(
    state: &AppState,
    auth_ctx: &AuthContext,
) -> Result<(), (StatusCode, axum::Json<ApiError>)> {
    let now = now_unix();
    let window_start = now - 60;

    let mut guard = state.rate_state.lock().await;
    let entry = guard
        .entry(auth_ctx.key_fingerprint.clone())
        .or_insert_with(Vec::new);
    entry.retain(|t| *t >= window_start);

    if entry.len() >= state.cfg.rate_limit_per_minute {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Rate limit exceeded",
        ));
    }

    entry.push(now);
    Ok(())
}
