use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::{
    audit::append_audit,
    auth::{enforce_rate_limit, require_client_or_approver},
    err,
    policy::{classify_secret_ref, contains_illegal_chars, target_allowed, SecretRefValidation},
    token_hash, trusted_input_completion_token, trusted_input_opaque_ref, trusted_input_session_id,
    unix_to_sqlite_datetime, ApiError, ApiResponse, AppState, CompleteTrustedInputSessionBody,
    CreateTrustedInputSessionBody,
};

use super::expire_stale_trusted_input_sessions;

type TrustedInputConsumeRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

type TrustedInputSessionViewRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsumedTrustedInputRef {
    pub(crate) session_id: String,
    pub(crate) provider_secret_ref: String,
}

pub(crate) fn extract_trusted_input_session_id(secret_ref: &str) -> Option<&str> {
    let session_id = secret_ref.strip_prefix("tir://session/")?;
    if session_id.is_empty()
        || session_id.contains('/')
        || session_id.chars().any(|c| c.is_whitespace())
        || contains_illegal_chars(session_id)
    {
        return None;
    }
    Some(session_id)
}

pub(crate) async fn consume_opaque_ref_for_request(
    state: &AppState,
    request_type: &str,
    secret_ref: &str,
    action: &str,
    target: &str,
) -> Result<Option<ConsumedTrustedInputRef>, (StatusCode, Json<ApiError>)> {
    let Some(session_id) = extract_trusted_input_session_id(secret_ref) else {
        return Ok(None);
    };

    let row: Option<TrustedInputConsumeRow> = sqlx::query_as(
        "SELECT status, request_type, action, target, provider_secret_ref, used_at
             FROM trusted_input_sessions
             WHERE id = ?
             LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to load trusted input session",
        )
    })?;

    let Some((
        status,
        bound_request_type,
        bound_action,
        bound_target,
        provider_secret_ref,
        used_at,
    )) = row
    else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_secret_ref",
            "Invalid secret_ref",
        ));
    };

    if status == "expired" {
        return Err(err(
            StatusCode::CONFLICT,
            "trusted_input_expired",
            "Trusted input session expired",
        ));
    }
    if status != "completed" {
        return Err(err(
            StatusCode::CONFLICT,
            "trusted_input_pending",
            "Trusted input session is not ready",
        ));
    }
    if used_at.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "trusted_input_consumed",
            "Trusted input ref already used",
        ));
    }
    if bound_request_type != request_type || bound_action != action || bound_target != target {
        return Err(err(
            StatusCode::FORBIDDEN,
            "trusted_input_context_mismatch",
            "Trusted input session does not match this request context",
        ));
    }

    let Some(provider_secret_ref) = provider_secret_ref else {
        return Err(err(
            StatusCode::FORBIDDEN,
            "trusted_input_incomplete",
            "Trusted input session is not ready",
        ));
    };

    let updated = sqlx::query(
        "UPDATE trusted_input_sessions
         SET used_at = datetime('now'),
             updated_at = datetime('now')
         WHERE id = ?
           AND status = 'completed'
           AND used_at IS NULL",
    )
    .bind(session_id)
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to consume trusted input session",
        )
    })?;

    if updated.rows_affected() == 0 {
        return Err(err(
            StatusCode::CONFLICT,
            "trusted_input_consumed",
            "Trusted input ref already used",
        ));
    }

    Ok(Some(ConsumedTrustedInputRef {
        session_id: session_id.to_string(),
        provider_secret_ref,
    }))
}

pub(crate) async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateTrustedInputSessionBody>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_client_or_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;
    expire_stale_trusted_input_sessions(&state)
        .await
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Failed to expire trusted input sessions",
            )
        })?;

    let request_type = body.request_type.trim();
    let action = body.action.trim();
    let target = body.target.trim();
    let reason = body.reason.clone().unwrap_or_default().trim().to_string();

    if request_type.is_empty() || request_type.len() > 64 || contains_illegal_chars(request_type) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request_type",
            "Invalid request_type",
        ));
    }
    if action.is_empty() || action.len() > 128 || contains_illegal_chars(action) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_action",
            "Invalid action",
        ));
    }
    if target.is_empty() || target.len() > 512 || contains_illegal_chars(target) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "Invalid target",
        ));
    }
    if !target_allowed(&state.cfg, target) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "target_denied",
            "Target denied by policy",
        ));
    }
    if !reason.is_empty() && (reason.len() > 1024 || contains_illegal_chars(&reason)) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_reason",
            "Invalid reason",
        ));
    }

    let session_id = trusted_input_session_id();
    let completion_token = trusted_input_completion_token();
    let completion_token_hash = token_hash(&completion_token);
    let expires_at = unix_to_sqlite_datetime(crate::now_unix() + state.cfg.request_ttl_seconds)
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "time_error",
                "Failed to compute trusted input expiry",
            )
        })?;

    sqlx::query(
        "INSERT INTO trusted_input_sessions (
            id, request_type, action, target, reason, status, completion_token_hash, expires_at
         ) VALUES (?, ?, ?, ?, ?, 'pending_input', ?, ?)",
    )
    .bind(&session_id)
    .bind(request_type)
    .bind(action)
    .bind(target)
    .bind(if reason.is_empty() {
        None::<String>
    } else {
        Some(reason.clone())
    })
    .bind(completion_token_hash)
    .bind(&expires_at)
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to create trusted input session",
        )
    })?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "trusted_input.session_create",
        None,
        &json!({
            "session_id": session_id,
            "request_type": request_type,
            "action": action,
            "target": target,
        }),
    )
    .await;

    Ok(crate::ok(json!({
        "id": session_id,
        "status": "pending_input",
        "completion_token": completion_token,
        "expires_at": expires_at,
        "request_type": request_type,
        "action": action,
        "target": target,
        "reason": if reason.is_empty() { None::<String> } else { Some(reason) },
        "opaque_ref": Value::Null,
    })))
}

pub(crate) async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_client_or_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;
    expire_stale_trusted_input_sessions(&state)
        .await
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Failed to expire trusted input sessions",
            )
        })?;

    let row: Option<TrustedInputSessionViewRow> = sqlx::query_as(
        "SELECT status, request_type, action, target, reason, opaque_ref, expires_at, completed_at, used_at
         FROM trusted_input_sessions
         WHERE id = ?
         LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to load trusted input session",
        )
    })?;

    let Some((
        status,
        request_type,
        action,
        target,
        reason,
        opaque_ref,
        expires_at,
        completed_at,
        used_at,
    )) = row
    else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "Trusted input session not found",
        ));
    };

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "trusted_input.session_read",
        None,
        &json!({
            "session_id": id,
            "status": status,
        }),
    )
    .await;

    Ok(crate::ok(json!({
        "id": id,
        "status": status,
        "request_type": request_type,
        "action": action,
        "target": target,
        "reason": reason,
        "expires_at": expires_at,
        "completed_at": completed_at,
        "used_at": used_at,
        "opaque_ref": opaque_ref,
    })))
}

pub(crate) async fn complete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CompleteTrustedInputSessionBody>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_client_or_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;
    expire_stale_trusted_input_sessions(&state)
        .await
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Failed to expire trusted input sessions",
            )
        })?;

    if body.completion_token.trim().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_completion_token",
            "completion_token is required",
        ));
    }

    match classify_secret_ref(body.secret_ref.trim()) {
        SecretRefValidation::Accepted => {}
        SecretRefValidation::RejectedPlaintextLike => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "raw_secret_rejected",
                "Plaintext secret values are not accepted; use an opaque secret_ref",
            ));
        }
        SecretRefValidation::RejectedMalformed => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_secret_ref",
                "Invalid secret_ref",
            ));
        }
    }

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT status, completion_token_hash
         FROM trusted_input_sessions
         WHERE id = ?
         LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to load trusted input session",
        )
    })?;

    let Some((status, expected_hash)) = row else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "Trusted input session not found",
        ));
    };

    if status == "expired" {
        return Err(err(
            StatusCode::CONFLICT,
            "trusted_input_expired",
            "Trusted input session expired",
        ));
    }
    if status != "pending_input" {
        return Err(err(
            StatusCode::CONFLICT,
            "invalid_state",
            "Trusted input session is not pending input",
        ));
    }
    if expected_hash != token_hash(body.completion_token.trim()) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_completion_token",
            "Invalid completion token",
        ));
    }

    let opaque_ref = trusted_input_opaque_ref(&id);

    sqlx::query(
        "UPDATE trusted_input_sessions
         SET status = 'completed',
             provider_secret_ref = ?,
             opaque_ref = ?,
             completed_at = datetime('now'),
             updated_at = datetime('now')
         WHERE id = ?
           AND status = 'pending_input'",
    )
    .bind(body.secret_ref.trim())
    .bind(&opaque_ref)
    .bind(&id)
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to complete trusted input session",
        )
    })?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "trusted_input.session_complete",
        None,
        &json!({
            "session_id": id,
            "opaque_ref": opaque_ref,
        }),
    )
    .await;

    Ok(crate::ok(json!({
        "id": id,
        "status": "completed",
        "opaque_ref": opaque_ref,
    })))
}
