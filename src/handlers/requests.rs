use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::policy::{
    contains_illegal_chars, is_valid_status_filter, requires_approval, target_allowed,
};
use crate::{
    audit::append_audit,
    auth::{enforce_rate_limit, require_approver, require_client_or_approver},
    capability_token, err, mask_secret_ref, now_unix, ok, request_id, token_hash,
    unix_to_sqlite_datetime, ApiError, ApiResponse, AppState, AuditQuery, AuditRow,
    CreateRequestBody, DecisionBody, ListQuery, RequestRow, RequestView,
};

use super::expire_stale_requests;

pub(crate) async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRequestBody>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_client_or_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;

    expire_stale_requests(&state).await.map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to expire stale requests",
        )
    })?;

    let request_type = body.request_type.trim();
    let secret_ref = body.secret_ref.trim();
    let action = body.action.trim();
    let target = body.target.trim();

    if request_type.is_empty() || request_type.len() > 64 || contains_illegal_chars(request_type) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request_type",
            "Invalid request_type",
        ));
    }
    if secret_ref.is_empty() || secret_ref.len() > 256 || contains_illegal_chars(secret_ref) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_secret_ref",
            "Invalid secret_ref",
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

    if let Some(amount) = body.amount_cents {
        if amount < 0 || amount > state.cfg.max_amount_cents {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_amount",
                "amount_cents is out of policy bounds",
            ));
        }
    }

    let id = request_id();
    let needs_approval = requires_approval(action, body.amount_cents);

    let mut capability_plaintext: Option<String> = None;
    let mut capability_expires_at: Option<String> = None;
    let mut capability_hash: Option<String> = None;

    let status = match state.cfg.mode {
        crate::BrokerMode::Off | crate::BrokerMode::Monitor => {
            let token = capability_token();
            let hash = token_hash(&token);
            let expiry_unix = now_unix() + state.cfg.capability_ttl_seconds;
            capability_expires_at = unix_to_sqlite_datetime(expiry_unix);
            capability_hash = Some(hash);
            capability_plaintext = Some(token);
            "approved"
        }
        crate::BrokerMode::Enforce => {
            if needs_approval {
                "pending_approval"
            } else {
                let token = capability_token();
                let hash = token_hash(&token);
                let expiry_unix = now_unix() + state.cfg.capability_ttl_seconds;
                capability_expires_at = unix_to_sqlite_datetime(expiry_unix);
                capability_hash = Some(hash);
                capability_plaintext = Some(token);
                "approved"
            }
        }
    };

    sqlx::query(
        "INSERT INTO secret_broker_requests (
            id, request_type, secret_ref, action, target, amount_cents, reason, status,
            requires_approval, capability_hash, capability_expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(request_type)
    .bind(secret_ref)
    .bind(action)
    .bind(target)
    .bind(body.amount_cents)
    .bind(body.reason)
    .bind(status)
    .bind(if needs_approval { 1_i64 } else { 0_i64 })
    .bind(capability_hash)
    .bind(capability_expires_at.clone())
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to create request",
        )
    })?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "request.create",
        Some(&id),
        &json!({
            "status": status,
            "request_type": request_type,
            "action": action,
            "target": target,
            "requires_approval": needs_approval,
        }),
    )
    .await;

    Ok(ok(json!({
        "id": id,
        "status": status,
        "requires_approval": needs_approval,
        "secret_ref_masked": mask_secret_ref(secret_ref),
        "capability_token": capability_plaintext,
        "capability_expires_at": capability_expires_at,
    })))
}

pub(crate) async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_client_or_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;

    expire_stale_requests(&state).await.map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to expire stale requests",
        )
    })?;

    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    if let Some(status) = query.status.as_deref() {
        if !is_valid_status_filter(status) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_status",
                "Invalid status filter",
            ));
        }
    }
    let rows: Vec<RequestRow> = if let Some(status) = query.status.as_deref() {
        sqlx::query_as(
            "SELECT id, request_type, secret_ref, action, target, amount_cents, reason, status, requires_approval, deny_reason, capability_expires_at, capability_used_at, created_at, updated_at
             FROM secret_broker_requests
             WHERE status = ?
             ORDER BY created_at DESC
             LIMIT ?",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&*state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", "Failed to list requests"))?
    } else {
        sqlx::query_as(
            "SELECT id, request_type, secret_ref, action, target, amount_cents, reason, status, requires_approval, deny_reason, capability_expires_at, capability_used_at, created_at, updated_at
             FROM secret_broker_requests
             ORDER BY created_at DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&*state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", "Failed to list requests"))?
    };

    let mut data = Vec::with_capacity(rows.len());
    for (
        id,
        request_type,
        secret_ref,
        action,
        target,
        amount_cents,
        reason,
        status,
        requires_approval_flag,
        deny_reason,
        capability_expires_at,
        capability_used_at,
        created_at,
        updated_at,
    ) in rows
    {
        let view = RequestView {
            id,
            request_type,
            secret_ref_masked: mask_secret_ref(&secret_ref),
            action,
            target,
            amount_cents,
            reason,
            status,
            requires_approval: requires_approval_flag == 1,
            deny_reason,
            capability_expires_at,
            capability_used_at,
            created_at,
            updated_at,
        };
        data.push(json!(view));
    }

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "request.list",
        None,
        &json!({"limit": limit, "filtered_status": query.status}),
    )
    .await;

    Ok(ok(json!(data)))
}

pub(crate) async fn approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;

    expire_stale_requests(&state).await.map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to expire stale requests",
        )
    })?;

    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM secret_broker_requests WHERE id = ? LIMIT 1")
            .bind(&id)
            .fetch_optional(&*state.db)
            .await
            .map_err(|_| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Failed to load request",
                )
            })?;

    let Some((status,)) = row else {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "Request not found"));
    };

    if status != "pending_approval" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "Request is not pending approval",
        ));
    }

    let token = capability_token();
    let hash = token_hash(&token);
    let expiry_unix = now_unix() + state.cfg.capability_ttl_seconds;
    let Some(expiry_sql) = unix_to_sqlite_datetime(expiry_unix) else {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Failed to compute capability expiry",
        ));
    };

    sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'approved', capability_hash = ?, capability_expires_at = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(hash)
    .bind(&expiry_sql)
    .bind(&id)
    .execute(&*state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", "Failed to approve request"))?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "request.approve",
        Some(&id),
        &json!({"capability_expires_at": expiry_sql}),
    )
    .await;

    Ok(ok(json!({
        "id": id,
        "status": "approved",
        "capability_token": token,
        "capability_expires_at": expiry_sql,
        "note": "capability token is single-use",
    })))
}

pub(crate) async fn deny_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;

    expire_stale_requests(&state).await.map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to expire stale requests",
        )
    })?;

    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM secret_broker_requests WHERE id = ? LIMIT 1")
            .bind(&id)
            .fetch_optional(&*state.db)
            .await
            .map_err(|_| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Failed to load request",
                )
            })?;

    let Some((status,)) = row else {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "Request not found"));
    };

    if status != "pending_approval" && status != "approved" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "Request cannot be denied in its current state",
        ));
    }

    let deny_reason = body
        .reason
        .unwrap_or_else(|| "Denied by approver".to_string());
    let deny_reason = deny_reason.trim().to_string();
    if deny_reason.is_empty() || deny_reason.len() > 1024 || contains_illegal_chars(&deny_reason) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_reason",
            "Invalid deny reason",
        ));
    }

    sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'denied', deny_reason = ?, updated_at = datetime('now')
         WHERE id = ? AND status != 'executed'",
    )
    .bind(&deny_reason)
    .bind(&id)
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to deny request",
        )
    })?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "request.deny",
        Some(&id),
        &json!({"reason": deny_reason}),
    )
    .await;

    Ok(ok(json!({ "id": id, "status": "denied" })))
}

pub(crate) async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_approver(&headers, &state.db).await?;
    enforce_rate_limit(&state, &auth_ctx).await?;

    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT id, actor_key, action, request_id, details, prev_hash, hash, created_at
         FROM audit_events ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to list audit events",
        )
    })?;

    let events: Vec<Value> = rows
        .into_iter()
        .map(
            |(id, actor_key, action, request_id, details, prev_hash, hash, created_at)| {
                let details_json = serde_json::from_str::<Value>(&details)
                    .unwrap_or_else(|_| json!({"raw": details}));
                json!({
                    "id": id,
                    "actor_key": actor_key,
                    "action": action,
                    "request_id": request_id,
                    "details": details_json,
                    "prev_hash": prev_hash,
                    "hash": hash,
                    "created_at": created_at,
                })
            },
        )
        .collect();

    Ok(ok(json!(events)))
}
