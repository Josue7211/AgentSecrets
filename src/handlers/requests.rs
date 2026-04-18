use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::policy::{
    classify_secret_ref, contains_illegal_chars, evaluate_request_policy, is_valid_status_filter,
    target_allowed, PolicyInput, PolicySummary, SecretRefValidation,
};
use crate::{
    audit::append_audit,
    auth::{enforce_rate_limit, require_approver, require_client_or_approver},
    capability_token, err,
    identity::{
        approval_identity_tier_lock, verify_headers, IdentityExpectations, IdentitySummary,
    },
    mask_secret_ref, now_unix, ok, request_id, token_hash, unix_to_sqlite_datetime, ApiError,
    ApiResponse, AppState, ApproveLookupRow, AuditQuery, AuditRow, CreateRequestBody, DecisionBody,
    ListQuery, RequestRow, RequestView,
};

use super::{
    expire_stale_requests, expire_stale_trusted_input_sessions,
    trusted_input::consume_opaque_ref_for_request,
};

struct CapabilityIssue {
    token: String,
    hash: String,
    issued_at: String,
    expires_at: String,
}

fn build_approval_payload(
    request_type: &str,
    secret_ref: &str,
    action: &str,
    target: &str,
    reason: Option<&str>,
    policy: &PolicySummary,
    identity: Option<&IdentitySummary>,
) -> Value {
    json!({
        "request_type": request_type,
        "secret_ref_masked": mask_secret_ref(secret_ref),
        "action": action,
        "target": target,
        "reason": reason,
        "policy": policy,
        "identity": identity,
    })
}

fn issue_capability(state: &AppState) -> Result<CapabilityIssue, (StatusCode, Json<ApiError>)> {
    let token = capability_token();
    let hash = token_hash(&token);
    let issued_unix = now_unix();
    let expiry_unix = issued_unix + state.cfg.capability_ttl_seconds;
    let Some(issued_sql) = unix_to_sqlite_datetime(issued_unix) else {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Failed to compute capability issue time",
        ));
    };
    let Some(expiry_sql) = unix_to_sqlite_datetime(expiry_unix) else {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Failed to compute capability expiry",
        ));
    };
    Ok(CapabilityIssue {
        token,
        hash,
        issued_at: issued_sql,
        expires_at: expiry_sql,
    })
}

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
    let secret_ref = body.secret_ref.trim();
    let action = body.action.trim();
    let target = body.target.trim();
    let reason = body.reason.clone();

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

    let identity = match verify_headers(
        &state.cfg,
        &headers,
        IdentityExpectations { action },
        now_unix(),
        &state.identity_replay_cache,
    ) {
        Ok(identity) => identity,
        Err(identity_err) => {
            let _ = append_audit(
                &state.db,
                &auth_ctx.key_fingerprint,
                "request.identity_rejected",
                None,
                &json!({
                    "request_type": request_type,
                    "action": action,
                    "target": target,
                    "reason": identity_err.code,
                }),
            )
            .await;

            return Err(err(
                StatusCode::FORBIDDEN,
                identity_err.code,
                identity_err.message,
            ));
        }
    };

    let trusted_input =
        consume_opaque_ref_for_request(&state, request_type, secret_ref, action, target).await?;
    let stored_secret_ref = if let Some(consumed) = trusted_input.as_ref() {
        consumed.provider_secret_ref.clone()
    } else {
        match classify_secret_ref(secret_ref) {
            SecretRefValidation::Accepted => secret_ref.to_string(),
            SecretRefValidation::RejectedPlaintextLike => {
                let _ = append_audit(
                    &state.db,
                    &auth_ctx.key_fingerprint,
                    "request.ingress_rejected",
                    None,
                    &json!({
                        "reason": "raw_secret_rejected",
                        "request_type": request_type,
                        "action": action,
                        "target": target,
                    }),
                )
                .await;

                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "raw_secret_rejected",
                    "Plaintext secret values are not accepted; use an opaque secret_ref",
                ));
            }
            SecretRefValidation::RejectedMalformed => {
                let _ = append_audit(
                    &state.db,
                    &auth_ctx.key_fingerprint,
                    "request.ingress_rejected",
                    None,
                    &json!({
                        "reason": "invalid_secret_ref",
                        "request_type": request_type,
                        "action": action,
                        "target": target,
                    }),
                )
                .await;

                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "invalid_secret_ref",
                    "Invalid secret_ref",
                ));
            }
        }
    };

    let policy = evaluate_request_policy(
        &state.cfg,
        PolicyInput {
            actor_role: auth_ctx.role,
            action,
            target,
            amount_cents: body.amount_cents,
        },
    );

    if policy.outcome == "deny" {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.policy_denied",
            None,
            &json!({
                "request_type": request_type,
                "action": action,
                "target": target,
                "policy": policy,
            }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "policy_denied",
            "Request denied by policy",
        ));
    }

    let id = request_id();
    let needs_approval = policy.outcome != "allow";

    let mut capability_plaintext: Option<String> = None;
    let mut capability_expires_at: Option<String> = None;
    let mut capability_hash: Option<String> = None;
    let mut capability_request_id: Option<String> = None;
    let mut capability_action: Option<String> = None;
    let mut capability_target: Option<String> = None;
    let mut capability_issued_at: Option<String> = None;
    let identity_status = identity
        .as_ref()
        .map(|item| item.status.clone())
        .unwrap_or_else(|| "disabled".to_string());
    let identity_mode = identity
        .as_ref()
        .map(|item| item.mode.clone())
        .unwrap_or_else(|| "off".to_string());

    let status = match state.cfg.mode {
        crate::BrokerMode::Off | crate::BrokerMode::Monitor => {
            let issued = issue_capability(&state)?;
            capability_hash = Some(issued.hash);
            capability_plaintext = Some(issued.token);
            capability_request_id = Some(id.clone());
            capability_action = Some(action.to_string());
            capability_target = Some(target.to_string());
            capability_issued_at = Some(issued.issued_at);
            capability_expires_at = Some(issued.expires_at);
            "approved"
        }
        crate::BrokerMode::Enforce => {
            if needs_approval {
                "pending_approval"
            } else {
                let issued = issue_capability(&state)?;
                capability_hash = Some(issued.hash);
                capability_plaintext = Some(issued.token);
                capability_request_id = Some(id.clone());
                capability_action = Some(action.to_string());
                capability_target = Some(target.to_string());
                capability_issued_at = Some(issued.issued_at);
                capability_expires_at = Some(issued.expires_at);
                "approved"
            }
        }
    };

    sqlx::query(
        "INSERT INTO secret_broker_requests (
            id, request_type, secret_ref, action, target, amount_cents, reason, status,
            requires_approval, capability_hash, capability_expires_at, capability_request_id,
            capability_action, capability_target, capability_issued_at,
            policy_outcome, policy_risk_score, policy_environment, policy_reasons,
            identity_status, identity_mode, identity_runtime_id, identity_host_id,
            identity_adapter_id, identity_verified_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(request_type)
    .bind(&stored_secret_ref)
    .bind(action)
    .bind(target)
    .bind(body.amount_cents)
    .bind(reason.clone())
    .bind(status)
    .bind(if needs_approval { 1_i64 } else { 0_i64 })
    .bind(capability_hash)
    .bind(capability_expires_at.clone())
    .bind(capability_request_id)
    .bind(capability_action)
    .bind(capability_target)
    .bind(capability_issued_at)
    .bind(policy.outcome.clone())
    .bind(policy.risk_score)
    .bind(policy.environment.clone())
    .bind(serde_json::to_string(&policy.reasons).unwrap_or_else(|_| "[]".to_string()))
    .bind(identity_status)
    .bind(identity_mode)
    .bind(identity.as_ref().map(|item| item.runtime_id.clone()))
    .bind(identity.as_ref().map(|item| item.host_id.clone()))
    .bind(identity.as_ref().map(|item| item.adapter_id.clone()))
    .bind(identity.as_ref().map(|item| item.verified_at.clone()))
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
            "policy": policy,
            "identity": identity,
            "trusted_input_session_id": trusted_input.as_ref().map(|item| item.session_id.as_str()),
        }),
    )
    .await;

    Ok(ok(json!({
        "id": id,
        "status": status,
        "requires_approval": needs_approval,
        "secret_ref_masked": mask_secret_ref(&stored_secret_ref),
        "capability_token": capability_plaintext,
        "capability_expires_at": capability_expires_at,
        "policy": policy,
        "identity": identity,
        "approval_payload": build_approval_payload(
            request_type,
            &stored_secret_ref,
            action,
            target,
            reason.as_deref(),
            &policy,
            identity.as_ref(),
        ),
    })))
}

fn parse_policy_summary(
    outcome: String,
    risk_score: i64,
    environment: String,
    reasons_json: String,
) -> PolicySummary {
    let reasons = serde_json::from_str::<Vec<String>>(&reasons_json).unwrap_or_default();
    PolicySummary {
        outcome,
        risk_score,
        environment,
        reasons,
    }
}

fn parse_identity_summary(
    status: String,
    mode: String,
    runtime_id: Option<String>,
    host_id: Option<String>,
    adapter_id: Option<String>,
    verified_at: Option<String>,
) -> Option<IdentitySummary> {
    let (Some(runtime_id), Some(host_id), Some(adapter_id), Some(verified_at)) =
        (runtime_id, host_id, adapter_id, verified_at)
    else {
        return None;
    };

    Some(IdentitySummary {
        status,
        mode,
        runtime_id,
        host_id,
        adapter_id,
        verified_at,
    })
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

    let row: Option<ApproveLookupRow> = sqlx::query_as(
        "SELECT status, request_type, secret_ref, action, reason, target,
                policy_outcome, policy_risk_score, policy_environment, policy_reasons,
                identity_status, identity_mode, identity_runtime_id, identity_host_id,
                identity_adapter_id, identity_verified_at
         FROM secret_broker_requests
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
            "Failed to load request",
        )
    })?;

    let Some((
        status,
        request_type,
        secret_ref,
        action,
        reason,
        target,
        policy_outcome,
        policy_risk_score,
        policy_environment,
        policy_reasons,
        identity_status,
        identity_mode,
        identity_runtime_id,
        identity_host_id,
        identity_adapter_id,
        identity_verified_at,
    )) = row
    else {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "Request not found"));
    };

    if status != "pending_approval" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "Request is not pending approval",
        ));
    }

    let policy = parse_policy_summary(
        policy_outcome,
        policy_risk_score,
        policy_environment,
        policy_reasons,
    );
    let identity = parse_identity_summary(
        identity_status,
        identity_mode,
        identity_runtime_id,
        identity_host_id,
        identity_adapter_id,
        identity_verified_at,
    );
    if let Err(identity_err) = approval_identity_tier_lock(&state.cfg, identity.as_ref()) {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.approve_rejected",
            Some(&id),
            &json!({ "reason": identity_err.code }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            identity_err.code,
            identity_err.message,
        ));
    }

    let issued = issue_capability(&state)?;

    sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'approved',
             capability_hash = ?,
             capability_expires_at = ?,
             capability_request_id = ?,
             capability_action = ?,
             capability_target = ?,
             capability_issued_at = ?,
             deny_reason = NULL,
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(&issued.hash)
    .bind(&issued.expires_at)
    .bind(&id)
    .bind(&action)
    .bind(&target)
    .bind(&issued.issued_at)
    .bind(&id)
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to approve request",
        )
    })?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "request.approve",
        Some(&id),
        &json!({
            "capability_expires_at": issued.expires_at,
            "policy": policy,
            "identity": identity,
        }),
    )
    .await;

    Ok(ok(json!({
        "id": id,
        "status": "approved",
        "capability_token": issued.token,
        "capability_expires_at": issued.expires_at,
        "note": "capability token is single-use",
        "identity": identity,
        "approval_payload": build_approval_payload(
            &request_type,
            &secret_ref,
            &action,
            &target,
            reason.as_deref(),
            &policy,
            identity.as_ref(),
        ),
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
         SET status = 'denied',
             deny_reason = ?,
             capability_hash = NULL,
             capability_expires_at = NULL,
             capability_request_id = NULL,
             capability_action = NULL,
             capability_target = NULL,
             capability_issued_at = NULL,
             capability_used_at = NULL,
             updated_at = datetime('now')
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
