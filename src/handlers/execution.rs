use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::{
    adapter::{AdapterErrorCode, AdapterRequest, TrustedExecutionAdapter},
    audit::append_audit,
    auth::{enforce_rate_limit, require_client_or_approver},
    err,
    identity::{execute_identity_guard, verify_headers, IdentityExpectations, IdentitySummary},
    now_unix, ok,
    provider::SecretProvider,
    sqlite_datetime_to_unix, token_hash, ApiError, ApiResponse, AppState, ExecuteBody,
    ExecuteLookupRow,
};

use super::expire_stale_requests;

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

pub(crate) async fn execute_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExecuteBody>,
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

    if body.id.trim().is_empty() || body.capability_token.trim().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "id and capability_token are required",
        ));
    }

    let row: Option<ExecuteLookupRow> = sqlx::query_as(
        "SELECT status, action, target, secret_ref, capability_hash, capability_expires_at,
                capability_request_id, capability_action, capability_target, capability_issued_at,
                identity_status, identity_mode, identity_runtime_id, identity_host_id,
                identity_adapter_id, identity_verified_at
         FROM secret_broker_requests
         WHERE id = ?
         LIMIT 1",
    )
    .bind(&body.id)
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
        action,
        target,
        secret_ref,
        capability_hash,
        capability_expires_at,
        capability_request_id,
        capability_action,
        capability_target,
        capability_issued_at,
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

    if status != "approved" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "Request is not approved",
        ));
    }

    let Some(expected_action) = body.action.as_deref() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "action is required",
        ));
    };
    let Some(expected_target) = body.target.as_deref() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "target is required",
        ));
    };

    let current_identity = match verify_headers(
        &state.cfg,
        &headers,
        IdentityExpectations {
            action: expected_action,
        },
        now_unix(),
        &state.identity_replay_cache,
    ) {
        Ok(identity) => identity,
        Err(identity_err) => {
            let _ = append_audit(
                &state.db,
                &auth_ctx.key_fingerprint,
                "request.identity_rejected",
                Some(&body.id),
                &json!({ "reason": identity_err.code }),
            )
            .await;

            return Err(err(
                StatusCode::FORBIDDEN,
                identity_err.code,
                identity_err.message,
            ));
        }
    };

    let stored_identity = parse_identity_summary(
        identity_status,
        identity_mode,
        identity_runtime_id,
        identity_host_id,
        identity_adapter_id,
        identity_verified_at,
    );

    let Some(stored_hash) = capability_hash else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "missing_capability",
            "No capability token available on request",
        ));
    };

    if stored_hash != token_hash(body.capability_token.trim()) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability",
            "Invalid capability token",
        ));
    }

    let Some(bound_request_id) = capability_request_id.as_deref() else {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "missing_request_binding" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    };
    let Some(bound_action) = capability_action.as_deref() else {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "missing_action_binding" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    };
    let Some(bound_target) = capability_target.as_deref() else {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "missing_target_binding" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    };
    let Some(_issued_at) = capability_issued_at.as_deref() else {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "missing_issue_time" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    };
    let Some(expires) = capability_expires_at.as_deref() else {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "missing_expiry" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    };

    if bound_request_id != body.id {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "request_binding_mismatch" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    }

    if action != bound_action || expected_action != bound_action {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.execute_rejected",
            Some(&body.id),
            &json!({ "reason": "action_mismatch" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "action_mismatch",
            "Action mismatch",
        ));
    }
    if target != bound_target || expected_target != bound_target {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.execute_rejected",
            Some(&body.id),
            &json!({ "reason": "target_mismatch" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "target_mismatch",
            "Target mismatch",
        ));
    }

    if let Err(identity_err) = execute_identity_guard(
        &state.cfg,
        stored_identity.as_ref(),
        current_identity.as_ref(),
    ) {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.execute_rejected",
            Some(&body.id),
            &json!({ "reason": identity_err.code }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            identity_err.code,
            identity_err.message,
        ));
    }

    let Some(exp_unix) = sqlite_datetime_to_unix(expires) else {
        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_invalid",
            Some(&body.id),
            &json!({ "reason": "invalid_expiry" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "invalid_capability_context",
            "Capability context is invalid",
        ));
    };

    if now_unix() > exp_unix {
        sqlx::query(
            "UPDATE secret_broker_requests
             SET status = 'expired',
                 capability_hash = NULL,
                 capability_expires_at = NULL,
                 capability_request_id = NULL,
                 capability_action = NULL,
                 capability_target = NULL,
                 capability_issued_at = NULL,
                 updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(&body.id)
        .execute(&*state.db)
        .await
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Failed to expire request",
            )
        })?;

        let _ = append_audit(
            &state.db,
            &auth_ctx.key_fingerprint,
            "request.capability_expired",
            Some(&body.id),
            &json!({ "reason": "expired" }),
        )
        .await;

        return Err(err(
            StatusCode::FORBIDDEN,
            "capability_expired",
            "Capability token expired",
        ));
    }

    let provider_resolution = match state.cfg.provider_bridge_mode {
        crate::provider::ProviderBridgeMode::Off => None,
        _ => {
            let resolved = match state.provider.resolve_for_use(&secret_ref).await {
                Ok(resolved) => resolved,
                Err(provider_err) => {
                    let code = match provider_err.code {
                        crate::provider::ProviderErrorCode::UnsupportedProvider => {
                            "provider_unsupported"
                        }
                        crate::provider::ProviderErrorCode::Unavailable => "provider_unavailable",
                    };

                    let _ = append_audit(
                        &state.db,
                        &auth_ctx.key_fingerprint,
                        "request.provider_resolve_failed",
                        Some(&body.id),
                        &json!({ "code": code }),
                    )
                    .await;

                    return Err(err(
                        StatusCode::BAD_GATEWAY,
                        code,
                        "Trusted provider resolution failed",
                    ));
                }
            };

            let _ = append_audit(
                &state.db,
                &auth_ctx.key_fingerprint,
                "request.provider_resolved",
                Some(&body.id),
                &json!({
                    "provider": resolved.provider_name,
                    "mode": match state.cfg.provider_bridge_mode {
                        crate::provider::ProviderBridgeMode::Off => "off",
                        crate::provider::ProviderBridgeMode::Stub => "stub",
                    },
                }),
            )
            .await;

            Some(resolved)
        }
    };

    let provider_result = provider_resolution.as_ref().map(|resolved| {
        json!({
            "name": resolved.provider_name,
            "resolution": "resolved",
            "secret_ref_masked": resolved.secret_ref_masked,
        })
    });

    let adapter_result = match state.cfg.execution_adapter_mode {
        crate::adapter::ExecutionAdapterMode::Off => None,
        _ => {
            let Some(resolved) = provider_resolution else {
                let _ = append_audit(
                    &state.db,
                    &auth_ctx.key_fingerprint,
                    "request.adapter_failed",
                    Some(&body.id),
                    &json!({ "code": "adapter_provider_missing" }),
                )
                .await;

                return Err(err(
                    StatusCode::BAD_GATEWAY,
                    "adapter_provider_missing",
                    "Trusted execution adapter could not run",
                ));
            };

            let adapter_request = AdapterRequest {
                action: &action,
                target: &target,
            };

            match state.adapter.execute(adapter_request, resolved).await {
                Ok(masked) => {
                    let _ = append_audit(
                        &state.db,
                        &auth_ctx.key_fingerprint,
                        "request.adapter_succeeded",
                        Some(&body.id),
                        &json!({
                            "adapter": masked.adapter,
                            "mode": match state.cfg.execution_adapter_mode {
                                crate::adapter::ExecutionAdapterMode::Off => "off",
                                crate::adapter::ExecutionAdapterMode::Stub => "stub",
                            },
                        }),
                    )
                    .await;

                    Some(
                        serde_json::to_value(masked)
                            .unwrap_or_else(|_| json!({"adapter": "unknown"})),
                    )
                }
                Err(adapter_err) => {
                    let (status, code) = match adapter_err.code {
                        AdapterErrorCode::Disabled => (StatusCode::BAD_GATEWAY, "adapter_disabled"),
                        AdapterErrorCode::UnsupportedAction => {
                            (StatusCode::BAD_REQUEST, "adapter_action_unsupported")
                        }
                        AdapterErrorCode::TargetMismatch => {
                            (StatusCode::BAD_REQUEST, "adapter_target_mismatch")
                        }
                        AdapterErrorCode::Unavailable => {
                            (StatusCode::BAD_GATEWAY, "adapter_unavailable")
                        }
                    };

                    let _ = append_audit(
                        &state.db,
                        &auth_ctx.key_fingerprint,
                        "request.adapter_failed",
                        Some(&body.id),
                        &json!({ "code": code }),
                    )
                    .await;

                    return Err(err(
                        status,
                        code,
                        "Trusted execution adapter rejected request",
                    ));
                }
            }
        }
    };

    let execution_result = json!({
        "ok": true,
        "masked": {
            "secret_ref": "[redacted]",
            "action": action,
            "target": target,
        },
        "provider": provider_result,
        "adapter": adapter_result,
        "identity": current_identity,
        "note": "no plaintext secrets returned",
    });

    let updated = sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'executed',
             capability_used_at = datetime('now'),
             execution_result = ?,
             capability_hash = NULL,
             capability_expires_at = NULL,
             capability_request_id = NULL,
             capability_action = NULL,
             capability_target = NULL,
             capability_issued_at = NULL,
             updated_at = datetime('now')
         WHERE id = ? AND capability_used_at IS NULL",
    )
    .bind(execution_result.to_string())
    .bind(&body.id)
    .execute(&*state.db)
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to execute request",
        )
    })?;

    if updated.rows_affected() == 0 {
        return Err(err(
            StatusCode::CONFLICT,
            "already_used",
            "Capability token already used",
        ));
    }

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "request.execute",
        Some(&body.id),
        &json!({"result": "masked"}),
    )
    .await;

    Ok(ok(json!({
        "id": body.id,
        "status": "executed",
        "result": execution_result,
    })))
}
