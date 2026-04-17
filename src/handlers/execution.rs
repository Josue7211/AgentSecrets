use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::{
    audit::append_audit,
    auth::{enforce_rate_limit, require_client_or_approver},
    err, now_unix, ok,
    provider::SecretProvider,
    sqlite_datetime_to_unix, token_hash, ApiError, ApiResponse, AppState, ExecuteBody,
    ExecuteLookupRow,
};

use super::expire_stale_requests;

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
        "SELECT status, action, target, secret_ref, capability_hash, capability_expires_at
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

    let Some((status, action, target, secret_ref, capability_hash, capability_expires_at)) = row
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

    if let Some(ref expected_action) = body.action {
        if expected_action != &action {
            return Err(err(
                StatusCode::FORBIDDEN,
                "action_mismatch",
                "Action mismatch",
            ));
        }
    }
    if let Some(ref expected_target) = body.target {
        if expected_target != &target {
            return Err(err(
                StatusCode::FORBIDDEN,
                "target_mismatch",
                "Target mismatch",
            ));
        }
    }

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

    if let Some(ref expires) = capability_expires_at {
        if let Some(exp_unix) = sqlite_datetime_to_unix(expires) {
            if now_unix() > exp_unix {
                sqlx::query(
                    "UPDATE secret_broker_requests SET status = 'expired', updated_at = datetime('now') WHERE id = ?",
                )
                .bind(&body.id)
                .execute(&*state.db)
                .await
                .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", "Failed to expire request"))?;

                return Err(err(
                    StatusCode::FORBIDDEN,
                    "capability_expired",
                    "Capability token expired",
                ));
            }
        }
    }

    let provider_result = match state.cfg.provider_bridge_mode {
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

            Some(json!({
                "name": resolved.provider_name,
                "resolution": "resolved",
                "secret_ref_masked": resolved.secret_ref_masked,
            }))
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
        "note": "no plaintext secrets returned",
    });

    let updated = sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'executed',
             capability_used_at = datetime('now'),
             execution_result = ?,
             capability_hash = NULL,
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
