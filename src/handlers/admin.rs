use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::keys::{rotate_api_key, ApiKeyRole};
use crate::{
    audit::append_audit,
    auth::{enforce_rate_limit, require_approver},
    err, ok, ApiError, ApiResponse, AppState,
};

async fn rotate_role(
    state: &AppState,
    headers: &HeaderMap,
    role: ApiKeyRole,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let auth_ctx = require_approver(headers, &state.db).await?;
    enforce_rate_limit(state, &auth_ctx).await?;

    let rotated = rotate_api_key(&state.db, role).await.map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to rotate API key",
        )
    })?;

    let _ = append_audit(
        &state.db,
        &auth_ctx.key_fingerprint,
        "api_key.rotate",
        None,
        &json!({
            "role": rotated.role.as_str(),
            "new_fingerprint": rotated.key_fingerprint,
        }),
    )
    .await;

    Ok(ok(json!({
        "role": rotated.role.as_str(),
        "api_key": rotated.api_key,
        "key_fingerprint": rotated.key_fingerprint,
        "note": "store this key securely; it is only returned once",
    })))
}

pub(crate) async fn rotate_by_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(role): Path<String>,
) -> Result<Json<ApiResponse<Value>>, (StatusCode, Json<ApiError>)> {
    let role = match role.as_str() {
        "client" => ApiKeyRole::Client,
        "approver" => ApiKeyRole::Approver,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_role",
                "Role must be client or approver",
            ))
        }
    };
    rotate_role(&state, &headers, role).await
}
