use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::AppState;
use crate::{adapter::TrustedExecutionAdapter, provider::SecretProvider};

pub(crate) async fn healthz(State(state): State<AppState>) -> Json<Value> {
    let provider = state.provider.health().await;
    let adapter = state.adapter.health().await;

    Json(json!({
        "ok": true,
        "service": "secret-broker",
        "mode": match state.cfg.mode {
            crate::BrokerMode::Off => "off",
            crate::BrokerMode::Monitor => "monitor",
            crate::BrokerMode::Enforce => "enforce",
        },
        "provider": provider,
        "adapter": adapter,
    }))
}

pub(crate) async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&*state.db)
        .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true, "ready": true}))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "ready": false})),
        ),
    }
}
