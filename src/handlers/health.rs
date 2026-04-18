use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::AppState;
use crate::{adapter::TrustedExecutionAdapter, provider::SecretProvider};

pub(crate) async fn healthz(State(state): State<AppState>) -> Json<Value> {
    let provider = state.provider.health().await;
    let adapter = state.adapter.health().await;
    let identity = crate::identity::health(&state.cfg);
    let required_host_modes = state
        .cfg
        .required_host_identity_modes
        .iter()
        .map(|(host_id, mode)| (host_id.clone(), json!(mode.as_str())))
        .collect::<serde_json::Map<String, Value>>();
    let effective_host_modes = state
        .cfg
        .required_host_identity_modes
        .keys()
        .map(|host_id| {
            (
                host_id.clone(),
                json!(
                    crate::identity::configured_mode_for_host(&state.cfg, Some(host_id)).as_str()
                ),
            )
        })
        .collect::<serde_json::Map<String, Value>>();
    let host_signed_hosts = crate::identity::usable_host_signed_hosts(&state.cfg);

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
        "identity": {
            "mode": identity.mode,
            "baseline_mode": identity.mode,
            "configured": identity.configured,
            "ready": identity.ready,
            "max_age_seconds": identity.max_age_seconds,
            "host_signed_hosts": host_signed_hosts,
            "required_host_modes": required_host_modes,
            "effective_host_modes": effective_host_modes,
        },
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
