use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

pub(crate) async fn append_audit(
    db: &SqlitePool,
    actor_key: &str,
    action: &str,
    request_id: Option<&str>,
    details: &Value,
) -> Result<(), sqlx::Error> {
    let prev: Option<(String,)> =
        sqlx::query_as("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1")
            .fetch_optional(db)
            .await?;

    let prev_hash = prev.map(|(h,)| h).unwrap_or_else(|| "GENESIS".to_string());
    let created_at = chrono::Utc::now().to_rfc3339();
    let canonical = json!({
        "prev_hash": prev_hash,
        "actor_key": actor_key,
        "action": action,
        "request_id": request_id,
        "details": details,
        "created_at": created_at,
    })
    .to_string();

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hex::encode(hasher.finalize());

    sqlx::query(
        "INSERT INTO audit_events (actor_key, action, request_id, details, prev_hash, hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(actor_key)
    .bind(action)
    .bind(request_id)
    .bind(details.to_string())
    .bind(prev_hash)
    .bind(hash)
    .bind(created_at)
    .execute(db)
    .await?;

    Ok(())
}
