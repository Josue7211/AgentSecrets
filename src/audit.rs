use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditVerificationReport {
    pub ok: bool,
    pub event_count: usize,
    pub last_hash: Option<String>,
    pub broken_at_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ForensicBundlePaths {
    pub summary_path: PathBuf,
    pub audit_path: PathBuf,
    pub requests_path: PathBuf,
}

type AuditChainRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
);

type RequestExportRow = (
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
);

fn canonical_audit_entry(
    prev_hash: &str,
    actor_key: &str,
    action: &str,
    request_id: Option<&str>,
    details: &Value,
    created_at: &str,
) -> String {
    json!({
        "prev_hash": prev_hash,
        "actor_key": actor_key,
        "action": action,
        "request_id": request_id,
        "details": details,
        "created_at": created_at,
    })
    .to_string()
}

fn hash_canonical(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

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
    let canonical = canonical_audit_entry(
        &prev_hash,
        actor_key,
        action,
        request_id,
        details,
        &created_at,
    );
    let hash = hash_canonical(&canonical);

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

async fn open_pool(db_url: &str) -> anyhow::Result<SqlitePool> {
    Ok(SqlitePool::connect(db_url).await?)
}

pub async fn verify_audit_chain(db_url: &str) -> anyhow::Result<AuditVerificationReport> {
    let pool = open_pool(db_url).await?;
    let rows: Vec<AuditChainRow> = sqlx::query_as(
        "SELECT id, actor_key, action, request_id, details, prev_hash, hash, created_at
         FROM audit_events
         ORDER BY id ASC",
    )
    .fetch_all(&pool)
    .await?;

    let mut last_hash = None;
    for (idx, row) in rows.iter().enumerate() {
        let (id, actor_key, action, request_id, details, prev_hash, hash, created_at) = row;
        let expected_prev = if idx == 0 {
            "GENESIS".to_string()
        } else {
            rows[idx - 1].6.clone()
        };
        if *prev_hash != expected_prev {
            return Ok(AuditVerificationReport {
                ok: false,
                event_count: rows.len(),
                last_hash,
                broken_at_id: Some(*id),
            });
        }

        let details_value: Value = serde_json::from_str(details)?;
        let canonical = canonical_audit_entry(
            prev_hash,
            actor_key,
            action,
            request_id.as_deref(),
            &details_value,
            created_at,
        );
        let expected_hash = hash_canonical(&canonical);
        if *hash != expected_hash {
            return Ok(AuditVerificationReport {
                ok: false,
                event_count: rows.len(),
                last_hash,
                broken_at_id: Some(*id),
            });
        }

        last_hash = Some(hash.clone());
    }

    Ok(AuditVerificationReport {
        ok: true,
        event_count: rows.len(),
        last_hash,
        broken_at_id: None,
    })
}

pub async fn export_forensic_bundle(
    db_url: &str,
    out_dir: &Path,
    request_id: Option<&str>,
) -> anyhow::Result<ForensicBundlePaths> {
    let pool = open_pool(db_url).await?;
    std::fs::create_dir_all(out_dir)?;
    let verification = verify_audit_chain(db_url).await?;

    let audit_rows: Vec<AuditChainRow> = if let Some(request_id) = request_id {
        sqlx::query_as(
            "SELECT id, actor_key, action, request_id, details, prev_hash, hash, created_at
             FROM audit_events
             WHERE request_id = ?
             ORDER BY id ASC",
        )
        .bind(request_id)
        .fetch_all(&pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, actor_key, action, request_id, details, prev_hash, hash, created_at
             FROM audit_events
             ORDER BY id ASC",
        )
        .fetch_all(&pool)
        .await?
    };

    let request_rows: Vec<RequestExportRow> = if let Some(request_id) = request_id {
        sqlx::query_as(
            "SELECT id, request_type, secret_ref, action, target, amount_cents, reason, status,
                    deny_reason, capability_used_at, created_at, updated_at
             FROM secret_broker_requests
             WHERE id = ?",
        )
        .bind(request_id)
        .fetch_all(&pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, request_type, secret_ref, action, target, amount_cents, reason, status,
                    deny_reason, capability_used_at, created_at, updated_at
             FROM secret_broker_requests",
        )
        .fetch_all(&pool)
        .await?
    };

    let summary_path = out_dir.join("summary.json");
    let audit_path = out_dir.join("audit.ndjson");
    let requests_path = out_dir.join("requests.json");

    let summary = json!({
        "ok": verification.ok,
        "event_count": verification.event_count,
        "last_hash": verification.last_hash,
        "broken_at_id": verification.broken_at_id,
        "request_scope": request_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;

    let mut audit_lines = Vec::with_capacity(audit_rows.len());
    for (id, actor_key, action, request_id, details, prev_hash, hash, created_at) in audit_rows {
        let details_value: Value = serde_json::from_str(&details)?;
        audit_lines.push(serde_json::to_string(&json!({
            "id": id,
            "actor_key": actor_key,
            "action": action,
            "request_id": request_id,
            "details": details_value,
            "prev_hash": prev_hash,
            "hash": hash,
            "created_at": created_at,
        }))?);
    }
    std::fs::write(&audit_path, audit_lines.join("\n"))?;

    let mut requests_json = Vec::with_capacity(request_rows.len());
    for (
        id,
        request_type,
        secret_ref,
        action,
        target,
        amount_cents,
        reason,
        status,
        deny_reason,
        capability_used_at,
        created_at,
        updated_at,
    ) in request_rows
    {
        requests_json.push(json!({
            "id": id,
            "request_type": request_type,
            "secret_ref_masked": crate::mask_secret_ref(&secret_ref),
            "action": action,
            "target": target,
            "amount_cents": amount_cents,
            "reason": reason,
            "status": status,
            "deny_reason": deny_reason,
            "capability_used_at": capability_used_at,
            "created_at": created_at,
            "updated_at": updated_at,
        }));
    }
    std::fs::write(
        &requests_path,
        serde_json::to_string_pretty(&requests_json)?,
    )?;

    Ok(ForensicBundlePaths {
        summary_path,
        audit_path,
        requests_path,
    })
}
