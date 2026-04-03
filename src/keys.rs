use serde::Serialize;
use sqlx::SqlitePool;

use crate::{key_fingerprint, random_hex, token_hash, Config};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ApiKeyRole {
    Client,
    Approver,
}

impl ApiKeyRole {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ApiKeyRole::Client => "client",
            ApiKeyRole::Approver => "approver",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RotatedApiKey {
    pub(crate) role: ApiKeyRole,
    pub(crate) api_key: String,
    pub(crate) key_fingerprint: String,
}

fn generate_api_key() -> String {
    format!("sbk_{}", random_hex(32))
}

pub(crate) async fn ensure_api_keys(pool: &SqlitePool, cfg: &Config) -> anyhow::Result<()> {
    for (role, token) in [
        (ApiKeyRole::Client, &cfg.client_api_key),
        (ApiKeyRole::Approver, &cfg.approver_api_key),
    ] {
        sqlx::query(
            "INSERT OR IGNORE INTO api_keys (role, key_hash, key_fingerprint, created_at, rotated_at)
             VALUES (?, ?, ?, datetime('now'), datetime('now'))",
        )
        .bind(role.as_str())
        .bind(token_hash(token))
        .bind(key_fingerprint(token))
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub(crate) async fn rotate_api_key(
    pool: &SqlitePool,
    role: ApiKeyRole,
) -> Result<RotatedApiKey, sqlx::Error> {
    let api_key = generate_api_key();
    let fingerprint = key_fingerprint(&api_key);
    sqlx::query(
        "INSERT INTO api_keys (role, key_hash, key_fingerprint, created_at, rotated_at)
         VALUES (?, ?, ?, datetime('now'), datetime('now'))
         ON CONFLICT(role) DO UPDATE SET
             key_hash = excluded.key_hash,
             key_fingerprint = excluded.key_fingerprint,
             rotated_at = datetime('now')",
    )
    .bind(role.as_str())
    .bind(token_hash(&api_key))
    .bind(&fingerprint)
    .execute(pool)
    .await?;

    Ok(RotatedApiKey {
        role,
        api_key,
        key_fingerprint: fingerprint,
    })
}
