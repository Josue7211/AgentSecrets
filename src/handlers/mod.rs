pub(crate) mod admin;
pub(crate) mod execution;
pub(crate) mod health;
pub(crate) mod requests;

use crate::AppState;

pub(super) async fn expire_stale_requests(state: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::now_unix();
    let request_cutoff = now - state.cfg.request_ttl_seconds;

    sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'expired', updated_at = datetime('now')
         WHERE status IN ('pending_approval','approved')
           AND CAST(strftime('%s', created_at) AS INTEGER) < ?",
    )
    .bind(request_cutoff)
    .execute(&*state.db)
    .await?;

    sqlx::query(
        "UPDATE secret_broker_requests
         SET status = 'expired', updated_at = datetime('now')
         WHERE status = 'approved'
           AND capability_expires_at IS NOT NULL
           AND CAST(strftime('%s', capability_expires_at) AS INTEGER) < ?",
    )
    .bind(now)
    .execute(&*state.db)
    .await?;

    Ok(())
}
