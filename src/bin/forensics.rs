use std::path::PathBuf;

fn usage() -> anyhow::Error {
    anyhow::anyhow!(
        "usage:\n  forensics verify-chain --db <sqlite-url>\n  forensics export-bundle --db <sqlite-url> --out <dir> [--request-id <id>]"
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };

    match command.as_str() {
        "verify-chain" => {
            let Some(flag) = args.next() else {
                return Err(usage());
            };
            if flag != "--db" {
                return Err(usage());
            }
            let Some(db_url) = args.next() else {
                return Err(usage());
            };
            let report = secret_broker::audit::verify_audit_chain(&db_url).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "export-bundle" => {
            let Some(db_flag) = args.next() else {
                return Err(usage());
            };
            if db_flag != "--db" {
                return Err(usage());
            }
            let Some(db_url) = args.next() else {
                return Err(usage());
            };
            let Some(out_flag) = args.next() else {
                return Err(usage());
            };
            if out_flag != "--out" {
                return Err(usage());
            }
            let Some(out_dir) = args.next() else {
                return Err(usage());
            };
            let mut request_id = None;
            if let Some(extra_flag) = args.next() {
                if extra_flag != "--request-id" {
                    return Err(usage());
                }
                request_id = args.next();
            }

            let bundle = secret_broker::audit::export_forensic_bundle(
                &db_url,
                &PathBuf::from(out_dir),
                request_id.as_deref(),
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "summary_path": bundle.summary_path,
                    "audit_path": bundle.audit_path,
                    "requests_path": bundle.requests_path,
                }))?
            );
        }
        _ => return Err(usage()),
    }

    Ok(())
}
