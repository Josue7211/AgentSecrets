use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().context("missing e2e-node command")?;
    let flags = parse_flags(args.collect())?;

    match command.as_str() {
        "create" => create_request(flags).await,
        "approve" => approve_request(flags).await,
        "execute" => execute_request(flags).await,
        other => Err(anyhow!("unsupported e2e-node command: {other}")),
    }
}

fn parse_flags(args: Vec<String>) -> Result<HashMap<String, String>> {
    if !args.len().is_multiple_of(2) {
        return Err(anyhow!("flags must be passed as --key value pairs"));
    }

    let mut flags = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index]
            .strip_prefix("--")
            .ok_or_else(|| anyhow!("invalid flag {}", args[index]))?
            .to_string();
        let value = args[index + 1].clone();
        flags.insert(key, value);
        index += 2;
    }

    Ok(flags)
}

fn required_flag(flags: &HashMap<String, String>, name: &str) -> Result<String> {
    flags
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow!("missing required flag --{name}"))
}

async fn create_request(flags: HashMap<String, String>) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let secret_ref = required_flag(&flags, "secret-ref")?;
    let action = required_flag(&flags, "action")?;
    let target = required_flag(&flags, "target")?;
    let reason = required_flag(&flags, "reason")?;
    let request_type = flags
        .get("request-type")
        .cloned()
        .unwrap_or_else(|| action.clone());

    println!(
        "transcript:create request_type={request_type} action={action} target={target} secret_ref={secret_ref}"
    );

    let body = json!({
        "request_type": request_type,
        "secret_ref": secret_ref,
        "action": action,
        "target": target,
        "reason": reason
    });

    let response = Client::new()
        .post(format!("{broker_url}/v1/requests"))
        .header("x-api-key", api_key)
        .json(&body)
        .send()
        .await
        .context("create request send failed")?;
    let status = response.status().as_u16();
    let json_body: Value = response
        .json()
        .await
        .context("create request body decode failed")?;

    println!("transcript:create status={status}");
    println!("transcript:create body={json_body}");
    println!(
        "RESULT_JSON={}",
        json!({
            "status": status,
            "body": json_body,
            "id": json_body["data"]["id"]
        })
    );
    Ok(())
}

async fn approve_request(flags: HashMap<String, String>) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let id = required_flag(&flags, "id")?;

    println!("transcript:approve id={id}");

    let response = Client::new()
        .post(format!("{broker_url}/v1/requests/{id}/approve"))
        .header("x-api-key", api_key)
        .send()
        .await
        .context("approve request send failed")?;
    let status = response.status().as_u16();
    let json_body: Value = response
        .json()
        .await
        .context("approve request body decode failed")?;

    println!("transcript:approve status={status}");
    println!("transcript:approve body={json_body}");
    println!(
        "RESULT_JSON={}",
        json!({
            "status": status,
            "body": json_body,
            "capability_token": json_body["data"]["capability_token"]
        })
    );
    Ok(())
}

async fn execute_request(flags: HashMap<String, String>) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let id = required_flag(&flags, "id")?;
    let capability_token = required_flag(&flags, "capability-token")?;
    let action = required_flag(&flags, "action")?;
    let target = required_flag(&flags, "target")?;

    println!("transcript:execute id={id} action={action} target={target}");

    let response = Client::new()
        .post(format!("{broker_url}/v1/execute"))
        .header("x-api-key", api_key)
        .json(&json!({
            "id": id,
            "capability_token": capability_token,
            "action": action,
            "target": target
        }))
        .send()
        .await
        .context("execute request send failed")?;
    let status = response.status().as_u16();
    let json_body: Value = response
        .json()
        .await
        .context("execute request body decode failed")?;

    println!("transcript:execute status={status}");
    println!("transcript:execute body={json_body}");
    println!(
        "RESULT_JSON={}",
        json!({
            "status": status,
            "body": json_body
        })
    );
    Ok(())
}
