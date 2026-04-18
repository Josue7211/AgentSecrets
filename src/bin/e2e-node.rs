use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedactionMode {
    Off,
    Supported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultMode {
    Raw,
    Redacted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKind {
    LocalHelper,
    OpenClaw,
}

#[derive(Debug, Clone)]
struct TranscriptRedactor {
    mode: RedactionMode,
    canary_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let redactor = TranscriptRedactor::from_env()?;
    let mut args = std::env::args().skip(1);
    let command = args.next().context("missing e2e-node command")?;
    let flags = parse_flags(args.collect())?;

    match command.as_str() {
        "create" => create_request(HostKind::LocalHelper, flags, &redactor).await,
        "approve" => approve_request(HostKind::LocalHelper, flags, &redactor).await,
        "execute" => execute_request(HostKind::LocalHelper, flags, &redactor).await,
        "trusted-start" => trusted_input_start(HostKind::LocalHelper, flags, &redactor).await,
        "trusted-complete" => trusted_input_complete(HostKind::LocalHelper, flags, &redactor).await,
        "openclaw-create" => create_request(HostKind::OpenClaw, flags, &redactor).await,
        "openclaw-approve" => approve_request(HostKind::OpenClaw, flags, &redactor).await,
        "openclaw-execute" => execute_request(HostKind::OpenClaw, flags, &redactor).await,
        "openclaw-trusted-start" => trusted_input_start(HostKind::OpenClaw, flags, &redactor).await,
        "openclaw-trusted-complete" => {
            trusted_input_complete(HostKind::OpenClaw, flags, &redactor).await
        }
        other => Err(anyhow!("unsupported e2e-node command: {other}")),
    }
}

impl TranscriptRedactor {
    fn from_env() -> Result<Self> {
        let mode = match std::env::var("SECRET_BROKER_E2E_REDACTION_MODE")
            .unwrap_or_else(|_| "off".to_string())
            .trim()
            .to_lowercase()
            .as_str()
        {
            "supported" => RedactionMode::Supported,
            _ => RedactionMode::Off,
        };

        if mode == RedactionMode::Supported
            && std::env::var("SECRET_BROKER_E2E_REDACTION_FORCE_FAILURE")
                .ok()
                .as_deref()
                == Some("1")
        {
            anyhow::bail!("supported-host redaction initialization failed");
        }

        Ok(Self {
            mode,
            canary_secret: std::env::var("SECRET_BROKER_E2E_CANARY_SECRET").ok(),
        })
    }

    fn print(&self, line: &str) {
        println!("{}", self.sanitize(line));
    }

    fn sanitize(&self, input: &str) -> String {
        if self.mode == RedactionMode::Off {
            return input.to_string();
        }

        let mut output = input.to_string();

        if let Some(canary_secret) = self.canary_secret.as_deref() {
            if !canary_secret.is_empty() {
                output = output.replace(canary_secret, "[redacted:canary]");
            }
        }

        output = replace_prefixed_segment(&output, "bw://", "[redacted:provider-ref]");
        output = replace_prefixed_segment(&output, "tir://session/", "[redacted:opaque-ref]");
        output = replace_prefixed_segment(&output, "sbt_", "[redacted:capability]");
        output = replace_prefixed_segment(&output, "tit_", "[redacted:completion-token]");

        output
    }
}

fn result_mode() -> ResultMode {
    match std::env::var("SECRET_BROKER_E2E_RESULT_MODE")
        .unwrap_or_else(|_| "raw".to_string())
        .trim()
        .to_lowercase()
        .as_str()
    {
        "redacted" => ResultMode::Redacted,
        _ => ResultMode::Raw,
    }
}

fn result_sidecar_path() -> Option<PathBuf> {
    std::env::var("SECRET_BROKER_E2E_RESULT_PATH")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

fn emit_result(redactor: &TranscriptRedactor, body: Value) -> Result<()> {
    let raw = body.to_string();

    if let Some(path) = result_sidecar_path() {
        std::fs::write(&path, &raw)
            .with_context(|| format!("failed to write result sidecar at {}", path.display()))?;
    }

    match result_mode() {
        ResultMode::Raw => println!("RESULT_JSON={raw}"),
        ResultMode::Redacted => redactor.print(&format!("RESULT_JSON={}", redactor.sanitize(&raw))),
    }

    Ok(())
}

impl HostKind {
    fn label(self) -> &'static str {
        match self {
            HostKind::LocalHelper => "local-helper",
            HostKind::OpenClaw => "openclaw",
        }
    }

    fn transcript_prefix(self) -> &'static str {
        match self {
            HostKind::LocalHelper => "transcript",
            HostKind::OpenClaw => "openclaw:transcript",
        }
    }
}

fn replace_prefixed_segment(input: &str, prefix: &str, replacement: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;

    while let Some(index) = remaining.find(prefix) {
        let (before, after_prefix) = remaining.split_at(index);
        output.push_str(before);

        let token_len = after_prefix
            .chars()
            .take_while(|c| {
                !c.is_whitespace() && *c != '"' && *c != ',' && *c != '}' && *c != ']' && *c != ')'
            })
            .map(char::len_utf8)
            .sum::<usize>();

        if token_len == 0 {
            output.push_str(prefix);
            remaining = &after_prefix[prefix.len()..];
            continue;
        }

        output.push_str(replacement);
        remaining = &after_prefix[token_len..];
    }

    output.push_str(remaining);
    output
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

async fn create_request(
    host: HostKind,
    flags: HashMap<String, String>,
    redactor: &TranscriptRedactor,
) -> Result<()> {
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

    redactor.print(&format!(
        "{}:create host={} request_type={request_type} action={action} target={target} secret_ref={secret_ref}",
        host.transcript_prefix(),
        host.label()
    ));

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

    redactor.print(&format!(
        "{}:create status={status}",
        host.transcript_prefix()
    ));
    redactor.print(&format!(
        "{}:create body={json_body}",
        host.transcript_prefix()
    ));
    emit_result(
        redactor,
        json!({
            "host": host.label(),
            "status": status,
            "body": {
                "ok": json_body["ok"],
                "data": {
                    "id": json_body["data"]["id"],
                    "status": json_body["data"]["status"],
                    "requires_approval": json_body["data"]["requires_approval"],
                    "secret_ref_masked": json_body["data"]["secret_ref_masked"]
                }
            },
            "id": json_body["data"]["id"]
        }),
    )
}

async fn approve_request(
    host: HostKind,
    flags: HashMap<String, String>,
    redactor: &TranscriptRedactor,
) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let id = required_flag(&flags, "id")?;

    redactor.print(&format!(
        "{}:approve host={} id={id}",
        host.transcript_prefix(),
        host.label()
    ));

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

    redactor.print(&format!(
        "{}:approve status={status}",
        host.transcript_prefix()
    ));
    redactor.print(&format!(
        "{}:approve body={json_body}",
        host.transcript_prefix()
    ));
    emit_result(
        redactor,
        json!({
            "host": host.label(),
            "status": status,
            "body": json_body,
            "capability_token": json_body["data"]["capability_token"]
        }),
    )
}

async fn execute_request(
    host: HostKind,
    flags: HashMap<String, String>,
    redactor: &TranscriptRedactor,
) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let id = required_flag(&flags, "id")?;
    let capability_token = required_flag(&flags, "capability-token")?;
    let action = required_flag(&flags, "action")?;
    let target = required_flag(&flags, "target")?;

    redactor.print(&format!(
        "{}:execute host={} id={id} action={action} target={target}",
        host.transcript_prefix(),
        host.label()
    ));

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

    redactor.print(&format!(
        "{}:execute status={status}",
        host.transcript_prefix()
    ));
    redactor.print(&format!(
        "{}:execute body={json_body}",
        host.transcript_prefix()
    ));
    emit_result(
        redactor,
        json!({
            "host": host.label(),
            "status": status,
            "body": json_body
        }),
    )
}

async fn trusted_input_start(
    host: HostKind,
    flags: HashMap<String, String>,
    redactor: &TranscriptRedactor,
) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let action = required_flag(&flags, "action")?;
    let target = required_flag(&flags, "target")?;
    let reason = required_flag(&flags, "reason")?;
    let request_type = flags
        .get("request-type")
        .cloned()
        .unwrap_or_else(|| action.clone());

    redactor.print(&format!(
        "{}:trusted-start host={} request_type={request_type} action={action} target={target}",
        host.transcript_prefix(),
        host.label()
    ));

    let response = Client::new()
        .post(format!("{broker_url}/v1/trusted-input/sessions"))
        .header("x-api-key", api_key)
        .json(&json!({
            "request_type": request_type,
            "action": action,
            "target": target,
            "reason": reason
        }))
        .send()
        .await
        .context("trusted input start send failed")?;
    let status = response.status().as_u16();
    let json_body: Value = response
        .json()
        .await
        .context("trusted input start body decode failed")?;

    redactor.print(&format!(
        "{}:trusted-start status={status}",
        host.transcript_prefix()
    ));
    redactor.print(&format!(
        "{}:trusted-start body={json_body}",
        host.transcript_prefix()
    ));
    emit_result(
        redactor,
        json!({
            "host": host.label(),
            "status": status,
            "body": {
                "ok": json_body["ok"],
                "data": {
                    "id": json_body["data"]["id"],
                    "status": json_body["data"]["status"],
                    "request_type": json_body["data"]["request_type"],
                    "action": json_body["data"]["action"],
                    "target": json_body["data"]["target"]
                }
            },
            "id": json_body["data"]["id"],
            "completion_token": json_body["data"]["completion_token"]
        }),
    )
}

async fn trusted_input_complete(
    host: HostKind,
    flags: HashMap<String, String>,
    redactor: &TranscriptRedactor,
) -> Result<()> {
    let broker_url = required_flag(&flags, "broker-url")?;
    let api_key = required_flag(&flags, "api-key")?;
    let id = required_flag(&flags, "id")?;
    let completion_token = required_flag(&flags, "completion-token")?;
    let secret_ref = required_flag(&flags, "secret-ref")?;

    redactor.print(&format!(
        "{}:trusted-complete host={} id={id} secret_ref={secret_ref}",
        host.transcript_prefix(),
        host.label()
    ));

    let response = Client::new()
        .post(format!(
            "{broker_url}/v1/trusted-input/sessions/{id}/complete"
        ))
        .header("x-api-key", api_key)
        .json(&json!({
            "completion_token": completion_token,
            "secret_ref": secret_ref
        }))
        .send()
        .await
        .context("trusted input complete send failed")?;
    let status = response.status().as_u16();
    let json_body: Value = response
        .json()
        .await
        .context("trusted input complete body decode failed")?;

    redactor.print(&format!(
        "{}:trusted-complete status={status}",
        host.transcript_prefix()
    ));
    redactor.print(&format!(
        "{}:trusted-complete body={json_body}",
        host.transcript_prefix()
    ));
    emit_result(
        redactor,
        json!({
            "host": host.label(),
            "status": status,
            "body": {
                "ok": json_body["ok"],
                "data": {
                    "id": json_body["data"]["id"],
                    "status": json_body["data"]["status"],
                    "opaque_ref": json_body["data"]["opaque_ref"]
                }
            },
            "opaque_ref": json_body["data"]["opaque_ref"]
        }),
    )
}
