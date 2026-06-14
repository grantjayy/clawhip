use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::Result;

use super::{Sink, SinkMessage, SinkTarget};

type HmacSha256 = Hmac<Sha256>;
const HERMES_DURABLE_BODY: &str = "hermes_durable";
const HERMES_SOURCE: &str = "clawhip:omx";

#[derive(Clone)]
pub struct HttpSink {
    client: reqwest::Client,
}

impl HttpSink {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Sink for HttpSink {
    async fn send(&self, target: &SinkTarget, message: &SinkMessage) -> Result<()> {
        let SinkTarget::HttpEndpoint {
            url,
            hmac_secret_env,
            body,
        } = target
        else {
            return Err("cannot send non-HTTP target via HTTP sink".into());
        };

        if body.as_deref() != Some(HERMES_DURABLE_BODY) {
            return Err("HTTP sink only supports body = \"hermes_durable\"".into());
        }
        let secret_env = hmac_secret_env
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("HTTP durable sink missing hmac_secret_env")?;
        let secret = std::env::var(secret_env)
            .map_err(|_| format!("HTTP durable sink secret env '{secret_env}' is not set"))?;
        if secret.is_empty() {
            return Err(format!("HTTP durable sink secret env '{secret_env}' is empty").into());
        }

        let body = hermes_durable_body(message)?;
        let bytes = serde_json::to_vec(&body)?;
        let signature = github_signature(&bytes, secret.as_bytes())?;
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Hub-Signature-256", signature)
            .body(bytes)
            .send()
            .await?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(format!("HTTP sink request failed with {status}: {body}").into())
    }
}

impl Default for HttpSink {
    fn default() -> Self {
        Self::new().expect("reqwest client")
    }
}

pub(crate) fn hermes_durable_body(message: &SinkMessage) -> Result<Value> {
    let (event_type, default_status) = match message.event_kind.as_str() {
        "session.finished" => ("completed", "success"),
        "session.failed" => ("failed", "failed"),
        "session.blocked" => ("blocked", "blocked"),
        other => return Err(format!("unsupported Hermes durable event '{other}'").into()),
    };

    let run_id = required_payload_string(&message.payload, "run_id")?;
    let origin_id = required_payload_string(&message.payload, "origin_id")?;
    let event_id = first_payload_string(&message.payload, &["event_id", "idempotency_key"])
        .ok_or("Hermes durable body missing required payload field 'event_id'")?;
    let status = first_payload_string(&message.payload, &["status"])
        .unwrap_or_else(|| default_status.to_string());
    let durable_message = first_payload_string(&message.payload, &["message", "summary", "reason"])
        .unwrap_or_else(|| message.content.clone());

    Ok(json!({
        "run_id": run_id,
        "origin_id": origin_id,
        "event_type": event_type,
        "status": status,
        "event_id": event_id,
        "message": durable_message,
        "source": HERMES_SOURCE,
    }))
}

pub(crate) fn github_signature(body: &[u8], secret: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    Ok(format!("sha256={}", hex_lower(&digest)))
}

fn required_payload_string(payload: &Value, key: &str) -> Result<String> {
    first_payload_string(payload, &[key])
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("Hermes durable body missing required payload field '{key}'").into())
}

fn first_payload_string(payload: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        payload.get(*key).and_then(|value| match value {
            Value::String(text) => {
                let trimmed = text.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        })
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::MessageFormat;

    fn message(event_kind: &str, payload: Value) -> SinkMessage {
        SinkMessage {
            event_kind: event_kind.into(),
            format: MessageFormat::Compact,
            content: "rendered fallback".into(),
            payload,
        }
    }

    #[test]
    fn renders_finished_durable_body() {
        let body = hermes_durable_body(&message(
            "session.finished",
            json!({
                "run_id": "dar_1",
                "origin_id": "agent:main",
                "event_id": "evt_1",
                "message": "done"
            }),
        ))
        .expect("body");

        assert_eq!(body["event_type"], "completed");
        assert_eq!(body["status"], "success");
        assert_eq!(body["source"], "clawhip:omx");
        assert_eq!(body["message"], "done");
    }

    #[test]
    fn renders_failed_and_blocked_status_defaults() {
        let failed = hermes_durable_body(&message(
            "session.failed",
            json!({
                "run_id": "dar_1", "origin_id": "origin", "event_id": "evt"
            }),
        ))
        .expect("failed");
        let blocked = hermes_durable_body(&message(
            "session.blocked",
            json!({
                "run_id": "dar_1", "origin_id": "origin", "event_id": "evt2"
            }),
        ))
        .expect("blocked");

        assert_eq!(failed["event_type"], "failed");
        assert_eq!(failed["status"], "failed");
        assert_eq!(blocked["event_type"], "blocked");
        assert_eq!(blocked["status"], "blocked");
    }

    #[test]
    fn preserves_payload_status_and_event_id_alias() {
        let body = hermes_durable_body(&message(
            "session.finished",
            json!({
                "run_id": "dar_1",
                "origin_id": "origin",
                "idempotency_key": "idem",
                "status": "custom-ok",
                "summary": "summary text"
            }),
        ))
        .expect("body");

        assert_eq!(body["event_id"], "idem");
        assert_eq!(body["status"], "custom-ok");
        assert_eq!(body["message"], "summary text");
    }

    #[test]
    fn fails_closed_without_required_ids_or_on_stopped() {
        assert!(
            hermes_durable_body(&message(
                "session.finished",
                json!({
                    "origin_id": "origin", "event_id": "evt"
                })
            ))
            .is_err()
        );
        assert!(
            hermes_durable_body(&message(
                "session.finished",
                json!({
                    "run_id": "dar", "event_id": "evt"
                })
            ))
            .is_err()
        );
        assert!(
            hermes_durable_body(&message(
                "session.stopped",
                json!({
                    "run_id": "dar", "origin_id": "origin", "event_id": "evt"
                })
            ))
            .is_err()
        );
    }

    #[test]
    fn signs_exact_body_with_github_header_convention() {
        let signature =
            github_signature(br#"{"run_id":"dar"}"#, b"durable-secret").expect("signature");
        assert_eq!(
            signature,
            "sha256=05e8c1d100b93ff74e6c851d7fd2fb967565ea642a9e6fc2cbbb2850a925bde5"
        );
    }
}
