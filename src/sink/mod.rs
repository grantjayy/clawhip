pub mod discord;
pub mod http;
pub mod slack;

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;

use crate::Result;
use crate::events::MessageFormat;
use serde_json::Value;

pub use discord::DiscordSink;
pub use http::HttpSink;
pub use slack::SlackSink;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SinkTarget {
    DiscordChannel(String),
    DiscordWebhook(String),
    SlackWebhook(String),
    Http(HttpTarget),
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HttpTarget {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub hmac_secret_env: Option<String>,
}

impl fmt::Debug for HttpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpTarget")
            .field(
                "url",
                &crate::telemetry::redacted_url_fingerprint(&self.url),
            )
            .field(
                "headers",
                &format_args!("<{} configured>", self.headers.len()),
            )
            .field("hmac_secret_env", &self.hmac_secret_env)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkMessage {
    pub event_kind: String,
    pub format: MessageFormat,
    pub content: String,
    pub payload: Value,
    pub telemetry: Option<SinkTelemetry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkTelemetry {
    pub correlation_id: String,
    pub route_result: Option<String>,
    pub route_index: Option<usize>,
    pub target: String,
    pub batch_count: Option<usize>,
}

#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, target: &SinkTarget, message: &SinkMessage) -> Result<()>;
}
