use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::json;
use sha2::Sha256;

use crate::Result;
use crate::sink::{HttpTarget, SinkMessage, SinkTarget};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct HttpSink {
    client: reqwest::Client,
}

impl Default for HttpSink {
    fn default() -> Self {
        Self::with_timeout(DEFAULT_HTTP_TIMEOUT)
            .expect("default HTTP sink timeout configuration should be valid")
    }
}

impl HttpSink {
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(Self { client })
    }

    pub async fn send_http(&self, target: &HttpTarget, message: &SinkMessage) -> Result<()> {
        let body = json!({
            "source": "clawhip",
            "event_type": message.event_kind,
            "summary": message.content,
            "payload": message.payload,
            "correlation_id": message.telemetry.as_ref().map(|t| t.correlation_id.as_str()),
            "target": message.telemetry.as_ref().map(|t| t.target.as_str()),
        });
        let body_bytes = serde_json::to_vec(&body)?;

        let mut headers = HeaderMap::new();
        for (name, value) in &target.headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())?;
            let header_value = HeaderValue::from_str(value)?;
            headers.insert(header_name, header_value);
        }
        headers
            .entry(reqwest::header::CONTENT_TYPE)
            .or_insert(HeaderValue::from_static("application/json"));

        if let Some(correlation_id) = message
            .telemetry
            .as_ref()
            .map(|t| t.correlation_id.trim())
            .filter(|v| !v.is_empty())
        {
            headers.insert("x-request-id", HeaderValue::from_str(correlation_id)?);
        }

        if let Some(env_name) = target
            .hmac_secret_env
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            let secret = std::env::var(env_name)
                .map_err(|_| format!("HTTP sink signing secret env var '{env_name}' is not set"))?;
            if secret.trim().is_empty() {
                return Err(
                    format!("HTTP sink signing secret env var '{env_name}' is empty").into(),
                );
            }
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
            mac.update(&body_bytes);
            let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
            headers.insert("x-hub-signature-256", HeaderValue::from_str(&signature)?);
        }

        let response = self
            .client
            .post(&target.url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await
            .map_err(|error| format!("HTTP sink request failed: {}", error.without_url()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = response.text().await.unwrap_or_default();
        let truncated: String = body.chars().take(300).collect();
        Err(format!("HTTP sink POST failed with status {status}: {truncated}").into())
    }
}

#[async_trait::async_trait]
impl crate::sink::Sink for HttpSink {
    async fn send(&self, target: &SinkTarget, message: &SinkMessage) -> Result<()> {
        match target {
            SinkTarget::Http(target) => self.send_http(target, message).await,
            _ => Err("cannot send non-HTTP target via HTTP sink".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::MessageFormat;
    use crate::sink::{Sink, SinkTelemetry};
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap as AxumHeaderMap, StatusCode};
    use axum::routing::post;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct Capture {
        headers: Option<AxumHeaderMap>,
        body: Option<Vec<u8>>,
        status: StatusCode,
    }

    async fn start_server(status: StatusCode) -> (String, Arc<Mutex<Capture>>) {
        let capture = Arc::new(Mutex::new(Capture {
            status,
            ..Capture::default()
        }));
        async fn handler(
            State(capture): State<Arc<Mutex<Capture>>>,
            headers: AxumHeaderMap,
            body: Bytes,
        ) -> StatusCode {
            let mut guard = capture.lock().unwrap();
            guard.headers = Some(headers);
            guard.body = Some(body.to_vec());
            guard.status
        }
        let app = Router::new()
            .route("/wake", post(handler))
            .with_state(capture.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/wake"), capture)
    }

    fn message() -> SinkMessage {
        SinkMessage {
            event_kind: "session.stopped".into(),
            format: MessageFormat::Compact,
            content: "done".into(),
            payload: json!({"hermes_session_id":"sess-1"}),
            telemetry: Some(SinkTelemetry {
                correlation_id: "corr-1".into(),
                route_result: None,
                route_index: Some(0),
                target: "http:redacted".into(),
                batch_count: None,
            }),
        }
    }

    #[tokio::test]
    async fn http_sink_posts_json_headers_and_signature() {
        unsafe {
            std::env::set_var("CLAWHIP_TEST_HMAC_SECRET", "secret");
        }
        let (url, capture) = start_server(StatusCode::ACCEPTED).await;
        let target = SinkTarget::Http(HttpTarget {
            url,
            headers: BTreeMap::from([("X-Test".into(), "ok".into())]),
            hmac_secret_env: Some("CLAWHIP_TEST_HMAC_SECRET".into()),
        });
        HttpSink::default().send(&target, &message()).await.unwrap();

        let guard = capture.lock().unwrap();
        let headers = guard.headers.as_ref().unwrap();
        let body = guard.body.as_ref().unwrap();
        assert_eq!(headers.get("x-test").unwrap(), "ok");
        assert_eq!(headers.get("x-request-id").unwrap(), "corr-1");
        let sig = headers
            .get("x-hub-signature-256")
            .unwrap()
            .to_str()
            .unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(body);
        assert_eq!(
            sig,
            format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
        );
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(parsed["source"], "clawhip");
        assert_eq!(parsed["event_type"], "session.stopped");
        assert_eq!(parsed["correlation_id"], "corr-1");
    }

    #[tokio::test]
    async fn http_sink_missing_signing_env_fails_closed() {
        unsafe {
            std::env::remove_var("CLAWHIP_MISSING_HMAC_SECRET");
        }
        let (url, _capture) = start_server(StatusCode::ACCEPTED).await;
        let target = SinkTarget::Http(HttpTarget {
            url,
            headers: Default::default(),
            hmac_secret_env: Some("CLAWHIP_MISSING_HMAC_SECRET".into()),
        });
        let err = HttpSink::default()
            .send(&target, &message())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("CLAWHIP_MISSING_HMAC_SECRET"));
    }

    #[tokio::test]
    async fn http_sink_transport_error_redacts_url() {
        let target = SinkTarget::Http(HttpTarget {
            url: "http://127.0.0.1:9/wake?token=secret#fragment".into(),
            headers: Default::default(),
            hmac_secret_env: None,
        });

        let err = HttpSink::default()
            .send(&target, &message())
            .await
            .unwrap_err()
            .to_string();

        assert!(!err.contains("token"));
        assert!(!err.contains("secret"));
        assert!(!err.contains("fragment"));
        assert!(!err.contains("/wake"));
    }

    #[tokio::test]
    async fn http_sink_request_timeout_is_bounded() {
        let app = Router::new().route(
            "/slow",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                StatusCode::ACCEPTED
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = SinkTarget::Http(HttpTarget {
            url: format!("http://{addr}/slow?token=secret"),
            headers: Default::default(),
            hmac_secret_env: None,
        });

        let err = HttpSink::with_timeout(Duration::from_millis(25))
            .unwrap()
            .send(&target, &message())
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("HTTP sink request failed"));
        assert!(!err.contains("token=secret"));
    }

    #[tokio::test]
    async fn http_sink_non_2xx_returns_error() {
        let (url, _capture) = start_server(StatusCode::BAD_GATEWAY).await;
        let target = SinkTarget::Http(HttpTarget {
            url,
            headers: Default::default(),
            hmac_secret_env: None,
        });
        let err = HttpSink::default()
            .send(&target, &message())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("502 Bad Gateway"));
    }
}
