// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Request-id middleware: propagates a sanitized inbound x-request-id or assigns
// a UUID per request, and echoes the effective id back as x-request-id.

use axum::{extract::Request, middleware::Next, response::Response};

/// Longest inbound `x-request-id` honored before falling back to a generated UUID.
const MAX_REQUEST_ID_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Accept an inbound request id only when it is short and made of
/// `[A-Za-z0-9._-]` — anything else (log-injection chars, oversized values)
/// is replaced with a freshly generated UUID.
fn sanitize_request_id(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        Some(value.to_string())
    } else {
        None
    }
}

pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_id)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    request.extensions_mut().insert(RequestId(id.clone()));
    let mut response = next.run(request).await;
    if let Ok(value) = id.parse() {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn test_app() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(request_id_middleware))
    }

    #[tokio::test]
    async fn adds_request_id_header() {
        let response = test_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn propagates_valid_inbound_request_id() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-request-id", "lb-trace_123.abc-DEF")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.headers().get("x-request-id").unwrap(), "lb-trace_123.abc-DEF");
    }

    #[test]
    fn sanitize_request_id_rules() {
        assert_eq!(sanitize_request_id("abc-DEF_123.45").as_deref(), Some("abc-DEF_123.45"));
        assert!(sanitize_request_id("").is_none());
        assert!(sanitize_request_id("forged\nINFO line").is_none());
        assert!(sanitize_request_id("has space").is_none());
        assert!(sanitize_request_id("semi;colon").is_none());
        assert!(sanitize_request_id("héllo").is_none());
        let max_len = "x".repeat(MAX_REQUEST_ID_LEN);
        assert!(sanitize_request_id(&max_len).is_some());
        let oversized = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        assert!(sanitize_request_id(&oversized).is_none());
    }

    #[tokio::test]
    async fn rejects_unsafe_inbound_request_id() {
        // Note: only values that are legal in an HTTP header can be exercised
        // end-to-end here; control chars are covered by the unit test above.
        let oversized = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        for bad in ["has space", "semi;colon", oversized.as_str()] {
            let response = test_app()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header("x-request-id", bad)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let echoed = response.headers().get("x-request-id").unwrap().to_str().unwrap();
            assert_ne!(echoed, bad, "unsafe id must not be echoed");
            assert!(
                uuid::Uuid::parse_str(echoed).is_ok(),
                "fallback id should be a UUID, got {echoed}"
            );
        }
    }
}
