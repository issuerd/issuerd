// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Realm resolution middleware: extracts the realm segment from /realms/ and /admin/realms/.

use axum::{extract::Request, middleware::Next, response::Response};

#[derive(Debug, Clone)]
pub struct ResolvedRealm(pub Option<String>);

pub async fn realm_resolution_middleware(mut request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let realm = if let Some(rest) = path.strip_prefix("/realms/") {
        rest.split('/').next().map(|s| s.to_string())
    } else if let Some(rest) = path.strip_prefix("/admin/realms/") {
        rest.split('/').next().map(|s| s.to_string())
    } else {
        None
    };

    request.extensions_mut().insert(ResolvedRealm(realm));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Extension,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn handler(Extension(realm): Extension<ResolvedRealm>) -> String {
        realm.0.unwrap_or_default()
    }

    #[tokio::test]
    async fn extracts_realm_from_oidc_path() {
        let app = Router::new()
            .route("/{*path}", get(handler))
            .layer(axum::middleware::from_fn(realm_resolution_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/realms/test/protocol/openid-connect/auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "test");
    }

    #[tokio::test]
    async fn extracts_realm_from_admin_path() {
        let app = Router::new()
            .route("/{*path}", get(handler))
            .layer(axum::middleware::from_fn(realm_resolution_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/master/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "master");
    }

    #[tokio::test]
    async fn no_realm_for_other_paths() {
        let app = Router::new()
            .route("/health", get(handler))
            .layer(axum::middleware::from_fn(realm_resolution_middleware));

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "");
    }
}
