// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// JAR (JWT-Secured Authorization Request, RFC 9101) validation and parameter merging.

//! JAR (JWT-Secured Authorization Request, RFC 9101).
//!
//! A client may send its authorization request as a signed Request Object in
//! the `request` parameter instead of plain query parameters. The object is
//! verified against the client's verification material (its JWKS — inline or
//! fetched via the client-assertion plumbing — for asymmetric algorithms, or
//! the client secret for HMAC), and its claims then become the effective
//! authorization request parameters following Keycloak's
//! `AuthzEndpointRequestParser` semantics:
//!
//! - object claims win per-key over the query parameters;
//! - `client_id` present in both must match, and the query `client_id` is
//!   REQUIRED (it selects the verification material);
//! - `iss` must equal the query `client_id` (RFC 9101 §4, enforced inside
//!   [`issuerd_token::validate_request_object`]);
//! - `response_type` present in both must match;
//! - a `request_uri` claim inside the object is rejected.
//!
//! Unsigned Request Objects are always rejected (FAPI-aligned; Keycloak
//! tolerates them unless the client pins a signature algorithm — recorded in
//! `tests/KEYCLOAK_DIFFS.md`). JAR-by-reference from arbitrary URLs
//! (`request_uri`) is not implemented; PAR references are consumed earlier
//! (by the PAR endpoint) and a pushed `request` object is validated at push time.

use std::collections::HashMap;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use issuerd_core::{Client, EventType, IssuerdError, Realm};
use tracing::{debug, warn};

use crate::state::ServerState;

/// Clock-skew leeway for Request Object `exp`/`iat` checks (aligned with the
/// client-assertion leeway).
const REQUEST_OBJECT_LEEWAY_SECS: u64 = 60;

/// Validate the `request` parameter and merge its claims into the parameter
/// map. `client` is the requesting client, already looked up by the query
/// `client_id`. On success the returned map replaces the query parameters
/// (with `request` consumed) and is re-parsed as a normal authorization
/// request.
pub(crate) async fn extract_request_object_params(
    state: &Arc<ServerState>,
    realm: &Realm,
    client: &Client,
    query_params: &HashMap<String, String>,
) -> Result<HashMap<String, String>, IssuerdError> {
    let request_object = query_params
        .get("request")
        .ok_or_else(|| IssuerdError::InvalidRequest("missing request parameter".into()))?;
    let query_client_id =
        query_params.get("client_id").filter(|s| !s.is_empty()).ok_or_else(|| {
            IssuerdError::InvalidRequest("client_id is required with the request parameter".into())
        })?;

    // Verification material: the client's inline JWKS wins over the fetched
    // one (Keycloak's OIDCAdvancedConfigWrapper precedence). A URL-sourced
    // JWKS is refetchable on a kid miss (client key rotation).
    let (jwks, jwks_url) = match crate::client_assertion::inline_client_jwks(client)? {
        Some(j) => (Some(j), None),
        None => match crate::client_assertion::client_jwks_url(client)? {
            Some(url) => {
                let j = crate::client_assertion::fetch_client_jwks(
                    state, &realm.id, &client.id, &url, false,
                )
                .await?;
                (Some(j), Some(url))
            }
            None => (None, None),
        },
    };

    let issuer = format!(
        "{}/realms/{}",
        state.config.issuer_url.trim_end_matches('/'),
        realm.name.as_str()
    );
    let requirements = issuerd_token::RequestObjectRequirements {
        expected_client_id: query_client_id,
        accepted_issuer: &issuer,
        leeway_secs: REQUEST_OBJECT_LEEWAY_SECS,
    };
    let claims = match issuerd_token::validate_request_object(
        request_object,
        jwks.as_ref(),
        client.secret.as_deref(),
        &requirements,
    ) {
        Ok(claims) => claims,
        Err(first_err) => {
            // One refetch when the cached set does not cover the object's kid
            // (the client-assertion retry pattern; inline sets never refetch).
            let rotated = jwks_url.as_ref().is_some_and(|_| {
                jwks.as_ref()
                    .is_some_and(|j| !issuerd_token::jwks_covers_assertion(j, request_object))
            });
            match (&jwks_url, rotated) {
                (Some(url), true) => {
                    debug!(
                        client_id = %client.client_id,
                        "cached client JWKS does not cover the request object kid; refetching"
                    );
                    let fresh = crate::client_assertion::fetch_client_jwks(
                        state, &realm.id, &client.id, url, true,
                    )
                    .await?;
                    issuerd_token::validate_request_object(
                        request_object,
                        Some(&fresh),
                        client.secret.as_deref(),
                        &requirements,
                    )?
                }
                _ => return Err(first_err),
            }
        }
    };

    // Keycloak `AuthzEndpointRequestObjectParser`: a request_uri claim inside
    // the object is rejected.
    if claims.contains_key("request_uri") {
        return Err(IssuerdError::InvalidRequest(
            "the request_uri claim must not be set in the request object".into(),
        ));
    }

    // Consistency rules (Keycloak's `AuthzEndpointRequestParser::parseRequest`
    // and `validateResponseTypeParameter`): a client_id / response_type
    // present in both the query and the object must match.
    if let Some(object_client_id) = claims.get("client_id").and_then(|v| v.as_str()) {
        if object_client_id != query_client_id {
            return Err(IssuerdError::InvalidRequest(
                "the client_id parameter doesn't match the one in the request object".into(),
            ));
        }
    }
    if let (Some(query_rt), Some(object_rt)) = (
        query_params.get("response_type"),
        claims.get("response_type").and_then(|v| v.as_str()),
    ) {
        if query_rt != object_rt {
            return Err(IssuerdError::InvalidRequest(
                "the response_type parameter doesn't match the one in the request object".into(),
            ));
        }
    }

    // Merge (Keycloak semantics): the query parameters are the base, the
    // object's claims win per-key; the `request` parameter itself is
    // consumed. The query-supplied client_id (already verified against the
    // object's iss) survives either way.
    let mut params = query_params.clone();
    params.remove("request");
    for (key, value) in issuerd_protocol::authorization::request_object_claims_to_params(&claims) {
        params.insert(key, value);
    }
    params.insert("client_id".to_string(), query_client_id.clone());
    Ok(params)
}

/// Render a JAR validation failure like the PAR resolution failures: an
/// error-page redirect for browsers, a JSON OAuth2 error otherwise, plus a
/// login-error event. No client redirect is possible — the Request Object
/// (which carries the redirect_uri) failed validation, so nothing in it can
/// be trusted (Keycloak renders its generic 400 error page here too).
///
/// The wire error is always `invalid_request` (the plan mandates it for the
/// unsigned-request-object conformance module); the specific reason goes to
/// the log and the event details.
pub(crate) async fn jar_resolution_error(
    state: &Arc<ServerState>,
    realm: &Realm,
    realm_name: &str,
    ip: &std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    params: &HashMap<String, String>,
    error: IssuerdError,
) -> Response {
    warn!(realm = %realm.id, error = %error, "request object validation failed");
    let mut details = HashMap::new();
    details.insert("error".to_string(), error.to_string());
    crate::routes::oidc::emit_oidc_event(
        state,
        &realm.id,
        EventType::LoginError,
        ip,
        params.get("client_id").and_then(|s| issuerd_core::ClientId::new(s).ok()),
        None,
        None,
        Some(error.to_string()),
        details,
    )
    .await;

    let invalid = IssuerdError::InvalidRequest("invalid request object".into());
    if crate::routes::oidc::wants_html(headers) {
        let mut redirect = url::form_urlencoded::Serializer::new(String::new());
        redirect.append_pair("error", invalid.oauth_error_code().as_ref());
        redirect.append_pair("realm", realm_name);
        return axum::response::Redirect::to(&format!("/login.html?{}", redirect.finish()))
            .into_response();
    }
    (
        axum::http::StatusCode::BAD_REQUEST,
        axum::Json(crate::routes::oidc::error_response(&invalid)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use issuerd_core::{
        ClientAuthenticatorType, ClientId, ClientProtocol, CryptoProvider, RealmId, Scope,
    };

    const SECRET: &str = "s3cr3t";
    const CLIENT_ID: &str = "jar-client";

    fn make_client() -> Client {
        Client {
            id: ClientId::new("client-uuid-1").unwrap(),
            realm_id: RealmId::new("master").unwrap(),
            client_id: issuerd_core::ClientIdentifier::new(CLIENT_ID).unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some(SECRET.to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn object_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": CLIENT_ID,
            "aud": "http://localhost:8080/realms/master",
            "exp": now() + 300,
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/cb",
            "scope": "openid profile",
            "state": "state-1",
            "nonce": "nonce-1",
        })
    }

    fn sign_hs256(claims: &serde_json::Value, secret: &str) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn query_params(request: &str) -> HashMap<String, String> {
        HashMap::from([
            ("client_id".to_string(), CLIENT_ID.to_string()),
            ("request".to_string(), request.to_string()),
        ])
    }

    async fn test_state_and_realm() -> (Arc<ServerState>, Realm) {
        let state = Arc::new(ServerState::from_config(&ServerConfig::default()).await.unwrap());
        let realm = state.resolve_realm("master").await.unwrap().unwrap();
        (state, realm)
    }

    #[tokio::test]
    async fn valid_request_object_merges_into_params() {
        let (state, realm) = test_state_and_realm().await;
        let jwt = sign_hs256(&object_claims(), SECRET);
        let params =
            extract_request_object_params(&state, &realm, &make_client(), &query_params(&jwt))
                .await
                .unwrap();
        assert_eq!(params.get("response_type").unwrap(), "code");
        assert_eq!(params.get("redirect_uri").unwrap(), "http://localhost:3000/cb");
        assert_eq!(params.get("scope").unwrap(), "openid profile");
        assert_eq!(params.get("state").unwrap(), "state-1");
        assert_eq!(params.get("client_id").unwrap(), CLIENT_ID);
        // The request parameter itself is consumed.
        assert!(!params.contains_key("request"));
        // The merged map parses as a normal authorization request.
        let req = issuerd_protocol::authorization::AuthorizationRequest::parse(&params).unwrap();
        assert_eq!(req.response_type.as_str(), "code");
    }

    #[tokio::test]
    async fn object_claims_win_over_query_params() {
        let (state, realm) = test_state_and_realm().await;
        let jwt = sign_hs256(&object_claims(), SECRET);
        let mut query = query_params(&jwt);
        // Conflicting query values lose to the signed object.
        query.insert("scope".to_string(), "openid email".to_string());
        query.insert("state".to_string(), "query-state".to_string());
        // A non-conflicting query parameter (kc_idp_hint) survives the merge.
        query.insert("kc_idp_hint".to_string(), "github".to_string());
        let params = extract_request_object_params(&state, &realm, &make_client(), &query)
            .await
            .unwrap();
        assert_eq!(params.get("scope").unwrap(), "openid profile");
        assert_eq!(params.get("state").unwrap(), "state-1");
        assert_eq!(params.get("kc_idp_hint").unwrap(), "github");
    }

    #[tokio::test]
    async fn missing_query_client_id_rejected() {
        let (state, realm) = test_state_and_realm().await;
        let jwt = sign_hs256(&object_claims(), SECRET);
        let query = HashMap::from([("request".to_string(), jwt)]);
        assert!(extract_request_object_params(&state, &realm, &make_client(), &query)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn iss_mismatch_rejected() {
        let (state, realm) = test_state_and_realm().await;
        let mut claims = object_claims();
        claims["iss"] = serde_json::json!("other-client");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(
            extract_request_object_params(&state, &realm, &make_client(), &query_params(&jwt))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn client_id_claim_mismatch_rejected() {
        let (state, realm) = test_state_and_realm().await;
        // iss matches the query (RFC check passes) but the client_id CLAIM
        // does not — Keycloak's consistency rule rejects it.
        let mut claims = object_claims();
        claims["client_id"] = serde_json::json!("other-client");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(
            extract_request_object_params(&state, &realm, &make_client(), &query_params(&jwt))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn response_type_mismatch_rejected() {
        let (state, realm) = test_state_and_realm().await;
        let jwt = sign_hs256(&object_claims(), SECRET);
        let mut query = query_params(&jwt);
        query.insert("response_type".to_string(), "id_token".to_string());
        assert!(extract_request_object_params(&state, &realm, &make_client(), &query)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn request_uri_claim_in_object_rejected() {
        let (state, realm) = test_state_and_realm().await;
        let mut claims = object_claims();
        claims["request_uri"] = serde_json::json!("https://evil.example.com/obj.jwt");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(
            extract_request_object_params(&state, &realm, &make_client(), &query_params(&jwt))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unsigned_request_object_rejected() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&object_claims()).unwrap().as_bytes());
        let jwt = format!("{header}.{payload}.");
        let (state, realm) = test_state_and_realm().await;
        assert!(
            extract_request_object_params(&state, &realm, &make_client(), &query_params(&jwt))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn wrong_secret_signature_rejected() {
        let (state, realm) = test_state_and_realm().await;
        let jwt = sign_hs256(&object_claims(), "wrong-secret");
        assert!(
            extract_request_object_params(&state, &realm, &make_client(), &query_params(&jwt))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rs256_request_object_via_inline_jwks() {
        let (state, realm) = test_state_and_realm().await;
        let crypto = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = serde_json::to_value(crypto.get_public_keys().await.unwrap()).unwrap();
        let kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();

        let mut client = make_client();
        client.attributes.insert("use.jwks.string".to_string(), "true".to_string());
        client
            .attributes
            .insert("jwks.string".to_string(), serde_json::to_string(&jwks).unwrap());

        let jwt = crypto
            .sign(
                &serde_json::to_string(&object_claims()).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid).unwrap(),
            )
            .await
            .unwrap();
        let params = extract_request_object_params(&state, &realm, &client, &query_params(&jwt))
            .await
            .unwrap();
        assert_eq!(params.get("response_type").unwrap(), "code");
    }

    #[tokio::test]
    async fn rs256_request_object_wrong_key_rejected() {
        let (state, realm) = test_state_and_realm().await;
        // Client's JWKS holds key A; the object is signed with key B.
        let crypto_a = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let crypto_b = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks_a = serde_json::to_value(crypto_a.get_public_keys().await.unwrap()).unwrap();
        let jwks_b = serde_json::to_value(crypto_b.get_public_keys().await.unwrap()).unwrap();
        let kid_b = jwks_b["keys"][0]["kid"].as_str().unwrap().to_string();

        let mut client = make_client();
        client.attributes.insert("use.jwks.string".to_string(), "true".to_string());
        client
            .attributes
            .insert("jwks.string".to_string(), serde_json::to_string(&jwks_a).unwrap());

        let jwt = crypto_b
            .sign(
                &serde_json::to_string(&object_claims()).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid_b).unwrap(),
            )
            .await
            .unwrap();
        assert!(extract_request_object_params(&state, &realm, &client, &query_params(&jwt))
            .await
            .is_err());
    }
}
