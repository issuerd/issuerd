// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use issuerd_core::*;
use issuerd_mcp::{
    step_up::{secure_id, PendingOperation},
    write_tools::McpOperation,
};
use sha2::{Digest, Sha256};

use crate::{
    ciba_step_up::{approval_key, approval_url, request_key, McpApprovalData},
    middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
    routes::oidc::{error_response, CibaAuthReqData, PendingAuthData},
    state::ServerState,
};

pub async fn get_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let realm_name = match realm {
        Some(realm) => realm,
        None => return error(StatusCode::NOT_FOUND, "invalid_request"),
    };
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(realm)) => realm,
        _ => return error(StatusCode::NOT_FOUND, "invalid_request"),
    };
    let Some(approval_id) = approval_id(query.as_deref()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let (approval, req_data) = match load(&state, &realm, &approval_id).await {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    let session = match authenticate(&state, &headers, &realm, &req_data).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return begin_login(&state, &realm, &approval_id, &req_data).await;
        }
        Err(response) => return response,
    };
    if let Err(response) = preconditions(&state, &realm, &req_data).await {
        return response;
    }
    let Some(operation) = req_data.operation.as_ref() else {
        return error(StatusCode::NOT_FOUND, "invalid_request");
    };
    let action = format!("/realms/{}/protocol/openid-connect/ext/ciba/approval", realm.name);
    let proof = csrf_proof(&approval, &session);
    let arguments =
        visible(&serde_json::to_string_pretty(&operation.canonical_args_json).unwrap_or_default());
    let mutation =
        visible(&serde_json::to_string_pretty(&operation.mutation.redacted()).unwrap_or_default());
    let tool = visible(operation.tool.as_str());
    let target = visible(&operation.mutation.target_id());
    let binding = visible(&operation.binding_message);
    let client = visible(operation.client_id.as_str());
    let realm_label = visible(realm.name.as_str());
    let expires = visible(&req_data.expires_at.to_rfc3339());
    let approval_input = visible(&approval_id);
    let proof = visible(&proof);
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve exact operation</title>
<style>body{{font-family:system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:1rem}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.5rem}}dt{{font-weight:600}}button{{padding:.75rem 1rem;margin-right:.5rem}}.deny{{background:#eee}}</style></head>
<body><h1>Approve exact operation</h1>
<p>One fresh approval authorizes only the operation shown below. It cannot authorize any other tool or changed arguments.</p>
<dl><dt>Realm</dt><dd>{realm_label}</dd><dt>Client</dt><dd>{client}</dd><dt>Tool</dt><dd>{tool}</dd>
<dt>Target</dt><dd>{target}</dd><dt>Binding message</dt><dd>{binding}</dd><dt>Expires</dt><dd>{expires}</dd></dl>
<h2>Normalized arguments</h2><pre>{arguments}</pre>
<h2>Expected state and exact mutation</h2><pre>{mutation}</pre>
<form method="post" action="{action}"><input type="hidden" name="approval_id" value="{approval_input}">
<input type="hidden" name="csrf_proof" value="{proof}">
<button type="submit" name="action" value="approve">Approve exactly once</button>
<button type="submit" name="action" value="deny" class="deny">Deny</button></form></body></html>"#
    );
    html_response(StatusCode::OK, html)
}

pub async fn post_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(realm) => realm,
        None => return error(StatusCode::NOT_FOUND, "invalid_request"),
    };
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(realm)) => realm,
        _ => return error(StatusCode::NOT_FOUND, "invalid_request"),
    };
    let params: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let mut approval_id = None;
    let mut action = None;
    let mut presented_proof = None;
    for (name, value) in params {
        let slot = match name.as_str() {
            "approval_id" => &mut approval_id,
            "action" => &mut action,
            "csrf_proof" => &mut presented_proof,
            _ => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        if slot.replace(value).is_some() {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        }
    }
    let (Some(approval_id), Some(action), Some(proof)) = (approval_id, action, presented_proof)
    else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !matches!(action.as_str(), "approve" | "deny") {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let (approval, mut req_data) = match load(&state, &realm, &approval_id).await {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    let session = match authenticate(&state, &headers, &realm, &req_data).await {
        Ok(Some(session)) => session,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "login_required"),
        Err(response) => return response,
    };
    let expected = csrf_proof(&approval, &session);
    let matches: bool = subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), proof.as_bytes()).into();
    if !matches {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    if let Err(response) = preconditions(&state, &realm, &req_data).await {
        return response;
    }
    if action == "approve" {
        if req_data
            .requested_acr_values
            .as_ref()
            .is_some_and(|values| !values.is_empty() && !values.iter().any(|value| value == "0"))
        {
            return error(StatusCode::FORBIDDEN, "access_denied");
        }
        req_data.authorized = true;
    } else {
        req_data.denied = true;
    }
    req_data.approval_auth_time = Some(session.auth_time.timestamp());
    req_data.approval_acr = Some("0".into());
    req_data.approval_amr = Some(vec![match session.auth_method {
        AuthMethod::Password => "pwd",
        AuthMethod::Spnego => "kba",
        AuthMethod::IdentityProvider => "idp",
        AuthMethod::Ciba | AuthMethod::Impersonation => {
            return error(StatusCode::FORBIDDEN, "access_denied");
        }
    }
    .into()]);
    let approval_bytes = match state.cache.get(&approval_key(&realm.id, &approval_id)).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        Err(error) => return temporary(&error),
    };
    let req_bytes = match serde_json::to_vec(&req_data) {
        Ok(bytes) => bytes,
        Err(error) => return temporary(&IssuerdError::ServerError(error.to_string())),
    };
    let Some(ttl) = crate::routes::oidc::remaining_ttl(req_data.expires_at) else {
        return error(StatusCode::BAD_REQUEST, "expired_token");
    };
    let decided = match state
        .cache
        .claim_and_create(
            &approval_key(&realm.id, &approval_id),
            approval_bytes,
            &request_key(&realm.id, &req_data.auth_req_id),
            req_bytes,
            Some(ttl),
        )
        .await
    {
        Ok(decided) => decided,
        Err(error) => return temporary(&error),
    };
    if !decided {
        return error(StatusCode::CONFLICT, "invalid_request");
    }
    let client_identifier = match ClientIdentifier::new(&req_data.client_id) {
        Ok(identifier) => identifier,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    let client = state
        .storage
        .get_client_by_client_id(&realm.id, &client_identifier)
        .await
        .ok()
        .flatten();
    let mut details = std::collections::HashMap::new();
    if let Some(operation) = req_data.operation.as_ref() {
        details.insert("operation_id".into(), operation.operation_id.clone());
    }
    crate::routes::oidc::emit_oidc_event(
        &state,
        &realm.id,
        if action == "approve" {
            EventType::CibaApprove
        } else {
            EventType::CibaDeny
        },
        &ip,
        client.map(|client| client.id),
        Some(session.user_id.clone()),
        Some(session.id.clone()),
        None,
        details,
    )
    .await;
    html_response(
        StatusCode::OK,
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Decision recorded</title></head><body><h1>{}</h1><p>You can return to the client.</p></body></html>",
            if action == "approve" { "Approved exactly once" } else { "Denied" }
        ),
    )
}

async fn load(
    state: &Arc<ServerState>,
    realm: &Realm,
    approval_id: &str,
) -> Result<(McpApprovalData, CibaAuthReqData), Response> {
    if !state.config.mcp.enabled || !state.config.mcp.step_up.enabled {
        return Err(error(StatusCode::NOT_FOUND, "invalid_request"));
    }
    let approval: McpApprovalData =
        match state.cache.get(&approval_key(&realm.id, approval_id)).await {
            Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                Ok(data) => data,
                Err(_) => return Err(error(StatusCode::BAD_REQUEST, "invalid_request")),
            },
            Ok(None) => return Err(error(StatusCode::NOT_FOUND, "invalid_request")),
            Err(error) => return Err(temporary(&error)),
        };
    let req_data: CibaAuthReqData =
        match state.cache.get(&request_key(&realm.id, &approval.auth_req_id)).await {
            Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                Ok(data) => data,
                Err(_) => return Err(error(StatusCode::BAD_REQUEST, "invalid_request")),
            },
            Ok(None) => return Err(error(StatusCode::BAD_REQUEST, "expired_token")),
            Err(error) => return Err(temporary(&error)),
        };
    if req_data.operation.is_none()
        || req_data.realm_id != realm.id.0
        || req_data.expires_at <= chrono::Utc::now()
    {
        return Err(error(StatusCode::BAD_REQUEST, "expired_token"));
    }
    Ok((approval, req_data))
}

async fn authenticate(
    state: &Arc<ServerState>,
    headers: &HeaderMap,
    realm: &Realm,
    req_data: &CibaAuthReqData,
) -> Result<Option<UserSession>, Response> {
    let session = crate::routes::oidc::resolve_session_from_cookie(state, headers, realm).await;
    let Some(session) = session else {
        return Ok(None);
    };
    if req_data.user_id.as_deref() != Some(session.user_id.as_ref()) {
        return Err(error(StatusCode::UNAUTHORIZED, "access_denied"));
    }
    let age = chrono::Utc::now().timestamp().saturating_sub(session.auth_time.timestamp());
    if !(0..=300).contains(&age) {
        return Ok(None);
    }
    if matches!(session.auth_method, AuthMethod::Ciba | AuthMethod::Impersonation) {
        return Err(error(StatusCode::FORBIDDEN, "access_denied"));
    }
    Ok(Some(session))
}

async fn begin_login(
    state: &Arc<ServerState>,
    realm: &Realm,
    approval_id: &str,
    req_data: &CibaAuthReqData,
) -> Response {
    let flow_id = secure_id();
    let pending = PendingAuthData {
        realm_id: realm.id.to_string(),
        client_id: req_data.client_id.clone(),
        redirect_uri: approval_url(state, realm.name.as_str(), approval_id),
        scope: vec!["openid".into()],
        state: None,
        nonce: None,
        response_type: "code".into(),
        code_challenge: None,
        code_challenge_method: None,
        ip_address: None,
        execution_id: FlowStageId::new("username-password").expect("static stage"),
        acr_values: req_data.requested_acr_values.clone().unwrap_or_default(),
        claims: None,
        _typestate_tag: "anonymous".into(),
        attempt_count: 0,
        remember_me: false,
        user_id: None,
        prompt_consent: false,
        locale: None,
        response_mode: None,
        authorization_details: None,
        resource: None,
    };
    let bytes = match serde_json::to_vec(&pending) {
        Ok(bytes) => bytes,
        Err(error) => return temporary(&IssuerdError::ServerError(error.to_string())),
    };
    let Some(ttl) = crate::routes::oidc::remaining_ttl(req_data.expires_at) else {
        return error(StatusCode::BAD_REQUEST, "expired_token");
    };
    if let Err(error) = state
        .cache
        .set(
            &crate::routes::oidc::pending_auth_cache_key(&realm.id, &flow_id),
            bytes,
            Some(ttl),
        )
        .await
    {
        return temporary(&error);
    }
    let mut response = axum::response::Redirect::to(&format!(
        "/login.html?execution_id={flow_id}&realm={}",
        realm.name
    ))
    .into_response();
    if let Ok(value) = header::HeaderValue::from_str(&crate::routes::oidc::flow_cookie_header(
        &flow_id,
        state.config.secure_cookies(),
    )) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn preconditions(
    state: &Arc<ServerState>,
    realm: &Realm,
    req_data: &CibaAuthReqData,
) -> Result<(), Response> {
    let Some(operation) = req_data.operation.as_ref() else {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_grant"));
    };
    let auth = operation_auth(operation, realm);
    let operation_input = McpOperation {
        tool: operation.tool,
        arguments: operation.canonical_args_json.clone(),
    };
    let prepared =
        crate::mcp_strict::prepare(&crate::mcp_service::admin_state(state), &auth, operation_input)
            .await;
    match prepared {
        Ok(Some(mutation)) if mutation.redacted() == operation.mutation.redacted() => Ok(()),
        Ok(_) => Err(error(StatusCode::CONFLICT, "precondition_failed")),
        Err(_) => Err(error(StatusCode::CONFLICT, "precondition_failed")),
    }
}

fn operation_auth(operation: &PendingOperation, realm: &Realm) -> issuerd_mcp::McpAuthContext {
    let realm = realm.name.clone();
    issuerd_mcp::McpAuthContext {
        realm_id: operation.realm_id.clone(),
        realm_name: realm,
        user_id: operation.subject_user_id.clone(),
        azp: operation.client_id.clone(),
        claims: AccessTokenClaims {
            jti: issuerd_core::JwtId::new(operation.origin_access_token_jti.clone())
                .expect("stored jti"),
            iss: Issuer::new("https://issuerd.invalid/realms/mcp").expect("static issuer"),
            sub: operation.subject_user_id.clone(),
            aud: Audience::new(operation.client_id.as_str()).expect("stored client"),
            exp: operation.expires_at,
            iat: operation.created_at,
            nbf: operation.created_at,
            scope: Scope::parse("openid mcp:write"),
            typ: JwtType::Bearer,
            azp: Some(operation.client_id.to_string()),
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
            resource: Some(operation.resource.clone()),
        },
    }
}

fn csrf_proof(approval: &McpApprovalData, session: &UserSession) -> String {
    let mut hash = Sha256::new();
    hash.update(approval.csrf_token.as_bytes());
    hash.update(b":");
    hash.update(session.id.as_ref().as_bytes());
    let digest = hash.finalize();
    let mut result = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(result, "{byte:02x}").expect("writing to a string cannot fail");
    }
    result
}

fn visible(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        if character.is_control()
            || matches!(
                character,
                '\u{200b}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
        {
            output.extend(character.escape_unicode());
        } else {
            match character {
                '&' => output.push_str("&amp;"),
                '<' => output.push_str("&lt;"),
                '>' => output.push_str("&gt;"),
                '"' => output.push_str("&quot;"),
                '\'' => output.push_str("&#x27;"),
                _ => output.push(character),
            }
        }
    }
    output
}

fn approval_id(query: Option<&str>) -> Option<String> {
    let mut values = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter(|(name, _)| name == "approval_id")
        .map(|(_, value)| value.into_owned());
    let first = values.next()?;
    if first.is_empty() || values.next().is_some() {
        return None;
    }
    Some(first)
}

fn html_response(status: StatusCode, html: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        .header("x-frame-options", "DENY")
        .body(Body::from(html))
        .expect("valid approval response")
}

fn error(status: StatusCode, code: &str) -> Response {
    let mut response = (status, axum::Json(serde_json::json!({"error": code}))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    response
}

fn temporary(error: &IssuerdError) -> Response {
    tracing::warn!(error = %error, "operation-bound approval state operation failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(error_response(&IssuerdError::TemporarilyUnavailable)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    #[tokio::test]
    async fn errors_keep_their_protocol_code() {
        let response = error(StatusCode::BAD_REQUEST, "expired_token");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "expired_token");
    }
}
