// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use issuerd_core::*;
use issuerd_mcp::{
    executor::pending_operation_key,
    step_up::{secure_id, PendingOperation, DEFAULT_GRANT_TTL_SECS},
};
use issuerd_protocol::ciba::CibaRequest;

use crate::{
    routes::{
        oidc::{error_response, persist_session, token_response, CibaAuthReqData, TokenResponse},
        protected_resource::realm_mcp_resource,
    },
    state::ServerState,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpApprovalData {
    pub auth_req_id: String,
    pub csrf_token: String,
}

pub fn request_key(realm_id: &RealmId, auth_req_id: &str) -> String {
    format!("mcp:ciba:{{{realm_id}}}:{auth_req_id}")
}

pub fn approval_key(realm_id: &RealmId, approval_id: &str) -> String {
    format!("mcp:approval:{{{realm_id}}}:{approval_id}")
}

pub fn approval_url(state: &ServerState, realm_name: &str, approval_id: &str) -> String {
    format!(
        "{}/realms/{realm_name}/protocol/openid-connect/ext/ciba/approval?approval_id={approval_id}",
        state.config.issuer_url.trim_end_matches('/')
    )
}

fn persisted_uuid(realm_id: &RealmId, auth_req_id: &str, kind: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        format!("mcp-ciba:{realm_id}:{kind}:{auth_req_id}").as_bytes(),
    )
    .to_string()
}

pub async fn initiate(
    state: Arc<ServerState>,
    realm: Realm,
    client: Client,
    request: CibaRequest,
    ip: IpAddr,
) -> Response {
    if !state.config.mcp.enabled || !state.config.mcp.step_up.enabled {
        return error(StatusCode::BAD_REQUEST, "unauthorized_client");
    }
    if let Err(error) = request.validate_step_up_scope(&client) {
        return (StatusCode::BAD_REQUEST, Json(error_response(&error))).into_response();
    }
    if request.client_notification_token.is_some() {
        return error(StatusCode::BAD_REQUEST, "unauthorized_client");
    }
    let Some(operation_id) = request.operation_id.as_deref() else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let realm_id = realm.id.clone();
    let key = pending_operation_key(&realm_id, operation_id);
    let pending_bytes = match state.cache.get(&key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        Err(error) => return temporary(&error),
    };
    let pending: PendingOperation = match serde_json::from_slice(&pending_bytes) {
        Ok(pending) => pending,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let now = chrono::Utc::now().timestamp();
    let expected_resource = realm_mcp_resource(&state.config.issuer_url, realm.name.as_str());
    if pending.expires_at <= now
        || pending.realm_id != realm_id
        || pending.client_id != client.client_id
        || pending.resource != expected_resource
        || request.resource.as_deref() != Some(expected_resource.as_str())
    {
        return error(StatusCode::BAD_REQUEST, "invalid_target");
    }
    if request.binding_message.as_deref() != Some(pending.binding_message.as_str()) {
        return error(StatusCode::BAD_REQUEST, "invalid_binding_message");
    }
    if request.acr_values.iter().any(|value| value != "0") {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let user = match state
        .storage
        .get_user_by_username(&realm_id, request.login_hint.as_deref().unwrap_or_default())
        .await
    {
        Ok(Some(user)) if user.enabled && user.id == pending.subject_user_id => user,
        Ok(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        Err(error) => return temporary(&error),
    };
    let remaining = u64::try_from(pending.expires_at.saturating_sub(now)).unwrap_or(0);
    if remaining == 0 {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let expires_in = request.requested_expiry.unwrap_or(remaining).min(remaining).max(1);
    let auth_req_id = secure_id();
    let approval_id = secure_id();
    let expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(i64::try_from(expires_in).unwrap_or(i64::MAX));
    let req_data = CibaAuthReqData {
        auth_req_id: auth_req_id.clone(),
        client_id: client.client_id.to_string(),
        realm_id: realm_id.to_string(),
        scope: vec!["openid".into(), MCP_SCOPE_STEP_UP.into()],
        user_id: Some(user.id.to_string()),
        authorized: false,
        denied: false,
        binding_message: Some(pending.binding_message.clone()),
        client_notification_token: None,
        last_polled_at: None,
        expires_at,
        resource: Some(expected_resource),
        operation: Some(pending.clone()),
        requested_acr_values: Some(request.acr_values),
        approval_id: Some(approval_id.clone()),
        approval_auth_time: None,
        approval_acr: None,
        approval_amr: None,
        poll_interval_secs: 5,
    };
    let approval = McpApprovalData {
        auth_req_id: auth_req_id.clone(),
        csrf_token: secure_id(),
    };
    let approval_bytes = match serde_json::to_vec(&approval) {
        Ok(bytes) => bytes,
        Err(error) => return temporary(&IssuerdError::ServerError(error.to_string())),
    };
    let approval_cache_key = approval_key(&realm_id, &approval_id);
    let ttl = std::time::Duration::from_secs(expires_in);
    let claimed = match state
        .cache
        .claim_and_create(
            &key,
            pending_bytes.clone(),
            &approval_cache_key,
            approval_bytes.clone(),
            Some(ttl),
        )
        .await
    {
        Ok(claimed) => claimed,
        Err(error) => return temporary(&error),
    };
    if !claimed {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let request_bytes = match serde_json::to_vec(&req_data) {
        Ok(bytes) => bytes,
        Err(error) => return temporary(&IssuerdError::ServerError(error.to_string())),
    };
    let request_cache_key = request_key(&realm_id, &auth_req_id);
    match state.cache.create_if_absent(&request_cache_key, request_bytes, Some(ttl)).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = state
                .cache
                .claim_and_create(
                    &approval_cache_key,
                    approval_bytes,
                    &key,
                    pending_bytes,
                    Some(std::time::Duration::from_secs(remaining)),
                )
                .await;
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        Err(error) => {
            let _ = state
                .cache
                .claim_and_create(
                    &approval_cache_key,
                    approval_bytes,
                    &key,
                    pending_bytes,
                    Some(std::time::Duration::from_secs(remaining)),
                )
                .await;
            return temporary(&error);
        }
    }
    let mut details = std::collections::HashMap::new();
    details.insert("operation_id".into(), operation_id.to_string());
    details.insert("expires_in".into(), expires_in.to_string());
    crate::routes::oidc::emit_oidc_event(
        &state,
        &realm_id,
        EventType::CibaAuth,
        &ip,
        Some(client.id.clone()),
        Some(user.id.clone()),
        None,
        None,
        details,
    )
    .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "auth_req_id": auth_req_id,
            "expires_in": expires_in,
            "interval": 5,
            "approval_url": approval_url(&state, realm.name.as_str(), &approval_id),
        })),
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
pub async fn issue(
    state: Arc<ServerState>,
    realm: Realm,
    client: Client,
    user: User,
    req_data: CibaAuthReqData,
    dpop_jkt: Option<String>,
    ip: IpAddr,
) -> Response {
    let Some(operation) = req_data.operation.clone() else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let Some(dpop_jkt) = dpop_jkt else {
        return error(StatusCode::BAD_REQUEST, "invalid_dpop_proof");
    };
    let now = chrono::Utc::now().timestamp();
    let Some(approval_auth_time) = req_data.approval_auth_time else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let requested_acr = req_data.requested_acr_values.unwrap_or_default();
    let acr_matches = requested_acr.is_empty()
        || req_data.approval_acr.as_ref().is_some_and(|acr| requested_acr.contains(acr));
    if operation.expires_at <= now
        || operation.origin_dpop_jkt != dpop_jkt
        || approval_auth_time > now
        || now.saturating_sub(approval_auth_time) > 300
        || !acr_matches
        || req_data.resource.as_deref() != Some(operation.resource.as_str())
    {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let realm_id = realm.id.clone();
    let session_id = SessionId::new(persisted_uuid(&realm_id, &req_data.auth_req_id, "session"))
        .expect("deterministic CIBA session IDs are UUIDs");
    let auth_time = chrono::DateTime::from_timestamp(approval_auth_time, 0)
        .expect("approval timestamp came from the system clock");
    let approval_auth_method = match req_data
        .approval_amr
        .as_ref()
        .and_then(|methods| methods.first())
        .map(String::as_str)
    {
        Some("kba") => AuthMethod::Spnego,
        Some("idp") => AuthMethod::IdentityProvider,
        _ => AuthMethod::Password,
    };
    let existing_session = match state.storage.get_user_session(&realm_id, &session_id).await {
        Ok(session) => session,
        Err(error) => return temporary(&error),
    };
    if existing_session.is_none() {
        let session = UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: approval_auth_method,
            remember_me: false,
            offline: false,
            ip_address: ip,
            started: auth_time,
            last_session_refresh: auth_time,
            auth_time,
            impersonator: None,
            clients: vec![ClientSession {
                id: ClientSessionId::new(persisted_uuid(
                    &realm_id,
                    &req_data.auth_req_id,
                    "client",
                ))
                .expect("deterministic CIBA client-session IDs are UUIDs"),
                client_id: client.id.clone(),
                session_id: session_id.clone(),
                redirect_uri: None,
                state: None,
                auth_method: approval_auth_method,
                timestamp: auth_time,
            }],
        };
        if let Err(response) = persist_session(&state, &realm_id, &session, false).await {
            return response;
        }
    }
    let mut token_realm = realm.clone();
    let grant_ttl = i64::try_from(DEFAULT_GRANT_TTL_SECS).unwrap_or(120);
    let lifetime = grant_ttl
        .min(operation.expires_at.saturating_sub(now))
        .min(i64::try_from(realm.access_token_lifespan.get()).unwrap_or(grant_ttl));
    if lifetime <= 0 {
        return error(StatusCode::BAD_REQUEST, "expired_token");
    }
    token_realm.access_token_lifespan = SecondsNonZero::new(lifetime as u64);
    let scope = vec!["openid".to_string(), MCP_SCOPE_STEP_UP.to_string()];
    let overlay = crate::claims::build_claims_overlay(
        &state,
        &realm_id,
        Some(&client),
        &user,
        &scope,
        ClaimTarget::AccessToken,
    )
    .await
    .unwrap_or_default();
    let overlay = crate::claims::bind_resource_aud_overlay(
        Some(overlay),
        client.client_id.as_str(),
        Some(&operation.resource),
    );
    let overlay = crate::dpop::bind_cnf_overlay(overlay, Some(&dpop_jkt));
    let token_jti = JwtId::new(format!("mcp-ciba-{}", req_data.auth_req_id))
        .expect("CIBA identifiers are nonempty");
    let access_token = match state
        .token_manager
        .issue_access_token_with_roles_and_jti(
            &user,
            &client,
            &token_realm,
            &scope,
            &session_id,
            None,
            None,
            overlay,
            &token_jti,
        )
        .await
    {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(realm = %realm_id, error = %error, "operation-bound token issuance failed");
            return temporary(&error);
        }
    };
    let grant = McpStepUpGrant {
        version: 1,
        operation_id: operation.operation_id.clone(),
        operation_hash: operation.operation_hash.clone(),
        canonicalization_version: operation.canonicalization_version,
        realm_id: realm_id.clone(),
        client_id: client.client_id.clone(),
        subject_user_id: user.id.clone(),
        resource: operation.resource.clone(),
        tool: operation.tool.as_str().into(),
        mutation: operation.mutation.clone(),
        origin_access_token_jti: operation.origin_access_token_jti.clone(),
        token_jti: token_jti.clone(),
        dpop_jkt,
        approval_auth_time,
        approval_acr: req_data.approval_acr.clone(),
        approval_amr: req_data.approval_amr.clone().unwrap_or_default(),
        status: McpStepUpExecutionStatus::Active,
        result_json: None,
        issued_at: now,
        expires_at: access_token.claims.exp.min(operation.expires_at),
        updated_at: now,
    };
    match state.storage.create_mcp_step_up_grant(&grant).await {
        Ok(()) => {}
        Err(IssuerdError::Conflict) => {
            match state.storage.get_mcp_step_up_grant(&token_jti).await {
                Ok(Some(existing))
                    if existing.operation_id == grant.operation_id
                        && existing.operation_hash == grant.operation_hash
                        && existing.mutation == grant.mutation
                        && existing.dpop_jkt == grant.dpop_jkt
                        && matches!(
                            existing.status,
                            McpStepUpExecutionStatus::Active | McpStepUpExecutionStatus::Succeeded
                        ) => {}
                Ok(_) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
                Err(error) => return temporary(&error),
            }
        }
        Err(error) => return temporary(&error),
    }
    let cache_key = request_key(&realm_id, &req_data.auth_req_id);
    if let Err(error) = state.cache.delete(&cache_key).await {
        return temporary(&error);
    }
    let expires_in = access_token.claims.exp.saturating_sub(now).max(0) as u64;
    token_response(TokenResponse {
        access_token: access_token.token,
        token_type: "DPoP".into(),
        expires_in,
        refresh_token: None,
        id_token: None,
        scope: Some(scope.join(" ")),
        issued_token_type: None,
        authorization_details: None,
    })
}

pub async fn poll(
    state: Arc<ServerState>,
    realm: Realm,
    client: Client,
    request: issuerd_protocol::token::TokenRequest,
    dpop_jkt: Option<String>,
    ip: IpAddr,
) -> Response {
    let Some(auth_req_id) = request.auth_req_id.as_deref().filter(|value| !value.is_empty()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let realm_id = realm.id.clone();
    let legacy_key = issuerd_cluster::cache_keys::ciba_auth_req(auth_req_id);
    let operation_key = request_key(&realm_id, auth_req_id);
    let (cache_key, original) = match state.cache.get(&legacy_key).await {
        Ok(Some(bytes)) => (legacy_key, bytes),
        Ok(None) => match state.cache.get(&operation_key).await {
            Ok(Some(bytes)) => (operation_key, bytes),
            Ok(None) => {
                crate::routes::oidc::emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    None,
                    "invalid_grant",
                )
                .await;
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            Err(error) => return temporary(&error),
        },
        Err(error) => return temporary(&error),
    };
    let req_data: CibaAuthReqData = match serde_json::from_slice(&original) {
        Ok(data) => data,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    if req_data.realm_id != realm_id.0 || req_data.client_id != client.client_id.to_string() {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if req_data.expires_at <= chrono::Utc::now() {
        return error(StatusCode::BAD_REQUEST, "expired_token");
    }
    if req_data.resource.as_deref() != request.resource.as_deref() {
        return error(StatusCode::BAD_REQUEST, "invalid_target");
    }
    if req_data.operation.is_some() && dpop_jkt.is_none() {
        return error(StatusCode::BAD_REQUEST, "invalid_dpop_proof");
    }
    let lock_key = format!("mcp:ciba-poll:{{{realm_id}}}:{auth_req_id}");
    match state
        .cache
        .create_if_absent(&lock_key, vec![1], Some(std::time::Duration::from_secs(30)))
        .await
    {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::BAD_REQUEST, "slow_down"),
        Err(error) => return temporary(&error),
    }
    let response =
        poll_locked(state.clone(), realm, client, req_data, cache_key, original, dpop_jkt, ip)
            .await;
    if let Err(error) = state.cache.delete(&lock_key).await {
        tracing::warn!(error = %error, "CIBA poll lock release failed");
    }
    response
}

#[allow(clippy::too_many_arguments)]
async fn poll_locked(
    state: Arc<ServerState>,
    realm: Realm,
    client: Client,
    mut req_data: CibaAuthReqData,
    cache_key: String,
    original: Vec<u8>,
    dpop_jkt: Option<String>,
    ip: IpAddr,
) -> Response {
    let realm_id = realm.id.clone();
    let now = chrono::Utc::now();
    if req_data.last_polled_at.is_some_and(|last| {
        now.signed_duration_since(last).num_seconds() < req_data.poll_interval_secs as i64
    }) {
        req_data.poll_interval_secs = req_data.poll_interval_secs.saturating_add(5);
        let bytes = match serde_json::to_vec(&req_data) {
            Ok(bytes) => bytes,
            Err(error) => return temporary(&IssuerdError::ServerError(error.to_string())),
        };
        return match state.cache.compare_and_swap(&cache_key, Some(original), bytes).await {
            Ok(true) => error(StatusCode::BAD_REQUEST, "slow_down"),
            Ok(false) => error(StatusCode::BAD_REQUEST, "invalid_grant"),
            Err(error) => temporary(&error),
        };
    }
    req_data.last_polled_at = Some(now);
    let bytes = match serde_json::to_vec(&req_data) {
        Ok(bytes) => bytes,
        Err(error) => return temporary(&IssuerdError::ServerError(error.to_string())),
    };
    let current = bytes.clone();
    match state.cache.compare_and_swap(&cache_key, Some(original.clone()), bytes).await {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
        Err(error) => return temporary(&error),
    }
    if req_data.denied {
        return error(StatusCode::BAD_REQUEST, "access_denied");
    }
    if !req_data.authorized {
        return error(StatusCode::BAD_REQUEST, "authorization_pending");
    }
    let Some(user_id) = req_data.user_id.as_deref().and_then(|id| UserId::new(id).ok()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let user = match state.storage.get_user(&realm_id, &user_id).await {
        Ok(Some(user)) if user.enabled => user,
        Ok(_) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
        Err(error) => return temporary(&error),
    };
    if req_data.operation.is_some() {
        return issue(state, realm, client, user, req_data, dpop_jkt, ip).await;
    }
    match state.cache.compare_and_delete(&cache_key, current).await {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
        Err(error) => return temporary(&error),
    }
    issue_legacy(state, realm, client, user, req_data, dpop_jkt, ip).await
}

async fn issue_legacy(
    state: Arc<ServerState>,
    realm: Realm,
    client: Client,
    user: User,
    req_data: CibaAuthReqData,
    dpop_jkt: Option<String>,
    ip: IpAddr,
) -> Response {
    let realm_id = realm.id.clone();
    let session_id = SessionId::new(issuerd_core::utils::generate_id()).expect("generated id");
    let scope = req_data.scope.clone();
    let offline = scope.iter().any(|scope| scope == OFFLINE_ACCESS_SCOPE);
    let auth_time = req_data
        .approval_auth_time
        .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
        .unwrap_or_else(chrono::Utc::now);
    let session = UserSession {
        id: session_id.clone(),
        realm_id: realm_id.clone(),
        user_id: user.id.clone(),
        login_username: user.username.clone(),
        auth_method: AuthMethod::Ciba,
        remember_me: false,
        offline,
        ip_address: ip,
        started: chrono::Utc::now(),
        last_session_refresh: chrono::Utc::now(),
        auth_time,
        impersonator: None,
        clients: vec![ClientSession {
            id: ClientSessionId::new(issuerd_core::utils::generate_id()).expect("generated id"),
            client_id: client.id.clone(),
            session_id: session_id.clone(),
            redirect_uri: None,
            state: None,
            auth_method: AuthMethod::Ciba,
            timestamp: chrono::Utc::now(),
        }],
    };
    if let Err(response) = persist_session(&state, &realm_id, &session, false).await {
        return response;
    }
    let overlay = crate::claims::build_claims_overlay(
        &state,
        &realm_id,
        Some(&client),
        &user,
        &scope,
        ClaimTarget::AccessToken,
    )
    .await
    .unwrap_or_default();
    let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt.as_deref());
    let access_token = match state
        .token_manager
        .issue_access_token_with_roles(
            &user,
            &client,
            &realm,
            &scope,
            &session_id,
            None,
            None,
            overlay,
        )
        .await
    {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(realm = %realm_id, error = %error, "legacy CIBA token issuance failed");
            return temporary(&error);
        }
    };
    let refresh_token = match state
        .token_manager
        .issue_refresh_token_with_resource(
            &user,
            &client,
            &realm,
            &session_id,
            &scope,
            offline,
            dpop_jkt.as_deref(),
            None,
            None,
        )
        .await
    {
        Ok(token) => Some(token.token),
        Err(error) => {
            tracing::warn!(realm = %realm_id, error = %error, "legacy CIBA refresh issuance failed");
            None
        }
    };
    let id_token = if scope.iter().any(|scope| scope == "openid") {
        match state
            .token_manager
            .issue_id_token(
                &user,
                &client,
                &realm,
                None,
                auth_time,
                &session_id,
                Some(&access_token),
                None,
                None,
                None,
            )
            .await
        {
            Ok(token) => Some(token.token),
            Err(error) => {
                tracing::warn!(realm = %realm_id, error = %error, "legacy CIBA ID-token issuance failed");
                None
            }
        }
    } else {
        None
    };
    let mut details = std::collections::HashMap::new();
    details.insert("method".into(), "ciba".into());
    crate::routes::oidc::emit_oidc_event(
        &state,
        &realm_id,
        EventType::Login,
        &ip,
        Some(client.id.clone()),
        Some(user.id.clone()),
        Some(session_id),
        None,
        details,
    )
    .await;
    token_response(TokenResponse {
        access_token: access_token.token,
        token_type: crate::dpop::token_type(dpop_jkt.is_some()),
        expires_in: realm.access_token_lifespan.get(),
        refresh_token,
        id_token,
        scope: Some(scope.join(" ")),
        issued_token_type: None,
        authorization_details: None,
    })
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({"error": code}))).into_response()
}

fn temporary(error: &IssuerdError) -> Response {
    tracing::warn!(error = %error, "operation-bound CIBA state operation failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::RETRY_AFTER, "5")],
        Json(error_response(&IssuerdError::TemporarilyUnavailable)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{
        extract::{RawQuery, State},
        http::{header, HeaderMap},
    };
    use http_body_util::BodyExt;
    use issuerd_mcp::{
        executor::{McpStrictCoordination, McpToolExecutor},
        McpAuthContext, McpRateLimiter,
    };
    use issuerd_protocol::token::GrantType;
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        ciba_approval,
        config::ServerConfig,
        middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
        routes::oidc::{enforce_token_validity, session_cookie_name},
    };

    struct Fixture {
        state: Arc<ServerState>,
        realm: Realm,
        client: Client,
        admin: User,
        executor: McpToolExecutor,
        resource: String,
    }

    async fn fixture() -> Fixture {
        let mut config = ServerConfig::with_test_admin();
        config.mcp.enabled = true;
        config.mcp.step_up.enabled = true;
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let realm = state.storage.get_realm_by_name("master").await.unwrap().unwrap();
        let client = Client {
            id: ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("mcp-confidential").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("test-secret".into()),
            redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::parse("mcp:read mcp:write mcp:step_up"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: Default::default(),
        };
        state.storage.create_client(&realm.id, &client).await.unwrap();
        let admin = state.storage.get_user_by_username(&realm.id, "admin").await.unwrap().unwrap();
        let resource = realm_mcp_resource(&state.config.issuer_url, "master");
        let executor = McpToolExecutor::new(
            state.storage.clone(),
            McpRateLimiter::new(state.cache.clone(), 1_000),
        )
        .with_application_service(Arc::new(crate::mcp_service::ServerMcpApplicationService::new(
            crate::mcp_service::admin_state(&state),
            state.clone(),
        )))
        .with_step_up(true);
        Fixture {
            state,
            realm,
            client,
            admin,
            executor,
            resource,
        }
    }

    fn user(realm: &Realm, username: &str) -> User {
        let now = chrono::Utc::now();
        User {
            id: UserId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            username: Username::new(username).unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    fn auth(fixture: &Fixture, scope: &str, jkt: &str) -> McpAuthContext {
        McpAuthContext {
            realm_id: fixture.realm.id.clone(),
            realm_name: fixture.realm.name.clone(),
            user_id: fixture.admin.id.clone(),
            azp: fixture.client.client_id.clone(),
            claims: AccessTokenClaims {
                jti: JwtId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
                iss: Issuer::new(format!("{}/realms/master", fixture.state.config.issuer_url))
                    .unwrap(),
                sub: fixture.admin.id.clone(),
                aud: Audience::new(fixture.client.client_id.as_str()).unwrap(),
                exp: chrono::Utc::now().timestamp() + 300,
                iat: chrono::Utc::now().timestamp(),
                nbf: chrono::Utc::now().timestamp(),
                scope: Scope::parse(scope),
                typ: JwtType::Bearer,
                azp: Some(fixture.client.client_id.to_string()),
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: [
                        "manage-users",
                        "manage-realm",
                        "manage-clients",
                        "view-realm",
                        "view-users",
                        "view-clients",
                    ]
                    .into_iter()
                    .map(|name| RoleName::new(name).unwrap())
                    .collect(),
                }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: Some(ConfirmationClaim { jkt: jkt.into() }),
                authorization_details: None,
                resource: Some(fixture.resource.clone()),
            },
        }
    }

    async fn response_json(response: Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response was not JSON: {bytes:?}: {error}"))
    }

    async fn response_text(response: Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn sso_headers(fixture: &Fixture) -> HeaderMap {
        let now = chrono::Utc::now();
        let session_id = SessionId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let session = UserSession {
            id: session_id.clone(),
            realm_id: fixture.realm.id.clone(),
            user_id: fixture.admin.id.clone(),
            login_username: fixture.admin.username.clone(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: Vec::new(),
        };
        fixture
            .state
            .storage
            .create_user_session(&fixture.realm.id, &session)
            .await
            .unwrap();
        let client = fixture
            .state
            .storage
            .get_client_by_client_id(
                &fixture.realm.id,
                &ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let token = fixture
            .state
            .token_manager
            .issue_sso_session_token(
                &fixture.admin,
                &client,
                &fixture.realm,
                &["openid".into()],
                &session_id,
                None,
                None,
            )
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", session_cookie_name(&fixture.realm.id), token.token)
                .parse()
                .unwrap(),
        );
        headers
    }

    fn approval_form(approval_id: &str, proof: &str, action: &str) -> String {
        format!("approval_id={approval_id}&csrf_proof={proof}&action={action}")
    }

    fn proof_from_html(html: &str) -> &str {
        html.split("name=\"csrf_proof\" value=\"")
            .nth(1)
            .and_then(|tail| tail.split('"').next())
            .expect("approval form has a session-bound CSRF proof")
    }

    async fn pending_operation(fixture: &Fixture, target: &User) -> (PendingOperation, String) {
        let permit = fixture
            .executor
            .preflight("users_delete", auth(fixture, "openid mcp:write", "origin-jkt"), 100)
            .await
            .unwrap();
        let arguments = json!({"id": target.id.to_string(), "confirmation": "DELETE"})
            .as_object()
            .cloned();
        match fixture
            .executor
            .coordinate_strict(
                &permit,
                arguments,
                fixture.resource.clone(),
                Some("origin-jkt".into()),
                chrono::Utc::now().timestamp(),
            )
            .await
            .unwrap()
        {
            McpStrictCoordination::Pending(operation) => {
                (*operation, permit.auth.claims.jti.to_string())
            }
            _ => panic!("ordinary DPoP call must create a pending operation"),
        }
    }

    async fn begin_ciba(fixture: &Fixture, pending: &PendingOperation) -> Response {
        initiate(
            fixture.state.clone(),
            fixture.realm.clone(),
            fixture.client.clone(),
            CibaRequest {
                scope: Scope::parse("openid mcp:step_up"),
                client_notification_token: None,
                acr_values: Vec::new(),
                login_hint_token: None,
                id_token_hint: None,
                login_hint: Some("admin".into()),
                binding_message: Some(pending.binding_message.clone()),
                user_code: None,
                requested_expiry: None,
                operation_id: Some(pending.operation_id.clone()),
                resource: Some(fixture.resource.clone()),
            },
            "127.0.0.1".parse().unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn strict_ciba_approval_issues_one_exact_operation_and_reconciles_replay() {
        let fixture = fixture().await;
        let target = user(&fixture.realm, "strict-delete-target");
        fixture.state.storage.create_user(&fixture.realm.id, &target).await.unwrap();
        let (pending, _) = pending_operation(&fixture, &target).await;
        let initiation = begin_ciba(&fixture, &pending).await;
        let status = initiation.status();
        let initiation = response_json(initiation).await;
        assert_eq!(status, StatusCode::OK, "{initiation}");
        let auth_req_id = initiation["auth_req_id"].as_str().unwrap().to_string();
        let approval_url = initiation["approval_url"].as_str().unwrap();
        assert!(!approval_url.contains(&auth_req_id));
        let approval_id = approval_url.split("approval_id=").nth(1).unwrap().to_string();

        let no_session = ciba_approval::get_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            HeaderMap::new(),
            RawQuery(Some(format!("approval_id={approval_id}"))),
        )
        .await;
        assert_eq!(no_session.status(), StatusCode::SEE_OTHER);
        let headers = sso_headers(&fixture).await;
        let approval = ciba_approval::get_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            headers.clone(),
            RawQuery(Some(format!("approval_id={approval_id}"))),
        )
        .await;
        assert_eq!(approval.status(), StatusCode::OK);
        let html = response_text(approval).await;
        assert!(html.contains("users_delete"));
        assert!(html.contains(&target.id.to_string()));
        let proof = proof_from_html(&html).to_string();
        let wrong_csrf = ciba_approval::post_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers.clone(),
            approval_form(&approval_id, "wrong", "approve"),
        )
        .await;
        assert_eq!(wrong_csrf.status(), StatusCode::FORBIDDEN);
        let approved = ciba_approval::post_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers.clone(),
            approval_form(&approval_id, &proof, "approve"),
        )
        .await;
        assert_eq!(approved.status(), StatusCode::OK);
        let replay_decision = ciba_approval::post_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            approval_form(&approval_id, &proof, "approve"),
        )
        .await;
        assert_eq!(replay_decision.status(), StatusCode::NOT_FOUND);

        let request = issuerd_protocol::token::TokenRequest::parse(&HashMap::from([
            ("grant_type".into(), GrantType::Ciba.as_str().into()),
            ("auth_req_id".into(), auth_req_id.clone()),
            ("resource".into(), fixture.resource.clone()),
        ]))
        .unwrap();
        let issued = poll(
            fixture.state.clone(),
            fixture.realm.clone(),
            fixture.client.clone(),
            request,
            Some("origin-jkt".into()),
            "127.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(issued.status(), StatusCode::OK);
        let issued = response_json(issued).await;
        assert!(issued["refresh_token"].is_null());
        assert_eq!(issued["scope"], "openid mcp:step_up");
        assert_eq!(issued["token_type"], "DPoP");
        let token = issued["access_token"].as_str().unwrap();
        let claims = fixture.state.token_service.validate_access_token(token).unwrap().claims;
        assert_eq!(claims.cnf.as_ref().unwrap().jkt, "origin-jkt");
        assert!(claims.aud.contains(&fixture.resource));
        assert_eq!(claims.resource.as_deref(), Some(fixture.resource.as_str()));
        assert_eq!(claims.jti.to_string(), format!("mcp-ciba-{auth_req_id}"));
        assert!(enforce_token_validity(&fixture.state, token, &claims).await.is_err());

        let final_auth = McpAuthContext {
            realm_id: fixture.realm.id.clone(),
            realm_name: fixture.realm.name.clone(),
            user_id: fixture.admin.id.clone(),
            azp: fixture.client.client_id.clone(),
            claims: claims.clone(),
        };
        assert!(fixture.executor.preflight("realm_get", final_auth.clone(), 200).await.is_err());
        let permit = fixture
            .executor
            .preflight("users_delete", final_auth.clone(), 200)
            .await
            .unwrap();
        let arguments = json!({"id": target.id.to_string(), "confirmation": "DELETE"})
            .as_object()
            .cloned();
        let wrong_target = user(&fixture.realm, "wrong-target");
        fixture
            .state
            .storage
            .create_user(&fixture.realm.id, &wrong_target)
            .await
            .unwrap();
        let wrong_arguments = json!({"id": wrong_target.id.to_string(), "confirmation": "DELETE"})
            .as_object()
            .cloned();
        assert!(matches!(
            fixture
                .executor
                .coordinate_strict(
                    &permit,
                    wrong_arguments,
                    fixture.resource.clone(),
                    Some("origin-jkt".into()),
                    chrono::Utc::now().timestamp(),
                )
                .await,
            Err(issuerd_mcp::McpError::OperationBindingMismatch)
        ));
        let first = fixture
            .executor
            .coordinate_strict(
                &permit,
                arguments.clone(),
                fixture.resource.clone(),
                Some("origin-jkt".into()),
                chrono::Utc::now().timestamp(),
            )
            .await
            .unwrap();
        let second = fixture
            .executor
            .coordinate_strict(
                &permit,
                arguments,
                fixture.resource.clone(),
                Some("origin-jkt".into()),
                chrono::Utc::now().timestamp(),
            )
            .await
            .unwrap();
        let (McpStrictCoordination::Complete(first), McpStrictCoordination::Complete(second)) =
            (first, second)
        else {
            panic!("approved operation must execute and reconcile")
        };
        assert_eq!(first, second);
        assert_eq!(first["status"], "completed");
        assert!(fixture
            .state
            .storage
            .get_user(&fixture.realm.id, &target.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn changed_preconditions_fail_definitely_without_mutation_or_reuse() {
        let fixture = fixture().await;
        let target = user(&fixture.realm, "changed-precondition-target");
        fixture.state.storage.create_user(&fixture.realm.id, &target).await.unwrap();
        let (pending, _) = pending_operation(&fixture, &target).await;
        let initiation = begin_ciba(&fixture, &pending).await;
        let initiation = response_json(initiation).await;
        let auth_req_id = initiation["auth_req_id"].as_str().unwrap().to_string();
        let approval_id = initiation["approval_url"]
            .as_str()
            .unwrap()
            .split("approval_id=")
            .nth(1)
            .unwrap()
            .to_string();
        let headers = sso_headers(&fixture).await;
        let html = response_text(
            ciba_approval::get_handler(
                State(fixture.state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".into()))),
                headers.clone(),
                RawQuery(Some(format!("approval_id={approval_id}"))),
            )
            .await,
        )
        .await;
        let proof = proof_from_html(&html);
        let approved = ciba_approval::post_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            approval_form(&approval_id, proof, "approve"),
        )
        .await;
        assert_eq!(approved.status(), StatusCode::OK);
        let request = issuerd_protocol::token::TokenRequest::parse(&HashMap::from([
            ("grant_type".into(), GrantType::Ciba.as_str().into()),
            ("auth_req_id".into(), auth_req_id.clone()),
            ("resource".into(), fixture.resource.clone()),
        ]))
        .unwrap();
        let issued = poll(
            fixture.state.clone(),
            fixture.realm.clone(),
            fixture.client.clone(),
            request,
            Some("origin-jkt".into()),
            "127.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(issued.status(), StatusCode::OK);
        let claims = fixture
            .state
            .token_service
            .validate_access_token(response_json(issued).await["access_token"].as_str().unwrap())
            .unwrap()
            .claims;
        let mut changed = fixture
            .state
            .storage
            .get_user(&fixture.realm.id, &target.id)
            .await
            .unwrap()
            .unwrap();
        changed.first_name = Some(DisplayName::new("Changed").unwrap());
        fixture.state.storage.update_user(&fixture.realm.id, &changed).await.unwrap();
        let final_auth = McpAuthContext {
            realm_id: fixture.realm.id.clone(),
            realm_name: fixture.realm.name.clone(),
            user_id: fixture.admin.id.clone(),
            azp: fixture.client.client_id.clone(),
            claims: claims.clone(),
        };
        let permit = fixture
            .executor
            .preflight("users_delete", final_auth.clone(), chrono::Utc::now().timestamp() as u64)
            .await
            .unwrap();
        let arguments = json!({"id": target.id.to_string(), "confirmation": "DELETE"})
            .as_object()
            .cloned();
        for _ in 0..2 {
            assert!(matches!(
                fixture
                    .executor
                    .coordinate_strict(
                        &permit,
                        arguments.clone(),
                        fixture.resource.clone(),
                        Some("origin-jkt".into()),
                        chrono::Utc::now().timestamp(),
                    )
                    .await,
                Err(issuerd_mcp::McpError::Conflict(_))
            ));
        }
        assert!(fixture
            .state
            .storage
            .get_user(&fixture.realm.id, &target.id)
            .await
            .unwrap()
            .is_some());
        let grant =
            fixture.state.storage.get_mcp_step_up_grant(&claims.jti).await.unwrap().unwrap();
        assert_eq!(grant.status, McpStepUpExecutionStatus::FailedDefinite);
    }

    #[tokio::test]
    async fn denied_operation_cannot_issue_a_grant_or_delete_target() {
        let fixture = fixture().await;
        let target = user(&fixture.realm, "strict-denied-target");
        fixture.state.storage.create_user(&fixture.realm.id, &target).await.unwrap();
        let (pending, _) = pending_operation(&fixture, &target).await;
        let initiation = begin_ciba(&fixture, &pending).await;
        let initiation = response_json(initiation).await;
        assert!(initiation["auth_req_id"].is_string(), "{initiation}");
        let auth_req_id = initiation["auth_req_id"].as_str().unwrap().to_string();
        let approval_id = initiation["approval_url"]
            .as_str()
            .unwrap()
            .split("approval_id=")
            .nth(1)
            .unwrap()
            .to_string();
        let headers = sso_headers(&fixture).await;
        let html = response_text(
            ciba_approval::get_handler(
                State(fixture.state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".into()))),
                headers.clone(),
                RawQuery(Some(format!("approval_id={approval_id}"))),
            )
            .await,
        )
        .await;
        let proof = proof_from_html(&html);
        let denied = ciba_approval::post_handler(
            State(fixture.state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".into()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            approval_form(&approval_id, proof, "deny"),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::OK);
        let request = issuerd_protocol::token::TokenRequest::parse(&HashMap::from([
            ("grant_type".into(), GrantType::Ciba.as_str().into()),
            ("auth_req_id".into(), auth_req_id.clone()),
            ("resource".into(), fixture.resource.clone()),
        ]))
        .unwrap();
        let poll = poll(
            fixture.state.clone(),
            fixture.realm.clone(),
            fixture.client.clone(),
            request,
            Some("origin-jkt".into()),
            "127.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(poll.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(poll).await["error"], "access_denied");
        assert!(fixture
            .state
            .storage
            .get_mcp_step_up_grant(&JwtId::new(format!("mcp-ciba-{auth_req_id}")).unwrap())
            .await
            .unwrap()
            .is_none());
        assert!(fixture
            .state
            .storage
            .get_user(&fixture.realm.id, &target.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn unsupported_acr_is_rejected_without_claiming_the_operation() {
        let fixture = fixture().await;
        let target = user(&fixture.realm, "unsupported-acr-target");
        fixture.state.storage.create_user(&fixture.realm.id, &target).await.unwrap();
        let (pending, _) = pending_operation(&fixture, &target).await;
        let response = initiate(
            fixture.state.clone(),
            fixture.realm.clone(),
            fixture.client.clone(),
            CibaRequest {
                scope: Scope::parse("openid mcp:step_up"),
                client_notification_token: None,
                acr_values: vec!["1".into()],
                login_hint_token: None,
                id_token_hint: None,
                login_hint: Some("admin".into()),
                binding_message: Some(pending.binding_message.clone()),
                user_code: None,
                requested_expiry: None,
                operation_id: Some(pending.operation_id.clone()),
                resource: Some(fixture.resource.clone()),
            },
            "127.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await["error"], "invalid_request");
        assert!(fixture
            .state
            .cache
            .get(&pending_operation_key(&fixture.realm.id, &pending.operation_id))
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn persisted_ciba_ids_are_stable_distinct_uuids() {
        let realm = RealmId::new("10000000-0000-4000-8000-000000000001").unwrap();
        let session = persisted_uuid(&realm, "request-id", "session");
        let client = persisted_uuid(&realm, "request-id", "client");
        assert_eq!(session, persisted_uuid(&realm, "request-id", "session"));
        assert_ne!(session, client);
        assert!(uuid::Uuid::parse_str(&session).is_ok());
        assert!(uuid::Uuid::parse_str(&client).is_ok());
    }
}
