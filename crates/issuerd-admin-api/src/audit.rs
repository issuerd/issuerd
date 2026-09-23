// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin audit-event emission with per-realm events configuration gating.

use chrono::Utc;
use issuerd_core::{
    AdminEvent, ClientId, EventId, IssuerdError, OperationType, RealmId, ResourceType,
};
use std::sync::Arc;
use tracing::warn;

use crate::{auth::AdminAuth, state::AdminApiState};

/// Gate an admin event on the realm's events configuration.
///
/// Returns `false` when the realm has admin-event recording disabled, and
/// clears `representation` unless the realm opted into storing request
/// bodies. When the realm's config is unknown (the row is gone or cannot be
/// loaded) the event is still recorded — the mutation it describes has
/// already happened and the audit trail must not depend on a transient
/// lookup — but the representation is stripped: a realm whose preferences
/// are unknown has not opted into storing request bodies (fail-closed on
/// the secrecy control).
async fn apply_realm_event_config(
    state: &AdminApiState,
    realm_id: &RealmId,
    representation: &mut Option<String>,
) -> bool {
    let realm = match state.storage.get_realm(realm_id).await {
        Ok(Some(realm)) => realm,
        Ok(None) => {
            *representation = None;
            return true;
        }
        Err(e) => {
            warn!(realm = %realm_id, error = %e,
                "realm events config load failed; admin event recorded without representation (fail-closed)");
            *representation = None;
            return true;
        }
    };
    if !realm.admin_events_enabled {
        return false;
    }
    if !realm.include_representations {
        *representation = None;
    }
    true
}

/// Derive the issuing realm's id for `auth_realm_id` attribution.
///
/// The token's `iss` is `{issuer_url}/realms/{realm_name}` — the trailing
/// segment is the realm name (the same extraction the auth middleware's realm
/// binding applies), resolved to the realm id for persistence (the Postgres
/// column is UUID). Realm-less issuers are rejected by that middleware, so a
/// `None` here is defensive: better a missing attribution than an event that
/// fails the UUID conversion on insert.
async fn issuing_realm_id(state: &AdminApiState, auth: &AdminAuth) -> Option<RealmId> {
    let iss = auth.claims.iss.as_str();
    let name = issuerd_core::typestate::extract_realm_from_issuer(iss).unwrap_or(iss);
    match state.storage.get_realm_by_name(name).await {
        Ok(realm) => realm.map(|r| r.id),
        Err(e) => {
            warn!(issuer = %iss, error = %e,
                "issuing realm lookup failed; admin event attribution dropped");
            None
        }
    }
}

pub async fn emit_admin_event(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm_id: &RealmId,
    operation_type: OperationType,
    resource_type: ResourceType,
    resource_path: &str,
    mut representation: Option<String>,
) {
    if !apply_realm_event_config(state, realm_id, &mut representation).await {
        return;
    }
    let event = AdminEvent {
        id: EventId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        auth_realm_id: issuing_realm_id(state, auth).await,
        auth_client_id: auth.claims.azp.as_ref().map(|c| ClientId::new(c.clone()).unwrap()),
        auth_user_id: Some(auth.claims.sub.clone()),
        operation_type,
        resource_type,
        resource_path: resource_path.to_string(),
        representation,
        error: None,
        event_time: Utc::now(),
    };
    // Persistence stays non-fatal — the mutation the event describes has
    // already happened — but a failure must be visible in the logs.
    if let Err(e) = state.storage.save_admin_event(&event).await {
        warn!(realm = %realm_id, resource_path = %resource_path, error = %e,
            "admin event persistence failed");
    }
}

pub async fn emit_admin_event_error(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm_id: &RealmId,
    resource_type: ResourceType,
    resource_path: &str,
    error: &IssuerdError,
) {
    let mut representation = None;
    if !apply_realm_event_config(state, realm_id, &mut representation).await {
        return;
    }
    let event = AdminEvent {
        id: EventId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        auth_realm_id: issuing_realm_id(state, auth).await,
        auth_client_id: auth.claims.azp.as_ref().map(|c| ClientId::new(c.clone()).unwrap()),
        auth_user_id: Some(auth.claims.sub.clone()),
        operation_type: OperationType::Action,
        resource_type,
        resource_path: resource_path.to_string(),
        representation: None,
        error: Some(error.to_string()),
        event_time: Utc::now(),
    };
    // Non-fatal, but logged (see emit_admin_event).
    if let Err(e) = state.storage.save_admin_event(&event).await {
        warn!(realm = %realm_id, resource_path = %resource_path, error = %e,
            "admin event persistence failed");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::test_state;
    use issuerd_core::{
        AccessTokenClaims, AdminEventQuery, Audience, Issuer, IssuerdError, JwtId, JwtType,
        RealmAccess, ResourceType, UserId,
    };

    fn admin_auth_with_issuer(iss: &str) -> AdminAuth {
        AdminAuth {
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new(iss).unwrap(),
                sub: UserId::new("admin").unwrap(),
                aud: Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: Some("admin-cli".to_string()),
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
                }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        }
    }

    fn admin_auth() -> AdminAuth {
        admin_auth_with_issuer("https://iss")
    }

    #[tokio::test]
    async fn issuing_realm_id_resolves_name_from_issuer_url() {
        let state = test_state(vec![]);
        let auth = admin_auth_with_issuer("http://localhost:8080/realms/master");
        // The segment is the realm NAME; the id is resolved from storage.
        assert_eq!(issuing_realm_id(&state, &auth).await, Some(RealmId::new("master").unwrap()));
    }

    #[tokio::test]
    async fn issuing_realm_id_without_resolvable_realm_is_none() {
        // `https://iss` carries no `/realms/` segment, and no realm is named
        // after it: attribution is dropped rather than persisted as a raw
        // string that would fail the Postgres UUID conversion.
        let state = test_state(vec![]);
        let auth = admin_auth();
        assert_eq!(issuing_realm_id(&state, &auth).await, None);
    }

    /// Flip the master realm's admin-event recording flags.
    async fn configure_admin_events(
        state: &Arc<AdminApiState>,
        enabled: bool,
        include_representations: bool,
    ) {
        let realm_id = RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.admin_events_enabled = enabled;
        realm.include_representations = include_representations;
        state.storage.update_realm(&realm).await.unwrap();
    }

    async fn recorded_events(state: &Arc<AdminApiState>, realm_id: &RealmId) -> Vec<AdminEvent> {
        state
            .storage
            .query_admin_events(
                realm_id,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn emit_admin_event_persists_event() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        configure_admin_events(&state, true, true).await;
        let auth = admin_auth();
        let realm_id = RealmId::new("master").unwrap();

        emit_admin_event(
            &state,
            &auth,
            &realm_id,
            OperationType::Create,
            ResourceType::Realm,
            "realms/master",
            Some("{\"name\":\"master\"}".to_string()),
        )
        .await;

        let events = recorded_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::Create);
        assert_eq!(events[0].resource_type, ResourceType::Realm);
        assert_eq!(events[0].resource_path, "realms/master");
        assert_eq!(events[0].representation, Some("{\"name\":\"master\"}".to_string()));
        assert_eq!(events[0].error, None);
        assert_eq!(events[0].realm_id, realm_id);
        // `https://iss` has no resolvable realm: attribution is None.
        assert_eq!(events[0].auth_realm_id, None);
    }

    #[tokio::test]
    async fn emit_admin_event_resolves_issuer_realm_name_to_id() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        configure_admin_events(&state, true, true).await;
        let auth = admin_auth_with_issuer("http://localhost:8080/realms/master");
        let realm_id = RealmId::new("master").unwrap();

        emit_admin_event(
            &state,
            &auth,
            &realm_id,
            OperationType::Create,
            ResourceType::Realm,
            "realms/master",
            None,
        )
        .await;

        let events = recorded_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        // The issuer segment is the realm NAME; the stored attribution is the
        // resolved realm id — PostgresStorage converts it via `to_uuid()`,
        // which a URL or name cannot survive.
        assert_eq!(events[0].auth_realm_id, Some(RealmId::new("master").unwrap()));
    }

    #[tokio::test]
    async fn emit_admin_event_error_persists_error() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        configure_admin_events(&state, true, true).await;
        let auth = admin_auth();
        let realm_id = RealmId::new("master").unwrap();

        emit_admin_event_error(
            &state,
            &auth,
            &realm_id,
            ResourceType::User,
            "users/alice",
            &IssuerdError::NotFound,
        )
        .await;

        let events = recorded_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::Action);
        assert_eq!(events[0].resource_type, ResourceType::User);
        assert_eq!(events[0].resource_path, "users/alice");
        assert_eq!(events[0].error, Some(IssuerdError::NotFound.to_string()));
        assert_eq!(events[0].representation, None);
    }

    #[tokio::test]
    async fn emit_admin_event_skipped_when_recording_disabled() {
        // Issuerd defaults to admin_events_enabled=true; disable explicitly
        // to exercise the gate.
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        configure_admin_events(&state, false, false).await;
        let auth = admin_auth();
        let realm_id = RealmId::new("master").unwrap();

        emit_admin_event(
            &state,
            &auth,
            &realm_id,
            OperationType::Create,
            ResourceType::Realm,
            "realms/master",
            Some("{}".to_string()),
        )
        .await;
        emit_admin_event_error(
            &state,
            &auth,
            &realm_id,
            ResourceType::User,
            "users/alice",
            &IssuerdError::NotFound,
        )
        .await;

        assert!(recorded_events(&state, &realm_id).await.is_empty());
    }

    #[tokio::test]
    async fn emit_admin_event_drops_representation_when_details_disabled() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        configure_admin_events(&state, true, false).await;
        let auth = admin_auth();
        let realm_id = RealmId::new("master").unwrap();

        emit_admin_event(
            &state,
            &auth,
            &realm_id,
            OperationType::Update,
            ResourceType::Realm,
            "realms/master",
            Some("{\"name\":\"master\"}".to_string()),
        )
        .await;

        let events = recorded_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].representation, None);
    }

    #[tokio::test]
    async fn emit_admin_event_strips_representation_when_realm_config_unknown() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let auth = admin_auth();
        let realm_id = RealmId::new("no-such-realm").unwrap();

        emit_admin_event(
            &state,
            &auth,
            &realm_id,
            OperationType::Delete,
            ResourceType::Realm,
            "realms/no-such-realm",
            Some("{}".to_string()),
        )
        .await;

        let events = recorded_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        // The audit event survives, but a realm whose preferences are unknown
        // has not opted into storing request bodies (fail-closed).
        assert_eq!(events[0].representation, None);
    }

    #[tokio::test]
    async fn emit_admin_event_strips_representation_when_realm_lookup_errors() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_realm()
            .returning(|_| Err(IssuerdError::ServerError("db down".into())));
        mock.expect_get_realm_by_name().returning(|_| Ok(None));
        mock.expect_save_admin_event()
            .times(1)
            .withf(|event| event.representation.is_none())
            .returning(|_| Ok(()));
        let state = crate::test_utils::tests::test_state_with_storage(Arc::new(mock), vec![]);
        let auth = admin_auth();
        let realm_id = RealmId::new("master").unwrap();

        emit_admin_event(
            &state,
            &auth,
            &realm_id,
            OperationType::Update,
            ResourceType::Realm,
            "realms/master",
            Some("{\"name\":\"master\"}".to_string()),
        )
        .await;
        // `times(1)` + `withf` prove the event was recorded with the
        // representation stripped despite the realm lookup failure.
    }
}
