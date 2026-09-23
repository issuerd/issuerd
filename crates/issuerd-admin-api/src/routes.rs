// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin API router assembly: endpoint paths wired to their handlers.

use axum::{middleware, routing::*, Json, Router};
use std::sync::Arc;
use utoipa::OpenApi;

use crate::{
    attack_detection, client_installation, client_roles, client_scopes, clients, composites,
    credentials, enums, events, federation, flows, groups, idp, import_export, initial_access,
    keys, realms, roles, scope_mappings, sessions, user_actions, users,
};
use crate::{auth::admin_auth_middleware, state::AdminApiState};

/// Build the inner admin API router (paths like `/realms`, `/realms/{realm}`, …).
///
/// The returned router is a plain `Router` and implements [`tower::Service`].
/// It is intended to be mounted under `/admin` by the caller via `nest_service`.
pub fn admin_routes(state: Arc<AdminApiState>) -> Router {
    Router::new()
        .route("/realms", get(realms::list_realms).post(realms::create_realm))
        .route("/realms/count", get(realms::count_realms))
        .route(
            "/realms/{realm}",
            get(realms::get_realm).put(realms::update_realm).delete(realms::delete_realm),
        )
        .route("/realms/{realm}/users", get(users::list_users).post(users::create_user))
        .route("/realms/{realm}/users/count", get(users::count_users))
        .route(
            "/realms/{realm}/users/{id}",
            get(users::get_user).put(users::update_user).delete(users::delete_user),
        )
        .route("/realms/{realm}/users/{id}/sessions", get(users::get_user_sessions))
        .route("/realms/{realm}/users/{id}/reset-password", put(users::reset_password))
        .route(
            "/realms/{realm}/users/{id}/credentials",
            get(credentials::list_user_credentials),
        )
        .route(
            "/realms/{realm}/users/{id}/credentials/{credential_id}",
            put(credentials::update_credential_label).delete(credentials::delete_credential),
        )
        .route(
            "/realms/{realm}/users/{id}/credentials/{credential_id}/moveAfter/{new_previous_credential_id}",
            put(credentials::move_credential_after),
        )
        .route(
            "/realms/{realm}/users/{id}/execute-actions-email",
            put(user_actions::execute_actions_email),
        )
        .route(
            "/realms/{realm}/users/{id}/impersonation",
            post(user_actions::impersonate_user),
        )
        .route(
            "/realms/{realm}/attack-detection/brute-force/users",
            get(attack_detection::list_locked_users),
        )
        .route(
            "/realms/{realm}/attack-detection/brute-force/users/{id}",
            get(attack_detection::get_user_brute_force_status)
                .delete(attack_detection::clear_user_brute_force_state),
        )
        .route("/realms/{realm}/test-smtp-connection", post(realms::test_smtp_connection))
        .route("/realms/{realm}/partialImport", post(import_export::partial_import))
        .route("/realms/{realm}/export", post(import_export::export_realm))
        .route("/realms/{realm}/push-revocation", post(import_export::push_revocation))
        .route("/realms/{realm}/users/{id}/role-mappings", get(users::get_user_role_mappings))
        .route(
            "/realms/{realm}/users/{id}/role-mappings/realm",
            get(users::get_user_realm_roles)
                .post(users::add_user_realm_roles)
                .delete(users::remove_user_realm_roles),
        )
        .route(
            "/realms/{realm}/users/{id}/role-mappings/realm/available",
            get(users::get_available_user_realm_roles),
        )
        .route(
            "/realms/{realm}/users/{id}/role-mappings/realm/composite",
            get(users::get_effective_user_realm_roles),
        )
        .route(
            "/realms/{realm}/users/{id}/role-mappings/clients/{client_id}",
            get(users::get_user_client_roles)
                .post(users::add_user_client_roles)
                .delete(users::remove_user_client_roles),
        )
        .route(
            "/realms/{realm}/users/{id}/role-mappings/clients/{client_id}/available",
            get(users::get_available_user_client_roles),
        )
        .route(
            "/realms/{realm}/users/{id}/role-mappings/clients/{client_id}/composite",
            get(users::get_effective_user_client_roles),
        )
        .route("/realms/{realm}/users/{id}/groups", get(users::get_user_groups))
        .route(
            "/realms/{realm}/users/{id}/groups/{group_id}",
            put(users::add_user_group).delete(users::remove_user_group),
        )
        .route(
            "/realms/{realm}/clients",
            get(clients::list_clients).post(clients::create_client),
        )
        .route("/realms/{realm}/clients/count", get(clients::count_clients))
        .route(
            "/realms/{realm}/clients-initial-access",
            get(initial_access::list_initial_access_tokens)
                .post(initial_access::create_initial_access_token),
        )
        .route(
            "/realms/{realm}/clients-initial-access/{id}",
            delete(initial_access::delete_initial_access_token),
        )
        .route(
            "/realms/{realm}/clients/{id}",
            get(clients::get_client)
                .put(clients::update_client)
                .delete(clients::delete_client),
        )
        .route("/realms/{realm}/clients/{id}/secret", get(clients::get_client_secret))
        .route(
            "/realms/{realm}/clients/{id}/installation/providers/{provider_id}",
            get(client_installation::get_installation_provider),
        )
        .route(
            "/realms/{realm}/clients/{id}/client-secret",
            post(clients::rotate_client_secret),
        )
        .route(
            "/realms/{realm}/clients/{id}/service-account-user",
            get(clients::get_service_account_user),
        )
        .route(
            "/realms/{realm}/clients/{id}/roles",
            get(client_roles::list_client_roles).post(client_roles::create_client_role),
        )
        .route(
            "/realms/{realm}/clients/{id}/roles/{role_name}",
            get(client_roles::get_client_role)
                .put(client_roles::update_client_role)
                .delete(client_roles::delete_client_role),
        )
        .route(
            "/realms/{realm}/clients/{id}/roles/{role_name}/composites",
            get(composites::get_client_role_composites)
                .post(composites::add_client_role_composites)
                .delete(composites::remove_client_role_composites),
        )
        .route(
            "/realms/{realm}/clients/{id}/roles/{role_name}/composites/realm",
            get(composites::get_client_role_composites_realm),
        )
        .route(
            "/realms/{realm}/clients/{id}/roles/{role_name}/composites/clients/{client_uuid}",
            get(composites::get_client_role_composites_clients),
        )
        .route(
            "/realms/{realm}/clients/{id}/protocol-mappers/models",
            get(client_scopes::list_client_mappers).post(client_scopes::create_client_mapper),
        )
        .route(
            "/realms/{realm}/clients/{id}/protocol-mappers/models/{mapper_id}",
            get(client_scopes::get_client_mapper)
                .put(client_scopes::update_client_mapper)
                .delete(client_scopes::delete_client_mapper),
        )
        .route(
            "/realms/{realm}/clients/{id}/default-client-scopes",
            get(client_scopes::get_default_client_scopes),
        )
        .route(
            "/realms/{realm}/clients/{id}/default-client-scopes/{scope_id}",
            put(client_scopes::assign_default_client_scope)
                .delete(client_scopes::unassign_default_client_scope),
        )
        .route(
            "/realms/{realm}/clients/{id}/optional-client-scopes",
            get(client_scopes::get_optional_client_scopes),
        )
        .route(
            "/realms/{realm}/clients/{id}/optional-client-scopes/{scope_id}",
            put(client_scopes::assign_optional_client_scope)
                .delete(client_scopes::unassign_optional_client_scope),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings",
            get(scope_mappings::get_client_scope_mappings),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings/realm",
            get(scope_mappings::get_scope_mapping_realm_roles)
                .post(scope_mappings::add_scope_mapping_realm_roles)
                .delete(scope_mappings::remove_scope_mapping_realm_roles),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings/realm/available",
            get(scope_mappings::get_available_scope_mapping_realm_roles),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings/realm/composite",
            get(scope_mappings::get_effective_scope_mapping_realm_roles),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}",
            get(scope_mappings::get_scope_mapping_client_roles)
                .post(scope_mappings::add_scope_mapping_client_roles)
                .delete(scope_mappings::remove_scope_mapping_client_roles),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}/available",
            get(scope_mappings::get_available_scope_mapping_client_roles),
        )
        .route(
            "/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}/composite",
            get(scope_mappings::get_effective_scope_mapping_client_roles),
        )
        .route(
            "/realms/{realm}/client-scopes",
            get(client_scopes::list_client_scopes).post(client_scopes::create_client_scope),
        )
        .route(
            "/realms/{realm}/client-scopes/{id}",
            get(client_scopes::get_client_scope)
                .put(client_scopes::update_client_scope)
                .delete(client_scopes::delete_client_scope),
        )
        .route(
            "/realms/{realm}/client-scopes/{id}/protocol-mappers/models",
            get(client_scopes::list_scope_mappers).post(client_scopes::create_scope_mapper),
        )
        .route(
            "/realms/{realm}/client-scopes/{id}/protocol-mappers/models/{mapper_id}",
            get(client_scopes::get_scope_mapper)
                .put(client_scopes::update_scope_mapper)
                .delete(client_scopes::delete_scope_mapper),
        )
        .route(
            "/realms/{realm}/default-default-client-scopes",
            get(client_scopes::list_default_default_client_scopes),
        )
        .route(
            "/realms/{realm}/default-default-client-scopes/{scope_id}",
            put(client_scopes::add_default_default_client_scope)
                .delete(client_scopes::remove_default_default_client_scope),
        )
        .route(
            "/realms/{realm}/default-optional-client-scopes",
            get(client_scopes::list_default_optional_client_scopes),
        )
        .route(
            "/realms/{realm}/default-optional-client-scopes/{scope_id}",
            put(client_scopes::add_default_optional_client_scope)
                .delete(client_scopes::remove_default_optional_client_scope),
        )
        .route(
            "/realms/{realm}/roles",
            get(roles::list_realm_roles).post(roles::create_realm_role),
        )
        .route("/realms/{realm}/roles/count", get(roles::count_realm_roles))
        .route(
            "/realms/{realm}/roles/{role_name}",
            get(roles::get_realm_role)
                .put(roles::update_realm_role)
                .delete(roles::delete_realm_role),
        )
        .route(
            "/realms/{realm}/roles/{role_name}/composites",
            get(composites::get_realm_role_composites)
                .post(composites::add_realm_role_composites)
                .delete(composites::remove_realm_role_composites),
        )
        .route(
            "/realms/{realm}/roles/{role_name}/composites/realm",
            get(composites::get_realm_role_composites_realm),
        )
        .route(
            "/realms/{realm}/roles/{role_name}/composites/clients/{client_uuid}",
            get(composites::get_realm_role_composites_clients),
        )
        .route("/realms/{realm}/groups", get(groups::list_groups).post(groups::create_group))
        .route("/realms/{realm}/groups/count", get(groups::count_groups))
        .route(
            "/realms/{realm}/groups/{id}",
            get(groups::get_group).put(groups::update_group).delete(groups::delete_group),
        )
        .route(
            "/realms/{realm}/groups/{id}/children",
            post(groups::create_child_group),
        )
        .route(
            "/realms/{realm}/groups/{id}/members",
            get(groups::get_group_members),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings",
            get(groups::get_group_role_mappings),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings/realm",
            get(groups::get_group_realm_roles)
                .post(groups::add_group_realm_roles)
                .delete(groups::remove_group_realm_roles),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings/realm/available",
            get(groups::get_available_group_realm_roles),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings/realm/composite",
            get(groups::get_effective_group_realm_roles),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}",
            get(groups::get_group_client_roles)
                .post(groups::add_group_client_roles)
                .delete(groups::remove_group_client_roles),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}/available",
            get(groups::get_available_group_client_roles),
        )
        .route(
            "/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}/composite",
            get(groups::get_effective_group_client_roles),
        )
        .route("/realms/{realm}/sessions", get(sessions::list_sessions))
        .route("/realms/{realm}/sessions/count", get(sessions::count_sessions))
        .route("/realms/{realm}/sessions/{session}", delete(sessions::delete_session))
        .route("/realms/{realm}/events", get(events::query_events).delete(events::clear_events))
        .route("/realms/{realm}/events/count", get(events::count_events))
        .route(
            "/realms/{realm}/admin-events",
            get(events::query_admin_events).delete(events::clear_admin_events),
        )
        .route(
            "/realms/{realm}/admin-events/count",
            get(events::count_admin_events),
        )
        .route(
            "/realms/{realm}/events/config",
            get(events::get_events_config).put(events::update_events_config),
        )
        .route(
            "/realms/{realm}/identity-provider/instances",
            get(idp::list_idps).post(idp::create_idp),
        )
        .route(
            "/realms/{realm}/identity-provider/instances/{alias}",
            get(idp::get_idp).put(idp::update_idp).delete(idp::delete_idp),
        )
        .route(
            "/realms/{realm}/identity-provider/instances/{alias}/mappers",
            get(idp::list_idp_mappers).post(idp::create_idp_mapper),
        )
        .route(
            "/realms/{realm}/identity-provider/instances/{alias}/mappers/{name}",
            put(idp::update_idp_mapper).delete(idp::delete_idp_mapper),
        )
        .route(
            "/realms/{realm}/identity-provider/instances/{alias}/test-connection",
            post(idp::test_idp_connection),
        )
        .route("/realms/{realm}/keys", get(keys::get_keys))
        .route("/realms/{realm}/keys/rotate", post(keys::rotate_keys))
        .route("/realms/{realm}/keys/{kid}/disable", put(keys::disable_key))
        .route(
            "/realms/{realm}/authentication/flows",
            get(flows::list_flows).post(flows::create_flow),
        )
        .route(
            "/realms/{realm}/authentication/flows/{flow_alias}",
            get(flows::get_flow).put(flows::update_flow).delete(flows::delete_flow),
        )
        .route("/realms/{realm}/authentication/flows/{flow_alias}/copy", post(flows::copy_flow))
        .route(
            "/realms/{realm}/authentication/flows/{flow_alias}/executions",
            put(flows::update_execution),
        )
        .route(
            "/realms/{realm}/authentication/flows/{flow_alias}/executions/execution",
            post(flows::add_execution),
        )
        .route(
            "/realms/{realm}/authentication/flows/{flow_alias}/executions/flow",
            post(flows::add_flow_execution),
        )
        .route(
            "/realms/{realm}/authentication/executions/{execution_id}",
            get(flows::get_execution).delete(flows::delete_execution),
        )
        .route(
            "/realms/{realm}/authentication/executions/{execution_id}/config",
            get(flows::get_execution_config)
                .post(flows::create_execution_config)
                .put(flows::update_execution_config)
                .delete(flows::delete_execution_config),
        )
        .route(
            "/realms/{realm}/user-federation/{provider_id}/sync",
            post(federation::sync_users),
        )
        .route("/serverinfo", get(enums::get_serverinfo))
        .route("/enums/protocols", get(enums::list_protocols))
        .route("/enums/ssl-required", get(enums::list_ssl_required))
        .route("/enums/event-types", get(enums::list_event_types))
        .route("/enums/event-listeners", get(enums::list_event_listeners))
        .route("/enums/credential-types", get(enums::list_credential_types))
        .route("/enums/algorithms", get(enums::list_algorithms))
        .route("/enums/grant-types", get(enums::list_grant_types))
        .route("/enums/response-types", get(enums::list_response_types))
        .route("/enums/response-modes", get(enums::list_response_modes))
        .route("/enums/requirements", get(enums::list_requirements))
        .route("/enums/authenticators", get(enums::list_authenticators))
        .route("/enums/provider-ids", get(enums::list_provider_ids))
        .route("/enums/client-authenticator-types", get(enums::list_client_authenticator_types))
        .route("/enums/operation-types", get(enums::list_operation_types))
        .route("/enums/prompts", get(enums::list_prompts))
        .route("/enums/resource-types", get(enums::list_resource_types))
        .route("/enums/hash-algorithms", get(enums::list_hash_algorithms))
        .route("/enums/auth-methods", get(enums::list_auth_methods))
        .route(
            "/enums/pkce-code-challenge-methods",
            get(enums::list_pkce_code_challenge_methods),
        )
        .route("/enums/jwk-use", get(enums::list_jwk_use))
        .route("/enums/jwk-key-types", get(enums::list_jwk_key_types))
        .route("/enums/ldap-vendors", get(enums::list_ldap_vendors))
        .route("/enums/ldap-search-scopes", get(enums::list_ldap_search_scopes))
        .route("/enums/edit-modes", get(enums::list_edit_modes))
        .route("/enums/required-actions", get(enums::list_required_actions))
        .route("/enums/otp-algorithms", get(enums::list_otp_algorithms))
        .route("/enums/broker-sync-modes", get(enums::list_broker_sync_modes))
        .route("/enums/broker-client-auth-methods", get(enums::list_broker_client_auth_methods))
        .route("/enums/idp-mapper-types", get(enums::list_idp_mapper_types))
        .route("/enums/mapper-types", get(enums::list_mapper_types))
        .route("/enums/locales", get(enums::list_locales))
        .route("/enums/themes", get(enums::list_themes))
        .route("/enums/subject-types", get(enums::list_subject_types))
        .route("/enums/identity-provider-presets", get(enums::list_identity_provider_presets))
        .route(
            "/enums/client-installations",
            get(enums::list_client_installations),
        )
        .route("/openapi.json", get(openapi_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth_middleware))
        .with_state(state)
}

/// Convenience wrapper that nests [`admin_routes`] under `/admin`.
pub fn routes(state: Arc<AdminApiState>) -> Router {
    Router::new().nest("/admin", admin_routes(state))
}

async fn openapi_handler() -> Json<utoipa::openapi::OpenApi> {
    Json(crate::openapi::AdminApiDoc::openapi())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn openapi_json_returns_valid_spec() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/openapi.json")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("openapi").and_then(|v| v.as_str()), Some("3.1.0"));
        let paths = json.get("paths").unwrap().as_object().unwrap();
        assert!(paths.contains_key("/admin/realms"));
    }
}
