// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::BTreeMap;
use std::sync::Arc;

use issuerd_admin_api::{auth::AdminAuth, state::AdminApiState};
use issuerd_core::*;
use issuerd_mcp::{
    strict_tools::{
        ClientSecurityArgs, DeleteArgs, EventsConfigArgs, FlowUpdateArgs, IdpCreateArgs,
        IdpUpdateArgs, NotBeforeArgs, RealmDeleteArgs, RealmSettingsArgs, RoleDeleteArgs,
        WebauthnDeleteArgs,
    },
    write_tools::{McpOperation, RoleAssignmentArgs},
    McpAuthContext, McpError, ToolName,
};
use serde::de::DeserializeOwned;

const ADMIN_ROLES: &[&str] = &[
    "view-realm",
    "view-users",
    "view-clients",
    "manage-realm",
    "manage-users",
    "manage-clients",
    "realm-admin",
    "impersonation",
];

pub async fn prepare(
    state: &Arc<AdminApiState>,
    auth: &McpAuthContext,
    operation: McpOperation,
) -> Result<Option<McpStepUpMutation>, McpError> {
    let realm_id = &auth.realm_id;
    let tool = operation.tool;
    let mutation = match tool {
        ToolName::UsersDelete => {
            let args: DeleteArgs = decode(&operation)?;
            confirm(&args.confirmation, "DELETE")?;
            let user = load_user(state, realm_id, &args.id).await?;
            McpStepUpMutation::DeleteUser { expected: user }
        }
        ToolName::GroupsDelete => {
            let args: DeleteArgs = decode(&operation)?;
            confirm(&args.confirmation, "DELETE")?;
            let group = load_group(state, realm_id, &args.id).await?;
            McpStepUpMutation::DeleteGroup { expected: group }
        }
        ToolName::RolesDelete => {
            let args: RoleDeleteArgs = decode(&operation)?;
            confirm(&args.confirmation, &args.name)?;
            let role = state
                .storage
                .get_role_by_name(realm_id, &args.name)
                .await?
                .filter(|role| !role.client_role)
                .ok_or(McpError::NotFound("role"))?;
            McpStepUpMutation::DeleteRole { expected: role }
        }
        ToolName::ClientsDelete => {
            let args: DeleteArgs = decode(&operation)?;
            let client = load_client(state, realm_id, &args.id).await?;
            confirm(&args.confirmation, client.client_id.as_str())?;
            McpStepUpMutation::DeleteClient { expected: client }
        }
        ToolName::ClientsUpdateSecurity => {
            let args: ClientSecurityArgs = decode(&operation)?;
            let expected = load_client(state, realm_id, &args.id).await?;
            if args.service_accounts_enabled == Some(true) {
                return Err(McpError::Forbidden(
                    "service-account provisioning is not a transactional MCP operation",
                ));
            }
            let mut updated = expected.clone();
            if let Some(values) = args.redirect_uris {
                updated.redirect_uris =
                    values.into_iter().map(RedirectUri::new).collect::<Result<Vec<_>, _>>()?;
            }
            if let Some(values) = args.web_origins {
                updated.web_origins =
                    values.into_iter().map(WebOrigin::new).collect::<Result<Vec<_>, _>>()?;
            }
            assign(&mut updated.public_client, args.public_client);
            assign(&mut updated.bearer_only, args.bearer_only);
            assign(&mut updated.consent_required, args.consent_required);
            assign(&mut updated.full_scope_allowed, args.full_scope_allowed);
            assign(&mut updated.service_accounts_enabled, args.service_accounts_enabled);
            validate_pairwise_subject_config(&updated, state.broker_client.as_ref()).await?;
            McpStepUpMutation::UpdateClientSecurity { expected, updated }
        }
        ToolName::RealmUpdateSettings => {
            let args: RealmSettingsArgs = decode(&operation)?;
            let expected = load_realm(state, realm_id).await?;
            let mut updated = expected.clone();
            if let Some(value) = args.display_name {
                updated.display_name = Some(DisplayName::new(value)?);
            }
            assign(&mut updated.enabled, args.enabled);
            if let Some(value) = args.ssl_required {
                updated.ssl_required = value.into();
            }
            assign(&mut updated.access_token_lifespan, seconds(args.access_token_lifespan)?);
            assign(&mut updated.refresh_token_lifespan, seconds(args.refresh_token_lifespan)?);
            assign(&mut updated.sso_session_idle_timeout, seconds(args.sso_session_idle_timeout)?);
            assign(&mut updated.sso_session_max_lifespan, seconds(args.sso_session_max_lifespan)?);
            assign(
                &mut updated.offline_session_idle_timeout,
                seconds(args.offline_session_idle_timeout)?,
            );
            assign(&mut updated.login_theme, Some(theme(args.login_theme)?));
            assign(&mut updated.email_theme, Some(theme(args.email_theme)?));
            assign(&mut updated.admin_theme, Some(theme(args.admin_theme)?));
            assign(&mut updated.registration_enabled, args.registration_enabled);
            assign(&mut updated.reset_password_allowed, args.reset_password_allowed);
            assign(&mut updated.remember_me_enabled, args.remember_me_enabled);
            assign(&mut updated.verify_email_enabled, args.verify_email_enabled);
            assign(&mut updated.login_with_email_allowed, args.login_with_email_allowed);
            assign(&mut updated.duplicate_emails_allowed, args.duplicate_emails_allowed);
            assign(&mut updated.edit_username_allowed, args.edit_username_allowed);
            McpStepUpMutation::UpdateRealmSettings { expected, updated }
        }
        ToolName::EventsConfigUpdate => {
            let args: EventsConfigArgs = decode(&operation)?;
            if args.admin_events_enabled == Some(false) {
                return Err(McpError::Forbidden(
                    "administrative audit cannot be disabled through MCP",
                ));
            }
            if args.events_expiration_secs.is_some_and(|value| value < 0) {
                return Err(McpError::InvalidInput(
                    "eventsExpirationSecs cannot be negative".into(),
                ));
            }
            let expected = load_realm(state, realm_id).await?;
            let mut updated = expected.clone();
            assign(&mut updated.events_enabled, args.events_enabled);
            assign(&mut updated.events_expiration_secs, args.events_expiration_secs);
            assign(&mut updated.admin_events_enabled, args.admin_events_enabled);
            assign(&mut updated.include_representations, args.include_representations);
            if let Some(listeners) = args.events_listeners {
                for listener in &listeners {
                    bounded_text(listener, "eventsListeners")?;
                }
                updated.events_listeners = listeners;
            }
            McpStepUpMutation::UpdateEventsConfig { expected, updated }
        }
        ToolName::IdpCreate => {
            let args: IdpCreateArgs = decode(&operation)?;
            if args.enabled == Some(true) {
                return Err(McpError::Forbidden(
                    "new identity providers must start disabled; no credentials are accepted through MCP",
                ));
            }
            let config = safe_config(args.config)?;
            let id = uuid(&args.id, "id")?;
            let new = IdentityProviderConfig {
                id: IdentityProviderId::new(id)?,
                alias: Alias::new(args.alias)?,
                provider_id: ProviderId::new(args.provider_id),
                enabled: args.enabled.unwrap_or(false),
                config: config.into_iter().collect(),
            };
            if state
                .storage
                .get_identity_provider_by_alias(realm_id, new.alias.as_str())
                .await?
                .is_some()
            {
                return Err(McpError::Conflict("identity provider alias already exists"));
            }
            McpStepUpMutation::CreateIdentityProvider {
                realm_id: realm_id.clone(),
                new,
            }
        }
        ToolName::IdpUpdate => {
            let args: IdpUpdateArgs = decode(&operation)?;
            let id = IdentityProviderId::new(uuid(&args.id, "id")?)?;
            let expected = state
                .storage
                .get_identity_provider(realm_id, &id)
                .await?
                .ok_or(McpError::NotFound("identity provider"))?;
            let mut updated = expected.clone();
            if let Some(alias) = args.alias {
                updated.alias = Alias::new(alias)?;
            }
            if let Some(provider_id) = args.provider_id {
                updated.provider_id = ProviderId::new(provider_id);
            }
            assign(&mut updated.enabled, args.enabled);
            if let Some(config) = args.config {
                updated.config = safe_config(Some(config))?.into_iter().collect();
            }
            McpStepUpMutation::UpdateIdentityProvider {
                realm_id: realm_id.clone(),
                expected,
                updated,
            }
        }
        ToolName::IdpDelete => {
            let args: DeleteArgs = decode(&operation)?;
            confirm(&args.confirmation, "DELETE")?;
            let id = IdentityProviderId::new(uuid(&args.id, "id")?)?;
            let expected = state
                .storage
                .get_identity_provider(realm_id, &id)
                .await?
                .ok_or(McpError::NotFound("identity provider"))?;
            McpStepUpMutation::DeleteIdentityProvider {
                realm_id: realm_id.clone(),
                expected,
            }
        }
        ToolName::FlowsUpdateExecutions => {
            let args: FlowUpdateArgs = decode(&operation)?;
            let expected = state
                .storage
                .get_flow_config(realm_id, &args.alias)
                .await?
                .ok_or(McpError::NotFound("flow"))?;
            if expected.built_in {
                return Err(McpError::Forbidden("built-in flows are read-only"));
            }
            if args.executions.len() != expected.stages.len() {
                return Err(McpError::InvalidInput(
                    "every execution must appear exactly once".into(),
                ));
            }
            let mut replacements = BTreeMap::new();
            for execution in args.executions {
                let id = uuid(&execution.id, "execution id")?;
                if replacements.insert(id, execution.requirement).is_some() {
                    return Err(McpError::InvalidInput("duplicate execution id".into()));
                }
            }
            let mut updated = expected.clone();
            for stage in &mut updated.stages {
                let Some(requirement) = replacements.remove(stage.id.as_ref()) else {
                    return Err(McpError::InvalidInput("unknown execution id".into()));
                };
                stage.requirement = requirement.into();
            }
            if !replacements.is_empty() {
                return Err(McpError::InvalidInput("unknown execution id".into()));
            }
            let mut flows = state.storage.list_flow_configs(realm_id).await?;
            for flow in &mut flows {
                if flow.alias == expected.alias {
                    *flow = updated.clone();
                }
            }
            issuerd_auth_flow::validation::validate_flows(&flows, state.plugin_registry.as_ref())
                .map_err(|errors| McpError::InvalidInput(errors.join("; ")))?;
            McpStepUpMutation::UpdateFlow { expected, updated }
        }
        ToolName::PushNotBefore => {
            let args: NotBeforeArgs = decode(&operation)?;
            let now = chrono::Utc::now().timestamp();
            if !(0..=now.saturating_add(60)).contains(&args.not_before) {
                return Err(McpError::InvalidInput(
                    "notBefore must be a Unix timestamp no more than 60 seconds in the future"
                        .into(),
                ));
            }
            let expected = load_realm(state, realm_id).await?;
            McpStepUpMutation::PushNotBefore {
                expected,
                not_before: args.not_before,
            }
        }
        ToolName::RealmDelete => {
            let args: RealmDeleteArgs = decode(&operation)?;
            let expected = load_realm(state, realm_id).await?;
            confirm(&args.confirm_name, expected.name.as_str())?;
            McpStepUpMutation::DeleteRealm { expected }
        }
        ToolName::MeTotpDelete => {
            let _: issuerd_mcp::tools::NoArgs = decode(&operation)?;
            let expected = state
                .storage
                .get_credentials(realm_id, &auth.user_id, CredentialType::Totp)
                .await?;
            if expected.is_empty() {
                return Err(McpError::NotFound("TOTP credential"));
            }
            McpStepUpMutation::DeleteTotp {
                realm_id: realm_id.clone(),
                user_id: auth.user_id.clone(),
                expected,
            }
        }
        ToolName::MeWebauthnDelete => {
            let args: WebauthnDeleteArgs = decode(&operation)?;
            let id = CredentialId::new(uuid(&args.id, "id")?)?;
            let expected = state
                .storage
                .list_credentials(realm_id, &auth.user_id)
                .await?
                .into_iter()
                .find(|credential| {
                    credential.id == id && credential.credential_type == CredentialType::WebAuthn
                })
                .ok_or(McpError::NotFound("WebAuthn credential"))?;
            McpStepUpMutation::DeleteWebauthn {
                realm_id: realm_id.clone(),
                user_id: auth.user_id.clone(),
                expected,
            }
        }
        ToolName::RolesUpdate => {
            let args: issuerd_mcp::write_tools::RoleUpdateArgs = decode(&operation)?;
            return role_update(state, realm_id, args).await;
        }
        ToolName::UsersAddToGroup | ToolName::UsersRemoveFromGroup => {
            let args: issuerd_mcp::write_tools::UserGroupArgs = decode(&operation)?;
            return group_membership(state, auth, tool, args).await;
        }
        ToolName::UsersAssignRole
        | ToolName::UsersUnassignRole
        | ToolName::GroupsAssignRole
        | ToolName::GroupsUnassignRole => {
            let args: RoleAssignmentArgs = decode(&operation)?;
            let Some(mutation) = role_mapping(state, auth, tool, args).await? else {
                return Ok(None);
            };
            mutation
        }
        _ => return Ok(None),
    };
    debug_assert_eq!(mutation.tool(), tool.as_str());
    Ok(Some(mutation))
}

async fn role_update(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    args: issuerd_mcp::write_tools::RoleUpdateArgs,
) -> Result<Option<McpStepUpMutation>, McpError> {
    let expected = state
        .storage
        .get_role_by_name(realm_id, &args.name)
        .await?
        .filter(|role| !role.client_role)
        .ok_or(McpError::NotFound("role"))?;
    let name_changed = args.new_name.as_ref().is_some_and(|name| name != expected.name.as_str());
    if args.composites.is_none() && !name_changed {
        return Ok(None);
    }
    let mut updated = expected.clone();
    if let Some(name) = args.new_name {
        bounded_text(&name, "newName")?;
        updated.name = RoleName::new(name)?;
    }
    if let Some(description) = args.description {
        if description.len() > 1024 || description.chars().any(char::is_control) {
            return Err(McpError::InvalidInput("description is invalid".into()));
        }
        updated.description = Some(description);
    }
    if let Some(composites) = args.composites {
        updated.composites = composites
            .into_iter()
            .map(|name| {
                bounded_text(&name, "composites")?;
                Ok(RoleName::new(name)?)
            })
            .collect::<Result<Vec<_>, McpError>>()?;
        updated.composite = !updated.composites.is_empty();
    }
    let all_roles = list_all_roles(state.storage.as_ref(), realm_id).await?;
    let evaluated: Vec<_> = all_roles
        .iter()
        .map(|role| {
            if role.id == expected.id {
                updated.clone()
            } else {
                role.clone()
            }
        })
        .collect();
    let before = expand_composites(vec![expected.clone()], &all_roles);
    let after = expand_composites(vec![updated.clone()], &evaluated);
    if !has_admin_role(&before) && !has_admin_role(&after) {
        return Ok(None);
    }
    Ok(Some(McpStepUpMutation::UpdateRole { expected, updated }))
}

async fn group_membership(
    state: &Arc<AdminApiState>,
    auth: &McpAuthContext,
    tool: ToolName,
    args: issuerd_mcp::write_tools::UserGroupArgs,
) -> Result<Option<McpStepUpMutation>, McpError> {
    let realm_id = &auth.realm_id;
    let user_id = UserId::new(uuid(&args.id, "id")?)?;
    let group_id = GroupId::new(uuid(&args.group_id, "groupId")?)?;
    let expected_group = state
        .storage
        .get_group(realm_id, &group_id)
        .await?
        .ok_or(McpError::NotFound("group"))?;
    let mut expected_roles =
        effective_group_roles(state.storage.as_ref(), realm_id, &group_id).await?;
    if !has_admin_role(&expected_roles) {
        return Ok(None);
    }
    if state.storage.get_user(realm_id, &user_id).await?.is_none() {
        return Err(McpError::NotFound("user"));
    }
    expected_roles.sort_by(|left, right| left.id.cmp(&right.id));
    let expected_present =
        state.storage.list_user_groups(realm_id, &user_id).await?.contains(&group_id);
    Ok(Some(McpStepUpMutation::UserGroupMembership {
        realm_id: realm_id.clone(),
        user_id,
        expected_group,
        expected_roles,
        assign: tool == ToolName::UsersAddToGroup,
        expected_present,
    }))
}

fn has_admin_role(roles: &[Role]) -> bool {
    roles.iter().any(|role| ADMIN_ROLES.contains(&role.name.as_str()))
}

async fn role_mapping(
    state: &Arc<AdminApiState>,
    auth: &McpAuthContext,
    tool: ToolName,
    args: RoleAssignmentArgs,
) -> Result<Option<McpStepUpMutation>, McpError> {
    let realm_id = &auth.realm_id;
    let id = uuid(&args.id, "id")?;
    let (expected_role, client_id) = if let Some(identifier) = &args.client_id {
        let identifier = ClientIdentifier::new(identifier)?;
        let client = state
            .storage
            .get_client_by_client_id(realm_id, &identifier)
            .await?
            .ok_or(McpError::NotFound("client"))?;
        let role = state
            .storage
            .get_client_role_by_name(realm_id, &client.id, &args.role)
            .await?
            .ok_or(McpError::NotFound("role"))?;
        (role, Some(client.id))
    } else {
        let role = state
            .storage
            .get_role_by_name(realm_id, &args.role)
            .await?
            .filter(|role| !role.client_role)
            .ok_or(McpError::NotFound("role"))?;
        (role, None)
    };
    let all_roles = list_all_roles(state.storage.as_ref(), realm_id).await?;
    let closure = expand_composites(vec![expected_role.clone()], &all_roles);
    if !closure.iter().any(|role| ADMIN_ROLES.contains(&role.name.as_str())) {
        return Ok(None);
    }
    let assign = matches!(tool, ToolName::UsersAssignRole | ToolName::GroupsAssignRole);
    if matches!(tool, ToolName::UsersAssignRole | ToolName::UsersUnassignRole) {
        let user_id = UserId::new(id)?;
        let present = if expected_role.client_role {
            state.storage.list_user_client_roles(realm_id, &user_id).await?
        } else {
            state.storage.list_user_realm_roles(realm_id, &user_id).await?
        }
        .contains(&expected_role.id);
        if state.storage.get_user(realm_id, &user_id).await?.is_none() {
            return Err(McpError::NotFound("user"));
        }
        Ok(Some(McpStepUpMutation::UserRoleMapping {
            realm_id: realm_id.clone(),
            user_id,
            expected_role,
            client_role: client_id.is_some(),
            assign,
            expected_present: present,
        }))
    } else {
        let group = state
            .storage
            .get_group(realm_id, &GroupId::new(id)?)
            .await?
            .ok_or(McpError::NotFound("group"))?;
        Ok(Some(McpStepUpMutation::GroupRoleMapping {
            expected: group,
            expected_role,
            client_id,
            assign,
        }))
    }
}

pub async fn committed(state: &Arc<AdminApiState>, grant: &McpStepUpGrant) {
    let realm_id = &grant.realm_id;
    match &grant.mutation {
        McpStepUpMutation::DeleteUser { expected } => {
            if let Err(error) = state
                .cache
                .increment(
                    &issuerd_cluster::cache_keys::session_version(
                        realm_id.as_ref(),
                        expected.id.as_ref(),
                    ),
                    None,
                )
                .await
            {
                tracing::warn!(realm = %realm_id, error = %error, "session version bump failed");
            }
            issuerd_cluster::invalidate::invalidate_user_claims(
                state.cache.as_ref(),
                realm_id,
                &expected.id,
            )
            .await;
        }
        McpStepUpMutation::DeleteClient { expected }
        | McpStepUpMutation::UpdateClientSecurity { expected, .. } => {
            issuerd_cluster::invalidate::invalidate_client_claims(
                state.cache.as_ref(),
                realm_id,
                &expected.id,
                expected.client_id.as_str(),
            )
            .await;
            if matches!(grant.mutation, McpStepUpMutation::DeleteClient { .. }) {
                issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), realm_id)
                    .await;
            }
        }
        McpStepUpMutation::DeleteTotp { user_id, .. }
        | McpStepUpMutation::DeleteWebauthn { user_id, .. } => {
            issuerd_cluster::invalidate::invalidate_user_claims(
                state.cache.as_ref(),
                realm_id,
                user_id,
            )
            .await;
        }
        McpStepUpMutation::UpdateRealmSettings { .. }
        | McpStepUpMutation::UpdateEventsConfig { .. }
        | McpStepUpMutation::PushNotBefore { .. } => {
            let name = realm_name(state, realm_id).await;
            if let Some(name) = name {
                issuerd_cluster::invalidate::delete_best_effort(
                    state.cache.as_ref(),
                    realm_id,
                    &issuerd_cluster::cache_keys::realm_by_name(&name),
                )
                .await;
            }
        }
        McpStepUpMutation::DeleteRealm { expected } => {
            issuerd_cluster::invalidate::delete_best_effort(
                state.cache.as_ref(),
                realm_id,
                &issuerd_cluster::cache_keys::realm_by_name(expected.name.as_str()),
            )
            .await;
        }
        _ => {
            issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), realm_id).await;
        }
    }
    let client = state
        .storage
        .get_client_by_client_id(realm_id, &grant.client_id)
        .await
        .ok()
        .flatten();
    let auth = AdminAuth {
        claims: AccessTokenClaims {
            jti: grant.token_jti.clone(),
            iss: Issuer::new("https://issuerd.invalid/realms/mcp").expect("static issuer"),
            sub: grant.subject_user_id.clone(),
            aud: Audience::new(grant.client_id.as_str()).expect("validated client identifier"),
            exp: grant.expires_at.max(0),
            iat: grant.issued_at.max(0),
            nbf: grant.issued_at.max(0),
            scope: Scope::parse("openid mcp:step_up"),
            typ: JwtType::Bearer,
            azp: Some(grant.client_id.to_string()),
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
            resource: Some(grant.resource.clone()),
        },
    };
    let operation_type = match grant.mutation {
        McpStepUpMutation::DeleteUser { .. }
        | McpStepUpMutation::DeleteGroup { .. }
        | McpStepUpMutation::DeleteRole { .. }
        | McpStepUpMutation::DeleteClient { .. }
        | McpStepUpMutation::DeleteIdentityProvider { .. }
        | McpStepUpMutation::DeleteRealm { .. }
        | McpStepUpMutation::DeleteTotp { .. }
        | McpStepUpMutation::DeleteWebauthn { .. } => OperationType::Delete,
        McpStepUpMutation::CreateIdentityProvider { .. } => OperationType::Create,
        _ => OperationType::Update,
    };
    let resource_type = match grant.mutation {
        McpStepUpMutation::DeleteUser { .. }
        | McpStepUpMutation::DeleteTotp { .. }
        | McpStepUpMutation::DeleteWebauthn { .. }
        | McpStepUpMutation::UserRoleMapping { .. }
        | McpStepUpMutation::UserGroupMembership { .. } => ResourceType::User,
        McpStepUpMutation::DeleteGroup { .. } | McpStepUpMutation::GroupRoleMapping { .. } => {
            ResourceType::Group
        }
        McpStepUpMutation::DeleteRole { .. } | McpStepUpMutation::UpdateRole { .. } => {
            ResourceType::Role
        }
        McpStepUpMutation::DeleteClient { .. } | McpStepUpMutation::UpdateClientSecurity { .. } => {
            ResourceType::Client
        }
        McpStepUpMutation::CreateIdentityProvider { .. }
        | McpStepUpMutation::UpdateIdentityProvider { .. }
        | McpStepUpMutation::DeleteIdentityProvider { .. } => ResourceType::IdentityProvider,
        _ => ResourceType::Realm,
    };
    let representation = serde_json::json!({
        "operationId": grant.operation_id,
        "tool": grant.tool,
        "clientId": client.as_ref().map(|client| client.id.to_string()),
    });
    issuerd_admin_api::audit::emit_admin_event(
        state,
        &auth,
        realm_id,
        operation_type,
        resource_type,
        &format!("mcp/{}/{}", grant.tool, grant.mutation.target_id()),
        Some(representation.to_string()),
    )
    .await;
}

async fn realm_name(state: &Arc<AdminApiState>, realm_id: &RealmId) -> Option<String> {
    state
        .storage
        .get_realm(realm_id)
        .await
        .ok()
        .flatten()
        .map(|realm| realm.name.to_string())
}

async fn load_user(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    id: &str,
) -> Result<User, McpError> {
    state
        .storage
        .get_user(realm_id, &UserId::new(uuid(id, "id")?)?)
        .await?
        .ok_or(McpError::NotFound("user"))
}

async fn load_group(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    id: &str,
) -> Result<Group, McpError> {
    state
        .storage
        .get_group(realm_id, &GroupId::new(uuid(id, "id")?)?)
        .await?
        .ok_or(McpError::NotFound("group"))
}

async fn load_client(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    id: &str,
) -> Result<Client, McpError> {
    state
        .storage
        .get_client(realm_id, &ClientId::new(uuid(id, "id")?)?)
        .await?
        .ok_or(McpError::NotFound("client"))
}

async fn load_realm(state: &Arc<AdminApiState>, realm_id: &RealmId) -> Result<Realm, McpError> {
    state.storage.get_realm(realm_id).await?.ok_or(McpError::NotFound("realm"))
}

fn decode<T: DeserializeOwned>(operation: &McpOperation) -> Result<T, McpError> {
    serde_json::from_value(operation.arguments.clone())
        .map_err(|error| McpError::InvalidInput(error.to_string()))
}

fn uuid(value: &str, field: &str) -> Result<String, McpError> {
    bounded_text(value, field)?;
    uuid::Uuid::parse_str(value)
        .map(|value| value.to_string())
        .map_err(|_| McpError::InvalidInput(format!("{field} must be a UUID")))
}

fn bounded_text(value: &str, field: &str) -> Result<(), McpError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(McpError::InvalidInput(format!("{field} is invalid")));
    }
    Ok(())
}

fn confirm(actual: &str, expected: &str) -> Result<(), McpError> {
    if actual != expected {
        return Err(McpError::InvalidInput("confirmation does not match".into()));
    }
    Ok(())
}

fn assign<T>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

fn seconds(value: Option<i64>) -> Result<Option<SecondsNonZero>, McpError> {
    value
        .map(|value| {
            SecondsNonZero::try_from(value)
                .map_err(|error| McpError::InvalidInput(error.to_string()))
        })
        .transpose()
}

fn theme(value: Option<String>) -> Result<Option<ThemeName>, McpError> {
    value.map(ThemeName::new).transpose().map_err(McpError::from)
}

fn safe_config(
    config: Option<BTreeMap<String, String>>,
) -> Result<BTreeMap<String, String>, McpError> {
    let config = config.unwrap_or_default();
    if config.len() > 100 {
        return Err(McpError::InvalidInput("at most 100 configuration keys".into()));
    }
    for (key, value) in &config {
        bounded_text(key, "configuration key")?;
        bounded_text(value, "configuration value")?;
        let normalized: String = key
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        if [
            "secret",
            "password",
            "bindcredential",
            "privatekey",
            "credential",
            "clientassertion",
        ]
        .iter()
        .any(|sensitive| normalized.contains(sensitive))
        {
            return Err(McpError::Forbidden(
                "secret-bearing identity-provider fields are not accepted through MCP",
            ));
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    struct Fixture {
        state: Arc<AdminApiState>,
        auth: McpAuthContext,
        realm: Realm,
        user: User,
    }

    fn user(realm: &Realm, name: &str) -> User {
        let now = chrono::Utc::now();
        User {
            id: UserId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            username: Username::new(name).unwrap(),
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

    fn client(realm: &Realm, identifier: &str) -> Client {
        Client {
            id: ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new(identifier).unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("client-secret".into()),
            redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: Default::default(),
        }
    }

    fn test_role(realm: &Realm, name: &str) -> Role {
        Role {
            id: RoleId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: RoleName::new(name).unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: Vec::new(),
            attributes: Default::default(),
        }
    }

    fn group(realm: &Realm, name: &str) -> Group {
        Group {
            id: GroupId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: GroupName::new(name).unwrap(),
            path: GroupPath::new(format!("/{name}")).unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: Vec::new(),
            attributes: Default::default(),
            realm_roles: Vec::new(),
            client_roles: Default::default(),
        }
    }

    async fn fixture() -> Fixture {
        let state = Arc::new(
            crate::state::ServerState::from_config(&crate::config::ServerConfig::with_test_admin())
                .await
                .unwrap(),
        );
        let realm = state.storage.get_realm_by_name("master").await.unwrap().unwrap();
        let user = user(&realm, "strict-builder-user");
        state.storage.create_user(&realm.id, &user).await.unwrap();
        let auth = McpAuthContext {
            realm_id: realm.id.clone(),
            realm_name: realm.name.clone(),
            user_id: user.id.clone(),
            azp: ClientIdentifier::new("admin-cli").unwrap(),
            claims: AccessTokenClaims {
                jti: JwtId::new("strict-builder").unwrap(),
                iss: Issuer::new("http://localhost/realms/master").unwrap(),
                sub: user.id.clone(),
                aud: Audience::new("admin-cli").unwrap(),
                exp: 4_000_000_000,
                iat: 1,
                nbf: 1,
                scope: Scope::parse("openid mcp:write"),
                typ: JwtType::Bearer,
                azp: Some("admin-cli".into()),
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: [
                        "manage-realm",
                        "manage-users",
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
                cnf: Some(ConfirmationClaim {
                    jkt: "builder-jkt".into(),
                }),
                authorization_details: None,
                resource: Some("http://localhost/realms/master/mcp".into()),
            },
        };
        Fixture {
            state: crate::mcp_service::admin_state(&state),
            auth,
            realm,
            user,
        }
    }

    async fn call(
        fixture: &Fixture,
        tool: ToolName,
        arguments: serde_json::Value,
    ) -> Result<Option<McpStepUpMutation>, McpError> {
        prepare(&fixture.state, &fixture.auth, McpOperation { tool, arguments }).await
    }

    async fn create_role_if_missing(state: &Arc<AdminApiState>, realm: &Realm, role: &Role) {
        if state
            .storage
            .get_role_by_name(&realm.id, role.name.as_str())
            .await
            .unwrap()
            .is_none()
        {
            state.storage.create_role(&realm.id, role).await.unwrap();
        }
    }

    #[tokio::test]
    async fn every_strict_builder_and_composite_admin_role_rule_is_covered() {
        let fixture = fixture().await;
        let realm = &fixture.realm;
        let user = &fixture.user;
        assert!(matches!(
            call(
                &fixture,
                ToolName::UsersDelete,
                json!({"id": user.id.to_string(), "confirmation": "DELETE"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::DeleteUser { .. })
        ));
        assert!(fixture.state.storage.get_user(&realm.id, &user.id).await.unwrap().is_some());

        let group = group(realm, "builder-group");
        fixture.state.storage.create_group(&realm.id, &group).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::GroupsDelete,
                json!({"id": group.id.to_string(), "confirmation": "DELETE"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::DeleteGroup { .. })
        ));

        let role = test_role(realm, "builder-role");
        fixture.state.storage.create_role(&realm.id, &role).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::RolesDelete,
                json!({"name": "builder-role", "confirmation": "builder-role"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::DeleteRole { .. })
        ));

        let client = client(realm, "builder-client");
        fixture.state.storage.create_client(&realm.id, &client).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::ClientsDelete,
                json!({"id": client.id.to_string(), "confirmation": "builder-client"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::DeleteClient { .. })
        ));
        assert!(matches!(
            call(
                &fixture,
                ToolName::ClientsUpdateSecurity,
                json!({"id": client.id.to_string(), "redirectUris": ["https://app.example/cb"]}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UpdateClientSecurity { .. })
        ));
        assert!(call(
            &fixture,
            ToolName::ClientsUpdateSecurity,
            json!({"id": client.id.to_string(), "serviceAccountsEnabled": true}),
        )
        .await
        .is_err());

        assert!(matches!(
            call(&fixture, ToolName::RealmUpdateSettings, json!({"displayName": "Builder Realm"}),)
                .await
                .unwrap(),
            Some(McpStepUpMutation::UpdateRealmSettings { .. })
        ));
        assert!(matches!(
            call(
                &fixture,
                ToolName::EventsConfigUpdate,
                json!({"eventsExpirationSecs": 600, "adminEventsEnabled": true}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UpdateEventsConfig { .. })
        ));
        assert!(
            call(&fixture, ToolName::EventsConfigUpdate, json!({"adminEventsEnabled": false}),)
                .await
                .is_err()
        );

        let idp_id = uuid::Uuid::new_v4().to_string();
        assert!(matches!(
            call(
                &fixture,
                ToolName::IdpCreate,
                json!({"id": idp_id, "alias": "builder-idp", "providerId": "oidc", "enabled": false}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::CreateIdentityProvider { .. })
        ));
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new(uuid::Uuid::new_v4()).unwrap(),
            alias: Alias::new("builder-idp").unwrap(),
            provider_id: ProviderId::new("oidc"),
            enabled: false,
            config: Default::default(),
        };
        fixture.state.storage.create_identity_provider(&realm.id, &idp).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::IdpUpdate,
                json!({"id": idp.id.to_string(), "alias": "builder-idp-renamed"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UpdateIdentityProvider { .. })
        ));
        assert!(matches!(
            call(
                &fixture,
                ToolName::IdpDelete,
                json!({"id": idp.id.to_string(), "confirmation": "DELETE"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::DeleteIdentityProvider { .. })
        ));

        let stage_id = uuid::Uuid::new_v4().to_string();
        let flow = FlowConfig {
            alias: Alias::new("builder-flow").unwrap(),
            realm_id: realm.id.clone(),
            provider_id: "basic-flow".into(),
            top_level: true,
            built_in: false,
            stages: vec![FlowStage {
                id: FlowStageId::new(stage_id.clone()).unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("auth-username-password").unwrap(),
                priority: 1,
                sub_flow_alias: None,
                authenticator_config: None,
            }],
        };
        fixture.state.storage.create_flow_config(&realm.id, &flow).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::FlowsUpdateExecutions,
                json!({"alias": "builder-flow", "executions": [{"id": stage_id, "requirement": "alternative"}]}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UpdateFlow { .. })
        ));

        assert!(matches!(
            call(
                &fixture,
                ToolName::PushNotBefore,
                json!({"notBefore": chrono::Utc::now().timestamp()}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::PushNotBefore { .. })
        ));
        assert!(matches!(
            call(&fixture, ToolName::RealmDelete, json!({"confirmName": "master"}),)
                .await
                .unwrap(),
            Some(McpStepUpMutation::DeleteRealm { .. })
        ));

        let totp = Credential {
            id: CredentialId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            credential_type: CredentialType::Totp,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: b"totp-secret".to_vec(),
            credential_data: serde_json::Value::Null,
            priority: 0,
        };
        fixture
            .state
            .storage
            .create_credential(&realm.id, &user.id, &totp)
            .await
            .unwrap();
        assert!(matches!(
            call(&fixture, ToolName::MeTotpDelete, json!({})).await.unwrap(),
            Some(McpStepUpMutation::DeleteTotp { .. })
        ));

        let webauthn = Credential {
            id: CredentialId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            credential_type: CredentialType::WebAuthn,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: b"webauthn-secret".to_vec(),
            credential_data: serde_json::Value::Null,
            priority: 0,
        };
        fixture
            .state
            .storage
            .create_credential(&realm.id, &user.id, &webauthn)
            .await
            .unwrap();
        assert!(matches!(
            call(&fixture, ToolName::MeWebauthnDelete, json!({"id": webauthn.id.to_string()}),)
                .await
                .unwrap(),
            Some(McpStepUpMutation::DeleteWebauthn { .. })
        ));

        let admin_role = test_role(realm, "manage-realm");
        create_role_if_missing(&fixture.state, realm, &admin_role).await;
        let mut delegated = test_role(realm, "delegated-admin");
        delegated.composite = true;
        delegated.composites = vec![RoleName::new("manage-realm").unwrap()];
        fixture.state.storage.create_role(&realm.id, &delegated).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::UsersAssignRole,
                json!({"id": user.id.to_string(), "role": "delegated-admin"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UserRoleMapping { .. })
        ));
        assert!(matches!(
            call(
                &fixture,
                ToolName::GroupsAssignRole,
                json!({"id": group.id.to_string(), "role": "delegated-admin"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::GroupRoleMapping { .. })
        ));

        let ordinary = test_role(realm, "ordinary-role");
        fixture.state.storage.create_role(&realm.id, &ordinary).await.unwrap();
        assert_eq!(
            call(
                &fixture,
                ToolName::UsersAssignRole,
                json!({"id": user.id.to_string(), "role": "ordinary-role"}),
            )
            .await
            .unwrap(),
            None
        );

        let impersonation = test_role(realm, "impersonation");
        create_role_if_missing(&fixture.state, realm, &impersonation).await;
        assert!(matches!(
            call(
                &fixture,
                ToolName::UsersAssignRole,
                json!({"id": user.id.to_string(), "role": "impersonation"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UserRoleMapping { .. })
        ));
        assert!(matches!(
            call(
                &fixture,
                ToolName::RolesUpdate,
                json!({"name": "ordinary-role", "composites": ["impersonation"]}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UpdateRole { .. })
        ));
        assert!(matches!(
            call(
                &fixture,
                ToolName::RolesUpdate,
                json!({"name": "ordinary-role", "newName": "impersonation"}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UpdateRole { .. })
        ));
        assert_eq!(
            call(
                &fixture,
                ToolName::RolesUpdate,
                json!({"name": "builder-role", "composites": ["ordinary-role"]}),
            )
            .await
            .unwrap(),
            None
        );

        let mut privileged_group = self::tests::group(realm, "privileged-group");
        privileged_group.realm_roles = vec![RoleName::new("manage-realm").unwrap()];
        fixture.state.storage.create_group(&realm.id, &privileged_group).await.unwrap();
        assert!(matches!(
            call(
                &fixture,
                ToolName::UsersAddToGroup,
                json!({"id": user.id.to_string(), "groupId": privileged_group.id.to_string()}),
            )
            .await
            .unwrap(),
            Some(McpStepUpMutation::UserGroupMembership { .. })
        ));
        let mut ordinary_group = self::tests::group(realm, "ordinary-group");
        ordinary_group.realm_roles = vec![RoleName::new("ordinary-role").unwrap()];
        fixture.state.storage.create_group(&realm.id, &ordinary_group).await.unwrap();
        assert_eq!(
            call(
                &fixture,
                ToolName::UsersAddToGroup,
                json!({"id": user.id.to_string(), "groupId": ordinary_group.id.to_string()}),
            )
            .await
            .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn deleted_realm_cache_uses_the_approved_realm_name() {
        let fixture = fixture().await;
        let realm = Realm {
            id: RealmId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: RealmName::new("deleted-realm").unwrap(),
            ..Realm::default()
        };
        fixture.state.storage.create_realm(&realm).await.unwrap();
        let cache_key = issuerd_cluster::cache_keys::realm_by_name(realm.name.as_str());
        fixture
            .state
            .cache
            .set(&cache_key, serde_json::to_vec(&realm).unwrap(), None)
            .await
            .unwrap();
        fixture.state.storage.delete_realm(&realm.id).await.unwrap();
        let now = chrono::Utc::now().timestamp();
        let grant = McpStepUpGrant {
            version: 1,
            operation_id: uuid::Uuid::new_v4().to_string(),
            operation_hash: "hash".into(),
            canonicalization_version: 1,
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("admin-cli").unwrap(),
            subject_user_id: fixture.user.id.clone(),
            resource: "https://issuer.example/realms/deleted-realm/mcp".into(),
            tool: "realm_delete".into(),
            mutation: McpStepUpMutation::DeleteRealm { expected: realm },
            origin_access_token_jti: "origin".into(),
            token_jti: JwtId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            dpop_jkt: "jkt".into(),
            approval_auth_time: now,
            approval_acr: None,
            approval_amr: vec!["pwd".into()],
            status: McpStepUpExecutionStatus::Succeeded,
            result_json: None,
            issued_at: now,
            expires_at: now + 120,
            updated_at: now,
        };
        committed(&fixture.state, &grant).await;
        assert!(fixture.state.cache.get(&cache_key).await.unwrap().is_none());
    }
}
