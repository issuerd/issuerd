// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Protocol-mapper driven claim assembly: scope resolution, mapper evaluation, role claims.

//! Protocol-mapper driven claim assembly.
//!
//! `issuerd-token` stays pure: it signs whatever claims it is given. This module is
//! where the *content* of tokens is decided: granted scope names are resolved
//! to [`ClientScope`] resources, their protocol mappers (plus the client-local
//! mappers on the client itself) are evaluated, and role claims are computed
//! from the user's effective role mappings, honoring `full_scope_allowed` and
//! per-client / per-scope scope-mappings.
//!
//! The result is a `serde_json::Map` "claims overlay" passed to
//! `TokenManager::issue_*` (access/ID tokens) or merged into the userinfo
//! response body.
//!
//! Pure mapper evaluation ([`evaluate_mappers`]) is storage-free and unit
//! tested directly; the async helpers only gather data, and all gathering
//! goes through the epoch-validated claims read-model cache
//! ([`crate::claims_cache`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::{Map, Value};

use issuerd_core::{
    expand_composites, mapper_config, ClaimTarget, Client, ClientId, ClientScope, Group,
    IssuerdError, MapperType, ProtocolMapper, RealmId, Role, RoleId, RoleName, ScopeMappings, User,
};

use crate::claims_cache::{ClaimsReader, UserClaims};
use crate::state::ServerState;

// ---------------------------------------------------------------------------
// Effective roles
// ---------------------------------------------------------------------------

/// A user's effective roles for a token, after group expansion, composite
/// resolution, and scope-mapping filtering.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EffectiveRoles {
    /// Realm role names, sorted and deduped.
    pub realm_roles: Vec<RoleName>,
    /// Client role names keyed by the OWNING client's `client_id` string
    /// (the `resource_access.{client}.roles` shape), sorted and deduped.
    pub client_roles: HashMap<String, Vec<RoleName>>,
}

/// Everything [`evaluate_mappers`] needs, pre-fetched by the caller.
pub struct MapperInput<'a> {
    pub user: &'a User,
    /// The client the token is issued for. `None` only in degraded paths
    /// (e.g. userinfo for a since-deleted client): client-local mappers,
    /// audience/web-origin mappers, and scope-mapping filtering are skipped.
    pub client: Option<&'a Client>,
    /// Groups the user belongs to (for the group-membership mapper).
    pub groups: &'a [Group],
    /// Effective roles (already scope-mapping filtered for this client).
    pub roles: &'a EffectiveRoles,
}

// ---------------------------------------------------------------------------
// Pure mapper evaluation
// ---------------------------------------------------------------------------

/// Coerce a raw string value to the configured JSON type. Returns `None`
/// (claim skipped) when the coercion fails.
fn typed_value(raw: &str, json_type: Option<&str>) -> Option<Value> {
    match json_type {
        Some("long") | Some("int") => raw.parse::<i64>().ok().map(Value::from),
        Some("double") => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number),
        Some("boolean") => raw.parse::<bool>().ok().map(Value::from),
        Some("JSON") => serde_json::from_str(raw).ok(),
        _ => Some(Value::String(raw.to_string())),
    }
}

fn insert_value(
    out: &mut Map<String, Value>,
    claim: &str,
    values: &[String],
    json_type: Option<&str>,
    multivalued: bool,
) {
    if multivalued {
        let vals: Vec<Value> = values.iter().filter_map(|v| typed_value(v, json_type)).collect();
        if !vals.is_empty() {
            out.insert(claim.to_string(), Value::Array(vals));
        }
    } else if let Some(first) = values.first() {
        if let Some(v) = typed_value(first, json_type) {
            out.insert(claim.to_string(), v);
        }
    }
}

/// Raw string value of a built-in user property.
fn user_property_value(user: &User, property: &str) -> Option<String> {
    match property {
        "username" => Some(user.username.as_str().to_string()),
        "email" => user.email.as_ref().map(|e| e.as_str().to_string()).filter(|s| !s.is_empty()),
        "firstName" => user.first_name.as_ref().map(|n| n.as_str().to_string()),
        "lastName" => user.last_name.as_ref().map(|n| n.as_str().to_string()),
        "emailVerified" => Some(user.email_verified.to_string()),
        "updatedAt" => Some(user.updated_at.timestamp().to_string()),
        _ => None,
    }
}

/// The user's full name: `first last`, a single part when only one is set,
/// falling back to the username when neither is set (legacy behavior).
fn full_name(user: &User) -> String {
    match (&user.first_name, &user.last_name) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.to_string(),
        (None, Some(l)) => l.to_string(),
        (None, None) => user.username.to_string(),
    }
}

const ADDRESS_FIELDS: [(&str, &str); 6] = [
    ("formatted", "address_formatted"),
    ("street_address", "address_street"),
    ("locality", "address_locality"),
    ("region", "address_region"),
    ("postal_code", "address_postal_code"),
    ("country", "address_country"),
];

fn address_object(user: &User) -> Map<String, Value> {
    let mut address = Map::new();
    for (field, attr_key) in ADDRESS_FIELDS {
        if let Some(v) = user.attributes.get(attr_key).and_then(|vals| vals.first()) {
            address.insert(field.to_string(), Value::String(v.clone()));
        }
    }
    address
}

/// Evaluate one mapper for one target, inserting produced claims into `out`.
fn evaluate_mapper(
    mapper: &ProtocolMapper,
    input: &MapperInput,
    target: ClaimTarget,
    out: &mut Map<String, Value>,
) {
    let json_type = mapper.config_value(mapper_config::JSON_TYPE);
    let multivalued = mapper.config_flag(mapper_config::MULTIVALUED, false);
    match mapper.mapper_type {
        MapperType::UserAttribute => {
            let Some(attr) = mapper.config_value(mapper_config::USER_ATTRIBUTE) else {
                return;
            };
            let claim = mapper.config_value(mapper_config::CLAIM_NAME).unwrap_or(attr).to_string();
            if let Some(values) = input.user.attributes.get(attr) {
                insert_value(out, &claim, values, json_type, multivalued);
            }
        }
        MapperType::UserProperty => {
            let Some(property) = mapper.config_value(mapper_config::USER_PROPERTY) else {
                return;
            };
            let claim =
                mapper.config_value(mapper_config::CLAIM_NAME).unwrap_or(property).to_string();
            if let Some(raw) = user_property_value(input.user, property) {
                if let Some(v) = typed_value(&raw, json_type) {
                    out.insert(claim, v);
                }
            }
        }
        MapperType::FullName => {
            out.insert("name".to_string(), Value::String(full_name(input.user)));
        }
        MapperType::Address => {
            let address = address_object(input.user);
            // Byte-compat with the hardcoded logic that predates client
            // scopes: the ID token
            // only carried `address` when at least one field was present,
            // while userinfo always emitted the (possibly empty) object.
            if !address.is_empty() || target == ClaimTarget::UserInfo {
                out.insert("address".to_string(), Value::Object(address));
            }
        }
        MapperType::GroupMembership => {
            let claim =
                mapper.config_value(mapper_config::CLAIM_NAME).unwrap_or("groups").to_string();
            let full_path = mapper.config_flag(mapper_config::FULL_PATH, false);
            let vals: Vec<Value> = input
                .groups
                .iter()
                .map(|g| {
                    if full_path {
                        Value::String(g.path.to_string())
                    } else {
                        Value::String(g.name.to_string())
                    }
                })
                .collect();
            out.insert(claim, Value::Array(vals));
        }
        MapperType::RealmRoleList => {
            if !input.roles.realm_roles.is_empty() {
                out.insert(
                    "realm_access".to_string(),
                    serde_json::json!({ "roles": input.roles.realm_roles }),
                );
            }
        }
        MapperType::ClientRoleList => {
            let filter = mapper.config_value(mapper_config::CLIENT_ROLE_MAPPING_CLIENT_ID);
            let resource_access: Map<String, Value> = input
                .roles
                .client_roles
                .iter()
                .filter(|(client_id, _)| filter.is_none_or(|f| f == client_id.as_str()))
                .map(|(client_id, roles)| {
                    (client_id.clone(), serde_json::json!({ "roles": roles }))
                })
                .collect();
            if !resource_access.is_empty() {
                out.insert("resource_access".to_string(), Value::Object(resource_access));
            }
        }
        MapperType::Audience => {
            let Some(client) = input.client else { return };
            let mut audiences: Vec<String> = vec![client.client_id.to_string()];
            for key in [
                mapper_config::INCLUDED_CLIENT_AUDIENCE,
                mapper_config::INCLUDED_CUSTOM_AUDIENCE,
            ] {
                if let Some(extra) = mapper.config_value(key) {
                    if !audiences.iter().any(|a| a == extra) {
                        audiences.push(extra.to_string());
                    }
                }
            }
            // Only override the typed single-value `aud` claim when the mapper
            // actually adds an audience.
            if audiences.len() > 1 {
                out.insert("aud".to_string(), serde_json::json!(audiences));
            }
        }
        MapperType::AllowedWebOrigins => {
            let Some(client) = input.client else { return };
            if !client.web_origins.is_empty() {
                let origins: Vec<String> =
                    client.web_origins.iter().map(|o| o.to_string()).collect();
                out.insert("allowed_origins".to_string(), serde_json::json!(origins));
            }
        }
    }
}

/// Pure evaluation of a mapper set for one claim target.
pub fn evaluate_mappers(
    mappers: &[&ProtocolMapper],
    input: &MapperInput,
    target: ClaimTarget,
) -> Map<String, Value> {
    let mut out = Map::new();
    for mapper in mappers {
        if mapper.applies_to(target) {
            evaluate_mapper(mapper, input, target, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Async gathering (via the claims read-model cache)
// ---------------------------------------------------------------------------

/// Resolve granted scope names to client-scope resources of the realm, in
/// input order; unknown names (resource-less scope tokens) silently
/// contribute no mappers. Resolved in Rust against the realm catalog — the
/// batched `get_client_scopes_by_names` contract, served from cache.
fn resolve_client_scopes(
    catalog: &[ClientScope],
    granted_scope_names: &[String],
) -> Vec<ClientScope> {
    granted_scope_names
        .iter()
        .filter_map(|name| catalog.iter().find(|s| &s.name == name).cloned())
        .collect()
}

/// Union of scope-mappings across the client and all granted client scopes.
fn allowed_scope_roles<'a>(
    client: &'a Client,
    granted_scopes: &'a [ClientScope],
) -> (HashSet<&'a RoleId>, HashMap<&'a ClientId, HashSet<&'a RoleId>>) {
    let mut realm: HashSet<&RoleId> = client.scope_mappings.realm_roles.iter().collect();
    let mut clients: HashMap<&ClientId, HashSet<&RoleId>> = HashMap::new();
    for (client_id, ids) in &client.scope_mappings.client_roles {
        clients.entry(client_id).or_default().extend(ids.iter());
    }
    for scope in granted_scopes {
        let ScopeMappings {
            realm_roles,
            client_roles,
        } = &scope.scope_mappings;
        realm.extend(realm_roles.iter());
        for (client_id, ids) in client_roles {
            clients.entry(client_id).or_default().extend(ids.iter());
        }
    }
    (realm, clients)
}

/// Compute a user's effective roles for a token issued to `client`.
///
/// Sources: direct user role mappings (realm + client), group role mappings,
/// composite expansion — all resolved in Rust against the cached realm role
/// catalog and the user's cached claims bundle. When
/// `client.full_scope_allowed` is false the result is intersected with the
/// union of the client's and the granted scopes' scope-mappings.
/// Unresolvable pieces degrade to "no roles" (the pre-cache per-query
/// leniency of token issuance).
async fn gather_effective_roles(
    reader: &ClaimsReader<'_>,
    catalog_roles: &[Role],
    client: Option<&Client>,
    claims: &UserClaims,
    granted_scopes: &[ClientScope],
) -> EffectiveRoles {
    let mut seeds: Vec<Role> = Vec::new();

    // Direct user mappings (stored ids resolve against the catalog).
    let direct_ids: HashSet<&RoleId> =
        claims.realm_role_ids.iter().chain(claims.client_role_ids.iter()).collect();
    seeds.extend(catalog_roles.iter().filter(|r| direct_ids.contains(&r.id)).cloned());

    // Group realm-role mappings (stored as names on the group row).
    let realm_by_name: HashMap<&str, &Role> = catalog_roles
        .iter()
        .filter(|r| !r.client_role)
        .map(|r| (r.name.as_str(), r))
        .collect();
    for group in &claims.groups {
        for name in &group.realm_roles {
            if let Some(role) = realm_by_name.get(name.as_str()) {
                seeds.push((*role).clone());
            }
        }
    }
    // Group client-role mappings: the groups' (owning client uuid, role name)
    // pairs resolve against the catalog in Rust (replaces one batched query
    // per owning client).
    let owner_names: HashSet<(&ClientId, &str)> = claims
        .groups
        .iter()
        .flat_map(|group| {
            group
                .client_roles
                .iter()
                .flat_map(|(owner_id, names)| names.iter().map(move |n| (owner_id, n.as_str())))
        })
        .collect();
    seeds.extend(
        catalog_roles
            .iter()
            .filter(|role| {
                role.client_role
                    && role
                        .client_id
                        .as_ref()
                        .is_some_and(|owner| owner_names.contains(&(owner, role.name.as_str())))
            })
            .cloned(),
    );

    let expanded = expand_composites(seeds, catalog_roles);

    // Scope-mapping filtering (only when the client subsets token roles).
    let full_scope_allowed = client.map(|c| c.full_scope_allowed).unwrap_or(true);
    let filtered: Vec<Role> = if full_scope_allowed {
        expanded
    } else {
        let Some(client) = client else {
            return EffectiveRoles::default();
        };
        let (allowed_realm, allowed_clients) = allowed_scope_roles(client, granted_scopes);
        expanded
            .into_iter()
            .filter(|role| match &role.client_id {
                None => allowed_realm.contains(&role.id),
                Some(owner) => allowed_clients.get(owner).is_some_and(|ids| ids.contains(&role.id)),
            })
            .collect()
    };

    // Resolve owning-client display ids for the resource_access shape through
    // the cached uuid→identifier reverse map: one unresolvable owner now only
    // drops that owner's roles (the previous batched lookup dropped all
    // client roles when the batch query itself failed).
    let mut realm_names: Vec<RoleName> = Vec::new();
    let mut owner_ids: HashSet<ClientId> = HashSet::new();
    for role in &filtered {
        if role.client_role {
            if let Some(owner) = &role.client_id {
                owner_ids.insert(owner.clone());
            }
        } else {
            realm_names.push(role.name.clone());
        }
    }
    let mut owner_identifiers: HashMap<ClientId, String> = HashMap::new();
    for owner in owner_ids {
        if let Some(identifier) = reader.client_identifier_by_uuid(&owner).await {
            owner_identifiers.insert(owner, identifier);
        }
    }
    let mut client_roles: HashMap<String, Vec<RoleName>> = HashMap::new();
    for role in filtered {
        if let (true, Some(owner)) = (role.client_role, &role.client_id) {
            if let Some(identifier) = owner_identifiers.get(owner) {
                client_roles.entry(identifier.clone()).or_default().push(role.name.clone());
            }
        }
    }

    realm_names.sort();
    realm_names.dedup();
    for names in client_roles.values_mut() {
        names.sort();
        names.dedup();
    }
    EffectiveRoles {
        realm_roles: realm_names,
        client_roles,
    }
}

/// Build the claims overlay for one issuance target.
///
/// Pipeline: granted scope names → client-scope resources → mappers (scope
/// mappers + client-local mappers) filtered by target → evaluate against the
/// user's effective roles/groups. Returns an empty map when nothing applies
/// (callers pass `Some(overlay)` unconditionally; empty overlays are cheap).
///
/// For the access-token target the name set additionally includes the
/// client's *default-assigned* client scopes, mirroring Keycloak's "default
/// scopes always apply" rule. This is what keeps `realm_access`/
/// `resource_access` flowing even when the request's scope list does not
/// name the `roles` scope (pre-client-scopes behavior was unconditional
/// `realm_access` in access tokens). ID-token and userinfo targets resolve
/// strictly from the granted names, preserving the exact pre-client-scopes
/// claim shapes there.
///
/// All gathering goes through the claims read-model cache ([`ClaimsReader`]):
/// warm-cache calls cost no storage queries. Mapper evaluation sees the
/// caller's `user` (freshly authenticated at issuance); the cached bundle
/// supplies the group rows and direct role-mapping ids.
pub async fn build_claims_overlay(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    client: Option<&Client>,
    user: &User,
    granted_scope_names: &[String],
    target: ClaimTarget,
) -> Result<Map<String, Value>, IssuerdError> {
    let reader = ClaimsReader::new(state, realm_id);
    let catalog = reader.realm_catalog().await;

    let mut names: Vec<String> = granted_scope_names.to_vec();
    if target == ClaimTarget::AccessToken {
        if let Some(client) = client {
            // Default-assigned scopes always apply: the cached assignment ids
            // resolve to names against the catalog.
            for scope_id in reader.client_default_scope_ids(&client.id).await {
                if let Some(scope) = catalog.scopes.iter().find(|s| s.id == scope_id) {
                    if !names.iter().any(|n| n == &scope.name) {
                        names.push(scope.name.clone());
                    }
                }
            }
        }
    }
    let scopes = resolve_client_scopes(&catalog.scopes, &names);

    let mut mappers: Vec<&ProtocolMapper> = Vec::new();
    for scope in &scopes {
        mappers.extend(scope.protocol_mappers.iter());
    }
    if let Some(client) = client {
        mappers.extend(client.protocol_mappers.iter());
    }
    mappers.retain(|m| m.applies_to(target));
    if mappers.is_empty() {
        return Ok(Map::new());
    }

    let needs_roles = mappers
        .iter()
        .any(|m| matches!(m.mapper_type, MapperType::RealmRoleList | MapperType::ClientRoleList));
    let needs_groups =
        needs_roles || mappers.iter().any(|m| m.mapper_type == MapperType::GroupMembership);

    // One bundle read covers the group rows and the direct role-mapping ids.
    // A missing bundle (deleted user, storage error) degrades to empty — the
    // pre-cache per-query leniency degraded the same way.
    let claims = if needs_groups {
        reader.user_claims(&user.id).await
    } else {
        None
    };
    let groups: &[Group] = claims.as_ref().map_or(&[], |c| c.groups.as_slice());
    let roles = match (needs_roles, &claims) {
        (true, Some(claims)) => {
            gather_effective_roles(&reader, &catalog.roles, client, claims, &scopes).await
        }
        _ => EffectiveRoles::default(),
    };

    let input = MapperInput {
        user,
        client,
        groups,
        roles: &roles,
    };
    Ok(evaluate_mappers(&mappers, &input, target))
}

/// Username of the dedicated service-account user backing a client's
/// client-credentials grant (Keycloak naming).
pub fn service_account_username(client: &Client) -> String {
    format!("service-account-{}", client.client_id)
}

/// Merge RAR `authorization_details` (RFC 9396 §9.1) into a claims
/// overlay. Same mechanics as DPoP's `bind_cnf_overlay`: the claim is injected
/// post-mapper-evaluation and read back through the typed
/// `AccessTokenClaims.authorization_details` field on the validation surface.
pub(crate) fn bind_authorization_details_overlay(
    overlay: Option<Map<String, Value>>,
    authorization_details: Option<&[Value]>,
) -> Option<Map<String, Value>> {
    match (overlay, authorization_details) {
        (overlay, None) => overlay,
        (overlay, Some(details)) => {
            let mut map = overlay.unwrap_or_default();
            map.insert("authorization_details".to_string(), Value::Array(details.to_vec()));
            Some(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        ClientAuthenticatorType, ClientIdentifier, ClientProtocol, DisplayName, Email, GroupId,
        GroupName, GroupPath, MapperId, RealmId, Scope, UserId, Username, WebOrigin,
    };

    fn test_user() -> User {
        let mut attributes = HashMap::new();
        attributes.insert("department".to_string(), vec!["engineering".to_string()]);
        attributes.insert("level".to_string(), vec!["7".to_string(), "8".to_string()]);
        attributes.insert("phone_number".to_string(), vec!["+1-555".to_string()]);
        attributes.insert("phone_number_verified".to_string(), vec!["true".to_string()]);
        attributes.insert("address_locality".to_string(), vec!["Springfield".to_string()]);
        attributes.insert("prefs".to_string(), vec![r#"{"theme":"dark"}"#.to_string()]);
        User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes,
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn test_client() -> Client {
        Client {
            id: ClientId::new("client-uuid-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("secret".into()),
            redirect_uris: vec![],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: Scope::parse("openid profile email"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: vec![],
            scope_mappings: ScopeMappings::default(),
            attributes: HashMap::new(),
        }
    }

    fn mapper(name: &str, mapper_type: MapperType, config: &[(&str, &str)]) -> ProtocolMapper {
        ProtocolMapper {
            id: MapperId::new(format!("m-{name}")).unwrap(),
            name: name.to_string(),
            mapper_type,
            config: config.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn empty_roles() -> EffectiveRoles {
        EffectiveRoles::default()
    }

    fn input<'a>(
        user: &'a User,
        client: Option<&'a Client>,
        groups: &'a [Group],
        roles: &'a EffectiveRoles,
    ) -> MapperInput<'a> {
        MapperInput {
            user,
            client,
            groups,
            roles,
        }
    }

    #[test]
    fn bind_authorization_details_overlay_merges_claim() {
        // None input: overlay passes through untouched.
        assert_eq!(bind_authorization_details_overlay(None, None), None);
        let mut existing = Map::new();
        existing.insert("sub_claim".to_string(), Value::String("x".into()));
        assert_eq!(
            bind_authorization_details_overlay(Some(existing.clone()), None),
            Some(existing.clone())
        );

        // Details are inserted as a JSON array, preserving other overlay keys.
        let details = vec![serde_json::json!({"type": "payment_initiation"})];
        let out = bind_authorization_details_overlay(Some(existing), Some(&details)).unwrap();
        assert_eq!(out.get("authorization_details"), Some(&Value::Array(details.clone())));
        assert_eq!(out.get("sub_claim"), Some(&Value::String("x".into())));

        // No pre-existing overlay: one is created.
        let out = bind_authorization_details_overlay(None, Some(&details)).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn user_attribute_mapper_string_first_value() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let m = mapper(
            "dept",
            MapperType::UserAttribute,
            &[("user.attribute", "department"), ("claim.name", "dept")],
        );
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(out.get("dept"), Some(&Value::String("engineering".into())));
    }

    #[test]
    fn user_attribute_mapper_multivalued_and_long() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let m = mapper(
            "levels",
            MapperType::UserAttribute,
            &[
                ("user.attribute", "level"),
                ("claim.name", "levels"),
                ("multivalued", "true"),
                ("jsonType.label", "long"),
            ],
        );
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert_eq!(out.get("levels"), Some(&serde_json::json!([7, 8])));
    }

    #[test]
    fn user_attribute_mapper_json_type_parses_json() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let m = mapper(
            "prefs",
            MapperType::UserAttribute,
            &[
                ("user.attribute", "prefs"),
                ("claim.name", "prefs"),
                ("jsonType.label", "JSON"),
            ],
        );
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert_eq!(out.get("prefs"), Some(&serde_json::json!({"theme": "dark"})));
    }

    #[test]
    fn user_attribute_mapper_skips_missing_and_bad_values() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let missing = mapper(
            "missing",
            MapperType::UserAttribute,
            &[("user.attribute", "nope"), ("claim.name", "nope")],
        );
        let bad_long = mapper(
            "bad",
            MapperType::UserAttribute,
            &[
                ("user.attribute", "department"),
                ("claim.name", "dept_num"),
                ("jsonType.label", "long"),
            ],
        );
        let out = evaluate_mappers(
            &[&missing, &bad_long],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn user_property_mapper_covers_builtin_properties() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let mk = |property: &str, claim: &str, jt: Option<&str>| {
            let mut cfg = vec![("user.property", property), ("claim.name", claim)];
            if let Some(jt) = jt {
                cfg.push(("jsonType.label", jt));
            }
            mapper(property, MapperType::UserProperty, &cfg)
        };
        let mappers = [
            mk("username", "preferred_username", None),
            mk("email", "email", None),
            mk("firstName", "given_name", None),
            mk("lastName", "family_name", None),
            mk("emailVerified", "email_verified", Some("boolean")),
            mk("updatedAt", "updated_at", Some("long")),
        ];
        let refs: Vec<&ProtocolMapper> = mappers.iter().collect();
        let out = evaluate_mappers(
            &refs,
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        assert_eq!(out.get("preferred_username"), Some(&Value::String("alice".into())));
        assert_eq!(out.get("email"), Some(&Value::String("alice@example.com".into())));
        assert_eq!(out.get("given_name"), Some(&Value::String("Alice".into())));
        assert_eq!(out.get("family_name"), Some(&Value::String("Smith".into())));
        assert_eq!(out.get("email_verified"), Some(&Value::Bool(true)));
        assert!(matches!(out.get("updated_at"), Some(Value::Number(_))));
    }

    #[test]
    fn user_property_email_skipped_when_missing() {
        let mut user = test_user();
        user.email = None;
        let client = test_client();
        let roles = empty_roles();
        let m = mapper(
            "email",
            MapperType::UserProperty,
            &[("user.property", "email"), ("claim.name", "email")],
        );
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn full_name_fallbacks() {
        let mut user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let m = mapper("full name", MapperType::FullName, &[]);
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        assert_eq!(out.get("name"), Some(&Value::String("Alice Smith".into())));

        user.last_name = None;
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        assert_eq!(out.get("name"), Some(&Value::String("Alice".into())));

        user.first_name = None;
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        assert_eq!(out.get("name"), Some(&Value::String("alice".into())));
    }

    #[test]
    fn address_mapper_empty_object_only_in_userinfo() {
        let mut user = test_user();
        user.attributes.remove("address_locality");
        let client = test_client();
        let roles = empty_roles();
        let m = mapper("address", MapperType::Address, &[]);
        let id_out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        assert!(id_out.get("address").is_none());
        let ui_out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert_eq!(ui_out.get("address"), Some(&serde_json::json!({})));

        // With data: nested object with the present field only.
        user.attributes.insert("address_country".to_string(), vec!["US".to_string()]);
        let ui_out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert_eq!(ui_out.get("address"), Some(&serde_json::json!({"country": "US"})));
    }

    #[test]
    fn group_membership_names_and_full_paths() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let groups = vec![Group {
            id: GroupId::new("g1").unwrap(),
            name: GroupName::new("devs").unwrap(),
            path: GroupPath::new("/devs").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        }];
        let names = mapper("groups", MapperType::GroupMembership, &[]);
        let out = evaluate_mappers(
            &[&names],
            &input(&user, Some(&client), &groups, &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(out.get("groups"), Some(&serde_json::json!(["devs"])));

        let paths = mapper("gpaths", MapperType::GroupMembership, &[("full.path", "true")]);
        let out = evaluate_mappers(
            &[&paths],
            &input(&user, Some(&client), &groups, &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(out.get("groups"), Some(&serde_json::json!(["/devs"])));
    }

    #[test]
    fn role_mappers_emit_access_claims() {
        let user = test_user();
        let client = test_client();
        let roles = EffectiveRoles {
            realm_roles: vec![RoleName::new("admin").unwrap()],
            client_roles: HashMap::from([(
                "my-app".to_string(),
                vec![RoleName::new("editor").unwrap()],
            )]),
        };
        let rm = mapper("realm roles", MapperType::RealmRoleList, &[]);
        let cm = mapper("client roles", MapperType::ClientRoleList, &[]);
        let out = evaluate_mappers(
            &[&rm, &cm],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(out.get("realm_access"), Some(&serde_json::json!({"roles": ["admin"]})));
        assert_eq!(
            out.get("resource_access"),
            Some(&serde_json::json!({"my-app": {"roles": ["editor"]}}))
        );

        // Empty roles -> claims omitted entirely.
        let roles = empty_roles();
        let out = evaluate_mappers(
            &[&rm, &cm],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn client_role_mapper_can_restrict_to_one_client() {
        let user = test_user();
        let client = test_client();
        let roles = EffectiveRoles {
            realm_roles: vec![],
            client_roles: HashMap::from([
                ("my-app".to_string(), vec![RoleName::new("editor").unwrap()]),
                ("other".to_string(), vec![RoleName::new("viewer").unwrap()]),
            ]),
        };
        let m = mapper(
            "only-my-app",
            MapperType::ClientRoleList,
            &[("usermodel.clientRoleMapping.clientId", "my-app")],
        );
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(
            out.get("resource_access"),
            Some(&serde_json::json!({"my-app": {"roles": ["editor"]}}))
        );
    }

    #[test]
    fn audience_mapper_extends_aud_only_when_adding() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let noop = mapper("aud-noop", MapperType::Audience, &[]);
        let out = evaluate_mappers(
            &[&noop],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert!(out.is_empty());

        let add = mapper(
            "aud-add",
            MapperType::Audience,
            &[
                ("included.client.audience", "backend-api"),
                ("included.custom.audience", "extra"),
            ],
        );
        let out = evaluate_mappers(
            &[&add],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(out.get("aud"), Some(&serde_json::json!(["my-app", "backend-api", "extra"])));
    }

    #[test]
    fn allowed_web_origins_mapper() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let m = mapper("origins", MapperType::AllowedWebOrigins, &[]);
        let out = evaluate_mappers(
            &[&m],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert_eq!(
            out.get("allowed_origins"),
            Some(&serde_json::json!(["https://app.example.com"]))
        );

        // No client (degraded path) -> nothing.
        let out =
            evaluate_mappers(&[&m], &input(&user, None, &[], &roles), ClaimTarget::AccessToken);
        assert!(out.is_empty());
    }

    #[test]
    fn target_flags_gate_evaluation() {
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let id_only = mapper(
            "id-only",
            MapperType::UserProperty,
            &[
                ("user.property", "username"),
                ("claim.name", "preferred_username"),
                ("access.token.claim", "false"),
                ("id.token.claim", "true"),
                ("userinfo.token.claim", "false"),
            ],
        );
        let access = evaluate_mappers(
            &[&id_only],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::AccessToken,
        );
        assert!(access.is_empty());
        let id = evaluate_mappers(
            &[&id_only],
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        assert_eq!(id.get("preferred_username"), Some(&Value::String("alice".into())));
    }

    #[test]
    fn builtin_seed_mappers_reproduce_legacy_claims() {
        // The seeded profile/email/phone mappers must produce exactly the
        // claims the hardcoded logic emitted (for the ID-token/userinfo targets).
        let user = test_user();
        let client = test_client();
        let roles = empty_roles();
        let scopes = issuerd_core::builtin_client_scopes(&RealmId::new("realm-1").unwrap());
        let mappers: Vec<&ProtocolMapper> = scopes
            .iter()
            .filter(|s| ["profile", "email", "phone"].contains(&s.name.as_str()))
            .flat_map(|s| s.protocol_mappers.iter())
            .collect();
        let out = evaluate_mappers(
            &mappers,
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::IdToken,
        );
        for key in [
            "preferred_username",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
        ] {
            assert!(out.contains_key(key), "missing claim {key}");
        }
        // userinfo-only claims must not leak into the ID token.
        assert!(!out.contains_key("updated_at"));
        let ui = evaluate_mappers(
            &mappers,
            &input(&user, Some(&client), &[], &roles),
            ClaimTarget::UserInfo,
        );
        assert!(ui.contains_key("updated_at"));
    }
}
