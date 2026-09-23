// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client scopes and protocol mappers (Keycloak-style claim mappings and role subsetting).

//! Client scopes and protocol mappers.
//!
//! Mirrors the Keycloak domain model: a [`ClientScope`] is a named, reusable
//! bundle of [`ProtocolMapper`]s (claim mappings) and [`ScopeMappings`] (role
//! subsetting). Clients are assigned scopes as *default* (always granted) or
//! *optional* (granted only when requested via the `scope` parameter). The
//! effective claim set of a token is the union of the mappers from every
//! granted scope plus the client-local mappers on the client itself.
//!
//! Built-in scopes ([`builtin_client_scopes`]) are seeded per realm and
//! reproduce the claim behavior that was hardcoded before client scopes were
//! introduced: `profile`, `email`, `address`, `phone`, `roles`,
//! `offline_access`, `web-origins`, and `acr`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ids::{ClientId, ClientScopeId, MapperId, RealmId, RoleId};
use crate::models::ClientProtocol;

// ---------------------------------------------------------------------------
// Mapper config keys (Keycloak wire spellings)
// ---------------------------------------------------------------------------

/// Well-known keys inside [`ProtocolMapper::config`].
pub mod mapper_config {
    /// User attribute name to read (user-attribute mapper).
    pub const USER_ATTRIBUTE: &str = "user.attribute";
    /// User property name to read (user-property mapper): `username`,
    /// `email`, `firstName`, `lastName`, `emailVerified`, `updatedAt`.
    pub const USER_PROPERTY: &str = "user.property";
    /// Claim name to write.
    pub const CLAIM_NAME: &str = "claim.name";
    /// JSON type of the emitted claim: `String` (default), `long`, `boolean`,
    /// or `JSON` (the attribute value is parsed as JSON).
    pub const JSON_TYPE: &str = "jsonType.label";
    /// Emit all attribute values as a JSON array instead of the first value.
    pub const MULTIVALUED: &str = "multivalued";
    /// Group-membership mapper: emit full group paths instead of names.
    pub const FULL_PATH: &str = "full.path";
    /// Audience mapper: client_id whose audience is added to `aud`.
    pub const INCLUDED_CLIENT_AUDIENCE: &str = "included.client.audience";
    /// Audience mapper: literal audience string added to `aud`.
    pub const INCLUDED_CUSTOM_AUDIENCE: &str = "included.custom.audience";
    /// Client-role-list mapper: restrict to roles of this client_id.
    pub const CLIENT_ROLE_MAPPING_CLIENT_ID: &str = "usermodel.clientRoleMapping.clientId";
    /// Include the claim in access tokens.
    pub const ACCESS_TOKEN_CLAIM: &str = "access.token.claim";
    /// Include the claim in ID tokens.
    pub const ID_TOKEN_CLAIM: &str = "id.token.claim";
    /// Include the claim in userinfo responses.
    pub const USERINFO_TOKEN_CLAIM: &str = "userinfo.token.claim";
}

/// Claim destination a mapper applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimTarget {
    AccessToken,
    IdToken,
    UserInfo,
}

/// Protocol mapper types, serialized with the Keycloak `protocolMapper` ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum MapperType {
    /// Maps a user attribute to a token claim.
    #[serde(rename = "oidc-usermodel-attribute-mapper")]
    UserAttribute,
    /// Maps a built-in user property (username, email, ...) to a claim.
    #[serde(rename = "oidc-usermodel-property-mapper")]
    UserProperty,
    /// Maps the user's full name to the `name` claim.
    #[serde(rename = "oidc-full-name-mapper")]
    FullName,
    /// Maps `address_*` user attributes to the nested `address` claim.
    #[serde(rename = "oidc-address-mapper")]
    Address,
    /// Maps the user's group memberships to a claim.
    #[serde(rename = "oidc-group-membership-mapper")]
    GroupMembership,
    /// Populates `realm_access.roles`.
    #[serde(rename = "oidc-usermodel-realm-role-mapper")]
    RealmRoleList,
    /// Populates `resource_access.{client}.roles`.
    #[serde(rename = "oidc-usermodel-client-role-mapper")]
    ClientRoleList,
    /// Adds audiences to the `aud` claim.
    #[serde(rename = "oidc-audience-mapper")]
    Audience,
    /// Populates the `allowed_origins` claim from the client web origins.
    #[serde(rename = "oidc-allowed-origins-mapper")]
    AllowedWebOrigins,
}

impl MapperType {
    /// All mapper types, in stable display order.
    pub const ALL: &'static [MapperType] = &[
        MapperType::UserAttribute,
        MapperType::UserProperty,
        MapperType::FullName,
        MapperType::Address,
        MapperType::GroupMembership,
        MapperType::RealmRoleList,
        MapperType::ClientRoleList,
        MapperType::Audience,
        MapperType::AllowedWebOrigins,
    ];

    /// Human-readable label for admin UIs.
    pub fn label(self) -> &'static str {
        match self {
            MapperType::UserAttribute => "User Attribute",
            MapperType::UserProperty => "User Property",
            MapperType::FullName => "Full Name",
            MapperType::Address => "User Address",
            MapperType::GroupMembership => "Group Membership",
            MapperType::RealmRoleList => "User Realm Role",
            MapperType::ClientRoleList => "User Client Role",
            MapperType::Audience => "Audience",
            MapperType::AllowedWebOrigins => "Allowed Web Origins",
        }
    }

    /// One-line description surfaced through the enums API.
    pub fn description(self) -> &'static str {
        match self {
            MapperType::UserAttribute => {
                "Map a custom user attribute to a token claim, with optional JSON typing"
            }
            MapperType::UserProperty => {
                "Map a built-in user property (username, email, first/last name, ...) to a claim"
            }
            MapperType::FullName => "Map the user's first + last name to the `name` claim",
            MapperType::Address => "Map address_* user attributes to the nested `address` claim",
            MapperType::GroupMembership => "Map the user's group memberships to a token claim",
            MapperType::RealmRoleList => {
                "Map the user's effective realm roles into the `realm_access` claim"
            }
            MapperType::ClientRoleList => {
                "Map the user's effective client roles into the `resource_access` claim"
            }
            MapperType::Audience => "Add an audience to the `aud` claim of the access token",
            MapperType::AllowedWebOrigins => {
                "Map the client's allowed web origins into the `allowed_origins` claim"
            }
        }
    }
}

/// A configurable claim mapping attached to a client or client scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProtocolMapper {
    pub id: MapperId,
    pub name: String,
    pub mapper_type: MapperType,
    /// Mapper configuration; see [`mapper_config`] for well-known keys.
    #[serde(default)]
    pub config: HashMap<String, String>,
}

impl ProtocolMapper {
    /// Read a boolean config flag; missing/unparseable values yield `default`.
    pub fn config_flag(&self, key: &str, default: bool) -> bool {
        self.config.get(key).map_or(default, |v| v == "true")
    }

    /// Read a string config value.
    pub fn config_value(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }

    /// Whether this mapper emits claims for the given target. Missing target
    /// flags default to `true` (Keycloak behavior for API-created mappers).
    pub fn applies_to(&self, target: ClaimTarget) -> bool {
        let key = match target {
            ClaimTarget::AccessToken => mapper_config::ACCESS_TOKEN_CLAIM,
            ClaimTarget::IdToken => mapper_config::ID_TOKEN_CLAIM,
            ClaimTarget::UserInfo => mapper_config::USERINFO_TOKEN_CLAIM,
        };
        self.config_flag(key, true)
    }
}

/// Role subsetting attached to a client or client scope: when a client has
/// `full_scope_allowed = false`, token roles are intersected with the union of
/// the client's own scope-mappings and the scope-mappings of every granted
/// client scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeMappings {
    /// Realm role ids included in tokens.
    #[serde(default)]
    pub realm_roles: Vec<RoleId>,
    /// Client role ids included in tokens, keyed by the owning client.
    #[serde(default)]
    pub client_roles: HashMap<ClientId, Vec<RoleId>>,
}

/// A named, reusable bundle of protocol mappers and scope-mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientScope {
    pub id: ClientScopeId,
    pub realm_id: RealmId,
    pub name: String,
    pub description: Option<String>,
    pub protocol: ClientProtocol,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    #[serde(default)]
    pub protocol_mappers: Vec<ProtocolMapper>,
    #[serde(default)]
    pub scope_mappings: ScopeMappings,
}

/// Names of the built-in client scopes seeded into every realm.
pub const BUILTIN_SCOPE_NAMES: &[&str] = &[
    "profile",
    "email",
    "address",
    "phone",
    "roles",
    "offline_access",
    "web-origins",
    "acr",
];

/// Built-in scopes assigned as *default* scopes to every realm (and mirrored
/// onto new clients that do not declare explicit scope lists).
pub const DEFAULT_DEFAULT_SCOPES: &[&str] = &["profile", "email", "roles"];

/// Built-in scopes assigned as *optional* scopes to every realm.
pub const DEFAULT_OPTIONAL_SCOPES: &[&str] =
    &["address", "phone", "offline_access", "web-origins", "acr"];

/// Whether `name` is one of the built-in client scope names.
pub fn is_builtin_scope_name(name: &str) -> bool {
    BUILTIN_SCOPE_NAMES.contains(&name)
}

fn targets(access: bool, id: bool, userinfo: bool) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(mapper_config::ACCESS_TOKEN_CLAIM.into(), access.to_string());
    cfg.insert(mapper_config::ID_TOKEN_CLAIM.into(), id.to_string());
    cfg.insert(mapper_config::USERINFO_TOKEN_CLAIM.into(), userinfo.to_string());
    cfg
}

fn mapper(
    name: &str,
    mapper_type: MapperType,
    extra: &[(&str, &str)],
    target_flags: (bool, bool, bool),
) -> ProtocolMapper {
    let (access, id, userinfo) = target_flags;
    let mut config = targets(access, id, userinfo);
    for (k, v) in extra {
        config.insert((*k).to_string(), (*v).to_string());
    }
    ProtocolMapper {
        id: MapperId::new(crate::utils::generate_id()).expect("generated id"),
        name: name.to_string(),
        mapper_type,
        config,
    }
}

fn user_property_mapper(
    name: &str,
    property: &str,
    claim: &str,
    json_type: Option<&str>,
    target_flags: (bool, bool, bool),
) -> ProtocolMapper {
    let mut extra = vec![
        (mapper_config::USER_PROPERTY, property),
        (mapper_config::CLAIM_NAME, claim),
    ];
    if let Some(jt) = json_type {
        extra.push((mapper_config::JSON_TYPE, jt));
    }
    mapper(name, MapperType::UserProperty, &extra, target_flags)
}

fn user_attribute_mapper(
    name: &str,
    attribute: &str,
    claim: &str,
    json_type: Option<&str>,
    target_flags: (bool, bool, bool),
) -> ProtocolMapper {
    let mut extra = vec![
        (mapper_config::USER_ATTRIBUTE, attribute),
        (mapper_config::CLAIM_NAME, claim),
    ];
    if let Some(jt) = json_type {
        extra.push((mapper_config::JSON_TYPE, jt));
    }
    mapper(name, MapperType::UserAttribute, &extra, target_flags)
}

fn scope(realm_id: &RealmId, name: &str, mappers: Vec<ProtocolMapper>) -> ClientScope {
    ClientScope {
        id: ClientScopeId::new(crate::utils::generate_id()).expect("generated id"),
        realm_id: realm_id.clone(),
        name: name.to_string(),
        description: Some(format!("OpenID Connect built-in scope: {name}")),
        protocol: ClientProtocol::OpenIdConnect,
        attributes: HashMap::new(),
        protocol_mappers: mappers,
        scope_mappings: ScopeMappings::default(),
    }
}

/// Build the eight built-in client scopes for a realm, with fresh random ids.
///
/// The mapper set reproduces the claim behavior that was hardcoded before
/// client scopes were introduced: `profile`/`email`/`address`/`phone`
/// claims go to ID tokens (pure implicit flow) and userinfo but not access
/// tokens; `roles` populates `realm_access`/`resource_access` on access
/// tokens only. One Keycloak-parity exception: the `username` mapper also
/// targets access tokens, so `preferred_username` is available to access-
/// token consumers (e.g. the admin console's user menu).
pub fn builtin_client_scopes(realm_id: &RealmId) -> Vec<ClientScope> {
    let profile = scope(
        realm_id,
        "profile",
        vec![
            user_property_mapper(
                "username",
                "username",
                "preferred_username",
                None,
                (true, true, true),
            ),
            mapper("full name", MapperType::FullName, &[], (false, true, true)),
            user_property_mapper(
                "given name",
                "firstName",
                "given_name",
                None,
                (false, true, true),
            ),
            user_property_mapper(
                "family name",
                "lastName",
                "family_name",
                None,
                (false, true, true),
            ),
            user_property_mapper(
                "updated at",
                "updatedAt",
                "updated_at",
                Some("long"),
                (false, false, true),
            ),
            user_attribute_mapper(
                "middle name",
                "middle_name",
                "middle_name",
                None,
                (false, false, true),
            ),
            user_attribute_mapper("nickname", "nickname", "nickname", None, (false, false, true)),
            user_attribute_mapper("profile", "profile", "profile", None, (false, false, true)),
            user_attribute_mapper("picture", "picture", "picture", None, (false, false, true)),
            user_attribute_mapper("website", "website", "website", None, (false, false, true)),
            user_attribute_mapper("gender", "gender", "gender", None, (false, false, true)),
            user_attribute_mapper(
                "birthdate",
                "birthdate",
                "birthdate",
                None,
                (false, false, true),
            ),
            user_attribute_mapper("zoneinfo", "zoneinfo", "zoneinfo", None, (false, false, true)),
            user_attribute_mapper("locale", "locale", "locale", None, (false, false, true)),
        ],
    );

    let email = scope(
        realm_id,
        "email",
        vec![
            user_property_mapper("email", "email", "email", None, (false, true, true)),
            user_property_mapper(
                "email verified",
                "emailVerified",
                "email_verified",
                Some("boolean"),
                (false, true, true),
            ),
        ],
    );

    let address = scope(
        realm_id,
        "address",
        vec![mapper(
            "address",
            MapperType::Address,
            &[],
            (false, true, true),
        )],
    );

    let phone = scope(
        realm_id,
        "phone",
        vec![
            user_attribute_mapper(
                "phone number",
                "phone_number",
                "phone_number",
                None,
                (false, true, true),
            ),
            user_attribute_mapper(
                "phone number verified",
                "phone_number_verified",
                "phone_number_verified",
                Some("boolean"),
                (false, true, true),
            ),
        ],
    );

    let roles = scope(
        realm_id,
        "roles",
        vec![
            mapper("realm roles", MapperType::RealmRoleList, &[], (true, false, false)),
            mapper("client roles", MapperType::ClientRoleList, &[], (true, false, false)),
        ],
    );

    let offline_access = scope(realm_id, "offline_access", vec![]);

    let web_origins = scope(
        realm_id,
        "web-origins",
        vec![mapper(
            "allowed web origins",
            MapperType::AllowedWebOrigins,
            &[],
            (true, false, false),
        )],
    );

    let acr = scope(realm_id, "acr", vec![]);

    vec![
        profile,
        email,
        address,
        phone,
        roles,
        offline_access,
        web_origins,
        acr,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_type_wire_spellings_match_keycloak() {
        let json = serde_json::to_string(&MapperType::UserAttribute).unwrap();
        assert_eq!(json, "\"oidc-usermodel-attribute-mapper\"");
        let back: MapperType = serde_json::from_str("\"oidc-audience-mapper\"").unwrap();
        assert_eq!(back, MapperType::Audience);
        for mt in MapperType::ALL {
            assert!(!mt.label().is_empty());
            assert!(!mt.description().is_empty());
        }
        assert_eq!(MapperType::ALL.len(), 9);
    }

    #[test]
    fn builtin_scopes_cover_expected_names() {
        let realm = RealmId::new("r1").unwrap();
        let scopes = builtin_client_scopes(&realm);
        let names: Vec<&str> = scopes.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "profile",
                "email",
                "address",
                "phone",
                "roles",
                "offline_access",
                "web-origins",
                "acr"
            ]
        );
        for s in &scopes {
            assert_eq!(s.realm_id, realm);
            assert_eq!(s.protocol, ClientProtocol::OpenIdConnect);
        }
    }

    #[test]
    fn builtin_profile_and_email_keep_legacy_targets() {
        let realm = RealmId::new("r1").unwrap();
        let scopes = builtin_client_scopes(&realm);
        let profile = scopes.iter().find(|s| s.name == "profile").unwrap();
        // preferred_username lands in all three targets (Keycloak parity, so
        // access-token consumers like the admin console can show the
        // username); the remaining profile claims stay out of access tokens.
        let username = profile.protocol_mappers.iter().find(|m| m.name == "username").unwrap();
        assert!(username.applies_to(ClaimTarget::AccessToken));
        assert!(username.applies_to(ClaimTarget::IdToken));
        assert!(username.applies_to(ClaimTarget::UserInfo));
        assert!(profile
            .protocol_mappers
            .iter()
            .filter(|m| m.name != "username")
            .all(|m| !m.applies_to(ClaimTarget::AccessToken)));
        // updated_at and attribute mappers are userinfo-only.
        let updated = profile.protocol_mappers.iter().find(|m| m.name == "updated at").unwrap();
        assert!(updated.applies_to(ClaimTarget::UserInfo));
        assert!(!updated.applies_to(ClaimTarget::IdToken));

        let roles = scopes.iter().find(|s| s.name == "roles").unwrap();
        assert!(roles.protocol_mappers.iter().all(|m| m.applies_to(ClaimTarget::AccessToken)
            && !m.applies_to(ClaimTarget::IdToken)
            && !m.applies_to(ClaimTarget::UserInfo)));
    }

    #[test]
    fn mapper_config_flag_defaults_and_parsing() {
        let m = ProtocolMapper {
            id: MapperId::new("m1").unwrap(),
            name: "m".into(),
            mapper_type: MapperType::UserAttribute,
            config: HashMap::new(),
        };
        assert!(m.applies_to(ClaimTarget::AccessToken));
        assert!(!m.config_flag("x", false));
        assert_eq!(m.config_value("x"), None);

        let mut cfg = HashMap::new();
        cfg.insert("access.token.claim".to_string(), "false".to_string());
        cfg.insert("claim.name".to_string(), "foo".to_string());
        let m2 = ProtocolMapper { config: cfg, ..m };
        assert!(!m2.applies_to(ClaimTarget::AccessToken));
        assert!(m2.applies_to(ClaimTarget::IdToken));
        assert_eq!(m2.config_value("claim.name"), Some("foo"));
        assert_eq!(m2.config_value(""), None);
    }

    #[test]
    fn scope_mappings_serde_defaults() {
        let sm: ScopeMappings = serde_json::from_str("{}").unwrap();
        assert!(sm.realm_roles.is_empty());
        assert!(sm.client_roles.is_empty());
        assert!(is_builtin_scope_name("roles"));
        assert!(!is_builtin_scope_name("custom"));
        assert!(DEFAULT_DEFAULT_SCOPES.contains(&"roles"));
        assert!(DEFAULT_OPTIONAL_SCOPES.contains(&"offline_access"));
    }
}
