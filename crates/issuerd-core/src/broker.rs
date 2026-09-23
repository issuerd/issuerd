// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Identity brokering: pure types and logic for login via external OIDC/social IdPs.

//! Identity brokering: pure types and logic for login via external
//! OIDC / social identity providers.
//!
//! This module contains **no I/O**. The [`BrokerClient`] trait abstracts the
//! server-to-server HTTP calls (discovery, code exchange, JWKS, userinfo) so
//! flow logic stays testable; the production implementation lives in
//! `issuerd-server` (`ReqwestBrokerClient`). Everything else — discovery/token
//! response parsing, claim mapping, first-broker-login conflict decisions — is
//! pure functions over `serde_json::Value` and the models in this crate.
//!
//! ## Configuration model
//!
//! An [`crate::IdentityProviderConfig`] with `provider_id` `"oidc"` (generic)
//! or a social provider id (`"google"`, `"github"`, `"microsoft"`,
//! `"facebook"` — arrive as `ProviderId::Custom`) becomes a working broker
//! when its free-form `config` map carries the keys below. Spellings follow
//! Keycloak's OIDC identity provider config where Keycloak defines them.
//!
//! | Key | Required | Meaning |
//! |-----|----------|---------|
//! | `clientId` | yes | client id registered at the external IdP |
//! | `clientSecret` | yes | client secret (basic auth by default) |
//! | `issuer` | discovery | OIDC issuer URL; discovery document is fetched from `{issuer}/.well-known/openid-configuration` |
//! | `authorizationUrl` | w/o discovery | explicit authorization endpoint |
//! | `tokenUrl` | w/o discovery | explicit token endpoint |
//! | `userInfoUrl` | no | explicit userinfo endpoint (fallback when no id_token) |
//! | `jwksUrl` | no | explicit JWKS endpoint (else from discovery) |
//! | `useDiscovery` | no | `"true"`/`"false"` (default: true when `issuer` set) |
//! | `defaultScope` | no | scopes requested at the IdP (default `openid profile email`) |
//! | `clientAuthMethod` | no | `client_secret_basic` (default) or `client_secret_post` |
//! | `pkceEnabled` | no | default `"true"` — we always hold an S256 verifier |
//! | `trustEmail` | no | trust the IdP's email as verified; skips review page and enables auto-link on email conflict |
//! | `syncMode` | no | `import` (mappers on first login only, default) or `force` (every login) |
//! | `storeTokens` | no | persist the external refresh token on the link (default false) |
//! | `displayName` | no | label on the login page button (defaults to alias) |
//! | `mappers` | no | JSON array of [`IdpMapper`] |

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{IdentityProviderConfig, ProviderId, User};
use crate::{IssuerdError, UserId};

// ---------------------------------------------------------------------------
// Identity provider link (account link between a local user and an IdP subject)
// ---------------------------------------------------------------------------

/// A link between a local user and an external identity provider account.
///
/// Uniqueness invariants (enforced by the storage backends):
/// - one external `(alias, external_subject)` maps to at most one local user;
/// - a local user has at most one link per provider alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProviderLink {
    pub user_id: UserId,
    pub provider_alias: String,
    /// The external subject identifier (`sub` claim; `id` for GitHub).
    pub external_subject: String,
    pub external_username: Option<String>,
    /// External refresh token, only when the IdP config has `storeTokens`
    /// enabled. Never exposed through any API response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_refresh_token: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Broker client trait (I/O boundary)
// ---------------------------------------------------------------------------

/// Server-to-server HTTP client for talking to an external identity provider.
///
/// Deliberately minimal and JSON-shaped: all parsing/validation of the
/// returned documents happens in pure functions ([`BrokerDiscoveryDocument`],
/// [`BrokerTokenResponse`], [`BrokeredIdentity`], and
/// `issuerd_token::validate_external_id_token`), so tests stub this trait and never
/// touch the network.
#[mockall::automock]
#[async_trait::async_trait]
pub trait BrokerClient: Send + Sync {
    /// GET a URL and parse the response body as JSON (discovery, JWKS).
    async fn get_json(&self, url: &str) -> Result<serde_json::Value, IssuerdError>;

    /// POST an `application/x-www-form-urlencoded` body to the token endpoint.
    /// When `basic_auth` is `Some((client_id, client_secret))`, credentials
    /// travel in the Authorization header (`client_secret_basic`); otherwise
    /// the caller includes them in `form` (`client_secret_post`).
    ///
    /// An OAuth2 error response from the IdP (`{"error": ...}` with a non-2xx
    /// status) maps to [`IssuerdError::InvalidGrant`]; transport failures map to
    /// [`IssuerdError::ServerError`].
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        basic_auth: Option<(String, String)>,
    ) -> Result<serde_json::Value, IssuerdError>;

    /// GET a JSON document with a Bearer token (userinfo).
    async fn get_json_bearer(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<serde_json::Value, IssuerdError>;

    /// GET a JSON document from an **untrusted, attacker-influenced** URL —
    /// currently the pairwise `sector_identifier_uri` a registrant supplies
    /// via dynamic client registration (OIDC Core §8.1), which is reachable
    /// without authentication when a realm has DCR enabled.
    ///
    /// Unlike the IdP-facing methods above — which call admin-configured,
    /// legitimately-internal endpoints — implementations MUST treat `url` as
    /// hostile: require `https`, resolve the host and reject any non-public
    /// IP, disable redirect following, cap the body size, and collapse every
    /// failure mode (DNS, connect, status, redirect, oversize, parse) into
    /// one generic error so the endpoint cannot be abused as a blind
    /// host/port oracle into the server's internal network (SSRF).
    ///
    /// The default implementation delegates to [`BrokerClient::get_json`] so
    /// existing test doubles and mocks keep compiling; the production
    /// implementation overrides it with the hardened fetch.
    async fn get_json_untrusted(&self, url: &str) -> Result<serde_json::Value, IssuerdError> {
        self.get_json(url).await
    }
}

// ---------------------------------------------------------------------------
// Discovery / token endpoint response parsing (pure)
// ---------------------------------------------------------------------------

/// The subset of an OIDC discovery document brokering needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerDiscoveryDocument {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub issuer: Option<String>,
    pub end_session_endpoint: Option<String>,
}

impl BrokerDiscoveryDocument {
    /// Parse a discovery document, requiring the two endpoints brokering
    /// cannot live without.
    pub fn parse(json: &serde_json::Value) -> Result<Self, IssuerdError> {
        let required = |name: &str| -> Result<String, IssuerdError> {
            json.get(name)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    IssuerdError::InvalidRequest(format!("IdP discovery document missing `{name}`"))
                })
        };
        let optional = |name: &str| -> Option<String> {
            json.get(name)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Ok(Self {
            authorization_endpoint: required("authorization_endpoint")?,
            token_endpoint: required("token_endpoint")?,
            userinfo_endpoint: optional("userinfo_endpoint"),
            jwks_uri: optional("jwks_uri"),
            issuer: optional("issuer"),
            end_session_endpoint: optional("end_session_endpoint"),
        })
    }
}

/// A token-endpoint response from the external IdP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerTokenResponse {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
}

impl BrokerTokenResponse {
    pub fn parse(json: &serde_json::Value) -> Result<Self, IssuerdError> {
        // Surface an OAuth2 error body even on a 200 (some IdPs misbehave).
        if json.get("error").and_then(|e| e.as_str()).is_some() {
            return Err(IssuerdError::InvalidGrant);
        }
        let opt_str = |name: &str| json.get(name).and_then(|v| v.as_str()).map(str::to_string);
        let expires_in = json
            .get("expires_in")
            .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));
        let resp = Self {
            access_token: opt_str("access_token"),
            id_token: opt_str("id_token"),
            refresh_token: opt_str("refresh_token"),
            expires_in,
            token_type: opt_str("token_type"),
        };
        if resp.access_token.is_none() && resp.id_token.is_none() {
            return Err(IssuerdError::InvalidRequest(
                "IdP token response carries neither access_token nor id_token".to_string(),
            ));
        }
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Brokered identity (pure)
// ---------------------------------------------------------------------------

/// The normalized external identity extracted from an ID token or userinfo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokeredIdentity {
    /// External subject (`sub`; GitHub: numeric `id` stringified).
    pub subject: String,
    /// `preferred_username` (GitHub: `login`).
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    /// `given_name`.
    pub first_name: Option<String>,
    /// `family_name`.
    pub last_name: Option<String>,
    /// `name` (full display name).
    pub display_name: Option<String>,
    /// Full claim set, retained for mapper evaluation.
    pub claims: serde_json::Value,
}

impl BrokeredIdentity {
    /// Build from a validated ID token claim set or a userinfo response.
    ///
    /// Fails when no usable subject identifier is present (`sub`, or GitHub's
    /// numeric `id`).
    pub fn from_claims(claims: serde_json::Value) -> Result<Self, IssuerdError> {
        let subject = claims
            .get("sub")
            .and_then(|v| {
                v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|n| n.to_string()))
            })
            .or_else(|| {
                claims.get("id").and_then(|v| {
                    v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|n| n.to_string()))
                })
            })
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                IssuerdError::InvalidRequest("external identity has no subject (`sub`)".to_string())
            })?;
        let opt_str = |name: &str| {
            claims
                .get(name)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let email_verified = claims
            .get("email_verified")
            .and_then(|v| v.as_bool().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(false);
        Ok(Self {
            subject,
            username: opt_str("preferred_username").or_else(|| opt_str("login")),
            email: opt_str("email"),
            email_verified,
            first_name: opt_str("given_name"),
            last_name: opt_str("family_name"),
            display_name: opt_str("name"),
            claims,
        })
    }

    /// The username pre-filled on the review-profile page / used for
    /// auto-created users: preferred username, else the email local part,
    /// else `{alias}.{subject}` (Keycloak's fallback shape).
    pub fn suggested_username(&self, alias: &str) -> String {
        if let Some(ref u) = self.username {
            if !u.trim().is_empty() {
                return u.trim().to_string();
            }
        }
        if let Some(ref email) = self.email {
            if let Some(local) = email.split('@').next() {
                if !local.is_empty() {
                    return local.to_string();
                }
            }
        }
        format!("{alias}.{}", self.subject)
    }
}

/// Whether validated ID-token claims need a userinfo round-trip: spec-compliant
/// IdPs put profile/email claims ONLY in the userinfo response when an access
/// token is issued alongside (OIDC Core 1.0 §5.4), so a code-flow id_token
/// legitimately carries nothing but the subject. Keycloak fetches userinfo by
/// default for the same reason.
pub fn claims_need_userinfo(claims: &serde_json::Value) -> bool {
    claims.get("email").is_none()
        && claims.get("preferred_username").is_none()
        && claims.get("name").is_none()
}

/// Merge a userinfo response into validated ID-token claims: userinfo supplies
/// keys the id_token lacks; the id_token always wins on conflicts (it is the
/// signed artifact). Per OIDC Core 1.0 §5.3.2 the userinfo `sub` MUST equal
/// the id_token `sub` — a mismatch rejects the login.
pub fn merge_userinfo_claims(
    mut id_claims: serde_json::Value,
    userinfo: serde_json::Value,
) -> Result<serde_json::Value, IssuerdError> {
    fn sub_of(v: &serde_json::Value) -> Option<&str> {
        v.get("sub").and_then(|s| s.as_str())
    }
    if let (Some(a), Some(b)) = (sub_of(&id_claims), sub_of(&userinfo)) {
        if a != b {
            return Err(IssuerdError::InvalidToken);
        }
    }
    if let (serde_json::Value::Object(base), serde_json::Value::Object(extra)) =
        (&mut id_claims, &userinfo)
    {
        for (key, value) in extra {
            if key != "sub" {
                base.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
    Ok(id_claims)
}

// ---------------------------------------------------------------------------
// IdP mappers (pure)
// ---------------------------------------------------------------------------

/// What an [`IdpMapper`] does with external claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdpMapperType {
    /// Copy a claim into a user attribute (`claim`, `attribute`).
    Attribute,
    /// Assign a realm role when a claim matches (`claim`, `claim_value`, `role`).
    Role,
    /// Derive the username from a template (`template`), e.g.
    /// `${ALIAS}.${CLAIM.sub}`. Applied only when a user is created.
    UsernameTemplate,
}

/// A single claim-mapping rule stored on the IdP config (in the `mappers`
/// config key, as a JSON array).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdpMapper {
    pub name: String,
    pub mapper_type: IdpMapperType,
    #[serde(default)]
    pub config: HashMap<String, String>,
}

/// The outcome of applying mappers: attribute mutations are applied to the
/// passed user in place; roles and a derived username are returned for the
/// caller to realize (role names must be resolved to role ids, a templated
/// username is only honored at user creation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapperEffects {
    /// Realm role names the mapper rules grant for this login.
    pub roles: Vec<String>,
    /// Username produced by a `UsernameTemplate` mapper, if any fired.
    pub username: Option<String>,
}

/// Extract string values from a claim: a string becomes a singleton, an
/// array contributes its string/number/bool members, anything else is empty.
pub fn claim_strings(claims: &serde_json::Value, name: &str) -> Vec<String> {
    match claims.get(name) {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                serde_json::Value::Bool(b) => Some(b.to_string()),
                _ => None,
            })
            .collect(),
        Some(serde_json::Value::Number(n)) => vec![n.to_string()],
        Some(serde_json::Value::Bool(b)) => vec![b.to_string()],
        _ => vec![],
    }
}

/// Render a username template: `${ALIAS}` expands to the provider alias,
/// `${CLAIM.<name>}` to the first string value of that claim. Returns `None`
/// when any referenced claim is absent (mapper then simply does not fire).
pub fn render_username_template(
    template: &str,
    alias: &str,
    claims: &serde_json::Value,
) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let expr = &after[..end];
        if expr == "ALIAS" {
            out.push_str(alias);
        } else {
            let claim = expr.strip_prefix("CLAIM.")?;
            let values = claim_strings(claims, claim);
            out.push_str(values.first()?);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Apply every mapper to the user / effect set. Attribute mappers overwrite
/// the mapped attribute with the claim's current values; role mappers collect
/// role names (duplicates removed); a username template mapper fires at most
/// once (first in list order).
pub fn apply_mappers(
    mappers: &[IdpMapper],
    alias: &str,
    claims: &serde_json::Value,
    user: &mut User,
) -> MapperEffects {
    let mut effects = MapperEffects::default();
    for mapper in mappers {
        match mapper.mapper_type {
            IdpMapperType::Attribute => {
                let (Some(claim), Some(attribute)) =
                    (mapper.config.get("claim"), mapper.config.get("attribute"))
                else {
                    continue;
                };
                let values = claim_strings(claims, claim);
                if values.is_empty() {
                    user.attributes.remove(attribute);
                } else {
                    user.attributes.insert(attribute.clone(), values);
                }
            }
            IdpMapperType::Role => {
                let (Some(claim), Some(claim_value), Some(role)) = (
                    mapper.config.get("claim"),
                    mapper.config.get("claim_value"),
                    mapper.config.get("role"),
                ) else {
                    continue;
                };
                if claim_strings(claims, claim).iter().any(|v| v == claim_value)
                    && !effects.roles.contains(role)
                {
                    effects.roles.push(role.clone());
                }
            }
            IdpMapperType::UsernameTemplate => {
                if effects.username.is_some() {
                    continue;
                }
                if let Some(template) = mapper.config.get("template") {
                    effects.username = render_username_template(template, alias, claims);
                }
            }
        }
    }
    effects
}

// ---------------------------------------------------------------------------
// Typed view over the IdP config map
// ---------------------------------------------------------------------------

/// How the broker authenticates to the external token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

/// Whether mapped attributes/roles are re-applied on every login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerSyncMode {
    /// Mappers run only when the user is first created / linked.
    Import,
    /// Mappers re-run on every brokered login, overwriting mapped attributes.
    Force,
}

/// Typed read access to an [`IdentityProviderConfig`]'s free-form `config`
/// map, following the key conventions documented on this module.
pub struct BrokerIdpSettings<'a> {
    idp: &'a IdentityProviderConfig,
}

impl<'a> BrokerIdpSettings<'a> {
    pub fn new(idp: &'a IdentityProviderConfig) -> Self {
        Self { idp }
    }

    fn get(&self, key: &str) -> Option<&'a str> {
        self.idp.config.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }

    fn get_bool(&self, key: &str, default: bool) -> bool {
        self.idp.config.get(key).and_then(|v| v.parse::<bool>().ok()).unwrap_or(default)
    }

    pub fn client_id(&self) -> Option<&'a str> {
        self.get("clientId")
    }

    pub fn client_secret(&self) -> Option<&'a str> {
        self.get("clientSecret")
    }

    pub fn issuer(&self) -> Option<&'a str> {
        self.get("issuer")
    }

    pub fn authorization_url(&self) -> Option<&'a str> {
        self.get("authorizationUrl")
    }

    pub fn token_url(&self) -> Option<&'a str> {
        self.get("tokenUrl")
    }

    pub fn userinfo_url(&self) -> Option<&'a str> {
        self.get("userInfoUrl")
    }

    pub fn jwks_url(&self) -> Option<&'a str> {
        self.get("jwksUrl")
    }

    /// Discovery drives endpoint resolution whenever an issuer is configured
    /// and `useDiscovery` was not explicitly disabled.
    pub fn use_discovery(&self) -> bool {
        self.get_bool("useDiscovery", self.issuer().is_some())
    }

    pub fn default_scope(&self) -> String {
        self.get("defaultScope").unwrap_or("openid profile email").to_string()
    }

    pub fn trust_email(&self) -> bool {
        self.get_bool("trustEmail", false)
    }

    pub fn sync_mode(&self) -> BrokerSyncMode {
        match self.get("syncMode") {
            Some("force") => BrokerSyncMode::Force,
            _ => BrokerSyncMode::Import,
        }
    }

    pub fn store_tokens(&self) -> bool {
        self.get_bool("storeTokens", false)
    }

    pub fn pkce_enabled(&self) -> bool {
        self.get_bool("pkceEnabled", true)
    }

    pub fn client_auth_method(&self) -> BrokerClientAuthMethod {
        match self.get("clientAuthMethod") {
            Some("client_secret_post") => BrokerClientAuthMethod::ClientSecretPost,
            _ => BrokerClientAuthMethod::ClientSecretBasic,
        }
    }

    /// Button label for the login page; defaults to the alias.
    pub fn display_name(&self) -> String {
        self.get("displayName")
            .map(str::to_string)
            .unwrap_or_else(|| self.idp.alias.to_string())
    }

    /// Parse the `mappers` config key (JSON array of [`IdpMapper`]).
    /// A malformed value yields an empty list rather than an error — a broken
    /// mapper set must not lock every user out of the realm.
    pub fn mappers(&self) -> Vec<IdpMapper> {
        self.idp
            .config
            .get("mappers")
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default()
    }

    /// Validate the minimum configuration for this provider to function as a
    /// broker. Returns a list of human-readable problems (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.client_id().is_none() {
            problems.push("clientId is required".to_string());
        }
        if self.client_secret().is_none() {
            problems.push("clientSecret is required".to_string());
        }
        if self.use_discovery() {
            if self.issuer().is_none() {
                problems.push("issuer is required when useDiscovery is enabled".to_string());
            }
        } else {
            if self.authorization_url().is_none() {
                problems.push("authorizationUrl is required without discovery".to_string());
            }
            if self.token_url().is_none() {
                problems.push("tokenUrl is required without discovery".to_string());
            }
        }
        problems
    }

    /// Whether this provider can act as a broker at all (social/OIDC, not a
    /// user-federation provider like LDAP/Kerberos).
    pub fn is_broker_provider(&self) -> bool {
        matches!(
            self.idp.provider_id,
            ProviderId::Oidc | ProviderId::Social | ProviderId::Custom(_)
        )
    }
}

// ---------------------------------------------------------------------------
// First-broker-login conflict decision (pure)
// ---------------------------------------------------------------------------

/// What the broker endpoint does with an identity that has no existing
/// [`IdentityProviderLink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstBrokerLoginDecision {
    /// Link to the existing user whose verified email matches (trust_email).
    AutoLink,
    /// Create a new user immediately without the review page.
    AutoCreate,
    /// Show the review-profile page (prefilled from the identity).
    ReviewProfile,
    /// Email matches an existing user: offer link-via-password re-auth, or
    /// creating a distinct account.
    LinkOrCreate,
}

/// Decide the first-broker-login path.
///
/// - Email conflict (an existing user has the identity's email): auto-link
///   only when the IdP is trusted (`trustEmail`) **and** the IdP asserted the
///   email as verified — anything else must prove account ownership via
///   password re-auth ([`FirstBrokerLoginDecision::LinkOrCreate`]).
/// - No conflict: trusted providers skip the review page; everyone else
///   reviews the prefilled profile first.
pub fn decide_first_broker_login(
    has_email_conflict: bool,
    trust_email: bool,
    email_verified: bool,
) -> FirstBrokerLoginDecision {
    if has_email_conflict {
        if trust_email && email_verified {
            FirstBrokerLoginDecision::AutoLink
        } else {
            FirstBrokerLoginDecision::LinkOrCreate
        }
    } else if trust_email {
        FirstBrokerLoginDecision::AutoCreate
    } else {
        FirstBrokerLoginDecision::ReviewProfile
    }
}

// ---------------------------------------------------------------------------
// Provider presets (config templates, not code)
// ---------------------------------------------------------------------------

/// A configuration template for a well-known provider. The admin SPA uses
/// presets to prefill the IdP form; everything remains editable afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdpPreset {
    /// The `provider_id` to set (e.g. `"google"`, `"oidc"`).
    pub provider_id: String,
    pub display_name: String,
    /// Default config entries for this provider (endpoints, scope).
    pub config: HashMap<String, String>,
}

/// Presets for the supported social/generic providers.
pub fn identity_provider_presets() -> Vec<IdpPreset> {
    let preset = |provider_id: &str, display_name: &str, entries: &[(&str, &str)]| IdpPreset {
        provider_id: provider_id.to_string(),
        display_name: display_name.to_string(),
        config: entries.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    };
    vec![
        preset("oidc", "OpenID Connect", &[("defaultScope", "openid profile email")]),
        preset(
            "google",
            "Google",
            &[
                ("issuer", "https://accounts.google.com"),
                ("defaultScope", "openid profile email"),
                ("trustEmail", "true"),
            ],
        ),
        preset(
            "microsoft",
            "Microsoft",
            &[
                ("issuer", "https://login.microsoftonline.com/common/v2.0"),
                ("defaultScope", "openid profile email"),
                ("trustEmail", "true"),
            ],
        ),
        preset(
            "github",
            "GitHub",
            &[
                ("authorizationUrl", "https://github.com/login/oauth/authorize"),
                ("tokenUrl", "https://github.com/login/oauth/access_token"),
                ("userInfoUrl", "https://api.github.com/user"),
                ("defaultScope", "read:user user:email"),
                ("useDiscovery", "false"),
            ],
        ),
        preset(
            "facebook",
            "Facebook",
            &[
                ("issuer", "https://www.facebook.com"),
                ("authorizationUrl", "https://www.facebook.com/v18.0/dialog/oauth"),
                ("tokenUrl", "https://graph.facebook.com/v18.0/oauth/access_token"),
                ("jwksUrl", "https://limited.facebook.com/.well-known/oauth/openid/jwks/"),
                ("defaultScope", "openid public_profile email"),
                ("useDiscovery", "false"),
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::RealmId;

    fn discovery_json() -> serde_json::Value {
        serde_json::json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "userinfo_endpoint": "https://idp.example.com/userinfo",
            "jwks_uri": "https://idp.example.com/jwks"
        })
    }

    #[test]
    fn discovery_parse_full() {
        let doc = BrokerDiscoveryDocument::parse(&discovery_json()).unwrap();
        assert_eq!(doc.authorization_endpoint, "https://idp.example.com/auth");
        assert_eq!(doc.token_endpoint, "https://idp.example.com/token");
        assert_eq!(doc.userinfo_endpoint.as_deref(), Some("https://idp.example.com/userinfo"));
        assert_eq!(doc.jwks_uri.as_deref(), Some("https://idp.example.com/jwks"));
    }

    #[test]
    fn discovery_parse_missing_token_endpoint_fails() {
        let mut doc = discovery_json();
        doc.as_object_mut().unwrap().remove("token_endpoint");
        assert!(BrokerDiscoveryDocument::parse(&doc).is_err());
    }

    #[test]
    fn token_response_parse() {
        let json = serde_json::json!({
            "access_token": "at",
            "id_token": "it",
            "refresh_token": "rt",
            "expires_in": 300,
            "token_type": "Bearer"
        });
        let resp = BrokerTokenResponse::parse(&json).unwrap();
        assert_eq!(resp.access_token.as_deref(), Some("at"));
        assert_eq!(resp.id_token.as_deref(), Some("it"));
        assert_eq!(resp.expires_in, Some(300));
    }

    #[test]
    fn token_response_error_body_is_invalid_grant() {
        let json = serde_json::json!({"error": "invalid_grant", "error_description": "bad code"});
        assert!(matches!(BrokerTokenResponse::parse(&json), Err(IssuerdError::InvalidGrant)));
    }

    #[test]
    fn token_response_without_any_token_fails() {
        let json = serde_json::json!({"token_type": "Bearer"});
        assert!(BrokerTokenResponse::parse(&json).is_err());
    }

    #[test]
    fn identity_from_oidc_claims() {
        let id = BrokeredIdentity::from_claims(serde_json::json!({
            "sub": "abc-123",
            "preferred_username": "jdoe",
            "email": "jdoe@example.com",
            "email_verified": true,
            "given_name": "John",
            "family_name": "Doe",
            "name": "John Doe"
        }))
        .unwrap();
        assert_eq!(id.subject, "abc-123");
        assert_eq!(id.username.as_deref(), Some("jdoe"));
        assert!(id.email_verified);
        assert_eq!(id.first_name.as_deref(), Some("John"));
        assert_eq!(id.suggested_username("google"), "jdoe");
    }

    #[test]
    fn identity_from_github_userinfo() {
        let id = BrokeredIdentity::from_claims(serde_json::json!({
            "id": 42,
            "login": "octocat",
            "email": null,
            "name": "The Octocat"
        }))
        .unwrap();
        assert_eq!(id.subject, "42");
        assert_eq!(id.username.as_deref(), Some("octocat"));
        assert_eq!(id.email, None);
        assert!(!id.email_verified);
    }

    #[test]
    fn identity_without_subject_fails() {
        assert!(BrokeredIdentity::from_claims(serde_json::json!({"email": "a@b.c"})).is_err());
    }

    #[test]
    fn suggested_username_fallbacks() {
        let mut id = BrokeredIdentity::from_claims(serde_json::json!({
            "sub": "s1",
            "email": "local@example.com"
        }))
        .unwrap();
        assert_eq!(id.suggested_username("github"), "local");
        id.email = None;
        assert_eq!(id.suggested_username("github"), "github.s1");
    }

    #[test]
    fn claims_need_userinfo_true_without_profile_claims() {
        assert!(claims_need_userinfo(&serde_json::json!({"sub": "s1"})));
        assert!(claims_need_userinfo(&serde_json::json!({})));
    }

    #[test]
    fn claims_need_userinfo_false_with_any_profile_claim() {
        assert!(!claims_need_userinfo(&serde_json::json!({"sub": "s1", "email": "a@b.c"})));
        assert!(!claims_need_userinfo(&serde_json::json!({"preferred_username": "octo"})));
        assert!(!claims_need_userinfo(&serde_json::json!({"name": "Octo Cat"})));
    }

    #[test]
    fn merge_userinfo_fills_missing_claims() {
        let id_claims = serde_json::json!({"sub": "s1", "iss": "https://idp.example"});
        let userinfo = serde_json::json!({
            "sub": "s1",
            "email": "a@b.c",
            "preferred_username": "octo"
        });
        let merged = merge_userinfo_claims(id_claims, userinfo).unwrap();
        assert_eq!(merged["sub"], "s1");
        assert_eq!(merged["email"], "a@b.c");
        assert_eq!(merged["preferred_username"], "octo");
        assert_eq!(merged["iss"], "https://idp.example");
    }

    #[test]
    fn merge_userinfo_id_token_wins_conflicts() {
        let id_claims = serde_json::json!({"sub": "s1", "email": "signed@example.com"});
        let userinfo = serde_json::json!({"sub": "s1", "email": "other@example.com", "name": "N"});
        let merged = merge_userinfo_claims(id_claims, userinfo).unwrap();
        assert_eq!(merged["email"], "signed@example.com");
        assert_eq!(merged["name"], "N");
    }

    #[test]
    fn merge_userinfo_sub_mismatch_rejected() {
        let id_claims = serde_json::json!({"sub": "s1"});
        let userinfo = serde_json::json!({"sub": "s2", "email": "a@b.c"});
        assert_eq!(merge_userinfo_claims(id_claims, userinfo), Err(IssuerdError::InvalidToken));
    }

    fn test_user() -> User {
        User {
            id: UserId::new("u1").unwrap(),
            realm_id: RealmId::new("r1").unwrap(),
            username: crate::Username::new("jdoe").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn attribute_mapper_copies_claim() {
        let mappers = vec![IdpMapper {
            name: "org".into(),
            mapper_type: IdpMapperType::Attribute,
            config: [
                ("claim".into(), "org".into()),
                ("attribute".into(), "organization".into()),
            ]
            .into_iter()
            .collect(),
        }];
        let mut user = test_user();
        let claims = serde_json::json!({"org": "acme"});
        let effects = apply_mappers(&mappers, "idp", &claims, &mut user);
        assert_eq!(user.attributes.get("organization"), Some(&vec!["acme".to_string()]));
        assert!(effects.roles.is_empty());
    }

    #[test]
    fn attribute_mapper_clears_missing_claim() {
        let mappers = vec![IdpMapper {
            name: "org".into(),
            mapper_type: IdpMapperType::Attribute,
            config: [
                ("claim".into(), "org".into()),
                ("attribute".into(), "organization".into()),
            ]
            .into_iter()
            .collect(),
        }];
        let mut user = test_user();
        user.attributes.insert("organization".into(), vec!["old".into()]);
        apply_mappers(&mappers, "idp", &serde_json::json!({}), &mut user);
        assert!(!user.attributes.contains_key("organization"));
    }

    #[test]
    fn role_mapper_matches_array_claim() {
        let mappers = vec![IdpMapper {
            name: "admins".into(),
            mapper_type: IdpMapperType::Role,
            config: [
                ("claim".into(), "groups".into()),
                ("claim_value".into(), "admins".into()),
                ("role".into(), "realm-admin".into()),
            ]
            .into_iter()
            .collect(),
        }];
        let mut user = test_user();
        let claims = serde_json::json!({"groups": ["users", "admins"]});
        let effects = apply_mappers(&mappers, "idp", &claims, &mut user);
        assert_eq!(effects.roles, vec!["realm-admin".to_string()]);

        let claims = serde_json::json!({"groups": ["users"]});
        let effects = apply_mappers(&mappers, "idp", &claims, &mut test_user());
        assert!(effects.roles.is_empty());
    }

    #[test]
    fn username_template_renders() {
        let claims = serde_json::json!({"sub": "1234"});
        assert_eq!(
            render_username_template("${ALIAS}.${CLAIM.sub}", "google", &claims),
            Some("google.1234".to_string())
        );
        assert_eq!(render_username_template("${CLAIM.missing}", "google", &claims), None);
        assert_eq!(render_username_template("static", "google", &claims), Some("static".into()));
    }

    #[test]
    fn username_template_mapper_fires_once() {
        let mappers = vec![
            IdpMapper {
                name: "t1".into(),
                mapper_type: IdpMapperType::UsernameTemplate,
                config: [("template".into(), "${ALIAS}.${CLAIM.sub}".into())].into_iter().collect(),
            },
            IdpMapper {
                name: "t2".into(),
                mapper_type: IdpMapperType::UsernameTemplate,
                config: [("template".into(), "other".into())].into_iter().collect(),
            },
        ];
        let claims = serde_json::json!({"sub": "9"});
        let effects = apply_mappers(&mappers, "gh", &claims, &mut test_user());
        assert_eq!(effects.username.as_deref(), Some("gh.9"));
    }

    #[test]
    fn conflict_decision_table() {
        use FirstBrokerLoginDecision::*;
        // Conflict: trusted+verified auto-links, everything else re-auths.
        assert_eq!(decide_first_broker_login(true, true, true), AutoLink);
        assert_eq!(decide_first_broker_login(true, true, false), LinkOrCreate);
        assert_eq!(decide_first_broker_login(true, false, true), LinkOrCreate);
        assert_eq!(decide_first_broker_login(true, false, false), LinkOrCreate);
        // No conflict: trusted skips review, untrusted reviews.
        assert_eq!(decide_first_broker_login(false, true, true), AutoCreate);
        assert_eq!(decide_first_broker_login(false, true, false), AutoCreate);
        assert_eq!(decide_first_broker_login(false, false, true), ReviewProfile);
        assert_eq!(decide_first_broker_login(false, false, false), ReviewProfile);
    }

    #[test]
    fn settings_read_config_keys() {
        let idp = IdentityProviderConfig {
            id: crate::IdentityProviderId::new("id").unwrap(),
            alias: crate::Alias::new("google").unwrap(),
            provider_id: ProviderId::Custom("google".into()),
            enabled: true,
            config: [
                ("clientId".into(), "cid".into()),
                ("clientSecret".into(), "sec".into()),
                ("issuer".into(), "https://accounts.google.com".into()),
                ("trustEmail".into(), "true".into()),
                ("syncMode".into(), "force".into()),
                ("clientAuthMethod".into(), "client_secret_post".into()),
                ("mappers".into(), r#"[{"name":"m","mapper_type":"attribute","config":{"claim":"c","attribute":"a"}}]"#.into()),
            ]
            .into_iter()
            .collect(),
        };
        let s = BrokerIdpSettings::new(&idp);
        assert_eq!(s.client_id(), Some("cid"));
        assert!(s.use_discovery());
        assert!(s.trust_email());
        assert_eq!(s.sync_mode(), BrokerSyncMode::Force);
        assert_eq!(s.client_auth_method(), BrokerClientAuthMethod::ClientSecretPost);
        assert_eq!(s.mappers().len(), 1);
        assert!(s.validate().is_empty());
        assert!(s.is_broker_provider());
    }

    #[test]
    fn settings_validate_reports_missing() {
        let idp = IdentityProviderConfig {
            id: crate::IdentityProviderId::new("id").unwrap(),
            alias: crate::Alias::new("broken").unwrap(),
            provider_id: ProviderId::Oidc,
            enabled: true,
            config: HashMap::new(),
        };
        let problems = BrokerIdpSettings::new(&idp).validate();
        assert!(problems.iter().any(|p| p.contains("clientId")));
        assert!(problems.iter().any(|p| p.contains("clientSecret")));
    }

    #[test]
    fn ldap_is_not_a_broker_provider() {
        let idp = IdentityProviderConfig {
            id: crate::IdentityProviderId::new("id").unwrap(),
            alias: crate::Alias::new("ad").unwrap(),
            provider_id: ProviderId::Ldap,
            enabled: true,
            config: HashMap::new(),
        };
        assert!(!BrokerIdpSettings::new(&idp).is_broker_provider());
    }

    #[test]
    fn presets_cover_the_four_social_providers_plus_generic() {
        let presets = identity_provider_presets();
        let ids: Vec<&str> = presets.iter().map(|p| p.provider_id.as_str()).collect();
        for expected in ["oidc", "google", "microsoft", "github", "facebook"] {
            assert!(ids.contains(&expected), "missing preset {expected}");
        }
        let github = presets.iter().find(|p| p.provider_id == "github").unwrap();
        assert_eq!(github.config.get("useDiscovery").map(String::as_str), Some("false"));
    }
}
