// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Request and response representations (DTOs) for the Admin REST API.

use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use issuerd_core::{
    AdminEvent, Algorithm, Alias, AuthenticatorConfig, Client, ClientAuthenticatorType, ClientId,
    ClientIdentifier, ClientProtocol, ClientScope, ClientScopeId, Credential, CredentialId,
    CredentialType, DisplayName, Email, Event, EventType, FlowConfig, FlowStage, FlowStageId,
    Group, GroupId, GroupName, GroupPath, IdentityProviderConfig, KeyStatus, MapperId, MapperType,
    OperationType, OtpHashAlgorithm, OtpPolicy, ProtocolMapper, ProviderId, Realm, RealmId,
    RealmName, RedirectUri, Requirement, ResourceType, Role, RoleId, RoleName, SecondsNonZero,
    SslRequired, ThemeName, User, UserId, UserSession, Username, WebOrigin,
};

// ---------------------------------------------------------------------------
// Representations
// ---------------------------------------------------------------------------

/// A single enum value suitable for populating dropdowns and comboboxes.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct EnumValueRepresentation {
    /// Machine-readable identifier used when saving configuration.
    pub id: String,
    /// Human-readable label shown in the UI.
    pub name: String,
    /// Optional longer description of the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Aggregated server metadata containing all available enum lists.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ServerInfoRepresentation {
    /// Supported client protocols.
    pub protocols: Vec<EnumValueRepresentation>,
    /// SSL requirement levels.
    pub ssl_required: Vec<EnumValueRepresentation>,
    /// Event types available for filtering.
    pub event_types: Vec<EnumValueRepresentation>,
    /// Event listener ids that can be activated per realm; only
    /// `logging` is built in.
    pub event_listeners: Vec<EnumValueRepresentation>,
    /// Supported credential types.
    pub credential_types: Vec<EnumValueRepresentation>,
    /// Supported signing algorithms.
    pub algorithms: Vec<EnumValueRepresentation>,
    /// Supported OAuth2 grant types.
    pub grant_types: Vec<EnumValueRepresentation>,
    /// Supported OIDC response types.
    pub response_types: Vec<EnumValueRepresentation>,
    /// Supported OIDC response modes.
    pub response_modes: Vec<EnumValueRepresentation>,
    /// Authentication flow stage requirements.
    pub requirements: Vec<EnumValueRepresentation>,
    /// Registered authenticator providers available for flow executions —
    /// drives the execution provider dropdown in the flow editor.
    pub authenticators: Vec<EnumValueRepresentation>,
    /// Supported identity provider types.
    pub provider_ids: Vec<EnumValueRepresentation>,
    /// Supported client authenticator types.
    pub client_authenticator_types: Vec<EnumValueRepresentation>,
    /// Admin event operation types.
    pub operation_types: Vec<EnumValueRepresentation>,
    /// OIDC prompt values.
    pub prompts: Vec<EnumValueRepresentation>,
    /// Admin event resource types.
    pub resource_types: Vec<EnumValueRepresentation>,
    /// Supported password hashing algorithms.
    pub hash_algorithms: Vec<EnumValueRepresentation>,
    /// Authentication methods used to establish sessions.
    pub auth_methods: Vec<EnumValueRepresentation>,
    /// PKCE code challenge methods.
    pub pkce_code_challenge_methods: Vec<EnumValueRepresentation>,
    /// JWK use values.
    pub jwk_use: Vec<EnumValueRepresentation>,
    /// JWK key types.
    pub jwk_key_types: Vec<EnumValueRepresentation>,
    /// LDAP server vendor presets.
    pub ldap_vendors: Vec<EnumValueRepresentation>,
    /// LDAP search scopes.
    pub ldap_search_scopes: Vec<EnumValueRepresentation>,
    /// Federation provider edit modes.
    pub edit_modes: Vec<EnumValueRepresentation>,
    /// Required actions that can be assigned to users.
    pub required_actions: Vec<EnumValueRepresentation>,
    /// TOTP hash algorithms (Keycloak `HmacSHA*` spellings).
    pub otp_algorithms: Vec<EnumValueRepresentation>,
    /// Broker sync modes (`import` / `force`).
    pub broker_sync_modes: Vec<EnumValueRepresentation>,
    /// Broker token-endpoint client authentication methods.
    pub broker_client_auth_methods: Vec<EnumValueRepresentation>,
    /// Identity provider mapper types.
    pub idp_mapper_types: Vec<EnumValueRepresentation>,
    /// OIDC protocol mapper types — drives the mapper-type
    /// dropdowns on client-scope and dedicated-scope forms.
    pub mapper_types: Vec<EnumValueRepresentation>,
    /// Identity provider presets: config templates that prefill the IdP form
    /// for well-known providers.
    pub identity_provider_presets: Vec<issuerd_core::IdpPreset>,
    /// UI locales with a built-in message bundle.
    pub locales: Vec<EnumValueRepresentation>,
    /// Available login themes (built-in plus themes directory scan).
    pub themes: Vec<EnumValueRepresentation>,
    /// OIDC subject identifier types (`public` / `pairwise`) —
    /// drives the client-form subject-type dropdown.
    pub subject_types: Vec<EnumValueRepresentation>,
    /// Client installation/adapter-config providers — drives the format
    /// dropdown of the "Download adapter config" dialog. Each `id` is accepted
    /// by `GET /admin/realms/{realm}/clients/{id}/installation/providers/{provider_id}`.
    pub client_installations: Vec<ClientInstallationProviderRepresentation>,
}

/// Metadata describing one client installation/adapter-config provider,
/// mirroring Keycloak's `clientInstallations` server-info entries.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ClientInstallationProviderRepresentation {
    /// Provider id accepted by the installation endpoint (e.g.
    /// `keycloak-oidc-keycloak-json`).
    pub id: String,
    /// Client protocol this provider applies to (`openid-connect`).
    pub protocol: String,
    /// Human-readable format label shown in the UI.
    pub display_type: String,
    /// Longer explanation of the format and how to use the downloaded file.
    pub help_text: String,
    /// Suggested filename when saving the downloaded config.
    pub filename: String,
    /// Media type of the downloaded config.
    pub media_type: String,
    /// When true, the format is binary/download-only and cannot be previewed.
    pub download_only: bool,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct RealmRepresentation {
    /// Unique realm identifier. Auto-generated if omitted on creation.
    pub id: Option<String>,
    /// Unique realm name (e.g. "master" or "acme-corp").
    pub realm: String,
    /// Human-readable display name shown on login pages.
    pub display_name: Option<String>,
    /// Whether the realm is active. Defaults to `true`.
    pub enabled: Option<bool>,
    /// SSL enforcement level: `"none"`, `"external"`, or `"all"`.
    pub ssl_required: Option<SslRequired>,
    /// JSON-serialized password policy configuration.
    pub password_policy: Option<String>,
    /// Access token lifetime in seconds.
    pub access_token_lifespan: Option<i64>,
    /// Refresh token lifetime in seconds.
    pub refresh_token_lifespan: Option<i64>,
    /// SSO session idle timeout in seconds.
    pub sso_session_idle_timeout: Option<i64>,
    /// Maximum SSO session lifetime in seconds.
    pub sso_session_max_lifespan: Option<i64>,
    /// Offline session idle timeout in seconds.
    pub offline_session_idle_timeout: Option<i64>,
    /// Theme used for the login UI.
    pub login_theme: Option<String>,
    /// Theme used for email templates.
    pub email_theme: Option<String>,
    /// Theme used for the admin console.
    pub admin_theme: Option<String>,
    /// Whether realm-level internationalization (localized login/email) is enabled.
    #[serde(rename = "internationalizationEnabled")]
    pub internationalization_enabled: Option<bool>,
    /// Locale tags (BCP 47) this realm can render.
    #[serde(rename = "supportedLocales")]
    pub supported_locales: Option<Vec<String>>,
    /// Fallback locale used when the client does not negotiate one.
    #[serde(rename = "defaultLocale")]
    pub default_locale: Option<String>,
    /// Name of the default realm role assigned to new users.
    pub default_role: Option<String>,
    /// Arbitrary realm-level attributes.
    pub attributes: Option<HashMap<String, String>>,
    /// Whether brute-force detection (login-failure tracking + lockout) is enabled.
    #[serde(rename = "bruteForceProtected")]
    pub brute_force_protected: Option<bool>,
    /// Number of consecutive login failures before the account+IP is locked.
    #[serde(rename = "maxLoginFailures")]
    pub max_login_failures: Option<u32>,
    /// Progressive lockout wait increment in seconds (0 = fixed lockout duration).
    #[serde(rename = "waitIncrementSecs")]
    pub wait_increment_secs: Option<u32>,
    /// Upper bound for the progressive lockout wait, in seconds.
    #[serde(rename = "maxFailureWaitSecs")]
    pub max_failure_wait_secs: Option<u32>,
    /// Fixed lockout duration in seconds (used when the wait increment is 0).
    #[serde(rename = "lockoutDurationSecs")]
    pub lockout_duration_secs: Option<u32>,
    /// Whether self-registration is enabled for this realm.
    #[serde(rename = "registrationEnabled")]
    pub registration_enabled: Option<bool>,
    /// Whether users may reset their own password ("forgot password").
    #[serde(rename = "resetPasswordAllowed")]
    pub reset_password_allowed: Option<bool>,
    /// Whether the login form offers a "remember me" checkbox.
    #[serde(rename = "rememberMeEnabled")]
    pub remember_me_enabled: Option<bool>,
    /// Whether email verification is enforced for this realm.
    #[serde(rename = "verifyEmailEnabled")]
    pub verify_email_enabled: Option<bool>,
    /// Whether users may log in with their email address instead of the username.
    #[serde(rename = "loginWithEmailAllowed")]
    pub login_with_email_allowed: Option<bool>,
    /// Whether multiple accounts may share the same email address.
    #[serde(rename = "duplicateEmailsAllowed")]
    pub duplicate_emails_allowed: Option<bool>,
    /// Whether users may change their own username.
    #[serde(rename = "editUsernameAllowed")]
    pub edit_username_allowed: Option<bool>,
    /// Idle timeout in seconds for sessions established via "remember me".
    #[serde(rename = "rememberMeSessionIdleSecs")]
    pub remember_me_session_idle_secs: Option<i64>,
    /// TOTP hash algorithm: `"HmacSHA1"`, `"HmacSHA256"`, or `"HmacSHA512"`.
    #[serde(rename = "otpPolicyAlgorithm")]
    pub otp_policy_algorithm: Option<String>,
    /// TOTP code length: 6 or 8 digits.
    #[serde(rename = "otpPolicyDigits")]
    pub otp_policy_digits: Option<i32>,
    /// TOTP time-step length in seconds.
    #[serde(rename = "otpPolicyPeriod")]
    pub otp_policy_period: Option<i32>,
    /// Number of future time steps accepted when verifying a TOTP code.
    #[serde(rename = "otpPolicyLookAheadWindow")]
    pub otp_policy_look_ahead_window: Option<i32>,
    /// Whether login/user events are recorded for this realm.
    #[serde(rename = "eventsEnabled")]
    pub events_enabled: Option<bool>,
    /// How long events are retained, in seconds (0 = never expire).
    #[serde(rename = "eventsExpiration")]
    pub events_expiration_secs: Option<i64>,
    /// Whether admin (audit) events are recorded for this realm.
    #[serde(rename = "adminEventsEnabled")]
    pub admin_events_enabled: Option<bool>,
    /// When `true`, admin events store the request body representation.
    #[serde(rename = "adminEventsDetailsEnabled")]
    pub include_representations: Option<bool>,
    /// Event listener ids active for this realm (default `["logging"]`).
    #[serde(rename = "eventsListeners")]
    pub events_listeners: Option<Vec<String>>,
    /// Revocation cutoff: tokens issued before this Unix timestamp are
    /// rejected (0 = no cutoff).
    #[serde(rename = "notBefore")]
    pub not_before: Option<i64>,
    /// Group paths assigned to every new user on creation.
    #[serde(rename = "defaultGroups")]
    pub default_groups: Option<Vec<String>>,
    /// Alias of the browser login flow (default `"browser"`).
    #[serde(rename = "browserFlow")]
    pub browser_flow: Option<String>,
    /// Alias of the direct grant flow (default `"direct grant"`).
    #[serde(rename = "directGrantFlow")]
    pub direct_grant_flow: Option<String>,
    /// Alias of the reset credentials flow (default `"reset credentials"`).
    #[serde(rename = "resetCredentialsFlow")]
    pub reset_credentials_flow: Option<String>,
    /// Alias of the first broker login flow (default `"first broker login"`).
    #[serde(rename = "firstBrokerLoginFlow")]
    pub first_broker_login_flow: Option<String>,
    /// Alias of the registration flow (default `"registration"`).
    #[serde(rename = "registrationFlow")]
    pub registration_flow: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct UserRepresentation {
    /// Unique user identifier. Auto-generated if omitted on creation.
    pub id: Option<String>,
    /// Login username. Must be unique within the realm.
    pub username: String,
    /// Email address.
    pub email: Option<String>,
    /// Given name.
    pub first_name: Option<String>,
    /// Family name.
    pub last_name: Option<String>,
    /// Whether the account is active. Defaults to `true`.
    pub enabled: Option<bool>,
    /// Whether the email address has been verified.
    pub email_verified: Option<bool>,
    /// ISO-8601 timestamp of account creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Custom user attributes (key → list of values).
    pub attributes: Option<HashMap<String, Vec<String>>>,
    /// User credentials (password, TOTP, etc.).
    pub credentials: Option<Vec<CredentialRepresentation>>,
    /// Realm role names assigned to this user.
    pub realm_roles: Option<Vec<String>>,
    /// Client role names mapped by client ID.
    pub client_roles: Option<HashMap<String, Vec<String>>>,
    /// Group IDs the user belongs to.
    pub groups: Option<Vec<String>>,
    /// Required actions assigned to the user (e.g. `"UPDATE_PASSWORD"`, `"VERIFY_EMAIL"`).
    #[serde(rename = "requiredActions")]
    pub required_actions: Option<Vec<String>>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct CredentialRepresentation {
    /// Unique credential identifier.
    pub id: Option<String>,
    /// Credential type: `"password"`, `"totp"`, `"hotp"`, `"web_authn"`, etc.
    #[serde(rename = "type")]
    pub credential_type: CredentialType,
    /// Human-readable label shown to the user (e.g. "My laptop").
    pub user_label: Option<String>,
    /// Creation timestamp in milliseconds since the Unix epoch (Keycloak `createdDate`).
    pub created_date: Option<i64>,
    /// Encrypted or hashed secret data.
    pub secret_data: Option<String>,
    /// Additional credential metadata in JSON format.
    pub credential_data: Option<String>,
    /// Priority order when multiple credentials of the same type exist.
    pub priority: Option<i32>,
    /// Whether the credential is temporary and must be changed on next login.
    pub temporary: Option<bool>,
    /// Plain-text value used when creating or updating a credential (e.g. new password). Never returned on read.
    pub value: Option<String>,
}

impl CredentialRepresentation {
    /// Metadata-only view of a stored credential for API responses.
    ///
    /// Carries id/type/label/createdDate/priority plus the non-secret
    /// `credential_data` metadata; `secret_data` and `value` are **never**
    /// populated. Prefer this over [`From<Credential>`] on every response
    /// path — the `From` impl predates the credentials CRUD endpoints and
    /// lossy-UTF8-encodes the secret bytes.
    pub fn redacted_from(c: &Credential) -> Self {
        Self {
            id: Some(c.id.to_string()),
            credential_type: c.credential_type.clone(),
            user_label: c.user_label.clone(),
            created_date: Some(c.created_date.timestamp_millis()),
            secret_data: None,
            credential_data: Some(c.credential_data.to_string()),
            priority: Some(c.priority),
            temporary: Some(
                c.credential_data.get("temporary").and_then(|v| v.as_bool()).unwrap_or(false),
            ),
            value: None,
        }
    }
}

impl UserRepresentation {
    /// Clone with all credential secrets redacted, suitable for persisting in
    /// the immutable admin-event audit log (readable via `view-events`).
    pub fn redacted_for_audit(&self) -> Self {
        let mut redacted = self.clone();
        if let Some(credentials) = redacted.credentials.as_mut() {
            for cred in credentials.iter_mut() {
                cred.value = None;
                cred.secret_data = None;
            }
        }
        redacted
    }
}

/// Request body for `PUT /users/{id}/credentials/{credentialId}`:
/// only the user-facing label is mutable. The primary wire spelling is
/// Keycloak's `userLabel`; the crate-local snake_case variant is accepted as
/// an alias for consistency with [`CredentialRepresentation`].
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct UpdateCredentialLabelRequest {
    /// New human-readable label (`null` clears it).
    #[serde(rename = "userLabel", alias = "user_label")]
    pub user_label: Option<String>,
}

/// Query parameters for `PUT /users/{id}/execute-actions-email`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ExecuteActionsEmailParams {
    /// URL the user is redirected to after completing the required actions.
    pub redirect_uri: Option<String>,
    /// Action-token validity in seconds. Defaults to 43200 (12 hours).
    pub lifespan: Option<i64>,
}

/// Token set returned by `POST /users/{id}/impersonation`: a full
/// OIDC token response issued to the impersonated session, so an admin
/// console can act as the target user.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ImpersonationResponse {
    /// Signed access token of the impersonated session.
    pub access_token: String,
    /// Refresh token of the impersonated session.
    pub refresh_token: String,
    /// ID token of the impersonated session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Access-token validity in seconds.
    pub expires_in: i64,
    /// Always `"Bearer"`.
    pub token_type: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ClientRepresentation {
    /// Unique client identifier. Auto-generated if omitted on creation.
    pub id: Option<String>,
    /// Client ID used in OIDC/OAuth2 requests (e.g. "my-app").
    pub client_id: String,
    /// Human-readable name.
    pub name: Option<String>,
    /// Brief description of the client's purpose.
    pub description: Option<String>,
    /// Whether the client is active. Defaults to `true`.
    pub enabled: Option<bool>,
    /// Protocol: `"openid-connect"` or `"saml"`. Defaults to `"openid-connect"`.
    pub protocol: Option<ClientProtocol>,
    /// If `true`, the client does not require a client secret.
    pub public_client: Option<bool>,
    /// If `true`, the client is a bearer-only service (no login UI).
    pub bearer_only: Option<bool>,
    /// Client authentication method: `"client-secret"`, `"client-jwt"`, etc.
    pub client_authenticator_type: Option<ClientAuthenticatorType>,
    /// Allowed redirect URIs for authorization code flows.
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed CORS origins.
    pub web_origins: Option<Vec<String>>,
    /// Scopes included in tokens by default.
    pub default_scopes: Option<Vec<String>>,
    /// Scopes that can be requested but are not included by default.
    pub optional_scopes: Option<Vec<String>>,
    /// If `true`, user consent is required for this client.
    pub consent_required: Option<bool>,
    /// If `true`, the client receives all realm roles in the token.
    pub full_scope_allowed: Option<bool>,
    /// If `true`, the client has a dedicated service account
    /// (`service-account-{client_id}`) backing the client-credentials grant.
    pub service_accounts_enabled: Option<bool>,
    /// Client-local protocol mappers (claim mappings applied in addition to
    /// the mappers of granted client scopes).
    pub protocol_mappers: Option<Vec<issuerd_core::ProtocolMapper>>,
    /// Client secret (only used when creating/updating; never returned in list responses).
    pub secret: Option<String>,
    /// Arbitrary client-level attributes.
    pub attributes: Option<HashMap<String, String>>,
}

impl ClientRepresentation {
    /// Clone with the client secret redacted, suitable for persisting in the
    /// immutable admin-event audit log (readable via `view-events`).
    pub fn redacted_for_audit(&self) -> Self {
        let mut redacted = self.clone();
        redacted.secret = None;
        redacted
    }
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ClientSecret {
    /// Type of secret: always `"client-secret"` for now.
    #[serde(rename = "type")]
    pub secret_type: String,
    /// The secret value.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Client installation / adapter config
// ---------------------------------------------------------------------------

/// Credentials block of the Keycloak adapter config (Keycloak's
/// `AdapterConfig.credentials`).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct AdapterCredentials {
    /// The client secret.
    pub secret: String,
}

/// Keycloak OIDC adapter config (`keycloak.json`) as produced by Keycloak's
/// `KeycloakOIDCClientInstallation`. Field names on the wire are kebab-case,
/// matching the reference implementation exactly.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct KeycloakAdapterConfigRepresentation {
    /// Realm name.
    pub realm: String,
    /// Server base URL with a trailing slash (the configured issuer base).
    #[serde(rename = "auth-server-url")]
    pub auth_server_url: String,
    /// SSL requirement of the realm (`none` / `external` / `all`).
    #[serde(rename = "ssl-required")]
    pub ssl_required: SslRequired,
    /// The client id (`resource` in adapter terminology).
    pub resource: String,
    /// Present (true) when the client is a public client.
    #[serde(rename = "public-client", skip_serializing_if = "Option::is_none")]
    pub public_client: Option<bool>,
    /// Present (true) when the client is bearer-only.
    #[serde(rename = "bearer-only", skip_serializing_if = "Option::is_none")]
    pub bearer_only: Option<bool>,
    /// Present (true) when the client defines its own roles.
    #[serde(
        rename = "use-resource-role-mappings",
        skip_serializing_if = "Option::is_none"
    )]
    pub use_resource_role_mappings: Option<bool>,
    /// Present (true) when the client defines its own roles, instructing the
    /// adapter to verify the token audience.
    #[serde(
        rename = "verify-token-audience",
        skip_serializing_if = "Option::is_none"
    )]
    pub verify_token_audience: Option<bool>,
    /// Client credentials (secret) — only for confidential clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<AdapterCredentials>,
}

/// Generic (product-neutral) OIDC client configuration — endpoint URLs plus
/// the client's own registration data.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct GenericOidcClientConfigRepresentation {
    /// Realm issuer URL.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// UserInfo endpoint URL.
    pub userinfo_endpoint: String,
    /// JWKS endpoint URL.
    pub jwks_uri: String,
    /// RP-initiated logout endpoint URL.
    pub end_session_endpoint: String,
    /// Token introspection endpoint URL.
    pub introspection_endpoint: String,
    /// The client id.
    pub client_id: String,
    /// The client secret — only present for confidential clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
}

/// Response of the client installation endpoint; the concrete shape depends on
/// the requested provider id.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ClientInstallationRepresentation {
    /// `keycloak-oidc-keycloak-json` — Keycloak adapter config.
    Keycloak(KeycloakAdapterConfigRepresentation),
    /// `generic-oidc-json` — generic OIDC client config.
    GenericOidc(GenericOidcClientConfigRepresentation),
}

/// Request body for minting an initial access token (Keycloak's
/// `clients-initial-access` API). The token gates dynamic client
/// registration at `POST /realms/{realm}/clients-registrations/openid-connect`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct InitialAccessTokenCreateRequest {
    /// Lifetime in seconds from now (`0`/omitted = never expires).
    pub expiration: Option<u64>,
    /// Maximum number of registrations this token may perform
    /// (`0`/omitted = unlimited).
    pub count: Option<u32>,
}

/// An initial access token. The raw `token` is returned exactly
/// once, at mint time; list responses carry no token material.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct InitialAccessTokenRepresentation {
    /// Server-assigned token identifier (used for revocation).
    pub id: String,
    /// The raw token — only present in the mint response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Lifetime in seconds from minting (`0` = never expires).
    pub expiration: u64,
    /// Maximum number of allowed registrations (`0` = unlimited).
    pub count: u32,
    /// Registrations still allowed (`0` when `count` is unlimited).
    pub remaining_count: u32,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct RoleRepresentation {
    /// Unique role identifier.
    pub id: Option<String>,
    /// Role name. Must be unique within its container.
    pub name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Whether this role is a composite of other roles.
    pub composite: Option<bool>,
    /// IDs of roles included in this composite.
    pub composites: Option<Vec<RoleName>>,
    /// Whether this is a client role (as opposed to a realm role).
    pub client_role: Option<bool>,
    /// ID of the realm or client that owns this role.
    pub container_id: Option<String>,
    /// Arbitrary role attributes.
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

/// A named, reusable bundle of protocol mappers.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ClientScopeRepresentation {
    /// Unique client scope identifier. Auto-generated if omitted on creation.
    pub id: Option<String>,
    /// Scope name (e.g. `"profile"`). Must be unique within the realm.
    pub name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Protocol: `"openid-connect"` (default) or `"saml"`.
    pub protocol: Option<ClientProtocol>,
    /// Arbitrary scope-level attributes.
    pub attributes: Option<HashMap<String, String>>,
    /// Protocol mappers bundled in this scope. Populated on single-scope GET;
    /// omitted on list responses (Keycloak behavior).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_mappers: Option<Vec<ProtocolMapperRepresentation>>,
}

/// A configurable claim mapping attached to a client or client scope
/// (Keycloak `ProtocolMapperRepresentation`).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ProtocolMapperRepresentation {
    /// Unique mapper identifier. Auto-generated if omitted on creation.
    pub id: Option<String>,
    /// Mapper name. Must be unique within the parent client or client scope.
    pub name: String,
    /// Protocol: always `"openid-connect"`; other values are rejected with 400.
    pub protocol: Option<String>,
    /// Mapper type, spelled with the Keycloak `protocolMapper` ids
    /// (e.g. `"oidc-usermodel-attribute-mapper"`).
    pub protocol_mapper: MapperType,
    /// Mapper configuration; see the well-known keys in `issuerd_core::mapper_config`.
    pub config: Option<HashMap<String, String>>,
}

/// Combined realm + client role mappings of a user, group, or client
/// (Keycloak `MappingsRepresentation`).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Default)]
pub struct MappingsRepresentation {
    /// Realm role mappings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_mappings: Option<Vec<RoleRepresentation>>,
    /// Client role mappings keyed by the client's `client_id` string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_mappings: Option<HashMap<String, ClientMappingsRepresentation>>,
}

/// Role mappings of one client (Keycloak `ClientMappingsRepresentation`).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct ClientMappingsRepresentation {
    /// Internal client UUID.
    pub id: String,
    /// The client's `client_id` string.
    pub client: String,
    /// Mapped roles.
    pub mappings: Vec<RoleRepresentation>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
#[schema(no_recursion)]
pub struct GroupRepresentation {
    /// Unique group identifier.
    pub id: Option<String>,
    /// Group name.
    pub name: String,
    /// Hierarchical path (e.g. "/top-level/sub-group").
    pub path: Option<String>,
    /// Custom group attributes.
    pub attributes: Option<HashMap<String, Vec<String>>>,
    /// Realm role names assigned to this group.
    pub realm_roles: Option<Vec<RoleName>>,
    /// Client role names mapped by client ID.
    pub client_roles: Option<HashMap<ClientId, Vec<RoleName>>>,
    /// Nested sub-groups.
    pub sub_groups: Option<Vec<GroupRepresentation>>,
    /// Parent group id (tri-state): absent = leave the
    /// stored parent unchanged on update; explicit `null` = move to root;
    /// a value = move under that group. Always populated on read (`null` for
    /// top-level groups).
    #[serde(default, deserialize_with = "deserialize_some")]
    pub parent_id: Option<Option<GroupId>>,
}

/// Serde helper for tri-state fields: with `#[serde(default,
/// deserialize_with = "deserialize_some")]` an absent field deserializes to
/// `None`, a present `null` to `Some(None)`, and a present value to
/// `Some(Some(v))` — plain `Option<Option<T>>` alone cannot tell the first
/// two apart.
fn deserialize_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct UserSessionRepresentation {
    /// Unique session identifier.
    pub id: String,
    /// Username used when the session was created.
    pub username: String,
    /// Unique identifier of the authenticated user.
    pub user_id: String,
    /// IP address of the client that created the session.
    pub ip_address: String,
    /// Session start time as a Unix timestamp.
    pub started: i64,
    /// Last access time as a Unix timestamp.
    pub last_access: i64,
    /// Offline session: backs an `offline_access` refresh token
    /// and survives SSO session expiry/logout.
    #[serde(default)]
    pub offline: bool,
    /// Map of client IDs to authentication methods used in this session.
    pub clients: HashMap<String, String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct EventRepresentation {
    /// Unique event identifier.
    pub id: Option<String>,
    /// Event time as a Unix timestamp.
    pub time: i64,
    /// Event type: `"login"`, `"logout"`, `"register"`, `"error"`, etc.
    pub event_type: EventType,
    /// ID of the realm where the event occurred.
    pub realm_id: String,
    /// Client ID associated with the event, if any.
    pub client_id: Option<String>,
    /// User ID associated with the event, if any.
    pub user_id: Option<String>,
    /// Username of the user associated with the event, resolved at query time.
    /// Falls back to the `username` event detail when the user no longer
    /// exists in the realm (deleted or not-yet-synced federated user).
    pub username: Option<String>,
    /// ID of the session associated with the event, if any.
    pub session_id: Option<String>,
    /// IP address of the client that triggered the event.
    pub ip_address: Option<String>,
    /// Additional event details (e.g. authentication method, redirect URI).
    pub details: Option<HashMap<String, String>>,
    /// Error message if the event represents a failure.
    pub error: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct AdminEventRepresentation {
    /// Unique event identifier.
    pub id: Option<String>,
    /// Event time as a Unix timestamp.
    pub time: i64,
    /// ID of the realm where the event occurred.
    pub realm_id: String,
    /// Realm ID of the authenticated admin that triggered the event.
    pub auth_realm_id: Option<String>,
    /// Client ID of the authenticated admin that triggered the event.
    pub auth_client_id: Option<String>,
    /// User ID of the authenticated admin that triggered the event.
    pub auth_user_id: Option<String>,
    /// Username of the authenticated admin, resolved at query time from
    /// `auth_realm_id` (master-realm tokens may administer other realms).
    pub auth_username: Option<String>,
    /// Operation type: `"CREATE"`, `"UPDATE"`, `"DELETE"`, `"ACTION"`.
    pub operation_type: OperationType,
    /// Resource type that was modified (e.g. `"USER"`, `"CLIENT"`, `"REALM"`).
    pub resource_type: ResourceType,
    /// Resource path that was modified (e.g. `"users/123"`).
    pub resource_path: String,
    /// JSON representation of the resource after the operation.
    pub representation: Option<String>,
    /// Error message if the operation failed.
    pub error: Option<String>,
}

/// Per-realm audit event configuration, exchanged via
/// `GET/PUT /admin/realms/{realm}/events/config`.
///
/// All fields are optional so the same shape serves both directions: `GET`
/// returns every field populated; on `PUT` an absent field keeps its current
/// value.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RealmEventsConfigRepresentation {
    /// Whether login/user events are recorded for this realm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_enabled: Option<bool>,
    /// How long events are retained, in seconds (0 = never expire).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_expiration: Option<i64>,
    /// Whether admin (audit) events are recorded for this realm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_events_enabled: Option<bool>,
    /// When `true`, admin events store the request body representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_events_details_enabled: Option<bool>,
    /// Event listener ids active for this realm. Any string is accepted
    /// (custom listener SPIs); only `logging` is built in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_listeners: Option<Vec<String>>,
}

impl From<&Realm> for RealmEventsConfigRepresentation {
    fn from(r: &Realm) -> Self {
        Self {
            events_enabled: Some(r.events_enabled),
            events_expiration: Some(r.events_expiration_secs),
            admin_events_enabled: Some(r.admin_events_enabled),
            admin_events_details_enabled: Some(r.include_representations),
            events_listeners: Some(r.events_listeners.clone()),
        }
    }
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct IdentityProviderRepresentation {
    /// Unique alias used to reference this IdP in URLs and login flows.
    pub alias: Alias,
    /// Human-readable display name shown on the login page.
    pub display_name: Option<String>,
    /// Provider type: `"google"`, `"github"`, `"oidc"`, `"saml"`, etc.
    pub provider_id: ProviderId,
    /// Whether the provider is active. Defaults to `true`.
    pub enabled: Option<bool>,
    /// Provider-specific configuration (client ID, authorization URL, etc.).
    pub config: Option<HashMap<String, String>>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct KeyMetadataRepresentation {
    /// Key provider identifier (e.g. `"rsa"`).
    pub provider_id: String,
    /// Key ID (`kid`) referenced in JWKS and JWT headers.
    pub kid: String,
    /// Key status: `"ACTIVE"` or `"PASSIVE"`.
    pub status: KeyStatus,
    /// Signature algorithm: `"RS256"`, `"ES256"`, etc.
    pub algorithm: Algorithm,
    /// Base64-encoded public key modulus (for RSA keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// PEM-encoded X.509 certificate, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct KeysMetadataRepresentation {
    /// Map of algorithm → `kid` for currently active signing keys.
    pub active: HashMap<String, String>,
    /// List of all keys including passive (non-signing) keys.
    pub passive: Vec<KeyMetadataRepresentation>,
}

/// Optional request body for `POST /admin/realms/{realm}/keys/rotate`.
/// Both fields default to the newest active key's parameters
/// (the server-default algorithm EdDSA when no key exists).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Default)]
pub struct RotateKeyRequest {
    /// JWS algorithm of the new key (e.g. `"RS256"`, `"ES256"`, `"ES512"`,
    /// `"EdDSA"`). Rotation keeps exactly one active key per algorithm: other
    /// active keys of the SAME algorithm are demoted, active keys of other
    /// algorithms keep signing for the realms pinned to them.
    pub algorithm: Option<String>,
    /// RSA key size in bits (2048..=8192); ignored for EC/OKP algorithms.
    /// Symmetric (HMAC) algorithms are rejected outright.
    pub key_size: Option<u32>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct FlowRepresentation {
    /// Unique flow alias (e.g. "browser", "direct grant").
    pub alias: Alias,
    /// Flow provider identifier (e.g. `"basic-flow"`).
    pub provider_id: Option<String>,
    /// Whether this is a top-level flow that can be bound to authentication bindings.
    pub top_level: Option<bool>,
    /// Whether this flow is built-in and cannot be deleted.
    pub built_in: Option<bool>,
    /// Ordered list of stages (authenticators or sub-flows) in this flow.
    pub stages: Option<Vec<FlowStageRepresentation>>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct FlowStageRepresentation {
    /// Unique stage identifier.
    pub id: String,
    /// Execution requirement: `"required"`, `"alternative"`, `"optional"`, `"disabled"`, or `"conditional"`.
    pub requirement: Requirement,
    /// Authenticator or execution provider identifier.
    pub authenticator: Alias,
    /// Priority order within the flow (lower numbers execute first).
    pub priority: i32,
    /// Alias of a sub-flow to execute, if this stage represents a sub-flow reference.
    pub sub_flow_alias: Option<Alias>,
    /// Authenticator configuration attached to this stage, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_config: Option<AuthenticatorConfigRepresentation>,
    /// Whether an authenticator configuration is attached to this stage. Lets
    /// clients skip the `GET .../executions/{execution_id}/config` probe, which
    /// answers 404 when no configuration exists. Output-only: ignored on write.
    #[serde(default)]
    pub has_config: bool,
    /// Alias of the flow owning this stage. Only populated by the cross-flow
    /// execution lookup (`GET .../authentication/executions/{execution_id}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_alias: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuthenticatorConfigRepresentation {
    /// Unique alias of this authenticator configuration.
    pub alias: Alias,
    /// Free-form key/value configuration consumed by the authenticator.
    pub config: HashMap<String, serde_json::Value>,
}

/// Request body for `POST .../authentication/flows/{flow_alias}/copy`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct CopyFlowRequest {
    /// Alias for the new flow copy.
    #[serde(rename = "newName")]
    pub new_name: String,
}

/// Request body for `POST .../authentication/flows/{flow_alias}/executions/execution`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct AddExecutionRequest {
    /// Authenticator provider id (see `/admin/enums/authenticators`).
    pub provider: String,
    /// Execution requirement; defaults to `required`.
    pub requirement: Option<Requirement>,
}

/// Request body for `POST .../authentication/flows/{flow_alias}/executions/flow`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct AddFlowExecutionRequest {
    /// Alias for the new sub-flow.
    pub alias: String,
    /// Execution requirement; defaults to `required`.
    pub requirement: Option<Requirement>,
}

/// Request body for `PUT .../authentication/flows/{flow_alias}/executions`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct UpdateExecutionRequest {
    /// Identifier of the stage to update.
    pub id: String,
    /// New execution requirement, if changing.
    pub requirement: Option<Requirement>,
    /// New priority, if changing.
    pub priority: Option<i32>,
}

/// Request body for `POST/PUT .../authentication/executions/{execution_id}/config`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct AuthenticatorConfigRequest {
    /// Alias for the authenticator configuration.
    pub alias: String,
    /// Free-form key/value configuration consumed by the authenticator.
    pub config: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct UserQueryParams {
    /// Search string matched against username, email, first name, and last name.
    pub search: Option<String>,
    /// Zero-based index of the first result to return.
    #[serde(default)]
    pub first: i32,
    /// Maximum number of results to return. Defaults to 20.
    #[serde(default = "default_max")]
    pub max: i32,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct EventQueryParams {
    /// Filter events by type (e.g. `"login"`, `"logout"`).
    pub event_type: Option<EventType>,
    /// RFC-3339 start timestamp for the query range.
    pub date_from: Option<String>,
    /// RFC-3339 end timestamp for the query range.
    pub date_to: Option<String>,
    /// Zero-based index of the first result to return.
    #[serde(default)]
    pub first: i32,
    /// Maximum number of results to return. Defaults to 20.
    #[serde(default = "default_max")]
    pub max: i32,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AdminEventQueryParams {
    /// Filter admin events by operation type (e.g. `"CREATE"`, `"UPDATE"`).
    pub operation_type: Option<OperationType>,
    /// Filter admin events by resource type (e.g. `"USER"`, `"CLIENT"`).
    pub resource_type: Option<ResourceType>,
    /// RFC-3339 start timestamp for the query range.
    pub date_from: Option<String>,
    /// RFC-3339 end timestamp for the query range.
    pub date_to: Option<String>,
    /// Zero-based index of the first result to return.
    #[serde(default)]
    pub first: i32,
    /// Maximum number of results to return. Defaults to 20.
    #[serde(default = "default_max")]
    pub max: i32,
}

fn default_max() -> i32 {
    20
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct PaginationQueryParams {
    /// Zero-based index of the first result to return.
    #[serde(default)]
    pub first: i32,
    /// Maximum number of results to return. Defaults to 20.
    #[serde(default = "default_max")]
    pub max: i32,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct UserCountQueryParams {
    /// Search string matched against username, email, first name, and last name.
    pub search: Option<String>,
}

/// Total number of matching records for a paginated list.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct CountRepresentation {
    pub count: i64,
}

// ---------------------------------------------------------------------------
// Mappers
// ---------------------------------------------------------------------------

impl TryFrom<RealmRepresentation> for Realm {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: RealmRepresentation) -> Result<Self, Self::Error> {
        fn lifespan(
            value: Option<i64>,
            default: i64,
            field: &str,
        ) -> Result<SecondsNonZero, issuerd_core::IssuerdError> {
            SecondsNonZero::try_from(value.unwrap_or(default)).map_err(|e| {
                issuerd_core::IssuerdError::InvalidRequest(format!("invalid {field}: {e}"))
            })
        }

        let ssl_required = rep.ssl_required.unwrap_or(SslRequired::External);
        // Computed before any field of `rep` is moved by the consumptions
        // below (omitted fields fall back to the model defaults).
        let otp_policy_defaults = Realm::default().otp_policy;
        let otp_policy = otp_policy_from_rep(&rep, &otp_policy_defaults)?;
        let password_policy = rep
            .password_policy
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| {
                issuerd_core::IssuerdError::InvalidRequest(format!("invalid password_policy: {e}"))
            })?
            .unwrap_or_default();
        // Defaults for the extended realm fields come from `Realm::default()` so the
        // representation layer cannot drift from the model defaults.
        let defaults = Realm::default();
        Ok(Realm {
            id: match rep.id {
                Some(s) => RealmId::new(s)?,
                None => RealmId::new(issuerd_core::utils::generate_id())?,
            },
            name: RealmName::new(rep.realm)?,
            display_name: rep.display_name.map(DisplayName::new).transpose()?,
            enabled: rep.enabled.unwrap_or(true),
            ssl_required,
            password_policy,
            access_token_lifespan: lifespan(
                rep.access_token_lifespan,
                300,
                "access_token_lifespan",
            )?,
            refresh_token_lifespan: lifespan(
                rep.refresh_token_lifespan,
                1800,
                "refresh_token_lifespan",
            )?,
            sso_session_idle_timeout: lifespan(
                rep.sso_session_idle_timeout,
                1800,
                "sso_session_idle_timeout",
            )?,
            sso_session_max_lifespan: lifespan(
                rep.sso_session_max_lifespan,
                36000,
                "sso_session_max_lifespan",
            )?,
            offline_session_idle_timeout: lifespan(
                rep.offline_session_idle_timeout,
                2592000,
                "offline_session_idle_timeout",
            )?,
            login_theme: rep.login_theme.map(ThemeName::new).transpose()?,
            email_theme: rep.email_theme.map(ThemeName::new).transpose()?,
            admin_theme: rep.admin_theme.map(ThemeName::new).transpose()?,
            internationalization_enabled: rep
                .internationalization_enabled
                .unwrap_or(defaults.internationalization_enabled),
            supported_locales: rep.supported_locales.unwrap_or_default(),
            default_locale: rep.default_locale,
            default_role: rep.default_role,
            attributes: rep.attributes.unwrap_or_default(),
            brute_force_protected: rep
                .brute_force_protected
                .unwrap_or(defaults.brute_force_protected),
            max_login_failures: rep.max_login_failures.unwrap_or(defaults.max_login_failures),
            wait_increment_secs: rep.wait_increment_secs.unwrap_or(defaults.wait_increment_secs),
            max_failure_wait_secs: rep
                .max_failure_wait_secs
                .unwrap_or(defaults.max_failure_wait_secs),
            lockout_duration_secs: rep
                .lockout_duration_secs
                .unwrap_or(defaults.lockout_duration_secs),
            registration_enabled: rep.registration_enabled.unwrap_or(defaults.registration_enabled),
            reset_password_allowed: rep
                .reset_password_allowed
                .unwrap_or(defaults.reset_password_allowed),
            remember_me_enabled: rep.remember_me_enabled.unwrap_or(defaults.remember_me_enabled),
            verify_email_enabled: rep.verify_email_enabled.unwrap_or(defaults.verify_email_enabled),
            login_with_email_allowed: rep
                .login_with_email_allowed
                .unwrap_or(defaults.login_with_email_allowed),
            duplicate_emails_allowed: rep
                .duplicate_emails_allowed
                .unwrap_or(defaults.duplicate_emails_allowed),
            edit_username_allowed: rep
                .edit_username_allowed
                .unwrap_or(defaults.edit_username_allowed),
            remember_me_session_idle_secs: lifespan(
                rep.remember_me_session_idle_secs,
                604_800,
                "remember_me_session_idle_secs",
            )?,
            otp_policy,
            events_enabled: rep.events_enabled.unwrap_or(defaults.events_enabled),
            events_expiration_secs: rep
                .events_expiration_secs
                .unwrap_or(defaults.events_expiration_secs),
            admin_events_enabled: rep.admin_events_enabled.unwrap_or(defaults.admin_events_enabled),
            include_representations: rep
                .include_representations
                .unwrap_or(defaults.include_representations),
            events_listeners: rep.events_listeners.unwrap_or(defaults.events_listeners),
            not_before: rep.not_before.unwrap_or(defaults.not_before),
            default_groups: rep.default_groups.unwrap_or_default(),
            browser_flow: rep.browser_flow,
            direct_grant_flow: rep.direct_grant_flow,
            reset_credentials_flow: rep.reset_credentials_flow,
            first_broker_login_flow: rep.first_broker_login_flow,
            registration_flow: rep.registration_flow,
        })
    }
}

/// Build the realm OTP policy from the representation fields. Omitted fields
/// fall back to the model defaults (PUT resets omitted fields); present
/// fields are validated and rejected with `InvalidRequest` when out of range.
fn otp_policy_from_rep(
    rep: &RealmRepresentation,
    defaults: &OtpPolicy,
) -> Result<OtpPolicy, issuerd_core::IssuerdError> {
    let invalid = |field: &str, value: &dyn std::fmt::Display, rule: &str| {
        issuerd_core::IssuerdError::InvalidRequest(format!("invalid {field}: {value} ({rule})"))
    };
    let algorithm = match &rep.otp_policy_algorithm {
        Some(s) => s.parse::<OtpHashAlgorithm>().map_err(|_| {
            invalid("otpPolicyAlgorithm", s, "expected HmacSHA1|HmacSHA256|HmacSHA512")
        })?,
        None => defaults.algorithm,
    };
    let digits = match rep.otp_policy_digits {
        Some(v @ (6 | 8)) => v as u32,
        Some(v) => return Err(invalid("otpPolicyDigits", &v, "must be 6 or 8")),
        None => defaults.digits,
    };
    let period_secs = match rep.otp_policy_period {
        Some(v) if v >= 1 => v as u32,
        Some(v) => return Err(invalid("otpPolicyPeriod", &v, "must be >= 1")),
        None => defaults.period_secs,
    };
    let look_ahead_window = match rep.otp_policy_look_ahead_window {
        Some(v) if (0..=5).contains(&v) => v as u32,
        Some(v) => return Err(invalid("otpPolicyLookAheadWindow", &v, "must be between 0 and 5")),
        None => defaults.look_ahead_window,
    };
    Ok(OtpPolicy {
        algorithm,
        digits,
        period_secs,
        look_ahead_window,
    })
}

impl From<Realm> for RealmRepresentation {
    fn from(r: Realm) -> Self {
        Self {
            id: Some(r.id.to_string()),
            realm: r.name.to_string(),
            display_name: r.display_name.map(|n| n.to_string()),
            enabled: Some(r.enabled),
            ssl_required: Some(r.ssl_required),
            password_policy: Some(serde_json::to_string(&r.password_policy).unwrap_or_default()),
            access_token_lifespan: Some(r.access_token_lifespan.get() as i64),
            refresh_token_lifespan: Some(r.refresh_token_lifespan.get() as i64),
            sso_session_idle_timeout: Some(r.sso_session_idle_timeout.get() as i64),
            sso_session_max_lifespan: Some(r.sso_session_max_lifespan.get() as i64),
            offline_session_idle_timeout: Some(r.offline_session_idle_timeout.get() as i64),
            login_theme: r.login_theme.as_ref().map(|t| t.to_string()),
            email_theme: r.email_theme.as_ref().map(|t| t.to_string()),
            admin_theme: r.admin_theme.as_ref().map(|t| t.to_string()),
            internationalization_enabled: Some(r.internationalization_enabled),
            supported_locales: Some(r.supported_locales),
            default_locale: r.default_locale,
            default_role: r.default_role,
            attributes: Some(r.attributes),
            brute_force_protected: Some(r.brute_force_protected),
            max_login_failures: Some(r.max_login_failures),
            wait_increment_secs: Some(r.wait_increment_secs),
            max_failure_wait_secs: Some(r.max_failure_wait_secs),
            lockout_duration_secs: Some(r.lockout_duration_secs),
            registration_enabled: Some(r.registration_enabled),
            reset_password_allowed: Some(r.reset_password_allowed),
            remember_me_enabled: Some(r.remember_me_enabled),
            verify_email_enabled: Some(r.verify_email_enabled),
            login_with_email_allowed: Some(r.login_with_email_allowed),
            duplicate_emails_allowed: Some(r.duplicate_emails_allowed),
            edit_username_allowed: Some(r.edit_username_allowed),
            remember_me_session_idle_secs: Some(r.remember_me_session_idle_secs.get() as i64),
            otp_policy_algorithm: Some(r.otp_policy.algorithm.as_str().to_string()),
            otp_policy_digits: Some(r.otp_policy.digits as i32),
            otp_policy_period: Some(r.otp_policy.period_secs as i32),
            otp_policy_look_ahead_window: Some(r.otp_policy.look_ahead_window as i32),
            events_enabled: Some(r.events_enabled),
            events_expiration_secs: Some(r.events_expiration_secs),
            admin_events_enabled: Some(r.admin_events_enabled),
            include_representations: Some(r.include_representations),
            events_listeners: Some(r.events_listeners),
            not_before: Some(r.not_before),
            default_groups: Some(r.default_groups),
            browser_flow: r.browser_flow,
            direct_grant_flow: r.direct_grant_flow,
            reset_credentials_flow: r.reset_credentials_flow,
            first_broker_login_flow: r.first_broker_login_flow,
            registration_flow: r.registration_flow,
        }
    }
}

impl TryFrom<UserRepresentation> for User {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: UserRepresentation) -> Result<Self, Self::Error> {
        Ok(User {
            id: match rep.id {
                Some(s) => UserId::new(s)?,
                None => UserId::new(issuerd_core::utils::generate_id())?,
            },
            realm_id: RealmId::new("placeholder").unwrap(), // set by caller
            username: Username::new(rep.username).map_err(|e| {
                issuerd_core::IssuerdError::InvalidRequest(format!("invalid username: {e}"))
            })?,
            email: rep.email.map(Email::new).transpose().map_err(|e| {
                issuerd_core::IssuerdError::InvalidRequest(format!("invalid email: {e}"))
            })?,
            email_verified: rep.email_verified.unwrap_or(false),
            first_name: rep.first_name.map(DisplayName::new).transpose()?,
            last_name: rep.last_name.map(DisplayName::new).transpose()?,
            enabled: rep.enabled.unwrap_or(true),
            federation_link: None,
            attributes: rep.attributes.unwrap_or_default(),
            required_actions: rep.required_actions.unwrap_or_default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
}

impl From<User> for UserRepresentation {
    fn from(u: User) -> Self {
        Self {
            id: Some(u.id.to_string()),
            username: u.username.to_string(),
            email: u.email.map(|e| e.to_string()),
            first_name: u.first_name.as_ref().map(|n| n.to_string()),
            last_name: u.last_name.as_ref().map(|n| n.to_string()),
            enabled: Some(u.enabled),
            email_verified: Some(u.email_verified),
            created_at: Some(u.created_at.to_rfc3339()),
            attributes: Some(u.attributes),
            credentials: None,
            realm_roles: None,
            client_roles: None,
            groups: None,
            required_actions: Some(u.required_actions),
        }
    }
}

impl TryFrom<ClientRepresentation> for Client {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: ClientRepresentation) -> Result<Self, Self::Error> {
        Ok(Client {
            id: match rep.id {
                Some(s) => issuerd_core::ClientId::new(s)?,
                None => issuerd_core::ClientId::new(issuerd_core::utils::generate_id())?,
            },
            realm_id: RealmId::new("placeholder").unwrap(), // set by caller
            client_id: ClientIdentifier::new(rep.client_id)?,
            name: rep.name.map(DisplayName::new).transpose()?,
            description: rep.description,
            enabled: rep.enabled.unwrap_or(true),
            protocol: rep.protocol.unwrap_or(issuerd_core::ClientProtocol::OpenIdConnect),
            public_client: rep.public_client.unwrap_or(false),
            bearer_only: rep.bearer_only.unwrap_or(false),
            client_authenticator_type: rep
                .client_authenticator_type
                .unwrap_or(issuerd_core::ClientAuthenticatorType::ClientSecret),
            secret: rep.secret,
            redirect_uris: rep
                .redirect_uris
                .unwrap_or_default()
                .into_iter()
                .map(RedirectUri::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    issuerd_core::IssuerdError::InvalidRequest(format!("invalid redirect_uri: {e}"))
                })?,
            web_origins: rep
                .web_origins
                .unwrap_or_default()
                .into_iter()
                .map(WebOrigin::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    issuerd_core::IssuerdError::InvalidRequest(format!("invalid web_origin: {e}"))
                })?,
            default_scopes: rep.default_scopes.map(Into::into).unwrap_or_default(),
            optional_scopes: rep.optional_scopes.map(Into::into).unwrap_or_default(),
            consent_required: rep.consent_required.unwrap_or(false),
            full_scope_allowed: rep.full_scope_allowed.unwrap_or(true),
            service_accounts_enabled: rep.service_accounts_enabled.unwrap_or(false),
            protocol_mappers: rep.protocol_mappers.unwrap_or_default(),
            // Scope mappings are managed through the `/scope-mappings`
            // sub-resources, not the client representation; the update
            // handler preserves the stored value.
            scope_mappings: Default::default(),
            attributes: rep.attributes.unwrap_or_default(),
        })
    }
}

impl From<Client> for ClientRepresentation {
    fn from(c: Client) -> Self {
        Self {
            id: Some(c.id.to_string()),
            client_id: c.client_id.to_string(),
            name: c.name.map(|n| n.to_string()),
            description: c.description,
            enabled: Some(c.enabled),
            protocol: Some(c.protocol),
            public_client: Some(c.public_client),
            bearer_only: Some(c.bearer_only),
            client_authenticator_type: Some(c.client_authenticator_type),
            // Secrets are never exposed on read; use the dedicated
            // `/client-secret` endpoint instead (Keycloak-compatible).
            secret: None,
            redirect_uris: Some(c.redirect_uris.into_iter().map(|r| r.to_string()).collect()),
            web_origins: Some(c.web_origins.into_iter().map(|o| o.to_string()).collect()),
            default_scopes: Some(c.default_scopes.to_vec()),
            optional_scopes: Some(c.optional_scopes.to_vec()),
            consent_required: Some(c.consent_required),
            full_scope_allowed: Some(c.full_scope_allowed),
            service_accounts_enabled: Some(c.service_accounts_enabled),
            protocol_mappers: Some(c.protocol_mappers),
            attributes: Some(c.attributes),
        }
    }
}

impl TryFrom<CredentialRepresentation> for Credential {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: CredentialRepresentation) -> Result<Self, Self::Error> {
        // The `temporary` flag rides inside `credential_data` (the Credential
        // model has no dedicated column): UPDATE_PASSWORD evaluation reads it.
        let mut credential_data = rep
            .credential_data
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null);
        if rep.temporary == Some(true) {
            if !credential_data.is_object() {
                credential_data = serde_json::json!({});
            }
            credential_data["temporary"] = serde_json::Value::Bool(true);
        }
        Ok(Credential {
            id: match rep.id {
                Some(s) => CredentialId::new(s)?,
                None => CredentialId::new(issuerd_core::utils::generate_id())?,
            },
            credential_type: rep.credential_type,
            user_label: rep.user_label,
            created_date: Utc::now(),
            secret_data: rep.secret_data.map(|s| s.into_bytes()).unwrap_or_default(),
            credential_data,
            priority: rep.priority.unwrap_or(0),
        })
    }
}

impl From<Credential> for CredentialRepresentation {
    fn from(c: Credential) -> Self {
        Self {
            id: Some(c.id.to_string()),
            credential_type: c.credential_type,
            user_label: c.user_label,
            created_date: Some(c.created_date.timestamp_millis()),
            secret_data: Some(String::from_utf8_lossy(&c.secret_data).to_string()),
            credential_data: Some(c.credential_data.to_string()),
            priority: Some(c.priority),
            temporary: Some(
                c.credential_data.get("temporary").and_then(|v| v.as_bool()).unwrap_or(false),
            ),
            value: None,
        }
    }
}

impl From<Role> for RoleRepresentation {
    fn from(r: Role) -> Self {
        // `containerId` is the owning client's internal id for client roles,
        // the realm id for realm roles (Keycloak convention).
        let container_id = if r.client_role {
            r.client_id
                .as_ref()
                .map(|c| c.to_string())
                .unwrap_or_else(|| r.realm_id.to_string())
        } else {
            r.realm_id.to_string()
        };
        Self {
            id: Some(r.id.to_string()),
            name: r.name.to_string(),
            description: r.description,
            composite: Some(r.composite),
            composites: Some(r.composites),
            client_role: Some(r.client_role),
            container_id: Some(container_id),
            attributes: Some(r.attributes),
        }
    }
}

impl TryFrom<RoleRepresentation> for Role {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: RoleRepresentation) -> Result<Self, Self::Error> {
        let client_role = rep.client_role.unwrap_or(false);
        // Honor `client_role`/`container_id` when set: a client role's
        // container is its owning client. Without them this builds a realm
        // role, as before (the realm itself is filled in by the caller).
        let client_id = if client_role {
            rep.container_id.map(ClientId::new).transpose()?
        } else {
            None
        };
        Ok(Role {
            id: match rep.id {
                Some(s) => RoleId::new(s)?,
                None => RoleId::new(issuerd_core::utils::generate_id())?,
            },
            name: RoleName::new(rep.name)?,
            description: rep.description,
            realm_id: RealmId::new("placeholder").unwrap(),
            client_role,
            client_id,
            composite: rep.composite.unwrap_or(false),
            composites: rep.composites.unwrap_or_default(),
            attributes: rep.attributes.unwrap_or_default(),
        })
    }
}

impl From<ProtocolMapper> for ProtocolMapperRepresentation {
    fn from(m: ProtocolMapper) -> Self {
        Self {
            id: Some(m.id.to_string()),
            name: m.name,
            protocol: Some("openid-connect".to_string()),
            protocol_mapper: m.mapper_type,
            config: Some(m.config),
        }
    }
}

impl TryFrom<ProtocolMapperRepresentation> for ProtocolMapper {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: ProtocolMapperRepresentation) -> Result<Self, Self::Error> {
        // Only OIDC mappers exist; reject anything else explicitly instead of
        // silently storing a mapper the token engine would ignore.
        if let Some(protocol) = &rep.protocol {
            if protocol != "openid-connect" {
                return Err(issuerd_core::IssuerdError::InvalidRequest(format!(
                    "unsupported protocol mapper protocol: {protocol}"
                )));
            }
        }
        Ok(ProtocolMapper {
            id: match rep.id {
                Some(s) => MapperId::new(s)?,
                None => MapperId::new(issuerd_core::utils::generate_id())?,
            },
            name: rep.name,
            mapper_type: rep.protocol_mapper,
            config: rep.config.unwrap_or_default(),
        })
    }
}

impl From<ClientScope> for ClientScopeRepresentation {
    fn from(s: ClientScope) -> Self {
        Self {
            id: Some(s.id.to_string()),
            name: s.name,
            description: s.description,
            protocol: Some(s.protocol),
            attributes: Some(s.attributes),
            protocol_mappers: Some(s.protocol_mappers.into_iter().map(Into::into).collect()),
        }
    }
}

impl ClientScopeRepresentation {
    /// Representation for list/assignment endpoints: Keycloak omits protocol
    /// mappers there (they are populated only on the single-scope GET).
    pub fn without_mappers(s: ClientScope) -> Self {
        let mut rep: Self = s.into();
        rep.protocol_mappers = None;
        rep
    }
}

impl TryFrom<ClientScopeRepresentation> for ClientScope {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: ClientScopeRepresentation) -> Result<Self, Self::Error> {
        Ok(ClientScope {
            id: match rep.id {
                Some(s) => ClientScopeId::new(s)?,
                None => ClientScopeId::new(issuerd_core::utils::generate_id())?,
            },
            realm_id: RealmId::new("placeholder").unwrap(), // set by caller
            name: rep.name,
            description: rep.description,
            protocol: rep.protocol.unwrap_or(ClientProtocol::OpenIdConnect),
            attributes: rep.attributes.unwrap_or_default(),
            protocol_mappers: rep
                .protocol_mappers
                .unwrap_or_default()
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            // Scope mappings live behind the `/scope-mappings` sub-resources,
            // not the scope representation; the update handler preserves them.
            scope_mappings: Default::default(),
        })
    }
}

impl From<Group> for GroupRepresentation {
    fn from(g: Group) -> Self {
        Self {
            id: Some(g.id.to_string()),
            name: g.name.to_string(),
            path: Some(g.path.to_string()),
            attributes: Some(g.attributes),
            realm_roles: Some(g.realm_roles),
            client_roles: Some(g.client_roles),
            sub_groups: Some(g.sub_groups.into_iter().map(Into::into).collect()),
            // Reads always populate the field (outer `Some`); `null` means a
            // top-level group.
            parent_id: Some(g.parent_id),
        }
    }
}

impl TryFrom<GroupRepresentation> for Group {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: GroupRepresentation) -> Result<Self, Self::Error> {
        let name = rep.name;
        Ok(Group {
            id: match rep.id {
                Some(s) => GroupId::new(s)?,
                None => GroupId::new(issuerd_core::utils::generate_id())?,
            },
            path: GroupPath::new(rep.path.unwrap_or_else(|| format!("/{}", name)))?,
            name: GroupName::new(name)?,
            realm_id: RealmId::new("placeholder").unwrap(),
            // Tri-state collapses here: the update handler re-applies the
            // absent/explicit-null distinction itself.
            parent_id: rep.parent_id.flatten(),
            sub_groups: rep
                .sub_groups
                .unwrap_or_default()
                .into_iter()
                .map(|sg| sg.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            attributes: rep.attributes.unwrap_or_default(),
            realm_roles: rep.realm_roles.unwrap_or_default(),
            client_roles: rep.client_roles.unwrap_or_default(),
        })
    }
}

impl From<UserSession> for UserSessionRepresentation {
    fn from(s: UserSession) -> Self {
        Self {
            id: s.id.to_string(),
            username: s.login_username.to_string(),
            user_id: s.user_id.to_string(),
            ip_address: s.ip_address.to_string(),
            started: s.started.timestamp(),
            last_access: s.last_session_refresh.timestamp(),
            offline: s.offline,
            clients: s
                .clients
                .into_iter()
                .map(|cs| {
                    (
                        cs.client_id.to_string(),
                        serde_json::to_string(&cs.auth_method)
                            .unwrap()
                            .trim_matches('"')
                            .to_string(),
                    )
                })
                .collect(),
        }
    }
}

impl From<Event> for EventRepresentation {
    fn from(e: Event) -> Self {
        Self {
            id: Some(e.id.to_string()),
            time: e.event_time.timestamp(),
            event_type: e.event_type,
            realm_id: e.realm_id.to_string(),
            client_id: e.client_id.map(|c| c.to_string()),
            user_id: e.user_id.map(|u| u.to_string()),
            // Filled in by the query handler, which resolves the user.
            username: None,
            session_id: e.session_id.map(|s| s.to_string()),
            ip_address: e.ip_address.map(|ip| ip.to_string()),
            details: Some(e.details),
            error: e.error,
        }
    }
}

impl From<AdminEvent> for AdminEventRepresentation {
    fn from(e: AdminEvent) -> Self {
        Self {
            id: Some(e.id.to_string()),
            time: e.event_time.timestamp(),
            realm_id: e.realm_id.to_string(),
            auth_realm_id: e.auth_realm_id.map(|r| r.to_string()),
            auth_client_id: e.auth_client_id.map(|c| c.to_string()),
            auth_user_id: e.auth_user_id.map(|u| u.to_string()),
            // Filled in by the query handler, which resolves the user.
            auth_username: None,
            operation_type: e.operation_type,
            resource_type: e.resource_type,
            resource_path: e.resource_path,
            representation: e.representation,
            error: e.error,
        }
    }
}

impl From<IdentityProviderConfig> for IdentityProviderRepresentation {
    fn from(i: IdentityProviderConfig) -> Self {
        // The display name lives in the `displayName` config key (Keycloak
        // wire spelling); surface it as a top-level field for convenience.
        let display_name = i.config.get("displayName").cloned();
        Self {
            alias: i.alias,
            display_name,
            provider_id: i.provider_id,
            enabled: Some(i.enabled),
            config: Some(i.config),
        }
    }
}

impl TryFrom<IdentityProviderRepresentation> for IdentityProviderConfig {
    type Error = issuerd_core::IssuerdError;

    fn try_from(rep: IdentityProviderRepresentation) -> Result<Self, Self::Error> {
        let mut config = rep.config.unwrap_or_default();
        if let Some(name) = rep.display_name {
            // An explicit config entry wins over the top-level shorthand.
            config.entry("displayName".to_string()).or_insert(name);
        }
        Ok(IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
            alias: rep.alias,
            provider_id: rep.provider_id,
            enabled: rep.enabled.unwrap_or(true),
            config,
        })
    }
}

impl From<AuthenticatorConfig> for AuthenticatorConfigRepresentation {
    fn from(c: AuthenticatorConfig) -> Self {
        Self {
            alias: c.alias,
            config: c.config.into_iter().collect(),
        }
    }
}

impl From<AuthenticatorConfigRepresentation> for AuthenticatorConfig {
    fn from(rep: AuthenticatorConfigRepresentation) -> Self {
        Self {
            alias: rep.alias,
            config: rep.config.into_iter().collect(),
        }
    }
}

impl From<FlowStage> for FlowStageRepresentation {
    fn from(s: FlowStage) -> Self {
        let has_config = s.authenticator_config.is_some();
        Self {
            id: s.id.to_string(),
            requirement: s.requirement,
            authenticator: s.authenticator,
            priority: s.priority,
            sub_flow_alias: s.sub_flow_alias,
            authenticator_config: s.authenticator_config.map(Into::into),
            has_config,
            flow_alias: None,
        }
    }
}

impl From<FlowConfig> for FlowRepresentation {
    fn from(f: FlowConfig) -> Self {
        Self {
            alias: f.alias,
            provider_id: Some(f.provider_id),
            top_level: Some(f.top_level),
            built_in: Some(f.built_in),
            stages: Some(f.stages.into_iter().map(FlowStageRepresentation::from).collect()),
        }
    }
}

/// Convert a [`FlowRepresentation`] into a [`FlowConfig`] bound to `realm_id`.
///
/// Stage ids in the representation are used as-is (callers creating new
/// stages must mint fresh ids first); missing optional fields fall back to
/// empty/false defaults.
pub fn flow_config_from_representation(
    realm_id: &RealmId,
    rep: FlowRepresentation,
) -> Result<FlowConfig, issuerd_core::IssuerdError> {
    Ok(FlowConfig {
        alias: rep.alias,
        realm_id: realm_id.clone(),
        provider_id: rep.provider_id.unwrap_or_default(),
        top_level: rep.top_level.unwrap_or(false),
        built_in: rep.built_in.unwrap_or(false),
        stages: rep
            .stages
            .unwrap_or_default()
            .into_iter()
            .map(flow_stage_from_representation)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a single [`FlowStageRepresentation`] into a [`FlowStage`].
pub fn flow_stage_from_representation(
    s: FlowStageRepresentation,
) -> Result<FlowStage, issuerd_core::IssuerdError> {
    Ok(FlowStage {
        id: FlowStageId::new(s.id)?,
        requirement: s.requirement,
        authenticator: s.authenticator,
        priority: s.priority,
        sub_flow_alias: s.sub_flow_alias,
        authenticator_config: s.authenticator_config.map(Into::into),
    })
}

/// Result of a user federation synchronisation run.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct SyncResultRepresentation {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub failed: usize,
    pub last_sync: String,
}

impl From<issuerd_core::SyncResult> for SyncResultRepresentation {
    fn from(r: issuerd_core::SyncResult) -> Self {
        Self {
            added: r.added,
            updated: r.updated,
            removed: r.removed,
            failed: r.failed,
            last_sync: r.last_sync.to_rfc3339(),
        }
    }
}

/// Request body for the SMTP test-connection endpoint.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct TestSmtpConnectionRequest {
    /// Recipient address the test email is sent to.
    pub email: String,
}

/// One locked-out (username, IP) pair, as returned by the attack-detection
/// brute-force user list.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BruteForceLockoutRepresentation {
    /// Username the lockout applies to.
    pub username: String,
    /// IP address the lockout applies to.
    pub ip: String,
    /// Current consecutive login-failure count for this pair.
    #[serde(rename = "numFailures")]
    pub num_failures: u32,
    /// Resolved user ID for the username, when the user still exists. Lets
    /// admins unlock directly without a username→id lookup over the
    /// (possibly paginated) users list.
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// Aggregated brute-force status for a single user across all source IPs.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BruteForceUserStatusRepresentation {
    /// Unique user identifier.
    #[serde(rename = "userId")]
    pub user_id: String,
    /// Login username.
    pub username: String,
    /// Total consecutive login failures across all source IPs.
    #[serde(rename = "numFailures")]
    pub num_failures: u32,
    /// Whether the user is currently locked out from at least one IP.
    pub locked: bool,
}

// ---------------------------------------------------------------------------
// Partial import / export
// ---------------------------------------------------------------------------

/// Conflict-resolution strategy for `POST /admin/realms/{realm}/partialImport`
/// (Keycloak `ifResourceExists`).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum IfResourceExists {
    /// Abort with 409 on the first already-existing resource.
    #[default]
    Fail,
    /// Skip existing resources and import the rest.
    Skip,
    /// Update existing resources with the document's fields.
    Overwrite,
}

/// Query parameters for the partial-import endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct PartialImportParams {
    /// Conflict strategy: `FAIL` (default), `SKIP`, or `OVERWRITE`. May also
    /// be supplied as the `ifResourceExists` field of the request body; the
    /// query parameter wins when both are set.
    #[serde(rename = "ifResourceExists")]
    pub if_resource_exists: Option<IfResourceExists>,
}

/// Role section of a partial-import document: realm roles plus client roles
/// keyed by the client's `client_id` string.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Default)]
pub struct PartialImportRolesRepresentation {
    /// Realm role definitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<RoleRepresentation>>,
    /// Client role definitions keyed by `client_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<HashMap<String, Vec<RoleRepresentation>>>,
}

/// Realm-partial document accepted by
/// `POST /admin/realms/{realm}/partialImport`. Unknown fields are ignored.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Default)]
pub struct PartialImportRepresentation {
    /// Conflict strategy; the `ifResourceExists` query parameter wins when
    /// both are set.
    #[serde(
        rename = "ifResourceExists",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub if_resource_exists: Option<IfResourceExists>,
    /// Users to import. Credentials are never accepted here (see the endpoint
    /// documentation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<UserRepresentation>>,
    /// Top-level groups to import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupRepresentation>>,
    /// Clients to import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ClientRepresentation>>,
    /// Realm and client roles to import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<PartialImportRolesRepresentation>,
    /// Identity providers to import.
    #[serde(
        rename = "identityProviders",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_providers: Option<Vec<IdentityProviderRepresentation>>,
}

/// Per-resource action recorded by a partial import.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImportAction {
    /// The resource did not exist and was created.
    Added,
    /// The resource already existed and was left unchanged.
    Skipped,
    /// The resource already existed and was updated.
    Updated,
}

/// Outcome for one resource in a partial-import run.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PartialImportResultEntry {
    /// Kind of the imported resource.
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    /// Identity the resource matched on (username, client_id, role name,
    /// group name, or IdP alias).
    #[serde(rename = "resourceName")]
    pub resource_name: String,
    /// What the import did with the resource.
    pub action: ImportAction,
}

/// Summary returned by the partial-import endpoint (a compact Keycloak-ish
/// shape: Keycloak returns the same counters plus a results list).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PartialImportResultRepresentation {
    /// Number of resources created.
    pub added: usize,
    /// Number of existing resources left unchanged.
    pub skipped: usize,
    /// Number of existing resources updated.
    pub updated: usize,
    /// Per-resource outcomes, in document order.
    pub results: Vec<PartialImportResultEntry>,
}

/// Roles section of the realm export: realm roles plus client roles keyed by
/// the client's `client_id` string.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone, Default)]
pub struct ExportRolesRepresentation {
    /// Realm role definitions.
    pub realm: Vec<RoleRepresentation>,
    /// Client role definitions keyed by `client_id`; clients without roles
    /// are omitted.
    pub client: HashMap<String, Vec<RoleRepresentation>>,
}

/// Full realm export returned by `POST /admin/realms/{realm}/export`: realm
/// fields at the top level (Keycloak-compatible where fields overlap) plus
/// users, clients, groups, roles, identity providers, and client scopes.
///
/// The document carries no secret material: users never include credentials,
/// client secrets are omitted, and identity-provider `clientSecret` config
/// values are masked. Groups are a flat list — hierarchy is carried by
/// `parent_id` (`sub_groups` is always empty).
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
pub struct RealmExportRepresentation {
    /// Realm fields, flattened to the top level (Keycloak export shape).
    #[serde(flatten)]
    pub realm: RealmRepresentation,
    /// All users of the realm, without credentials.
    pub users: Vec<UserRepresentation>,
    /// All clients of the realm, secrets omitted.
    pub clients: Vec<ClientRepresentation>,
    /// All groups of the realm (flat list, `parent_id` carries hierarchy).
    pub groups: Vec<GroupRepresentation>,
    /// Realm and client role definitions.
    pub roles: ExportRolesRepresentation,
    /// Identity provider configurations (`clientSecret` values masked).
    #[serde(rename = "identityProviders")]
    pub identity_providers: Vec<IdentityProviderRepresentation>,
    /// Client scopes including their protocol mappers.
    #[serde(rename = "clientScopes")]
    pub client_scopes: Vec<ClientScopeRepresentation>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{AuthMethod, PasswordPolicy};

    #[test]
    fn realm_representation_roundtrip() {
        let rep = RealmRepresentation {
            id: Some("realm-1".to_string()),
            realm: "test".to_string(),
            display_name: Some("Test".to_string()),
            enabled: Some(true),
            ssl_required: Some(SslRequired::External),
            password_policy: None,
            access_token_lifespan: Some(300),
            refresh_token_lifespan: Some(1800),
            sso_session_idle_timeout: Some(1800),
            sso_session_max_lifespan: Some(36000),
            offline_session_idle_timeout: Some(2592000),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            internationalization_enabled: None,
            supported_locales: None,
            default_locale: None,
            default_role: None,
            attributes: None,
            brute_force_protected: None,
            max_login_failures: None,
            wait_increment_secs: None,
            max_failure_wait_secs: None,
            lockout_duration_secs: None,
            registration_enabled: None,
            reset_password_allowed: None,
            remember_me_enabled: None,
            verify_email_enabled: None,
            login_with_email_allowed: None,
            duplicate_emails_allowed: None,
            edit_username_allowed: None,
            remember_me_session_idle_secs: None,
            otp_policy_algorithm: None,
            otp_policy_digits: None,
            otp_policy_period: None,
            otp_policy_look_ahead_window: None,
            events_enabled: None,
            events_expiration_secs: None,
            admin_events_enabled: None,
            include_representations: None,
            events_listeners: None,
            not_before: None,
            default_groups: None,
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
        };
        let json = serde_json::to_string(&rep).unwrap();
        let back: RealmRepresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.realm, "test");
    }

    #[test]
    fn realm_representation_with_themes_try_into() {
        let rep = RealmRepresentation {
            id: Some("realm-1".to_string()),
            realm: "test".to_string(),
            display_name: Some("Test".to_string()),
            enabled: Some(true),
            ssl_required: Some(SslRequired::External),
            password_policy: None,
            access_token_lifespan: Some(300),
            refresh_token_lifespan: Some(1800),
            sso_session_idle_timeout: Some(1800),
            sso_session_max_lifespan: Some(36000),
            offline_session_idle_timeout: Some(2592000),
            login_theme: Some("keycloak".to_string()),
            email_theme: Some("email".to_string()),
            admin_theme: Some("admin".to_string()),
            internationalization_enabled: None,
            supported_locales: None,
            default_locale: None,
            default_role: None,
            attributes: None,
            brute_force_protected: None,
            max_login_failures: None,
            wait_increment_secs: None,
            max_failure_wait_secs: None,
            lockout_duration_secs: None,
            registration_enabled: None,
            reset_password_allowed: None,
            remember_me_enabled: None,
            verify_email_enabled: None,
            login_with_email_allowed: None,
            duplicate_emails_allowed: None,
            edit_username_allowed: None,
            remember_me_session_idle_secs: None,
            otp_policy_algorithm: None,
            otp_policy_digits: None,
            otp_policy_period: None,
            otp_policy_look_ahead_window: None,
            events_enabled: None,
            events_expiration_secs: None,
            admin_events_enabled: None,
            include_representations: None,
            events_listeners: None,
            not_before: None,
            default_groups: None,
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
        };
        let realm: Realm = rep.try_into().unwrap();
        assert_eq!(realm.login_theme, Some(ThemeName::new("keycloak").unwrap()));
        assert_eq!(realm.email_theme, Some(ThemeName::new("email").unwrap()));
        assert_eq!(realm.admin_theme, Some(ThemeName::new("admin").unwrap()));
    }

    #[test]
    fn realm_into_representation_with_themes() {
        let realm = Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: Some(DisplayName::new("Test").unwrap()),
            enabled: true,
            ssl_required: SslRequired::External,
            password_policy: PasswordPolicy::default(),
            login_theme: Some(ThemeName::new("keycloak").unwrap()),
            email_theme: Some(ThemeName::new("email").unwrap()),
            admin_theme: Some(ThemeName::new("admin").unwrap()),
            default_role: None,
            access_token_lifespan: SecondsNonZero::new(300),
            refresh_token_lifespan: SecondsNonZero::new(1800),
            sso_session_idle_timeout: SecondsNonZero::new(1800),
            sso_session_max_lifespan: SecondsNonZero::new(36000),
            offline_session_idle_timeout: SecondsNonZero::new(2592000),
            attributes: HashMap::new(),
            ..Default::default()
        };
        let rep: RealmRepresentation = realm.into();
        assert_eq!(rep.login_theme, Some("keycloak".to_string()));
        assert_eq!(rep.email_theme, Some("email".to_string()));
        assert_eq!(rep.admin_theme, Some("admin".to_string()));
    }

    #[test]
    fn realm_representation_with_i18n_roundtrip() {
        let rep = RealmRepresentation {
            id: Some("realm-1".to_string()),
            realm: "test".to_string(),
            display_name: None,
            enabled: None,
            ssl_required: None,
            password_policy: None,
            access_token_lifespan: None,
            refresh_token_lifespan: None,
            sso_session_idle_timeout: None,
            sso_session_max_lifespan: None,
            offline_session_idle_timeout: None,
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            internationalization_enabled: Some(true),
            supported_locales: Some(vec!["en".to_string(), "de".to_string()]),
            default_locale: Some("en".to_string()),
            default_role: None,
            attributes: None,
            brute_force_protected: None,
            max_login_failures: None,
            wait_increment_secs: None,
            max_failure_wait_secs: None,
            lockout_duration_secs: None,
            registration_enabled: None,
            reset_password_allowed: None,
            remember_me_enabled: None,
            verify_email_enabled: None,
            login_with_email_allowed: None,
            duplicate_emails_allowed: None,
            edit_username_allowed: None,
            remember_me_session_idle_secs: None,
            otp_policy_algorithm: None,
            otp_policy_digits: None,
            otp_policy_period: None,
            otp_policy_look_ahead_window: None,
            events_enabled: None,
            events_expiration_secs: None,
            admin_events_enabled: None,
            include_representations: None,
            events_listeners: None,
            not_before: None,
            default_groups: None,
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
        };
        // Keycloak wire spellings.
        let json = serde_json::to_value(&rep).unwrap();
        assert_eq!(json["internationalizationEnabled"], true);
        assert_eq!(json["supportedLocales"], serde_json::json!(["en", "de"]));
        assert_eq!(json["defaultLocale"], "en");

        let realm: Realm = rep.try_into().unwrap();
        assert!(realm.internationalization_enabled);
        assert_eq!(realm.supported_locales, vec!["en".to_string(), "de".to_string()]);
        assert_eq!(realm.default_locale, Some("en".to_string()));

        let back: RealmRepresentation = realm.into();
        assert_eq!(back.internationalization_enabled, Some(true));
        assert_eq!(back.supported_locales, Some(vec!["en".to_string(), "de".to_string()]));
        assert_eq!(back.default_locale, Some("en".to_string()));
    }

    #[test]
    fn realm_representation_without_i18n_uses_model_defaults() {
        let rep = RealmRepresentation {
            id: None,
            realm: "test".to_string(),
            display_name: None,
            enabled: None,
            ssl_required: None,
            password_policy: None,
            access_token_lifespan: None,
            refresh_token_lifespan: None,
            sso_session_idle_timeout: None,
            sso_session_max_lifespan: None,
            offline_session_idle_timeout: None,
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            internationalization_enabled: None,
            supported_locales: None,
            default_locale: None,
            default_role: None,
            attributes: None,
            brute_force_protected: None,
            max_login_failures: None,
            wait_increment_secs: None,
            max_failure_wait_secs: None,
            lockout_duration_secs: None,
            registration_enabled: None,
            reset_password_allowed: None,
            remember_me_enabled: None,
            verify_email_enabled: None,
            login_with_email_allowed: None,
            duplicate_emails_allowed: None,
            edit_username_allowed: None,
            remember_me_session_idle_secs: None,
            otp_policy_algorithm: None,
            otp_policy_digits: None,
            otp_policy_period: None,
            otp_policy_look_ahead_window: None,
            events_enabled: None,
            events_expiration_secs: None,
            admin_events_enabled: None,
            include_representations: None,
            events_listeners: None,
            not_before: None,
            default_groups: None,
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
        };
        let realm: Realm = rep.try_into().unwrap();
        assert!(!realm.internationalization_enabled);
        assert!(realm.supported_locales.is_empty());
        assert_eq!(realm.default_locale, None);
    }

    #[test]
    fn user_representation_try_into_user() {
        let rep = UserRepresentation {
            id: Some("user-1".to_string()),
            username: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            first_name: Some("Alice".to_string()),
            last_name: Some("Smith".to_string()),
            enabled: Some(true),
            email_verified: Some(true),
            created_at: None,
            attributes: None,
            credentials: None,
            realm_roles: None,
            client_roles: None,
            groups: None,
            required_actions: None,
        };
        let user: User = rep.try_into().unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, Some(Email::new("alice@example.com").unwrap()));
        assert_eq!(user.first_name, Some(DisplayName::new("Alice").unwrap()));
        assert_eq!(user.last_name, Some(DisplayName::new("Smith").unwrap()));
    }

    #[test]
    fn client_representation_try_into_client() {
        let rep = ClientRepresentation {
            id: Some("client-1".to_string()),
            client_id: "my-app".to_string(),
            name: Some("My App".to_string()),
            description: Some("desc".to_string()),
            enabled: Some(true),
            protocol: Some(ClientProtocol::OpenIdConnect),
            public_client: Some(false),
            bearer_only: Some(false),
            client_authenticator_type: Some(ClientAuthenticatorType::ClientSecret),
            redirect_uris: Some(vec!["https://app.example.com/callback".to_string()]),
            web_origins: Some(vec!["https://app.example.com".to_string()]),
            default_scopes: Some(vec!["openid".to_string()]),
            optional_scopes: Some(vec!["profile".to_string()]),
            consent_required: Some(false),
            full_scope_allowed: Some(true),
            service_accounts_enabled: None,
            protocol_mappers: None,
            secret: Some("s3cr3t".to_string()),
            attributes: None,
        };
        let client: Client = rep.try_into().unwrap();
        assert_eq!(client.client_id, "my-app");
        assert_eq!(client.name, Some(DisplayName::new("My App").unwrap()));
        assert_eq!(client.description, Some("desc".to_string()));
        assert_eq!(client.redirect_uris.len(), 1);
        assert_eq!(client.web_origins.len(), 1);
        assert!(client.default_scopes.contains("openid"));
        assert!(client.optional_scopes.contains("profile"));
    }

    #[test]
    fn user_representation_roundtrip() {
        let rep = UserRepresentation {
            id: Some("user-1".to_string()),
            username: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            first_name: Some("Alice".to_string()),
            last_name: Some("Smith".to_string()),
            enabled: Some(true),
            email_verified: Some(true),
            created_at: None,
            attributes: None,
            credentials: None,
            realm_roles: None,
            client_roles: None,
            groups: None,
            required_actions: None,
        };
        let json = serde_json::to_string(&rep).unwrap();
        let back: UserRepresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.username, "alice");
    }

    #[test]
    fn client_representation_roundtrip() {
        let rep = ClientRepresentation {
            id: Some("client-1".to_string()),
            client_id: "my-app".to_string(),
            name: Some("My App".to_string()),
            description: None,
            enabled: Some(true),
            protocol: Some(ClientProtocol::OpenIdConnect),
            public_client: Some(false),
            bearer_only: Some(false),
            client_authenticator_type: None,
            redirect_uris: Some(vec!["https://app.example.com/callback".to_string()]),
            web_origins: None,
            default_scopes: None,
            optional_scopes: None,
            consent_required: Some(false),
            full_scope_allowed: Some(true),
            service_accounts_enabled: None,
            protocol_mappers: None,
            secret: None,
            attributes: None,
        };
        let json = serde_json::to_string(&rep).unwrap();
        let back: ClientRepresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.client_id, "my-app");
    }

    #[test]
    fn realm_invalid_ssl_required() {
        let json = r#"{"realm":"test","ssl_required":"invalid"}"#;
        let result: Result<RealmRepresentation, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn realm_invalid_password_policy() {
        let rep = RealmRepresentation {
            id: None,
            realm: "test".to_string(),
            display_name: None,
            enabled: None,
            ssl_required: None,
            password_policy: Some("not-json".to_string()),
            access_token_lifespan: None,
            refresh_token_lifespan: None,
            sso_session_idle_timeout: None,
            sso_session_max_lifespan: None,
            offline_session_idle_timeout: None,
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            internationalization_enabled: None,
            supported_locales: None,
            default_locale: None,
            default_role: None,
            attributes: None,
            brute_force_protected: None,
            max_login_failures: None,
            wait_increment_secs: None,
            max_failure_wait_secs: None,
            lockout_duration_secs: None,
            registration_enabled: None,
            reset_password_allowed: None,
            remember_me_enabled: None,
            verify_email_enabled: None,
            login_with_email_allowed: None,
            duplicate_emails_allowed: None,
            edit_username_allowed: None,
            remember_me_session_idle_secs: None,
            otp_policy_algorithm: None,
            otp_policy_digits: None,
            otp_policy_period: None,
            otp_policy_look_ahead_window: None,
            events_enabled: None,
            events_expiration_secs: None,
            admin_events_enabled: None,
            include_representations: None,
            events_listeners: None,
            not_before: None,
            default_groups: None,
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
        };
        let result: Result<Realm, _> = rep.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn credential_all_types() {
        for (_type_str, expected) in [
            ("password", CredentialType::Password),
            ("totp", CredentialType::Totp),
            ("hotp", CredentialType::Hotp),
            ("web_authn", CredentialType::WebAuthn),
            ("web_authn_passwordless", CredentialType::WebAuthnPasswordless),
            ("kerberos", CredentialType::Kerberos),
            ("ssh_public_key", CredentialType::SshPublicKey),
            ("custom", CredentialType::Custom("custom".to_string())),
        ] {
            let rep = CredentialRepresentation {
                id: None,
                credential_type: expected.clone(),
                user_label: None,
                created_date: None,
                secret_data: None,
                credential_data: None,
                priority: None,
                temporary: None,
                value: None,
            };
            let cred: Credential = rep.try_into().unwrap();
            assert_eq!(cred.credential_type, expected);
        }
    }

    #[test]
    fn credential_from_domain() {
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("label".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: b"secret".to_vec(),
            credential_data: serde_json::json!("data"),
            priority: 1,
        };
        let rep: CredentialRepresentation = cred.into();
        assert_eq!(rep.credential_type, CredentialType::Password);
        assert_eq!(rep.id, Some("cred-1".to_string()));
        assert_eq!(rep.priority, Some(1));
        assert_eq!(rep.temporary, Some(false));
        assert!(rep.value.is_none());
    }

    #[test]
    fn credential_redacted_never_carries_secret() {
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("label".to_string()),
            created_date: chrono::DateTime::from_timestamp_millis(1_700_000_000_123).unwrap(),
            secret_data: b"argon2id-hash".to_vec(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id", "temporary": true}),
            priority: 2,
        };
        let rep = CredentialRepresentation::redacted_from(&cred);
        assert_eq!(rep.id, Some("cred-1".to_string()));
        assert_eq!(rep.credential_type, CredentialType::Password);
        assert_eq!(rep.user_label, Some("label".to_string()));
        assert_eq!(rep.created_date, Some(1_700_000_000_123));
        assert_eq!(rep.priority, Some(2));
        assert_eq!(rep.temporary, Some(true));
        assert_eq!(
            rep.credential_data.as_deref(),
            Some(r#"{"hash_algorithm":"argon2id","temporary":true}"#)
        );
        // The whole point: no secret material on the wire, in any field.
        assert!(rep.secret_data.is_none());
        assert!(rep.value.is_none());
        let serialized = serde_json::to_string(&rep).unwrap();
        assert!(!serialized.contains("argon2id-hash"));
    }

    #[test]
    fn role_try_from_representation() {
        let rep = RoleRepresentation {
            id: Some("role-1".to_string()),
            name: "admin".to_string(),
            description: Some("desc".to_string()),
            composite: Some(true),
            composites: Some(vec![RoleName::new("r1").unwrap()]),
            client_role: Some(false),
            container_id: None,
            attributes: Some({
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec!["v".to_string()]);
                m
            }),
        };
        let role: Role = rep.try_into().unwrap();
        assert_eq!(role.name, issuerd_core::RoleName::new("admin").unwrap());
        assert!(role.composite);
    }

    #[test]
    fn group_with_subgroups_roundtrip() {
        let rep = GroupRepresentation {
            id: Some("g1".to_string()),
            name: "parent".to_string(),
            path: Some("/parent".to_string()),
            attributes: None,
            realm_roles: None,
            client_roles: None,
            sub_groups: Some(vec![GroupRepresentation {
                id: Some("g2".to_string()),
                name: "child".to_string(),
                path: Some("/parent/child".to_string()),
                attributes: None,
                realm_roles: None,
                client_roles: None,
                sub_groups: None,
                parent_id: None,
            }]),
            parent_id: None,
        };
        let group: Group = rep.try_into().unwrap();
        assert_eq!(group.sub_groups.len(), 1);
        assert_eq!(group.sub_groups[0].name, issuerd_core::GroupName::new("child").unwrap());

        let back: GroupRepresentation = group.into();
        assert_eq!(back.sub_groups.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn user_session_from_domain() {
        let session = UserSession {
            id: issuerd_core::SessionId::new("s1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            user_id: UserId::new("u1").unwrap(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![issuerd_core::ClientSession {
                id: issuerd_core::ClientSessionId::new("cs1").unwrap(),
                client_id: issuerd_core::ClientId::new("c1").unwrap(),
                session_id: issuerd_core::SessionId::new("s1").unwrap(),
                redirect_uri: None,
                state: None,
                auth_method: AuthMethod::Password,
                timestamp: chrono::Utc::now(),
            }],
        };
        let rep: UserSessionRepresentation = session.into();
        assert_eq!(rep.username, "alice");
        assert_eq!(rep.clients.len(), 1);
    }

    #[test]
    fn event_from_domain() {
        let ev = Event {
            id: issuerd_core::EventId::new("e1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            event_time: chrono::Utc::now(),
            event_type: issuerd_core::EventType::Login,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(issuerd_core::ClientId::new("c1").unwrap()),
            user_id: Some(UserId::new("u1").unwrap()),
            session_id: Some(issuerd_core::SessionId::new("s1").unwrap()),
            error: None,
            details: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), "v".to_string());
                m
            },
        };
        let rep: EventRepresentation = ev.into();
        assert_eq!(rep.event_type, EventType::Login);
        assert_eq!(rep.realm_id, "realm-1");
        assert!(rep.details.is_some());
    }

    #[test]
    fn flow_invalid_requirement() {
        let json = r#"{"alias":"browser","stages":[{"id":"stage-1","requirement":"unknown","authenticator":"auth","priority":0}]}"#;
        let result: Result<FlowRepresentation, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn identity_provider_roundtrip() {
        let rep = IdentityProviderRepresentation {
            alias: Alias::new("google").unwrap(),
            display_name: Some("Google".to_string()),
            provider_id: ProviderId::new("google"),
            enabled: Some(false),
            config: Some({
                let mut m = HashMap::new();
                m.insert("clientId".to_string(), "123".to_string());
                m
            }),
        };
        let idp: IdentityProviderConfig = rep.try_into().unwrap();
        assert!(!idp.enabled);
        assert_eq!(idp.config.get("displayName"), Some(&"Google".to_string()));

        let back: IdentityProviderRepresentation = idp.into();
        assert_eq!(back.alias, Alias::new("google").unwrap());
        assert_eq!(back.display_name, Some("Google".to_string()));
    }

    #[test]
    fn user_into_representation() {
        let user = User {
            id: UserId::new("u1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            email_verified: true,
            federation_link: Some("ldap-1".to_string()),
            required_actions: vec![],
            attributes: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec!["v".to_string()]);
                m
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let rep: UserRepresentation = user.into();
        assert_eq!(rep.id, Some("u1".to_string()));
        assert_eq!(rep.username, "alice");
        assert_eq!(rep.email, Some("alice@example.com".to_string()));
        assert_eq!(rep.first_name, Some("Alice".to_string()));
        assert_eq!(rep.last_name, Some("Smith".to_string()));
        assert_eq!(rep.enabled, Some(true));
        assert_eq!(rep.email_verified, Some(true));
        assert!(rep.created_at.is_some());
        assert!(rep.credentials.is_none());
        assert!(rep.realm_roles.is_none());
        assert!(rep.client_roles.is_none());
        assert!(rep.groups.is_none());
    }

    #[test]
    fn client_into_representation() {
        let client = Client {
            id: ClientId::new("c1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: Some(DisplayName::new("My App").unwrap()),
            description: Some("desc".to_string()),
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("secret".to_string()),
            redirect_uris: vec![RedirectUri::new("https://app.example.com/callback").unwrap()],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: issuerd_core::Scope::parse("openid"),
            optional_scopes: issuerd_core::Scope::parse("email"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), "v".to_string());
                m
            },
        };
        let rep: ClientRepresentation = client.into();
        assert_eq!(rep.id, Some("c1".to_string()));
        assert_eq!(rep.client_id, "my-app");
        assert_eq!(rep.name, Some("My App".to_string()));
        assert_eq!(rep.description, Some("desc".to_string()));
        assert_eq!(rep.enabled, Some(true));
        assert_eq!(rep.protocol, Some(ClientProtocol::OpenIdConnect));
        assert_eq!(rep.public_client, Some(false));
        assert_eq!(rep.bearer_only, Some(false));
        assert_eq!(rep.client_authenticator_type, Some(ClientAuthenticatorType::ClientSecret));
        assert!(rep.secret.is_none(), "client secret must be redacted on read");
        assert_eq!(rep.redirect_uris, Some(vec!["https://app.example.com/callback".to_string()]));
        assert_eq!(rep.web_origins, Some(vec!["https://app.example.com".to_string()]));
        assert_eq!(rep.default_scopes, Some(vec!["openid".to_string()]));
        assert_eq!(rep.optional_scopes, Some(vec!["email".to_string()]));
        assert_eq!(rep.consent_required, Some(false));
        assert_eq!(rep.full_scope_allowed, Some(true));
        assert_eq!(
            rep.attributes,
            Some({
                let mut m = HashMap::new();
                m.insert("k".to_string(), "v".to_string());
                m
            })
        );
    }

    #[test]
    fn role_into_representation() {
        let role = Role {
            id: RoleId::new("r1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Admin role".to_string()),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: true,
            composites: vec![RoleName::new("user").unwrap()],
            attributes: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec!["v".to_string()]);
                m
            },
        };
        let rep: RoleRepresentation = role.into();
        assert_eq!(rep.id, Some("r1".to_string()));
        assert_eq!(rep.name, "admin");
        assert_eq!(rep.description, Some("Admin role".to_string()));
        assert_eq!(rep.composite, Some(true));
        assert_eq!(rep.composites, Some(vec![RoleName::new("user").unwrap()]));
        assert_eq!(rep.client_role, Some(false));
        assert_eq!(rep.container_id, Some("realm-1".to_string()));
        assert_eq!(
            rep.attributes,
            Some({
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec!["v".to_string()]);
                m
            })
        );
    }

    #[test]
    fn admin_event_into_representation() {
        let event = AdminEvent {
            id: issuerd_core::EventId::new("ae1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            event_time: chrono::Utc::now(),
            auth_realm_id: Some(RealmId::new("realm-1").unwrap()),
            auth_client_id: Some(ClientId::new("c1").unwrap()),
            auth_user_id: Some(UserId::new("u1").unwrap()),
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: "realms/realm-1".to_string(),
            representation: Some("{\"name\":\"test\"}".to_string()),
            error: None,
        };
        let rep: AdminEventRepresentation = event.into();
        assert_eq!(rep.id, Some("ae1".to_string()));
        assert_eq!(rep.realm_id, "realm-1");
        assert_eq!(rep.auth_realm_id, Some("realm-1".to_string()));
        assert_eq!(rep.auth_client_id, Some("c1".to_string()));
        assert_eq!(rep.auth_user_id, Some("u1".to_string()));
        assert_eq!(rep.operation_type, OperationType::Create);
        assert_eq!(rep.resource_type, ResourceType::Realm);
        assert_eq!(rep.resource_path, "realms/realm-1");
        assert_eq!(rep.representation, Some("{\"name\":\"test\"}".to_string()));
        assert_eq!(rep.error, None);
    }

    #[test]
    fn flow_config_into_representation() {
        let flow = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![issuerd_core::FlowStage {
                id: FlowStageId::new("stage-1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("auth-cookie").unwrap(),
                priority: 0,
                sub_flow_alias: None,
                authenticator_config: None,
            }],
        };
        let rep: FlowRepresentation = flow.into();
        assert_eq!(rep.alias, Alias::new("browser").unwrap());
        assert_eq!(rep.provider_id, Some("basic-flow".to_string()));
        assert_eq!(rep.top_level, Some(true));
        assert_eq!(rep.built_in, Some(true));
        assert_eq!(rep.stages.as_ref().unwrap().len(), 1);
        assert_eq!(rep.stages.unwrap()[0].id, "stage-1");
    }

    #[test]
    fn flow_stage_has_config_tracks_embedded_config() {
        let stage = |config: Option<AuthenticatorConfig>| issuerd_core::FlowStage {
            id: FlowStageId::new("stage-1").unwrap(),
            requirement: Requirement::Required,
            authenticator: Alias::new("auth-cookie").unwrap(),
            priority: 0,
            sub_flow_alias: None,
            authenticator_config: config,
        };
        let with: FlowStageRepresentation = stage(Some(AuthenticatorConfig {
            alias: Alias::new("cookie-cfg").unwrap(),
            config: serde_json::Map::new(),
        }))
        .into();
        assert!(with.has_config);
        assert!(with.authenticator_config.is_some());
        let without: FlowStageRepresentation = stage(None).into();
        assert!(!without.has_config);
        assert!(without.authenticator_config.is_none());
    }

    #[test]
    fn flow_stage_representation_deserializes_without_has_config() {
        // Payloads produced before `has_config` existed must still parse.
        let stage: FlowStageRepresentation = serde_json::from_value(serde_json::json!({
            "id": "stage-1",
            "requirement": "required",
            "authenticator": "auth-cookie",
            "priority": 0,
            "sub_flow_alias": null
        }))
        .unwrap();
        assert!(!stage.has_config);
    }

    #[test]
    fn flow_representation_into_config() {
        let rep = FlowRepresentation {
            alias: Alias::new("browser").unwrap(),
            provider_id: Some("basic-flow".to_string()),
            top_level: Some(true),
            built_in: Some(true),
            stages: Some(vec![FlowStageRepresentation {
                id: "stage-1".to_string(),
                requirement: Requirement::Required,
                authenticator: Alias::new("auth-cookie").unwrap(),
                priority: 0,
                sub_flow_alias: None,
                authenticator_config: Some(AuthenticatorConfigRepresentation {
                    alias: Alias::new("cookie-cfg").unwrap(),
                    config: HashMap::from([("k".to_string(), serde_json::Value::from("v"))]),
                }),
                has_config: true,
                flow_alias: None,
            }]),
        };
        let realm_id = RealmId::new("realm-1").unwrap();
        let config = flow_config_from_representation(&realm_id, rep).unwrap();
        assert_eq!(config.alias, Alias::new("browser").unwrap());
        assert_eq!(config.realm_id, realm_id);
        assert_eq!(config.provider_id, "basic-flow");
        assert!(config.top_level);
        assert!(config.built_in);
        assert_eq!(config.stages.len(), 1);
        let cfg = config.stages[0].authenticator_config.clone().unwrap();
        assert_eq!(cfg.alias, Alias::new("cookie-cfg").unwrap());
        assert_eq!(cfg.config.get("k"), Some(&serde_json::Value::from("v")));
    }

    #[test]
    fn sync_result_into_representation() {
        let result = issuerd_core::SyncResult {
            added: 5,
            updated: 3,
            removed: 1,
            failed: 0,
            last_sync: chrono::Utc::now(),
        };
        let rep: SyncResultRepresentation = result.into();
        assert_eq!(rep.added, 5);
        assert_eq!(rep.updated, 3);
        assert_eq!(rep.removed, 1);
        assert_eq!(rep.failed, 0);
    }

    #[test]
    fn user_representation_invalid_username() {
        let rep = UserRepresentation {
            id: None,
            username: "".to_string(),
            email: None,
            first_name: None,
            last_name: None,
            enabled: None,
            email_verified: None,
            created_at: None,
            attributes: None,
            credentials: None,
            realm_roles: None,
            client_roles: None,
            groups: None,
            required_actions: None,
        };
        let result: Result<User, _> = rep.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn client_representation_invalid_redirect_uri() {
        let rep = ClientRepresentation {
            id: None,
            client_id: "my-app".to_string(),
            name: None,
            description: None,
            enabled: None,
            protocol: None,
            public_client: None,
            bearer_only: None,
            client_authenticator_type: None,
            redirect_uris: Some(vec!["not a uri".to_string()]),
            web_origins: None,
            default_scopes: None,
            optional_scopes: None,
            consent_required: None,
            full_scope_allowed: None,
            service_accounts_enabled: None,
            protocol_mappers: None,
            secret: None,
            attributes: None,
        };
        let result: Result<Client, _> = rep.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn client_representation_invalid_web_origin() {
        let rep = ClientRepresentation {
            id: None,
            client_id: "my-app".to_string(),
            name: None,
            description: None,
            enabled: None,
            protocol: None,
            public_client: None,
            bearer_only: None,
            client_authenticator_type: None,
            redirect_uris: None,
            web_origins: Some(vec!["not an origin".to_string()]),
            default_scopes: None,
            optional_scopes: None,
            consent_required: None,
            full_scope_allowed: None,
            service_accounts_enabled: None,
            protocol_mappers: None,
            secret: None,
            attributes: None,
        };
        let result: Result<Client, _> = rep.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn client_role_representation_roundtrip() {
        let role = Role {
            id: RoleId::new("r1").unwrap(),
            name: RoleName::new("client-admin").unwrap(),
            description: None,
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: true,
            client_id: Some(ClientId::new("client-9").unwrap()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        let rep: RoleRepresentation = role.into();
        // Client roles are contained by their owning client, not the realm.
        assert_eq!(rep.client_role, Some(true));
        assert_eq!(rep.container_id, Some("client-9".to_string()));

        let back: Role = rep.try_into().unwrap();
        assert!(back.client_role);
        assert_eq!(back.client_id, Some(ClientId::new("client-9").unwrap()));
    }

    #[test]
    fn realm_role_representation_container_is_realm() {
        let role = Role {
            id: RoleId::new("r1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        let rep: RoleRepresentation = role.into();
        assert_eq!(rep.client_role, Some(false));
        assert_eq!(rep.container_id, Some("realm-1".to_string()));

        let back: Role = rep.try_into().unwrap();
        assert!(!back.client_role);
        assert_eq!(back.client_id, None);
    }

    #[test]
    fn protocol_mapper_representation_roundtrip() {
        let mapper = ProtocolMapper {
            id: MapperId::new("m1").unwrap(),
            name: "my mapper".to_string(),
            mapper_type: MapperType::UserAttribute,
            config: {
                let mut m = HashMap::new();
                m.insert("claim.name".to_string(), "foo".to_string());
                m
            },
        };
        let rep: ProtocolMapperRepresentation = mapper.into();
        assert_eq!(rep.id, Some("m1".to_string()));
        assert_eq!(rep.protocol, Some("openid-connect".to_string()));
        assert_eq!(rep.protocol_mapper, MapperType::UserAttribute);

        let back: ProtocolMapper = rep.try_into().unwrap();
        assert_eq!(back.id, MapperId::new("m1").unwrap());
        assert_eq!(back.config_value("claim.name"), Some("foo"));
    }

    #[test]
    fn protocol_mapper_representation_rejects_non_oidc_protocol() {
        let rep = ProtocolMapperRepresentation {
            id: None,
            name: "m".to_string(),
            protocol: Some("saml".to_string()),
            protocol_mapper: MapperType::UserAttribute,
            config: None,
        };
        let result: Result<ProtocolMapper, _> = rep.try_into();
        assert!(matches!(result, Err(issuerd_core::IssuerdError::InvalidRequest(_))));

        // Omitted protocol defaults to OIDC and generates an id.
        let rep = ProtocolMapperRepresentation {
            id: None,
            name: "m".to_string(),
            protocol: None,
            protocol_mapper: MapperType::FullName,
            config: None,
        };
        let mapper: ProtocolMapper = rep.try_into().unwrap();
        assert!(!mapper.id.as_ref().is_empty());
    }

    #[test]
    fn client_scope_representation_roundtrip() {
        let scope = ClientScope {
            id: ClientScopeId::new("s1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            name: "profile".to_string(),
            description: Some("desc".to_string()),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::new(),
            protocol_mappers: vec![ProtocolMapper {
                id: MapperId::new("m1").unwrap(),
                name: "username".to_string(),
                mapper_type: MapperType::UserProperty,
                config: HashMap::new(),
            }],
            scope_mappings: Default::default(),
        };
        let rep: ClientScopeRepresentation = scope.clone().into();
        assert_eq!(rep.id, Some("s1".to_string()));
        assert_eq!(rep.protocol_mappers.as_ref().unwrap().len(), 1);

        // List endpoints strip the mappers.
        let listed = ClientScopeRepresentation::without_mappers(scope);
        assert!(listed.protocol_mappers.is_none());

        let back: ClientScope = rep.try_into().unwrap();
        assert_eq!(back.name, "profile");
        assert_eq!(back.protocol_mappers.len(), 1);
    }

    #[test]
    fn mappings_representation_serde_omits_empty_sides() {
        let empty = MappingsRepresentation::default();
        let json = serde_json::to_value(&empty).unwrap();
        assert!(json.get("realm_mappings").is_none());
        assert!(json.get("client_mappings").is_none());

        let with_realm = MappingsRepresentation {
            realm_mappings: Some(vec![RoleRepresentation {
                id: Some("r1".to_string()),
                name: "admin".to_string(),
                description: None,
                composite: Some(false),
                composites: None,
                client_role: Some(false),
                container_id: None,
                attributes: None,
            }]),
            client_mappings: None,
        };
        let json = serde_json::to_value(&with_realm).unwrap();
        assert_eq!(json["realm_mappings"][0]["name"], "admin");
        assert!(json.get("client_mappings").is_none());
    }
}
