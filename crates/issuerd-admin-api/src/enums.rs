// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Dynamic enum value listings backing /admin/enums/* and serverinfo.

use std::sync::Arc;

use axum::{
    extract::{Extension, State},
    Json,
};

use crate::auth::{require_roles, AdminAuth};
use crate::dto::{EnumValueRepresentation, ServerInfoRepresentation};
use crate::error::AdminApiError;
use crate::state::AdminApiState;

// ---------------------------------------------------------------------------
// Data builders
// ---------------------------------------------------------------------------

fn protocols() -> Vec<EnumValueRepresentation> {
    vec![
        EnumValueRepresentation {
            id: "openid-connect".to_string(),
            name: "OpenID Connect".to_string(),
            description: Some("OIDC/OAuth2 protocol".to_string()),
        },
        EnumValueRepresentation {
            id: "saml".to_string(),
            name: "SAML 2.0".to_string(),
            description: Some("Security Assertion Markup Language".to_string()),
        },
    ]
}

fn ssl_required() -> Vec<EnumValueRepresentation> {
    vec![
        EnumValueRepresentation {
            id: "none".to_string(),
            name: "None".to_string(),
            description: Some("SSL is not required".to_string()),
        },
        EnumValueRepresentation {
            id: "external".to_string(),
            name: "External requests".to_string(),
            description: Some("SSL required for external requests".to_string()),
        },
        EnumValueRepresentation {
            id: "all".to_string(),
            name: "All requests".to_string(),
            description: Some("SSL required for all requests".to_string()),
        },
    ]
}

fn event_types() -> Vec<EnumValueRepresentation> {
    vec![
        ("login", "Login", "Successful user login"),
        ("login_error", "Login Error", "Failed user login"),
        ("register", "Register", "Successful user registration"),
        ("register_error", "Register Error", "Failed user registration"),
        ("logout", "Logout", "User logout"),
        ("logout_error", "Logout Error", "Failed logout"),
        ("code_to_token", "Code to Token", "Authorization code exchanged for tokens"),
        ("code_to_token_error", "Code to Token Error", "Failed code exchange"),
        ("client_login", "Client Login", "Successful client authentication"),
        ("client_login_error", "Client Login Error", "Failed client authentication"),
        ("refresh_token", "Refresh Token", "Token refresh"),
        ("refresh_token_error", "Refresh Token Error", "Failed token refresh"),
        ("token_exchange", "Token Exchange", "Successful RFC 8693 token exchange"),
        ("token_exchange_error", "Token Exchange Error", "Failed RFC 8693 token exchange"),
        ("ciba_auth", "CIBA Auth", "CIBA backchannel authentication request accepted"),
        (
            "ciba_auth_error",
            "CIBA Auth Error",
            "CIBA backchannel authentication request or approval submission rejected",
        ),
        ("ciba_approve", "CIBA Approve", "CIBA request approved by the user"),
        ("ciba_deny", "CIBA Deny", "CIBA request denied by the user"),
        ("invalid_signature", "Invalid Signature", "Token with invalid signature"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn event_listeners() -> Vec<EnumValueRepresentation> {
    vec![EnumValueRepresentation {
        id: "logging".to_string(),
        name: "Logging".to_string(),
        description: Some(
            "Writes events to the server log via tracing; the built-in default listener"
                .to_string(),
        ),
    }]
}

fn credential_types() -> Vec<EnumValueRepresentation> {
    vec![
        ("password", "Password", "Password-based credential"),
        ("totp", "TOTP", "Time-based One-Time Password"),
        ("hotp", "HOTP", "HMAC-based One-Time Password"),
        ("web_authn", "WebAuthn", "Web Authentication standard"),
        ("web_authn_passwordless", "WebAuthn Passwordless", "Passwordless WebAuthn"),
        ("kerberos", "Kerberos", "Kerberos authentication"),
        ("ssh_public_key", "SSH Public Key", "SSH public key credential"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn algorithms() -> Vec<EnumValueRepresentation> {
    vec![
        ("RS256", "RS256", "RSA with SHA-256"),
        ("RS384", "RS384", "RSA with SHA-384"),
        ("RS512", "RS512", "RSA with SHA-512"),
        ("ES256", "ES256", "ECDSA with SHA-256"),
        ("ES384", "ES384", "ECDSA with SHA-384"),
        ("ES512", "ES512", "ECDSA with SHA-512"),
        (
            "HS256",
            "HS256",
            "HMAC with SHA-256 (symmetric; not applicable to realm token signing)",
        ),
        (
            "HS384",
            "HS384",
            "HMAC with SHA-384 (symmetric; not applicable to realm token signing)",
        ),
        (
            "HS512",
            "HS512",
            "HMAC with SHA-512 (symmetric; not applicable to realm token signing)",
        ),
        ("EdDSA", "EdDSA", "Edwards-curve Digital Signature Algorithm"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn grant_types() -> Vec<EnumValueRepresentation> {
    vec![
        ("authorization_code", "Authorization Code", "OAuth2 authorization code grant"),
        ("refresh_token", "Refresh Token", "OAuth2 refresh token grant"),
        ("password", "Password", "Resource Owner Password Credentials"),
        ("client_credentials", "Client Credentials", "OAuth2 client credentials grant"),
        (
            "urn:ietf:params:oauth:grant-type:device_code",
            "Device Code",
            "OAuth2 device authorization grant",
        ),
        (
            "urn:openid:params:grant-type:ciba",
            "CIBA",
            "Client Initiated Backchannel Authentication",
        ),
        (
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "Token Exchange",
            "OAuth2 token exchange",
        ),
        (
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "JWT Bearer",
            "JWT profile for OAuth2 client authentication",
        ),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn subject_types() -> Vec<EnumValueRepresentation> {
    vec![
        (
            "public",
            "Public",
            "Every client receives the same subject identifier (the internal user id)",
        ),
        (
            "pairwise",
            "Pairwise",
            "Subject identifiers are derived per sector (OIDC Core §8); different sectors see unlinkable identifiers for the same user",
        ),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn response_types() -> Vec<EnumValueRepresentation> {
    vec![
        ("code", "Code", "Authorization code only"),
        ("id_token", "ID Token", "ID token only"),
        ("token", "Token", "Access token only (implicit)"),
        ("code id_token", "Code + ID Token", "Hybrid flow"),
        ("code token", "Code + Token", "Hybrid flow"),
        ("id_token token", "ID Token + Token", "Hybrid flow"),
        ("code id_token token", "Code + ID Token + Token", "Hybrid flow"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn response_modes() -> Vec<EnumValueRepresentation> {
    vec![
        ("query", "Query", "Parameters appended to redirect URI"),
        ("fragment", "Fragment", "Parameters in URI fragment"),
        ("form_post", "Form Post", "Parameters sent via auto-submitted HTML form"),
        ("jwt", "JWT", "JARM: signed JWT in the response type's default mode"),
        ("query.jwt", "Query JWT", "JARM: signed JWT appended to redirect URI"),
        ("fragment.jwt", "Fragment JWT", "JARM: signed JWT in URI fragment"),
        (
            "form_post.jwt",
            "Form Post JWT",
            "JARM: signed JWT sent via auto-submitted HTML form",
        ),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn requirements() -> Vec<EnumValueRepresentation> {
    vec![
        ("required", "Required", "Execution must succeed"),
        ("alternative", "Alternative", "At least one alternative must succeed"),
        ("optional", "Optional", "Execution is optional"),
        ("disabled", "Disabled", "Execution is disabled"),
        ("conditional", "Conditional", "Execution depends on condition evaluation"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn provider_ids() -> Vec<EnumValueRepresentation> {
    vec![
        ("ldap", "LDAP", "LDAP directory server (OpenLDAP, Active Directory)"),
        ("kerberos", "Kerberos", "Kerberos / SPNEGO authentication (Unix only)"),
        // Broker-capable providers: login via an external IdP.
        ("oidc", "OpenID Connect", "Generic OIDC identity brokering"),
        ("google", "Google", "Sign in with Google"),
        ("microsoft", "Microsoft", "Sign in with a Microsoft account"),
        ("github", "GitHub", "Sign in with GitHub (userinfo-based, no ID token)"),
        ("facebook", "Facebook", "Sign in with Facebook"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn client_authenticator_types() -> Vec<EnumValueRepresentation> {
    vec![
        ("client-secret", "Client Secret", "Authenticate with client ID and secret"),
        ("client-jwt", "Client JWT", "Authenticate with signed JWT assertion"),
        (
            "client-secret-jwt",
            "Client Secret JWT",
            "Authenticate with HMAC-signed JWT using client secret",
        ),
        ("client-x509", "Client X.509", "Authenticate with X.509 client certificate"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn operation_types() -> Vec<EnumValueRepresentation> {
    vec![
        ("CREATE", "Create", "Resource was created"),
        ("UPDATE", "Update", "Resource was updated"),
        ("DELETE", "Delete", "Resource was deleted"),
        ("ACTION", "Action", "Action was performed on resource"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn prompts() -> Vec<EnumValueRepresentation> {
    vec![
        ("none", "None", "No user interaction"),
        ("login", "Login", "Force re-authentication"),
        ("consent", "Consent", "Force consent screen"),
        ("select_account", "Select Account", "Force account selection"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn resource_types() -> Vec<EnumValueRepresentation> {
    use issuerd_core::ResourceType;
    vec![
        (ResourceType::Realm, "Realm", "Realm settings"),
        (ResourceType::User, "User", "User account"),
        (ResourceType::Client, "Client", "OIDC/OAuth2 client"),
        (ResourceType::ClientScope, "Client Scope", "Client scope with protocol mappers"),
        (ResourceType::Group, "Group", "User group"),
        (ResourceType::Role, "Role", "Role definition"),
        (ResourceType::Session, "Session", "User session"),
        (
            ResourceType::IdentityProvider,
            "Identity Provider",
            "External identity provider",
        ),
        (ResourceType::UserFederation, "User Federation", "LDAP/Kerberos federation"),
        (
            ResourceType::InitialAccessToken,
            "Initial Access Token",
            "Initial access token for dynamic client registration",
        ),
    ]
    .into_iter()
    .map(|(rt, name, desc)| EnumValueRepresentation {
        id: serde_json::to_string(&rt).unwrap().trim_matches('"').to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn hash_algorithms() -> Vec<EnumValueRepresentation> {
    vec![
        ("argon2id", "Argon2id", "Argon2id password hashing"),
        ("pbkdf2", "PBKDF2", "PBKDF2 password hashing"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn auth_methods() -> Vec<EnumValueRepresentation> {
    use issuerd_core::AuthMethod;
    vec![
        (AuthMethod::Password, "Password", "Password-based authentication"),
        (AuthMethod::Spnego, "SPNEGO", "Kerberos/SPNEGO authentication"),
        (AuthMethod::Ciba, "CIBA", "Client Initiated Backchannel Authentication"),
    ]
    .into_iter()
    .map(|(am, name, desc)| EnumValueRepresentation {
        id: serde_json::to_string(&am).unwrap().trim_matches('"').to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn pkce_code_challenge_methods() -> Vec<EnumValueRepresentation> {
    use issuerd_core::PkceCodeChallengeMethod;
    vec![
        (PkceCodeChallengeMethod::S256, "S256", "SHA-256 code challenge method"),
        (PkceCodeChallengeMethod::Plain, "Plain", "Plain text code challenge method"),
    ]
    .into_iter()
    .map(|(m, name, desc)| EnumValueRepresentation {
        id: serde_json::to_string(&m).unwrap().trim_matches('"').to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn jwk_use() -> Vec<EnumValueRepresentation> {
    use issuerd_core::JwkUse;
    vec![
        (JwkUse::Sig, "Signature", "Digital signature"),
        (JwkUse::Enc, "Encryption", "Key encryption"),
    ]
    .into_iter()
    .map(|(u, name, desc)| EnumValueRepresentation {
        id: serde_json::to_string(&u).unwrap().trim_matches('"').to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn jwk_key_types() -> Vec<EnumValueRepresentation> {
    use issuerd_core::JwkKty;
    vec![
        (JwkKty::Rsa, "RSA", "RSA key"),
        (JwkKty::Ec, "EC", "Elliptic Curve key"),
        (JwkKty::Oct, "OCT", "Octet sequence"),
        (JwkKty::Okp, "OKP", "Octet Key Pair"),
    ]
    .into_iter()
    .map(|(k, name, desc)| EnumValueRepresentation {
        id: serde_json::to_string(&k).unwrap().trim_matches('"').to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn ldap_vendors() -> Vec<EnumValueRepresentation> {
    vec![
        ("GENERIC", "Generic", "Standard LDAP server (OpenLDAP, 389 DS, etc.)"),
        ("ACTIVE_DIRECTORY", "Active Directory", "Microsoft Active Directory"),
        ("SAMBA", "Samba AD DC", "Samba Active Directory Domain Controller"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn ldap_search_scopes() -> Vec<EnumValueRepresentation> {
    vec![
        ("SUBTREE", "Subtree", "Search the base entry and all descendants"),
        ("ONELEVEL", "One Level", "Search immediate children only"),
        ("BASE", "Base", "Search the base entry only"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn edit_modes() -> Vec<EnumValueRepresentation> {
    vec![
        (
            "READONLY",
            "Read Only",
            "Users are imported but not written back to the provider",
        ),
        ("WRITABLE", "Writable", "Changes to users are written back to the provider"),
        ("UNSYNCED", "Unsynced", "Users are linked but not imported or synchronized"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn required_actions() -> Vec<EnumValueRepresentation> {
    vec![
        ("VERIFY_EMAIL", "Verify Email", "User must verify their email address"),
        (
            "UPDATE_PASSWORD",
            "Update Password",
            "User must choose a new password at next login",
        ),
        ("UPDATE_PROFILE", "Update Profile", "User must review and update their profile"),
        (
            "CONFIGURE_TOTP",
            "Configure OTP",
            "User must configure a one-time-password generator",
        ),
        (
            "TERMS_AND_CONDITIONS",
            "Terms and Conditions",
            "User must accept the terms and conditions",
        ),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn otp_algorithms() -> Vec<EnumValueRepresentation> {
    vec![
        ("HmacSHA1", "HMAC-SHA-1", "TOTP codes via HMAC-SHA-1 (RFC 6238 default)"),
        ("HmacSHA256", "HMAC-SHA-256", "TOTP codes via HMAC-SHA-256"),
        ("HmacSHA512", "HMAC-SHA-512", "TOTP codes via HMAC-SHA-512"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn broker_sync_modes() -> Vec<EnumValueRepresentation> {
    vec![
        ("import", "Import", "Apply mappers only when the user is first created"),
        ("force", "Force", "Re-apply mappers on every brokered login"),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn broker_client_auth_methods() -> Vec<EnumValueRepresentation> {
    vec![
        (
            "client_secret_basic",
            "Client Secret (Basic)",
            "Client credentials in the Authorization header (default)",
        ),
        (
            "client_secret_post",
            "Client Secret (POST)",
            "Client credentials in the token request body",
        ),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn idp_mapper_types() -> Vec<EnumValueRepresentation> {
    vec![
        (
            "attribute",
            "Attribute",
            "Copy a claim into a user attribute (claim, attribute)",
        ),
        (
            "role",
            "Role",
            "Assign a realm role when a claim matches (claim, claim_value, role)",
        ),
        (
            "username_template",
            "Username Template",
            "Derive the username from a template at user creation (template)",
        ),
    ]
    .into_iter()
    .map(|(id, name, desc)| EnumValueRepresentation {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

fn mapper_types() -> Vec<EnumValueRepresentation> {
    issuerd_core::MapperType::ALL
        .iter()
        .map(|mt| EnumValueRepresentation {
            id: serde_json::to_string(mt).unwrap().trim_matches('"').to_string(),
            name: mt.label().to_string(),
            description: Some(mt.description().to_string()),
        })
        .collect()
}

fn locales() -> Vec<EnumValueRepresentation> {
    issuerd_core::i18n::SHIPPED_LOCALES
        .iter()
        .map(|tag| EnumValueRepresentation {
            id: (*tag).to_string(),
            name: locale_label(tag).to_string(),
            description: Some("Built-in message bundle".to_string()),
        })
        .collect()
}

/// Human-readable label for a shipped locale tag.
fn locale_label(tag: &str) -> &str {
    match tag {
        "en" => "English",
        "de" => "German",
        _ => tag,
    }
}

/// Authenticator providers registered in the plugin registry. The label is
/// each authenticator's display name; the description reuses it (the
/// `Authenticator` trait exposes no separate description).
async fn authenticators(state: &AdminApiState) -> Vec<EnumValueRepresentation> {
    let mut ids = state.plugin_registry.list_authenticator_ids();
    ids.sort();
    let mut values = Vec::with_capacity(ids.len());
    for id in ids {
        // A registry entry that fails to resolve is skipped rather than
        // failing the whole listing.
        let Ok(Some(authenticator)) = state.plugin_registry.get_authenticator(&id).await else {
            continue;
        };
        let display_name = authenticator.display_name().to_string();
        values.push(EnumValueRepresentation {
            id,
            name: display_name.clone(),
            description: Some(display_name),
        });
    }
    values
}

fn themes(names: &[String]) -> Vec<EnumValueRepresentation> {
    names
        .iter()
        .map(|name| EnumValueRepresentation {
            id: name.clone(),
            name: name.clone(),
            description: Some("Login theme".to_string()),
        })
        .collect()
}

async fn build_server_info(state: &AdminApiState) -> ServerInfoRepresentation {
    ServerInfoRepresentation {
        protocols: protocols(),
        ssl_required: ssl_required(),
        event_types: event_types(),
        event_listeners: event_listeners(),
        credential_types: credential_types(),
        algorithms: algorithms(),
        grant_types: grant_types(),
        response_types: response_types(),
        response_modes: response_modes(),
        requirements: requirements(),
        authenticators: authenticators(state).await,
        provider_ids: provider_ids(),
        client_authenticator_types: client_authenticator_types(),
        operation_types: operation_types(),
        prompts: prompts(),
        resource_types: resource_types(),
        hash_algorithms: hash_algorithms(),
        auth_methods: auth_methods(),
        pkce_code_challenge_methods: pkce_code_challenge_methods(),
        jwk_use: jwk_use(),
        jwk_key_types: jwk_key_types(),
        ldap_vendors: ldap_vendors(),
        ldap_search_scopes: ldap_search_scopes(),
        edit_modes: edit_modes(),
        required_actions: required_actions(),
        otp_algorithms: otp_algorithms(),
        broker_sync_modes: broker_sync_modes(),
        broker_client_auth_methods: broker_client_auth_methods(),
        idp_mapper_types: idp_mapper_types(),
        mapper_types: mapper_types(),
        identity_provider_presets: issuerd_core::identity_provider_presets(),
        locales: locales(),
        themes: themes(&state.available_themes),
        subject_types: subject_types(),
        client_installations: crate::client_installation::providers(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Get server metadata and available enum values.
///
/// Returns a comprehensive list of constants, enum values, and supported
/// configuration options used by the admin console dropdowns and forms.
#[utoipa::path(
    get,
    path = "/admin/serverinfo",
    responses(
        (status = 200, description = "Server metadata", body = ServerInfoRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
    ),
    tag = "Server Info"
)]
pub async fn get_serverinfo(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<ServerInfoRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    Ok(Json(build_server_info(&state).await))
}

macro_rules! enum_endpoint {
    ($name:ident, $path:expr, $builder:ident, $tag:expr) => {
        #[utoipa::path(
            get,
            path = $path,
            responses(
                (status = 200, description = "List of enum values", body = Vec<EnumValueRepresentation>),
                (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
                (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
            ),
            tag = $tag
        )]
        pub async fn $name(
            Extension(auth): Extension<AdminAuth>,
        ) -> Result<Json<Vec<EnumValueRepresentation>>, AdminApiError> {
            require_roles(&auth, &["view-realm", "manage-realm"])?;
            Ok(Json($builder()))
        }
    };
}

enum_endpoint!(list_protocols, "/admin/enums/protocols", protocols, "Enums");
enum_endpoint!(list_ssl_required, "/admin/enums/ssl-required", ssl_required, "Enums");
enum_endpoint!(list_event_types, "/admin/enums/event-types", event_types, "Enums");
enum_endpoint!(list_event_listeners, "/admin/enums/event-listeners", event_listeners, "Enums");
enum_endpoint!(
    list_credential_types,
    "/admin/enums/credential-types",
    credential_types,
    "Enums"
);
enum_endpoint!(list_algorithms, "/admin/enums/algorithms", algorithms, "Enums");
enum_endpoint!(list_grant_types, "/admin/enums/grant-types", grant_types, "Enums");
enum_endpoint!(list_response_types, "/admin/enums/response-types", response_types, "Enums");
enum_endpoint!(list_response_modes, "/admin/enums/response-modes", response_modes, "Enums");
enum_endpoint!(list_requirements, "/admin/enums/requirements", requirements, "Enums");
enum_endpoint!(list_provider_ids, "/admin/enums/provider-ids", provider_ids, "Enums");
enum_endpoint!(
    list_client_authenticator_types,
    "/admin/enums/client-authenticator-types",
    client_authenticator_types,
    "Enums"
);
enum_endpoint!(list_operation_types, "/admin/enums/operation-types", operation_types, "Enums");
enum_endpoint!(list_prompts, "/admin/enums/prompts", prompts, "Enums");
enum_endpoint!(list_resource_types, "/admin/enums/resource-types", resource_types, "Enums");
enum_endpoint!(list_hash_algorithms, "/admin/enums/hash-algorithms", hash_algorithms, "Enums");
enum_endpoint!(list_auth_methods, "/admin/enums/auth-methods", auth_methods, "Enums");
enum_endpoint!(
    list_pkce_code_challenge_methods,
    "/admin/enums/pkce-code-challenge-methods",
    pkce_code_challenge_methods,
    "Enums"
);
enum_endpoint!(list_jwk_use, "/admin/enums/jwk-use", jwk_use, "Enums");
enum_endpoint!(list_jwk_key_types, "/admin/enums/jwk-key-types", jwk_key_types, "Enums");
enum_endpoint!(list_ldap_vendors, "/admin/enums/ldap-vendors", ldap_vendors, "Enums");
enum_endpoint!(
    list_ldap_search_scopes,
    "/admin/enums/ldap-search-scopes",
    ldap_search_scopes,
    "Enums"
);
enum_endpoint!(list_edit_modes, "/admin/enums/edit-modes", edit_modes, "Enums");
enum_endpoint!(
    list_required_actions,
    "/admin/enums/required-actions",
    required_actions,
    "Enums"
);
enum_endpoint!(list_otp_algorithms, "/admin/enums/otp-algorithms", otp_algorithms, "Enums");
enum_endpoint!(
    list_broker_sync_modes,
    "/admin/enums/broker-sync-modes",
    broker_sync_modes,
    "Enums"
);
enum_endpoint!(
    list_broker_client_auth_methods,
    "/admin/enums/broker-client-auth-methods",
    broker_client_auth_methods,
    "Enums"
);
enum_endpoint!(
    list_idp_mapper_types,
    "/admin/enums/idp-mapper-types",
    idp_mapper_types,
    "Enums"
);
enum_endpoint!(list_mapper_types, "/admin/enums/mapper-types", mapper_types, "Enums");
enum_endpoint!(list_locales, "/admin/enums/locales", locales, "Enums");
enum_endpoint!(list_subject_types, "/admin/enums/subject-types", subject_types, "Enums");

/// List registered authenticator providers (flow execution provider ids).
#[utoipa::path(
    get,
    path = "/admin/enums/authenticators",
    responses(
        (status = 200, description = "List of enum values", body = Vec<EnumValueRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
    ),
    tag = "Enums"
)]
pub async fn list_authenticators(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<Vec<EnumValueRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    Ok(Json(authenticators(&state).await))
}

/// List available login themes (built-in plus themes directory scan).
#[utoipa::path(
    get,
    path = "/admin/enums/themes",
    responses(
        (status = 200, description = "List of enum values", body = Vec<EnumValueRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
    ),
    tag = "Enums"
)]
pub async fn list_themes(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<Vec<EnumValueRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    Ok(Json(themes(&state.available_themes)))
}

/// List client installation providers (formats accepted by the client
/// installation endpoint for the "Download adapter config" dialog).
#[utoipa::path(
    get,
    path = "/admin/enums/client-installations",
    responses(
        (status = 200, description = "List of client installation providers", body = Vec<crate::dto::ClientInstallationProviderRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
    ),
    tag = "Enums"
)]
pub async fn list_client_installations(
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<Vec<crate::dto::ClientInstallationProviderRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    Ok(Json(crate::client_installation::providers()))
}

/// List identity provider presets (config templates for well-known providers).
#[utoipa::path(
    get,
    path = "/admin/enums/identity-provider-presets",
    responses(
        (status = 200, description = "List of identity provider presets", body = Vec<issuerd_core::IdpPreset>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
    ),
    tag = "Enums"
)]
pub async fn list_identity_provider_presets(
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<Vec<issuerd_core::IdpPreset>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    Ok(Json(issuerd_core::identity_provider_presets()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_info_contains_all_sections() {
        let state = crate::test_utils::tests::test_state(vec![]);
        let info = build_server_info(&state).await;
        assert!(!info.protocols.is_empty());
        assert!(!info.ssl_required.is_empty());
        assert!(!info.event_types.is_empty());
        assert!(!info.event_listeners.is_empty());
        assert!(!info.credential_types.is_empty());
        assert!(!info.algorithms.is_empty());
        assert!(!info.grant_types.is_empty());
        assert!(!info.response_types.is_empty());
        assert!(!info.response_modes.is_empty());
        assert!(!info.requirements.is_empty());
        assert!(!info.authenticators.is_empty());
        assert!(!info.provider_ids.is_empty());
        assert!(!info.client_authenticator_types.is_empty());
        assert!(!info.operation_types.is_empty());
        assert!(!info.prompts.is_empty());
        assert!(!info.resource_types.is_empty());
        assert!(!info.hash_algorithms.is_empty());
        assert!(!info.auth_methods.is_empty());
        assert!(!info.pkce_code_challenge_methods.is_empty());
        assert!(!info.jwk_use.is_empty());
        assert!(!info.jwk_key_types.is_empty());
        assert!(!info.ldap_vendors.is_empty());
        assert!(!info.ldap_search_scopes.is_empty());
        assert!(!info.edit_modes.is_empty());
        assert!(!info.required_actions.is_empty());
        assert!(!info.otp_algorithms.is_empty());
        assert!(!info.broker_sync_modes.is_empty());
        assert!(!info.broker_client_auth_methods.is_empty());
        assert!(!info.idp_mapper_types.is_empty());
        assert!(!info.mapper_types.is_empty());
        assert!(!info.identity_provider_presets.is_empty());
        assert!(!info.locales.is_empty());
        assert!(!info.themes.is_empty());
        assert!(!info.client_installations.is_empty());
    }

    #[test]
    fn client_installations_are_nonempty_with_metadata() {
        let list = crate::client_installation::providers();
        for provider in &list {
            assert!(!provider.display_type.is_empty());
            assert!(!provider.help_text.is_empty());
            assert!(!provider.filename.is_empty());
            assert_eq!(provider.media_type, "application/json");
            assert!(!provider.download_only);
        }
    }

    #[test]
    fn event_listeners_ship_logging_with_description() {
        let list = event_listeners();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "logging");
        assert!(list[0].description.as_ref().is_some_and(|d| !d.is_empty()));
    }

    #[test]
    fn locales_match_shipped_bundles_with_labels() {
        let list = locales();
        let ids: Vec<&str> = list.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, issuerd_core::i18n::SHIPPED_LOCALES);
        let en = list.iter().find(|v| v.id == "en").unwrap();
        assert_eq!(en.name, "English");
        let de = list.iter().find(|v| v.id == "de").unwrap();
        assert_eq!(de.name, "German");
        for item in &list {
            assert!(item.description.as_ref().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn themes_map_names_to_ids_and_labels() {
        let names = vec!["issuerd".to_string(), "acme".to_string()];
        let list = themes(&names);
        assert_eq!(list.len(), 2);
        for (item, name) in list.iter().zip(names.iter()) {
            assert_eq!(&item.id, name);
            assert_eq!(&item.name, name);
            assert!(item.description.as_ref().is_some_and(|d| !d.is_empty()));
        }
    }

    #[tokio::test]
    async fn authenticators_list_registered_ids_with_display_names() {
        let state = crate::test_utils::tests::test_state(vec![]);
        let list = authenticators(&state).await;
        let ids: Vec<&str> = list.iter().map(|v| v.id.as_str()).collect();
        for expected in ["auth-cookie", "auth-otp-form", "auth-registration"] {
            assert!(ids.contains(&expected), "authenticators missing {expected}");
        }
        // Sorted by id; the label comes from the authenticator's display name
        // (the stub registry echoes the id as its display name).
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
        let cookie = list.iter().find(|v| v.id == "auth-cookie").unwrap();
        assert_eq!(cookie.name, "auth-cookie");
        assert_eq!(cookie.description.as_deref(), Some("auth-cookie"));
    }

    #[tokio::test]
    async fn serverinfo_handler_includes_locales_and_themes() {
        let role = issuerd_core::RoleName::new("view-realm").unwrap();
        let state = crate::test_utils::tests::test_state(vec![role.clone()]);
        let token_service = crate::test_utils::tests::MockTokenService { roles: vec![role] };
        let validated =
            issuerd_core::TokenService::validate_access_token(&token_service, "tok").unwrap();
        let auth = AdminAuth {
            claims: validated.claims,
        };
        let Json(info) = get_serverinfo(State(state), Extension(auth)).await.unwrap();
        let locale_ids: Vec<&str> = info.locales.iter().map(|v| v.id.as_str()).collect();
        assert!(locale_ids.contains(&"en") && locale_ids.contains(&"de"));
        let theme_ids: Vec<&str> = info.themes.iter().map(|v| v.id.as_str()).collect();
        assert!(theme_ids.contains(&"issuerd"));
    }

    #[test]
    fn provider_ids_include_broker_providers() {
        let list = provider_ids();
        let ids: Vec<&str> = list.iter().map(|v| v.id.as_str()).collect();
        for expected in ["oidc", "google", "microsoft", "github", "facebook"] {
            assert!(ids.contains(&expected), "provider_ids missing {expected}");
        }
    }

    #[test]
    fn identity_provider_presets_have_provider_ids_and_descriptions() {
        let list = provider_ids();
        let known: Vec<&str> = list.iter().map(|v| v.id.as_str()).collect();
        for preset in issuerd_core::identity_provider_presets() {
            assert!(
                known.contains(&preset.provider_id.as_str()),
                "preset {} has no matching provider_ids entry",
                preset.provider_id
            );
            assert!(!preset.display_name.is_empty());
        }
    }

    #[test]
    fn enum_lists_have_ids_and_names() {
        for list in [
            protocols(),
            ssl_required(),
            event_types(),
            event_listeners(),
            credential_types(),
            algorithms(),
            grant_types(),
            response_types(),
            response_modes(),
            requirements(),
            provider_ids(),
            client_authenticator_types(),
            operation_types(),
            prompts(),
            resource_types(),
            hash_algorithms(),
            auth_methods(),
            pkce_code_challenge_methods(),
            jwk_use(),
            jwk_key_types(),
            ldap_vendors(),
            ldap_search_scopes(),
            edit_modes(),
            required_actions(),
            otp_algorithms(),
            broker_sync_modes(),
            broker_client_auth_methods(),
            idp_mapper_types(),
            mapper_types(),
        ] {
            for item in &list {
                assert!(!item.id.is_empty(), "enum id must not be empty");
                assert!(!item.name.is_empty(), "enum name must not be empty");
            }
        }
    }

    #[test]
    fn required_actions_match_auth_flow_ids() {
        let actions = required_actions();
        let expected = [
            "VERIFY_EMAIL",
            "UPDATE_PASSWORD",
            "UPDATE_PROFILE",
            "CONFIGURE_TOTP",
            "TERMS_AND_CONDITIONS",
        ];
        assert_eq!(actions.len(), expected.len());
        for (action, exp) in actions.iter().zip(expected.iter()) {
            assert_eq!(action.id, *exp);
            // Descriptions are part of the API contract and must be surfaced
            // in the UI — never drop them.
            assert!(action.description.as_ref().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn otp_algorithms_match_core_wire_spellings() {
        let algs = otp_algorithms();
        let expected = ["HmacSHA1", "HmacSHA256", "HmacSHA512"];
        assert_eq!(algs.len(), expected.len());
        for (alg, exp) in algs.iter().zip(expected.iter()) {
            assert_eq!(alg.id, *exp);
            // The enum ids must parse back into the core algorithm type —
            // the realm DTO and the database column use the same spelling.
            assert!(alg.id.parse::<issuerd_core::OtpHashAlgorithm>().is_ok());
            assert!(alg.description.as_ref().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn algorithms_match_core_variants() {
        let algs = algorithms();
        let expected = vec![
            "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512",
            "EdDSA",
        ];
        assert_eq!(algs.len(), expected.len());
        for (alg, exp) in algs.iter().zip(expected.iter()) {
            assert_eq!(alg.id, *exp);
        }
    }

    #[test]
    fn hmac_algorithms_are_marked_not_applicable_to_realm_signing() {
        // The SPA renders these descriptions next to the realm signing
        // algorithm and rotation dropdowns: symmetric HS* values parse as
        // valid `Algorithm`s but are ignored for realm token signing (and
        // rejected by rotation), and that contract must be visible to the
        // admin instead of silently ignored.
        for alg in algorithms() {
            let desc = alg.description.as_deref().unwrap_or_default();
            if alg.id.starts_with("HS") {
                assert!(
                    desc.contains("not applicable to realm token signing"),
                    "HS* description must disclose the realm-signing exclusion: {alg:?}"
                );
            } else {
                assert!(
                    !desc.contains("not applicable to realm token signing"),
                    "asymmetric algorithms stay applicable: {alg:?}"
                );
            }
        }
    }

    #[test]
    fn mapper_types_roundtrip_core_wire_spellings() {
        let list = mapper_types();
        assert_eq!(list.len(), issuerd_core::MapperType::ALL.len());
        for item in &list {
            // The enum id is the serde wire spelling and must parse back.
            let parsed: issuerd_core::MapperType =
                serde_json::from_str(&format!("\"{}\"", item.id)).unwrap();
            assert!(issuerd_core::MapperType::ALL.contains(&parsed));
            assert!(item.description.as_ref().is_some_and(|d| !d.is_empty()));
        }
    }
}
