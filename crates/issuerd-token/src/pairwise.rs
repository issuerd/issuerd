// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Pairwise subject derivation (OIDC Core §8).
//!
//! For clients opted into `subject_type = "pairwise"` (see
//! [`Client::pairwise_subjects`]), the `sub` claim of every user-facing token
//! (ID, access, refresh, logout) is derived instead of copied from the user
//! id: `base64url(HMAC-SHA256(sector_key, len(sector) || sector || user_id))`
//! under the realm's secret sector key. The result is stable per
//! (realm, sector, user) — required so a client can recognize a returning
//! user — and unlinkable across sectors. Derivation is pure: the sector
//! identifier needs no I/O at issuance time (the `sector_identifier_uri`
//! document is validated at registration, see
//! [`issuerd_core::pairwise::validate_pairwise_subject_config`]).

use base64::Engine as _;
use issuerd_core::{Client, IssuerdError, Realm, User, UserId};

/// Derive the pairwise subject identifier for `(sector, user_id)` under
/// `sector_key`.
pub fn pairwise_sub(sector_key: &str, sector: &str, user_id: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, sector_key.as_bytes());
    // Frame the input with a length prefix: a bare `sector || user_id`
    // concatenation is ambiguous — distinct pairs like ("a.com", "x1") and
    // ("a.comx", "1") would hash identically, letting subs collide across
    // sectors. NOTE: this framing changes every derived sub relative to the
    // initial pairwise implementation — acceptable pre-1.0 (no backward-
    // compatibility requirement, see AGENTS.md).
    let mut input = Vec::with_capacity(4 + sector.len() + user_id.len());
    input.extend_from_slice(&(sector.len() as u32).to_be_bytes());
    input.extend_from_slice(sector.as_bytes());
    input.extend_from_slice(user_id.as_bytes());
    let tag = ring::hmac::sign(&key, &input);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag.as_ref())
}

/// Resolve the `sub` claim for tokens issued to `client` on behalf of
/// `user`.
///
/// Public clients (the default) get the user id verbatim. Pairwise clients
/// get a sector-scoped derivation of it. Subjects that are already
/// client-scoped are exempt from derivation — the synthetic
/// client-credentials subject (`sub == client_id`) and the per-client
/// service-account user: their ids are unique to this client, so
/// they are trivially unlinkable across clients, and hashing them would only
/// break server-side user resolution (userinfo, session checks).
pub fn effective_subject(
    user: &User,
    client: &Client,
    realm: &Realm,
) -> Result<UserId, IssuerdError> {
    if !client.pairwise_subjects()
        || user.id.0.as_str() == client.client_id.as_str()
        || user.username.as_str() == client.service_account_username()
    {
        return Ok(user.id.clone());
    }
    let sector = client.resolve_sector_identifier()?.ok_or_else(|| {
        IssuerdError::ServerError(format!(
            "pairwise client {} has no sector identifier \
             (no redirect URIs and no sector_identifier_uri)",
            client.client_id
        ))
    })?;
    let sector_key = realm.pairwise_sector_key().ok_or_else(|| {
        IssuerdError::ServerError(format!(
            "realm {} has no pairwise sector key (missing `{}` attribute)",
            realm.id,
            Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE
        ))
    })?;
    UserId::new(pairwise_sub(sector_key, &sector, user.id.0.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        ClientAuthenticatorType, ClientId, ClientIdentifier, ClientProtocol, DisplayName, Email,
        RealmId, RedirectUri, Scope, Username,
    };
    use std::collections::HashMap;

    fn user(username: &str) -> User {
        User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new(username).unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn client(redirect_uris: &[&str], attributes: &[(&str, &str)]) -> Client {
        Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: redirect_uris.iter().map(|u| RedirectUri::new(*u).unwrap()).collect(),
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: false,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: attributes.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn realm() -> Realm {
        let mut realm = Realm {
            id: RealmId::new("realm-1").unwrap(),
            ..Default::default()
        };
        realm.attributes.insert(
            Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string(),
            "test-sector-key".to_string(),
        );
        realm
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            pairwise_sub("key", "app.example.com", "user-1"),
            pairwise_sub("key", "app.example.com", "user-1")
        );
    }

    #[test]
    fn derivation_varies_by_sector_user_and_key() {
        let base = pairwise_sub("key", "app.example.com", "user-1");
        assert_ne!(base, pairwise_sub("key", "other.example.com", "user-1"));
        assert_ne!(base, pairwise_sub("key", "app.example.com", "user-2"));
        assert_ne!(base, pairwise_sub("other-key", "app.example.com", "user-1"));
    }

    #[test]
    fn framing_prevents_concatenation_collisions() {
        // With a bare `sector || user_id` concatenation both pairs would hash
        // the same input "a.comx1"; the length framing must separate them.
        assert_ne!(pairwise_sub("key", "a.com", "x1"), pairwise_sub("key", "a.comx", "1"));
    }

    #[test]
    fn derivation_is_base64url_without_padding() {
        let sub = pairwise_sub("key", "app.example.com", "user-1");
        assert!(sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!sub.contains('='));
    }

    #[test]
    fn public_client_keeps_user_id() {
        let c = client(&["https://app.example.com/cb"], &[]);
        assert_eq!(
            effective_subject(&user("alice"), &c, &realm()).unwrap(),
            UserId::new("user-1").unwrap()
        );
    }

    #[test]
    fn pairwise_client_derives_sector_scoped_sub() {
        let c = client(&["https://app.example.com/cb"], &[("subject_type", "pairwise")]);
        let sub = effective_subject(&user("alice"), &c, &realm()).unwrap();
        assert_eq!(sub.0.as_str(), pairwise_sub("test-sector-key", "app.example.com", "user-1"));
        assert_ne!(sub.0.as_str(), "user-1");
    }

    #[test]
    fn same_sector_clients_share_sub() {
        let attrs = [("subject_type", "pairwise")];
        let c1 = client(&["https://app.example.com/cb1"], &attrs);
        let c2 = client(&["https://app.example.com/cb2"], &attrs);
        assert_eq!(
            effective_subject(&user("alice"), &c1, &realm()).unwrap(),
            effective_subject(&user("alice"), &c2, &realm()).unwrap()
        );
    }

    #[test]
    fn different_sector_clients_differ() {
        let attrs = [("subject_type", "pairwise")];
        let c1 = client(&["https://a.example.com/cb"], &attrs);
        let c2 = client(&["https://b.example.com/cb"], &attrs);
        assert_ne!(
            effective_subject(&user("alice"), &c1, &realm()).unwrap(),
            effective_subject(&user("alice"), &c2, &realm()).unwrap()
        );
    }

    #[test]
    fn service_account_subject_is_exempt() {
        let mut c = client(&[], &[("subject_type", "pairwise")]);
        c.service_accounts_enabled = true;
        let sa = user(&c.service_account_username());
        assert_eq!(effective_subject(&sa, &c, &realm()).unwrap(), UserId::new("user-1").unwrap());
    }

    #[test]
    fn synthetic_client_credentials_subject_is_exempt() {
        let c = client(&[], &[("subject_type", "pairwise")]);
        let mut synthetic = user("my-app");
        synthetic.id = UserId::new("my-app").unwrap();
        assert_eq!(
            effective_subject(&synthetic, &c, &realm()).unwrap(),
            UserId::new("my-app").unwrap()
        );
    }

    #[test]
    fn missing_sector_is_an_error() {
        let c = client(&[], &[("subject_type", "pairwise")]);
        assert!(effective_subject(&user("alice"), &c, &realm()).is_err());
    }

    #[test]
    fn missing_sector_key_is_an_error() {
        let c = client(&["https://app.example.com/cb"], &[("subject_type", "pairwise")]);
        let realm = Realm::default();
        assert!(effective_subject(&user("alice"), &c, &realm).is_err());
    }
}
