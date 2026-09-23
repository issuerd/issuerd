// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Pairwise subject identifiers (OIDC Core §8).
//!
//! A client opts in via the `subject_type` attribute (`"public"` default |
//! `"pairwise"`). For pairwise clients every user-facing `sub` (ID token,
//! access token, refresh token, logout token — and, derived from those,
//! userinfo and introspection output) is computed as
//! `base64url(HMAC-SHA256(sector_key, sector_identifier || user_id))` so the
//! same person presents unlinkable identifiers to clients in different
//! sectors while keeping a stable identifier within one sector.
//!
//! The sector key is a per-realm secret stored in the realm attributes
//! ([`Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE`]), generated at realm creation
//! (and backfilled for pre-existing realms) by `issuerd-storage`'s seeding, so it
//! is stable across restarts and shared by every cluster node. The sector
//! identifier is the host of the client's `sector_identifier_uri` attribute
//! when set (an https URL, validated at registration time against the JSON
//! document it serves, per §8.1), otherwise the common host of the client's registered
//! redirect URIs; multiple distinct redirect-URI hosts without a
//! `sector_identifier_uri` are ambiguous and rejected.

use std::collections::BTreeSet;

use crate::models::{Client, Realm};
use crate::{IssuerdError, RedirectUri};

impl Realm {
    /// Realm attribute holding the secret HMAC key feeding pairwise `sub`
    /// derivation. Generated once at realm creation by storage
    /// seeding; treat as sensitive — it is visible to realm admins through
    /// the attributes map, and rotating it changes every pairwise subject of
    /// the realm.
    pub const PAIRWISE_SECTOR_KEY_ATTRIBUTE: &'static str = "pairwise_sector_key";

    /// The realm's pairwise sector key, if set and non-empty.
    pub fn pairwise_sector_key(&self) -> Option<&str> {
        self.attributes
            .get(Self::PAIRWISE_SECTOR_KEY_ATTRIBUTE)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    }
}

impl Client {
    /// Client attribute selecting the subject identifier type (OIDC Core §8
    /// registration metadata spelling): `"public"` (default) or `"pairwise"`.
    pub const SUBJECT_TYPE_ATTRIBUTE: &'static str = "subject_type";

    /// Client attribute naming the sector identifier document URL (OIDC Core
    /// §8.1): a JSON array of redirect URIs sharing one sector. When set, its
    /// host component is the client's sector identifier.
    pub const SECTOR_IDENTIFIER_URI_ATTRIBUTE: &'static str = "sector_identifier_uri";

    /// Whether this client receives pairwise (sector-scoped) subject
    /// identifiers instead of the public user id.
    pub fn pairwise_subjects(&self) -> bool {
        self.attributes
            .get(Self::SUBJECT_TYPE_ATTRIBUTE)
            .is_some_and(|v| v == "pairwise")
    }

    /// The configured `sector_identifier_uri` attribute, if set and non-empty.
    pub fn sector_identifier_uri(&self) -> Option<&str> {
        self.attributes
            .get(Self::SECTOR_IDENTIFIER_URI_ATTRIBUTE)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    }

    /// Username of the dedicated service-account user backing this client's
    /// client-credentials grant (`service-account-{client_id}`).
    /// Centralized here so token issuance (issuerd-token) can recognize subjects
    /// that are already client-scoped and exempt them from pairwise
    /// derivation.
    pub fn service_account_username(&self) -> String {
        format!("service-account-{}", self.client_id)
    }

    /// Resolve this client's sector identifier (OIDC Core §8.1): the host of
    /// the configured `sector_identifier_uri`, or — when unset — the single
    /// host shared by every registered redirect URI.
    ///
    /// Returns `Ok(None)` when the client has no redirect URIs and no sector
    /// URI (no browser surface; pairwise derivation cannot apply). Returns
    /// `Err` when the sector URI is malformed or the redirect URIs span
    /// multiple hosts without a sector URI — registration-time validation
    /// (`validate_pairwise_subject_config`) rejects that configuration, so an
    /// error here means the client predates the validation or bypassed it.
    pub fn resolve_sector_identifier(&self) -> Result<Option<String>, IssuerdError> {
        if let Some(uri) = self.sector_identifier_uri() {
            let parsed = url::Url::parse(uri).map_err(|e| {
                IssuerdError::InvalidRequest(format!("invalid sector_identifier_uri: {e}"))
            })?;
            return parsed.host_str().map(|h| Some(h.to_string())).ok_or_else(|| {
                IssuerdError::InvalidRequest("sector_identifier_uri has no host component".into())
            });
        }

        let mut hosts = BTreeSet::new();
        for uri in &self.redirect_uris {
            // `RedirectUri` values are validated absolute URLs at
            // construction, so parsing cannot fail; a host-less scheme
            // (e.g. `urn:`) is skipped rather than treated as a distinct
            // sector.
            if let Ok(parsed) = url::Url::parse(uri.as_str()) {
                if let Some(host) = parsed.host_str() {
                    hosts.insert(host.to_string());
                }
            }
        }
        match hosts.len() {
            0 => Ok(None),
            1 => Ok(hosts.into_iter().next()),
            _ => Err(IssuerdError::InvalidRequest(
                "pairwise subject type requires a sector_identifier_uri when redirect URIs span multiple hosts"
                    .into(),
            )),
        }
    }
}

/// Validate a fetched `sector_identifier_uri` document against the client's
/// registered redirect URIs (OIDC Core §8.1): the document must be a JSON
/// array of URI strings and must list every registered redirect URI.
pub fn validate_sector_document(
    document: &serde_json::Value,
    redirect_uris: &[RedirectUri],
) -> Result<(), IssuerdError> {
    let entries = document.as_array().ok_or_else(|| {
        IssuerdError::InvalidRequest(
            "sector_identifier_uri document must be a JSON array of redirect URIs".into(),
        )
    })?;
    let mut listed = BTreeSet::new();
    for entry in entries {
        let Some(uri) = entry.as_str() else {
            return Err(IssuerdError::InvalidRequest(
                "sector_identifier_uri document entries must be URI strings".into(),
            ));
        };
        listed.insert(uri.to_string());
    }
    for uri in redirect_uris {
        if !listed.contains(uri.as_str()) {
            return Err(IssuerdError::InvalidRequest(format!(
                "sector_identifier_uri document does not list the client's redirect URI {}",
                uri.as_str()
            )));
        }
    }
    Ok(())
}

/// Registration-time validation of a client's pairwise configuration
/// (OIDC Core §8.1): no-op for public clients. For pairwise clients, the
/// `sector_identifier_uri` document is fetched and checked against the
/// registered redirect URIs; without one, the redirect URIs must resolve to
/// an unambiguous sector.
///
/// `http` is the server's generic JSON fetcher (the broker client), keeping
/// this crate free of a concrete HTTP dependency. The fetch goes through
/// [`crate::BrokerClient::get_json_untrusted`]: the URI can be supplied by
/// an unauthenticated registrant when dynamic client registration is open,
/// so it must be treated as hostile (SSRF hardening).
pub async fn validate_pairwise_subject_config(
    client: &Client,
    http: &dyn crate::BrokerClient,
) -> Result<(), IssuerdError> {
    if !client.pairwise_subjects() {
        return Ok(());
    }
    if let Some(uri) = client.sector_identifier_uri() {
        // Validates URI syntax + host presence before hitting the network.
        client.resolve_sector_identifier()?;
        // OIDC Core §8.1: the sector document MUST be served over https.
        // Enforced before any fetch — plain http would additionally widen
        // the SSRF surface of this attacker-influenced URL.
        let parsed = url::Url::parse(uri).map_err(|e| {
            IssuerdError::InvalidRequest(format!("invalid sector_identifier_uri: {e}"))
        })?;
        if parsed.scheme() != "https" {
            return Err(IssuerdError::InvalidRequest(
                "sector_identifier_uri must use https".into(),
            ));
        }
        // Uniform, leak-free failure message: the underlying cause (DNS vs
        // connect vs status vs body) is logged server-side by the fetcher,
        // never reflected to the registrant (blind-oracle hardening).
        let document = http.get_json_untrusted(uri).await.map_err(|_| {
            IssuerdError::InvalidRequest("sector_identifier_uri could not be fetched".into())
        })?;
        validate_sector_document(&document, &client.redirect_uris)?;
    } else {
        // Ambiguity check only (`Ok(None)` — no redirect URIs — is allowed:
        // such a client has no browser flow for pairwise to apply to).
        client.resolve_sector_identifier()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Client;
    use crate::{ClientId, ClientIdentifier, RealmId};
    use std::collections::HashMap;

    fn client(redirect_uris: &[&str], attributes: &[(&str, &str)]) -> Client {
        Client {
            id: ClientId::new("client-uuid").unwrap(),
            realm_id: RealmId::new("realm").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: crate::ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: crate::ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: redirect_uris.iter().map(|u| RedirectUri::new(*u).unwrap()).collect(),
            web_origins: vec![],
            default_scopes: crate::Scope::from(vec![]),
            optional_scopes: crate::Scope::from(vec![]),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: vec![],
            scope_mappings: crate::client_scope::ScopeMappings::default(),
            attributes: attributes
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn pairwise_opt_in_via_attribute() {
        assert!(!client(&[], &[]).pairwise_subjects());
        assert!(!client(&[], &[("subject_type", "public")]).pairwise_subjects());
        assert!(client(&[], &[("subject_type", "pairwise")]).pairwise_subjects());
    }

    #[test]
    fn sector_from_single_redirect_host() {
        let c = client(
            &[
                "https://app.example.com/cb",
                "https://app.example.com/silent",
            ],
            &[("subject_type", "pairwise")],
        );
        assert_eq!(c.resolve_sector_identifier().unwrap(), Some("app.example.com".to_string()));
    }

    #[test]
    fn sector_from_multiple_schemes_same_host() {
        let c = client(
            &[
                "https://app.example.com/cb",
                "http://app.example.com:8080/cb",
            ],
            &[("subject_type", "pairwise")],
        );
        assert_eq!(c.resolve_sector_identifier().unwrap(), Some("app.example.com".to_string()));
    }

    #[test]
    fn sector_ambiguity_rejected() {
        let c = client(
            &["https://a.example.com/cb", "https://b.example.com/cb"],
            &[("subject_type", "pairwise")],
        );
        assert!(c.resolve_sector_identifier().is_err());
    }

    #[test]
    fn sector_identifier_uri_wins_over_redirect_hosts() {
        let c = client(
            &["https://a.example.com/cb", "https://b.example.com/cb"],
            &[
                ("subject_type", "pairwise"),
                ("sector_identifier_uri", "https://sector.example.com/ofa.json"),
            ],
        );
        assert_eq!(c.resolve_sector_identifier().unwrap(), Some("sector.example.com".to_string()));
    }

    #[test]
    fn sector_identifier_uri_must_have_host() {
        let c = client(
            &[],
            &[
                ("subject_type", "pairwise"),
                ("sector_identifier_uri", "not a url"),
            ],
        );
        assert!(c.resolve_sector_identifier().is_err());
    }

    #[test]
    fn no_redirect_uris_yields_no_sector() {
        let c = client(&[], &[("subject_type", "pairwise")]);
        assert_eq!(c.resolve_sector_identifier().unwrap(), None);
    }

    #[test]
    fn sector_document_must_list_all_redirect_uris() {
        let doc = serde_json::json!(["https://app.example.com/cb"]);
        let c = client(
            &[
                "https://app.example.com/cb",
                "https://app.example.com/other",
            ],
            &[],
        );
        assert!(validate_sector_document(&doc, &c.redirect_uris).is_err());

        let full = serde_json::json!([
            "https://app.example.com/cb",
            "https://app.example.com/other",
            "https://app.example.com/extra"
        ]);
        assert!(validate_sector_document(&full, &c.redirect_uris).is_ok());
    }

    #[test]
    fn sector_document_shape_enforced() {
        let c = client(&["https://app.example.com/cb"], &[]);
        assert!(
            validate_sector_document(&serde_json::json!({"uris": []}), &c.redirect_uris).is_err()
        );
        assert!(validate_sector_document(&serde_json::json!([42]), &c.redirect_uris).is_err());
    }

    #[test]
    fn service_account_username_convention() {
        let c = client(&[], &[]);
        assert_eq!(c.service_account_username(), "service-account-my-app");
    }

    #[tokio::test]
    async fn http_sector_uri_rejected_before_any_fetch() {
        let c = client(
            &["https://app.example.com/cb"],
            &[
                ("subject_type", "pairwise"),
                ("sector_identifier_uri", "http://sector.example.com/ofa.json"),
            ],
        );
        // No expectations are set on the mock: any fetch attempt panics,
        // proving the https check runs before the network is touched.
        let http = crate::MockBrokerClient::new();
        let err = validate_pairwise_subject_config(&c, &http).await.unwrap_err();
        assert_eq!(
            err,
            IssuerdError::InvalidRequest("sector_identifier_uri must use https".to_string())
        );
    }

    #[tokio::test]
    async fn sector_fetch_failure_has_uniform_message() {
        let c = client(
            &["https://app.example.com/cb"],
            &[
                ("subject_type", "pairwise"),
                ("sector_identifier_uri", "https://sector.example.com/ofa.json"),
            ],
        );
        let mut http = crate::MockBrokerClient::new();
        // Whatever the underlying failure mode (here a DNS-flavoured one),
        // the registrant must see one generic message — no host/port oracle.
        http.expect_get_json_untrusted().returning(|_| {
            Err(IssuerdError::ServerError("dns lookup failed: NXDOMAIN".to_string()))
        });
        let err = validate_pairwise_subject_config(&c, &http).await.unwrap_err();
        assert_eq!(
            err,
            IssuerdError::InvalidRequest("sector_identifier_uri could not be fetched".to_string())
        );
    }

    #[tokio::test]
    async fn https_sector_uri_fetches_and_validates_document() {
        let c = client(
            &["https://app.example.com/cb"],
            &[
                ("subject_type", "pairwise"),
                ("sector_identifier_uri", "https://sector.example.com/ofa.json"),
            ],
        );
        let mut http = crate::MockBrokerClient::new();
        http.expect_get_json_untrusted()
            .returning(|_| Ok(serde_json::json!(["https://app.example.com/cb"])));
        assert!(validate_pairwise_subject_config(&c, &http).await.is_ok());
    }

    #[test]
    fn realm_sector_key_accessor() {
        let mut realm = Realm::default();
        assert_eq!(realm.pairwise_sector_key(), None);
        realm
            .attributes
            .insert(Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string(), "secret".to_string());
        assert_eq!(realm.pairwise_sector_key(), Some("secret"));
    }
}
