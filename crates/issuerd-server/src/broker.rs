// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Identity brokering: production BrokerClient and code-to-identity orchestration.

//! Identity brokering: the production [`BrokerClient`] and the
//! orchestration that turns an external authorization code into a verified
//! [`BrokeredIdentity`].
//!
//! The HTTP surface is deliberately tiny — four JSON calls behind
//! [`ReqwestBrokerClient`]. Endpoint discovery and the IdP's JWKS are cached
//! in the distributed cache per (realm, alias) so a brokered login costs at
//! most one server-to-server call (the code exchange) in the steady state.
//! The fourth call, [`BrokerClient::get_json_ssrf_guarded`], fetches
//! attacker-influenced URLs (pairwise `sector_identifier_uri`, client
//! `jwks.url`) behind an SSRF guard: https-only, public-IP-only against an
//! explicit non-public CIDR blocklist, no redirects, capped body, and a
//! single generic error for every failure mode.

use issuerd_core::{
    BrokerClient, BrokerDiscoveryDocument, BrokerIdpSettings, BrokerTokenResponse,
    BrokeredIdentity, IdentityProviderConfig, IssuerdError, RealmId,
};
use tracing::{debug, warn};

use crate::state::ServerState;

/// How long resolved IdP metadata (discovery doc) stays cached.
const DISCOVERY_CACHE_TTL_SECS: u64 = 3600;
/// How long the IdP JWKS stays cached before a refetch.
const JWKS_CACHE_TTL_SECS: u64 = 3600;
/// Clock skew leeway for external ID token validation.
const EXTERNAL_TOKEN_LEEWAY_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// ReqwestBrokerClient
// ---------------------------------------------------------------------------

/// Production [`BrokerClient`] over `reqwest` (rustls). Timeouts are short:
/// a hung IdP must not stall login requests.
pub struct ReqwestBrokerClient {
    client: reqwest::Client,
    /// Separate client for attacker-influenced URLs (`get_json_ssrf_guarded`):
    /// redirect following is disabled so a public URL cannot bounce the
    /// fetch into the internal network (SSRF hardening).
    untrusted_client: reqwest::Client,
}

/// Body-size cap for documents fetched from untrusted URLs (64 KiB) — both
/// current consumers are small JSON documents (a `sector_identifier_uri`
/// array of redirect URIs, a client JWKS).
const MAX_UNTRUSTED_BODY_BYTES: usize = 64 * 1024;

impl ReqwestBrokerClient {
    pub fn new() -> Result<Self, IssuerdError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| IssuerdError::ServerError(format!("broker HTTP client init: {e}")))?;
        let untrusted_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| IssuerdError::ServerError(format!("broker HTTP client init: {e}")))?;
        Ok(Self {
            client,
            untrusted_client,
        })
    }
}

/// Non-public IPv4 ranges the SSRF-guarded fetch refuses to dial: "this
/// network" (0.0.0.0/8), RFC 1918 private (10/8, 172.16/12, 192.168/16),
/// CGNAT shared address space (100.64.0.0/10, RFC 6598 — carrier metadata
/// endpoints live here), loopback (127/8), link-local (169.254/16 — cloud
/// metadata), IETF protocol assignments (192.0.0.0/24), documentation
/// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), benchmarking
/// (198.18.0.0/15, RFC 2544), multicast (224/4), and the reserved 240/4
/// block (includes the 255.255.255.255 broadcast).
fn blocked_v4_ranges() -> &'static [ipnet::Ipv4Net] {
    static RANGES: std::sync::OnceLock<Vec<ipnet::Ipv4Net>> = std::sync::OnceLock::new();
    RANGES.get_or_init(|| {
        [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ]
        .iter()
        .map(|cidr| cidr.parse().expect("static CIDR literal must parse"))
        .collect()
    })
}

/// Non-public IPv6 ranges (see [`blocked_v4_ranges`]): unspecified (::/128)
/// and loopback (::1/128), NAT64 (64:ff9b::/96, RFC 6052 — translator
/// prefix, the embedded v4 address is not validated), Teredo (2001::/32,
/// RFC 4380), documentation (2001:db8::/32, RFC 3849), 6to4 (2002::/16,
/// RFC 3056), unique-local (fc00::/7), link-local (fe80::/10), and multicast
/// (ff00::/8). v4-mapped addresses (::ffff:0:0/96) are deliberately NOT
/// listed here: [`is_publicly_routable`] recurses into the v4 rules for
/// them, so a mapped public address stays fetchable.
fn blocked_v6_ranges() -> &'static [ipnet::Ipv6Net] {
    static RANGES: std::sync::OnceLock<Vec<ipnet::Ipv6Net>> = std::sync::OnceLock::new();
    RANGES.get_or_init(|| {
        [
            "::/128",
            "::1/128",
            "64:ff9b::/96",
            "2001::/32",
            "2001:db8::/32",
            "2002::/16",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ]
        .iter()
        .map(|cidr| cidr.parse().expect("static CIDR literal must parse"))
        .collect()
    })
}

/// Whether `ip` is publicly routable — i.e. outside every explicitly listed
/// non-public range above. An explicit CIDR blocklist, not the `std`
/// `is_private`/`is_documentation`/... convenience methods, so coverage does
/// not shift with std implementation details (and ranges std does not model
/// at all — CGNAT, benchmarking, reserved 240/4, NAT64/Teredo/6to4 — are
/// covered). v4-mapped IPv6 addresses inherit the v4 rules. Pure function so
/// the SSRF guard is unit-testable without network access.
fn is_publicly_routable(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => !blocked_v4_ranges().iter().any(|net| net.contains(v4)),
        std::net::IpAddr::V6(v6) => {
            // v4-mapped addresses (::ffff:a.b.c.d) inherit the v4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_publicly_routable(&std::net::IpAddr::V4(mapped));
            }
            !blocked_v6_ranges().iter().any(|net| net.contains(v6))
        }
    }
}

fn transport_err(context: &str, e: reqwest::Error) -> IssuerdError {
    warn!(error = %e, context, "identity provider call failed");
    IssuerdError::ServerError(format!("identity provider unreachable: {context}"))
}

#[async_trait::async_trait]
impl BrokerClient for ReqwestBrokerClient {
    async fn get_json(&self, url: &str) -> Result<serde_json::Value, IssuerdError> {
        let resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| transport_err(url, e))?;
        if !resp.status().is_success() {
            warn!(status = %resp.status(), url, "IdP GET returned non-success");
            return Err(IssuerdError::ServerError(
                "identity provider returned an error".to_string(),
            ));
        }
        resp.json::<serde_json::Value>().await.map_err(|e| transport_err(url, e))
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        basic_auth: Option<(String, String)>,
    ) -> Result<serde_json::Value, IssuerdError> {
        let mut req = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form);
        if let Some((id, secret)) = basic_auth {
            req = req.basic_auth(id, Some(secret));
        }
        let resp = req.send().await.map_err(|e| transport_err(url, e))?;
        let status = resp.status();
        let body = resp.json::<serde_json::Value>().await.map_err(|e| transport_err(url, e))?;
        if !status.is_success() {
            // OAuth2 error body -> invalid_grant (bad/expired code); anything
            // without an `error` field is an upstream failure.
            if body.get("error").and_then(|e| e.as_str()).is_some() {
                debug!(url, "IdP token endpoint rejected the grant");
                return Err(IssuerdError::InvalidGrant);
            }
            warn!(status = %status, url, "IdP token endpoint returned non-success");
            return Err(IssuerdError::ServerError(
                "identity provider token endpoint failed".to_string(),
            ));
        }
        Ok(body)
    }

    async fn get_json_bearer(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<serde_json::Value, IssuerdError> {
        let resp = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| transport_err(url, e))?;
        if !resp.status().is_success() {
            warn!(status = %resp.status(), url, "IdP userinfo returned non-success");
            return Err(IssuerdError::ServerError("identity provider userinfo failed".to_string()));
        }
        resp.json::<serde_json::Value>().await.map_err(|e| transport_err(url, e))
    }

    /// Hardened fetch for attacker-influenced URLs (the pairwise
    /// `sector_identifier_uri` from open dynamic client registration, a
    /// client's configured `jwks.url` presented to unauthenticated client
    /// assertions / JAR request objects).
    ///
    /// Every failure mode — scheme, DNS, non-public address, connect,
    /// redirect, non-success status, oversize body, JSON parse — collapses
    /// into the SAME generic [`IssuerdError::InvalidRequest`]; the real cause is
    /// logged only, so this endpoint cannot serve as a blind host/port
    /// oracle into the internal network.
    ///
    /// Residual risk: DNS-rebinding TOCTOU — the answer checked here can
    /// differ from the one the connector re-resolves when dialing. The full
    /// mitigation would be a pinning connector that dials the validated IP
    /// directly.
    async fn get_json_ssrf_guarded(&self, url: &str) -> Result<serde_json::Value, IssuerdError> {
        // One generic, leak-free error for every failure mode.
        let fail = |why: &str| {
            warn!(url, why, "SSRF-guarded fetch rejected/failed");
            IssuerdError::InvalidRequest("untrusted URL could not be fetched".to_string())
        };

        // Never fetch untrusted URLs over plain http. (For
        // `sector_identifier_uri` the pairwise validator enforces https too,
        // OIDC Core §8.1 — this gate protects every caller.)
        let parsed = url::Url::parse(url).map_err(|e| fail(&format!("url parse: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(fail("non-https scheme"));
        }
        let host = parsed.host_str().ok_or_else(|| fail("no host component"))?;
        let port = parsed.port_or_known_default().ok_or_else(|| fail("no port"))?;

        // Resolve the host and refuse the request if ANY resolved address is
        // not publicly routable.
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| fail(&format!("dns: {e}")))?;
        let mut resolved_any = false;
        for addr in addrs {
            resolved_any = true;
            if !is_publicly_routable(&addr.ip()) {
                return Err(fail(&format!("non-public address {}", addr.ip())));
            }
        }
        if !resolved_any {
            return Err(fail("dns: no addresses"));
        }

        // Redirects are disabled on this client, so a 3xx surfaces as the
        // response status and is treated as a fetch failure.
        let resp = self
            .untrusted_client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| fail(&format!("connect: {e}")))?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(fail(&format!("redirect: {status}")));
        }
        if !status.is_success() {
            return Err(fail(&format!("status: {status}")));
        }

        // Cap the body at 64 KiB: refuse early via Content-Length when the
        // server advertises one, then enforce while streaming the body.
        if resp.content_length().is_some_and(|n| n > MAX_UNTRUSTED_BODY_BYTES as u64) {
            return Err(fail("content-length exceeds cap"));
        }
        let mut body = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await.map_err(|e| fail(&format!("body: {e}")))? {
            if body.len() + chunk.len() > MAX_UNTRUSTED_BODY_BYTES {
                return Err(fail("body exceeds cap"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| fail(&format!("json parse: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Endpoint resolution (discovery + explicit config), cached
// ---------------------------------------------------------------------------

/// The endpoints a brokered login needs, resolved from discovery or explicit
/// config keys (explicit keys win over discovered values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedIdpEndpoints {
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub jwks_url: Option<String>,
    /// Expected `iss` for ID token validation.
    pub issuer: Option<String>,
}

fn discovery_cache_key(realm_id: &RealmId, alias: &str) -> String {
    format!("broker_meta:{}:{}", realm_id.0, alias)
}

fn jwks_cache_key(realm_id: &RealmId, alias: &str) -> String {
    format!("broker_jwks:{}:{}", realm_id.0, alias)
}

/// Resolve the IdP's endpoints, fetching + caching the discovery document
/// when the config uses discovery.
pub(crate) async fn resolve_idp_endpoints(
    state: &ServerState,
    realm_id: &RealmId,
    idp: &IdentityProviderConfig,
) -> Result<ResolvedIdpEndpoints, IssuerdError> {
    let settings = BrokerIdpSettings::new(idp);
    let discovered: Option<BrokerDiscoveryDocument> = if settings.use_discovery() {
        let issuer = settings
            .issuer()
            .ok_or_else(|| IssuerdError::InvalidRequest("IdP config missing issuer".to_string()))?;
        let cache_key = discovery_cache_key(realm_id, idp.alias.as_ref());
        let cached = state
            .cache
            .get(&cache_key)
            .await
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|json| BrokerDiscoveryDocument::parse(&json).ok());
        match cached {
            Some(doc) => Some(doc),
            None => {
                let url =
                    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
                let json = state.broker_client.get_json(&url).await?;
                let doc = BrokerDiscoveryDocument::parse(&json)?;
                if let Ok(bytes) = serde_json::to_vec(&json) {
                    let _ = state
                        .cache
                        .set(
                            &cache_key,
                            bytes,
                            Some(std::time::Duration::from_secs(DISCOVERY_CACHE_TTL_SECS)),
                        )
                        .await;
                }
                Some(doc)
            }
        }
    } else {
        None
    };

    let pick = |explicit: Option<&str>, discovered: Option<&String>, name: &str| {
        explicit.map(str::to_string).or_else(|| discovered.cloned()).ok_or_else(|| {
            IssuerdError::InvalidRequest(format!(
                "IdP config missing {name} (not discovered either)"
            ))
        })
    };
    let doc = discovered.as_ref();
    Ok(ResolvedIdpEndpoints {
        authorization_url: pick(
            settings.authorization_url(),
            doc.map(|d| &d.authorization_endpoint),
            "authorizationUrl",
        )?,
        token_url: pick(settings.token_url(), doc.map(|d| &d.token_endpoint), "tokenUrl")?,
        userinfo_url: settings
            .userinfo_url()
            .map(str::to_string)
            .or_else(|| doc.and_then(|d| d.userinfo_endpoint.clone())),
        jwks_url: settings
            .jwks_url()
            .map(str::to_string)
            .or_else(|| doc.and_then(|d| d.jwks_uri.clone())),
        issuer: settings
            .issuer()
            .map(str::to_string)
            .or_else(|| doc.and_then(|d| d.issuer.clone())),
    })
}

/// Fetch the IdP JWKS through the per-(realm, alias) cache. `force_refresh`
/// bypasses the cached copy (used for a one-shot retry when the token's `kid`
/// is unknown — the IdP may have rotated keys).
async fn fetch_jwks(
    state: &ServerState,
    realm_id: &RealmId,
    alias: &str,
    jwks_url: &str,
    force_refresh: bool,
) -> Result<serde_json::Value, IssuerdError> {
    let cache_key = jwks_cache_key(realm_id, alias);
    if !force_refresh {
        if let Ok(Some(bytes)) = state.cache.get(&cache_key).await {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                return Ok(json);
            }
        }
    }
    let json = state.broker_client.get_json(jwks_url).await?;
    if let Ok(bytes) = serde_json::to_vec(&json) {
        let _ = state
            .cache
            .set(&cache_key, bytes, Some(std::time::Duration::from_secs(JWKS_CACHE_TTL_SECS)))
            .await;
    }
    Ok(json)
}

// ---------------------------------------------------------------------------
// Code exchange -> verified identity
// ---------------------------------------------------------------------------

/// Exchange an authorization code at the external IdP and turn the result
/// into a verified [`BrokeredIdentity`]:
///
/// 1. POST the code to the token endpoint (client auth per config, PKCE
///    verifier when the login held one).
/// 2. If an `id_token` came back, validate it against the IdP's JWKS
///    (signature, issuer, audience = our client id, nonce, expiry). An
///    unknown-`kid` failure triggers one JWKS refetch retry.
/// 3. Otherwise, fall back to the userinfo endpoint with the access token
///    (GitHub-style IdPs without OIDC ID tokens).
///
/// Returns the identity plus the external refresh token (only meaningful when
/// the IdP config has `storeTokens` enabled — the caller decides to persist).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_code_for_identity(
    state: &ServerState,
    realm_id: &RealmId,
    idp: &IdentityProviderConfig,
    endpoints: &ResolvedIdpEndpoints,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: Option<&str>,
    expected_nonce: Option<&str>,
) -> Result<(BrokeredIdentity, Option<String>), IssuerdError> {
    let settings = BrokerIdpSettings::new(idp);
    let client_id = settings
        .client_id()
        .ok_or_else(|| IssuerdError::InvalidRequest("IdP config missing clientId".to_string()))?;
    let client_secret = settings.client_secret().ok_or_else(|| {
        IssuerdError::InvalidRequest("IdP config missing clientSecret".to_string())
    })?;

    let mut form: Vec<(String, String)> = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("redirect_uri".to_string(), redirect_uri.to_string()),
    ];
    let basic_auth = match settings.client_auth_method() {
        issuerd_core::BrokerClientAuthMethod::ClientSecretBasic => {
            Some((client_id.to_string(), client_secret.to_string()))
        }
        issuerd_core::BrokerClientAuthMethod::ClientSecretPost => {
            form.push(("client_id".to_string(), client_id.to_string()));
            form.push(("client_secret".to_string(), client_secret.to_string()));
            None
        }
    };
    if let Some(verifier) = pkce_verifier {
        form.push(("code_verifier".to_string(), verifier.to_string()));
    }

    let token_json = state.broker_client.post_form(&endpoints.token_url, &form, basic_auth).await?;
    let tokens = BrokerTokenResponse::parse(&token_json)?;

    if let Some(ref id_token) = tokens.id_token {
        let jwks_url = endpoints.jwks_url.as_deref().ok_or_else(|| {
            IssuerdError::InvalidRequest(
                "IdP issued an id_token but no JWKS URL is configured/discovered".to_string(),
            )
        })?;
        let requirements = issuerd_token::ExternalIdTokenRequirements {
            expected_issuer: endpoints.issuer.as_deref(),
            expected_audience: client_id,
            expected_nonce,
            leeway_secs: EXTERNAL_TOKEN_LEEWAY_SECS,
        };
        // One retry with a refetched JWKS: the IdP may have rotated keys and
        // our cached set may be stale.
        let jwks = fetch_jwks(state, realm_id, idp.alias.as_ref(), jwks_url, false).await?;
        let claims = match issuerd_token::validate_external_id_token(&jwks, id_token, &requirements)
        {
            Ok(claims) => claims,
            Err(first_err) => {
                debug!(error = %first_err, "external ID token validation failed; refetching JWKS");
                let fresh = fetch_jwks(state, realm_id, idp.alias.as_ref(), jwks_url, true).await?;
                issuerd_token::validate_external_id_token(&fresh, id_token, &requirements)?
            }
        };
        // OIDC Core 1.0 §5.4: when an access token is issued alongside the
        // id_token, profile/email claims may live ONLY in the userinfo response
        // (our own loopback IdP does exactly this), so a code-flow id_token can
        // legitimately carry nothing but the subject. Fetch userinfo and merge
        // it (id_token wins conflicts; sub mismatch rejects) before mapping.
        let claims = match (&endpoints.userinfo_url, &tokens.access_token) {
            (Some(userinfo_url), Some(access_token))
                if issuerd_core::claims_need_userinfo(&claims) =>
            {
                let fetched = state.broker_client.get_json_bearer(userinfo_url, access_token).await;
                match fetched {
                    Ok(userinfo) => issuerd_core::merge_userinfo_claims(claims, userinfo)?,
                    Err(e) => {
                        debug!(error = %e, "userinfo fetch failed; using id_token claims only");
                        claims
                    }
                }
            }
            _ => claims,
        };
        let identity = BrokeredIdentity::from_claims(claims)?;
        return Ok((identity, tokens.refresh_token));
    }

    // No ID token: userinfo fallback (requires an access token + endpoint).
    let access_token = tokens.access_token.as_deref().ok_or_else(|| {
        IssuerdError::InvalidRequest(
            "IdP token response has no id_token and no access_token".to_string(),
        )
    })?;
    let userinfo_url = endpoints.userinfo_url.as_deref().ok_or_else(|| {
        IssuerdError::InvalidRequest(
            "IdP has no userinfo endpoint and issued no id_token".to_string(),
        )
    })?;
    let userinfo = state.broker_client.get_json_bearer(userinfo_url, access_token).await?;
    let identity = BrokeredIdentity::from_claims(userinfo)?;
    Ok((identity, tokens.refresh_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn reqwest_client_builds() {
        assert!(ReqwestBrokerClient::new().is_ok());
    }

    #[tokio::test]
    async fn guarded_fetch_rejects_non_https_before_any_network_io() {
        let client = ReqwestBrokerClient::new().unwrap();
        let err = client.get_json_ssrf_guarded("http://app.example.com/jwks").await.unwrap_err();
        assert!(
            matches!(err, IssuerdError::InvalidRequest(_)),
            "plain http must be refused up front: {err}"
        );
    }

    /// Every blocklisted range: at least one address inside (both range
    /// edges where meaningful) must be blocked.
    #[test]
    fn ssrf_blocklist_blocks_every_listed_range() {
        let blocked: &[(&str, &[&str])] = &[
            ("0.0.0.0/8", &["0.0.0.0", "0.1.2.3", "0.255.255.255"]),
            ("10.0.0.0/8", &["10.0.0.0", "10.0.0.1", "10.255.255.255"]),
            ("100.64.0.0/10", &["100.64.0.0", "100.100.100.200", "100.127.255.255"]),
            ("127.0.0.0/8", &["127.0.0.0", "127.0.0.1", "127.255.255.255"]),
            ("169.254.0.0/16", &["169.254.0.0", "169.254.1.1", "169.254.255.255"]),
            ("172.16.0.0/12", &["172.16.0.0", "172.16.0.1", "172.31.255.255"]),
            ("192.0.0.0/24", &["192.0.0.0", "192.0.0.1", "192.0.0.255"]),
            ("192.0.2.0/24", &["192.0.2.0", "192.0.2.1", "192.0.2.255"]),
            ("192.168.0.0/16", &["192.168.0.0", "192.168.1.1", "192.168.255.255"]),
            ("198.18.0.0/15", &["198.18.0.0", "198.18.0.1", "198.19.255.255"]),
            ("198.51.100.0/24", &["198.51.100.0", "198.51.100.1", "198.51.100.255"]),
            ("203.0.113.0/24", &["203.0.113.0", "203.0.113.7", "203.0.113.255"]),
            ("224.0.0.0/4", &["224.0.0.0", "224.0.0.1", "239.255.255.255"]),
            ("240.0.0.0/4", &["240.0.0.0", "240.0.0.1", "255.255.255.255"]),
            ("::/128", &["::"]),
            ("::1/128", &["::1"]),
            ("64:ff9b::/96", &["64:ff9b::", "64:ff9b::808:808", "64:ff9b::ffff:ffff"]),
            ("2001::/32", &["2001::", "2001::1", "2001:0:ffff:ffff:ffff:ffff:ffff:ffff"]),
            ("2001:db8::/32", &["2001:db8::", "2001:db8::1"]),
            ("2002::/16", &["2002::", "2002::1", "2002:ffff::1"]),
            (
                "fc00::/7",
                &[
                    "fc00::",
                    "fc00::1",
                    "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
            ),
            (
                "fe80::/10",
                &[
                    "fe80::",
                    "fe80::1",
                    "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
            ),
            (
                "ff00::/8",
                &[
                    "ff00::",
                    "ff02::1",
                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
            ),
            // v4-mapped IPv6 recurses into the v4 rules: a mapped address is
            // blocked exactly when its embedded v4 address is.
            (
                "::ffff:0:0/96 (recursed)",
                &[
                    "::ffff:0.0.0.0",
                    "::ffff:10.0.0.1",
                    "::ffff:100.64.0.1",
                    "::ffff:127.0.0.1",
                    "::ffff:169.254.1.1",
                    "::ffff:172.16.0.1",
                    "::ffff:192.0.0.1",
                    "::ffff:192.0.2.1",
                    "::ffff:192.168.1.1",
                    "::ffff:198.18.0.1",
                    "::ffff:198.51.100.1",
                    "::ffff:203.0.113.7",
                    "::ffff:224.0.0.1",
                    "::ffff:240.0.0.1",
                ],
            ),
        ];
        for (range, addrs) in blocked {
            for addr in *addrs {
                let ip = IpAddr::from_str(addr).unwrap();
                assert!(!is_publicly_routable(&ip), "{addr} ({range}) must be blocked");
            }
        }
    }

    /// Every blocklisted range: at least one address just outside it must
    /// pass (plus generally-known public addresses).
    #[test]
    fn ssrf_blocklist_passes_public_neighbors_of_every_range() {
        let passing: &[(&str, &[&str])] = &[
            ("0.0.0.0/8", &["1.0.0.1"]),
            ("10.0.0.0/8", &["9.255.255.255", "11.0.0.0"]),
            ("100.64.0.0/10", &["100.63.255.255", "100.128.0.0"]),
            ("127.0.0.0/8", &["126.255.255.255", "128.0.0.1"]),
            ("169.254.0.0/16", &["169.253.255.255", "169.255.0.1"]),
            ("172.16.0.0/12", &["172.15.255.255", "172.32.0.0"]),
            ("192.0.0.0/24", &["191.255.255.255", "192.0.1.1"]),
            ("192.0.2.0/24", &["192.0.1.255", "192.0.3.1"]),
            ("192.168.0.0/16", &["192.167.255.255", "192.169.0.1"]),
            ("198.18.0.0/15", &["198.17.255.255", "198.20.0.1"]),
            ("198.51.100.0/24", &["198.51.99.255", "198.51.101.1"]),
            ("203.0.113.0/24", &["203.0.112.255", "203.0.114.1"]),
            ("224.0.0.0/4", &["223.255.255.255"]),
            // 240/4 tops the address space and its lower neighbor 224/4 is
            // also blocked, so its nearest passing address is below 224/4.
            ("240.0.0.0/4", &["223.255.255.255"]),
            ("::/128", &["::2"]),
            ("::1/128", &["::2"]),
            ("64:ff9b::/96", &["64:ff9b:0:0:0:1::", "64:ff9c::1"]),
            ("2001::/32", &["2001:1::1"]),
            ("2001:db8::/32", &["2001:db9::1"]),
            ("2002::/16", &["2003::1"]),
            ("fc00::/7", &["fe00::1"]),
            ("fe80::/10", &["fec0::1"]),
            ("ff00::/8", &["feff::1"]),
            // v4-mapped recursion: a mapped PUBLIC v4 address stays fetchable.
            ("::ffff:0:0/96 (recursed)", &["::ffff:8.8.8.8", "::ffff:1.0.0.1"]),
        ];
        for (range, addrs) in passing {
            for addr in *addrs {
                let ip = IpAddr::from_str(addr).unwrap();
                assert!(is_publicly_routable(&ip), "{addr} (outside {range}) must be accepted");
            }
        }

        for accepted in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            let ip = IpAddr::from_str(accepted).unwrap();
            assert!(is_publicly_routable(&ip), "{accepted} must be accepted");
        }
    }
}
