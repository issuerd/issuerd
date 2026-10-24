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
//! single generic error for every failure mode. The public-IP check lifts
//! only under `[outbound_http] allow_private_addresses` (test rigs only).
//!
//! The IdP-facing calls (discovery, JWKS, token, userinfo — URLs a realm
//! admin configures or the discovery document names) are SSRF-gated too:
//! HTTPS is required and every address they dial, on every redirect hop, must
//! be publicly routable, unless the operator sets `[outbound_http]
//! allow_private_identity_providers` for an internal development IdP. Redirects
//! never downgrade HTTPS to HTTP. Response bodies are capped in both modes.

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

/// HTTPS-only client for configured URLs that must not reach non-public
/// addresses. The resolver validates and supplies the exact addresses the
/// connector dials; redirects are disabled.
#[derive(Clone)]
pub(crate) struct SsrfGuardedClient {
    client: reqwest::Client,
    allow_private_addresses: bool,
}

/// Production [`BrokerClient`] over `reqwest` (rustls). Timeouts are short:
/// a hung IdP must not stall login requests.
pub struct ReqwestBrokerClient {
    /// IdP-facing client (discovery, JWKS, token, userinfo), built for
    /// `idp_egress`.
    client: reqwest::Client,
    /// Separate client for attacker-influenced URLs (`get_json_ssrf_guarded`).
    untrusted_client: SsrfGuardedClient,
    /// How the IdP-facing calls are SSRF-gated.
    idp_egress: IdpEgress,
}

/// How the IdP-facing calls are SSRF-gated, fixed when the client is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdpEgress {
    /// `[outbound_http] allow_private_identity_providers`: no gate (IdPs on
    /// the internal network, trusted by the operator).
    Unrestricted,
    /// Direct connections: [`PublicOnlyResolver`] checks every address the
    /// connector dials, on every hop.
    Direct,
    /// An outbound proxy is configured through the environment: the proxy,
    /// not this process, resolves the target, so the target host is resolved
    /// and checked up front and redirects stay on that host.
    Proxied,
}

/// The `*_PROXY` variables reqwest reads for its automatic outbound proxy.
const PROXY_ENV_VARS: [&str; 6] = [
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

fn env_proxy_configured() -> bool {
    PROXY_ENV_VARS
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|val| !val.is_empty()))
}

/// Timeout for the SSRF checks' own DNS lookups (the request timeout).
const DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// reqwest's default redirect hop limit, kept for the gated IdP client.
const MAX_IDP_REDIRECTS: usize = 10;

/// Body-size cap for documents fetched from untrusted URLs (64 KiB) — both
/// current consumers are small JSON documents (a `sector_identifier_uri`
/// array of redirect URIs, a client JWKS).
const MAX_UNTRUSTED_BODY_BYTES: usize = 64 * 1024;

/// Body-size cap for IdP responses (discovery, JWKS, token, userinfo) — far
/// above any real document, small enough that an IdP URL cannot stream the
/// server out of memory.
const MAX_IDP_BODY_BYTES: usize = 1024 * 1024;

impl ReqwestBrokerClient {
    /// Build the broker client. `extra_roots` are the additional root CAs from
    /// `[outbound_http] extra_ca_bundle` (empty = public webpki roots only).
    /// `allow_private_addresses` lifts the SSRF guard's public-IP check
    /// (test rigs only); `allow_private_identity_providers` lifts the
    /// public-address gate of the IdP-facing calls.
    pub fn new(
        extra_roots: &[reqwest::Certificate],
        allow_private_addresses: bool,
        allow_private_identity_providers: bool,
    ) -> Result<Self, IssuerdError> {
        let idp_egress = if allow_private_identity_providers {
            IdpEgress::Unrestricted
        } else if env_proxy_configured() {
            IdpEgress::Proxied
        } else {
            IdpEgress::Direct
        };
        let client = idp_client_builder(extra_roots, idp_egress)
            .build()
            .map_err(|e| IssuerdError::ServerError(format!("broker HTTP client init: {e}")))?;
        let untrusted_client = SsrfGuardedClient::new(
            extra_roots,
            allow_private_addresses,
            std::time::Duration::from_secs(10),
        )
        .map_err(|e| IssuerdError::ServerError(format!("broker HTTP client init: {e}")))?;
        Ok(Self {
            client,
            untrusted_client,
            idp_egress,
        })
    }
}

/// The IdP-facing client for `egress`. `Direct` drops reqwest's automatic
/// proxy (only non-environment, OS-configured proxies remain at that point)
/// so the connector always resolves the target through
/// [`PublicOnlyResolver`].
fn idp_client_builder(
    extra_roots: &[reqwest::Certificate],
    egress: IdpEgress,
) -> reqwest::ClientBuilder {
    let builder = crate::outbound_http::client_builder(extra_roots)
        .timeout(std::time::Duration::from_secs(10));
    match egress {
        IdpEgress::Unrestricted => builder,
        IdpEgress::Direct => builder
            .no_proxy()
            .dns_resolver(std::sync::Arc::new(PublicOnlyResolver))
            .redirect(idp_redirect_policy(false)),
        IdpEgress::Proxied => builder.redirect(idp_redirect_policy(true)),
    }
}

/// Redirect policy of the gated IdP client: reqwest's default hop limit plus
/// [`idp_redirect_verdict`].
fn idp_redirect_policy(same_host_only: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match idp_redirect_verdict(attempt.url(), attempt.previous(), same_host_only) {
            Ok(()) => attempt.follow(),
            Err(why) => attempt.error(why),
        }
    })
}

/// Whether the gated IdP client may follow a redirect to `next` (`previous`
/// holds the original URL and every earlier hop). A hop to a non-public IP
/// literal is refused here because the connector never asks the resolver
/// about literals. With `same_host_only` (behind a proxy, which resolves
/// hops itself) only hops back to the original, pre-checked host are
/// followed.
fn idp_redirect_verdict(
    next: &url::Url,
    previous: &[url::Url],
    same_host_only: bool,
) -> Result<(), &'static str> {
    if previous.len() >= MAX_IDP_REDIRECTS {
        return Err("too many redirects");
    }
    if previous.iter().any(|url| url.scheme() == "https") && next.scheme() != "https" {
        return Err("redirect to an insecure scheme");
    }
    if is_non_public_ip_literal(next) {
        return Err("redirect to a non-public address");
    }
    if same_host_only && previous.first().and_then(|u| u.host_str()) != next.host_str() {
        return Err("cross-host redirect behind a proxy");
    }
    Ok(())
}

/// Whether `url`'s host is an IP literal outside the public address space.
fn is_non_public_ip_literal(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(v4)) => !is_publicly_routable(&std::net::IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => !is_publicly_routable(&std::net::IpAddr::V6(v6)),
        _ => false,
    }
}

/// DNS resolver of the gated IdP client. It refuses a host unless every
/// address it resolves to is publicly routable, and hands the connector
/// exactly those checked addresses — so the check and the connection use
/// the same answer on every request.
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: the connector substitutes the URL's port.
            let addrs = resolve_public(&host, 0).await.map_err(|why| {
                warn!(why, host, "outbound host refused by the SSRF resolver");
                why
            })?;
            let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
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

/// The error for an IdP call the SSRF gate refused or whose body broke the
/// cap/parse — the same text as [`transport_err`], so the admin
/// test-connection endpoint cannot tell a refused internal target from a
/// dead host. The real cause is logged only.
fn idp_unreachable(url: &str, why: &str) -> IssuerdError {
    warn!(why, url, "identity provider call refused or failed");
    IssuerdError::ServerError(format!("identity provider unreachable: {url}"))
}

/// Resolve `host` (within [`DNS_TIMEOUT`]) and return its addresses only if
/// EVERY one is publicly routable; otherwise the reason, for the log.
async fn resolve_public(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    let addrs: Vec<_> = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "dns: timed out".to_string())?
        .map_err(|e| format!("dns: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("dns: no addresses".to_string());
    }
    if let Some(bad) = addrs.iter().find(|a| !is_publicly_routable(&a.ip())) {
        return Err(format!("non-public address {}", bad.ip()));
    }
    Ok(addrs)
}

/// Read an IdP response body, capped at [`MAX_IDP_BODY_BYTES`], as JSON.
async fn read_idp_json(
    mut resp: reqwest::Response,
    url: &str,
) -> Result<serde_json::Value, IssuerdError> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| transport_err(url, e))? {
        if body.len() + chunk.len() > MAX_IDP_BODY_BYTES {
            return Err(idp_unreachable(url, "response body exceeds cap"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| idp_unreachable(url, &format!("json parse: {e}")))
}

impl ReqwestBrokerClient {
    /// Up-front part of the IdP SSRF gate (their URLs come from realm-admin
    /// IdP config or from the IdP's discovery document). The connector never
    /// asks the resolver about IP literals, so a non-public literal is
    /// refused here. Behind a proxy the proxy resolves the target, so the
    /// host is resolved and checked here instead; the proxy's own lookup can
    /// still differ (DNS-rebinding window, proxied mode only). In direct
    /// mode the hostname check happens in [`PublicOnlyResolver`], on the
    /// addresses actually dialed.
    async fn check_idp_url(&self, url: &str) -> Result<(), IssuerdError> {
        if self.idp_egress == IdpEgress::Unrestricted {
            return Ok(());
        }
        let refuse = |why: &str| idp_unreachable(url, why);
        let parsed = url::Url::parse(url).map_err(|e| refuse(&format!("url parse: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(refuse("non-https scheme"));
        }
        if is_non_public_ip_literal(&parsed) {
            return Err(refuse("non-public address literal"));
        }
        if self.idp_egress == IdpEgress::Proxied {
            if let Some(url::Host::Domain(host)) = parsed.host() {
                resolve_public(host, 0).await.map_err(|why| refuse(&why))?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl BrokerClient for ReqwestBrokerClient {
    async fn get_json(&self, url: &str) -> Result<serde_json::Value, IssuerdError> {
        self.check_idp_url(url).await?;
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
        read_idp_json(resp, url).await
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        basic_auth: Option<(String, String)>,
    ) -> Result<serde_json::Value, IssuerdError> {
        self.check_idp_url(url).await?;
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
        let body = read_idp_json(resp, url).await?;
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
        self.check_idp_url(url).await?;
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
        read_idp_json(resp, url).await
    }

    /// Hardened fetch for attacker-influenced URLs (the pairwise
    /// `sector_identifier_uri` from open dynamic client registration, a
    /// client's configured `jwks.url` presented to unauthenticated client
    /// assertions / JAR request objects, a pre-registered `request_uri`).
    ///
    /// Every failure mode — scheme, DNS, non-public address, connect,
    /// redirect, non-success status, oversize body, JSON parse — collapses
    /// into the SAME generic [`IssuerdError::InvalidRequest`]; the real cause is
    /// logged only, so this endpoint cannot serve as a blind host/port
    /// oracle into the internal network.
    ///
    /// Hostname resolution and connection share one validated answer through
    /// [`PublicOnlyResolver`], so a DNS change cannot substitute an internal
    /// address between the check and the connection.
    async fn get_json_ssrf_guarded(&self, url: &str) -> Result<serde_json::Value, IssuerdError> {
        let body = self.untrusted_client.get_bytes(url).await?;
        serde_json::from_slice(&body).map_err(|e| guarded_request_fail(&format!("json parse: {e}")))
    }

    /// The text variant of [`Self::get_json_ssrf_guarded`] (a pre-registered
    /// `request_uri` serves a JWT, not JSON).
    async fn get_text_ssrf_guarded(&self, url: &str) -> Result<String, IssuerdError> {
        let body = self.untrusted_client.get_bytes(url).await?;
        String::from_utf8(body).map_err(|e| guarded_request_fail(&format!("utf8: {e}")))
    }
}

/// One generic, leak-free error for every failure mode of an SSRF-guarded
/// request: the real cause is logged only, so callers cannot serve as a blind
/// host/port oracle into the internal network.
fn guarded_request_fail(why: &str) -> IssuerdError {
    warn!(why, "SSRF-guarded request rejected/failed");
    IssuerdError::InvalidRequest("untrusted URL could not be fetched".to_string())
}

impl SsrfGuardedClient {
    pub(crate) fn new(
        extra_roots: &[reqwest::Certificate],
        allow_private_addresses: bool,
        timeout: std::time::Duration,
    ) -> Result<Self, reqwest::Error> {
        let builder = crate::outbound_http::client_builder(extra_roots)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        let builder = if allow_private_addresses {
            builder
        } else {
            builder.dns_resolver(std::sync::Arc::new(PublicOnlyResolver))
        };
        Ok(Self {
            client: builder.build()?,
            allow_private_addresses,
        })
    }

    fn check_url(&self, url: &str) -> Result<(), IssuerdError> {
        let parsed =
            url::Url::parse(url).map_err(|e| guarded_request_fail(&format!("url parse: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(guarded_request_fail("non-https scheme"));
        }
        if parsed.host_str().is_none() {
            return Err(guarded_request_fail("no host component"));
        }
        if parsed.port_or_known_default().is_none() {
            return Err(guarded_request_fail("no port"));
        }
        // The connector does not invoke its DNS resolver for IP literals.
        // Hostnames are checked by PublicOnlyResolver, which returns exactly
        // the validated addresses that the connector then dials.
        if !self.allow_private_addresses && is_non_public_ip_literal(&parsed) {
            return Err(guarded_request_fail("non-public address literal"));
        }
        Ok(())
    }

    /// GET a small document with the shared URL and transport guards.
    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, IssuerdError> {
        self.check_url(url)?;
        let resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| guarded_request_fail(&format!("connect: {e}")))?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(guarded_request_fail(&format!("redirect: {status}")));
        }
        if !status.is_success() {
            return Err(guarded_request_fail(&format!("status: {status}")));
        }

        if resp.content_length().is_some_and(|n| n > MAX_UNTRUSTED_BODY_BYTES as u64) {
            return Err(guarded_request_fail("content-length exceeds cap"));
        }
        let mut body = Vec::new();
        let mut resp = resp;
        while let Some(chunk) =
            resp.chunk().await.map_err(|e| guarded_request_fail(&format!("body: {e}")))?
        {
            if body.len() + chunk.len() > MAX_UNTRUSTED_BODY_BYTES {
                return Err(guarded_request_fail("body exceeds cap"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// POST a form without following redirects. The response body is not
    /// consumed; the caller decides whether the returned HTTP status succeeds.
    pub(crate) async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<reqwest::StatusCode, IssuerdError> {
        self.check_url(url)?;
        let resp = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|e| guarded_request_fail(&format!("connect: {e}")))?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(guarded_request_fail(&format!("redirect: {status}")));
        }
        Ok(status)
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
        assert!(ReqwestBrokerClient::new(&[], false, false).is_ok());
    }

    #[tokio::test]
    async fn guarded_fetch_rejects_non_https_before_any_network_io() {
        let client = ReqwestBrokerClient::new(&[], false, false).unwrap();
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

    /// A tiny HTTPS server on loopback (an rcgen-minted CA signs the
    /// `localhost` server certificate) serving a JSON document; returns the
    /// base URL and the CA certificate the client must trust.
    async fn start_loopback_tls_json() -> (String, reqwest::Certificate) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // aws-lc's webpki fork requires the CA key-usage bits explicitly.
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        // A distinct DN: with rcgen's default the CA and the leaf would share
        // "CN=rcgen self signed cert", making the leaf look self-signed.
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "issuerd test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "idp.test".to_string()])
                .unwrap()
                .signed_by(&server_key, &ca_cert, &ca_key)
                .unwrap();

        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            server_cert.pem().into_bytes(),
            server_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // axum_server registers the socket with the tokio runtime.
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new()
            .route(
                "/jwks",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"keys": []})) }),
            )
            .route(
                "/doc",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route(
                "/big",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({"pad": "x".repeat(MAX_IDP_BODY_BYTES)}))
                }),
            )
            .route(
                "/to",
                axum::routing::get(
                    |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| async move { axum::response::Redirect::temporary(&q["url"]) },
                ),
            );
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        (format!("https://127.0.0.1:{port}"), root)
    }

    /// The SSRF guard's public-IP check blocks loopback by default and lifts
    /// only under `[outbound_http] allow_private_addresses` — the https and
    /// TLS-trust rules are enforced in both modes (the allowed fetch really
    /// validates against the rig's CA).
    #[tokio::test]
    async fn guarded_fetch_private_addresses_follow_the_config_flag() {
        let (base, root) = start_loopback_tls_json().await;
        let url = format!("{base}/jwks");

        // Default posture: loopback is refused by the guard (never dialed).
        let client = ReqwestBrokerClient::new(std::slice::from_ref(&root), false, false).unwrap();
        let err = client.get_json_ssrf_guarded(&url).await.unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)), "{err}");

        // Test-rig mode: the same fetch succeeds end to end.
        let client = ReqwestBrokerClient::new(&[root], true, false).unwrap();
        let json = client.get_json_ssrf_guarded(&url).await.unwrap();
        assert_eq!(json["keys"], serde_json::json!([]));
    }

    /// The allowance lifts ONLY the address check: plain http stays refused
    /// even with the flag on.
    #[tokio::test]
    async fn guarded_fetch_allow_private_keeps_the_https_rule() {
        let client = ReqwestBrokerClient::new(&[], true, false).unwrap();
        let err = client.get_json_ssrf_guarded("http://127.0.0.1/jwks").await.unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)), "{err}");
    }

    /// A refused IdP call fails exactly like a dead host, so the admin
    /// test-connection endpoint is no internal-network oracle.
    fn assert_idp_unreachable(err: &IssuerdError, url: &str) {
        let expected = format!("identity provider unreachable: {url}");
        assert!(
            matches!(err, IssuerdError::ServerError(m) if *m == expected),
            "{url} must be refused as unreachable: {err}"
        );
    }

    fn gated_client(egress: IdpEgress, builder: reqwest::ClientBuilder) -> ReqwestBrokerClient {
        ReqwestBrokerClient {
            client: builder.build().unwrap(),
            untrusted_client: SsrfGuardedClient::new(
                &[],
                false,
                std::time::Duration::from_secs(10),
            )
            .unwrap(),
            idp_egress: egress,
        }
    }

    /// Default posture: every IdP-facing call (discovery/JWKS GET, token
    /// POST, userinfo GET) refuses internal and metadata IP literals, over
    /// http and https, before any connection is made.
    #[tokio::test]
    async fn idp_calls_refuse_non_public_ip_literals_by_default() {
        let client = ReqwestBrokerClient::new(&[], false, false).unwrap();
        for url in [
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.5:8500/v1/agent/.well-known/openid-configuration",
            "https://127.0.0.1/realms/x/protocol/openid-connect/certs",
            "https://192.168.1.1/token",
            "http://[::1]/userinfo",
            "http://[::ffff:10.0.0.5]/userinfo",
        ] {
            assert_idp_unreachable(&client.get_json(url).await.unwrap_err(), url);
            assert_idp_unreachable(&client.post_form(url, &[], None).await.unwrap_err(), url);
            assert_idp_unreachable(&client.get_json_bearer(url, "at").await.unwrap_err(), url);
        }
    }

    /// HTTPS public hosts pass the up-front check; plain HTTP requires the
    /// explicit unrestricted development mode.
    #[tokio::test]
    async fn idp_up_front_check_enforces_https_by_default() {
        let client = gated_client(IdpEgress::Direct, idp_client_builder(&[], IdpEgress::Direct));
        for url in [
            "http://idp.example.com/.well-known/openid-configuration",
            "http://8.8.8.8/x",
        ] {
            assert_idp_unreachable(&client.check_idp_url(url).await.unwrap_err(), url);
        }
        for url in [
            "https://idp.example.com/.well-known/openid-configuration",
            "https://8.8.8.8/x",
        ] {
            client.check_idp_url(url).await.unwrap();
        }

        let development =
            gated_client(IdpEgress::Unrestricted, idp_client_builder(&[], IdpEgress::Unrestricted));
        development.check_idp_url("http://localhost:8080").await.unwrap();
    }

    /// The resolver hands the connector exactly the checked addresses and
    /// refuses a host with any non-public address.
    #[tokio::test]
    async fn public_only_resolver_returns_only_checked_addresses() {
        use reqwest::dns::Resolve;
        let addrs: Vec<_> =
            PublicOnlyResolver.resolve("8.8.8.8".parse().unwrap()).await.unwrap().collect();
        assert_eq!(addrs, vec!["8.8.8.8:0".parse().unwrap()]);
        for host in ["localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254"] {
            assert!(PublicOnlyResolver.resolve(host.parse().unwrap()).await.is_err(), "{host}");
        }
    }

    #[test]
    fn idp_redirect_verdict_rules() {
        let u = |s: &str| url::Url::parse(s).unwrap();
        let origin = [u("https://idp.example.com/a")];
        // HTTPS-to-HTTP downgrades are refused; HTTPS public hops are followed.
        assert!(idp_redirect_verdict(&u("http://other.example.org/b"), &origin, false).is_err());
        assert!(idp_redirect_verdict(&u("https://8.8.8.8/b"), &origin, false).is_ok());
        let development_origin = [u("http://idp.example.com/a")];
        assert!(
            idp_redirect_verdict(&u("http://other.example.org/b"), &development_origin, false)
                .is_ok()
        );
        // Non-public literals are refused (the resolver never sees them).
        for hop in [
            "http://127.0.0.1/b",
            "http://169.254.169.254/latest",
            "http://[::1]/b",
            "http://[::ffff:192.168.0.1]/b",
            "http://2130706433/b",
        ] {
            assert!(idp_redirect_verdict(&u(hop), &origin, false).is_err(), "{hop}");
        }
        // reqwest's default hop limit.
        let nine = vec![u("https://idp.example.com/a"); 9];
        assert!(idp_redirect_verdict(&u("https://idp.example.com/b"), &nine, false).is_ok());
        let ten = vec![u("https://idp.example.com/a"); 10];
        assert!(idp_redirect_verdict(&u("https://idp.example.com/b"), &ten, false).is_err());
        // Behind a proxy only same-host hops are followed, and never downgraded.
        assert!(idp_redirect_verdict(&u("http://idp.example.com/b"), &origin, true).is_err());
        assert!(idp_redirect_verdict(&u("https://other.example.org/b"), &origin, true).is_err());
    }

    /// Proxied mode resolves and checks the target up front.
    #[tokio::test]
    async fn idp_proxied_mode_checks_the_target_up_front() {
        let client = gated_client(IdpEgress::Proxied, idp_client_builder(&[], IdpEgress::Proxied));
        let url = "http://localhost:8500/v1/agent";
        assert_idp_unreachable(&client.check_idp_url(url).await.unwrap_err(), url);
        client.check_idp_url("https://8.8.8.8/x").await.unwrap();
    }

    /// The IdP gate lifts only under `allow_private_identity_providers` — the
    /// test-rig flag for attacker-influenced URLs does not lift it.
    #[tokio::test]
    async fn idp_calls_private_targets_follow_their_own_config_flag() {
        let (base, root) = start_loopback_tls_json().await;
        let url = format!("{base}/jwks");

        let client = ReqwestBrokerClient::new(std::slice::from_ref(&root), false, false).unwrap();
        assert_idp_unreachable(&client.get_json(&url).await.unwrap_err(), &url);
        let client = ReqwestBrokerClient::new(std::slice::from_ref(&root), true, false).unwrap();
        assert_idp_unreachable(&client.get_json(&url).await.unwrap_err(), &url);

        let client = ReqwestBrokerClient::new(&[root], false, true).unwrap();
        let json = client.get_json(&url).await.unwrap();
        assert_eq!(json["keys"], serde_json::json!([]));
    }

    /// A plain-http loopback IdP: `/doc` serves JSON, `/big` a document over
    /// the body cap, `/to?url=..` redirects to `url`.
    async fn start_loopback_http_idp() -> u16 {
        let app = axum::Router::new()
            .route(
                "/doc",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route(
                "/big",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({"pad": "x".repeat(MAX_IDP_BODY_BYTES)}))
                }),
            )
            .route(
                "/to",
                axum::routing::get(
                    |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| async move { axum::response::Redirect::temporary(&q["url"]) },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    /// Direct mode end to end, without DNS: `idp.test` stands in for a public
    /// IdP host (a reqwest DNS override pins it to the loopback server).
    /// HTTPS and public hops are followed; a hop to a non-public literal, or
    /// to a name that resolves non-public, is refused; the body is capped.
    #[tokio::test]
    async fn idp_direct_mode_follows_public_hops_only_and_caps_the_body() {
        let (base, root) = start_loopback_tls_json().await;
        let port = base.parse::<url::Url>().unwrap().port().unwrap();
        let pinned = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let builder = idp_client_builder(std::slice::from_ref(&root), IdpEgress::Direct)
            .resolve("idp.test", pinned);
        let client = gated_client(IdpEgress::Direct, builder);
        let base = base.replace("127.0.0.1", "idp.test");

        assert_eq!(client.get_json(&format!("{base}/doc")).await.unwrap()["ok"], true);
        let hop = format!("{base}/to?url={base}/doc");
        assert_eq!(client.get_json(&hop).await.unwrap()["ok"], true);

        for target in [
            format!("http://127.0.0.1:{port}/doc"),
            format!("http://localhost:{port}/doc"),
        ] {
            let url = format!("{base}/to?url={target}");
            assert_idp_unreachable(&client.get_json(&url).await.unwrap_err(), &url);
        }
        let url = format!("http://localhost:{port}/doc");
        assert_idp_unreachable(&client.get_json(&url).await.unwrap_err(), &url);
        let url = format!("{base}/big");
        assert_idp_unreachable(&client.get_json(&url).await.unwrap_err(), &url);
    }

    /// `allow_private_identity_providers` restores the pre-gate behaviour
    /// (internal targets, redirects followed); only the body cap remains.
    #[tokio::test]
    async fn idp_unrestricted_mode_follows_redirects_and_caps_the_body() {
        let port = start_loopback_http_idp().await;
        let base = format!("http://127.0.0.1:{port}");
        let client = ReqwestBrokerClient::new(&[], false, true).unwrap();
        let hop = format!("{base}/to?url=http://localhost:{port}/doc");
        assert_eq!(client.get_json(&hop).await.unwrap()["ok"], true);
        let url = format!("{base}/big");
        assert_idp_unreachable(&client.get_json(&url).await.unwrap_err(), &url);
    }
}
