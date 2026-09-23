// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client IP resolution middleware honoring trusted proxies (X-Forwarded-For / X-Real-IP).

use axum::{
    extract::{ConnectInfo, Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::ProxyConfig;
use crate::state::ServerState;

#[derive(Debug, Clone)]
pub struct ClientIp(pub IpAddr);

pub async fn proxy_ip_middleware(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = resolve_client_ip(&state.config.proxy, addr.ip(), request.headers());
    request.extensions_mut().insert(ClientIp(ip));
    next.run(request).await
}

/// Determine the client IP for this request.
///
/// `X-Forwarded-For` / `X-Real-IP` are attacker-controlled unless the direct
/// peer is a known reverse proxy, so the headers are honored only when the
/// corresponding trust flag is enabled *and* the peer matches
/// `trusted_proxies`. Within XFF the rightmost untrusted entry wins: entries
/// to the right were appended by proxies we trust, while the leftmost entry
/// is the most spoofable.
fn resolve_client_ip(cfg: &ProxyConfig, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    // Entries may be bare IPs ("10.0.0.1") or CIDR ranges ("10.0.0.0/8");
    // ipnet's FromStr requires a prefix, so fall back to host parsing.
    let trusted: Vec<IpNet> = cfg
        .trusted_proxies
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            s.parse::<IpNet>().ok().or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
        })
        .collect();
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(&ip));

    if !is_trusted(peer) {
        return peer;
    }

    if cfg.trust_x_forwarded_for {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            let entries: Vec<IpAddr> =
                xff.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if let Some(client) = entries.iter().rev().find(|ip| !is_trusted(**ip)) {
                return *client;
            }
        }
    }

    if cfg.trust_x_real_ip {
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return ip;
        }
    }

    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use axum::{
        body::Body,
        extract::Extension,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn cfg(trusted: &[&str], xff: bool, real_ip: bool) -> ProxyConfig {
        ProxyConfig {
            trusted_proxies: trusted.iter().map(|s| s.to_string()).collect(),
            trust_x_forwarded_for: xff,
            trust_x_real_ip: real_ip,
        }
    }

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (k, v) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn untrusted_peer_headers_ignored() {
        let c = cfg(&[], true, true);
        let h = headers_with(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "9.10.11.12")]);
        let peer: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(resolve_client_ip(&c, peer, &h), peer);
    }

    #[test]
    fn trusted_peer_xff_rightmost_untrusted_wins() {
        // Peer 127.0.0.1 is trusted; 5.6.7.8 is the host it received from.
        let c = cfg(&["127.0.0.1"], true, false);
        let h = headers_with(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        assert_eq!(
            resolve_client_ip(&c, "127.0.0.1".parse::<IpAddr>().unwrap(), &h),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_proxy_entries_are_skipped_via_cidr() {
        let c = cfg(&["127.0.0.1", "10.0.0.0/8"], true, false);
        let h = headers_with(&[("x-forwarded-for", "1.2.3.4, 10.0.0.1")]);
        assert_eq!(
            resolve_client_ip(&c, "127.0.0.1".parse::<IpAddr>().unwrap(), &h),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn disabled_flag_ignores_header() {
        let c = cfg(&["127.0.0.1"], false, true);
        let h = headers_with(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "9.10.11.12")]);
        assert_eq!(
            resolve_client_ip(&c, "127.0.0.1".parse::<IpAddr>().unwrap(), &h),
            "9.10.11.12".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn no_usable_header_falls_back_to_peer() {
        let c = cfg(&["127.0.0.1"], true, true);
        let h = headers_with(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(
            resolve_client_ip(&c, "127.0.0.1".parse::<IpAddr>().unwrap(), &h),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    async fn handler(Extension(client_ip): Extension<ClientIp>) -> String {
        client_ip.0.to_string()
    }

    #[tokio::test]
    async fn middleware_wires_config_from_state() {
        let server_cfg = ServerConfig {
            proxy: cfg(&["127.0.0.1"], true, false),
            ..Default::default()
        };
        let state = Arc::new(ServerState::from_config(&server_cfg).await.unwrap());

        let app = Router::new()
            .route("/", get(handler))
            .layer(axum::middleware::from_fn_with_state(state, proxy_ip_middleware));

        let mut req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "1.2.3.4, 5.6.7.8")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "5.6.7.8");
    }
}
