// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Shared construction of outbound HTTP clients.
//!
//! Every reqwest client the server builds — the identity-broker client, the
//! SSRF-guarded client-JWKS/sector fetch, the back-channel logout dispatcher —
//! starts from [`client_builder`], so the `[outbound_http] extra_ca_bundle`
//! roots (parsed at boot by
//! [`crate::config::OutboundHttpConfig::load_extra_roots`]) apply uniformly.
//! The extra roots are ADDITIVE to the public webpki root store; with an empty
//! slice the builder is exactly the default.

/// A `reqwest::ClientBuilder` with the extra root CAs applied on top of the
/// public webpki roots. Callers layer their own timeout/redirect policy on
/// top before `.build()`.
pub(crate) fn client_builder(extra_roots: &[reqwest::Certificate]) -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder();
    for root in extra_roots {
        builder = builder.add_root_certificate(root.clone());
    }
    builder
}

#[cfg(test)]
mod tests {
    #[test]
    fn builder_without_extra_roots_builds() {
        assert!(super::client_builder(&[]).build().is_ok());
    }

    #[test]
    fn builder_with_extra_roots_builds() {
        // A real certificate from the config tests' bundle: the builder must
        // accept it (it lands in the client's root store).
        let certs = reqwest::Certificate::from_pem_bundle(crate::config::TEST_CA_BUNDLE.as_bytes())
            .unwrap();
        assert_eq!(certs.len(), 2);
        assert!(super::client_builder(&certs).build().is_ok());
    }
}
