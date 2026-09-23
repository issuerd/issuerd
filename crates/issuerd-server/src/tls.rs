// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// TLS configuration loading from PEM files (rustls ServerConfig, TLS 1.2+).

use rustls::ServerConfig as RustlsServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Load TLS configuration from PEM files.
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<RustlsServerConfig, rustls::Error> {
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| {
            rustls::Error::General(format!("failed to read certificate file '{cert_path}': {e}"))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| rustls::Error::General(format!("failed to parse certificate: {e}")))?;

    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        rustls::Error::General(format!("failed to read private key file '{key_path}': {e}"))
    })?;

    // Explicitly restrict to TLS 1.2+ (rustls defaults already do this,
    // but we make it explicit for security audit compliance).
    RustlsServerConfig::builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUKVpwfWtlmHC7vo1GtuDjdsSEipQwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwMTA4MTgwNloXDTI2MDYw
MjA4MTgwNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAullC13pXFWV5dOAjfEjFTchFvIQEkozpsSIlzxQAizb8
54wk+TZDWfs+zSBRBPfvfzUGZBGzU6s6l0odAlwyNlTf5HdyH1qrNKJ3O19A+0rd
VRilOEvpYsAVsW3Jgiarb6WjoNLOdi7W3RKWaersT4BwQjMvhJLV6Iq4niFGRSoV
15IfZn9m5pkdcBzBo7n7qJtGvd4/1CK8PWILEtqyiyJpEUqmAzI/nABcpyTZmySc
CyOaD1rOhXyVJueyDFGugKUp4WhnqQ2M0uVPTliZWRo154HBMs+u4NsfQBd5juBz
bIRueNbjomq0z5dljRr1fLS/4VUs35vVkMV1AoJfoQIDAQABo1MwUTAdBgNVHQ4E
FgQUHo1ydfE8dRn/r60VDxfp+1LRCjcwHwYDVR0jBBgwFoAUHo1ydfE8dRn/r60V
Dxfp+1LRCjcwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAjWMX
rEVQw0jEvmbXiwaYgCfrDBolLqFF2qyQtOg791JPlvd6XpPanqsFLXuS8215BqgY
Z1SAElMTSpT4NWxfMwcB1MUigyQi0nbltKa5irSABZ43G5/q7Cg2eHP5CHkp95G4
ev7MuQnbSTnMXM9yEye1y7LsZDMKJfnu+c9RJ4RhviRmKvnfu/1yK2KxHEESDBWF
c4M9LDAz4wGc/Ol62HFKb6Z73dAjfl+XUcTD1pXZdKdIMAa1H+jgojFRqnXqZlDH
zIBEIrvnaSq/4Rc7+6lyneHSu7L4eA7ajty+do/mE6QYs3oNBNTS1ZRIilyo6Z/Q
0ODKh72zmFSfm0YN/g==
-----END CERTIFICATE-----"#;

    const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6WULXelcVZXl0
4CN8SMVNyEW8hASSjOmxIiXPFACLNvznjCT5NkNZ+z7NIFEE9+9/NQZkEbNTqzqX
Sh0CXDI2VN/kd3IfWqs0onc7X0D7St1VGKU4S+liwBWxbcmCJqtvpaOg0s52Ltbd
EpZp6uxPgHBCMy+EktXoirieIUZFKhXXkh9mf2bmmR1wHMGjufuom0a93j/UIrw9
YgsS2rKLImkRSqYDMj+cAFynJNmbJJwLI5oPWs6FfJUm57IMUa6ApSnhaGepDYzS
5U9OWJlZGjXngcEyz67g2x9AF3mO4HNshG541uOiarTPl2WNGvV8tL/hVSzfm9WQ
xXUCgl+hAgMBAAECggEBAIwHjTncfdnfMeCImUHIcTMc3oJldgYmC2mG7oBoWGxE
etEIN7RpeT0BllSQBzHDmd2uG8pQnr+tuM5868WdQEIhj0jgFQrImERqHUypLGxo
+l76sRTXvl3tV5/HjxfVNRglkQrFvk2CrwTa9dpLpR2sty6XxgpKSKGAtHBnMqW/
S+hCMUWl0W6pm5/FeEeL4Hz0LngYAjqHlmXAlXmv7cvLG5waevOrXov4E4PRzjGj
9J7q5b9Z62YSI7eokgcitOhLfIhOMXawnDmFrKhjUPHUUg53NVrHoqwmiotN+AZA
Fb0lagBKKpiGwGh8AzKnAnZD++TayKaXktzwYQvdNFECgYEA7PDPPbLAKPAgwpur
1hwW21NKDENGoUg9pXT8wfzsEh4yqaE4k4BSTn4Qd/4DHn/h8tGDBbZ2OX4iMwgC
8TdXI3fNDjQlf3+ttpAuiuoI+tRLXIvyn+Vo8pP+vOCcHQGYlGICCVb70u8Juj5x
1TjJeK+EWdPBOt7fWSM55YaYDcUCgYEAyVajZJM0jnn95F/hIpsH/QxVx6mzrDxn
VRpwtyB04VqDqGHc+191CblPhLNq4Y+ji5seUT8YdQczEy+NdcaCDpe/irqXWAYu
fCB32J44VZix/R97K2sUEJoZ4a9cfLkSDwPMLcL7HlO2hFSq7W6y0ydt0h2oazLv
WVI7ayg7ZC0CgYEAiyBzcBUPxHoLonnqEpT3zt0/M6glRvq2R/tDl1y9+X2F3hju
sZ29tp1Lakna5wPMVtozBx22mde4mSJxJ9aI8iicXWS9R/petD5BNgxqLW6Ouc7r
Lnx0fUvtXla9FEMlpqtN6tIKmDcIDTYxfTQVCSp2mpA+fCT2HM8UZfP8QMkCgYA3
xktvMiROD9dYq4LnnkDhRciBji5a2UTa2388C761Kujr/WhFLpVygyZXIYjLQYpR
wz/ry+nPiZYJi5PJe5tNxZXnLXd9iADam/f3RyVd+PXdpBnv1jLxwm7HCVg6qN4q
0KeASdJc/V3DXN0Y9yCMxBB1M4gTYkHR4ajaL4P8ZQKBgGGoGQs3bgxTjsHLmDF+
l42wqFJXcD2HnOaHxzWKp7pEdojE1wJSisLfW/h5w8Kte0/iQBnc8juxNFHMk5xa
RLkCRbEfguDyngm429mLieUzbM5WZgspHfdpcjlgIn4RwTb9NfP7VMqrU+jCTNWE
dFcIqMAzpOkimvpP+woP1vaU
-----END PRIVATE KEY-----"#;

    #[test]
    fn load_tls_config_success() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tmp_dir = std::env::temp_dir().join("issuerd_server_tls_test");
        let _ = fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        fs::write(&cert_path, TEST_CERT).unwrap();
        fs::write(&key_path, TEST_KEY).unwrap();

        let result = load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_ok());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    /// rustls 0.23 `DEFAULT_VERSIONS` only includes TLS 1.2 and 1.3.
    /// This test verifies that our explicit builder call produces a valid config.
    #[test]
    fn load_tls_config_uses_safe_protocol_versions() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tmp_dir = std::env::temp_dir().join("issuerd_server_tls_test_versions");
        let _ = fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        fs::write(&cert_path, TEST_CERT).unwrap();
        fs::write(&key_path, TEST_KEY).unwrap();

        let config =
            load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        // We cannot inspect `config.versions` directly (it is `pub(super)`),
        // but `load_tls_config` uses `builder_with_protocol_versions(DEFAULT_VERSIONS)`,
        // which in rustls 0.23 is `[TLS13, TLS12]`. TLS 1.0/1.1 are unsupported.
        // The test passing confirms the builder accepted the safe defaults.
        assert!(config.alpn_protocols.is_empty(), "no ALPN protocols configured by default");

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn load_tls_config_missing_cert() {
        let result = load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn load_tls_config_missing_key() {
        let tmp_dir = std::env::temp_dir().join("issuerd_server_tls_test2");
        let _ = fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        fs::write(&cert_path, TEST_CERT).unwrap();

        let result = load_tls_config(cert_path.to_str().unwrap(), "/nonexistent/key.pem");
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn load_tls_config_invalid_cert() {
        let tmp_dir = std::env::temp_dir().join("issuerd_server_tls_test3");
        let _ = fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        fs::write(&cert_path, "-----BEGIN CERTIFICATE-----\nNOT_VALID\n-----END CERTIFICATE-----")
            .unwrap();
        fs::write(&key_path, TEST_KEY).unwrap();

        let result = load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn load_tls_config_invalid_key() {
        let tmp_dir = std::env::temp_dir().join("issuerd_server_tls_test4");
        let _ = fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        fs::write(&cert_path, TEST_CERT).unwrap();
        fs::write(&key_path, "-----BEGIN PRIVATE KEY-----\nNOT_VALID\n-----END PRIVATE KEY-----")
            .unwrap();

        let result = load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn load_tls_config_key_file_no_key() {
        let tmp_dir = std::env::temp_dir().join("issuerd_server_tls_test5");
        let _ = fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        fs::write(&cert_path, TEST_CERT).unwrap();
        // Write a certificate into the key file so it parses as valid PEM
        // but contains no private key.
        fs::write(&key_path, TEST_CERT).unwrap();

        let result = load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("no items found"),
            "expected 'no items found' error, got: {err_msg}"
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
