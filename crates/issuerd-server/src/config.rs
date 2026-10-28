// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Server configuration types with figment-based layered loading (TOML/YAML/JSON + env).

use figment::{
    providers::{Env, Format, Json, Serialized, Toml},
    Figment,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::PathBuf;

use issuerd_core::IssuerdError;

/// YAML [`Format`] provider backed by serde-saphyr (pure-Rust parser) instead
/// of figment's built-in `yaml` feature, which would pull serde_yaml and the
/// unmaintained unsafe-libyaml (RUSTSEC-2024-0449) into the build graph.
/// Routed through figment's `Data` provider, so file resolution and profile
/// semantics are identical to the built-in TOML/JSON formats.
#[derive(Debug, Clone, Copy)]
struct YamlSafe;

impl Format for YamlSafe {
    type Error = serde_saphyr::Error;

    const NAME: &'static str = "YAML";

    fn from_str<T: DeserializeOwned>(string: &str) -> Result<T, Self::Error> {
        serde_saphyr::from_str(string)
    }
}

/// Server configuration with figment-based loading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    pub issuer_url: String,
    pub tls: Option<TlsConfig>,
    pub storage: StorageConfig,
    pub redis: Option<String>,
    pub logging: LoggingConfig,
    pub web_ui: WebUiConfig,
    pub proxy: ProxyConfig,
    pub cors: CorsConfig,
    /// Multi-node clustering settings.
    pub cluster: ClusterConfig,
    /// SMTP/email settings (`[smtp]` section). Disabled by default.
    pub smtp: SmtpConfig,
    /// Read-model cache settings (`[cache]` section).
    #[serde(default)]
    pub cache: CacheConfig,
    /// OAuth/OIDC protocol tuning (`[oauth]` section).
    #[serde(default)]
    pub oauth: OAuthConfig,
    /// DPoP (RFC 9449) settings (`[dpop]` section).
    #[serde(default)]
    pub dpop: DpopConfig,
    /// MCP endpoint settings (`[mcp]` section). Disabled by default.
    #[serde(default)]
    pub mcp: McpConfig,
    /// Crypto settings (`[crypto]` section).
    #[serde(default)]
    pub crypto: CryptoSettings,
    /// Outbound HTTP settings (`[outbound_http]` section).
    #[serde(default)]
    pub outbound_http: OutboundHttpConfig,
    /// Login-theme asset directory (`[themes]` section).
    pub themes: ThemesConfig,
    /// Optional path to a provision config file (YAML/TOML/JSON).
    /// Applied exactly once at first startup; ignored on restarts.
    pub provision: Option<PathBuf>,
    /// Password for the `admin` user that the in-memory/JSON-file first-boot
    /// bootstrap seeds into the `master` realm
    /// (`ISSUERD_BOOTSTRAP_ADMIN_PASSWORD`). Unset or empty ⇒ a random
    /// password is generated and printed once to stderr.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_admin_password: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".to_string(),
            port: 8080,
            issuer_url: "http://localhost:8080".to_string(),
            tls: None,
            storage: StorageConfig::InMemory,
            redis: None,
            logging: LoggingConfig::default(),
            web_ui: WebUiConfig::default(),
            proxy: ProxyConfig::default(),
            cors: CorsConfig::default(),
            cluster: ClusterConfig::default(),
            smtp: SmtpConfig::default(),
            cache: CacheConfig::default(),
            oauth: OAuthConfig::default(),
            dpop: DpopConfig::default(),
            mcp: McpConfig::default(),
            crypto: CryptoSettings::default(),
            outbound_http: OutboundHttpConfig::default(),
            themes: ThemesConfig::default(),
            provision: None,
            bootstrap_admin_password: None,
        }
    }
}

impl ServerConfig {
    /// Load configuration from file (TOML/YAML/JSON) and environment overrides.
    ///
    /// Environment variables prefixed with `ISSUERD_` are merged on top of
    /// the file values.  If `path` is `None`, only defaults + environment are used.
    pub fn load(path: Option<PathBuf>) -> Result<Self, IssuerdError> {
        let mut figment = Figment::new().merge(Serialized::defaults(Self::default()));

        if let Some(p) = path {
            if p.exists() {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("toml").to_lowercase();
                match ext.as_str() {
                    "yaml" | "yml" => {
                        figment = figment.merge(YamlSafe::file(p));
                    }
                    "json" => {
                        figment = figment.merge(Json::file(p));
                    }
                    _ => {
                        figment = figment.merge(Toml::file(p));
                    }
                }
            }
        }

        figment = figment.merge(
            Env::prefixed("ISSUERD_")
                .split("__")
                .map(|k| k.as_str().to_ascii_lowercase().into()),
        );

        figment
            .extract::<Self>()
            .map_err(|e| IssuerdError::ServerError(format!("config load failed: {e}")))
    }

    /// Whether server-set browser cookies carry the `Secure` attribute.
    ///
    /// Derived from the configured `issuer_url` — never from the request:
    /// `true` exactly when the public scheme is `https`. Every TLS deployment
    /// (direct, or behind a TLS-terminating proxy where `issuer_url` keeps
    /// the public `https` scheme) gets `Secure` on all authentication
    /// cookies — SSO session, remember-me, flow correlation, and the logout
    /// clears — while plain-HTTP development rigs keep working.
    pub fn secure_cookies(&self) -> bool {
        url::Url::parse(&self.issuer_url).is_ok_and(|u| u.scheme() == "https")
    }

    /// Generate a fully-populated example config for documentation / CLI usage.
    pub fn generate_example() -> Self {
        Self {
            bind: "0.0.0.0".to_string(),
            port: 8080,
            issuer_url: "http://localhost:8080".to_string(),
            tls: Some(TlsConfig {
                cert_path: "certs/issuerd.test.internal.crt".to_string(),
                key_path: "certs/issuerd.test.internal.key".to_string(),
            }),
            storage: StorageConfig::Postgres {
                url: "postgres://issuerd:issuerd_secret@localhost:5433/issuerd".to_string(),
            },
            redis: Some("redis://localhost:6379".to_string()),
            logging: LoggingConfig {
                format: "pretty".to_string(),
                level: "info".to_string(),
            },
            web_ui: WebUiConfig { enabled: true },
            proxy: ProxyConfig {
                trusted_proxies: vec![],
                trust_x_forwarded_for: true,
                trust_x_real_ip: true,
            },
            cors: CorsConfig::default(),
            themes: ThemesConfig::default(),
            cluster: ClusterConfig::default(),
            smtp: SmtpConfig {
                enabled: false,
                host: "127.0.0.1".to_string(),
                port: 1025,
                from: "issuerd@test.internal".to_string(),
                from_display: Some("Issuerd".to_string()),
                reply_to: None,
                starttls: false,
                ssl: false,
                username: None,
                password: None,
            },
            cache: CacheConfig::default(),
            oauth: OAuthConfig::default(),
            dpop: DpopConfig::default(),
            mcp: McpConfig::default(),
            crypto: CryptoSettings::default(),
            outbound_http: OutboundHttpConfig::default(),
            provision: Some(PathBuf::from("provision.yaml")),
            bootstrap_admin_password: None,
        }
    }
}

#[cfg(test)]
impl ServerConfig {
    /// Defaults plus the well-known `admin`/`admin` bootstrap admin that unit
    /// tests log in with.
    pub(crate) fn with_test_admin() -> Self {
        Self {
            bootstrap_admin_password: Some("admin".to_string()),
            ..Self::default()
        }
    }
}

/// Serialize `value` to `path` inferring format from the file extension.
///
/// Supported extensions: `.toml` (default), `.yaml`/`.yml`, `.json`.
pub fn write_example<T: serde::Serialize>(
    value: &T,
    path: &std::path::Path,
) -> Result<(), IssuerdError> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("toml").to_lowercase();
    let content = match ext.as_str() {
        "yaml" | "yml" => serde_saphyr::to_string(value)
            .map_err(|e| IssuerdError::ServerError(format!("yaml serialization failed: {e}")))?,
        "json" => serde_json::to_string_pretty(value)
            .map_err(|e| IssuerdError::ServerError(format!("json serialization failed: {e}")))?,
        _ => toml::to_string_pretty(value)
            .map_err(|e| IssuerdError::ServerError(format!("toml serialization failed: {e}")))?,
    };
    std::fs::write(path, content)
        .map_err(|e| IssuerdError::ServerError(format!("write failed: {e}")))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageConfig {
    InMemory,
    Postgres { url: String },
    JsonFile { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub format: String,
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: "pretty".to_string(),
            level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUiConfig {
    pub enabled: bool,
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub trusted_proxies: Vec<String>,
    pub trust_x_forwarded_for: bool,
    pub trust_x_real_ip: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: vec![],
            trust_x_forwarded_for: true,
            trust_x_real_ip: true,
        }
    }
}

/// CORS configuration.
///
/// Empty by default: no cross-origin browser requests are allowed. The embedded
/// admin SPA is served same-origin and the dev server proxies API calls, so
/// neither needs CORS. Add origins (scheme + host + port) only for browser
/// clients hosted on other origins, e.g. `allowed_origins = ["https://app.example.com"]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

/// Multi-node clustering configuration.
///
/// Clustering is opt-in. When `enabled` is true the server enforces the
/// multi-node contract at boot: PostgreSQL storage and a Redis cache are
/// required (boot fails otherwise), signing keys are loaded from shared
/// storage, and a background task refreshes the JWKS snapshot from storage so
/// keys added or rotated by peer nodes propagate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Enforce the multi-node deployment contract (Postgres + Redis required).
    pub enabled: bool,
    /// Stable identity of this node (used in logs). Defaults to the hostname.
    pub node_id: Option<String>,
    /// Redis Cluster node URLs (e.g. `["redis://r1:6379", "redis://r2:6379"]`).
    /// When non-empty this overrides the single-node `redis` URL.
    pub redis_nodes: Vec<String>,
    /// How often (seconds) the node re-reads the shared signing-key set from
    /// storage and refreshes its JWKS snapshot.
    pub jwks_refresh_interval_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            redis_nodes: Vec::new(),
            jwks_refresh_interval_secs: 30,
        }
    }
}

impl ClusterConfig {
    /// Resolve the node identity: configured value, else hostname, else a
    /// random id. Used for log correlation only.
    pub fn resolved_node_id(&self) -> String {
        if let Some(id) = &self.node_id {
            return id.clone();
        }
        if let Ok(host) = std::env::var("HOSTNAME") {
            if !host.is_empty() {
                return host;
            }
        }
        issuerd_core::utils::generate_id()
    }
}

/// Read-model cache configuration (`[cache]` section).
///
/// One knob governs every read-model cache on the token hot paths: session
/// validity snapshots (`userinfo`/`introspect` session checks), the
/// realm-by-name resolution cache, and the claims read-model (per-user
/// claims bundles, the realm role/scope catalog, client bundles). Precise
/// invalidation (delete on single-entity mutation) and epoch bumps
/// (realm-wide definition changes) make committed writes visible
/// immediately; a write that bypasses both stays hidden for at most
/// `read_cache_ttl_secs` — the consciously accepted bounded-staleness
/// window, same class as Keycloak's Infinispan propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// TTL in seconds of every read-model cache entry. `0` disables all
    /// read-model caches (every lookup hits storage — pre-cache behavior).
    pub read_cache_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            read_cache_ttl_secs: 60,
        }
    }
}

/// Default authorization-code lifetime: 10 minutes — the common interoperable
/// value (Keycloak uses the same).
pub const AUTH_CODE_TTL_DEFAULT_SECS: u64 = 600;
/// Shortest accepted authorization-code lifetime.
pub const AUTH_CODE_TTL_MIN_SECS: u64 = 10;
/// Longest accepted authorization-code lifetime. Codes are bearer grants
/// delivered through the browser — keep the redemption window short.
pub const AUTH_CODE_TTL_MAX_SECS: u64 = 600;

/// OAuth/OIDC protocol tuning (`[oauth]` section).
///
/// The whole section is optional and every key has a default, so existing
/// configuration files keep booting unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Lifetime of an authorization code in seconds: how long the client has
    /// to redeem it at the token endpoint
    /// (`[oauth] auth_code_ttl_secs`, env
    /// `ISSUERD_OAUTH__AUTH_CODE_TTL_SECS`). Default 600, accepted range
    /// 10–600; out-of-range values abort the boot. A FAPI 2.0 high-assurance
    /// profile wants ≤ 60 s — set 60 here or per realm (see
    /// [`OAuthConfig::REALM_AUTH_CODE_TTL_ATTRIBUTE`]) when building such a
    /// profile. (Full FAPI 2.0 message signing is out of scope; this is only
    /// the TTL knob a profile needs.)
    pub auth_code_ttl_secs: u64,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            auth_code_ttl_secs: AUTH_CODE_TTL_DEFAULT_SECS,
        }
    }
}

impl OAuthConfig {
    /// Realm attribute that overrides [`OAuthConfig::auth_code_ttl_secs`]
    /// for one realm (set via the realm representation's `attributes` map or
    /// the provision YAML `attributes` block). Must parse as an integer
    /// within the same 10–600 bounds; an absent, malformed, or out-of-range
    /// value falls back to the server-wide setting.
    pub const REALM_AUTH_CODE_TTL_ATTRIBUTE: &'static str = "auth_code_ttl_secs";

    /// Boot-time validation: reject out-of-range values with a clear error
    /// instead of silently clamping them.
    pub fn validate(&self) -> Result<(), IssuerdError> {
        if !(AUTH_CODE_TTL_MIN_SECS..=AUTH_CODE_TTL_MAX_SECS).contains(&self.auth_code_ttl_secs) {
            return Err(IssuerdError::InvalidRequest(format!(
                "oauth.auth_code_ttl_secs must be within \
                 {AUTH_CODE_TTL_MIN_SECS}..={AUTH_CODE_TTL_MAX_SECS} seconds, got {}",
                self.auth_code_ttl_secs
            )));
        }
        Ok(())
    }

    /// Effective authorization-code TTL for a realm: the realm attribute when
    /// present and in bounds, else the server-wide value.
    pub fn auth_code_ttl(&self, realm: &issuerd_core::Realm) -> std::time::Duration {
        let secs = realm
            .attributes
            .get(Self::REALM_AUTH_CODE_TTL_ATTRIBUTE)
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| (AUTH_CODE_TTL_MIN_SECS..=AUTH_CODE_TTL_MAX_SECS).contains(v))
            .unwrap_or(self.auth_code_ttl_secs);
        std::time::Duration::from_secs(secs)
    }
}

/// Default server-nonce lifetime: 30 seconds (the value Keycloak documents
/// for its own DPoP nonce).
pub const DPOP_NONCE_LIFETIME_DEFAULT_SECS: u64 = 30;
/// Shortest accepted server-nonce lifetime.
pub const DPOP_NONCE_LIFETIME_MIN_SECS: u64 = 5;
/// Longest accepted server-nonce lifetime. The nonce exists to bound proof
/// freshness below the proof acceptance window (300 s) — keep it there.
pub const DPOP_NONCE_LIFETIME_MAX_SECS: u64 = 300;

/// DPoP (RFC 9449) settings (`[dpop]` section).
///
/// The whole section is optional and every key has a default, so existing
/// configuration files keep booting unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpopConfig {
    /// Server-provided nonces (`[dpop.nonce]`, RFC 9449 §8/§9). Disabled by
    /// default — replay protection then rides on single-use `jti` plus the
    /// proof acceptance window, as before.
    #[serde(default)]
    pub nonce: DpopNonceConfig,
}

impl DpopConfig {
    /// Boot-time validation: reject out-of-range values with a clear error
    /// instead of silently clamping them.
    pub fn validate(&self) -> Result<(), IssuerdError> {
        let lifetime = self.nonce.lifetime_secs;
        if !(DPOP_NONCE_LIFETIME_MIN_SECS..=DPOP_NONCE_LIFETIME_MAX_SECS).contains(&lifetime) {
            return Err(IssuerdError::InvalidRequest(format!(
                "dpop.nonce.lifetime_secs must be within \
                 {DPOP_NONCE_LIFETIME_MIN_SECS}..={DPOP_NONCE_LIFETIME_MAX_SECS} seconds, \
                 got {lifetime}"
            )));
        }
        Ok(())
    }
}

/// How the server treats the DPoP `nonce` claim (`[dpop.nonce] mode`).
///
/// Nonces are unguessable random values the server issues via the
/// `DPoP-Nonce` response header and the client echoes in the proof's `nonce`
/// claim; each nonce is single-use and expires after `lifetime_secs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpopNonceMode {
    /// No nonces issued or verified (default; pre-feature behavior).
    #[default]
    Disabled,
    /// A fresh nonce rides every response to a proof-carrying request. A
    /// proof without a `nonce` claim is accepted; a proof carrying an
    /// unknown/stale nonce is challenged with `use_dpop_nonce` (the
    /// RFC 9449 §8/§9 retry path — compliant clients recover transparently).
    Supported,
    /// Every proof MUST carry a live server-issued nonce; absence or an
    /// unknown/stale value is rejected with `use_dpop_nonce` plus a fresh
    /// nonce. Requests without a `DPoP` proof header are unaffected.
    Required,
}

/// Server-provided DPoP nonces (`[dpop.nonce]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopNonceConfig {
    /// Issuance/verification mode (`"disabled" | "supported" | "required"`).
    pub mode: DpopNonceMode,
    /// Nonce lifetime in seconds — the cache TTL. Default 30, accepted range
    /// 5–300; out-of-range values abort the boot.
    pub lifetime_secs: u64,
}

impl Default for DpopNonceConfig {
    fn default() -> Self {
        Self {
            mode: DpopNonceMode::Disabled,
            lifetime_secs: DPOP_NONCE_LIFETIME_DEFAULT_SECS,
        }
    }
}

/// Default distributed invocation allowance for each client and subject.
pub const MCP_INVOCATION_RATE_LIMIT_DEFAULT_PER_MINUTE: u32 = 60;

fn default_mcp_require_dpop() -> bool {
    true
}

fn default_mcp_invocation_rate_limit_per_minute() -> u32 {
    MCP_INVOCATION_RATE_LIMIT_DEFAULT_PER_MINUTE
}

/// MCP (Model Context Protocol) settings (`[mcp]` section).
///
/// The whole section and every key are optional. Defaults keep existing
/// configurations booting with the MCP surface disabled and strict DPoP
/// metadata enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Master switch for the MCP surface. Default `false`: the MCP and
    /// protected-resource metadata routes answer 404 and any `resource`
    /// parameter is refused with `invalid_target`.
    #[serde(default)]
    pub enabled: bool,
    /// Require DPoP-bound tokens and proofs. `false` is an explicit Bearer
    /// compatibility choice, not a downgrade of the strict step-up profile.
    #[serde(default = "default_mcp_require_dpop")]
    pub require_dpop: bool,
    /// Distributed tool-invocation allowance per client and subject per minute.
    #[serde(default = "default_mcp_invocation_rate_limit_per_minute")]
    pub invocation_rate_limit_per_minute: u32,
    /// Exact allowed browser origins. Empty rejects every present `Origin`
    /// when MCP Origin validation is enforced; requests without it remain
    /// available to non-browser clients.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Independent rollout gate for operation-bound step-up behavior.
    #[serde(default)]
    pub step_up: McpStepUpConfig,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_dpop: true,
            invocation_rate_limit_per_minute: MCP_INVOCATION_RATE_LIMIT_DEFAULT_PER_MINUTE,
            allowed_origins: Vec::new(),
            step_up: McpStepUpConfig::default(),
        }
    }
}

/// Operation-bound MCP step-up settings (`[mcp.step_up]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpStepUpConfig {
    /// Enable only after every cluster node and approval route supports the
    /// operation-bound flow. Independent of `[mcp].enabled`.
    #[serde(default)]
    pub enabled: bool,
}

/// Crypto settings (`[crypto]` section).
///
/// Currently only envelope encryption of signing keys at rest. The whole
/// section is optional and defaults to "not configured".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoSettings {
    /// Envelope encryption of signing keys at rest (`[crypto.key_encryption]`,
    /// PostgreSQL storage only). Absent keeps the pre-encryption behavior —
    /// signing keys are stored in plaintext — and the daemon logs a startup
    /// WARN on PostgreSQL deployments.
    pub key_encryption: Option<KeyEncryptionConfig>,
}

impl CryptoSettings {
    /// Validate `[crypto.key_encryption]` (when present) and build the KEK
    /// provider. `Ok(None)` means the section is absent (plaintext mode).
    /// Invalid configuration — malformed base64, a key that is not exactly
    /// 32 bytes, empty/overlong/duplicate key ids — is a boot-fatal error.
    pub fn build_kek_provider(
        &self,
    ) -> Result<Option<std::sync::Arc<dyn issuerd_core::KeyEncryptionKeyProvider>>, IssuerdError>
    {
        self.key_encryption
            .as_ref()
            .map(KeyEncryptionConfig::build_provider)
            .transpose()
    }
}

/// Envelope encryption of signing keys at rest (`[crypto.key_encryption]`).
///
/// The Key Encryption Key (KEK) encrypts the cluster-wide JWT signing keys
/// before they are written to PostgreSQL, so a database dump yields only
/// ciphertext. The KEK itself must never be stored in the database; source it
/// from the environment (`ISSUERD_CRYPTO__KEY_ENCRYPTION__KEY_BASE64`) or a
/// permission-protected config file. Generate one with `openssl rand -base64 32`.
///
/// PostgreSQL-only: with any other storage backend the section is ignored
/// (boot WARN) — protect JSON snapshots at the filesystem level instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEncryptionConfig {
    /// Identifier of the active KEK, stored on every encrypted row so a later
    /// rotation knows which KEK must decrypt it. Non-empty, at most 64 chars,
    /// unique across `previous_keys`.
    pub key_id: String,
    /// Base64-encoded 32-byte KEK (AES-256). Prefer the
    /// `ISSUERD_CRYPTO__KEY_ENCRYPTION__KEY_BASE64` env var over the file.
    pub key_base64: String,
    /// Previous KEKs, accepted for decryption only: the KEK-rotation window.
    /// File-only setting (env vars cannot index into arrays).
    #[serde(default)]
    pub previous_keys: Vec<PreviousKekConfig>,
}

impl KeyEncryptionConfig {
    fn build_provider(
        &self,
    ) -> Result<std::sync::Arc<dyn issuerd_core::KeyEncryptionKeyProvider>, IssuerdError> {
        let active = decode_kek(&self.key_base64)?;
        let mut previous = Vec::with_capacity(self.previous_keys.len());
        for prev in &self.previous_keys {
            previous.push((prev.key_id.clone(), decode_kek(&prev.key_base64)?));
        }
        let provider =
            issuerd_storage::Aes256GcmKekProvider::new(self.key_id.clone(), active, previous)?;
        Ok(std::sync::Arc::new(provider))
    }
}

/// A retired KEK kept for decryption during a KEK-rotation window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousKekConfig {
    /// The `key_id` the KEK had while it was active (matches the `kek_kid`
    /// stored on rows it encrypted).
    pub key_id: String,
    /// Base64-encoded 32-byte KEK.
    pub key_base64: String,
}

/// Decode a configured KEK: standard base64 of exactly 32 bytes (AES-256).
fn decode_kek(key_base64: &str) -> Result<[u8; 32], IssuerdError> {
    use base64::Engine;
    let bytes =
        base64::engine::general_purpose::STANDARD
            .decode(key_base64.trim())
            .map_err(|e| {
                IssuerdError::KeyEncryption(format!("KEK key_base64 is not valid base64: {e}"))
            })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        IssuerdError::KeyEncryption(format!(
            "KEK must decode to exactly 32 bytes (AES-256), got {}",
            bytes.len()
        ))
    })
}

/// Outbound HTTP configuration (`[outbound_http]` section).
///
/// Every outbound HTTPS call the server makes — identity-broker and client
/// JWKS fetches, pairwise `sector_identifier_uri` documents, back-channel
/// logout POSTs — rides reqwest/rustls with the public webpki roots. A
/// deployment behind a private CA (corporate proxy, hermetic test rig) adds
/// its roots here; the extra bundle is ADDITIVE to the public roots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutboundHttpConfig {
    /// Path to a PEM bundle of additional root CA certificates (the file may
    /// hold several). A missing file, unparseable content, or a bundle with
    /// zero valid certificates aborts the boot (fail closed — an operator
    /// typo must not silently fall back to public roots only).
    pub extra_ca_bundle: Option<PathBuf>,
    /// **Test rigs and explicit internal endpoints only** — allow the
    /// SSRF-guarded outbound calls (client `jwks_url` documents, pairwise
    /// `sector_identifier_uri` documents, JAR-by-reference `request_uri`
    /// objects, and back-channel logout POSTs) to dial private, loopback,
    /// link-local, and otherwise non-publicly-routable addresses. The
    /// https-only scheme check, the no-redirect policy, applicable body-size
    /// caps, and the timeout stay enforced. Never enable in production: the
    /// guard is what keeps configured URLs from probing the internal network.
    /// Default false.
    #[serde(default)]
    pub allow_private_addresses: bool,
    /// Allow the identity-broker calls (discovery, JWKS, token, userinfo, the
    /// admin test-connection probe) to dial private, loopback, link-local,
    /// and otherwise non-publicly-routable addresses, directly or through a
    /// redirect — for an IdP on the internal network. The response-size cap
    /// stays. Enabling it lets every admin who can configure an identity
    /// provider (`manage-realm` in any realm) point server-side requests at
    /// the internal network. Default false.
    #[serde(default)]
    pub allow_private_identity_providers: bool,
}

impl OutboundHttpConfig {
    /// Load the configured extra root certificates. An empty root list when
    /// the knob is unset; a bad path, unparseable content, or an empty bundle
    /// is a boot-fatal error.
    pub fn load_extra_roots(&self) -> Result<Vec<reqwest::Certificate>, IssuerdError> {
        let roots = if let Some(path) = &self.extra_ca_bundle {
            let bytes = std::fs::read(path).map_err(|e| {
                IssuerdError::ServerError(format!(
                    "outbound_http.extra_ca_bundle: cannot read {}: {e}",
                    path.display()
                ))
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|e| {
                IssuerdError::ServerError(format!(
                    "outbound_http.extra_ca_bundle: {} is not a valid PEM certificate bundle: {e}",
                    path.display()
                ))
            })?;
            if certs.is_empty() {
                return Err(IssuerdError::ServerError(format!(
                    "outbound_http.extra_ca_bundle: {} contains no certificates",
                    path.display()
                )));
            }
            certs
        } else {
            Vec::new()
        };
        Ok(roots)
    }
}

/// Login-theme asset configuration (`[themes]` section).
///
/// Themes are directories of static assets under `dir`: the realm's
/// `login_theme` selects the directory served at `/realms/{realm}/theme/...`,
/// with a per-file fallback to the built-in `issuerd` theme. A theme may
/// also carry `messages_{locale}.json` message-bundle overrides that merge
/// over the built-in bundles (see `crate::i18n`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemesConfig {
    /// Root directory containing one subdirectory per theme. Relative paths
    /// resolve against the daemon's working directory.
    pub dir: PathBuf,
}

impl Default for ThemesConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("themes"),
        }
    }
}

/// SMTP/email configuration (`[smtp]` section).
///
/// Email sending is **disabled by default**: the server wires a no-op sender
/// until `enabled = true`, and verification emails then fail loudly instead
/// of being silently dropped.
///
/// Realm-level overrides follow the Keycloak model: realm attributes under
/// `smtpServer.*` (e.g. `smtpServer.host`, `smtpServer.from`,
/// `smtpServer.fromDisplayName`, `smtpServer.user`, `smtpServer.password`,
/// `smtpServer.starttls`, `smtpServer.ssl`, `smtpServer.port`,
/// `smtpServer.replyTo`) override the global values for that realm only;
/// `enabled` remains a global gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub from: String,
    pub from_display: Option<String>,
    pub reply_to: Option<String>,
    pub starttls: bool,
    pub ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 25,
            from: "issuerd@localhost".to_string(),
            from_display: None,
            reply_to: None,
            starttls: false,
            ssl: false,
            username: None,
            password: None,
        }
    }
}

impl SmtpConfig {
    /// Resolve the effective SMTP settings for a realm by merging
    /// `smtpServer.*` realm attributes over this global configuration.
    ///
    /// The global `username`/`password` belong to the global relay: they are
    /// inherited only while the realm's effective host, port, `ssl` and
    /// `starttls` all equal the global ones. A realm that changes any of them
    /// must supply its own `smtpServer.user`/`smtpServer.password`, so a realm
    /// admin cannot make the server authenticate to a host they choose with
    /// the operator's credentials.
    pub fn for_realm(&self, realm: &issuerd_core::Realm) -> Self {
        let attr = |key: &str| realm.attributes.get(&format!("smtpServer.{key}"));
        let flag = |key: &str, default: bool| attr(key).map(|v| v == "true").unwrap_or(default);
        let host = attr("host").cloned().unwrap_or_else(|| self.host.clone());
        let port = attr("port").and_then(|v| v.parse().ok()).unwrap_or(self.port);
        let starttls = flag("starttls", self.starttls);
        let ssl = flag("ssl", self.ssl);
        let global_transport =
            host == self.host && port == self.port && starttls == self.starttls && ssl == self.ssl;
        let global_secret = |v: &Option<String>| v.clone().filter(|_| global_transport);
        Self {
            enabled: self.enabled,
            host,
            port,
            from: attr("from").cloned().unwrap_or_else(|| self.from.clone()),
            from_display: attr("fromDisplayName").cloned().or_else(|| self.from_display.clone()),
            reply_to: attr("replyTo").cloned().or_else(|| self.reply_to.clone()),
            starttls,
            ssl,
            username: attr("user").cloned().or_else(|| global_secret(&self.username)),
            password: attr("password").cloned().or_else(|| global_secret(&self.password)),
        }
    }
}

/// Two self-signed test root CAs (P-256, CN "Issuerd Test Root CA 1/2") in
/// one PEM bundle. `pub(crate)`: the `outbound_http` module's builder test
/// reuses it.
#[cfg(test)]
pub(crate) const TEST_CA_BUNDLE: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlzCCAT2gAwIBAgIUcUefgec+cRxhBR1jLoWQIvQzDAMwCgYIKoZIzj0EAwIw\n\
ITEfMB0GA1UEAwwWSXNzdWVyZCBUZXN0IFJvb3QgQ0EgMTAeFw0yNjEwMTExMjM2\n\
NTZaFw0zNjEwMDgxMjM2NTZaMCExHzAdBgNVBAMMFklzc3VlcmQgVGVzdCBSb290\n\
IENBIDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQu0vi1aIYQyp8tVOWJEWQ8\n\
S+kbGuFoqdUC9MoP8msh7f+J41XStvkBoNpHk+HmitWK2Qhy/87ApgY5yEO1T4Pr\n\
o1MwUTAdBgNVHQ4EFgQUCW4VegNmq1RUny3Vd6Iyzy75k6kwHwYDVR0jBBgwFoAU\n\
CW4VegNmq1RUny3Vd6Iyzy75k6kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD\n\
AgNIADBFAiA2OPBMyCmEUhrcjK1276F3V1yCoxFIxPkQvkIb2owsggIhAKbKyiIP\n\
24PqbhXyX1NX2ua29G6a3iw0bE8cYyJMuED3\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
MIIBljCCAT2gAwIBAgIUC930DsPyCirPWa+66Fa5kPKlgaowCgYIKoZIzj0EAwIw\n\
ITEfMB0GA1UEAwwWSXNzdWVyZCBUZXN0IFJvb3QgQ0EgMjAeFw0yNjEwMTExMjM2\n\
NTZaFw0zNjEwMDgxMjM2NTZaMCExHzAdBgNVBAMMFklzc3VlcmQgVGVzdCBSb290\n\
IENBIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1jiXesqhcNE5llJg+M+uU\n\
V5jHbmIeBZZEr8VX3SlDDrdTK4r3FIyl0ac3bkKmlbdjq9KqGsypVppIr41QUti/\n\
o1MwUTAdBgNVHQ4EFgQUrfs5KKraDHH/LzD1gD5E4UNDpSwwHwYDVR0jBBgwFoAU\n\
rfs5KKraDHH/LzD1gD5E4UNDpSwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD\n\
AgNHADBEAiA1ZQXpVoozsS20Oxe4VEtNMW879GrDGg5GcIgou+93WgIgFLkrIjV8\n\
3O4kYIoY4KWau+mzQNF+FRhTLNW01/ArJF4=\n\
-----END CERTIFICATE-----\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_path(name: &str, ext: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("issuerd_server_config_test_{}", name));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!("config.{}", ext));
        (path, dir)
    }

    #[test]
    fn default_config_values() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.bind, "0.0.0.0");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.issuer_url, "http://localhost:8080");
        assert!(cfg.tls.is_none());
        assert!(matches!(cfg.storage, StorageConfig::InMemory));
        assert!(cfg.redis.is_none());
        assert_eq!(cfg.logging.format, "pretty");
        assert_eq!(cfg.logging.level, "info");
        assert!(cfg.web_ui.enabled);
        assert!(cfg.proxy.trusted_proxies.is_empty());
        assert!(cfg.proxy.trust_x_forwarded_for);
        assert!(cfg.proxy.trust_x_real_ip);
        assert!(cfg.cors.allowed_origins.is_empty());
        assert!(!cfg.cluster.enabled);
        assert!(cfg.cluster.node_id.is_none());
        assert!(cfg.cluster.redis_nodes.is_empty());
        assert_eq!(cfg.cluster.jwks_refresh_interval_secs, 30);
        assert!(!cfg.smtp.enabled);
        assert_eq!(cfg.smtp.host, "127.0.0.1");
        assert_eq!(cfg.smtp.port, 25);
        assert_eq!(cfg.smtp.from, "issuerd@localhost");
        assert!(!cfg.smtp.starttls);
        assert!(!cfg.smtp.ssl);
        assert_eq!(cfg.cache.read_cache_ttl_secs, 60);
        assert_eq!(cfg.oauth.auth_code_ttl_secs, 600);
    }

    #[test]
    fn smtp_for_realm_merges_overrides() {
        let base = SmtpConfig {
            enabled: true,
            username: Some("global-user".to_string()),
            ..SmtpConfig::default()
        };
        let mut realm = issuerd_core::Realm::default();
        realm
            .attributes
            .insert("smtpServer.host".to_string(), "mail.realm.example".to_string());
        realm.attributes.insert("smtpServer.port".to_string(), "2525".to_string());
        realm
            .attributes
            .insert("smtpServer.from".to_string(), "realm@example.com".to_string());
        realm.attributes.insert("smtpServer.starttls".to_string(), "true".to_string());

        let merged = base.for_realm(&realm);
        assert_eq!(merged.host, "mail.realm.example");
        assert_eq!(merged.port, 2525);
        assert_eq!(merged.from, "realm@example.com");
        assert!(merged.starttls);
        assert!(merged.enabled);
        // Global credentials never follow a realm-chosen transport.
        assert_eq!(merged.username, None);

        // No attributes -> identical to global.
        let plain = issuerd_core::Realm::default();
        let merged = base.for_realm(&plain);
        assert_eq!(merged.host, base.host);
        assert_eq!(merged.port, base.port);
        assert_eq!(merged.username.as_deref(), Some("global-user"));
    }

    #[test]
    fn smtp_for_realm_withholds_global_credentials_from_realm_transport() {
        let base = SmtpConfig {
            enabled: true,
            host: "relay.operator.example".to_string(),
            port: 587,
            starttls: true,
            username: Some("global-user".to_string()),
            password: Some("global-secret".to_string()),
            ..SmtpConfig::default()
        };
        let realm_with = |pairs: &[(&str, &str)]| {
            let mut realm = issuerd_core::Realm::default();
            for (k, v) in pairs {
                realm.attributes.insert(format!("smtpServer.{k}"), v.to_string());
            }
            realm
        };

        for overrides in [
            vec![("host", "mx.attacker.example")],
            vec![("port", "2525")],
            vec![("ssl", "true")],
            vec![("starttls", "false")],
            vec![("host", "10.0.0.5"), ("port", "25"), ("starttls", "false")],
        ] {
            let merged = base.for_realm(&realm_with(&overrides));
            assert_eq!(merged.username, None, "{overrides:?}");
            assert_eq!(merged.password, None, "{overrides:?}");
        }

        // A realm user without its own password gets no global password.
        let merged =
            base.for_realm(&realm_with(&[("host", "mx.attacker.example"), ("user", "realm-user")]));
        assert_eq!(merged.username.as_deref(), Some("realm-user"));
        assert_eq!(merged.password, None);

        // Realm-supplied credentials are used for a realm transport.
        let merged = base.for_realm(&realm_with(&[
            ("host", "mail.realm.example"),
            ("user", "realm-user"),
            ("password", "realm-secret"),
        ]));
        assert_eq!(merged.username.as_deref(), Some("realm-user"));
        assert_eq!(merged.password.as_deref(), Some("realm-secret"));

        // Overrides that leave the global transport unchanged keep the
        // global credentials, as do non-transport overrides.
        for overrides in [
            vec![
                ("host", "relay.operator.example"),
                ("port", "587"),
                ("starttls", "true"),
            ],
            vec![("from", "realm@example.com"), ("fromDisplayName", "Realm")],
        ] {
            let merged = base.for_realm(&realm_with(&overrides));
            assert_eq!(merged.username.as_deref(), Some("global-user"), "{overrides:?}");
            assert_eq!(merged.password.as_deref(), Some("global-secret"), "{overrides:?}");
        }
    }

    #[test]
    fn load_cluster_section_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("cluster_toml", "toml");
        fs::write(
            &path,
            r#"
[cluster]
enabled = true
node_id = "node-1"
redis_nodes = ["redis://r1:6379", "redis://r2:6379"]
jwks_refresh_interval_secs = 15
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert!(cfg.cluster.enabled);
        assert_eq!(cfg.cluster.node_id.as_deref(), Some("node-1"));
        assert_eq!(cfg.cluster.redis_nodes.len(), 2);
        assert_eq!(cfg.cluster.jwks_refresh_interval_secs, 15);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_cluster_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISSUERD_CLUSTER__ENABLED", "true");
        std::env::set_var("ISSUERD_CLUSTER__JWKS_REFRESH_INTERVAL_SECS", "7");
        let cfg = ServerConfig::load(None).unwrap();
        assert!(cfg.cluster.enabled);
        assert_eq!(cfg.cluster.jwks_refresh_interval_secs, 7);
        std::env::remove_var("ISSUERD_CLUSTER__ENABLED");
        std::env::remove_var("ISSUERD_CLUSTER__JWKS_REFRESH_INTERVAL_SECS");
    }

    #[test]
    fn cluster_node_id_resolution() {
        let cluster = ClusterConfig {
            node_id: Some("explicit".to_string()),
            ..Default::default()
        };
        assert_eq!(cluster.resolved_node_id(), "explicit");
        let fallback = ClusterConfig::default().resolved_node_id();
        assert!(!fallback.is_empty());
    }

    #[test]
    fn load_from_toml_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("toml_ok", "toml");
        fs::write(
            &path,
            r#"
bind = "127.0.0.1"
port = 9090
issuer_url = "http://example.com"
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1");
        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.issuer_url, "http://example.com");
        // Sections absent from an existing config file keep their defaults
        // (backward compatibility).
        assert_eq!(cfg.cache.read_cache_ttl_secs, 60);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_yaml_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("yaml_ok", "yaml");
        fs::write(&path, "bind: 127.0.0.1\nport: 9091\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1");
        assert_eq!(cfg.port, 9091);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_empty_yaml_file_uses_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        // serde-saphyr reads an empty document as an empty mapping, so an
        // empty YAML file merges nothing and defaults apply — same lenient
        // behavior as an empty TOML file (serde_yaml used to reject it).
        let (path, dir) = temp_path("yaml_empty", "yaml");
        fs::write(&path, "").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.port, 8080);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_yaml_file_with_null_and_inline_list() {
        let _guard = ENV_LOCK.lock().unwrap();
        // YAML `null` maps to `None` for Option fields, and inline flow lists
        // parse — the two shapes the shipped provision/config examples use.
        let (path, dir) = temp_path("yaml_null", "yaml");
        fs::write(
            &path,
            "redis: null\nport: 9094\nproxy:\n  trusted_proxies: [\"10.0.0.1\", \"10.0.0.2\"]\n",
        )
        .unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.port, 9094);
        assert_eq!(cfg.redis, None);
        assert_eq!(cfg.proxy.trusted_proxies, vec!["10.0.0.1", "10.0.0.2"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_json_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("json_ok", "json");
        fs::write(&path, r#"{"bind":"127.0.0.1","port":9092}"#).unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1");
        assert_eq!(cfg.port, 9092);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_yml_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("yml_ok", "yml");
        fs::write(&path, "bind: 127.0.0.1\nport: 9093\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1");
        assert_eq!(cfg.port, 9093);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_nonexistent_path_uses_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Defensively remove any leaked env var so other tests don't pollute us.
        std::env::remove_var("ISSUERD_BIND");
        std::env::remove_var("ISSUERD_PORT");
        std::env::remove_var("ISSUERD_ISSUER_URL");
        let cfg =
            ServerConfig::load(Some(std::path::PathBuf::from("/nonexistent/path.toml"))).unwrap();
        assert_eq!(cfg.bind, "0.0.0.0");
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn load_invalid_config_returns_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("toml_bad", "toml");
        fs::write(&path, "port = \"not_a_number\"").unwrap();
        let result = ServerConfig::load(Some(path));
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Set an environment variable that should override the default issuer_url.
        // Use issuer_url because no other test asserts on it.
        std::env::set_var("ISSUERD_ISSUER_URL", "http://env-override:9999");
        let cfg = ServerConfig::load(None).unwrap();
        assert_eq!(cfg.issuer_url, "http://env-override:9999");
        std::env::remove_var("ISSUERD_ISSUER_URL");
    }

    #[test]
    fn bootstrap_admin_password_unset_by_default_and_env_overridable() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("ISSUERD_BOOTSTRAP_ADMIN_PASSWORD");
        assert!(ServerConfig::default().bootstrap_admin_password.is_none());
        assert!(ServerConfig::load(None).unwrap().bootstrap_admin_password.is_none());
        std::env::set_var("ISSUERD_BOOTSTRAP_ADMIN_PASSWORD", "from-env");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_BOOTSTRAP_ADMIN_PASSWORD");
        assert_eq!(cfg.bootstrap_admin_password.as_deref(), Some("from-env"));
    }

    // ------------------------------------------------------------------
    // [crypto.key_encryption]
    // ------------------------------------------------------------------

    fn test_kek_base64(byte: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    #[test]
    fn key_encryption_absent_by_default() {
        let cfg = ServerConfig::default();
        assert!(cfg.crypto.key_encryption.is_none());
        assert!(cfg.crypto.build_kek_provider().unwrap().is_none());
        assert!(ServerConfig::generate_example().crypto.key_encryption.is_none());
    }

    #[test]
    fn key_encryption_loads_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("crypto_toml", "toml");
        fs::write(
            &path,
            format!(
                r#"
[crypto.key_encryption]
key_id = "kek-2026-01"
key_base64 = "{}"

[[crypto.key_encryption.previous_keys]]
key_id = "kek-2025-01"
key_base64 = "{}"
"#,
                test_kek_base64(7),
                test_kek_base64(9)
            ),
        )
        .unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        let kec = cfg.crypto.key_encryption.as_ref().expect("section parsed");
        assert_eq!(kec.key_id, "kek-2026-01");
        assert_eq!(kec.previous_keys.len(), 1);
        assert_eq!(kec.previous_keys[0].key_id, "kek-2025-01");

        // The section builds a working provider (round-trip through both KEKs).
        let kek = cfg.crypto.build_kek_provider().unwrap().expect("provider");
        assert_eq!(kek.active_key_id(), "kek-2026-01");
        let blob = kek.encrypt(b"der").unwrap();
        assert_eq!(kek.decrypt("kek-2026-01", &blob).unwrap(), b"der");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_encryption_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISSUERD_CRYPTO__KEY_ENCRYPTION__KEY_ID", "env-kek");
        std::env::set_var("ISSUERD_CRYPTO__KEY_ENCRYPTION__KEY_BASE64", test_kek_base64(3));
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_CRYPTO__KEY_ENCRYPTION__KEY_ID");
        std::env::remove_var("ISSUERD_CRYPTO__KEY_ENCRYPTION__KEY_BASE64");
        let kec = cfg.crypto.key_encryption.as_ref().expect("env section parsed");
        assert_eq!(kec.key_id, "env-kek");
        assert!(cfg.crypto.build_kek_provider().unwrap().is_some());
    }

    #[test]
    fn key_encryption_invalid_configs_fail_boot_validation() {
        let valid = test_kek_base64(1);
        for (label, kec) in [
            (
                "bad base64",
                KeyEncryptionConfig {
                    key_id: "k".to_string(),
                    key_base64: "!!! not base64 !!!".to_string(),
                    previous_keys: vec![],
                },
            ),
            (
                "31-byte key",
                KeyEncryptionConfig {
                    key_id: "k".to_string(),
                    key_base64: {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.encode([1u8; 31])
                    },
                    previous_keys: vec![],
                },
            ),
            (
                "33-byte key",
                KeyEncryptionConfig {
                    key_id: "k".to_string(),
                    key_base64: {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.encode([1u8; 33])
                    },
                    previous_keys: vec![],
                },
            ),
            (
                "empty key_id",
                KeyEncryptionConfig {
                    key_id: String::new(),
                    key_base64: valid.clone(),
                    previous_keys: vec![],
                },
            ),
            (
                "duplicate key_id",
                KeyEncryptionConfig {
                    key_id: "dup".to_string(),
                    key_base64: valid.clone(),
                    previous_keys: vec![PreviousKekConfig {
                        key_id: "dup".to_string(),
                        key_base64: test_kek_base64(2),
                    }],
                },
            ),
            (
                "bad previous key",
                KeyEncryptionConfig {
                    key_id: "k".to_string(),
                    key_base64: valid.clone(),
                    previous_keys: vec![PreviousKekConfig {
                        key_id: "old".to_string(),
                        key_base64: "c2hvcnQ=".to_string(), // 5 bytes
                    }],
                },
            ),
        ] {
            let settings = CryptoSettings {
                key_encryption: Some(kec),
            };
            assert!(settings.build_kek_provider().is_err(), "{label} must fail validation");
        }
    }

    // ------------------------------------------------------------------
    // [outbound_http]
    // ------------------------------------------------------------------

    #[test]
    fn outbound_http_absent_by_default() {
        let cfg = ServerConfig::default();
        assert!(cfg.outbound_http.extra_ca_bundle.is_none());
        assert!(cfg.outbound_http.load_extra_roots().unwrap().is_empty());
        assert!(ServerConfig::generate_example().outbound_http.extra_ca_bundle.is_none());
        // The SSRF guard's public-IP check is on unless explicitly lifted.
        assert!(!cfg.outbound_http.allow_private_addresses);
        assert!(!ServerConfig::generate_example().outbound_http.allow_private_addresses);
        // The IdP calls' SSRF gate is on unless explicitly lifted.
        assert!(!cfg.outbound_http.allow_private_identity_providers);
        assert!(!ServerConfig::generate_example().outbound_http.allow_private_identity_providers);
    }

    #[test]
    fn outbound_http_allow_private_identity_providers_loads() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("outbound_http_private_idp_toml", "toml");
        fs::write(&path, "[outbound_http]\nallow_private_identity_providers = true\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert!(cfg.outbound_http.allow_private_identity_providers);
        // Independent of the test-rig flag for attacker-influenced URLs.
        assert!(!cfg.outbound_http.allow_private_addresses);
        let _ = fs::remove_dir_all(&dir);

        std::env::set_var("ISSUERD_OUTBOUND_HTTP__ALLOW_PRIVATE_IDENTITY_PROVIDERS", "true");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_OUTBOUND_HTTP__ALLOW_PRIVATE_IDENTITY_PROVIDERS");
        assert!(cfg.outbound_http.allow_private_identity_providers);
    }

    #[test]
    fn outbound_http_allow_private_addresses_loads() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("outbound_http_private_toml", "toml");
        fs::write(&path, "[outbound_http]\nallow_private_addresses = true\n").unwrap();
        let cfg = ServerConfig::load(Some(path.clone())).unwrap();
        assert!(cfg.outbound_http.allow_private_addresses);
        // Absent in the file: the default (false) applies.
        fs::write(&path, "[outbound_http]\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert!(!cfg.outbound_http.allow_private_addresses);
        let _ = fs::remove_dir_all(&dir);

        std::env::set_var("ISSUERD_OUTBOUND_HTTP__ALLOW_PRIVATE_ADDRESSES", "true");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_OUTBOUND_HTTP__ALLOW_PRIVATE_ADDRESSES");
        assert!(cfg.outbound_http.allow_private_addresses);
    }

    #[test]
    fn outbound_http_loads_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("outbound_http_toml", "toml");
        fs::write(&path, "[outbound_http]\nextra_ca_bundle = \"/etc/ssl/corp.pem\"\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(
            cfg.outbound_http.extra_ca_bundle.as_deref(),
            Some(std::path::Path::new("/etc/ssl/corp.pem"))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbound_http_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISSUERD_OUTBOUND_HTTP__EXTRA_CA_BUNDLE", "/tmp/roots.pem");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_OUTBOUND_HTTP__EXTRA_CA_BUNDLE");
        assert_eq!(
            cfg.outbound_http.extra_ca_bundle.as_deref(),
            Some(std::path::Path::new("/tmp/roots.pem"))
        );
    }

    #[test]
    fn outbound_http_bundle_loading_failures_fail_closed() {
        let _guard = ENV_LOCK.lock().unwrap();

        // Missing file.
        let cfg = OutboundHttpConfig {
            extra_ca_bundle: Some(PathBuf::from("/nonexistent/roots.pem")),
            allow_private_addresses: false,
            allow_private_identity_providers: false,
        };
        let err = cfg.load_extra_roots().unwrap_err();
        assert!(err.to_string().contains("extra_ca_bundle"), "{err}");
        assert!(err.to_string().contains("cannot read"), "{err}");

        let (path, dir) = temp_path("outbound_garbage", "pem");

        // Malformed PEM block (bad base64 in a CERTIFICATE section).
        fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let cfg = OutboundHttpConfig {
            extra_ca_bundle: Some(path.clone()),
            allow_private_addresses: false,
            allow_private_identity_providers: false,
        };
        let err = cfg.load_extra_roots().unwrap_err();
        assert!(err.to_string().contains("not a valid PEM"), "{err}");

        // A readable file with zero certificates (plain text / empty file) —
        // fail closed rather than silently trusting nothing extra.
        for content in ["this is not a PEM bundle\n", ""] {
            fs::write(&path, content).unwrap();
            let cfg = OutboundHttpConfig {
                extra_ca_bundle: Some(path.clone()),
                allow_private_addresses: false,
                allow_private_identity_providers: false,
            };
            let err = cfg.load_extra_roots().unwrap_err();
            assert!(err.to_string().contains("no certificates"), "{err}");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbound_http_valid_bundle_loads_all_certificates() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("outbound_ok", "pem");
        fs::write(&path, TEST_CA_BUNDLE).unwrap();
        let cfg = OutboundHttpConfig {
            extra_ca_bundle: Some(path.clone()),
            allow_private_addresses: false,
            allow_private_identity_providers: false,
        };
        let certs = cfg.load_extra_roots().unwrap();
        assert_eq!(certs.len(), 2, "both bundle certificates load");
        let _ = fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // [oauth]
    // ------------------------------------------------------------------

    #[test]
    fn oauth_default_auth_code_ttl_unchanged() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.oauth.auth_code_ttl_secs, AUTH_CODE_TTL_DEFAULT_SECS);
        assert_eq!(cfg.oauth.auth_code_ttl_secs, 600);
        cfg.oauth.validate().unwrap();
        // The generated example carries the same default.
        assert_eq!(ServerConfig::generate_example().oauth.auth_code_ttl_secs, 600);
    }

    #[test]
    fn oauth_loads_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("oauth_toml", "toml");
        fs::write(&path, "[oauth]\nauth_code_ttl_secs = 60\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.oauth.auth_code_ttl_secs, 60);
        cfg.oauth.validate().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oauth_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISSUERD_OAUTH__AUTH_CODE_TTL_SECS", "45");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_OAUTH__AUTH_CODE_TTL_SECS");
        assert_eq!(cfg.oauth.auth_code_ttl_secs, 45);
    }

    #[test]
    fn oauth_validate_enforces_bounds() {
        for ok in [AUTH_CODE_TTL_MIN_SECS, 60, AUTH_CODE_TTL_MAX_SECS] {
            OAuthConfig {
                auth_code_ttl_secs: ok,
            }
            .validate()
            .unwrap_or_else(|e| panic!("{ok}s must pass validation: {e}"));
        }
        for bad in [0, 9, 601, 6000] {
            assert!(
                OAuthConfig {
                    auth_code_ttl_secs: bad
                }
                .validate()
                .is_err(),
                "{bad}s must fail validation"
            );
        }
    }

    #[test]
    fn auth_code_ttl_realm_override() {
        let oauth = OAuthConfig {
            auth_code_ttl_secs: 600,
        };
        let mut realm = issuerd_core::Realm::default();
        // Absent attribute -> server default.
        assert_eq!(oauth.auth_code_ttl(&realm), std::time::Duration::from_secs(600));
        // A valid override is honored (the FAPI 2.0 profile value).
        realm
            .attributes
            .insert(OAuthConfig::REALM_AUTH_CODE_TTL_ATTRIBUTE.to_string(), "60".to_string());
        assert_eq!(oauth.auth_code_ttl(&realm), std::time::Duration::from_secs(60));
        // Malformed or out-of-range attributes fall back to the server value.
        for bad in ["abc", "", "5", "601", "-10", "60.5"] {
            realm
                .attributes
                .insert(OAuthConfig::REALM_AUTH_CODE_TTL_ATTRIBUTE.to_string(), bad.to_string());
            assert_eq!(
                oauth.auth_code_ttl(&realm),
                std::time::Duration::from_secs(600),
                "attribute {bad:?} must fall back to the server default"
            );
        }
        // The fallback base is the configured server value, not a hardcoded one.
        let strict = OAuthConfig {
            auth_code_ttl_secs: 30,
        };
        realm.attributes.clear();
        assert_eq!(strict.auth_code_ttl(&realm), std::time::Duration::from_secs(30));
    }

    // ------------------------------------------------------------------
    // [dpop]
    // ------------------------------------------------------------------

    #[test]
    fn dpop_nonce_disabled_by_default() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.dpop.nonce.mode, DpopNonceMode::Disabled);
        assert_eq!(cfg.dpop.nonce.lifetime_secs, DPOP_NONCE_LIFETIME_DEFAULT_SECS);
        cfg.dpop.validate().unwrap();
        // The generated example carries the same defaults.
        let example = ServerConfig::generate_example();
        assert_eq!(example.dpop.nonce.mode, DpopNonceMode::Disabled);
        assert_eq!(example.dpop.nonce.lifetime_secs, 30);
    }

    #[test]
    fn dpop_loads_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("dpop_toml", "toml");
        fs::write(&path, "[dpop.nonce]\nmode = \"required\"\nlifetime_secs = 15\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(cfg.dpop.nonce.mode, DpopNonceMode::Required);
        assert_eq!(cfg.dpop.nonce.lifetime_secs, 15);
        cfg.dpop.validate().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpop_mode_snake_case_values() {
        assert_eq!(
            serde_json::from_value::<DpopNonceMode>(serde_json::json!("disabled")).unwrap(),
            DpopNonceMode::Disabled
        );
        assert_eq!(
            serde_json::from_value::<DpopNonceMode>(serde_json::json!("supported")).unwrap(),
            DpopNonceMode::Supported
        );
        assert_eq!(
            serde_json::from_value::<DpopNonceMode>(serde_json::json!("required")).unwrap(),
            DpopNonceMode::Required
        );
        assert!(serde_json::from_value::<DpopNonceMode>(serde_json::json!("Required")).is_err());
    }

    #[test]
    fn dpop_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISSUERD_DPOP__NONCE__MODE", "supported");
        std::env::set_var("ISSUERD_DPOP__NONCE__LIFETIME_SECS", "45");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_DPOP__NONCE__MODE");
        std::env::remove_var("ISSUERD_DPOP__NONCE__LIFETIME_SECS");
        assert_eq!(cfg.dpop.nonce.mode, DpopNonceMode::Supported);
        assert_eq!(cfg.dpop.nonce.lifetime_secs, 45);
    }

    #[test]
    fn dpop_validate_enforces_bounds() {
        let nonce = |lifetime_secs| DpopConfig {
            nonce: DpopNonceConfig {
                mode: DpopNonceMode::Supported,
                lifetime_secs,
            },
        };
        for ok in [
            DPOP_NONCE_LIFETIME_MIN_SECS,
            30,
            DPOP_NONCE_LIFETIME_MAX_SECS,
        ] {
            nonce(ok)
                .validate()
                .unwrap_or_else(|e| panic!("{ok}s must pass validation: {e}"));
        }
        for bad in [0, 4, 301, 6000] {
            assert!(nonce(bad).validate().is_err(), "{bad}s must fail validation");
        }
    }

    // ------------------------------------------------------------------
    // [mcp]
    // ------------------------------------------------------------------

    #[test]
    fn mcp_secure_defaults() {
        let cfg = ServerConfig::default();
        assert!(!cfg.mcp.enabled);
        assert!(cfg.mcp.require_dpop);
        assert_eq!(cfg.mcp.invocation_rate_limit_per_minute, 60);
        assert!(cfg.mcp.allowed_origins.is_empty());
        assert!(!cfg.mcp.step_up.enabled);

        let example = ServerConfig::generate_example();
        assert!(!example.mcp.enabled);
        assert!(example.mcp.require_dpop);
        assert_eq!(example.mcp.invocation_rate_limit_per_minute, 60);
        assert!(example.mcp.allowed_origins.is_empty());
        assert!(!example.mcp.step_up.enabled);
    }

    #[test]
    fn mcp_legacy_toml_uses_secure_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("mcp_legacy_toml", "toml");
        fs::write(&path, "[mcp]\nenabled = true\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert!(cfg.mcp.enabled);
        assert!(cfg.mcp.require_dpop);
        assert_eq!(cfg.mcp.invocation_rate_limit_per_minute, 60);
        assert!(cfg.mcp.allowed_origins.is_empty());
        assert!(!cfg.mcp.step_up.enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mcp_profile_loads_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("mcp_profile_toml", "toml");
        fs::write(
            &path,
            "[mcp]\nenabled = true\nrequire_dpop = false\ninvocation_rate_limit_per_minute = 120\nallowed_origins = [\"https://inspector.example.com\"]\n[mcp.step_up]\nenabled = true\n",
        )
        .unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert!(cfg.mcp.enabled);
        assert!(!cfg.mcp.require_dpop);
        assert_eq!(cfg.mcp.invocation_rate_limit_per_minute, 120);
        assert_eq!(cfg.mcp.allowed_origins, ["https://inspector.example.com"]);
        assert!(cfg.mcp.step_up.enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mcp_step_up_gate_is_independent() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (path, dir) = temp_path("mcp_step_up_toml", "toml");
        fs::write(&path, "[mcp.step_up]\nenabled = true\n").unwrap();
        let cfg = ServerConfig::load(Some(path)).unwrap();
        assert!(!cfg.mcp.enabled);
        assert!(cfg.mcp.step_up.enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mcp_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISSUERD_MCP__ENABLED", "true");
        std::env::set_var("ISSUERD_MCP__REQUIRE_DPOP", "false");
        std::env::set_var("ISSUERD_MCP__INVOCATION_RATE_LIMIT_PER_MINUTE", "120");
        std::env::set_var("ISSUERD_MCP__STEP_UP__ENABLED", "true");
        let cfg = ServerConfig::load(None).unwrap();
        std::env::remove_var("ISSUERD_MCP__ENABLED");
        std::env::remove_var("ISSUERD_MCP__REQUIRE_DPOP");
        std::env::remove_var("ISSUERD_MCP__INVOCATION_RATE_LIMIT_PER_MINUTE");
        std::env::remove_var("ISSUERD_MCP__STEP_UP__ENABLED");
        assert!(cfg.mcp.enabled);
        assert!(!cfg.mcp.require_dpop);
        assert_eq!(cfg.mcp.invocation_rate_limit_per_minute, 120);
        assert!(cfg.mcp.step_up.enabled);
    }

    #[test]
    fn secure_cookies_follows_issuer_scheme() {
        let cfg = ServerConfig::default();
        assert!(!cfg.secure_cookies(), "http issuer -> no Secure flag");
        let https = ServerConfig {
            issuer_url: "https://idp.example.com".to_string(),
            ..Default::default()
        };
        assert!(https.secure_cookies(), "https issuer -> Secure flag");
        let upper = ServerConfig {
            issuer_url: "HTTPS://idp.example.com:8443".to_string(),
            ..Default::default()
        };
        assert!(upper.secure_cookies(), "URL schemes are case-insensitive");
        let garbage = ServerConfig {
            issuer_url: "not a url".to_string(),
            ..Default::default()
        };
        assert!(
            !garbage.secure_cookies(),
            "unparseable issuer -> no Secure flag (boot rejects such configs anyway)"
        );
    }

    #[test]
    fn example_roundtrip_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = ServerConfig::generate_example();
        let (path, dir) = temp_path("example_toml", "toml");
        write_example(&original, &path).unwrap();
        let loaded = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(loaded.bind, original.bind);
        assert_eq!(loaded.port, original.port);
        assert_eq!(loaded.issuer_url, original.issuer_url);
        assert!(loaded.tls.is_some());
        assert!(matches!(loaded.storage, StorageConfig::Postgres { .. }));
        assert_eq!(loaded.redis, original.redis);
        assert_eq!(loaded.logging.format, original.logging.format);
        assert_eq!(loaded.web_ui.enabled, original.web_ui.enabled);
        assert_eq!(loaded.provision, original.provision);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn example_roundtrip_yaml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = ServerConfig::generate_example();
        let (path, dir) = temp_path("example_yaml", "yaml");
        write_example(&original, &path).unwrap();
        let loaded = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(loaded.bind, original.bind);
        assert_eq!(loaded.port, original.port);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn example_roundtrip_json() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = ServerConfig::generate_example();
        let (path, dir) = temp_path("example_json", "json");
        write_example(&original, &path).unwrap();
        let loaded = ServerConfig::load(Some(path)).unwrap();
        assert_eq!(loaded.bind, original.bind);
        assert_eq!(loaded.port, original.port);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Verify the committed `examples/issuerd.example.toml` is valid and matches the
    /// generated example struct. If this fails, regenerate with:
    ///   cargo run --bin issuerd -- example server-config -o examples/issuerd.example.toml
    #[test]
    fn committed_example_file_is_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let example_path = manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/issuerd.example.toml");
        let loaded = ServerConfig::load(Some(example_path)).unwrap();
        let generated = ServerConfig::generate_example();
        assert_eq!(loaded.bind, generated.bind);
        assert_eq!(loaded.port, generated.port);
        assert_eq!(loaded.issuer_url, generated.issuer_url);
        assert!(loaded.tls.is_some());
        assert!(matches!(loaded.storage, StorageConfig::Postgres { .. }));
        assert_eq!(loaded.redis, generated.redis);
        assert_eq!(loaded.logging.format, generated.logging.format);
        assert_eq!(loaded.web_ui.enabled, generated.web_ui.enabled);
        assert_eq!(loaded.provision, generated.provision);
    }
}
