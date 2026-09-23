// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Server configuration types with figment-based layered loading (TOML/YAML/JSON + env).

use figment::{
    providers::{Env, Format, Json, Serialized, Toml, Yaml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use issuerd_core::IssuerdError;

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
    /// Login-theme asset directory (`[themes]` section).
    pub themes: ThemesConfig,
    /// Optional path to a provision config file (YAML/TOML/JSON).
    /// Applied exactly once at first startup; ignored on restarts.
    pub provision: Option<PathBuf>,
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
            themes: ThemesConfig::default(),
            provision: None,
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
                        figment = figment.merge(Yaml::file(p));
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
            provision: Some(PathBuf::from("provision.yaml")),
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
        "yaml" | "yml" => serde_yaml::to_string(value)
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
    pub fn for_realm(&self, realm: &issuerd_core::Realm) -> Self {
        let attr = |key: &str| realm.attributes.get(&format!("smtpServer.{key}"));
        let flag = |key: &str, default: bool| attr(key).map(|v| v == "true").unwrap_or(default);
        Self {
            enabled: self.enabled,
            host: attr("host").cloned().unwrap_or_else(|| self.host.clone()),
            port: attr("port").and_then(|v| v.parse().ok()).unwrap_or(self.port),
            from: attr("from").cloned().unwrap_or_else(|| self.from.clone()),
            from_display: attr("fromDisplayName").cloned().or_else(|| self.from_display.clone()),
            reply_to: attr("replyTo").cloned().or_else(|| self.reply_to.clone()),
            starttls: flag("starttls", self.starttls),
            ssl: flag("ssl", self.ssl),
            username: attr("user").cloned().or_else(|| self.username.clone()),
            password: attr("password").cloned().or_else(|| self.password.clone()),
        }
    }
}

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
        // Untouched keys fall back to the global config.
        assert_eq!(merged.username.as_deref(), Some("global-user"));
        assert!(merged.enabled);

        // No attributes -> identical to global.
        let plain = issuerd_core::Realm::default();
        let merged = base.for_realm(&plain);
        assert_eq!(merged.host, base.host);
        assert_eq!(merged.port, base.port);
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
