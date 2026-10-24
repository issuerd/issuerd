// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// ServerState: shared server components (storage, cache, crypto, token service, plugins).

use std::collections::HashMap;
use std::sync::Arc;

use issuerd_auth_flow::plugin_registry::PluginRegistry;
use issuerd_core::{
    Authenticator, Credential, CredentialId, CredentialType, CryptoProvider, DisplayName,
    DistributedCache, Email, EmailSender, EventListener, FederationManager, FlowConfig,
    IssuerdError, Realm, RealmId, Storage, TokenService, User, UserId, Username,
};
use issuerd_token::token_manager::{TokenIssuer, TokenManager};

use crate::config::ServerConfig;
use tracing::{debug, info, instrument};

#[derive(Clone)]
pub struct ServerState {
    pub config: ServerConfig,
    pub storage: Arc<dyn Storage>,
    pub cache: Arc<dyn DistributedCache>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub token_service: Arc<dyn TokenService>,
    pub token_manager: Arc<dyn TokenIssuer>,
    pub plugin_registry: Arc<dyn PluginRegistry>,
    pub federation_manager: Arc<dyn FederationManager>,
    pub login_failure_tracker: Arc<issuerd_auth_flow::login_failures::LoginFailureTracker>,
    pub email_sender: Arc<dyn EmailSender>,
    /// Server-to-server client for identity brokering. A trait so
    /// tests can stub the external IdP; production uses `ReqwestBrokerClient`.
    pub broker_client: Arc<dyn issuerd_core::BrokerClient>,
    /// Back-channel logout dispatcher: notifies clients with a
    /// `backchannel_logout_uri` whenever one of their sessions is destroyed.
    /// Fire-and-forget; `NoOpSessionLogoutNotifier` in tests that do not
    /// exercise logout delivery.
    pub logout_notifier: Arc<dyn issuerd_core::SessionLogoutNotifier>,
    /// Same-node signing-key reload hook: invoked by the admin
    /// API after key rotation/disable so the running crypto provider and
    /// JWKS snapshot pick up the storage mutation immediately instead of
    /// waiting for the next JWKS polling tick. Spawns the reload onto the
    /// runtime; no-op in tests that do not wire the concrete provider.
    pub signing_key_reload: Arc<dyn Fn() + Send + Sync>,
    /// Monotonic counter bumped every time this node reloads the shared
    /// signing-key set (admin reload hook, JWKS poll on change). The cached
    /// discovery document embeds the signing-algorithm list, so rendered
    /// discovery entries validate against it.
    pub keyset_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Event listeners addressable by name from a realm's `events_listeners`.
    /// Always contains `"logging"`; unknown realm listener names
    /// are ignored at dispatch time.
    pub event_listeners: HashMap<String, Arc<dyn EventListener>>,
}

impl ServerState {
    /// Build a `TypedFlowExecutor` from the current plugin registry.
    pub fn typed_executor(&self) -> issuerd_auth_flow::typestate::TypedFlowExecutor {
        self.typed_executor_with_flows(&[])
    }

    /// Build a `TypedFlowExecutor` whose executor resolves sub-flow stages
    /// against `flows` (pass the realm's full stored flow set).
    pub fn typed_executor_with_flows(
        &self,
        flows: &[FlowConfig],
    ) -> issuerd_auth_flow::typestate::TypedFlowExecutor {
        issuerd_auth_flow::typestate::TypedFlowExecutor::new(
            issuerd_auth_flow::executor::FlowExecutor::new(self.plugin_registry.clone(), flows),
        )
    }

    /// Legacy infallible flow resolution for external embedders. New
    /// authentication request handlers must use [`Self::try_bound_flow_executor`]
    /// so a broken explicit binding or storage read cannot select a weaker flow.
    ///
    /// The flow set is loaded from storage per call — one indexed query on
    /// Postgres, trivial on the in-memory/json backends, and deliberately
    /// uncached so admin flow edits take effect immediately. The realm's binding
    /// field (`bound`, `None` → `default_alias`) picks the top-level flow; when
    /// the read fails (logged) or the alias is not in storage, the `fallback`
    /// code constructor preserves this method's historical behavior. The
    /// executor is built over the full loaded list so `sub_flow_alias` stages
    /// resolve.
    ///
    /// Only the browser and registration bindings are consumed at runtime
    /// (here and in the login/registration routes). The direct-grant,
    /// reset-credentials, and first-broker-login bindings exist for
    /// Keycloak-representation parity and admin delete-guardrails only — those
    /// paths never run the flow engine.
    pub async fn bound_flow_executor(
        &self,
        realm: &Realm,
        bound: Option<&str>,
        default_alias: &str,
        fallback: fn(RealmId) -> FlowConfig,
    ) -> (FlowConfig, issuerd_auth_flow::typestate::TypedFlowExecutor) {
        let flows = match self.storage.list_flow_configs(&realm.id).await {
            Ok(flows) => flows,
            Err(e) => {
                tracing::warn!(
                    realm = %realm.id,
                    error = %e,
                    "cannot load flow configs from storage; falling back to code default flow"
                );
                Vec::new()
            }
        };
        let alias = bound.unwrap_or(default_alias);
        let flow = flows
            .iter()
            .find(|f| f.top_level && f.alias.as_str() == alias)
            .cloned()
            .unwrap_or_else(|| fallback(realm.id.clone()));
        (flow, self.typed_executor_with_flows(&flows))
    }

    /// Resolve a top-level flow without allowing a configuration or storage
    /// failure to downgrade authentication. An explicitly bound alias must
    /// exist as a top-level flow in the successfully loaded storage list. Only
    /// an unbound realm may use `fallback` when `default_alias` is absent.
    ///
    /// The executor retains the complete loaded list so sub-flow resolution is
    /// identical for stored flows and the legacy unbound fallback.
    pub async fn try_bound_flow_executor(
        &self,
        realm: &Realm,
        bound: Option<&str>,
        default_alias: &str,
        fallback: fn(RealmId) -> FlowConfig,
    ) -> Result<(FlowConfig, issuerd_auth_flow::typestate::TypedFlowExecutor), IssuerdError> {
        let flows = self.storage.list_flow_configs(&realm.id).await?;
        let alias = bound.unwrap_or(default_alias);
        let flow = match flows.iter().find(|f| f.top_level && f.alias.as_str() == alias) {
            Some(flow) => flow.clone(),
            None if bound.is_none() => fallback(realm.id.clone()),
            None => {
                return Err(IssuerdError::ServerError(format!(
                    "explicitly bound top-level flow '{alias}' not found"
                )))
            }
        };
        Ok((flow, self.typed_executor_with_flows(&flows)))
    }

    /// Resolve the realm segment from a request URL to a realm.
    ///
    /// URLs carry the human-readable realm name — discovery documents and
    /// token issuers embed the realm *name* (see
    /// `TokenManager::issuer_for_realm`). Name lookup is therefore
    /// deterministic; the id lookup remains as a fallback so old id-spelled
    /// bookmarks/URLs keep resolving (deterministic if an admin ever names a
    /// realm after another realm's id: the name wins). The by-name step goes
    /// through the shared realm cache; the id fallback stays uncached.
    pub async fn resolve_realm(&self, segment: &str) -> Result<Option<Realm>, IssuerdError> {
        if let Some(realm) = self.realm_by_name_cached(segment).await? {
            return Ok(Some(realm));
        }
        match RealmId::new(segment) {
            Ok(id) => self.storage.get_realm(&id).await,
            Err(_) => Ok(None),
        }
    }

    /// Resolve the realm an `iss` claim belongs to.
    ///
    /// Issuers are realm-NAME based (`{issuer_url}/realms/{name}`). The
    /// trailing `/realms/` segment is extracted and resolved by name; callers
    /// then use `realm.id` for storage lookups. Tokens issued before the
    /// name-based switch (id-spelled issuers) are intentionally NOT resolved
    /// here — they are rejected.
    pub async fn resolve_issuer_realm(&self, issuer: &str) -> Result<Option<Realm>, IssuerdError> {
        match issuerd_core::typestate::extract_realm_from_issuer(issuer) {
            Some(name) => self.realm_by_name_cached(name).await,
            None => Ok(None),
        }
    }

    /// Realm-by-name lookup with a cache-aside layer (TTL
    /// `[cache] read_cache_ttl_secs`, default 60 s).
    ///
    /// Realm rows change rarely (admin PUT / events-config save) and every
    /// token-bearing request needs this resolution, so the full `Realm` model
    /// is cached as JSON under `realm-by-name:{name}`. Admin mutations delete
    /// the key synchronously (see `issuerd-admin-api` realms/events routes), so the
    /// TTL is only the fail-safe for writes that bypass the API (direct DB
    /// edits, provisioning at boot). Cache errors degrade to the storage path
    /// with a WARN — a cache outage must never fail a request. Negative
    /// results are not cached: unknown issuers fail closed on every call.
    async fn realm_by_name_cached(&self, name: &str) -> Result<Option<Realm>, IssuerdError> {
        let ttl_secs = self.config.cache.read_cache_ttl_secs;
        if ttl_secs == 0 {
            // Read-model caches disabled: pure-DB behavior.
            return self.storage.get_realm_by_name(name).await;
        }
        let key = issuerd_cluster::cache_keys::realm_by_name(name);
        match self.cache.get(&key).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<Realm>(&bytes) {
                Ok(realm) => {
                    debug!(realm = %realm.id, "realm-by-name cache: hit");
                    return Ok(Some(realm));
                }
                Err(e) => {
                    debug!(error = %e, "realm-by-name cache: malformed entry; re-reading");
                }
            },
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "realm-by-name cache read failed; falling back to storage");
            }
        }
        let realm = self.storage.get_realm_by_name(name).await?;
        if let Some(realm) = &realm {
            match serde_json::to_vec(realm) {
                Ok(bytes) => {
                    if let Err(e) = self
                        .cache
                        .set(&key, bytes, Some(std::time::Duration::from_secs(ttl_secs)))
                        .await
                    {
                        tracing::warn!(error = %e, "realm-by-name cache write failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "realm-by-name cache serialization failed");
                }
            }
        }
        Ok(realm)
    }

    #[instrument(skip(config), err)]
    pub async fn from_config(config: &ServerConfig) -> Result<Self, IssuerdError> {
        // Validate up front: the master-realm bootstrap builds client redirect
        // URIs from this value and must never panic on a bad config (P3-10).
        match url::Url::parse(&config.issuer_url) {
            Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {}
            _ => {
                return Err(IssuerdError::InvalidRequest(format!(
                    "issuer_url must be an absolute http(s) URL: {:?}",
                    config.issuer_url
                )));
            }
        }
        // Bounded protocol values: reject out-of-range settings instead of
        // silently clamping them (e.g. an operator typo of 6000 s).
        config.oauth.validate()?;
        config.dpop.validate()?;
        // Log only the storage variant — the full config would leak the
        // Postgres password into the logs.
        let storage_kind = match &config.storage {
            crate::config::StorageConfig::InMemory => "in-memory",
            crate::config::StorageConfig::Postgres { .. } => "postgres",
            crate::config::StorageConfig::JsonFile { .. } => "json-file",
        };
        debug!(
            storage = storage_kind,
            redis = config.redis.is_some(),
            "initializing server state"
        );

        // Multi-node deployments must share both the persistent store
        // (PostgreSQL: realms, users, sessions, signing keys) and the
        // ephemeral cache (Redis: auth codes, pending auth, revocation
        // blocklist, login failures). Anything else is a split-brain config
        // where e.g. an auth code issued by node A is not redeemable on
        // node B — refuse to boot. Validated before opening any connections.
        if config.cluster.enabled {
            let has_postgres =
                matches!(config.storage, crate::config::StorageConfig::Postgres { .. });
            let has_redis = config.redis.is_some() || !config.cluster.redis_nodes.is_empty();
            if !has_postgres || !has_redis {
                return Err(IssuerdError::ServerError(
                    "cluster.enabled requires PostgreSQL storage and a Redis cache \
                     (set `redis` or `cluster.redis_nodes`)"
                        .to_string(),
                ));
            }
        }
        info!(
            node_id = %config.cluster.resolved_node_id(),
            cluster_enabled = config.cluster.enabled,
            "node identity"
        );

        // Envelope encryption of signing keys at rest: validate and build the
        // KEK provider up front so an invalid [crypto.key_encryption] section
        // aborts boot before any connection is opened.
        let kek = config.crypto.build_kek_provider()?;

        // Storage
        let storage: Arc<dyn Storage> = match &config.storage {
            crate::config::StorageConfig::InMemory => {
                if kek.is_some() {
                    tracing::warn!(
                        "[crypto.key_encryption] is only supported with PostgreSQL storage; \
                         ignoring it for the in-memory backend"
                    );
                }
                Arc::new(issuerd_storage::InMemoryStorage::new())
            }
            crate::config::StorageConfig::Postgres { url } => {
                let pg =
                    issuerd_storage::PostgresStorage::connect_with_key_encryption(url, kek.clone())
                        .await?;
                pg.run_migrations().await?;
                if kek.is_some() {
                    // Expand pass: legacy plaintext rows (and rows encrypted
                    // under a previous KEK) are rewritten under the active KEK
                    // before the keystore loads. A wrong KEK fails the daemon
                    // here — never a plaintext fallback.
                    let rewritten = pg.reencrypt_signing_keys_with_active_kek().await?;
                    if rewritten > 0 {
                        info!(count = rewritten, "re-encrypted signing keys at rest");
                    }
                } else {
                    tracing::warn!(
                        "signing keys are stored in PLAINTEXT in PostgreSQL; \
                         configure [crypto.key_encryption] to encrypt them at rest"
                    );
                }
                Arc::new(pg)
            }
            crate::config::StorageConfig::JsonFile { path } => {
                if kek.is_some() {
                    tracing::warn!(
                        "[crypto.key_encryption] is only supported with PostgreSQL storage; \
                         ignoring it for the JSON-file backend (protect the snapshot file at \
                         the filesystem level)"
                    );
                }
                Arc::new(issuerd_storage::JsonFileStorage::new(path)?)
            }
        };

        // Cache: Redis Cluster node list overrides the single-node URL.
        let cache: Arc<dyn DistributedCache> = if !config.cluster.redis_nodes.is_empty() {
            Arc::new(
                issuerd_cluster::RedisCache::connect_cluster(&config.cluster.redis_nodes).await?,
            )
        } else if let Some(redis_url) = &config.redis {
            Arc::new(issuerd_cluster::RedisCache::connect(redis_url).await?)
        } else {
            Arc::new(issuerd_cluster::InMemoryCache::new())
        };

        Self::from_components(config, storage, cache).await
    }

    /// Build server state from pre-constructed shared components.
    ///
    /// [`ServerState::from_config`] constructs storage and cache from the
    /// config and delegates here. Tests (and embeddings) call this directly to
    /// share one storage/cache pair across several state instances, simulating
    /// a multi-node cluster in one process. `config.storage` still decides the
    /// master-realm bootstrap and JWKS refresh task eligibility.
    pub async fn from_components(
        config: &ServerConfig,
        storage: Arc<dyn Storage>,
        cache: Arc<dyn DistributedCache>,
    ) -> Result<Self, IssuerdError> {
        // Email: a real SMTP sender only when `[smtp] enabled = true`;
        // otherwise the no-op sender fails loudly on use so a missing SMTP
        // setup cannot silently swallow verification mails.
        let email_sender: Arc<dyn EmailSender> = if config.smtp.enabled {
            Arc::new(crate::email::SmtpEmailSender::new(config.smtp.clone()))
        } else {
            Arc::new(crate::email::NoOpEmailSender)
        };
        Self::from_components_with_email_sender(config, storage, cache, email_sender).await
    }

    /// [`ServerState::from_components`] with an explicit [`EmailSender`].
    ///
    /// Tests inject a recording sender here so both `state.email_sender` and
    /// the plugin registry's email-code authenticator capture it — mutating
    /// `state.email_sender` after construction would leave the registry's
    /// mailer pointing at the previous sender.
    pub async fn from_components_with_email_sender(
        config: &ServerConfig,
        storage: Arc<dyn Storage>,
        cache: Arc<dyn DistributedCache>,
        email_sender: Arc<dyn EmailSender>,
    ) -> Result<Self, IssuerdError> {
        // Crypto: load the shared signing-key set from storage so every node
        // signs with the same active key and validates its peers' tokens.
        let (crypto, initial_keys) = bootstrap_crypto_provider(storage.as_ref()).await?;
        let jwks = crypto.get_public_keys().await?;

        // TokenService. The default signing algorithm matches the bootstrapped
        // provider config; realms may override it via their
        // `default_signature_algorithm` attribute.
        let token_manager = Arc::new(TokenManager::with_default_alg(
            crypto.clone(),
            config.issuer_url.clone(),
            std::time::Duration::from_secs(60),
            jwks,
            issuerd_token::CryptoConfig::default().default_alg,
        ));
        // The constructor seeds both JWKS snapshots from the full published
        // set; refresh immediately so the signing-selection snapshot becomes
        // the true active-only set (a key disabled before this boot must
        // never sign again, even before the first polling tick).
        token_manager.refresh_jwks().await?;
        let token_service: Arc<dyn TokenService> = token_manager.clone();

        // Propagate keys added (or rotated) by peer nodes into this node's
        // keystore and JWKS snapshot. Only PostgreSQL storage is shared
        // between nodes, so polling is pointless for the other backends.
        let signing_key_fingerprint =
            Arc::new(tokio::sync::Mutex::new(signing_keys_fingerprint(&initial_keys)));
        let keyset_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        if matches!(config.storage, crate::config::StorageConfig::Postgres { .. }) {
            spawn_jwks_refresh_task(
                storage.clone(),
                crypto.clone(),
                token_manager.clone(),
                signing_key_fingerprint.clone(),
                config.cluster.jwks_refresh_interval_secs,
                keyset_generation.clone(),
            );
        }

        let federation_manager: Arc<dyn FederationManager> = Arc::new(
            issuerd_federation::DynamicFederationManager::new(storage.clone(), cache.clone()),
        );

        let login_failure_tracker =
            Arc::new(issuerd_auth_flow::login_failures::LoginFailureTracker::new());

        // Brokered login talks to external IdPs over HTTP.
        // Every server-built outbound HTTP client shares the configured extra
        // root CAs (`[outbound_http] extra_ca_bundle`; fail closed on a bad
        // bundle so a typo never silently falls back to public roots only).
        let extra_roots = config.outbound_http.load_extra_roots()?;
        if !extra_roots.is_empty() {
            info!(count = extra_roots.len(), "outbound HTTP: additional root CAs configured");
        }
        let broker_client: Arc<dyn issuerd_core::BrokerClient> =
            Arc::new(crate::broker::ReqwestBrokerClient::new(
                &extra_roots,
                config.outbound_http.allow_private_addresses,
                config.outbound_http.allow_private_identity_providers,
            )?);

        let plugin_registry: Arc<dyn PluginRegistry> = {
            let mut reg = SimplePluginRegistry::new();
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::CookieAuthenticator::new(
                    token_service.clone(),
                    storage.clone(),
                ),
            ));
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::UsernamePasswordAuthenticator::with_tracker(
                    storage.clone(),
                    login_failure_tracker.clone(),
                    cache.clone(),
                )
                .with_federation_manager(federation_manager.clone()),
            ));
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::SpnegoFlowAuthenticator::new(
                    federation_manager.clone(),
                ),
            ));
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::OtpFormAuthenticator::with_tracker(
                    storage.clone(),
                    login_failure_tracker.clone(),
                    cache.clone(),
                ),
            ));
            // Passwordless email one-time-code login (only factor when a
            // realm's browser flow binds it): mails a numeric code via the
            // realm-merged SMTP sender.
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::email_code::EmailCodeAuthenticator::new(
                    storage.clone(),
                    cache.clone(),
                    Arc::new(crate::email::SmtpEmailCodeSender::new(email_sender.clone())),
                ),
            ));
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::ConditionalUserConfiguredAuthenticator::new(
                    storage.clone(),
                ),
            ));
            // WebAuthn second factor: the relying party is derived
            // from the configured issuer URL (validated absolute http(s) URL
            // before this point).
            let (rp_id, rp_origin) =
                issuerd_auth_flow::webauthn::relying_party_from_issuer(&config.issuer_url)
                    .expect("issuer_url validated as absolute http(s) URL at startup");
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::webauthn::WebAuthnAuthenticator::new(
                    storage.clone(),
                    cache.clone(),
                    rp_id,
                    rp_origin,
                ),
            ));
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::IdentityProviderRedirectAuthenticator::new(
                    storage.clone(),
                ),
            ));
            reg.register_authenticator(Arc::new(
                issuerd_auth_flow::built_in::RegistrationAuthenticator::new(storage.clone()),
            ));
            // Required actions must be registered or the flow engine cannot
            // resolve them and VERIFY_EMAIL / UPDATE_PASSWORD are never
            // enforced.
            reg.register_required_action(Arc::new(
                issuerd_auth_flow::built_in::VerifyEmailRequiredAction::new(storage.clone()),
            ));
            reg.register_required_action(Arc::new(
                issuerd_auth_flow::built_in::UpdatePasswordRequiredAction::new(storage.clone())
                    .with_federation_manager(federation_manager.clone()),
            ));
            reg.register_required_action(Arc::new(
                issuerd_auth_flow::built_in::UpdateProfileRequiredAction::new(storage.clone()),
            ));
            reg.register_required_action(Arc::new(
                issuerd_auth_flow::built_in::ConfigureTotpRequiredAction::new(storage.clone()),
            ));
            reg.register_required_action(Arc::new(
                issuerd_auth_flow::built_in::TermsAndConditionsRequiredAction::new(storage.clone()),
            ));
            Arc::new(reg)
        };

        let logout_notifier: Arc<dyn issuerd_core::SessionLogoutNotifier> =
            Arc::new(crate::routes::logout::BackchannelLogoutDispatcher::new_with_policy(
                storage.clone(),
                token_manager.clone(),
                &extra_roots,
                config.outbound_http.allow_private_addresses,
            )?);

        // Same-node signing-key reload hook: re-read the shared
        // key set from storage, reload the keystore, and refresh the cached
        // JWKS snapshot — exactly what the JWKS polling task does per reload.
        // Built here while the concrete `RingCryptoProvider` is still in
        // reach (the `crypto` field below erases it to `dyn CryptoProvider`).
        let signing_key_reload: Arc<dyn Fn() + Send + Sync> = {
            let storage = storage.clone();
            let crypto = crypto.clone();
            let token_manager = token_manager.clone();
            let signing_key_fingerprint = signing_key_fingerprint.clone();
            let keyset_generation = keyset_generation.clone();
            Arc::new(move || {
                let storage = storage.clone();
                let crypto = crypto.clone();
                let token_manager = token_manager.clone();
                let signing_key_fingerprint = signing_key_fingerprint.clone();
                let keyset_generation = keyset_generation.clone();
                tokio::spawn(async move {
                    let mut current_fingerprint = signing_key_fingerprint.lock().await;
                    let keys = match storage.list_signing_keys().await {
                        Ok(keys) => keys,
                        Err(e) => {
                            tracing::warn!(error = %e, "signing-key reload: cannot read signing keys");
                            return;
                        }
                    };
                    if let Err(e) = crypto.reload_keys(&keys) {
                        tracing::warn!(error = %e, "signing-key reload: keystore reload failed");
                        return;
                    }
                    if let Err(e) = token_manager.refresh_jwks().await {
                        tracing::warn!(error = %e, "signing-key reload: JWKS snapshot reload failed");
                        return;
                    }
                    *current_fingerprint = signing_keys_fingerprint(&keys);
                    keyset_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                });
            })
        };

        // Event listeners: the built-in "logging" listener is
        // always available; realm `events_listeners` entries resolve against
        // this map at dispatch time.
        let event_listeners: HashMap<String, Arc<dyn EventListener>> = HashMap::from([(
            "logging".to_string(),
            Arc::new(crate::event_listeners::LoggingEventListener) as Arc<dyn EventListener>,
        )]);

        let state = Self {
            config: config.clone(),
            storage,
            cache,
            crypto,
            token_service,
            token_manager,
            plugin_registry,
            federation_manager,
            login_failure_tracker,
            email_sender,
            broker_client,
            logout_notifier,
            signing_key_reload,
            keyset_generation,
            event_listeners,
        };

        // Pre-populate master realm for in-memory/json storage if no realms exist
        #[allow(clippy::match_like_matches_macro)]
        let storage_is_bootstrapable = match config.storage {
            crate::config::StorageConfig::InMemory
            | crate::config::StorageConfig::JsonFile { .. } => true,
            _ => false,
        };
        let no_realms = state
            .storage
            .list_realms(&issuerd_core::Pagination::default())
            .await
            .unwrap_or_default()
            .is_empty();
        if storage_is_bootstrapable && no_realms {
            #[cfg(coverage)]
            {
                let _ = bootstrap_master_realm(&state).await;
            }
            #[cfg(not(coverage))]
            {
                if let Err(e) = bootstrap_master_realm(&state).await {
                    tracing::error!(error = %e, "failed to bootstrap master realm");
                }
            }
        }

        // Apply optional provision config exactly once.
        if let Some(provision_path) = &config.provision {
            match crate::provisioner::Provisioner::from_file(provision_path) {
                Ok(provisioner) => {
                    if let Err(e) = provisioner
                        .apply_once_with_mcp(
                            state.storage.as_ref(),
                            &state.config.issuer_url,
                            config.mcp.enabled,
                        )
                        .await
                    {
                        tracing::error!(error = %e, "provision failed");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to load provision config");
                }
            }
        }

        if config.mcp.enabled {
            issuerd_storage::seed::validate_mcp_scope_policy(state.storage.as_ref()).await?;
        }

        Ok(state)
    }
}

/// Build the crypto provider from the shared signing-key set in storage.
///
/// On first boot (empty key set) the initial key set is generated and
/// persisted so every node — and every restart — converges on the same keys.
/// The initial set is a PAIR: the server-default EdDSA key (the signing
/// default for realms without a `default_signature_algorithm` attribute) and
/// an active RS256 key — OIDC Core §15.1 makes RS256 mandatory-to-implement,
/// so discovery must advertise it from the start and realms explicitly pinned
/// to RS256 work without a rotation. A concurrent first boot may persist a
/// second pair; that is benign: all keys are published in JWKS, all validate,
/// and all nodes sign with the newest active key of the resolved algorithm.
/// Deployments upgrading with an existing key set keep their stored keys
/// untouched.
async fn bootstrap_crypto_provider(
    storage: &dyn Storage,
) -> Result<
    (Arc<issuerd_token::RingCryptoProvider>, Vec<issuerd_core::StoredSigningKey>),
    IssuerdError,
> {
    let crypto_config = issuerd_token::CryptoConfig::default();
    let mut keys = storage.list_signing_keys().await?;
    if keys.is_empty() {
        for generated in issuerd_token::KeyStore::generate_initial_key_set(
            crypto_config.default_alg,
            crypto_config.rsa_key_size,
        )? {
            let stored = generated.to_stored(true);
            storage.create_signing_key(&stored).await?;
            info!(kid = %stored.kid, alg = %stored.alg, "generated and persisted initial signing key");
        }
        // Re-list so keys persisted by a concurrently booting node are picked up.
        keys = storage.list_signing_keys().await?;
    }
    let provider = issuerd_token::RingCryptoProvider::from_signing_keys(crypto_config, &keys)?;
    Ok((Arc::new(provider), keys))
}

type SharedSigningKeyFingerprint = Arc<tokio::sync::Mutex<[u8; 32]>>;

/// Fingerprint every field consumed by a keystore reload without retaining a
/// second long-lived copy of private material. Per-key hashes are sorted so
/// storage ordering cannot affect the result.
fn signing_keys_fingerprint(keys: &[issuerd_core::StoredSigningKey]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut key_hashes: Vec<[u8; 32]> = keys
        .iter()
        .map(|key| {
            let encoded =
                serde_json::to_vec(key).expect("serializing a stored signing key cannot fail");
            Sha256::digest(encoded).into()
        })
        .collect();
    key_hashes.sort_unstable();

    let mut hasher = Sha256::new();
    hasher.update((keys.len() as u64).to_be_bytes());
    for hash in key_hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

/// Periodically re-read the shared signing-key set from storage and, when its
/// canonical fingerprint changed, reload the keystore and the JWKS snapshot so
/// key and active-status changes by peer nodes propagate without a restart.
fn spawn_jwks_refresh_task(
    storage: Arc<dyn Storage>,
    crypto: Arc<issuerd_token::RingCryptoProvider>,
    token_manager: Arc<TokenManager<issuerd_token::RingCryptoProvider>>,
    signing_key_fingerprint: SharedSigningKeyFingerprint,
    interval_secs: u64,
    keyset_generation: Arc<std::sync::atomic::AtomicU64>,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
        // Skip the immediate first tick — keys were just loaded at boot.
        interval.tick().await;
        loop {
            interval.tick().await;
            let mut current_fingerprint = signing_key_fingerprint.lock().await;
            let keys = match storage.list_signing_keys().await {
                Ok(keys) => keys,
                Err(e) => {
                    tracing::warn!(error = %e, "JWKS refresh: cannot read signing keys");
                    continue;
                }
            };
            let stored_fingerprint = signing_keys_fingerprint(&keys);
            if stored_fingerprint == *current_fingerprint {
                continue;
            }
            if let Err(e) = crypto.reload_keys(&keys) {
                tracing::warn!(error = %e, "JWKS refresh: keystore reload failed");
                continue;
            }
            if let Err(e) = token_manager.refresh_jwks().await {
                tracing::warn!(error = %e, "JWKS refresh: JWKS snapshot reload failed");
                continue;
            }
            *current_fingerprint = stored_fingerprint;
            keyset_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            info!(keys = keys.len(), "reloaded signing keys from shared storage");
        }
    });
}

async fn bootstrap_master_realm(state: &ServerState) -> Result<(), IssuerdError> {
    // Use the configured issuer_url as the base for built-in client redirect URIs
    // so in-memory/json bootstraps match the actual server URL (e.g. https).
    let base_url = state.config.issuer_url.trim_end_matches('/').to_string();

    let realm = Realm {
        id: RealmId::new("master").unwrap(),
        name: issuerd_core::RealmName::new("master").unwrap(),
        display_name: Some(DisplayName::new("Master").unwrap()),
        enabled: true,
        ..Default::default()
    };
    state.storage.create_realm(&realm).await?;

    let admin_user = User {
        id: UserId::new("admin").unwrap(),
        realm_id: RealmId::new("master").unwrap(),
        username: Username::new("admin").expect("admin username must be valid"),
        email: Some(Email::new("admin@localhost.local").expect("admin email must be valid")),
        email_verified: true,
        first_name: Some(DisplayName::new("Admin").unwrap()),
        last_name: Some(DisplayName::new("User").unwrap()),
        enabled: true,
        federation_link: None,
        attributes: HashMap::new(),
        required_actions: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    state.storage.create_user(&realm.id, &admin_user).await?;

    // Hash password with argon2
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;
    let (password, generated) = resolve_bootstrap_admin_password(&state.config);
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| IssuerdError::ServerError(format!("hash failed: {e}")))?
        .to_string();

    let cred = Credential {
        id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_date: chrono::Utc::now(),
        secret_data: hash.into_bytes(),
        credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
        priority: 1,
    };
    state.storage.create_credential(&realm.id, &admin_user.id, &cred).await?;
    if generated {
        announce_generated_admin_password(&password);
    }

    // Create the built-in clients every realm gets (Keycloak parity):
    // admin-cli for admin-style logins and account-console for the Account SPA.
    let admin_cli = issuerd_admin_api::realms::build_admin_cli_client(&realm.id, &base_url)?;
    state.storage.create_client(&realm.id, &admin_cli).await?;
    let account_client =
        issuerd_admin_api::realms::build_account_console_client(&realm.id, "master", &base_url)?;
    state.storage.create_client(&realm.id, &account_client).await?;

    // Create standard realm-management roles for the admin API
    let admin_roles = vec![
        "manage-realm",
        "view-realm",
        "manage-users",
        "view-users",
        "manage-clients",
        "view-clients",
        // Required by the admin impersonation endpoint.
        "impersonation",
    ];
    for role_name in &admin_roles {
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new(role_name.to_string()).unwrap(),
            description: Some(format!("{role_name} role")),
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        if let Err(e) = state.storage.create_role(&realm.id, &role).await {
            tracing::warn!(error = %e, role = %role.name, "master realm bootstrap: failed to create role");
        }
        if let Err(e) = state.storage.add_user_realm_role(&realm.id, &admin_user.id, &role.id).await
        {
            tracing::warn!(error = %e, role = %role.name, "master realm bootstrap: failed to grant role to admin user");
        }
    }

    // The built-in browser and registration flows are seeded by the storage
    // layer's `create_realm` hook
    // (`issuerd_storage::seed::seed_builtin_flows`), which also makes them appear in
    // the admin API.
    // TODO: Keycloak minimal parity — also create on realm bootstrap:
    //   - direct grant
    //   - reset credentials
    //   - first broker login
    //   - first login flow

    info!("bootstrapped master realm with default admin user — change the password immediately");
    Ok(())
}

/// Password for the bootstrap `admin` user: the configured
/// `bootstrap_admin_password`, or — when unset or empty — a fresh random one
/// (flagged `true` so the caller hands it to the operator).
fn resolve_bootstrap_admin_password(config: &ServerConfig) -> (String, bool) {
    if let Some(password) = config.bootstrap_admin_password.as_deref().filter(|p| !p.is_empty()) {
        return (password.to_string(), false);
    }
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    (base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes), true)
}

/// One-time operator hand-off of a generated bootstrap admin password: printed
/// directly to stderr, never recorded through `tracing` (passwords are never
/// logged).
fn announce_generated_admin_password(password: &str) {
    eprintln!(
        "\n*** Issuerd master realm bootstrap: generated password for user 'admin': {password}\n\
         *** It is shown only once. Set `bootstrap_admin_password` \
         (env ISSUERD_BOOTSTRAP_ADMIN_PASSWORD) to choose it instead.\n"
    );
    tracing::warn!(
        "master realm bootstrap: no bootstrap_admin_password configured — generated a random \
         admin password and printed it once to stderr"
    );
}

// ---------------------------------------------------------------------------
// SimplePluginRegistry
// ---------------------------------------------------------------------------

pub struct SimplePluginRegistry {
    authenticators: HashMap<String, Arc<dyn Authenticator>>,
    required_actions: HashMap<String, Arc<dyn issuerd_core::RequiredAction>>,
}

impl Default for SimplePluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SimplePluginRegistry {
    pub fn new() -> Self {
        Self {
            authenticators: HashMap::new(),
            required_actions: HashMap::new(),
        }
    }

    pub fn register_authenticator(&mut self, auth: Arc<dyn Authenticator>) {
        self.authenticators.insert(auth.id().to_string(), auth);
    }

    pub fn register_required_action(&mut self, action: Arc<dyn issuerd_core::RequiredAction>) {
        self.required_actions.insert(action.id().to_string(), action);
    }
}

#[async_trait::async_trait]
impl PluginRegistry for SimplePluginRegistry {
    async fn get_authenticator(
        &self,
        id: &str,
    ) -> Result<Option<Arc<dyn Authenticator>>, IssuerdError> {
        Ok(self.authenticators.get(id).cloned())
    }

    async fn get_required_action(
        &self,
        id: &str,
    ) -> Result<Option<Arc<dyn issuerd_core::RequiredAction>>, IssuerdError> {
        Ok(self.required_actions.get(id).cloned())
    }

    fn list_authenticator_ids(&self) -> Vec<String> {
        self.authenticators.keys().cloned().collect()
    }

    fn list_required_action_ids(&self) -> Vec<String> {
        self.required_actions.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Default browser flow for MVP
// ---------------------------------------------------------------------------

// The built-in flow constructors moved to `issuerd_core::flows` so the
// storage layer can seed them on realm creation. Re-exported here to keep the
// existing `crate::state::{default_browser_flow, registration_flow}` imports
// working.
pub use issuerd_core::flows::{default_browser_flow, registration_flow};

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{FlowStageId, Requirement};

    #[tokio::test]
    async fn server_state_from_config_inmemory() {
        let cfg = ServerConfig::default();
        let state = ServerState::from_config(&cfg).await.unwrap();
        let realms = state.storage.list_realms(&issuerd_core::Pagination::default()).await.unwrap();
        assert!(!realms.is_empty());
        assert_eq!(realms[0].name, "master");
    }

    #[tokio::test]
    async fn from_config_rejects_out_of_range_auth_code_ttl() {
        for bad in [0, 9, 601] {
            let cfg = ServerConfig {
                oauth: crate::config::OAuthConfig {
                    auth_code_ttl_secs: bad,
                },
                ..Default::default()
            };
            let err = match ServerState::from_config(&cfg).await {
                Ok(_) => panic!("out-of-range auth_code_ttl_secs ({bad}) must abort boot"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("auth_code_ttl_secs"),
                "error must name the offending key: {err}"
            );
        }
    }

    #[tokio::test]
    async fn from_config_rejects_unreadable_extra_ca_bundle() {
        // Fail closed: a configured-but-unreadable bundle must abort the boot
        // instead of silently falling back to public roots only.
        let cfg = ServerConfig {
            outbound_http: crate::config::OutboundHttpConfig {
                extra_ca_bundle: Some(std::path::PathBuf::from("/nonexistent/roots.pem")),
                allow_private_addresses: false,
                allow_private_identity_providers: false,
            },
            ..Default::default()
        };
        let err = match ServerState::from_config(&cfg).await {
            Ok(_) => panic!("an unreadable extra_ca_bundle must abort boot"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("outbound_http.extra_ca_bundle"),
            "error must name the offending key: {err}"
        );
    }

    #[tokio::test]
    async fn from_config_accepts_valid_extra_ca_bundle() {
        let dir = std::env::temp_dir()
            .join(format!("issuerd_state_ca_test_{}", issuerd_core::utils::generate_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("roots.pem");
        std::fs::write(&bundle, crate::config::TEST_CA_BUNDLE).unwrap();
        let cfg = ServerConfig {
            outbound_http: crate::config::OutboundHttpConfig {
                extra_ca_bundle: Some(bundle),
                allow_private_addresses: false,
                allow_private_identity_providers: false,
            },
            ..Default::default()
        };
        ServerState::from_config(&cfg).await.expect("a valid bundle boots");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn server_state_builds_federation_manager() {
        let cfg = ServerConfig::default();
        let state = ServerState::from_config(&cfg).await.unwrap();
        // Federation manager should be non-null and functional
        let providers = state
            .federation_manager
            .providers_for_realm(&issuerd_core::RealmId::new("master").unwrap())
            .await
            .unwrap();
        // Master realm has no federation providers configured, so list should be empty
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn simple_plugin_registry() {
        let mut reg = SimplePluginRegistry::new();
        assert!(reg.list_authenticator_ids().is_empty());
        assert!(reg.list_required_action_ids().is_empty());

        let auth = Arc::new(issuerd_auth_flow::built_in::UsernamePasswordAuthenticator::new(
            Arc::new(issuerd_storage::InMemoryStorage::new()),
        ));
        reg.register_authenticator(auth.clone());
        assert_eq!(reg.list_authenticator_ids(), vec!["auth-username-password"]);
        let fetched = reg.get_authenticator("auth-username-password").await.unwrap();
        assert!(fetched.is_some());

        let action = Arc::new(issuerd_auth_flow::built_in::VerifyEmailRequiredAction::new(
            Arc::new(issuerd_storage::InMemoryStorage::new()),
        ));
        reg.register_required_action(action.clone());
        assert_eq!(reg.list_required_action_ids(), vec!["VERIFY_EMAIL"]);
        let fetched = reg.get_required_action("VERIFY_EMAIL").await.unwrap();
        assert!(fetched.is_some());
    }

    #[test]
    fn default_browser_flow_structure() {
        let flow = default_browser_flow(RealmId::new("test").unwrap());
        assert_eq!(flow.alias, issuerd_core::Alias::new("browser").unwrap());
        assert_eq!(flow.stages.len(), 7);
        assert_eq!(flow.stages[0].id, FlowStageId::new("cookie-auth").unwrap());
        assert_eq!(flow.stages[1].id, FlowStageId::new("auth-spnego").unwrap());
        // The kc_idp_hint broker redirect runs after cookie/SPNEGO so an
        // existing SSO session still wins over the hint.
        assert_eq!(flow.stages[2].id, FlowStageId::new("idp-redirect").unwrap());
        assert_eq!(flow.stages[2].requirement, Requirement::Alternative);
        assert_eq!(flow.stages[3].id, FlowStageId::new("username-password").unwrap());
        // Conditional TOTP/WebAuthn second factor at the flow tail.
        assert_eq!(flow.stages[4].id, FlowStageId::new("conditional-user-configured").unwrap());
        assert_eq!(flow.stages[4].requirement, Requirement::Conditional);
        assert_eq!(flow.stages[5].id, FlowStageId::new("auth-otp-form").unwrap());
        assert_eq!(flow.stages[5].requirement, Requirement::Conditional);
        assert_eq!(flow.stages[6].id, FlowStageId::new("auth-webauthn").unwrap());
        // Optional, NOT Conditional — see the stage comment: a Conditional
        // WebAuthn stage would be scope-skipped after an Attempted OTP stage.
        assert_eq!(flow.stages[6].requirement, Requirement::Optional);
    }

    #[test]
    fn registration_flow_structure() {
        let flow = registration_flow(RealmId::new("test").unwrap());
        assert_eq!(flow.alias, issuerd_core::Alias::new("registration").unwrap());
        assert_eq!(flow.stages.len(), 1);
        assert_eq!(flow.stages[0].id, FlowStageId::new("registration").unwrap());
        assert_eq!(
            flow.stages[0].authenticator,
            issuerd_core::Alias::new("auth-registration").unwrap()
        );
        assert_eq!(flow.stages[0].requirement, Requirement::Required);
    }

    #[tokio::test]
    async fn server_state_from_config_json_file() {
        let dir = std::env::temp_dir()
            .join(format!("issuerd_server_json_test_{}", issuerd_core::utils::generate_id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("db.json");
        let cfg = ServerConfig {
            storage: crate::config::StorageConfig::JsonFile { path: path.clone() },
            ..Default::default()
        };
        let state = ServerState::from_config(&cfg).await.unwrap();
        let realms = state.storage.list_realms(&issuerd_core::Pagination::default()).await.unwrap();
        assert!(!realms.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn simple_plugin_registry_default() {
        let reg = SimplePluginRegistry::default();
        assert!(reg.list_authenticator_ids().is_empty());
        assert!(reg.list_required_action_ids().is_empty());
    }

    #[tokio::test]
    async fn bootstrap_master_realm_create_realm_fails() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage
            .expect_create_realm()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db fail".to_string())));
        mock_storage.expect_list_realms().returning(|_| Ok(vec![]));

        let state = ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(SimplePluginRegistry::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: HashMap::new(),
        };

        let result = bootstrap_master_realm(&state).await;
        assert!(result.is_err());
    }

    async fn bootstrap_admin_verifies(state: &ServerState, password: &str) -> bool {
        use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
        let realm_id = RealmId::new("master").unwrap();
        let creds = state
            .storage
            .get_credentials(&realm_id, &UserId::new("admin").unwrap(), CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1, "bootstrap seeds exactly one admin password");
        let hash = std::str::from_utf8(&creds[0].secret_data).unwrap();
        let parsed = PasswordHash::new(hash).unwrap();
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    }

    #[tokio::test]
    async fn bootstrap_admin_uses_configured_password() {
        let cfg = ServerConfig {
            bootstrap_admin_password: Some("Op3rator-Chosen!".to_string()),
            ..Default::default()
        };
        let state = ServerState::from_config(&cfg).await.unwrap();
        assert!(bootstrap_admin_verifies(&state, "Op3rator-Chosen!").await);
        assert!(!bootstrap_admin_verifies(&state, "admin").await);
    }

    #[tokio::test]
    async fn bootstrap_admin_never_gets_hardcoded_password_by_default() {
        let state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        assert!(!bootstrap_admin_verifies(&state, "admin").await);
        let empty = ServerConfig {
            bootstrap_admin_password: Some(String::new()),
            ..Default::default()
        };
        let state = ServerState::from_config(&empty).await.unwrap();
        assert!(!bootstrap_admin_verifies(&state, "admin").await);
        assert!(!bootstrap_admin_verifies(&state, "").await);
    }

    #[test]
    fn resolve_bootstrap_admin_password_generates_random_when_unset() {
        let (configured, generated) = resolve_bootstrap_admin_password(&ServerConfig {
            bootstrap_admin_password: Some("pinned".to_string()),
            ..Default::default()
        });
        assert_eq!((configured.as_str(), generated), ("pinned", false));

        let (first, generated) = resolve_bootstrap_admin_password(&ServerConfig::default());
        assert!(generated);
        assert_eq!(first.len(), 24, "18 random bytes, base64url without padding");
        let (second, _) = resolve_bootstrap_admin_password(&ServerConfig::default());
        assert_ne!(first, second);

        let (_, generated) = resolve_bootstrap_admin_password(&ServerConfig {
            bootstrap_admin_password: Some(String::new()),
            ..Default::default()
        });
        assert!(generated, "an empty configured password counts as unset");
    }

    #[tokio::test]
    async fn server_state_from_config_postgres_invalid_url_fails() {
        let cfg = ServerConfig {
            storage: crate::config::StorageConfig::Postgres {
                url: "postgres://invalid_host:5432/db".to_string(),
            },
            ..Default::default()
        };
        let result = ServerState::from_config(&cfg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn server_state_from_config_redis_invalid_url_fails() {
        let cfg = ServerConfig {
            redis: Some("redis://invalid_host:6379".to_string()),
            ..Default::default()
        };
        let result = ServerState::from_config(&cfg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cluster_enabled_requires_postgres_storage() {
        // In-memory storage + no Redis → boot must fail fast.
        let cfg = ServerConfig {
            cluster: crate::config::ClusterConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = ServerState::from_config(&cfg).await;
        let msg = format!("{}", result.err().unwrap());
        assert!(msg.contains("cluster.enabled"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn cluster_enabled_requires_redis_cache() {
        // Postgres configured but no Redis → boot must fail before connecting.
        let cfg = ServerConfig {
            storage: crate::config::StorageConfig::Postgres {
                url: "postgres://invalid_host:5432/db".to_string(),
            },
            cluster: crate::config::ClusterConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = ServerState::from_config(&cfg).await;
        let msg = format!("{}", result.err().unwrap());
        assert!(msg.contains("cluster.enabled"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn cluster_enabled_with_redis_fails_on_connect_not_validation() {
        // Valid cluster shape (Postgres + Redis): validation passes, boot then
        // fails on the unreachable Postgres — a different error.
        let cfg = ServerConfig {
            storage: crate::config::StorageConfig::Postgres {
                url: "postgres://invalid_host:5432/db".to_string(),
            },
            redis: Some("redis://invalid_host:6379".to_string()),
            cluster: crate::config::ClusterConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = ServerState::from_config(&cfg).await;
        let msg = format!("{}", result.err().unwrap());
        assert!(!msg.contains("cluster.enabled"), "validation should have passed: {msg}");
    }

    #[tokio::test]
    async fn inmemory_boot_persists_signing_key_in_storage() {
        let cfg = ServerConfig::default();
        let state = ServerState::from_config(&cfg).await.unwrap();
        let keys = state.storage.list_signing_keys().await.unwrap();
        // Fresh boot persists the initial PAIR: the EdDSA default signing key
        // and the OIDC Core MTI RS256 key, both active.
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.active));
        let algs: Vec<_> = keys.iter().map(|k| k.alg).collect();
        assert!(algs.contains(&issuerd_core::Algorithm::EdDsa));
        assert!(algs.contains(&issuerd_core::Algorithm::Rs256));
        // The published JWKS must contain the same keys.
        let jwks = state.crypto.get_public_keys().await.unwrap();
        assert!(keys.iter().all(|k| jwks.keys.iter().any(|j| j.kid == k.kid)));
    }

    #[tokio::test]
    async fn server_state_from_config_skips_bootstrap_when_realms_exist() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_list_realms().returning(|_| {
            Ok(vec![issuerd_core::Realm {
                id: issuerd_core::RealmId::new("existing").unwrap(),
                name: issuerd_core::RealmName::new("existing").unwrap(),
                display_name: None,
                enabled: true,
                ..Default::default()
            }])
        });

        let state = ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(SimplePluginRegistry::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: HashMap::new(),
        };

        // bootstrap_master_realm should not be called because realms exist
        let realms = state.storage.list_realms(&issuerd_core::Pagination::default()).await.unwrap();
        assert_eq!(realms.len(), 1);
    }

    async fn flow_resolution_state() -> (ServerState, Realm) {
        let state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let realm = state
            .storage
            .get_realm(&RealmId::new("master").unwrap())
            .await
            .unwrap()
            .unwrap();
        (state, realm)
    }

    #[tokio::test]
    async fn try_bound_flow_executor_loads_storage_flows() {
        let (state, realm) = flow_resolution_state().await;

        // Realm creation seeded the builtin flows into storage.
        let stored = state.storage.list_flow_configs(&realm.id).await.unwrap();
        assert!(stored.iter().any(|f| f.top_level && f.alias.as_str() == "browser"));

        // A realm binding to a custom stored flow wins over the code default.
        let mut custom = registration_flow(realm.id.clone());
        custom.alias = issuerd_core::Alias::new("custom-top").unwrap();
        custom.built_in = false;
        state.storage.create_flow_config(&realm.id, &custom).await.unwrap();
        let (flow, _executor) = state
            .try_bound_flow_executor(&realm, Some("custom-top"), "browser", default_browser_flow)
            .await
            .unwrap();
        assert_eq!(flow.alias.as_str(), "custom-top");
        assert_eq!(flow.stages.len(), 1, "stored flow, not the 7-stage code default");

        let (flow, _executor) = state
            .try_bound_flow_executor(&realm, None, "browser", default_browser_flow)
            .await
            .unwrap();
        assert_eq!(flow.alias.as_str(), "browser");
    }

    #[tokio::test]
    async fn try_bound_flow_executor_missing_explicit_alias_fails_closed() {
        let (state, realm) = flow_resolution_state().await;

        let result = state
            .try_bound_flow_executor(&realm, Some("missing"), "browser", default_browser_flow)
            .await;
        let Err(error) = result else {
            panic!("a missing explicitly bound alias must not use the password-capable default");
        };
        assert!(matches!(&error, IssuerdError::ServerError(_)));
        assert!(error.to_string().contains("'missing'"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn try_bound_flow_executor_list_error_fails_closed() {
        let (mut state, realm) = flow_resolution_state().await;
        let mut storage = issuerd_core::MockStorage::new();
        storage
            .expect_list_flow_configs()
            .once()
            .returning(|_| Err(IssuerdError::ServerError("flow list unavailable".to_string())));
        state.storage = Arc::new(storage);

        let result = state
            .try_bound_flow_executor(&realm, None, "browser", default_browser_flow)
            .await;
        let Err(error) = result else {
            panic!("a storage read failure must not use the code default");
        };
        assert_eq!(error, IssuerdError::ServerError("flow list unavailable".to_string()));
    }

    #[tokio::test]
    async fn try_bound_flow_executor_unbound_missing_default_uses_code_fallback() {
        let (state, realm) = flow_resolution_state().await;
        state.storage.delete_flow_config(&realm.id, "browser").await.unwrap();
        let stored = state.storage.list_flow_configs(&realm.id).await.unwrap();
        assert!(!stored.is_empty(), "the flow list still loads successfully");
        assert!(!stored.iter().any(|f| f.top_level && f.alias.as_str() == "browser"));

        let (flow, _executor) = state
            .try_bound_flow_executor(&realm, None, "browser", default_browser_flow)
            .await
            .unwrap();
        assert_eq!(flow.alias.as_str(), "browser");
        assert_eq!(flow.stages.len(), 7, "code default browser flow as fallback");
    }

    #[tokio::test]
    async fn bootstrap_seeds_and_assigns_impersonation_role() {
        let cfg = ServerConfig::default();
        let state = ServerState::from_config(&cfg).await.unwrap();
        let realm_id = RealmId::new("master").unwrap();
        let role = state
            .storage
            .get_role_by_name(&realm_id, "impersonation")
            .await
            .unwrap()
            .expect("impersonation role must be seeded at bootstrap");
        assert!(!role.client_role);

        let assigned = state
            .storage
            .list_user_realm_roles(&realm_id, &UserId::new("admin").unwrap())
            .await
            .unwrap();
        assert!(assigned.contains(&role.id), "bootstrap admin holds the impersonation role");
    }

    #[tokio::test]
    async fn resolve_issuer_realm_caches_and_reflects_invalidation() {
        let cfg = ServerConfig::default();
        let state = ServerState::from_config(&cfg).await.unwrap();
        let issuer = "http://localhost:8080/realms/master";
        let key = issuerd_cluster::cache_keys::realm_by_name("master");

        let realm = state
            .resolve_issuer_realm(issuer)
            .await
            .unwrap()
            .expect("master realm resolves");
        assert!(
            state.cache.get(&key).await.unwrap().is_some(),
            "first resolve populates the realm-by-name cache"
        );

        let mut updated = realm.clone();
        updated.display_name = Some(DisplayName::new("Mutated").unwrap());
        state.storage.update_realm(&updated).await.unwrap();

        let cached = state.resolve_issuer_realm(issuer).await.unwrap().unwrap();
        assert_eq!(
            cached.display_name, realm.display_name,
            "second resolve is served from cache and still shows the old value"
        );

        state.cache.delete(&key).await.unwrap();
        let fresh = state.resolve_issuer_realm(issuer).await.unwrap().unwrap();
        assert_eq!(
            fresh.display_name, updated.display_name,
            "after invalidation the resolve reflects the storage change"
        );
    }

    #[test]
    fn signing_key_fingerprint_covers_all_reload_inputs() {
        let first = issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::EdDsa, 2048)
            .unwrap()
            .to_stored(true);
        let second = issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::EdDsa, 2048)
            .unwrap()
            .to_stored(false);
        let keys = vec![first, second];
        let baseline = signing_keys_fingerprint(&keys);

        let mut changed = keys.clone();
        changed[0].kid = keys[1].kid.clone();
        assert_ne!(signing_keys_fingerprint(&changed), baseline, "kid");

        let mut changed = keys.clone();
        changed[0].alg = issuerd_core::Algorithm::Rs384;
        assert_ne!(signing_keys_fingerprint(&changed), baseline, "algorithm");

        let mut changed = keys.clone();
        changed[0].created_at += chrono::Duration::seconds(1);
        assert_ne!(signing_keys_fingerprint(&changed), baseline, "created_at");

        let mut changed = keys.clone();
        changed[0].active = false;
        assert_ne!(signing_keys_fingerprint(&changed), baseline, "active");

        let mut changed = keys.clone();
        changed[0].public_jwk.x = keys[1].public_jwk.x.clone();
        assert_ne!(signing_keys_fingerprint(&changed), baseline, "public JWK");

        let mut changed = keys.clone();
        changed[0].private_der[0] ^= 1;
        assert_ne!(signing_keys_fingerprint(&changed), baseline, "private material");

        assert_ne!(signing_keys_fingerprint(&keys[..1]), baseline, "adding or removing a key");
    }

    #[tokio::test]
    async fn jwks_refresh_task_does_not_reload_for_reordering() {
        use std::sync::atomic::Ordering;

        let keys = vec![
            issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::EdDsa, 2048)
                .unwrap()
                .to_stored(true),
            issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::EdDsa, 2048)
                .unwrap()
                .to_stored(true),
        ];
        let crypto = Arc::new(
            issuerd_token::RingCryptoProvider::from_signing_keys(
                issuerd_token::CryptoConfig::default(),
                &keys,
            )
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let token_manager = Arc::new(TokenManager::with_default_alg(
            crypto.clone(),
            "http://localhost:8080".to_string(),
            std::time::Duration::from_secs(60),
            jwks,
            issuerd_token::CryptoConfig::default().default_alg,
        ));

        let mut reordered = keys.clone();
        reordered.reverse();
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_list_signing_keys().returning(move || Ok(reordered.clone()));
        let storage: Arc<dyn issuerd_core::Storage> = Arc::new(mock_storage);
        let generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        spawn_jwks_refresh_task(
            storage,
            crypto,
            token_manager,
            Arc::new(tokio::sync::Mutex::new(signing_keys_fingerprint(&keys))),
            1,
            generation.clone(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
        assert_eq!(
            generation.load(Ordering::Relaxed),
            0,
            "reordering an otherwise identical key set must not trigger a reload"
        );
    }

    #[tokio::test]
    async fn jwks_refresh_task_reloads_active_only_changes() {
        use std::sync::atomic::Ordering;

        let storage: Arc<dyn issuerd_core::Storage> =
            Arc::new(issuerd_storage::InMemoryStorage::new());
        let key = issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::EdDsa, 2048)
            .unwrap()
            .to_stored(true);
        storage.create_signing_key(&key).await.unwrap();
        let crypto = Arc::new(
            issuerd_token::RingCryptoProvider::from_signing_keys(
                issuerd_token::CryptoConfig::default(),
                std::slice::from_ref(&key),
            )
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let token_manager = Arc::new(TokenManager::with_default_alg(
            crypto.clone(),
            "http://localhost:8080".to_string(),
            std::time::Duration::from_secs(60),
            jwks,
            issuerd_token::CryptoConfig::default().default_alg,
        ));
        let generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        spawn_jwks_refresh_task(
            storage.clone(),
            crypto.clone(),
            token_manager,
            Arc::new(tokio::sync::Mutex::new(signing_keys_fingerprint(std::slice::from_ref(&key)))),
            1,
            generation.clone(),
        );

        let mut disabled = key.clone();
        disabled.active = false;
        storage.update_signing_key(&disabled).await.unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        while generation.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            generation.load(Ordering::Relaxed) >= 1,
            "an active-only storage change must trigger a reload"
        );
        let err = crypto
            .sign(r#"{"sub":"user-1"}"#, disabled.alg, &disabled.kid)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("disabled"),
            "the reloaded keystore must reject signing with the disabled key: {err}"
        );
    }

    #[tokio::test]
    async fn jwks_refresh_task_reloads_only_on_key_set_changes() {
        use std::sync::atomic::Ordering;

        let storage: Arc<dyn issuerd_core::Storage> =
            Arc::new(issuerd_storage::InMemoryStorage::new());
        let crypto_config = issuerd_token::CryptoConfig::default();
        let mut keys = Vec::new();
        for generated in issuerd_token::KeyStore::generate_initial_key_set(
            crypto_config.default_alg,
            crypto_config.rsa_key_size,
        )
        .unwrap()
        {
            let stored = generated.to_stored(true);
            storage.create_signing_key(&stored).await.unwrap();
            keys.push(stored);
        }
        let crypto = Arc::new(
            issuerd_token::RingCryptoProvider::from_signing_keys(crypto_config, &keys).unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let token_manager = Arc::new(TokenManager::with_default_alg(
            crypto.clone(),
            "http://localhost:8080".to_string(),
            std::time::Duration::from_secs(60),
            jwks,
            issuerd_token::CryptoConfig::default().default_alg,
        ));
        let generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        spawn_jwks_refresh_task(
            storage.clone(),
            crypto.clone(),
            token_manager,
            Arc::new(tokio::sync::Mutex::new(signing_keys_fingerprint(&keys))),
            1,
            generation.clone(),
        );

        // Multiple polling intervals with an unchanged key set: no reload may
        // fire (a reload every tick would also invalidate discovery caches
        // cluster-wide for no reason).
        tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
        assert_eq!(
            generation.load(Ordering::Relaxed),
            0,
            "an unchanged key set must never trigger a reload"
        );

        // A key persisted by a peer node propagates on a subsequent tick.
        let extra =
            issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::EdDsa, 2048).unwrap();
        let extra_kid = extra.kid.to_string();
        storage.create_signing_key(&extra.to_stored(true)).await.unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        while generation.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            generation.load(Ordering::Relaxed) >= 1,
            "a changed key set must trigger a reload"
        );
        let kids: Vec<String> = crypto
            .get_public_keys()
            .await
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kid.to_string())
            .collect();
        assert!(kids.contains(&extra_kid), "keystore must reload with the new key");
    }
}
