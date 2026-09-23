// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Dynamic federation manager: loads providers from realm identity-provider configuration.

use std::collections::HashMap;
use std::sync::Arc;

use issuerd_core::{
    FederatedUser, FederationManager, FederationProvider, FederationProviderType, IssuerdError,
    RealmId, Storage,
};

/// Loads federation providers dynamically from realm identity-provider
/// configuration.
pub struct DynamicFederationManager {
    storage: Arc<dyn Storage>,
    #[allow(dead_code)]
    cache: Arc<dyn issuerd_core::DistributedCache>,
}

impl DynamicFederationManager {
    pub fn new(storage: Arc<dyn Storage>, cache: Arc<dyn issuerd_core::DistributedCache>) -> Self {
        Self { storage, cache }
    }

    async fn load_providers(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<Arc<dyn FederationProvider>>, IssuerdError> {
        let idps = self.storage.list_identity_providers(realm_id).await?;
        let mut providers: Vec<(i32, Arc<dyn FederationProvider>)> = Vec::new();

        for idp in idps {
            if !idp.enabled {
                continue;
            }
            let provider_type = match idp.provider_id.as_str() {
                "ldap" => FederationProviderType::Ldap,
                "kerberos" => FederationProviderType::Kerberos,
                _ => continue,
            };

            let priority = idp.config.get("priority").and_then(|s| s.parse().ok()).unwrap_or(0);

            let provider = match provider_type {
                FederationProviderType::Ldap => {
                    let config = crate::ldap::config::LdapConfig::from_hashmap(&idp.config)
                        .map_err(|e| IssuerdError::ServerError(e.to_string()))?;
                    let mappers = build_default_mappers(&idp.config);
                    Arc::new(
                        crate::ldap::provider::LdapFederationProvider::new(
                            idp.id.to_string(),
                            config,
                            mappers,
                        )
                        .await
                        .map_err(|e| IssuerdError::ServerError(e.to_string()))?,
                    ) as Arc<dyn FederationProvider>
                }
                FederationProviderType::Kerberos => {
                    let config = crate::kerberos::config::KerberosConfig::from_hashmap(&idp.config)
                        .map_err(|e| IssuerdError::ServerError(e.to_string()))?;
                    Arc::new(
                        crate::kerberos::provider::KerberosFederationProvider::new(
                            idp.id.to_string(),
                            config,
                        )
                        .map_err(|e| IssuerdError::ServerError(e.to_string()))?,
                    ) as Arc<dyn FederationProvider>
                }
            };
            providers.push((priority, provider));
        }

        providers.sort_by_key(|b| std::cmp::Reverse(b.0));
        Ok(providers.into_iter().map(|(_, p)| p).collect())
    }
}

#[async_trait::async_trait]
impl FederationManager for DynamicFederationManager {
    async fn providers_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<Arc<dyn FederationProvider>>, IssuerdError> {
        self.load_providers(realm_id).await
    }

    async fn find_user(
        &self,
        realm_id: &RealmId,
        username: &str,
    ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, IssuerdError> {
        let providers = self.providers_for_realm(realm_id).await?;
        for provider in providers {
            match provider.find_user(username).await {
                Ok(Some(user)) => return Ok(Some((provider, user))),
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        provider_id = %provider.id(),
                        error = %e,
                        "federation provider error"
                    );
                    continue;
                }
            }
        }
        Ok(None)
    }

    async fn find_user_by_email(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, IssuerdError> {
        let providers = self.providers_for_realm(realm_id).await?;
        for provider in providers {
            match provider.find_user_by_email(email).await {
                Ok(Some(user)) => return Ok(Some((provider, user))),
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        provider_id = %provider.id(),
                        error = %e,
                        "federation provider error"
                    );
                    continue;
                }
            }
        }
        Ok(None)
    }
}

/// Build the LDAP mapper chain from the identity-provider config.
///
/// Currently supported: the group mapper (`group-ldap-mapper`), enabled when
/// the config carries `groupsDn` (see [`crate::mapper::GroupMapper::from_config`]).
fn build_default_mappers(
    config: &HashMap<String, String>,
) -> Vec<Box<dyn crate::mapper::LdapMapper>> {
    let mut mappers: Vec<Box<dyn crate::mapper::LdapMapper>> = Vec::new();
    if let Some(group_mapper) = crate::mapper::GroupMapper::from_config(config) {
        mappers.push(Box::new(group_mapper));
    }
    mappers
}

/// No-op federation manager for use in tests or when federation is disabled.
pub struct NoOpFederationManager;

#[async_trait::async_trait]
impl FederationManager for NoOpFederationManager {
    async fn providers_for_realm(
        &self,
        _realm_id: &RealmId,
    ) -> Result<Vec<Arc<dyn FederationProvider>>, IssuerdError> {
        Ok(vec![])
    }

    async fn find_user(
        &self,
        _realm_id: &RealmId,
        _username: &str,
    ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, IssuerdError> {
        Ok(None)
    }

    async fn find_user_by_email(
        &self,
        _realm_id: &RealmId,
        _email: &str,
    ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, IssuerdError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use issuerd_cluster::InMemoryCache;
    use issuerd_core::{
        FederationManager, IdentityProviderConfig, IdentityProviderId, Realm, RealmId, RealmName,
    };
    use issuerd_storage::InMemoryStorage;

    use super::*;

    fn kerberos_idp(id: &str, priority: i32, enabled: bool) -> IdentityProviderConfig {
        let mut config = HashMap::new();
        config.insert("kerberosRealm".to_string(), "TEST.ISSUERD.LOCAL".to_string());
        config.insert("allowKerberosAuthentication".to_string(), "false".to_string());
        config.insert("priority".to_string(), priority.to_string());
        IdentityProviderConfig {
            id: IdentityProviderId::new(id).unwrap(),
            alias: issuerd_core::Alias::new(id).unwrap(),
            provider_id: issuerd_core::ProviderId::new("kerberos"),
            enabled,
            config,
        }
    }

    async fn setup_storage_with_idps(idps: Vec<IdentityProviderConfig>) -> Arc<InMemoryStorage> {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = Realm {
            id: RealmId::new("test-realm").unwrap(),
            name: RealmName::new("test").unwrap(),
            ..Default::default()
        };
        storage.create_realm(&realm).await.unwrap();
        for idp in idps {
            storage.create_identity_provider(&realm.id, &idp).await.unwrap();
        }
        storage
    }

    #[tokio::test]
    async fn noop_manager_returns_empty() {
        let mgr = NoOpFederationManager;
        let realm_id = RealmId::new("test").unwrap();
        assert!(mgr.providers_for_realm(&realm_id).await.unwrap().is_empty());
        assert!(mgr.find_user(&realm_id, "alice").await.unwrap().is_none());
        assert!(mgr.find_user_by_email(&realm_id, "alice@example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dynamic_manager_empty_realm() {
        let storage = setup_storage_with_idps(vec![]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        let providers = mgr.providers_for_realm(&realm_id).await.unwrap();
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn dynamic_manager_kerberos_provider() {
        let storage = setup_storage_with_idps(vec![kerberos_idp("krb1", 10, true)]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        let providers = mgr.providers_for_realm(&realm_id).await.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider_type(), issuerd_core::FederationProviderType::Kerberos);
    }

    #[tokio::test]
    async fn dynamic_manager_skips_disabled_and_unknown() {
        let unknown = IdentityProviderConfig {
            id: IdentityProviderId::new("saml1").unwrap(),
            alias: issuerd_core::Alias::new("saml1").unwrap(),
            provider_id: issuerd_core::ProviderId::new("saml"),
            enabled: true,
            config: HashMap::new(),
        };
        let storage = setup_storage_with_idps(vec![
            kerberos_idp("krb1", 10, true),
            kerberos_idp("krb2", 5, false),
            unknown,
        ])
        .await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        let providers = mgr.providers_for_realm(&realm_id).await.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id(), "krb1");
    }

    #[tokio::test]
    async fn dynamic_manager_priority_sort() {
        let storage = setup_storage_with_idps(vec![
            kerberos_idp("krb-low", 1, true),
            kerberos_idp("krb-high", 100, true),
        ])
        .await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        let providers = mgr.providers_for_realm(&realm_id).await.unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].id(), "krb-high");
        assert_eq!(providers[1].id(), "krb-low");
    }

    #[tokio::test]
    async fn dynamic_manager_find_user_success() {
        let storage = setup_storage_with_idps(vec![kerberos_idp("krb1", 10, true)]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        let (provider, user) = mgr.find_user(&realm_id, "alice").await.unwrap().unwrap();
        assert_eq!(provider.id(), "krb1");
        assert_eq!(user.username, "alice");
    }

    #[tokio::test]
    async fn dynamic_manager_find_user_not_found() {
        let storage = setup_storage_with_idps(vec![]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.find_user(&realm_id, "nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dynamic_manager_find_user_by_email_none() {
        let storage = setup_storage_with_idps(vec![kerberos_idp("krb1", 10, true)]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.find_user_by_email(&realm_id, "alice@example.com").await.unwrap().is_none());
    }

    #[test]
    fn build_default_mappers_returns_empty() {
        let mappers = build_default_mappers(&HashMap::new());
        assert!(mappers.is_empty());
    }

    #[test]
    fn build_default_mappers_wires_group_mapper_from_config() {
        let config = HashMap::from([(
            "groupsDn".to_string(),
            "OU=IssuerdGroups,DC=test,DC=issuerd,DC=local".to_string(),
        )]);
        let mappers = build_default_mappers(&config);
        assert_eq!(mappers.len(), 1);
        assert_eq!(mappers[0].id(), "group-ldap-mapper");
        assert_eq!(mappers[0].requested_attributes(), vec!["memberOf".to_string()]);
    }

    #[tokio::test]
    async fn dynamic_manager_load_providers_error_bad_ldap_config() {
        let mut config = HashMap::new();
        config.insert("priority".to_string(), "10".to_string());
        // Missing required LDAP fields => LdapConfig::from_hashmap will fail.
        let bad_ldap = IdentityProviderConfig {
            id: IdentityProviderId::new("ldap1").unwrap(),
            alias: issuerd_core::Alias::new("ldap1").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        let storage = setup_storage_with_idps(vec![bad_ldap]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        // load_providers should propagate the error.
        assert!(mgr.providers_for_realm(&realm_id).await.is_err());
    }

    #[tokio::test]
    async fn dynamic_manager_storage_error_propagates() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_list_identity_providers()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db down".into())));
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(Arc::new(mock), cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.providers_for_realm(&realm_id).await.is_err());
    }

    #[tokio::test]
    async fn dynamic_manager_find_user_storage_error() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_list_identity_providers()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db down".into())));
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(Arc::new(mock), cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.find_user(&realm_id, "alice").await.is_err());
    }

    #[tokio::test]
    async fn dynamic_manager_find_user_by_email_storage_error() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_list_identity_providers()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db down".into())));
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(Arc::new(mock), cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.find_user_by_email(&realm_id, "alice@example.com").await.is_err());
    }

    #[tokio::test]
    async fn dynamic_manager_kerberos_config_missing_realm() {
        let mut config = HashMap::new();
        config.insert("priority".to_string(), "10".to_string());
        // Missing kerberosRealm => KerberosConfig::from_hashmap fails.
        let bad_krb = IdentityProviderConfig {
            id: IdentityProviderId::new("krb-bad").unwrap(),
            alias: issuerd_core::Alias::new("krb-bad").unwrap(),
            provider_id: issuerd_core::ProviderId::new("kerberos"),
            enabled: true,
            config,
        };
        let storage = setup_storage_with_idps(vec![bad_krb]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.providers_for_realm(&realm_id).await.is_err());
    }

    #[tokio::test]
    async fn dynamic_manager_kerberos_provider_new_fails_bad_keytab() {
        let mut config = HashMap::new();
        config.insert("kerberosRealm".to_string(), "TEST.ISSUERD.LOCAL".to_string());
        config.insert("allowKerberosAuthentication".to_string(), "true".to_string());
        config.insert("serverPrincipal".to_string(), "HTTP/test@TEST.ISSUERD.LOCAL".to_string());
        config.insert("keyTab".to_string(), "/nonexistent/keytab".to_string());
        config.insert("priority".to_string(), "10".to_string());
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new("krb1").unwrap(),
            alias: issuerd_core::Alias::new("krb1").unwrap(),
            provider_id: issuerd_core::ProviderId::new("kerberos"),
            enabled: true,
            config,
        };
        let storage = setup_storage_with_idps(vec![idp]).await;
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(InMemoryCache::new());
        let mgr = DynamicFederationManager::new(storage, cache);
        let realm_id = RealmId::new("test-realm").unwrap();
        assert!(mgr.providers_for_realm(&realm_id).await.is_err());
    }
}
