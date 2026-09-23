// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// LDAP federation provider: user lookup, password validation/write, and user sync.

use std::collections::HashMap;
use std::sync::Arc;

use issuerd_core::{
    EditMode, FederatedUser, FederationError, FederationProvider, FederationProviderType,
    SyncResult,
};
use ldap3::Scope;

use crate::ldap::config::{LdapConfig, LdapSearchScope};
use crate::ldap::pool::{LdapConnectionFactory, LdapConnectionPool};
use crate::mapper::LdapMapper;

/// Cap on per-entry WARN lines emitted while streaming users: the first
/// failures are logged with full detail, the rest are counted and reported
/// once at the end (one systematic failure must not produce 100k lines).
const MAX_DETAILED_FAILURE_LOGS: usize = 10;

/// Escape an LDAP attribute value according to RFC 4514.
///
/// The following characters are escaped with a backslash:
/// `\`, `"`, `+`, `,`, `;`, `<`, `>`, `=`.  A leading or trailing space
/// and a leading `#` are also escaped.  Non-printable characters are
/// emitted as `\XX` hex escapes.
pub fn escape_dn_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let last = bytes.len().saturating_sub(1);
    for (i, &b) in bytes.iter().enumerate() {
        let at_start = i == 0;
        let at_end = i == last;
        match b {
            b'\\' | b'"' | b'+' | b',' | b';' | b'<' | b'>' | b'=' => {
                escaped.push('\\');
                escaped.push(b as char);
            }
            b' ' if at_start || at_end => {
                escaped.push('\\');
                escaped.push(' ');
            }
            b'#' if at_start => {
                escaped.push('\\');
                escaped.push('#');
            }
            b if b < 0x20 || b == 0x7f => {
                escaped.push_str(&format!("\\{b:02x}"));
            }
            _ => escaped.push(b as char),
        }
    }
    escaped
}

/// LDAP-backed federation provider.
pub struct LdapFederationProvider {
    id: String,
    config: LdapConfig,
    factory: Arc<dyn LdapConnectionFactory>,
    mappers: Vec<Box<dyn LdapMapper>>,
}

impl LdapFederationProvider {
    /// Create a new provider with a real connection pool.
    pub async fn new(
        id: String,
        config: LdapConfig,
        mappers: Vec<Box<dyn LdapMapper>>,
    ) -> Result<Self, FederationError> {
        let pool = LdapConnectionPool::new(&config, 5).await?;
        Ok(Self {
            id,
            config,
            factory: Arc::new(pool),
            mappers,
        })
    }

    /// Create a new provider with a custom connection factory (used in tests).
    #[cfg(test)]
    pub fn with_factory(
        id: String,
        config: LdapConfig,
        factory: Arc<dyn LdapConnectionFactory>,
        mappers: Vec<Box<dyn LdapMapper>>,
    ) -> Self {
        Self {
            id,
            config,
            factory,
            mappers,
        }
    }

    /// Attribute list for user searches: `"*"` plus any attributes the
    /// mappers explicitly need (some directories do not return operational
    /// attributes like `memberOf` for `"*"`).
    fn search_attributes_owned(&self) -> Vec<String> {
        let mut attrs = vec!["*".to_string()];
        for mapper in &self.mappers {
            for attr in mapper.requested_attributes() {
                if !attrs.iter().any(|a| a.eq_ignore_ascii_case(&attr)) {
                    attrs.push(attr);
                }
            }
        }
        attrs
    }

    async fn search_user(
        &self,
        username: &str,
    ) -> Result<Option<HashMap<String, Vec<String>>>, FederationError> {
        let mut conn = self.factory.acquire().await?;
        conn.bind(&self.config.bind_dn, &self.config.bind_credential).await?;
        let filter = self.config.user_search_filter(username);
        let scope = match self.config.search_scope {
            LdapSearchScope::Subtree => Scope::Subtree,
            LdapSearchScope::OneLevel => Scope::OneLevel,
            LdapSearchScope::Base => Scope::Base,
        };
        let attrs = self.search_attributes_owned();
        let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
        let entries = conn
            .paged_search(&self.config.users_dn, scope, &filter, &attr_refs, self.config.batch_size)
            .await?;
        if entries.is_empty() {
            return Ok(None);
        }
        let entry = &entries[0];
        let mut attrs = HashMap::new();
        for (k, v) in &entry.attrs {
            attrs.insert(k.clone(), v.clone());
        }
        Ok(Some(attrs))
    }

    async fn search_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<HashMap<String, Vec<String>>>, FederationError> {
        let mut conn = self.factory.acquire().await?;
        conn.bind(&self.config.bind_dn, &self.config.bind_credential).await?;
        let filter = self.config.email_search_filter(email);
        let scope = match self.config.search_scope {
            LdapSearchScope::Subtree => Scope::Subtree,
            LdapSearchScope::OneLevel => Scope::OneLevel,
            LdapSearchScope::Base => Scope::Base,
        };
        let attrs = self.search_attributes_owned();
        let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
        let entries = conn.search(&self.config.users_dn, scope, &filter, &attr_refs).await?;
        if entries.is_empty() {
            return Ok(None);
        }
        let entry = &entries[0];
        let mut attrs = HashMap::new();
        for (k, v) in &entry.attrs {
            attrs.insert(k.clone(), v.clone());
        }
        Ok(Some(attrs))
    }

    fn apply_mappers(
        &self,
        attrs: &HashMap<String, Vec<String>>,
        username: &str,
    ) -> Result<FederatedUser, FederationError> {
        let mut user = FederatedUser {
            username: username.to_string(),
            federation_link: self.id.clone(),
            enabled: true,
            ..Default::default()
        };
        for mapper in &self.mappers {
            mapper.map_user(attrs, &mut user)?;
        }
        for mapper in &self.mappers {
            if let Some(enabled) = mapper.map_enabled(attrs) {
                user.enabled = enabled;
            }
        }
        let mut memberships = Vec::new();
        for mapper in &self.mappers {
            memberships.extend(mapper.map_memberships(attrs));
        }
        if !memberships.is_empty() {
            user.attributes.insert("memberOf".to_string(), memberships);
        }
        user.groups = self.collect_groups(attrs);
        Ok(user)
    }

    /// Whether any wired mapper reports group memberships — only then is
    /// `FederatedUser.groups` authoritative (`Some`); otherwise it stays
    /// `None` and callers must not touch local memberships.
    fn groups_reported(&self) -> bool {
        self.mappers.iter().any(|m| m.reports_groups())
    }

    fn collect_groups(&self, attrs: &HashMap<String, Vec<String>>) -> Option<Vec<String>> {
        if !self.groups_reported() {
            return None;
        }
        let mut groups = Vec::new();
        for mapper in &self.mappers {
            groups.extend(mapper.map_groups(attrs));
        }
        groups.sort();
        groups.dedup();
        Some(groups)
    }

    fn build_user_dn(&self, username: &str) -> String {
        format!(
            "{}={},{}",
            self.config.rdn_attribute,
            escape_dn_value(username),
            self.config.users_dn
        )
    }
}

#[async_trait::async_trait]
impl FederationProvider for LdapFederationProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> FederationProviderType {
        FederationProviderType::Ldap
    }

    async fn find_user(&self, username: &str) -> Result<Option<FederatedUser>, FederationError> {
        let attrs = match self.search_user(username).await? {
            Some(a) => a,
            None => return Ok(None),
        };
        let user = self.apply_mappers(&attrs, username)?;
        Ok(Some(user))
    }

    async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<FederatedUser>, FederationError> {
        let attrs = match self.search_user_by_email(email).await? {
            Some(a) => a,
            None => return Ok(None),
        };
        // Use the username from the config attribute if present, otherwise email local-part
        let username = attrs
            .get(&self.config.username_attribute)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| email.split('@').next().unwrap_or(email).to_string());
        let user = self.apply_mappers(&attrs, &username)?;
        Ok(Some(user))
    }

    async fn validate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<bool, FederationError> {
        // Always perform the bind even when the user is not found to avoid a
        // timing side-channel that would reveal whether a username exists.
        let user_exists = match self.search_user(username).await {
            Ok(Some(_)) => true,
            Ok(None) => {
                tracing::debug!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), "LDAP user not found by search; performing dummy bind");
                false
            }
            Err(e) => {
                tracing::debug!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), error = %e, "LDAP user search error");
                return Err(e);
            }
        };
        let user_dn = self.build_user_dn(username);
        tracing::debug!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), user_dn = %user_dn, "attempting LDAP bind for password validation");
        let mut conn = self.factory.acquire().await?;
        match conn.bind(&user_dn, password).await {
            Ok(()) if user_exists => {
                tracing::debug!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), "LDAP password validation succeeded");
                Ok(true)
            }
            Ok(()) => {
                tracing::debug!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), "LDAP password validation failed: user not found");
                Ok(false)
            }
            Err(FederationError::InvalidCredentials) => {
                tracing::debug!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), "LDAP password validation failed: invalid credentials");
                Ok(false)
            }
            Err(e) => {
                tracing::warn!(provider_id = %self.id, username = %issuerd_core::utils::sanitize_log_str(username), error = %e, "LDAP password validation error");
                Err(e)
            }
        }
    }

    async fn update_password(&self, username: &str, password: &str) -> Result<(), FederationError> {
        if self.config.edit_mode == EditMode::ReadOnly {
            return Err(FederationError::NotSupported);
        }
        let user_dn = self.build_user_dn(username);
        let mut conn = self.factory.acquire().await?;
        conn.bind(&self.config.bind_dn, &self.config.bind_credential).await?;

        if self.config.vendor == crate::ldap::config::LdapVendor::ActiveDirectory {
            // AD: unicodePwd with UTF-16LE, quoted
            let mut encoded: Vec<u8> = vec![0x22, 0x00]; // opening quote LE
            for chunk in password.encode_utf16() {
                encoded.extend_from_slice(&chunk.to_le_bytes());
            }
            encoded.extend_from_slice(&[0x22, 0x00]); // closing quote LE
            conn.modify_replace(&user_dn, "unicodePwd", &[encoded]).await?;
        } else {
            conn.modify_replace(&user_dn, "userPassword", &[password.as_bytes().to_vec()])
                .await?;
        }
        Ok(())
    }

    fn supports_password_update(&self) -> bool {
        self.config.edit_mode != EditMode::ReadOnly
    }

    async fn sync_users(&self) -> Result<SyncResult, FederationError> {
        let users = self.stream_users().await?;
        Ok(SyncResult {
            added: users.len(),
            updated: 0,
            removed: 0,
            failed: 0,
            last_sync: chrono::Utc::now(),
        })
    }

    async fn stream_users(&self) -> Result<Vec<FederatedUser>, FederationError> {
        let mut conn = self.factory.acquire().await?;
        conn.bind(&self.config.bind_dn, &self.config.bind_credential).await?;

        let filter = self.config.all_users_filter();
        let scope = match self.config.search_scope {
            LdapSearchScope::Subtree => Scope::Subtree,
            LdapSearchScope::OneLevel => Scope::OneLevel,
            LdapSearchScope::Base => Scope::Base,
        };
        let attrs = self.search_attributes_owned();
        let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
        let entries = conn
            .paged_search(&self.config.users_dn, scope, &filter, &attr_refs, self.config.batch_size)
            .await?;

        let mut users = Vec::new();
        let mut mapper_errors = 0usize;
        for entry in entries {
            let username = entry
                .attrs
                .get(&self.config.username_attribute)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            if username.is_empty() {
                continue;
            }
            let mut user = FederatedUser {
                username: username.clone(),
                federation_link: self.id.clone(),
                enabled: true,
                ..Default::default()
            };
            for mapper in &self.mappers {
                if let Err(e) = mapper.map_user(&entry.attrs, &mut user) {
                    mapper_errors += 1;
                    if mapper_errors <= MAX_DETAILED_FAILURE_LOGS {
                        tracing::warn!(
                            username = %issuerd_core::utils::sanitize_log_str(&user.username),
                            error = %e,
                            "LDAP entry mapper error"
                        );
                    }
                }
            }
            for mapper in &self.mappers {
                if let Some(enabled) = mapper.map_enabled(&entry.attrs) {
                    user.enabled = enabled;
                }
            }
            let mut memberships = Vec::new();
            for mapper in &self.mappers {
                memberships.extend(mapper.map_memberships(&entry.attrs));
            }
            if !memberships.is_empty() {
                user.attributes.insert("memberOf".to_string(), memberships);
            }
            user.groups = self.collect_groups(&entry.attrs);
            users.push(user);
        }
        if mapper_errors > MAX_DETAILED_FAILURE_LOGS {
            tracing::warn!(
                suppressed = mapper_errors - MAX_DETAILED_FAILURE_LOGS,
                "further LDAP entry mapper errors suppressed"
            );
        }
        Ok(users)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::ldap::connection::LdapClient;

    use super::*;
    use crate::mapper::{MsadAccountControlMapper, UserAttributeMapper};

    struct MockLdapClient {
        bind_results: Mutex<Vec<Result<(), FederationError>>>,
        search_results: Mutex<Vec<Result<Vec<ldap3::SearchEntry>, FederationError>>>,
        modify_results: Mutex<Vec<Result<(), FederationError>>>,
    }

    #[async_trait::async_trait]
    impl LdapClient for MockLdapClient {
        async fn bind(&mut self, _dn: &str, _pw: &str) -> Result<(), FederationError> {
            self.bind_results.lock().unwrap().remove(0)
        }
        async fn search(
            &mut self,
            _base: &str,
            _scope: ldap3::Scope,
            _filter: &str,
            _attrs: &[&str],
        ) -> Result<Vec<ldap3::SearchEntry>, FederationError> {
            self.search_results.lock().unwrap().remove(0)
        }
        async fn paged_search(
            &mut self,
            _base: &str,
            _scope: ldap3::Scope,
            _filter: &str,
            _attrs: &[&str],
            _page_size: i32,
        ) -> Result<Vec<ldap3::SearchEntry>, FederationError> {
            self.search_results.lock().unwrap().remove(0)
        }
        async fn modify_replace(
            &mut self,
            _dn: &str,
            _attr: &str,
            _values: &[Vec<u8>],
        ) -> Result<(), FederationError> {
            self.modify_results.lock().unwrap().remove(0)
        }
        async fn modify_add(
            &mut self,
            _dn: &str,
            _attr: &str,
            _values: &[Vec<u8>],
        ) -> Result<(), FederationError> {
            self.modify_results.lock().unwrap().remove(0)
        }
        async fn add(
            &mut self,
            _dn: &str,
            _attrs: Vec<(String, Vec<String>)>,
        ) -> Result<(), FederationError> {
            self.modify_results.lock().unwrap().remove(0)
        }
    }

    struct MockFactory {
        clients: Mutex<Vec<MockLdapClient>>,
    }

    #[async_trait::async_trait]
    impl LdapConnectionFactory for MockFactory {
        async fn acquire(&self) -> Result<Box<dyn LdapClient>, FederationError> {
            let client = self.clients.lock().unwrap().remove(0);
            Ok(Box::new(client))
        }
    }

    fn test_config() -> LdapConfig {
        LdapConfig {
            connection_url: "ldap://test".to_string(),
            bind_dn: "cn=admin,dc=test".to_string(),
            bind_credential: "admin".to_string(),
            users_dn: "ou=users,dc=test".to_string(),
            base_dn: "dc=test".to_string(),
            username_attribute: "uid".to_string(),
            rdn_attribute: "uid".to_string(),
            uuid_attribute: "entryUUID".to_string(),
            user_object_classes: vec!["inetOrgPerson".to_string()],
            edit_mode: EditMode::Writable,
            custom_user_search_filter: None,
            search_scope: LdapSearchScope::Subtree,
            use_starttls: false,
            no_tls_verify: false,
            pagination: false,
            batch_size: 1000,
            max_conditions: 1000,
            vendor: crate::ldap::config::LdapVendor::Generic,
        }
    }

    fn make_provider(
        factory: MockFactory,
        mappers: Vec<Box<dyn LdapMapper>>,
    ) -> LdapFederationProvider {
        LdapFederationProvider::with_factory(
            "ldap-test".to_string(),
            test_config(),
            Arc::new(factory),
            mappers,
        )
    }

    fn memberof_entry(username: &str, member_of: &[&str]) -> ldap3::SearchEntry {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec![username.to_string()]);
        attrs.insert(
            "memberOf".to_string(),
            member_of.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        );
        ldap3::SearchEntry {
            dn: format!("uid={username},ou=users,dc=test"),
            attrs,
            bin_attrs: HashMap::new(),
        }
    }

    fn group_mapper() -> Box<dyn LdapMapper> {
        Box::new(
            crate::mapper::GroupMapper::from_config(&HashMap::from([(
                "groupsDn".to_string(),
                "ou=groups,dc=test".to_string(),
            )]))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn find_user_populates_groups_only_with_group_mapper() {
        let with_mapper = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![memberof_entry(
                    "alice",
                    &["cn=devs,ou=groups,dc=test", "cn=other,ou=elsewhere,dc=test"],
                )])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };
        let provider = make_provider(with_mapper, vec![group_mapper()]);
        let user = provider.find_user("alice").await.unwrap().unwrap();
        assert_eq!(user.groups, Some(vec!["devs".to_string()]));

        let without_mapper = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![memberof_entry(
                    "alice",
                    &["cn=devs,ou=groups,dc=test"],
                )])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };
        let provider = make_provider(without_mapper, vec![]);
        let user = provider.find_user("alice").await.unwrap().unwrap();
        // No group mapper wired: groups are "not reported", not empty.
        assert_eq!(user.groups, None);
    }

    #[tokio::test]
    async fn stream_users_populates_groups_with_group_mapper() {
        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![
                    memberof_entry("alice", &["cn=devs,ou=groups,dc=test"]),
                    memberof_entry("bob", &[]),
                ])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };
        let provider = make_provider(factory, vec![group_mapper()]);
        let users = provider.stream_users().await.unwrap();
        assert_eq!(users[0].groups, Some(vec!["devs".to_string()]));
        // Mapper wired but no memberships: authoritative empty set.
        assert_eq!(users[1].groups, Some(vec![]));
    }

    #[tokio::test]
    async fn ldap_provider_find_user_success() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        attrs.insert("mail".to_string(), vec!["alice@example.com".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![entry])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };

        let provider = make_provider(
            factory,
            vec![Box::new(UserAttributeMapper {
                user_attribute: "email".to_string(),
                ldap_attribute: "mail".to_string(),
                read_only: true,
                always_read_from_ldap: false,
                is_mandatory_in_ldap: false,
                default_value: None,
            })],
        );

        let user = provider.find_user("alice").await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, Some("alice@example.com".to_string()));
    }

    #[tokio::test]
    async fn ldap_provider_find_user_not_found() {
        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };

        let provider = make_provider(factory, vec![]);
        assert!(provider.find_user("bob").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ldap_provider_validate_password_success() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![
                MockLdapClient {
                    bind_results: Mutex::new(vec![Ok(())]),
                    search_results: Mutex::new(vec![Ok(vec![entry])]),
                    modify_results: Mutex::new(vec![]),
                },
                MockLdapClient {
                    bind_results: Mutex::new(vec![Ok(())]),
                    search_results: Mutex::new(vec![]),
                    modify_results: Mutex::new(vec![]),
                },
            ]),
        };

        let provider = make_provider(factory, vec![]);
        assert!(provider.validate_password("alice", "secret").await.unwrap());
    }

    #[tokio::test]
    async fn ldap_provider_validate_password_bad() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![
                MockLdapClient {
                    bind_results: Mutex::new(vec![Ok(())]),
                    search_results: Mutex::new(vec![Ok(vec![entry])]),
                    modify_results: Mutex::new(vec![]),
                },
                MockLdapClient {
                    bind_results: Mutex::new(vec![Err(FederationError::InvalidCredentials)]),
                    search_results: Mutex::new(vec![]),
                    modify_results: Mutex::new(vec![]),
                },
            ]),
        };

        let provider = make_provider(factory, vec![]);
        assert!(!provider.validate_password("alice", "wrong").await.unwrap());
    }

    #[tokio::test]
    async fn ldap_provider_validate_password_not_found() {
        // Even when the user is not found, a bind attempt must be performed so
        // the response time does not reveal whether the username exists.
        let factory = MockFactory {
            clients: Mutex::new(vec![
                MockLdapClient {
                    bind_results: Mutex::new(vec![Ok(())]),
                    search_results: Mutex::new(vec![Ok(vec![])]),
                    modify_results: Mutex::new(vec![]),
                },
                MockLdapClient {
                    bind_results: Mutex::new(vec![Err(FederationError::InvalidCredentials)]),
                    search_results: Mutex::new(vec![]),
                    modify_results: Mutex::new(vec![]),
                },
            ]),
        };

        let provider = make_provider(factory, vec![]);
        assert!(!provider.validate_password("missing", "secret").await.unwrap());
    }

    #[test]
    fn ldap_provider_escape_dn_value() {
        assert_eq!(escape_dn_value("alice"), "alice");
        assert_eq!(escape_dn_value("alice,admin"), "alice\\,admin");
        assert_eq!(escape_dn_value("alice=admin"), "alice\\=admin");
        assert_eq!(escape_dn_value("alice+admin"), "alice\\+admin");
        assert_eq!(escape_dn_value(" alice "), "\\ alice\\ ");
        assert_eq!(escape_dn_value("#alice"), "\\#alice");
        assert_eq!(escape_dn_value("alice\\admin"), "alice\\\\admin");
        assert_eq!(escape_dn_value("alice\"admin"), "alice\\\"admin");
        assert_eq!(escape_dn_value("alice<admin>"), "alice\\<admin\\>");
        assert_eq!(escape_dn_value("alice;admin"), "alice\\;admin");
    }

    #[test]
    fn ldap_provider_build_user_dn_escaped() {
        let factory = MockFactory {
            clients: Mutex::new(vec![]),
        };
        let provider = make_provider(factory, vec![]);
        assert_eq!(provider.build_user_dn("alice,admin"), "uid=alice\\,admin,ou=users,dc=test");
    }

    #[tokio::test]
    async fn ldap_provider_update_password_readonly() {
        let mut config = test_config();
        config.edit_mode = EditMode::ReadOnly;

        let factory = MockFactory {
            clients: Mutex::new(vec![]),
        };

        let provider = LdapFederationProvider::with_factory(
            "ldap-test".to_string(),
            config,
            Arc::new(factory),
            vec![],
        );
        let err = provider.update_password("alice", "new").await.unwrap_err();
        assert!(matches!(err, FederationError::NotSupported));
    }

    #[tokio::test]
    async fn ldap_provider_update_password_ad_unicode() {
        let mut config = test_config();
        config.vendor = crate::ldap::config::LdapVendor::ActiveDirectory;

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![]),
                modify_results: Mutex::new(vec![Ok(())]),
            }]),
        };

        let provider = LdapFederationProvider::with_factory(
            "ldap-test".to_string(),
            config,
            Arc::new(factory),
            vec![],
        );
        provider.update_password("alice", "NewPass1!").await.unwrap();
    }

    #[tokio::test]
    async fn ldap_provider_update_password_generic() {
        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![]),
                modify_results: Mutex::new(vec![Ok(())]),
            }]),
        };

        let provider = make_provider(factory, vec![]);
        provider.update_password("alice", "newpass").await.unwrap();
    }

    #[tokio::test]
    async fn ldap_provider_find_user_msad_disabled() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        attrs.insert("userAccountControl".to_string(), vec!["514".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![entry])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };

        let provider = make_provider(factory, vec![Box::new(MsadAccountControlMapper)]);
        let user = provider.find_user("alice").await.unwrap().unwrap();
        assert!(!user.enabled);
    }

    #[tokio::test]
    async fn ldap_provider_find_user_by_email_success() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        attrs.insert("mail".to_string(), vec!["alice@example.com".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![entry])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };

        let provider = make_provider(factory, vec![]);
        let user = provider.find_user_by_email("alice@example.com").await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
    }

    #[tokio::test]
    async fn ldap_provider_find_user_by_email_not_found() {
        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };
        let provider = make_provider(factory, vec![]);
        assert!(provider.find_user_by_email("nobody@example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ldap_provider_validate_password_search_error() {
        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Err(FederationError::NetworkError("down".into()))]),
                modify_results: Mutex::new(vec![]),
            }]),
        };
        let provider = make_provider(factory, vec![]);
        let err = provider.validate_password("alice", "secret").await.unwrap_err();
        assert!(matches!(err, FederationError::NetworkError(_)));
    }

    #[tokio::test]
    async fn ldap_provider_sync_users() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![entry])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };

        let provider = make_provider(factory, vec![]);
        let result = provider.sync_users().await.unwrap();
        assert_eq!(result.added, 1);
    }

    #[tokio::test]
    async fn ldap_provider_stream_users_mapper_error() {
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        let entry = ldap3::SearchEntry {
            dn: "uid=alice,ou=users,dc=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![Ok(vec![entry])]),
                modify_results: Mutex::new(vec![]),
            }]),
        };

        let provider = make_provider(
            factory,
            vec![Box::new(UserAttributeMapper {
                user_attribute: "email".to_string(),
                ldap_attribute: "mail".to_string(),
                read_only: true,
                always_read_from_ldap: false,
                is_mandatory_in_ldap: true,
                default_value: None,
            })],
        );
        let users = provider.stream_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
    }

    #[tokio::test]
    async fn ldap_provider_update_password_unsynced() {
        let mut config = test_config();
        config.edit_mode = EditMode::Unsynced;

        let factory = MockFactory {
            clients: Mutex::new(vec![MockLdapClient {
                bind_results: Mutex::new(vec![Ok(())]),
                search_results: Mutex::new(vec![]),
                modify_results: Mutex::new(vec![Ok(())]),
            }]),
        };

        let provider = LdapFederationProvider::with_factory(
            "ldap-test".to_string(),
            config,
            Arc::new(factory),
            vec![],
        );
        provider.update_password("alice", "new").await.unwrap();
    }

    #[tokio::test]
    async fn ldap_provider_supports_password_update_tracks_edit_mode() {
        let cases = [
            (EditMode::ReadOnly, false),
            (EditMode::Writable, true),
            (EditMode::Unsynced, true),
        ];
        for (edit_mode, expected) in cases {
            let mut config = test_config();
            config.edit_mode = edit_mode;
            let provider = LdapFederationProvider::with_factory(
                "ldap-test".to_string(),
                config,
                Arc::new(MockFactory {
                    clients: Mutex::new(vec![]),
                }),
                vec![],
            );
            assert_eq!(
                issuerd_core::FederationProvider::supports_password_update(&provider),
                expected,
                "edit_mode {edit_mode:?}"
            );
        }
    }
}
