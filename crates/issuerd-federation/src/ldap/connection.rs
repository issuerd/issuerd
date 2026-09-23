// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// LDAP client abstraction plus the ldap3-backed connection implementation.

use issuerd_core::FederationError;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry, SearchResult};

/// Abstract LDAP operations for testability.
#[async_trait::async_trait]
pub trait LdapClient: Send + Sync {
    async fn bind(&mut self, dn: &str, pw: &str) -> Result<(), FederationError>;
    async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, FederationError>;
    /// Perform a paged search (RFC 2696) to retrieve arbitrarily large result sets.
    async fn paged_search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        page_size: i32,
    ) -> Result<Vec<SearchEntry>, FederationError>;
    async fn modify_replace(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[Vec<u8>],
    ) -> Result<(), FederationError>;

    async fn modify_add(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[Vec<u8>],
    ) -> Result<(), FederationError>;

    async fn add(
        &mut self,
        dn: &str,
        attrs: Vec<(String, Vec<String>)>,
    ) -> Result<(), FederationError>;
}

/// A single LDAP connection handle.
pub struct LdapConnection {
    ldap: Ldap,
}

impl LdapConnection {
    /// Connect to an LDAP server (plain TCP, `ldaps://`, or StartTLS).
    /// `no_tls_verify` disables certificate verification on the TLS variants
    /// (INSECURE — lab/dev only, e.g. self-signed directory certificates).
    pub async fn connect(
        url: &str,
        use_starttls: bool,
        no_tls_verify: bool,
    ) -> Result<Self, FederationError> {
        let settings = LdapConnSettings::new()
            .set_starttls(use_starttls)
            .set_no_tls_verify(no_tls_verify);
        let (conn, ldap) =
            LdapConnAsync::with_settings(settings, url).await.map_err(map_ldap_err)?;

        // Drive the connection in the background.
        tokio::spawn(async move {
            // The driver only resolves once the connection is dead; an error
            // here orphans every later operation on the handle, so surface it.
            if let Err(e) = conn.drive().await {
                tracing::warn!(error = %e, "LDAP connection driver ended with an error");
            }
        });

        Ok(Self { ldap })
    }
}

#[async_trait::async_trait]
impl LdapClient for LdapConnection {
    async fn bind(&mut self, dn: &str, pw: &str) -> Result<(), FederationError> {
        let result = self.ldap.simple_bind(dn, pw).await.map_err(map_ldap_err)?;
        if result.rc != 0 {
            // 49 = invalid credentials
            if result.rc == 49 {
                return Err(FederationError::InvalidCredentials);
            }
            return Err(FederationError::NetworkError(format!(
                "LDAP bind failed: rc={} text={:?}",
                result.rc, result.text
            )));
        }
        Ok(())
    }

    async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, FederationError> {
        let search_result: SearchResult =
            self.ldap.search(base, scope, filter, attrs).await.map_err(map_ldap_err)?;

        let (entries, result) = search_result
            .success()
            .map_err(|e| FederationError::NetworkError(format!("LDAP search failed: {e}")))?;

        if result.rc == 10 {
            // Referral — explicitly not chased per spec.
            return Err(FederationError::NetworkError("referral".into()));
        }

        Ok(entries.into_iter().map(SearchEntry::construct).collect())
    }

    async fn paged_search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        page_size: i32,
    ) -> Result<Vec<SearchEntry>, FederationError> {
        use ldap3::adapters::{EntriesOnly, PagedResults};

        let adapters: Vec<Box<dyn ldap3::adapters::Adapter<'_, &str, &[&str]>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(page_size)),
        ];
        let mut stream = self
            .ldap
            .streaming_search_with(adapters, base, scope, filter, attrs)
            .await
            .map_err(map_ldap_err)?;

        let mut entries = Vec::new();
        while let Some(entry) = stream.next().await.map_err(map_ldap_err)? {
            entries.push(SearchEntry::construct(entry));
        }
        let result = stream.finish().await;
        if result.rc != 0 && result.rc != 10 {
            return Err(FederationError::NetworkError(format!(
                "LDAP paged search failed: rc={} text={:?}",
                result.rc, result.text
            )));
        }
        Ok(entries)
    }

    async fn modify_replace(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[Vec<u8>],
    ) -> Result<(), FederationError> {
        use ldap3::Mod;
        use std::collections::HashSet;

        let attr_bytes = attr.as_bytes().to_vec();
        let set: HashSet<Vec<u8>> = values.iter().cloned().collect();
        let result = self
            .ldap
            .modify(dn, vec![Mod::Replace(attr_bytes, set)])
            .await
            .map_err(map_ldap_err)?;

        if result.rc != 0 {
            return Err(FederationError::NetworkError(format!(
                "LDAP modify failed: rc={} text={:?}",
                result.rc, result.text
            )));
        }
        Ok(())
    }

    async fn modify_add(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[Vec<u8>],
    ) -> Result<(), FederationError> {
        use ldap3::Mod;
        use std::collections::HashSet;

        let attr_bytes = attr.as_bytes().to_vec();
        let set: HashSet<Vec<u8>> = values.iter().cloned().collect();
        let result = self
            .ldap
            .modify(dn, vec![Mod::Add(attr_bytes, set)])
            .await
            .map_err(map_ldap_err)?;

        if result.rc != 0 {
            return Err(FederationError::NetworkError(format!(
                "LDAP modify_add failed: rc={} text={:?}",
                result.rc, result.text
            )));
        }
        Ok(())
    }

    async fn add(
        &mut self,
        dn: &str,
        attrs: Vec<(String, Vec<String>)>,
    ) -> Result<(), FederationError> {
        use std::collections::HashSet;

        let ldap_attrs: Vec<(String, HashSet<String>)> = attrs
            .into_iter()
            .map(|(k, vals)| {
                let set: HashSet<String> = vals.into_iter().collect();
                (k, set)
            })
            .collect();

        let result = self.ldap.add(dn, ldap_attrs).await.map_err(map_ldap_err)?;

        if result.rc != 0 {
            return Err(FederationError::NetworkError(format!(
                "LDAP add failed: rc={} text={:?}",
                result.rc, result.text
            )));
        }
        Ok(())
    }
}

fn map_ldap_err(e: LdapError) -> FederationError {
    match e {
        LdapError::LdapResult { result } if result.rc == 49 => FederationError::InvalidCredentials,
        LdapError::Io { source } => FederationError::NetworkError(source.to_string()),
        _ => FederationError::NetworkError(e.to_string()),
    }
}
