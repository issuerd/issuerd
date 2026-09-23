// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Semaphore-guarded LDAP connection pool and connection factory trait.

use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};

use crate::ldap::config::LdapConfig;
use crate::ldap::connection::{LdapClient, LdapConnection};
use issuerd_core::FederationError;

/// Factory that produces LDAP connections.
#[async_trait::async_trait]
pub trait LdapConnectionFactory: Send + Sync {
    async fn acquire(&self) -> Result<Box<dyn LdapClient>, FederationError>;
}

/// A simple semaphore-guarded pool of LDAP connections.
pub struct LdapConnectionPool {
    #[allow(dead_code)]
    config: LdapConfig,
    semaphore: Arc<Semaphore>,
    connections: Arc<Mutex<Vec<LdapConnection>>>,
}

impl LdapConnectionPool {
    /// Create a new pool with `size` connections.
    pub async fn new(config: &LdapConfig, size: usize) -> Result<Self, FederationError> {
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = LdapConnection::connect(
                &config.connection_url,
                config.use_starttls,
                config.no_tls_verify,
            )
            .await?;
            conns.push(conn);
        }
        Ok(Self {
            config: config.clone(),
            semaphore: Arc::new(Semaphore::new(size)),
            connections: Arc::new(Mutex::new(conns)),
        })
    }
}

#[async_trait::async_trait]
impl LdapConnectionFactory for LdapConnectionPool {
    async fn acquire(&self) -> Result<Box<dyn LdapClient>, FederationError> {
        let permit =
            self.semaphore.clone().acquire_owned().await.map_err(|e| {
                FederationError::ProviderUnavailable(format!("semaphore closed: {e}"))
            })?;

        let mut guard = self.connections.lock().await;
        let conn = guard
            .pop()
            .ok_or_else(|| FederationError::ProviderUnavailable("pool exhausted".into()))?;
        drop(guard);

        Ok(Box::new(PooledConnection {
            pool: Arc::clone(&self.connections),
            conn: Some(conn),
            _permit: permit,
        }))
    }
}

/// RAII guard that returns the connection to the pool on drop.
struct PooledConnection {
    pool: Arc<Mutex<Vec<LdapConnection>>>,
    conn: Option<LdapConnection>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let pool = Arc::clone(&self.pool);
            tokio::spawn(async move {
                pool.lock().await.push(conn);
            });
        }
    }
}

#[async_trait::async_trait]
impl LdapClient for PooledConnection {
    async fn bind(&mut self, dn: &str, pw: &str) -> Result<(), FederationError> {
        self.conn.as_mut().unwrap().bind(dn, pw).await
    }

    async fn search(
        &mut self,
        base: &str,
        scope: ldap3::Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<ldap3::SearchEntry>, FederationError> {
        self.conn.as_mut().unwrap().search(base, scope, filter, attrs).await
    }

    async fn paged_search(
        &mut self,
        base: &str,
        scope: ldap3::Scope,
        filter: &str,
        attrs: &[&str],
        page_size: i32,
    ) -> Result<Vec<ldap3::SearchEntry>, FederationError> {
        self.conn
            .as_mut()
            .unwrap()
            .paged_search(base, scope, filter, attrs, page_size)
            .await
    }

    async fn modify_replace(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[Vec<u8>],
    ) -> Result<(), FederationError> {
        self.conn.as_mut().unwrap().modify_replace(dn, attr, values).await
    }

    async fn modify_add(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[Vec<u8>],
    ) -> Result<(), FederationError> {
        self.conn.as_mut().unwrap().modify_add(dn, attr, values).await
    }

    async fn add(
        &mut self,
        dn: &str,
        attrs: Vec<(String, Vec<String>)>,
    ) -> Result<(), FederationError> {
        self.conn.as_mut().unwrap().add(dn, attrs).await
    }
}
