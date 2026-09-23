// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User federation crate root: LDAP/Kerberos providers, mappers, and sync.

#![forbid(unsafe_code)]

pub mod kerberos;
pub mod ldap;
pub mod manager;
pub mod mapper;
pub mod sync;

pub use kerberos::{KerberosConfig, KerberosFederationProvider};
pub use ldap::config::{LdapConfig, LdapSearchScope, LdapVendor};
pub use ldap::pool::LdapConnectionPool;
pub use ldap::provider::LdapFederationProvider;
pub use manager::{DynamicFederationManager, NoOpFederationManager};
