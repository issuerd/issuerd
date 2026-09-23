// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Kerberos federation module: config, provider, and SPNEGO acceptor (Unix only).

pub mod config;
pub mod provider;

#[cfg(unix)]
pub mod spnego;

pub use config::KerberosConfig;
pub use provider::KerberosFederationProvider;

#[cfg(unix)]
pub use spnego::SpnegoAuthenticator;
