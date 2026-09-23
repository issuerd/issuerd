// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// issuerd-server crate root: module declarations for the HTTP server composition root.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod broker;
pub mod claims;
pub mod claims_cache;
pub mod client_assertion;
pub mod config;
pub mod discovery_cache;
pub mod dpop;
pub mod email;
pub mod event_listeners;
pub mod groups;
pub mod i18n;
pub mod middleware;
pub mod openapi;
pub mod provisioner;
pub mod qr;
pub mod routes;
pub mod session_cache;
pub mod state;
pub mod tls;
pub mod typestate;
pub mod userinfo_cache;
