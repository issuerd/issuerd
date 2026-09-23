// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC/OAuth2 protocol parsing and validation crate root (pure functions, no I/O).

#![forbid(unsafe_code)]

pub mod authorization;
pub mod ciba;
pub mod device;
pub mod discovery;
pub mod error;
pub mod introspection;
pub mod pkce;
pub mod token;
pub mod utils;
