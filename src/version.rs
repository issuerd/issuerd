// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Version constants and full version string formatting.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_HASH: &str = env!("ISSUERD_GIT_HASH");

pub fn full_version() -> String {
    format!("Issuerd v{} ({})", VERSION, GIT_HASH)
}
