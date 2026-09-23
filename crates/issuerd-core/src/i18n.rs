// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// UI internationalization shared vocabulary (shipped locales).

//! UI internationalization shared vocabulary.
//!
//! The actual bundle loading and locale resolution live in `issuerd-server`; this
//! module holds only the data both `issuerd-server` and `issuerd-admin-api` need.

/// Locales with a built-in message bundle (embedded at compile time by the
/// server).
pub const SHIPPED_LOCALES: &[&str] = &["en", "de"];
