// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Authentication flow engine crate root (pluggable authenticators and required actions).

#![forbid(unsafe_code)]

pub mod built_in;
pub mod email_code;
pub mod executor;
pub mod login_failures;
pub mod plugin_registry;
pub mod totp;
pub mod typestate;
pub mod validation;
pub mod webauthn;
