// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Typestate wrappers for the server-side auth lifecycle.

//! Typestate wrappers for server-side auth lifecycle.
//!
//! Provides `TypedPendingAuthData` for cache round-trips and `AuthRequest`
//! for the OIDC authorization request lifecycle.

pub mod auth_request;
pub mod pending_auth;

pub use auth_request::AuthRequest;
pub use pending_auth::{TypedPendingAuthData, TypedPendingAuthDataEnum};
