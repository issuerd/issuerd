// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// REST Admin API crate root: public module declarations.

#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod dto;
pub mod email;
pub mod enums;
pub mod error;
pub mod openapi;
pub mod routes;
pub mod state;

pub mod attack_detection;
pub mod client_installation;
pub mod client_roles;
pub mod client_scopes;
pub mod clients;
pub mod composites;
pub mod credentials;
pub mod events;
pub mod federation;
pub mod flows;
pub mod groups;
pub mod idp;
pub mod import_export;
pub mod initial_access;
pub mod keys;
pub mod realms;
pub mod roles;
pub mod scope_mappings;
pub mod sessions;
pub mod user_actions;
pub mod users;

#[cfg(test)]
pub mod test_utils;
