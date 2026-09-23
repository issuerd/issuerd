// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Storage crate surface: backend modules and public re-exports.

#![forbid(unsafe_code)]

pub mod db_types;
pub mod json;
pub mod key_encryption;
pub mod memory;
pub mod migration;
pub mod postgres;
pub mod seed;

pub use json::JsonFileStorage;
pub use key_encryption::Aes256GcmKekProvider;
pub use memory::InMemoryStorage;
pub use postgres::PostgresStorage;
