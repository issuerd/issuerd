// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Storage crate surface: backend modules and public re-exports.

#![forbid(unsafe_code)]

pub mod db_types;
pub mod json;
mod json_webhooks;
pub mod key_encryption;
pub mod memory;
mod memory_webhooks;
pub mod migration;
pub mod postgres;
mod postgres_webhooks;
pub mod seed;
pub mod sqlite;
mod sqlite_types;
mod sqlite_webhooks;
pub mod step_up;
pub mod step_up_sqlite;

pub use json::JsonFileStorage;
pub use key_encryption::Aes256GcmKekProvider;
pub use memory::InMemoryStorage;
pub use postgres::PostgresStorage;
pub use sqlite::SqliteStorage;
