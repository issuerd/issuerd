// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Distributed primitives crate root: cache, node discovery, events, and key schemas.

#![forbid(unsafe_code)]

pub mod cache;
pub mod discovery;
pub mod events;
pub mod invalidate;
pub mod keys;
pub mod redis_cache;

pub use cache::InMemoryCache;
pub use discovery::{NodeDiscovery, NodeEvent, NodeInfo, StaticDiscovery};
pub use events::{ClusterEvent, ClusterEventBus};
pub use keys::cache_keys;
pub use redis_cache::RedisCache;
