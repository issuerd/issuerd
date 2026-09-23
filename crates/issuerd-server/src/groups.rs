// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Group helpers shared by the interactive user-creation paths (default-group assignment).

//! Group helpers shared by the interactive user-creation paths.

use std::sync::Arc;

use tracing::warn;

use issuerd_core::{Pagination, Realm, UserId};

use crate::state::ServerState;

/// Assign the realm's `default_groups` (group **paths**, e.g. `/developers`)
/// to a freshly created user.
///
/// There is no storage lookup by path, so the realm's groups are listed and
/// matched by path — group sets are small and this runs once per interactive
/// user creation (registration, broker first login). Unknown paths are
/// skipped with a warning; admin-created users deliberately get no default
/// groups (Keycloak behavior).
pub(crate) async fn assign_default_groups(
    state: &Arc<ServerState>,
    realm: &Realm,
    user_id: &UserId,
) {
    if realm.default_groups.is_empty() {
        return;
    }
    let groups = match state.storage.list_groups(&realm.id, &Pagination::default()).await {
        Ok(groups) => groups,
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "default groups: cannot list groups");
            return;
        }
    };
    for path in &realm.default_groups {
        match groups.iter().find(|g| g.path.as_str() == path) {
            Some(group) => {
                if let Err(e) = state.storage.add_user_group(&realm.id, user_id, &group.id).await {
                    warn!(realm = %realm.id, path = %path, error = %e, "default group assignment failed");
                }
            }
            None => {
                warn!(realm = %realm.id, path = %path, "default group path not found; skipping")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{Group, GroupId, GroupName, GroupPath, RealmId, RealmName};

    fn realm_with_defaults(id: &str, paths: &[&str]) -> Realm {
        Realm {
            id: RealmId::new(id).unwrap(),
            name: RealmName::new(id).unwrap(),
            enabled: true,
            default_groups: paths.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    fn group(realm_id: &RealmId, name: &str, path: &str) -> Group {
        Group {
            id: GroupId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: GroupName::new(name).unwrap(),
            path: GroupPath::new(path).unwrap(),
            realm_id: realm_id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: Default::default(),
            realm_roles: vec![],
            client_roles: Default::default(),
        }
    }

    #[tokio::test]
    async fn assigns_matching_paths_and_skips_unknown() {
        let cfg = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = realm_with_defaults("groups-realm", &["/developers", "/missing"]);
        state.storage.create_realm(&realm).await.unwrap();
        let dev = group(&realm.id, "developers", "/developers");
        state.storage.create_group(&realm.id, &dev).await.unwrap();
        let user_id = UserId::new("user-1").unwrap();

        assign_default_groups(&state, &realm, &user_id).await;

        let memberships = state.storage.list_user_groups(&realm.id, &user_id).await.unwrap();
        assert_eq!(memberships, vec![dev.id.clone()]);
    }

    #[tokio::test]
    async fn no_default_groups_is_a_noop() {
        let cfg = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = realm_with_defaults("plain-realm", &[]);
        state.storage.create_realm(&realm).await.unwrap();
        let user_id = UserId::new("user-1").unwrap();

        assign_default_groups(&state, &realm, &user_id).await;

        let memberships = state.storage.list_user_groups(&realm.id, &user_id).await.unwrap();
        assert!(memberships.is_empty());
    }
}
