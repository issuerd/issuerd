// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Role resolution helpers: composite expansion, effective role sets, group reconciliation.

//! Role resolution helpers: composite expansion and effective
//! role sets for users and groups. Shared by `issuerd-server` (token claim
//! assembly) and `issuerd-admin-api` (`…/role-mappings/…/effective` endpoints).
//!
//! Also hosts [`reconcile_group_memberships`], the storage-level primitive
//! behind LDAP group synchronisation (used by `issuerd-federation`'s
//! `UserSynchronizer` and `issuerd-auth-flow`'s federated-user import).

use std::collections::HashSet;

use crate::error::IssuerdError;
use crate::ids::{GroupId, RealmId, RoleId, UserId};
use crate::models::{Group, GroupName, GroupPath, Role};
use crate::traits::Storage;

/// Expand composite roles. Resolution rules: composites of a client role look
/// up the name in the same client first, then realm roles; composites of a
/// realm role look up realm roles first, then any client role with that name.
/// Cycle-safe via a visited set.
pub fn expand_composites(seeds: Vec<Role>, all_roles: &[Role]) -> Vec<Role> {
    let realm_by_name: std::collections::HashMap<&str, &Role> = all_roles
        .iter()
        .filter(|r| !r.client_role)
        .map(|r| (r.name.as_str(), r))
        .collect();
    let client_by_name: std::collections::HashMap<(&crate::ids::ClientId, &str), &Role> = all_roles
        .iter()
        .filter(|r| r.client_role)
        .filter_map(|r| r.client_id.as_ref().map(|c| ((c, r.name.as_str()), r)))
        .collect();

    let mut seen: HashSet<RoleId> = HashSet::new();
    let mut out = Vec::new();
    let mut queue: Vec<Role> = seeds;
    while let Some(role) = queue.pop() {
        if !seen.insert(role.id.clone()) {
            continue;
        }
        for composite_name in &role.composites {
            let resolved: Option<&Role> = if role.client_role {
                role.client_id
                    .as_ref()
                    .and_then(|c| client_by_name.get(&(c, composite_name.as_str())).copied())
                    .or_else(|| realm_by_name.get(composite_name.as_str()).copied())
            } else {
                realm_by_name.get(composite_name.as_str()).copied().or_else(|| {
                    all_roles
                        .iter()
                        .find(|r| r.client_role && r.name.as_str() == composite_name.as_str())
                })
            };
            if let Some(composite) = resolved {
                if !seen.contains(&composite.id) {
                    queue.push(composite.clone());
                }
            }
        }
        out.push(role);
    }
    out
}

/// All roles of a realm (unpaged; role counts are small by design).
pub async fn list_all_roles(
    storage: &dyn Storage,
    realm_id: &RealmId,
) -> Result<Vec<Role>, IssuerdError> {
    storage
        .list_roles(
            realm_id,
            &crate::traits::Pagination {
                first: 0,
                max: i32::MAX,
            },
        )
        .await
}

/// Resolve role ids against a loaded role list, skipping dangling references.
fn resolve_ids(ids: impl IntoIterator<Item = RoleId>, all_roles: &[Role]) -> Vec<Role> {
    let wanted: HashSet<RoleId> = ids.into_iter().collect();
    all_roles.iter().filter(|r| wanted.contains(&r.id)).cloned().collect()
}

/// Resolve the role mappings embedded in a group row (realm role names +
/// per-client role names) against the realm's roles.
fn resolve_group_role_names(group: &Group, all_roles: &[Role]) -> Vec<Role> {
    let mut out: Vec<Role> = Vec::new();
    for name in &group.realm_roles {
        if let Some(role) =
            all_roles.iter().find(|r| !r.client_role && r.name.as_str() == name.as_str())
        {
            out.push(role.clone());
        }
    }
    for (owner_id, names) in &group.client_roles {
        for name in names {
            if let Some(role) = all_roles.iter().find(|r| {
                r.client_role
                    && r.client_id.as_ref() == Some(owner_id)
                    && r.name.as_str() == name.as_str()
            }) {
                out.push(role.clone());
            }
        }
    }
    out
}

/// Effective roles of a user: direct realm + client role mappings, group
/// mappings of every group the user belongs to, and composite expansion.
/// Not scope-mapping filtered — that is token-specific and lives in
/// `issuerd-server`'s claims assembly.
pub async fn effective_user_roles(
    storage: &dyn Storage,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<Vec<Role>, IssuerdError> {
    let all_roles = list_all_roles(storage, realm_id).await?;

    let mut seeds: Vec<Role> = Vec::new();
    let realm_ids = storage.list_user_realm_roles(realm_id, user_id).await.unwrap_or_default();
    let client_ids = storage.list_user_client_roles(realm_id, user_id).await.unwrap_or_default();
    seeds.extend(resolve_ids(realm_ids.into_iter().chain(client_ids), &all_roles));

    if let Ok(group_ids) = storage.list_user_groups(realm_id, user_id).await {
        for gid in group_ids {
            if let Ok(Some(group)) = storage.get_group(realm_id, &gid).await {
                seeds.extend(resolve_group_role_names(&group, &all_roles));
            }
        }
    }

    Ok(expand_composites(seeds, &all_roles))
}

/// Effective roles of a group: the mappings stored on the group row plus
/// composite expansion.
pub async fn effective_group_roles(
    storage: &dyn Storage,
    realm_id: &RealmId,
    group_id: &GroupId,
) -> Result<Vec<Role>, IssuerdError> {
    let all_roles = list_all_roles(storage, realm_id).await?;
    let group = storage.get_group(realm_id, group_id).await?;
    let Some(group) = group else {
        return Err(IssuerdError::NotFound);
    };
    let seeds = resolve_group_role_names(&group, &all_roles);
    Ok(expand_composites(seeds, &all_roles))
}

// ---------------------------------------------------------------------------
// LDAP group synchronisation
// ---------------------------------------------------------------------------

/// Group attribute marking a group as managed by external (LDAP) group
/// synchronisation. Only memberships in marked groups are ever removed by
/// [`reconcile_group_memberships`] — manually assigned groups are untouched.
pub const LDAP_SYNC_MARKER_ATTRIBUTE: &str = "ldap_sync";

/// Outcome of [`reconcile_group_memberships`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GroupReconcileResult {
    /// Memberships added to the user.
    pub added: usize,
    /// Sync-managed memberships removed from the user.
    pub removed: usize,
    /// Groups created on demand (did not exist locally).
    pub created_groups: usize,
    /// Pre-existing groups taken under sync management (marker set).
    pub adopted_groups: usize,
    /// Desired names skipped because they are not valid group names.
    pub skipped: usize,
}

/// In-memory index of a realm's groups, shared across a sync run so many
/// users do not each re-query the same group rows. Name matching is
/// case-insensitive (directories like AD treat CNs case-insensitively).
#[derive(Debug, Default)]
pub struct GroupIndex {
    by_name: std::collections::HashMap<String, Group>,
    by_id: std::collections::HashMap<GroupId, Group>,
}

impl GroupIndex {
    /// Load every group of the realm (group counts are small by design).
    pub async fn load(storage: &dyn Storage, realm_id: &RealmId) -> Result<Self, IssuerdError> {
        let mut index = GroupIndex::default();
        let mut page = crate::traits::Pagination {
            first: 0,
            max: 1000,
        };
        loop {
            let batch = storage.list_groups(realm_id, &page).await?;
            if batch.is_empty() {
                break;
            }
            for group in batch {
                index.insert(group);
            }
            page.first += page.max;
        }
        Ok(index)
    }

    fn insert(&mut self, group: Group) {
        self.by_id.insert(group.id.clone(), group.clone());
        self.by_name.insert(group.name.as_str().to_lowercase(), group);
    }

    fn get_by_name(&self, lower_name: &str) -> Option<&Group> {
        self.by_name.get(lower_name)
    }
}

/// Reconcile a user's local group memberships with the group set reported by
/// an external directory (e.g. AD `memberOf`). See
/// [`reconcile_group_memberships_indexed`] for the semantics; this variant
/// resolves groups straight from storage (right for single-user calls).
pub async fn reconcile_group_memberships(
    storage: &dyn Storage,
    realm_id: &RealmId,
    user_id: &UserId,
    desired_group_names: &[String],
) -> Result<GroupReconcileResult, IssuerdError> {
    let mut index = GroupIndex::default();
    reconcile_group_memberships_indexed(storage, realm_id, user_id, desired_group_names, &mut index)
        .await
}

/// Reconcile a user's local group memberships with the group set reported by
/// an external directory (e.g. AD `memberOf`).
///
/// - Groups in `desired_group_names` are found by name (case-insensitive via
///   `index`) or created on demand (top-level, marked with
///   [`LDAP_SYNC_MARKER_ATTRIBUTE`]); missing memberships are added.
/// - A pre-existing group that sync assigns to a user is adopted: the marker
///   attribute is set so future runs manage its membership.
/// - Memberships in marker-carrying groups that are NOT in the desired set
///   are removed (this is how directory group removal propagates).
/// - Role mappings on groups are never touched — only membership.
/// - A find-or-create race with a concurrent reconcile falls back to the
///   already-created row instead of failing.
pub async fn reconcile_group_memberships_indexed(
    storage: &dyn Storage,
    realm_id: &RealmId,
    user_id: &UserId,
    desired_group_names: &[String],
    index: &mut GroupIndex,
) -> Result<GroupReconcileResult, IssuerdError> {
    let mut result = GroupReconcileResult::default();
    // lowercased (matching key) → trimmed original (used when creating).
    let mut desired: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for name in desired_group_names {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            desired.entry(trimmed.to_lowercase()).or_insert_with(|| trimmed.to_string());
        }
    }

    let current_ids = storage.list_user_groups(realm_id, user_id).await?;

    for (lower, original) in &desired {
        let group = match resolve_group_by_name(storage, realm_id, lower, original, index).await? {
            Some(group) => {
                if !is_sync_managed(&group) {
                    let mut adopted = group.clone();
                    adopted
                        .attributes
                        .insert(LDAP_SYNC_MARKER_ATTRIBUTE.to_string(), vec!["true".to_string()]);
                    storage.update_group(realm_id, &adopted).await?;
                    index.insert(adopted);
                    result.adopted_groups += 1;
                }
                group
            }
            None => {
                let Ok(name) = GroupName::new(original) else {
                    result.skipped += 1;
                    continue;
                };
                match create_sync_group(storage, realm_id, name, index).await? {
                    Some(group) => {
                        result.created_groups += 1;
                        group
                    }
                    // Lost the find-or-create race: use the winner's row.
                    None => match storage.get_group_by_name(realm_id, original).await? {
                        Some(group) => {
                            index.insert(group.clone());
                            group
                        }
                        None => return Err(IssuerdError::Conflict),
                    },
                }
            }
        };
        if !current_ids.contains(&group.id) {
            storage.add_user_group(realm_id, user_id, &group.id).await?;
            result.added += 1;
        }
    }

    for gid in &current_ids {
        let group = match index.by_id.get(gid) {
            Some(group) => Some(group.clone()),
            None => storage.get_group(realm_id, gid).await?,
        };
        let Some(group) = group else {
            continue;
        };
        if is_sync_managed(&group) && !desired.contains_key(&group.name.as_str().to_lowercase()) {
            storage.remove_user_group(realm_id, user_id, gid).await?;
            result.removed += 1;
        }
    }

    Ok(result)
}

/// Resolve a group by name: shared index first (case-insensitive), then an
/// exact-case storage lookup with the original spelling.
async fn resolve_group_by_name(
    storage: &dyn Storage,
    realm_id: &RealmId,
    lower: &str,
    original: &str,
    index: &mut GroupIndex,
) -> Result<Option<Group>, IssuerdError> {
    if let Some(group) = index.get_by_name(lower) {
        return Ok(Some(group.clone()));
    }
    let found = storage.get_group_by_name(realm_id, original).await?;
    if let Some(group) = &found {
        index.insert(group.clone());
    }
    Ok(found)
}

/// Insert a new sync-managed group. Returns `Ok(None)` when a concurrent
/// reconcile created the same group first (unique-violation race).
async fn create_sync_group(
    storage: &dyn Storage,
    realm_id: &RealmId,
    name: GroupName,
    index: &mut GroupIndex,
) -> Result<Option<Group>, IssuerdError> {
    let group = Group {
        id: GroupId::new(crate::utils::generate_id())?,
        name: name.clone(),
        path: GroupPath::new(format!("/{}", name.as_str()))?,
        realm_id: realm_id.clone(),
        parent_id: None,
        sub_groups: vec![],
        attributes: std::collections::HashMap::from([(
            LDAP_SYNC_MARKER_ATTRIBUTE.to_string(),
            vec!["true".to_string()],
        )]),
        realm_roles: vec![],
        client_roles: std::collections::HashMap::new(),
    };
    match storage.create_group(realm_id, &group).await {
        Ok(()) => {
            index.insert(group.clone());
            Ok(Some(group))
        }
        Err(IssuerdError::Conflict) => Ok(None),
        Err(e) => Err(e),
    }
}

fn is_sync_managed(group: &Group) -> bool {
    group
        .attributes
        .get(LDAP_SYNC_MARKER_ATTRIBUTE)
        .is_some_and(|values| values.iter().any(|v| v == "true"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RoleName;

    fn mk_role(id: &str, name: &str, composites: &[&str]) -> Role {
        Role {
            id: RoleId::new(id).unwrap(),
            name: RoleName::new(name).unwrap(),
            description: None,
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: !composites.is_empty(),
            composites: composites.iter().map(|c| RoleName::new(*c).unwrap()).collect(),
            attributes: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn composites_expand_transitively() {
        let a = mk_role("r-a", "a", &["b"]);
        let b = mk_role("r-b", "b", &["c"]);
        let c = mk_role("r-c", "c", &[]);
        let all = vec![a.clone(), b.clone(), c.clone()];
        let expanded = expand_composites(vec![a], &all);
        let mut names: Vec<&str> = expanded.iter().map(|r| r.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn composites_are_cycle_safe() {
        let a = mk_role("r-a", "a", &["b"]);
        let b = mk_role("r-b", "b", &["a"]);
        let all = vec![a.clone(), b.clone()];
        let expanded = expand_composites(vec![a], &all);
        assert_eq!(expanded.len(), 2);
    }

    #[test]
    fn unknown_composite_names_are_skipped() {
        let a = mk_role("r-a", "a", &["ghost"]);
        let all = vec![a.clone()];
        let expanded = expand_composites(vec![a], &all);
        assert_eq!(expanded.len(), 1);
    }

    // ------------------------------------------------------------------
    // reconcile_group_memberships
    // ------------------------------------------------------------------

    mod reconcile {
        use super::*;
        use crate::MockStorage;

        fn group(id: &str, name: &str, sync_marked: bool) -> Group {
            let attributes = if sync_marked {
                std::collections::HashMap::from([(
                    LDAP_SYNC_MARKER_ATTRIBUTE.to_string(),
                    vec!["true".to_string()],
                )])
            } else {
                std::collections::HashMap::new()
            };
            Group {
                id: GroupId::new(id).unwrap(),
                name: crate::models::GroupName::new(name).unwrap(),
                path: crate::models::GroupPath::new(format!("/{name}")).unwrap(),
                realm_id: RealmId::new("r1").unwrap(),
                parent_id: None,
                sub_groups: vec![],
                attributes,
                realm_roles: vec![],
                client_roles: std::collections::HashMap::new(),
            }
        }

        fn realm() -> RealmId {
            RealmId::new("r1").unwrap()
        }

        fn user() -> UserId {
            UserId::new("u1").unwrap()
        }

        #[tokio::test]
        async fn creates_missing_group_and_adds_membership() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            mock.expect_get_group_by_name().returning(|_, _| Ok(None));
            mock.expect_create_group()
                .times(1)
                .withf(|_, g: &Group| {
                    g.name.as_str() == "developers"
                        && is_sync_managed(g)
                        && g.path.as_str() == "/developers"
                })
                .returning(|_, _| Ok(()));
            mock.expect_add_user_group().times(1).returning(|_, _, _| Ok(()));

            let result =
                reconcile_group_memberships(&mock, &realm(), &user(), &["developers".into()])
                    .await
                    .unwrap();
            assert_eq!(result.added, 1);
            assert_eq!(result.created_groups, 1);
            assert_eq!(result.removed, 0);
        }

        #[tokio::test]
        async fn adopts_existing_unmarked_group() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            mock.expect_get_group_by_name()
                .returning(|_, _| Ok(Some(group("g1", "developers", false))));
            // Adoption: the marker attribute is written back via update_group.
            mock.expect_update_group()
                .times(1)
                .withf(|_, g: &Group| is_sync_managed(g))
                .returning(|_, _| Ok(()));
            mock.expect_add_user_group().times(1).returning(|_, _, _| Ok(()));

            let result =
                reconcile_group_memberships(&mock, &realm(), &user(), &["developers".into()])
                    .await
                    .unwrap();
            assert_eq!(result.added, 1);
            assert_eq!(result.created_groups, 0);
        }

        #[tokio::test]
        async fn removes_only_sync_managed_stale_memberships() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| {
                Ok(vec![GroupId::new("g1").unwrap(), GroupId::new("g2").unwrap()])
            });
            mock.expect_get_group().returning(|_, id| {
                Ok(Some(match id.to_string().as_str() {
                    "g1" => group("g1", "developers", true),
                    _ => group("g2", "manual", false),
                }))
            });
            // Only the sync-managed group membership is removed.
            mock.expect_remove_user_group()
                .times(1)
                .withf(|_, _, gid| gid.to_string() == "g1")
                .returning(|_, _, _| Ok(()));

            let result = reconcile_group_memberships(&mock, &realm(), &user(), &[]).await.unwrap();
            assert_eq!(result.removed, 1);
            assert_eq!(result.added, 0);
        }

        #[tokio::test]
        async fn keeps_current_memberships_still_desired() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups()
                .returning(|_, _| Ok(vec![GroupId::new("g1").unwrap()]));
            mock.expect_get_group_by_name()
                .returning(|_, _| Ok(Some(group("g1", "developers", true))));
            mock.expect_get_group()
                .returning(|_, _| Ok(Some(group("g1", "developers", true))));
            mock.expect_update_group().times(0);
            mock.expect_add_user_group().times(0);
            mock.expect_remove_user_group().times(0);

            let result =
                reconcile_group_memberships(&mock, &realm(), &user(), &["developers".into()])
                    .await
                    .unwrap();
            assert_eq!(result, GroupReconcileResult::default());
        }

        #[tokio::test]
        async fn skips_blank_names() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            mock.expect_get_group_by_name().times(0);
            mock.expect_create_group().times(0);
            mock.expect_add_user_group().times(0);

            let result = reconcile_group_memberships(
                &mock,
                &realm(),
                &user(),
                &[String::new(), "  ".into()],
            )
            .await
            .unwrap();
            assert_eq!(result, GroupReconcileResult::default());
        }

        #[tokio::test]
        async fn skips_names_groupname_rejects() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            mock.expect_get_group_by_name().returning(|_, _| Ok(None));
            mock.expect_create_group().times(0);
            mock.expect_add_user_group().times(0);

            let too_long = "x".repeat(300);
            let result = reconcile_group_memberships(
                &mock,
                &realm(),
                &user(),
                &["with\u{0007}control".into(), too_long],
            )
            .await
            .unwrap();
            assert_eq!(result.skipped, 2);
        }

        #[tokio::test]
        async fn adoption_preserves_role_mappings() {
            let mut with_roles = group("g1", "developers", false);
            with_roles.realm_roles = vec![RoleName::new("developer").unwrap()];
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            mock.expect_get_group_by_name()
                .returning(move |_, _| Ok(Some(with_roles.clone())));
            mock.expect_update_group()
                .times(1)
                .withf(|_, g: &Group| {
                    is_sync_managed(g) && g.realm_roles == vec![RoleName::new("developer").unwrap()]
                })
                .returning(|_, _| Ok(()));
            mock.expect_add_user_group().times(1).returning(|_, _, _| Ok(()));

            let result =
                reconcile_group_memberships(&mock, &realm(), &user(), &["developers".into()])
                    .await
                    .unwrap();
            assert_eq!(result.adopted_groups, 1);
        }

        #[tokio::test]
        async fn case_mismatch_adopts_via_preloaded_index() {
            // AD reports "Developers"; the realm already has "developers".
            let mut mock = MockStorage::new();
            let list_calls = std::sync::atomic::AtomicUsize::new(0);
            mock.expect_list_groups().returning(move |_, _| {
                if list_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    Ok(vec![group("g1", "developers", false)])
                } else {
                    Ok(vec![])
                }
            });
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            mock.expect_update_group().times(1).returning(|_, _| Ok(()));
            // No duplicate group may be created.
            mock.expect_create_group().times(0);
            mock.expect_add_user_group().times(1).returning(|_, _, _| Ok(()));

            let mut index = GroupIndex::load(&mock, &realm()).await.unwrap();
            let result = reconcile_group_memberships_indexed(
                &mock,
                &realm(),
                &user(),
                &["Developers".into()],
                &mut index,
            )
            .await
            .unwrap();
            assert_eq!(result.adopted_groups, 1);
            assert_eq!(result.created_groups, 0);
            assert_eq!(result.added, 1);
        }

        #[tokio::test]
        async fn find_or_create_race_falls_back_to_existing_row() {
            let mut mock = MockStorage::new();
            mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
            // Cold index: first lookup misses, the race-loser retry finds it.
            let calls = std::sync::atomic::AtomicUsize::new(0);
            mock.expect_get_group_by_name().returning(move |_, _| {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    Ok(None)
                } else {
                    Ok(Some(group("g9", "developers", true)))
                }
            });
            mock.expect_create_group()
                .times(1)
                .returning(|_, _| Err(IssuerdError::Conflict));
            mock.expect_add_user_group()
                .times(1)
                .withf(|_, _, gid| gid.to_string() == "g9")
                .returning(|_, _, _| Ok(()));

            let result =
                reconcile_group_memberships(&mock, &realm(), &user(), &["developers".into()])
                    .await
                    .unwrap();
            assert_eq!(result.added, 1);
            assert_eq!(result.created_groups, 0);
        }
    }
}
