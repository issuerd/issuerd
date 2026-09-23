// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Maps LDAP group memberships to Issuerd group names.

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError};

use crate::mapper::LdapMapper;

/// Maps LDAP group memberships to Issuerd group names.
#[derive(Debug, Clone)]
pub struct GroupMapper {
    pub groups_dn: String,
    pub group_name_attribute: String,
    pub group_object_classes: Vec<String>,
    pub membership_attribute: String,
    pub membership_type: MembershipType,
    pub mode: GroupSyncMode,
    pub preserve_group_inheritance: bool,
    pub user_roles_retrieve_strategy: UserRolesRetrieveStrategy,
    /// User attribute holding the membership DNs (default `memberOf`).
    pub member_of_attribute: String,
    /// Optional allowlist of group names (CNs) to sync, matched
    /// case-insensitively. `None` syncs every group under `groups_dn`.
    pub groups_include: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipType {
    Dn,
    Uid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSyncMode {
    ReadOnly,
    LdapOnly,
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRolesRetrieveStrategy {
    GetGroupsFromUserMemberOf,
    LoadGroupsByMemberAttribute,
}

impl GroupMapper {
    /// Build a group mapper from an identity-provider config map, or `None`
    /// when group sync is not configured (no `groupsDn` key).
    ///
    /// Keys (Keycloak-style camelCase):
    /// - `groupsDn` (required to enable): base DN of the groups subtree.
    /// - `groupNameLdapAttribute` (default `cn`). NOTE: only meaningful for
    ///   the (unimplemented) `LoadGroupsByMemberAttribute` strategy — with
    ///   `GetGroupsFromUserMemberOf` the group name is always the RDN value
    ///   of the `memberOf` DN.
    /// - `memberOfLdapAttribute` (default `memberOf`).
    /// - `groupsInclude` (optional): comma-separated group-name allowlist.
    pub fn from_config(config: &HashMap<String, String>) -> Option<Self> {
        let groups_dn = config.get("groupsDn")?.trim().to_string();
        if groups_dn.is_empty() {
            return None;
        }
        let groups_include = config.get("groupsInclude").and_then(|raw| {
            let names: Vec<String> =
                raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            (!names.is_empty()).then_some(names)
        });
        Some(Self {
            groups_dn,
            group_name_attribute: config
                .get("groupNameLdapAttribute")
                .filter(|s| !s.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| "cn".to_string()),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: config
                .get("memberOfLdapAttribute")
                .filter(|s| !s.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| "memberOf".to_string()),
            groups_include,
        })
    }

    fn extract_group_name(&self, dn: &str) -> Option<String> {
        // CN=Admins,OU=Groups,DC=ex,DC=com -> Admins
        split_dn_components(dn)
            .into_iter()
            .next()?
            .split_once('=')
            .map(|(_, name)| unescape_dn_value(name.trim()))
    }

    /// Normalize a DN for suffix comparison: lowercase, no spaces around
    /// component separators (LDAP servers differ in cosmetic spacing).
    fn normalize_dn(dn: &str) -> String {
        split_dn_components(dn)
            .into_iter()
            .map(|part| part.trim().to_lowercase())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Suffix match on normalized component lists (exact boundary on whole
    /// RDN components — `OU=Groups2` must not match base `OU=Groups`).
    fn is_under_groups_dn(&self, dn: &str) -> bool {
        let dn = Self::normalize_dn(dn);
        let base = Self::normalize_dn(&self.groups_dn);
        dn.len() > base.len()
            && dn.ends_with(&base)
            && dn.as_bytes()[dn.len() - base.len() - 1] == b','
    }

    fn is_included(&self, name: &str) -> bool {
        match &self.groups_include {
            None => true,
            Some(names) => names.iter().any(|n| n.eq_ignore_ascii_case(name)),
        }
    }
}

/// Split a distinguished name into its RDN components, honoring RFC 4514
/// backslash escapes (`CN=Smith\, John,OU=...` is two components, not three).
fn split_dn_components(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::with_capacity(dn.len());
    let mut escaped = false;
    for ch in dn.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            current.push(ch);
            escaped = true;
        } else if ch == ',' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// Reverse RFC 4514 escaping in a single RDN value (`Smith\, John` →
/// `Smith, John`). Unknown escape sequences keep the backslash.
fn unescape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

impl LdapMapper for GroupMapper {
    fn id(&self) -> &str {
        "group-ldap-mapper"
    }

    fn map_user(
        &self,
        _ldap_attrs: &HashMap<String, Vec<String>>,
        _user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        Ok(())
    }

    fn map_memberships(&self, ldap_attrs: &HashMap<String, Vec<String>>) -> Vec<String> {
        match self.user_roles_retrieve_strategy {
            UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf => ldap_attrs
                .get(&self.member_of_attribute)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|dn| self.is_under_groups_dn(dn))
                .filter_map(|dn| self.extract_group_name(&dn))
                .filter(|name| self.is_included(name))
                .collect(),
            UserRolesRetrieveStrategy::LoadGroupsByMemberAttribute => {
                // NOTE: LoadGroupsByMemberAttribute is not implemented in MVP.
                // It requires an extra LDAP search: (&(objectClass=group)(member={userDn}))
                // This can be added later without breaking the LdapMapper trait.
                vec![]
            }
        }
    }

    fn map_groups(&self, ldap_attrs: &HashMap<String, Vec<String>>) -> Vec<String> {
        self.map_memberships(ldap_attrs)
    }

    fn requested_attributes(&self) -> Vec<String> {
        vec![self.member_of_attribute.clone()]
    }

    fn reports_groups(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper(groups_dn: &str) -> GroupMapper {
        GroupMapper::from_config(&HashMap::from([("groupsDn".to_string(), groups_dn.to_string())]))
            .unwrap()
    }

    #[test]
    fn split_dn_respects_escaped_commas() {
        assert_eq!(
            split_dn_components(r"CN=Smith\, John,OU=Groups,DC=ex"),
            vec!["CN=Smith\\, John", "OU=Groups", "DC=ex"]
        );
        assert_eq!(split_dn_components("CN=plain,DC=ex"), vec!["CN=plain", "DC=ex"]);
    }

    #[test]
    fn extract_group_name_unescapes_value() {
        let m = mapper("OU=Groups,DC=ex");
        assert_eq!(
            m.extract_group_name(r"CN=Smith\, John,OU=Groups,DC=ex"),
            Some("Smith, John".to_string())
        );
    }

    #[test]
    fn memberships_with_escaped_comma_group() {
        let m = mapper("OU=Groups,DC=ex");
        let attrs = HashMap::from([(
            "memberOf".to_string(),
            vec![r"CN=Smith\, John,OU=Groups,DC=ex".to_string()],
        )]);
        assert_eq!(m.map_memberships(&attrs), vec!["Smith, John".to_string()]);
    }

    #[test]
    fn suffix_check_requires_component_boundary() {
        let m = mapper("OU=Groups,DC=ex");
        assert!(!m.is_under_groups_dn("CN=devs,OU=Groups2,DC=ex"));
        assert!(m.is_under_groups_dn("CN=devs,OU=Sub,OU=Groups,DC=ex"));
        assert!(!m.is_under_groups_dn("OU=Groups,DC=ex"));
    }

    #[test]
    fn unescape_dn_value_handles_trailing_backslash() {
        assert_eq!(unescape_dn_value(r"foo\"), "foo\\");
        assert_eq!(unescape_dn_value(r"a\,b\=c"), "a,b=c");
    }
}
