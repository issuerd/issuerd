// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// LDAP mapper trait and built-in mappers (group, role, full-name, user-attribute, MSAD).

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError, User};

pub mod full_name;
pub mod group;
pub mod msad_account_control;
pub mod role;
pub mod user_attribute;

pub use full_name::FullNameMapper;
pub use group::{GroupMapper, GroupSyncMode, MembershipType, UserRolesRetrieveStrategy};
pub use msad_account_control::MsadAccountControlMapper;
pub use role::RoleMapper;
pub use user_attribute::UserAttributeMapper;

/// Transform LDAP attributes into `FederatedUser` fields.
pub trait LdapMapper: Send + Sync {
    fn id(&self) -> &str;

    /// Map LDAP attributes to a `FederatedUser` builder.
    fn map_user(
        &self,
        ldap_attrs: &HashMap<String, Vec<String>>,
        user: &mut FederatedUser,
    ) -> Result<(), FederationError>;

    /// Determine if the user should be enabled based on LDAP state.
    fn map_enabled(&self, _ldap_attrs: &HashMap<String, Vec<String>>) -> Option<bool> {
        None
    }

    /// Map LDAP group memberships to Issuerd role/group names.
    fn map_memberships(&self, _ldap_attrs: &HashMap<String, Vec<String>>) -> Vec<String> {
        vec![]
    }

    /// Map LDAP group memberships to Issuerd *group* names (subset of
    /// [`LdapMapper::map_memberships`] for group mappers; role mappers keep
    /// this empty). Feeds `FederatedUser.groups`.
    fn map_groups(&self, _ldap_attrs: &HashMap<String, Vec<String>>) -> Vec<String> {
        vec![]
    }

    /// Extra LDAP attributes this mapper needs on user entries. Providers
    /// union these into search requests (which already include `"*"` — some
    /// directories still require explicitly naming operational attributes).
    fn requested_attributes(&self) -> Vec<String> {
        vec![]
    }

    /// Whether this mapper reports group memberships (i.e. a group mapper is
    /// wired). Providers use it to distinguish "user has no groups" from
    /// "group sync not configured" on `FederatedUser.groups`.
    fn reports_groups(&self) -> bool {
        false
    }

    /// Reverse map: build LDAP attributes from a `User` for write-back.
    fn to_ldap_attrs(&self, _user: &User) -> HashMap<String, Vec<String>> {
        HashMap::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::DisplayName;
    use issuerd_core::FederatedUser;

    #[test]
    fn user_attribute_mapper_email() {
        let mapper = UserAttributeMapper {
            user_attribute: "email".to_string(),
            ldap_attribute: "mail".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("mail".to_string(), vec!["alice@example.com".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.email, Some("alice@example.com".to_string()));
    }

    #[test]
    fn user_attribute_mapper_missing_mandatory() {
        let mapper = UserAttributeMapper {
            user_attribute: "email".to_string(),
            ldap_attribute: "mail".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: true,
            default_value: None,
        };
        let mut user = FederatedUser::default();
        let attrs = HashMap::new();
        let err = mapper.map_user(&attrs, &mut user).unwrap_err();
        assert!(matches!(err, FederationError::SchemaMismatch(_)));
    }

    #[test]
    fn user_attribute_mapper_default_value() {
        let mapper = UserAttributeMapper {
            user_attribute: "email".to_string(),
            ldap_attribute: "mail".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: Some("nobody@example.com".to_string()),
        };
        let mut user = FederatedUser::default();
        let attrs = HashMap::new();
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.email, Some("nobody@example.com".to_string()));
    }

    #[test]
    fn msad_account_control_enabled() {
        let mapper = MsadAccountControlMapper;
        let mut attrs = HashMap::new();
        attrs.insert("userAccountControl".to_string(), vec!["512".to_string()]);
        assert_eq!(mapper.map_enabled(&attrs), Some(true));
    }

    #[test]
    fn msad_account_control_disabled() {
        let mapper = MsadAccountControlMapper;
        let mut attrs = HashMap::new();
        attrs.insert("userAccountControl".to_string(), vec!["514".to_string()]);
        assert_eq!(mapper.map_enabled(&attrs), Some(false));
    }

    #[test]
    fn msad_pwd_last_set_zero() {
        let mapper = MsadAccountControlMapper;
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("pwdLastSet".to_string(), vec!["0".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.attributes.get("UPDATE_PASSWORD"), Some(&vec!["true".to_string()]));
    }

    #[test]
    fn full_name_mapper_split() {
        let mapper = FullNameMapper {
            ldap_attribute: "cn".to_string(),
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["Alice Smith".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.first_name, Some(DisplayName::new("Alice").unwrap()));
        assert_eq!(user.last_name, Some(DisplayName::new("Smith").unwrap()));
    }

    #[test]
    fn full_name_mapper_single_word() {
        let mapper = FullNameMapper {
            ldap_attribute: "cn".to_string(),
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["Alice".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.first_name, Some(DisplayName::new("Alice").unwrap()));
        assert_eq!(user.last_name, None);
    }

    #[test]
    fn group_mapper_memberof() {
        let mapper = GroupMapper {
            groups_dn: "OU=Groups,DC=ex,DC=com".to_string(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        };
        let mut attrs = HashMap::new();
        attrs.insert("memberOf".to_string(), vec!["CN=Admins,OU=Groups,DC=ex,DC=com".to_string()]);
        let groups = mapper.map_memberships(&attrs);
        assert_eq!(groups, vec!["Admins"]);
    }

    #[test]
    fn group_mapper_no_memberof() {
        let mapper = GroupMapper {
            groups_dn: "OU=Groups,DC=ex,DC=com".to_string(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        };
        let attrs = HashMap::new();
        let groups = mapper.map_memberships(&attrs);
        assert!(groups.is_empty());
    }

    #[test]
    fn role_mapper_realm_roles() {
        let mapper = RoleMapper {
            roles_dn: "ou=roles,dc=test".to_string(),
            role_name_attribute: "cn".to_string(),
            client_id: None,
        };
        let mut attrs = HashMap::new();
        attrs.insert("memberOf".to_string(), vec!["CN=admin,OU=Roles,DC=ex,DC=com".to_string()]);
        let roles = mapper.map_memberships(&attrs);
        assert_eq!(roles, vec!["admin"]);
    }

    #[test]
    fn user_attribute_mapper_id() {
        let mapper = UserAttributeMapper {
            user_attribute: "email".to_string(),
            ldap_attribute: "mail".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        };
        assert_eq!(mapper.id(), "user-attribute-ldap-mapper");
    }

    #[test]
    fn user_attribute_mapper_first_name() {
        let mapper = UserAttributeMapper {
            user_attribute: "firstName".to_string(),
            ldap_attribute: "givenName".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("givenName".to_string(), vec!["Alice".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.first_name, Some(DisplayName::new("Alice").unwrap()));
    }

    #[test]
    fn user_attribute_mapper_last_name() {
        let mapper = UserAttributeMapper {
            user_attribute: "lastName".to_string(),
            ldap_attribute: "sn".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("sn".to_string(), vec!["Smith".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.last_name, Some(DisplayName::new("Smith").unwrap()));
    }

    #[test]
    fn user_attribute_mapper_username_skipped() {
        let mapper = UserAttributeMapper {
            user_attribute: "username".to_string(),
            ldap_attribute: "uid".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("uid".to_string(), vec!["alice".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        // username mapping is intentionally skipped — set from DN/username search
        assert_eq!(user.username, "");
    }

    #[test]
    fn user_attribute_mapper_custom_attribute() {
        let mapper = UserAttributeMapper {
            user_attribute: "department".to_string(),
            ldap_attribute: "ou".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        };
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("ou".to_string(), vec!["Engineering".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.attributes.get("department"), Some(&vec!["Engineering".to_string()]));
    }

    #[test]
    fn full_name_mapper_id() {
        let mapper = FullNameMapper {
            ldap_attribute: "cn".to_string(),
        };
        assert_eq!(mapper.id(), "full-name-ldap-mapper");
    }

    #[test]
    fn full_name_mapper_missing_attribute() {
        let mapper = FullNameMapper {
            ldap_attribute: "cn".to_string(),
        };
        let mut user = FederatedUser::default();
        let attrs = HashMap::new();
        mapper.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.first_name, None);
        assert_eq!(user.last_name, None);
    }

    #[test]
    fn msad_account_control_id() {
        let mapper = MsadAccountControlMapper;
        assert_eq!(mapper.id(), "msad-user-account-control-mapper");
    }

    #[test]
    fn msad_account_control_unparsable() {
        let mapper = MsadAccountControlMapper;
        let mut attrs = HashMap::new();
        attrs.insert("userAccountControl".to_string(), vec!["not_a_number".to_string()]);
        assert_eq!(mapper.map_enabled(&attrs), None);
    }

    #[test]
    fn msad_pwd_last_set_non_zero() {
        let mapper = MsadAccountControlMapper;
        let mut user = FederatedUser::default();
        let mut attrs = HashMap::new();
        attrs.insert("pwdLastSet".to_string(), vec!["132000000000000000".to_string()]);
        mapper.map_user(&attrs, &mut user).unwrap();
        assert!(!user.attributes.contains_key("UPDATE_PASSWORD"));
    }

    #[test]
    fn group_mapper_id_and_map_user() {
        let mapper = GroupMapper {
            groups_dn: "OU=Groups,DC=ex,DC=com".to_string(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        };
        assert_eq!(mapper.id(), "group-ldap-mapper");
        let mut user = FederatedUser::default();
        mapper.map_user(&HashMap::new(), &mut user).unwrap();
    }

    #[test]
    fn group_mapper_load_groups_by_member() {
        let mapper = GroupMapper {
            groups_dn: "OU=Groups,DC=ex,DC=com".to_string(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::LoadGroupsByMemberAttribute,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        };
        let mut attrs = HashMap::new();
        attrs.insert("memberOf".to_string(), vec!["CN=Admins,OU=Groups,DC=ex,DC=com".to_string()]);
        let groups = mapper.map_memberships(&attrs);
        // LoadGroupsByMemberAttribute is not implemented in MVP — returns empty vec
        assert!(groups.is_empty());
    }

    #[test]
    fn group_mapper_extract_group_name_malformed() {
        let mapper = GroupMapper {
            groups_dn: "OU=Groups,DC=ex,DC=com".to_string(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        };
        let mut attrs = HashMap::new();
        attrs.insert("memberOf".to_string(), vec!["Admins,OU=Groups,DC=ex,DC=com".to_string()]);
        let groups = mapper.map_memberships(&attrs);
        // Missing "=" means split_once returns None — name is skipped
        assert!(groups.is_empty());
    }

    #[test]
    fn role_mapper_id_and_map_user() {
        let mapper = RoleMapper {
            roles_dn: "ou=roles,dc=test".to_string(),
            role_name_attribute: "cn".to_string(),
            client_id: None,
        };
        assert_eq!(mapper.id(), "role-ldap-mapper");
        let mut user = FederatedUser::default();
        mapper.map_user(&HashMap::new(), &mut user).unwrap();
    }

    #[test]
    fn group_mapper_filters_by_groups_dn() {
        let mapper = GroupMapper::from_config(&HashMap::from([(
            "groupsDn".to_string(),
            "OU=IssuerdGroups,DC=test,DC=issuerd,DC=local".to_string(),
        )]))
        .unwrap();
        let attrs = HashMap::from([(
            "memberOf".to_string(),
            vec![
                "CN=developers,OU=IssuerdGroups,DC=test,DC=issuerd,DC=local".to_string(),
                "CN=Domain Admins,CN=Users,DC=test,DC=issuerd,DC=local".to_string(),
            ],
        )]);
        let groups = mapper.map_memberships(&attrs);
        assert_eq!(groups, vec!["developers"]);
    }

    #[test]
    fn group_mapper_include_allowlist_case_insensitive() {
        let mapper = GroupMapper::from_config(&HashMap::from([
            (
                "groupsDn".to_string(),
                "OU=IssuerdGroups,DC=test,DC=issuerd,DC=local".to_string(),
            ),
            ("groupsInclude".to_string(), " Developers , admins ".to_string()),
        ]))
        .unwrap();
        let attrs = HashMap::from([(
            "memberOf".to_string(),
            vec![
                "CN=developers,OU=IssuerdGroups,DC=test,DC=issuerd,DC=local".to_string(),
                "CN=loadgroup_7,OU=IssuerdGroups,DC=test,DC=issuerd,DC=local".to_string(),
            ],
        )]);
        assert_eq!(mapper.map_memberships(&attrs), vec!["developers"]);
    }

    #[test]
    fn group_mapper_from_config_disabled_without_groups_dn() {
        assert!(GroupMapper::from_config(&HashMap::new()).is_none());
        assert!(GroupMapper::from_config(&HashMap::from([(
            "groupsDn".to_string(),
            "   ".to_string()
        )]))
        .is_none());
    }

    #[test]
    fn group_mapper_from_config_defaults_and_requested_attributes() {
        let mapper = GroupMapper::from_config(&HashMap::from([(
            "groupsDn".to_string(),
            "ou=groups,dc=test".to_string(),
        )]))
        .unwrap();
        assert_eq!(mapper.group_name_attribute, "cn");
        assert_eq!(mapper.member_of_attribute, "memberOf");
        assert_eq!(mapper.groups_include, None);
        assert_eq!(mapper.requested_attributes(), vec!["memberOf".to_string()]);
        let attrs = HashMap::from([(
            "memberOf".to_string(),
            vec!["CN=devs,ou=groups,dc=test".to_string()],
        )]);
        assert_eq!(mapper.map_groups(&attrs), vec!["devs"]);
    }

    #[test]
    fn group_mapper_dn_spacing_and_case_normalized() {
        let mapper = GroupMapper::from_config(&HashMap::from([(
            "groupsDn".to_string(),
            "ou=groups, dc=test".to_string(),
        )]))
        .unwrap();
        let attrs = HashMap::from([(
            "memberOf".to_string(),
            vec!["CN=devs,OU=Groups,DC=Test".to_string()],
        )]);
        assert_eq!(mapper.map_memberships(&attrs), vec!["devs"]);
    }

    #[test]
    fn role_mapper_extract_role_name_malformed() {
        let mapper = RoleMapper {
            roles_dn: "ou=roles,dc=test".to_string(),
            role_name_attribute: "cn".to_string(),
            client_id: None,
        };
        let mut attrs = HashMap::new();
        attrs.insert("memberOf".to_string(), vec!["admin,OU=Roles,DC=ex,DC=com".to_string()]);
        let roles = mapper.map_memberships(&attrs);
        assert!(roles.is_empty());
    }
}
