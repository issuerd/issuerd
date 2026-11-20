// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Reference validation and second-pass restoration for Keycloak migration.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use issuerd_core::{
    Client, ClientId, ClientIdentifier, Group, Pagination, ResourceType, Role, ScopeMappings,
};

use crate::{
    dto::{
        PartialImportRepresentation, PartialImportResultRepresentation, RoleRepresentation,
        ScopeMappingRepresentation,
    },
    error::AdminApiError,
    import_export::resource_was_skipped,
    state::AdminApiState,
};

const ALL: Pagination = Pagination {
    first: 0,
    max: i32::MAX,
};

#[derive(Default)]
struct Catalog {
    clients: HashMap<String, String>,
    scopes: HashSet<String>,
    realm_roles: HashSet<String>,
    client_roles: HashMap<String, HashSet<String>>,
    groups: HashMap<String, String>,
}

impl Catalog {
    async fn load(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
        body: &PartialImportRepresentation,
    ) -> Result<Self, AdminApiError> {
        let mut catalog = Self::default();
        for client in state.storage.list_clients(realm_id, &ALL).await? {
            catalog.clients.insert(client.id.to_string(), client.client_id.to_string());
            catalog
                .clients
                .insert(client.client_id.to_string(), client.client_id.to_string());
        }
        for client in body.clients.as_deref().unwrap_or_default() {
            ClientIdentifier::new(client.client_id.clone())?;
            if catalog
                .clients
                .insert(client.client_id.clone(), client.client_id.clone())
                .is_some()
                && !state
                    .storage
                    .get_client_by_client_id(
                        realm_id,
                        &ClientIdentifier::new(client.client_id.clone())?,
                    )
                    .await?
                    .is_some()
            {
                return Err(AdminApiError::BadRequest(format!(
                    "duplicate client '{}' in the import document",
                    client.client_id
                )));
            }
        }
        catalog.scopes.extend(
            state
                .storage
                .list_client_scopes(realm_id, &ALL)
                .await?
                .into_iter()
                .map(|scope| scope.name),
        );
        catalog.scopes.extend(
            body.client_scopes
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|scope| scope.name.clone()),
        );
        for role in state.storage.list_roles(realm_id, &ALL).await? {
            catalog.insert_role(role);
        }
        if let Some(roles) = &body.roles {
            let mut document_realm_roles = HashSet::new();
            let mut document_client_roles = HashSet::new();
            for role in roles.realm.as_deref().unwrap_or_default() {
                if !document_realm_roles.insert(role.name.clone()) {
                    return Err(AdminApiError::BadRequest(format!(
                        "duplicate realm role '{}' in the import document",
                        role.name
                    )));
                }
                catalog.realm_roles.insert(role.name.clone());
            }
            for (client_id, roles) in roles.client.as_ref().into_iter().flatten() {
                catalog.require_client(client_id)?;
                for role in roles {
                    if !document_client_roles.insert((client_id.clone(), role.name.clone())) {
                        return Err(AdminApiError::BadRequest(format!(
                            "duplicate client role '{client_id}/{name}' in the import document",
                            name = role.name
                        )));
                    }
                    catalog
                        .client_roles
                        .entry(client_id.clone())
                        .or_default()
                        .insert(role.name.clone());
                }
            }
        }
        for group in state.storage.list_groups(realm_id, &ALL).await? {
            catalog.insert_group(group);
        }
        for group in body.groups.as_deref().unwrap_or_default() {
            let path = format!("/{}", group.name);
            if group.path.as_ref().is_some_and(|value| *value != path) {
                return Err(AdminApiError::BadRequest(format!(
                    "group '{}': only top-level group paths are supported",
                    group.name
                )));
            }
            if catalog.groups.contains_key(&path)
                && state.storage.get_group_by_name(realm_id, &group.name).await?.is_none()
            {
                return Err(AdminApiError::BadRequest(format!(
                    "duplicate group '{}' in the import document",
                    group.name
                )));
            }
            catalog.groups.insert(path.clone(), group.name.clone());
            catalog.groups.insert(group.name.clone(), group.name.clone());
        }
        Ok(catalog)
    }

    fn insert_role(&mut self, role: Role) {
        if role.client_role {
            if let Some(client_id) = role.client_id {
                let owner = self.clients.get(client_id.as_ref()).cloned().unwrap_or_else(|| {
                    self.clients
                        .iter()
                        .find_map(|(alias, canonical)| {
                            (alias == client_id.as_ref()).then_some(canonical.clone())
                        })
                        .unwrap_or_else(|| client_id.to_string())
                });
                self.client_roles.entry(owner).or_default().insert(role.name.to_string());
            }
        } else {
            self.realm_roles.insert(role.name.to_string());
        }
    }

    fn insert_group(&mut self, group: Group) {
        self.groups.insert(group.id.to_string(), group.name.to_string());
        self.groups.insert(group.path.to_string(), group.name.to_string());
        self.groups.insert(group.name.to_string(), group.name.to_string());
    }

    fn require_client(&self, reference: &str) -> Result<String, AdminApiError> {
        self.clients.get(reference).cloned().ok_or_else(|| {
            AdminApiError::BadRequest(format!("reference to unknown client '{reference}'"))
        })
    }

    fn require_scope(&self, reference: &str) -> Result<(), AdminApiError> {
        if self.scopes.contains(reference) {
            Ok(())
        } else {
            Err(AdminApiError::BadRequest(format!(
                "reference to unknown client scope '{reference}'"
            )))
        }
    }

    fn require_realm_role(&self, reference: &str) -> Result<(), AdminApiError> {
        if self.realm_roles.contains(reference) {
            Ok(())
        } else {
            Err(AdminApiError::BadRequest(format!(
                "reference to unknown realm role '{reference}'"
            )))
        }
    }

    fn require_client_role(&self, client: &str, role: &str) -> Result<(), AdminApiError> {
        let owner = self.require_client(client)?;
        if self.client_roles.get(&owner).is_some_and(|roles| roles.contains(role)) {
            Ok(())
        } else {
            Err(AdminApiError::BadRequest(format!(
                "reference to unknown client role '{owner}/{role}'"
            )))
        }
    }

    fn require_group(&self, reference: &str) -> Result<(), AdminApiError> {
        if self.groups.contains_key(reference) {
            Ok(())
        } else {
            Err(AdminApiError::BadRequest(format!("reference to unknown group '{reference}'")))
        }
    }

    fn client_role_owner_count(&self, role: &str) -> usize {
        self.client_roles.values().filter(|roles| roles.contains(role)).count()
    }
}

fn reject_duplicates(owner: &str, names: &[String]) -> Result<(), AdminApiError> {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(AdminApiError::BadRequest(format!(
                "{owner}: duplicate role reference '{name}'"
            )));
        }
    }
    Ok(())
}

fn mapping_target(
    catalog: &Catalog,
    mapping: &ScopeMappingRepresentation,
) -> Result<(bool, String), AdminApiError> {
    let scope = mapping.client_scope.as_ref().or(mapping.client_template.as_ref());
    match (&mapping.client, scope) {
        (Some(client), None) => Ok((true, catalog.require_client(client)?)),
        (None, Some(scope)) => {
            catalog.require_scope(scope)?;
            Ok((false, scope.clone()))
        }
        _ => Err(AdminApiError::BadRequest(
            "scope mapping must name exactly one client or clientScope".to_string(),
        )),
    }
}

fn validate_scope_mappings(
    catalog: &Catalog,
    body: &PartialImportRepresentation,
) -> Result<(), AdminApiError> {
    for mapping in body.scope_mappings.as_deref().unwrap_or_default() {
        mapping_target(catalog, mapping)?;
        let roles = mapping.roles.as_deref().unwrap_or_default();
        reject_duplicates("scope mapping", roles)?;
        for role in roles {
            catalog.require_realm_role(role)?;
        }
    }
    for (owner, mappings) in body.client_scope_mappings.as_ref().into_iter().flatten() {
        catalog.require_client(owner)?;
        for mapping in mappings {
            mapping_target(catalog, mapping)?;
            let roles = mapping.roles.as_deref().unwrap_or_default();
            reject_duplicates("client scope mapping", roles)?;
            for role in roles {
                catalog.require_client_role(owner, role)?;
            }
        }
    }
    Ok(())
}

fn validate_user_and_group_mappings(
    catalog: &Catalog,
    body: &PartialImportRepresentation,
) -> Result<(), AdminApiError> {
    for user in body.users.as_deref().unwrap_or_default() {
        let owner = format!("user '{}'", user.username);
        let realm_roles = user.realm_roles.as_deref().unwrap_or_default();
        reject_duplicates(&owner, realm_roles)?;
        for role in realm_roles {
            catalog.require_realm_role(role)?;
        }
        for (client, roles) in user.client_roles.as_ref().into_iter().flatten() {
            reject_duplicates(&owner, roles)?;
            for role in roles {
                catalog.require_client_role(client, role)?;
            }
        }
        for group in user.groups.as_deref().unwrap_or_default() {
            catalog.require_group(group)?;
        }
    }
    for group in body.groups.as_deref().unwrap_or_default() {
        let owner = format!("group '{}'", group.name);
        let realm_roles: Vec<String> = group
            .realm_roles
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|name| name.to_string())
            .collect();
        reject_duplicates(&owner, &realm_roles)?;
        for role in &realm_roles {
            catalog.require_realm_role(role)?;
        }
        for (client, roles) in group.client_roles.as_ref().into_iter().flatten() {
            let roles: Vec<String> = roles.iter().map(|name| name.to_string()).collect();
            reject_duplicates(&owner, &roles)?;
            for role in roles {
                catalog.require_client_role(client.as_ref(), &role)?;
            }
        }
    }
    Ok(())
}

fn validate_legacy_composite(
    catalog: &Catalog,
    source_client: Option<&str>,
    role: &str,
) -> Result<(), AdminApiError> {
    if let Some(client) = source_client {
        if catalog.realm_roles.contains(role)
            || catalog.client_roles.get(client).is_some_and(|roles| roles.contains(role))
        {
            return Ok(());
        }
    } else if catalog.realm_roles.contains(role) || catalog.client_role_owner_count(role) == 1 {
        return Ok(());
    }
    Err(AdminApiError::BadRequest(format!(
        "composite role reference '{role}' is missing or ambiguous"
    )))
}

fn validate_composites(
    catalog: &Catalog,
    body: &PartialImportRepresentation,
) -> Result<(), AdminApiError> {
    if let Some(roles) = &body.roles {
        for role in roles.realm.as_deref().unwrap_or_default() {
            if body.composite_references.contains_key(&format!("R\0{}", role.name)) {
                continue;
            }
            for composite in role.composites.as_deref().unwrap_or_default() {
                validate_legacy_composite(catalog, None, composite.as_str())?;
            }
        }
        for (client, roles) in roles.client.as_ref().into_iter().flatten() {
            for role in roles {
                if body.composite_references.contains_key(&format!("C\0{client}\0{}", role.name)) {
                    continue;
                }
                for composite in role.composites.as_deref().unwrap_or_default() {
                    validate_legacy_composite(catalog, Some(client), composite.as_str())?;
                }
            }
        }
    }
    for (key, references) in &body.composite_references {
        let parts: Vec<&str> = key.split('\0').collect();
        let source_client = match parts.as_slice() {
            ["R", _role] => None,
            ["C", client, _role] => Some(*client),
            _ => {
                return Err(AdminApiError::BadRequest(
                    "invalid internal composite reference".to_string(),
                ))
            }
        };
        for role in &references.realm {
            catalog.require_realm_role(role)?;
            if let Some(client) = source_client {
                if catalog.client_roles.get(client).is_some_and(|roles| roles.contains(role)) {
                    return Err(AdminApiError::BadRequest(format!(
                        "composite reference '{client}' realm role '{role}' is shadowed by a same-client role"
                    )));
                }
            }
        }
        for (owner, roles) in &references.client {
            for role in roles {
                catalog.require_client_role(owner, role)?;
                match source_client {
                    Some(source) if source == owner => {}
                    Some(source) => {
                        return Err(AdminApiError::BadRequest(format!(
                            "composite reference from client '{source}' to another client's role '{owner}/{role}' is unsupported"
                        )))
                    }
                    None => {
                        if catalog.realm_roles.contains(role)
                            || catalog.client_role_owner_count(role) != 1
                        {
                            return Err(AdminApiError::BadRequest(format!(
                                "composite reference to client role '{owner}/{role}' is ambiguous"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn validate_references(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    body: &PartialImportRepresentation,
) -> Result<(), AdminApiError> {
    let catalog = Catalog::load(state, realm_id, body).await?;
    validate_scope_mappings(&catalog, body)?;
    validate_user_and_group_mappings(&catalog, body)?;
    validate_composites(&catalog, body)?;
    Ok(())
}

async fn client_by_reference(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    reference: &str,
) -> Result<Option<Client>, AdminApiError> {
    let identifier = ClientIdentifier::new(reference.to_string())?;
    if let Some(client) = state.storage.get_client_by_client_id(realm_id, &identifier).await? {
        return Ok(Some(client));
    }
    let id = ClientId::new(reference.to_string())?;
    Ok(state.storage.get_client(realm_id, &id).await?)
}

async fn realm_role(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    name: &str,
) -> Result<Role, AdminApiError> {
    state
        .storage
        .get_role_by_name(realm_id, name)
        .await?
        .filter(|role| !role.client_role)
        .ok_or_else(|| AdminApiError::BadRequest(format!("unknown realm role '{name}'")))
}

async fn client_role(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    client: &str,
    name: &str,
) -> Result<Role, AdminApiError> {
    let client = client_by_reference(state, realm_id, client)
        .await?
        .ok_or_else(|| AdminApiError::BadRequest(format!("unknown client '{client}'")))?;
    state
        .storage
        .get_client_role_by_name(realm_id, &client.id, name)
        .await?
        .ok_or_else(|| {
            AdminApiError::BadRequest(format!(
                "unknown client role '{}/{}'",
                client.client_id, name
            ))
        })
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

async fn apply_scope_mapping(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    mapping: &ScopeMappingRepresentation,
    client_roles: Option<&str>,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    let scope_name = mapping.client_scope.as_ref().or(mapping.client_template.as_ref());
    if let Some(client) = &mapping.client {
        if resource_was_skipped(summary, ResourceType::Client, client) {
            return Ok(());
        }
        let mut target = client_by_reference(state, realm_id, client).await?.ok_or_else(|| {
            AdminApiError::BadRequest(format!("unknown scope-mapping client '{client}'"))
        })?;
        for role_name in mapping.roles.as_deref().unwrap_or_default() {
            let role = match client_roles {
                Some(owner) => client_role(state, realm_id, owner, role_name).await?,
                None => realm_role(state, realm_id, role_name).await?,
            };
            if role.client_role {
                let owner = role.client_id.clone().ok_or_else(|| {
                    AdminApiError::BadRequest("client role has no owning client".to_string())
                })?;
                push_unique(
                    target.scope_mappings.client_roles.entry(owner).or_default(),
                    role.id.clone(),
                );
            } else {
                push_unique(&mut target.scope_mappings.realm_roles, role.id.clone());
            }
        }
        state.storage.update_client(realm_id, &target).await?;
        Ok(())
    } else if let Some(scope) = scope_name {
        if resource_was_skipped(summary, ResourceType::ClientScope, scope) {
            return Ok(());
        }
        let mut target =
            state.storage.get_client_scope_by_name(realm_id, scope).await?.ok_or_else(|| {
                AdminApiError::BadRequest(format!("unknown scope-mapping client scope '{scope}'"))
            })?;
        for role_name in mapping.roles.as_deref().unwrap_or_default() {
            let role = match client_roles {
                Some(owner) => client_role(state, realm_id, owner, role_name).await?,
                None => realm_role(state, realm_id, role_name).await?,
            };
            if role.client_role {
                let owner = role.client_id.clone().ok_or_else(|| {
                    AdminApiError::BadRequest("client role has no owning client".to_string())
                })?;
                push_unique(
                    target.scope_mappings.client_roles.entry(owner).or_default(),
                    role.id.clone(),
                );
            } else {
                push_unique(&mut target.scope_mappings.realm_roles, role.id.clone());
            }
        }
        state.storage.update_client_scope(realm_id, &target).await?;
        Ok(())
    } else {
        Err(AdminApiError::BadRequest(
            "scope mapping must name a client or clientScope".to_string(),
        ))
    }
}

async fn restore_scope_mappings(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    body: &PartialImportRepresentation,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    if body.scope_mappings.is_none() && body.client_scope_mappings.is_none() {
        return Ok(());
    }
    for rep in body.clients.as_deref().unwrap_or_default() {
        if resource_was_skipped(summary, ResourceType::Client, &rep.client_id) {
            continue;
        }
        let mut client = client_by_reference(state, realm_id, &rep.client_id)
            .await?
            .ok_or_else(|| AdminApiError::BadRequest("imported client is missing".to_string()))?;
        client.scope_mappings = ScopeMappings::default();
        state.storage.update_client(realm_id, &client).await?;
    }
    for rep in body.client_scopes.as_deref().unwrap_or_default() {
        if resource_was_skipped(summary, ResourceType::ClientScope, &rep.name) {
            continue;
        }
        let mut scope =
            state.storage.get_client_scope_by_name(realm_id, &rep.name).await?.ok_or_else(
                || AdminApiError::BadRequest("imported client scope is missing".to_string()),
            )?;
        scope.scope_mappings = ScopeMappings::default();
        state.storage.update_client_scope(realm_id, &scope).await?;
    }
    for mapping in body.scope_mappings.as_deref().unwrap_or_default() {
        apply_scope_mapping(state, realm_id, mapping, None, summary).await?;
    }
    for (owner, mappings) in body.client_scope_mappings.as_ref().into_iter().flatten() {
        for mapping in mappings {
            apply_scope_mapping(state, realm_id, mapping, Some(owner), summary).await?;
        }
    }
    Ok(())
}

async fn restore_group_roles(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    body: &PartialImportRepresentation,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    for rep in body.groups.as_deref().unwrap_or_default() {
        if resource_was_skipped(summary, ResourceType::Group, &rep.name)
            || (rep.realm_roles.is_none() && rep.client_roles.is_none())
        {
            continue;
        }
        let mut group =
            state.storage.get_group_by_name(realm_id, &rep.name).await?.ok_or_else(|| {
                AdminApiError::BadRequest("imported group is missing".to_string())
            })?;
        if let Some(roles) = &rep.realm_roles {
            group.realm_roles = roles.clone();
        }
        if let Some(roles) = &rep.client_roles {
            let mut resolved = HashMap::new();
            for (owner, names) in roles {
                let client = client_by_reference(state, realm_id, owner.as_ref())
                    .await?
                    .ok_or_else(|| {
                        AdminApiError::BadRequest(format!("unknown group-role client '{owner}'"))
                    })?;
                resolved.insert(client.id, names.clone());
            }
            group.client_roles = resolved;
        }
        state.storage.update_group(realm_id, &group).await?;
    }
    Ok(())
}

async fn restore_user_assignments(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    body: &PartialImportRepresentation,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    for rep in body.users.as_deref().unwrap_or_default() {
        if resource_was_skipped(summary, ResourceType::User, &rep.username) {
            continue;
        }
        let user = state
            .storage
            .get_user_by_username(realm_id, &rep.username)
            .await?
            .ok_or_else(|| AdminApiError::BadRequest("imported user is missing".to_string()))?;
        if let Some(roles) = &rep.realm_roles {
            for role_id in state.storage.list_user_realm_roles(realm_id, &user.id).await? {
                state.storage.remove_user_realm_role(realm_id, &user.id, &role_id).await?;
            }
            for name in roles {
                let role = realm_role(state, realm_id, name).await?;
                state.storage.add_user_realm_role(realm_id, &user.id, &role.id).await?;
            }
        }
        if let Some(mappings) = &rep.client_roles {
            for role_id in state.storage.list_user_client_roles(realm_id, &user.id).await? {
                state.storage.remove_user_client_role(realm_id, &user.id, &role_id).await?;
            }
            for (owner, roles) in mappings {
                for name in roles {
                    let role = client_role(state, realm_id, owner, name).await?;
                    state.storage.add_user_client_role(realm_id, &user.id, &role.id).await?;
                }
            }
        }
        if let Some(groups) = &rep.groups {
            for group_id in state.storage.list_user_groups(realm_id, &user.id).await? {
                state.storage.remove_user_group(realm_id, &user.id, &group_id).await?;
            }
            for reference in groups {
                let group = if reference.starts_with('/') {
                    state
                        .storage
                        .list_groups(realm_id, &ALL)
                        .await?
                        .into_iter()
                        .find(|group| group.path.as_str() == reference)
                } else if let Some(group) =
                    state.storage.get_group_by_name(realm_id, reference).await?
                {
                    Some(group)
                } else {
                    let id = issuerd_core::GroupId::new(reference.clone())?;
                    state.storage.get_group(realm_id, &id).await?
                };
                let group = group.ok_or_else(|| {
                    AdminApiError::BadRequest(format!(
                        "user '{}': unknown group '{reference}'",
                        rep.username
                    ))
                })?;
                state.storage.add_user_group(realm_id, &user.id, &group.id).await?;
            }
        }
    }
    Ok(())
}

async fn update_composite(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    client: Option<&str>,
    rep: &RoleRepresentation,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    if rep.composites.is_none() && rep.composite.is_none() {
        return Ok(());
    }
    let resource_name =
        client.map_or_else(|| rep.name.clone(), |client| format!("{client}/{}", rep.name));
    if resource_was_skipped(summary, ResourceType::Role, &resource_name) {
        return Ok(());
    }
    let mut role = match client {
        Some(client) => client_role(state, realm_id, client, &rep.name).await?,
        None => realm_role(state, realm_id, &rep.name).await?,
    };
    role.composite = rep.composite.unwrap_or(rep.composites.is_some());
    role.composites = rep.composites.clone().unwrap_or_default();
    state.storage.update_role(realm_id, &role).await?;
    Ok(())
}

async fn restore_composites(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    body: &PartialImportRepresentation,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    if let Some(roles) = &body.roles {
        for role in roles.realm.as_deref().unwrap_or_default() {
            update_composite(state, realm_id, None, role, summary).await?;
        }
        for (client, roles) in roles.client.as_ref().into_iter().flatten() {
            for role in roles {
                update_composite(state, realm_id, Some(client), role, summary).await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn restore_mappings(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    body: &PartialImportRepresentation,
    summary: &PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    restore_scope_mappings(state, realm_id, body, summary).await?;
    restore_group_roles(state, realm_id, body, summary).await?;
    restore_user_assignments(state, realm_id, body, summary).await?;
    restore_composites(state, realm_id, body, summary).await?;
    Ok(())
}
