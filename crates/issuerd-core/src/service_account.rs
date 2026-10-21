// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Client-bound service-account user provisioning and resolution.

use crate::{Client, IssuerdError, RealmId, Storage, User, Username};

/// Load the service-account user linked to `client`, rejecting an ID or
/// back-link mismatch instead of falling back to a username lookup.
pub async fn find_service_account_user(
    storage: &dyn Storage,
    realm_id: &RealmId,
    client: &Client,
) -> Result<Option<User>, IssuerdError> {
    let Some(user) = storage.get_user(realm_id, &client.service_account_user_id()).await? else {
        return Ok(None);
    };
    if client.is_service_account_user(&user) {
        return Ok(Some(user));
    }
    Err(IssuerdError::ServerError(format!(
        "service-account identity linkage mismatch for client {}",
        client.id
    )))
}

/// Resolve or create the service-account user for `client`.
///
/// Existing users are never adopted by username. If the conventional name is
/// occupied, the linked account uses the client UUID as its unique username.
/// Once the linked account exists, an unlinked account occupying the
/// conventional name is disabled without copying its roles.
pub async fn ensure_service_account_user(
    storage: &dyn Storage,
    realm_id: &RealmId,
    client: &Client,
) -> Result<User, IssuerdError> {
    let conventional = client.service_account_username();
    if let Some(user) = find_service_account_user(storage, realm_id, client).await? {
        if user.username.as_str() == conventional {
            return Ok(user);
        }
        let legacy = storage.get_user_by_username(realm_id, &conventional).await?;
        disable_legacy_user(storage, realm_id, legacy).await?;
        return Ok(user);
    }
    let legacy = storage.get_user_by_username(realm_id, &conventional).await?;
    let username = if legacy.is_some() {
        format!("{}{}", Username::SERVICE_ACCOUNT_PREFIX, client.id)
    } else {
        conventional
    };
    let now = chrono::Utc::now();
    let user = User {
        id: client.service_account_user_id(),
        realm_id: realm_id.clone(),
        username: Username::new(username)?,
        email: None,
        email_verified: false,
        first_name: None,
        last_name: None,
        enabled: true,
        federation_link: None,
        attributes: std::collections::HashMap::from([(
            Client::SERVICE_ACCOUNT_CLIENT_ID_ATTRIBUTE.to_string(),
            vec![client.id.to_string()],
        )]),
        required_actions: Vec::new(),
        created_at: now,
        updated_at: now,
    };
    match storage.create_user(realm_id, &user).await {
        Ok(()) => {
            let user =
                find_service_account_user(storage, realm_id, client).await?.ok_or_else(|| {
                    IssuerdError::ServerError(
                        "newly created service-account user is missing".to_string(),
                    )
                })?;
            disable_legacy_user(storage, realm_id, legacy).await?;
            Ok(user)
        }
        Err(error) => match find_service_account_user(storage, realm_id, client).await {
            Ok(Some(user)) => {
                disable_legacy_user(storage, realm_id, legacy).await?;
                Ok(user)
            }
            Ok(None) => Err(error),
            Err(link_error) => Err(link_error),
        },
    }
}

async fn disable_legacy_user(
    storage: &dyn Storage,
    realm_id: &RealmId,
    legacy: Option<User>,
) -> Result<(), IssuerdError> {
    if let Some(mut legacy) = legacy {
        if legacy.enabled
            && !legacy.attributes.contains_key(Client::SERVICE_ACCOUNT_CLIENT_ID_ATTRIBUTE)
        {
            legacy.enabled = false;
            storage.update_user(realm_id, &legacy).await?;
        }
    }
    Ok(())
}
