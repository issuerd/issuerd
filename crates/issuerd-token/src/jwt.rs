// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Generic JWT wrapper and typed access/ID/refresh token containers.

use chrono::{DateTime, Utc};
use issuerd_core::{
    AccessTokenClaims, Algorithm, IdTokenClaims, JwsHeader, JwsType, KeyId, RefreshTokenClaims,
    UserId,
};
use serde::{Deserialize, Serialize};

/// Generic JWT wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwt<T> {
    pub header: JwsHeader,
    pub claims: T,
}

impl<T> Jwt<T> {
    pub fn new(claims: T, kid: KeyId) -> Self
    where
        T: Default,
    {
        Self {
            header: JwsHeader {
                alg: Algorithm::Rs256,
                typ: Some(JwsType::Jwt),
                kid,
            },
            claims,
        }
    }
}

/// Access token wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub token: String,
    pub claims: AccessTokenClaims,
}

/// ID token wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdToken {
    pub token: String,
    pub claims: IdTokenClaims,
}

/// Refresh token wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub token: String,
    pub claims: RefreshTokenClaims,
}

/// Refresh token metadata (opaque, stored in cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenMeta {
    pub jti: issuerd_core::JwtId,
    pub user_id: UserId,
    pub realm_id: issuerd_core::RealmId,
    pub client_id: issuerd_core::ClientId,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{ClientId, RealmId};

    #[test]
    fn jwt_new_sets_header() {
        let jwt = Jwt::new((), KeyId::new("key-1").unwrap());
        assert_eq!(jwt.header.alg, issuerd_core::Algorithm::Rs256);
        assert_eq!(jwt.header.typ, Some(JwsType::Jwt));
        assert_eq!(jwt.header.kid, KeyId::new("key-1").unwrap());
    }

    #[test]
    fn refresh_token_meta_serde_roundtrip() {
        let meta = RefreshTokenMeta {
            jti: issuerd_core::JwtId::new("jti-123").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientId::new("client-1").unwrap(),
            scope: "openid profile".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        };

        let json = serde_json::to_string(&meta).unwrap();
        let back: RefreshTokenMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.jti, meta.jti);
        assert_eq!(back.user_id, meta.user_id);
        assert_eq!(back.realm_id, meta.realm_id);
        assert_eq!(back.client_id, meta.client_id);
        assert_eq!(back.scope, meta.scope);
    }
}
