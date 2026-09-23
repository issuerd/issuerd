// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Building RFC 7662 introspection responses from validated access-token claims.

use issuerd_core::{AccessTokenClaims, ClientIdentifier, IntrospectionResponse};

/// Build an introspection response from validated claims.
pub fn introspect(claims: Option<&AccessTokenClaims>) -> IntrospectionResponse {
    match claims {
        Some(c) => IntrospectionResponse {
            active: true,
            scope: Some(c.scope.clone()),
            client_id: c.azp.as_deref().and_then(|s| ClientIdentifier::new(s).ok()),
            username: None,
            // RFC 9449 §6.1: DPoP-bound tokens introspect as `DPoP` + `cnf`.
            token_type: Some(if c.cnf.is_some() {
                issuerd_core::TokenType::Dpop
            } else {
                issuerd_core::TokenType::Bearer
            }),
            cnf: c.cnf.clone(),
            authorization_details: c.authorization_details.clone(),
            exp: Some(c.exp),
            iat: Some(c.iat),
            nbf: Some(c.nbf),
            sub: Some(c.sub.to_string()),
            aud: Some(c.aud.clone()),
            iss: Some(c.iss.clone()),
            jti: Some(c.jti.clone()),
        },
        None => IntrospectionResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            cnf: None,
            authorization_details: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{Audience, ClientIdentifier, Issuer, JwtId, JwtType, UserId};

    fn sample_claims() -> AccessTokenClaims {
        AccessTokenClaims {
            jti: JwtId::new("jti-1").unwrap(),
            iss: Issuer::new("https://issuer").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: 1234567890,
            iat: 1234567800,
            nbf: 1234567800,
            scope: issuerd_core::Scope::parse("openid profile"),
            typ: JwtType::Bearer,
            azp: Some("my-app".to_string()),
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
        }
    }

    #[test]
    fn introspect_some_claims() {
        let claims = sample_claims();
        let resp = introspect(Some(&claims));
        assert!(resp.active);
        assert_eq!(resp.scope, Some(issuerd_core::Scope::parse("openid profile")));
        assert_eq!(resp.client_id, Some(ClientIdentifier::new("my-app").unwrap()));
        assert_eq!(resp.token_type, Some(issuerd_core::TokenType::Bearer));
        assert_eq!(resp.exp, Some(1234567890));
        assert_eq!(resp.iat, Some(1234567800));
        assert_eq!(resp.nbf, Some(1234567800));
        assert_eq!(resp.sub, Some("user-1".to_string()));
        assert_eq!(resp.aud, Some(Audience::new("my-app").unwrap()));
        assert_eq!(resp.iss, Some(Issuer::new("https://issuer").unwrap()));
        assert_eq!(resp.jti, Some(JwtId::new("jti-1").unwrap()));
        assert_eq!(resp.username, None);
    }

    #[test]
    fn introspect_none_claims() {
        let resp = introspect(None);
        assert!(!resp.active);
        assert_eq!(resp.scope, None);
        assert_eq!(resp.client_id, None);
        assert_eq!(resp.token_type, None);
        assert_eq!(resp.exp, None);
        assert_eq!(resp.iat, None);
        assert_eq!(resp.nbf, None);
        assert_eq!(resp.sub, None);
        assert_eq!(resp.aud, None);
        assert_eq!(resp.iss, None);
        assert_eq!(resp.jti, None);
        assert_eq!(resp.username, None);
    }
}
