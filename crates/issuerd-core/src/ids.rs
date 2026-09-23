// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Strongly typed identifier newtypes (RealmId, UserId, ClientId, ...) via macro.

use crate::IssuerdError;
use serde::{Deserialize, Serialize};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            Serialize,
            Deserialize,
            PartialOrd,
            Ord,
            utoipa::ToSchema,
        )]
        pub struct $name(pub String);

        impl $name {
            /// Create a new identifier, rejecting empty strings.
            pub fn new(id: impl Into<String>) -> Result<Self, IssuerdError> {
                let s = id.into();
                if s.is_empty() {
                    Err(IssuerdError::InvalidRequest(format!(
                        "{} cannot be empty",
                        stringify!($name)
                    )))
                } else {
                    Ok(Self(s))
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IssuerdError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IssuerdError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = IssuerdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}

id_type!(RealmId);
id_type!(UserId);
id_type!(ClientId);
id_type!(SessionId);
id_type!(KeyId);
id_type!(EventId);
id_type!(RoleId);
id_type!(GroupId);
id_type!(IdentityProviderId);
id_type!(CredentialId);
id_type!(ClientSessionId);
id_type!(FlowStageId);
id_type!(JwtId);
id_type!(ClientScopeId);
id_type!(MapperId);

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Compile-time distinctness
    // ------------------------------------------------------------------
    #[test]
    fn id_type_distinctness() {
        // These lines prove at compile time that the types are not interchangeable.
        let _realm = RealmId("realm-1".into());
        let _user = UserId("user-1".into());
        let _client = ClientId("client-1".into());
        let _session = SessionId("session-1".into());
        let _key = KeyId("key-1".into());
        let _event = EventId("event-1".into());

        // Uncommenting any of the following should produce a compile error:
        // let _: RealmId = _user;
        // let _: UserId = _realm;
    }

    // ------------------------------------------------------------------
    // Serde roundtrip
    // ------------------------------------------------------------------
    #[test]
    fn realm_id_serde_roundtrip() {
        let id = RealmId("realm-1".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"realm-1\"");
        let decoded: RealmId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn user_id_serde_roundtrip() {
        let id = UserId("user-1".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"user-1\"");
        let decoded: UserId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn client_id_serde_roundtrip() {
        let id = ClientId("client-1".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"client-1\"");
        let decoded: ClientId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn session_id_serde_roundtrip() {
        let id = SessionId("session-1".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"session-1\"");
        let decoded: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn key_id_serde_roundtrip() {
        let id = KeyId("key-1".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"key-1\"");
        let decoded: KeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn event_id_serde_roundtrip() {
        let id = EventId("event-1".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"event-1\"");
        let decoded: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    // ------------------------------------------------------------------
    // Trait coverage
    // ------------------------------------------------------------------
    #[test]
    fn id_traits() {
        let id = RealmId("realm-1".into());
        assert_eq!(format!("{id}"), "realm-1");
        assert_eq!(id.as_ref(), "realm-1");
        assert_eq!(RealmId::new("realm-1").unwrap(), id);
        assert_eq!(RealmId::try_from("realm-1").unwrap(), id);
        assert_eq!(RealmId::try_from("realm-1".to_string()).unwrap(), id);
    }

    #[test]
    fn id_ordering() {
        let a = RealmId("a".into());
        let b = RealmId("b".into());
        assert!(a < b);
    }

    #[test]
    fn id_from_str_rejects_empty() {
        let err = "".parse::<RealmId>().unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[test]
    fn id_from_str_accepts_non_empty() {
        let id = "realm-1".parse::<RealmId>().unwrap();
        assert_eq!(id.0, "realm-1");
    }

    #[test]
    fn id_new_rejects_empty() {
        let err = RealmId::new("").unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }
}
