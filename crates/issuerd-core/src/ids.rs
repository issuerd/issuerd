// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Strongly typed identifier newtypes (RealmId, UserId, ClientId, ...) via macro.

use crate::IssuerdError;
use serde::{Deserialize, Serialize};

fn canonicalize_identifier(id: String) -> String {
    uuid::Uuid::parse_str(&id).map(|uuid| uuid.to_string()).unwrap_or(id)
}

fn preserve_identifier(id: String) -> String {
    id
}

macro_rules! id_type {
    ($name:ident) => {
        id_type!($name, canonicalize_identifier);
    };
    ($name:ident, $normalize:ident) => {
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord, utoipa::ToSchema,
        )]
        pub struct $name(pub String);

        impl $name {
            /// Create a new identifier, rejecting empty strings.
            pub fn new(id: impl Into<String>) -> Result<Self, IssuerdError> {
                let s = $normalize(id.into());
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

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let id = <String as Deserialize>::deserialize(deserializer)?;
                Ok(Self($normalize(id)))
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
id_type!(KeyId, preserve_identifier);
id_type!(EventId);
id_type!(RoleId);
id_type!(GroupId);
id_type!(IdentityProviderId);
id_type!(CredentialId);
id_type!(ClientSessionId);
id_type!(FlowStageId);
id_type!(JwtId, preserve_identifier);
id_type!(ClientScopeId);
id_type!(MapperId);
id_type!(WebhookSubscriptionId);
id_type!(WebhookDeliveryId);

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

    #[test]
    fn uuid_ids_are_canonicalized_but_legacy_strings_are_unchanged() {
        let upper = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
        let lower = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert_eq!(RealmId::new(upper).unwrap().0, lower);
        assert_eq!(CredentialId::new(format!("{{{upper}}}")).unwrap().0, lower);
        assert_eq!(UserId::new(format!("urn:uuid:{upper}")).unwrap().0, lower);
        let decoded: CredentialId = serde_json::from_str(&format!("\"{upper}\"")).unwrap();
        assert_eq!(decoded.0, lower);
        assert_eq!(
            std::collections::HashSet::from([
                RealmId::new(upper).unwrap(),
                RealmId::new(lower).unwrap(),
            ])
            .len(),
            1
        );
        assert_eq!(RealmId::new("not-a-uuid").unwrap().0, "not-a-uuid");
        let empty: RealmId = serde_json::from_str("\"\"").unwrap();
        assert!(empty.0.is_empty());
    }

    #[test]
    fn protocol_kid_and_jti_preserve_case() {
        let upper = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
        assert_eq!(KeyId::new(upper).unwrap().0, upper);
        assert_eq!(JwtId::new(upper).unwrap().0, upper);
        let decoded: KeyId = serde_json::from_str(&format!("\"{upper}\"")).unwrap();
        assert_eq!(decoded.0, upper);
        let decoded: JwtId = serde_json::from_str(&format!("\"{upper}\"")).unwrap();
        assert_eq!(decoded.0, upper);
    }
}
