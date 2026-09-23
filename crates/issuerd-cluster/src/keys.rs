// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Cache key schema helpers (colon-delimited, entity-prefixed keys).

/// Cache key schema helpers.
///
/// All keys are colon-delimited and prefixed by entity type to prevent
/// collisions across different kinds of cached data.
pub mod cache_keys {
    /// `session:{realm}:{session_id}`
    pub fn session(realm: &str, session_id: &str) -> String {
        format!("session:{realm}:{session_id}")
    }

    /// `login-failure:{realm}:{identifier}`
    pub fn login_failure(realm: &str, identifier: &str) -> String {
        format!("login-failure:{realm}:{identifier}")
    }

    /// `realm:{realm_id}`
    pub fn realm(realm_id: &str) -> String {
        format!("realm:{realm_id}")
    }

    /// `realm-by-name:{name}` — the realm-NAME lookup cache
    /// (`ServerState::resolve_issuer_realm`), a different keyspace from
    /// [`realm`] (id-keyed).
    pub fn realm_by_name(name: &str) -> String {
        format!("realm-by-name:{name}")
    }

    /// `sessv:{realm}:{user_id}` — per-user session-validity version
    /// counter. Bumped on bulk per-user session revocation (user delete /
    /// logout-all); cached session snapshots carrying an older version are
    /// treated as misses.
    pub fn session_version(realm: &str, user_id: &str) -> String {
        format!("sessv:{realm}:{user_id}")
    }

    /// `user-claims:{realm}:{user_id}` — per-user claims bundle (user row,
    /// groups, direct role-mapping ids) backing the token/userinfo claims
    /// assembly.
    pub fn user_claims(realm: &str, user_id: &str) -> String {
        format!("user-claims:{realm}:{user_id}")
    }

    /// `realm-catalog:{realm}` — realm-wide claims catalog (all role
    /// definitions + all client-scope definitions with their mappers).
    pub fn realm_catalog(realm: &str) -> String {
        format!("realm-catalog:{realm}")
    }

    /// `client-scopes:{realm}:{client_uuid}` — default-assigned client-scope
    /// ids of one client (by its internal UUID id).
    pub fn client_scopes(realm: &str, client_uuid: &str) -> String {
        format!("client-scopes:{realm}:{client_uuid}")
    }

    /// `client-uuid:{realm}:{client_uuid}` — reverse map from a client's
    /// internal UUID id to its public `client_id` identifier (role-owner
    /// resolution in claims assembly).
    pub fn client_uuid(realm: &str, client_uuid: &str) -> String {
        format!("client-uuid:{realm}:{client_uuid}")
    }

    /// `claimsepoch:{realm}` — realm-wide claims epoch counter. Bumped on
    /// any realm-level definition change that cached claims bundles cannot
    /// be precisely invalidated for (role/scope/mapper/composite/group
    /// definition CRUD, bulk imports, federation sync runs); cached entries
    /// carrying an older epoch are treated as misses.
    pub fn claims_epoch(realm: &str) -> String {
        format!("claimsepoch:{realm}")
    }

    /// `usergen:{realm}:{user_id}` — per-user claims-content generation
    /// counter. Bumped by `invalidate::invalidate_user_claims` (user
    /// update/delete, per-user role-mapping or group-membership change);
    /// the rendered userinfo response cache validates against it.
    pub fn user_claims_generation(realm: &str, user_id: &str) -> String {
        format!("usergen:{realm}:{user_id}")
    }

    /// `clientgen:{realm}:{client_id}` — per-client claims-content
    /// generation counter. Bumped by `invalidate::invalidate_client_claims`
    /// (client update/delete, mapper/scope-assignment changes).
    pub fn client_claims_generation(realm: &str, client_id: &str) -> String {
        format!("clientgen:{realm}:{client_id}")
    }

    /// `uinfo-resp:{realm}:{user_id}:{fingerprint}` — rendered userinfo
    /// response body for one (user, client, scope-set, claims-parameter)
    /// combination, validated against epoch + generation counters.
    pub fn userinfo_response(realm: &str, user_id: &str, fingerprint: &str) -> String {
        format!("uinfo-resp:{realm}:{user_id}:{fingerprint}")
    }

    /// `discovery-resp:{realm_name}` — rendered OIDC discovery document,
    /// validated against the realm row content hash + keyset generation.
    pub fn discovery_response(realm_name: &str) -> String {
        format!("discovery-resp:{realm_name}")
    }

    /// `client:{realm}:{client_id}`
    pub fn client(realm: &str, client_id: &str) -> String {
        format!("client:{realm}:{client_id}")
    }

    /// `user:{realm}:{user_id}`
    pub fn user(realm: &str, user_id: &str) -> String {
        format!("user:{realm}:{user_id}")
    }

    /// `ciba:{auth_req_id}`
    pub fn ciba_auth_req(auth_req_id: &str) -> String {
        format!("ciba:{auth_req_id}")
    }

    /// `device:{device_code}`
    pub fn device_code(device_code: &str) -> String {
        format!("device:{device_code}")
    }

    /// `user_code:{user_code}`
    pub fn user_code(user_code: &str) -> String {
        format!("user_code:{user_code}")
    }

    /// `action:{token_id}`
    pub fn action_token(token_id: &str) -> String {
        format!("action:{token_id}")
    }

    /// `events:{realm}`
    pub fn event_channel(realm: &str) -> String {
        format!("events:{realm}")
    }
}

#[cfg(test)]
mod tests {
    use super::cache_keys;

    #[test]
    fn session_key_format() {
        assert_eq!(cache_keys::session("master", "sess-123"), "session:master:sess-123");
    }

    #[test]
    fn login_failure_key_format() {
        assert_eq!(cache_keys::login_failure("master", "alice"), "login-failure:master:alice");
    }

    #[test]
    fn realm_key_format() {
        assert_eq!(cache_keys::realm("master"), "realm:master");
    }

    #[test]
    fn realm_by_name_key_format() {
        assert_eq!(cache_keys::realm_by_name("master"), "realm-by-name:master");
        // Distinct keyspace from the id-keyed `realm:` helper.
        assert_ne!(cache_keys::realm_by_name("master"), cache_keys::realm("master"));
    }

    #[test]
    fn session_version_key_format() {
        assert_eq!(cache_keys::session_version("realm-1", "user-1"), "sessv:realm-1:user-1");
    }

    #[test]
    fn claims_cache_key_formats() {
        assert_eq!(cache_keys::user_claims("master", "user-1"), "user-claims:master:user-1");
        assert_eq!(cache_keys::realm_catalog("master"), "realm-catalog:master");
        assert_eq!(cache_keys::client_scopes("master", "uuid-1"), "client-scopes:master:uuid-1");
        assert_eq!(cache_keys::client_uuid("master", "uuid-1"), "client-uuid:master:uuid-1");
        assert_eq!(cache_keys::claims_epoch("master"), "claimsepoch:master");
        assert_eq!(cache_keys::user_claims_generation("master", "user-1"), "usergen:master:user-1");
        assert_eq!(
            cache_keys::client_claims_generation("master", "my-app"),
            "clientgen:master:my-app"
        );
        assert_eq!(
            cache_keys::userinfo_response("master", "user-1", "fp"),
            "uinfo-resp:master:user-1:fp"
        );
        assert_eq!(cache_keys::discovery_response("master"), "discovery-resp:master");
    }

    #[test]
    fn client_key_format() {
        assert_eq!(cache_keys::client("master", "my-app"), "client:master:my-app");
    }

    #[test]
    fn user_key_format() {
        assert_eq!(cache_keys::user("master", "user-123"), "user:master:user-123");
    }

    #[test]
    fn ciba_key_format() {
        assert_eq!(cache_keys::ciba_auth_req("req-123"), "ciba:req-123");
    }

    #[test]
    fn device_code_key_format() {
        assert_eq!(cache_keys::device_code("dev-123"), "device:dev-123");
    }

    #[test]
    fn user_code_key_format() {
        assert_eq!(cache_keys::user_code("ABCD-EFGH"), "user_code:ABCD-EFGH");
    }

    #[test]
    fn action_token_key_format() {
        assert_eq!(cache_keys::action_token("tok-123"), "action:tok-123");
    }

    #[test]
    fn event_channel_key_format() {
        assert_eq!(cache_keys::event_channel("master"), "events:master");
    }

    #[test]
    fn no_collisions_between_entity_types() {
        // Same realm and identifier used for different entity types
        let session = cache_keys::session("r1", "s1");
        let user = cache_keys::user("r1", "s1");
        let client = cache_keys::client("r1", "s1");
        let realm = cache_keys::realm("r1:s1");

        assert_ne!(session, user);
        assert_ne!(session, client);
        assert_ne!(user, client);
        assert_ne!(session, realm);
    }
}
