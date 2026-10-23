// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Fuzz target: OAuth2 token endpoint request parsing
// (issuerd-protocol/src/token.rs, RFC 6749 and extensions).

#![no_main]
#![forbid(unsafe_code)]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use issuerd_protocol::token::TokenRequest;
use libfuzzer_sys::fuzz_target;

/// Form-body map for `TokenRequest::parse`, shaped as optional fields for
/// the parameters the parser actually reads (all grants: authorization_code,
/// refresh_token, password, client_credentials, JWT client assertion, device
/// code, CIBA, RFC 8693 token exchange) so the fuzzer reaches the per-grant
/// parsing paths instead of dying on the missing-`grant_type` check.
#[derive(Debug, Default, Arbitrary)]
struct TokenParams {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    assertion: Option<String>,
    assertion_type: Option<String>,
    device_code: Option<String>,
    auth_req_id: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    requested_token_type: Option<String>,
    audience: Option<String>,
    requested_subject: Option<String>,
    actor_token: Option<String>,
    authorization_details: Option<String>,
}

macro_rules! insert_opt {
    ($map:ident, $name:literal, $value:expr) => {
        if let Some(v) = $value {
            $map.insert($name.to_string(), v);
        }
    };
}

impl TokenParams {
    fn into_map(self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        insert_opt!(map, "grant_type", self.grant_type);
        insert_opt!(map, "code", self.code);
        insert_opt!(map, "redirect_uri", self.redirect_uri);
        insert_opt!(map, "client_id", self.client_id);
        insert_opt!(map, "client_secret", self.client_secret);
        insert_opt!(map, "code_verifier", self.code_verifier);
        insert_opt!(map, "refresh_token", self.refresh_token);
        insert_opt!(map, "scope", self.scope);
        insert_opt!(map, "username", self.username);
        insert_opt!(map, "password", self.password);
        insert_opt!(map, "totp", self.totp);
        insert_opt!(map, "assertion", self.assertion);
        insert_opt!(map, "assertion_type", self.assertion_type);
        insert_opt!(map, "device_code", self.device_code);
        insert_opt!(map, "auth_req_id", self.auth_req_id);
        insert_opt!(map, "subject_token", self.subject_token);
        insert_opt!(map, "subject_token_type", self.subject_token_type);
        insert_opt!(map, "requested_token_type", self.requested_token_type);
        insert_opt!(map, "audience", self.audience);
        insert_opt!(map, "requested_subject", self.requested_subject);
        insert_opt!(map, "actor_token", self.actor_token);
        insert_opt!(map, "authorization_details", self.authorization_details);
        map
    }
}

fuzz_target!(|params: TokenParams| {
    let params = params.into_map();
    // Must never panic, whatever the body contains; both Result arms are
    // legitimate outcomes.
    let _ = TokenRequest::parse(&params);
});
