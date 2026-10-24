// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Fuzz target: OIDC/OAuth2 authorization request parsing
// (issuerd-protocol/src/authorization.rs).

#![no_main]
#![forbid(unsafe_code)]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use issuerd_protocol::authorization::AuthorizationRequest;
use libfuzzer_sys::fuzz_target;

/// Query-parameter map for `AuthorizationRequest::parse`, shaped as optional
/// fields for the parameters the parser actually reads so the fuzzer reaches
/// the deep validation paths instead of dying on the first
/// missing-parameter check. Values stay arbitrary strings — the parser's job
/// is to reject anything malformed without panicking.
#[derive(Debug, Default, Arbitrary)]
struct AuthorizationParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    response_mode: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    login_hint: Option<String>,
    id_token_hint: Option<String>,
    acr_values: Option<String>,
    ui_locales: Option<String>,
    claims: Option<String>,
    authorization_details: Option<String>,
    registration: Option<String>,
    // JAR parameters: their presence must be rejected defensively.
    request: Option<String>,
    request_uri: Option<String>,
}

macro_rules! insert_opt {
    ($map:ident, $name:literal, $value:expr) => {
        if let Some(v) = $value {
            $map.insert($name.to_string(), v);
        }
    };
}

impl AuthorizationParams {
    fn into_map(self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        insert_opt!(map, "response_type", self.response_type);
        insert_opt!(map, "client_id", self.client_id);
        insert_opt!(map, "redirect_uri", self.redirect_uri);
        insert_opt!(map, "scope", self.scope);
        insert_opt!(map, "state", self.state);
        insert_opt!(map, "nonce", self.nonce);
        insert_opt!(map, "response_mode", self.response_mode);
        insert_opt!(map, "prompt", self.prompt);
        insert_opt!(map, "max_age", self.max_age);
        insert_opt!(map, "code_challenge", self.code_challenge);
        insert_opt!(map, "code_challenge_method", self.code_challenge_method);
        insert_opt!(map, "login_hint", self.login_hint);
        insert_opt!(map, "id_token_hint", self.id_token_hint);
        insert_opt!(map, "acr_values", self.acr_values);
        insert_opt!(map, "ui_locales", self.ui_locales);
        insert_opt!(map, "claims", self.claims);
        insert_opt!(map, "authorization_details", self.authorization_details);
        insert_opt!(map, "registration", self.registration);
        insert_opt!(map, "request", self.request);
        insert_opt!(map, "request_uri", self.request_uri);
        map
    }
}

fuzz_target!(|params: AuthorizationParams| {
    let params = params.into_map();
    // Must never panic, whatever the map contains; both Result arms are
    // legitimate outcomes.
    let _ = AuthorizationRequest::parse(&params);
});
