// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Workspace integration test root declaring all integration test modules.

mod harness;

#[path = "integration/account_security.rs"]
mod account_security;
#[path = "integration/admin_api_e2e.rs"]
mod admin_api_e2e;
#[path = "integration/admin_depth.rs"]
mod admin_depth;
#[path = "integration/algorithm_agility.rs"]
mod algorithm_agility;
#[path = "integration/bench.rs"]
mod bench;
#[path = "integration/client_scopes.rs"]
mod client_scopes;
#[path = "integration/cluster.rs"]
mod cluster;
#[path = "integration/cluster_e2e.rs"]
mod cluster_e2e;
#[path = "integration/concurrency.rs"]
mod concurrency;
#[path = "integration/consent.rs"]
mod consent;
#[path = "integration/cross_realm_auth.rs"]
mod cross_realm_auth;
#[path = "integration/dpop.rs"]
mod dpop;
#[path = "integration/dynamic_client_registration.rs"]
mod dynamic_client_registration;
#[path = "integration/email_code_login.rs"]
mod email_code_login;
#[path = "integration/federation_ad.rs"]
mod federation_ad;
#[path = "integration/federation_ldap.rs"]
mod federation_ldap;
#[path = "integration/federation_load_ad.rs"]
mod federation_load_ad;
#[path = "integration/federation_load_common.rs"]
mod federation_load_common;
#[path = "integration/federation_load_openldap.rs"]
mod federation_load_openldap;
#[path = "integration/federation_load_samba.rs"]
mod federation_load_samba;
#[path = "integration/federation_samba.rs"]
mod federation_samba;
#[path = "integration/i18n.rs"]
mod i18n;
#[path = "integration/identity_brokering.rs"]
mod identity_brokering;
#[path = "integration/jar_jarm_form_post.rs"]
mod jar_jarm_form_post;
#[path = "integration/jwt_client_auth.rs"]
mod jwt_client_auth;
#[path = "integration/logout_channels.rs"]
mod logout_channels;
#[path = "integration/mfa.rs"]
mod mfa;
#[path = "integration/oauth2_grants.rs"]
mod oauth2_grants;
#[path = "integration/offline_tokens.rs"]
mod offline_tokens;
#[path = "integration/oidc_auth_code.rs"]
mod oidc_auth_code;
#[path = "integration/oidc_discovery.rs"]
mod oidc_discovery;
#[path = "integration/pairwise_subjects.rs"]
mod pairwise_subjects;
#[path = "integration/par.rs"]
mod par;
#[path = "integration/rar.rs"]
mod rar;
#[path = "integration/spec_conformance.rs"]
mod spec_conformance;
#[path = "integration/token_exchange.rs"]
mod token_exchange;
#[path = "integration/token_lifecycle.rs"]
mod token_lifecycle;
#[path = "integration/token_validation.rs"]
mod token_validation;
#[path = "integration/user_self_service.rs"]
mod user_self_service;
#[path = "integration/userinfo_cache.rs"]
mod userinfo_cache;
#[path = "integration/webauthn.rs"]
mod webauthn;
