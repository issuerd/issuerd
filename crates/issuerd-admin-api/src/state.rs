// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Shared Admin API state: storage, crypto, cache, and service dependencies.

use issuerd_auth_flow::plugin_registry::PluginRegistry;
use issuerd_core::{
    BrokerClient, CryptoProvider, DistributedCache, EmailSender, FederationManager,
    SessionLogoutNotifier, Storage, TokenService,
};
use issuerd_token::TokenIssuer;
use std::sync::Arc;

/// i18n message-bundle resolver for outbound email copy: maps
/// (realm, recipient user) to the flat key→text bundle of the recipient's
/// locale. Wired by the composition root (issuerd-server).
///
/// Bundle text is trusted operator content: values are inserted into the
/// templates verbatim, and any `{{double-brace}}` sequences they contain are
/// NOT re-substituted (or are, depending on placeholder order) — bundle files
/// must use the documented single-brace `{realm}`/`{user}`/`{minutes}`
/// placeholders only.
pub type EmailBundleResolver = Arc<
    dyn Fn(&issuerd_core::Realm, &issuerd_core::User) -> std::collections::HashMap<String, String>
        + Send
        + Sync,
>;

pub struct AdminApiState {
    pub storage: Arc<dyn Storage>,
    pub token_service: Arc<dyn TokenService>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub federation_manager: Arc<dyn FederationManager>,
    /// Authenticator/required-action registry; drives flow
    /// validation-on-save and the `/admin/enums/authenticators` listing.
    pub plugin_registry: Arc<dyn PluginRegistry>,
    /// Distributed cache holding login-failure counters and lockout markers;
    /// queried by the attack-detection endpoints. Also stores the
    /// execute-actions-email continuation entries.
    pub cache: Arc<dyn DistributedCache>,
    /// Realm email sender; used by the SMTP test-connection endpoint and the
    /// execute-actions-email endpoint.
    pub email_sender: Arc<dyn EmailSender>,
    /// Server-to-server HTTP client for brokered IdPs; used by the identity
    /// provider test-connection endpoint.
    pub broker_client: Arc<dyn BrokerClient>,
    /// Back-channel logout notifier; invoked when the admin API
    /// destroys a user session so clients with a `backchannel_logout_uri`
    /// receive a logout token.
    pub logout_notifier: Arc<dyn SessionLogoutNotifier>,
    /// Available login theme directory names discovered at boot;
    /// always contains at least the built-in `"issuerd"` theme.
    pub available_themes: Vec<String>,
    /// Token issuer for admin-initiated sessions (impersonation).
    /// Wired from the server's `TokenManager`.
    pub token_issuer: Arc<dyn TokenIssuer>,
    /// Same-node signing-key reload hook: invoked after key
    /// rotation/disable so the running crypto provider and JWKS snapshot pick
    /// up the storage mutation immediately. Peer cluster nodes converge via
    /// the JWKS polling task. No-op in tests.
    pub signing_key_reload: Arc<dyn Fn() + Send + Sync>,
    /// Public base URL of the server (the configured issuer URL without a
    /// trailing slash); used to build absolute links in outbound email.
    pub base_url: String,
    /// Optional i18n message-bundle resolver for outbound email copy, keyed by
    /// (realm, recipient user). Wired by the composition root (issuerd-server);
    /// `None` keeps the built-in English copy.
    pub email_bundle: Option<EmailBundleResolver>,
    /// Locales offered by the locales enum endpoint and serverinfo: the
    /// shipped built-ins plus every theme-supplied `messages_<locale>.json`
    /// discovered in the themes directory at boot.
    pub available_locales: Vec<String>,
}
