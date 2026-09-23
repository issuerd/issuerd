// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Crate root of issuerd-core: shared types, traits, errors, and models re-exports.

#![forbid(unsafe_code)]

pub mod broker;
pub mod client_scope;
pub mod error;
pub mod events;
pub mod federation;
pub mod flows;
pub mod i18n;
pub mod ids;
pub mod models;
pub mod pairwise;
pub mod password;
pub mod provision;
pub mod roles;
pub mod scope;
pub mod traits;
pub mod typestate;
pub mod utils;

pub use broker::{
    apply_mappers, claims_need_userinfo, decide_first_broker_login, identity_provider_presets,
    merge_userinfo_claims, render_username_template, BrokerClient, BrokerClientAuthMethod,
    BrokerDiscoveryDocument, BrokerIdpSettings, BrokerSyncMode, BrokerTokenResponse,
    BrokeredIdentity, FirstBrokerLoginDecision, IdentityProviderLink, IdpMapper, IdpMapperType,
    IdpPreset, MapperEffects, MockBrokerClient,
};
pub use client_scope::{
    builtin_client_scopes, is_builtin_scope_name, mapper_config, ClaimTarget, ClientScope,
    MapperType, ProtocolMapper, ScopeMappings, BUILTIN_SCOPE_NAMES, DEFAULT_DEFAULT_SCOPES,
    DEFAULT_OPTIONAL_SCOPES,
};
pub use error::{IssuerdError, OAuth2Error, OAuth2ErrorCode};
pub use events::{AdminEvent, Event, EventType, OperationType, ResourceType};
pub use federation::{
    EditMode, FederatedUser, FederationError, FederationManager, FederationProvider,
    FederationProviderConfig, FederationProviderType, SpnegoAuthResult, SpnegoStatus, SyncResult,
};
pub use ids::{
    ClientId, ClientScopeId, ClientSessionId, CredentialId, EventId, FlowStageId, GroupId,
    IdentityProviderId, JwtId, KeyId, MapperId, RealmId, RoleId, SessionId, UserId,
};
pub use models::{
    Alias, ClaimName, ClientIdentifier, DisplayName, LogoutToken, LogoutTokenClaims, ProviderId,
    ThemeName, *,
};
pub use pairwise::{validate_pairwise_subject_config, validate_sector_document};
pub use password::{PasswordPolicyError, PasswordPolicyViolation};
pub use provision::{
    ProvisionClient, ProvisionConfig, ProvisionFlowConfig, ProvisionFlowStage, ProvisionGroup,
    ProvisionIdentityProvider, ProvisionRealm, ProvisionRole, ProvisionUser,
};
pub use roles::{effective_group_roles, effective_user_roles, expand_composites, list_all_roles};
pub use scope::{Scope, OFFLINE_ACCESS_SCOPE};
pub use traits::*;
// Re-export commonly used typestate types for ergonomics
pub use typestate::{
    ActionState, ActionsCleared, ActionsPending, AnonymousState, AuthRequestState, AuthState,
    AuthenticatedState, ChallengeKind, CompletedFlow, CookieKind, FailedFlow, FlowStatus,
    LoginFormKind, OtpFormKind, PendingActionRequired, PendingAnonymous, PendingChallenged,
    PendingState, RedirectKind, RunningFlow, SessionAnonymous, SessionAuthenticated,
    SessionAuthorized, SessionConsentRequired, SessionExpired, SessionState, TypedAuthContext,
    TypedChallenge, TypedFlowResult, TypedSession, WebAuthnKind,
};
