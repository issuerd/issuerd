// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Public module surface and re-exports of the issuerd-token crate.

#![forbid(unsafe_code)]

pub mod action_tokens;
pub mod client_assertion;
pub mod crypto_provider;
pub mod dpop;
pub mod es512;
pub mod external;
pub mod hash;
pub mod introspection;
pub mod jwt;
pub mod pairwise;
pub mod request_object;
pub mod token_manager;

pub use action_tokens::{action_token_claims, issue_action_token, verify_action_token};
pub use client_assertion::{
    jwks_covers_assertion, validate_client_secret_assertion, validate_private_key_assertion,
    ClientAssertionClaims, ClientAssertionRequirements,
};
pub use crypto_provider::{CryptoConfig, KeyStore, RingCryptoProvider, SigningKey};
pub use dpop::{
    access_token_hash, jwk_thumbprint, validate_dpop_proof, DpopProofRequirements,
    VerifiedDpopProof, DPOP_PROOF_TYP,
};
pub use external::{validate_external_id_token, ExternalIdTokenRequirements};
pub use hash::{compute_at_hash, compute_c_hash};
pub use jwt::{AccessToken, IdToken, RefreshToken};
pub use pairwise::{effective_subject, pairwise_sub};
pub use request_object::{validate_request_object, RequestObjectRequirements};
pub use token_manager::TokenIssuer;
