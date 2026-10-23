// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Fuzz target: PKCE code verifier/challenge verification
// (issuerd-protocol/src/pkce.rs, RFC 7636).
//
// The input style mirrors the crate's `#[cfg(kani)]` proof harnesses: small
// bounded byte strings converted lossily to `&str`, plus an explicit method
// selector, so the fuzzer explores the length guard, the method arms, and
// the challenge comparison independently.

#![no_main]
#![forbid(unsafe_code)]

use arbitrary::Arbitrary;
use issuerd_core::PkceCodeChallengeMethod;
use issuerd_protocol::pkce::PkceVerifier;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum MethodInput {
    Missing,
    S256,
    Plain,
}

#[derive(Debug, Arbitrary)]
struct PkceInput {
    // Bounded raw bytes, converted lossily: invalid UTF-8 exercises the
    // multi-byte/length-window edge cases without killing the fuzzer.
    verifier: Vec<u8>,
    challenge: Vec<u8>,
    method: MethodInput,
}

fuzz_target!(|input: PkceInput| {
    let verifier = String::from_utf8_lossy(&input.verifier);
    let challenge = String::from_utf8_lossy(&input.challenge);
    let method = match input.method {
        MethodInput::Missing => None,
        MethodInput::S256 => Some(PkceCodeChallengeMethod::S256),
        MethodInput::Plain => Some(PkceCodeChallengeMethod::Plain),
    };

    // Must never panic, whatever the strings contain; both Result arms are
    // legitimate outcomes.
    let _ = PkceVerifier::verify(&verifier, &challenge, method);

    // Self-consistency (also pinned by the crate's proptests): a challenge
    // computed from the verifier itself verifies exactly when the verifier
    // sits inside the RFC 7636 43–128 byte window.
    let computed = PkceVerifier::s256_challenge(&verifier);
    let in_window = (43..=128).contains(&verifier.len());
    assert_eq!(
        PkceVerifier::verify(&verifier, &computed, Some(PkceCodeChallengeMethod::S256)).is_ok(),
        in_window,
    );
});
