// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use serde::Deserialize;

#[derive(Deserialize)]
struct Input {
    password: String,
    salt: String,
}

fn main() {
    let input: Input =
        serde_json::from_reader(std::io::stdin()).expect("invalid hash-helper input");
    let salt = SaltString::from_b64(&input.salt).expect("invalid salt");
    let params = argon2::Params::new(7168, 5, 1, Some(32)).expect("valid Argon2 parameters");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(input.password.as_bytes(), &salt)
        .expect("Argon2 hashing failed");
    print!("{hash}");
}
