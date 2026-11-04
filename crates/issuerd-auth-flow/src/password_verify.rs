// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Central verifier for stored password credentials.

#[cfg(test)]
pub(crate) mod tests {
    use chrono::Utc;
    use issuerd_core::{Credential, CredentialId, CredentialType};
    use serde_json::{json, Value};

    use super::*;

    pub(crate) const PASSWORD: &str = "Keycl0ak!pass";
    const WRONG: &str = "not-the-password";

    // Exported by Keycloak itself: tests/base/.../migration-realm-19.0.3-Migration.json,
    // testsuite/.../migration-realm-24.0.4.json and testsuite/.../testrealm-token-exchange-v2.json
    // in keycloak/keycloak. Their SHA-256 rows hold a 64-byte derived key.
    const KC_19_SHA256_SECRET: &str = r#"{"value":"v5ktaLYXAJgePltpedJm6oZq+CzIQM+XzRs+oktwnUHusJiMMDHzkcNFUx2WQaem595/RGCTw/8tO8tcazV4Ww==","salt":"rBWsuTNkZ1aXmkrzqVr2fA=="}"#;
    const KC_19_SHA256_DATA: &str = r#"{"hashIterations":27500,"algorithm":"pbkdf2-sha256"}"#;
    const KC_24_SHA256_SECRET: &str = r#"{"value":"OnsOPGVN5ku0lAuW+6IUMhiYyre5C9itUlMBH9xtQgWYYqeYG3kiRkWrdBVWfvv1t5F4r7FnNLqQzZ7R5Fna2w==","salt":"WQWgqINSHrX0yk5oIl4xpw==","additionalParameters":{}}"#;
    const KC_24_SHA256_DATA: &str =
        r#"{"hashIterations":27500,"algorithm":"pbkdf2-sha256","additionalParameters":{}}"#;
    const KC_SHA256_PASSWORD: &str = "admin";
    const KC_ARGON2_SECRET: &str = r#"{"value":"GNjvIqBcbM+mqCUt7nqYgl696zKTjNO1wLnvPkDfMFA=","salt":"txHDSAn9HgpQ7GE8Be9zTQ==","additionalParameters":{}}"#;
    const KC_ARGON2_DATA: &str = r#"{"hashIterations":5,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["7168"],"type":["id"],"version":["1.3"],"parallelism":["1"]}}"#;
    const KC_ARGON2_PASSWORD: &str = "password";

    // Everything below was derived outside Rust with Python's hashlib and
    // argon2-cffi. Each entry is (digest, iterations, salt, derived key).
    const SHA256_27500: (&str, u32, &str, &str) = (
        "pbkdf2-sha256",
        27_500,
        "x5gm+pKpqaRl4x8gzgYzCg==",
        "Ysjv8TgUTxPDbFyQQ9byzkZKSAw6u6iin/OYKULIVDc=",
    );
    const SHA256_600000: (&str, u32, &str, &str) = (
        "pbkdf2-sha256",
        600_000,
        "PCGyjDdPnH/SjWQUqzf1Ew==",
        "kBzMc9dXf/lKYuRUQMGCL+mA/KuOnRajUowC5l/td3U=",
    );
    const SHA512_30000: (&str, u32, &str, &str) = (
        "pbkdf2-sha512",
        30_000,
        "KsXHtVtR09QpbuSqrbHY/A==",
        "TOnaXrr6ftbPgJCtlkY1NZfnuIoXDTzDBMkeiaf+s7pWBbYTqGXooG4pCCx/hiAGA7jBvulE+SaAuq+SGfDulA==",
    );
    const SHA512_210000: (&str, u32, &str, &str) = (
        "pbkdf2-sha512",
        210_000,
        "i+LHQTLtzkHeFbP6wJ2P4A==",
        "OPwVRsqytrqyh9jaXg9Yj84XmXBgQcmHbKR/ZYNV6mUm81jeiYrzIBWn9HolI55rDyy9f7pcDTSaAdwVhEnA/g==",
    );
    const SHA512_32_BYTE_KEY: (&str, u32, &str, &str) = (
        "pbkdf2-sha512",
        1_000,
        "KzNzG2PRWTTJhc1HikOv0g==",
        "9zvvIwqzDxQnz4dyJr33nOPde6AfAc627jIVgXrgbp4=",
    );
    const SHA256_16_BYTE_KEY: (&str, u32, &str, &str) =
        ("pbkdf2-sha256", 1_000, "4lF2kDSCzSDSFOglqQfFVQ==", "JDEm7IJwoNB+hjrCeN0O3g==");
    const SHA256_ONE_ITERATION: (&str, u32, &str, &str) = (
        "pbkdf2-sha256",
        1,
        "yVxyT+e5C+t6achTja36Nw==",
        "c+iOyqZZKilR8yRw6QjlUGNNkbjET02Y3VGX9qvitUk=",
    );
    const SHA256_AT_CAP: (&str, u32, &str, &str) = (
        "pbkdf2-sha256",
        2_000_000,
        "Qh5DVC2Dc3c9YcRL6CPsnQ==",
        "WeEyQqSCB0cYXvaJ1xNJHbkjGF8BgmftOMg9qMrh288=",
    );
    const SHA256_UNICODE_PASSWORD: (&str, u32, &str, &str) = (
        "pbkdf2-sha256",
        1_000,
        "fRBCD4GGgfSbaqkUt8/YQA==",
        "6fbsRIrWh/3MKjECARV/vqwmRXf0UxH94aet3rQ8Qro=",
    );
    const UNICODE_PASSWORD: &str = "pä$$wörd-日本語";

    const ARGON2ID_SALT: &str = "sTkyFFYJJW7wQ9Jp3Yzf3Q==";
    const ARGON2ID_VALUE: &str = "8p+kFiuwL6QywmK/8nWwGAXDLYcTxy92v5QPxuTZz6Q=";

    const PHC_SHA256_27500: &str =
        "$pbkdf2-sha256$i=27500$x5gm+pKpqaRl4x8gzgYzCg$Ysjv8TgUTxPDbFyQQ9byzkZKSAw6u6iin/OYKULIVDc";
    const PHC_SHA256_600000: &str =
        "$pbkdf2-sha256$i=600000$PCGyjDdPnH/SjWQUqzf1Ew$kBzMc9dXf/lKYuRUQMGCL+mA/KuOnRajUowC5l/td3U";
    const PHC_SHA512_30000: &str = "$pbkdf2-sha512$i=30000$KsXHtVtR09QpbuSqrbHY/A$TOnaXrr6ftbPgJCtlkY1NZfnuIoXDTzDBMkeiaf+s7pWBbYTqGXooG4pCCx/hiAGA7jBvulE+SaAuq+SGfDulA";
    const PHC_SHA512_210000: &str = "$pbkdf2-sha512$i=210000$i+LHQTLtzkHeFbP6wJ2P4A$OPwVRsqytrqyh9jaXg9Yj84XmXBgQcmHbKR/ZYNV6mUm81jeiYrzIBWn9HolI55rDyy9f7pcDTSaAdwVhEnA/g";
    const PHC_SHA256_ONE_ITERATION: &str =
        "$pbkdf2-sha256$i=1$yVxyT+e5C+t6achTja36Nw$c+iOyqZZKilR8yRw6QjlUGNNkbjET02Y3VGX9qvitUk";
    const PHC_ARGON2ID_KEYCLOAK_PARAMS: &str =
        "$argon2id$v=19$m=7168,t=5,p=1$sTkyFFYJJW7wQ9Jp3Yzf3Q$8p+kFiuwL6QywmK/8nWwGAXDLYcTxy92v5QPxuTZz6Q";
    const PHC_ARGON2ID_DEFAULT_PARAMS: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$Atu8NJgJV+eZPuQSCySkZg$yJ2SMsYKmNOlixd68VI0phejDGe2AfRuwbSZkS6LbYU";
    const PHC_ARGON2I: &str =
        "$argon2i$v=19$m=7168,t=5,p=1$BHvgYp0sbdal7E5TXWn9JA$85tZAWNDOGBI3oEtStmODNq/9OcrTtcwkj83rFpsUec";
    const PHC_ARGON2D: &str =
        "$argon2d$v=19$m=7168,t=5,p=1$bYs0suyZRcih6IDvLj0c4w$tOf2oLRR+Qg4zrB9rsfUtHQ+cKqoOjBIGeh8dORQSpg";

    const SHA1_SALT: &str = "sVZYIKXNrEDgUg0j+dCxSQ==";
    const SHA1_VALUE: &str = "VAk9tTOF3Wh8ss0Ewzo24F97gZg=";
    const PHC_SHA1: &str = "$pbkdf2$i=20000$sVZYIKXNrEDgUg0j+dCxSQ$VAk9tTOF3Wh8ss0Ewzo24F97gZg";

    const FIFTEEN_BYTES: &str = "AAAAAAAAAAAAAAAAAAAA";
    const VALID_SALT: &str = SHA256_27500.2;
    const VALID_VALUE: &str = SHA256_27500.3;

    pub(crate) fn credential(secret: &[u8], data: Value) -> Credential {
        Credential {
            id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: secret.to_vec(),
            credential_data: data,
            priority: 1,
        }
    }

    fn keycloak_row(secret: &str, data: &str) -> Credential {
        credential(secret.as_bytes(), Value::String(data.to_string()))
    }

    fn phc_row(phc: &str) -> Credential {
        credential(phc.as_bytes(), json!({"hash_algorithm": "argon2id"}))
    }

    fn pbkdf2_row(vector: (&str, u32, &str, &str)) -> Credential {
        let (algorithm, iterations, salt, value) = vector;
        credential(
            json!({"value": value, "salt": salt}).to_string().as_bytes(),
            json!({"hashIterations": iterations, "algorithm": algorithm}),
        )
    }

    fn argon2_params() -> Value {
        json!({
            "hashIterations": 5,
            "algorithm": "argon2",
            "additionalParameters": {
                "hashLength": ["32"],
                "memory": ["7168"],
                "type": ["id"],
                "version": ["1.3"],
                "parallelism": ["1"],
            },
        })
    }

    fn argon2_row(data: Value) -> Credential {
        credential(
            json!({"value": ARGON2ID_VALUE, "salt": ARGON2ID_SALT}).to_string().as_bytes(),
            data,
        )
    }

    /// One row of each format a long-lived Keycloak realm can hold, with its password.
    pub(crate) fn keycloak_rows() -> Vec<(&'static str, Credential)> {
        vec![
            (KC_SHA256_PASSWORD, keycloak_row(KC_24_SHA256_SECRET, KC_24_SHA256_DATA)),
            (PASSWORD, pbkdf2_row(SHA512_30000)),
            (KC_ARGON2_PASSWORD, keycloak_row(KC_ARGON2_SECRET, KC_ARGON2_DATA)),
        ]
    }

    pub(crate) fn unverifiable_rows() -> Vec<Credential> {
        vec![
            credential(&[0x80, 0x81, 0x82], json!({})),
            credential(b"not-a-phc-string", json!({"hash_algorithm": "argon2id"})),
            phc_row(PHC_SHA1),
            credential(
                json!({"value": SHA1_VALUE, "salt": SHA1_SALT}).to_string().as_bytes(),
                json!({"hashIterations": 20_000, "algorithm": "pbkdf2"}),
            ),
            credential(
                json!({"value": VALID_VALUE, "salt": VALID_SALT}).to_string().as_bytes(),
                json!({"hashIterations": MAX_PBKDF2_ITERATIONS + 1, "algorithm": "pbkdf2-sha256"}),
            ),
        ]
    }

    fn assert_verifies(password: &str, cred: &Credential, label: &str) {
        assert_eq!(check_credential(password, cred), PasswordCheck::Match, "{label}");
        assert_eq!(check_credential(WRONG, cred), PasswordCheck::Mismatch, "{label}");
    }

    fn assert_unverifiable(cred: &Credential, label: &str) {
        assert_eq!(check_credential(PASSWORD, cred), PasswordCheck::Unverifiable, "{label}");
    }

    #[test]
    fn keycloak_exported_pbkdf2_sha256_rows_verify() {
        let rows = [
            ("19.0.3, no additionalParameters", KC_19_SHA256_SECRET, KC_19_SHA256_DATA),
            ("24.0.4", KC_24_SHA256_SECRET, KC_24_SHA256_DATA),
        ];
        for (label, secret, data) in rows {
            assert_verifies(KC_SHA256_PASSWORD, &keycloak_row(secret, data), label);
        }
    }

    #[test]
    fn keycloak_exported_argon2id_row_verifies() {
        assert_verifies(
            KC_ARGON2_PASSWORD,
            &keycloak_row(KC_ARGON2_SECRET, KC_ARGON2_DATA),
            "keycloak argon2id",
        );
    }

    #[test]
    fn keycloak_json_argon2id_pair_matches_its_phc_form() {
        assert_verifies(PASSWORD, &argon2_row(argon2_params()), "json");
        assert_verifies(PASSWORD, &phc_row(PHC_ARGON2ID_KEYCLOAK_PARAMS), "phc");
    }

    #[test]
    fn keycloak_json_pbkdf2_uses_each_rows_own_digest_and_iterations() {
        for vector in [SHA256_27500, SHA256_600000, SHA512_30000, SHA512_210000] {
            assert_verifies(PASSWORD, &pbkdf2_row(vector), &format!("{vector:?}"));
        }
    }

    #[test]
    fn phc_pbkdf2_uses_each_rows_own_digest_and_iterations() {
        for phc in [
            PHC_SHA256_27500,
            PHC_SHA256_600000,
            PHC_SHA512_30000,
            PHC_SHA512_210000,
        ] {
            assert_verifies(PASSWORD, &phc_row(phc), phc);
        }
    }

    #[test]
    fn phc_pbkdf2_accepts_explicit_output_length_param() {
        let phc = "$pbkdf2-sha256$i=27500,l=32$x5gm+pKpqaRl4x8gzgYzCg$Ysjv8TgUTxPDbFyQQ9byzkZKSAw6u6iin/OYKULIVDc";
        assert_verifies(PASSWORD, &phc_row(phc), phc);
    }

    #[test]
    fn phc_argon2_rows_keep_verifying() {
        for phc in [
            PHC_ARGON2ID_DEFAULT_PARAMS,
            PHC_ARGON2ID_KEYCLOAK_PARAMS,
            PHC_ARGON2I,
            PHC_ARGON2D,
        ] {
            assert_verifies(PASSWORD, &phc_row(phc), phc);
        }
    }

    #[test]
    fn iteration_bounds_are_inclusive() {
        assert_eq!(MAX_PBKDF2_ITERATIONS, 2_000_000);
        assert_verifies(PASSWORD, &pbkdf2_row(SHA256_ONE_ITERATION), "one iteration json");
        assert_verifies(PASSWORD, &phc_row(PHC_SHA256_ONE_ITERATION), "one iteration phc");
        assert_verifies(PASSWORD, &pbkdf2_row(SHA256_AT_CAP), "at cap");
    }

    #[test]
    fn derived_key_length_comes_from_the_stored_row() {
        assert_verifies(PASSWORD, &pbkdf2_row(SHA256_16_BYTE_KEY), "16-byte sha256");
        assert_verifies(PASSWORD, &pbkdf2_row(SHA512_32_BYTE_KEY), "32-byte sha512");
    }

    #[test]
    fn digest_is_bound_to_the_row() {
        let (_, iterations, salt, value) = SHA256_27500;
        let cred = pbkdf2_row(("pbkdf2-sha512", iterations, salt, value));
        assert_eq!(check_credential(PASSWORD, &cred), PasswordCheck::Mismatch);
    }

    #[test]
    fn iterations_are_bound_to_the_row() {
        let (algorithm, iterations, salt, value) = SHA256_27500;
        let json = pbkdf2_row((algorithm, iterations + 1, salt, value));
        assert_eq!(check_credential(PASSWORD, &json), PasswordCheck::Mismatch);
        let phc = phc_row(&PHC_SHA256_27500.replace("i=27500", "i=27501"));
        assert_eq!(check_credential(PASSWORD, &phc), PasswordCheck::Mismatch);
    }

    #[test]
    fn salt_and_value_are_bound_to_the_row() {
        let (algorithm, iterations, salt, value) = SHA256_27500;
        let other_salt = pbkdf2_row((algorithm, iterations, SHA256_600000.2, value));
        assert_eq!(check_credential(PASSWORD, &other_salt), PasswordCheck::Mismatch);
        let other_value = pbkdf2_row((algorithm, iterations, salt, SHA256_600000.3));
        assert_eq!(check_credential(PASSWORD, &other_value), PasswordCheck::Mismatch);
    }

    #[test]
    fn credential_data_may_be_object_or_json_encoded_string() {
        let secret = json!({"value": VALID_VALUE, "salt": VALID_SALT}).to_string();
        let data = json!({"hashIterations": SHA256_27500.1, "algorithm": SHA256_27500.0});
        for form in [data.clone(), Value::String(data.to_string())] {
            assert_verifies(PASSWORD, &credential(secret.as_bytes(), form), "pbkdf2");
        }
        let params = argon2_params();
        assert_verifies(PASSWORD, &argon2_row(params.clone()), "argon2 object");
        assert_verifies(PASSWORD, &argon2_row(Value::String(params.to_string())), "argon2 string");
    }

    #[test]
    fn unknown_keycloak_fields_are_ignored() {
        let secret = json!({
            "value": VALID_VALUE,
            "salt": VALID_SALT,
            "additionalParameters": {"future": ["x"]},
        })
        .to_string();
        let data = json!({
            "hashIterations": SHA256_27500.1,
            "algorithm": SHA256_27500.0,
            "additionalParameters": {},
            "future": true,
        });
        assert_verifies(PASSWORD, &credential(secret.as_bytes(), data), "extra fields");
    }

    #[test]
    fn phc_rows_ignore_credential_data_metadata() {
        for data in [
            json!({"hash_algorithm": "argon2id"}),
            json!({"hashIterations": 1, "algorithm": "pbkdf2-sha512"}),
            json!(null),
            json!("not json"),
        ] {
            let cred = credential(PHC_SHA256_27500.as_bytes(), data.clone());
            assert_verifies(PASSWORD, &cred, &data.to_string());
        }
    }

    #[test]
    fn credential_type_does_not_affect_verification() {
        let mut history = pbkdf2_row(SHA256_27500);
        history.credential_type = CredentialType::Custom("password-history".to_string());
        assert_verifies(PASSWORD, &history, "history row");
    }

    #[test]
    fn candidate_password_is_compared_exactly() {
        assert_verifies(UNICODE_PASSWORD, &pbkdf2_row(SHA256_UNICODE_PASSWORD), "unicode");
        let cred = pbkdf2_row(SHA256_27500);
        let long = "x".repeat(1024 * 1024);
        for candidate in [
            "keycl0ak!pass",
            "KEYCL0AK!PASS",
            "Keycl0ak!pass ",
            " Keycl0ak!pass",
            "",
            long.as_str(),
        ] {
            assert_eq!(check_credential(candidate, &cred), PasswordCheck::Mismatch);
        }
    }

    #[test]
    fn malformed_secret_data_is_unverifiable() {
        let good_data = json!({"hashIterations": SHA256_27500.1, "algorithm": SHA256_27500.0});
        let secrets: Vec<Vec<u8>> = vec![
            vec![0x80, 0x81, 0x82],
            vec![],
            b"not-a-phc-string".to_vec(),
            b"{".to_vec(),
            b"{}".to_vec(),
            b"[]".to_vec(),
            b"null".to_vec(),
            b"\"text\"".to_vec(),
            json!({"salt": VALID_SALT}).to_string().into_bytes(),
            json!({"value": VALID_VALUE}).to_string().into_bytes(),
            json!({"value": null, "salt": VALID_SALT}).to_string().into_bytes(),
            json!({"value": VALID_VALUE, "salt": null}).to_string().into_bytes(),
            json!({"value": 1, "salt": VALID_SALT}).to_string().into_bytes(),
            json!({"value": VALID_VALUE, "salt": 1}).to_string().into_bytes(),
            json!({"value": "%%%", "salt": VALID_SALT}).to_string().into_bytes(),
            json!({"value": VALID_VALUE, "salt": "%%%"}).to_string().into_bytes(),
            json!({"value": "", "salt": VALID_SALT}).to_string().into_bytes(),
            json!({"value": VALID_VALUE, "salt": ""}).to_string().into_bytes(),
            json!({"value": VALID_VALUE, "salt": "__SALT__"}).to_string().into_bytes(),
            json!({"value": FIFTEEN_BYTES, "salt": VALID_SALT}).to_string().into_bytes(),
        ];
        for secret in secrets {
            let label = String::from_utf8_lossy(&secret).to_string();
            assert_unverifiable(&credential(&secret, good_data.clone()), &label);
        }
    }

    #[test]
    fn malformed_pbkdf2_credential_data_is_unverifiable() {
        let secret = json!({"value": VALID_VALUE, "salt": VALID_SALT}).to_string();
        let algorithm = SHA256_27500.0;
        let cases = [
            json!(null),
            json!([]),
            json!(1),
            json!(""),
            json!("not json"),
            json!("\"nested\""),
            json!({}),
            json!({"hash_algorithm": "argon2id"}),
            json!({"hashIterations": 27_500}),
            json!({"algorithm": algorithm}),
            json!({"hashIterations": 27_500, "algorithm": null}),
            json!({"hashIterations": 27_500, "algorithm": 1}),
            json!({"hashIterations": null, "algorithm": algorithm}),
            json!({"hashIterations": 0, "algorithm": algorithm}),
            json!({"hashIterations": -1, "algorithm": algorithm}),
            json!({"hashIterations": 1.5, "algorithm": algorithm}),
            json!({"hashIterations": "27500", "algorithm": algorithm}),
            json!({"hashIterations": MAX_PBKDF2_ITERATIONS + 1, "algorithm": algorithm}),
            json!({"hashIterations": 1_u64 << 32, "algorithm": algorithm}),
        ];
        for data in cases {
            assert_unverifiable(&credential(secret.as_bytes(), data.clone()), &data.to_string());
        }
    }

    #[test]
    fn unknown_algorithms_are_unverifiable() {
        let secret = json!({"value": VALID_VALUE, "salt": VALID_SALT}).to_string();
        for algorithm in [
            "",
            "PBKDF2-SHA256",
            "pbkdf2-sha1",
            "pbkdf2-sha384",
            "pbkdf2_sha256",
            "bcrypt",
            "scrypt",
            "argon2id",
        ] {
            let data = json!({"hashIterations": 27_500, "algorithm": algorithm});
            assert_unverifiable(&credential(secret.as_bytes(), data), algorithm);
        }
    }

    #[test]
    fn sha1_pbkdf2_never_verifies_even_with_the_right_password() {
        let json_row = credential(
            json!({"value": SHA1_VALUE, "salt": SHA1_SALT}).to_string().as_bytes(),
            json!({"hashIterations": 20_000, "algorithm": "pbkdf2"}),
        );
        assert_unverifiable(&json_row, "json");
        assert_unverifiable(&phc_row(PHC_SHA1), "phc");
    }

    #[test]
    fn malformed_keycloak_argon2_params_are_unverifiable() {
        let edit = |change: &dyn Fn(&mut Value)| {
            let mut data = argon2_params();
            change(&mut data);
            data
        };
        let param = |key: &'static str, value: Value| {
            edit(&move |data: &mut Value| data["additionalParameters"][key] = value.clone())
        };
        let over_cap = (MAX_ARGON2_MEMORY_KIB + 1).to_string();
        let cases = [
            edit(&|data| {
                data.as_object_mut().unwrap().remove("additionalParameters");
            }),
            edit(&|data| data["additionalParameters"] = json!({})),
            edit(&|data| data["additionalParameters"] = json!(null)),
            edit(&|data| {
                data["additionalParameters"].as_object_mut().unwrap().remove("memory");
            }),
            edit(&|data| {
                data["additionalParameters"].as_object_mut().unwrap().remove("parallelism");
            }),
            edit(&|data| {
                data["additionalParameters"].as_object_mut().unwrap().remove("type");
            }),
            edit(&|data| {
                data["additionalParameters"].as_object_mut().unwrap().remove("version");
            }),
            edit(&|data| data["hashIterations"] = json!(0)),
            edit(&|data| data["hashIterations"] = json!(u32::MAX)),
            param("type", json!(["i"])),
            param("type", json!(["d"])),
            param("type", json!([])),
            param("type", json!("id")),
            param("version", json!(["1.0"])),
            param("version", json!([])),
            param("memory", json!(["lots"])),
            param("memory", json!(["0"])),
            param("memory", json!(["-1"])),
            param("memory", json!([])),
            param("memory", json!(7168)),
            param("memory", json!([over_cap])),
            param("parallelism", json!(["0"])),
            param("parallelism", json!(["4294967295"])),
            param("parallelism", json!(["many"])),
        ];
        for data in cases {
            assert_unverifiable(&argon2_row(data.clone()), &data.to_string());
        }
    }

    #[test]
    fn malformed_or_unsupported_phc_strings_are_unverifiable() {
        let salt = "x5gm+pKpqaRl4x8gzgYzCg";
        let hash = "Ysjv8TgUTxPDbFyQQ9byzkZKSAw6u6iin/OYKULIVDc";
        let cases = [
            "$".to_string(),
            "$$$$".to_string(),
            "$pbkdf2-sha256".to_string(),
            format!("$pbkdf2-sha256${salt}${hash}"),
            format!("$pbkdf2-sha256$i=0${salt}${hash}"),
            format!("$pbkdf2-sha256$i=abc${salt}${hash}"),
            format!("$pbkdf2-sha256$i={}${salt}${hash}", MAX_PBKDF2_ITERATIONS + 1),
            format!("$pbkdf2-sha256$i=4294967296${salt}${hash}"),
            format!("$pbkdf2-sha256$i=27500${salt}"),
            format!("$pbkdf2-sha256$i=27500${salt}${FIFTEEN_BYTES}"),
            format!("$pbkdf2-sha1$i=27500${salt}${hash}"),
            format!("$pbkdf2-sha384$i=27500${salt}${hash}"),
            format!("$scrypt$ln=16,r=8,p=1${salt}${hash}"),
            "$2b$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234".to_string(),
            format!("$argon2id$v=19$m=7168,t=5,p=1${salt}"),
        ];
        for phc in cases {
            assert_unverifiable(&phc_row(&phc), &phc);
        }
    }

    #[test]
    fn truncated_rows_never_panic_or_match_below_the_minimum_key_length() {
        let (algorithm, iterations, salt, value) = SHA256_ONE_ITERATION;
        let json_secret = json!({"value": value, "salt": salt}).to_string();
        let data = json!({"hashIterations": iterations, "algorithm": algorithm});
        for end in 0..json_secret.len() {
            let cred = credential(&json_secret.as_bytes()[..end], data.clone());
            assert_ne!(check_credential(PASSWORD, &cred), PasswordCheck::Match, "json {end}");
        }

        // A longer prefix of a PBKDF2 key is itself a valid shorter key, so it
        // only has to stay panic-free. 22 base64 characters encode 16 bytes.
        let min_key_end = PHC_SHA256_ONE_ITERATION.rfind('$').unwrap() + 1 + 22;
        for end in 0..PHC_SHA256_ONE_ITERATION.len() {
            let check = check_credential(PASSWORD, &phc_row(&PHC_SHA256_ONE_ITERATION[..end]));
            if end < min_key_end {
                assert_ne!(check, PasswordCheck::Match, "phc {end}");
            }
        }
    }

    #[test]
    fn check_credentials_without_rows_is_unverifiable() {
        assert_eq!(check_credentials(PASSWORD, &[]), PasswordCheck::Unverifiable);
    }

    #[test]
    fn check_credentials_with_only_bad_rows_is_unverifiable() {
        assert_eq!(check_credentials(PASSWORD, &unverifiable_rows()), PasswordCheck::Unverifiable);
    }

    #[test]
    fn check_credentials_mismatch_wins_over_unverifiable_in_any_order() {
        let bad = credential(b"not-a-phc-string", json!({}));
        let good = pbkdf2_row(SHA256_27500);
        for rows in [[bad.clone(), good.clone()], [good, bad]] {
            assert_eq!(check_credentials(WRONG, &rows), PasswordCheck::Mismatch);
        }
    }

    #[test]
    fn check_credentials_match_wins_in_any_order() {
        let bad = credential(b"not-a-phc-string", json!({}));
        let other = phc_row(PHC_ARGON2ID_DEFAULT_PARAMS);
        let good = keycloak_row(KC_24_SHA256_SECRET, KC_24_SHA256_DATA);
        let orders = [
            [bad.clone(), other.clone(), good.clone()],
            [good.clone(), bad.clone(), other.clone()],
            [other, good, bad],
        ];
        for rows in orders {
            assert_eq!(check_credentials(KC_SHA256_PASSWORD, &rows), PasswordCheck::Match);
        }
    }

    #[test]
    fn check_credentials_dispatches_per_row_across_mixed_formats() {
        let rows: Vec<Credential> = keycloak_rows().into_iter().map(|(_, cred)| cred).collect();
        for (password, _) in keycloak_rows() {
            assert_eq!(check_credentials(password, &rows), PasswordCheck::Match, "{password}");
        }
        assert_eq!(check_credentials(WRONG, &rows), PasswordCheck::Mismatch);
    }
}
