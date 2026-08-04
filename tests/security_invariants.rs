//! Tests for the three security invariants identified in
//! docs/clasp/STATUS.md (J1-J3), each tied to a real disclosed
//! vulnerability class, plus round-trip correctness for both key types.

use clasp::{AsymmetricAlgorithm, AsymmetricKey, ClaspError, SymmetricAlgorithm, SymmetricKey};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
}

fn future_exp() -> usize {
    // Fixed far-future timestamp -- avoids relying on a live clock in tests.
    4_102_444_800 // 2100-01-01T00:00:00Z
}

const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh3P9zwNro7SElB6q
jr7LWhT8YDvQpzBVJDDMreMBKoGhRANCAAQOxGAkIYc1+dPwtMKUb5F3ABGK3nF2
0OrQZaf6iLOcXdj+JW85jyrKeneE0CUIfY5VTsd1Z068ZBjrylWo08/K
-----END PRIVATE KEY-----";

const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDsRgJCGHNfnT8LTClG+RdwARit5x
dtDq0GWn+oiznF3Y/iVvOY8qynp3hNAlCH2OVU7HdWdOvGQY68pVqNPPyg==
-----END PUBLIC KEY-----";

/// Baseline: HMAC round-trip must actually work end to end, not just
/// reject bad input.
#[test]
fn hmac_round_trip_succeeds() {
    let secret = b"correct-horse-battery-staple";
    let claims = Claims { sub: "alice".into(), exp: future_exp() };
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap();

    let key = SymmetricKey::new(secret, SymmetricAlgorithm::HS256);
    let decoded: Claims = key.verify(&token).expect("valid token must verify");
    assert_eq!(decoded, claims);
}

/// Baseline: EC (ES256) round-trip must also actually work end to end.
#[test]
fn ec_round_trip_succeeds() {
    let claims = Claims { sub: "bob".into(), exp: future_exp() };
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &EncodingKey::from_ec_pem(EC_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap();

    let key =
        AsymmetricKey::from_ec_pem(EC_PUBLIC_PEM.as_bytes(), AsymmetricAlgorithm::ES256).unwrap();
    let decoded: Claims = key.verify(&token).expect("valid token must verify");
    assert_eq!(decoded, claims);
}

/// J1: the algorithm allowlist is always exactly one algorithm -- a token
/// signed with a *different* algorithm than the key expects must be
/// rejected, even if the signature itself is otherwise validly formed.
#[test]
fn j1_algorithm_not_in_allowlist_rejected() {
    let secret = b"correct-horse-battery-staple";
    let claims = Claims { sub: "alice".into(), exp: future_exp() };
    // Sign with HS384...
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::HS384),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap();

    // ...but the key only accepts HS256.
    let key = SymmetricKey::new(secret, SymmetricAlgorithm::HS256);
    let result: Result<Claims, _> = key.verify(&token);
    assert!(result.is_err(), "token signed with a different algorithm must be rejected");
}

/// J2 (CVE-2026-48526-style): an RSA algorithm must be rejected at
/// *construction* time when loading key material declared as a different
/// family (EC here) -- never silently accepted and discovered later at
/// verification time. No real key material is needed for this: the family
/// check runs before the PEM is even parsed.
#[test]
fn j2_algorithm_key_family_mismatch_rejected_at_construction() {
    let not_actually_parsed = b"this is not real PEM data";
    let result = AsymmetricKey::from_ec_pem(not_actually_parsed, AsymmetricAlgorithm::RS256);
    match result {
        Ok(_) => panic!("expected AlgorithmKeyMismatch, construction succeeded instead"),
        Err(ClaspError::AlgorithmKeyMismatch { algorithm, expected_family }) => {
            assert_eq!(algorithm, "RS256");
            assert_eq!(expected_family, "EC");
        }
        Err(other) => panic!("expected AlgorithmKeyMismatch, got a different error: {other}"),
    }
}

/// J3: `alg: none` (and case variants) must never verify successfully.
/// Hand-crafts the classic "none" bypass token directly rather than going
/// through `encode()`, since a real encoder wouldn't produce this in the
/// first place -- the attack is a hand-modified token, not a normal one.
#[test]
fn j3_alg_none_rejected() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    for alg_variant in ["none", "None", "NoNe", "NONE"] {
        let header = format!(r#"{{"alg":"{alg_variant}","typ":"JWT"}}"#);
        let payload = format!(r#"{{"sub":"attacker","exp":{}}}"#, future_exp());
        let token = format!("{}.{}.", b64.encode(header), b64.encode(payload));

        let key = SymmetricKey::new(b"whatever-secret", SymmetricAlgorithm::HS256);
        let result: Result<Claims, _> = key.verify(&token);
        assert!(result.is_err(), "alg={alg_variant} must be rejected, not silently accepted");
    }
}
