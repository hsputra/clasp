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

// TEST KEYS ONLY. Generated solely for this test suite, sign nothing
// outside it, and protect nothing real -- never reuse any key below in
// a real deployment.
const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh3P9zwNro7SElB6q
jr7LWhT8YDvQpzBVJDDMreMBKoGhRANCAAQOxGAkIYc1+dPwtMKUb5F3ABGK3nF2
0OrQZaf6iLOcXdj+JW85jyrKeneE0CUIfY5VTsd1Z068ZBjrylWo08/K
-----END PRIVATE KEY-----";

const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDsRgJCGHNfnT8LTClG+RdwARit5x
dtDq0GWn+oiznF3Y/iVvOY8qynp3hNAlCH2OVU7HdWdOvGQY68pVqNPPyg==
-----END PUBLIC KEY-----";

const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCcKwu+riUEE2Lr
pk3YDWMFBL4hITGv+gzZ9hS4gni8casan3dFRNhdE6+KzBcEYM1yR4llGuvr8+zc
Kcu70GloY9Pls+AEbYsyxQjWiV3IxkLf6oOIooPsd0dbJPFwzFzKOmA5qYvCeLzp
xIEUv0SnIjVzNxbPB0RLMgFpvDsyoTXQJgqqs0A2EvrmIpXkLqEZU+stQJVy9Ufn
byfaH/FiZtuTy92OinYptwd0kDa7xxhvE5RAg8FnV6EwI13QTPQFTss3k1+W2oWS
dNf8YksGovoz3Vl/nmpE/omKPZdhcTko9+nA/7wkrXUE7QwMQPT7WZ8hwJnw9yfl
l1wUwesfAgMBAAECggEAQwE5JdQkL659t+v/5F5CCQoy5ZYPcpjP4MjztQLN+NSw
fFjFXOQgDTeADwZoLcm2/HxzF/1IElHzY7dPIcNXJqIGbb0StfOmUN83Xo1LvvRK
BzbgvsQz5EZ9SD7+lM4qVd5cIQF85LDXJVnZpGQ4eZl0431UfPl6NOU8s/g+Ugcr
M/oE5Z7z82Ktx1NZ06qy0A9IhHqaoK1bR23Ih5LqqYr6K6eNpsFNeAa+cYDjQYLP
1nt7XoNsfTJOgHoXpsOqV+C4B+gKo0UB3tNg2Vk1ebmbGT5ZlZof9v19K7XP6zb3
HncHK8l+Ffc/cP0GirsupPl0UqzsbsxubMuLOsoxWQKBgQDXsVwx4TZ+77YKeS6P
7z/riVDbGFJatgxxNi77o6a1tkoJrPHlThuEB5+rzKdHj7qIIeIuQ+FwhlKcDjqX
XqpZqwCCJV06M37/lQ+nYyZmOkvNYtnZ0tbakDxQYgwVwD9ps3Xd9LpEsQA/VrV+
aiSzCJCv5LTJJ9JeQNNzidIWNQKBgQC5Wg33IBsP5TTvGKpqKohyZ0ByawJk6jru
aSLSPf+naCToM4LSZyK28aoMlX+ORdcuyxLF+NuSbrNScBl7NVgxkWdU8kYAI+Cd
q9jVejvXOXiuFClySs/w7ax9e2DXoJqWUT6pDkw9w4ILCyg8N4fK5qFD1Ur4XTJl
d+seqfgWgwKBgHHKuTf7d/Op5WFLI1x+PTu2+vhLsY73wkKr8keBw/7Tx+Wo3wk5
ltyl5QAO/SWM1zzgm2ILH9FsnAKGozSelcKuq5r9uVxuNI8EBfkqHuUJ1lnpz8LS
L9WpCJjj0TpcbVgHfKR3axm4Q8gmp6Okve3SE/sn7pS9NIfTLXsj97kNAoGACh0X
1fwyfdOL59/4rIJVn6hyo8ui/c6qGIg0FjS71m6gVOs6oDBwfHsDRFyD8UduTmdW
RuclVAAmWME1IrvubAX7FW+C0k8i2neeBUf+K+g+5YDEIjBi2Eqfttkcl6dzx+/2
81KMZnJcji21rFN7XV7oPcNNq++p6E96zNmJZ/ECgYAxGmFG6lsuLc2JsmHRZS6k
SsdxfEeKpMKGhNozE4bratNOMiq5oA/kPsX15MMf1vtMRgYnWYG0Y2OAr7aBbsiC
7Rbeus2ax5q2m33PQSyp7yVjOUPste9SmSXxeizzDVTVEDBUfwasgsk88SdH7RPd
DManTY7vjcvzMOZKAvWcug==
-----END PRIVATE KEY-----";

const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCsLvq4lBBNi66ZN2A1j
BQS+ISExr/oM2fYUuIJ4vHGrGp93RUTYXROviswXBGDNckeJZRrr6/Ps3CnLu9Bp
aGPT5bPgBG2LMsUI1oldyMZC3+qDiKKD7HdHWyTxcMxcyjpgOamLwni86cSBFL9E
pyI1czcWzwdESzIBabw7MqE10CYKqrNANhL65iKV5C6hGVPrLUCVcvVH528n2h/x
Ymbbk8vdjop2KbcHdJA2u8cYbxOUQIPBZ1ehMCNd0Ez0BU7LN5NfltqFknTX/GJL
BqL6M91Zf55qRP6Jij2XYXE5KPfpwP+8JK11BO0MDED0+1mfIcCZ8Pcn5ZdcFMHr
HwIDAQAB
-----END PUBLIC KEY-----";

const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKn5UftjznXsXYsRUxwdBl7Axy5qoyFgzcSNzR0FCAEf
-----END PRIVATE KEY-----";

const ED_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPxFpfAvzoKhzcH8o5Cj1ULbzqW5EepDlQkXdLeuQcV4=
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

/// Baseline: Ed25519 (EdDSA) round-trip must also actually work end to end
/// -- completes round-trip coverage for all three AsymmetricKey families
/// (RSA/EC/Ed), not just construction-time validation.
#[test]
fn ed25519_round_trip_succeeds() {
    let claims = Claims { sub: "dave".into(), exp: future_exp() };
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_pem(ED_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap();

    let key =
        AsymmetricKey::from_ed_pem(ED_PUBLIC_PEM.as_bytes(), AsymmetricAlgorithm::EdDSA).unwrap();
    let decoded: Claims = key.verify(&token).expect("valid token must verify");
    assert_eq!(decoded, claims);
}

/// Baseline: RSA (RS256) round-trip must also actually work end to end.
#[test]
fn rsa_round_trip_succeeds() {
    let claims = Claims { sub: "carol".into(), exp: future_exp() };
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap();

    let key = AsymmetricKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes(), AsymmetricAlgorithm::RS256)
        .unwrap();
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
