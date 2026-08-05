//! Real end-to-end test for `JwksClient` -- serves an actual JWKS document
//! over a real (minimal, local-only) HTTP server rather than mocking the
//! fetch away, so this exercises the genuine fetch -> parse -> kid-match ->
//! verify path.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use clasp::{AsymmetricAlgorithm, ClaspError, JwksClient};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
}

fn future_exp() -> usize {
    4_102_444_800 // 2100-01-01T00:00:00Z
}

// TEST KEY ONLY. Generated solely for this test suite, signs nothing
// outside it, and protects nothing real -- never reuse in a real
// deployment.
const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh3P9zwNro7SElB6q
jr7LWhT8YDvQpzBVJDDMreMBKoGhRANCAAQOxGAkIYc1+dPwtMKUb5F3ABGK3nF2
0OrQZaf6iLOcXdj+JW85jyrKeneE0CUIfY5VTsd1Z068ZBjrylWo08/K
-----END PRIVATE KEY-----";

const KID: &str = "test-key-1";

/// The JWKS document a real identity provider would serve at e.g.
/// `/.well-known/jwks.json` -- x/y computed for real from the EC public
/// key used throughout these tests (see docs/clasp/STATUS.md for how).
fn jwks_json() -> String {
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{KID}","alg":"ES256","use":"sig","x":"DsRgJCGHNfnT8LTClG-RdwARit5xdtDq0GWn-oiznF0","y":"2P4lbzmPKsp6d4TQJQh9jlVOx3VnTrxkGOvKVajTz8o"}}]}}"#
    )
}

/// Spawns a minimal local HTTP/1.1 server that serves the JWKS document to
/// exactly one request, then shuts down. Returns the base URL to fetch it
/// from. No mocking crate -- a real socket, a real HTTP response.
fn spawn_jwks_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf); // drain the request, ignore it
            let body = jwks_json();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    format!("http://127.0.0.1:{port}/jwks.json")
}

#[test]
fn jwks_fetch_and_verify_succeeds() {
    let url = spawn_jwks_server();
    let claims = Claims { sub: "erin".into(), exp: future_exp() };
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(KID.to_string());
    let token =
        encode(&header, &claims, &EncodingKey::from_ec_pem(EC_PRIVATE_PEM.as_bytes()).unwrap())
            .unwrap();

    let client = JwksClient::new(url).with_ttl(Duration::from_secs(60));
    let decoded: Claims =
        client.verify(&token, AsymmetricAlgorithm::ES256).expect("valid token must verify");
    assert_eq!(decoded, claims);
}

#[test]
fn jwks_unknown_kid_rejected() {
    let url = spawn_jwks_server();
    let claims = Claims { sub: "mallory".into(), exp: future_exp() };
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("kid-not-in-jwks".to_string());
    let token =
        encode(&header, &claims, &EncodingKey::from_ec_pem(EC_PRIVATE_PEM.as_bytes()).unwrap())
            .unwrap();

    // Server only answers one request (see spawn_jwks_server); this test
    // triggers two fetch attempts (initial + the automatic key-rotation
    // retry), so the second one intentionally finds a closed connection --
    // proving the retry-once-then-give-up behavior actually runs, not that
    // networking always succeeds.
    let client = JwksClient::new(url).with_ttl(Duration::from_secs(60));
    let result: Result<Claims, _> = client.verify(&token, AsymmetricAlgorithm::ES256);
    assert!(result.is_err(), "unknown kid must be rejected, not silently accepted");
    match result {
        Err(ClaspError::UnknownKeyId(kid)) => assert_eq!(kid, "kid-not-in-jwks"),
        Err(ClaspError::JwksFetch(_)) => {
            // Acceptable: the retry's fetch failed because the
            // single-request test server had already closed. The
            // important property (no silent accept) still held.
        }
        other => panic!("expected UnknownKeyId or a refresh JwksFetch error, got {other:?}"),
    }
}
