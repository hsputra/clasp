//! Isolates pure-Rust JwksClient cache-hit cost from any Python/FFI
//! overhead, to diagnose where the ~27us measured from Python is actually
//! going.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use clasp::{AsymmetricAlgorithm, JwksClient};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh3P9zwNro7SElB6q
jr7LWhT8YDvQpzBVJDDMreMBKoGhRANCAAQOxGAkIYc1+dPwtMKUb5F3ABGK3nF2
0OrQZaf6iLOcXdj+JW85jyrKeneE0CUIfY5VTsd1Z068ZBjrylWo08/K
-----END PRIVATE KEY-----";

const KID: &str = "bench-key";

fn jwks_json() -> String {
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{KID}","alg":"ES256","use":"sig","x":"DsRgJCGHNfnT8LTClG-RdwARit5xdtDq0GWn-oiznF0","y":"2P4lbzmPKsp6d4TQJQh9jlVOx3VnTrxkGOvKVajTz8o"}}]}}"#
    )
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = jwks_json();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(KID.to_string());
    let claims = Claims { sub: "bench".into(), exp: 4_102_444_800 };
    let token =
        encode(&header, &claims, &EncodingKey::from_ec_pem(EC_PRIVATE_PEM.as_bytes()).unwrap())
            .unwrap();

    let client = JwksClient::new(format!("http://127.0.0.1:{port}/jwks.json"))
        .with_ttl(Duration::from_secs(300));
    let _: Value = client.verify(&token, AsymmetricAlgorithm::ES256).unwrap(); // warm cache

    const N: u32 = 50_000;
    let t0 = Instant::now();
    for _ in 0..N {
        let _: Value = client.verify_cached(&token, AsymmetricAlgorithm::ES256).unwrap().unwrap();
    }
    let elapsed = t0.elapsed();
    println!("{N} pure-Rust cache-hit verifications (via JwksClient) in {elapsed:?}");
    println!("per-call: {:.2}us", elapsed.as_secs_f64() * 1_000_000.0 / N as f64);

    // Breakdown: isolate DecodingKey::from_jwk() reconstruction cost from
    // the cost of decode() itself (given an already-built key), to find
    // out where the ~27us is actually going.
    let jwk_set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(&jwks_json()).unwrap();
    let jwk = jwk_set.find(KID).unwrap();

    let t0 = Instant::now();
    for _ in 0..N {
        let _ = jsonwebtoken::DecodingKey::from_jwk(jwk).unwrap();
    }
    let from_jwk_elapsed = t0.elapsed();
    println!(
        "\nDecodingKey::from_jwk() alone: {:.2}us/call",
        from_jwk_elapsed.as_secs_f64() * 1_000_000.0 / N as f64
    );

    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).unwrap();
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    let t0 = Instant::now();
    for _ in 0..N {
        let _: jsonwebtoken::TokenData<Value> =
            jsonwebtoken::decode(&token, &decoding_key, &validation).unwrap();
    }
    let decode_elapsed = t0.elapsed();
    println!(
        "decode() alone (key pre-built):  {:.2}us/call",
        decode_elapsed.as_secs_f64() * 1_000_000.0 / N as f64
    );
}
