# Clasp

Fast, type-safe JWT/JWKS verification for Python — written in Rust.

## Why

Most JWT libraries treat algorithm choice as a runtime string comparison,
which is exactly the class of bug behind real, disclosed CVEs — algorithm
confusion (an RSA public key misused as an HMAC secret), and `alg=none`
bypasses missed by case-sensitive checks. Clasp makes that class of bug
impossible by construction: symmetric and asymmetric keys are distinct
Rust types, so mixing them is a compile error, not a runtime footgun.

## Performance

All numbers below are real, measured, single-threaded benchmarks against
the same signed token, not vendor-cited figures — methodology for each is
in [`docs`](https://github.com/hsputra/clasp) if you want to reproduce
them.

| Comparison | Result |
|---|---|
| vs. properly-configured PyJWT (`cryptography` backend), HS256 `decode()` | **5.53x faster** |
| vs. `python-jose`'s default pure-Python backend (a common unintentional misconfiguration — see below), RS256 | **16.0x faster** |
| vs. `python-jose`'s default pure-Python backend, ES256 | **42.6x faster** |
| JWKS cache-hit, vs. PyJWT with the key cached in-process (zero I/O, apples-to-apples) | **1.45x faster** |
| JWKS cache-hit, vs. PyJWT re-fetching the key from Redis on every call | **5.22x faster** |

Properly-configured PyJWT is already fast — its crypto math is
C-accelerated — so Clasp doesn't chase an inflated speedup claim there;
5.53x is the honest, real gap once Python-side JOSE parsing and cache
overhead are removed from around an already-fast crypto call.
`python-jose`, by contrast, **defaults to a pure-Python RSA/ECDSA
backend** unless explicitly reconfigured with the `cryptography` extra —
a misconfiguration many projects run on unknowingly, where a native
implementation is a large, legitimate win.

## Status

Implemented and tested: HMAC (HS256/384/512), RSA (RS256/384/512,
PS256/384/512), EC (ES256/384), and Ed25519 verification, plus JWKS
fetch/cache with key rotation. Pre-1.0 / alpha — API may still change.
Not yet implemented: OAuth2 token introspection (RFC 7662; a different
mechanism from JWT self-verification, deliberately out of scope for now).

## License

Dual-licensed under MIT or Apache-2.0, at your option.
