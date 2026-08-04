# Clasp

Fast, type-safe JWT/JWKS verification for Python — written in Rust.

## Why

Most JWT libraries treat algorithm choice as a runtime string comparison,
which is exactly the class of bug behind real, disclosed CVEs — algorithm
confusion (an RSA public key misused as an HMAC secret), and `alg=none`
bypasses missed by case-sensitive checks. Clasp makes that class of bug
impossible by construction: symmetric and asymmetric keys are distinct
Rust types, so mixing them is a compile error, not a runtime footgun.

On performance: properly-configured PyJWT is already fast (its crypto math
is C-accelerated) — Clasp doesn't chase an inflated speedup claim there.
The real, common gap is `python-jose`'s default pure-Python RSA backend, a
misconfiguration many projects run on unknowingly, where a native
implementation is a large, legitimate win.

## Status

Early development. Scaffold only — no verification logic yet.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
