use std::fmt;

#[derive(Debug)]
pub enum ClaspError {
    /// Token verification failed (bad signature, expired, malformed, unknown
    /// `alg`, etc.) -- covers J3 by construction: jsonwebtoken's `Algorithm`
    /// enum has no "none" variant, so a token claiming `alg: none` (in any
    /// case) fails to even parse as a valid algorithm, and errors here
    /// rather than silently verifying.
    Verification(jsonwebtoken::errors::Error),
    /// The requested algorithm doesn't match the key material's family
    /// (e.g. asking for `ES256` while loading an RSA PEM). Caught at key
    /// construction time, not at verification time.
    AlgorithmKeyMismatch { algorithm: &'static str, expected_family: &'static str },
    /// The key material itself couldn't be parsed (bad PEM, wrong format).
    InvalidKey(jsonwebtoken::errors::Error),
    /// Fetching or parsing the JWKS document itself failed (network error,
    /// non-2xx response, invalid JSON/JWKS shape).
    JwksFetch(String),
    /// The token's header has no `kid` claim, so it can't be matched
    /// against a JWKS at all.
    MissingKeyId,
    /// The token's `kid` doesn't match any key in the JWKS, even after one
    /// forced refresh (handles the common key-rotation case: a cached JWKS
    /// predates a newly-rotated-in key). If it's still not found after a
    /// refresh, the kid is genuinely unknown or the token is bogus.
    UnknownKeyId(String),
}

impl fmt::Display for ClaspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaspError::Verification(e) => write!(f, "verification failed: {e}"),
            ClaspError::AlgorithmKeyMismatch { algorithm, expected_family } => write!(
                f,
                "algorithm {algorithm} is not valid for a {expected_family} key"
            ),
            ClaspError::InvalidKey(e) => write!(f, "invalid key material: {e}"),
            ClaspError::JwksFetch(msg) => write!(f, "failed to fetch/parse JWKS: {msg}"),
            ClaspError::MissingKeyId => write!(f, "token has no \"kid\" header claim"),
            ClaspError::UnknownKeyId(kid) => {
                write!(f, "no key with kid \"{kid}\" found in JWKS (even after refresh)")
            }
        }
    }
}

impl std::error::Error for ClaspError {}
