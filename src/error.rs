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
        }
    }
}

impl std::error::Error for ClaspError {}
