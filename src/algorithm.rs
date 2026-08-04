/// HMAC-family algorithms -- usable only with `SymmetricKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    HS256,
    HS384,
    HS512,
}

impl SymmetricAlgorithm {
    pub(crate) fn to_jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            SymmetricAlgorithm::HS256 => jsonwebtoken::Algorithm::HS256,
            SymmetricAlgorithm::HS384 => jsonwebtoken::Algorithm::HS384,
            SymmetricAlgorithm::HS512 => jsonwebtoken::Algorithm::HS512,
        }
    }

    /// Parses a name like `"HS256"`. Used by the Python bindings, where
    /// algorithms arrive as strings -- deliberately narrow (exact,
    /// case-sensitive match against a fixed set, no fallback), the same
    /// "no permissive string handling" principle that closes J3 at the
    /// core Rust layer.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "HS256" => Some(Self::HS256),
            "HS384" => Some(Self::HS384),
            "HS512" => Some(Self::HS512),
            _ => None,
        }
    }
}

/// Public-key-family algorithms -- usable only with `AsymmetricKey`. Kept as
/// a single enum for a simple API surface, but each `AsymmetricKey`
/// constructor (`from_rsa_pem`, `from_ec_pem`, `from_ed_pem`) validates the
/// chosen algorithm belongs to the right key family (J2's spirit extended:
/// not just "symmetric vs asymmetric" is a type error, but "RSA algorithm
/// with an EC key" is a construction-time error too, not a silent mismatch
/// discovered later at verification time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    EdDSA,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFamily {
    Rsa,
    Ec,
    Ed,
}

impl AsymmetricAlgorithm {
    pub(crate) fn to_jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            AsymmetricAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            AsymmetricAlgorithm::RS384 => jsonwebtoken::Algorithm::RS384,
            AsymmetricAlgorithm::RS512 => jsonwebtoken::Algorithm::RS512,
            AsymmetricAlgorithm::PS256 => jsonwebtoken::Algorithm::PS256,
            AsymmetricAlgorithm::PS384 => jsonwebtoken::Algorithm::PS384,
            AsymmetricAlgorithm::PS512 => jsonwebtoken::Algorithm::PS512,
            AsymmetricAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            AsymmetricAlgorithm::ES384 => jsonwebtoken::Algorithm::ES384,
            AsymmetricAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }

    /// See `SymmetricAlgorithm::parse` for why this is a strict, exact
    /// match with no fallback.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::RS256),
            "RS384" => Some(Self::RS384),
            "RS512" => Some(Self::RS512),
            "PS256" => Some(Self::PS256),
            "PS384" => Some(Self::PS384),
            "PS512" => Some(Self::PS512),
            "ES256" => Some(Self::ES256),
            "ES384" => Some(Self::ES384),
            "EdDSA" => Some(Self::EdDSA),
            _ => None,
        }
    }

    pub(crate) fn family(self) -> KeyFamily {
        match self {
            AsymmetricAlgorithm::RS256
            | AsymmetricAlgorithm::RS384
            | AsymmetricAlgorithm::RS512
            | AsymmetricAlgorithm::PS256
            | AsymmetricAlgorithm::PS384
            | AsymmetricAlgorithm::PS512 => KeyFamily::Rsa,
            AsymmetricAlgorithm::ES256 | AsymmetricAlgorithm::ES384 => KeyFamily::Ec,
            AsymmetricAlgorithm::EdDSA => KeyFamily::Ed,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            AsymmetricAlgorithm::RS256 => "RS256",
            AsymmetricAlgorithm::RS384 => "RS384",
            AsymmetricAlgorithm::RS512 => "RS512",
            AsymmetricAlgorithm::PS256 => "PS256",
            AsymmetricAlgorithm::PS384 => "PS384",
            AsymmetricAlgorithm::PS512 => "PS512",
            AsymmetricAlgorithm::ES256 => "ES256",
            AsymmetricAlgorithm::ES384 => "ES384",
            AsymmetricAlgorithm::EdDSA => "EdDSA",
        }
    }
}

impl KeyFamily {
    pub(crate) fn name(self) -> &'static str {
        match self {
            KeyFamily::Rsa => "RSA",
            KeyFamily::Ec => "EC",
            KeyFamily::Ed => "Ed25519",
        }
    }
}
