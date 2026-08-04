use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::de::DeserializeOwned;

use crate::algorithm::{AsymmetricAlgorithm, KeyFamily, SymmetricAlgorithm};
use crate::error::ClaspError;

/// An HMAC verification key. Cannot be constructed from or confused with
/// asymmetric key material -- there is no shared constructor, no `From`
/// conversion, and no algorithm parameter that could select an asymmetric
/// algorithm. This is J2 (CVE-2026-48526-style RSA-key-used-as-HMAC-secret
/// confusion) closed by construction, not by a runtime check.
pub struct SymmetricKey {
    decoding_key: DecodingKey,
    algorithm: SymmetricAlgorithm,
}

impl SymmetricKey {
    pub fn new(secret: &[u8], algorithm: SymmetricAlgorithm) -> Self {
        Self { decoding_key: DecodingKey::from_secret(secret), algorithm }
    }

    /// Verifies `token` and returns its claims deserialized as `T`.
    ///
    /// J1: the algorithm allowlist is always exactly the one algorithm this
    /// key was constructed with -- there is no "accept any algorithm" mode.
    /// J3: `alg: none` (in any case) is not a valid `jsonwebtoken::Algorithm`
    /// variant, so such a token fails to parse as this algorithm and is
    /// rejected before signature verification is even attempted.
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, ClaspError> {
        verify_with(token, &self.decoding_key, self.algorithm.to_jwt())
    }
}

/// A public-key verification key (RSA/EC/Ed25519). Same J2 property as
/// `SymmetricKey` in the opposite direction: there is no constructor that
/// accepts a raw HMAC secret, so an HMAC secret can never end up here.
/// Additionally, each constructor validates the chosen algorithm belongs to
/// the key family it's loading (an EC key with `RS256` fails at
/// construction, not silently at verification time).
pub struct AsymmetricKey {
    decoding_key: DecodingKey,
    algorithm: AsymmetricAlgorithm,
}

impl AsymmetricKey {
    pub fn from_rsa_pem(pem: &[u8], algorithm: AsymmetricAlgorithm) -> Result<Self, ClaspError> {
        Self::from_pem(pem, algorithm, KeyFamily::Rsa, DecodingKey::from_rsa_pem)
    }

    pub fn from_ec_pem(pem: &[u8], algorithm: AsymmetricAlgorithm) -> Result<Self, ClaspError> {
        Self::from_pem(pem, algorithm, KeyFamily::Ec, DecodingKey::from_ec_pem)
    }

    pub fn from_ed_pem(pem: &[u8], algorithm: AsymmetricAlgorithm) -> Result<Self, ClaspError> {
        Self::from_pem(pem, algorithm, KeyFamily::Ed, DecodingKey::from_ed_pem)
    }

    fn from_pem(
        pem: &[u8],
        algorithm: AsymmetricAlgorithm,
        expected_family: KeyFamily,
        parse: fn(&[u8]) -> jsonwebtoken::errors::Result<DecodingKey>,
    ) -> Result<Self, ClaspError> {
        if algorithm.family() != expected_family {
            return Err(ClaspError::AlgorithmKeyMismatch {
                algorithm: algorithm.name(),
                expected_family: expected_family.name(),
            });
        }
        let decoding_key = parse(pem).map_err(ClaspError::InvalidKey)?;
        Ok(Self { decoding_key, algorithm })
    }

    /// Same J1/J3 properties as `SymmetricKey::verify` -- see there.
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, ClaspError> {
        verify_with(token, &self.decoding_key, self.algorithm.to_jwt())
    }
}

fn verify_with<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
) -> Result<T, ClaspError> {
    let validation = Validation::new(algorithm);
    let data = decode::<T>(token, key, &validation).map_err(ClaspError::Verification)?;
    Ok(data.claims)
}
