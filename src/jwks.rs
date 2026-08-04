use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::de::DeserializeOwned;

use crate::algorithm::AsymmetricAlgorithm;
use crate::error::ClaspError;

struct CachedJwks {
    jwk_set: JwkSet,
    fetched_at: Instant,
}

/// Fetches and caches a JWKS document (the standard way OIDC/Auth0/
/// Cognito-style identity providers publish rotating public keys), and
/// verifies tokens against it by matching the token's `kid` header claim
/// to the right key.
///
/// Same J1 property as `SymmetricKey`/`AsymmetricKey`: the caller must
/// still specify the expected algorithm explicitly. A JWKS response
/// controls *which key*, never *which algorithm is acceptable* -- an
/// attacker who could influence the JWKS response (or forge a `kid` that
/// happens to match a key of a different, weaker algorithm) still can't
/// get a different algorithm accepted than the one the caller asked for.
pub struct JwksClient {
    url: String,
    ttl: Duration,
    cache: RwLock<Option<CachedJwks>>,
}

impl JwksClient {
    /// Default cache TTL: 5 minutes. Long enough to avoid re-fetching on
    /// every verification (the whole point of caching), short enough that
    /// a compromised/revoked key stops being trusted within a bounded
    /// window even without a key-rotation event triggering a refresh.
    const DEFAULT_TTL: Duration = Duration::from_secs(300);

    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), ttl: Self::DEFAULT_TTL, cache: RwLock::new(None) }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Verifies `token`, returning its claims deserialized as `T`.
    ///
    /// Flow: use the cached JWKS if it's fresh; if the token's `kid` isn't
    /// found there, force one refresh and retry once before giving up --
    /// this is the common, legitimate key-rotation case (the identity
    /// provider rotated in a new key since our last fetch), not just a
    /// bogus-token case.
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        algorithm: AsymmetricAlgorithm,
    ) -> Result<T, ClaspError> {
        if let Some(claims) = self.verify_cached(token, algorithm)? {
            return Ok(claims);
        }

        // Cache was stale, or the kid wasn't found in it (possibly a
        // legitimate key rotation) -- refresh once and retry before
        // concluding the token is bad.
        let header = decode_header(token).map_err(ClaspError::Verification)?;
        let kid = header.kid.ok_or(ClaspError::MissingKeyId)?;
        self.refresh()?;
        self.try_verify(&kid, token, algorithm)?.ok_or(ClaspError::UnknownKeyId(kid))
    }

    /// Verifies `token` using *only* the current cache -- never performs
    /// network I/O, and returns `Ok(None)` (not an error) if the cache is
    /// stale or doesn't contain the token's `kid`, signaling "try the full
    /// `verify()` instead." Exists so callers with their own I/O/threading
    /// model (e.g. the Python bindings, which only need to release the GIL
    /// when a real network fetch might happen) can take the fast,
    /// no-syscall path on a cache hit without paying for that unconditionally.
    pub fn verify_cached<T: DeserializeOwned>(
        &self,
        token: &str,
        algorithm: AsymmetricAlgorithm,
    ) -> Result<Option<T>, ClaspError> {
        if self.cache_is_stale() {
            return Ok(None);
        }
        let header = decode_header(token).map_err(ClaspError::Verification)?;
        let Some(kid) = header.kid else {
            return Err(ClaspError::MissingKeyId);
        };
        self.try_verify(&kid, token, algorithm)
    }

    fn cache_is_stale(&self) -> bool {
        match self.cache.read().expect("JWKS cache lock poisoned").as_ref() {
            None => true,
            Some(cached) => cached.fetched_at.elapsed() > self.ttl,
        }
    }

    fn refresh(&self) -> Result<(), ClaspError> {
        let jwk_set = fetch_jwks(&self.url)?;
        let mut cache = self.cache.write().expect("JWKS cache lock poisoned");
        *cache = Some(CachedJwks { jwk_set, fetched_at: Instant::now() });
        Ok(())
    }

    fn try_verify<T: DeserializeOwned>(
        &self,
        kid: &str,
        token: &str,
        algorithm: AsymmetricAlgorithm,
    ) -> Result<Option<T>, ClaspError> {
        let cache = self.cache.read().expect("JWKS cache lock poisoned");
        let jwk_set = &cache.as_ref().expect("refreshed just before this call").jwk_set;
        let Some(jwk) = jwk_set.find(kid) else {
            return Ok(None);
        };
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(ClaspError::InvalidKey)?;
        let validation = Validation::new(algorithm.to_jwt());
        let data =
            decode::<T>(token, &decoding_key, &validation).map_err(ClaspError::Verification)?;
        Ok(Some(data.claims))
    }
}

fn fetch_jwks(url: &str) -> Result<JwkSet, ClaspError> {
    let body = ureq::get(url)
        .call()
        .map_err(|e| ClaspError::JwksFetch(e.to_string()))?
        .into_string()
        .map_err(|e| ClaspError::JwksFetch(e.to_string()))?;
    serde_json::from_str(&body).map_err(|e| ClaspError::JwksFetch(e.to_string()))
}
