mod algorithm;
mod error;
mod jwks;
mod key;

pub use algorithm::{AsymmetricAlgorithm, SymmetricAlgorithm};
pub use error::ClaspError;
pub use jwks::JwksClient;
pub use key::{AsymmetricKey, SymmetricKey};

#[cfg(feature = "python")]
mod python {
    use std::time::Duration;

    use pyo3::exceptions::{PyRuntimeError, PyValueError};
    use pyo3::prelude::*;
    use serde_json::Value;

    use crate::{
        AsymmetricAlgorithm, AsymmetricKey, ClaspError, JwksClient, SymmetricAlgorithm,
        SymmetricKey,
    };

    fn to_py_err(e: ClaspError) -> PyErr {
        match e {
            ClaspError::AlgorithmKeyMismatch { .. } => PyValueError::new_err(e.to_string()),
            ClaspError::InvalidKey(_) => PyValueError::new_err(e.to_string()),
            ClaspError::Verification(_) => PyRuntimeError::new_err(e.to_string()),
            ClaspError::JwksFetch(_) => PyRuntimeError::new_err(e.to_string()),
            ClaspError::MissingKeyId => PyValueError::new_err(e.to_string()),
            ClaspError::UnknownKeyId(_) => PyValueError::new_err(e.to_string()),
        }
    }

    fn parse_symmetric(name: &str) -> PyResult<SymmetricAlgorithm> {
        SymmetricAlgorithm::parse(name)
            .ok_or_else(|| PyValueError::new_err(format!("unknown symmetric algorithm: {name}")))
    }

    fn parse_asymmetric(name: &str) -> PyResult<AsymmetricAlgorithm> {
        AsymmetricAlgorithm::parse(name)
            .ok_or_else(|| PyValueError::new_err(format!("unknown asymmetric algorithm: {name}")))
    }

    /// v0.1: claims come back as a JSON string, not a native dict --
    /// avoids pulling in an extra serde_json<->PyObject conversion
    /// dependency for the first release. `import json; json.loads(...)`
    /// on the caller's side. A native-dict `verify()` is v0.2 scope.
    #[pyclass(name = "SymmetricKey")]
    struct PySymmetricKey(SymmetricKey);

    #[pymethods]
    impl PySymmetricKey {
        #[new]
        fn new(secret: &[u8], algorithm: &str) -> PyResult<Self> {
            Ok(Self(SymmetricKey::new(secret, parse_symmetric(algorithm)?)))
        }

        fn verify(&self, token: &str) -> PyResult<String> {
            let claims: Value = self.0.verify(token).map_err(to_py_err)?;
            Ok(claims.to_string())
        }
    }

    #[pyclass(name = "AsymmetricKey")]
    struct PyAsymmetricKey(AsymmetricKey);

    #[pymethods]
    impl PyAsymmetricKey {
        #[staticmethod]
        fn from_rsa_pem(pem: &[u8], algorithm: &str) -> PyResult<Self> {
            Ok(Self(
                AsymmetricKey::from_rsa_pem(pem, parse_asymmetric(algorithm)?)
                    .map_err(to_py_err)?,
            ))
        }

        #[staticmethod]
        fn from_ec_pem(pem: &[u8], algorithm: &str) -> PyResult<Self> {
            Ok(Self(
                AsymmetricKey::from_ec_pem(pem, parse_asymmetric(algorithm)?).map_err(to_py_err)?,
            ))
        }

        #[staticmethod]
        fn from_ed_pem(pem: &[u8], algorithm: &str) -> PyResult<Self> {
            Ok(Self(
                AsymmetricKey::from_ed_pem(pem, parse_asymmetric(algorithm)?).map_err(to_py_err)?,
            ))
        }

        fn verify(&self, token: &str) -> PyResult<String> {
            let claims: Value = self.0.verify(token).map_err(to_py_err)?;
            Ok(claims.to_string())
        }
    }

    /// Fetches and caches a JWKS document, verifying tokens by matching
    /// their `kid` header claim against it -- the standard way OIDC/
    /// Auth0/Cognito-style providers publish rotating public keys.
    #[pyclass(name = "JwksClient")]
    struct PyJwksClient(JwksClient);

    #[pymethods]
    impl PyJwksClient {
        #[new]
        #[pyo3(signature = (url, ttl_seconds=300))]
        fn new(url: &str, ttl_seconds: u64) -> Self {
            Self(JwksClient::new(url).with_ttl(Duration::from_secs(ttl_seconds)))
        }

        fn verify(&self, py: Python<'_>, token: &str, algorithm: &str) -> PyResult<String> {
            let alg = parse_asymmetric(algorithm)?;
            // Network I/O -- release the GIL while fetching/verifying so it
            // doesn't block other Python threads.
            py.allow_threads(|| {
                let claims: Value = self.0.verify(token, alg).map_err(to_py_err)?;
                Ok(claims.to_string())
            })
        }
    }

    #[pymodule]
    fn clasp(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<PySymmetricKey>()?;
        m.add_class::<PyAsymmetricKey>()?;
        m.add_class::<PyJwksClient>()?;
        Ok(())
    }
}
