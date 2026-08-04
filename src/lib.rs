#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;

    #[pymodule]
    fn clasp(_py: Python<'_>, _m: &Bound<'_, PyModule>) -> PyResult<()> {
        Ok(())
    }
}
