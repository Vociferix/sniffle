use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use sniffle::prelude::*;
use std::io::Write;
use std::sync::Arc;
use parking_lot::RwLock;

#[pyclass]
#[pyo3(name = "Pdu")]
#[repr(transparent)]
pub struct PyPdu(AnyPdu);

pub struct PyEncoder<'a>(&'a PyByteArray);

impl<'a> PyEncoder<'a> {
    fn new(array: &'a PyByteArray) -> Self {
        Self(array)
    }
}

impl<'a> Write for PyEncoder<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe { self.0.as_bytes_mut().write(buf) }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[pymethods]
impl PyPdu {
    fn header_len(&self) -> usize {
        self.0.header_len()
    }

    fn trailer_len(&self) -> usize {
        self.0.trailer_len()
    }

    fn total_len(&self) -> usize {
        self.0.total_len()
    }

    fn __len__(&self) -> usize {
        self.total_len()
    }

    fn make_canonical(&mut self) {
        self.0.make_canonical()
    }

    fn canonicalize(&self) -> Self {
        let mut copy = self.0.clone();
        copy.make_canonical();
        Self(copy)
    }

    fn serialize_header<'a>(&self, py: Python<'a>, buf: Option<&'a PyByteArray>) -> PyResult<&'a PyByteArray> {
        let buf = buf.unwrap_or_else(|| PyByteArray::new(py, &[][..]));
        buf.resize(buf.len() + self.header_len())?;
        self.0.serialize_header(&mut PyEncoder::new(buf))?;
        Ok(buf)
    }

    fn serialize_trailer<'a>(&self, py: Python<'a>, buf: Option<&'a PyByteArray>) -> PyResult<&'a PyByteArray> {
        let buf = buf.unwrap_or_else(|| PyByteArray::new(py, &[][..]));
        buf.resize(buf.len() + self.trailer_len())?;
        self.0.serialize_trailer(&mut PyEncoder::new(buf))?;
        Ok(buf)
    }

    fn serialize<'a>(&self, py: Python<'a>, buf: Option<&'a PyByteArray>) -> PyResult<&'a PyByteArray> {
        let buf = buf.unwrap_or_else(|| PyByteArray::new(py, &[][..]));
        buf.resize(buf.len() + self.total_len())?;
        self.0.serialize(&mut PyEncoder::new(buf))?;
        Ok(buf)
    }
}

/// This module is implemented in Rust.
#[pymodule]
#[pyo3(name = "sniffle")]
fn sniffle_module(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyPdu>()?;
    Ok(())
}
