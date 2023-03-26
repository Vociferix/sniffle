use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyIndexError};
use pyo3::types::{PyBytes, PyByteArray};

use std::str::FromStr;
use sniffle::prelude::*;

#[pyclass]
#[pyo3(name = "Ipv6Address")]
#[repr(transparent)]
pub struct PyIpv6Address(Ipv6Address);

#[derive(FromPyObject)]
pub enum Ipv6AddressInit<'a> {
    #[pyo3(transparent, annotation = "int")]
    Int(i128),
    #[pyo3(transparent, annotation = "int")]
    UInt(u128),
    #[pyo3(transparent, annotation = "str")]
    String(&'a str),
    #[pyo3(transparent, annotation = "bytes")]
    Bytes(&'a PyBytes),
    #[pyo3(transparent, annotation = "bytearray")]
    ByteArray(&'a PyByteArray),
    #[pyo3(transparent, annotation = "list[int]")]
    List(&'a [u8]),
}

#[pymethods]
impl PyIpv6Address {
    #[new]
    fn new(value: Ipv6AddressInit<'_>) -> PyResult<Self> {
        match value {
            Ipv6AddressInit::Int(val) => Ok(Self(Ipv6Address::from(val))),
            Ipv6AddressInit::UInt(val) => Ok(Self(Ipv6Address::from(val))),
            Ipv6AddressInit::String(s) => match Ipv6Address::from_str(s) {
                Ok(addr) => Ok(Self(addr)),
                Err(_) => Err(PyValueError::new_err(format!("invalid IPv6 address literal: '{s}'"))),
            },
            Ipv6AddressInit::Bytes(bytes) => {
                let bytes = bytes.as_bytes();
                Ok(Self(Ipv6Address::new(match bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => { return Err(PyValueError::new_err(format!("invalid IPv6 address bytes: expected 16 bytes, received {}", bytes.len()))); }
                })))
            },
            Ipv6AddressInit::ByteArray(bytes) => unsafe {
                let bytes = bytes.as_bytes();
                Ok(Self(Ipv6Address::new(match bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => { return Err(PyValueError::new_err(format!("invalid IPv6 address bytes: expected 16 bytes, received {}", bytes.len()))); }
                })))
            },
            Ipv6AddressInit::List(bytes) => {
                Ok(Self(Ipv6Address::new(match bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => { return Err(PyValueError::new_err(format!("invalid IPv6 address bytes: expected 16 bytes, received {}", bytes.len()))); }
                })))
            },
        }
    }

    #[staticmethod]
    fn from_prefix_len(prefix_len: u32) -> Self {
        Self(Ipv6Address::from_prefix_len(prefix_len))
    }

    fn is_unspecified(&self) -> bool {
        return self.0.is_local_unicast()
    }

    fn is_loopback(&self) -> bool {
        return self.0.is_loopback()
    }

    fn is_local_unicast(&self) -> bool {
        return self.0.is_local_unicast()
    }

    fn is_multicast(&self) -> bool {
        return self.0.is_multicast()
    }

    fn next(&self) -> Self {
        Self(self.0.next())
    }

    fn prev(&self) -> Self {
        Self(self.0.prev())
    }

    fn __len__(&self) -> usize {
        self.0.len()
    }

    fn __getitem__(&self, idx: usize) -> PyResult<u8> {
        if idx >= 16 {
            Err(PyIndexError::new_err("IPv6 address byte index out of range"))
        } else {
            Ok(self.0[idx])
        }
    }

    fn __setitem__(&mut self, idx: usize, value: u8) -> PyResult<()> {
        if idx >= 16 {
            Err(PyIndexError::new_err("IPv6 address byte index out of range"))
        } else {
            self.0[idx] = value;
            Ok(())
        }
    }

    fn __repr__(&self) -> String {
        format!("Ipv6Address('{}')", self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __int__(&self) -> u128 {
        self.0.into()
    }

    fn __bytes__<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        PyBytes::new(py, &self.0)
    }

    fn __richcmp__(&self, rhs: &PyIpv6Address, op: pyo3::basic::CompareOp) -> bool {
        op.matches(self.0.cmp(&rhs.0))
    }

    fn __copy__(&self) -> Self {
        Self(self.0.clone())
    }

    fn __deepcopy__(&self, _memo: &PyAny) -> Self {
        Self(self.0.clone())
    }

    fn __invert__(&self) -> Self {
        Self(!self.0)
    }

    fn __and__(&self, rhs: &PyIpv6Address) -> Self {
        Self(self.0 & rhs.0)
    }

    fn __or__(&self, rhs: &PyIpv6Address) -> Self {
        Self(self.0 | rhs.0)
    }

    fn __iand__(&mut self, rhs: &PyIpv6Address) {
        self.0 &= rhs.0
    }

    fn __ior__(&mut self, rhs: &PyIpv6Address) {
        self.0 |= rhs.0
    }
}
