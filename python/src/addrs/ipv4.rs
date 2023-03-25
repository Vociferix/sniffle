use pyo3::exceptions::{PyValueError, PyIndexError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};

use std::str::FromStr;
use sniffle::prelude::*;

#[pyclass]
#[pyo3(name = "Ipv4Address")]
#[repr(transparent)]
pub struct PyIpv4Address(Ipv4Address);

#[derive(FromPyObject)]
pub enum Ipv4AddressInit<'a> {
    #[pyo3(transparent, annotation = "int")]
    Int(i32),
    #[pyo3(transparent, annotation = "int")]
    UInt(u32),
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
impl PyIpv4Address {
    #[new]
    fn new(value: Ipv4AddressInit<'_>) -> PyResult<Self> {
        match value {
            Ipv4AddressInit::Int(val) => Ok(Self(Ipv4Address::from(val))),
            Ipv4AddressInit::UInt(val) => Ok(Self(Ipv4Address::from(val))),
            Ipv4AddressInit::String(s) => match Ipv4Address::from_str(s) {
                Ok(addr) => Ok(Self(addr)),
                Err(_) => Err(PyValueError::new_err(format!("invalid IPv4 address literal: '{s}'"))),
            },
            Ipv4AddressInit::Bytes(bytes) => {
                let bytes = bytes.as_bytes();
                if bytes.len() != 4 {
                    Err(PyValueError::new_err(format!("invalid IPv4 address bytes: expected 4 bytes, received {}", bytes.len())))
                } else {
                    Ok(Self(Ipv4Address::new([bytes[0], bytes[1], bytes[2], bytes[3]])))
                }
            },
            Ipv4AddressInit::ByteArray(bytes) => unsafe {
                let bytes = bytes.as_bytes();
                if bytes.len() != 4 {
                    Err(PyValueError::new_err(format!("invalid IPv4 address bytes: expected 4 bytes, received {}", bytes.len())))
                } else {
                    Ok(Self(Ipv4Address::new([bytes[0], bytes[1], bytes[2], bytes[3]])))
                }
            },
            Ipv4AddressInit::List(bytes) => {
                if bytes.len() != 4 {
                    Err(PyValueError::new_err(format!("invalid IPv4 address bytes: expected 4 bytes, received {}", bytes.len())))
                } else {
                    Ok(Self(Ipv4Address::new([bytes[0], bytes[1], bytes[2], bytes[3]])))
                }
            },
        }
    }

    #[staticmethod]
    fn from_prefix_len(prefix_len: u32) -> Self {
        Self(Ipv4Address::from_prefix_len(prefix_len))
    }

    fn is_private(&self) -> bool {
        self.0.is_private()
    }

    fn is_loopback(&self) -> bool {
        self.0.is_loopback()
    }

    fn is_multicast(&self) -> bool {
        self.0.is_multicast()
    }

    fn is_unicast(&self) -> bool {
        self.0.is_unicast()
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
        if idx >= 4 {
            Err(PyIndexError::new_err("IPv4 address byte index out of range"))
        } else {
            Ok(self.0[idx])
        }
    }

    fn __setitem__(&mut self, idx: usize, value: u8) -> PyResult<()> {
        if idx >= 4 {
            Err(PyIndexError::new_err("IPv4 address byte index out of range"))
        } else {
            self.0[idx] = value;
            Ok(())
        }
    }

    fn __repr__(&self) -> String {
        format!("Ipv4Address('{}')", self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __int__(&self) -> u32 {
        self.0.into()
    }

    fn __bytes__<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        PyBytes::new(py, &self.0)
    }

    fn __richcmp__(&self, rhs: &PyIpv4Address, op: pyo3::basic::CompareOp) -> bool {
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

    fn __and__(&self, rhs: &PyIpv4Address) -> Self {
        Self(self.0 & rhs.0)
    }

    fn __or__(&self, rhs: &PyIpv4Address) -> Self {
        Self(self.0 | rhs.0)
    }

    fn __iand__(&mut self, rhs: &PyIpv4Address) {
        self.0 &= rhs.0;
    }

    fn __ior__(&mut self, rhs: &PyIpv4Address) {
        self.0 |= rhs.0;
    }
}
