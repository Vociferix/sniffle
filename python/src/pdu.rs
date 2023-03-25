use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use sniffle::prelude::*;
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub struct PduHolder {
    refs: HashMap<usize, Py<PyPdu>>,
}

pub struct PduRef {
    holder: Arc<RwLock<PduHolder>>,
    addr: usize,
}

impl PduRef {
    pub unsafe fn unsafe_read<F, R>(&self, f: F) -> R
        where F: for<'a> FnOnce(&'a AnyPdu) -> R,
    {
        f(&*(self.addr as *const AnyPdu))
    }

    pub fn read<F, R>(&self, f: F) -> R
        where F: for<'a> FnOnce(&'a AnyPdu) -> R,
    {
        let _guard = self.holder.read();
        unsafe { self.unsafe_read(f) }
    }

    pub unsafe fn unsafe_write<F, R>(&self, f: F) -> R
        where F: for<'a> FnOnce(&'a mut AnyPdu) -> R,
    {
        f(&mut *(self.addr as *mut AnyPdu))
    }

    pub fn write<F, R>(&self, f: F) -> R
        where F: for<'a> FnOnce(&'a mut AnyPdu) -> R,
    {
        let _guard = self.holder.write();
        unsafe { self.unsafe_write(f) }
    }
}

#[pyclass]
#[pyo3(name = "Pdu")]
#[repr(transparent)]
pub struct PyPdu(PduRef);

#[pymethods]
impl PyPdu {
    pub fn header_len(&self) -> usize {
        self.0.read(|pdu| pdu.header_len())
    }

    pub fn trailer_len(&self) -> usize {
        self.0.read(|pdu| pdu.trailer_len())
    }

    pub fn total_len(&self) -> usize {
        self.0.read(|pdu| pdu.total_len())
    }

    pub fn __len__(&self) -> usize {
        self.total_len()
    }

    pub fn inner_pdu(&self, py: Python<'_>) -> PyResult<Option<Py<Self>>> {
        let mut holder = self.0.holder.write();
        let Some(addr) = (unsafe { self.0.unsafe_read(|pdu| -> Option<usize> {
            pdu.inner_pdu().map(|inner| inner as *const AnyPdu as usize)
        }) }) else { return Ok(None); };
        Ok(Some(match holder.refs.entry(addr) {
            Entry::Vacant(entry) => {
                entry.insert(Py::new(py, PyPdu(PduRef {
                    holder: self.0.holder.clone(),
                    addr,
                }))?).clone()
            },
            Entry::Occupied(entry) => {
                entry.get().clone()
            },
        }))
    }

    pub fn parent_pdu(&self, py: Python<'_>) -> PyResult<Option<Py<Self>>> {
        let mut holder = self.0.holder.write();
        let Some(addr) = (unsafe { self.0.unsafe_read(|pdu| -> Option<usize> {
            pdu.parent_pdu().map(|inner| inner as *const AnyPdu as usize)
        }) }) else { return Ok(None); };
        Ok(Some(match holder.refs.entry(addr) {
            Entry::Vacant(entry) => {
                entry.insert(Py::new(py, PyPdu(PduRef {
                    holder: self.0.holder.clone(),
                    addr,
                }))?).clone()
            },
            Entry::Occupied(entry) => {
                entry.get().clone()
            },
        }))
    }

    pub fn serialize_header<'a>(&self, py: Python<'a>, buf: Option<&'a PyByteArray>) -> PyResult<&'a PyByteArray> {
        let _guard = self.0.holder.read();
        let len = unsafe { self.0.unsafe_read(|pdu| pdu.header_len()) };
        match buf {
            Some(buf) => {
                buf.resize(len)?;
                unsafe { self.0.unsafe_read(|pdu| pdu.serialize_header(&mut buf.as_bytes_mut()))?; }
                Ok(buf)
            },
            None => {
                Ok(PyByteArray::new_with(py, len, |mut buf| {
                    unsafe { self.0.unsafe_read(|pdu| pdu.serialize_header(&mut buf))?; }
                    Ok(())
                })?)
            },
        }
    }

    pub fn serialize_trailer<'a>(&self, py: Python<'a>, buf: Option<&'a PyByteArray>) -> PyResult<&'a PyByteArray> {
        let _guard = self.0.holder.read();
        let len = unsafe { self.0.unsafe_read(|pdu| pdu.trailer_len()) };
        match buf {
            Some(buf) => {
                buf.resize(len)?;
                unsafe { self.0.unsafe_read(|pdu| pdu.serialize_trailer(&mut buf.as_bytes_mut()))?; }
                Ok(buf)
            },
            None => {
                Ok(PyByteArray::new_with(py, len, |mut buf| {
                    unsafe { self.0.unsafe_read(|pdu| pdu.serialize_trailer(&mut buf))?; }
                    Ok(())
                })?)
            },
        }
    }

    pub fn serialize<'a>(&self, py: Python<'a>, buf: Option<&'a PyByteArray>) -> PyResult<&'a PyByteArray> {
        let _guard = self.0.holder.read();
        let len = unsafe { self.0.unsafe_read(|pdu| pdu.total_len()) };
        match buf {
            Some(buf) => {
                buf.resize(len)?;
                unsafe { self.0.unsafe_read(|pdu| pdu.serialize(&mut buf.as_bytes_mut()))?; }
                Ok(buf)
            },
            None => {
                Ok(PyByteArray::new_with(py, len, |mut buf| {
                    unsafe { self.0.unsafe_read(|pdu| pdu.serialize(&mut buf))?; }
                    Ok(())
                })?)
            },
        }
    }
}


