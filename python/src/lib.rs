use pyo3::prelude::*;

pub mod pdu;
pub mod addrs;

/// This module is implemented in Rust.
#[pymodule]
#[pyo3(name = "sniffle")]
fn sniffle_module(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<addrs::PyIpv4Address>()?;
    m.add_class::<addrs::PyIpv6Address>()?;
    m.add_class::<pdu::PyPdu>()?;
    Ok(())
}
