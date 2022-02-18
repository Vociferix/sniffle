#[cfg(feature = "npcap")]
use super::*;
#[cfg(feature = "npcap")]
use std::ffi::{CStr, CString};
#[cfg(feature = "npcap")]
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum TSType {
    Host,
    HostLowPrecision,
    HostHighPrecision,
    Adapter,
    AdapterUnsynced,
}

#[derive(Debug, Clone, Copy)]
pub struct ParseTSTypeError;

#[cfg(feature = "npcap")]
impl FromStr for TSType {
    type Err = ParseTSTypeError;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        unsafe {
            let name = match CString::new(name) {
                Ok(name) => name,
                Err(_) => {
                    return Err(ParseTSTypeError);
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());
            let val = pcap_tstamp_type_name_to_val(c_name);
            if val < 0 {
                Err(ParseTSTypeError)
            } else {
                match val {
                    PCAP_TSTAMP_HOST => Ok(TSType::Host),
                    PCAP_TSTAMP_HOST_LOWPREC => Ok(TSType::HostLowPrecision),
                    PCAP_TSTAMP_HOST_HIPREC => Ok(TSType::HostHighPrecision),
                    PCAP_TSTAMP_ADAPTER => Ok(TSType::Adapter),
                    PCAP_TSTAMP_ADAPTER_UNSYNCED => Ok(TSType::AdapterUnsynced),
                    _ => Err(ParseTSTypeError),
                }
            }
        }
    }
}

#[cfg(feature = "npcap")]
impl fmt::Display for TSType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let t = match self {
                TSType::Host => PCAP_TSTAMP_HOST,
                TSType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                TSType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                TSType::Adapter => PCAP_TSTAMP_ADAPTER,
                TSType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
            };
            let c_name = pcap_tstamp_type_val_to_name(t);
            if c_name.is_null() {
                write!(f, "UNKNOWN")
            } else {
                write!(f, "{}", CStr::from_ptr(c_name).to_string_lossy())
            }
        }
    }
}

#[cfg(feature = "npcap")]
impl TSType {
    pub fn name(&self) -> Option<String> {
        unsafe {
            let t = match self {
                TSType::Host => PCAP_TSTAMP_HOST,
                TSType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                TSType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                TSType::Adapter => PCAP_TSTAMP_ADAPTER,
                TSType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
            };
            let c_name = pcap_tstamp_type_val_to_name(t);
            if c_name.is_null() {
                None
            } else {
                Some(make_string(c_name))
            }
        }
    }

    pub fn description(&self) -> Option<String> {
        unsafe {
            let t = match self {
                TSType::Host => PCAP_TSTAMP_HOST,
                TSType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                TSType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                TSType::Adapter => PCAP_TSTAMP_ADAPTER,
                TSType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
            };
            let c_desc = pcap_tstamp_type_val_to_description(t);
            if c_desc.is_null() {
                None
            } else {
                Some(make_string(c_desc))
            }
        }
    }
}
