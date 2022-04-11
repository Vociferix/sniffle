#[cfg(feature = "npcap")]
use super::*;
#[cfg(feature = "npcap")]
use std::ffi::{CStr, CString};
#[cfg(feature = "npcap")]
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum TsType {
    Host,
    HostLowPrecision,
    HostHighPrecision,
    Adapter,
    AdapterUnsynced,
}

#[derive(Debug, Clone, Copy)]
pub struct ParseTsTypeError;

#[cfg(feature = "npcap")]
impl FromStr for TsType {
    type Err = ParseTsTypeError;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        unsafe {
            let name = match CString::new(name) {
                Ok(name) => name,
                Err(_) => {
                    return Err(ParseTsTypeError);
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());
            let val = pcap_tstamp_type_name_to_val(c_name);
            if val < 0 {
                Err(ParseTsTypeError)
            } else {
                match val {
                    PCAP_TSTAMP_HOST => Ok(TsType::Host),
                    PCAP_TSTAMP_HOST_LOWPREC => Ok(TsType::HostLowPrecision),
                    PCAP_TSTAMP_HOST_HIPREC => Ok(TsType::HostHighPrecision),
                    PCAP_TSTAMP_ADAPTER => Ok(TsType::Adapter),
                    PCAP_TSTAMP_ADAPTER_UNSYNCED => Ok(TsType::AdapterUnsynced),
                    _ => Err(ParseTsTypeError),
                }
            }
        }
    }
}

#[cfg(feature = "npcap")]
impl fmt::Display for TsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let t = match self {
                TsType::Host => PCAP_TSTAMP_HOST,
                TsType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                TsType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                TsType::Adapter => PCAP_TSTAMP_ADAPTER,
                TsType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
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
impl TsType {
    pub fn name(&self) -> Option<String> {
        unsafe {
            let t = match self {
                TsType::Host => PCAP_TSTAMP_HOST,
                TsType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                TsType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                TsType::Adapter => PCAP_TSTAMP_ADAPTER,
                TsType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
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
                TsType::Host => PCAP_TSTAMP_HOST,
                TsType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                TsType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                TsType::Adapter => PCAP_TSTAMP_ADAPTER,
                TsType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
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
