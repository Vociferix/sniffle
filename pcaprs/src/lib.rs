#![doc = include_str!("../README.md")]

use std::{
    ffi::CString,
    fmt,
    path::Path,
    time::{Duration, SystemTime},
};

use libpcap_sys::*;

mod capture;
mod device;
mod dump;
mod filter;
mod injector;
mod link_type;
mod pcap;
mod tstype;
mod utils;

pub use capture::*;
pub use device::*;
pub use dump::*;
pub use filter::*;
pub use injector::*;
pub use link_type::*;
pub use pcap::*;
pub use tstype::*;
use utils::*;

#[derive(Debug)]
#[non_exhaustive]
pub enum PcapError {
    General(String),
    Break,
    NotActivated,
    Activated,
    NoSuchDevice(String),
    RfMonNotSupported,
    PermDenied(String),
    IfaceNotUp,
    #[cfg(feature = "npcap")]
    CantSetTsType,
    #[cfg(feature = "npcap")]
    PromiscPermDenied,
    #[cfg(feature = "npcap")]
    TsPrecisionNotSupported,
    PromiscNotSupported(String),
    #[cfg(feature = "npcap")]
    TsTypeNotSupported,
    IO(std::io::Error),
}

pub type Result<T> = std::result::Result<T, PcapError>;

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Copy)]
pub enum TsPrecision {
    Micro,
    Nano,
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::ffi::CStr;
        match self {
            Self::General(ref msg) => write!(f, "{}", msg),
            Self::Break => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_BREAK)).to_string_lossy()
                )
            },
            Self::NotActivated => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_NOT_ACTIVATED)).to_string_lossy()
                )
            },
            Self::Activated => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_ACTIVATED)).to_string_lossy()
                )
            },
            Self::NoSuchDevice(ref msg) => write!(f, "{}", msg),
            Self::RfMonNotSupported => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_RFMON_NOTSUP)).to_string_lossy()
                )
            },
            Self::PermDenied(ref msg) => write!(f, "{}", msg),
            Self::IfaceNotUp => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_IFACE_NOT_UP)).to_string_lossy()
                )
            },
            #[cfg(feature = "npcap")]
            Self::CantSetTsType => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_CANTSET_TSTAMP_TYPE))
                        .to_string_lossy()
                )
            },
            #[cfg(feature = "npcap")]
            Self::PromiscPermDenied => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_PROMISC_PERM_DENIED))
                        .to_string_lossy()
                )
            },
            #[cfg(feature = "npcap")]
            Self::TsPrecisionNotSupported => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_ERROR_TSTAMP_PRECISION_NOTSUP))
                        .to_string_lossy()
                )
            },
            Self::PromiscNotSupported(ref msg) => write!(f, "{}", msg),
            #[cfg(feature = "npcap")]
            Self::TsTypeNotSupported => unsafe {
                write!(
                    f,
                    "{}",
                    CStr::from_ptr(pcap_statustostr(PCAP_WARNING_TSTAMP_TYPE_NOTSUP))
                        .to_string_lossy()
                )
            },
            Self::IO(ref err) => write!(f, "{}", err),
        }
    }
}

impl From<std::io::Error> for PcapError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl std::error::Error for PcapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
