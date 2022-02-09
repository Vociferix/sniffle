use super::utils::make_string;
use libpcap_sys::*;
use std::ffi::{CStr, CString};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Hash)]
pub struct LinkType(pub u16);

#[derive(Debug, Clone, Copy)]
pub struct ParseLinkTypeError;

macro_rules! link_type {
    ($name:ident) => {
        pub const $name: LinkType = LinkType(link_types::LinkType::$name.0);
    };
}

impl FromStr for LinkType {
    type Err = ParseLinkTypeError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        unsafe {
            let name = match CString::new(name) {
                Ok(name) => name,
                Err(_) => {
                    return Err(ParseLinkTypeError);
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());
            let val = pcap_datalink_name_to_val(c_name);
            if val < 0 {
                Err(ParseLinkTypeError)
            } else {
                Ok(Self(val as u16))
            }
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let c_name = pcap_datalink_val_to_name(self.0 as i32);
            if c_name == std::ptr::null() {
                write!(f, "DLT({})", self.0)
            } else {
                write!(f, "{}", CStr::from_ptr(c_name).to_string_lossy())
            }
        }
    }
}

impl fmt::Display for ParseLinkTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid datalink name")
    }
}

impl std::error::Error for ParseLinkTypeError {}

impl LinkType {
    pub fn name(&self) -> Option<String> {
        unsafe {
            let c_name = pcap_datalink_val_to_name(self.0 as i32);
            if c_name == std::ptr::null() {
                None
            } else {
                Some(make_string(c_name))
            }
        }
    }

    pub fn description(&self) -> Option<String> {
        unsafe {
            let c_desc = pcap_datalink_val_to_description(self.0 as i32);
            if c_desc == std::ptr::null() {
                None
            } else {
                Some(make_string(c_desc))
            }
        }
    }

    pub fn description_or_dlt(&self) -> String {
        unsafe { make_string(pcap_datalink_val_to_description_or_dlt(self.0 as i32)) }
    }

    link_types::for_each_link_type!(link_type);
}

impl From<link_types::LinkType> for LinkType {
    fn from(link: link_types::LinkType) -> Self {
        Self(link.0)
    }
}

impl From<LinkType> for link_types::LinkType {
    fn from(link: LinkType) -> Self {
        Self(link.0)
    }
}

impl PartialEq for LinkType {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for LinkType {}
