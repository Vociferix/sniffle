#![doc = include_str!("../README.md")]

mod device;
#[cfg(feature = "pcaprs")]
mod device_injector;
#[cfg(feature = "pcaprs")]
mod device_sniffer;
mod dissection;
mod eui_address;
mod ipv4_address;
mod ipv6_address;
mod link_type;
mod mac_address;
mod packet;
mod pdu;
mod raw_pdu;
mod session;
mod sniff;
mod transmit;

pub use ::concat_idents;
pub use ctor;

pub use device::{ConnectionStatus, Device, DeviceBuilder, DeviceIPv4, DeviceIPv6};

#[cfg(feature = "pcaprs")]
pub use device::AllDevicesIter;

#[cfg(feature = "pcaprs")]
pub use device_injector::DeviceInjector;

#[cfg(feature = "pcaprs")]
pub use device_sniffer::{DeviceSniffer, DeviceSnifferConfig, DeviceTSPrecision, DeviceTSType};

pub use dissection::{AnyDissector, Dissector, DissectorTable, Priority};

pub use eui_address::{EUIAddress, EUIParseError};

pub use mac_address::MACAddress;

pub use ipv4_address::{IPv4Address, IPv4Network, IPv4NetworkIter};

pub use ipv6_address::{IPv6Address, IPv6Network, IPv6NetworkIter};

pub use link_type::{LinkType, LinkTypeTable};

#[doc(hidden)]
pub use link_type::_register_link_layer_pdu;

pub use packet::Packet;

pub use pdu::{AnyPDU, BasePDU, PDUType, TempPDU, PDU, PDUExt};

pub use raw_pdu::RawPDU;

pub use session::Session;

#[doc(hidden)]
pub use session::{_register_dissector, _register_dissector_table};

pub use sniff::{RawPacket, Sniff, SniffError, SniffIter};

pub use transmit::{Transmit, TransmitError};
