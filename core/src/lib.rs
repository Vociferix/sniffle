#![doc = include_str!("../README.md")]

mod device;
#[cfg(feature = "pcaprs")]
mod device_injector;
#[cfg(feature = "pcaprs")]
mod device_sniffer;
mod dissection;
pub(crate) mod dump;
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

pub use device::{ConnectionStatus, Device, DeviceBuilder, DeviceIpv4, DeviceIpv6};

#[cfg(feature = "pcaprs")]
pub use device::AllDevicesIter;

#[cfg(feature = "pcaprs")]
pub use device_injector::DeviceInjector;

#[cfg(feature = "pcaprs")]
pub use device_sniffer::{DeviceSniffer, DeviceSnifferConfig, DeviceTsPrecision, DeviceTsType};

pub use dissection::{
    AnyDissector, DResult, Dissect, DissectError, DissectParser, Dissector, DissectorTable,
    DissectorTableParser, Priority,
};

pub use dump::{Dump, DumpValue, Dumper, ListDumper, LogDumper, NodeDumper};

pub use eui_address::{EuiAddress, EuiParseError};

pub use mac_address::MacAddress;

pub use ipv4_address::{Ipv4Address, Ipv4Network, Ipv4NetworkIter};

pub use ipv6_address::{Ipv6Address, Ipv6Network, Ipv6NetworkIter};

pub use link_type::{LinkType, LinkTypeTable};

#[doc(hidden)]
pub use link_type::_register_link_layer_pdu;

pub use packet::Packet;

pub use pdu::{AnyPdu, BasePdu, Pdu, PduExt, PduType, TempPdu};

pub use raw_pdu::RawPdu;

pub use session::{Session, Virtual};

#[doc(hidden)]
pub use session::{_register_dissector, _register_dissector_table};

pub use sniff::{RawPacket, Sniff, SniffError, SniffIter, SniffRaw, Sniffer};

pub use transmit::{Transmit, TransmitError};
