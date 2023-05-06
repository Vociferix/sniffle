#![doc = include_str!("../README.md")]

mod device;
#[cfg(feature = "pcaprs")]
mod device_injector;
#[cfg(feature = "pcaprs")]
mod device_sniffer;
mod dissection;
pub(crate) mod dump;
mod link_type;
mod packet;
mod pdu;
mod raw_pdu;
mod session;
mod sniff;
mod transmit;

pub use ctor;
pub use paste;

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

pub use sniffle_address::*;

pub use link_type::{LinkType, LinkTypeTable};

#[doc(hidden)]
pub use link_type::_register_link_layer_pdu;

pub use packet::Packet;

pub use pdu::{AnyPdu, BasePdu, Pdu, PduExt, PduType, TempPdu};

pub use raw_pdu::RawPdu;

pub use session::{Session, Virtual};

#[doc(hidden)]
pub use session::{_register_dissector, _register_dissector_table};

pub use sniff::{RawPacket, Sniff, SniffRaw, Sniffer};

pub use transmit::Transmit;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Malformed capture")]
    MalformedCapture,
    #[error("Packet does not have a valid link type")]
    UnknownLinkType,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "pcaprs")]
    #[error(transparent)]
    Pcap(#[from] pcaprs::PcapError),
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + Send + 'static>),
}
