#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub use ::concat_idents;

#[doc(hidden)]
pub use ctor;

pub use nom;

#[doc(hidden)]
pub use sniffle_core::{_register_dissector, _register_dissector_table, _register_link_layer_pdu};

#[doc(inline)]
pub use sniffle_core::Packet;

pub mod address {
    #[doc(inline)]
    pub use sniffle_core::{
        EUIAddress, EUIParseError, IPv4Address, IPv4NetworkIter, IPv6Address, IPv6NetworkIter,
        MACAddress,
    };
}

pub mod dissect {
    #[doc(inline)]
    pub use sniffle_core::{
        dissector_table, register_dissector, register_dissector_table, AnyDissector, Dissector,
        DissectorTable, Priority, Session,
    };
}

pub mod dump {
    #[doc(inline)]
    pub use sniffle_core::{ByteDumpFormatter, DebugDumper, Dump, Dumper, NodeDumper};
}

pub mod sniff {
    #[doc(inline)]
    pub use sniffle_core::{
        register_link_layer_pdu, LinkType, LinkTypeTable, RawPacket, Sniff, SniffError, SniffIter,
    };
}

pub mod transmit {
    #[doc(inline)]
    pub use sniffle_core::{Transmit, TransmitError};
}

pub mod device {
    #[doc(inline)]
    pub use sniffle_core::{
        ConnectionStatus, Device, DeviceBuilder, DeviceIPv4, DeviceIPv6, DeviceTSPrecision,
        DeviceTSType,
    };

    #[cfg(feature = "libpcap")]
    #[doc(inline)]
    pub use sniffle_core::{AllDevicesIter, DeviceInjector, DeviceSniffer, DeviceSnifferConfig};
}

pub mod pdu {
    #[doc(inline)]
    pub use sniffle_core::{AnyPDU, BasePDU, PDUExt, PDUType, RawPDU, TempPDU, PDU};
}

pub mod encode {
    #[doc(inline)]
    pub use sniffle_ende::encode::*;
}

pub mod decode {
    #[doc(inline)]
    pub use sniffle_ende::decode::*;
}

#[doc = include_str!("../uint/README.md")]
pub mod uint {
    #[doc(inline)]
    pub use sniffle_uint::*;
}

#[doc = include_str!("../capfile/README.md")]
pub mod capfile {
    #[doc(inline)]
    pub use sniffle_capfile::*;
}

/// Re-exports commonly used sniffle types, functions, and macros.
pub mod prelude {
    pub use crate::{
        address::EUIAddress, address::EUIParseError, address::IPv4Address, address::IPv6Address,
        address::MACAddress, capfile::pcap, capfile::pcapng, capfile::FileSniffer,
        device::ConnectionStatus, device::Device, dissect::register_dissector, dissect::Priority,
        dissect::Session, dump::DebugDumper, dump::Dump, pdu::AnyPDU, pdu::PDUExt, pdu::PDU,
        protos, sniff::Sniff, sniff::SniffError, transmit::Transmit, transmit::TransmitError,
        Packet,
    };

    #[cfg(feature = "libpcap")]
    pub use crate::device::{DeviceInjector, DeviceSniffer, DeviceSnifferConfig};
}

pub mod protos;
