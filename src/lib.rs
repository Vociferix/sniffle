#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub use ::concat_idents;

#[doc(hidden)]
pub use ctor;

pub use nom;

#[doc(hidden)]
pub use sniffle_core::{
    _register_dissector,
    _register_dissector_table,
    _register_link_layer_pdu,
};

#[doc(inline)]
pub use sniffle_core::Packet;

pub mod address {
    #[doc(inline)]
    pub use sniffle_core::{
        EUIAddress,
        EUIParseError,
        IPv4Address,
        IPv4NetworkIter,
        IPv6Address,
        IPv6NetworkIter,
        MACAddress,
    };
}

pub mod dissect {
    #[doc(inline)]
    pub use sniffle_core::{
        AnyDissector,
        Dissector,
        DissectorTable,
        Priority,
        Session,
        dissector_table,
        register_dissector,
        register_dissector_table,
    };
}

pub mod sniff {
    #[doc(inline)]
    pub use sniffle_core::{
        SniffIter,
        SniffError,
        Sniff,
        RawPacket,
        LinkType,
        LinkTypeTable,
        register_link_layer_pdu,
    };
}

pub mod transmit {
    #[doc(inline)]
    pub use sniffle_core::{
        TransmitError,
        Transmit,
    };
}

pub mod device {
    #[doc(inline)]
    pub use sniffle_core::{
        Device,
        DeviceBuilder,
        DeviceIPv4,
        DeviceIPv6,
        DeviceTSPrecision,
        DeviceTSType,
        ConnectionStatus,
    };

    #[cfg(feature = "libpcap")]
    #[doc(inline)]
    pub use sniffle_core::{
        AllDevicesIter,
        DeviceInjector,
        DeviceSniffer,
        DeviceSnifferConfig,
    };
}

pub mod pdu {
    #[doc(inline)]
    pub use sniffle_core::{
        AnyPDU,
        BasePDU,
        RawPDU,
        TempPDU,
        PDU,
        PDUType,
    };
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
        Packet,
        address::EUIAddress,
        address::EUIParseError,
        address::IPv4Address,
        address::IPv6Address,
        address::MACAddress,
        decode::DecodeError,
        device::ConnectionStatus,
        dissect::Priority,
        dissect::Session,
        dissect::register_dissector,
        sniff::Sniff,
        sniff::SniffError,
        transmit::Transmit,
        transmit::TransmitError,
        device::Device,
        pdu::AnyPDU,
        pdu::PDU,
        capfile::FileSniffer,
        capfile::pcap,
        capfile::pcapng,
        protos,
    };

    #[cfg(feature = "libpcap")]
    pub use crate::device::{
        DeviceInjector,
        DeviceSniffer,
        DeviceSnifferConfig
    };
}

pub mod protos;
