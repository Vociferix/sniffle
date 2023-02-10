#![doc = include_str!("../README.md")]

pub use nom;

#[doc(hidden)]
pub use sniffle_core::{_register_dissector, _register_dissector_table, _register_link_layer_pdu};

#[doc(inline)]
pub use sniffle_core::{Error, Packet};

/// Type alias to prevent `use sniffle::prelude::*` from causing conflicts
/// with other types or traits named `Error`.
pub type SniffleError = Error;

pub mod address {
    #[doc(inline)]
    pub use sniffle_core::{
        EuiAddress, EuiParseError, Ipv4Address, Ipv4NetworkIter, Ipv6Address, Ipv6NetworkIter,
        MacAddress,
    };
}

pub mod dissect {
    #[doc(inline)]
    pub use sniffle_core::{
        dissector_table, register_dissector, register_dissector_table, AnyDissector, DResult,
        Dissect, DissectError, Dissector, DissectorTable, Priority, Session,
    };
}

pub mod dump {
    #[doc(inline)]
    pub use sniffle_core::{Dump, DumpValue, Dumper, ListDumper, LogDumper, NodeDumper};
}

pub mod sniff {
    #[doc(inline)]
    pub use sniffle_core::{
        register_link_layer_pdu, LinkType, LinkTypeTable, RawPacket, Sniff, Sniffer, Error
    };
}

pub mod transmit {
    #[doc(inline)]
    pub use sniffle_core::{Transmit, Error};
}

pub mod device {
    #[doc(inline)]
    pub use sniffle_core::{
        ConnectionStatus, Device, DeviceBuilder, DeviceIpv4, DeviceIpv6, DeviceTsPrecision,
        DeviceTsType,
    };

    #[cfg(feature = "libpcap")]
    #[doc(inline)]
    pub use sniffle_core::{AllDevicesIter, DeviceInjector, DeviceSniffer, DeviceSnifferConfig};
}

pub mod pdu {
    #[doc(inline)]
    pub use sniffle_core::{AnyPdu, BasePdu, Pdu, PduExt, PduType, RawPdu, TempPdu};
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
        address::EuiAddress, address::Ipv4Address, address::Ipv6Address, address::MacAddress,
        capfile::pcap, capfile::pcapng, capfile::FileSniffer, device::ConnectionStatus,
        device::Device, dissect::register_dissector, dissect::Priority, dissect::Session,
        dump::Dump, dump::LogDumper, pdu::AnyPdu, pdu::Pdu, pdu::PduExt, protos, protos::RawPdu,
        sniff::Sniff, transmit::Transmit, Packet, SniffleError,
    };

    #[cfg(feature = "libpcap")]
    pub use crate::device::{DeviceInjector, DeviceSniffer, DeviceSnifferConfig};
}

pub mod utils {
    pub use sniffle_utils::*;
}

pub mod protos {
    pub(self) use sniffle_protos as xprotos;

    #[doc(inline)]
    pub use xprotos::{RawPdu, Virtual};

    pub mod ethertype {
        use super::xprotos;

        #[doc(inline)]
        pub use xprotos::ethertype::{Ethertype, EthertypeIter, EthertypeSet};

        #[doc(hidden)]
        pub use xprotos::ethertype::_register_ethertype_pdu;

        #[doc(inline)]
        pub use xprotos::register_ethertype_pdu;
    }

    pub mod ip_proto {
        use super::xprotos;

        #[doc(inline)]
        pub use xprotos::ip_proto::IpProto;

        #[doc(hidden)]
        pub use xprotos::ip_proto::_register_ip_proto_pdu;

        #[doc(inline)]
        pub use xprotos::register_ip_proto_pdu;
    }

    #[doc(inline)]
    pub use xprotos::ethernet_ii;

    #[doc(inline)]
    pub use xprotos::ipv4;
}
