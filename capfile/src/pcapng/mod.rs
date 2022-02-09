pub mod reader;
mod recorder;
mod sniffer;
pub mod writer;

pub use recorder::{FileRecorder, Recorder};
pub use sniffer::{FileSniffer, Sniffer};

use sniffle_core::EUIAddress;
use sniffle_core::IPv4Address;
use sniffle_core::IPv6Address;
use sniffle_core::MACAddress;

const BE_MAGIC: u32 = u32::from_ne_bytes([0x1A, 0x2B, 0x3C, 0x4D]);
const LE_MAGIC: u32 = u32::from_ne_bytes([0x4D, 0x3C, 0x2B, 0x1A]);

const OPT_ENDOFOPT: u16 = 0;
const OPT_COMMENT: u16 = 1;
//const OPT_CUSTOM_STR: u16 = 2988;
//const OPT_CUSTOM_BYTES: u16 = 2989;
//const OPT_CUSTOM_STR_NO_COPY: u16 = 19372;
//const OPT_CUSTOM_BYTES_NO_COPY: u16 = 19373;

const SHB_HARDWARE: u16 = 2;
const SHB_OS: u16 = 3;
const SHB_USERAPPL: u16 = 4;

const IF_NAME: u16 = 2;
const IF_DESCRIPTION: u16 = 3;
const IF_IPV4ADDR: u16 = 4;
const IF_IPV6ADDR: u16 = 5;
const IF_MACADDR: u16 = 6;
const IF_EUIADDR: u16 = 7;
const IF_SPEED: u16 = 8;
const IF_TSRESOL: u16 = 9;
const IF_TZONE: u16 = 10;
const IF_FILTER: u16 = 11;
const IF_OS: u16 = 12;
const IF_FCSLEN: u16 = 13;
const IF_TSOFFSET: u16 = 14;
const IF_HARDWARE: u16 = 15;
const IF_TXSPEED: u16 = 16;
const IF_RXSPEED: u16 = 17;

const EPB_FLAGS: u16 = 2;
const EPB_HASH: u16 = 3;
const EPB_DROPCOUNT: u16 = 4;
const EPB_PACKETID: u16 = 5;
const EPB_QUEUE: u16 = 6;
const EPB_VERDICT: u16 = 7;

const NS_DNSNAME: u16 = 2;
const NS_DNSIP4ADDR: u16 = 3;
const NS_DNSIP6ADDR: u16 = 4;

const ISB_STARTTIME: u16 = 2;
const ISB_ENDTIME: u16 = 3;
const ISB_IFRECV: u16 = 4;
const ISB_IFDROP: u16 = 5;
const ISB_FILTERACCEPT: u16 = 6;
const ISB_OSDROP: u16 = 7;
const ISB_USRDELIV: u16 = 8;

//const PACK_FLAGS: u16 = 2;
//const PACK_HASH: u16 = 3;

const NRB_RECORD_END: u16 = 0;
const NRB_RECORD_IPV4: u16 = 1;
const NRB_RECORD_IPV6: u16 = 2;

pub const SECRET_TLS_KEY_LOG: u32 = 0x544c534b;
pub const SECRET_WIREGUARD_KEY_LOG: u32 = 0x57474b4c;
pub const SECRET_ZIGBEE_NWK_KEY: u32 = 0x5a4e574b;
pub const SECRET_ZIGBEE_APS_KEY: u32 = 0x5a415053;

const SHB_ID: u32 = 0x0A0D0D0A;
const IDB_ID: u32 = 0x00000001;
const EPB_ID: u32 = 0x00000006;
const SPB_ID: u32 = 0x00000003;
const NRB_ID: u32 = 0x00000004;
const ISB_ID: u32 = 0x00000005;
const SJB_ID: u32 = 0x00000009;
const DSB_ID: u32 = 0x0000000A;
//const OPB_ID: u32 = 0x00000002;

pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

pub enum ReceptionType {
    Unicast,
    Multicast,
    Broadcast,
    Promiscuous,
    Unspecified,
}
