pub mod reader;
mod recorder;
mod sniffer;
pub mod writer;

pub use recorder::{FileRecorder, Recorder};
pub use sniffer::{FileSniffer, Sniffer};

use pcaprs::TSPrecision;

pub struct Header {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

pub struct RecordHeader {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

const BE_MAGIC_U: u32 = u32::from_ne_bytes([0xA1, 0xB2, 0xC3, 0xD4]);
const LE_MAGIC_U: u32 = u32::from_ne_bytes([0xD4, 0xC3, 0xB2, 0xA1]);
const BE_MAGIC_N: u32 = u32::from_ne_bytes([0xA1, 0xB2, 0x3C, 0x4D]);
const LE_MAGIC_N: u32 = u32::from_ne_bytes([0x4D, 0x3C, 0xB2, 0xA1]);

impl Header {
    pub fn is_big_endian(&self) -> bool {
        match self.magic {
            BE_MAGIC_U => true,
            BE_MAGIC_N => true,
            _ => false,
        }
    }

    pub fn is_little_endian(&self) -> bool {
        match self.magic {
            LE_MAGIC_U => true,
            LE_MAGIC_N => true,
            _ => false,
        }
    }

    pub fn is_micro(&self) -> bool {
        match self.magic {
            LE_MAGIC_U => true,
            BE_MAGIC_U => true,
            _ => false,
        }
    }

    pub fn is_nano(&self) -> bool {
        match self.magic {
            LE_MAGIC_N => true,
            BE_MAGIC_N => true,
            _ => false,
        }
    }
}
