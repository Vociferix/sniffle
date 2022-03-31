#![doc = include_str!("../README.md")]

pub mod pcap;
pub mod pcapng;

use sniffle_core::{RawPacket, Session, SniffError, SniffRaw};

#[non_exhaustive]
pub enum CapfileType {
    Unknown,
    Pcap,
    PcapNG,
}

#[non_exhaustive]
pub enum Sniffer<F: std::io::BufRead + std::io::Seek> {
    Pcap(pcap::Sniffer<F>),
    PcapNG(pcapng::Sniffer<F>),
}

pub type FileSniffer = Sniffer<std::io::BufReader<std::fs::File>>;

impl CapfileType {
    pub fn from_file<F: std::io::Read + std::io::Seek>(
        file: &mut F,
    ) -> Result<Self, std::io::Error> {
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic[..])?;
        file.seek(std::io::SeekFrom::Current(-4))?;
        let magic = u32::from_le_bytes(magic);
        Ok(match magic {
            0x0A0D0D0A => Self::PcapNG,
            0xA1B2C3D4 => Self::Pcap,
            0xD4C3B2A1 => Self::Pcap,
            0xA1B23C4D => Self::Pcap,
            0x4D3CB2A1 => Self::Pcap,
            _ => Self::Unknown,
        })
    }

    pub fn is_pcap(&self) -> bool {
        matches!(self, Self::Pcap)
    }

    pub fn is_pcapng(&self) -> bool {
        matches!(self, Self::PcapNG)
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl<F: std::io::BufRead + std::io::Seek> Sniffer<F> {
    pub fn new_raw(mut file: F) -> Result<Self, SniffError> {
        let ft = CapfileType::from_file(&mut file)?;
        Ok(match ft {
            CapfileType::Pcap => Self::Pcap(pcap::Sniffer::new_raw(file)?),
            CapfileType::PcapNG => Self::PcapNG(pcapng::Sniffer::new_raw(file)?),
            CapfileType::Unknown => {
                return Err(SniffError::MalformedCapture);
            }
        })
    }

    pub fn new(file: F) -> Result<sniffle_core::Sniffer<Self>, SniffError> {
        Ok(sniffle_core::Sniffer::new(Self::new_raw(file)?))
    }

    pub fn new_with_session(
        file: F,
        session: Session,
    ) -> Result<sniffle_core::Sniffer<Self>, SniffError> {
        Ok(sniffle_core::Sniffer::with_session(
            Self::new_raw(file)?,
            session,
        ))
    }

    pub fn open_raw<P: AsRef<std::path::Path>>(path: P) -> Result<FileSniffer, SniffError> {
        FileSniffer::new_raw(std::io::BufReader::new(std::fs::File::open(path)?))
    }

    pub fn open<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<sniffle_core::Sniffer<FileSniffer>, SniffError> {
        Ok(sniffle_core::Sniffer::new(Self::open_raw(path)?))
    }

    pub fn open_with_session<P: AsRef<std::path::Path>>(
        path: P,
        session: Session,
    ) -> Result<sniffle_core::Sniffer<FileSniffer>, SniffError> {
        Ok(sniffle_core::Sniffer::with_session(
            Self::open_raw(path)?,
            session,
        ))
    }

    pub fn capfile_type(&self) -> CapfileType {
        match self {
            Self::Pcap(_) => CapfileType::Pcap,
            Self::PcapNG(_) => CapfileType::PcapNG,
        }
    }
}

impl<F: std::io::BufRead + std::io::Seek> SniffRaw for Sniffer<F> {
    fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError> {
        match self {
            Self::Pcap(pcap) => pcap.sniff_raw(),
            Self::PcapNG(pcapng) => pcapng.sniff_raw(),
        }
    }
}
