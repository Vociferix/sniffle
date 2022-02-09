pub mod pcap;
pub mod pcapng;

use sniffle_core::{Packet, RawPacket, Session, Sniff, SniffError};

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
        match self {
            Self::Pcap => true,
            _ => false,
        }
    }

    pub fn is_pcapng(&self) -> bool {
        match self {
            Self::PcapNG => true,
            _ => false,
        }
    }

    pub fn is_unknown(&self) -> bool {
        match self {
            Self::Unknown => true,
            _ => false,
        }
    }
}

impl<F: std::io::BufRead + std::io::Seek> Sniffer<F> {
    pub fn new(mut file: F, session: Option<Session>) -> Result<Self, SniffError> {
        let ft = CapfileType::from_file(&mut file)?;
        Ok(match ft {
            CapfileType::Pcap => Self::Pcap(pcap::Sniffer::new(file, session)?),
            CapfileType::PcapNG => Self::PcapNG(pcapng::Sniffer::new(file, session)?),
            CapfileType::Unknown => {
                return Err(SniffError::MalformedCapture);
            }
        })
    }

    pub fn open<P: AsRef<std::path::Path>>(
        path: P,
        session: Option<Session>,
    ) -> Result<FileSniffer, SniffError> {
        FileSniffer::new(std::io::BufReader::new(std::fs::File::open(path)?), session)
    }

    pub fn capfile_type(&self) -> CapfileType {
        match self {
            Self::Pcap(_) => CapfileType::Pcap,
            Self::PcapNG(_) => CapfileType::PcapNG,
        }
    }
}

impl<F: std::io::BufRead + std::io::Seek> Sniff for Sniffer<F> {
    fn session(&self) -> &Session {
        match self {
            Self::Pcap(pcap) => pcap.session(),
            Self::PcapNG(pcapng) => pcapng.session(),
        }
    }

    fn session_mut(&mut self) -> &mut Session {
        match self {
            Self::Pcap(pcap) => pcap.session_mut(),
            Self::PcapNG(pcapng) => pcapng.session_mut(),
        }
    }

    fn next_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError> {
        match self {
            Self::Pcap(pcap) => pcap.next_raw(),
            Self::PcapNG(pcapng) => pcapng.next_raw(),
        }
    }

    fn sniff(&mut self) -> Result<Option<Packet>, SniffError> {
        match self {
            Self::Pcap(pcap) => pcap.sniff(),
            Self::PcapNG(pcapng) => pcapng.sniff(),
        }
    }
}
