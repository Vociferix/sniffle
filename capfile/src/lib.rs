#![doc = include_str!("../README.md")]

pub mod pcap;
pub mod pcapng;

use async_trait::async_trait;
use sniffle_core::{Error, RawPacket, Session, SniffRaw};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[non_exhaustive]
pub enum CapfileType {
    Unknown,
    Pcap,
    PcapNG,
}

#[non_exhaustive]
pub enum Sniffer<F: tokio::io::AsyncBufRead + tokio::io::AsyncSeek + Send + Unpin> {
    Pcap(pcap::Sniffer<F>),
    PcapNG(pcapng::Sniffer<F>),
}

pub type FileSniffer = Sniffer<tokio::io::BufReader<tokio::fs::File>>;

impl CapfileType {
    pub async fn from_file<F: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin>(
        file: &mut F,
    ) -> Result<Self, std::io::Error> {
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic[..]).await?;
        file.seek(std::io::SeekFrom::Current(-4)).await?;
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

impl<F: tokio::io::AsyncBufRead + tokio::io::AsyncSeek + Send + Unpin> Sniffer<F> {
    pub async fn new_raw(mut file: F) -> Result<Self, Error> {
        let ft = CapfileType::from_file(&mut file).await?;
        Ok(match ft {
            CapfileType::Pcap => Self::Pcap(pcap::Sniffer::new_raw(file).await?),
            CapfileType::PcapNG => Self::PcapNG(pcapng::Sniffer::new_raw(file).await?),
            CapfileType::Unknown => {
                return Err(Error::MalformedCapture);
            }
        })
    }

    pub async fn new(file: F) -> Result<sniffle_core::Sniffer<Self>, Error> {
        Ok(sniffle_core::Sniffer::new(Self::new_raw(file).await?))
    }

    pub async fn new_with_session(
        file: F,
        session: Session,
    ) -> Result<sniffle_core::Sniffer<Self>, Error> {
        Ok(sniffle_core::Sniffer::with_session(
            Self::new_raw(file).await?,
            session,
        ))
    }

    pub async fn open_raw<P: AsRef<std::path::Path>>(path: P) -> Result<FileSniffer, Error> {
        FileSniffer::new_raw(tokio::io::BufReader::new(
            tokio::fs::File::open(path).await?,
        ))
        .await
    }

    pub async fn open<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<sniffle_core::Sniffer<FileSniffer>, Error> {
        Ok(sniffle_core::Sniffer::new(Self::open_raw(path).await?))
    }

    pub async fn open_with_session<P: AsRef<std::path::Path>>(
        path: P,
        session: Session,
    ) -> Result<sniffle_core::Sniffer<FileSniffer>, Error> {
        Ok(sniffle_core::Sniffer::with_session(
            Self::open_raw(path).await?,
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

#[async_trait]
impl<F: tokio::io::AsyncBufRead + tokio::io::AsyncSeek + Send + Unpin> SniffRaw for Sniffer<F> {
    async fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, Error> {
        match self {
            Self::Pcap(pcap) => pcap.sniff_raw().await,
            Self::PcapNG(pcapng) => pcapng.sniff_raw().await,
        }
    }
}
