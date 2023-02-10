use super::reader::*;
use super::*;
use async_trait::async_trait;
use sniffle_core::{Error, LinkType, RawPacket, Session, SniffRaw};
use std::time::{Duration, SystemTime};

pub struct Sniffer<F: tokio::io::AsyncBufRead + Send + Unpin> {
    reader: Reader<F>,
    buf: Vec<u8>,
}

pub type FileSniffer = Sniffer<tokio::io::BufReader<tokio::fs::File>>;

impl<F: tokio::io::AsyncBufRead + Send + Unpin> Sniffer<F> {
    pub async fn new_raw(file: F) -> Result<Self, Error> {
        Ok(Self {
            reader: Reader::new(file).await?,
            buf: Vec::new(),
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
        Ok(FileSniffer {
            reader: FileReader::open(path).await?,
            buf: Vec::new(),
        })
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

    pub fn reader(&self) -> &Reader<F> {
        &self.reader
    }

    pub fn reader_mut(&mut self) -> &mut Reader<F> {
        &mut self.reader
    }
}

#[async_trait]
impl<F: tokio::io::AsyncBufRead + Send + Unpin> SniffRaw for Sniffer<F> {
    async fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, Error> {
        let mut buf = std::mem::take(&mut self.buf);
        let hdr = match self.reader.next_record(&mut buf).await? {
            Some(hdr) => hdr,
            None => {
                return Ok(None);
            }
        };
        self.buf = buf;
        Ok(Some(RawPacket::new(
            LinkType(self.reader.header().network as u16),
            match self.reader.timestamp_precision() {
                TsPrecision::Nano => SystemTime::UNIX_EPOCH
                    .checked_add(Duration::new(hdr.ts_sec as u64, hdr.ts_frac))
                    .unwrap_or(SystemTime::UNIX_EPOCH),
                TsPrecision::Micro => SystemTime::UNIX_EPOCH
                    .checked_add(Duration::new(hdr.ts_sec as u64, hdr.ts_frac * 1000))
                    .unwrap_or(SystemTime::UNIX_EPOCH),
            },
            hdr.orig_len as usize,
            Some(self.reader.header().snaplen as usize),
            &self.buf[..],
            None,
        )))
    }
}
