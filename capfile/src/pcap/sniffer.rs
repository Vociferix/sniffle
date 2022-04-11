use super::reader::*;
use super::*;
use sniffle_core::{LinkType, RawPacket, Session, SniffError, SniffRaw};
use std::time::{Duration, SystemTime};

pub struct Sniffer<F: std::io::BufRead> {
    reader: Reader<F>,
    buf: Vec<u8>,
}

pub type FileSniffer = Sniffer<std::io::BufReader<std::fs::File>>;

impl<F: std::io::BufRead> Sniffer<F> {
    pub fn new_raw(file: F) -> Result<Self, SniffError> {
        Ok(Self {
            reader: Reader::new(file)?,
            buf: Vec::new(),
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
        Ok(FileSniffer {
            reader: FileReader::open(path)?,
            buf: Vec::new(),
        })
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

    pub fn reader(&self) -> &Reader<F> {
        &self.reader
    }

    pub fn reader_mut(&mut self) -> &mut Reader<F> {
        &mut self.reader
    }
}

impl<F: std::io::BufRead> SniffRaw for Sniffer<F> {
    fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError> {
        let mut buf = std::mem::take(&mut self.buf);
        let hdr = match self.reader.next_record(&mut buf)? {
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
