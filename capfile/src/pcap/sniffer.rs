use super::reader::*;
use super::*;
use sniffle_core::{LinkType, RawPacket, Session, Sniff, SniffError};
use std::time::{Duration, SystemTime};

pub struct Sniffer<F: std::io::BufRead> {
    reader: Reader<F>,
    session: Session,
    buf: Vec<u8>,
}

pub type FileSniffer = Sniffer<std::io::BufReader<std::fs::File>>;

impl<F: std::io::BufRead> Sniffer<F> {
    pub fn new(file: F, session: Option<Session>) -> Result<Self, SniffError> {
        Ok(Self {
            reader: Reader::new(file)?,
            session: session.unwrap_or_default(),
            buf: Vec::new(),
        })
    }

    pub fn open<P: AsRef<std::path::Path>>(
        path: P,
        session: Option<Session>,
    ) -> Result<FileSniffer, SniffError> {
        Ok(FileSniffer {
            reader: FileReader::open(path)?,
            session: session.unwrap_or_default(),
            buf: Vec::new(),
        })
    }

    pub fn reader(&self) -> &Reader<F> {
        &self.reader
    }

    pub fn reader_mut(&mut self) -> &mut Reader<F> {
        &mut self.reader
    }
}

impl<F: std::io::BufRead> Sniff for Sniffer<F> {
    fn session(&self) -> &Session {
        &self.session
    }

    fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    fn next_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError> {
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
                TSPrecision::Nano => SystemTime::UNIX_EPOCH
                    .checked_add(Duration::new(hdr.ts_sec as u64, hdr.ts_frac))
                    .unwrap_or(SystemTime::UNIX_EPOCH),
                TSPrecision::Micro => SystemTime::UNIX_EPOCH
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
