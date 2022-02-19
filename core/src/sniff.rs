use super::{AnyPDU, Device, LinkType, LinkTypeTable, Packet, RawPDU, Session};
use sniffle_ende::decode::DecodeError;
use std::time::SystemTime;
use thiserror::Error;

pub struct RawPacket<'a> {
    datalink: LinkType,
    ts: SystemTime,
    snaplen: usize,
    len: usize,
    data: &'a [u8],
    device: Option<std::rc::Rc<Device>>,
}

impl<'a> RawPacket<'a> {
    pub fn new(
        datalink: LinkType,
        timestamp: SystemTime,
        orig_len: usize,
        snaplen: Option<usize>,
        data: &'a [u8],
        device: Option<std::rc::Rc<Device>>,
    ) -> Self {
        Self {
            datalink,
            ts: timestamp,
            snaplen: snaplen.unwrap_or(65535),
            len: orig_len,
            data,
            device,
        }
    }

    pub fn datalink(&self) -> LinkType {
        self.datalink
    }

    pub fn timestamp(&self) -> SystemTime {
        self.ts
    }

    pub fn snaplen(&self) -> usize {
        self.snaplen
    }

    pub fn orig_len(&self) -> usize {
        self.len
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn device(&self) -> Option<&Device> {
        self.device.as_deref()
    }

    pub fn share_device(&self) -> Option<std::rc::Rc<Device>> {
        self.device.clone()
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SniffError {
    #[error("Malformed capture")]
    MalformedCapture,
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[cfg(feature = "pcaprs")]
    #[error(transparent)]
    Pcap(#[from] pcaprs::PcapError),
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + 'static>),
}

pub trait Sniff: Sized {
    fn next_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError>;

    fn session(&self) -> &Session;
    fn session_mut(&mut self) -> &mut Session;

    fn sniff(&mut self) -> Result<Option<Packet>, SniffError> {
        let session = std::mem::replace(self.session_mut(), Session::new_from_scratch());
        let ret = match self.next_raw()? {
            Some(pkt) => {
                let RawPacket {
                    datalink,
                    ts,
                    len,
                    snaplen,
                    data,
                    device,
                } = pkt;
                match session.table_dissect::<LinkTypeTable>(&datalink, data, None) {
                    Ok((_rem, Some(pdu))) => {
                        Ok(Some(Packet::new(ts, pdu, Some(len), Some(snaplen), device)))
                    }
                    Err(sniffle_ende::nom::Err::Error(DecodeError::NotSupported)) => {
                        panic!("Attempt to dissect PDU that doesn't support dissection")
                    }
                    Err(sniffle_ende::nom::Err::Failure(DecodeError::NotSupported)) => {
                        panic!("Attempt to dissect PDU that doesn't support dissection")
                    }
                    _ => Ok(Some(Packet::new(
                        ts,
                        AnyPDU::new(RawPDU::new(Vec::from(data))),
                        Some(len),
                        Some(snaplen),
                        device,
                    ))),
                }
            }
            None => Ok(None),
        };
        let _ = std::mem::replace(self.session_mut(), session);
        ret
    }

    fn iter(&mut self) -> SniffIter<'_, Self> {
        SniffIter(self)
    }
}

pub struct SniffIter<'a, S: Sniff>(&'a mut S);

impl<'a, S: Sniff> Iterator for SniffIter<'a, S> {
    type Item = Result<Packet, SniffError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.sniff() {
            Ok(res) => res.map(Ok),
            Err(e) => Some(Err(e)),
        }
    }
}
