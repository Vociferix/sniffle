use super::{AnyPDU, Device, LinkType, LinkTypeTable, Packet, RawPDU, Session};
use std::time::SystemTime;
use thiserror::Error;

pub struct RawPacket<'a> {
    datalink: LinkType,
    ts: SystemTime,
    snaplen: usize,
    len: usize,
    data: &'a [u8],
    device: Option<std::sync::Arc<Device>>,
}

impl<'a> RawPacket<'a> {
    pub fn new(
        datalink: LinkType,
        timestamp: SystemTime,
        orig_len: usize,
        snaplen: Option<usize>,
        data: &'a [u8],
        device: Option<std::sync::Arc<Device>>,
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

    pub fn share_device(&self) -> Option<std::sync::Arc<Device>> {
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

pub trait SniffRaw {
    fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError>;
}

pub trait Sniff {
    fn sniff(&mut self) -> Result<Option<Packet>, SniffError>;

    fn iter(&mut self) -> SniffIter<'_, Self> {
        SniffIter(self)
    }
}

pub struct Sniffer<S: SniffRaw> {
    raw_sniffer: S,
    session: Session,
}

#[repr(transparent)]
pub struct SniffIter<'a, S: Sniff + ?Sized>(&'a mut S);

impl<S: SniffRaw> Sniffer<S> {
    pub fn new(raw_sniffer: S) -> Self {
        Self {
            raw_sniffer,
            session: Session::default(),
        }
    }

    pub fn with_session(raw_sniffer: S, session: Session) -> Self {
        Self {
            raw_sniffer,
            session,
        }
    }

    pub fn into_raw(self) -> S {
        self.raw_sniffer
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

impl<S: SniffRaw> Sniff for Sniffer<S> {
    fn sniff(&mut self) -> Result<Option<Packet>, SniffError> {
        let session = std::mem::replace(&mut self.session, Session::new_from_scratch());
        if let Some(pdu) = session.next_virtual_packet() {
            let ret = Ok(Some(session.last_info(move |info| {
                Packet::new(info.ts, pdu, None, Some(info.snaplen), info.dev.clone())
            })));
            let _ = std::mem::replace(self.session_mut(), session);
            return ret;
        }
        let ret = match self.raw_sniffer.sniff_raw()? {
            Some(pkt) => {
                let RawPacket {
                    datalink,
                    ts,
                    len,
                    snaplen,
                    data,
                    device,
                } = pkt;
                session.last_info_mut(|info| {
                    info.ts = ts;
                    info.dev = device.clone();
                    info.snaplen = snaplen;
                });
                match session.table_dissect::<LinkTypeTable>(&datalink, data, None) {
                    Ok((_rem, pdu)) => {
                        Ok(Some(Packet::new(ts, pdu, Some(len), Some(snaplen), device)))
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
}

impl<'a, S: Sniff> Iterator for SniffIter<'a, S> {
    type Item = Result<Packet, SniffError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.sniff() {
            Ok(Some(pkt)) => Some(Ok(pkt)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<S: SniffRaw> Sniff for S {
    fn sniff(&mut self) -> Result<Option<Packet>, SniffError> {
        Ok(self.sniff_raw()?.map(|pkt| {
            Packet::new(
                pkt.ts,
                AnyPDU::new(RawPDU::new(Vec::from(pkt.data))),
                Some(pkt.len),
                Some(pkt.snaplen),
                pkt.device,
            )
        }))
    }
}
