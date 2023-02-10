use super::{AnyPdu, Device, Error, LinkType, LinkTypeTable, Packet, RawPdu, Session};
use async_trait::async_trait;
use std::time::SystemTime;

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

#[async_trait]
pub trait SniffRaw: Send {
    async fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, Error>;
}

#[async_trait]
pub trait Sniff: Send {
    async fn sniff(&mut self) -> Result<Option<Packet>, Error>;
}

pub struct Sniffer<S: SniffRaw> {
    raw_sniffer: S,
    session: Session,
}

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

async fn sniff_impl<S: SniffRaw>(
    sniffer: &mut Sniffer<S>,
    session: &Session,
    last_info: &mut super::session::LastInfo,
) -> Result<Option<Packet>, Error> {
    if let Some(pkt) = sniffer.raw_sniffer.sniff_raw().await? {
        let RawPacket {
            datalink,
            ts,
            len,
            snaplen,
            data,
            device,
        } = pkt;
        last_info.ts = ts;
        last_info.dev = device.clone();
        last_info.snaplen = snaplen;
        match session.table_dissect::<LinkTypeTable>(&datalink, data, None) {
            Ok((_rem, pdu)) => Ok(Some(Packet::new(ts, pdu, Some(len), Some(snaplen), device))),
            _ => Ok(Some(Packet::new(
                ts,
                AnyPdu::new(RawPdu::new(Vec::from(data))),
                Some(len),
                Some(snaplen),
                device,
            ))),
        }
    } else {
        Ok(None)
    }
}

#[async_trait]
impl<S: SniffRaw> Sniff for Sniffer<S> {
    async fn sniff(&mut self) -> Result<Option<Packet>, Error> {
        let session = std::mem::replace(&mut self.session, Session::new_from_scratch());
        if let Some(pdu) = session.next_virtual_packet().await {
            let ret = Ok(Some(
                session
                    .last_info(move |info| {
                        Packet::new(info.ts, pdu, None, Some(info.snaplen), info.dev.clone())
                    })
                    .await,
            ));
            let _ = std::mem::replace(self.session_mut(), session);
            return ret;
        }

        let mut last_info = super::session::LastInfo {
            ts: SystemTime::UNIX_EPOCH,
            dev: None,
            snaplen: 0,
        };
        let ret = sniff_impl(self, &session, &mut last_info).await;
        session
            .last_info_mut(move |info| {
                *info = last_info;
            })
            .await;
        let _ = std::mem::replace(self.session_mut(), session);
        ret
    }
}

#[async_trait]
impl<S: SniffRaw> Sniff for S {
    async fn sniff(&mut self) -> Result<Option<Packet>, Error> {
        Ok(self.sniff_raw().await?.map(|pkt| {
            Packet::new(
                pkt.ts,
                AnyPdu::new(RawPdu::new(Vec::from(pkt.data))),
                Some(pkt.len),
                Some(pkt.snaplen),
                pkt.device,
            )
        }))
    }
}
