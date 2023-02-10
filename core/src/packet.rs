#![allow(clippy::len_without_is_empty)]

use super::{AnyPdu, Device, Dump, DumpValue, Dumper, Pdu, PduExt, Virtual, RawPacket, Error, LinkType};
use sniffle_ende::encode::Encoder;
use std::time::SystemTime;

#[derive(Clone)]
pub struct Packet {
    ts: SystemTime,
    pdu: AnyPdu,
    len: usize,
    snaplen: usize,
    dev: Option<std::sync::Arc<Device>>,
}

impl Packet {
    pub fn new<P: Pdu>(
        timestamp: SystemTime,
        pdu: P,
        length: Option<usize>,
        snaplen: Option<usize>,
        device: Option<std::sync::Arc<Device>>,
    ) -> Self {
        let len = length.unwrap_or_else(|| pdu.total_len());
        Self {
            ts: timestamp,
            pdu: AnyPdu::new(pdu),
            len,
            snaplen: snaplen.unwrap_or(65535),
            dev: device,
        }
    }

    pub fn pdu(&self) -> &AnyPdu {
        &self.pdu
    }

    pub fn pdu_mut(&mut self) -> &mut AnyPdu {
        &mut self.pdu
    }

    pub fn snaplen(&self) -> usize {
        self.snaplen
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn timestamp(&self) -> SystemTime {
        self.ts
    }

    pub fn device(&self) -> Option<&Device> {
        self.dev.as_deref()
    }

    pub fn share_device(&self) -> Option<std::sync::Arc<Device>> {
        self.dev.clone()
    }

    pub fn is_virtual(&self) -> bool {
        self.pdu.is::<Virtual>()
    }

    pub fn datalink(&self) -> Option<LinkType> {
        LinkType::from_pdu(&self.pdu)
    }

    pub fn serialize<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.pdu.serialize(encoder)
    }

    pub fn make_canonical(&mut self) {
        self.pdu.make_all_canonical();
    }

    pub fn dump<D: Dump>(&self, dumper: &mut Dumper<D>) -> Result<(), D::Error> {
        let mut node = dumper.add_packet()?;
        node.add_field("Timestamp", DumpValue::Time(self.ts), None)?;
        let mut capnode = node.add_node("Capture", None)?;
        if let Ok(len) = self.len.try_into() {
            capnode.add_field("Length", DumpValue::UInt(len), None)?;
        }
        if let Ok(caplen) = self.pdu.total_len().try_into() {
            capnode.add_field("Capture Length", DumpValue::UInt(caplen), None)?;
        }
        if let Ok(snaplen) = self.snaplen.try_into() {
            capnode.add_field("Snap Length", DumpValue::UInt(snaplen), None)?;
        }
        if let Some(dev) = self.device() {
            if dev.name().is_empty() {
                if let Some(descr) = dev.description() {
                    if !descr.is_empty() {
                        capnode.add_info("Interface", descr)?;
                    }
                }
            } else {
                capnode.add_info("Interface", dev.name())?;
            }
        }
        drop(capnode);
        let mut pdu = self.pdu();
        loop {
            pdu.dump(&mut node)?;
            let next = pdu.inner_pdu();
            pdu = match next {
                Some(next) => next,
                None => {
                    return Ok(());
                }
            }
        }
    }

    pub fn find<P: Pdu>(&self) -> Option<&P> {
        self.pdu.find::<P>()
    }

    pub fn find_mut<P: Pdu>(&mut self) -> Option<&mut P> {
        self.pdu.find_mut::<P>()
    }

    pub fn into_pdu(self) -> AnyPdu {
        self.pdu
    }

    pub fn make_raw<'a>(&self, buf: &'a mut Vec<u8>) -> Result<RawPacket<'a>, Error> {
        let link_type = match self.datalink() {
            Some(link_type) => link_type,
            None => {
                return Err(Error::UnknownLinkType);
            }
        };
        self.make_raw_with_datalink(buf, link_type)
    }

    pub fn make_raw_with_datalink<'a>(&self, buf: &'a mut Vec<u8>, datalink: LinkType) -> Result<RawPacket<'a>, Error> {
        buf.clear();
        self.serialize(buf)?;
        Ok(RawPacket::new(
            datalink,
            self.ts,
            self.snaplen,
            Some(self.len),
            &buf[..],
            self.dev.clone()
        ))
    }
}

impl<P: Pdu> From<P> for Packet {
    fn from(pdu: P) -> Self {
        Self::new(SystemTime::now(), pdu, None, None, None)
    }
}

impl From<Packet> for AnyPdu {
    fn from(pkt: Packet) -> Self {
        pkt.pdu
    }
}
