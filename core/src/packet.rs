#![allow(clippy::len_without_is_empty)]

use super::{AnyPDU, Device, Dump, DumpValue, Dumper, PDUExt, Virtual, PDU};
use std::time::SystemTime;

pub struct Packet {
    ts: SystemTime,
    pdu: AnyPDU,
    len: usize,
    snaplen: usize,
    dev: Option<std::sync::Arc<Device>>,
}

impl Packet {
    pub fn new<P: PDU>(
        timestamp: SystemTime,
        pdu: P,
        length: Option<usize>,
        snaplen: Option<usize>,
        device: Option<std::sync::Arc<Device>>,
    ) -> Self {
        let len = length.unwrap_or_else(|| pdu.total_len());
        Self {
            ts: timestamp,
            pdu: AnyPDU::new(pdu),
            len,
            snaplen: snaplen.unwrap_or(65535),
            dev: device,
        }
    }

    pub fn pdu(&self) -> &AnyPDU {
        &self.pdu
    }

    pub fn pdu_mut(&mut self) -> &mut AnyPDU {
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
}

impl<P: PDU> From<P> for Packet {
    fn from(pdu: P) -> Self {
        Self::new(SystemTime::now(), pdu, None, None, None)
    }
}

impl From<Packet> for AnyPDU {
    fn from(pkt: Packet) -> Self {
        pkt.pdu
    }
}
