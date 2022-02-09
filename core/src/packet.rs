use super::{AnyPDU, Device, PDU};
use std::time::SystemTime;

pub struct Packet {
    ts: SystemTime,
    pdu: AnyPDU,
    len: usize,
    snaplen: usize,
    dev: Option<std::rc::Rc<Device>>,
}

impl Packet {
    pub fn new<P: PDU>(
        timestamp: SystemTime,
        pdu: P,
        length: Option<usize>,
        snaplen: Option<usize>,
        device: Option<std::rc::Rc<Device>>,
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
        self.dev.as_ref().map(|dev| &**dev)
    }

    pub fn share_device(&self) -> Option<std::rc::Rc<Device>> {
        self.dev.clone()
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
