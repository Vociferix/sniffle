use super::writer::*;
use super::*;
use sniffle_core::{Device, LinkType, Packet, Transmit, TransmitError, PDU};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::time::SystemTime;

struct IfaceKey {
    iface: Option<Device>,
    link_type: LinkType,
    snaplen: u32,
}

struct IfaceInfo {
    id: u32,
    ts_offset: i64,
}

pub struct Recorder<F: std::io::Write + std::io::Seek> {
    writer: Writer<F>,
    ifaces: HashMap<IfaceKey, IfaceInfo>,
    buf: Vec<u8>,
}

pub type FileRecorder = Recorder<std::io::BufWriter<std::fs::File>>;

impl Hash for IfaceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.iface
            .as_ref()
            .map(|iface| iface.name())
            .unwrap_or("")
            .hash(state);
        self.link_type.0.hash(state);
        self.snaplen.hash(state);
    }
}

impl PartialEq for IfaceKey {
    fn eq(&self, other: &Self) -> bool {
        self.iface.as_ref().map(|iface| iface.name())
            == other.iface.as_ref().map(|iface| iface.name())
            && self.link_type == other.link_type
            && self.snaplen == other.snaplen
    }
}

impl Eq for IfaceKey {}

impl<F: std::io::Write + std::io::Seek> Recorder<F> {
    pub fn new(file: F) -> Result<Self, TransmitError> {
        let mut writer = Writer::new(file);
        writer
            .write_shb(0x01020304u32.to_ne_bytes() == [1, 2, 3, 4], 1, 0)?
            .finish()?;
        Ok(Self {
            writer,
            ifaces: HashMap::new(),
            buf: Vec::new(),
        })
    }

    pub fn create<P: AsRef<std::path::Path>>(path: P) -> Result<FileRecorder, TransmitError> {
        FileRecorder::new(std::io::BufWriter::new(std::fs::File::create(path)?))
    }

    fn write_iface(
        &mut self,
        packet: &Packet,
        link_type: LinkType,
        ts_offset: i64,
    ) -> Result<(), TransmitError> {
        let mut opts = self
            .writer
            .write_idb(link_type.0, packet.snaplen() as u32)?;
        if let Some(dev) = packet.device() {
            opts.write_name(dev.name())?;
            if let Some(desc) = dev.description() {
                opts.write_description(desc)?;
            }
            for addr in dev.ipv4_addresses() {
                opts.write_ipv4_address(
                    *addr.address(),
                    addr.netmask()
                        .copied()
                        .unwrap_or_else(|| IPv4Address::from([0xFF, 0xFF, 0xFF, 0xFF])),
                )?;
            }
            for addr in dev.ipv6_addresses() {
                opts.write_ipv6_address(*addr.address(), addr.prefix_length().unwrap_or(0) as u8)?;
            }
            for addr in dev.mac_addresses() {
                opts.write_mac_address(*addr)?;
            }
        }
        opts.write_tsoffset(ts_offset)?;
        opts.write_tsresol(9)?;
        opts.finish()
    }
}

impl<F: std::io::Write + std::io::Seek> Transmit for Recorder<F> {
    fn transmit(&mut self, packet: &Packet) -> Result<(), TransmitError> {
        let link_type = match LinkType::from_pdu(packet.pdu()) {
            Some(link) => link,
            None => {
                return Err(TransmitError::UnknownLinkType);
            }
        };

        let iface = IfaceKey {
            iface: packet.device().cloned(),
            link_type,
            snaplen: packet.snaplen() as u32,
        };
        let next_id = self.ifaces.len() as u32;
        let iface_info = self.ifaces.entry(iface).or_insert(IfaceInfo {
            id: next_id,
            ts_offset: 0,
        });
        let id = iface_info.id;

        let ts = if id == next_id {
            let (ts_offset, ts) = match packet.timestamp().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos() as u64),
                Err(e) => {
                    let dur = e.duration();
                    let secs = dur.as_secs();
                    let nanos = dur.subsec_nanos() as u64;
                    if nanos > 0 {
                        (-(secs as i64) - 1, 1_000_000_000 - nanos)
                    } else {
                        (-(secs as i64), 0)
                    }
                }
            };
            iface_info.ts_offset = ts_offset;
            let _ = iface_info;
            self.write_iface(packet, link_type, ts_offset)?;
            ts
        } else {
            let ts = match packet.timestamp().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(dur) => {
                    ((dur.as_secs() as i64 - iface_info.ts_offset) as u64 * 1_000_000_000)
                        + (dur.subsec_nanos() as u64)
                }
                Err(e) => {
                    let dur = e.duration();
                    let secs = (-(dur.as_secs() as i64) - iface_info.ts_offset) as u64;
                    let nanos = dur.subsec_nanos() as u64;
                    if nanos > 0 {
                        ((secs - 1) * 1_000_000_000) + (1_000_000_000 - nanos)
                    } else {
                        secs * 1_000_000_000
                    }
                }
            };
            let _ = iface_info;
            ts
        };

        let mut buf = std::mem::take(&mut self.buf);
        let mut data = self.writer.write_epb(id, ts)?;
        packet.pdu().serialize(&mut buf)?;
        data.write_all(&buf[..])?;
        data.finish()?;
        self.buf = buf;
        Ok(())
    }
}
