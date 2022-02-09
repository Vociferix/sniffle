use super::reader::*;
use sniffle_core::{
    Device, DeviceBuilder, DeviceIPv4, DeviceIPv6, LinkType, RawPacket, Session, Sniff, SniffError,
};
use std::io::{BufRead, Seek};
use std::time::{Duration, SystemTime};

struct Iface {
    device: std::rc::Rc<Device>,
    link: LinkType,
    snaplen: u32,
    tsresol: u8,
    tsoffset: i64,
}

pub struct Sniffer<F: BufRead + Seek> {
    file: Reader<F>,
    session: Session,
    ifaces: Vec<Iface>,
    buf: Vec<u8>,
}

pub type FileSniffer = Sniffer<std::io::BufReader<std::fs::File>>;

fn ts_calc(ts: u64, tsresol: u8, tsoffset: i64) -> SystemTime {
    let (secs, nanos) = if (tsresol & 0b1000_0000) == 0 {
        let mut mag: u64 = 1;
        for _ in 0..tsresol {
            mag *= 10;
        }
        let ts_secs = ts / mag;
        (ts_secs, (ts - (ts_secs * mag)) * 1_000_000_000 / mag)
    } else {
        let tsresol = tsresol & 0b0111_1111;
        let ts_secs = ts >> tsresol;
        let ts_frac = ts & !(u64::MAX << tsresol);
        (
            ts_secs,
            (ts_frac * 1_000_000_000 / (1u64 << tsresol)) as u64,
        )
    };
    let secs = if tsoffset < 0 {
        match tsoffset.checked_neg() {
            Some(tsoffset) => match u64::try_from(tsoffset) {
                Ok(tsoffset) => secs.saturating_sub(tsoffset),
                Err(_) => 0,
            },
            None => 0,
        }
    } else {
        match u64::try_from(tsoffset) {
            Ok(tsoffset) => secs.saturating_add(tsoffset),
            Err(_) => u64::MAX,
        }
    };
    SystemTime::UNIX_EPOCH + Duration::new(secs, nanos as u32)
}

impl<F: BufRead + Seek> Sniffer<F> {
    pub fn new(file: F, session: Option<Session>) -> Result<Self, SniffError> {
        Ok(Self::init(Reader::new(file)?, session))
    }

    pub fn open<P: AsRef<std::path::Path>>(
        path: P,
        session: Option<Session>,
    ) -> Result<FileSniffer, SniffError> {
        Ok(FileSniffer::init(FileReader::open(path)?, session))
    }

    fn init(file: Reader<F>, session: Option<Session>) -> Self {
        Self {
            file,
            session: session.unwrap_or_else(|| Session::new()),
            ifaces: Vec::new(),
            buf: Vec::new(),
        }
    }
}

impl<F: BufRead + Seek> Sniff for Sniffer<F> {
    fn next_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError> {
        loop {
            match self.file.next_block()? {
                Some(block) => match block {
                    Block::SHB(_) => {
                        self.ifaces.clear();
                    }
                    Block::IDB(mut idb) => {
                        let mut bldr = DeviceBuilder::new();
                        let mut tsresol = 6u8;
                        let mut tsoffset = 0i64;
                        while let Some(opt) = idb.next_option()? {
                            match opt {
                                IDBOption::Name(mut opt) => {
                                    let mut name = String::new();
                                    opt.string(&mut name)?;
                                    bldr.name(name);
                                }
                                IDBOption::Description(mut opt) => {
                                    let mut desc = String::new();
                                    opt.string(&mut desc)?;
                                    bldr.description(desc);
                                }
                                IDBOption::IPv4(mut opt) => {
                                    bldr.add_ipv4(DeviceIPv4::new(
                                        opt.address()?,
                                        Some(opt.netmask()?),
                                        None,
                                        None,
                                    ));
                                }
                                IDBOption::IPv6(mut opt) => {
                                    bldr.add_ipv6(DeviceIPv6::new(
                                        opt.address()?,
                                        Some(opt.prefix_length()? as u32),
                                    ));
                                }
                                IDBOption::MAC(mut opt) => {
                                    bldr.add_mac(opt.address()?);
                                }
                                IDBOption::TSResol(mut opt) => {
                                    tsresol = opt.value()?;
                                }
                                IDBOption::TSOffset(mut opt) => {
                                    tsoffset = opt.value()?;
                                }
                                _ => {}
                            }
                        }
                        let link = LinkType(idb.link_type()?);
                        let snaplen = idb.snaplen()?;
                        let _ = idb;
                        self.ifaces.push(Iface {
                            device: std::rc::Rc::new(bldr.into_device()),
                            link,
                            snaplen,
                            tsresol,
                            tsoffset,
                        });
                    }
                    Block::EPB(mut epb) => {
                        let iface_id = epb.interface_id()? as usize;
                        let tsresol = self.ifaces[iface_id].tsresol;
                        let tsoffset = self.ifaces[iface_id].tsoffset;
                        let link = self.ifaces[iface_id].link;
                        let snaplen = self.ifaces[iface_id].snaplen;
                        let device = self.ifaces[iface_id].device.clone();
                        let ts = ts_calc(epb.timestamp()?, tsresol, tsoffset);
                        let orig_len = epb.original_length()?;
                        epb.packet_data(&mut self.buf)?;
                        break Ok(Some(RawPacket::new(
                            link,
                            ts,
                            orig_len as usize,
                            Some(snaplen as usize),
                            &self.buf[..],
                            Some(device),
                        )));
                    }
                    Block::SPB(mut spb) => {
                        let link = self.ifaces[0].link;
                        let snaplen = self.ifaces[0].snaplen;
                        let device = self.ifaces[0].device.clone();
                        let orig_len = spb.original_length()?;
                        spb.packet_data(&mut self.buf)?;
                        break Ok(Some(RawPacket::new(
                            link,
                            SystemTime::UNIX_EPOCH,
                            orig_len as usize,
                            Some(snaplen as usize),
                            &self.buf[..],
                            Some(device),
                        )));
                    }
                    _ => {}
                },
                None => {
                    break Ok(None);
                }
            }
        }
    }

    fn session(&self) -> &Session {
        &self.session
    }

    fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}
