use super::reader::*;
use async_trait::async_trait;
use sniffle_core::{
    Device, DeviceBuilder, DeviceIpv4, DeviceIpv6, Error, LinkType, RawPacket, Session, SniffRaw,
};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufRead, AsyncSeek};

struct Iface {
    device: std::sync::Arc<Device>,
    link: LinkType,
    snaplen: u32,
    tsresol: u8,
    tsoffset: i64,
}

pub struct Sniffer<F: AsyncBufRead + AsyncSeek + Send + Unpin> {
    file: Reader<F>,
    ifaces: Vec<Iface>,
    buf: Vec<u8>,
}

pub type FileSniffer = Sniffer<tokio::io::BufReader<tokio::fs::File>>;

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
            ts_frac * 1_000_000_000 / (1u64 << tsresol),
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

impl<F: AsyncBufRead + AsyncSeek + Send + Unpin> Sniffer<F> {
    pub async fn new_raw(file: F) -> Result<Self, Error> {
        Ok(Self {
            file: Reader::new(file).await?,
            ifaces: Vec::new(),
            buf: Vec::new(),
        })
    }

    pub async fn new(file: F) -> Result<sniffle_core::Sniffer<Self>, Error> {
        Ok(sniffle_core::Sniffer::new(Self::new_raw(file).await?))
    }

    pub async fn new_with_session(
        file: F,
        session: Session,
    ) -> Result<sniffle_core::Sniffer<Self>, Error> {
        Ok(sniffle_core::Sniffer::with_session(
            Self::new_raw(file).await?,
            session,
        ))
    }

    pub async fn open_raw<P: AsRef<std::path::Path>>(path: P) -> Result<FileSniffer, Error> {
        Ok(FileSniffer {
            file: FileReader::open(path).await?,
            ifaces: Vec::new(),
            buf: Vec::new(),
        })
    }

    pub async fn open<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<sniffle_core::Sniffer<FileSniffer>, Error> {
        Ok(sniffle_core::Sniffer::new(Self::open_raw(path).await?))
    }

    pub async fn open_with_session<P: AsRef<std::path::Path>>(
        path: P,
        session: Session,
    ) -> Result<sniffle_core::Sniffer<FileSniffer>, Error> {
        Ok(sniffle_core::Sniffer::with_session(
            Self::open_raw(path).await?,
            session,
        ))
    }
}

#[async_trait]
impl<F: AsyncBufRead + AsyncSeek + Send + Unpin> SniffRaw for Sniffer<F> {
    async fn sniff_raw(&mut self) -> Result<Option<RawPacket<'_>>, Error> {
        loop {
            match self.file.next_block().await? {
                Some(block) => match block {
                    Block::Shb(_) => {
                        self.ifaces.clear();
                    }
                    Block::Idb(mut idb) => {
                        let mut bldr = DeviceBuilder::new();
                        let mut tsresol = 6u8;
                        let mut tsoffset = 0i64;
                        while let Some(opt) = idb.next_option().await? {
                            match opt {
                                IdbOption::Name(mut opt) => {
                                    let mut name = String::new();
                                    opt.string(&mut name).await?;
                                    bldr.name(name);
                                }
                                IdbOption::Description(mut opt) => {
                                    let mut desc = String::new();
                                    opt.string(&mut desc).await?;
                                    bldr.description(desc);
                                }
                                IdbOption::Ipv4(mut opt) => {
                                    bldr.add_ipv4(DeviceIpv4::new(
                                        opt.address().await?,
                                        Some(opt.netmask().await?),
                                        None,
                                        None,
                                    ));
                                }
                                IdbOption::Ipv6(mut opt) => {
                                    bldr.add_ipv6(DeviceIpv6::new(
                                        opt.address().await?,
                                        Some(opt.prefix_length().await? as u32),
                                    ));
                                }
                                IdbOption::Mac(mut opt) => {
                                    bldr.add_mac(opt.address().await?);
                                }
                                IdbOption::TsResol(mut opt) => {
                                    tsresol = opt.value().await?;
                                }
                                IdbOption::TsOffset(mut opt) => {
                                    tsoffset = opt.value().await?;
                                }
                                _ => {}
                            }
                        }
                        let link = LinkType(idb.link_type().await?);
                        let snaplen = idb.snaplen().await?;
                        let _ = idb;
                        self.ifaces.push(Iface {
                            device: std::sync::Arc::new(bldr.into_device()),
                            link,
                            snaplen,
                            tsresol,
                            tsoffset,
                        });
                    }
                    Block::Epb(mut epb) => {
                        let iface_id = epb.interface_id().await? as usize;
                        let tsresol = self.ifaces[iface_id].tsresol;
                        let tsoffset = self.ifaces[iface_id].tsoffset;
                        let link = self.ifaces[iface_id].link;
                        let snaplen = self.ifaces[iface_id].snaplen;
                        let device = self.ifaces[iface_id].device.clone();
                        let ts = ts_calc(epb.timestamp().await?, tsresol, tsoffset);
                        let orig_len = epb.original_length().await?;
                        epb.packet_data(&mut self.buf).await?;
                        break Ok(Some(RawPacket::new(
                            link,
                            ts,
                            orig_len as usize,
                            Some(snaplen as usize),
                            &self.buf[..],
                            Some(device),
                        )));
                    }
                    Block::Spb(mut spb) => {
                        let link = self.ifaces[0].link;
                        let snaplen = self.ifaces[0].snaplen;
                        let device = self.ifaces[0].device.clone();
                        let orig_len = spb.original_length().await?;
                        spb.packet_data(&mut self.buf).await?;
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
}
