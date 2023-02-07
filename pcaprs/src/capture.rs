use super::*;

#[derive(Debug, Clone)]
pub struct Stats(pcap_stat);

pub struct Packet<'a> {
    pub(crate) pcap: &'a mut Pcap,
    pub(crate) datalink: LinkType,
    pub(crate) ts: SystemTime,
    pub(crate) len: u32,
    pub(crate) data: &'a [u8],
}

pub trait Capture: Sized {
    fn pcap(&self) -> &Pcap;
    fn pcap_mut(&mut self) -> &mut Pcap;

    fn snaplen(&self) -> Result<u32> {
        unsafe {
            let snaplen = pcap_snapshot(self.pcap().raw_handle().as_ptr());
            if snaplen < 0 {
                Err(PcapError::NotActivated)
            } else {
                Ok(snaplen as u32)
            }
        }
    }

    #[cfg(feature = "npcap")]
    fn buffer_size(&self) -> Result<u32> {
        unsafe {
            let bufsize = pcap_bufsize(self.pcap().raw_handle().as_ptr());
            if bufsize < 0 {
                Err(PcapError::NotActivated)
            } else {
                Ok(bufsize as u32)
            }
        }
    }

    #[cfg(feature = "npcap")]
    fn timestamp_precision(&self) -> TsPrecision {
        unsafe {
            if pcap_get_tstamp_precision(self.pcap().raw_handle().as_ptr())
                == PCAP_TSTAMP_PRECISION_MICRO as i32
            {
                TsPrecision::Micro
            } else {
                TsPrecision::Nano
            }
        }
    }

    #[cfg(not(feature = "npcap"))]
    fn timestamp_precision(&self) -> TsPrecision {
        TsPrecision::Micro
    }

    fn set_direction(&mut self, direction: Direction) -> Result<()> {
        let direction = match direction {
            Direction::In => PCAP_D_IN,
            Direction::Out => PCAP_D_OUT,
            Direction::InOut => PCAP_D_INOUT,
        };
        unsafe {
            if pcap_setdirection(self.pcap().raw_handle().as_ptr(), direction) != 0 {
                Err(PcapError::General(make_string(pcap_geterr(
                    self.pcap().raw_handle().as_ptr(),
                ))))
            } else {
                Ok(())
            }
        }
    }

    fn link_type(&self) -> Result<LinkType> {
        unsafe {
            let datalink = pcap_datalink(self.pcap().raw_handle().as_ptr());
            if datalink < 0 {
                Err(PcapError::NotActivated)
            } else {
                Ok(LinkType(datalink as u16))
            }
        }
    }

    fn stats(&self) -> Result<Stats> {
        let mut stats = pcap_stat::default();
        unsafe {
            if pcap_stats(
                self.pcap().raw_handle().as_ptr(),
                (&mut stats) as *mut pcap_stat,
            ) != 0
            {
                return Err(PcapError::General(make_string(pcap_geterr(
                    self.pcap().raw_handle().as_ptr(),
                ))));
            }
        }
        Ok(Stats(stats))
    }

    fn next_packet(&mut self) -> Option<Result<Packet<'_>>> {
        unsafe {
            let mut data: *const u8 = std::ptr::null_mut();
            let mut hdr: *mut pcap_pkthdr = std::ptr::null_mut();
            let datalink = pcap_datalink(self.pcap().raw_handle().as_ptr());
            if datalink < 0 {
                return Some(Err(PcapError::NotActivated));
            }
            let datalink = LinkType(datalink as u16);
            loop {
                match pcap_next_ex(
                    self.pcap().raw_handle().as_ptr(),
                    (&mut hdr) as *mut *mut pcap_pkthdr,
                    (&mut data) as *mut *const libc::c_uchar,
                ) {
                    0 => {}
                    1 => {
                        break;
                    }
                    PCAP_ERROR_BREAK => {
                        return None;
                    }
                    _ => {
                        return Some(Err(PcapError::General(make_string(pcap_geterr(
                            self.pcap().raw_handle().as_ptr(),
                        )))));
                    }
                }
            }
            let hdr = &*hdr;
            let data = std::slice::from_raw_parts(data, hdr.caplen as usize);
            let ts = match self.timestamp_precision() {
                TsPrecision::Micro => {
                    std::time::UNIX_EPOCH
                        + Duration::new(hdr.ts.tv_sec as u64, (hdr.ts.tv_usec as u32) * 1000)
                }
                TsPrecision::Nano => {
                    std::time::UNIX_EPOCH
                        + Duration::new(hdr.ts.tv_sec as u64, hdr.ts.tv_usec as u32)
                }
            };
            Some(Ok(Packet {
                pcap: self.pcap_mut(),
                datalink,
                ts,
                len: hdr.len,
                data,
            }))
        }
    }
}

impl Stats {
    pub fn received(&self) -> u32 {
        self.0.ps_recv
    }

    pub fn dropped(&self) -> u32 {
        self.0.ps_drop
    }

    pub fn iface_dropped(&self) -> u32 {
        self.0.ps_ifdrop
    }

    #[cfg(windows)]
    pub fn captured(&self) -> u32 {
        self.0.ps_capt
    }

    #[cfg(windows)]
    pub fn sent(&self) -> u32 {
        self.0.ps_sent
    }

    #[cfg(windows)]
    pub fn lost(&self) -> u32 {
        self.0.ps_netdrop
    }
}

impl<'a> Packet<'a> {
    pub fn pcap<'b: 'a>(&'b self) -> &'a Pcap {
        self.pcap
    }

    pub fn datalink(&self) -> LinkType {
        self.datalink
    }

    pub fn timestamp(&self) -> SystemTime {
        self.ts
    }

    pub fn orig_len(&self) -> u32 {
        self.len
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}
