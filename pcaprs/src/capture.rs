use super::*;

#[derive(Debug, Clone)]
pub struct Stats(pcap_stat);

pub struct Packet<'a> {
    pcap: &'a mut Pcap,
    datalink: LinkType,
    ts: SystemTime,
    len: u32,
    data: &'a [u8],
}

#[cfg(windows)]
pub trait AsEventHandle: std::os::windows::io::AsRawHandle {}

#[cfg(windows)]
impl<T: std::os::windows::io::AsRawHandle> AsEventHandle for T {}

#[cfg(unix)]
pub trait AsEventHandle: std::os::unix::io::AsRawFd {}

#[cfg(unix)]
impl<T: std::os::unix::io::AsRawFd> AsEventHandle for T {}

#[cfg(not(any(windows, unix)))]
pub trait AsEventHandle {}

#[cfg(not(any(windows, unix)))]
impl<T> AsEventHandle for T {}

pub trait Capture: Sized + AsEventHandle {
    fn pcap(&self) -> &Pcap;
    fn pcap_mut(&mut self) -> &mut Pcap;

    fn snaplen(&self) -> Result<u32> {
        unsafe {
            let snaplen = pcap_snapshot(self.pcap().raw_handle());
            if snaplen < 0 {
                Err(PcapError::NotActivated)
            } else {
                Ok(snaplen as u32)
            }
        }
    }

    fn buffer_size(&self) -> Result<u32> {
        unsafe {
            let bufsize = pcap_bufsize(self.pcap().raw_handle());
            if bufsize < 0 {
                Err(PcapError::NotActivated)
            } else {
                Ok(bufsize as u32)
            }
        }
    }

    fn timestamp_precision(&self) -> TSPrecision {
        unsafe {
            if pcap_get_tstamp_precision(self.pcap().raw_handle())
                == PCAP_TSTAMP_PRECISION_MICRO as i32
            {
                TSPrecision::Micro
            } else {
                TSPrecision::Nano
            }
        }
    }

    fn set_direction(&mut self, direction: Direction) -> Result<()> {
        let direction = match direction {
            Direction::In => PCAP_D_IN,
            Direction::Out => PCAP_D_OUT,
            Direction::InOut => PCAP_D_INOUT,
        };
        unsafe {
            if pcap_setdirection(self.pcap().raw_handle(), direction) != 0 {
                Err(PcapError::General(make_string(pcap_geterr(
                    self.pcap().raw_handle(),
                ))))
            } else {
                Ok(())
            }
        }
    }

    fn set_nonblocking(&mut self, enable: bool) -> Result<()> {
        let enable = if enable { 1 } else { 0 };
        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            if pcap_setnonblock(self.pcap().raw_handle(), enable, errbuf_ptr) != 0 {
                Err(PcapError::General(make_string(errbuf_ptr)))
            } else {
                Ok(())
            }
        }
    }

    fn is_nonblocking(&self) -> Result<bool> {
        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            let ret = pcap_getnonblock(self.pcap().raw_handle(), errbuf_ptr);
            if ret < 0 {
                Err(PcapError::General(make_string(errbuf_ptr)))
            } else {
                Ok(ret != 0)
            }
        }
    }

    fn link_type(&self) -> Result<LinkType> {
        unsafe {
            let datalink = pcap_datalink(self.pcap().raw_handle());
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
            if pcap_stats(self.pcap().raw_handle(), (&mut stats) as *mut pcap_stat) != 0 {
                return Err(PcapError::General(make_string(pcap_geterr(
                    self.pcap().raw_handle(),
                ))));
            }
        }
        Ok(Stats(stats))
    }

    fn try_next_packet<'a>(&'a mut self) -> Option<Result<Option<Packet<'a>>>> {
        unsafe {
            let mut data: *const u8 = std::ptr::null_mut();
            let mut hdr: *mut pcap_pkthdr = std::ptr::null_mut();
            let datalink = pcap_datalink(self.pcap().raw_handle());
            if datalink < 0 {
                return Some(Err(PcapError::NotActivated));
            }
            let datalink = LinkType(datalink as u16);
            match pcap_next_ex(
                self.pcap().raw_handle(),
                (&mut hdr) as *mut *mut pcap_pkthdr,
                (&mut data) as *mut *const libc::c_uchar,
            ) {
                0 => {
                    return Some(Ok(None));
                }
                1 => {}
                PCAP_ERROR_BREAK => {
                    return None;
                }
                _ => {
                    return Some(Err(PcapError::General(make_string(pcap_geterr(
                        self.pcap().raw_handle(),
                    )))));
                }
            }
            let hdr = &*hdr;
            let data = std::slice::from_raw_parts(data, hdr.caplen as usize);
            let ts = if pcap_get_tstamp_precision(self.pcap().raw_handle())
                == PCAP_TSTAMP_PRECISION_MICRO as i32
            {
                std::time::UNIX_EPOCH
                    + Duration::new(hdr.ts.tv_sec as u64, (hdr.ts.tv_usec as u32) * 1000)
            } else {
                std::time::UNIX_EPOCH + Duration::new(hdr.ts.tv_sec as u64, hdr.ts.tv_usec as u32)
            };
            Some(Ok(Some(Packet {
                pcap: self.pcap_mut(),
                datalink,
                ts,
                len: hdr.len,
                data,
            })))
        }
    }

    fn next_packet<'a>(&'a mut self) -> Option<Result<Packet<'a>>> {
        unsafe {
            let mut data: *const u8 = std::ptr::null_mut();
            let mut hdr: *mut pcap_pkthdr = std::ptr::null_mut();
            let datalink = pcap_datalink(self.pcap().raw_handle());
            if datalink < 0 {
                return Some(Err(PcapError::NotActivated));
            }
            let datalink = LinkType(datalink as u16);
            loop {
                match pcap_next_ex(
                    self.pcap().raw_handle(),
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
                            self.pcap().raw_handle(),
                        )))));
                    }
                }
            }
            let hdr = &*hdr;
            let data = std::slice::from_raw_parts(data, hdr.caplen as usize);
            let ts = if pcap_get_tstamp_precision(self.pcap().raw_handle())
                == PCAP_TSTAMP_PRECISION_MICRO as i32
            {
                std::time::UNIX_EPOCH
                    + Duration::new(hdr.ts.tv_sec as u64, (hdr.ts.tv_usec as u32) * 1000)
            } else {
                std::time::UNIX_EPOCH + Duration::new(hdr.ts.tv_sec as u64, hdr.ts.tv_usec as u32)
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
