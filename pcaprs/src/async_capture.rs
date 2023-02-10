use super::*;

#[cfg(not(windows))]
use tokio::io::{unix::AsyncFd, Interest};

pub struct AsyncCapture<C: Capture> {
    cap: C,
    #[cfg(not(windows))]
    fd: AsyncFd<libc::c_int>,
}

#[cfg(windows)]
struct WaitHandle(usize);

#[cfg(windows)]
impl WaitHandle {
    fn wait(&self) -> Result<()> {
        unsafe {
            let handle = std::mem::transmute(self.0);
            loop {
                match winapi::um::synchapi::WaitForSingleObject(
                    handle,
                    winapi::um::winbase::INFINITE,
                ) {
                    winapi::um::winbase::WAIT_OBJECT_0 => {
                        break;
                    }
                    _ => {
                        return Err(PcapError::IO(std::io::Error::from_raw_os_error(
                            winapi::um::errhandlingapi::GetLastError(),
                        )));
                    }
                }
            }
            Ok(())
        }
    }
}

struct PktInfo {
    data: *const u8,
    hdr: *mut pcap_pkthdr,
}

unsafe impl Send for PktInfo {}

impl PktInfo {
    fn new() -> Self {
        Self {
            data: std::ptr::null_mut(),
            hdr: std::ptr::null_mut(),
        }
    }
}

impl<C: Capture> AsyncCapture<C> {
    pub fn new(mut capture: C) -> Result<Self> {
        capture.pcap_mut().set_nonblocking(true)?;
        #[cfg(not(windows))]
        let fd = unsafe {
            AsyncFd::with_interest(
                pcap_get_selectable_fd(capture.pcap().raw_handle().as_ptr()),
                Interest::READABLE,
            )?
        };
        Ok(Self {
            cap: capture,
            #[cfg(not(windows))]
            fd,
        })
    }

    pub fn into_inner(mut self) -> Result<C> {
        self.cap.pcap_mut().set_nonblocking(false)?;
        Ok(self.cap)
    }

    #[cfg(windows)]
    fn wait_handle(capture: &C) -> WaitHandle {
        unsafe {
            WaitHandle(std::mem::transmute(pcap_getevent(
                capture.pcap().raw_handle().as_ptr(),
            )))
        }
    }

    pub async fn wait_for_packets(&self) -> Result<()> {
        #[cfg(windows)]
        {
            let wh = Self::wait_handle(&self.cap);
            tokio::task::spawn_blocking(move || wh.wait())
                .await
                .unwrap()
        }

        #[cfg(not(windows))]
        Ok(self.fd.readable().await?.retain_ready())
    }

    pub async fn next_packet<'a>(&'a mut self) -> Option<Result<Packet<'a>>> {
        unsafe {
            let mut pkt_info = PktInfo::new();
            let datalink = pcap_datalink(self.cap.pcap().raw_handle().as_ptr());
            if datalink < 0 {
                return Some(Err(PcapError::NotActivated));
            }
            let datalink = LinkType(datalink as u16);
            loop {
                match pcap_next_ex(
                    self.cap.pcap().raw_handle().as_ptr(),
                    (&mut pkt_info.hdr) as *mut *mut pcap_pkthdr,
                    (&mut pkt_info.data) as *mut *const libc::c_uchar,
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
                            self.cap.pcap().raw_handle().as_ptr(),
                        )))));
                    }
                }

                if let Err(err) = self.wait_for_packets().await {
                    return Some(Err(err));
                }
            }
            let hdr = &*pkt_info.hdr;
            let data = std::slice::from_raw_parts(pkt_info.data, hdr.caplen as usize);
            let ts = match self.cap.timestamp_precision() {
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
                datalink,
                ts,
                len: hdr.len,
                data,
            }))
        }
    }

    pub fn snaplen(&self) -> Result<u32> {
        self.cap.snaplen()
    }

    #[cfg(feature = "npcap")]
    pub fn buffer_size(&self) -> Result<u32> {
        self.cap.buffer_size()
    }

    pub fn timestamp_precision(&self) -> TsPrecision {
        self.cap.timestamp_precision()
    }

    pub fn set_direction(&mut self, direction: Direction) -> Result<()> {
        self.cap.set_direction(direction)
    }

    pub fn link_type(&self) -> Result<LinkType> {
        self.cap.link_type()
    }

    pub fn stats(&self) -> Result<Stats> {
        self.cap.stats()
    }
}
