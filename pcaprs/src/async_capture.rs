use super::*;

#[repr(transparent)]
pub struct AsyncCapture<C: Capture>(C);

#[cfg(not(windows))]
struct WaitHandle(libc::c_int);

#[cfg(windows)]
struct WaitHandle(usize);

impl WaitHandle {
    #[cfg(not(windows))]
    fn wait(&self) -> Result<()> {
        unsafe {
            let mut fd = libc::pollfd {
                fd: self.0,
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                match libc::poll(&mut fd as *mut libc::pollfd, 1, -1) {
                    0 => {
                        continue;
                    }
                    err if err < 0 => {
                        return Err(PcapError::IO(std::io::Error::from_raw_os_error(
                            *libc::__errno_location(),
                        )));
                    }
                    _ => {}
                }
                if fd.revents != 0 {
                    break;
                }
            }
            Ok(())
        }
    }

    #[cfg(windows)]
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

impl<C: Capture> AsyncCapture<C> {
    pub fn new(mut capture: C) -> Result<Self> {
        capture.pcap_mut().set_nonblocking(true)?;
        Ok(Self(capture))
    }

    pub fn into_inner(mut self) -> Result<C> {
        self.0.pcap_mut().set_nonblocking(false)?;
        Ok(self.0)
    }

    #[cfg(not(windows))]
    fn wait_handle(capture: &C) -> WaitHandle {
        unsafe { WaitHandle(pcap_get_selectable_fd(capture.pcap().raw_handle().as_ptr())) }
    }

    #[cfg(windows)]
    fn wait_handle(capture: &C) -> WaitHandle {
        unsafe {
            WaitHandle(std::mem::transmute(pcap_getevent(
                capture.pcap().raw_handle().as_ptr(),
            )))
        }
    }

    pub async fn wait_for_packets(capture: &C) -> Result<()> {
        let wh = Self::wait_handle(capture);
        tokio::task::spawn_blocking(move || wh.wait())
            .await
            .unwrap()
    }

    pub async fn next_packet<'a>(&'a mut self) -> Option<Result<Packet<'a>>> {
        unsafe {
            let mut data: *const u8 = std::ptr::null_mut();
            let mut hdr: *mut pcap_pkthdr = std::ptr::null_mut();
            let datalink = pcap_datalink(self.0.pcap().raw_handle().as_ptr());
            if datalink < 0 {
                return Some(Err(PcapError::NotActivated));
            }
            let datalink = LinkType(datalink as u16);
            loop {
                match pcap_next_ex(
                    self.0.pcap().raw_handle().as_ptr(),
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
                            self.0.pcap().raw_handle().as_ptr(),
                        )))));
                    }
                }

                if let Err(err) = Self::wait_for_packets(&self.0).await {
                    return Some(Err(err));
                }
            }
            let hdr = &*hdr;
            let data = std::slice::from_raw_parts(data, hdr.caplen as usize);
            let ts = match self.0.timestamp_precision() {
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
        self.0.snaplen()
    }

    #[cfg(feature = "npcap")]
    pub fn buffer_size(&self) -> Result<u32> {
        self.0.buffer_size()
    }

    pub fn timestamp_precision(&self) -> TsPrecision {
        self.0.timestamp_precision()
    }

    pub fn set_direction(&mut self, direction: Direction) -> Result<()> {
        self.0.set_direction(direction)
    }

    pub fn link_type(&self) -> Result<LinkType> {
        self.0.link_type()
    }

    pub fn stats(&self) -> Result<Stats> {
        self.0.stats()
    }
}
