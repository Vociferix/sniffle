use super::*;

pub struct AsyncCapture<C: Capture> {
    cap: C,
}

unsafe fn set_nonblocking<C: Capture>(cap: &mut C, enable: bool) -> Result<()> {
    let enable = if enable { 1 } else { 0 };
    unsafe {
        let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
        let errbuf_ptr = errbuf.as_mut_ptr();
        if pcap_setnonblock(cap.pcap().raw_handle().as_ptr(), enable, errbuf_ptr) != 0 {
            Err(PcapError::General(make_string(errbuf_ptr)))
        } else {
            Ok(())
        }
    }
}

enum Waiter {
    #[cfg(feature = "tokio")]
    Tokio(tokio::task::JoinHandle<Result<()>>),
    #[cfg(feature = "async-std")]
    AsyncStd(async_std::task::JoinHandle<Result<()>>),
    #[cfg(feature = "smol")]
    Smol(smol::Task<Result<()>>),
}

impl Waiter {
    #[cfg(all(feature = "tokio", feature = "async-std", feature = "smol"))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        if tokio::runtime::Handle::try_current().is_ok() {
            Self::Tokio(tokio::task::spawn_blocking(f))
        } else if async_std::task::try_current().is_some() {
            Self::AsyncStd(tokio::task::spawn_blocking(f))
        } else {
            Self::Smol(smol::unblock(f))
        }
    }

    #[cfg(all(feature = "tokio", feature = "async-std", not(feature = "smol")))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        if tokio::runtime::Handle::try_current().is_ok() {
            Self::Tokio(tokio::task::spawn_blocking(f))
        } else {
            Self::AsyncStd(tokio::task::spawn_blocking(f))
        }
    }

    #[cfg(all(feature = "tokio", not(feature = "async-std"), feature = "smol"))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        if tokio::runtime::Handle::try_current().is_ok() {
            Self::Tokio(tokio::task::spawn_blocking(f))
        } else {
            Self::Smol(smol::unblock(f))
        }
    }

    #[cfg(all(not(feature = "tokio"), feature = "async-std", feature = "smol"))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        if async_std::task::try_current().is_some() {
            Self::AsyncStd(tokio::task::spawn_blocking(f))
        } else {
            Self::Smol(smol::unblock(f))
        }
    }

    #[cfg(all(not(feature = "tokio"), not(feature = "async-std"), feature = "smol"))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        Self::Smol(smol::unblock(f))
    }

    #[cfg(all(not(feature = "tokio"), feature = "async-std", not(feature = "smol")))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        Self::AsyncStd(async_std::task::spawn_blocking(f))
    }

    #[cfg(all(feature = "tokio", not(feature = "async-std"), not(feature = "smol")))]
    fn new<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Self {
        Self::Tokio(tokio::task::spawn_blocking(f))
    }

    async fn wait(self) -> Result<()> {
        match self {
            #[cfg(feature = "tokio")]
            Self::Tokio(waiter) => waiter.await.unwrap(),
            #[cfg(feature = "async-std")]
            Self::AsyncStd(waiter) => waiter.await,
            #[cfg(feature = "smol")]
            Self::Smol(waiter) => waiter.await,
        }
    }
}

async fn spawn_blocking<F: 'static + Send + FnOnce() -> Result<()>>(f: F) -> Result<()> {
    Waiter::new(f).wait().await
}

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
        unsafe {
            set_nonblocking(&mut capture, true)?;
        }
        Ok(Self { cap: capture })
    }

    pub fn into_inner(mut self) -> Result<C> {
        unsafe {
            set_nonblocking(&mut self.cap, false)?;
        }
        Ok(self.cap)
    }

    #[cfg(not(windows))]
    fn wait_handle(&self) -> WaitHandle {
        unsafe {
            WaitHandle(pcap_get_selectable_fd(
                self.cap.pcap().raw_handle().as_ptr(),
            ))
        }
    }

    #[cfg(windows)]
    fn wait_handle(&self) -> WaitHandle {
        unsafe {
            WaitHandle(std::mem::transmute(pcap_getevent(
                self.cap.pcap().raw_handle().as_ptr(),
            )))
        }
    }

    pub async fn wait_for_packets(&self) -> Result<()> {
        let wh = self.wait_handle();
        spawn_blocking(move || wh.wait()).await
    }

    pub async fn next_packet<'a>(&'a mut self) -> Option<Result<Packet<'a>>> {
        unsafe {
            let mut data: *const u8 = std::ptr::null_mut();
            let mut hdr: *mut pcap_pkthdr = std::ptr::null_mut();
            let datalink = pcap_datalink(self.cap.pcap().raw_handle().as_ptr());
            if datalink < 0 {
                return Some(Err(PcapError::NotActivated));
            }
            let datalink = LinkType(datalink as u16);
            loop {
                match pcap_next_ex(
                    self.cap.pcap().raw_handle().as_ptr(),
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
                            self.cap.pcap().raw_handle().as_ptr(),
                        )))));
                    }
                }

                if let Err(err) = self.wait_for_packets().await {
                    return Some(Err(err));
                }
            }
            let hdr = &*hdr;
            let data = std::slice::from_raw_parts(data, hdr.caplen as usize);
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
                pcap: self.cap.pcap_mut(),
                datalink,
                ts,
                len: hdr.len,
                data,
            }))
        }
    }
}
