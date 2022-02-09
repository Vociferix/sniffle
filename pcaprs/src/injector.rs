use super::*;

#[derive(Debug)]
pub struct Injector(pub(crate) Pcap);

impl Injector {
    pub fn new<D: AsDeviceName>(device: D) -> Result<Self> {
        Ok(Self(
            PcapConfig::create(device.as_device_name())
                .promiscuous_mode(true)
                .activate()?,
        ))
    }

    pub fn inject(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            let ptr = data.as_ptr();
            let len = data.len() as libc::c_int;
            if pcap_sendpacket(self.0.raw_handle(), ptr, len) != 0 {
                Err(PcapError::General(make_string(pcap_geterr(
                    self.0.raw_handle(),
                ))))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for Injector {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawHandle for Injector {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.0.as_raw_handle()
    }
}
