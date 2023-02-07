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
            if pcap_sendpacket(self.0.raw_handle().as_ptr(), ptr, len) != 0 {
                Err(PcapError::General(make_string(pcap_geterr(
                    self.0.raw_handle().as_ptr(),
                ))))
            } else {
                Ok(())
            }
        }
    }
}
