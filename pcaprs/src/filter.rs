use super::*;

#[derive(Debug)]
pub struct OfflineFilter(bpf_program);

unsafe impl Send for OfflineFilter {}

unsafe impl Sync for OfflineFilter {}

impl OfflineFilter {
    pub fn new(datalink: LinkType, snaplen: u32, filter: &str, optimize: bool) -> Result<Self> {
        Self::with_netmask(
            datalink,
            snaplen,
            filter,
            optimize,
            [0xff, 0xff, 0xff, 0xff],
        )
    }

    pub fn with_netmask(
        datalink: LinkType,
        snaplen: u32,
        filter: &str,
        optimize: bool,
        mask: Ipv4Address,
    ) -> Result<Self> {
        let mut prog = bpf_program::default();
        let prog_ptr = (&mut prog) as *mut bpf_program;
        let datalink = datalink.0 as i32;
        let snaplen = snaplen as i32;
        let optimize = if optimize { 1 } else { 0 };
        let mask = u32::from_be_bytes(mask);
        unsafe {
            let filter = match CString::new(filter) {
                Ok(filter) => filter,
                Err(e) => {
                    return Err(PcapError::General(format!("{}", e)));
                }
            };
            let c_filter =
                std::mem::transmute::<*const u8, *const i8>(filter.as_bytes_with_nul().as_ptr());
            if pcap_compile_nopcap(snaplen, datalink, prog_ptr, c_filter, optimize, mask) != 0 {
                return Err(PcapError::General(String::from("invalid filter")));
            }
        }
        Ok(Self(prog))
    }

    pub fn filter(&mut self, packet: &[u8]) -> bool {
        self.filter_partial(packet, packet.len() as u32)
    }

    pub fn filter_partial(&mut self, packet: &[u8], orig_len: u32) -> bool {
        let hdr = pcap_pkthdr {
            ts: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: packet.len() as u32,
            len: orig_len,
        };
        let data = packet.as_ptr();
        unsafe {
            pcap_offline_filter(
                (&mut self.0) as *mut bpf_program,
                (&hdr) as *const pcap_pkthdr,
                data,
            ) != 0
        }
    }
}
