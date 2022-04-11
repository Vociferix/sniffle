use super::*;
use std::path::Path;

#[derive(Debug)]
pub struct DumpFile {
    _pcap: Pcap,
    dumper: *mut pcap_dumper_t,
    nano: bool,
}

impl DumpFile {
    pub fn create<P: AsRef<Path>>(
        filepath: P,
        datalink: LinkType,
        snaplen: u32,
        precision: TsPrecision,
    ) -> Result<Self> {
        let pcap = Pcap::open_dead(datalink, snaplen, Some(precision))?;
        unsafe {
            let name = match CString::new(filepath.as_ref().to_string_lossy().as_ref().as_bytes()) {
                Ok(name) => name,
                Err(e) => {
                    return Err(PcapError::NoSuchDevice(format!("{}", e)));
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());
            let dumper = pcap_dump_open(pcap.raw_handle(), c_name);
            if dumper.is_null() {
                Err(PcapError::General(make_string(pcap_geterr(
                    pcap.raw_handle(),
                ))))
            } else {
                match precision {
                    TsPrecision::Micro => Ok(DumpFile {
                        _pcap: pcap,
                        dumper,
                        nano: false,
                    }),
                    TsPrecision::Nano => Ok(DumpFile {
                        _pcap: pcap,
                        dumper,
                        nano: true,
                    }),
                }
            }
        }
    }

    #[cfg(feature = "npcap")]
    pub fn open<P: AsRef<Path>>(
        filepath: P,
        datalink: LinkType,
        snaplen: u32,
        precision: TsPrecision,
    ) -> Result<Self> {
        let pcap = Pcap::open_dead(datalink, snaplen, Some(precision))?;
        unsafe {
            let name = match CString::new(filepath.as_ref().to_string_lossy().as_ref().as_bytes()) {
                Ok(name) => name,
                Err(e) => {
                    return Err(PcapError::NoSuchDevice(format!("{}", e)));
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());
            let dumper = pcap_dump_open_append(pcap.raw_handle(), c_name);
            if dumper.is_null() {
                Err(PcapError::General(make_string(pcap_geterr(
                    pcap.raw_handle(),
                ))))
            } else {
                match precision {
                    TsPrecision::Micro => Ok(DumpFile {
                        _pcap: pcap,
                        dumper,
                        nano: false,
                    }),
                    TsPrecision::Nano => Ok(DumpFile {
                        _pcap: pcap,
                        dumper,
                        nano: true,
                    }),
                }
            }
        }
    }

    pub fn dump(&mut self, timestamp: SystemTime, pkt: &[u8]) -> Result<()> {
        self.dump_partial(timestamp, pkt, pkt.len() as u32)
    }

    pub fn dump_partial(&mut self, timestamp: SystemTime, pkt: &[u8], orig_len: u32) -> Result<()> {
        let mut hdr = pcap_pkthdr::default();
        let ptr = pkt.as_ptr();
        match timestamp.duration_since(std::time::UNIX_EPOCH) {
            Ok(dur) => {
                hdr.ts.tv_sec = dur.as_secs() as time_t;
                hdr.ts.tv_usec = if self.nano {
                    dur.subsec_nanos()
                } else {
                    dur.subsec_micros()
                } as suseconds_t;
            }
            Err(e) => {
                return Err(PcapError::General(format!("{}", e)));
            }
        }
        hdr.caplen = pkt.len() as u32;
        hdr.len = orig_len;
        unsafe {
            pcap_dump(
                std::mem::transmute::<*mut pcap_dumper_t, *mut libc::c_uchar>(self.dumper),
                (&mut hdr) as *mut pcap_pkthdr,
                std::mem::transmute::<_, *mut libc::c_uchar>(ptr),
            );
        }
        Ok(())
    }
}
