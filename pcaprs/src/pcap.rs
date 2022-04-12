use super::*;
use std::ptr::NonNull;

#[derive(Debug)]
#[repr(transparent)]
pub struct Pcap(NonNull<pcap_t>);

#[derive(Debug)]
pub struct FilteredPcap {
    pcap: Pcap,
    filter: bpf_program,
}

#[derive(Debug, Clone)]
pub struct PcapConfig {
    source: String,
    snaplen: Option<u32>,
    promisc: Option<bool>,
    rfmon: Option<bool>,
    timeout: Option<Duration>,
    ts_type: Option<TsType>,
    immediate: Option<bool>,
    bufsize: Option<u32>,
    ts_prec: Option<TsPrecision>,
}

impl Pcap {
    pub(crate) unsafe fn raw_handle(&self) -> NonNull<pcap_t> {
        self.0
    }

    pub fn into_raw(self) -> NonNull<pcap_t> {
        self.0
    }

    /// Constructs a Pcap object from a raw libpcap handle
    ///
    /// # Safety
    /// The raw handle must be a non-null pointer to an _active_ libpcap
    /// packet capture instance. A handle returned by Pcap::into_raw will
    /// satisfy this condition upon release, usage in direct calls into
    /// libpcap can cause it to no longer satisfy the condition.
    pub unsafe fn from_raw(handle: NonNull<pcap_t>) -> Pcap {
        Pcap(handle)
    }

    pub fn activate(config: &PcapConfig) -> Result<Self> {
        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            let name = match CString::new(&config.source[..]) {
                Ok(name) => name,
                Err(e) => {
                    return Err(PcapError::NoSuchDevice(format!("{}", e)));
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());

            let hndl = NonNull::new(pcap_create(c_name, errbuf_ptr))
                .ok_or_else(|| PcapError::General(make_string(errbuf_ptr)))?;

            if let Some(snaplen) = config.snaplen {
                if pcap_set_snaplen(hndl.as_ptr(), snaplen as i32) != 0 {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::Activated);
                }
            }

            if let Some(bufsize) = config.bufsize {
                if pcap_set_buffer_size(hndl.as_ptr(), bufsize as i32) != 0 {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::Activated);
                }
            }

            if let Some(promisc) = config.promisc {
                if pcap_set_promisc(hndl.as_ptr(), if promisc { 1 } else { 0 }) != 0 {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::Activated);
                }
            }

            if let Some(rfmon) = config.rfmon {
                if pcap_can_set_rfmon(hndl.as_ptr()) != 0 {
                    if pcap_set_rfmon(hndl.as_ptr(), if rfmon { 1 } else { 0 }) != 0 {
                        pcap_close(hndl.as_ptr());
                        return Err(PcapError::Activated);
                    }
                } else if rfmon {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::RfMonNotSupported);
                }
            }

            if let Some(timeout) = config.timeout {
                let timeout = timeout.as_millis() as libc::c_int;
                if pcap_set_timeout(hndl.as_ptr(), timeout) != 0 {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::Activated);
                }
            }

            #[cfg(feature = "npcap")]
            if let Some(ts_type) = config.ts_type {
                let ts_type = match ts_type {
                    TsType::Host => PCAP_TSTAMP_HOST,
                    TsType::HostLowPrecision => PCAP_TSTAMP_HOST_LOWPREC,
                    TsType::HostHighPrecision => PCAP_TSTAMP_HOST_HIPREC,
                    TsType::Adapter => PCAP_TSTAMP_ADAPTER,
                    TsType::AdapterUnsynced => PCAP_TSTAMP_ADAPTER_UNSYNCED,
                };
                match pcap_set_tstamp_type(hndl.as_ptr(), ts_type) {
                    PCAP_WARNING_TSTAMP_TYPE_NOTSUP => {
                        pcap_close(hndl.as_ptr());
                        return Err(PcapError::TsTypeNotSupported);
                    }
                    PCAP_ERROR_ACTIVATED => {
                        pcap_close(hndl.as_ptr());
                        return Err(PcapError::Activated);
                    }
                    PCAP_ERROR_CANTSET_TSTAMP_TYPE => {
                        pcap_close(hndl.as_ptr());
                        return Err(PcapError::CantSetTsType);
                    }
                    _ => {}
                }
            }

            #[cfg(feature = "npcap")]
            if let Some(immediate) = config.immediate {
                if pcap_set_immediate_mode(hndl.as_ptr(), if immediate { 1 } else { 0 }) != 0 {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::Activated);
                }
            }

            #[cfg(feature = "npcap")]
            if let Some(ts_prec) = config.ts_prec {
                let ts_prec = match ts_prec {
                    TsPrecision::Micro => PCAP_TSTAMP_PRECISION_MICRO,
                    TsPrecision::Nano => PCAP_TSTAMP_PRECISION_NANO,
                };
                match pcap_set_tstamp_precision(hndl.as_ptr(), ts_prec as i32) {
                    PCAP_ERROR_TSTAMP_PRECISION_NOTSUP => {
                        pcap_close(hndl.as_ptr());
                        return Err(PcapError::TsPrecisionNotSupported);
                    }
                    PCAP_ERROR_ACTIVATED => {
                        pcap_close(hndl.as_ptr());
                        return Err(PcapError::Activated);
                    }
                    _ => {}
                }
            }

            match pcap_activate(hndl.as_ptr()) {
                PCAP_WARNING | PCAP_ERROR => {
                    let err = PcapError::General(make_string(pcap_geterr(hndl.as_ptr())));
                    pcap_close(hndl.as_ptr());
                    return Err(err);
                }
                #[cfg(feature = "npcap")]
                PCAP_WARNING_PROMISC_NOTSUP => {
                    let err =
                        PcapError::PromiscNotSupported(make_string(pcap_geterr(hndl.as_ptr())));
                    pcap_close(hndl.as_ptr());
                    return Err(err);
                }
                #[cfg(feature = "npcap")]
                PCAP_WARNING_TSTAMP_TYPE_NOTSUP => {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::TsTypeNotSupported);
                }
                PCAP_ERROR_ACTIVATED => {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::Activated);
                }
                PCAP_ERROR_NO_SUCH_DEVICE => {
                    let err = PcapError::NoSuchDevice(make_string(pcap_geterr(hndl.as_ptr())));
                    pcap_close(hndl.as_ptr());
                    return Err(err);
                }
                PCAP_ERROR_PERM_DENIED => {
                    let err = PcapError::PermDenied(make_string(pcap_geterr(hndl.as_ptr())));
                    pcap_close(hndl.as_ptr());
                    return Err(err);
                }
                #[cfg(feature = "npcap")]
                PCAP_ERROR_PROMISC_PERM_DENIED => {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::PromiscPermDenied);
                }
                PCAP_ERROR_RFMON_NOTSUP => {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::RfMonNotSupported);
                }
                PCAP_ERROR_IFACE_NOT_UP => {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::IfaceNotUp);
                }
                0 => {}
                rc => {
                    pcap_close(hndl.as_ptr());
                    return Err(PcapError::General(make_string(pcap_statustostr(rc))));
                }
            }

            Ok(Pcap(hndl))
        }
    }

    pub fn open_live<D: AsDeviceName>(
        device: D,
        snaplen: u32,
        promisc_mode: bool,
        timeout: Duration,
    ) -> Result<Pcap> {
        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            let name = match CString::new(device.as_device_name()) {
                Ok(name) => name,
                Err(e) => {
                    return Err(PcapError::NoSuchDevice(format!("{}", e)));
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());

            let promisc = if promisc_mode { 1 } else { 0 };
            let timeout = timeout.as_millis() as i32;

            Ok(Pcap(
                NonNull::new(pcap_open_live(
                    c_name,
                    snaplen as i32,
                    promisc,
                    timeout,
                    errbuf_ptr,
                ))
                .ok_or_else(|| PcapError::General(make_string(errbuf_ptr)))?,
            ))
        }
    }

    pub fn open_offline<P: AsRef<Path>>(
        filepath: P,
        #[cfg(feature = "npcap")] precision: Option<TsPrecision>,
        #[cfg(not(feature = "npcap"))] _precision: Option<TsPrecision>,
    ) -> Result<Pcap> {
        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            let name = match CString::new(filepath.as_ref().to_string_lossy().as_ref().as_bytes()) {
                Ok(name) => name,
                Err(e) => {
                    return Err(PcapError::NoSuchDevice(format!("{}", e)));
                }
            };
            let c_name =
                std::mem::transmute::<*const u8, *const i8>(name.as_bytes_with_nul().as_ptr());

            #[cfg(feature = "npcap")]
            let hndl = NonNull::new(match precision {
                Some(prec) => {
                    let prec = match prec {
                        TsPrecision::Micro => PCAP_TSTAMP_PRECISION_MICRO,
                        TsPrecision::Nano => PCAP_TSTAMP_PRECISION_NANO,
                    };
                    pcap_open_offline_with_tstamp_precision(c_name, prec, errbuf_ptr)
                }
                None => pcap_open_offline(c_name, errbuf_ptr),
            });

            #[cfg(not(feature = "npcap"))]
            let hndl = NonNull::new(pcap_open_offline(c_name, errbuf_ptr));

            Ok(Pcap(hndl.ok_or_else(|| {
                PcapError::General(make_string(errbuf_ptr))
            })?))
        }
    }

    pub fn open_dead(
        linktype: LinkType,
        snaplen: u32,
        #[cfg(feature = "npcap")] precision: Option<TsPrecision>,
        #[cfg(not(feature = "npcap"))] _precision: Option<TsPrecision>,
    ) -> Result<Pcap> {
        unsafe {
            #[cfg(feature = "npcap")]
            let hndl = NonNull::new(match precision {
                Some(prec) => {
                    let prec = match prec {
                        TsPrecision::Micro => PCAP_TSTAMP_PRECISION_MICRO,
                        TsPrecision::Nano => PCAP_TSTAMP_PRECISION_NANO,
                    };
                    pcap_open_dead_with_tstamp_precision(linktype.0 as i32, snaplen as i32, prec)
                }
                None => pcap_open_dead(linktype.0 as i32, snaplen as i32),
            });

            #[cfg(not(feature = "npcap"))]
            let hndl = NonNull::new(pcap_open_dead(linktype.0 as i32, snaplen as i32));

            Ok(Pcap(hndl.ok_or_else(|| {
                PcapError::General(String::from("unknown error"))
            })?))
        }
    }

    pub fn filter(self, filter: &str, optimize: bool) -> Result<FilteredPcap> {
        Self::filter_with_netmask(self, filter, optimize, [0xff, 0xff, 0xff, 0xff])
    }

    pub fn filter_with_netmask(
        self,
        filter: &str,
        optimize: bool,
        mask: Ipv4Address,
    ) -> Result<FilteredPcap> {
        let mut filt = FilteredPcap {
            pcap: self,
            filter: bpf_program::default(),
        };
        let prog_ptr = (&mut filt.filter) as *mut bpf_program;
        let optimize = if optimize { 1 } else { 0 };
        unsafe {
            let filter = match CString::new(filter) {
                Ok(filter) => filter,
                Err(e) => {
                    return Err(PcapError::General(format!("{}", e)));
                }
            };
            let c_filter =
                std::mem::transmute::<*const u8, *const i8>(filter.as_bytes_with_nul().as_ptr());
            if pcap_compile(
                filt.pcap.0.as_ptr(),
                prog_ptr,
                c_filter,
                optimize,
                u32::from_be_bytes(mask),
            ) != 0
            {
                return Err(PcapError::General(make_string(pcap_geterr(
                    filt.pcap.0.as_ptr(),
                ))));
            }
            if pcap_setfilter(filt.pcap.0.as_ptr(), prog_ptr) != 0 {
                return Err(PcapError::General(make_string(pcap_geterr(
                    filt.pcap.0.as_ptr(),
                ))));
            }
        }
        Ok(filt)
    }
}

impl Capture for Pcap {
    fn pcap(&self) -> &Pcap {
        self
    }

    fn pcap_mut(&mut self) -> &mut Pcap {
        self
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        unsafe {
            pcap_close(self.0.as_ptr());
        }
    }
}

impl Capture for FilteredPcap {
    fn pcap(&self) -> &Pcap {
        self.pcap.pcap()
    }

    fn pcap_mut(&mut self) -> &mut Pcap {
        self.pcap.pcap_mut()
    }
}

impl Drop for FilteredPcap {
    fn drop(&mut self) {
        unsafe {
            pcap_freecode((&mut self.filter) as *mut bpf_program);
        }
    }
}

impl PcapConfig {
    pub fn create(source: &str) -> Self {
        PcapConfig {
            source: String::from(source),
            snaplen: None,
            promisc: None,
            rfmon: None,
            timeout: None,
            ts_type: None,
            immediate: None,
            bufsize: None,
            ts_prec: None,
        }
    }

    pub fn activate(&self) -> Result<Pcap> {
        Pcap::activate(self)
    }

    pub fn snaplen(&mut self, snaplen: u32) -> &mut Self {
        self.snaplen = Some(snaplen);
        self
    }

    pub fn promiscuous_mode(&mut self, enable: bool) -> &mut Self {
        self.promisc = Some(enable);
        self
    }

    pub fn rfmon_mode(&mut self, enable: bool) -> &mut Self {
        self.rfmon = Some(enable);
        self
    }

    pub fn timeout(&mut self, dur: Duration) -> &mut Self {
        self.timeout = Some(dur);
        self
    }

    pub fn timestamp_type(&mut self, ts_type: TsType) -> &mut Self {
        self.ts_type = Some(ts_type);
        self
    }

    pub fn immediate_mode(&mut self, enable: bool) -> &mut Self {
        self.immediate = Some(enable);
        self
    }

    pub fn buffer_size(&mut self, size: u32) -> &mut Self {
        self.bufsize = Some(size);
        self
    }

    pub fn timestamp_precision(&mut self, prec: TsPrecision) -> &mut Self {
        self.ts_prec = Some(prec);
        self
    }
}

impl<P: AsRef<Path>> From<P> for PcapConfig {
    fn from(file: P) -> Self {
        PcapConfig::create(file.as_ref().to_string_lossy().as_ref())
    }
}

impl From<&Device> for PcapConfig {
    fn from(dev: &Device) -> Self {
        PcapConfig::create(dev.name())
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for Pcap {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        unsafe { pcap_get_selectable_fd(self.0.as_ptr()) }
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawHandle for Pcap {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        unsafe { std::mem::transmute(pcap_getevent(self.0.as_ptr())) }
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for FilteredPcap {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.pcap.as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawHandle for FilteredPcap {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.pcap.as_raw_handle()
    }
}
