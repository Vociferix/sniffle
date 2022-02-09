use super::{Device, LinkType, RawPacket, Session, Sniff, SniffError};
use pcaprs::Capture;

pub type DeviceTSType = pcaprs::TSType;
pub type DeviceTSPrecision = pcaprs::TSPrecision;

pub struct DeviceSniffer {
    pcap: pcaprs::Pcap,
    dev: std::rc::Rc<Device>,
    session: Session,
}

pub struct DeviceSnifferConfig {
    config: pcaprs::PcapConfig,
    device: std::rc::Rc<Device>,
    session: Option<Session>,
}

impl DeviceSniffer {
    pub fn open(config: DeviceSnifferConfig) -> Result<Self, SniffError> {
        let DeviceSnifferConfig {
            config,
            device,
            session,
        } = config;
        Ok(Self {
            pcap: config.activate()?,
            dev: device,
            session: session.unwrap_or_else(|| Session::new()),
        })
    }

    pub fn pcap(&self) -> &pcaprs::Pcap {
        &self.pcap
    }

    pub fn pcap_mut(&mut self) -> &mut pcaprs::Pcap {
        &mut self.pcap
    }

    pub fn into_pcap(self) -> pcaprs::Pcap {
        self.pcap
    }

    pub fn device(&self) -> &Device {
        &*self.dev
    }

    pub fn device_mut(&mut self) -> Option<&mut Device> {
        std::rc::Rc::get_mut(&mut self.dev)
    }

    pub fn share_device(&self) -> std::rc::Rc<Device> {
        self.dev.clone()
    }
}

impl Sniff for DeviceSniffer {
    fn next_raw(&mut self) -> Result<Option<RawPacket<'_>>, SniffError> {
        let snaplen = self.pcap.snaplen()? as usize;
        match self.pcap.next_packet() {
            Some(res) => match res {
                Ok(pkt) => Ok(Some(RawPacket::new(
                    LinkType(pkt.datalink().0),
                    pkt.timestamp(),
                    pkt.orig_len() as usize,
                    Some(snaplen),
                    pkt.data(),
                    Some(self.dev.clone()),
                ))),
                Err(e) => Err(SniffError::Pcap(e)),
            },
            None => Ok(None),
        }
    }

    fn session(&self) -> &Session {
        &self.session
    }

    fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

impl DeviceSnifferConfig {
    pub fn create(device: Device) -> Self {
        let config = pcaprs::PcapConfig::create(device.name());
        Self {
            config,
            device: std::rc::Rc::new(device),
            session: None,
        }
    }

    pub fn open(self) -> Result<DeviceSniffer, SniffError> {
        DeviceSniffer::open(self)
    }

    pub fn snaplen(self, snaplen: u32) -> Self {
        let mut config = self;
        let _ = config.config.snaplen(snaplen);
        config
    }

    pub fn promiscuous_mode(self, enable: bool) -> Self {
        let mut config = self;
        let _ = config.config.promiscuous_mode(enable);
        config
    }

    pub fn rfmon_mode(self, enable: bool) -> Self {
        let mut config = self;
        let _ = config.config.rfmon_mode(enable);
        config
    }

    pub fn timeout(self, dur: std::time::Duration) -> Self {
        let mut config = self;
        let _ = config.config.timeout(dur);
        config
    }

    pub fn timestamp_type(self, ts_type: DeviceTSType) -> Self {
        let mut config = self;
        let _ = config.config.timestamp_type(ts_type);
        config
    }

    pub fn immediate_mode(self, enable: bool) -> Self {
        let mut config = self;
        let _ = config.config.immediate_mode(enable);
        config
    }

    pub fn buffer_size(self, size: u32) -> Self {
        let mut config = self;
        let _ = config.config.buffer_size(size);
        config
    }

    pub fn timestamp_precision(self, prec: DeviceTSPrecision) -> Self {
        let mut config = self;
        let _ = config.config.timestamp_precision(prec);
        config
    }

    pub fn session(self, session: Session) -> Self {
        let mut config = self;
        config.session = Some(session);
        config
    }
}
