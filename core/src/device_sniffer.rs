use super::{Device, LinkType, RawPacket, Session, Error, SniffRaw, Sniffer};
use async_trait::async_trait;
use pcaprs::{AsyncCapture, Capture, Pcap, PcapConfig, TsPrecision, TsType};

pub type DeviceTsType = TsType;
pub type DeviceTsPrecision = TsPrecision;

pub struct DeviceSniffer {
    pcap: AsyncCapture<Pcap>,
    dev: std::sync::Arc<Device>,
}

pub struct DeviceSnifferConfig {
    config: PcapConfig,
    device: std::sync::Arc<Device>,
}

impl DeviceSniffer {
    pub fn open_raw(config: DeviceSnifferConfig) -> Result<Self, Error> {
        let DeviceSnifferConfig { config, device } = config;
        Ok(Self {
            pcap: config.activate()?.into_async()?,
            dev: device,
        })
    }

    pub fn open(config: DeviceSnifferConfig) -> Result<Sniffer<Self>, Error> {
        Ok(Sniffer::new(Self::open_raw(config)?))
    }

    pub fn open_with_session(
        config: DeviceSnifferConfig,
        session: Session,
    ) -> Result<Sniffer<Self>, Error> {
        Ok(Sniffer::with_session(Self::open_raw(config)?, session))
    }

    pub fn into_pcap(self) -> AsyncCapture<Pcap> {
        self.pcap
    }

    pub fn device(&self) -> &Device {
        &*self.dev
    }

    pub fn device_mut(&mut self) -> Option<&mut Device> {
        std::sync::Arc::get_mut(&mut self.dev)
    }

    pub fn share_device(&self) -> std::sync::Arc<Device> {
        self.dev.clone()
    }
}

#[async_trait]
impl SniffRaw for DeviceSniffer {
    async fn sniff_raw<'a>(&'a mut self) -> Result<Option<RawPacket<'a>>, Error> {
        let snaplen = self.pcap.snaplen()? as usize;
        match self.pcap.next_packet().await {
            Some(res) => match res {
                Ok(pkt) => Ok(Some(RawPacket::new(
                    LinkType(pkt.datalink().0),
                    pkt.timestamp(),
                    pkt.orig_len() as usize,
                    Some(snaplen),
                    pkt.data(),
                    Some(self.dev.clone()),
                ))),
                Err(e) => Err(Error::Pcap(e)),
            },
            None => Ok(None),
        }
    }
}

impl DeviceSnifferConfig {
    pub fn create(device: Device) -> Self {
        let config = PcapConfig::create(device.name());
        Self {
            config,
            device: std::sync::Arc::new(device),
        }
    }

    pub fn open_raw(self) -> Result<DeviceSniffer, Error> {
        DeviceSniffer::open_raw(self)
    }

    pub fn open(self) -> Result<Sniffer<DeviceSniffer>, Error> {
        DeviceSniffer::open(self)
    }

    pub fn open_with_session(self, session: Session) -> Result<Sniffer<DeviceSniffer>, Error> {
        DeviceSniffer::open_with_session(self, session)
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

    pub fn timestamp_type(self, ts_type: DeviceTsType) -> Self {
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

    pub fn timestamp_precision(self, prec: DeviceTsPrecision) -> Self {
        let mut config = self;
        let _ = config.config.timestamp_precision(prec);
        config
    }
}
