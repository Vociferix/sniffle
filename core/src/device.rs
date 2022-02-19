use super::{IPv4Address, IPv6Address, MACAddress};

const IS_LOOPBACK: u32 = 1 << 0;
const IS_RUNNING: u32 = 1 << 1;
const IS_UP: u32 = 1 << 2;
const STATUS_MASK: u32 = 3 << 3;
const STATUS_UNKNOWN: u32 = 0 << 3;
const STATUS_CONNECTED: u32 = 1 << 3;
const STATUS_DISCONNECTED: u32 = 2 << 3;
#[cfg(feature = "npcap")]
const STATUS_NA: u32 = 3 << 3;

#[derive(Debug, Clone, Copy)]
pub enum ConnectionStatus {
    Unknown,
    Connected,
    Disconnected,
    NotApplicable,
}

#[derive(Debug, Clone)]
pub struct DeviceIPv4 {
    addr: IPv4Address,
    mask: Option<IPv4Address>,
    brd: Option<IPv4Address>,
    dst: Option<IPv4Address>,
}

#[derive(Debug, Clone)]
pub struct DeviceIPv6 {
    addr: IPv6Address,
    prefix_len: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Device {
    name: String,
    desc: Option<String>,
    flags: u32,
    mac_addrs: Vec<MACAddress>,
    ipv4_addrs: Vec<DeviceIPv4>,
    ipv6_addrs: Vec<DeviceIPv6>,
}

#[derive(Debug, Clone)]
pub struct DeviceBuilder {
    device: Device,
}

#[cfg(feature = "pcaprs")]
pub struct AllDevicesIter(pcaprs::AllDevicesIter);

impl DeviceIPv4 {
    pub fn new(
        addr: IPv4Address,
        netmask: Option<IPv4Address>,
        broadcast: Option<IPv4Address>,
        destination: Option<IPv4Address>,
    ) -> Self {
        Self {
            addr,
            mask: netmask,
            brd: broadcast,
            dst: destination,
        }
    }

    pub fn address(&self) -> &IPv4Address {
        &self.addr
    }

    pub fn netmask(&self) -> Option<&IPv4Address> {
        self.mask.as_ref()
    }

    pub fn broadcast(&self) -> Option<&IPv4Address> {
        self.brd.as_ref()
    }

    pub fn destination(&self) -> Option<&IPv4Address> {
        self.dst.as_ref()
    }
}

impl DeviceIPv6 {
    pub fn new(addr: IPv6Address, prefix_len: Option<u32>) -> Self {
        Self { addr, prefix_len }
    }

    pub fn address(&self) -> &IPv6Address {
        &self.addr
    }

    pub fn prefix_length(&self) -> Option<u32> {
        self.prefix_len
    }
}

impl Device {
    #[cfg(feature = "pcaprs")]
    pub fn all() -> AllDevicesIter {
        AllDevicesIter(pcaprs::Device::all())
    }

    #[cfg(feature = "pcaprs")]
    pub fn lookup(name: &str) -> Option<Device> {
        pcaprs::Device::lookup(name).map(Device::from)
    }

    #[cfg(feature = "pcaprs")]
    pub fn default() -> Option<Device> {
        Self::all().next()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.desc.as_deref()
    }

    pub fn mac_addresses(&self) -> &[MACAddress] {
        &self.mac_addrs[..]
    }

    pub fn ipv4_addresses(&self) -> &[DeviceIPv4] {
        &self.ipv4_addrs[..]
    }

    pub fn ipv6_addresses(&self) -> &[DeviceIPv6] {
        &self.ipv6_addrs[..]
    }

    pub fn is_loopback(&self) -> bool {
        (self.flags & IS_LOOPBACK) > 0
    }

    pub fn is_running(&self) -> bool {
        (self.flags & IS_RUNNING) > 0
    }

    pub fn is_up(&self) -> bool {
        (self.flags & IS_UP) > 0
    }

    pub fn connection_status(&self) -> ConnectionStatus {
        match self.flags & STATUS_MASK {
            STATUS_UNKNOWN => ConnectionStatus::Unknown,
            STATUS_CONNECTED => ConnectionStatus::Connected,
            STATUS_DISCONNECTED => ConnectionStatus::Disconnected,
            _ => ConnectionStatus::NotApplicable,
        }
    }

    #[cfg(feature = "pcaprs")]
    pub fn try_refresh(self) -> Result<Self, Self> {
        let new = Self::lookup(self.name());
        match new {
            Some(dev) => Ok(dev),
            None => Err(self),
        }
    }

    #[cfg(feature = "pcaprs")]
    pub fn refresh(self) -> Option<Self> {
        Self::lookup(self.name())
    }

    #[cfg(feature = "pcaprs")]
    pub fn refresh_inplace(&mut self) -> bool {
        let name = std::mem::take(&mut self.name);
        match Self::lookup(&name[..]) {
            Some(dev) => {
                *self = dev;
                true
            }
            None => {
                self.name = name;
                false
            }
        }
    }
}

#[cfg(feature = "pcaprs")]
impl From<pcaprs::Device> for Device {
    fn from(dev: pcaprs::Device) -> Self {
        let mut flags: u32 = 0;
        if dev.is_loopback() {
            flags |= IS_LOOPBACK;
        }
        #[cfg(feature = "npcap")]
        if dev.is_running() {
            flags |= IS_RUNNING;
        }
        #[cfg(feature = "npcap")]
        if dev.is_up() {
            flags |= IS_UP;
        }
        #[cfg(feature = "npcap")]
        {
            flags |= match dev.connection_status() {
                pcaprs::ConnectionStatus::Unknown => STATUS_UNKNOWN,
                pcaprs::ConnectionStatus::Connected => STATUS_CONNECTED,
                pcaprs::ConnectionStatus::Disconnected => STATUS_DISCONNECTED,
                _ => STATUS_NA,
            };
        }
        #[cfg(not(feature = "npcap"))]
        {
            flags |= STATUS_UNKNOWN;
        }
        Self {
            name: String::from(dev.name()),
            desc: dev.description().map(String::from),
            flags,
            mac_addrs: dev
                .mac_addresses()
                .iter()
                .map(|addr| MACAddress::from(*addr))
                .collect(),
            ipv4_addrs: dev
                .ipv4_addresses()
                .iter()
                .map(|addr| DeviceIPv4::from(addr.clone()))
                .collect(),
            ipv6_addrs: dev
                .ipv6_addresses()
                .iter()
                .map(|addr| DeviceIPv6::from(addr.clone()))
                .collect(),
        }
    }
}

#[cfg(feature = "pcaprs")]
impl From<pcaprs::DeviceIPv4> for DeviceIPv4 {
    fn from(ipv4: pcaprs::DeviceIPv4) -> Self {
        Self {
            addr: (*ipv4.address()).into(),
            mask: ipv4.netmask().map(|addr| (*addr).into()),
            brd: ipv4.broadcast().map(|addr| (*addr).into()),
            dst: ipv4.destination().map(|addr| (*addr).into()),
        }
    }
}

#[cfg(feature = "pcaprs")]
impl From<pcaprs::DeviceIPv6> for DeviceIPv6 {
    fn from(ipv6: pcaprs::DeviceIPv6) -> Self {
        Self {
            addr: (*ipv6.address()).into(),
            prefix_len: ipv6.prefix_length(),
        }
    }
}

impl DeviceBuilder {
    pub fn new() -> Self {
        Self {
            device: Device {
                name: String::new(),
                desc: None,
                flags: 0,
                mac_addrs: Vec::new(),
                ipv4_addrs: Vec::new(),
                ipv6_addrs: Vec::new(),
            },
        }
    }

    pub fn name(&mut self, name: String) -> &mut Self {
        self.device.name = name;
        self
    }

    pub fn description(&mut self, desc: String) -> &mut Self {
        self.device.desc = Some(desc);
        self
    }

    pub fn add_mac(&mut self, mac: MACAddress) -> &mut Self {
        self.device.mac_addrs.push(mac);
        self
    }

    pub fn add_ipv4(&mut self, ipv4: DeviceIPv4) -> &mut Self {
        self.device.ipv4_addrs.push(ipv4);
        self
    }

    pub fn add_ipv6(&mut self, ipv6: DeviceIPv6) -> &mut Self {
        self.device.ipv6_addrs.push(ipv6);
        self
    }

    pub fn loopback(&mut self, is_loopback: bool) -> &mut Self {
        if is_loopback {
            self.device.flags |= IS_LOOPBACK;
        } else {
            self.device.flags &= !IS_LOOPBACK;
        }
        self
    }

    pub fn device(&mut self) -> Device {
        self.device.clone()
    }

    pub fn into_device(self) -> Device {
        self.device
    }
}

impl Default for DeviceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "pcaprs")]
impl From<pcaprs::ConnectionStatus> for ConnectionStatus {
    fn from(status: pcaprs::ConnectionStatus) -> Self {
        match status {
            pcaprs::ConnectionStatus::Unknown => ConnectionStatus::Unknown,
            pcaprs::ConnectionStatus::Connected => ConnectionStatus::Connected,
            pcaprs::ConnectionStatus::Disconnected => ConnectionStatus::Disconnected,
            pcaprs::ConnectionStatus::NotApplicable => ConnectionStatus::NotApplicable,
        }
    }
}

#[cfg(feature = "pcaprs")]
impl From<pcaprs::AllDevicesIter> for AllDevicesIter {
    fn from(iter: pcaprs::AllDevicesIter) -> Self {
        Self(iter)
    }
}

#[cfg(feature = "pcaprs")]
impl Iterator for AllDevicesIter {
    type Item = Device;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|dev| dev.into())
    }
}
