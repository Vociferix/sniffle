use super::*;

#[derive(Debug, Clone)]
enum SingleOrMulti<T> {
    Empty(Vec<T>),
    Single([T; 1]),
    Multi(Vec<T>),
}

impl<T> From<T> for SingleOrMulti<T> {
    fn from(val: T) -> Self {
        Self::Single([val])
    }
}

impl<T> From<Vec<T>> for SingleOrMulti<T> {
    fn from(val: Vec<T>) -> Self {
        Self::Multi(val)
    }
}

impl<T> std::ops::Deref for SingleOrMulti<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Empty(ref vec) => &vec[..],
            Self::Single(ref arr) => &arr[..],
            Self::Multi(ref vec) => &vec[..],
        }
    }
}

impl<T> SingleOrMulti<T> {
    fn new() -> Self {
        Self::Empty(Vec::new())
    }

    fn push(&mut self, item: T) {
        let tmp = std::mem::replace(self, Self::new());
        match tmp {
            Self::Empty(_) => {
                *self = Self::Single([item]);
            }
            Self::Single([val]) => {
                *self = Self::Multi(vec![val, item]);
            }
            Self::Multi(mut v) => {
                v.push(item);
                *self = Self::Multi(v);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ConnectionStatus {
    Unknown,
    Connected,
    Disconnected,
    NotApplicable,
}

pub type MacAddress = [u8; 6];
pub type IPv4Address = [u8; 4];
pub type IPv6Address = [u8; 16];

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
    mac_addrs: SingleOrMulti<MacAddress>,
    ipv4_addrs: SingleOrMulti<DeviceIPv4>,
    ipv6_addrs: SingleOrMulti<DeviceIPv6>,
}

#[derive(Debug, Clone)]
pub struct DeviceBuilder {
    device: Device,
}

pub struct AllDevicesIter {
    ptr: *mut pcap_if_t,
    curr: *const pcap_if_t,
}

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
        self.prefix_len.clone()
    }
}

impl Device {
    pub fn all() -> AllDevicesIter {
        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            let mut devs: *mut pcap_if_t = std::ptr::null_mut();
            let rc = pcap_findalldevs(&mut devs as *mut *mut pcap_if_t, errbuf_ptr);
            if rc < 0 || devs == std::ptr::null_mut() {
                AllDevicesIter {
                    ptr: std::ptr::null_mut(),
                    curr: std::ptr::null(),
                }
            } else {
                AllDevicesIter {
                    ptr: devs,
                    curr: devs,
                }
            }
        }
    }

    pub fn lookup(name: &str) -> Option<Device> {
        let mut ret: Option<Device> = None;

        unsafe {
            let mut errbuf: [libc::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];
            let errbuf_ptr = errbuf.as_mut_ptr();
            let mut devs: *mut pcap_if_t = std::ptr::null_mut();
            let rc = pcap_findalldevs(&mut devs as *mut *mut pcap_if_t, errbuf_ptr);
            if rc == 0 {
                let free_ptr = devs;
                while devs != std::ptr::null_mut() {
                    let dev = &*devs;
                    if dev.name != std::ptr::null_mut() {
                        if name == &std::ffi::CStr::from_ptr(dev.name).to_string_lossy() {
                            ret = Some(Device::from(dev));
                            break;
                        }
                    }
                    devs = dev.next;
                }
                if free_ptr != std::ptr::null_mut() {
                    pcap_freealldevs(free_ptr);
                }
            }
        }

        ret
    }

    pub fn default() -> Option<Device> {
        Self::all().next()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.desc.as_ref().map(|d| d.as_str())
    }

    pub fn mac_addresses(&self) -> &[MacAddress] {
        &self.mac_addrs
    }

    pub fn ipv4_addresses(&self) -> &[DeviceIPv4] {
        &self.ipv4_addrs
    }

    pub fn ipv6_addresses(&self) -> &[DeviceIPv6] {
        &self.ipv6_addrs
    }

    pub fn is_loopback(&self) -> bool {
        (self.flags & PCAP_IF_LOOPBACK) > 0
    }

    pub fn is_running(&self) -> bool {
        (self.flags & PCAP_IF_RUNNING) > 0
    }

    pub fn is_up(&self) -> bool {
        (self.flags & PCAP_IF_UP) > 0
    }

    pub fn connection_status(&self) -> ConnectionStatus {
        match self.flags & PCAP_IF_CONNECTION_STATUS {
            PCAP_IF_CONNECTION_STATUS_UNKNOWN => ConnectionStatus::Unknown,
            PCAP_IF_CONNECTION_STATUS_CONNECTED => ConnectionStatus::Connected,
            PCAP_IF_CONNECTION_STATUS_DISCONNECTED => ConnectionStatus::Disconnected,
            _ => ConnectionStatus::NotApplicable,
        }
    }

    pub fn try_refresh(self) -> std::result::Result<Self, Self> {
        let new = Self::lookup(self.name());
        match new {
            Some(dev) => Ok(dev),
            None => Err(self),
        }
    }

    pub fn refresh(self) -> Option<Self> {
        Self::lookup(self.name())
    }

    pub fn refresh_inplace(&mut self) -> bool {
        let name = std::mem::replace(&mut self.name, String::new());
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

pub trait AsDeviceName {
    fn as_device_name(&self) -> &str;
}

impl AsDeviceName for Device {
    fn as_device_name(&self) -> &str {
        self.name()
    }
}

impl<T: AsRef<str>> AsDeviceName for T {
    fn as_device_name(&self) -> &str {
        self.as_ref()
    }
}

impl DeviceBuilder {
    pub fn new() -> Self {
        Self {
            device: Device {
                name: String::new(),
                desc: None,
                flags: 0,
                mac_addrs: SingleOrMulti::new(),
                ipv4_addrs: SingleOrMulti::new(),
                ipv6_addrs: SingleOrMulti::new(),
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

    pub fn add_mac(&mut self, mac: MacAddress) -> &mut Self {
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
            self.device.flags |= libpcap_sys::PCAP_IF_LOOPBACK;
        } else {
            self.device.flags &= !libpcap_sys::PCAP_IF_LOOPBACK;
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

#[cfg(target_os = "windows")]
unsafe fn read_address(bldr: &mut DeviceBuilder, addr: &pcap_addr_t) {
    if addr.addr != std::ptr::null_mut() {
        match (*addr.addr).sa_family as i32 {
            winapi::shared::ws2def::AF_INET => {
                let ip4addr = (*std::mem::transmute::<
                    *mut sockaddr,
                    *mut winapi::shared::ws2def::SOCKADDR_IN,
                >(addr.addr))
                .sin_addr
                .S_un
                .S_addr()
                .to_be_bytes();
                let mask: Option<IPv4Address> = if addr.netmask != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<
                            *mut sockaddr,
                            *mut winapi::shared::ws2def::SOCKADDR_IN,
                        >(addr.netmask))
                        .sin_addr
                        .S_un
                        .S_addr()
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                let brd: Option<IPv4Address> = if addr.broadaddr != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<
                            *mut sockaddr,
                            *mut winapi::shared::ws2def::SOCKADDR_IN,
                        >(addr.broadaddr))
                        .sin_addr
                        .S_un
                        .S_addr()
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                let dst: Option<IPv4Address> = if addr.dstaddr != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<
                            *mut sockaddr,
                            *mut winapi::shared::ws2def::SOCKADDR_IN,
                        >(addr.dstaddr))
                        .sin_addr
                        .S_un
                        .S_addr()
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                bldr.add_ipv4(DeviceIPv4::new(ip4addr, mask, brd, dst));
            }
            winapi::shared::ws2def::AF_INET6 => {
                let ip6addr = (*std::mem::transmute::<
                    *mut sockaddr,
                    *mut winapi::shared::ws2ipdef::SOCKADDR_IN6,
                >(addr.addr))
                .sin6_addr
                .u
                .Byte()
                .clone();
                let prefixlen: Option<u32> = if addr.netmask != std::ptr::null_mut() {
                    let mask = &(*std::mem::transmute::<
                        *mut sockaddr,
                        *mut winapi::shared::ws2ipdef::SOCKADDR_IN6,
                    >(addr.netmask))
                    .sin6_addr
                    .u
                    .Byte()
                    .clone();
                    let mut count: u32 = 0;
                    for byte in mask.iter() {
                        let byte = *byte;
                        if byte == 0xFF {
                            count += 8;
                        } else if byte < 0b11110000 {
                            if byte < 0b11000000 {
                                if byte < 0b10000000 {
                                    count += 0;
                                } else {
                                    count += 1;
                                }
                            } else {
                                if byte < 0b11100000 {
                                    count += 2;
                                } else {
                                    count += 3;
                                }
                            }
                        } else {
                            if byte < 0b11111100 {
                                if byte < 0b11111000 {
                                    count += 4;
                                } else {
                                    count += 5;
                                }
                            } else {
                                if byte < 0b11111110 {
                                    count += 6;
                                } else {
                                    count += 7;
                                }
                            }
                        }
                    }
                    Some(count)
                } else {
                    None
                };
                bldr.add_ipv6(DeviceIPv6::new(ip6addr, prefixlen));
            }
            // XXX Does this actually work on Windows?
            winapi::shared::ws2def::AF_LINK => {
                let tmp = &(*std::mem::transmute::<
                    *mut sockaddr,
                    *mut winapi::shared::ws2def::SOCKADDR_DL,
                >(addr.addr))
                .sdl_data;
                bldr.add_mac([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]]);
            }
            _ => {}
        }
    }
}

// BSD like systems use AF_LINK and sockaddr_dl
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "illumos"
))]
unsafe fn read_address(bldr: &mut DeviceBuilder, addr: &pcap_addr_t) {
    if addr.addr != std::ptr::null_mut() {
        match (*addr.addr).sa_family as i32 {
            libc::AF_INET => {
                let ip4addr =
                    (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(addr.addr))
                        .sin_addr
                        .s_addr
                        .to_be_bytes();
                let mask: Option<IPv4Address> = if addr.netmask != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(
                            addr.netmask,
                        ))
                        .sin_addr
                        .s_addr
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                let brd: Option<IPv4Address> = if addr.broadaddr != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(
                            addr.broadaddr,
                        ))
                        .sin_addr
                        .s_addr
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                let dst: Option<IPv4Address> = if addr.dstaddr != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(
                            addr.dstaddr,
                        ))
                        .sin_addr
                        .s_addr
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                bldr.add_ipv4(DeviceIPv4::new(ip4addr, mask, brd, dst));
            }
            libc::AF_INET6 => {
                let ip6addr =
                    (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in6>(addr.addr))
                        .sin6_addr
                        .s6_addr
                        .clone();
                let prefixlen: Option<u32> = if addr.netmask != std::ptr::null_mut() {
                    let mask = &(*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in6>(
                        addr.netmask,
                    ))
                    .sin6_addr
                    .s6_addr;
                    let mut count: u32 = 0;
                    for byte in mask.iter() {
                        let byte = *byte;
                        if byte == 0xFF {
                            count += 8;
                        } else if byte < 0b11110000 {
                            if byte < 0b11000000 {
                                if byte < 0b10000000 {
                                    count += 0;
                                } else {
                                    count += 1;
                                }
                            } else {
                                if byte < 0b11100000 {
                                    count += 2;
                                } else {
                                    count += 3;
                                }
                            }
                        } else {
                            if byte < 0b11111100 {
                                if byte < 0b11111000 {
                                    count += 4;
                                } else {
                                    count += 5;
                                }
                            } else {
                                if byte < 0b11111110 {
                                    count += 6;
                                } else {
                                    count += 7;
                                }
                            }
                        }
                    }
                    Some(count)
                } else {
                    None
                };
                bldr.add_ipv6(DeviceIPv6::new(ip6addr, prefixlen));
            }
            libc::AF_LINK => {
                let tmp =
                    &(*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_dl>(addr.addr))
                        .sdl_data;
                builder.add_mac([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]]);
            }
            _ => {}
        }
    }
}

// Basically Linux. Anything that doesn't use AF_PACKET and sockaddr_ll and
// isn't covered by one of the other implementations of this function isn't
// supported (for now).
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "windows"
)))]
unsafe fn read_address(bldr: &mut DeviceBuilder, addr: &pcap_addr_t) {
    if addr.addr != std::ptr::null_mut() {
        match (*addr.addr).sa_family as i32 {
            libc::AF_INET => {
                let ip4addr =
                    (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(addr.addr))
                        .sin_addr
                        .s_addr
                        .to_be_bytes();
                let mask: Option<IPv4Address> = if addr.netmask != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(
                            addr.netmask,
                        ))
                        .sin_addr
                        .s_addr
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                let brd: Option<IPv4Address> = if addr.broadaddr != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(
                            addr.broadaddr,
                        ))
                        .sin_addr
                        .s_addr
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                let dst: Option<IPv4Address> = if addr.dstaddr != std::ptr::null_mut() {
                    Some(
                        (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in>(
                            addr.dstaddr,
                        ))
                        .sin_addr
                        .s_addr
                        .to_be_bytes(),
                    )
                } else {
                    None
                };
                bldr.add_ipv4(DeviceIPv4::new(ip4addr, mask, brd, dst));
            }
            libc::AF_INET6 => {
                let ip6addr =
                    (*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in6>(addr.addr))
                        .sin6_addr
                        .s6_addr
                        .clone();
                let prefixlen: Option<u32> = if addr.netmask != std::ptr::null_mut() {
                    let mask = &(*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_in6>(
                        addr.netmask,
                    ))
                    .sin6_addr
                    .s6_addr;
                    let mut count: u32 = 0;
                    for byte in mask.iter() {
                        let byte = *byte;
                        if byte == 0xFF {
                            count += 8;
                        } else if byte < 0b11110000 {
                            if byte < 0b11000000 {
                                if byte < 0b10000000 {
                                    count += 0;
                                } else {
                                    count += 1;
                                }
                            } else {
                                if byte < 0b11100000 {
                                    count += 2;
                                } else {
                                    count += 3;
                                }
                            }
                        } else {
                            if byte < 0b11111100 {
                                if byte < 0b11111000 {
                                    count += 4;
                                } else {
                                    count += 5;
                                }
                            } else {
                                if byte < 0b11111110 {
                                    count += 6;
                                } else {
                                    count += 7;
                                }
                            }
                        }
                    }
                    Some(count)
                } else {
                    None
                };
                bldr.add_ipv6(DeviceIPv6::new(ip6addr, prefixlen));
            }
            libc::AF_PACKET => {
                let tmp =
                    &(*std::mem::transmute::<*mut sockaddr, *mut libc::sockaddr_ll>(addr.addr))
                        .sll_addr;
                bldr.add_mac([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]]);
            }
            _ => {}
        }
    }
}

impl From<&pcap_if_t> for Device {
    fn from(pcap_if: &pcap_if_t) -> Device {
        let mut builder = DeviceBuilder::new();
        builder.name(unsafe { make_string(pcap_if.name) });

        if pcap_if.description != std::ptr::null_mut() {
            builder.description(unsafe { make_string(pcap_if.description) });
        }

        let mut addresses = pcap_if.addresses;
        while addresses != std::ptr::null_mut() {
            let addr = unsafe { &*addresses };
            unsafe {
                read_address(&mut builder, addr);
            }
            addresses = addr.next;
        }

        builder.device.flags = pcap_if.flags as u32;

        builder.into_device()
    }
}

impl Iterator for AllDevicesIter {
    type Item = Device;

    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.curr;
        if curr == std::ptr::null() {
            None
        } else {
            let dev = unsafe { &*curr };
            self.curr = dev.next;
            Some(Device::from(dev))
        }
    }
}

impl Drop for AllDevicesIter {
    fn drop(&mut self) {
        let ptr = self.ptr;
        if ptr != std::ptr::null_mut() {
            unsafe {
                pcap_freealldevs(ptr);
            }
        }
        self.ptr = std::ptr::null_mut();
        self.curr = std::ptr::null();
    }
}
