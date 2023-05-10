use std::{
    cmp::Ordering,
    fmt::{self, Display},
    hash::{Hash, Hasher},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, DerefMut, Not},
    str::FromStr,
};

use sniffle_ende::decode::{Decode, DecodeBuf, DecodeError};
use sniffle_ende::encode::{Encodable, Encode, EncodeBuf};

use crate::{ipv4, ipv4_subnet, Address, AddressParseError, Subnet};

use sniffle_address_parse::parse_ipv4;

/// Representation of an IPv4 address
#[derive(Clone, Copy, Debug, Default)]
#[repr(transparent)]
pub struct Ipv4Address([u8; 4]);

/// Representtion of an IPv4 subnet
pub type Ipv4Subnet = Subnet<Ipv4Address>;

impl Ipv4Address {
    fn value(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    fn from_value(val: u32) -> Self {
        Self(val.to_be_bytes())
    }

    /// IPv4 address commonly used to represent an unspecified (or any) address
    ///
    /// `0.0.0.0`
    pub const UNSPECIFIED: Self = ipv4!("0.0.0.0");

    /// The IPv4 localhost address
    ///
    /// `127.0.0.1`
    pub const LOCALHOST: Self = ipv4!("127.0.0.1");

    /// The IPv4 broadcast address
    ///
    /// `255.255.255.255`
    pub const BROADCAST: Self = ipv4!("255.255.255.255");

    /// Set of subnets reserved for private networks
    ///
    /// * `10.0.0.0/8`
    /// * `172.16.0.0/12`
    /// * `192.168.0.0/16`
    pub const PRIVATE_SUBNETS: [Ipv4Subnet; 3] = [
        ipv4_subnet!("10.0.0.0/8"),
        ipv4_subnet!("172.16.0.0/12"),
        ipv4_subnet!("192.168.0.0/16"),
    ];

    /// Addresses reserved for loopback
    ///
    /// `127.0.0.0/8`
    pub const LOOPBACK_SUBNET: Ipv4Subnet = ipv4_subnet!("127.0.0.0/8");

    /// Addresses reserved for multicast
    ///
    /// `224.0.0.0/4`
    pub const MULTICAST_SUBNET: Ipv4Subnet = ipv4_subnet!("224.0.0.0/4");

    /// Addresses reserved for link local
    ///
    /// `169.254.0.0/16`
    pub const LINK_LOCAL_SUBNET: Ipv4Subnet = ipv4_subnet!("169.254.0.0/16");

    /// Shared address space
    ///
    /// `100.64.0.0/10`
    pub const SHARED_SUBNET: Ipv4Subnet = ipv4_subnet!("100.64.0.0/10");

    /// Addresses reserved for benchmarking
    ///
    /// `198.18.0.0/15`
    pub const BENCHMARKING_SUBNET: Ipv4Subnet = ipv4_subnet!("198.18.0.0/15");

    /// Addresses reserved for future use
    ///
    /// `240.0.0.0/4`
    pub const RESERVED_SUBNET: Ipv4Subnet = ipv4_subnet!("240.0.0.0/4");

    /// Addresses reserved for documentation purposes (TEST-NET-1)
    ///
    /// `192.0.2.0/24`
    pub const TEST_NET_1: Ipv4Subnet = ipv4_subnet!("192.0.2.0/24");

    /// Addresses reserved for documentation purposes (TEST-NET-2)
    ///
    /// `198.51.100.0/24`
    pub const TEST_NET_2: Ipv4Subnet = ipv4_subnet!("198.51.100.0/24");

    /// Addresses reserved for documentation purposes (TEST-NET-3)
    ///
    /// `203.0.113.0/24`
    pub const TEST_NET_3: Ipv4Subnet = ipv4_subnet!("203.0.113.0/24");

    /// Address ranges reserved for documentation purposes
    ///
    /// This array consists of `TEST_NET_1`, `TEST_NET_2`, and `TEST_NET_3`
    /// * `192.0.2.0/24`
    /// * `198.51.100.0/24`
    /// * `203.0.113.0/24`
    pub const DOCUMENTATION_SUBNETS: [Ipv4Subnet; 3] = [
        ipv4_subnet!("192.0.2.0/24"),
        ipv4_subnet!("198.51.100.0/24"),
        ipv4_subnet!("203.0.113.0/24"),
    ];

    /// Creates an IPv4 address from a raw bytes representation
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Checks if the address is reserved for private networks
    pub fn is_private(&self) -> bool {
        for subnet in Self::PRIVATE_SUBNETS.iter() {
            if subnet.contains(self) {
                return true;
            }
        }
        false
    }

    /// Checks if the address is reserved for loopback
    pub fn is_loopback(&self) -> bool {
        Self::LOOPBACK_SUBNET.contains(self)
    }

    /// Checks if the address is reserved for multicast
    pub fn is_multicast(&self) -> bool {
        Self::MULTICAST_SUBNET.contains(self)
    }

    /// Checks if the address is the subnet broadcast address
    ///
    /// The last address of a subnet is the subnet's broadcast address.
    pub fn is_broadcast(&self, subnet: &Ipv4Subnet) -> bool {
        *self == subnet.base_addr() | !subnet.mask()
    }

    /// Checks if the address is a link local address
    pub fn is_link_local(&self) -> bool {
        Self::LINK_LOCAL_SUBNET.contains(self)
    }

    /// Checks if the address is in the shared address space
    pub fn is_shared(&self) -> bool {
        Self::SHARED_SUBNET.contains(self)
    }

    /// Checks if the address is reserved for benchmarking
    pub fn is_benchmarking(&self) -> bool {
        Self::BENCHMARKING_SUBNET.contains(self)
    }

    /// Checks if the address is reserved for future use
    pub fn is_reserved(&self) -> bool {
        Self::RESERVED_SUBNET.contains(self)
    }

    /// Checks if the address is reserved for documentation purposes
    pub fn is_documentation(&self) -> bool {
        for subnet in Self::DOCUMENTATION_SUBNETS.iter() {
            if subnet.contains(self) {
                return true;
            }
        }
        false
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Address {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self::new(addr.octets())
    }
}

impl From<Ipv4Address> for std::net::Ipv4Addr {
    fn from(addr: Ipv4Address) -> Self {
        addr.0.into()
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(raw: [u8; 4]) -> Self {
        Self(raw)
    }
}

impl From<Ipv4Address> for [u8; 4] {
    fn from(addr: Ipv4Address) -> Self {
        addr.0
    }
}

impl From<u32> for Ipv4Address {
    fn from(uint: u32) -> Self {
        Self(uint.to_ne_bytes())
    }
}

impl From<Ipv4Address> for u32 {
    fn from(addr: Ipv4Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<i32> for Ipv4Address {
    fn from(uint: i32) -> Self {
        Self(uint.to_ne_bytes())
    }
}

impl From<Ipv4Address> for i32 {
    fn from(addr: Ipv4Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl Deref for Ipv4Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Ipv4Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Ipv4Address {
    fn eq(&self, other: &Self) -> bool {
        self.value().eq(&other.value())
    }
}

impl Eq for Ipv4Address {}

impl PartialOrd for Ipv4Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value().partial_cmp(&other.value())
    }

    fn lt(&self, other: &Self) -> bool {
        self.value().lt(&other.value())
    }

    fn le(&self, other: &Self) -> bool {
        self.value().le(&other.value())
    }

    fn gt(&self, other: &Self) -> bool {
        self.value().gt(&other.value())
    }

    fn ge(&self, other: &Self) -> bool {
        self.value().ge(&other.value())
    }
}

impl Ord for Ipv4Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value().cmp(&other.value())
    }

    fn max(self, other: Self) -> Self {
        Self::from_value(self.value().max(other.value()))
    }

    fn min(self, other: Self) -> Self {
        Self::from_value(self.value().min(other.value()))
    }

    fn clamp(self, min: Self, max: Self) -> Self {
        Self::from_value(self.value().clamp(min.value(), max.value()))
    }
}

impl Hash for Ipv4Address {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.value().hash(state)
    }
}

impl BitAnd for Ipv4Address {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from_value(self.value() & rhs.value())
    }
}

impl BitAnd for &Ipv4Address {
    type Output = Ipv4Address;

    fn bitand(self, rhs: Self) -> Self::Output {
        Ipv4Address::from_value(self.value() & rhs.value())
    }
}

impl BitAnd<&Ipv4Address> for Ipv4Address {
    type Output = Ipv4Address;

    fn bitand(self, rhs: &Self) -> Self::Output {
        Self::from_value(self.value() & rhs.value())
    }
}

impl BitAnd<Ipv4Address> for &Ipv4Address {
    type Output = Ipv4Address;

    fn bitand(self, rhs: Ipv4Address) -> Self::Output {
        Ipv4Address::from_value(self.value() & rhs.value())
    }
}

impl BitAndAssign for Ipv4Address {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = &*self & &rhs;
    }
}

impl BitAndAssign<&Ipv4Address> for Ipv4Address {
    fn bitand_assign(&mut self, rhs: &Self) {
        *self = &*self & rhs;
    }
}

impl BitOr for Ipv4Address {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from_value(self.value() | rhs.value())
    }
}

impl BitOr for &Ipv4Address {
    type Output = Ipv4Address;

    fn bitor(self, rhs: Self) -> Self::Output {
        Ipv4Address::from_value(self.value() | rhs.value())
    }
}

impl BitOr<&Ipv4Address> for Ipv4Address {
    type Output = Ipv4Address;

    fn bitor(self, rhs: &Self) -> Self::Output {
        Self::from_value(self.value() | rhs.value())
    }
}

impl BitOr<Ipv4Address> for &Ipv4Address {
    type Output = Ipv4Address;

    fn bitor(self, rhs: Ipv4Address) -> Self::Output {
        Ipv4Address::from_value(self.value() | rhs.value())
    }
}

impl BitOrAssign for Ipv4Address {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = &*self | &rhs;
    }
}

impl BitOrAssign<&Ipv4Address> for Ipv4Address {
    fn bitor_assign(&mut self, rhs: &Self) {
        *self = &*self | rhs;
    }
}

impl BitXor for Ipv4Address {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor for &Ipv4Address {
    type Output = Ipv4Address;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Ipv4Address::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor<&Ipv4Address> for Ipv4Address {
    type Output = Ipv4Address;

    fn bitxor(self, rhs: &Self) -> Self::Output {
        Self::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor<Ipv4Address> for &Ipv4Address {
    type Output = Ipv4Address;

    fn bitxor(self, rhs: Ipv4Address) -> Self::Output {
        Ipv4Address::from_value(self.value() ^ rhs.value())
    }
}

impl BitXorAssign for Ipv4Address {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = &*self ^ &rhs;
    }
}

impl BitXorAssign<&Ipv4Address> for Ipv4Address {
    fn bitxor_assign(&mut self, rhs: &Self) {
        *self = &*self ^ rhs;
    }
}

impl Not for Ipv4Address {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from_value(!self.value())
    }
}

impl Not for &Ipv4Address {
    type Output = Ipv4Address;

    fn not(self) -> Self::Output {
        Ipv4Address::from_value(!self.value())
    }
}

impl FromStr for Ipv4Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_ipv4(s)?))
    }
}

impl Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

unsafe impl bytemuck::Zeroable for Ipv4Address {}

unsafe impl bytemuck::Pod for Ipv4Address {}

impl Decode for Ipv4Address {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
        self.0.decode(buf)
    }

    fn decode_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<(), DecodeError> {
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(slice);
        bytes.decode(buf)
    }
}

impl Encodable for Ipv4Address {
    fn encoded_size(&self) -> usize {
        4
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        4 * slice.len()
    }
}

impl Encode for Ipv4Address {
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        self.0.encode(buf)
    }

    fn encode_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        let bytes: &[u8] = bytemuck::cast_slice(slice);
        bytes.encode(buf)
    }
}

impl Address for Ipv4Address {
    type Raw = [u8; 4];

    fn from_prefix_len(prefix_len: u32) -> Self {
        if prefix_len >= 32 {
            Self::from_value(!0u32)
        } else {
            Self::from_value(!(!0u32 >> prefix_len))
        }
    }

    fn as_prefix_len(&self) -> u32 {
        self.value().leading_ones()
    }

    fn next_addr(&self) -> Self {
        Self::from_value(self.value().wrapping_add(1))
    }

    fn prev_addr(&self) -> Self {
        Self::from_value(self.value().wrapping_sub(1))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{ipv4, ipv4_subnet, AddressParseError, SubnetParseError};
    use std::str::FromStr;

    type Addr = Ipv4Address;
    type Subnet = Ipv4Subnet;

    #[test]
    fn from_macro() {
        const ADDR1: Addr = ipv4!("127.0.0.1");
        assert_eq!(ADDR1, Addr::new([127, 0, 0, 1]));

        const ADDR2: Addr = ipv4!("0.0.0.0");
        assert_eq!(ADDR2, Addr::new([0, 0, 0, 0]));

        const ADDR3: Addr = ipv4!("255.255.255.255");
        assert_eq!(ADDR3, Addr::new([255, 255, 255, 255]));

        const SUBNET: Subnet = ipv4_subnet!("127.0.0.1/8");
        assert_eq!(SUBNET.base_addr(), Addr::new([127, 0, 0, 0]));
        assert_eq!(SUBNET.prefix_len(), 8);
        assert_eq!(SUBNET.mask(), Addr::new([255, 0, 0, 0]));
    }

    #[test]
    fn addr_from_str() -> Result<(), AddressParseError> {
        assert!(Addr::from_str("").is_err());
        assert!(Addr::from_str("1").is_err());
        assert!(Addr::from_str("1.1").is_err());
        assert!(Addr::from_str("1.1.1").is_err());
        assert_eq!(Addr::from_str("1.1.1.1")?, Addr::new([1, 1, 1, 1]));
        assert!(Addr::from_str("1.1.1.1.1").is_err());
        assert_eq!(Addr::from_str("0.0.0.0")?, Addr::new([0, 0, 0, 0]));
        assert_eq!(
            Addr::from_str("255.255.255.255")?,
            Addr::new([255, 255, 255, 255])
        );
        assert!(Addr::from_str("...").is_err());
        assert!(Addr::from_str(".0.0.").is_err());
        assert!(Addr::from_str("..").is_err());
        assert!(Addr::from_str(".").is_err());
        assert!(Addr::from_str("256.0.0.0").is_err());
        assert!(Addr::from_str("0.256.0.0").is_err());
        assert!(Addr::from_str("0.0.256.0").is_err());
        assert!(Addr::from_str("0.0.0.256").is_err());
        Ok(())
    }

    #[test]
    fn addr_to_str() {
        assert_eq!(Addr::new([0, 0, 0, 0]).to_string(), "0.0.0.0");
        assert_eq!(
            Addr::new([255, 255, 255, 255]).to_string(),
            "255.255.255.255"
        );
    }

    #[test]
    fn subnet_from_str() -> Result<(), SubnetParseError> {
        let subnet: Subnet = "1.1.1.1".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([1, 1, 1, 1]));
        assert_eq!(subnet.prefix_len(), 32);
        assert_eq!(subnet.mask(), Addr::new([255, 255, 255, 255]));

        let subnet: Subnet = "1.1.1.1/32".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([1, 1, 1, 1]));
        assert_eq!(subnet.prefix_len(), 32);
        assert_eq!(subnet.mask(), Addr::new([255, 255, 255, 255]));

        let subnet: Subnet = "1.1.1.1/0".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([0, 0, 0, 0]));
        assert_eq!(subnet.prefix_len(), 0);
        assert_eq!(subnet.mask(), Addr::new([0, 0, 0, 0]));

        let subnet: Subnet = "1.1.1.1/16".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([1, 1, 0, 0]));
        assert_eq!(subnet.prefix_len(), 16);
        assert_eq!(subnet.mask(), Addr::new([255, 255, 0, 0]));

        assert!(Subnet::from_str("1.1.1.1/").is_err());
        assert!(Subnet::from_str("1.1.1.1/33").is_err());

        Ok(())
    }

    #[test]
    fn subnet_to_str() {
        assert_eq!(
            Subnet::new(Addr::new([1, 1, 1, 1]), 0).to_string(),
            "0.0.0.0/0"
        );
        assert_eq!(
            Subnet::new(Addr::new([1, 1, 1, 1]), 32).to_string(),
            "1.1.1.1/32"
        );
        assert_eq!(
            Subnet::new(Addr::new([1, 1, 1, 1]), 16).to_string(),
            "1.1.0.0/16"
        );
    }

    #[test]
    fn from_prefix_len() {
        assert_eq!(Addr::from_prefix_len(0), Addr::new([0, 0, 0, 0]));
        assert_eq!(Addr::from_prefix_len(4), Addr::new([0xF0, 0, 0, 0]));
        assert_eq!(Addr::from_prefix_len(8), Addr::new([0xFF, 0, 0, 0]));
        assert_eq!(Addr::from_prefix_len(12), Addr::new([0xFF, 0xF0, 0, 0]));
        assert_eq!(Addr::from_prefix_len(16), Addr::new([0xFF, 0xFF, 0, 0]));
        assert_eq!(Addr::from_prefix_len(20), Addr::new([0xFF, 0xFF, 0xF0, 0]));
        assert_eq!(Addr::from_prefix_len(24), Addr::new([0xFF, 0xFF, 0xFF, 0]));
        assert_eq!(
            Addr::from_prefix_len(28),
            Addr::new([0xFF, 0xFF, 0xFF, 0xF0])
        );
        assert_eq!(
            Addr::from_prefix_len(32),
            Addr::new([0xFF, 0xFF, 0xFF, 0xFF])
        );
        assert_eq!(
            Addr::from_prefix_len(36),
            Addr::new([0xFF, 0xFF, 0xFF, 0xFF])
        );
    }

    #[test]
    fn to_prefix_len() {
        assert_eq!(Addr::new([0, 0, 0, 0]).as_prefix_len(), 0);
        assert_eq!(Addr::new([0xF0, 0, 0, 0]).as_prefix_len(), 4);
        assert_eq!(Addr::new([0xFF, 0, 0, 0]).as_prefix_len(), 8);
        assert_eq!(Addr::new([0xFF, 0xF0, 0, 0]).as_prefix_len(), 12);
        assert_eq!(Addr::new([0xFF, 0xFF, 0, 0]).as_prefix_len(), 16);
        assert_eq!(Addr::new([0xFF, 0xFF, 0xF0, 0]).as_prefix_len(), 20);
        assert_eq!(Addr::new([0xFF, 0xFF, 0xFF, 0]).as_prefix_len(), 24);
        assert_eq!(Addr::new([0xFF, 0xFF, 0xFF, 0xF0]).as_prefix_len(), 28);
        assert_eq!(Addr::new([0xFF, 0xFF, 0xFF, 0xFF]).as_prefix_len(), 32);
    }
}
