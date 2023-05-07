use std::{
    cmp::Ordering,
    fmt::{self, Display},
    hash::{Hash, Hasher},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, DerefMut, Not},
    str::FromStr,
};

use sniffle_decode::{Decode, DecodeBuf, DecodeError};
use sniffle_encode::{Encodable, Encode, EncodeBuf};

use bytemuck;

use crate::{ipv6, ipv6_subnet, Address, AddressParseError, Subnet};

use sniffle_address_parse::parse_ipv6;

/// Representation of an IPv4 address
#[derive(Clone, Copy, Debug, Default)]
#[repr(transparent)]
pub struct Ipv6Address([u8; 16]);

/// Representtion of an IPv4 subnet
pub type Ipv6Subnet = Subnet<Ipv6Address>;

impl Ipv6Address {
    fn value(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    fn from_value(val: u128) -> Self {
        Self(val.to_be_bytes())
    }

    /// IPv6 address commonly used to represent an unspecified (or any) address
    ///
    /// `::`
    pub const UNSPECIFIED: Ipv6Address = ipv6!("::");

    /// The IPv6 localhost address
    ///
    /// `::1`
    pub const LOCALHOST: Ipv6Address = ipv6!("::1");

    /// Address reserved for unique local use
    ///
    /// `fc00::/7`
    pub const UNIQUE_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("fc00::/7");

    /// Addresses reserved for multicast
    ///
    /// `ff00::/8`
    pub const MULTICAST_SUBNET: Ipv6Subnet = ipv6_subnet!("ff00::/8");

    /// Addresses reserved for link-local scoped unicast
    ///
    /// `fe80::/10`
    pub const UNICAST_LINK_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("fe80::/10");

    /// Addresses reserved for documentation
    ///
    /// `2001:db8::/32`
    pub const DOCUMENTATION_SUBNET: Ipv6Subnet = ipv6_subnet!("2001:db8::/32");

    /// Addresses reserved for benchmarking
    ///
    /// `2001:2::/48`
    pub const BENCHMARKING_SUBNET: Ipv6Subnet = ipv6_subnet!("2001:2::/48");

    /// Multicast addresses with interface-local scope
    ///
    /// `ff01::/16`
    pub const MULTICAST_INTERFACE_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff01::/16");

    /// Multicast addresses with link local scope
    ///
    /// `ff02::/16`
    pub const MULTICAST_LINK_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff02::/16");

    /// Multicast addresses with realm-local scope
    ///
    /// `ff03::/16`
    pub const MULTICAST_REALM_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff03::/16");

    /// Multicast addresses with admin-local scope
    ///
    /// `ff04::/16`
    pub const MULTICAST_ADMIN_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff04::/16");

    /// Multicast addresses with site-local scope
    ///
    /// `ff05::/16`
    pub const MULTICAST_SITE_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff05::/16");

    /// Multicast addresses with organization-local scope
    ///
    /// `ff08::/16`
    pub const MULTICAST_ORGANIZATION_LOCAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff08::/16");

    /// Multicast addresses with global scope
    ///
    /// `ff0e::/16`
    pub const MULTICAST_GLOBAL_SUBNET: Ipv6Subnet = ipv6_subnet!("ff0e::/16");

    /// Addresses reserved for IPv4 mapped addresses
    ///
    /// `::ffff:0:0`
    pub const IPV4_MAPPED_SUBNET: Ipv6Subnet = ipv6_subnet!("::ffff:0:0/96");

    /// Addresses reserved for IPv4 compatibility
    ///
    /// `::/96`
    pub const IPV4_COMPAT_SUBNET: Ipv6Subnet = ipv6_subnet!("::/96");

    /// Creates an IPv6 address from a raw bytes representation
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Creates an IPv6 address from raw 16-bit words
    pub const fn from_words(words: [u16; 8]) -> Self {
        let segs = [
            words[0].to_be_bytes(),
            words[1].to_be_bytes(),
            words[2].to_be_bytes(),
            words[3].to_be_bytes(),
            words[4].to_be_bytes(),
            words[5].to_be_bytes(),
            words[6].to_be_bytes(),
            words[7].to_be_bytes(),
        ];
        Self([
            segs[0][0], segs[0][1], segs[1][0], segs[1][1], segs[2][0], segs[2][1], segs[3][0],
            segs[3][1], segs[4][0], segs[4][1], segs[5][0], segs[5][1], segs[6][0], segs[6][1],
            segs[7][0], segs[7][1],
        ])
    }

    /// Returns true if this address is the loopback address, `::1`
    pub fn is_loopback(&self) -> bool {
        return *self == Self::LOCALHOST;
    }

    /// Returns true if this is a unique local address
    pub fn is_unique_local(&self) -> bool {
        Self::UNIQUE_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a multicast address
    pub fn is_multicast(&self) -> bool {
        Self::MULTICAST_SUBNET.contains(self)
    }

    /// Returns true if this is a unicast link-local address
    pub fn is_unicast_link_local(&self) -> bool {
        Self::UNICAST_LINK_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a reserved for documentation address
    pub fn is_documentation(&self) -> bool {
        Self::DOCUMENTATION_SUBNET.contains(self)
    }

    /// Returns true if this is a reserved for benchmarking address
    pub fn is_benchmarking(&self) -> bool {
        Self::BENCHMARKING_SUBNET.contains(self)
    }

    /// Returns true if this is a interface-local scoped multicast address
    pub fn is_multicast_interface_local(&self) -> bool {
        Self::MULTICAST_INTERFACE_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a link-local scoped multicast address
    pub fn is_multicast_link_local(&self) -> bool {
        Self::MULTICAST_LINK_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a realm-local scoped multicast address
    pub fn is_multicast_realm_local(&self) -> bool {
        Self::MULTICAST_REALM_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a admin-local scoped multicast address
    pub fn is_multicast_admin_local(&self) -> bool {
        Self::MULTICAST_ADMIN_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a site-local scoped multicast address
    pub fn is_multicast_site_local(&self) -> bool {
        Self::MULTICAST_SITE_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a organization-local scoped multicast address
    pub fn is_multicast_organization_local(&self) -> bool {
        Self::MULTICAST_ORGANIZATION_LOCAL_SUBNET.contains(self)
    }

    /// Returns true if this is a global scoped multicast address
    pub fn is_multicast_global(&self) -> bool {
        Self::MULTICAST_GLOBAL_SUBNET.contains(self)
    }

    /// Returns true if this is an IPv4 mapped address
    pub fn is_ipv4_mapped(&self) -> bool {
        Self::IPV4_MAPPED_SUBNET.contains(self)
    }

    /// Returns true if this is an IPv4 compatible address
    pub fn is_ipv4_compatible(&self) -> bool {
        Self::IPV4_COMPAT_SUBNET.contains(self)
    }

    /// Returns true if this is a unicast address
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }
}

impl From<crate::Ipv4Address> for Ipv6Address {
    fn from(v4: crate::Ipv4Address) -> Self {
        let v4: [u8; 4] = v4.into();
        Self([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, v4[0], v4[1], v4[2], v4[3],
        ])
    }
}

impl From<std::net::Ipv4Addr> for Ipv6Address {
    fn from(v4: std::net::Ipv4Addr) -> Self {
        let v4 = v4.octets();
        Self([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, v4[0], v4[1], v4[2], v4[3],
        ])
    }
}

impl From<std::net::Ipv6Addr> for Ipv6Address {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self::new(addr.octets())
    }
}

impl From<Ipv6Address> for std::net::Ipv6Addr {
    fn from(addr: Ipv6Address) -> Self {
        addr.0.into()
    }
}

impl From<[u8; 16]> for Ipv6Address {
    fn from(raw: [u8; 16]) -> Self {
        Self(raw)
    }
}

impl From<Ipv6Address> for [u8; 16] {
    fn from(addr: Ipv6Address) -> Self {
        addr.0
    }
}

impl From<[u16; 8]> for Ipv6Address {
    fn from(raw: [u16; 8]) -> Self {
        Self(bytemuck::cast(raw))
    }
}

impl From<Ipv6Address> for [u16; 8] {
    fn from(addr: Ipv6Address) -> Self {
        bytemuck::cast(addr.0)
    }
}

impl From<u128> for Ipv6Address {
    fn from(uint: u128) -> Self {
        Self(uint.to_ne_bytes())
    }
}

impl From<Ipv6Address> for u128 {
    fn from(addr: Ipv6Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<i128> for Ipv6Address {
    fn from(uint: i128) -> Self {
        Self(uint.to_ne_bytes())
    }
}

impl From<Ipv6Address> for i128 {
    fn from(addr: Ipv6Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl Deref for Ipv6Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Ipv6Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Ipv6Address {
    fn eq(&self, other: &Self) -> bool {
        self.value().eq(&other.value())
    }
}

impl Eq for Ipv6Address {}

impl PartialOrd for Ipv6Address {
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

impl Ord for Ipv6Address {
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

impl Hash for Ipv6Address {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.value().hash(state)
    }
}

impl BitAnd for Ipv6Address {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from_value(self.value() & rhs.value())
    }
}

impl BitAnd for &Ipv6Address {
    type Output = Ipv6Address;

    fn bitand(self, rhs: Self) -> Self::Output {
        Ipv6Address::from_value(self.value() & rhs.value())
    }
}

impl BitAnd<&Ipv6Address> for Ipv6Address {
    type Output = Ipv6Address;

    fn bitand(self, rhs: &Self) -> Self::Output {
        Self::from_value(self.value() & rhs.value())
    }
}

impl BitAnd<Ipv6Address> for &Ipv6Address {
    type Output = Ipv6Address;

    fn bitand(self, rhs: Ipv6Address) -> Self::Output {
        Ipv6Address::from_value(self.value() & rhs.value())
    }
}

impl BitAndAssign for Ipv6Address {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = &*self & &rhs;
    }
}

impl BitAndAssign<&Ipv6Address> for Ipv6Address {
    fn bitand_assign(&mut self, rhs: &Self) {
        *self = &*self & rhs;
    }
}

impl BitOr for Ipv6Address {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from_value(self.value() | rhs.value())
    }
}

impl BitOr for &Ipv6Address {
    type Output = Ipv6Address;

    fn bitor(self, rhs: Self) -> Self::Output {
        Ipv6Address::from_value(self.value() | rhs.value())
    }
}

impl BitOr<&Ipv6Address> for Ipv6Address {
    type Output = Ipv6Address;

    fn bitor(self, rhs: &Self) -> Self::Output {
        Self::from_value(self.value() | rhs.value())
    }
}

impl BitOr<Ipv6Address> for &Ipv6Address {
    type Output = Ipv6Address;

    fn bitor(self, rhs: Ipv6Address) -> Self::Output {
        Ipv6Address::from_value(self.value() | rhs.value())
    }
}

impl BitOrAssign for Ipv6Address {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = &*self | &rhs;
    }
}

impl BitOrAssign<&Ipv6Address> for Ipv6Address {
    fn bitor_assign(&mut self, rhs: &Self) {
        *self = &*self | rhs;
    }
}

impl BitXor for Ipv6Address {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor for &Ipv6Address {
    type Output = Ipv6Address;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Ipv6Address::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor<&Ipv6Address> for Ipv6Address {
    type Output = Ipv6Address;

    fn bitxor(self, rhs: &Self) -> Self::Output {
        Self::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor<Ipv6Address> for &Ipv6Address {
    type Output = Ipv6Address;

    fn bitxor(self, rhs: Ipv6Address) -> Self::Output {
        Ipv6Address::from_value(self.value() ^ rhs.value())
    }
}

impl BitXorAssign for Ipv6Address {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = &*self ^ &rhs;
    }
}

impl BitXorAssign<&Ipv6Address> for Ipv6Address {
    fn bitxor_assign(&mut self, rhs: &Self) {
        *self = &*self ^ rhs;
    }
}

impl Not for Ipv6Address {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from_value(!self.value())
    }
}

impl Not for &Ipv6Address {
    type Output = Ipv6Address;

    fn not(self) -> Self::Output {
        Ipv6Address::from_value(!self.value())
    }
}

impl FromStr for Ipv6Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_ipv6(s)?))
    }
}

impl Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let disp = [
            u16::from_be_bytes([self.0[0], self.0[1]]),
            u16::from_be_bytes([self.0[2], self.0[3]]),
            u16::from_be_bytes([self.0[4], self.0[5]]),
            u16::from_be_bytes([self.0[6], self.0[7]]),
            u16::from_be_bytes([self.0[8], self.0[9]]),
            u16::from_be_bytes([self.0[10], self.0[11]]),
            u16::from_be_bytes([self.0[12], self.0[13]]),
            u16::from_be_bytes([self.0[14], self.0[15]]),
        ];

        let mut start: usize = 0;
        let mut end: usize = 0;
        let mut tmp_start: usize = 0;
        let mut tmp_end: usize = 0;
        for (n, word) in disp.iter().enumerate() {
            if *word == 0 {
                tmp_end = n + 1;
            } else if tmp_end - tmp_start > end - start {
                start = tmp_start;
                end = tmp_end;
                tmp_start = n + 1;
                tmp_end = n + 1;
            } else {
                tmp_start = n + 1;
                tmp_end = n + 1;
            }
        }
        if tmp_end - tmp_start > end - start {
            start = tmp_start;
            end = tmp_end;
        }

        if start == end {
            write!(
                f,
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                disp[0], disp[1], disp[2], disp[3], disp[4], disp[5], disp[6], disp[7],
            )
        } else if start == 0 {
            if end == 8 {
                write!(f, "::")?;
            } else {
                write!(f, ":")?;
                for word in disp[end..].iter() {
                    write!(f, ":{:x}", word)?;
                }
            }
            Ok(())
        } else if end == 8 {
            for word in disp[..start].iter() {
                write!(f, "{:x}:", word)?;
            }
            write!(f, ":")
        } else {
            for word in disp[..start].iter() {
                write!(f, "{:x}:", word)?;
            }
            for word in disp[end..].iter() {
                write!(f, ":{:x}", word)?;
            }
            Ok(())
        }
    }
}

unsafe impl bytemuck::Zeroable for Ipv6Address {}

unsafe impl bytemuck::Pod for Ipv6Address {}

impl Decode for Ipv6Address {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
        self.0.decode(buf)
    }

    fn decode_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<(), DecodeError> {
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(slice);
        bytes.decode(buf)
    }
}

impl Encodable for Ipv6Address {
    fn encoded_size(&self) -> usize {
        16
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        16 * slice.len()
    }
}

impl Encode for Ipv6Address {
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        self.0.encode(buf);
    }

    fn encode_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        let bytes: &[u8] = bytemuck::cast_slice(slice);
        bytes.encode(buf);
    }
}

impl Address for Ipv6Address {
    type Raw = [u8; 16];

    fn from_prefix_len(prefix_len: u32) -> Self {
        if prefix_len >= 128 {
            Self::from_value(!0u128)
        } else {
            Self::from_value(!(!0u128 >> prefix_len))
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
    use crate::{AddressParseError, SubnetParseError};

    type Addr = Ipv6Address;
    type Subnet = Ipv6Subnet;

    #[test]
    fn addr_from_str() -> Result<(), AddressParseError> {
        assert!(Addr::from_str("").is_err());
        assert!(Addr::from_str("1").is_err());
        assert!(Addr::from_str("1:1").is_err());
        assert_eq!(
            Addr::from_str("::")?,
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            Addr::from_str("1::")?,
            Addr::new([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            Addr::from_str("::1")?,
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            Addr::from_str("1::1")?,
            Addr::new([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            Addr::from_str("1:1:1:1:1:1:1:1")?,
            Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
        );
        assert!(Addr::from_str(":::").is_err());
        assert!(Addr::from_str("::::").is_err());
        assert!(Addr::from_str("1::1::1").is_err());
        assert!(Addr::from_str("::1::").is_err());
        assert_eq!(
            Addr::from_str("1:1::1:1")?,
            Addr::new([0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1])
        );
        assert!(Addr::from_str("::fffff").is_err());
        assert!(Addr::from_str("::defg").is_err());
        assert_eq!(
            Addr::from_str("::ffff")?,
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF])
        );

        Ok(())
    }

    #[test]
    fn addr_to_str() {
        assert_eq!(
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(),
            "::"
        );
        assert_eq!(
            Addr::new([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(),
            "1::"
        );
        assert_eq!(
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).to_string(),
            "::1"
        );
        assert_eq!(
            Addr::new([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).to_string(),
            "1::1"
        );
        assert_eq!(
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]).to_string(),
            "::1:1"
        );
        assert_eq!(
            Addr::new([0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(),
            "1:1::"
        );
        assert_eq!(
            Addr::new([0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]).to_string(),
            "1:1::1:1"
        );
        assert_eq!(
            Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]).to_string(),
            "1:1:1:1:1:1:1:1"
        );
    }

    #[test]
    fn subnet_from_str() -> Result<(), SubnetParseError> {
        let subnet: Subnet = "fe80::1".parse()?;
        assert_eq!(
            subnet.base_addr(),
            Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(subnet.prefix_len(), 128);
        assert_eq!(
            subnet.mask(),
            Addr::new([
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
            ])
        );

        let subnet: Subnet = "fe80::1/128".parse()?;
        assert_eq!(
            subnet.base_addr(),
            Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(subnet.prefix_len(), 128);
        assert_eq!(
            subnet.mask(),
            Addr::new([
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
            ])
        );

        let subnet: Subnet = "fe80::1/0".parse()?;
        assert_eq!(
            subnet.base_addr(),
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(subnet.prefix_len(), 0);
        assert_eq!(
            subnet.mask(),
            Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );

        let subnet: Subnet = "fe80::1/64".parse()?;
        assert_eq!(
            subnet.base_addr(),
            Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(subnet.prefix_len(), 64);
        assert_eq!(
            subnet.mask(),
            Addr::new([255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0])
        );

        assert!(Subnet::from_str("fe80::1/").is_err());
        assert!(Subnet::from_str("fe80::1/129").is_err());

        Ok(())
    }

    #[test]
    fn subnet_to_str() {
        assert_eq!(
            Subnet::new(
                Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]),
                0
            )
            .to_string(),
            "::/0"
        );
        assert_eq!(
            Subnet::new(
                Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]),
                128
            )
            .to_string(),
            "1:1:1:1:1:1:1:1/128"
        );
        assert_eq!(
            Subnet::new(
                Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]),
                64
            )
            .to_string(),
            "1:1:1:1::/64"
        );
    }
}
