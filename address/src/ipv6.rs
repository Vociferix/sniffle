use std::{
    fmt::{self, Display},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, DerefMut, Not},
    str::FromStr,
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use sniffle_ende::{
    decode::{cast, DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

use bytemuck;

use crate::{Address, Subnet, AddressParseError};

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

    pub const UNSPECIFIED: Ipv6Address = Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    pub const LOCALHOST: Ipv6Address = Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    pub const UNIQUE_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 7);

    pub const MULTICAST_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 8);

    pub const UNICAST_LINK_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 10);

    pub const DOCUMENTATION_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 32);

    pub const BENCHMARKING_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0x20, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48);

    pub const MULTICAST_INTERFACE_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const MULTICAST_LINK_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const MULTICAST_REALM_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const MULTICAST_ADMIN_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const MULTICAST_SITE_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const MULTICAST_ORGANIZATION_LOCAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const MULTICAST_GLOBAL_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 16);

    pub const IPV4_MAPPED_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]), 96);

    pub const IPV4_COMPAT_SUBNET: Ipv6Subnet = Ipv6Subnet::new(Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 96);

    /// Creates an IPv6 address from a raw bytes representation
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn is_loopback(&self) -> bool {
        return *self == Self::LOCALHOST;
    }

    pub fn is_unique_local(&self) -> bool {
        Self::UNIQUE_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast(&self) -> bool {
        Self::MULTICAST_SUBNET.contains(self)
    }

    pub fn is_unicast_link_local(&self) -> bool {
        Self::UNICAST_LINK_LOCAL_SUBNET.contains(self)
    }

    pub fn is_documentation(&self) -> bool {
        Self::DOCUMENTATION_SUBNET.contains(self)
    }

    pub fn is_benchmarking(&self) -> bool {
        Self::BENCHMARKING_SUBNET.contains(self)
    }

    pub fn is_multicast_interface_local(&self) -> bool {
        Self::MULTICAST_INTERFACE_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast_link_local(&self) -> bool {
        Self::MULTICAST_LINK_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast_realm_local(&self) -> bool {
        Self::MULTICAST_REALM_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast_admin_local(&self) -> bool {
        Self::MULTICAST_ADMIN_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast_site_local(&self) -> bool {
        Self::MULTICAST_SITE_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast_organization_local(&self) -> bool {
        Self::MULTICAST_ORGANIZATION_LOCAL_SUBNET.contains(self)
    }

    pub fn is_multicast_global(&self) -> bool {
        Self::MULTICAST_GLOBAL_SUBNET.contains(self)
    }

    pub fn is_ipv4_mapped(&self) -> bool {
        Self::IPV4_MAPPED_SUBNET.contains(self)
    }

    pub fn is_ipv4_compatible(&self) -> bool {
        Self::IPV4_COMPAT_SUBNET.contains(self)
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
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

impl Eq for Ipv6Address { }

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
        where H: Hasher
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
        let mut addr = [0u8; 16];
        let mut idx = 0usize;

        let mut iter = s.split("::");
        let Some(first) = iter.next() else {
            return Err(AddressParseError::InvalidLength);
        };

        if !first.is_empty() {
            for word in first.split(':') {
                if idx >= 16 {
                    return Err(AddressParseError::InvalidLength);
                }

                let w = u16::from_str_radix(word, 16)?.to_be_bytes();
                addr[idx] = w[0];
                idx += 1;
                addr[idx] = w[1];
                idx += 1;
            }
        }

        if let Some(second) = iter.next() {
            if let Some(_) = iter.next() {
                return Err(AddressParseError::InvalidLength);
            }

            let end = idx;
            idx = 15;

            if !second.is_empty() {
                for word in second.split(':').rev() {
                    if idx < end {
                        return Err(AddressParseError::InvalidLength);
                    }

                    let w = u16::from_str_radix(word, 16)?.to_be_bytes();
                    addr[idx] = w[1];
                    idx -= 1;
                    addr[idx] = w[0];
                    idx -= 1;
                }
            }
        } else if idx < 16 {
            return Err(AddressParseError::InvalidLength);
        }

        Ok(Self::new(addr))
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

impl Decode for Ipv6Address {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(<[u8; 16]>::decode, Self::from)(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

impl Encode for Ipv6Address {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        encoder.encode(&self[..]).map(|_| ())
    }

    fn encode_many<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> std::io::Result<()> {
        unsafe {
            encoder.encode(std::slice::from_raw_parts(
                slice.as_ptr() as *const u8,
                slice.len() * 16,
            ))
            .map(|_| ())
        }
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
    use crate::{SubnetParseError, AddressParseError};

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
        assert_eq!(Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(), "::");
        assert_eq!(Addr::new([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(), "1::");
        assert_eq!(Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).to_string(), "::1");
        assert_eq!(Addr::new([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).to_string(), "1::1");
        assert_eq!(Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]).to_string(), "::1:1");
        assert_eq!(Addr::new([0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(), "1:1::");
        assert_eq!(Addr::new([0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]).to_string(), "1:1::1:1");
        assert_eq!(Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]).to_string(), "1:1:1:1:1:1:1:1");
    }

    #[test]
    fn subnet_from_str() -> Result<(), SubnetParseError> {
        let subnet: Subnet = "fe80::1".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(subnet.prefix_len(), 128);
        assert_eq!(subnet.mask(), Addr::new([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]));

        let subnet: Subnet = "fe80::1/128".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(subnet.prefix_len(), 128);
        assert_eq!(subnet.mask(), Addr::new([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]));

        let subnet: Subnet = "fe80::1/0".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(subnet.prefix_len(), 0);
        assert_eq!(subnet.mask(), Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

        let subnet: Subnet = "fe80::1/64".parse()?;
        assert_eq!(subnet.base_addr(), Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(subnet.prefix_len(), 64);
        assert_eq!(subnet.mask(), Addr::new([255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]));

        assert!(Subnet::from_str("fe80::1/").is_err());
        assert!(Subnet::from_str("fe80::1/129").is_err());

        Ok(())
    }

    #[test]
    fn subnet_to_str() {
        assert_eq!(Subnet::new(Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]), 0).to_string(), "::/0");
        assert_eq!(Subnet::new(Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]), 128).to_string(), "1:1:1:1:1:1:1:1/128");
        assert_eq!(Subnet::new(Addr::new([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]), 64).to_string(), "1:1:1:1::/64");
    }
}
