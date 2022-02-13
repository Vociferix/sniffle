use sniffle_ende::{
    decode::{cast, DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct IPv4Address([u8; 4]);

pub struct IPv4Network {
    base: IPv4Address,
    mask: IPv4Address,
}

pub struct IPv4NetworkIter {
    curr: Option<u32>,
    last: u32,
}

impl Iterator for IPv4NetworkIter {
    type Item = IPv4Address;

    fn next(&mut self) -> Option<Self::Item> {
        let tmp = self.curr.clone();
        match tmp {
            Some(addr) => {
                if addr == self.last {
                    self.curr = None;
                } else {
                    self.curr = Some(addr + 1);
                }
                Some(IPv4Address(addr.to_be_bytes()))
            }
            None => None,
        }
    }
}

impl IPv4Network {
    pub const fn new(base: IPv4Address, mask: IPv4Address) -> Self {
        Self { base, mask }
    }

    pub const fn from_prefix_len(base: IPv4Address, prefix_len: u32) -> Self {
        Self {
            base,
            mask: IPv4Address::from_prefix_len(prefix_len),
        }
    }

    pub const fn base_address(&self) -> &IPv4Address {
        &self.base
    }

    pub const fn network_mask(&self) -> &IPv4Address {
        &self.mask
    }

    pub fn contains(&self, addr: &IPv4Address) -> bool {
        (*addr & self.mask) == self.base
    }

    pub fn first(&self) -> IPv4Address {
        self.base
    }

    pub fn last(&self) -> IPv4Address {
        self.base | self.mask
    }

    pub fn iter(&self) -> IPv4NetworkIter {
        IPv4NetworkIter {
            curr: Some(u32::from_be_bytes(self.first().0)),
            last: u32::from_be_bytes(self.last().0),
        }
    }
}

impl IntoIterator for IPv4Network {
    type Item = IPv4Address;
    type IntoIter = IPv4NetworkIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IPv4Address {
    const PRIVATE_NETS: [IPv4Network; 3] = [
        IPv4Network::from_prefix_len(IPv4Address::new(10, 0, 0, 0), 8),
        IPv4Network::from_prefix_len(IPv4Address::new(172, 16, 0, 0), 12),
        IPv4Network::from_prefix_len(IPv4Address::new(192, 168, 0, 0), 16),
    ];

    const LOOPBACK_NET: IPv4Network =
        IPv4Network::from_prefix_len(IPv4Address::new(127, 0, 0, 0), 8);

    const MULTICAST_NET: IPv4Network =
        IPv4Network::from_prefix_len(IPv4Address::new(224, 0, 0, 0), 4);

    pub const fn new(b0: u8, b1: u8, b2: u8, b3: u8) -> Self {
        Self([b0, b1, b2, b3])
    }

    pub const fn from_prefix_len(prefix_len: u32) -> IPv4Address {
        IPv4Address((!(!0u32 >> prefix_len)).to_be_bytes())
    }

    pub fn is_private(&self) -> bool {
        for net in Self::PRIVATE_NETS.iter() {
            if net.contains(self) {
                return true;
            }
        }
        false
    }

    pub fn is_loopback(&self) -> bool {
        Self::LOOPBACK_NET.contains(self)
    }

    pub fn is_multicast(&self) -> bool {
        Self::MULTICAST_NET.contains(self)
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    pub fn next(&self) -> IPv4Address {
        IPv4Address::from(u32::from(*self).wrapping_add(1))
    }

    pub fn prev(&self) -> IPv4Address {
        IPv4Address::from(u32::from(*self).wrapping_sub(1))
    }
}

impl From<[u8; 4]> for IPv4Address {
    fn from(addr: [u8; 4]) -> Self {
        Self(addr)
    }
}

impl From<IPv4Address> for [u8; 4] {
    fn from(addr: IPv4Address) -> Self {
        addr.0
    }
}

impl From<u32> for IPv4Address {
    fn from(addr: u32) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<IPv4Address> for u32 {
    fn from(addr: IPv4Address) -> Self {
        u32::from_ne_bytes(addr.0)
    }
}

impl From<i32> for IPv4Address {
    fn from(addr: i32) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<IPv4Address> for i32 {
    fn from(addr: IPv4Address) -> i32 {
        i32::from_ne_bytes(addr.0)
    }
}

impl Decode for IPv4Address {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(<[u8; 4]>::decode, |bytes| Self::from(bytes))(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

impl Encode for IPv4Address {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        encoder.encode(&self[..]).map(|_| ())
    }

    fn encode_many<'a, W: Encoder<'a> + ?Sized>(
        slice: &[Self],
        encoder: &mut W,
    ) -> std::io::Result<()> {
        unsafe {
            encoder
                .encode(std::slice::from_raw_parts(
                    slice.as_ptr() as *const u8,
                    slice.len() * 4,
                ))
                .map(|_| ())
        }
    }
}

impl std::ops::Deref for IPv4Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl std::ops::DerefMut for IPv4Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub enum IPv4ParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
}

impl From<std::num::ParseIntError> for IPv4ParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        IPv4ParseError::ParseInt(e)
    }
}

impl std::str::FromStr for IPv4Address {
    type Err = IPv4ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 4];
        let mut iter = s.split('.');
        addr[0] = u8::from_str_radix(iter.next().ok_or(IPv4ParseError::BadLength)?, 10)?;
        addr[1] = u8::from_str_radix(iter.next().ok_or(IPv4ParseError::BadLength)?, 10)?;
        addr[2] = u8::from_str_radix(iter.next().ok_or(IPv4ParseError::BadLength)?, 10)?;
        addr[3] = u8::from_str_radix(iter.next().ok_or(IPv4ParseError::BadLength)?, 10)?;
        iter.next()
            .ok_or(())
            .err()
            .ok_or(IPv4ParseError::BadLength)?;
        Ok(Self(addr))
    }
}

impl std::fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl std::ops::BitAnd for IPv4Address {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from(u32::from(self) & u32::from(rhs))
    }
}

impl std::ops::BitAndAssign for IPv4Address {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for IPv4Address {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from(u32::from(self) | u32::from(rhs))
    }
}

impl std::ops::BitOrAssign for IPv4Address {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for IPv4Address {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from(!u32::from(self))
    }
}

impl PartialOrd for IPv4Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u32::from_be_bytes(self.clone().0).partial_cmp(&u32::from_be_bytes(other.clone().0))
    }
}

impl Ord for IPv4Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u32::from_be_bytes(self.clone().0).cmp(&u32::from_be_bytes(other.clone().0))
    }
}
