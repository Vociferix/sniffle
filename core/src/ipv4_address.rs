use sniffle_ende::{
    decode::{cast, DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Ipv4Address([u8; 4]);

pub struct Ipv4Network {
    base: Ipv4Address,
    mask: Ipv4Address,
}

pub struct Ipv4NetworkIter {
    curr: Option<u32>,
    last: u32,
}

impl Iterator for Ipv4NetworkIter {
    type Item = Ipv4Address;

    fn next(&mut self) -> Option<Self::Item> {
        let tmp = self.curr;
        match tmp {
            Some(addr) => {
                if addr == self.last {
                    self.curr = None;
                } else {
                    self.curr = Some(addr + 1);
                }
                Some(Ipv4Address(addr.to_be_bytes()))
            }
            None => None,
        }
    }
}

impl Ipv4Network {
    pub const fn new(base: Ipv4Address, mask: Ipv4Address) -> Self {
        Self { base, mask }
    }

    pub const fn from_prefix_len(base: Ipv4Address, prefix_len: u32) -> Self {
        Self {
            base,
            mask: Ipv4Address::from_prefix_len(prefix_len),
        }
    }

    pub const fn base_address(&self) -> &Ipv4Address {
        &self.base
    }

    pub const fn network_mask(&self) -> &Ipv4Address {
        &self.mask
    }

    pub fn contains(&self, addr: &Ipv4Address) -> bool {
        (*addr & self.mask) == self.base
    }

    pub fn first(&self) -> Ipv4Address {
        self.base
    }

    pub fn last(&self) -> Ipv4Address {
        self.base | self.mask
    }

    pub fn iter(&self) -> Ipv4NetworkIter {
        Ipv4NetworkIter {
            curr: Some(u32::from_be_bytes(self.first().0)),
            last: u32::from_be_bytes(self.last().0),
        }
    }
}

impl IntoIterator for Ipv4Network {
    type Item = Ipv4Address;
    type IntoIter = Ipv4NetworkIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Ipv4Address {
    const PRIVATE_NETS: [Ipv4Network; 3] = [
        Ipv4Network::from_prefix_len(Ipv4Address::new([10, 0, 0, 0]), 8),
        Ipv4Network::from_prefix_len(Ipv4Address::new([172, 16, 0, 0]), 12),
        Ipv4Network::from_prefix_len(Ipv4Address::new([192, 168, 0, 0]), 16),
    ];

    const LOOPBACK_NET: Ipv4Network =
        Ipv4Network::from_prefix_len(Ipv4Address::new([127, 0, 0, 0]), 8);

    const MULTICAST_NET: Ipv4Network =
        Ipv4Network::from_prefix_len(Ipv4Address::new([224, 0, 0, 0]), 4);

    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Ipv4Address {
        Ipv4Address((!(!0u32 >> prefix_len)).to_be_bytes())
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

    pub fn next(&self) -> Ipv4Address {
        Ipv4Address::new(u32::from_be(self.0).wraping_add(1).to_be())
    }

    pub fn prev(&self) -> Ipv4Address {
        Ipv4Address::new(u32::from_be(self.0).wraping_sub(1).to_be())
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(addr: [u8; 4]) -> Self {
        Self(addr)
    }
}

impl From<Ipv4Address> for [u8; 4] {
    fn from(addr: Ipv4Address) -> Self {
        addr.0
    }
}

impl From<u32> for Ipv4Address {
    fn from(addr: u32) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<Ipv4Address> for u32 {
    fn from(addr: Ipv4Address) -> Self {
        u32::from_ne_bytes(addr.0)
    }
}

impl From<i32> for Ipv4Address {
    fn from(addr: i32) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<Ipv4Address> for i32 {
    fn from(addr: Ipv4Address) -> i32 {
        i32::from_ne_bytes(addr.0)
    }
}

impl Decode for Ipv4Address {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(<[u8; 4]>::decode, Self::from)(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

impl Encode for Ipv4Address {
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

impl std::ops::Deref for Ipv4Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl std::ops::DerefMut for Ipv4Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub enum Ipv4ParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
}

impl From<std::num::ParseIntError> for Ipv4ParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Ipv4ParseError::ParseInt(e)
    }
}

impl std::str::FromStr for Ipv4Address {
    type Err = Ipv4ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 4];
        let mut iter = s.split('.');
        addr[0] = iter.next().ok_or(Ipv4ParseError::BadLength)?.parse()?;
        addr[1] = iter.next().ok_or(Ipv4ParseError::BadLength)?.parse()?;
        addr[2] = iter.next().ok_or(Ipv4ParseError::BadLength)?.parse()?;
        addr[3] = iter.next().ok_or(Ipv4ParseError::BadLength)?.parse()?;
        iter.next()
            .ok_or(())
            .err()
            .ok_or(Ipv4ParseError::BadLength)?;
        Ok(Self(addr))
    }
}

impl std::fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl std::ops::BitAnd for Ipv4Address {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from(u32::from(self) & u32::from(rhs))
    }
}

impl std::ops::BitAndAssign for Ipv4Address {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for Ipv4Address {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from(u32::from(self) | u32::from(rhs))
    }
}

impl std::ops::BitOrAssign for Ipv4Address {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for Ipv4Address {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from(!u32::from(self))
    }
}

impl PartialOrd for Ipv4Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u32::from_be_bytes(self.0).partial_cmp(&u32::from_be_bytes(other.0))
    }
}

impl Ord for Ipv4Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u32::from_be_bytes(self.0).cmp(&u32::from_be_bytes(other.0))
    }
}
