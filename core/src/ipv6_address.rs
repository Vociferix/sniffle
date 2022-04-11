use sniffle_ende::{
    decode::{cast, DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Ipv6Address([u8; 16]);

pub struct Ipv6Network {
    base: Ipv6Address,
    mask: Ipv6Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6NetworkIter {
    curr: Option<u128>,
    last: u128,
}

impl Iterator for Ipv6NetworkIter {
    type Item = Ipv6Address;

    fn next(&mut self) -> Option<Self::Item> {
        let tmp = self.curr;
        match tmp {
            Some(addr) => {
                let last = self.last;
                if addr == last {
                    self.curr = None;
                } else {
                    self.curr = Some(addr + 1);
                }
                Some(Ipv6Address(addr.to_be_bytes()))
            }
            None => None,
        }
    }
}

impl Ipv6Network {
    pub const fn new(base: Ipv6Address, mask: Ipv6Address) -> Self {
        Self { base, mask }
    }

    pub const fn from_prefix_len(base: Ipv6Address, prefix_len: u32) -> Self {
        Self {
            base,
            mask: Ipv6Address::from_prefix_len(prefix_len),
        }
    }

    pub const fn base_address(&self) -> &Ipv6Address {
        &self.base
    }

    pub const fn network_mask(&self) -> &Ipv6Address {
        &self.mask
    }

    pub fn contains(&self, addr: &Ipv6Address) -> bool {
        (*addr & self.mask) == self.base
    }

    pub fn first(&self) -> Ipv6Address {
        self.base
    }

    pub fn last(&self) -> Ipv6Address {
        self.base | self.mask
    }

    pub fn iter(&self) -> Ipv6NetworkIter {
        Ipv6NetworkIter {
            curr: Some(u128::from_be_bytes(self.first().0)),
            last: u128::from_be_bytes(self.last().0),
        }
    }
}

impl IntoIterator for Ipv6Network {
    type Item = Ipv6Address;
    type IntoIter = Ipv6NetworkIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Ipv6Address {
    const UNSPECIFIED: Ipv6Address = Ipv6Address([0u8; 16]);

    const LOOPBACK: Ipv6Address =
        Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    const LOCAL_UNICAST_NET: Ipv6Network = Ipv6Network::from_prefix_len(
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        10,
    );

    const MULTICAST_NET: Ipv6Network = Ipv6Network::from_prefix_len(
        Ipv6Address::new([0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        8,
    );

    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Self {
        Ipv6Address((!(!0u128 >> prefix_len)).to_be_bytes())
    }

    pub fn next(&self) -> Ipv6Address {
        Ipv6Address::from(u128::from_be_bytes(self.0).wrapping_add(1).to_be_bytes())
    }

    pub fn prev(&self) -> Ipv6Address {
        Ipv6Address::from(u128::from_be_bytes(self.0).wrapping_sub(1).to_be_bytes())
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    pub fn is_local_unicast(&self) -> bool {
        Self::LOCAL_UNICAST_NET.contains(self)
    }

    pub fn is_multicast(&self) -> bool {
        Self::MULTICAST_NET.contains(self)
    }
}

impl From<[u8; 16]> for Ipv6Address {
    fn from(addr: [u8; 16]) -> Self {
        Self(addr)
    }
}

impl From<Ipv6Address> for [u8; 16] {
    fn from(addr: Ipv6Address) -> Self {
        addr.0
    }
}

impl From<u128> for Ipv6Address {
    fn from(addr: u128) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<Ipv6Address> for u128 {
    fn from(addr: Ipv6Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<i128> for Ipv6Address {
    fn from(addr: i128) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<Ipv6Address> for i128 {
    fn from(addr: Ipv6Address) -> Self {
        Self::from_ne_bytes(addr.0)
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

    fn encode_many<'a, W: Encoder<'a> + ?Sized>(
        slice: &[Self],
        encoder: &mut W,
    ) -> std::io::Result<()> {
        unsafe {
            encoder
                .encode(std::slice::from_raw_parts(
                    slice.as_ptr() as *const u8,
                    slice.len() * 16,
                ))
                .map(|_| ())
        }
    }
}

impl std::ops::Deref for Ipv6Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl std::ops::DerefMut for Ipv6Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub enum Ipv6ParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
    Invalid,
}

impl From<std::num::ParseIntError> for Ipv6ParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}

impl std::str::FromStr for Ipv6Address {
    type Err = Ipv6ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 16];
        let mut iter = s.split(':');
        let mut idx: usize = 0;
        for word in iter.by_ref() {
            if idx >= 16 {
                return Err(Ipv6ParseError::BadLength);
            }

            if word.is_empty() {
                break;
            }

            let w = u16::from_str_radix(word, 16)?.to_be_bytes();
            addr[idx] = w[0];
            idx += 1;
            addr[idx] = w[1];
            idx += 1;
        }

        let mut iter = iter.rev();
        let end = idx;
        idx = 15;
        for word in iter.by_ref() {
            if idx < end {
                return Err(Ipv6ParseError::BadLength);
            }

            if word.is_empty() {
                return Err(Ipv6ParseError::Invalid);
            }

            let w = u16::from_str_radix(word, 16)?.to_be_bytes();
            addr[idx] = w[1];
            idx -= 1;
            addr[idx] = w[0];
            idx -= 1;
        }

        Ok(Self(addr))
    }
}

impl std::fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                tmp_start = n;
                tmp_end = n;
            } else {
                tmp_start = n;
                tmp_end = n;
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
            write!(f, ":")?;
            for word in disp[end..].iter() {
                write!(f, ":{:x}", word)?;
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

impl std::ops::BitAnd for Ipv6Address {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from(u128::from(self) & u128::from(rhs))
    }
}

impl std::ops::BitAndAssign for Ipv6Address {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for Ipv6Address {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from(u128::from(self) | u128::from(rhs))
    }
}

impl std::ops::BitOrAssign for Ipv6Address {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for Ipv6Address {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from(!u128::from(self))
    }
}

impl PartialOrd for Ipv6Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u128::from_be_bytes(self.0).partial_cmp(&u128::from_be_bytes(other.0))
    }
}

impl Ord for Ipv6Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u128::from_be_bytes(self.0).cmp(&u128::from_be_bytes(other.0))
    }
}
