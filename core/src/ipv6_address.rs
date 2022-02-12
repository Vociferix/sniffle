use sniffle_ende::{
    decode::{cast, Decode, DecodeError},
    encode::{Encode, Encoder},
    nom::{combinator::map, IResult},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct IPv6Address([u8; 16]);

pub struct IPv6Network {
    base: IPv6Address,
    mask: IPv6Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPv6NetworkIter {
    curr: Option<u128>,
    last: u128,
}

impl Iterator for IPv6NetworkIter {
    type Item = IPv6Address;

    fn next(&mut self) -> Option<Self::Item> {
        let tmp = self.curr.clone();
        match tmp {
            Some(addr) => {
                let last = self.last.clone();
                if addr == last {
                    self.curr = None;
                } else {
                    self.curr = Some(addr + 1);
                }
                Some(IPv6Address(addr.to_be_bytes()))
            }
            None => None,
        }
    }
}

impl IPv6Network {
    pub const fn new(base: IPv6Address, mask: IPv6Address) -> Self {
        Self { base, mask }
    }

    pub const fn from_prefix_len(base: IPv6Address, prefix_len: u32) -> Self {
        Self {
            base,
            mask: IPv6Address::from_prefix_len(prefix_len),
        }
    }

    pub const fn base_address(&self) -> &IPv6Address {
        &self.base
    }

    pub const fn network_mask(&self) -> &IPv6Address {
        &self.mask
    }

    pub fn contains(&self, addr: &IPv6Address) -> bool {
        (*addr & self.mask) == self.base
    }

    pub fn first(&self) -> IPv6Address {
        self.base
    }

    pub fn last(&self) -> IPv6Address {
        self.base | self.mask
    }

    pub fn iter(&self) -> IPv6NetworkIter {
        IPv6NetworkIter {
            curr: Some(u128::from_be_bytes(self.first().0)),
            last: u128::from_be_bytes(self.last().0),
        }
    }
}

impl IntoIterator for IPv6Network {
    type Item = IPv6Address;
    type IntoIter = IPv6NetworkIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IPv6Address {
    const UNSPECIFIED: IPv6Address = IPv6Address([0u8; 16]);

    const LOOPBACK: IPv6Address = IPv6Address::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);

    const LOCAL_UNICAST_NET: IPv6Network = IPv6Network::from_prefix_len(
        IPv6Address::new(0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        10,
    );

    const MULTICAST_NET: IPv6Network = IPv6Network::from_prefix_len(
        IPv6Address::new(0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        8,
    );

    pub const fn new(
        b0: u8,
        b1: u8,
        b2: u8,
        b3: u8,
        b4: u8,
        b5: u8,
        b6: u8,
        b7: u8,
        b8: u8,
        b9: u8,
        b10: u8,
        b11: u8,
        b12: u8,
        b13: u8,
        b14: u8,
        b15: u8,
    ) -> Self {
        Self([
            b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15,
        ])
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Self {
        IPv6Address((!(!0u128 >> prefix_len)).to_be_bytes())
    }

    pub fn next(&self) -> IPv6Address {
        IPv6Address::from(
            u128::from_be_bytes(self.0.clone())
                .wrapping_add(1)
                .to_be_bytes(),
        )
    }

    pub fn prev(&self) -> IPv6Address {
        IPv6Address::from(
            u128::from_be_bytes(self.0.clone())
                .wrapping_sub(1)
                .to_be_bytes(),
        )
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

impl From<[u8; 16]> for IPv6Address {
    fn from(addr: [u8; 16]) -> Self {
        Self(addr)
    }
}

impl From<IPv6Address> for [u8; 16] {
    fn from(addr: IPv6Address) -> Self {
        addr.0
    }
}

impl From<u128> for IPv6Address {
    fn from(addr: u128) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<IPv6Address> for u128 {
    fn from(addr: IPv6Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<i128> for IPv6Address {
    fn from(addr: i128) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<IPv6Address> for i128 {
    fn from(addr: IPv6Address) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl Decode for IPv6Address {
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        map(<[u8; 16]>::decode, |bytes| Self::from(bytes))(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe { cast(buf) }
    }
}

impl Encode for IPv6Address {
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

impl std::ops::Deref for IPv6Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl std::ops::DerefMut for IPv6Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub enum IPv6ParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
    Invalid,
}

impl From<std::num::ParseIntError> for IPv6ParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}

impl std::str::FromStr for IPv6Address {
    type Err = IPv6ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 16];
        let mut iter = s.split(':');
        let mut idx: usize = 0;
        while let Some(word) = iter.next() {
            if idx >= 16 {
                return Err(IPv6ParseError::BadLength);
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
        while let Some(word) = iter.next() {
            if idx < end {
                return Err(IPv6ParseError::BadLength);
            }

            if word.is_empty() {
                return Err(IPv6ParseError::Invalid);
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

impl std::fmt::Display for IPv6Address {
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

impl std::ops::BitAnd for IPv6Address {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from(u128::from(self) & u128::from(rhs))
    }
}

impl std::ops::BitAndAssign for IPv6Address {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for IPv6Address {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from(u128::from(self) | u128::from(rhs))
    }
}

impl std::ops::BitOrAssign for IPv6Address {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for IPv6Address {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from(!u128::from(self))
    }
}

impl PartialOrd for IPv6Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u128::from_be_bytes(self.clone().0).partial_cmp(&u128::from_be_bytes(other.clone().0))
    }
}

impl Ord for IPv6Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u128::from_be_bytes(self.clone().0).cmp(&u128::from_be_bytes(other.clone().0))
    }
}
