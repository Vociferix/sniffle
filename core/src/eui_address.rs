use sniffle_ende::{
    decode::{cast, Decode, DecodeError},
    encode::{Encode, Encoder},
    nom::{combinator::map, IResult},
};

use super::MACAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct EUIAddress([u8; 8]);

impl EUIAddress {
    const BROADCAST: EUIAddress = EUIAddress::new(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

    pub const fn new(b0: u8, b1: u8, b2: u8, b3: u8, b4: u8, b5: u8, b6: u8, b7: u8) -> Self {
        Self([b0, b1, b2, b3, b4, b5, b6, b7])
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Self {
        EUIAddress((!(!0u64 >> prefix_len)).to_be_bytes())
    }

    pub fn next(&self) -> EUIAddress {
        EUIAddress::from(u64::from(*self).wrapping_add(1))
    }

    pub fn prev(&self) -> EUIAddress {
        EUIAddress::from(u64::from(*self).wrapping_sub(1))
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl From<[u8; 8]> for EUIAddress {
    fn from(addr: [u8; 8]) -> Self {
        Self(addr)
    }
}

impl From<EUIAddress> for [u8; 8] {
    fn from(addr: EUIAddress) -> Self {
        addr.0
    }
}

impl From<u64> for EUIAddress {
    fn from(addr: u64) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<EUIAddress> for u64 {
    fn from(addr: EUIAddress) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<i64> for EUIAddress {
    fn from(addr: i64) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<EUIAddress> for i64 {
    fn from(addr: EUIAddress) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<MACAddress> for EUIAddress {
    fn from(addr: MACAddress) -> Self {
        Self([
            addr[0] ^ 2,
            addr[1],
            addr[2],
            0xFF,
            0xFE,
            addr[3],
            addr[4],
            addr[5],
        ])
    }
}

impl Decode for EUIAddress {
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        map(<[u8; 8]>::decode, |bytes| Self::from(bytes))(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe { cast(buf) }
    }
}

impl Encode for EUIAddress {
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
                    slice.len() * 8,
                ))
                .map(|_| ())
        }
    }
}

impl std::ops::Deref for EUIAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl std::ops::DerefMut for EUIAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub enum EUIParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
}

impl From<std::num::ParseIntError> for EUIParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}

impl std::str::FromStr for EUIAddress {
    type Err = EUIParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split(':');
        let addr: [u8; 8] = [
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EUIParseError::BadLength)?, 16)?,
        ];
        iter.next()
            .ok_or(())
            .err()
            .ok_or(EUIParseError::BadLength)?;
        Ok(Self(addr))
    }
}

impl std::fmt::Display for EUIAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        )
    }
}

impl std::ops::BitAnd for EUIAddress {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from(u64::from(self) & u64::from(rhs))
    }
}

impl std::ops::BitAndAssign for EUIAddress {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for EUIAddress {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from(u64::from(self) | u64::from(rhs))
    }
}

impl std::ops::BitOrAssign for EUIAddress {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for EUIAddress {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from(!u64::from(self))
    }
}

impl PartialOrd for EUIAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u64::from_be_bytes(self.clone().0).partial_cmp(&u64::from_be_bytes(other.clone().0))
    }
}

impl Ord for EUIAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u64::from_be_bytes(self.clone().0).cmp(&u64::from_be_bytes(other.clone().0))
    }
}
