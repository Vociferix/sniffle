use sniffle_ende::{
    decode::{cast, DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

use super::MacAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct EuiAddress([u8; 8]);

impl EuiAddress {
    const BROADCAST: EuiAddress = EuiAddress::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Self {
        EuiAddress((!(!0u64 >> prefix_len)).to_be_bytes())
    }

    pub fn next(&self) -> EuiAddress {
        EuiAddress::from(u64::from(*self).wrapping_add(1))
    }

    pub fn prev(&self) -> EuiAddress {
        EuiAddress::from(u64::from(*self).wrapping_sub(1))
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl From<[u8; 8]> for EuiAddress {
    fn from(addr: [u8; 8]) -> Self {
        Self(addr)
    }
}

impl From<EuiAddress> for [u8; 8] {
    fn from(addr: EuiAddress) -> Self {
        addr.0
    }
}

impl From<u64> for EuiAddress {
    fn from(addr: u64) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<EuiAddress> for u64 {
    fn from(addr: EuiAddress) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<i64> for EuiAddress {
    fn from(addr: i64) -> Self {
        Self(addr.to_ne_bytes())
    }
}

impl From<EuiAddress> for i64 {
    fn from(addr: EuiAddress) -> Self {
        Self::from_ne_bytes(addr.0)
    }
}

impl From<MacAddress> for EuiAddress {
    fn from(addr: MacAddress) -> Self {
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

impl Decode for EuiAddress {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(<[u8; 8]>::decode, Self::from)(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

impl Encode for EuiAddress {
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

impl std::ops::Deref for EuiAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl std::ops::DerefMut for EuiAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub enum EuiParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
}

impl From<std::num::ParseIntError> for EuiParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}

impl std::str::FromStr for EuiAddress {
    type Err = EuiParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split(':');
        let addr: [u8; 8] = [
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(EuiParseError::BadLength)?, 16)?,
        ];
        iter.next()
            .ok_or(())
            .err()
            .ok_or(EuiParseError::BadLength)?;
        Ok(Self(addr))
    }
}

impl std::fmt::Display for EuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        )
    }
}

impl std::ops::BitAnd for EuiAddress {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::from(u64::from(self) & u64::from(rhs))
    }
}

impl std::ops::BitAndAssign for EuiAddress {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for EuiAddress {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from(u64::from(self) | u64::from(rhs))
    }
}

impl std::ops::BitOrAssign for EuiAddress {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for EuiAddress {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::from(!u64::from(self))
    }
}

impl PartialOrd for EuiAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u64::from_be_bytes(self.0).partial_cmp(&u64::from_be_bytes(other.0))
    }
}

impl Ord for EuiAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u64::from_be_bytes(self.0).cmp(&u64::from_be_bytes(other.0))
    }
}
