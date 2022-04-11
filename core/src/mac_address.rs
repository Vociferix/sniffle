use sniffle_ende::{
    decode::{DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct MacAddress([u8; 8]);

impl MacAddress {
    const BROADCAST: MacAddress = MacAddress::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
        ])
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Self {
        MacAddress((!(!0u64 >> prefix_len)).to_be_bytes())
    }

    pub fn next(&self) -> MacAddress {
        Self((u64::from_be_bytes(self.0).wrapping_add(0x10000)).to_be_bytes())
    }

    pub fn prev(&self) -> MacAddress {
        Self((u64::from_be_bytes(self.0).wrapping_sub(0x10000)).to_be_bytes())
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(addr: [u8; 6]) -> Self {
        Self::new(addr)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(addr: MacAddress) -> Self {
        [
            addr.0[0], addr.0[1], addr.0[2], addr.0[3], addr.0[4], addr.0[5],
        ]
    }
}

impl Decode for MacAddress {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(<[u8; 6]>::decode, Self::from)(buf)
    }
}

impl Encode for MacAddress {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        encoder.encode(&self[..]).map(|_| ())
    }
}

impl std::ops::Deref for MacAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..6]
    }
}

impl std::ops::DerefMut for MacAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..6]
    }
}

pub enum MACParseError {
    ParseInt(std::num::ParseIntError),
    BadLength,
}

impl From<std::num::ParseIntError> for MACParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}

impl std::str::FromStr for MacAddress {
    type Err = MACParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split(':');
        let addr: [u8; 8] = [
            u8::from_str_radix(iter.next().ok_or(MACParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(MACParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(MACParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(MACParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(MACParseError::BadLength)?, 16)?,
            u8::from_str_radix(iter.next().ok_or(MACParseError::BadLength)?, 16)?,
            0,
            0,
        ];
        iter.next()
            .ok_or(())
            .err()
            .ok_or(MACParseError::BadLength)?;
        Ok(Self(addr))
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

impl std::ops::BitAnd for MacAddress {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self((u64::from_be_bytes(self.0) & u64::from_be_bytes(rhs.0)).to_be_bytes())
    }
}

impl std::ops::BitAndAssign for MacAddress {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for MacAddress {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self((u64::from_be_bytes(self.0) | u64::from_be_bytes(rhs.0)).to_be_bytes())
    }
}

impl std::ops::BitOrAssign for MacAddress {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for MacAddress {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self((!u64::from_be_bytes(self.0)).to_be_bytes())
    }
}

impl PartialOrd for MacAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u64::from_be_bytes(self.0).partial_cmp(&u64::from_be_bytes(other.0))
    }
}

impl Ord for MacAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u64::from_be_bytes(self.0).cmp(&u64::from_be_bytes(other.0))
    }
}
