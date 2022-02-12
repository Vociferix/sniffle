use sniffle_ende::{
    decode::{Decode, DecodeError},
    encode::{Encode, Encoder},
    nom::{combinator::map, IResult},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct MACAddress([u8; 8]);

impl MACAddress {
    const BROADCAST: MACAddress = MACAddress::new(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

    pub const fn new(b0: u8, b1: u8, b2: u8, b3: u8, b4: u8, b5: u8) -> Self {
        Self([b0, b1, b2, b3, b4, b5, 0, 0])
    }

    pub const fn from_prefix_len(prefix_len: u32) -> Self {
        MACAddress((!(!0u64 >> prefix_len)).to_be_bytes())
    }

    pub fn next(&self) -> MACAddress {
        let addr = (u64::from_be_bytes(self.0.clone()).wrapping_add(0x10000)).to_be_bytes();
        Self::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
    }

    pub fn prev(&self) -> MACAddress {
        let addr = (u64::from_be_bytes(self.0.clone()).wrapping_sub(0x10000)).to_be_bytes();
        Self::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl From<[u8; 6]> for MACAddress {
    fn from(addr: [u8; 6]) -> Self {
        Self::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
    }
}

impl From<MACAddress> for [u8; 6] {
    fn from(addr: MACAddress) -> Self {
        [
            addr.0[0], addr.0[1], addr.0[2], addr.0[3], addr.0[4], addr.0[5],
        ]
    }
}

impl Decode for MACAddress {
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        map(<[u8; 6]>::decode, |bytes| Self::from(bytes))(buf)
    }
}

impl Encode for MACAddress {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        encoder.encode(&self[..]).map(|_| ())
    }
}

impl std::ops::Deref for MACAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..6]
    }
}

impl std::ops::DerefMut for MACAddress {
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

impl std::str::FromStr for MACAddress {
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

impl std::fmt::Display for MACAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

impl std::ops::BitAnd for MACAddress {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self((u64::from_be_bytes(self.0) & u64::from_be_bytes(rhs.0)).to_be_bytes())
    }
}

impl std::ops::BitAndAssign for MACAddress {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl std::ops::BitOr for MACAddress {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self((u64::from_be_bytes(self.0) | u64::from_be_bytes(rhs.0)).to_be_bytes())
    }
}

impl std::ops::BitOrAssign for MACAddress {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::Not for MACAddress {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self((!u64::from_be_bytes(self.0)).to_be_bytes())
    }
}

impl PartialOrd for MACAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u64::from_be_bytes(self.clone().0).partial_cmp(&u64::from_be_bytes(other.clone().0))
    }
}

impl Ord for MACAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u64::from_be_bytes(self.clone().0).cmp(&u64::from_be_bytes(other.clone().0))
    }
}
