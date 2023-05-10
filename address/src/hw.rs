use std::{
    fmt::{self, Display},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, DerefMut, Not},
    str::FromStr,
};

use sniffle_ende::decode::{Decode, DecodeBuf, DecodeError};
use sniffle_ende::encode::{Encodable, Encode, EncodeBuf};

use crate::{Address, AddressParseError};

use sniffle_address_parse::parse_hw;

/// Representation of generic hardware address
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HwAddress<const LEN: usize>([u8; LEN]);

impl<const LEN: usize> HwAddress<LEN> {
    /// The typical broadcast address for hardware addresses
    ///
    /// `ff:ff:...`
    pub const BROADCAST: Self = Self([0xffu8; LEN]);

    /// Creates a hardware address from a raw bytes representation
    pub const fn new(addr: [u8; LEN]) -> Self {
        Self(addr)
    }

    /// Creates a hardware address using another address as the prefix.
    ///
    /// Remaining bytes past the prefix will be zero.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_address::{hw, HwAddress};
    /// let addr: HwAddress<8> = HwAddress::from_prefix(hw!("12:34:56:78"));
    /// assert_eq!(addr, hw!("12:34:56:78:00:00:00:00"));
    /// ```
    pub fn from_prefix<const PREFIX_LEN: usize>(prefix: HwAddress<PREFIX_LEN>) -> Self {
        prefix.pad_right(0)
    }

    /// Creates a hardware address using another address as the suffix.
    ///
    /// Remaining bytes before the suffix will be zero.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_address::{hw, HwAddress};
    /// let addr: HwAddress<8> = HwAddress::from_suffix(hw!("12:34:56:78"));
    /// assert_eq!(addr, hw!("00:00:00:00:12:34:56:78"));
    /// ```
    pub fn from_suffix<const SUFFIX_LEN: usize>(suffix: HwAddress<SUFFIX_LEN>) -> Self {
        suffix.pad_left(0)
    }

    /// Extends the address to the right, using the provided padding byte value
    ///
    /// ## Example
    /// ```
    /// # use sniffle_address::{hw, HwAddress};
    /// let padded: HwAddress<8> = hw!("12:34:56:78").pad_right(0);
    /// assert_eq!(padded, hw!("12:34:56:78:00:00:00:00"));
    /// ```
    pub fn pad_right<const NEW_LEN: usize>(self, padding: u8) -> HwAddress<NEW_LEN> {
        let mut new_addr = [padding; NEW_LEN];
        let mut idx = 0usize;
        while idx < LEN && idx < NEW_LEN {
            new_addr[idx] = self.0[idx];
            idx += 1;
        }
        HwAddress::<NEW_LEN>(new_addr)
    }

    /// Extends the address to the left, using the provided padding byte value
    ///
    /// ## Example
    /// ```
    /// # use sniffle_address::{hw, HwAddress};
    /// let padded_addr: HwAddress<8> = hw!("12:34:56:78").pad_left(0);
    /// assert_eq!(padded_addr, hw!("00:00:00:00:12:34:56:78"));
    /// ```
    pub fn pad_left<const NEW_LEN: usize>(&self, padding: u8) -> HwAddress<NEW_LEN> {
        let mut new_addr = [padding; NEW_LEN];
        let mut old_idx = LEN - 1;
        let mut new_idx = NEW_LEN - 1;
        loop {
            new_addr[new_idx] = self.0[old_idx];
            if new_idx == 0 || old_idx == 0 {
                break;
            }
            new_idx -= 1;
            old_idx -= 1;
        }
        HwAddress::<NEW_LEN>(new_addr)
    }
}

impl<const LEN: usize> Default for HwAddress<LEN> {
    fn default() -> Self {
        Self([0u8; LEN])
    }
}

impl<const LEN: usize> From<[u8; LEN]> for HwAddress<LEN> {
    fn from(raw: [u8; LEN]) -> Self {
        Self(raw)
    }
}

impl<const LEN: usize> From<HwAddress<LEN>> for [u8; LEN] {
    fn from(addr: HwAddress<LEN>) -> Self {
        addr.0
    }
}

impl<const LEN: usize> Deref for HwAddress<LEN> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> DerefMut for HwAddress<LEN> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LEN: usize> BitAndAssign<&HwAddress<LEN>> for HwAddress<LEN> {
    fn bitand_assign(&mut self, rhs: &Self) {
        for (dst, src) in self.0.iter_mut().zip(rhs.0.iter()) {
            *dst &= *src;
        }
    }
}

impl<const LEN: usize> BitAndAssign for HwAddress<LEN> {
    fn bitand_assign(&mut self, rhs: Self) {
        self.bitand_assign(&rhs)
    }
}

impl<const LEN: usize> BitAnd<&HwAddress<LEN>> for HwAddress<LEN> {
    type Output = Self;

    fn bitand(mut self, rhs: &Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<const LEN: usize> BitAnd for HwAddress<LEN> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.bitand(&rhs)
    }
}

impl<const LEN: usize> BitAnd<HwAddress<LEN>> for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn bitand(self, rhs: HwAddress<LEN>) -> Self::Output {
        self.clone().bitand(rhs)
    }
}

impl<const LEN: usize> BitAnd for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.clone().bitand(rhs)
    }
}

impl<const LEN: usize> BitOrAssign<&HwAddress<LEN>> for HwAddress<LEN> {
    fn bitor_assign(&mut self, rhs: &Self) {
        for (dst, src) in self.0.iter_mut().zip(rhs.0.iter()) {
            *dst |= *src;
        }
    }
}

impl<const LEN: usize> BitOrAssign for HwAddress<LEN> {
    fn bitor_assign(&mut self, rhs: Self) {
        self.bitor_assign(&rhs)
    }
}

impl<const LEN: usize> BitOr<&HwAddress<LEN>> for HwAddress<LEN> {
    type Output = Self;

    fn bitor(mut self, rhs: &Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<const LEN: usize> BitOr for HwAddress<LEN> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.bitor(&rhs)
    }
}

impl<const LEN: usize> BitOr<HwAddress<LEN>> for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn bitor(self, rhs: HwAddress<LEN>) -> Self::Output {
        self.clone().bitor(rhs)
    }
}

impl<const LEN: usize> BitOr for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.clone().bitor(rhs)
    }
}

impl<const LEN: usize> BitXorAssign<&HwAddress<LEN>> for HwAddress<LEN> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        for (dst, src) in self.0.iter_mut().zip(rhs.0.iter()) {
            *dst ^= *src;
        }
    }
}

impl<const LEN: usize> BitXorAssign for HwAddress<LEN> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.bitxor_assign(&rhs)
    }
}

impl<const LEN: usize> BitXor<&HwAddress<LEN>> for HwAddress<LEN> {
    type Output = Self;

    fn bitxor(mut self, rhs: &Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<const LEN: usize> BitXor for HwAddress<LEN> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.bitxor(&rhs)
    }
}

impl<const LEN: usize> BitXor<HwAddress<LEN>> for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn bitxor(self, rhs: HwAddress<LEN>) -> Self::Output {
        self.clone().bitxor(rhs)
    }
}

impl<const LEN: usize> BitXor for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.clone().bitxor(rhs)
    }
}

impl<const LEN: usize> Not for HwAddress<LEN> {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        for byte in self.0.iter_mut() {
            *byte = !*byte;
        }
        self
    }
}

impl<const LEN: usize> Not for &HwAddress<LEN> {
    type Output = HwAddress<LEN>;

    fn not(self) -> Self::Output {
        self.clone().not()
    }
}

impl<const LEN: usize> FromStr for HwAddress<LEN> {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; LEN];
        parse_hw(s, &mut addr)?;
        Ok(Self(addr))
    }
}

impl<const LEN: usize> Display for HwAddress<LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for byte in self.0.iter() {
            if first {
                first = false;
                write!(f, "{:02x}", *byte)?;
            } else {
                write!(f, ":{:02x}", *byte)?;
            }
        }
        Ok(())
    }
}

unsafe impl<const LEN: usize> bytemuck::Zeroable for HwAddress<LEN> {}

unsafe impl<const LEN: usize> bytemuck::Pod for HwAddress<LEN> {}

impl<const LEN: usize> Decode for HwAddress<LEN> {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
        self.0.decode(buf)
    }

    fn decode_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<(), DecodeError> {
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(slice);
        bytes.decode(buf)
    }
}

impl<const LEN: usize> Encodable for HwAddress<LEN> {
    fn encoded_size(&self) -> usize {
        LEN
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        LEN * slice.len()
    }
}

impl<const LEN: usize> Encode for HwAddress<LEN> {
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        self.0.encode(buf);
    }

    fn encode_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        let bytes: &[u8] = bytemuck::cast_slice(slice);
        bytes.encode(buf);
    }
}

impl<const LEN: usize> Address for HwAddress<LEN> {
    type Raw = [u8; LEN];

    fn from_prefix_len(mut prefix_len: u32) -> Self {
        if prefix_len >= ((LEN * 8) as u32) {
            return Self([0xff; LEN]);
        }

        let mut addr = [0u8; LEN];
        let mut idx = 0usize;
        while prefix_len >= 8 {
            addr[idx] = 0xff;
            idx += 1;
            prefix_len -= 8;
        }

        addr[idx] = !(!0u8 >> prefix_len);

        Self(addr)
    }

    fn as_prefix_len(&self) -> u32 {
        let mut prefix_len = 0u32;
        for byte in self.0.iter() {
            if *byte == 0xff {
                prefix_len += 8;
            } else {
                prefix_len += byte.leading_ones();
                break;
            }
        }
        return prefix_len;
    }

    fn next_addr(&self) -> Self {
        let mut addr = self.0.clone();
        let mut idx = LEN - 1;
        loop {
            let (val, ovrflo) = addr[idx].overflowing_add(1);
            addr[idx] = val;
            if !ovrflo || idx == 0 {
                break;
            }
            idx -= 1;
        }
        Self(addr)
    }

    fn prev_addr(&self) -> Self {
        let mut addr = self.0.clone();
        let mut idx = LEN - 1;
        loop {
            let (val, ovrflo) = addr[idx].overflowing_sub(1);
            addr[idx] = val;
            if !ovrflo || idx == 0 {
                break;
            }
            idx -= 1;
        }
        Self(addr)
    }
}
