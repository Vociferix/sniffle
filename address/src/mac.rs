#![allow(unused_imports)]

use std::{
    cmp::Ordering,
    fmt::{self, Display},
    hash::{Hash, Hasher},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, DerefMut, Not},
    str::FromStr,
};

use sniffle_ende::{
    decode::{cast, DResult, Decode},
    encode::{Encode, Encoder},
    nom::combinator::map,
};

use sniffle_uint::{IntoMasked, U48};

use crate::{Address, AddressParseError, HwAddress, Subnet};

use sniffle_address_parse::parse_hw;

/// Representation of a 48-bit MAC address
///
/// MacAddress is in many ways equivalent to HwAddress<6>, but its implementation is
/// more fine tuned to to its specific 48-bit size than the generic HwAddress.
/// Additionally, it provides lookup of OUI/Manufacturer information, while HwAddress
/// does not. HwAddress is intended for use with generic addresses, and MacAddress is
/// specifically for MAC addresses. MacAddress and HwAddress<6> can be infallibly
/// converted from one to the other if desired.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct MacAddress([u8; 8]);

impl MacAddress {
    /// The MAC broadcast address
    ///
    /// `ff:ff:ff:ff:ff:ff`
    pub const BROADCAST: Self = Self([0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    fn value(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    fn from_value(val: u64) -> Self {
        Self(val.to_be_bytes())
    }

    /// Creates a MAC address from a raw bytes representation
    pub const fn new(raw: [u8; 6]) -> Self {
        Self([0, 0, raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]])
    }

    /// Attempts to convert an IPv6 EUI-64 address to a MAC address
    ///
    /// This conversion is performed by removing the `ff:fe` bytes in the
    /// middle of the EUI address, and inverting the 7th bit. For this
    /// conversion to be valid, the EUI address must have the byte values
    /// `ff:fe` in byte indexes 3 and 4. Otherwise, the provided address
    /// is returned as an error.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_address::{hw, mac, MacAddress};
    /// assert_eq!(MacAddress::from_eui(hw!("12:34:56:ff:fe:78:9a:bc")), Ok(mac!("10:34:56:78:9a:bc")));
    /// assert!(MacAddress::from_eui(hw!("12:34:56:78:9a:bc:de:f0")).is_err());
    /// ```
    pub fn from_eui(eui: HwAddress<8>) -> Result<Self, HwAddress<8>> {
        if eui[3] != 0xff || eui[4] != 0xfe {
            Err(eui)
        } else {
            Ok(MacAddress([
                0,
                0,
                eui[0] ^ 2,
                eui[1],
                eui[2],
                eui[5],
                eui[6],
                eui[7],
            ]))
        }
    }

    /// Converts a MAC address to an IPv6 EUI-64 address
    ///
    /// This conversion is performed by inserting bytes `ff:fe` directly in the
    /// middle of the MAC address, and inverting the 7th bit. For example:
    ///
    /// ## Example
    /// ```
    /// # use sniffle_address::{hw, mac, HwAddress, MacAddress};
    /// assert_eq!(mac!("12:34:56:78:9a:bc").to_eui(), hw!("10:34:56:ff:fe:78:9a:bc"));
    /// ```
    pub fn to_eui(&self) -> HwAddress<8> {
        HwAddress::new([
            self.0[2] ^ 2,
            self.0[3],
            self.0[4],
            0xff,
            0xfe,
            self.0[5],
            self.0[6],
            self.0[7],
        ])
    }

    /// Returns the OUI assignment corresponding to this address, if any.
    ///
    /// NOTE: Runs in `O(log(n))` time, where `n` is the length of `oui::Assignment::DATABASE`.
    pub fn oui(&self) -> Option<&'static oui::Assignment> {
        match oui::Assignment::DATABASE.binary_search_by(|entry| {
            if &entry.range().base_addr() > self {
                Ordering::Greater
            } else if entry.range().contains(self) {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        }) {
            Ok(pos) => Some(&oui::Assignment::DATABASE[pos]),
            Err(_) => None,
        }
    }
}

impl Default for MacAddress {
    fn default() -> Self {
        Self([0u8; 8])
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(raw: [u8; 6]) -> Self {
        Self::new(raw)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(addr: MacAddress) -> Self {
        [
            addr.0[2], addr.0[3], addr.0[4], addr.0[5], addr.0[6], addr.0[7],
        ]
    }
}

impl From<HwAddress<6>> for MacAddress {
    fn from(addr: HwAddress<6>) -> Self {
        <[u8; 6]>::from(addr).into()
    }
}

impl From<MacAddress> for HwAddress<6> {
    fn from(addr: MacAddress) -> Self {
        <[u8; 6]>::from(addr).into()
    }
}

impl From<U48> for MacAddress {
    fn from(addr: U48) -> Self {
        let addr: u64 = addr.into();
        Self(addr.to_be_bytes())
    }
}

impl From<MacAddress> for U48 {
    fn from(addr: MacAddress) -> Self {
        u64::from_be_bytes(addr.0).into_masked()
    }
}

impl Deref for MacAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[2..]
    }
}

impl DerefMut for MacAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[2..]
    }
}

impl PartialEq for MacAddress {
    fn eq(&self, other: &Self) -> bool {
        self.value().eq(&other.value())
    }
}

impl Eq for MacAddress {}

impl PartialOrd for MacAddress {
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

impl Ord for MacAddress {
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

impl Hash for MacAddress {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.value().hash(state)
    }
}

impl BitAnd for &MacAddress {
    type Output = MacAddress;

    fn bitand(self, rhs: Self) -> Self::Output {
        MacAddress::from_value(self.value() & rhs.value())
    }
}

impl BitAnd<MacAddress> for &MacAddress {
    type Output = MacAddress;

    fn bitand(self, rhs: MacAddress) -> Self::Output {
        self.bitand(&rhs)
    }
}

impl BitAnd<&MacAddress> for MacAddress {
    type Output = Self;

    fn bitand(self, rhs: &Self) -> Self::Output {
        BitAnd::bitand(&self, rhs)
    }
}

impl BitAnd for MacAddress {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.bitand(&rhs)
    }
}

impl BitAndAssign<&MacAddress> for MacAddress {
    fn bitand_assign(&mut self, rhs: &Self) {
        *self = &*self & rhs;
    }
}

impl BitAndAssign for MacAddress {
    fn bitand_assign(&mut self, rhs: Self) {
        self.bitand_assign(&rhs)
    }
}

impl BitOr for &MacAddress {
    type Output = MacAddress;

    fn bitor(self, rhs: Self) -> Self::Output {
        MacAddress::from_value(self.value() | rhs.value())
    }
}

impl BitOr<MacAddress> for &MacAddress {
    type Output = MacAddress;

    fn bitor(self, rhs: MacAddress) -> Self::Output {
        self.bitor(&rhs)
    }
}

impl BitOr<&MacAddress> for MacAddress {
    type Output = Self;

    fn bitor(self, rhs: &Self) -> Self::Output {
        BitOr::bitor(&self, rhs)
    }
}

impl BitOr for MacAddress {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.bitor(&rhs)
    }
}

impl BitOrAssign<&MacAddress> for MacAddress {
    fn bitor_assign(&mut self, rhs: &Self) {
        *self = &*self | rhs;
    }
}

impl BitOrAssign for MacAddress {
    fn bitor_assign(&mut self, rhs: Self) {
        self.bitor_assign(&rhs)
    }
}

impl BitXor for &MacAddress {
    type Output = MacAddress;

    fn bitxor(self, rhs: Self) -> Self::Output {
        MacAddress::from_value(self.value() ^ rhs.value())
    }
}

impl BitXor<MacAddress> for &MacAddress {
    type Output = MacAddress;

    fn bitxor(self, rhs: MacAddress) -> Self::Output {
        self.bitxor(&rhs)
    }
}

impl BitXor<&MacAddress> for MacAddress {
    type Output = Self;

    fn bitxor(self, rhs: &Self) -> Self::Output {
        BitXor::bitxor(&self, rhs)
    }
}

impl BitXor for MacAddress {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.bitxor(&rhs)
    }
}

impl BitXorAssign<&MacAddress> for MacAddress {
    fn bitxor_assign(&mut self, rhs: &Self) {
        *self = &*self ^ rhs;
    }
}

impl BitXorAssign for MacAddress {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.bitxor_assign(&rhs)
    }
}

impl Not for &MacAddress {
    type Output = MacAddress;

    fn not(self) -> Self::Output {
        MacAddress::from_value(!self.value())
    }
}

impl Not for MacAddress {
    type Output = Self;

    fn not(self) -> Self::Output {
        Not::not(&self)
    }
}

impl FromStr for MacAddress {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 8];
        parse_hw(s, &mut addr[2..])?;
        Ok(Self(addr))
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl Decode for MacAddress {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(<[u8; 6]>::decode, Self::from)(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

impl Encode for MacAddress {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        encoder.encode(&self.0[2..]).map(|_| ())
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

impl Address for MacAddress {
    type Raw = [u8; 6];

    fn from_prefix_len(prefix_len: u32) -> Self {
        if prefix_len >= 48 {
            Self([0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        } else {
            Self::from_value(!(!0u64 >> (prefix_len + 16)) & 0x0000_ffff_ffff_ffff)
        }
    }

    fn as_prefix_len(&self) -> u32 {
        (self.value() | 0xffff000000000000).leading_ones()
    }

    fn next_addr(&self) -> Self {
        Self::from_value((self.value() + 1) & 0x0000_ffff_ffff_ffff)
    }

    fn prev_addr(&self) -> Self {
        Self::from_value(self.value().wrapping_sub(1) & 0x0000_ffff_ffff_ffff)
    }
}

/// OUI assignment database and utilities
pub mod oui {

    use crate::{MacAddress, Subnet};
    use std::fmt::{self, Display};

    /// An assignment of a range of MAC addresses to a manufacturer
    #[derive(Debug)]
    pub struct Assignment {
        range: Subnet<MacAddress>,
        abbrv: &'static str,
        name: &'static str,
    }

    impl Assignment {
        /// Database of OUI assignments according to IEEE
        ///
        /// This list is sorted in ascending address order.
        pub const DATABASE: &'static [Self] = ASSIGNMENTS;

        /// Returns the range of addresses associated with this assignment
        pub fn range(&self) -> &Subnet<MacAddress> {
            &self.range
        }

        /// Returns an abbreviation of the manufacturer's name
        pub fn abbrv(&self) -> &'static str {
            self.abbrv
        }

        /// Returns the full manufacturer's name
        pub fn name(&self) -> &'static str {
            self.name
        }
    }

    include!(concat!(env!("OUT_DIR"), "/oui_assignments.rs"));

    /// A MacAddress wrapper to format the address using OUI assignment information.
    pub struct Fmt<'a>(&'a MacAddress, Option<&'static Assignment>);

    /// Wraps a MacAddress to format the address using OUI assignment information.
    ///
    /// If the address has no associated OUI assignment, the address is formatted
    /// normally.
    ///
    /// NOTE: Looking up the OUI assignment runs in `O(log(n))` time, where `n` is
    /// the length of `oui::Assignment::DATABASE`.
    ///
    /// ## Example:
    /// ```
    /// # use sniffle_address::{mac, oui};
    /// let addr = mac!("00:00:00:12:34:56");
    /// let string = format!("{}", oui::fmt(&addr));
    /// assert_eq!(string, "Xerox_12:34:56");
    /// ```
    pub fn fmt(addr: &MacAddress) -> Fmt<'_> {
        Fmt(addr, addr.oui())
    }

    /// Wraps a MacAddress to format the address using OUI assignment information.
    ///
    /// If the `oui_info` is `None`, the address is formatted normally.
    ///
    /// ## Example:
    /// ```
    /// # use sniffle_address::{mac, oui};
    /// let addr = mac!("00:00:00:12:34:56");
    /// let oui_info = addr.oui();
    /// let string = format!("{}", oui::fmt_with(&addr, oui_info));
    /// assert_eq!(string, "Xerox_12:34:56");
    /// ```
    pub fn fmt_with<'a>(addr: &'a MacAddress, oui_info: Option<&'static Assignment>) -> Fmt<'a> {
        Fmt(addr, oui_info)
    }

    impl<'a> Display for Fmt<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if let Some(ent) = self.1 {
                let len = ent.range().prefix_len();
                if len == 36 {
                    write!(
                        f,
                        "{}_{:x}:{:02x}",
                        ent.abbrv(),
                        self.0[4] & 0x0F,
                        self.0[5]
                    )?;
                } else if len == 32 {
                    write!(f, "{}_{:02x}:{:02x}", ent.abbrv(), self.0[4], self.0[5])?;
                } else if len == 28 {
                    write!(
                        f,
                        "{}_{:x}:{:02x}:{:02x}",
                        ent.abbrv(),
                        self.0[3] & 0x0F,
                        self.0[4],
                        self.0[5]
                    )?;
                } else {
                    write!(
                        f,
                        "{}_{:02x}:{:02x}:{:02x}",
                        ent.abbrv(),
                        self.0[3],
                        self.0[4],
                        self.0[5]
                    )?;
                }
                Ok(())
            } else {
                Display::fmt(&self.0, f)
            }
        }
    }
}
