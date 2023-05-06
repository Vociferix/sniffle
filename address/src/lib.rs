use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    ops::{
        BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Bound, Deref, DerefMut,
        Not, RangeBounds,
    },
    str::FromStr,
};

use sniffle_ende::{decode::Decode, encode::Encode};

use sniffle_address_parse::parse_subnet;

#[doc(hidden)]
pub use sniffle_address_macros::{
    raw_hw, raw_ipv4, raw_ipv4_subnet, raw_ipv6, raw_ipv6_subnet, raw_mac,
};

mod hw;
mod ipv4;
mod ipv6;
mod mac;

pub use hw::*;
pub use ipv4::*;
pub use ipv6::*;
pub use mac::oui;
pub use mac::MacAddress;

/// Macro that supports compile time evaluated `MacAddress` literals.
///
/// ## Example
/// ```
/// # use sniffle_address::{mac, MacAddress};
/// const CONST_MAC: MacAddress = mac!("01:02:03:04:05:06");
/// assert_eq!(CONST_MAC, MacAddress::new([1, 2, 3, 4, 5, 6]));
/// assert_eq!(mac!("01-02-03-04-05-06"), MacAddress::new([1, 2, 3, 4, 5, 6]));
/// ```
#[macro_export]
macro_rules! mac {
    ($s:literal) => {{
        $crate::MacAddress::new($crate::raw_mac!($s))
    }};
}

/// Macro that supports compile time evaluated `HwAddress` literals.
///
/// ## Example
/// ```
/// # use sniffle_address::{hw, HwAddress};
/// const CONST_HW: HwAddress<4> = hw!("01:02:03:04");
/// assert_eq!(CONST_HW, HwAddress::new([1, 2, 3, 4]));
/// assert_eq!(hw!("01-02-03-04-05-06-07-08"), HwAddress::new([1, 2, 3, 4, 5, 6, 7, 8]));
/// ```
#[macro_export]
macro_rules! hw {
    ($s:literal) => {{
        $crate::HwAddress::new($crate::raw_hw!($s))
    }};
}

/// Macro that supports compile time evaluated `Ipv4Address` literals.
///
/// ## Example
/// ```
/// # use sniffle_address::{ipv4, Ipv4Address};
/// const CONST_IP: Ipv4Address = ipv4!("1.2.3.4");
/// assert_eq!(CONST_IP, Ipv4Address::new([1, 2, 3, 4]));
/// assert_eq!(ipv4!("192.168.0.1"), Ipv4Address::new([192, 168, 0, 1]));
/// ```
#[macro_export]
macro_rules! ipv4 {
    ($s:literal) => {{
        $crate::Ipv4Address::new($crate::raw_ipv4!($s))
    }};
}

/// Macro that supports compile time evaluated `Ipv4Subnet` literals.
///
/// ## Example
/// ```
/// # use sniffle_address::{ipv4, ipv4_subnet, Ipv4Subnet};
/// const CONST_SUBNET: Ipv4Subnet = ipv4_subnet!("192.168.0.0/16");
/// assert_eq!(CONST_SUBNET, Ipv4Subnet::new(ipv4!("192.168.0.0"), 16));
/// assert_eq!(ipv4_subnet!("10.0.0.0/8"), Ipv4Subnet::new(ipv4!("10.0.0.0"), 8));
/// ```
#[macro_export]
macro_rules! ipv4_subnet {
    ($s:literal) => {{
        let (addr, prefix_len) = $crate::raw_ipv4_subnet!($s);
        $crate::Ipv4Subnet::new($crate::Ipv4Address::new(addr), prefix_len)
    }};
}

/// Macro that supports compile time evaluated `Ipv6Address` literals.
///
/// ## Example
/// ```
/// # use sniffle_address::{ipv6, Ipv6Address};
/// const CONST_IP: Ipv6Address = ipv6!("fe80::1");
/// assert_eq!(CONST_IP, Ipv6Address::from_words([0xfe80, 0, 0, 0, 0, 0, 0, 1]));
/// assert_eq!(ipv6!("::1"), Ipv6Address::from_words([0, 0, 0, 0, 0, 0, 0, 1]));
/// assert_eq!(ipv6!("::1.2.3.4"), Ipv6Address::from_words([0, 0, 0, 0, 0, 0, 0x0102, 0x0304]));
/// ```
#[macro_export]
macro_rules! ipv6 {
    ($s:literal) => {{
        $crate::Ipv6Address::new($crate::raw_ipv6!($s))
    }};
}

/// Macro that supports compile time evaluated `Ipv6Subnet` literals.
///
/// ## Example
/// ```
/// # use sniffle_address::{ipv6, ipv6_subnet, Ipv6Subnet};
/// const CONST_SUBNET: Ipv6Subnet = ipv6_subnet!("fe80::/10");
/// assert_eq!(CONST_SUBNET, Ipv6Subnet::new(ipv6!("fe80::"), 10));
/// assert_eq!(ipv6_subnet!("ff00::/8"), Ipv6Subnet::new(ipv6!("ff00::"), 8));
/// ```
#[macro_export]
macro_rules! ipv6_subnet {
    ($s:literal) => {{
        let (addr, prefix_len) = $crate::raw_ipv6_subnet!($s);
        $crate::Ipv6Subnet::new($crate::Ipv6Address::new(addr), prefix_len)
    }};
}

mod private {
    pub trait Sealed {}

    impl<const SZ: usize> Sealed for [u8; SZ] {}
}

/// A trait for the raw representation of an address.
///
/// All addresses are represented as a statically sized array of bytes.
pub trait RawAddress: private::Sealed {
    /// The number of bytes in the raw address
    const BYTE_WIDTH: usize;

    /// The number of bits in the raw address
    const BIT_WIDTH: usize;
}

impl<const SZ: usize> RawAddress for [u8; SZ] {
    const BYTE_WIDTH: usize = SZ;
    const BIT_WIDTH: usize = SZ * 8;
}

/// A trait representing for types representing a network address.
pub trait Address:
    Clone
    + Copy
    + Debug
    + Display
    + FromStr<Err = AddressParseError>
    + Default
    + Deref<Target = [u8]>
    + DerefMut
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Hash
    + BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + From<Self::Raw>
    + Into<Self::Raw>
    + Encode
    + Decode
    + Send
    + Sync
    + Unpin
{
    /// The byte array representation of the raw address
    type Raw: RawAddress;

    /// Constructs a subnet mask from a prefix length in bits
    fn from_prefix_len(prefix_len: u32) -> Self;

    /// Converts a subnet mask into the corresponding prefix length
    fn as_prefix_len(&self) -> u32;

    /// Returns the next logical address
    ///
    /// Repeated calls to this _successor_ function should produce
    /// addresses in ascending order according its `Ord` implementation.
    fn next_addr(&self) -> Self;

    /// Returns the previous logical address
    ///
    /// Repeated calls to this _predecesor_ function should produce
    /// address in descending order according to its `Ord` implementation.
    fn prev_addr(&self) -> Self;
}

/// A range of addresses reprented by a base address and a mask
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subnet<A: Address> {
    base: A,
    prefix_len: u32,
}

/// An iterator over a range of addresses
pub struct AddressIter<A: Address> {
    curr: Option<A>,
    last: A,
}

pub use sniffle_address_parse::AddressParseError;

pub use sniffle_address_parse::SubnetParseError;

impl<A: Address> Subnet<A> {
    /// Creates a subnet from a base address and a prefix length.
    ///
    /// The prefix length is a simpler representation of a netmask,
    /// which is the number of leading bits that are fixed.
    pub const fn new(base: A, prefix_len: u32) -> Self {
        Self { base, prefix_len }
    }

    /// The base address of the subnet
    pub fn base_addr(&self) -> A {
        self.base & self.mask()
    }

    /// The netmask of the subnet
    pub fn mask(&self) -> A {
        A::from_prefix_len(self.prefix_len)
    }

    /// The prefix length of the subnet
    pub fn prefix_len(&self) -> u32 {
        self.prefix_len
    }

    /// Returns true if the subnet contains the address `addr`
    pub fn contains(&self, addr: &A) -> bool {
        (*addr & self.mask()) == self.base
    }

    /// The first usable address of the subnet
    ///
    /// This is equivalent to the next address after `base_addr()`
    pub fn first(&self) -> A {
        (self.base & self.mask()).next_addr()
    }

    /// The last address of the subnet
    pub fn last(&self) -> A {
        self.base | !self.mask()
    }

    /// Returns an iterator across all usable addresses in the subnet
    pub fn iter(&self) -> AddressIter<A> {
        AddressIter {
            curr: Some(self.first()),
            last: self.last(),
        }
    }
}

impl<A: Address> FromStr for Subnet<A> {
    type Err = SubnetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix_len) = parse_subnet(s, A::from_str, A::Raw::BIT_WIDTH as u32)?;
        Ok(Self::new(addr, prefix_len))
    }
}

impl<A: Address> Display for Subnet<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base_addr(), self.prefix_len())
    }
}

impl<A: Address> AddressIter<A> {
    pub fn new<R: RangeBounds<A>>(range: R) -> Self {
        let first = match range.start_bound() {
            Bound::Unbounded => A::from_prefix_len(0),
            Bound::Included(addr) => *addr,
            Bound::Excluded(addr) => addr.next_addr(),
        };
        let last = match range.end_bound() {
            Bound::Unbounded => A::from_prefix_len(A::Raw::BIT_WIDTH as u32),
            Bound::Included(addr) => *addr,
            Bound::Excluded(addr) => addr.prev_addr(),
        };
        Self {
            curr: Some(first),
            last,
        }
    }
}

impl<A: Address> Iterator for AddressIter<A> {
    type Item = A;

    fn next(&mut self) -> Option<Self::Item> {
        let tmp = self.curr;
        match tmp {
            Some(addr) => {
                if addr == self.last {
                    self.curr = None
                } else {
                    self.curr = Some(addr.next_addr())
                }
                Some(addr)
            }
            None => None,
        }
    }
}

impl<A: Address> IntoIterator for Subnet<A> {
    type Item = A;
    type IntoIter = AddressIter<A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<A: Address> IntoIterator for &Subnet<A> {
    type Item = A;
    type IntoIter = AddressIter<A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
