use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, DerefMut, Not, RangeBounds, Bound},
    str::FromStr,
};

use sniffle_ende::{
    decode::Decode,
    encode::Encode,
};

use thiserror::Error;

mod ipv4;
mod ipv6;

pub use ipv4::*;
pub use ipv6::*;

mod private {
    pub trait Sealed { }

    impl<const SZ: usize> Sealed for [u8; SZ] { }
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
    + FromStr<Err=AddressParseError>
    + Default
    + Deref<Target = [u8]>
    + DerefMut
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Hash
    + BitAnd<Output=Self>
    + BitAndAssign
    + BitOr<Output=Self>
    + BitOrAssign
    + BitXor<Output=Self>
    + BitXorAssign
    + Not<Output=Self>
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

#[derive(Debug, Clone, Error)]
pub enum AddressParseError {
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Invalid address length")]
    InvalidLength,
}

#[derive(Debug, Clone, Error)]
pub enum SubnetParseError {
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Invalid address length")]
    InvalidLength,
    #[error("Invalid subnet prefix length")]
    InvalidPrefixLen,
}

impl From<AddressParseError> for SubnetParseError {
    fn from(e: AddressParseError) -> Self {
        match e {
            AddressParseError::ParseInt(e) => Self::from(e),
            AddressParseError::InvalidLength => Self::InvalidLength,
        }
    }
}

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
        match s.rfind('/') {
            Some(pos) => {
                let addr: A = s[..pos].parse()?;
                let prefix_len: u32 = s[(pos + 1)..].parse()?;
                if prefix_len > A::Raw::BIT_WIDTH as u32 {
                    Err(SubnetParseError::InvalidPrefixLen)
                } else {
                    Ok(Self::new(addr, prefix_len))
                }
            },
            None => {
                Ok(Self::new(s.parse()?, A::Raw::BIT_WIDTH as u32))
            }
        }
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
