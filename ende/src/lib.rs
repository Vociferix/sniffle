#![recursion_limit = "256"]

pub mod decode;
pub mod encode;

mod bitpack;

pub use bitpack::BitPack;

pub use sniffle_ende_derive::BitPack;

/// Utility to simplify packing uints.
///
/// Packing uints will result in a single uint that matches the exact bit width
/// of the input uints combined. As such, it is only possible to pack up to
/// a total of 64 (or 128 with the "u128" feature enabled) bits, since there
/// is no possible result uint beyond u64 (or u128).
///
/// ## Example
/// ```
/// # use sniffle_uint::*;
/// # use sniffle_ende::pack;
/// let val1 = U2::new(0b10).unwrap();
/// let val2 = U7::new(0b0110101).unwrap();
/// let val3 = U1::new(0b0).unwrap();
/// let val4 = U3::new(0b110).unwrap();
///
/// let packed = pack!(val1, val2, val3, val4);
///
/// assert_eq!(packed, U13::new(0b10_0110101_0_110).unwrap());
/// ```
#[macro_export]
macro_rules! pack {
    ($term:expr) => {{ $term }};
    ($first:expr, $($rest:expr),+) => {{
        fn pack_<T: $crate::BitPack>(vals: T) -> T::Packed {
            vals.pack()
        }
        pack_(($first, $($rest),+))
    }};
}

/// Utility to simplify unpacking uints.
///
/// ## Example
/// ```
/// # use sniffle_uint::*;
/// # use sniffle_ende::unpack;
/// let packed = U13::new(0b10_0110101_0_110).unwrap();
///
/// let unpacked: (U2, U7, U1, U3) = unpack!(packed);
///
/// assert_eq!(unpacked.0, U2::new(0b10).unwrap());
/// assert_eq!(unpacked.1, U7::new(0b0110101).unwrap());
/// assert_eq!(unpacked.2, U1::new(0b0).unwrap());
/// assert_eq!(unpacked.3, U3::new(0b110).unwrap());
/// ```
#[macro_export]
macro_rules! unpack {
    ($val:expr) => {{
        fn unpack_<T: $crate::BitPack>(val: T::Packed) -> T {
            T::unpack(val)
        }
        unpack_($val)
    }};
}
