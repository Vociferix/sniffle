A crate for working with unsigned integers of various bit widths.

This crate works as an alternative to existing bitfield crates. The
uint types provided by this crate can be used as fields in a struct
to emulate bit fields, but the resulting struct is not packed like
with actual bit fields. However, the fields are accessible like a
normal struct field, where most bitfield crates provide some other
way of getting and setting the individual bitfields, and require
macros that generate the actual struct. The `pack` and `unpack`
macros provide the mechanism for packing and unpacking uints like
bitfields.

This crate is a utility for the `sniffle` crate, but can be used
outside of `sniffle`. In `sniffle` this crate is used for parsing
and writing packet headers that have fields with unusual bit widths
(i.e. not 8, 16, 32, or 64 bits).

The uints provided by this crate are represented using a builtin
unsigned integer (`u8`, `u16`, `u32`, or `u64`) capable of holding
the required number of bits. However, they provide an interface
that guarantees a valid n-bit value at all times.

## Packing and Unpacking
Packing and unpacking are the bitwise concatenation and spliting of
uints, respectively. While these are simple bitwise operations, the
`pack` and `unpack` macros provide type safety, such that the
concatenation of two uints results in a uint whose bit width equals
the sum of the bit widths of the unpacked types. For example,
packing a U17 and a U23 together results in a U40. This also means
that the result of a pack has no padding bits, which could be
confusing when trying to determine if padding is in the most or
least significant bits of the packed value.

Out-of-the-box, packing can be performed with all tuples of uints
where the packed type would be another available uint type. Tuples
are packed such that the first (index 0) uint in the tuple is
packed into the most significant bits, and the last uint is packed
into the least significant bits. This "big endian" order was chosen
to logically match with the idea of concatenating the values of the
tuple in order.

## u128 Feature
The optional u128 feature enables using `u128` in order to provide
uints `U65` to `U127`. However, the compilation time increases
exponentially with more uint types. 64 bits is generally enough for
most use cases, so this feature is not enabled by default, but when
enabling this feature, be aware that compile times will be very
long. Times will vary, but expect a compile time on the order of
15 minutes with this feature enabled.

## Example
```rust
use sniffle_uint::{self as uint, BitPack, pack, unpack};

// NOTE: The size of BitFields is greater than 1 byte, even if the
//       the bits add up to 8. Each field in this struct is
//       represented with a u8, since each field is less than 8
//       bits and u8 is the smallest builtin uint.
struct BitFields {
    pub a: uint::U3,
    pub b: uint::U4,
    pub c: uint::U1,
}

// NOTE: Perhaps a derive macro will be provided for this pattern
//       in the future.
impl BitPack for BitFields {
    type Packed = u8;

    fn pack(self) -> Self::Packed {
        uint::pack!(self.a, self.b, self.c)
    }

    fn unpack(packed: Self::Packed) -> Self {
        let (a, b, c) = uint::unpack!(packed);
        Self { a, b, c }
    }
}

impl From<u8> for BitFields {
    fn from(value: u8) -> Self {
        Self::unpack(value)
    }
}

impl From<BitFields> for u8 {
    fn from(fields: BitFields) -> Self {
        fields.pack()
    }
}
```
