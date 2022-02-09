pub mod decode;
pub mod encode;

pub use nom;

const BIG_ENDIAN_ACTUAL: u32 = u32::from_be_bytes([1, 2, 3, 4]);
const BIG_ENDIAN_EXPECTED: u32 = 0x01020304;
pub(crate) const IS_BIG_ENDIAN: bool = BIG_ENDIAN_ACTUAL == BIG_ENDIAN_EXPECTED;

const LITTLE_ENDIAN_ACTUAL: u32 = u32::from_le_bytes([1, 2, 3, 4]);
const LITTLE_ENDIAN_EXPECTED: u32 = 0x04030201;
pub(crate) const IS_LITTLE_ENDIAN: bool = LITTLE_ENDIAN_ACTUAL == LITTLE_ENDIAN_EXPECTED;
