#![recursion_limit = "256"]
#![allow(clippy::modulo_one)]

/// A 8-bit unsigned integer.
pub type U8 = u8;

/// A 16-bit unsigned integer.
pub type U16 = u16;

/// A 32-bit unsigned integer.
pub type U32 = u32;

/// A 64-bit unsigned integer.
pub type U64 = u64;

#[cfg(feature = "u128")]
/// A 128-bit unsigned integer.
pub type U128 = u128;

pub trait FromMasked<T> {
    fn from_masked(value: T) -> Self;
}

pub trait IntoMasked<T> {
    fn into_masked(self) -> T;
}

impl<T, U: FromMasked<T>> IntoMasked<U> for T {
    fn into_masked(self) -> U {
        U::from_masked(self)
    }
}

impl<T: FromMasked<U31>> FromMasked<i32> for T {
    fn from_masked(value: i32) -> Self {
        Self::from_masked(U31((value as u32) & 0x7FFFFFFF))
    }
}

macro_rules! uint {
    ($name:ident, $width:literal, $repr:ty) => {
        #[doc=concat!("A ", stringify!($width), "-bit unsigned integer.\n\nRepresented with a `", stringify!($repr), "`.")]
        #[derive(Clone, Copy, Debug)]
        #[repr(transparent)]
        pub struct $name($repr);

        impl $name {
            pub const MIN: Self = Self(0);

            pub const MAX: Self = Self(!(<$repr>::MAX << $width));

            pub const BITS: u32 = $width;

            pub const fn new(n: $repr) -> Option<Self> {
                if n > Self::MAX.0 {
                    None
                } else {
                    Some(Self(n))
                }
            }

            pub const fn get(self) -> $repr {
                self.0
            }

            pub const fn count_ones(self) -> u32 {
                self.0.count_ones()
            }

            pub const fn count_zeros(self) -> u32 {
                (self.0 | !Self::MAX.0).count_zeros()
            }

            pub const fn leading_zeros(self) -> u32 {
                (!(!self.0 << (<$repr>::BITS - Self::BITS))).leading_zeros()
            }

            pub const fn trailing_zeros(self) -> u32 {
                (self.0 | !Self::MAX.0).trailing_zeros()
            }

            pub const fn leading_ones(self) -> u32 {
                (self.0 << (<$repr>::BITS - Self::BITS)).leading_ones()
            }

            pub const fn trailing_ones(self) -> u32 {
                self.0.trailing_ones()
            }

            pub const fn rotate_left(self, n: u32) -> Self {
                let n = n % Self::BITS;
                Self(((self.0 << n) | (self.0 >> (Self::BITS - n))) & Self::MAX.0)
            }

            pub const fn rotate_right(self, n: u32) -> Self {
                let n = n % Self::BITS;
                Self(((self.0 >> n) | (self.0 << (Self::BITS - n))) & Self::MAX.0)
            }

            pub const fn reverse_bits(self) -> Self {
                Self(self.0.reverse_bits() >> (<$repr>::BITS - Self::BITS))
            }

            pub const fn checked_add(self, rhs: Self) -> Option<Self> {
                match self.0.checked_add(rhs.0) {
                    Some(val) => {
                        if val > Self::MAX.0 {
                            None
                        } else {
                            Some(Self(val))
                        }
                    }
                    None => None,
                }
            }

            pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
                match self.0.checked_sub(rhs.0) {
                    Some(val) => Some(Self(val)),
                    None => None,
                }
            }

            pub const fn checked_mul(self, rhs: Self) -> Option<Self> {
                match self.0.checked_mul(rhs.0) {
                    Some(val) => {
                        if val > Self::MAX.0 {
                            None
                        } else {
                            Some(Self(val))
                        }
                    }
                    None => None,
                }
            }

            pub const fn checked_div(self, rhs: Self) -> Option<Self> {
                match self.0.checked_div(rhs.0) {
                    Some(val) => Some(Self(val)),
                    None => None,
                }
            }

            pub const fn checked_div_euclid(self, rhs: Self) -> Option<Self> {
                match self.0.checked_div_euclid(rhs.0) {
                    Some(val) => Some(Self(val)),
                    None => None,
                }
            }

            pub const fn checked_rem(self, rhs: Self) -> Option<Self> {
                match self.0.checked_rem(rhs.0) {
                    Some(val) => Some(Self(val)),
                    None => None,
                }
            }

            pub const fn checked_rem_euclid(self, rhs: Self) -> Option<Self> {
                match self.0.checked_rem_euclid(rhs.0) {
                    Some(val) => Some(Self(val)),
                    None => None,
                }
            }

            pub const fn checked_neg(self) -> Option<Self> {
                match self.0.checked_neg() {
                    Some(val) => Some(Self(val)),
                    None => None,
                }
            }

            pub const fn checked_shl(self, rhs: u32) -> Option<Self> {
                if rhs >= Self::BITS {
                    None
                } else {
                    Some(Self((self.0 << rhs) & Self::MAX.0))
                }
            }

            pub const fn checked_shr(self, rhs: u32) -> Option<Self> {
                if rhs >= Self::BITS {
                    None
                } else {
                    Some(Self((self.0 >> rhs) & Self::MAX.0))
                }
            }

            pub const fn checked_pow(self, exp: u32) -> Option<Self> {
                match self.0.checked_pow(exp) {
                    Some(val) => {
                        if val > Self::MAX.0 {
                            None
                        } else {
                            Some(Self(val))
                        }
                    }
                    None => None,
                }
            }

            pub const fn saturating_add(self, rhs: Self) -> Self {
                let val = self.0.saturating_add(rhs.0);
                if val > Self::MAX.0 {
                    Self::MAX
                } else {
                    Self(val)
                }
            }

            pub const fn saturating_sub(self, rhs: Self) -> Self {
                Self(self.0.saturating_sub(rhs.0))
            }

            pub const fn saturating_mul(self, rhs: Self) -> Self {
                let val = self.0.saturating_mul(rhs.0);
                if val > Self::MAX.0 {
                    Self::MAX
                } else {
                    Self(val)
                }
            }

            pub const fn saturating_pow(self, exp: u32) -> Self {
                let val = self.0.saturating_pow(exp);
                if val > Self::MAX.0 {
                    Self::MAX
                } else {
                    Self(val)
                }
            }

            pub const fn wrapping_add(self, rhs: Self) -> Self {
                Self(self.0.wrapping_add(rhs.0) & Self::MAX.0)
            }

            pub const fn wrapping_sub(self, rhs: Self) -> Self {
                if self.0 < rhs.0 {
                    Self((Self::MAX.0 - (rhs.0 - self.0)).wrapping_add(1) & Self::MAX.0)
                } else {
                    Self(self.0 - rhs.0)
                }
            }

            pub const fn wrapping_mul(self, rhs: Self) -> Self {
                Self(self.0.wrapping_mul(rhs.0) & Self::MAX.0)
            }

            pub const fn wrapping_div(self, rhs: Self) -> Self {
                Self(self.0.wrapping_div(rhs.0))
            }

            pub const fn wrapping_div_euclid(self, rhs: Self) -> Self {
                Self(self.0.wrapping_div_euclid(rhs.0))
            }

            pub const fn wrapping_rem(self, rhs: Self) -> Self {
                Self(self.0.wrapping_rem(rhs.0))
            }

            pub const fn wrapping_rem_euclid(self, rhs: Self) -> Self {
                Self(self.0.wrapping_rem_euclid(rhs.0))
            }

            pub const fn wrapping_neg(self) -> Self {
                Self((Self::MAX.0 - self.0).wrapping_add(1) & Self::MAX.0)
            }

            pub const fn wrapping_shl(self, rhs: u32) -> Self {
                Self((self.0 << (rhs % Self::BITS)) & Self::MAX.0)
            }

            pub const fn wrapping_shr(self, rhs: u32) -> Self {
                Self(self.0 >> (rhs % Self::BITS))
            }

            pub const fn wrapping_pow(self, exp: u32) -> Self {
                Self(self.0.wrapping_pow(exp) & Self::MAX.0)
            }

            pub const fn overflowing_add(self, rhs: Self) -> (Self, bool) {
                let (val, ovr) = self.0.overflowing_add(rhs.0);
                if val > Self::MAX.0 {
                    (Self(val & Self::MAX.0), true)
                } else {
                    (Self(val), ovr)
                }
            }

            pub const fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
                if self.0 < rhs.0 {
                    (self.wrapping_sub(rhs), true)
                } else {
                    (Self(self.0 - rhs.0), false)
                }
            }

            pub const fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
                let (val, ovr) = self.0.overflowing_mul(rhs.0);
                if val > Self::MAX.0 {
                    (Self(val & Self::MAX.0), true)
                } else {
                    (Self(val), ovr)
                }
            }

            pub const fn overflowing_div(self, rhs: Self) -> (Self, bool) {
                (Self(self.0.overflowing_div(rhs.0).0), false)
            }

            pub const fn overflowing_div_euclid(self, rhs: Self) -> (Self, bool) {
                self.overflowing_div(rhs)
            }

            pub const fn overflowing_rem(self, rhs: Self) -> (Self, bool) {
                (Self(self.0.overflowing_rem(rhs.0).0), false)
            }

            pub const fn overflowing_rem_euclid(self, rhs: Self) -> (Self, bool) {
                self.overflowing_rem(rhs)
            }

            pub const fn overflowing_neg(self) -> (Self, bool) {
                let (val, ovr) = self.0.overflowing_neg();
                if val > Self::MAX.0 {
                    (Self(val & Self::MAX.0), true)
                } else {
                    (Self(val), ovr)
                }
            }

            pub const fn overflowing_shl(self, rhs: u32) -> (Self, bool) {
                (Self(self.0 << (rhs % Self::BITS)), rhs >= Self::BITS)
            }

            pub const fn overflowing_shr(self, rhs: u32) -> (Self, bool) {
                (Self(self.0 >> (rhs % Self::BITS)), rhs >= Self::BITS)
            }

            pub const fn overflowing_pow(self, exp: u32) -> (Self, bool) {
                let (val, ovr) = self.0.overflowing_pow(exp);
                if val > Self::MAX.0 {
                    (Self(val & Self::MAX.0), true)
                } else {
                    (Self(val), ovr)
                }
            }

            pub fn pow(self, exp: u32) -> Self {
                let val = self.0.pow(exp);
                debug_assert!(val <= Self::MAX.0, "attempt to exponentiate with overflow");
                Self(val & Self::MAX.0)
            }

            pub const fn div_euclid(self, rhs: Self) -> Self {
                Self(self.0.div_euclid(rhs.0))
            }

            pub const fn rem_euclid(self, rhs: Self) -> Self {
                Self(self.0.rem_euclid(rhs.0))
            }

            pub const fn is_power_of_two(self) -> bool {
                self.0.is_power_of_two()
            }

            pub fn next_power_of_two(self) -> Self {
                let val = self.0.next_power_of_two();
                debug_assert!(
                    val <= Self::MAX.0,
                    "attempt to get next power of two with overflow"
                );
                Self(val)
            }

            pub const fn checked_next_power_of_two(self) -> Option<Self> {
                match self.0.checked_next_power_of_two() {
                    Some(val) => {
                        if val > Self::MAX.0 {
                            None
                        } else {
                            Some(Self(val))
                        }
                    }
                    None => None,
                }
            }
        }

        impl std::ops::Add<$name> for $name {
            type Output = $name;

            fn add(self, other: $name) -> $name {
                let val = self.0 + other.0;
                debug_assert!(val <= Self::MAX.0, "attempt to add with overflow");
                Self(val)
            }
        }

        impl<'a> std::ops::Add<&'a $name> for $name {
            type Output = <$name as std::ops::Add<$name>>::Output;

            fn add(self, other: &'a $name) -> <$name as std::ops::Add<$name>>::Output {
                self + *other
            }
        }

        impl<'a> std::ops::Add<$name> for &'a $name {
            type Output = <$name as std::ops::Add<$name>>::Output;

            fn add(self, other: $name) -> <$name as std::ops::Add<$name>>::Output {
                *self + other
            }
        }

        impl<'a, 'b> std::ops::Add<&'a $name> for &'b $name {
            type Output = <$name as std::ops::Add<$name>>::Output;

            fn add(self, other: &'a $name) -> <$name as std::ops::Add<$name>>::Output {
                *self + *other
            }
        }

        impl std::ops::AddAssign<$name> for $name {
            fn add_assign(&mut self, other: $name) {
                self.0 += other.0;
                debug_assert!(self.0 <= Self::MAX.0, "attempt to add with overflow");
            }
        }

        impl<'a> std::ops::AddAssign<&'a $name> for $name {
            fn add_assign(&mut self, other: &'a $name) {
                *self += *other;
            }
        }

        impl std::fmt::Binary for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::Binary::fmt(&self.0, f)
            }
        }

        impl std::ops::BitAnd<$name> for $name {
            type Output = $name;

            fn bitand(self, rhs: $name) -> $name {
                Self(self.0 & rhs.0)
            }
        }

        impl<'a> std::ops::BitAnd<&'a $name> for $name {
            type Output = <$name as std::ops::BitAnd<$name>>::Output;

            fn bitand(self, rhs: &'a $name) -> <$name as std::ops::BitAnd<$name>>::Output {
                self & *rhs
            }
        }

        impl<'a> std::ops::BitAnd<$name> for &'a $name {
            type Output = <$name as std::ops::BitAnd<$name>>::Output;

            fn bitand(self, rhs: $name) -> <$name as std::ops::BitAnd<$name>>::Output {
                *self & rhs
            }
        }

        impl<'a, 'b> std::ops::BitAnd<&'a $name> for &'b $name {
            type Output = <$name as std::ops::BitAnd<$name>>::Output;

            fn bitand(self, rhs: &'a $name) -> <$name as std::ops::BitAnd<$name>>::Output {
                *self & *rhs
            }
        }

        impl std::ops::BitAndAssign<$name> for $name {
            fn bitand_assign(&mut self, other: $name) {
                self.0 &= other.0;
            }
        }

        impl<'a> std::ops::BitAndAssign<&'a $name> for $name {
            fn bitand_assign(&mut self, other: &'a $name) {
                *self &= *other;
            }
        }

        impl std::ops::BitOr<$name> for $name {
            type Output = $name;

            fn bitor(self, other: $name) -> $name {
                Self(self.0 | other.0)
            }
        }

        impl<'a> std::ops::BitOr<&'a $name> for $name {
            type Output = <$name as std::ops::BitOr<$name>>::Output;

            fn bitor(self, other: &'a $name) -> <$name as std::ops::BitOr<$name>>::Output {
                self | *other
            }
        }

        impl<'a> std::ops::BitOr<$name> for &'a $name {
            type Output = <$name as std::ops::BitOr<$name>>::Output;

            fn bitor(self, other: $name) -> <$name as std::ops::BitOr<$name>>::Output {
                *self | other
            }
        }

        impl<'a, 'b> std::ops::BitOr<&'a $name> for &'b $name {
            type Output = <$name as std::ops::BitOr<$name>>::Output;

            fn bitor(self, other: &'a $name) -> <$name as std::ops::BitOr<$name>>::Output {
                *self | *other
            }
        }

        impl std::ops::BitOrAssign<$name> for $name {
            fn bitor_assign(&mut self, other: $name) {
                self.0 |= other.0;
            }
        }

        impl<'a> std::ops::BitOrAssign<&'a $name> for $name {
            fn bitor_assign(&mut self, other: &'a $name) {
                *self |= *other;
            }
        }

        impl std::ops::BitXor<$name> for $name {
            type Output = $name;

            fn bitxor(self, other: $name) -> $name {
                Self(self.0 ^ other.0)
            }
        }

        impl<'a> std::ops::BitXor<&'a $name> for $name {
            type Output = <$name as std::ops::BitXor<$name>>::Output;

            fn bitxor(self, other: &'a $name) -> <$name as std::ops::BitXor<$name>>::Output {
                self ^ *other
            }
        }

        impl<'a> std::ops::BitXor<$name> for &'a $name {
            type Output = <$name as std::ops::BitXor<$name>>::Output;

            fn bitxor(self, other: $name) -> <$name as std::ops::BitXor<$name>>::Output {
                *self ^ other
            }
        }

        impl<'a, 'b> std::ops::BitXor<&'a $name> for &'b $name {
            type Output = <$name as std::ops::BitXor<$name>>::Output;

            fn bitxor(self, other: &'a $name) -> <$name as std::ops::BitXor<$name>>::Output {
                *self ^ *other
            }
        }

        impl std::ops::BitXorAssign<$name> for $name {
            fn bitxor_assign(&mut self, other: $name) {
                self.0 ^= other.0;
            }
        }

        impl<'a> std::ops::BitXorAssign<&'a $name> for $name {
            fn bitxor_assign(&mut self, other: &'a $name) {
                *self ^= *other;
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self(0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::ops::Div<$name> for $name {
            type Output = $name;

            fn div(self, other: $name) -> $name {
                Self(self.0 / other.0)
            }
        }

        impl<'a> std::ops::Div<&'a $name> for $name {
            type Output = <$name as std::ops::Div<$name>>::Output;

            fn div(self, other: &'a $name) -> <$name as std::ops::Div<$name>>::Output {
                self / *other
            }
        }

        impl<'a> std::ops::Div<$name> for &'a $name {
            type Output = <$name as std::ops::Div<$name>>::Output;

            fn div(self, other: $name) -> <$name as std::ops::Div<$name>>::Output {
                *self / other
            }
        }

        impl<'a, 'b> std::ops::Div<&'a $name> for &'b $name {
            type Output = <$name as std::ops::Div<$name>>::Output;

            fn div(self, other: &'a $name) -> <$name as std::ops::Div<$name>>::Output {
                *self / *other
            }
        }

        impl std::ops::DivAssign<$name> for $name {
            fn div_assign(&mut self, other: $name) {
                self.0 /= other.0;
            }
        }

        impl<'a> std::ops::DivAssign<&'a $name> for $name {
            fn div_assign(&mut self, other: &'a $name) {
                *self /= *other;
            }
        }

        impl From<bool> for $name {
            fn from(small: bool) -> Self {
                Self(<$repr>::from(small))
            }
        }

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                std::hash::Hash::hash(&self.0, state);
            }
        }

        impl std::fmt::LowerExp for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::LowerExp::fmt(&self.0, f)
            }
        }

        impl std::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl std::ops::Mul<$name> for $name {
            type Output = $name;

            fn mul(self, other: $name) -> $name {
                let val = self.0 * other.0;
                debug_assert!(val <= Self::MAX.0, "attempt to multiply with overflow");
                Self(val)
            }
        }

        impl<'a> std::ops::Mul<&'a $name> for $name {
            type Output = <$name as std::ops::Mul<$name>>::Output;

            fn mul(self, other: &'a $name) -> <$name as std::ops::Mul<$name>>::Output {
                self * *other
            }
        }

        impl<'a> std::ops::Mul<$name> for &'a $name {
            type Output = <$name as std::ops::Mul<$name>>::Output;

            fn mul(self, other: $name) -> <$name as std::ops::Mul<$name>>::Output {
                *self * other
            }
        }

        impl<'a, 'b> std::ops::Mul<&'a $name> for &'b $name {
            type Output = <$name as std::ops::Mul<$name>>::Output;

            fn mul(self, other: &'a $name) -> <$name as std::ops::Mul<$name>>::Output {
                *self * *other
            }
        }

        impl std::ops::MulAssign<$name> for $name {
            fn mul_assign(&mut self, other: $name) {
                self.0 *= other.0;
                debug_assert!(self.0 <= Self::MAX.0, "attempt to mul with overflow");
            }
        }

        impl<'a> std::ops::MulAssign<&'a $name> for $name {
            fn mul_assign(&mut self, other: &'a $name) {
                *self *= *other;
            }
        }

        impl std::ops::Not for $name {
            type Output = $name;

            fn not(self) -> $name {
                Self(!self.0 & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Not for &'a $name {
            type Output = <$name as std::ops::Not>::Output;

            fn not(self) -> <$name as std::ops::Not>::Output {
                !*self
            }
        }

        impl std::fmt::Octal for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::Octal::fmt(&self.0, f)
            }
        }

        impl std::cmp::PartialEq<$name> for $name {
            fn eq(&self, other: &$name) -> bool {
                std::cmp::PartialEq::<$repr>::eq(&self.0, &other.0)
            }
        }

        impl std::cmp::PartialOrd<$name> for $name {
            fn partial_cmp(&self, other: &$name) -> Option<std::cmp::Ordering> {
                std::cmp::PartialOrd::<$repr>::partial_cmp(&self.0, &other.0)
            }

            fn lt(&self, other: &$name) -> bool {
                std::cmp::PartialOrd::<$repr>::lt(&self.0, &other.0)
            }

            fn le(&self, other: &$name) -> bool {
                std::cmp::PartialOrd::<$repr>::le(&self.0, &other.0)
            }

            fn ge(&self, other: &$name) -> bool {
                std::cmp::PartialOrd::<$repr>::ge(&self.0, &other.0)
            }

            fn gt(&self, other: &$name) -> bool {
                std::cmp::PartialOrd::<$repr>::gt(&self.0, &other.0)
            }
        }

        impl std::cmp::Eq for $name {}

        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                <$repr as std::cmp::Ord>::cmp(&self.0, &other.0)
            }

            fn max(self, other: Self) -> Self {
                Self(<$repr as std::cmp::Ord>::max(self.0, other.0))
            }

            fn min(self, other: Self) -> Self {
                Self(<$repr as std::cmp::Ord>::min(self.0, other.0))
            }

            fn clamp(self, min: Self, max: Self) -> Self {
                Self(<$repr as std::cmp::Ord>::clamp(self.0, min.0, max.0))
            }
        }

        impl std::iter::Product<$name> for $name {
            fn product<I: Iterator<Item = $name>>(iter: I) -> $name {
                let val = std::iter::Product::<$repr>::product(iter.map(|val| val.0));
                debug_assert!(val <= Self::MAX.0, "attempt to multiply with overflow");
                Self(val)
            }
        }

        impl<'a> std::iter::Product<&'a $name> for $name {
            fn product<I: Iterator<Item = &'a $name>>(iter: I) -> $name {
                std::iter::Product::<$name>::product(iter.map(|val| *val))
            }
        }

        impl std::ops::Rem<$name> for $name {
            type Output = $name;

            fn rem(self, other: $name) -> $name {
                Self(self.0 % other.0)
            }
        }

        impl<'a> std::ops::Rem<&'a $name> for $name {
            type Output = <$name as std::ops::Rem<$name>>::Output;

            fn rem(self, other: &'a $name) -> <$name as std::ops::Rem<$name>>::Output {
                self % *other
            }
        }

        impl<'a> std::ops::Rem<$name> for &'a $name {
            type Output = <$name as std::ops::Rem<$name>>::Output;

            fn rem(self, other: $name) -> <$name as std::ops::Rem<$name>>::Output {
                *self % other
            }
        }

        impl<'a, 'b> std::ops::Rem<&'a $name> for &'b $name {
            type Output = <$name as std::ops::Rem<$name>>::Output;

            fn rem(self, other: &'a $name) -> <$name as std::ops::Rem<$name>>::Output {
                *self % *other
            }
        }

        impl std::ops::RemAssign<$name> for $name {
            fn rem_assign(&mut self, other: $name) {
                self.0 %= other.0;
            }
        }

        impl<'a> std::ops::RemAssign<&'a $name> for $name {
            fn rem_assign(&mut self, other: &'a $name) {
                *self %= *other;
            }
        }

        impl std::ops::Shl<u8> for $name {
            type Output = $name;

            fn shl(self, other: u8) -> $name {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a u8> for $name {
            type Output = $name;

            fn shl(self, other: &'a u8) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<u8> for &'a $name {
            type Output = $name;

            fn shl(self, other: u8) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a u8> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a u8) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<u16> for $name {
            type Output = $name;

            fn shl(self, other: u16) -> $name {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a u16> for $name {
            type Output = $name;

            fn shl(self, other: &'a u16) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<u16> for &'a $name {
            type Output = $name;

            fn shl(self, other: u16) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a u16> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a u16) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<u32> for $name {
            type Output = $name;

            fn shl(self, other: u32) -> $name {
                debug_assert!(other < Self::BITS, "attempt to shift left with overflow");
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a u32> for $name {
            type Output = $name;

            fn shl(self, other: &'a u32) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<u32> for &'a $name {
            type Output = $name;

            fn shl(self, other: u32) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a u32> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a u32) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<u64> for $name {
            type Output = $name;

            fn shl(self, other: u64) -> $name {
                debug_assert!(
                    other < Self::BITS as u64,
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a u64> for $name {
            type Output = $name;

            fn shl(self, other: &'a u64) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<u64> for &'a $name {
            type Output = $name;

            fn shl(self, other: u64) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a u64> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a u64) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<u128> for $name {
            type Output = $name;

            fn shl(self, other: u128) -> $name {
                debug_assert!(
                    other < Self::BITS as u128,
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a u128> for $name {
            type Output = $name;

            fn shl(self, other: &'a u128) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<u128> for &'a $name {
            type Output = $name;

            fn shl(self, other: u128) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a u128> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a u128) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<usize> for $name {
            type Output = $name;

            fn shl(self, other: usize) -> $name {
                debug_assert!(
                    other < Self::BITS as usize,
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a usize> for $name {
            type Output = $name;

            fn shl(self, other: &'a usize) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<usize> for &'a $name {
            type Output = $name;

            fn shl(self, other: usize) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a usize> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a usize) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<i8> for $name {
            type Output = $name;

            fn shl(self, other: i8) -> $name {
                debug_assert!(
                    other < Self::BITS as i8 || other <= -(Self::BITS as i8),
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a i8> for $name {
            type Output = $name;

            fn shl(self, other: &'a i8) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<i8> for &'a $name {
            type Output = $name;

            fn shl(self, other: i8) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a i8> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a i8) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<i16> for $name {
            type Output = $name;

            fn shl(self, other: i16) -> $name {
                debug_assert!(
                    other < Self::BITS as i16 || other <= -(Self::BITS as i16),
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a i16> for $name {
            type Output = $name;

            fn shl(self, other: &'a i16) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<i16> for &'a $name {
            type Output = $name;

            fn shl(self, other: i16) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a i16> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a i16) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<i32> for $name {
            type Output = $name;

            fn shl(self, other: i32) -> $name {
                debug_assert!(
                    other < Self::BITS as i32 || other <= -(Self::BITS as i32),
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a i32> for $name {
            type Output = $name;

            fn shl(self, other: &'a i32) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<i32> for &'a $name {
            type Output = $name;

            fn shl(self, other: i32) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a i32> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a i32) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<i64> for $name {
            type Output = $name;

            fn shl(self, other: i64) -> $name {
                debug_assert!(
                    other < Self::BITS as i64 || other <= -(Self::BITS as i64),
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a i64> for $name {
            type Output = $name;

            fn shl(self, other: &'a i64) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<i64> for &'a $name {
            type Output = $name;

            fn shl(self, other: i64) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a i64> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a i64) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<i128> for $name {
            type Output = $name;

            fn shl(self, other: i128) -> $name {
                debug_assert!(
                    other < Self::BITS as i128 || other <= -(Self::BITS as i128),
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a i128> for $name {
            type Output = $name;

            fn shl(self, other: &'a i128) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<i128> for &'a $name {
            type Output = $name;

            fn shl(self, other: i128) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a i128> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a i128) -> $name {
                *self << *other
            }
        }

        impl std::ops::Shl<isize> for $name {
            type Output = $name;

            fn shl(self, other: isize) -> $name {
                debug_assert!(
                    other < Self::BITS as isize || other <= -(Self::BITS as isize),
                    "attempt to shift left with overflow"
                );
                Self((self.0 << other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shl<&'a isize> for $name {
            type Output = $name;

            fn shl(self, other: &'a isize) -> $name {
                self << *other
            }
        }

        impl<'a> std::ops::Shl<isize> for &'a $name {
            type Output = $name;

            fn shl(self, other: isize) -> $name {
                *self << other
            }
        }

        impl<'a, 'b> std::ops::Shl<&'a isize> for &'b $name {
            type Output = $name;

            fn shl(self, other: &'a isize) -> $name {
                *self << *other
            }
        }

        impl std::ops::ShlAssign<u8> for $name {
            fn shl_assign(&mut self, other: u8) {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a u8> for $name {
            fn shl_assign(&mut self, other: &'a u8) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<u16> for $name {
            fn shl_assign(&mut self, other: u16) {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a u16> for $name {
            fn shl_assign(&mut self, other: &'a u16) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<u32> for $name {
            fn shl_assign(&mut self, other: u32) {
                debug_assert!(other < Self::BITS, "attempt to shift left with overflow");
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a u32> for $name {
            fn shl_assign(&mut self, other: &'a u32) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<u64> for $name {
            fn shl_assign(&mut self, other: u64) {
                debug_assert!(
                    other < Self::BITS as u64,
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a u64> for $name {
            fn shl_assign(&mut self, other: &'a u64) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<u128> for $name {
            fn shl_assign(&mut self, other: u128) {
                debug_assert!(
                    other < Self::BITS as u128,
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a u128> for $name {
            fn shl_assign(&mut self, other: &'a u128) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<usize> for $name {
            fn shl_assign(&mut self, other: usize) {
                debug_assert!(
                    other < Self::BITS as usize,
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a usize> for $name {
            fn shl_assign(&mut self, other: &'a usize) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<i8> for $name {
            fn shl_assign(&mut self, other: i8) {
                debug_assert!(
                    other < Self::BITS as i8 || other <= -(Self::BITS as i8),
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a i8> for $name {
            fn shl_assign(&mut self, other: &'a i8) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<i16> for $name {
            fn shl_assign(&mut self, other: i16) {
                debug_assert!(
                    other < Self::BITS as i16 || other <= -(Self::BITS as i16),
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a i16> for $name {
            fn shl_assign(&mut self, other: &'a i16) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<i32> for $name {
            fn shl_assign(&mut self, other: i32) {
                debug_assert!(
                    other < Self::BITS as i32 || other <= -(Self::BITS as i32),
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a i32> for $name {
            fn shl_assign(&mut self, other: &'a i32) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<i64> for $name {
            fn shl_assign(&mut self, other: i64) {
                debug_assert!(
                    other < Self::BITS as i64 || other <= -(Self::BITS as i64),
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a i64> for $name {
            fn shl_assign(&mut self, other: &'a i64) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<i128> for $name {
            fn shl_assign(&mut self, other: i128) {
                debug_assert!(
                    other < Self::BITS as i128 || other <= -(Self::BITS as i128),
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a i128> for $name {
            fn shl_assign(&mut self, other: &'a i128) {
                *self <<= *other;
            }
        }

        impl std::ops::ShlAssign<isize> for $name {
            fn shl_assign(&mut self, other: isize) {
                debug_assert!(
                    other < Self::BITS as isize || other <= -(Self::BITS as isize),
                    "attempt to shift left with overflow"
                );
                self.0 <<= other;
            }
        }

        impl<'a> std::ops::ShlAssign<&'a isize> for $name {
            fn shl_assign(&mut self, other: &'a isize) {
                *self <<= *other;
            }
        }

        impl std::ops::Shr<u8> for $name {
            type Output = $name;

            fn shr(self, other: u8) -> $name {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a u8> for $name {
            type Output = $name;

            fn shr(self, other: &'a u8) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<u8> for &'a $name {
            type Output = $name;

            fn shr(self, other: u8) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a u8> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a u8) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<u16> for $name {
            type Output = $name;

            fn shr(self, other: u16) -> $name {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a u16> for $name {
            type Output = $name;

            fn shr(self, other: &'a u16) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<u16> for &'a $name {
            type Output = $name;

            fn shr(self, other: u16) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a u16> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a u16) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<u32> for $name {
            type Output = $name;

            fn shr(self, other: u32) -> $name {
                debug_assert!(other < Self::BITS, "attempt to shift left with overflow");
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a u32> for $name {
            type Output = $name;

            fn shr(self, other: &'a u32) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<u32> for &'a $name {
            type Output = $name;

            fn shr(self, other: u32) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a u32> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a u32) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<u64> for $name {
            type Output = $name;

            fn shr(self, other: u64) -> $name {
                debug_assert!(
                    other < Self::BITS as u64,
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a u64> for $name {
            type Output = $name;

            fn shr(self, other: &'a u64) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<u64> for &'a $name {
            type Output = $name;

            fn shr(self, other: u64) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a u64> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a u64) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<u128> for $name {
            type Output = $name;

            fn shr(self, other: u128) -> $name {
                debug_assert!(
                    other < Self::BITS as u128,
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a u128> for $name {
            type Output = $name;

            fn shr(self, other: &'a u128) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<u128> for &'a $name {
            type Output = $name;

            fn shr(self, other: u128) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a u128> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a u128) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<usize> for $name {
            type Output = $name;

            fn shr(self, other: usize) -> $name {
                debug_assert!(
                    other < Self::BITS as usize,
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a usize> for $name {
            type Output = $name;

            fn shr(self, other: &'a usize) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<usize> for &'a $name {
            type Output = $name;

            fn shr(self, other: usize) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a usize> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a usize) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<i8> for $name {
            type Output = $name;

            fn shr(self, other: i8) -> $name {
                debug_assert!(
                    other < Self::BITS as i8 || other <= -(Self::BITS as i8),
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a i8> for $name {
            type Output = $name;

            fn shr(self, other: &'a i8) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<i8> for &'a $name {
            type Output = $name;

            fn shr(self, other: i8) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a i8> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a i8) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<i16> for $name {
            type Output = $name;

            fn shr(self, other: i16) -> $name {
                debug_assert!(
                    other < Self::BITS as i16 || other <= -(Self::BITS as i16),
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a i16> for $name {
            type Output = $name;

            fn shr(self, other: &'a i16) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<i16> for &'a $name {
            type Output = $name;

            fn shr(self, other: i16) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a i16> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a i16) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<i32> for $name {
            type Output = $name;

            fn shr(self, other: i32) -> $name {
                debug_assert!(
                    other < Self::BITS as i32 || other <= -(Self::BITS as i32),
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a i32> for $name {
            type Output = $name;

            fn shr(self, other: &'a i32) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<i32> for &'a $name {
            type Output = $name;

            fn shr(self, other: i32) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a i32> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a i32) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<i64> for $name {
            type Output = $name;

            fn shr(self, other: i64) -> $name {
                debug_assert!(
                    other < Self::BITS as i64 || other <= -(Self::BITS as i64),
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a i64> for $name {
            type Output = $name;

            fn shr(self, other: &'a i64) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<i64> for &'a $name {
            type Output = $name;

            fn shr(self, other: i64) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a i64> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a i64) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<i128> for $name {
            type Output = $name;

            fn shr(self, other: i128) -> $name {
                debug_assert!(
                    other < Self::BITS as i128 || other <= -(Self::BITS as i128),
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a i128> for $name {
            type Output = $name;

            fn shr(self, other: &'a i128) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<i128> for &'a $name {
            type Output = $name;

            fn shr(self, other: i128) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a i128> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a i128) -> $name {
                *self >> *other
            }
        }

        impl std::ops::Shr<isize> for $name {
            type Output = $name;

            fn shr(self, other: isize) -> $name {
                debug_assert!(
                    other < Self::BITS as isize || other <= -(Self::BITS as isize),
                    "attempt to shift left with overflow"
                );
                Self((self.0 >> other) & Self::MAX.0)
            }
        }

        impl<'a> std::ops::Shr<&'a isize> for $name {
            type Output = $name;

            fn shr(self, other: &'a isize) -> $name {
                self >> *other
            }
        }

        impl<'a> std::ops::Shr<isize> for &'a $name {
            type Output = $name;

            fn shr(self, other: isize) -> $name {
                *self >> other
            }
        }

        impl<'a, 'b> std::ops::Shr<&'a isize> for &'b $name {
            type Output = $name;

            fn shr(self, other: &'a isize) -> $name {
                *self >> *other
            }
        }

        impl std::ops::ShrAssign<u8> for $name {
            fn shr_assign(&mut self, other: u8) {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a u8> for $name {
            fn shr_assign(&mut self, other: &'a u8) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<u16> for $name {
            fn shr_assign(&mut self, other: u16) {
                debug_assert!(
                    (other as u32) < Self::BITS,
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a u16> for $name {
            fn shr_assign(&mut self, other: &'a u16) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<u32> for $name {
            fn shr_assign(&mut self, other: u32) {
                debug_assert!(other < Self::BITS, "attempt to shift left with overflow");
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a u32> for $name {
            fn shr_assign(&mut self, other: &'a u32) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<u64> for $name {
            fn shr_assign(&mut self, other: u64) {
                debug_assert!(
                    other < Self::BITS as u64,
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a u64> for $name {
            fn shr_assign(&mut self, other: &'a u64) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<u128> for $name {
            fn shr_assign(&mut self, other: u128) {
                debug_assert!(
                    other < Self::BITS as u128,
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a u128> for $name {
            fn shr_assign(&mut self, other: &'a u128) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<usize> for $name {
            fn shr_assign(&mut self, other: usize) {
                debug_assert!(
                    other < Self::BITS as usize,
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a usize> for $name {
            fn shr_assign(&mut self, other: &'a usize) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<i8> for $name {
            fn shr_assign(&mut self, other: i8) {
                debug_assert!(
                    other < Self::BITS as i8 || other <= -(Self::BITS as i8),
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a i8> for $name {
            fn shr_assign(&mut self, other: &'a i8) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<i16> for $name {
            fn shr_assign(&mut self, other: i16) {
                debug_assert!(
                    other < Self::BITS as i16 || other <= -(Self::BITS as i16),
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a i16> for $name {
            fn shr_assign(&mut self, other: &'a i16) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<i32> for $name {
            fn shr_assign(&mut self, other: i32) {
                debug_assert!(
                    other < Self::BITS as i32 || other <= -(Self::BITS as i32),
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a i32> for $name {
            fn shr_assign(&mut self, other: &'a i32) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<i64> for $name {
            fn shr_assign(&mut self, other: i64) {
                debug_assert!(
                    other < Self::BITS as i64 || other <= -(Self::BITS as i64),
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a i64> for $name {
            fn shr_assign(&mut self, other: &'a i64) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<i128> for $name {
            fn shr_assign(&mut self, other: i128) {
                debug_assert!(
                    other < Self::BITS as i128 || other <= -(Self::BITS as i128),
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a i128> for $name {
            fn shr_assign(&mut self, other: &'a i128) {
                *self >>= *other;
            }
        }

        impl std::ops::ShrAssign<isize> for $name {
            fn shr_assign(&mut self, other: isize) {
                debug_assert!(
                    other < Self::BITS as isize || other <= -(Self::BITS as isize),
                    "attempt to shift left with overflow"
                );
                self.0 >>= other;
            }
        }

        impl<'a> std::ops::ShrAssign<&'a isize> for $name {
            fn shr_assign(&mut self, other: &'a isize) {
                *self >>= *other;
            }
        }

        impl std::ops::Sub<$name> for $name {
            type Output = $name;

            fn sub(self, other: $name) -> $name {
                let val = self.0 - other.0;
                debug_assert!(val <= Self::MAX.0, "attempt to sub with overflow");
                Self(val)
            }
        }

        impl<'a> std::ops::Sub<&'a $name> for $name {
            type Output = <$name as std::ops::Sub<$name>>::Output;

            fn sub(self, other: &'a $name) -> <$name as std::ops::Sub<$name>>::Output {
                self - *other
            }
        }

        impl<'a> std::ops::Sub<$name> for &'a $name {
            type Output = <$name as std::ops::Sub<$name>>::Output;

            fn sub(self, other: $name) -> <$name as std::ops::Sub<$name>>::Output {
                *self - other
            }
        }

        impl<'a, 'b> std::ops::Sub<&'a $name> for &'b $name {
            type Output = <$name as std::ops::Sub<$name>>::Output;

            fn sub(self, other: &'a $name) -> <$name as std::ops::Sub<$name>>::Output {
                *self - *other
            }
        }

        impl std::ops::SubAssign<$name> for $name {
            fn sub_assign(&mut self, other: $name) {
                self.0 -= other.0;
                debug_assert!(self.0 <= Self::MAX.0, "attempt to sub with overflow");
            }
        }

        impl<'a> std::ops::SubAssign<&'a $name> for $name {
            fn sub_assign(&mut self, other: &'a $name) {
                *self -= *other;
            }
        }

        impl std::iter::Sum<$name> for $name {
            fn sum<I: Iterator<Item = $name>>(iter: I) -> $name {
                let val = std::iter::Sum::<$repr>::sum(iter.map(|val| val.0));
                debug_assert!(val <= Self::MAX.0, "attempt to add with overflow");
                Self(val)
            }
        }

        impl<'a> std::iter::Sum<&'a $name> for $name {
            fn sum<I: Iterator<Item = &'a $name>>(iter: I) -> $name {
                std::iter::Sum::<$name>::sum(iter.map(|val| *val))
            }
        }

        impl std::fmt::UpperExp for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::UpperExp::fmt(&self.0, f)
            }
        }

        impl std::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                std::fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl RawValue for $name {
            type Raw = $repr;

            fn from_raw(raw: Self::Raw) -> Self {
                Self(raw)
            }

            fn into_raw(self) -> Self::Raw {
                self.0
            }
        }
    };
}

macro_rules! from_impl {
    ($tgt:ty; $src:ty) => {
        impl From<$src> for $tgt {
            fn from(val: $src) -> Self {
                Self::from_raw(val.into_raw().into())
            }
        }

        impl std::convert::TryFrom<$tgt> for $src {
            type Error = std::num::TryFromIntError;

            fn try_from(val: $tgt) -> Result<Self, Self::Error> {
                let ret = Self::from_raw(val.into_raw().try_into()?);
                if ret.into_raw() > Self::MAX.into_raw() {
                    <u8 as std::convert::TryFrom<u16>>::try_from(256).map(|_| Self::from_raw(0))
                } else {
                    Ok(ret)
                }
            }
        }

        impl FromMasked<$tgt> for $src {
            fn from_masked(val: $tgt) -> Self {
                let mask: <$tgt as RawValue>::Raw = Self::MAX.into_raw().into();
                Self::from_raw((val.into_raw() & mask) as <Self as RawValue>::Raw)
            }
        }
    };
    ({$tgt:ty}; $src:ty) => {
        from_impl!($tgt; $src);
    };
    ($tgt:ty; {$src:ty}) => {
        from_impl!($tgt; $src);
    };
    ({$tgt:ty}; {$src:ty}) => { };
    ($tgt:tt; $src:tt, $($srcs:tt),+) => {
        from_impl!($tgt; $src);
        from_impl!($tgt; $($srcs),+);
    };
    ($tgt:tt) => { };
    ($tgt:tt, $($srcs:tt),+) => {
        from_impl!($tgt; $($srcs),+);
        from_impl!($($srcs),+);
    }
}

uint!(U1, 1, u8);
uint!(U2, 2, u8);
uint!(U3, 3, u8);
uint!(U4, 4, u8);
uint!(U5, 5, u8);
uint!(U6, 6, u8);
uint!(U7, 7, u8);
//uint!(U8, 8, u8);
uint!(U9, 9, u16);
uint!(U10, 10, u16);
uint!(U11, 11, u16);
uint!(U12, 12, u16);
uint!(U13, 13, u16);
uint!(U14, 14, u16);
uint!(U15, 15, u16);
//uint!(U16, 16, u16);
uint!(U17, 17, u32);
uint!(U18, 18, u32);
uint!(U19, 19, u32);
uint!(U20, 20, u32);
uint!(U21, 21, u32);
uint!(U22, 22, u32);
uint!(U23, 23, u32);
uint!(U24, 24, u32);
uint!(U25, 25, u32);
uint!(U26, 26, u32);
uint!(U27, 27, u32);
uint!(U28, 28, u32);
uint!(U29, 29, u32);
uint!(U30, 30, u32);
uint!(U31, 31, u32);
//uint!(U32, 32, u32);
uint!(U33, 33, u64);
uint!(U34, 34, u64);
uint!(U35, 35, u64);
uint!(U36, 36, u64);
uint!(U37, 37, u64);
uint!(U38, 38, u64);
uint!(U39, 39, u64);
uint!(U40, 40, u64);
uint!(U41, 41, u64);
uint!(U42, 42, u64);
uint!(U43, 43, u64);
uint!(U44, 44, u64);
uint!(U45, 45, u64);
uint!(U46, 46, u64);
uint!(U47, 47, u64);
uint!(U48, 48, u64);
uint!(U49, 49, u64);
uint!(U50, 50, u64);
uint!(U51, 51, u64);
uint!(U52, 52, u64);
uint!(U53, 53, u64);
uint!(U54, 54, u64);
uint!(U55, 55, u64);
uint!(U56, 56, u64);
uint!(U57, 57, u64);
uint!(U58, 58, u64);
uint!(U59, 59, u64);
uint!(U60, 60, u64);
uint!(U61, 61, u64);
uint!(U62, 62, u64);
uint!(U63, 63, u64);
//uint!(U64, 64, u64);

#[cfg(feature = "u128")]
mod u128_extra {
    use super::*;

    uint!(U65, 65, u128);
    uint!(U66, 66, u128);
    uint!(U67, 67, u128);
    uint!(U68, 68, u128);
    uint!(U69, 69, u128);
    uint!(U70, 70, u128);
    uint!(U71, 71, u128);
    uint!(U72, 72, u128);
    uint!(U73, 73, u128);
    uint!(U74, 74, u128);
    uint!(U75, 75, u128);
    uint!(U76, 76, u128);
    uint!(U77, 77, u128);
    uint!(U78, 78, u128);
    uint!(U79, 79, u128);
    uint!(U80, 80, u128);
    uint!(U81, 81, u128);
    uint!(U82, 82, u128);
    uint!(U83, 83, u128);
    uint!(U84, 84, u128);
    uint!(U85, 85, u128);
    uint!(U86, 86, u128);
    uint!(U87, 87, u128);
    uint!(U88, 88, u128);
    uint!(U89, 89, u128);
    uint!(U90, 90, u128);
    uint!(U91, 91, u128);
    uint!(U92, 92, u128);
    uint!(U93, 93, u128);
    uint!(U94, 94, u128);
    uint!(U95, 95, u128);
    uint!(U96, 96, u128);
    uint!(U97, 97, u128);
    uint!(U98, 98, u128);
    uint!(U99, 99, u128);
    uint!(U100, 100, u128);
    uint!(U101, 101, u128);
    uint!(U102, 102, u128);
    uint!(U103, 103, u128);
    uint!(U104, 104, u128);
    uint!(U105, 105, u128);
    uint!(U106, 106, u128);
    uint!(U107, 107, u128);
    uint!(U108, 108, u128);
    uint!(U109, 109, u128);
    uint!(U110, 110, u128);
    uint!(U111, 111, u128);
    uint!(U112, 112, u128);
    uint!(U113, 113, u128);
    uint!(U114, 114, u128);
    uint!(U115, 115, u128);
    uint!(U116, 116, u128);
    uint!(U117, 117, u128);
    uint!(U118, 118, u128);
    uint!(U119, 119, u128);
    uint!(U120, 120, u128);
    uint!(U121, 121, u128);
    uint!(U122, 122, u128);
    uint!(U123, 123, u128);
    uint!(U124, 124, u128);
    uint!(U125, 125, u128);
    uint!(U126, 126, u128);
    uint!(U127, 127, u128);
    //uint!(U128, 128, u128);
}

#[cfg(feature = "u128")]
pub use u128_extra::*;

#[cfg(feature = "u128")]
from_impl!(
    { u128 },
    U127,
    U126,
    U125,
    U124,
    U123,
    U122,
    U121,
    U120,
    U119,
    U118,
    U117,
    U116,
    U115,
    U114,
    U113,
    U112,
    U111,
    U110,
    U109,
    U108,
    U107,
    U106,
    U105,
    U104,
    U103,
    U102,
    U101,
    U100,
    U99,
    U98,
    U97,
    U96,
    U95,
    U94,
    U93,
    U92,
    U91,
    U90,
    U89,
    U88,
    U87,
    U86,
    U85,
    U84,
    U83,
    U82,
    U81,
    U80,
    U79,
    U78,
    U77,
    U76,
    U75,
    U74,
    U73,
    U72,
    U71,
    U70,
    U69,
    U68,
    U67,
    U66,
    U65,
    { u64 },
    U63,
    U62,
    U61,
    U60,
    U59,
    U58,
    U57,
    U56,
    U55,
    U54,
    U53,
    U52,
    U51,
    U50,
    U49,
    U48,
    U47,
    U46,
    U45,
    U44,
    U43,
    U42,
    U41,
    U40,
    U39,
    U38,
    U37,
    U36,
    U35,
    U34,
    U33,
    { u32 },
    U31,
    U30,
    U29,
    U28,
    U27,
    U26,
    U25,
    U24,
    U23,
    U22,
    U21,
    U20,
    U19,
    U18,
    U17,
    { u16 },
    U15,
    U14,
    U13,
    U12,
    U11,
    U10,
    U9,
    { u8 },
    U7,
    U6,
    U5,
    U4,
    U3,
    U2,
    U1
);

#[cfg(not(feature = "u128"))]
from_impl!(
    { u64 },
    U63,
    U62,
    U61,
    U60,
    U59,
    U58,
    U57,
    U56,
    U55,
    U54,
    U53,
    U52,
    U51,
    U50,
    U49,
    U48,
    U47,
    U46,
    U45,
    U44,
    U43,
    U42,
    U41,
    U40,
    U39,
    U38,
    U37,
    U36,
    U35,
    U34,
    U33,
    { u32 },
    U31,
    U30,
    U29,
    U28,
    U27,
    U26,
    U25,
    U24,
    U23,
    U22,
    U21,
    U20,
    U19,
    U18,
    U17,
    { u16 },
    U15,
    U14,
    U13,
    U12,
    U11,
    U10,
    U9,
    { u8 },
    U7,
    U6,
    U5,
    U4,
    U3,
    U2,
    U1
);

impl From<U1> for bool {
    fn from(val: U1) -> bool {
        val.0 != 0
    }
}

trait RawValue {
    type Raw;

    fn from_raw(raw: Self::Raw) -> Self;
    fn into_raw(self) -> Self::Raw;
}

macro_rules! prim_raw_value_impl {
    ($t:ty) => {
        impl RawValue for $t {
            type Raw = Self;

            fn from_raw(raw: Self::Raw) -> Self {
                raw
            }

            fn into_raw(self) -> Self::Raw {
                self
            }
        }
    };
}

prim_raw_value_impl!(u8);
prim_raw_value_impl!(u16);
prim_raw_value_impl!(u32);
prim_raw_value_impl!(u64);
prim_raw_value_impl!(u128);
prim_raw_value_impl!(usize);
prim_raw_value_impl!(i8);
prim_raw_value_impl!(i16);
prim_raw_value_impl!(i32);
prim_raw_value_impl!(i64);
prim_raw_value_impl!(i128);
prim_raw_value_impl!(isize);
