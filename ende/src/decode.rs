use super::*;
use nom::number::streaming as num;
use nom::{error::ParseError, IResult};
use std::mem::MaybeUninit;

#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError<'a> {
    Nom(nom::error::Error<&'a [u8]>),
    Malformed,
}

pub type DResult<'a, T> = IResult<&'a [u8], T, DecodeError<'a>>;

pub trait Decode: Sized {
    fn decode(buf: &[u8]) -> DResult<'_, Self>;

    fn decode_many<const LEN: usize>(mut buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe {
            let mut ret: [MaybeUninit<Self>; LEN] = MaybeUninit::uninit().assume_init();
            for (i, elem) in ret.iter_mut().enumerate() {
                let (rem, val) = match Self::decode(buf) {
                    Ok(res) => res,
                    Err(e) => {
                        return match e {
                            nom::Err::Incomplete(needed) => {
                                if i == LEN - 1 {
                                    Err(nom::Err::Incomplete(needed))
                                } else {
                                    Err(nom::Err::Incomplete(nom::Needed::Unknown))
                                }
                            }
                            _ => Err(e),
                        };
                    }
                };
                buf = rem;
                *elem = MaybeUninit::new(val);
            }
            Ok((buf, transmute(ret)))
        }
    }
}

pub trait DecodeBe: Sized {
    fn decode_be(buf: &[u8]) -> DResult<'_, Self>;

    fn decode_many_be<const LEN: usize>(mut buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe {
            let mut ret: [MaybeUninit<Self>; LEN] = MaybeUninit::uninit().assume_init();
            for (i, elem) in ret.iter_mut().enumerate() {
                let (rem, val) = match Self::decode_be(buf) {
                    Ok(res) => res,
                    Err(e) => {
                        return match e {
                            nom::Err::Incomplete(needed) => {
                                if i == LEN - 1 {
                                    Err(nom::Err::Incomplete(needed))
                                } else {
                                    Err(nom::Err::Incomplete(nom::Needed::Unknown))
                                }
                            }
                            _ => Err(e),
                        };
                    }
                };
                buf = rem;
                *elem = MaybeUninit::new(val);
            }
            Ok((buf, transmute(ret)))
        }
    }
}

pub trait DecodeLe: Sized {
    fn decode_le(buf: &[u8]) -> DResult<'_, Self>;

    fn decode_many_le<const LEN: usize>(mut buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe {
            let mut ret: [MaybeUninit<Self>; LEN] = MaybeUninit::uninit().assume_init();
            for (i, elem) in ret.iter_mut().enumerate() {
                let (rem, val) = match Self::decode_le(buf) {
                    Ok(res) => res,
                    Err(e) => {
                        return match e {
                            nom::Err::Incomplete(needed) => {
                                if i == LEN - 1 {
                                    Err(nom::Err::Incomplete(needed))
                                } else {
                                    Err(nom::Err::Incomplete(nom::Needed::Unknown))
                                }
                            }
                            _ => Err(e),
                        };
                    }
                };
                buf = rem;
                *elem = MaybeUninit::new(val);
            }
            Ok((buf, transmute(ret)))
        }
    }
}

pub fn decode<D: Decode>(buf: &[u8]) -> DResult<'_, D> {
    D::decode(buf)
}

pub fn decode_be<D: DecodeBe>(buf: &[u8]) -> DResult<'_, D> {
    D::decode_be(buf)
}

pub fn decode_le<D: DecodeLe>(buf: &[u8]) -> DResult<'_, D> {
    D::decode_le(buf)
}

impl<'a> ParseError<&'a [u8]> for DecodeError<'a> {
    fn from_error_kind(input: &'a [u8], kind: nom::error::ErrorKind) -> Self {
        Self::Nom(nom::error::Error::from_error_kind(input, kind))
    }

    fn append(_: &'a [u8], _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> From<nom::error::Error<&'a [u8]>> for DecodeError<'a> {
    fn from(e: nom::error::Error<&'a [u8]>) -> Self {
        Self::Nom(e)
    }
}

impl<D: Decode, const LEN: usize> Decode for [D; LEN] {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        D::decode_many(buf)
    }
}

impl<D: DecodeBe, const LEN: usize> DecodeBe for [D; LEN] {
    fn decode_be(buf: &[u8]) -> DResult<'_, Self> {
        D::decode_many_be(buf)
    }
}

impl<D: DecodeLe, const LEN: usize> DecodeLe for [D; LEN] {
    fn decode_le(buf: &[u8]) -> DResult<'_, Self> {
        D::decode_many_le(buf)
    }
}

/// Decodes a type, T, by directly filling the memory it occupies with
/// the bytes contained in the in the byte slice, up to the size of the
/// resulting type.
///
/// # Safety
/// Great care must be taken to ensure this function is safe to use on
/// any given type, T. In general, it is unsound to decode any arbitrary
/// type with this function, but the only necessary condition is that the
/// first `std::mem::size_of::<T>()` bytes (agnostic of alignment) are
/// guaranteed to constitute a valid instance of type T. Although it is
/// possible for this function to be sound in more exotic scenarios, most
/// uses of this function should be for built in types, such as integers
/// and floating point types (not references!), and arrays,
/// `repr(transparent)` types, and `repr(C)` types, consisting entirely
/// of built in types; in short, types with well defined layout and which
/// have no invalid representations.
pub unsafe fn cast<T>(buf: &[u8]) -> DResult<'_, T> {
    let mut ret: MaybeUninit<T> = MaybeUninit::uninit();

    if std::mem::size_of::<T>() != 0 {
        let mut buf: &[u8] = &buf[..std::mem::size_of::<T>()];
        if std::io::copy(
            &mut buf,
            &mut (std::slice::from_raw_parts_mut(
                std::ptr::addr_of_mut!(ret) as *mut u8,
                std::mem::size_of::<T>(),
            )),
        )
        .is_err()
        {
            return Err(nom::Err::Incomplete(nom::Needed::Size(
                std::num::NonZeroUsize::new_unchecked(std::mem::size_of::<T>()),
            )));
        };
    }
    Ok((&buf[std::mem::size_of::<T>()..], transmute(ret)))
}

impl Decode for u8 {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        num::u8(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

impl Decode for i8 {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        num::i8(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
        unsafe { cast(buf) }
    }
}

macro_rules! make_decode {
    ($t:ty, $be_func:ident, $le_func:ident) => {
        impl DecodeBe for $t {
            fn decode_be(buf: &[u8]) -> DResult<'_, Self> {
                num::$be_func(buf)
            }

            fn decode_many_be<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
                unsafe {
                    match cast::<[Self; LEN]>(buf) {
                        Ok((rem, mut ret)) => {
                            if !IS_BIG_ENDIAN {
                                for elem in ret.iter_mut() {
                                    *elem = Self::from_be_bytes(elem.to_ne_bytes());
                                }
                            }
                            Ok((rem, ret))
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }

        impl DecodeLe for $t {
            fn decode_le(buf: &[u8]) -> DResult<'_, Self> {
                num::$le_func(buf)
            }

            fn decode_many_le<const LEN: usize>(buf: &[u8]) -> DResult<'_, [Self; LEN]> {
                unsafe {
                    match cast::<[Self; LEN]>(buf) {
                        Ok((rem, mut ret)) => {
                            if !IS_LITTLE_ENDIAN {
                                for elem in ret.iter_mut() {
                                    *elem = Self::from_le_bytes(elem.to_ne_bytes());
                                }
                            }
                            Ok((rem, ret))
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
    };
}

unsafe fn transmute<T, U>(x: T) -> U {
    std::ptr::read(std::mem::transmute::<_, *const U>(std::ptr::addr_of!(x)))
}

make_decode!(u16, be_u16, le_u16);
make_decode!(u32, be_u32, le_u32);
make_decode!(u64, be_u64, le_u64);
make_decode!(u128, be_u128, le_u128);
make_decode!(i16, be_i16, le_i16);
make_decode!(i32, be_i32, le_i32);
make_decode!(i64, be_i64, le_i64);
make_decode!(i128, be_i128, le_i128);
make_decode!(f32, be_f32, le_f32);
make_decode!(f64, be_f64, le_f64);
