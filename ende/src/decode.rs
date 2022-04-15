use nom::number::streaming as num;
use nom::{error::ParseError, IResult};
use std::mem::MaybeUninit;

#[derive(Debug, PartialEq)]
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
        if buf.len() < std::mem::size_of::<T>() {
            return Err(nom::Err::Incomplete(nom::Needed::Size(
                std::num::NonZeroUsize::new_unchecked(std::mem::size_of::<T>() - buf.len()),
            )));
        }
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
                            if !cfg!(target_endian = "big") {
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
                            if !cfg!(target_endian = "little") {
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

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! incomplete {
        () => {
            nom::Err::Incomplete(nom::Needed::Unknown)
        };
        ($size:expr) => {
            nom::Err::Incomplete(nom::Needed::Size(
                std::num::NonZeroUsize::new($size).unwrap(),
            ))
        };
    }

    #[test]
    fn u8_decode() {
        let buf = &[1, 2, 3, 4][..];
        assert_eq!(u8::decode(buf), Ok((&[2, 3, 4][..], 1)));
        assert_eq!(u8::decode(&buf[1..]), Ok((&[3, 4][..], 2)));
        assert_eq!(u8::decode(&buf[2..]), Ok((&[4][..], 3)));
        assert_eq!(u8::decode(&buf[3..]), Ok((&[][..], 4)));
        assert_eq!(u8::decode(&buf[4..]), Err(incomplete!(1)));
    }

    #[test]
    fn u8_array_decode() {
        let buf = &[1, 2, 3, 4][..];
        assert_eq!(<[u8; 2]>::decode(buf), Ok((&[3, 4][..], [1, 2])));
        assert_eq!(<[u8; 2]>::decode(&buf[1..]), Ok((&[4][..], [2, 3])));
        assert_eq!(<[u8; 2]>::decode(&buf[2..]), Ok((&[][..], [3, 4])));
        assert_eq!(<[u8; 2]>::decode(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u8; 2]>::decode(&buf[4..]), Err(incomplete!(2)));
    }

    #[test]
    fn u16_decode_be() {
        let buf = &[1, 2, 3, 4][..];
        assert_eq!(u16::decode_be(buf), Ok((&[3, 4][..], 0x0102)));
        assert_eq!(u16::decode_be(&buf[1..]), Ok((&[4][..], 0x0203)));
        assert_eq!(u16::decode_be(&buf[2..]), Ok((&[][..], 0x0304)));
        assert_eq!(u16::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u16::decode_be(&buf[4..]), Err(incomplete!(2)));
    }

    #[test]
    fn u16_array_decode_be() {
        let buf = &[1, 2, 3, 4, 5, 6, 7, 8][..];
        assert_eq!(
            <[u16; 2]>::decode_be(buf),
            Ok((&[5, 6, 7, 8][..], [0x0102, 0x0304]))
        );
        assert_eq!(
            <[u16; 2]>::decode_be(&buf[1..]),
            Ok((&[6, 7, 8][..], [0x0203, 0x0405]))
        );
        assert_eq!(
            <[u16; 2]>::decode_be(&buf[2..]),
            Ok((&[7, 8][..], [0x0304, 0x0506]))
        );
        assert_eq!(
            <[u16; 2]>::decode_be(&buf[3..]),
            Ok((&[8][..], [0x0405, 0x0607]))
        );
        assert_eq!(
            <[u16; 2]>::decode_be(&buf[4..]),
            Ok((&[][..], [0x0506, 0x0708]))
        );
        assert_eq!(<[u16; 2]>::decode_be(&buf[5..]), Err(incomplete!(1)));
        assert_eq!(<[u16; 2]>::decode_be(&buf[6..]), Err(incomplete!(2)));
        assert_eq!(<[u16; 2]>::decode_be(&buf[7..]), Err(incomplete!(3)));
        assert_eq!(<[u16; 2]>::decode_be(&buf[8..]), Err(incomplete!(4)));
    }

    #[test]
    fn u16_decode_le() {
        let buf = &[1, 2, 3, 4][..];
        assert_eq!(u16::decode_le(buf), Ok((&[3, 4][..], 0x0201)));
        assert_eq!(u16::decode_le(&buf[1..]), Ok((&[4][..], 0x0302)));
        assert_eq!(u16::decode_le(&buf[2..]), Ok((&[][..], 0x0403)));
        assert_eq!(u16::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u16::decode_le(&buf[4..]), Err(incomplete!(2)));
    }

    #[test]
    fn u16_array_decode_le() {
        let buf = &[1, 2, 3, 4, 5, 6, 7, 8][..];
        assert_eq!(
            <[u16; 2]>::decode_le(buf),
            Ok((&[5, 6, 7, 8][..], [0x0201, 0x0403]))
        );
        assert_eq!(
            <[u16; 2]>::decode_le(&buf[1..]),
            Ok((&[6, 7, 8][..], [0x0302, 0x0504]))
        );
        assert_eq!(
            <[u16; 2]>::decode_le(&buf[2..]),
            Ok((&[7, 8][..], [0x0403, 0x0605]))
        );
        assert_eq!(
            <[u16; 2]>::decode_le(&buf[3..]),
            Ok((&[8][..], [0x0504, 0x0706]))
        );
        assert_eq!(
            <[u16; 2]>::decode_le(&buf[4..]),
            Ok((&[][..], [0x0605, 0x0807]))
        );
        assert_eq!(<[u16; 2]>::decode_le(&buf[5..]), Err(incomplete!(1)));
        assert_eq!(<[u16; 2]>::decode_le(&buf[6..]), Err(incomplete!(2)));
        assert_eq!(<[u16; 2]>::decode_le(&buf[7..]), Err(incomplete!(3)));
        assert_eq!(<[u16; 2]>::decode_le(&buf[8..]), Err(incomplete!(4)));
    }

    #[test]
    fn u32_decode_be() {
        let buf = &[1, 2, 3, 4, 5, 6][..];
        assert_eq!(u32::decode_be(buf), Ok((&[5, 6][..], 0x01020304)));
        assert_eq!(u32::decode_be(&buf[1..]), Ok((&[6][..], 0x02030405)));
        assert_eq!(u32::decode_be(&buf[2..]), Ok((&[][..], 0x03040506)));
        assert_eq!(u32::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u32::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(u32::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(u32::decode_be(&buf[6..]), Err(incomplete!(4)));
    }

    #[test]
    fn u32_array_decode_be() {
        let buf = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..];
        assert_eq!(
            <[u32; 2]>::decode_be(buf),
            Ok((&[9, 10][..], [0x01020304, 0x05060708]))
        );
        assert_eq!(
            <[u32; 2]>::decode_be(&buf[1..]),
            Ok((&[10][..], [0x02030405, 0x06070809]))
        );
        assert_eq!(
            <[u32; 2]>::decode_be(&buf[2..]),
            Ok((&[][..], [0x03040506, 0x0708090A]))
        );
        assert_eq!(<[u32; 2]>::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(<[u32; 2]>::decode_be(&buf[10..]), Err(incomplete!(8)));
    }

    #[test]
    fn u32_decode_le() {
        let buf = &[1, 2, 3, 4, 5, 6][..];
        assert_eq!(u32::decode_le(buf), Ok((&[5, 6][..], 0x04030201)));
        assert_eq!(u32::decode_le(&buf[1..]), Ok((&[6][..], 0x05040302)));
        assert_eq!(u32::decode_le(&buf[2..]), Ok((&[][..], 0x06050403)));
        assert_eq!(u32::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u32::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(u32::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(u32::decode_le(&buf[6..]), Err(incomplete!(4)));
    }

    #[test]
    fn u32_array_decode_le() {
        let buf = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..];
        assert_eq!(
            <[u32; 2]>::decode_le(buf),
            Ok((&[9, 10][..], [0x04030201, 0x08070605]))
        );
        assert_eq!(
            <[u32; 2]>::decode_le(&buf[1..]),
            Ok((&[10][..], [0x05040302, 0x09080706]))
        );
        assert_eq!(
            <[u32; 2]>::decode_le(&buf[2..]),
            Ok((&[][..], [0x06050403, 0x0A090807]))
        );
        assert_eq!(<[u32; 2]>::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(<[u32; 2]>::decode_le(&buf[10..]), Err(incomplete!(8)));
    }

    #[test]
    fn u64_decode_be() {
        let buf = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..];
        assert_eq!(u64::decode_be(buf), Ok((&[9, 10][..], 0x0102030405060708)));
        assert_eq!(
            u64::decode_be(&buf[1..]),
            Ok((&[10][..], 0x0203040506070809))
        );
        assert_eq!(u64::decode_be(&buf[2..]), Ok((&[][..], 0x030405060708090A)));
        assert_eq!(u64::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u64::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(u64::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(u64::decode_be(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(u64::decode_be(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(u64::decode_be(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(u64::decode_be(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(u64::decode_be(&buf[10..]), Err(incomplete!(8)));
    }

    #[test]
    fn u64_array_decode_be() {
        let buf = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ][..];
        assert_eq!(
            <[u64; 2]>::decode_be(buf),
            Ok((&[17, 18][..], [0x0102030405060708, 0x090A0B0C0D0E0F10]))
        );
        assert_eq!(
            <[u64; 2]>::decode_be(&buf[1..]),
            Ok((&[18][..], [0x0203040506070809, 0x0A0B0C0D0E0F1011]))
        );
        assert_eq!(
            <[u64; 2]>::decode_be(&buf[2..]),
            Ok((&[][..], [0x030405060708090A, 0x0B0C0D0E0F101112]))
        );
        assert_eq!(<[u64; 2]>::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[10..]), Err(incomplete!(8)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[11..]), Err(incomplete!(9)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[12..]), Err(incomplete!(10)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[13..]), Err(incomplete!(11)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[14..]), Err(incomplete!(12)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[15..]), Err(incomplete!(13)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[16..]), Err(incomplete!(14)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[17..]), Err(incomplete!(15)));
        assert_eq!(<[u64; 2]>::decode_be(&buf[18..]), Err(incomplete!(16)));
    }

    #[test]
    fn u64_decode_le() {
        let buf = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..];
        assert_eq!(u64::decode_le(buf), Ok((&[9, 10][..], 0x0807060504030201)));
        assert_eq!(
            u64::decode_le(&buf[1..]),
            Ok((&[10][..], 0x0908070605040302))
        );
        assert_eq!(u64::decode_le(&buf[2..]), Ok((&[][..], 0x0A09080706050403)));
        assert_eq!(u64::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u64::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(u64::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(u64::decode_le(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(u64::decode_le(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(u64::decode_le(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(u64::decode_le(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(u64::decode_le(&buf[10..]), Err(incomplete!(8)));
    }

    #[test]
    fn u64_array_decode_le() {
        let buf = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ][..];
        assert_eq!(
            <[u64; 2]>::decode_le(buf),
            Ok((&[17, 18][..], [0x0807060504030201, 0x100F0E0D0C0B0A09]))
        );
        assert_eq!(
            <[u64; 2]>::decode_le(&buf[1..]),
            Ok((&[18][..], [0x0908070605040302, 0x11100F0E0D0C0B0A]))
        );
        assert_eq!(
            <[u64; 2]>::decode_le(&buf[2..]),
            Ok((&[][..], [0x0A09080706050403, 0x1211100F0E0D0C0B]))
        );
        assert_eq!(<[u64; 2]>::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[10..]), Err(incomplete!(8)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[11..]), Err(incomplete!(9)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[12..]), Err(incomplete!(10)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[13..]), Err(incomplete!(11)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[14..]), Err(incomplete!(12)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[15..]), Err(incomplete!(13)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[16..]), Err(incomplete!(14)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[17..]), Err(incomplete!(15)));
        assert_eq!(<[u64; 2]>::decode_le(&buf[18..]), Err(incomplete!(16)));
    }

    #[test]
    fn u128_decode_be() {
        let buf = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ][..];
        assert_eq!(
            u128::decode_be(buf),
            Ok((&[17, 18][..], 0x0102030405060708090A0B0C0D0E0F10))
        );
        assert_eq!(
            u128::decode_be(&buf[1..]),
            Ok((&[18][..], 0x02030405060708090A0B0C0D0E0F1011))
        );
        assert_eq!(
            u128::decode_be(&buf[2..]),
            Ok((&[][..], 0x030405060708090A0B0C0D0E0F101112))
        );
        assert_eq!(u128::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u128::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(u128::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(u128::decode_be(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(u128::decode_be(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(u128::decode_be(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(u128::decode_be(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(u128::decode_be(&buf[10..]), Err(incomplete!(8)));
        assert_eq!(u128::decode_be(&buf[11..]), Err(incomplete!(9)));
        assert_eq!(u128::decode_be(&buf[12..]), Err(incomplete!(10)));
        assert_eq!(u128::decode_be(&buf[13..]), Err(incomplete!(11)));
        assert_eq!(u128::decode_be(&buf[14..]), Err(incomplete!(12)));
        assert_eq!(u128::decode_be(&buf[15..]), Err(incomplete!(13)));
        assert_eq!(u128::decode_be(&buf[16..]), Err(incomplete!(14)));
        assert_eq!(u128::decode_be(&buf[17..]), Err(incomplete!(15)));
        assert_eq!(u128::decode_be(&buf[18..]), Err(incomplete!(16)));
    }

    #[test]
    fn u128_array_decode_be() {
        let buf = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        ][..];
        assert_eq!(
            <[u128; 2]>::decode_be(buf),
            Ok((
                &[33, 34][..],
                [
                    0x0102030405060708090A0B0C0D0E0F10,
                    0x1112131415161718191A1B1C1D1E1F20
                ]
            ))
        );
        assert_eq!(
            <[u128; 2]>::decode_be(&buf[1..]),
            Ok((
                &[34][..],
                [
                    0x02030405060708090A0B0C0D0E0F1011,
                    0x12131415161718191A1B1C1D1E1F2021
                ]
            ))
        );
        assert_eq!(
            <[u128; 2]>::decode_be(&buf[2..]),
            Ok((
                &[][..],
                [
                    0x030405060708090A0B0C0D0E0F101112,
                    0x131415161718191A1B1C1D1E1F202122
                ]
            ))
        );
        assert_eq!(<[u128; 2]>::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[10..]), Err(incomplete!(8)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[11..]), Err(incomplete!(9)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[12..]), Err(incomplete!(10)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[13..]), Err(incomplete!(11)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[14..]), Err(incomplete!(12)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[15..]), Err(incomplete!(13)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[16..]), Err(incomplete!(14)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[17..]), Err(incomplete!(15)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[18..]), Err(incomplete!(16)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[19..]), Err(incomplete!(17)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[20..]), Err(incomplete!(18)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[21..]), Err(incomplete!(19)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[22..]), Err(incomplete!(20)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[23..]), Err(incomplete!(21)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[24..]), Err(incomplete!(22)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[25..]), Err(incomplete!(23)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[26..]), Err(incomplete!(24)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[27..]), Err(incomplete!(25)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[28..]), Err(incomplete!(26)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[29..]), Err(incomplete!(27)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[30..]), Err(incomplete!(28)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[31..]), Err(incomplete!(29)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[32..]), Err(incomplete!(30)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[33..]), Err(incomplete!(31)));
        assert_eq!(<[u128; 2]>::decode_be(&buf[34..]), Err(incomplete!(32)));
    }

    #[test]
    fn u128_decode_le() {
        let buf = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ][..];
        assert_eq!(
            u128::decode_le(buf),
            Ok((&[17, 18][..], 0x100F0E0D0C0B0A090807060504030201))
        );
        assert_eq!(
            u128::decode_le(&buf[1..]),
            Ok((&[18][..], 0x11100F0E0D0C0B0A0908070605040302))
        );
        assert_eq!(
            u128::decode_le(&buf[2..]),
            Ok((&[][..], 0x1211100F0E0D0C0B0A09080706050403))
        );
        assert_eq!(u128::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(u128::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(u128::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(u128::decode_le(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(u128::decode_le(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(u128::decode_le(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(u128::decode_le(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(u128::decode_le(&buf[10..]), Err(incomplete!(8)));
        assert_eq!(u128::decode_le(&buf[11..]), Err(incomplete!(9)));
        assert_eq!(u128::decode_le(&buf[12..]), Err(incomplete!(10)));
        assert_eq!(u128::decode_le(&buf[13..]), Err(incomplete!(11)));
        assert_eq!(u128::decode_le(&buf[14..]), Err(incomplete!(12)));
        assert_eq!(u128::decode_le(&buf[15..]), Err(incomplete!(13)));
        assert_eq!(u128::decode_le(&buf[16..]), Err(incomplete!(14)));
        assert_eq!(u128::decode_le(&buf[17..]), Err(incomplete!(15)));
        assert_eq!(u128::decode_le(&buf[18..]), Err(incomplete!(16)));
    }

    #[test]
    fn u128_array_decode_le() {
        let buf = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        ][..];
        assert_eq!(
            <[u128; 2]>::decode_le(buf),
            Ok((
                &[33, 34][..],
                [
                    0x100F0E0D0C0B0A090807060504030201,
                    0x201F1E1D1C1B1A191817161514131211
                ]
            ))
        );
        assert_eq!(
            <[u128; 2]>::decode_le(&buf[1..]),
            Ok((
                &[34][..],
                [
                    0x11100F0E0D0C0B0A0908070605040302,
                    0x21201F1E1D1C1B1A1918171615141312
                ]
            ))
        );
        assert_eq!(
            <[u128; 2]>::decode_le(&buf[2..]),
            Ok((
                &[][..],
                [
                    0x1211100F0E0D0C0B0A09080706050403,
                    0x2221201F1E1D1C1B1A19181716151413
                ]
            ))
        );
        assert_eq!(<[u128; 2]>::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[6..]), Err(incomplete!(4)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[7..]), Err(incomplete!(5)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[8..]), Err(incomplete!(6)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[9..]), Err(incomplete!(7)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[10..]), Err(incomplete!(8)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[11..]), Err(incomplete!(9)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[12..]), Err(incomplete!(10)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[13..]), Err(incomplete!(11)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[14..]), Err(incomplete!(12)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[15..]), Err(incomplete!(13)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[16..]), Err(incomplete!(14)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[17..]), Err(incomplete!(15)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[18..]), Err(incomplete!(16)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[19..]), Err(incomplete!(17)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[20..]), Err(incomplete!(18)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[21..]), Err(incomplete!(19)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[22..]), Err(incomplete!(20)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[23..]), Err(incomplete!(21)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[24..]), Err(incomplete!(22)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[25..]), Err(incomplete!(23)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[26..]), Err(incomplete!(24)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[27..]), Err(incomplete!(25)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[28..]), Err(incomplete!(26)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[29..]), Err(incomplete!(27)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[30..]), Err(incomplete!(28)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[31..]), Err(incomplete!(29)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[32..]), Err(incomplete!(30)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[33..]), Err(incomplete!(31)));
        assert_eq!(<[u128; 2]>::decode_le(&buf[34..]), Err(incomplete!(32)));
    }

    #[test]
    fn i8_decode() {
        let buf = &[1, 2, 0xFF, 0x80][..];
        assert_eq!(i8::decode(buf), Ok((&[2, 0xFF, 0x80][..], 1)));
        assert_eq!(i8::decode(&buf[1..]), Ok((&[0xFF, 0x80][..], 2)));
        assert_eq!(i8::decode(&buf[2..]), Ok((&[0x80][..], -1)));
        assert_eq!(i8::decode(&buf[3..]), Ok((&[][..], -128)));
        assert_eq!(i8::decode(&buf[4..]), Err(incomplete!(1)));
    }

    #[test]
    fn i8_array_decode() {
        let buf = &[1, 2, 0xFF, 0x80][..];
        assert_eq!(<[i8; 2]>::decode(buf), Ok((&[0xFF, 0x80][..], [1, 2])));
        assert_eq!(<[i8; 2]>::decode(&buf[1..]), Ok((&[0x80][..], [2, -1])));
        assert_eq!(<[i8; 2]>::decode(&buf[2..]), Ok((&[][..], [-1, -128])));
        assert_eq!(<[i8; 2]>::decode(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[i8; 2]>::decode(&buf[4..]), Err(incomplete!(2)));
    }

    #[test]
    fn i16_decode_be() {
        let buf = &[1, 2, 0xFF, 0][..];
        assert_eq!(i16::decode_be(buf), Ok((&[0xFF, 0][..], 0x0102)));
        assert_eq!(i16::decode_be(&buf[1..]), Ok((&[0][..], 0x02FF)));
        assert_eq!(i16::decode_be(&buf[2..]), Ok((&[][..], -256)));
        assert_eq!(i16::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(i16::decode_be(&buf[4..]), Err(incomplete!(2)));
    }

    #[test]
    fn i16_array_decode_be() {
        let buf = &[1, 2, 0xFF, 0, 0x80, 1][..];
        assert_eq!(
            <[i16; 2]>::decode_be(buf),
            Ok((&[0x80, 1][..], [0x0102, -256]))
        );
        assert_eq!(
            <[i16; 2]>::decode_be(&buf[1..]),
            Ok((&[1][..], [0x02FF, 0x80]))
        );
        assert_eq!(
            <[i16; 2]>::decode_be(&buf[2..]),
            Ok((&[][..], [-256, -32767]))
        );
        assert_eq!(<[i16; 2]>::decode_be(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[i16; 2]>::decode_be(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[i16; 2]>::decode_be(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[i16; 2]>::decode_be(&buf[6..]), Err(incomplete!(4)));
    }

    #[test]
    fn i16_decode_le() {
        let buf = &[1, 2, 0, 0xFF][..];
        assert_eq!(i16::decode_le(buf), Ok((&[0, 0xFF][..], 0x0201)));
        assert_eq!(i16::decode_le(&buf[1..]), Ok((&[0xFF][..], 2)));
        assert_eq!(i16::decode_le(&buf[2..]), Ok((&[][..], -256)));
        assert_eq!(i16::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(i16::decode_le(&buf[4..]), Err(incomplete!(2)));
    }

    #[test]
    fn i16_array_decode_le() {
        let buf = &[1, 2, 0, 0xFF, 1, 0x80][..];
        assert_eq!(
            <[i16; 2]>::decode_le(buf),
            Ok((&[1, 0x80][..], [0x0201, -256]))
        );
        assert_eq!(
            <[i16; 2]>::decode_le(&buf[1..]),
            Ok((&[0x80][..], [2, 0x1FF]))
        );
        assert_eq!(
            <[i16; 2]>::decode_le(&buf[2..]),
            Ok((&[][..], [-256, -32767]))
        );
        assert_eq!(<[i16; 2]>::decode_le(&buf[3..]), Err(incomplete!(1)));
        assert_eq!(<[i16; 2]>::decode_le(&buf[4..]), Err(incomplete!(2)));
        assert_eq!(<[i16; 2]>::decode_le(&buf[5..]), Err(incomplete!(3)));
        assert_eq!(<[i16; 2]>::decode_le(&buf[6..]), Err(incomplete!(4)));
    }
}
