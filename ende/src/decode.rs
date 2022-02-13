use super::*;
use nom::combinator::map;
use nom::{error::ParseError, IResult};

#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError<'a> {
    Nom(nom::error::Error<&'a [u8]>),
    NotSupported,
    Malformed,
}

pub trait Decode: Sized {
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>>;

    fn decode_many<const LEN: usize>(
        mut buf: &[u8],
    ) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe {
            let mut ret: [Self; LEN] = std::mem::MaybeUninit::uninit().assume_init();
            for (i, elem) in ret.iter_mut().enumerate() {
                let (rem, val) = match Self::decode(buf) {
                    Ok(res) => res,
                    Err(e) => {
                        for idx in 0..i {
                            drop(std::mem::replace(
                                &mut ret[idx],
                                std::mem::MaybeUninit::uninit().assume_init(),
                            ));
                        }
                        std::mem::forget(ret);
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
                *elem = val;
            }
            Ok((buf, ret))
        }
    }
}

pub trait DecodeBE: Sized {
    fn decode_be(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>>;

    fn decode_many_be<const LEN: usize>(
        mut buf: &[u8],
    ) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe {
            let mut ret: [Self; LEN] = std::mem::MaybeUninit::uninit().assume_init();
            for (i, elem) in ret.iter_mut().enumerate() {
                let (rem, val) = match Self::decode_be(buf) {
                    Ok(res) => res,
                    Err(e) => {
                        for idx in 0..i {
                            drop(std::mem::replace(
                                &mut ret[idx],
                                std::mem::MaybeUninit::uninit().assume_init(),
                            ));
                        }
                        std::mem::forget(ret);
                        return Err(e);
                    }
                };
                buf = rem;
                *elem = val;
            }
            Ok((buf, ret))
        }
    }
}

pub trait DecodeLE: Sized {
    fn decode_le(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>>;

    fn decode_many_le<const LEN: usize>(
        mut buf: &[u8],
    ) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe {
            let mut ret: [Self; LEN] = std::mem::MaybeUninit::uninit().assume_init();
            for (i, elem) in ret.iter_mut().enumerate() {
                let (rem, val) = match Self::decode_le(buf) {
                    Ok(res) => res,
                    Err(e) => {
                        for idx in 0..i {
                            drop(std::mem::replace(
                                &mut ret[idx],
                                std::mem::MaybeUninit::uninit().assume_init(),
                            ));
                        }
                        std::mem::forget(ret);
                        return Err(e);
                    }
                };
                buf = rem;
                *elem = val;
            }
            Ok((buf, ret))
        }
    }
}

pub fn decode<D: Decode>(buf: &[u8]) -> IResult<&[u8], D, DecodeError<'_>> {
    D::decode(buf)
}

pub fn decode_be<D: DecodeBE>(buf: &[u8]) -> IResult<&[u8], D, DecodeError<'_>> {
    D::decode_be(buf)
}

pub fn decode_le<D: DecodeLE>(buf: &[u8]) -> IResult<&[u8], D, DecodeError<'_>> {
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
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        D::decode_many(buf)
    }
}

impl<D: DecodeBE, const LEN: usize> DecodeBE for [D; LEN] {
    fn decode_be(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        D::decode_many_be(buf)
    }
}

impl<D: DecodeLE, const LEN: usize> DecodeLE for [D; LEN] {
    fn decode_le(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        D::decode_many_le(buf)
    }
}

pub unsafe fn cast<T>(buf: &[u8]) -> IResult<&[u8], T, DecodeError<'_>> {
    let mut ret: T = std::mem::MaybeUninit::uninit().assume_init();

    if std::mem::size_of::<T>() != 0 {
        let mut buf: &[u8] = &buf[..std::mem::size_of::<T>()];
        if let Err(_) = std::io::copy(
            &mut buf,
            &mut (std::slice::from_raw_parts_mut(
                &mut ret as *mut T as *mut u8,
                std::mem::size_of::<T>(),
            )),
        ) {
            return Err(nom::Err::Incomplete(nom::Needed::Size(
                std::num::NonZeroUsize::new_unchecked(std::mem::size_of::<T>()),
            )));
        };
    }
    Ok((&buf[std::mem::size_of::<T>()..], ret))
}

impl Decode for u8 {
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        if buf.len() == 0 {
            unsafe {
                Err(nom::Err::Incomplete(nom::Needed::Size(
                    std::num::NonZeroUsize::new_unchecked(1),
                )))
            }
        } else {
            Ok((&buf[1..], buf[0]))
        }
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe { cast(buf) }
    }
}

impl Decode for i8 {
    fn decode(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
        map(u8::decode, |val| i8::from_ne_bytes([val]))(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
        unsafe { cast(buf) }
    }
}

macro_rules! make_decode {
    ($t:ty) => {
        impl DecodeBE for $t {
            fn decode_be(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
                map(<[u8; std::mem::size_of::<Self>()]>::decode, |bytes| {
                    Self::from_be_bytes(bytes)
                })(buf)
            }

            fn decode_many_be<const LEN: usize>(
                buf: &[u8],
            ) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
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

        impl DecodeLE for $t {
            fn decode_le(buf: &[u8]) -> IResult<&[u8], Self, DecodeError<'_>> {
                map(<[u8; std::mem::size_of::<Self>()]>::decode, |bytes| {
                    Self::from_le_bytes(bytes)
                })(buf)
            }

            fn decode_many_le<const LEN: usize>(
                buf: &[u8],
            ) -> IResult<&[u8], [Self; LEN], DecodeError<'_>> {
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

make_decode!(u16);
make_decode!(u32);
make_decode!(u64);
make_decode!(u128);
make_decode!(i16);
make_decode!(i32);
make_decode!(i64);
make_decode!(i128);
make_decode!(f32);
make_decode!(f64);
