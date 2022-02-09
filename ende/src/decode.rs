use super::*;
use nom::combinator::map;
use nom::IResult;
use std::convert::Infallible;

pub trait Decode: Sized {
    type Error: std::error::Error;

    fn decode(buf: &[u8]) -> IResult<&[u8], Self, Self::Error>;

    fn decode_many<const LEN: usize>(mut buf: &[u8]) -> IResult<&[u8], [Self; LEN], Self::Error> {
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
    type Error: std::error::Error;

    fn decode_be(buf: &[u8]) -> IResult<&[u8], Self, Self::Error>;

    fn decode_many_be<const LEN: usize>(
        mut buf: &[u8],
    ) -> IResult<&[u8], [Self; LEN], Self::Error> {
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
    type Error: std::error::Error;

    fn decode_le(buf: &[u8]) -> IResult<&[u8], Self, Self::Error>;

    fn decode_many_le<const LEN: usize>(
        mut buf: &[u8],
    ) -> IResult<&[u8], [Self; LEN], Self::Error> {
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

pub fn decode<D: Decode>(buf: &[u8]) -> IResult<&[u8], D, D::Error> {
    D::decode(buf)
}

pub fn decode_be<D: DecodeBE>(buf: &[u8]) -> IResult<&[u8], D, D::Error> {
    D::decode_be(buf)
}

pub fn decode_le<D: DecodeLE>(buf: &[u8]) -> IResult<&[u8], D, D::Error> {
    D::decode_le(buf)
}

impl<D: Decode, const LEN: usize> Decode for [D; LEN] {
    type Error = D::Error;

    fn decode(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
        D::decode_many(buf)
    }
}

impl<D: DecodeBE, const LEN: usize> DecodeBE for [D; LEN] {
    type Error = D::Error;

    fn decode_be(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
        D::decode_many_be(buf)
    }
}

impl<D: DecodeLE, const LEN: usize> DecodeLE for [D; LEN] {
    type Error = D::Error;

    fn decode_le(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
        D::decode_many_le(buf)
    }
}

pub unsafe fn cast<T>(mut buf: &[u8]) -> IResult<&[u8], T, Infallible> {
    let mut ret: T = std::mem::MaybeUninit::uninit().assume_init();
    if std::mem::size_of::<T>() != 0 {
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
    type Error = Infallible;

    fn decode(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
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

    fn decode_many<const LEN: usize>(buf: &[u8]) -> IResult<&[u8], [Self; LEN], Self::Error> {
        unsafe { cast(buf) }
    }
}

impl Decode for i8 {
    type Error = Infallible;

    fn decode(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
        map(u8::decode, |val| i8::from_ne_bytes([val]))(buf)
    }

    fn decode_many<const LEN: usize>(buf: &[u8]) -> IResult<&[u8], [Self; LEN], Self::Error> {
        unsafe { cast(buf) }
    }
}

macro_rules! make_decode {
    ($t:ty) => {
        impl DecodeBE for $t {
            type Error = Infallible;

            fn decode_be(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
                map(<[u8; std::mem::size_of::<Self>()]>::decode, |bytes| {
                    Self::from_be_bytes(bytes)
                })(buf)
            }

            fn decode_many_be<const LEN: usize>(
                buf: &[u8],
            ) -> IResult<&[u8], [Self; LEN], Self::Error> {
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
            type Error = Infallible;

            fn decode_le(buf: &[u8]) -> IResult<&[u8], Self, Self::Error> {
                map(<[u8; std::mem::size_of::<Self>()]>::decode, |bytes| {
                    Self::from_le_bytes(bytes)
                })(buf)
            }

            fn decode_many_le<const LEN: usize>(
                buf: &[u8],
            ) -> IResult<&[u8], [Self; LEN], Self::Error> {
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
