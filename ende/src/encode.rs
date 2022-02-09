use super::*;
use std::io::{Result, Write};

pub trait Encoder: Write + 'static {
    fn encode<E: BasicEncode + ?Sized>(&mut self, data: &E) -> Result<&mut Self> {
        data.encode_one(self)?;
        Ok(self)
    }

    fn encode_be<E: BasicEncodeBE + ?Sized>(&mut self, data: &E) -> Result<&mut Self> {
        data.encode_one_be(self)?;
        Ok(self)
    }

    fn encode_le<E: BasicEncodeLE + ?Sized>(&mut self, data: &E) -> Result<&mut Self> {
        data.encode_one_le(self)?;
        Ok(self)
    }

    fn as_dyn_mut(&mut self) -> &mut DynEncoder;
}

pub type DynEncoder = dyn Write + 'static;

pub trait Encode: Sized {
    fn encode<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()>;

    fn encode_many<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        for elem in slice.iter() {
            elem.encode(encoder)?;
        }
        Ok(())
    }
}

pub trait EncodeBE: Sized {
    fn encode_be<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()>;

    fn encode_many_be<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        for elem in slice.iter() {
            elem.encode_be(encoder)?;
        }
        Ok(())
    }
}

pub trait EncodeLE: Sized {
    fn encode_le<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()>;

    fn encode_many_le<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        for elem in slice.iter() {
            elem.encode_le(encoder)?;
        }
        Ok(())
    }
}

pub trait BasicEncode {
    fn encode_one<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()>;
}

pub trait BasicEncodeBE {
    fn encode_one_be<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()>;
}

pub trait BasicEncodeLE {
    fn encode_one_le<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()>;
}

pub trait SliceEncode: Sized {
    fn encode_slice<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()>;
}

pub trait SliceEncodeBE: Sized {
    fn encode_slice_be<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()>;
}

pub trait SliceEncodeLE: Sized {
    fn encode_slice_le<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()>;
}

impl<W: Write + Sized + 'static> Encoder for W {
    fn as_dyn_mut(&mut self) -> &mut DynEncoder {
        self
    }
}

impl Encoder for DynEncoder {
    fn as_dyn_mut(&mut self) -> &mut DynEncoder {
        self
    }
}

impl<E: Encode> BasicEncode for E {
    fn encode_one<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        self.encode(encoder)
    }
}

impl<E: EncodeBE> BasicEncodeBE for E {
    fn encode_one_be<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        self.encode_be(encoder)
    }
}

impl<E: EncodeLE> BasicEncodeLE for E {
    fn encode_one_le<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        self.encode_le(encoder)
    }
}

impl<E: Encode> SliceEncode for E {
    fn encode_slice<W: Encoder + ?Sized>(slice: &[E], encoder: &mut W) -> Result<()> {
        Self::encode_many(slice, encoder)
    }
}

impl<E: EncodeBE> SliceEncodeBE for E {
    fn encode_slice_be<W: Encoder + ?Sized>(slice: &[E], encoder: &mut W) -> Result<()> {
        Self::encode_many_be(slice, encoder)
    }
}

impl<E: EncodeLE> SliceEncodeLE for E {
    fn encode_slice_le<W: Encoder + ?Sized>(slice: &[E], encoder: &mut W) -> Result<()> {
        Self::encode_many_le(slice, encoder)
    }
}

impl<E: SliceEncode> BasicEncode for [E] {
    fn encode_one<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        E::encode_slice(self, encoder)
    }
}

impl<E: SliceEncodeBE> BasicEncodeBE for [E] {
    fn encode_one_be<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        E::encode_slice_be(self, encoder)
    }
}

impl<E: SliceEncodeLE> BasicEncodeLE for [E] {
    fn encode_one_le<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        E::encode_slice_le(self, encoder)
    }
}

impl Encode for u8 {
    fn encode<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        encoder.write_all(&[*self])
    }

    fn encode_many<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        encoder.write_all(slice)
    }
}

impl Encode for i8 {
    fn encode<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        encoder.write_all(&self.to_ne_bytes())
    }

    fn encode_many<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        unsafe { encoder.write_all(std::mem::transmute(slice)) }
    }
}

macro_rules! make_encode {
    ($t:ty) => {
        impl EncodeBE for $t {
            fn encode_be<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
                encoder.write_all(&self.to_be_bytes()[..])
            }

            fn encode_many_be<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
                if IS_BIG_ENDIAN {
                    unsafe {
                        encoder.write_all(std::slice::from_raw_parts(
                            slice.as_ptr() as *const u8,
                            slice.len() * std::mem::size_of::<Self>(),
                        ))
                    }
                } else {
                    for elem in slice.iter() {
                        encoder.write_all(&elem.to_be_bytes()[..])?;
                    }
                    Ok(())
                }
            }
        }

        impl EncodeLE for $t {
            fn encode_le<W: Encoder + ?Sized>(&self, encoder: &mut W) -> Result<()> {
                encoder.write_all(&self.to_le_bytes()[..])
            }

            fn encode_many_le<W: Encoder + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
                if IS_LITTLE_ENDIAN {
                    unsafe {
                        encoder.write_all(std::slice::from_raw_parts(
                            slice.as_ptr() as *const u8,
                            slice.len() * std::mem::size_of::<Self>(),
                        ))
                    }
                } else {
                    for elem in slice.iter() {
                        encoder.write_all(&elem.to_le_bytes()[..])?;
                    }
                    Ok(())
                }
            }
        }
    };
}

make_encode!(u16);
make_encode!(u32);
make_encode!(u64);
make_encode!(u128);
make_encode!(i16);
make_encode!(i32);
make_encode!(i64);
make_encode!(i128);
make_encode!(f32);
make_encode!(f64);
