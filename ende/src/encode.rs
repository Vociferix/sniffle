use std::io::{Result, Write};

pub trait Encoder<'a>: Write + 'a {
    fn encode<E: BasicEncode + ?Sized>(&mut self, data: &E) -> Result<&mut Self> {
        data.encode_one(self)?;
        Ok(self)
    }

    fn encode_be<E: BasicEncodeBe + ?Sized>(&mut self, data: &E) -> Result<&mut Self> {
        data.encode_one_be(self)?;
        Ok(self)
    }

    fn encode_le<E: BasicEncodeLe + ?Sized>(&mut self, data: &E) -> Result<&mut Self> {
        data.encode_one_le(self)?;
        Ok(self)
    }

    fn as_dyn_mut(&mut self) -> &mut DynEncoder<'a>;
}

pub type DynEncoder<'a> = dyn Write + 'a;

pub trait Encode: Sized {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()>;

    fn encode_many<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        for elem in slice.iter() {
            elem.encode(encoder)?;
        }
        Ok(())
    }
}

pub trait EncodeBe: Sized {
    fn encode_be<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()>;

    fn encode_many_be<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        for elem in slice.iter() {
            elem.encode_be(encoder)?;
        }
        Ok(())
    }
}

pub trait EncodeLe: Sized {
    fn encode_le<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()>;

    fn encode_many_le<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        for elem in slice.iter() {
            elem.encode_le(encoder)?;
        }
        Ok(())
    }
}

pub trait BasicEncode {
    fn encode_one<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()>;
}

pub trait BasicEncodeBe {
    fn encode_one_be<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()>;
}

pub trait BasicEncodeLe {
    fn encode_one_le<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()>;
}

pub trait SliceEncode: Sized {
    fn encode_slice<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()>;
}

pub trait SliceEncodeBe: Sized {
    fn encode_slice_be<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()>;
}

pub trait SliceEncodeLe: Sized {
    fn encode_slice_le<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()>;
}

impl<'a, W: Write + Sized + 'a> Encoder<'a> for W {
    fn as_dyn_mut(&mut self) -> &mut DynEncoder<'a> {
        self
    }
}

impl<'a> Encoder<'a> for DynEncoder<'a> {
    fn as_dyn_mut(&mut self) -> &mut DynEncoder<'a> {
        self
    }
}

impl<E: Encode> BasicEncode for E {
    fn encode_one<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        self.encode(encoder)
    }
}

impl<E: EncodeBe> BasicEncodeBe for E {
    fn encode_one_be<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        self.encode_be(encoder)
    }
}

impl<E: EncodeLe> BasicEncodeLe for E {
    fn encode_one_le<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        self.encode_le(encoder)
    }
}

impl<E: Encode> SliceEncode for E {
    fn encode_slice<'a, W: Encoder<'a> + ?Sized>(slice: &[E], encoder: &mut W) -> Result<()> {
        Self::encode_many(slice, encoder)
    }
}

impl<E: EncodeBe> SliceEncodeBe for E {
    fn encode_slice_be<'a, W: Encoder<'a> + ?Sized>(slice: &[E], encoder: &mut W) -> Result<()> {
        Self::encode_many_be(slice, encoder)
    }
}

impl<E: EncodeLe> SliceEncodeLe for E {
    fn encode_slice_le<'a, W: Encoder<'a> + ?Sized>(slice: &[E], encoder: &mut W) -> Result<()> {
        Self::encode_many_le(slice, encoder)
    }
}

impl<E: SliceEncode> BasicEncode for [E] {
    fn encode_one<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        E::encode_slice(self, encoder)
    }
}

impl<E: SliceEncodeBe> BasicEncodeBe for [E] {
    fn encode_one_be<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        E::encode_slice_be(self, encoder)
    }
}

impl<E: SliceEncodeLe> BasicEncodeLe for [E] {
    fn encode_one_le<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        E::encode_slice_le(self, encoder)
    }
}

impl Encode for u8 {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        encoder.write_all(&[*self])
    }

    fn encode_many<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        encoder.write_all(slice)
    }
}

impl Encode for i8 {
    fn encode<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
        encoder.write_all(&self.to_ne_bytes())
    }

    fn encode_many<'a, W: Encoder<'a> + ?Sized>(slice: &[Self], encoder: &mut W) -> Result<()> {
        unsafe { encoder.write_all(std::mem::transmute(slice)) }
    }
}

macro_rules! make_encode {
    ($t:ty) => {
        impl EncodeBe for $t {
            fn encode_be<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
                encoder.write_all(&self.to_be_bytes()[..])
            }

            fn encode_many_be<'a, W: Encoder<'a> + ?Sized>(
                slice: &[Self],
                encoder: &mut W,
            ) -> Result<()> {
                if cfg!(target_endian = "big") {
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

        impl EncodeLe for $t {
            fn encode_le<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> Result<()> {
                encoder.write_all(&self.to_le_bytes()[..])
            }

            fn encode_many_le<'a, W: Encoder<'a> + ?Sized>(
                slice: &[Self],
                encoder: &mut W,
            ) -> Result<()> {
                if cfg!(target_endian = "little") {
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
