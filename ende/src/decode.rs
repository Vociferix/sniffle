use bytes::Buf;
use crate::BitPack;

use sniffle_uint::*;

pub use sniffle_ende_derive::Decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("Not enough data to decode")]
    NeedMore,
    #[error("Data is malformed")]
    Malformed,
}

pub type Result<T> = std::result::Result<T, DecodeError>;

pub trait DecodeBuf: Buf + Sized {
    fn skip(&mut self, num_bytes: usize) -> Result<()> {
        if num_bytes > self.remaining() {
            Err(DecodeError::NeedMore)
        } else {
            self.advance(num_bytes);
            Ok(())
        }
    }

    fn decode_to<D: Decode>(&mut self, item: &mut D) -> Result<()> {
        item.decode(self)
    }

    fn decode_be_to<D: DecodeBe>(&mut self, item: &mut D) -> Result<()> {
        item.decode_be(self)
    }

    fn decode_le_to<D: DecodeLe>(&mut self, item: &mut D) -> Result<()> {
        item.decode_le(self)
    }

    fn decode_with<D>(&mut self, mut init: D) -> Result<D>
    where
        D: Decode + Sized,
    {
        init.decode(self)?;
        Ok(init)
    }

    fn decode_be_with<D>(&mut self, mut init: D) -> Result<D>
    where
        D: DecodeBe + Sized,
    {
        init.decode_be(self)?;
        Ok(init)
    }

    fn decode_le_with<D>(&mut self, mut init: D) -> Result<D>
    where
        D: DecodeLe + Sized,
    {
        init.decode_le(self)?;
        Ok(init)
    }

    fn decode<D>(&mut self) -> Result<D>
    where
        D: Decode + Sized + Default,
    {
        self.decode_with(D::default())
    }

    fn decode_be<D>(&mut self) -> Result<D>
    where
        D: DecodeBe + Sized + Default,
    {
        self.decode_be_with(D::default())
    }

    fn decode_le<D>(&mut self) -> Result<D>
    where
        D: DecodeLe + Sized + Default,
    {
        self.decode_le_with(D::default())
    }
}

impl<B: Buf + Sized> DecodeBuf for B {}

pub trait Decode {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()>;

    fn decode_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()>
    where
        Self: Sized,
    {
        for item in slice.iter_mut() {
            item.decode(buf)?;
        }
        Ok(())
    }
}

pub trait DecodeBe {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()>;

    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()>
    where
        Self: Sized,
    {
        for item in slice.iter_mut() {
            item.decode_be(buf)?;
        }
        Ok(())
    }
}

pub trait DecodeLe {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()>;

    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()>
    where
        Self: Sized,
    {
        for item in slice.iter_mut() {
            item.decode_le(buf)?;
        }
        Ok(())
    }
}

impl<D: Decode + Sized> Decode for [D] {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        D::decode_slice(self, buf)
    }
}

impl<D: DecodeBe + Sized> DecodeBe for [D] {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        D::decode_be_slice(self, buf)
    }
}

impl<D: DecodeLe + Sized> DecodeLe for [D] {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        D::decode_le_slice(self, buf)
    }
}

impl<D: Decode + Sized, const LEN: usize> Decode for [D; LEN] {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        D::decode_slice(self, buf)
    }
}

impl<D: DecodeBe + Sized, const LEN: usize> DecodeBe for [D; LEN] {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        D::decode_be_slice(self, buf)
    }
}

impl<D: DecodeLe + Sized, const LEN: usize> DecodeLe for [D; LEN] {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        D::decode_le_slice(self, buf)
    }
}

impl Decode for () {
    fn decode<B: DecodeBuf>(&mut self, _buf: &mut B) -> Result<()> {
        Ok(())
    }

    fn decode_slice<B: DecodeBuf>(_slice: &mut [Self], _buf: &mut B) -> Result<()> {
        Ok(())
    }
}

impl Decode for u8 {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if !buf.has_remaining() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u8();
            Ok(())
        }
    }

    fn decode_slice<B: DecodeBuf>(slice: &mut [u8], buf: &mut B) -> Result<()> {
        if buf.remaining() < slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(slice);
            Ok(())
        }
    }
}

impl Decode for i8 {
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if !buf.has_remaining() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i8();
            Ok(())
        }
    }

    fn decode_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for u16 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u16();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for u16 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u16_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for i16 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i16();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for i16 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i16_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for u32 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u32();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for u32 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u32_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for i32 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i32();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for i32 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i32_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for u64 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u64();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for u64 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u64_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for i64 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i64();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for i64 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i64_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for u128 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u128();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for u128 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_u128_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for i128 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i128();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for i128 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_i128_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for f32 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_f32();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for f32 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_f32_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for f64 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_f64();
            Ok(())
        }
    }

    #[cfg(target_endian = "big")]
    fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeLe for f64 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() {
            Err(DecodeError::NeedMore)
        } else {
            *self = buf.get_f64_le();
            Ok(())
        }
    }

    #[cfg(target_endian = "little")]
    fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B) -> Result<()> {
        if buf.remaining() < std::mem::size_of::<Self>() * slice.len() {
            Err(DecodeError::NeedMore)
        } else {
            buf.copy_to_slice(bytemuck::cast_slice_mut(slice));
            Ok(())
        }
    }
}

impl DecodeBe for U24 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 3 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 4];
            buf.copy_to_slice(&mut tmp[1..]);
            *self = u32::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeLe for U24 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 3 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 4];
            buf.copy_to_slice(&mut tmp[1..]);
            *self = u32::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeBe for U40 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 5 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 8];
            buf.copy_to_slice(&mut tmp[3..]);
            *self = u64::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeLe for U40 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 5 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 8];
            buf.copy_to_slice(&mut tmp[3..]);
            *self = u64::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeBe for U48 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 6 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 8];
            buf.copy_to_slice(&mut tmp[2..]);
            *self = u64::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeLe for U48 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 8 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 8];
            buf.copy_to_slice(&mut tmp[2..]);
            *self = u64::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeBe for U56 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 7 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 8];
            buf.copy_to_slice(&mut tmp[1..]);
            *self = u64::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl DecodeLe for U56 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 7 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 8];
            buf.copy_to_slice(&mut tmp[1..]);
            *self = u64::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U72 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 9 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[7..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U72 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 9 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[7..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U80 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 10 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[6..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U80 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 10 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[6..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U88 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 11 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[5..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U88 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 11 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[5..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U96 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 12 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[4..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U96 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 12 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[4..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U104 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 13 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[3..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U104 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 13 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[3..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U112 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 14 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[2..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U112 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 14 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[2..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeBe for U120 {
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 15 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[1..]);
            *self = u128::from_be_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

#[cfg(feature = "u128")]
impl DecodeLe for U120 {
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        if buf.remaining() < 15 {
            Err(DecodeError::NeedMore)
        } else {
            let mut tmp = [0u8; 16];
            buf.copy_to_slice(&mut tmp[1..]);
            *self = u128::from_le_bytes(tmp).into_masked();
            Ok(())
        }
    }
}

impl<T> Decode for T
    where T: BitPack,
          <T as BitPack>::Packed: Decode + Default,
{
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        *self = Self::unpack(buf.decode()?);
        Ok(())
    }
}

impl<T> DecodeBe for T
    where T: BitPack,
          <T as BitPack>::Packed: DecodeBe + Default,
{
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        *self = Self::unpack(buf.decode_be()?);
        Ok(())
    }
}

impl<T> DecodeLe for T
    where T: BitPack,
          <T as BitPack>::Packed: DecodeLe + Default,
{
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        *self = Self::unpack(buf.decode_le()?);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::BitPack;
    use sniffle_bytes::bytes;

    #[derive(Decode, Debug, Default, PartialEq, Eq)]
    struct Struct {
        a: u8,
        b: i8,
        #[big]
        c: u32,
        #[little]
        d: i32,
        e: [u8; 4],
        f: [i8; 4],
        #[little]
        g: [u16; 2],
        #[big]
        h: [i16; 2],
    }

    #[test]
    fn decode_derive() {
        let mut buf: &[u8] = &bytes!("
            82       # a == 130
            82       # b == -126
            01020304 # c == 16909060
            04030280 # d == -2147351804
            01020304 # f == [1, 2, 3, 4]
            feff0001 # g == [-2, -1, 0, 1]
            01020304 # h == [513, 1027]
            01020304 # i == [258, 772]
        ");

        assert_eq!(
            buf.decode(),
            Ok(Struct {
                a: 130,
                b: -126,
                c: 16909060,
                d: -2147351804,
                e: [1, 2, 3, 4],
                f: [-2, -1, 0, 1],
                g: [513, 1027],
                h: [258, 772],
            })
        );
    }

    #[derive(BitPack, Default, Debug, PartialEq, Eq)]
    struct Ipv4VerLen {
        version: U4,
        length: U4,
    }

    #[derive(BitPack, Default, Debug, PartialEq, Eq)]
    struct Ipv4DscpEcn {
        dscp: U6,
        ecn: U2,
    }

    #[derive(BitPack, Default, Debug, PartialEq, Eq)]
    struct Ipv4FlagsFragOff {
        flags: U3,
        frag_offset: U13,
    }

    #[derive(Decode, Debug, Default, PartialEq, Eq)]
    struct Ipv4Header {
        ver_len: Ipv4VerLen,
        dscp_ecn: Ipv4DscpEcn,
        #[big]
        total_len: u16,
        #[big]
        ident: u16,
        #[big]
        flags_frag_offset: Ipv4FlagsFragOff,
        ttl: u8,
        protocol: u8,
        #[big]
        chksum: u16,
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
    }

    #[test]
    fn decode_derive_bitpack() {
        let mut buf: &[u8] = &bytes!("
            45       # version == 4, length == 5 (5 * 4 == 20)
            00       # dscp == 0, ecn == 0
            0014     # total_len == 20
            1234     # ident == 0x1234
            4000     # flags == 3, frag_offset == 0
            80       # ttl == 128
            fe       # protocol == 0xfe
            4321     # chksum == 0x4321
            c0a80001 # src_addr == 192.168.0.1
            c0a80002 # dst_addr == 192.168.0.2
        ");

        assert_eq!(
            buf.decode(),
            Ok(Ipv4Header {
                ver_len: Ipv4VerLen {
                    version: 4.into_masked(),
                    length: 5.into_masked(),
                },
                dscp_ecn: Ipv4DscpEcn {
                    dscp: 0.into_masked(),
                    ecn: 0.into_masked(),
                },
                total_len: 20,
                ident: 0x1234,
                flags_frag_offset: Ipv4FlagsFragOff {
                    flags: 2.into_masked(),
                    frag_offset: 0.into_masked(),
                },
                ttl: 128,
                protocol: 0xfe,
                chksum: 0x4321,
                src_addr: [192, 168, 0, 1],
                dst_addr: [192, 168, 0, 2],
            })
        );
    }
}
