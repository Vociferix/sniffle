use bytes::Buf;

pub use sniffle_decode_derive::Decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("Not enough data to decode")]
    NeedMore,
    #[error("Data is malformed")]
    Malformed,
}

pub type Result<T> = std::result::Result<T, DecodeError>;

pub trait DecodeBuf: Buf + Sized {
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

#[cfg(test)]
mod test {
    use super::*;

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
    fn do_decode() {
        let mut buf: &[u8] = &[
            0x82, // a == 130
            0x82, // b == -126
            1, 2, 3, 4, // c == 16909060
            4, 3, 2, 0x80, // d == -2147351804
            1, 2, 3, 4, // f == [1, 2, 3, 4]
            0xfe, 0xff, 0, 1, // g == [-2, -1, 0, 1]
            1, 2, 3, 4, // h == [513, 1027]
            1, 2, 3, 4, // i == [258, 772]
        ];

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
}
