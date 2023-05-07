use bytes::BufMut;

pub trait EncodeBuf: BufMut + Sized {
    fn encodable<E: Encodable + ?Sized>(&self, item: &E) -> bool {
        self.remaining_mut() >= item.encoded_size()
    }

    fn encode<E: Encode + ?Sized>(&mut self, item: &E) {
        item.encode(self)
    }

    fn encode_be<E: EncodeBe + ?Sized>(&mut self, item: &E) {
        item.encode_be(self)
    }

    fn encode_le<E: EncodeLe + ?Sized>(&mut self, item: &E) {
        item.encode_le(self)
    }
}

impl<B: BufMut + Sized> EncodeBuf for B {}

pub trait Encodable {
    fn encoded_size(&self) -> usize;

    fn encoded_slice_size(slice: &[Self]) -> usize
    where
        Self: Sized,
    {
        slice.iter().fold(0, |acc, item| acc + item.encoded_size())
    }
}

pub trait Encode: Encodable {
    fn encode<B: EncodeBuf>(&self, buf: &mut B);

    fn encode_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B)
    where
        Self: Sized,
    {
        for item in slice.iter() {
            item.encode(buf)
        }
    }
}

pub trait EncodeBe: Encodable {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B);

    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B)
    where
        Self: Sized,
    {
        for item in slice.iter() {
            item.encode_be(buf)
        }
    }
}

pub trait EncodeLe: Encodable {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B);

    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B)
    where
        Self: Sized,
    {
        for item in slice.iter() {
            item.encode_le(buf)
        }
    }
}

impl<E: Encodable> Encodable for [E] {
    fn encoded_size(&self) -> usize {
        E::encoded_slice_size(self)
    }
}

impl<E: Encode> Encode for [E] {
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_slice(self, buf)
    }
}

impl<E: EncodeBe> EncodeBe for [E] {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_be_slice(self, buf)
    }
}

impl<E: EncodeLe> EncodeLe for [E] {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_le_slice(self, buf)
    }
}

impl Encodable for () {
    fn encoded_size(&self) -> usize {
        0
    }

    fn encoded_slice_size(_slice: &[Self]) -> usize {
        0
    }
}

impl Encode for () {
    fn encode<B: EncodeBuf>(&self, _buf: &mut B) {}

    fn encode_slice<B: EncodeBuf>(_slice: &[Self], _buf: &mut B) {}
}

impl Encodable for u8 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<u8>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<u8>()
    }
}

impl Encode for u8 {
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u8(*self);
    }

    fn encode_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(slice)
    }
}

impl Encodable for i8 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<i8>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<i8>()
    }
}

impl Encode for i8 {
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i8(*self);
    }

    fn encode_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for u16 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<u16>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<u16>()
    }
}

impl EncodeBe for u16 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u16(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u16 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u16_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for i16 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<i16>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<i16>()
    }
}

impl EncodeBe for i16 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i16(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i16 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i16_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for u32 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<u32>()
    }
}

impl EncodeBe for u32 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u32(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u32 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u32_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for i32 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<i32>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<i32>()
    }
}

impl EncodeBe for i32 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i32(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i32 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i32_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for u64 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<u64>()
    }
}

impl EncodeBe for u64 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u64(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u64 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u64_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for i64 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<i64>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<i64>()
    }
}

impl EncodeBe for i64 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i64(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i64 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i64_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for u128 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<u128>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<u128>()
    }
}

impl EncodeBe for u128 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u128(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u128 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u128_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for i128 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<i128>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<i128>()
    }
}

impl EncodeBe for i128 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i128(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i128 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i128_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for f32 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<f32>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<f32>()
    }
}

impl EncodeBe for f32 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f32(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for f32 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f32_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl Encodable for f64 {
    fn encoded_size(&self) -> usize {
        std::mem::size_of::<f64>()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        slice.len() * std::mem::size_of::<f64>()
    }
}

impl EncodeBe for f64 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f64(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for f64 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f64_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}
