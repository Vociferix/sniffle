use bytes::BufMut;

use crate::BitPack;

use sniffle_uint::*;

pub use sniffle_ende_derive::Encode;

pub trait EncodeBuf: BufMut + Sized {
    fn pad(&mut self, pad_value: u8, num_bytes: usize) {
        self.put_bytes(pad_value, num_bytes);
    }

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

impl Encodable for U24 {
    fn encoded_size(&self) -> usize {
        3
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        3 * slice.len()
    }
}

impl EncodeBe for U24 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u32 = (*self).into();
        buf.put(&tmp.to_be_bytes()[1..]);
    }
}

impl EncodeLe for U24 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u32 = (*self).into();
        buf.put(&tmp.to_le_bytes()[1..]);
    }
}

impl Encodable for U40 {
    fn encoded_size(&self) -> usize {
        5
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        5 * slice.len()
    }
}

impl EncodeBe for U40 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_be_bytes()[3..]);
    }
}

impl EncodeLe for U40 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_le_bytes()[3..]);
    }
}

impl Encodable for U48 {
    fn encoded_size(&self) -> usize {
        6
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        6 * slice.len()
    }
}

impl EncodeBe for U48 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_be_bytes()[2..]);
    }
}

impl EncodeLe for U48 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_le_bytes()[2..]);
    }
}

impl Encodable for U56 {
    fn encoded_size(&self) -> usize {
        7
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        7 * slice.len()
    }
}

impl EncodeBe for U56 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_be_bytes()[1..]);
    }
}

impl EncodeLe for U56 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_le_bytes()[1..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U72 {
    fn encoded_size(&self) -> usize {
        9
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        9 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U72 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[7..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U72 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[7..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U80 {
    fn encoded_size(&self) -> usize {
        10
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        10 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U80 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[6..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U80 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[6..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U88 {
    fn encoded_size(&self) -> usize {
        11
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        11 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U88 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[5..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U88 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[5..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U96 {
    fn encoded_size(&self) -> usize {
        12
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        12 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U96 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[4..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U96 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[4..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U104 {
    fn encoded_size(&self) -> usize {
        13
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        13 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U104 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[3..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U104 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[3..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U112 {
    fn encoded_size(&self) -> usize {
        14
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        14 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U112 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[2..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U112 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[2..]);
    }
}

#[cfg(feature = "u128")]
impl Encodable for U120 {
    fn encoded_size(&self) -> usize {
        15
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        15 * slice.len()
    }
}

#[cfg(feature = "u128")]
impl EncodeBe for U120 {
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[1..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U120 {
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[1..]);
    }
}

impl<T> Encodable for T
    where T: BitPack,
          <T as BitPack>::Packed: Encodable + Default,
{
    fn encoded_size(&self) -> usize {
        <T as BitPack>::Packed::default().encoded_size()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        <T as BitPack>::Packed::default().encoded_size() * slice.len()
    }
}

impl<T> Encode for T
    where T: BitPack + Clone,
          <T as BitPack>::Packed: Encode + Default,
{
    fn encode<B: EncodeBuf>(&self, buf: &mut B) {
        self.clone().pack().encode(buf);
    }
}

impl<T> EncodeBe for T
    where T: BitPack + Clone,
          <T as BitPack>::Packed: EncodeBe + Default,
{
    fn encode_be<B: EncodeBuf>(&self, buf: &mut B) {
        self.clone().pack().encode_be(buf);
    }
}

impl<T> EncodeLe for T
    where T: BitPack + Clone,
          <T as BitPack>::Packed: EncodeLe + Default,
{
    fn encode_le<B: EncodeBuf>(&self, buf: &mut B) {
        self.clone().pack().encode_le(buf);
    }
}
