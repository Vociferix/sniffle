use bytes::BufMut;

use crate::pack::Pack;

use sniffle_uint::*;

/// Derive the [`Encode`] trait on a struct.
///
/// Each field must implement [`Encode`], [`EncodeBe`], or [`EncodeLe`].
/// Fields that implement [`EncodeBe`] and [`EncodeLe`] need to be annotated
/// with `#[big]` or `#[little]` to specify whether the field should be
/// encoded as big endian or little endian.
///
/// This trait also derives the [`Encodable`] trait, which is a
/// prerequisite of the [`Encode`] trait.
///
/// ## Example
/// ```
/// # use sniffle_ende::{pack::Pack, encode::Encode, encode::EncodeBuf};
/// # use sniffle_uint::*;
/// #[derive(Encode, Debug, Default, PartialEq, Eq)]
/// struct Ipv4Header {
///     ver_len: Ipv4VerLen,
///     dscp_ecn: Ipv4DscpEcn,
///     #[big]
///     total_len: u16,
///     #[big]
///     ident: u16,
///     #[big]
///     flags_frag_offset: Ipv4FlagsFragOff,
///     ttl: u8,
///     protocol: u8,
///     #[big]
///     chksum: u16,
///     src_addr: [u8; 4],
///     dst_addr: [u8; 4],
/// }
///
/// // Bit fields for version and length
/// #[derive(Pack, Clone, Default, Debug, PartialEq, Eq)]
/// struct Ipv4VerLen {
///     version: U4,
///     length: U4,
/// }
///
/// // Bit fields for DSCP and ECN
/// #[derive(Pack, Clone, Default, Debug, PartialEq, Eq)]
/// struct Ipv4DscpEcn {
///     dscp: U6,
///     ecn: U2,
/// }
///
/// // Bit fields for IPv4 flags and fragment offset
/// #[derive(Pack, Clone, Default, Debug, PartialEq, Eq)]
/// struct Ipv4FlagsFragOff {
///     flags: U3,
///     frag_offset: U13,
/// }
///
/// let hdr = Ipv4Header {
///     ver_len: Ipv4VerLen {
///         version: 4.into_masked(),
///         length: 5.into_masked(),
///     },
///     dscp_ecn: Ipv4DscpEcn {
///         dscp: 0.into_masked(),
///         ecn: 0.into_masked(),
///     },
///     total_len: 20,
///     ident: 0x1234,
///     flags_frag_offset: Ipv4FlagsFragOff {
///         flags: 2.into_masked(),
///         frag_offset: 0.into_masked(),
///     },
///     ttl: 128,
///     protocol: 0xfe,
///     chksum: 0x4321,
///     src_addr: [192, 168, 0, 1],
///     dst_addr: [192, 168, 0, 2],
/// };
/// let mut buffer = [0u8; 20];
/// let mut buf: &mut [u8] = &mut buffer;
/// buf.encode(&hdr);
///
/// assert_eq!(buffer, [
///     0x45,                    // version == 4, length == 5
///     0x00,                    // dscp == 0, ecn == 0
///     0x00, 0x14,              // total_len == 20
///     0x12, 0x34,              // ident = 0x1234
///     0x40, 0x00,              // flags == 2, frag_offset == 0
///     0x80,                    // ttl == 128
///     0xfe,                    // protocol = 0xfe
///     0x43, 0x21,              // chksum == 0x4321
///     0xc0, 0xa8, 0x00, 0x01,  // src_addr == 192.168.0.1
///     0xc0, 0xa8, 0x00, 0x02,  // dst_addr == 192.168.0.2
/// ])
/// ```
pub use sniffle_ende_derive::Encode;

/// Trait representing an encodable data output buffer.
///
/// This trait is an extension to the [`bytes::BufMut`] trait to support
/// interoperability with the [`Encodable`], [`Encode`], [`EncodeBe`],
/// and [`EncodeLe`] traits.
pub trait EncodeBuf: BufMut + Sized {
    /// Writes padding bytes to the buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::EncodeBuf;
    /// let mut buffer = [0u8; 8];
    /// let mut encbuf: &mut [u8] = &mut buffer;
    /// encbuf.pad(42, 4);
    /// assert_eq!(encbuf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [42, 42, 42, 42, 0, 0, 0, 0]);
    /// ```
    fn pad(&mut self, pad_value: u8, num_bytes: usize) {
        self.put_bytes(pad_value, num_bytes);
    }

    /// Checks whether an object can be encoded into the buffer.
    ///
    /// A object is encodable if there is enough space in the buffer
    /// for the serialized encoding of the object. If this function
    /// returns `false`, a call to [`EncodeBuf::encode`],
    /// [`EncodeBuf::encode_be`], or [`EncodeBuf::encode_le`] with
    /// the same encodable object will result in a panic.
    ///
    /// Some buffer types may always return `true`, such as
    /// [`Vec<u8>`]. But something like a `&mut [u8]` cannot grow,
    /// and thus has a limited capacity.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeBuf, Encodable};
    /// let buf: &mut [u8] = &mut [0; 4];
    /// assert!(buf.encodable(&0u32));
    /// assert!(!buf.encodable(&0u64));
    /// ```
    fn encodable<E: Encodable + ?Sized>(&self, item: &E) -> bool {
        self.remaining_mut() >= item.encoded_size()
    }

    /// Encodes an object implementing [`Encode`] onto the buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{Encode, EncodeBuf};
    /// let mut buffer = [0u8; 8];
    /// let mut encbuf: &mut [u8] = &mut buffer;
    /// encbuf.encode(&[1u8, 2, 3, 4]);
    /// assert_eq!(encbuf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    /// ```
    fn encode<E: Encode + ?Sized>(&mut self, item: &E) {
        item.encode_to(self)
    }

    /// Encodes an object implementing [`EncodeBe`] as big endian onto the buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeBe, EncodeBuf};
    /// let mut buffer = [0u8; 8];
    /// let mut encbuf: &mut [u8] = &mut buffer;
    /// encbuf.encode_be(&0x01020304);
    /// assert_eq!(encbuf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    /// ```
    fn encode_be<E: EncodeBe + ?Sized>(&mut self, item: &E) {
        item.encode_be_to(self)
    }

    /// Encodes an object implementing [`EncodeLe`] as little endian onto the buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeLe, EncodeBuf};
    /// let mut buffer = [0u8; 8];
    /// let mut encbuf: &mut [u8] = &mut buffer;
    /// encbuf.encode_le(&0x04030201);
    /// assert_eq!(encbuf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    /// ```
    fn encode_le<E: EncodeLe + ?Sized>(&mut self, item: &E) {
        item.encode_le_to(self)
    }
}

impl<B: BufMut + Sized> EncodeBuf for B {}

/// Base trait that provides information about the encoded size of an object.
///
/// This trait is a common super trait of [`Encode`], [`EncodeBe`], and
/// [`EncodeLe`]. This trait descibes the size of an object in bytes when
/// encoded on to a buffer implementing [`EncodeBuf`].
pub trait Encodable {
    /// Returns the encoded size of the object in bytes.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{Encodable, EncodeBuf};
    /// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// struct Example(u32);
    ///
    /// impl Encodable for Example {
    ///     fn encoded_size(&self) -> usize {
    ///         self.0.encoded_size()
    ///     }
    /// }
    ///
    /// assert_eq!(Example(42).encoded_size(), 4);
    /// ```
    fn encoded_size(&self) -> usize;

    /// Returns the cumulative size of a slice of objects in bytes.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more efficient solution exists. By default, this
    /// function simply iterates through the slice and sums the size of each
    /// item. In many cases, the type's encoding has a constant size, so the
    /// constant size can just be multiplied by the length of the slice.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{Encodable, EncodeBuf};
    /// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// struct Example(u32);
    ///
    /// impl Encodable for Example {
    ///     fn encoded_size(&self) -> usize {
    ///         self.0.encoded_size()
    ///     }
    ///
    ///     fn encoded_slice_size(slice: &[Self]) -> usize {
    ///         std::mem::size_of::<u32>() * slice.len()
    ///     }
    /// }
    ///
    /// assert_eq!([Example(42), Example(24)].encoded_size(), 8);
    /// ```
    fn encoded_slice_size(slice: &[Self]) -> usize
    where
        Self: Sized,
    {
        slice.iter().fold(0, |acc, item| acc + item.encoded_size())
    }
}

/// Trait that allows a type to be encoded to a buffer.
pub trait Encode: Encodable {
    /// Implements encoding an object onto a buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{Encode, Encodable, EncodeBuf};
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Addr {
    ///     addr_bytes: [u8; 4],
    /// }
    ///
    /// impl Encodable for Addr {
    ///     fn encoded_size(&self) -> usize {
    ///         self.addr_bytes.encoded_size()
    ///     }
    /// }
    ///
    /// // note that this simple example can be derived with #[derive(Encode)]
    /// impl Encode for Addr {
    ///     fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
    ///         self.addr_bytes.encode_to(buf)
    ///     }
    /// }
    ///
    /// let mut buffer = [0u8; 8];
    /// let mut buf: &mut [u8] = &mut buffer;
    /// let addr = Addr { addr_bytes: [1, 2, 3, 4] };
    /// buf.encode(&addr);
    /// assert_eq!(buf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    /// ```
    fn encode_to<B: EncodeBuf>(&self, buf: &mut B);

    /// Implements encoding a slice of objects onto a buffer.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more efficient solution exists. By default, this function
    /// simply iterates through the slice and encodes items one-by-one. In many
    /// cases, a slice can be encoded in bulk using `unsafe` code or using
    /// utilities like the [`bytemuck`] crate.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{Encode, Encodable, EncodeBuf};
    /// #[repr(transparent)]
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Addr {
    ///     addr_bytes: [u8; 4],
    /// }
    ///
    /// unsafe impl bytemuck::Zeroable for Addr { }
    ///
    /// unsafe impl bytemuck::Pod for Addr { }
    ///
    /// impl Encodable for Addr {
    ///     fn encoded_size(&self) -> usize {
    ///         self.addr_bytes.encoded_size()
    ///     }
    ///
    ///     // If you're implementing `encode_slice`, you probably also want
    ///     // to implement `encoded_slice_size`.
    ///     fn encoded_slice_size(slice: &[Self]) -> usize {
    ///         4 * slice.len()
    ///     }
    /// }
    ///
    /// impl Encode for Addr {
    ///     fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
    ///         self.addr_bytes.encode_to(buf)
    ///     }
    ///
    ///     fn encode_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
    ///         let bytes: &[u8] = bytemuck::cast_slice(slice);
    ///         buf.encode(bytes)
    ///     }
    /// }
    ///
    /// let mut buffer = [0u8; 12];
    /// let mut buf: &mut [u8] = &mut buffer;
    /// let addrs = [Addr { addr_bytes: [1, 2, 3, 4] }, Addr { addr_bytes: [4, 3, 2, 1] }];
    /// buf.encode(&addrs);
    /// assert_eq!(buf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 4, 3, 2, 1, 0, 0, 0, 0]);
    /// ```
    fn encode_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B)
    where
        Self: Sized,
    {
        for item in slice.iter() {
            item.encode_to(buf)
        }
    }
}

/// Trait that allows a type to be encoded as big endian to a buffer.
///
/// Generally, a type that implements [`EncodeBe`] will also implement [`EncodeLe`]
/// so that the user can choose to encode as big or little endian as needed. If there
/// is only one possible endianness to encode as, the type should instead implement
/// [`Encode`].
pub trait EncodeBe: Encodable {
    /// Implements encoded an object as big endian on to a buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeBe, Encodable, EncodeBuf};
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Example {
    ///     value: u32,
    /// }
    ///
    /// impl Encodable for Example {
    ///     fn encoded_size(&self) -> usize {
    ///         self.value.encoded_size()
    ///     }
    /// }
    ///
    /// impl EncodeBe for Example {
    ///     fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
    ///         self.value.encode_be_to(buf);
    ///     }
    /// }
    ///
    /// let mut buffer = [0u8; 8];
    /// let mut buf: &mut [u8] = &mut buffer;
    /// let ex = Example { value: 0x01020304 };
    /// buf.encode_be(&ex);
    /// assert_eq!(buf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    /// ```
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B);

    /// Implements encoding a slice of objects as big endian onto a buffer.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more efficient solution exists. By default, this function
    /// simply iterates through the slice and encodes items one-by-one. In many
    /// cases, a slice can be encoded in bulk using `unsafe` code or using
    /// utilities like the [`bytemuck`] crate.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeBe, Encodable, EncodeBuf};
    /// #[repr(transparent)]
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Example {
    ///     value: u32,
    /// }
    ///
    /// unsafe impl bytemuck::Zeroable for Example { }
    ///
    /// unsafe impl bytemuck::Pod for Example { }
    ///
    /// impl Encodable for Example {
    ///     fn encoded_size(&self) -> usize {
    ///         self.value.encoded_size()
    ///     }
    ///
    ///     // If you're implementing `encode_be_slice`, you probably also want
    ///     // to implement `encoded_slice_size`.
    ///     fn encoded_slice_size(slice: &[Self]) -> usize {
    ///         std::mem::size_of::<u32>() * slice.len()
    ///     }
    /// }
    ///
    /// impl EncodeBe for Example {
    ///     fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
    ///         self.value.encode_be_to(buf);
    ///     }
    ///
    ///     fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
    ///         let values: &[u32] = bytemuck::cast_slice(slice);
    ///         buf.encode_be(values)
    ///     }
    /// }
    ///
    /// let mut buffer = [0u8; 12];
    /// let mut buf: &mut [u8] = &mut buffer;
    /// let exs = [Example { value: 0x01020304 }, Example { value: 0x04030201 }];
    /// buf.encode_be(&exs);
    /// assert_eq!(buf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [1, 2, 3, 4, 4, 3, 2, 1, 0, 0, 0, 0]);
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B)
    where
        Self: Sized,
    {
        for item in slice.iter() {
            item.encode_be_to(buf)
        }
    }
}

/// Trait that allows a type to be encoded as little endian to a buffer.
///
/// Generally, a type that implements [`EncodeLe`] will also implement [`EncodeBe`]
/// so that the user can choose to encode as big or little endian as needed. If there
/// is only one possible endianness to encode as, the type should instead implement
/// [`Encode`].
pub trait EncodeLe: Encodable {
    /// Implements encoded an object as little endian on to a buffer.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeLe, Encodable, EncodeBuf};
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Example {
    ///     value: u32,
    /// }
    ///
    /// impl Encodable for Example {
    ///     fn encoded_size(&self) -> usize {
    ///         self.value.encoded_size()
    ///     }
    /// }
    ///
    /// impl EncodeLe for Example {
    ///     fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
    ///         self.value.encode_le_to(buf);
    ///     }
    /// }
    ///
    /// let mut buffer = [0u8; 8];
    /// let mut buf: &mut [u8] = &mut buffer;
    /// let ex = Example { value: 0x01020304 };
    /// buf.encode_le(&ex);
    /// assert_eq!(buf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [4, 3, 2, 1, 0, 0, 0, 0]);
    /// ```
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B);

    /// Implements encoding a slice of objects as little endian onto a buffer.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more efficient solution exists. By default, this function
    /// simply iterates through the slice and encodes items one-by-one. In many
    /// cases, a slice can be encoded in bulk using `unsafe` code or using
    /// utilities like the [`bytemuck`] crate.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::encode::{EncodeLe, Encodable, EncodeBuf};
    /// #[repr(transparent)]
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Example {
    ///     value: u32,
    /// }
    ///
    /// unsafe impl bytemuck::Zeroable for Example { }
    ///
    /// unsafe impl bytemuck::Pod for Example { }
    ///
    /// impl Encodable for Example {
    ///     fn encoded_size(&self) -> usize {
    ///         self.value.encoded_size()
    ///     }
    ///
    ///     // If you're implementing `encode_le_slice`, you probably also want
    ///     // to implement `encoded_slice_size`.
    ///     fn encoded_slice_size(slice: &[Self]) -> usize {
    ///         std::mem::size_of::<u32>() * slice.len()
    ///     }
    /// }
    ///
    /// impl EncodeLe for Example {
    ///     fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
    ///         self.value.encode_le_to(buf);
    ///     }
    ///
    ///     fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
    ///         let values: &[u32] = bytemuck::cast_slice(slice);
    ///         buf.encode_le(values)
    ///     }
    /// }
    ///
    /// let mut buffer = [0u8; 12];
    /// let mut buf: &mut [u8] = &mut buffer;
    /// let exs = [Example { value: 0x01020304 }, Example { value: 0x04030201 }];
    /// buf.encode_le(&exs);
    /// assert_eq!(buf, &mut [0, 0, 0, 0]);
    /// assert_eq!(buffer, [4, 3, 2, 1, 1, 2, 3, 4, 0, 0, 0, 0]);
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B)
    where
        Self: Sized,
    {
        for item in slice.iter() {
            item.encode_le_to(buf)
        }
    }
}

impl<E: Encodable> Encodable for [E] {
    fn encoded_size(&self) -> usize {
        E::encoded_slice_size(self)
    }
}

impl<E: Encode> Encode for [E] {
    fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_slice_to(self, buf)
    }
}

impl<E: EncodeBe> EncodeBe for [E] {
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_be_slice_to(self, buf)
    }
}

impl<E: EncodeLe> EncodeLe for [E] {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_le_slice_to(self, buf)
    }
}

impl<E: Encodable, const LEN: usize> Encodable for [E; LEN] {
    fn encoded_size(&self) -> usize {
        E::encoded_slice_size(self)
    }
}

impl<E: Encode, const LEN: usize> Encode for [E; LEN] {
    fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_slice_to(self, buf)
    }
}

impl<E: EncodeBe, const LEN: usize> EncodeBe for [E; LEN] {
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_be_slice_to(self, buf)
    }
}

impl<E: EncodeLe, const LEN: usize> EncodeLe for [E; LEN] {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        E::encode_le_slice_to(self, buf)
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
    fn encode_to<B: EncodeBuf>(&self, _buf: &mut B) {}

    fn encode_slice_to<B: EncodeBuf>(_slice: &[Self], _buf: &mut B) {}
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
    fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u8(*self);
    }

    fn encode_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i8(*self);
    }

    fn encode_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u16(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u16 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u16_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i16(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i16 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i16_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u32(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u32 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u32_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i32(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i32 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i32_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u64(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u64 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u64_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i64(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i64 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i64_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u128(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for u128 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_u128_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i128(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for i128 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_i128_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f32(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for f32 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f32_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f64(*self);
    }

    #[cfg(target_endian = "big")]
    fn encode_be_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
        buf.put(bytemuck::cast_slice(slice))
    }
}

impl EncodeLe for f64 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        buf.put_f64_le(*self);
    }

    #[cfg(target_endian = "little")]
    fn encode_le_slice_to<B: EncodeBuf>(slice: &[Self], buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u32 = (*self).into();
        buf.put(&tmp.to_be_bytes()[1..]);
    }
}

impl EncodeLe for U24 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_be_bytes()[3..]);
    }
}

impl EncodeLe for U40 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_be_bytes()[2..]);
    }
}

impl EncodeLe for U48 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u64 = (*self).into();
        buf.put(&tmp.to_be_bytes()[1..]);
    }
}

impl EncodeLe for U56 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[7..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U72 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[6..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U80 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[5..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U88 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[4..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U96 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[3..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U104 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[2..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U112 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
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
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_be_bytes()[1..]);
    }
}

#[cfg(feature = "u128")]
impl EncodeLe for U120 {
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        let tmp: u128 = (*self).into();
        buf.put(&tmp.to_le_bytes()[1..]);
    }
}

impl<T> Encodable for T
where
    T: Pack,
    <T as Pack>::Packed: Encodable + Default,
{
    fn encoded_size(&self) -> usize {
        <T as Pack>::Packed::default().encoded_size()
    }

    fn encoded_slice_size(slice: &[Self]) -> usize {
        <T as Pack>::Packed::default().encoded_size() * slice.len()
    }
}

impl<T> Encode for T
where
    T: Pack + Clone,
    <T as Pack>::Packed: Encode + Default,
{
    fn encode_to<B: EncodeBuf>(&self, buf: &mut B) {
        self.clone().pack().encode_to(buf);
    }
}

impl<T> EncodeBe for T
where
    T: Pack + Clone,
    <T as Pack>::Packed: EncodeBe + Default,
{
    fn encode_be_to<B: EncodeBuf>(&self, buf: &mut B) {
        self.clone().pack().encode_be_to(buf);
    }
}

impl<T> EncodeLe for T
where
    T: Pack + Clone,
    <T as Pack>::Packed: EncodeLe + Default,
{
    fn encode_le_to<B: EncodeBuf>(&self, buf: &mut B) {
        self.clone().pack().encode_le_to(buf);
    }
}
