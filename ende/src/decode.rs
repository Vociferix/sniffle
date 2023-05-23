use crate::pack::Pack;
use bytes::Buf;

use sniffle_uint::*;

/// Derive the [`Decode`] trait on a struct.
///
/// Each field must implement [`Decode`], [`DecodeBe`], or [`DecodeLe`].
/// Fields that implement [`DecodeBe`] and [`DecodeLe`] need to be annotated
/// with `#[big]` or `#[little]` to specify whether the field should be
/// decoded as big endian or little endian.
///
/// ## Example
/// ```
/// # use sniffle_ende::{pack::Pack, decode::Decode, decode::DecodeBuf};
/// # use sniffle_uint::*;
/// #[derive(Decode, Debug, Default, PartialEq, Eq)]
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
/// #[derive(Pack, Default, Debug, PartialEq, Eq)]
/// struct Ipv4VerLen {
///     version: U4,
///     length: U4,
/// }
///
/// // Bit fields for DSCP and ECN
/// #[derive(Pack, Default, Debug, PartialEq, Eq)]
/// struct Ipv4DscpEcn {
///     dscp: U6,
///     ecn: U2,
/// }
///
/// // Bit fields for IPv4 flags and fragment offset
/// #[derive(Pack, Default, Debug, PartialEq, Eq)]
/// struct Ipv4FlagsFragOff {
///     flags: U3,
///     frag_offset: U13,
/// }
///
/// let mut buf: &[u8] = &[
///     0x45,                    // version == 4, length == 5
///     0x00,                    // dscp == 0, ecn == 0
///     0x00, 0x14,              // total_len == 20
///     0x12, 0x34,              // ident = 0x1234
///     0x40, 0x00,              // flags == 3, frag_offset == 0
///     0x80,                    // ttl == 128
///     0xfe,                    // protocol = 0xfe
///     0x43, 0x21,              // chksum == 0x4321
///     0xc0, 0xa8, 0x00, 0x01,  // src_addr == 192.168.0.1
///     0xc0, 0xa8, 0x00, 0x02,  // dst_addr == 192.168.0.2
/// ];
///
/// assert_eq!(
///     buf.decode(),
///     Ok(Ipv4Header {
///         ver_len: Ipv4VerLen {
///             version: 4.into_masked(),
///             length: 5.into_masked(),
///         },
///         dscp_ecn: Ipv4DscpEcn {
///             dscp: 0.into_masked(),
///             ecn: 0.into_masked(),
///         },
///         total_len: 20,
///         ident: 0x1234,
///         flags_frag_offset: Ipv4FlagsFragOff {
///             flags: 2.into_masked(),
///             frag_offset: 0.into_masked(),
///         },
///         ttl: 128,
///         protocol: 0xfe,
///         chksum: 0x4321,
///         src_addr: [192, 168, 0, 1],
///         dst_addr: [192, 168, 0, 2],
///     }),
/// );
/// ```
pub use sniffle_ende_derive::Decode;

/// Error codes corresponding to the [`Decode`], [`DecodeBe`], and [`DecodeLe`] traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Designates that more data was expected.
    ///
    /// When input data is streaming, this may mean that more data
    /// needs to be retreived from the stream in order to decode.
    /// Otherwise, this error may simply mean that the data is
    /// malformed or corrupted.
    #[error("Not enough data to decode")]
    NeedMore,
    /// Designates that data is malformed or corrupted.
    ///
    /// Unlike [`DecodeError::NeedMore`], there is no possibility of decoding in
    /// the presence of more data. The data cannot be decoded as the requested type.
    #[error("Data is malformed")]
    Malformed,
}

type Result<T> = std::result::Result<T, DecodeError>;

/// Trait representing a decodable data input buffer.
///
/// This trait is an extension to the [`bytes::Buf`] trait to support
/// interoperability with the [`Decode`], [`DecodeBe`], and [`DecodeLe`]
/// traits.
pub trait DecodeBuf: Buf + Sized {
    /// Consume bytes from the buffer without decoding as any datatype.
    ///
    /// May be useful for ignoring padding or reserved byte ranges.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::DecodeBuf;
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// buf.skip(4).unwrap();
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn skip(&mut self, num_bytes: usize) -> Result<()> {
        if num_bytes > self.remaining() {
            Err(DecodeError::NeedMore)
        } else {
            self.advance(num_bytes);
            Ok(())
        }
    }

    /// Consume and decode buffer data into a type implementing [`Decode`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{Decode, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let bytes: [u8; 4] = buf.decode().unwrap();
    /// assert_eq!(bytes, [1, 2, 3, 4]);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode<D>(&mut self) -> Result<D>
    where
        D: Decode + Sized + Default,
    {
        self.decode_with(D::default())
    }

    /// Consume and decode big endian buffer data into a type implementing [`DecodeBe`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeBe, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let num: u32 = buf.decode_be().unwrap();
    /// assert_eq!(num, 0x01020304);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_be<D>(&mut self) -> Result<D>
    where
        D: DecodeBe + Sized + Default,
    {
        self.decode_be_with(D::default())
    }

    /// Consume and decode little endian buffer data into a type implementing [`DecodeLe`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeLe, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let num: u32 = buf.decode_le().unwrap();
    /// assert_eq!(num, 0x04030201);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_le<D>(&mut self) -> Result<D>
    where
        D: DecodeLe + Sized + Default,
    {
        self.decode_le_with(D::default())
    }

    /// Consume and decode buffer data into a type implementing [`Decode`].
    ///
    /// Unlike, [`DecodeBuf::decode`], this function does not require that the decoded
    /// type also implement [`Default`]. The initial value (`init`), is essentially
    /// ignored and is used only to create an object that can be decoded into.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{Decode, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let bytes = buf.decode_with([0u8; 4]).unwrap();
    /// assert_eq!(bytes, [1, 2, 3, 4]);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_with<D>(&mut self, mut init: D) -> Result<D>
    where
        D: Decode + Sized,
    {
        init.decode(self)?;
        Ok(init)
    }

    /// Consume and decode big endian buffer data into a type implementing [`DecodeBe`].
    ///
    /// Unlike, [`DecodeBuf::decode_be`], this function does not require that the decoded
    /// type also implement [`Default`]. The initial value (`init`), is essentially
    /// ignored and is used only to create an object that can be decoded into.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeBe, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let num = buf.decode_be_with(0u32).unwrap();
    /// assert_eq!(num, 0x01020304);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_be_with<D>(&mut self, mut init: D) -> Result<D>
    where
        D: DecodeBe + Sized,
    {
        init.decode_be(self)?;
        Ok(init)
    }

    /// Consume and decode little endian buffer data into a type implementing [`DecodeLe`].
    ///
    /// Unlike, [`DecodeBuf::decode_le`], this function does not require that the decoded
    /// type also implement [`Default`]. The initial value (`init`), is essentially
    /// ignored and is used only to create an object that can be decoded into.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeLe, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let num = buf.decode_le_with(0u32).unwrap();
    /// assert_eq!(num, 0x04030201);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_le_with<D>(&mut self, mut init: D) -> Result<D>
    where
        D: DecodeLe + Sized,
    {
        init.decode_le(self)?;
        Ok(init)
    }

    /// Consume and decode buffer data into a type implementing [`Decode`].
    ///
    /// Unlike, [`DecodeBuf::decode`] and [`DecodeBuf::decode_with`], this function
    /// does not require that the decoded type also implement [`Default`] or
    /// [`Sized`]. This funciton is useful for decoding into already existing
    /// object instances, and instances of unsized types.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{Decode, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let mut bytes = [0u8; 4];
    /// buf.decode_to(&mut bytes).unwrap();
    /// assert_eq!(bytes, [1, 2, 3, 4]);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_to<D>(&mut self, item: &mut D) -> Result<()>
    where
        D: Decode + ?Sized,
    {
        item.decode(self)
    }

    /// Consume and decode big endian buffer data into a type implementing [`DecodeBe`].
    ///
    /// Unlike, [`DecodeBuf::decode_be`] and [`DecodeBuf::decode_be_with`], this function
    /// does not require that the decoded type also implement [`Default`] or [`Sized`].
    /// This funciton is useful for decoding into already existing object instances,
    /// and instances of unsized types.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeBe, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let mut num = 0u32;
    /// buf.decode_be_to(&mut num).unwrap();
    /// assert_eq!(num, 0x01020304);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_be_to<D>(&mut self, item: &mut D) -> Result<()>
    where
        D: DecodeBe + ?Sized,
    {
        item.decode_be(self)
    }

    /// Consume and decode little endian buffer data into a type implementing [`DecodeLe`].
    ///
    /// Unlike, [`DecodeBuf::decode_le`] and [`DecodeBuf::decode_le_with`], this function
    /// does not require that the decoded type also implement [`Default`] or [`Sized`].
    /// This funciton is useful for decoding into already existing object instances,
    /// and instances of unsized types.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeLe, DecodeBuf};
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let mut num = 0u32;
    /// buf.decode_le_to(&mut num).unwrap();
    /// assert_eq!(num, 0x04030201);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_le_to<D>(&mut self, item: &mut D) -> Result<()>
    where
        D: DecodeLe + ?Sized,
    {
        item.decode_le(self)
    }
}

impl<B: Buf + Sized> DecodeBuf for B {}

/// Trait that allows a type to be decoded from a buffer.
pub trait Decode {
    /// Implements parsing a portion of a buffer onto a object.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{Decode, DecodeBuf, DecodeError};
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Addr {
    ///     addr_bytes: [u8; 4],
    /// }
    ///
    /// // Note that this simple example can be derived with #[derive(Decode)]
    /// impl Decode for Addr {
    ///     fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
    ///         buf.decode_to(&mut self.addr_bytes)
    ///     }
    /// }
    ///
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let addr: Addr = buf.decode().unwrap();
    /// assert_eq!(addr.addr_bytes, [1, 2, 3, 4]);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()>;

    /// Implements parsing a portion of a buffer onto a slices of objects.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more effcient solution exists. By default this function
    /// simply iterates through the slice and decodes items one-by-one. In many
    /// cases, a slice can be decoded in bulk using `unsafe` code or using
    /// utilities like the [`bytemuck`] crate.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{Decode, DecodeBuf, DecodeError};
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
    /// impl Decode for Addr {
    ///     fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
    ///         buf.decode_to(&mut self.addr_bytes)
    ///     }
    ///
    ///     fn decode_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B)
    ///         -> Result<(), DecodeError>
    ///     {
    ///         let bytes: &mut [u8] = bytemuck::cast_slice_mut(slice);
    ///         buf.decode_to(bytes)
    ///     }
    /// }
    ///
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    /// let addr: [Addr; 2] = buf.decode().unwrap();
    /// assert_eq!(addr[0].addr_bytes, [1, 2, 3, 4]);
    /// assert_eq!(addr[1].addr_bytes, [5, 6, 7, 8]);
    /// assert_eq!(buf, &[9, 10, 11, 12]);
    /// ```
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

/// Trait that allows a type to be decoded as big endian from a buffer.
///
/// Generally, a type that implements [`DecodeBe`] will also implement [`DecodeLe`] so
/// that the user can choose to decode as big or little endian as needed. If there
/// is only one valid endianness to decode as, the type should instead implement
/// [`Decode`].
pub trait DecodeBe {
    /// Implements parsing a portion of a buffer onto a object as big endian.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeBe, DecodeBuf, DecodeError};
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Example {
    ///     value: u32,
    /// }
    ///
    /// impl DecodeBe for Example {
    ///     fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
    ///         buf.decode_be_to(&mut self.value)
    ///     }
    /// }
    ///
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let ex: Example = buf.decode_be().unwrap();
    /// assert_eq!(ex.value, 0x01020304);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()>;

    /// Implements parsing a portion of a buffer onto a slices of objects as big endian.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more effcient solution exists. By default this function
    /// simply iterates through the slice and decodes items one-by-one. In many
    /// cases, a slice can be decoded in bulk using `unsafe` code or using
    /// utilities like the [`bytemuck`] crate.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeBe, DecodeBuf, DecodeError};
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
    /// impl DecodeBe for Example {
    ///     fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
    ///         buf.decode_be_to(&mut self.value)
    ///     }
    ///
    ///     fn decode_be_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B)
    ///         -> Result<(), DecodeError>
    ///     {
    ///         let values: &mut [u32] = bytemuck::cast_slice_mut(slice);
    ///         buf.decode_be_to(values)
    ///     }
    /// }
    ///
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    /// let ex: [Example; 2] = buf.decode_be().unwrap();
    /// assert_eq!(ex[0].value, 0x01020304);
    /// assert_eq!(ex[1].value, 0x05060708);
    /// assert_eq!(buf, &[9, 10, 11, 12]);
    /// ```
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

/// Trait that allows a type to be decoded as little endian from a buffer.
///
/// Generally, a type that implements [`DecodeLe`] will also implement [`DecodeBe`] so
/// that the user can choose to decode as big or little endian as needed. If there
/// is only one valid endianness to decode as, the type should instead implement
/// [`Decode`].
pub trait DecodeLe {
    /// Implements parsing a portion of a buffer onto a object as little endian.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeLe, DecodeBuf, DecodeError};
    /// #[derive(Clone, Copy, Debug, Default)]
    /// struct Example {
    ///     value: u32,
    /// }
    ///
    /// impl DecodeLe for Example {
    ///     fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
    ///         buf.decode_le_to(&mut self.value)
    ///     }
    /// }
    ///
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    /// let ex: Example = buf.decode_le().unwrap();
    /// assert_eq!(ex.value, 0x04030201);
    /// assert_eq!(buf, &[5, 6, 7, 8]);
    /// ```
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()>;

    /// Implements parsing a portion of a buffer onto a slices of objects as little endian.
    ///
    /// The implementer may choose to provide their own implementation of this
    /// function when a more effcient solution exists. By default this function
    /// simply iterates through the slice and decodes items one-by-one. In many
    /// cases, a slice can be decoded in bulk using `unsafe` code or using
    /// utilities like the [`bytemuck`] crate.
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::decode::{DecodeLe, DecodeBuf, DecodeError};
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
    /// impl DecodeLe for Example {
    ///     fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<(), DecodeError> {
    ///         buf.decode_le_to(&mut self.value)
    ///     }
    ///
    ///     fn decode_le_slice<B: DecodeBuf>(slice: &mut [Self], buf: &mut B)
    ///         -> Result<(), DecodeError>
    ///     {
    ///         let values: &mut [u32] = bytemuck::cast_slice_mut(slice);
    ///         buf.decode_le_to(values)
    ///     }
    /// }
    ///
    /// let mut buf: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    /// let ex: [Example; 2] = buf.decode_le().unwrap();
    /// assert_eq!(ex[0].value, 0x04030201);
    /// assert_eq!(ex[1].value, 0x08070605);
    /// assert_eq!(buf, &[9, 10, 11, 12]);
    /// ```
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
where
    T: Pack,
    <T as Pack>::Packed: Decode + Default,
{
    fn decode<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        *self = Self::unpack_from(buf.decode()?);
        Ok(())
    }
}

impl<T> DecodeBe for T
where
    T: Pack,
    <T as Pack>::Packed: DecodeBe + Default,
{
    fn decode_be<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        *self = Self::unpack_from(buf.decode_be()?);
        Ok(())
    }
}

impl<T> DecodeLe for T
where
    T: Pack,
    <T as Pack>::Packed: DecodeLe + Default,
{
    fn decode_le<B: DecodeBuf>(&mut self, buf: &mut B) -> Result<()> {
        *self = Self::unpack_from(buf.decode_le()?);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pack::Pack;
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
        let mut buf: &[u8] = &bytes!(
            "
            82       # a == 130
            82       # b == -126
            01020304 # c == 16909060
            04030280 # d == -2147351804
            01020304 # f == [1, 2, 3, 4]
            feff0001 # g == [-2, -1, 0, 1]
            01020304 # h == [513, 1027]
            01020304 # i == [258, 772]
        "
        );

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

    #[derive(Pack, Default, Debug, PartialEq, Eq)]
    struct Ipv4VerLen {
        version: U4,
        length: U4,
    }

    #[derive(Pack, Default, Debug, PartialEq, Eq)]
    struct Ipv4DscpEcn {
        dscp: U6,
        ecn: U2,
    }

    #[derive(Pack, Default, Debug, PartialEq, Eq)]
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
        let mut buf: &[u8] = &bytes!(
            "
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
        "
        );

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
