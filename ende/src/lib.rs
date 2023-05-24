#![recursion_limit = "256"]

//! This crate provides utilities for encoding and decoding formatted binary
//! data. Unlike `serde`, this crate does not allow serialization of arbitrary
//! types with arbitrary encodings. Instead it is intended for implementing
//! a specific binary format for a specific type. This crate's main purpose
//! is to support the `sniffle` crate, which implements reading and writing
//! raw network traffic.
//!
//! # Motivating example:
//! ```
//! # use sniffle_uint::*;
//! # use sniffle_ende::{
//! #     pack::Pack,
//! #     encode::{Encode, EncodeBuf},
//! #     decode::{Decode, DecodeBuf, DecodeError}
//! # };
//! // use sniffle::uint::*;
//! // use sniffle::encode::{Encode, EncodeBuf};
//! // use sniffle::decode::{Decode, DecodeBuf, DecodeError};
//!
//! // Implementation of the IPv4 datagram header (without IPv4 options)
//! #[derive(Decode, Encode, Debug, Default, PartialEq, Eq)]
//! struct Ipv4Header {
//!     ver_len: Ipv4VerLen,
//!     dscp_ecn: Ipv4DscpEcn,
//!     #[big] // <- decode and encode field as big endian
//!     total_len: u16,
//!     #[big]
//!     ident: u16,
//!     #[big]
//!     flags_frag_offset: Ipv4FlagsFragOff,
//!     ttl: u8,
//!     protocol: u8,
//!     #[big]
//!     chksum: u16,
//!     src_addr: [u8; 4],
//!     dst_addr: [u8; 4],
//! }
//!
//! // Bit fields for IPv4 header version and length
//! #[derive(Pack, Clone, Default, Debug, PartialEq, Eq)]
//! struct Ipv4VerLen {
//!     version: U4, // <- 4-bit field
//!     length: U4,  // <- 4-bit field
//! }
//!
//! // Bit fields for IPv4 header DSCP and ECN
//! #[derive(Pack, Clone, Default, Debug, PartialEq, Eq)]
//! struct Ipv4DscpEcn {
//!     dscp: U6, // <- 6-bit field
//!     ecn: U2,  // <- 2-bit field
//! }
//!
//! // Bit fields for IPv4 header flags and fragment offset
//! #[derive(Pack, Clone, Default, Debug, PartialEq, Eq)]
//! struct Ipv4FlagsFragOff {
//!     flags: U3,        // <- 3-bit field
//!     frag_offset: U13, // <- 13-bit field
//! }
//!
//! let buffer = [
//!     0x45,                    // version == 4, length == 5
//!     0x00,                    // dscp == 0, ecn == 0
//!     0x00, 0x14,              // total_len == 20
//!     0x12, 0x34,              // ident = 0x1234
//!     0x40, 0x00,              // flags == 2, frag_offset == 0
//!     0x80,                    // ttl == 128
//!     0xfe,                    // protocol = 0xfe
//!     0x43, 0x21,              // chksum == 0x4321
//!     0xc0, 0xa8, 0x00, 0x01,  // src_addr == 192.168.0.1
//!     0xc0, 0xa8, 0x00, 0x02,  // dst_addr == 192.168.0.2
//! ];
//!
//! let mut buf: &[u8] = &buffer;
//! let header: Ipv4Header = buf.decode().unwrap();
//! assert_eq!(header, Ipv4Header {
//!     ver_len: Ipv4VerLen {
//!         version: 4.into_masked(),
//!         length: 5.into_masked(),
//!     },
//!     dscp_ecn: Ipv4DscpEcn {
//!         dscp: 0.into_masked(),
//!         ecn: 0.into_masked(),
//!     },
//!     total_len: 20,
//!     ident: 0x1234,
//!     flags_frag_offset: Ipv4FlagsFragOff {
//!         flags: 2.into_masked(),
//!         frag_offset: 0.into_masked(),
//!     },
//!     ttl: 128,
//!     protocol: 0xfe,
//!     chksum: 0x4321,
//!     src_addr: [192, 168, 0, 1],
//!     dst_addr: [192, 168, 0, 2],
//! });
//!
//! let mut new_buffer = [0u8; 20];
//! let mut buf: &mut [u8] = &mut new_buffer;
//! buf.encode(&header);
//! assert_eq!(new_buffer, buffer);
//! ```

extern crate self as sniffle_ende;

pub mod decode;
pub mod encode;
pub mod pack;
