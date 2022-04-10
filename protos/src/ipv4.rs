use super::ip_proto::IPProto;
use crate::prelude::*;
use checksum::U16OnesComplement;
use chrono::{offset::Utc, DateTime};
use nom::{
    combinator::{all_consuming, consumed, flat_map, map, rest},
    multi::{fold_many0, length_value, many0},
    sequence::tuple,
    Parser,
};
use sniffle_core::IPv4Address;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct IPv4 {
    base: BasePDU,
    version: uint::U4,
    ihl: uint::U4,
    dscp: uint::U6,
    ecn: uint::U2,
    totlen: u16,
    ident: u16,
    flags: uint::U3,
    frag_offset: uint::U13,
    ttl: u8,
    proto: IPProto,
    chksum: u16,
    src_addr: IPv4Address,
    dst_addr: IPv4Address,
    opts: Vec<Opt>,
    padding: Padding,
}

#[derive(Debug, Clone)]
enum Padding {
    Auto,
    Manual(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum OptionType {
    Eool,
    Nop,
    Sec,
    Lsrr,
    Ts,
    ESec,
    Cipso,
    Rr,
    Sid,
    Ssrr,
    Zsu,
    Mtup,
    Mtur,
    Finn,
    Visa,
    Encode,
    Imitd,
    Eip,
    Tr,
    AddExt,
    RtrAlt,
    Sdb,
    Dps,
    Ump,
    Qs,
    Unspecified(u8),
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum OptionClass {
    Control,
    DebugMeas,
    Reserved(uint::U2),
}

#[derive(Clone, Debug)]
pub struct RawOption {
    pub opt_type: OptionType,
    pub len: Option<u8>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RouteRecord {
    pub pointer: u8,
    pub routes: Vec<IPv4Address>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct StreamId(pub u16);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum TimestampFlag {
    TsOnly,
    AddrAndTs,
    PrespecifiedAddrs,
    Unknown(uint::U4),
}

#[derive(Clone, Copy, Debug)]
pub enum TimestampEntry {
    Ts(SystemTime),
    Addr(IPv4Address),
}

#[derive(Clone, Debug)]
pub struct Timestamp {
    pub pointer: u8,
    pub overflow: uint::U4,
    pub flag: TimestampFlag,
    pub entries: Vec<TimestampEntry>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Classification {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
    Unspecified(u8),
}

#[derive(Clone, Debug)]
pub struct BasicSecurity {
    pub classification: Classification,
    pub authority: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ExtendedSecurity {
    pub format: u8,
    pub sec_info: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MTU(pub u16);

#[derive(Clone, Debug)]
pub struct Traceroute {
    pub id: u16,
    pub out_hops: u16,
    pub return_hops: u16,
    pub orig_addr: IPv4Address,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct RouterAlert(pub u16);

#[derive(Clone, Debug)]
pub struct QuickStart {
    pub func: uint::U4,
    pub rate_req: uint::U4,
    pub ttl: u8,
    pub nonce: uint::U30,
    pub reserved: uint::U2,
}

#[derive(Clone, Debug)]
pub enum Opt {
    Eool,
    Nop,
    Sec(BasicSecurity),
    Lsrr(RouteRecord),
    Ts(Timestamp),
    ESec(ExtendedSecurity),
    Cipso(Vec<u8>),
    Rr(RouteRecord),
    Sid(StreamId),
    Ssrr(RouteRecord),
    Zsu(Vec<u8>),
    Mtup(MTU),
    Mtur(MTU),
    Finn(Vec<u8>),
    Visa(Vec<u8>),
    Encode(Vec<u8>),
    Imitd(Vec<u8>),
    Eip(Vec<u8>),
    Tr(Traceroute),
    AddExt(Vec<u8>),
    RtrAlt(RouterAlert),
    Sdb(Vec<u8>),
    Dps(Vec<u8>),
    Ump(Vec<u8>),
    Qs(QuickStart),
    Raw(RawOption),
}

impl From<uint::U2> for OptionClass {
    fn from(val: uint::U2) -> Self {
        let num: u8 = val.into();
        match num {
            0 => OptionClass::DebugMeas,
            2 => OptionClass::Control,
            _ => OptionClass::Reserved(val),
        }
    }
}

impl From<OptionClass> for uint::U2 {
    fn from(class: OptionClass) -> Self {
        match class {
            OptionClass::DebugMeas => 0.into_masked(),
            OptionClass::Control => 2.into_masked(),
            OptionClass::Reserved(val) => val,
        }
    }
}

impl OptionType {
    pub fn new(copied: bool, class: OptionClass, number: uint::U5) -> Self {
        let copied: u8 = if copied { 0x80 } else { 0 };
        let class: u8 = u8::from(uint::U2::from(class)) << 5;
        let number: u8 = number.into();
        Self::from(copied | class | number)
    }

    pub fn copied(&self) -> bool {
        use OptionType::*;

        match *self {
            Eool | Nop | Ts | Rr | Zsu | Mtup | Mtur | Encode | Tr | Qs => false,
            Unspecified(val) => (val & 0x80) > 0,
            _ => true,
        }
    }

    pub fn class(&self) -> OptionClass {
        use OptionType::*;

        match *self {
            Ts | Finn | Tr => OptionClass::Control,
            Unspecified(val) => {
                let class = (val & 0b0110_0000) >> 5;
                match class {
                    0 => OptionClass::DebugMeas,
                    2 => OptionClass::Control,
                    _ => OptionClass::Reserved(class.into_masked()),
                }
            }
            _ => OptionClass::DebugMeas,
        }
    }

    pub fn number(&self) -> uint::U5 {
        use OptionType::*;
        match *self {
            Eool => 0,
            Nop => 1,
            Sec => 2,
            Lsrr => 3,
            Ts => 4,
            ESec => 5,
            Cipso => 6,
            Rr => 7,
            Sid => 8,
            Ssrr => 9,
            Zsu => 10,
            Mtup => 11,
            Mtur => 12,
            Finn => 13,
            Visa => 14,
            Encode => 15,
            Imitd => 16,
            Eip => 17,
            Tr => 18,
            AddExt => 19,
            RtrAlt => 20,
            Sdb => 21,
            Dps => 23,
            Ump => 24,
            Qs => 25,
            Unspecified(val) => val,
        }
        .into_masked()
    }

    pub fn octet(&self) -> u8 {
        use OptionType::*;
        match *self {
            Eool => 0,
            Nop => 1,
            Sec => 130,
            Lsrr => 131,
            Ts => 68,
            ESec => 133,
            Cipso => 134,
            Rr => 7,
            Sid => 136,
            Ssrr => 137,
            Zsu => 10,
            Mtup => 11,
            Mtur => 12,
            Finn => 205,
            Visa => 142,
            Encode => 15,
            Imitd => 144,
            Eip => 145,
            Tr => 82,
            AddExt => 147,
            RtrAlt => 148,
            Sdb => 149,
            Dps => 151,
            Ump => 152,
            Qs => 25,
            Unspecified(val) => val,
        }
    }
}

impl From<u8> for OptionType {
    fn from(value: u8) -> Self {
        use OptionType::*;
        match value {
            0 => Eool,
            1 => Nop,
            130 => Sec,
            131 => Lsrr,
            68 => Ts,
            133 => ESec,
            134 => Cipso,
            7 => Rr,
            136 => Sid,
            137 => Ssrr,
            10 => Zsu,
            11 => Mtup,
            12 => Mtur,
            205 => Finn,
            142 => Visa,
            15 => Encode,
            144 => Imitd,
            145 => Eip,
            82 => Tr,
            147 => AddExt,
            148 => RtrAlt,
            149 => Sdb,
            151 => Dps,
            152 => Ump,
            25 => Qs,
            _ => Unspecified(value),
        }
    }
}

impl From<OptionType> for u8 {
    fn from(value: OptionType) -> Self {
        value.octet()
    }
}

impl From<u8> for Classification {
    fn from(val: u8) -> Self {
        use Classification::*;
        match val {
            0b00000001 => Reserved4,
            0b00111101 => TopSecret,
            0b01011010 => Secret,
            0b10010110 => Confidential,
            0b01100110 => Reserved3,
            0b11001100 => Reserved2,
            0b10101011 => Unclassified,
            0b11110001 => Reserved1,
            _ => Unspecified(val),
        }
    }
}

impl From<Classification> for u8 {
    fn from(val: Classification) -> u8 {
        use Classification::*;
        match val {
            Unclassified => 0b10101011,
            Confidential => 0b10010110,
            Secret => 0b01011010,
            TopSecret => 0b00111101,
            Reserved1 => 0b11110001,
            Reserved2 => 0b11001100,
            Reserved3 => 0b01100110,
            Reserved4 => 0b00000001,
            Unspecified(val) => val,
        }
    }
}

impl From<uint::U4> for TimestampFlag {
    fn from(val: uint::U4) -> Self {
        let num: u8 = val.into();
        match num {
            0 => TimestampFlag::TsOnly,
            1 => TimestampFlag::AddrAndTs,
            3 => TimestampFlag::PrespecifiedAddrs,
            _ => TimestampFlag::Unknown(val),
        }
    }
}

impl From<TimestampFlag> for uint::U4 {
    fn from(val: TimestampFlag) -> Self {
        match val {
            TimestampFlag::TsOnly => 0.into_masked(),
            TimestampFlag::AddrAndTs => 1.into_masked(),
            TimestampFlag::PrespecifiedAddrs => 3.into_masked(),
            TimestampFlag::Unknown(val) => val,
        }
    }
}

fn serialize_basic_security<'a, E: Encoder<'a> + ?Sized>(
    opt: &BasicSecurity,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder
        .encode(&u8::from(opt.classification))?
        .encode(&opt.authority[..])?;
    Ok(())
}

fn serialize_route_record<'a, E: Encoder<'a> + ?Sized>(
    opt: &RouteRecord,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder.encode(&opt.pointer)?.encode(&opt.routes[..])?;
    Ok(())
}

fn serialize_timestamp<'a, E: Encoder<'a> + ?Sized>(
    opt: &Timestamp,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder
        .encode(&opt.pointer)?
        .encode(&uint::pack!(opt.overflow, uint::U4::from(opt.flag)))?;
    for entry in opt.entries.iter() {
        match entry {
            TimestampEntry::Ts(ts) => {
                encoder.encode_be(
                    &(ts.duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u32),
                )?;
            }
            TimestampEntry::Addr(addr) => {
                encoder.encode(addr)?;
            }
        }
    }
    Ok(())
}

fn serialize_extended_security<'a, E: Encoder<'a> + ?Sized>(
    opt: &ExtendedSecurity,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder.encode(&opt.format)?.encode(&opt.sec_info[..])?;
    Ok(())
}

fn serialize_traceroute<'a, E: Encoder<'a> + ?Sized>(
    opt: &Traceroute,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder
        .encode_be(&opt.id)?
        .encode_be(&opt.out_hops)?
        .encode_be(&opt.return_hops)?
        .encode(&opt.orig_addr)?;
    Ok(())
}

fn serialize_quick_start<'a, E: Encoder<'a> + ?Sized>(
    opt: &QuickStart,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder
        .encode(&uint::pack!(opt.func, opt.rate_req))?
        .encode(&opt.ttl)?
        .encode_be(&uint::pack!(opt.nonce, opt.reserved))?;
    Ok(())
}

fn dissect_body<F: for<'a> FnMut(&'a [u8]) -> DResult<'a, Opt>>(
    buf: &[u8],
    opt_type: OptionType,
    f: F,
) -> DResult<'_, Opt> {
    length_value(u8::decode, all_consuming(f))
        .or(move |buf| dissect_raw(buf, opt_type))
        .parse(buf)
}

fn dissect_sec(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Sec, |buf| {
        u8::decode
            .map(Classification::from)
            .and(rest.map(Vec::from))
            .map(|(classification, authority)| {
                Opt::Sec(BasicSecurity {
                    classification,
                    authority,
                })
            })
            .parse(buf)
    })
}

fn dissect_lsrr(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Lsrr, |buf| {
        u8::decode
            .and(many0(IPv4Address::decode))
            .map(|(pointer, routes)| Opt::Lsrr(RouteRecord { pointer, routes }))
            .parse(buf)
    })
}

fn dissect_ts(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Ts, |buf| {
        flat_map(tuple((u8::decode, u8::decode)), |(pointer, of)| {
            let (overflow, flag): (uint::U4, uint::U4) = uint::unpack!(of);
            let flag = TimestampFlag::from(flag);
            all_consuming(move |buf| match flag {
                TimestampFlag::TsOnly | TimestampFlag::Unknown(_) => fold_many0(
                    u32::decode_be.map(|ts| {
                        SystemTime::UNIX_EPOCH
                            .checked_add(Duration::from_millis(ts as u64))
                            .unwrap()
                    }),
                    Vec::new,
                    |mut acc: Vec<_>, ts| {
                        acc.push(TimestampEntry::Ts(ts));
                        acc
                    },
                )(buf),
                TimestampFlag::AddrAndTs | TimestampFlag::PrespecifiedAddrs => {
                    fold_many0(
                        (IPv4Address::decode).and(u32::decode_be.map(|ts| {
                            SystemTime::UNIX_EPOCH
                                .checked_add(Duration::from_millis(ts as u64))
                                .unwrap()
                        })),
                        Vec::new,
                        |mut acc: Vec<_>, (addr, ts)| {
                            acc.push(TimestampEntry::Addr(addr));
                            acc.push(TimestampEntry::Ts(ts));
                            acc
                        },
                    )(buf)
                }
            })
            .map(move |entries| {
                Opt::Ts(Timestamp {
                    pointer,
                    overflow,
                    flag,
                    entries,
                })
            })
        })(buf)
    })
}

fn dissect_esec(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::ESec, |buf| {
        map(
            tuple((u8::decode, map(rest, Vec::from))),
            |(format, sec_info)| Opt::ESec(ExtendedSecurity { format, sec_info }),
        )(buf)
    })
}

fn dissect_cipso(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Cipso, |buf| {
        map(rest, |data| Opt::Cipso(Vec::from(data)))(buf)
    })
}

fn dissect_rr(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Rr, |buf| {
        u8::decode
            .and(many0(IPv4Address::decode))
            .map(|(pointer, routes)| Opt::Rr(RouteRecord { pointer, routes }))
            .parse(buf)
    })
}

fn dissect_sid(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Sid, |buf| {
        map(u16::decode_be, |sid| Opt::Sid(StreamId(sid)))(buf)
    })
}

fn dissect_ssrr(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Ssrr, |buf| {
        u8::decode
            .and(many0(IPv4Address::decode))
            .map(|(pointer, routes)| Opt::Ssrr(RouteRecord { pointer, routes }))
            .parse(buf)
    })
}

fn dissect_zsu(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Zsu, |buf| {
        map(rest, |data| Opt::Zsu(Vec::from(data)))(buf)
    })
}

fn dissect_mtup(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Mtup, |buf| {
        map(u16::decode_be, |sid| Opt::Mtup(MTU(sid)))(buf)
    })
}

fn dissect_mtur(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Mtur, |buf| {
        map(u16::decode_be, |sid| Opt::Mtur(MTU(sid)))(buf)
    })
}

fn dissect_finn(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Finn, |buf| {
        map(rest, |data| Opt::Finn(Vec::from(data)))(buf)
    })
}

fn dissect_visa(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Visa, |buf| {
        map(rest, |data| Opt::Visa(Vec::from(data)))(buf)
    })
}

fn dissect_encode(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Encode, |buf| {
        map(rest, |data| Opt::Encode(Vec::from(data)))(buf)
    })
}

fn dissect_imitd(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Imitd, |buf| {
        map(rest, |data| Opt::Imitd(Vec::from(data)))(buf)
    })
}

fn dissect_eip(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Eip, |buf| {
        map(rest, |data| Opt::Eip(Vec::from(data)))(buf)
    })
}

fn dissect_tr(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Tr, |buf| {
        map(
            tuple((
                u16::decode_be,
                u16::decode_be,
                u16::decode_be,
                IPv4Address::decode,
            )),
            |(id, out_hops, return_hops, orig_addr)| {
                Opt::Tr(Traceroute {
                    id,
                    out_hops,
                    return_hops,
                    orig_addr,
                })
            },
        )(buf)
    })
}

fn dissect_addext(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::AddExt, |buf| {
        map(rest, |data| Opt::AddExt(Vec::from(data)))(buf)
    })
}

fn dissect_rtralt(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::RtrAlt, |buf| {
        map(u16::decode_be, |ra| Opt::RtrAlt(RouterAlert(ra)))(buf)
    })
}

fn dissect_sdb(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Sdb, |buf| {
        map(rest, |data| Opt::Sdb(Vec::from(data)))(buf)
    })
}

fn dissect_dps(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Dps, |buf| {
        map(rest, |data| Opt::Dps(Vec::from(data)))(buf)
    })
}

fn dissect_ump(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Ump, |buf| {
        map(rest, |data| Opt::Ump(Vec::from(data)))(buf)
    })
}

fn dissect_qs(buf: &[u8]) -> DResult<'_, Opt> {
    dissect_body(buf, OptionType::Qs, |buf| {
        map(
            tuple((u8::decode, u8::decode, u32::decode_be)),
            |(frr, ttl, nr)| {
                let (func, rate_req): (uint::U4, uint::U4) = uint::unpack!(frr);
                let (nonce, reserved): (uint::U30, uint::U2) = uint::unpack!(nr);
                Opt::Qs(QuickStart {
                    func,
                    rate_req,
                    ttl,
                    nonce,
                    reserved,
                })
            },
        )(buf)
    })
}

fn dissect_raw(buf: &[u8], opt_type: OptionType) -> DResult<'_, Opt> {
    if buf.is_empty() {
        Ok((
            buf,
            Opt::Raw(RawOption {
                opt_type,
                len: None,
                data: Vec::new(),
            }),
        ))
    } else {
        u8::decode
            .and(rest)
            .map(move |(len, data)| {
                Opt::Raw(RawOption {
                    opt_type,
                    len: Some(len),
                    data: Vec::from(data),
                })
            })
            .parse(buf)
    }
}

impl Opt {
    pub fn dissect(buf: &[u8]) -> DResult<'_, Self> {
        flat_map(map(u8::decode, OptionType::from), |opt_type| {
            move |buf| match opt_type {
                OptionType::Eool => Ok((buf, Opt::Eool)),
                OptionType::Nop => Ok((buf, Opt::Nop)),
                OptionType::Sec => dissect_sec(buf),
                OptionType::Lsrr => dissect_lsrr(buf),
                OptionType::Ts => dissect_ts(buf),
                OptionType::ESec => dissect_esec(buf),
                OptionType::Cipso => dissect_cipso(buf),
                OptionType::Rr => dissect_rr(buf),
                OptionType::Sid => dissect_sid(buf),
                OptionType::Ssrr => dissect_ssrr(buf),
                OptionType::Zsu => dissect_zsu(buf),
                OptionType::Mtup => dissect_mtup(buf),
                OptionType::Mtur => dissect_mtur(buf),
                OptionType::Finn => dissect_finn(buf),
                OptionType::Visa => dissect_visa(buf),
                OptionType::Encode => dissect_encode(buf),
                OptionType::Imitd => dissect_imitd(buf),
                OptionType::Eip => dissect_eip(buf),
                OptionType::Tr => dissect_tr(buf),
                OptionType::AddExt => dissect_addext(buf),
                OptionType::RtrAlt => dissect_rtralt(buf),
                OptionType::Sdb => dissect_sdb(buf),
                OptionType::Dps => dissect_dps(buf),
                OptionType::Ump => dissect_ump(buf),
                OptionType::Qs => dissect_qs(buf),
                OptionType::Unspecified(opt_type) => {
                    dissect_raw(buf, OptionType::Unspecified(opt_type))
                }
            }
        })(buf)
    }

    fn serialize_data<'a, E: Encoder<'a> + ?Sized>(&self, encoder: &mut E) -> std::io::Result<()> {
        use Opt::*;
        match self {
            Sec(opt) => serialize_basic_security(opt, encoder)?,
            Lsrr(opt) => serialize_route_record(opt, encoder)?,
            Ts(opt) => serialize_timestamp(opt, encoder)?,
            ESec(opt) => serialize_extended_security(opt, encoder)?,
            Cipso(opt) => {
                encoder.encode(&opt[..])?;
            }
            Rr(opt) => serialize_route_record(opt, encoder)?,
            Sid(opt) => {
                encoder.encode_be(&opt.0)?;
            }
            Ssrr(opt) => serialize_route_record(opt, encoder)?,
            Zsu(opt) => {
                encoder.encode(&opt[..])?;
            }
            Mtup(opt) => {
                encoder.encode_be(&opt.0)?;
            }
            Mtur(opt) => {
                encoder.encode_be(&opt.0)?;
            }
            Finn(opt) => {
                encoder.encode(&opt[..])?;
            }
            Visa(opt) => {
                encoder.encode(&opt[..])?;
            }
            Encode(opt) => {
                encoder.encode(&opt[..])?;
            }
            Imitd(opt) => {
                encoder.encode(&opt[..])?;
            }
            Eip(opt) => {
                encoder.encode(&opt[..])?;
            }
            Tr(opt) => serialize_traceroute(opt, encoder)?,
            AddExt(opt) => {
                encoder.encode(&opt[..])?;
            }
            RtrAlt(opt) => {
                encoder.encode_be(&opt.0)?;
            }
            Sdb(opt) => {
                encoder.encode(&opt[..])?;
            }
            Dps(opt) => {
                encoder.encode(&opt[..])?;
            }
            Ump(opt) => {
                encoder.encode(&opt[..])?;
            }
            Qs(opt) => serialize_quick_start(opt, encoder)?,
            _ => (),
        }
        Ok(())
    }

    pub fn serialize<'a, E: Encoder<'a> + ?Sized>(&self, encoder: &mut E) -> std::io::Result<()> {
        if let Opt::Raw(raw) = self {
            encoder.encode(&raw.opt_type.octet())?;
            if let Some(len) = raw.len {
                encoder.encode(&len)?;
            }
            encoder.encode(&raw.data[..])?;
        } else {
            encoder.encode(&self.option_type().octet())?;
            if let Some(len) = self.length() {
                encoder.encode(&len)?;
                self.serialize_data(encoder)?;
            }
        }
        Ok(())
    }

    pub fn to_raw(&self) -> RawOption {
        if let Opt::Raw(raw) = self {
            raw.clone()
        } else if let Some(len) = self.length() {
            let mut data = Vec::new();
            self.serialize_data(&mut data).unwrap();
            RawOption {
                opt_type: self.option_type(),
                len: Some(len),
                data,
            }
        } else {
            RawOption {
                opt_type: self.option_type(),
                len: None,
                data: Vec::new(),
            }
        }
    }

    pub fn option_type(&self) -> OptionType {
        use Opt::*;
        match self {
            Eool => OptionType::Eool,
            Nop => OptionType::Nop,
            Sec(_) => OptionType::Sec,
            Lsrr(_) => OptionType::Lsrr,
            Ts(_) => OptionType::Ts,
            ESec(_) => OptionType::ESec,
            Cipso(_) => OptionType::Cipso,
            Rr(_) => OptionType::Rr,
            Sid(_) => OptionType::Sid,
            Ssrr(_) => OptionType::Ssrr,
            Zsu(_) => OptionType::Zsu,
            Mtup(_) => OptionType::Mtup,
            Mtur(_) => OptionType::Mtur,
            Finn(_) => OptionType::Finn,
            Visa(_) => OptionType::Visa,
            Encode(_) => OptionType::Encode,
            Imitd(_) => OptionType::Imitd,
            Eip(_) => OptionType::Eip,
            Tr(_) => OptionType::Tr,
            AddExt(_) => OptionType::AddExt,
            RtrAlt(_) => OptionType::RtrAlt,
            Sdb(_) => OptionType::Sdb,
            Dps(_) => OptionType::Dps,
            Ump(_) => OptionType::Ump,
            Qs(_) => OptionType::Qs,
            Raw(opt) => opt.opt_type,
        }
    }

    pub fn length(&self) -> Option<u8> {
        use Opt::*;
        match self {
            Eool => None,
            Nop => None,
            Sec(opt) => Some(1 + opt.authority.len()),
            Lsrr(opt) => Some(1 + opt.routes.len() * 4),
            Ts(opt) => Some(2 + opt.entries.len() * 4),
            ESec(opt) => Some(1 + opt.sec_info.len()),
            Cipso(opt) => Some(opt.len()),
            Rr(opt) => Some(1 + opt.routes.len()),
            Sid(_) => Some(2),
            Ssrr(opt) => Some(1 + opt.routes.len()),
            Zsu(opt) => Some(opt.len()),
            Mtup(_) => Some(2),
            Mtur(_) => Some(2),
            Finn(opt) => Some(opt.len()),
            Visa(opt) => Some(opt.len()),
            Encode(opt) => Some(opt.len()),
            Imitd(opt) => Some(opt.len()),
            Eip(opt) => Some(opt.len()),
            Tr(_) => Some(10),
            AddExt(opt) => Some(opt.len()),
            RtrAlt(_) => Some(2),
            Sdb(opt) => Some(opt.len()),
            Dps(opt) => Some(opt.len()),
            Ump(opt) => Some(opt.len()),
            Qs(_) => Some(6),
            Raw(opt) => {
                return opt.len;
            }
        }
        .map(|len| if len > 253 { 255u8 } else { (len + 2) as u8 })
    }

    pub fn actual_length(&self) -> usize {
        use Opt::*;
        match self {
            Eool => None,
            Nop => None,
            Sec(opt) => Some(1 + opt.authority.len()),
            Lsrr(opt) => Some(1 + opt.routes.len() * 4),
            Ts(opt) => Some(2 + opt.entries.len() * 4),
            ESec(opt) => Some(1 + opt.sec_info.len()),
            Cipso(opt) => Some(opt.len()),
            Rr(opt) => Some(1 + opt.routes.len()),
            Sid(_) => Some(2),
            Ssrr(opt) => Some(1 + opt.routes.len()),
            Zsu(opt) => Some(opt.len()),
            Mtup(_) => Some(2),
            Mtur(_) => Some(2),
            Finn(opt) => Some(opt.len()),
            Visa(opt) => Some(opt.len()),
            Encode(opt) => Some(opt.len()),
            Imitd(opt) => Some(opt.len()),
            Eip(opt) => Some(opt.len()),
            Tr(_) => Some(10),
            AddExt(opt) => Some(opt.len()),
            RtrAlt(_) => Some(2),
            Sdb(opt) => Some(opt.len()),
            Dps(opt) => Some(opt.len()),
            Ump(opt) => Some(opt.len()),
            Qs(_) => Some(6),
            Raw(opt) => {
                return if opt.data.is_empty() && opt.len.is_none() {
                    1usize
                } else {
                    2 + opt.data.len()
                };
            }
        }
        .map(|len| len + 2)
        .unwrap_or(1usize)
    }
}

dissector_table!(pub IPProtoDissectorTable, IPProto);
dissector_table!(pub HeurDissectorTable);

const PADDING: [u8; 3] = [0u8; 3];

impl IPv4 {
    pub fn new() -> Self {
        Self {
            base: Default::default(),
            version: Default::default(),
            ihl: Default::default(),
            dscp: Default::default(),
            ecn: Default::default(),
            totlen: Default::default(),
            ident: Default::default(),
            flags: Default::default(),
            frag_offset: Default::default(),
            ttl: Default::default(),
            proto: IPProto::RESERVED,
            chksum: Default::default(),
            src_addr: Default::default(),
            dst_addr: Default::default(),
            opts: Vec::new(),
            padding: Padding::Auto,
        }
    }

    pub fn with_addresses(src_addr: IPv4Address, dst_addr: IPv4Address) -> Self {
        Self {
            base: Default::default(),
            version: Default::default(),
            ihl: Default::default(),
            dscp: Default::default(),
            ecn: Default::default(),
            totlen: Default::default(),
            ident: Default::default(),
            flags: Default::default(),
            frag_offset: Default::default(),
            ttl: Default::default(),
            proto: IPProto::RESERVED,
            chksum: Default::default(),
            src_addr,
            dst_addr,
            opts: Vec::new(),
            padding: Padding::Auto,
        }
    }

    pub fn version(&self) -> uint::U4 {
        self.version
    }

    pub fn version_mut(&mut self) -> &mut uint::U4 {
        &mut self.version
    }

    pub fn ihl(&self) -> uint::U4 {
        self.ihl
    }

    pub fn ihl_mut(&mut self) -> &mut uint::U4 {
        &mut self.ihl
    }

    pub fn dscp(&self) -> uint::U6 {
        self.dscp
    }

    pub fn dscp_mut(&mut self) -> &mut uint::U6 {
        &mut self.dscp
    }

    pub fn ecn(&self) -> uint::U2 {
        self.ecn
    }

    pub fn ecn_mut(&mut self) -> &mut uint::U2 {
        &mut self.ecn
    }

    pub fn totlen(&self) -> u16 {
        self.totlen
    }

    pub fn totlen_mut(&mut self) -> &mut u16 {
        &mut self.totlen
    }

    pub fn identifier(&self) -> u16 {
        self.ident
    }

    pub fn identifier_mut(&mut self) -> &mut u16 {
        &mut self.ident
    }

    pub fn flags(&self) -> uint::U3 {
        self.flags
    }

    pub fn flags_mut(&mut self) -> &mut uint::U3 {
        &mut self.flags
    }

    pub fn fragment_offset(&self) -> uint::U13 {
        self.frag_offset
    }

    pub fn fragment_offset_mut(&mut self) -> &mut uint::U13 {
        &mut self.frag_offset
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn ttl_mut(&mut self) -> &mut u8 {
        &mut self.ttl
    }

    pub fn proto(&self) -> IPProto {
        self.proto
    }

    pub fn proto_mut(&mut self) -> &mut IPProto {
        &mut self.proto
    }

    pub fn update_proto(&mut self) -> IPProto {
        // TODO
        self.proto
    }

    pub fn checksum(&self) -> u16 {
        self.chksum
    }

    pub fn checksum_mut(&mut self) -> &mut u16 {
        &mut self.chksum
    }

    pub fn update_checksum(&mut self) -> u16 {
        let mut acc = U16OnesComplement::new();
        self.chksum = 0;
        let _ = self.serialize_header(&mut acc);
        self.chksum = acc.checksum();
        self.chksum
    }

    pub fn src_address(&self) -> IPv4Address {
        self.src_addr
    }

    pub fn src_address_mut(&mut self) -> &mut IPv4Address {
        &mut self.src_addr
    }

    pub fn dst_address(&self) -> IPv4Address {
        self.dst_addr
    }

    pub fn dst_address_mut(&mut self) -> &mut IPv4Address {
        &mut self.dst_addr
    }

    pub fn options(&self) -> &[Opt] {
        &self.opts[..]
    }

    pub fn options_mut(&mut self) -> &mut Vec<Opt> {
        &mut self.opts
    }

    fn opts_len(&self) -> usize {
        let mut len = 0usize;
        for opt in self.opts.iter() {
            len += opt.actual_length();
        }
        len
    }

    fn auto_padding_len(&self) -> usize {
        let reported_len = (u32::from(self.ihl) * 4) as usize;
        let opts_len = self.opts_len();
        if reported_len < 20 + opts_len {
            0
        } else {
            reported_len - 20 - opts_len
        }
    }

    pub fn padding(&self) -> &[u8] {
        match &self.padding {
            Padding::Auto => &PADDING[..self.auto_padding_len()],
            Padding::Manual(padding) => &padding[..],
        }
    }

    pub fn padding_mut(&mut self) -> &mut Vec<u8> {
        let padding = match &mut self.padding {
            Padding::Auto => vec![0u8; self.auto_padding_len()],
            Padding::Manual(padding) => std::mem::take(padding),
        };
        self.padding = Padding::Manual(padding);
        match &mut self.padding {
            Padding::Manual(padding) => padding,
            _ => unreachable!(),
        }
    }
}

impl Dissect for IPv4 {
    fn dissect<'a>(
        buf: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self> {
        map(
            tuple((
                consumed(flat_map(
                    tuple((
                        u8::decode,
                        u8::decode,
                        u16::decode_be,
                        u16::decode_be,
                        u16::decode_be,
                        u8::decode,
                        u8::decode,
                        u16::decode_be,
                        IPv4Address::decode,
                        IPv4Address::decode,
                    )),
                    move |(vi, de, totlen, ident, ff, ttl, proto, chksum, src_addr, dst_addr)| {
                        let (version, ihl): (uint::U4, uint::U4) = uint::unpack!(vi);
                        let (dscp, ecn): (uint::U6, uint::U2) = uint::unpack!(de);
                        let (flags, frag_offset): (uint::U3, uint::U13) = uint::unpack!(ff);
                        let proto = IPProto(proto);

                        move |mut buf: &'a [u8]| {
                            let len: usize = (u32::from(ihl) * 4) as usize;
                            if len < 20 {
                                return Err(nom::Err::Error(DissectError::Malformed));
                            } else if buf.len() < len - 20 {
                                return Err(nom::Err::Incomplete(nom::Needed::Size(
                                    std::num::NonZeroUsize::new(len - 20 - buf.len()).unwrap(),
                                )));
                            }

                            let (opts, padding) = if len > 20 {
                                let opt_len = len - 20;
                                let opt_buf = &buf[..opt_len];
                                buf = &buf[opt_len..];
                                let mut done = false;
                                tuple((
                                    fold_many0(
                                        move |tmp_buf: &'a [u8]| {
                                            if done {
                                                return Err(nom::Err::Error(
                                                    DissectError::Malformed,
                                                ));
                                            }
                                            let (tmp_buf, opt) = Opt::dissect(tmp_buf)?;
                                            done = opt.option_type() == OptionType::Eool;
                                            Ok((tmp_buf, opt))
                                        },
                                        Vec::new,
                                        |mut acc: Vec<_>, opt| {
                                            acc.push(opt);
                                            acc
                                        },
                                    ),
                                    map(rest, move |padding: &'a [u8]| {
                                        if padding.len() < 4 && len % 4 == 0 {
                                            Padding::Auto
                                        } else {
                                            Padding::Manual(Vec::from(padding))
                                        }
                                    }),
                                ))(opt_buf)?
                                .1
                            } else {
                                (Vec::new(), Padding::Auto)
                            };

                            Ok((
                                buf,
                                IPv4 {
                                    base: BasePDU::default(),
                                    version,
                                    ihl,
                                    dscp,
                                    ecn,
                                    totlen,
                                    ident,
                                    flags,
                                    frag_offset,
                                    ttl,
                                    proto,
                                    chksum,
                                    src_addr,
                                    dst_addr,
                                    opts,
                                    padding,
                                },
                            ))
                        }
                    },
                )),
                rest,
            )),
            |((hdr_data, mut ipv4), buf): ((&'a [u8], _), &'a [u8])| {
                let (payload, rem) = if buf.len() + hdr_data.len() <= ipv4.totlen as usize {
                    (buf, &buf[buf.len()..])
                } else {
                    let payload_len = ipv4.totlen as usize - hdr_data.len();
                    (&buf[..payload_len], &buf[payload_len..])
                };
                if !payload.is_empty() {
                    let (rem, mut inner) = session
                        .table_dissector::<IPProtoDissectorTable>(
                            &ipv4.proto,
                            Some(TempPDU::new(&ipv4, &parent)),
                        )
                        .or(session.table_dissector::<HeurDissectorTable>(
                            &(),
                            Some(TempPDU::new(&ipv4, &parent)),
                        ))
                        .or(map(RawPDU::decode, AnyPDU::new))
                        .parse(payload)?;
                    if !rem.is_empty() {
                        get_inner_most(&mut inner)
                            .set_inner_pdu(AnyPDU::new(RawPDU::new(Vec::from(rem))));
                    }
                    ipv4.set_inner_pdu(inner);
                }
                Ok((rem, ipv4))
            },
        )(buf)?
        .1
    }
}

fn get_inner_most(pdu: &mut AnyPDU) -> &mut AnyPDU {
    let has_inner = pdu.inner_pdu().is_some();
    if !has_inner {
        pdu
    } else {
        get_inner_most(pdu.inner_pdu_mut().unwrap())
    }
}

impl PDU for IPv4 {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn header_len(&self) -> usize {
        20 + self.opts_len() + self.padding().len()
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        let vi = uint::pack!(self.version, self.ihl);
        let de = uint::pack!(self.dscp, self.ecn);
        let ff = uint::pack!(self.flags, self.frag_offset);

        encoder
            .encode(&vi)?
            .encode(&de)?
            .encode_be(&self.totlen)?
            .encode_be(&self.ident)?
            .encode_be(&ff)?
            .encode(&self.ttl)?
            .encode(&self.proto.0)?
            .encode_be(&self.chksum)?
            .encode(&self.src_addr)?
            .encode(&self.dst_addr)?;
        for opt in self.opts.iter() {
            opt.serialize(encoder)?;
        }
        encoder.encode(self.padding())?;
        Ok(())
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<D>) -> Result<(), D::Error> {
        let mut node = dumper.add_node(
            "IPv4",
            Some(&format!("{}->{}", self.src_addr, self.dst_addr)[..]),
        )?;
        node.add_field("Version", DumpValue::UInt(self.version.into()), None)?;
        node.add_field("IHL", DumpValue::UInt(self.ihl.into()), None)?;
        node.add_field("DSCP", DumpValue::UInt(self.dscp.into()), None)?;
        node.add_field("ECN", DumpValue::UInt(self.ecn.into()), None)?;
        node.add_field("Total Length", DumpValue::UInt(self.totlen.into()), None)?;
        node.add_field("Identification", DumpValue::UInt(self.ident.into()), None)?;
        {
            let flags: u8 = self.flags.into();
            let reserved = (flags & 0b100) > 0;
            let dont_frag = (flags & 0b010) > 0;
            let more_frags = (flags & 0b001) > 0;
            let mut node = node.add_node(
                "Flags",
                Some(
                    &format!(
                        "{}{}{}",
                        if reserved { 1 } else { 0 },
                        if dont_frag { 1 } else { 0 },
                        if more_frags { 1 } else { 0 }
                    )[..],
                ),
            )?;
            node.add_field("Don't Fragment", DumpValue::Bool(dont_frag), None)?;
            node.add_field("More Fragments", DumpValue::Bool(more_frags), None)?;
        }
        node.add_field(
            "Fragment Offset",
            DumpValue::UInt(self.frag_offset.into()),
            None,
        )?;
        node.add_field("Time to Live", DumpValue::UInt(self.ttl.into()), None)?;
        node.add_field("Protocol", DumpValue::UInt(self.proto.0.into()), None)?;
        node.add_field("Checksum", DumpValue::UInt(self.chksum.into()), None)?;
        node.add_field(
            "Source Address",
            DumpValue::Bytes(&self.src_addr[..]),
            Some(&format!("{}", self.src_addr)),
        )?;
        node.add_field(
            "Destination Address",
            DumpValue::Bytes(&self.dst_addr[..]),
            Some(&format!("{}", self.dst_addr)),
        )?;
        if !self.opts.is_empty() {
            let mut node = node.add_node("Options", None)?;
            for opt in self.opts.iter() {
                match opt {
                    Opt::Eool => node.add_info("End of Options List", "")?,
                    Opt::Nop => node.add_info("No Operation", "")?,
                    Opt::Sec(sec) => {
                        let mut node = node.add_node("Security", None)?;
                        node.add_field(
                            "Classification",
                            DumpValue::UInt(u8::from(sec.classification).into()),
                            match sec.classification {
                                Classification::Unclassified => Some("UNCLASSIFIED"),
                                Classification::Confidential => Some("CONFIDENTIAL"),
                                Classification::Secret => Some("SECRET"),
                                Classification::TopSecret => Some("TOP SECRET"),
                                _ => None,
                            },
                        )?;
                        node.add_field("Authority", DumpValue::Bytes(&sec.authority[..]), None)?;
                    }
                    Opt::Lsrr(rr) => {
                        let mut node = node.add_node("Loose Source Route Record", None)?;
                        node.add_field("Pointer", DumpValue::UInt(rr.pointer.into()), None)?;
                        let mut list = node.add_list("Routes", None)?;
                        for i in 0..rr.routes.len() {
                            list.add_item(
                                DumpValue::Bytes(&rr.routes[i][..]),
                                Some(
                                    &format!(
                                        "{} {}",
                                        if i == rr.pointer as usize { "->" } else { "  " },
                                        rr.routes[i]
                                    )[..],
                                ),
                            )?;
                        }
                    }
                    Opt::Ts(ts) => {
                        let mut node = node.add_node("Timestamp", None)?;
                        node.add_field("Pointer", DumpValue::UInt(ts.pointer.into()), None)?;
                        node.add_field("Overflow", DumpValue::UInt(ts.overflow.into()), None)?;
                        node.add_field(
                            "Flag",
                            DumpValue::UInt(uint::U4::from(ts.flag).into()),
                            match ts.flag {
                                TimestampFlag::TsOnly => Some("Timestamp Only (0)"),
                                TimestampFlag::AddrAndTs => Some("Address and Timestamp (1)"),
                                TimestampFlag::PrespecifiedAddrs => {
                                    Some("Prespecified Addresses (3)")
                                }
                                _ => Some("Unknown (2)"),
                            },
                        )?;
                        if ts.entries.is_empty() {
                            node.add_info("Entries", "Empty")?;
                        } else {
                            let mut list = node.add_list("Entries", None)?;
                            for i in 0..ts.entries.len() {
                                match ts.entries[i] {
                                    TimestampEntry::Ts(t) => list.add_item(
                                        DumpValue::Time(t),
                                        Some(
                                            &format!(
                                                "{} {}",
                                                if i == ts.pointer as usize { "->" } else { "  " },
                                                DateTime::<Utc>::from(t)
                                                    .format("%Y-%m-%d %H:%M:%S%.f")
                                            )[..],
                                        ),
                                    )?,
                                    TimestampEntry::Addr(addr) => list.add_item(
                                        DumpValue::Bytes(&addr[..]),
                                        Some(
                                            &format!(
                                                "{}, {}",
                                                if i == ts.pointer as usize { "->" } else { "  " },
                                                addr
                                            )[..],
                                        ),
                                    )?,
                                }
                            }
                        }
                    }
                    Opt::ESec(esec) => {
                        let mut node = node.add_node("Extended Security", None)?;
                        node.add_field("Format", DumpValue::UInt(esec.format.into()), None)?;
                        node.add_field(
                            "Security Info",
                            DumpValue::Bytes(&esec.sec_info[..]),
                            None,
                        )?;
                    }
                    Opt::Cipso(cipso) => {
                        node.add_field("Commercial Security", DumpValue::Bytes(&cipso[..]), None)?
                    }
                    Opt::Rr(rr) => {
                        let mut node = node.add_node("Route Record", None)?;
                        node.add_field("Pointer", DumpValue::UInt(rr.pointer.into()), None)?;
                        let mut list = node.add_list("Routes", None)?;
                        for i in 0..rr.routes.len() {
                            list.add_item(
                                DumpValue::Bytes(&rr.routes[i][..]),
                                Some(
                                    &format!(
                                        "{} {}",
                                        if i == rr.pointer as usize { "->" } else { "  " },
                                        rr.routes[i]
                                    )[..],
                                ),
                            )?;
                        }
                    }
                    Opt::Sid(sid) => {
                        node.add_field("Stream ID", DumpValue::UInt(sid.0.into()), None)?
                    }
                    Opt::Ssrr(rr) => {
                        let mut node = node.add_node("Strict Source Route Record", None)?;
                        node.add_field("Pointer", DumpValue::UInt(rr.pointer.into()), None)?;
                        let mut list = node.add_list("Routes", None)?;
                        for i in 0..rr.routes.len() {
                            list.add_item(
                                DumpValue::Bytes(&rr.routes[i][..]),
                                Some(
                                    &format!(
                                        "{} {}",
                                        if i == rr.pointer as usize { "->" } else { "  " },
                                        rr.routes[i]
                                    )[..],
                                ),
                            )?;
                        }
                    }
                    Opt::Zsu(zsu) => node.add_field(
                        "Experimental Measurement",
                        DumpValue::Bytes(&zsu[..]),
                        None,
                    )?,
                    Opt::Mtup(mtu) => {
                        node.add_field("MTU Probe", DumpValue::UInt(mtu.0.into()), None)?
                    }
                    Opt::Mtur(mtu) => {
                        node.add_field("MTU Reply", DumpValue::UInt(mtu.0.into()), None)?
                    }
                    Opt::Finn(finn) => node.add_field(
                        "Experimental Flow Control",
                        DumpValue::Bytes(&finn[..]),
                        None,
                    )?,
                    Opt::Visa(visa) => node.add_field(
                        "Experimental Access Control",
                        DumpValue::Bytes(&visa[..]),
                        None,
                    )?,
                    Opt::Encode(encode) => {
                        node.add_field("Encode", DumpValue::Bytes(&encode[..]), None)?
                    }
                    Opt::Imitd(imitd) => node.add_field(
                        "IMI Traffic Descriptor",
                        DumpValue::Bytes(&imitd[..]),
                        None,
                    )?,
                    Opt::Eip(eip) => node.add_field(
                        "Extended Internet Protocol",
                        DumpValue::Bytes(&eip[..]),
                        None,
                    )?,
                    Opt::Tr(tr) => {
                        let mut node = node.add_node("Traceroute", None)?;
                        node.add_field("ID", DumpValue::UInt(tr.id.into()), None)?;
                        node.add_field(
                            "Outbound Hop Count",
                            DumpValue::UInt(tr.out_hops.into()),
                            None,
                        )?;
                        node.add_field(
                            "Return Hop Count",
                            DumpValue::UInt(tr.return_hops.into()),
                            None,
                        )?;
                        node.add_field(
                            "Originator IP Address",
                            DumpValue::Bytes(&tr.orig_addr[..]),
                            Some(&format!("{}", tr.orig_addr)[..]),
                        )?;
                    }
                    Opt::AddExt(ext) => {
                        node.add_field("Address Extension", DumpValue::Bytes(&ext[..]), None)?
                    }
                    Opt::RtrAlt(ra) => {
                        node.add_field("Router Alert", DumpValue::UInt(ra.0.into()), None)?
                    }
                    Opt::Sdb(sdb) => node.add_field(
                        "Selective Directed Broadcast",
                        DumpValue::Bytes(&sdb[..]),
                        None,
                    )?,
                    Opt::Dps(dps) => {
                        node.add_field("Dynamic Packet State", DumpValue::Bytes(&dps[..]), None)?
                    }
                    Opt::Ump(ump) => node.add_field(
                        "Upstream Multicast Packet",
                        DumpValue::Bytes(&ump[..]),
                        None,
                    )?,
                    Opt::Qs(qs) => {
                        let mut node = node.add_node("Quick Start", None)?;
                        node.add_field("Function", DumpValue::UInt(qs.func.into()), None)?;
                        node.add_field("Rate Request", DumpValue::UInt(qs.rate_req.into()), None)?;
                        node.add_field("Time to Live", DumpValue::UInt(qs.ttl.into()), None)?;
                        node.add_field("Nonce", DumpValue::UInt(qs.nonce.into()), None)?;
                    }
                    Opt::Raw(opt) => {
                        let mut node = node.add_node("Unknown Option", None)?;
                        {
                            let mut node = node.add_node(
                                "Type",
                                Some(&format!("{}", u8::from(opt.opt_type))[..]),
                            )?;
                            node.add_field("Copied", DumpValue::Bool(opt.opt_type.copied()), None)?;
                            node.add_field(
                                "Class",
                                DumpValue::UInt(uint::U2::from(opt.opt_type.class()).into()),
                                Some(match opt.opt_type.class() {
                                    OptionClass::DebugMeas => "Debug and Measurement (0)",
                                    OptionClass::Control => "Control (2)",
                                    OptionClass::Reserved(val) if u8::from(val) == 1 => {
                                        "Reserved (1)"
                                    }
                                    _ => "Reserved (3)",
                                }),
                            )?;
                            node.add_field(
                                "Number",
                                DumpValue::UInt(opt.opt_type.number().into()),
                                None,
                            )?;
                        }
                        if opt.len.is_some() || !opt.data.is_empty() {
                            node.add_field(
                                "Length",
                                DumpValue::UInt(opt.len.unwrap_or(0).into()),
                                None,
                            )?;
                            node.add_field("Data", DumpValue::Bytes(&opt.data[..]), None)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn make_canonical(&mut self) {
        self.padding = Padding::Auto;
        self.version = 4u8.into_masked();
        let header_len = self.header_len();
        let inner_len = self.inner_pdu().map(|pdu| pdu.total_len()).unwrap_or(0);
        self.ihl = match (header_len as u64 / 4).try_into() {
            Ok(val) => val,
            _ => 0xFu8.into_masked(),
        };
        self.totlen = match (header_len + inner_len).try_into() {
            Ok(val) => val,
            _ => 0xFFFFu16,
        };
        self.update_proto();
        self.update_checksum();
    }
}

impl Default for IPv4 {
    fn default() -> Self {
        Self::new()
    }
}

use super::ethernet_ii::EthertypeDissectorTable;
use super::ethertype::Ethertype;
register_dissector!(
    ipv4,
    EthertypeDissectorTable,
    Ethertype::IPV4,
    Priority(0),
    IPv4::dissect
);
crate::register_ethertype_pdu!(IPv4, Ethertype::IPV4);
