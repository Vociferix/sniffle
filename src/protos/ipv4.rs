use super::prelude::*;
use crate::address::IPv4Address;
use std::time::SystemTime;

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
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct IPProto(pub u8);

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
    opt_type: OptionType,
    len: Option<u8>,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RouteRecord {
    pointer: u8,
    routes: Vec<IPv4Address>,
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
    pointer: u8,
    overflow: uint::U4,
    flag: TimestampFlag,
    entries: Vec<TimestampEntry>,
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
    classification: Classification,
    authority: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ExtendedSecurity {
    format: u8,
    sec_info: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MTU(pub u16);

#[derive(Clone, Debug)]
pub struct Traceroute {
    id: u16,
    out_hops: u16,
    return_hops: u16,
    orig_addr: IPv4Address,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct RouterAlert(pub u16);

#[derive(Clone, Debug)]
pub struct QuickStart {
    func: uint::U4,
    rate_req: uint::U4,
    ttl: u8,
    nonce: uint::U30,
    reserved: uint::U2,
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

fn serialize_basic_security<'a, E: Encoder<'a>>(
    opt: &BasicSecurity,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder
        .encode(&u8::from(opt.classification))?
        .encode(&opt.authority[..])?;
    Ok(())
}

fn serialize_route_record<'a, E: Encoder<'a>>(
    opt: &RouteRecord,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder.encode(&opt.pointer)?.encode(&opt.routes[..])?;
    Ok(())
}

fn serialize_timestamp<'a, E: Encoder<'a>>(
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

fn serialize_extended_security<'a, E: Encoder<'a>>(
    opt: &ExtendedSecurity,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder.encode(&opt.format)?.encode(&opt.sec_info[..])?;
    Ok(())
}

fn serialize_traceroute<'a, E: Encoder<'a>>(
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

fn serialize_quick_start<'a, E: Encoder<'a>>(
    opt: &QuickStart,
    encoder: &mut E,
) -> std::io::Result<()> {
    encoder
        .encode(&uint::pack!(opt.func, opt.rate_req))?
        .encode(&opt.ttl)?
        .encode_be(&uint::pack!(opt.nonce, opt.reserved))?;
    Ok(())
}

impl Opt {
    pub fn dissect(buf: &[u8]) -> DResult<'_, Self> {
        todo!()
    }

    fn serialize_data<'a, E: Encoder<'a>>(&self, encoder: &mut E) -> std::io::Result<()> {
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

    pub fn serialize<'a, E: Encoder<'a>>(&self, encoder: &mut E) -> std::io::Result<()> {
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
        } else {
            if let Some(len) = self.length() {
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
            Raw(opt) => opt.len.map(|len| len as usize),
        }
        .map(|len| if len > 253 { 255u8 } else { (len + 2) as u8 })
    }
}

macro_rules! ip_proto {
    ($name:ident = $val:literal) => {
        pub const $name: IPProto = IPProto($val);
    };
}

impl IPProto {
    ip_proto!(HOPOPT = 0);
    ip_proto!(ICMP = 1);
    ip_proto!(IGMP = 2);
    ip_proto!(GGP = 3);
    ip_proto!(IPV4 = 4);
    ip_proto!(ST = 5);
    ip_proto!(TCP = 6);
    ip_proto!(CBT = 7);
    ip_proto!(EGP = 8);
    ip_proto!(IGP = 9);
    ip_proto!(BBN_RCC_MON = 10);
    ip_proto!(NVP_II = 11);
    ip_proto!(PUP = 12);
    ip_proto!(ARGUS = 13);
    ip_proto!(EMCON = 14);
    ip_proto!(XNET = 15);
    ip_proto!(CHAOS = 16);
    ip_proto!(UDP = 17);
    ip_proto!(MUX = 18);
    ip_proto!(DCN_MEAS = 19);
    ip_proto!(HMP = 20);
    ip_proto!(PRM = 21);
    ip_proto!(XNS_IDP = 22);
    ip_proto!(TRUNK_1 = 23);
    ip_proto!(TRUNK_2 = 24);
    ip_proto!(LEAF_1 = 25);
    ip_proto!(LEAF_2 = 26);
    ip_proto!(RDP = 27);
    ip_proto!(IRTP = 28);
    ip_proto!(ISO_TP4 = 29);
    ip_proto!(NETBLT = 30);
    ip_proto!(MFE_NSP = 31);
    ip_proto!(MERIT_INP = 32);
    ip_proto!(DCCP = 33);
    ip_proto!(_3PC = 34);
    ip_proto!(IDPR = 35);
    ip_proto!(XTP = 36);
    ip_proto!(DDP = 37);
    ip_proto!(IDPR_CMTP = 38);
    ip_proto!(TP_PLUS_PLUS = 39);
    ip_proto!(IL = 40);
    ip_proto!(IPV6 = 41);
    ip_proto!(SDRP = 42);
    ip_proto!(IPV6_ROUTE = 43);
    ip_proto!(IPV6_FRAG = 44);
    ip_proto!(IDRP = 45);
    ip_proto!(RSVP = 46);
    ip_proto!(GRE = 47);
    ip_proto!(DSR = 48);
    ip_proto!(BNA = 49);
    ip_proto!(ESP = 50);
    ip_proto!(AH = 51);
    ip_proto!(I_NLSP = 52);
    ip_proto!(SWIPE = 53);
    ip_proto!(NARP = 54);
    ip_proto!(MOBILE = 55);
    ip_proto!(TLSP = 56);
    ip_proto!(SKIP = 57);
    ip_proto!(IPV6_ICMP = 58);
    ip_proto!(IPV6_NONXT = 59);
    ip_proto!(IPV6_OPTS = 60);
    ip_proto!(ANY_HOST_INTERNAL_PROTOCOL = 61);
    ip_proto!(CFTP = 62);
    ip_proto!(ANY_LOCAL_NETWORK = 63);
    ip_proto!(SAT_EXPAK = 64);
    ip_proto!(KRYPTOLAN = 65);
    ip_proto!(RVD = 66);
    ip_proto!(IPPC = 67);
    ip_proto!(ANY_DISTRIBUTED_FILE_SYSTEM = 68);
    ip_proto!(SAT_MON = 69);
    ip_proto!(VISA = 70);
    ip_proto!(IPCV = 71);
    ip_proto!(CPNX = 72);
    ip_proto!(CPHB = 73);
    ip_proto!(WSN = 74);
    ip_proto!(PVP = 75);
    ip_proto!(BR_SAT_MON = 76);
    ip_proto!(SUN_ND = 77);
    ip_proto!(WB_MON = 78);
    ip_proto!(WB_EXPAK = 79);
    ip_proto!(ISO_IP = 80);
    ip_proto!(VMTP = 81);
    ip_proto!(SECURE_VMTP = 82);
    ip_proto!(VINES = 83);
    ip_proto!(TTP = 84);
    ip_proto!(IPTM = 84);
    ip_proto!(NSFNET_IGP = 85);
    ip_proto!(DGP = 86);
    ip_proto!(TCF = 87);
    ip_proto!(EIGRP = 88);
    ip_proto!(OSPFIGP = 89);
    ip_proto!(SPRITE_RPC = 90);
    ip_proto!(LARP = 91);
    ip_proto!(MTP = 92);
    ip_proto!(AX_25 = 93);
    ip_proto!(IPIP = 94);
    ip_proto!(MICP = 95);
    ip_proto!(SCC_SP = 96);
    ip_proto!(ETHERIP = 97);
    ip_proto!(ENCAP = 98);
    ip_proto!(ANY_PRIVATE_ENCRYPTION_SCHEME = 99);
    ip_proto!(GMTP = 100);
    ip_proto!(IFMP = 101);
    ip_proto!(PNNI = 102);
    ip_proto!(PIM = 103);
    ip_proto!(ARIS = 104);
    ip_proto!(SCPS = 105);
    ip_proto!(QNX = 106);
    ip_proto!(A_N = 107);
    ip_proto!(IPCOMP = 108);
    ip_proto!(SNP = 109);
    ip_proto!(COMPAQ_PEER = 110);
    ip_proto!(IPX_IN_IP = 111);
    ip_proto!(VRRP = 112);
    ip_proto!(PGM = 113);
    ip_proto!(ANY_0_HOP_PROTOCOL = 114);
    ip_proto!(L2TP = 115);
    ip_proto!(DDX = 116);
    ip_proto!(IATP = 117);
    ip_proto!(STP = 118);
    ip_proto!(SRP = 119);
    ip_proto!(UTI = 120);
    ip_proto!(SMP = 121);
    ip_proto!(SM = 122);
    ip_proto!(PTP = 123);
    ip_proto!(ISI_OVER_IPV4 = 124);
    ip_proto!(FIRE = 125);
    ip_proto!(CRTP = 126);
    ip_proto!(CRUDP = 127);
    ip_proto!(SSCOPMCE = 128);
    ip_proto!(IPLT = 129);
    ip_proto!(SPS = 130);
    ip_proto!(PIPE = 131);
    ip_proto!(SCTP = 132);
    ip_proto!(FC = 133);
    ip_proto!(RSVP_E2E_IGNORE = 134);
    ip_proto!(MOBILITY_HEADER = 135);
    ip_proto!(UDPLITE = 136);
    ip_proto!(MPLS_IN_IP = 137);
    ip_proto!(MANET = 138);
    ip_proto!(SHIM6 = 140);
    ip_proto!(WESP = 141);
    ip_proto!(ROHC = 142);
    ip_proto!(ETHERNET = 143);
    ip_proto!(RESERVED = 255);
}

impl From<u8> for IPProto {
    fn from(proto: u8) -> Self {
        Self(proto)
    }
}

impl From<IPProto> for u8 {
    fn from(proto: IPProto) -> Self {
        proto.0
    }
}

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

    pub fn checksum(&self) -> u16 {
        self.chksum
    }

    pub fn checksum_mut(&mut self) -> &mut u16 {
        &mut self.chksum
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
}

impl PDU for IPv4 {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn dissect<'a>(
        buf: &'a [u8],
        session: &Session,
        parent: Option<&mut TempPDU<'_>>,
    ) -> DResult<'a, Self> {
        todo!()
    }

    fn header_len(&self) -> usize {
        // TODO: choose the larger value between IHL and actual length
        //       with options
        todo!()
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        todo!()
    }

    fn serialize_trailer<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        todo!()
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<D>) -> Result<(), D::Error> {
        todo!()
    }

    fn make_canonical(&mut self) {
        todo!()
    }
}

impl Default for IPv4 {
    fn default() -> Self {
        Self::new()
    }
}